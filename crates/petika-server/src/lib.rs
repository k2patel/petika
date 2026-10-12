//! Experimental single-account ciphertext snapshot API support.
use petika_core::{StoreFile, validate_envelope};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    #[serde(
        default = "snapshot_version",
        deserialize_with = "read_snapshot_version"
    )]
    pub schema_version: u32,
    pub revision: u64,
    pub encrypted: String,
}

fn snapshot_version() -> u32 {
    1
}
fn read_snapshot_version<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<u32, D::Error> {
    let version = u32::deserialize(d)?;
    if version == 1 {
        Ok(version)
    } else {
        Err(serde::de::Error::custom("unsupported snapshot schema"))
    }
}

pub enum Update {
    Saved(u64),
    Conflict(u64),
}

pub struct Repository {
    path: PathBuf,
}
impl Repository {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
    pub fn ready(&self) -> Result<()> {
        let file = StoreFile::lock(&self.path)?;
        if file.exists() {
            let _: Snapshot = serde_json::from_slice(&file.read()?)?;
        }
        Ok(())
    }
    pub fn read(&self) -> Result<Option<Snapshot>> {
        let file = StoreFile::lock(&self.path)?;
        if !file.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&file.read()?)?))
    }
    pub fn update(&self, expected: u64, encrypted: String) -> Result<Update> {
        validate_envelope(encrypted.as_bytes())?;
        let file = StoreFile::lock(&self.path)?;
        let current = if file.exists() {
            serde_json::from_slice::<Snapshot>(&file.read()?)?.revision
        } else {
            0
        };
        if current != expected {
            return Ok(Update::Conflict(current));
        }
        let revision = current.checked_add(1).ok_or("revision limit reached")?;
        let bytes = serde_json::to_vec(&Snapshot {
            schema_version: 1,
            revision,
            encrypted,
        })?;
        // Journal first. A failed current-pointer write leaves an unacknowledged revision,
        // which the next attempt may replace. Mirror only through the current pointer.
        let journal = StoreFile::lock(
            self.path
                .parent()
                .unwrap()
                .join("revisions")
                .join(format!("{revision:020}.json")),
        )?;
        journal.write(&bytes, false)?;
        file.write(&bytes, !file.exists())?;
        Ok(Update::Saved(revision))
    }
}

/// Mirrors to a local Git repository only. Remote replication is an operator task.
/// Re-running after failure repairs the mirror from the latest durable API snapshot.
pub fn mirror_once(repository: &Repository, directory: &Path) -> Result<Option<u64>> {
    let Some(snapshot) = repository.read()? else {
        return Ok(None);
    };
    std::fs::create_dir_all(directory)?;
    let _lock = StoreFile::lock(directory.join("mirror-state"))?;
    let git_directory = directory.join("repository.git");
    let git = if git_directory.join("HEAD").exists() {
        gix::open(&git_directory)?
    } else {
        gix::init_bare(&git_directory)?
    };
    let mut parents = Vec::new();
    let previous = if git.head()?.is_unborn() {
        0
    } else {
        let commit = git.head_commit()?;
        parents.push(commit.id);
        std::str::from_utf8(commit.message_raw()?.as_ref())?
            .trim()
            .strip_prefix("Encrypted revision ")
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("mirror has unrelated history")?
    };
    if previous > snapshot.revision {
        return Err("mirror is ahead of API; restore explicitly".into());
    }
    for revision in previous + 1..=snapshot.revision {
        let journal = StoreFile::lock(
            repository
                .path
                .parent()
                .unwrap()
                .join("revisions")
                .join(format!("{revision:020}.json")),
        )?;
        let bytes = journal.read()?;
        let saved: Snapshot = serde_json::from_slice(&bytes)?;
        if saved.revision != revision {
            return Err("invalid journal revision".into());
        }
        let blob = git.write_blob(&bytes)?;
        let mut tree = git.empty_tree().edit()?;
        tree.upsert("snapshot.json", gix::object::tree::EntryKind::Blob, blob)?;
        let tree = tree.write()?;
        let signature = gix::actor::Signature {
            name: "Petika".into(),
            email: "petika@localhost".into(),
            time: gix::date::Time::now_utc(),
        };
        let mut time = Default::default();
        let signature = signature.to_ref(&mut time);
        let commit = git.commit_as(
            signature,
            signature,
            "HEAD",
            format!("Encrypted revision {revision}"),
            tree,
            parents.iter().copied(),
        )?;
        parents = vec![commit.detach()];
    }
    Ok(Some(snapshot.revision))
}

pub mod accounts;
