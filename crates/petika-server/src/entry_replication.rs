//! Ordered, server-only Git replication. No fetch/merge/reset/force push.
use crate::{Result, entry_journal::Journal};
use petika_core::{
    StoreFile,
    entry_format::{digest, transport::Cursor},
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::File;
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub version: u32,
    pub local: Cursor,
    pub local_commit: String,
    pub remote: Option<Cursor>,
    pub remote_commit: Option<String>,
    pub destination_digest: Option<String>,
    pub state: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    pub version: u32,
    pub remote: String,
}

pub fn read_status(directory: &Path) -> Result<Option<Status>> {
    if !directory.join("status.json").exists() {
        return Ok(None);
    }
    let file = StoreFile::lock(directory.join("status.json"))?;
    let status: Status = serde_json::from_slice(&file.read()?)?;
    if status.version != 1
        || status.local.revision == 0
        || status.local.revision > petika_core::entry_format::MAX_COUNTER
        || !super::entry_journal::identifier(&status.local.digest)
        || status.local_commit.len() != 40
        || !status.local_commit.bytes().all(|b| b.is_ascii_hexdigit())
        || status.remote.as_ref().is_some_and(|c| {
            c.revision == 0
                || c.revision > status.local.revision
                || !super::entry_journal::identifier(&c.digest)
        })
        || status.remote.is_some() != status.remote_commit.is_some()
        || status.remote.is_some() && status.destination_digest.is_none()
        || status
            .destination_digest
            .as_ref()
            .is_some_and(|id| !super::entry_journal::identifier(id))
        || !matches!(
            status.state.as_str(),
            "local" | "pending" | "confirmed" | "error" | "diverged"
        )
    {
        return Err("invalid replication status".into());
    }
    Ok(Some(status))
}
fn save(directory: &Path, status: &Status) -> Result<()> {
    let file = StoreFile::lock(directory.join("status.json"))?;
    file.write(&serde_json::to_vec(status)?, !file.exists())?;
    Ok(())
}
fn tree(
    git: &gix::Repository,
    journal: &Journal,
    revision: u64,
) -> Result<(gix::ObjectId, Cursor)> {
    let (object, objects) = journal.committed_tree(revision)?;
    let cursor = Cursor::from_head(&object.head)?;
    let mut tree = git.empty_tree().edit()?;
    tree.upsert(
        "head.json",
        gix::object::tree::EntryKind::Blob,
        git.write_blob(serde_json::to_vec(&object.head)?)?,
    )?;
    tree.upsert(
        "index.json",
        gix::object::tree::EntryKind::Blob,
        git.write_blob(object.envelope.as_bytes())?,
    )?;
    if let Some(state) = journal.epoch_state(&cursor)? {
        tree.upsert(
            "epoch.json",
            gix::object::tree::EntryKind::Blob,
            git.write_blob(serde_json::to_vec(&state)?)?,
        )?;
        if let Some(transition) = journal.epoch_transition(&cursor)? {
            tree.upsert(
                "transition.json",
                gix::object::tree::EntryKind::Blob,
                git.write_blob(serde_json::to_vec(&transition)?)?,
            )?;
        }
    }
    for (id, envelope) in objects {
        tree.upsert(
            format!("entries/{id}.json"),
            gix::object::tree::EntryKind::Blob,
            git.write_blob(envelope.as_bytes())?,
        )?;
    }
    Ok((tree.write()?.detach(), cursor))
}
fn message(cursor: &Cursor) -> String {
    format!(
        "Petika entry revision {} {}",
        cursor.revision, cursor.digest
    )
}
fn sync_directory(directory: &Path) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            sync_directory(&entry.path())?;
        } else if kind.is_file() {
            #[cfg(unix)]
            File::open(entry.path())?.sync_all()?;
            #[cfg(not(unix))]
            std::fs::OpenOptions::new()
                .write(true)
                .open(entry.path())?
                .sync_all()?;
        } else {
            return Err("unexpected Git filesystem object".into());
        }
    }
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    Ok(())
}
/// The journal view and replication writer are exclusively held while local
/// objects/refs are generated. Existing commit ancestry/trees must exactly match
/// the authoritative journal; a crash before status publication is recoverable.
pub fn mirror_local(journal: &Journal, directory: &Path) -> Result<Status> {
    mirror_local_checked(journal, directory, |_| Ok(()))
}
fn mirror_local_checked(
    journal: &Journal,
    directory: &Path,
    mut boundary: impl FnMut(u8) -> Result<()>,
) -> Result<Status> {
    let _writer = StoreFile::lock(directory.join("writer"))?;
    let repository = directory.join("repository.git");
    let git = if repository.join("HEAD").exists() {
        gix::open(&repository)?
    } else {
        gix::init_bare(&repository)?
    };
    let current = journal.current().ok_or("uninitialized entry journal")?;
    let mut previous = 0;
    let mut parents = Vec::new();
    let mut known = BTreeMap::new();
    if !git.head()?.is_unborn() {
        let mut commit = git.head_commit()?;
        loop {
            let text = std::str::from_utf8(commit.message_raw()?.as_ref())?
                .trim()
                .to_owned();
            let revision = text
                .strip_prefix("Petika entry revision ")
                .and_then(|s| s.split_once(' '))
                .and_then(|(s, _)| s.parse::<u64>().ok())
                .ok_or("unrelated Git history")?;
            if revision == 0
                || revision > current.revision
                || (!known.is_empty() && revision + 1 != *known.keys().next().unwrap())
            {
                return Err("Git history is ahead or discontinuous".into());
            }
            let (expected, cursor) = tree(&git, journal, revision)?;
            if text != message(&cursor) || commit.tree_id()?.detach() != expected {
                return Err("Git history diverged from journal".into());
            }
            known.insert(revision, commit.id.to_string());
            if previous == 0 {
                previous = revision;
                parents.push(commit.id);
            }
            let ids: Vec<_> = commit.parent_ids().map(|id| id.detach()).collect();
            if revision == 1 {
                if !ids.is_empty() {
                    return Err("unexpected Git root parent".into());
                }
                break;
            }
            if ids.len() != 1 {
                return Err("unexpected Git ancestry".into());
            }
            commit = git.find_commit(ids[0])?;
        }
    }
    let old = read_status(directory)?;
    if let Some(old) = &old {
        if known.get(&old.local.revision) != Some(&old.local_commit)
            || Cursor::from_head(&journal.committed_tree(old.local.revision)?.0.head)? != old.local
        {
            return Err("Git checkpoint is ahead or was replaced".into());
        }
        if let Some(remote) = &old.remote
            && (known.get(&remote.revision) != old.remote_commit.as_ref()
                || Cursor::from_head(&journal.committed_tree(remote.revision)?.0.head)? != *remote)
        {
            return Err("remote replication checkpoint mismatch".into());
        }
    }
    for revision in previous + 1..=current.revision {
        let (tree, cursor) = tree(&git, journal, revision)?;
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
            message(&cursor),
            tree,
            parents.iter().copied(),
        )?;
        parents = vec![commit.detach()];
        boundary(1)?;
    }
    sync_directory(&repository)?;
    boundary(2)?;
    let status = Status {
        version: 1,
        local: current,
        local_commit: parents[0].to_string(),
        remote: old.as_ref().and_then(|s| s.remote.clone()),
        remote_commit: old.as_ref().and_then(|s| s.remote_commit.clone()),
        destination_digest: old.and_then(|s| s.destination_digest),
        state: "local".into(),
    };
    save(directory, &status)?;
    boundary(3)?;
    Ok(status)
}
// Spool bounded output to a private file; do not expose credentials or remote
// diagnostics. Kill a hung/verbose Git process rather than holding API locks.
fn git_output(repository: &Path, args: &[&str]) -> Result<String> {
    let output = tempfile::tempfile()?;
    let mut child=Command::new("git").arg("--git-dir").arg(repository)
        .args(["-c","credential.interactive=false","-c","protocol.ext.allow=never","-c","http.lowSpeedTime=10","-c","http.lowSpeedLimit=1"])
        .args(args).env("GIT_TERMINAL_PROMPT","0").env("GIT_SSH_COMMAND","ssh -oBatchMode=yes -oConnectTimeout=10 -oServerAliveInterval=5 -oServerAliveCountMax=2")
        .stdin(Stdio::null()).stdout(Stdio::from(output.try_clone()?)).stderr(Stdio::null()).spawn()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline || output.metadata()?.len() > 65536 {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Git transport limit exceeded".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if !status.success() {
        return Err("Git transport failed; accepted journal retained".into());
    }
    use std::io::{Seek, SeekFrom};
    let mut output = output;
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = String::new();
    output.take(65537).read_to_string(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("Git output too large".into());
    }
    Ok(bytes)
}
fn validate_remote(config: &RemoteConfig) -> Result<()> {
    if config.version != 1
        || config.remote.len() > 4096
        || config.remote.chars().any(char::is_control)
    {
        return Err("invalid Git destination".into());
    }
    if Path::new(&config.remote).is_absolute() {
        return Ok(());
    }
    let url = url::Url::parse(&config.remote)?;
    if !matches!(url.scheme(), "https" | "ssh")
        || url.host_str().is_none()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("use an SSH/HTTPS URL or absolute local bare-repository path".into());
    }
    Ok(())
}
fn remote_head(repository: &Path, remote: &str) -> Result<Option<String>> {
    let output = git_output(
        repository,
        &["ls-remote", "--heads", "--", remote, "refs/heads/main"],
    )?;
    if output.trim().is_empty() {
        return Ok(None);
    }
    let lines: Vec<_> = output.lines().collect();
    if lines.len() != 1 {
        return Err("ambiguous Git remote head".into());
    }
    let (id, reference) = lines[0].split_once('\t').ok_or("invalid Git remote head")?;
    if reference != "refs/heads/main"
        || id.len() != 40
        || !id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid Git remote head".into());
    }
    Ok(Some(id.to_owned()))
}
/// Called without journal/account/backup locks. External commits stop pushes.
/// Only ordinary fast-forward push is used, followed by remote ref verification.
pub fn push_remote(directory: &Path, config: &RemoteConfig) -> Result<Status> {
    let _writer = StoreFile::lock(directory.join("writer"))?;
    let mut status = read_status(directory)?.ok_or("local mirror unavailable")?;
    if let Err(error) = validate_remote(config) {
        status.state = "error".into();
        save(directory, &status)?;
        return Err(error);
    }
    let destination = digest(config.remote.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if status.destination_digest.as_ref() != Some(&destination) {
        status.remote = None;
        status.remote_commit = None;
        status.destination_digest = Some(destination);
    }
    status.state = "pending".into();
    save(directory, &status)?;
    let repository = directory.join("repository.git");
    let result = (|| -> Result<()> {
        let git = gix::open(&repository)?;
        if git.head_commit()?.id != gix::ObjectId::from_hex(status.local_commit.as_bytes())? {
            return Err("local Git head changed".into());
        }
        let mut known = BTreeMap::new();
        let mut commit = git.head_commit()?;
        let mut revision = status.local.revision;
        loop {
            known.insert(commit.id.to_string(), revision);
            let parents: Vec<_> = commit.parent_ids().map(|id| id.detach()).collect();
            if revision == 1 {
                if !parents.is_empty() {
                    return Err("invalid mirror root".into());
                }
                break;
            }
            if parents.len() != 1 {
                return Err("invalid mirror ancestry".into());
            }
            commit = git.find_commit(parents[0])?;
            revision -= 1;
        }
        let remote = remote_head(&repository, &config.remote)?;
        let remote_revision = remote.as_ref().and_then(|id| known.get(id)).copied();
        if (remote.is_some() && remote_revision.is_none())
            || remote_revision.unwrap_or(0)
                < status.remote.as_ref().map(|c| c.revision).unwrap_or(0)
        {
            status.state = "diverged".into();
            return Err("remote Git history diverged".into());
        }
        git_output(
            &repository,
            &[
                "push",
                "--porcelain",
                "--",
                &config.remote,
                "HEAD:refs/heads/main",
            ],
        )?;
        if remote_head(&repository, &config.remote)?.as_deref() != Some(&status.local_commit) {
            return Err("remote Git confirmation missing".into());
        }
        status.remote = Some(status.local.clone());
        status.remote_commit = Some(status.local_commit.clone());
        status.state = "confirmed".into();
        Ok(())
    })();
    if result.is_err() && status.state != "diverged" {
        status.state = "error".into();
    }
    save(directory, &status)?;
    result?;
    Ok(status)
}
pub fn start_worker(
    data: PathBuf,
    mirror: PathBuf,
    gate: Arc<crate::maintenance_gate::MaintenanceGate>,
) {
    std::thread::spawn(move || {
        loop {
            if let Ok(entries) = std::fs::read_dir(data.join("collections")) {
                for entry in entries.flatten() {
                    let id = entry.file_name().to_string_lossy().into_owned();
                    if !super::entry_journal::identifier(&id)
                        || !entry.path().join("entries/committed-root").is_file()
                    {
                        continue;
                    }
                    let directory = mirror.join(&id).join("entries");
                    let local = (|| -> Result<()> {
                        let _gate = gate.operation().map_err(|_| "backup gate busy")?;
                        let journal = Journal::open(entry.path().join("entries"))?;
                        mirror_local(&journal, &directory)?;
                        Ok(())
                    })();
                    if local.is_err() {
                        if let Ok(Some(mut status)) = read_status(&directory) {
                            status.state = "error".into();
                            let _ = save(&directory, &status);
                        }
                        continue;
                    }
                    let path = entry.path().join("entry-git.json");
                    if path.exists() {
                        let config = (|| -> Result<RemoteConfig> {
                            Ok(serde_json::from_slice(&StoreFile::lock(path)?.read()?)?)
                        })();
                        if let Ok(config) = config {
                            let _ = push_remote(&directory, &config);
                        } else if let Ok(Some(mut status)) = read_status(&directory) {
                            status.state = "error".into();
                            let _ = save(&directory, &status);
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use petika_core::entry_format::{RootKey, SUITE, index::Head, transport::HistoryObject};
    #[test]
    fn crash_worker() {
        let Ok(root) = std::env::var("PETIKA_GIT_CRASH_ROOT") else {
            return;
        };
        let stage: u8 = std::env::var("PETIKA_GIT_CRASH_STAGE")
            .unwrap()
            .parse()
            .unwrap();
        let root = PathBuf::from(root);
        let journal = Journal::open(root.join("journal")).unwrap();
        let _ = mirror_local_checked(&journal, &root.join("mirror"), |point| {
            if point == stage {
                std::process::exit(73);
            }
            Ok(())
        });
        panic!("crash point not reached");
    }
    #[test]
    fn process_termination_replays_ordered_commits_without_duplicate_revisions() {
        for stage in 1..=3 {
            let dir = tempfile::tempdir().unwrap();
            let mut journal = Journal::open(dir.path().join("journal")).unwrap();
            let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
            for revision in 1..=3 {
                let envelope = format!("opaque encrypted index {revision}");
                let head = Head {
                    version: 1,
                    context: root.context().clone(),
                    suite: SUITE.into(),
                    revision,
                    parent_digest: journal.current().map(|c| c.digest).unwrap_or_default(),
                    index_digest: super::super::entry_journal::hash(envelope.as_bytes()),
                    wrapper_set_digest: "e".repeat(64),
                    membership_generation: 1,
                };
                let expected = journal.current();
                journal
                    .append(
                        expected.as_ref(),
                        &"f".repeat(64),
                        &format!("{revision:064x}"),
                        HistoryObject { head, envelope },
                    )
                    .unwrap();
            }
            drop(journal);
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "entry_replication::tests::crash_worker"])
                .env("PETIKA_GIT_CRASH_ROOT", dir.path())
                .env("PETIKA_GIT_CRASH_STAGE", stage.to_string())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(73));
            let journal = Journal::open(dir.path().join("journal")).unwrap();
            let recovered = mirror_local(&journal, &dir.path().join("mirror")).unwrap();
            assert_eq!(recovered.local.revision, 3);
            let again = mirror_local(&journal, &dir.path().join("mirror")).unwrap();
            assert_eq!(recovered.local_commit, again.local_commit);
            let output = Command::new("git")
                .arg("--git-dir")
                .arg(dir.path().join("mirror/repository.git"))
                .args(["rev-list", "--count", "HEAD"])
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "3");
        }
    }
}
