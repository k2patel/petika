//! Offline ciphertext recovery against existing local trust, never bootstrap.
use crate::{Result, entry_sync::with_identity};
use clap::Args;
use petika_core::{
    Entry, StoreFile,
    entry_format::{
        RootKey,
        checkpoint::TrustedCheckpoint,
        checkpoint_store::CheckpointStore,
        epoch_transaction::{EpochState, EpochWrapper},
        index::VerifiedIndex,
        transport::HistoryObject,
    },
    identity::{EntryHandoff, EntryKeyPackage},
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
const LIMIT: usize = 16 * 1024 * 1024;
#[derive(Args)]
pub struct OutputArgs {
    /// Independently retained local pin; never copied from this backup.
    #[arg(long)]
    pub pin: PathBuf,
    /// New directory for the verified cache; never overwrite another recovery.
    #[arg(long)]
    pub output: PathBuf,
}
#[derive(Args)]
pub struct GitArgs {
    #[command(flatten)]
    pub output: OutputArgs,
    #[arg(long)]
    pub repository: PathBuf,
    #[arg(long)]
    pub commit: String,
    #[arg(
        long,
        required_unless_present = "recovery_wrapper_id",
        conflicts_with = "recovery_wrapper_id"
    )]
    pub recipient_identity: Option<PathBuf>,
    /// Explicit wrapper ID from the pinned epoch; no automatic fallback.
    #[arg(long, required_unless_present = "recipient_identity")]
    pub recovery_wrapper_id: Option<String>,
}
#[derive(Args)]
pub struct BackupArgs {
    #[command(flatten)]
    pub output: OutputArgs,
    /// One collection JSON from a verified user backup bundle.
    #[arg(long)]
    pub backup: PathBuf,
    #[arg(long)]
    pub recipient_identity: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserBackup {
    backup_version: u32,
    format: String,
    deployment_id: String,
    owner_id: String,
    collection_id: String,
    object: HistoryObject,
    handoff: EntryHandoff,
    entries: BTreeMap<String, String>,
}
fn pin(args: &OutputArgs, object: &HistoryObject) -> Result<(CheckpointStore, TrustedCheckpoint)> {
    if args.output.exists() || args.output.is_symlink() {
        return Err("Recovery destination exists; choose a new directory".into());
    }
    let store = CheckpointStore::lock(&args.pin)?;
    if store.head(&object.head.context)? != object.head {
        return Err("Backup differs from retained local head; no rollback or trust reset".into());
    }
    let trust = store.trusted(&object.head.context)?;
    Ok((store, trust))
}
fn verify(
    object: &HistoryObject,
    entries: &BTreeMap<String, String>,
    root: &RootKey,
    trust: &TrustedCheckpoint,
) -> Result<()> {
    trust.validate_root(root)?;
    let index = VerifiedIndex::open(root, object.head.clone(), object.envelope.as_bytes())?;
    if petika_core::entry_format::checkpoint::wrapper_set_digest(&index.index().wrappers)?
        != trust.checkpoint().wrapper_set_digest
        || entries.len() != index.index().entries.len()
    {
        return Err("Backup object or wrapper coverage mismatch".into());
    }
    for entry in &index.index().entries {
        let envelope = entries.get(&entry.id).ok_or("Missing live ciphertext")?;
        let plaintext = index.open_entry(root, &entry.id, envelope.as_bytes())?;
        let _: Entry = serde_json::from_slice(&plaintext)?;
    }
    Ok(())
}
fn publish(
    args: &OutputArgs,
    object: &HistoryObject,
    entries: &BTreeMap<String, String>,
    handoff: Option<&EntryHandoff>,
    recovery: Option<(&str, &str)>,
) -> Result<()> {
    // No output directory is published until every ciphertext has authenticated.
    #[cfg(unix)]
    let directory = {
        use std::os::unix::fs::DirBuilderExt;
        let mut directory = std::fs::DirBuilder::new();
        directory.mode(0o700);
        directory
    };
    #[cfg(not(unix))]
    let directory = std::fs::DirBuilder::new();
    directory.create(&args.output)?;
    crate::entry_sync::cache_object(&args.output, object)?;
    for envelope in entries.values() {
        let digest =
            crate::entry_edit::hex(&petika_core::entry_format::digest(envelope.as_bytes()));
        StoreFile::lock(args.output.join(format!("entry-{digest}.json")))?
            .write(envelope.as_bytes(), true)?;
    }
    if let Some(handoff) = handoff {
        StoreFile::lock(args.output.join("handoff.json"))?
            .write(&serde_json::to_vec(handoff)?, true)?;
    }
    if let Some((id, envelope)) = recovery {
        StoreFile::lock(args.output.join(format!("recovery-{id}.json")))?
            .write(envelope.as_bytes(), true)?;
    }
    let anchor = format!("{}.json", object.head.digest()?);
    StoreFile::lock(args.output.join("RECOVERY.json"))?.write(&serde_json::to_vec(&serde_json::json!({"version":1,"head":object.head,"anchor":anchor,"entries":entries.len()}))?, true)?;
    println!(
        "Verified {} encrypted entries recovered. Local pin and server unchanged.",
        entries.len()
    );
    println!("Anchor: {}", args.output.join(anchor).display());
    if handoff.is_some() {
        println!(
            "Use --handoff {} with the recipient identity and retained pin.",
            args.output.join("handoff.json").display()
        );
    }
    Ok(())
}
pub fn backup(args: &BackupArgs, stdin: bool) -> Result<()> {
    let saved: UserBackup = serde_json::from_slice(&StoreFile::lock(&args.backup)?.read()?)?;
    if saved.backup_version != 2
        || saved.format != "entry-v1"
        || saved.deployment_id != saved.object.head.context.deployment_id
        || saved.collection_id != saved.object.head.context.collection_id
    {
        return Err("Invalid entry backup binding".into());
    }
    let (_store, trust) = pin(&args.output, &saved.object)?;
    let handoff = EntryHandoff::parse(&serde_json::to_vec(&saved.handoff)?)?;
    if handoff.checkpoint != *trust.checkpoint() {
        return Err("Backup checkpoint differs from retained trust".into());
    }
    with_identity(&args.recipient_identity, stdin, |identity| {
        if identity.public_identity().user_id != saved.owner_id {
            return Err("Backup belongs to another user".into());
        }
        let root = identity.open_entry_key_package(
            handoff.package.as_bytes(),
            &handoff.checkpoint.authority,
            &trust,
            &handoff.wrappers,
        )?;
        verify(&saved.object, &saved.entries, &root, &trust)
    })?;
    publish(
        &args.output,
        &saved.object,
        &saved.entries,
        Some(&handoff),
        None,
    )
}
fn git_read(repository: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .args(["--no-replace-objects", "-C"])
        .arg(repository)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or("Missing Git output")?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() > limit {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Git read failed or exceeds recovery limits".into());
    }
    if !child.wait()?.success() {
        return Err("Git read failed; require a complete local clone".into());
    }
    Ok(bytes)
}
pub fn git(args: &GitArgs, stdin: bool) -> Result<()> {
    if !args.repository.is_dir()
        || !matches!(args.commit.len(), 40 | 64)
        || !args
            .commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Choose a local full clone and a complete lowercase commit ID".into());
    }
    if git_read(
        &args.repository,
        &["rev-parse", "--is-shallow-repository"],
        32,
    )? != b"false\n"
    {
        return Err("Shallow backup cannot be recovered".into());
    }
    git_read(
        &args.repository,
        &["fsck", "--full", "--strict"],
        1024 * 1024,
    )?;
    git_read(
        &args.repository,
        &["cat-file", "-e", &format!("{}^{{commit}}", args.commit)],
        32,
    )?;
    let tree = git_read(
        &args.repository,
        &["ls-tree", "-r", "-z", &args.commit],
        1024 * 1024,
    )?;
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for line in tree.split(|b| *b == 0).filter(|b| !b.is_empty()) {
        let line = std::str::from_utf8(line)?;
        let (meta, name) = line.split_once('\t').ok_or("Invalid Git tree")?;
        let parts: Vec<_> = meta.split_whitespace().collect();
        let entry = name
            .strip_prefix("entries/")
            .and_then(|n| n.strip_suffix(".json"));
        if parts.len() != 3
            || parts[0] != "100644"
            || parts[1] != "blob"
            || !(matches!(
                name,
                "head.json" | "index.json" | "epoch.json" | "transition.json"
            ) || entry.is_some_and(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }))
        {
            return Err("Unexpected Git tree entry".into());
        }
        let bytes = git_read(
            &args.repository,
            &["cat-file", "blob", parts[2]],
            LIMIT.saturating_sub(total),
        )?;
        total = total
            .checked_add(bytes.len())
            .ok_or("Backup size overflow")?;
        if total > LIMIT || files.len() >= 4100 || files.insert(name.to_owned(), bytes).is_some() {
            return Err("Backup exceeds limits or has duplicate files".into());
        }
    }
    let object = HistoryObject {
        head: serde_json::from_slice(files.get("head.json").ok_or("Missing Git head")?)?,
        envelope: String::from_utf8(files.remove("index.json").ok_or("Missing Git index")?)?,
    };
    let state: EpochState =
        serde_json::from_slice(files.get("epoch.json").ok_or("Missing Git epoch")?)?;
    let (_store, trust) = pin(&args.output, &object)?;
    let refs = state.references(&trust)?;
    let entries = files
        .into_iter()
        .filter_map(|(name, bytes)| {
            name.strip_prefix("entries/")
                .and_then(|n| n.strip_suffix(".json"))
                .map(|id| (id.to_owned(), String::from_utf8(bytes)))
        })
        .map(|(id, bytes)| Ok((id, bytes?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    if let Some(path) = &args.recipient_identity {
        let handoff = with_identity(path, stdin, |identity| {
            let own = identity.public_identity();
            let mut selected = None;
            for wrapper in &state.wrappers {
                if let EpochWrapper::Recipient(envelope) = wrapper {
                    let package = EntryKeyPackage::parse(envelope.as_bytes())?;
                    if package.recipient_user_id == own.user_id
                        && package.recipient_identity_version == own.identity_version
                        && package.recipient_fingerprint == own.fingerprint
                        && selected.replace(envelope.clone()).is_some()
                    {
                        return Err("Duplicate recipient wrapper".into());
                    }
                }
            }
            let handoff = EntryHandoff {
                handoff_version: 1,
                checkpoint: state.checkpoint.clone(),
                package: selected.ok_or("No matching recipient wrapper")?,
                wrappers: refs.clone(),
            };
            let handoff = EntryHandoff::parse(&serde_json::to_vec(&handoff)?)?;
            let root = identity.open_entry_key_package(
                handoff.package.as_bytes(),
                &handoff.checkpoint.authority,
                &trust,
                &handoff.wrappers,
            )?;
            verify(&object, &entries, &root, &trust)?;
            Ok(handoff)
        })?;
        publish(&args.output, &object, &entries, Some(&handoff), None)
    } else {
        let id = args
            .recovery_wrapper_id
            .as_ref()
            .ok_or("Choose an unlock method")?;
        let mut selected = None;
        for wrapper in &state.wrappers {
            if let EpochWrapper::Recovery(envelope) = wrapper
                && wrapper.reference(&trust)?.wrapper_id == *id
                && selected.replace(envelope).is_some()
            {
                return Err("Duplicate recovery wrapper".into());
            }
        }
        let envelope = selected.ok_or("Recovery wrapper not present")?;
        let passphrase = crate::secret("Entry recovery passphrase (local only): ", stdin)?;
        let root = trust.open_recovery(envelope.as_bytes(), &passphrase, &refs)?;
        verify(&object, &entries, &root, &trust)?;
        publish(&args.output, &object, &entries, None, Some((id, envelope)))
    }
}
