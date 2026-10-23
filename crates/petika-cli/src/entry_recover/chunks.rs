//! One-ciphertext-at-a-time import; a complete cache is published only after authentication.
use super::*;
use petika_core::entry_format::{checkpoint::wrapper_set_digest, transaction::EntryVersion};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    backup_version: u32,
    format: String,
    deployment_id: String,
    owner_id: String,
    collection_id: String,
    head_digest: String,
    object: HistoryObject,
    handoff: EntryHandoff,
    entries: BTreeMap<String, EntryVersion>,
}

pub(super) fn read_chunk(path: &Path, limit: usize) -> Result<Vec<u8>> {
    if !path.symlink_metadata()?.file_type().is_file() {
        return Err("Chunk must be a regular file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("Chunk exceeds per-object limit".into());
    }
    Ok(bytes)
}

pub(super) fn recover(args: &BackupArgs, bytes: &[u8], stdin: bool) -> Result<()> {
    let saved: Manifest = serde_json::from_slice(bytes)?;
    if saved.backup_version != 3
        || saved.format != "entry-chunks-v1"
        || saved.deployment_id != saved.object.head.context.deployment_id
        || saved.collection_id != saved.object.head.context.collection_id
        || saved.head_digest != saved.object.head.digest()?
        || saved.entries.len() > 4096
    {
        return Err("Invalid chunk manifest binding".into());
    }
    let folder = args.backup.with_extension("entries");
    if !folder.symlink_metadata()?.file_type().is_dir() {
        return Err("Missing regular chunk directory".into());
    }
    let (_store, trust) = pin(&args.output, &saved.object)?;
    let handoff = EntryHandoff::parse(&serde_json::to_vec(&saved.handoff)?)?;
    if handoff.checkpoint != *trust.checkpoint() {
        return Err("Backup checkpoint differs from retained trust".into());
    }
    let parent = args
        .output
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let stage = tempfile::tempdir_in(parent)?;
    let mut files = Vec::new();
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
        trust.validate_root(&root)?;
        let index = VerifiedIndex::open(
            &root,
            saved.object.head.clone(),
            saved.object.envelope.as_bytes(),
        )?;
        if wrapper_set_digest(&index.index().wrappers)? != trust.checkpoint().wrapper_set_digest
            || index.index().entries.len() != saved.entries.len()
        {
            return Err("Chunk/index coverage mismatch".into());
        }
        let expected: std::collections::BTreeSet<_> = index
            .index()
            .entries
            .iter()
            .map(|e| format!("{}.json", e.id))
            .collect();
        let mut actual = std::collections::BTreeSet::new();
        for item in std::fs::read_dir(&folder)? {
            let item = item?;
            if actual.len() >= expected.len() || !item.file_type()?.is_file() {
                return Err("Unexpected chunk directory entry".into());
            }
            actual.insert(
                item.file_name()
                    .into_string()
                    .map_err(|_| "Invalid chunk filename")?,
            );
        }
        if actual != expected {
            return Err("Missing or unexpected chunks".into());
        }
        for entry in &index.index().entries {
            let reference = saved
                .entries
                .get(&entry.id)
                .ok_or("Missing chunk reference")?;
            if reference.revision != entry.revision || reference.digest != entry.digest {
                return Err("Chunk reference differs from authenticated index".into());
            }
            let value = read_chunk(&folder.join(format!("{}.json", entry.id)), 512 * 1024)?;
            let plaintext = index.open_entry(&root, &entry.id, &value)?;
            let _: Entry = serde_json::from_slice(&plaintext)?;
            let name = format!("entry-{}.json", entry.digest);
            StoreFile::lock(stage.path().join(&name))?.write(&value, true)?;
            files.push(name);
        }
        Ok(())
    })?;
    // Private staging pins the exact ciphertext bytes already authenticated; no source reread.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&args.output.output)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(&args.output.output)?;
    crate::entry_sync::cache_object(&args.output.output, &saved.object)?;
    for name in files {
        StoreFile::lock(args.output.output.join(&name))?
            .write(&read_chunk(&stage.path().join(name), 512 * 1024)?, true)?;
    }
    StoreFile::lock(args.output.output.join("handoff.json"))?
        .write(&serde_json::to_vec(&handoff)?, true)?;
    let anchor = format!("{}.json", saved.head_digest);
    StoreFile::lock(args.output.output.join("RECOVERY.json"))?.write(
        &serde_json::to_vec(&serde_json::json!({
            "version":1,"head":saved.object.head,"anchor":anchor,"entries":saved.entries.len()
        }))?,
        true,
    )?;
    println!(
        "Verified {} encrypted chunks recovered. Local pin and server unchanged.",
        saved.entries.len()
    );
    println!("Anchor: {}", args.output.output.join(anchor).display());
    Ok(())
}
