//! Explicit checkpoint confirmation and crash-resumable, bounded history reads.
use crate::{Result, account};
use clap::Subcommand;
use petika_core::{
    StoreFile,
    entry_format::{
        RootKey,
        checkpoint::{Checkpoint, TrustedCheckpoint},
        checkpoint_store::CheckpointStore,
        index::VerifiedIndex,
        transport::*,
    },
};
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum Command {
    /// Initialize a new local pin using independently confirmed public values.
    Trust {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        checkpoint_digest: String,
        #[arg(long)]
        authority_fingerprint: String,
        /// Confirm you compared both values through an independent trusted channel.
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        index: PathBuf,
        #[arg(long)]
        recovery: PathBuf,
        #[arg(long)]
        pin: PathBuf,
        #[arg(long)]
        cache: PathBuf,
    },
    /// Catch up an existing pin; never bootstraps trust from the server.
    Sync {
        #[arg(long, default_value = "personal")]
        collection: String,
        /// Original confirmed index supplies context; resume uses cached pinned head.
        #[arg(long)]
        anchor: PathBuf,
        #[arg(long)]
        recovery: PathBuf,
        #[arg(long)]
        pin: PathBuf,
        #[arg(long)]
        cache: PathBuf,
    },
}
fn read_object(path: &Path) -> Result<HistoryObject> {
    let object: HistoryObject = serde_json::from_slice(&StoreFile::lock(path)?.read()?)?;
    object.head.digest()?;
    Ok(object)
}
fn cache_object(directory: &Path, object: &HistoryObject) -> Result<()> {
    let path = directory.join(format!("{}.json", object.head.digest()?));
    let file = StoreFile::lock(path)?;
    let bytes = serde_json::to_vec(object)?;
    if file.exists() {
        if file.read()? != bytes {
            return Err("Cached index mismatch; preserve evidence and reconcile".into());
        }
    } else {
        file.write(&bytes, true)?;
    }
    Ok(())
}
fn unlock(
    recovery: &Path,
    object: &HistoryObject,
    trusted: &TrustedCheckpoint,
    stdin: bool,
) -> Result<(RootKey, VerifiedIndex)> {
    let passphrase = crate::secret("Entry recovery passphrase (local only): ", stdin)?;
    let bytes = StoreFile::lock(recovery)?.read()?;
    let root = RootKey::open_recovery(&object.head.context, &passphrase, &bytes)?;
    // Decrypt locally to obtain authenticated wrapper references, but expose or
    // persist nothing until both root commitment and active wrapper are checked.
    let verified = VerifiedIndex::open(&root, object.head.clone(), object.envelope.as_bytes())?;
    trusted.validate_root(&root)?;
    let wrapper: serde_json::Value = serde_json::from_slice(&bytes)?;
    let id = wrapper["wrapper_id"]
        .as_str()
        .ok_or("Missing recovery wrapper ID")?;
    trusted.validate_wrapper(&verified.index().wrappers, id, &bytes)?;
    Ok((root, verified))
}
pub fn run(session: &Path, command: &Command, stdin: bool) -> Result<()> {
    match command {
        Command::Trust {
            checkpoint,
            checkpoint_digest,
            authority_fingerprint,
            confirm,
            index,
            recovery,
            pin,
            cache,
        } => {
            if !confirm {
                return Err("Compare the checkpoint digest and authority fingerprint independently, then supply --confirm. This establishes an initial anchor, not global freshness.".into());
            }
            let object = read_object(index)?;
            let cp: Checkpoint = serde_json::from_slice(&StoreFile::lock(checkpoint)?.read()?)?;
            let trusted =
                TrustedCheckpoint::bootstrap(cp, checkpoint_digest, authority_fingerprint)?;
            let (_, verified) = unlock(recovery, &object, &trusted, stdin)?;
            verified.matches_checkpoint(&trusted)?;
            let store = CheckpointStore::lock(pin)?;
            // Cache first. A crash before pin creation leaves harmless ciphertext;
            // a committed pin always has its exact immutable index available.
            cache_object(cache, &object)?;
            store.initialize(&trusted, &verified)?;
            println!(
                "Confirmed checkpoint saved. Existing pins are never overwritten. This does not prove global freshness."
            );
        }
        Command::Sync {
            collection,
            anchor,
            recovery,
            pin,
            cache,
        } => {
            let anchor = read_object(anchor)?;
            let store = CheckpointStore::lock(pin)?;
            let head = store.head(&anchor.head.context)?;
            let cached = cache.join(format!("{}.json", head.digest()?));
            let object = read_object(&cached).map_err(|_| "Pinned encrypted index is missing or invalid; restore its cache from backup. Do not reset the checkpoint.")?;
            if object.head != head {
                return Err("Pinned cache mismatch; reconcile without resetting trust".into());
            }
            let trusted = store.trusted(&object.head.context)?;
            let (root, mut previous) = unlock(recovery, &object, &trusted, stdin)?;
            let client = account::client(session)?;
            let id = account::collection(&client, collection, false)?;
            if id != head.context.collection_id {
                return Err("Selected collection differs from confirmed checkpoint".into());
            }
            let mut request = HistoryRequest {
                version: 1,
                context: head.context.clone(),
                after: Cursor::from_head(&head)?,
                target: None,
                limit: 32,
            };
            loop {
                let bytes = client.entry_history(&id, &serde_json::to_vec(&request)?)?;
                let page = HistoryPage::parse(&bytes, &request)?;
                page.verify(&request, &root, &previous)?;
                for object in &page.items {
                    cache_object(cache, object)?;
                }
                if let Some(accepted) =
                    store.accept_history_response(&request, &bytes, &root, &previous)?
                {
                    previous = accepted;
                }
                match page.next_request(&request)? {
                    Some(next) => request = next,
                    None => break,
                }
            }
            println!(
                "Verified history through revision {}. The server's pagination target does not prove global freshness. Entry payloads and Git replication are not synchronized by this command.",
                previous.head().revision
            );
        }
    }
    Ok(())
}
