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

#[derive(clap::Args)]
#[group(multiple = true)]
pub struct UnlockArgs {
    /// Explicit recovery-wrapper unlock; never an automatic fallback.
    #[arg(long, required_unless_present = "handoff", conflicts_with = "handoff")]
    pub recovery: Option<PathBuf>,
    /// Active recipient handoff for the already confirmed checkpoint.
    #[arg(
        long,
        requires = "recipient_identity",
        required_unless_present = "recovery"
    )]
    pub handoff: Option<PathBuf>,
    /// Protected local identity bundle; unlocks locally with its own passphrase.
    #[arg(long, requires = "handoff")]
    pub recipient_identity: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Command {
    /// List IDs and names from the authenticated pinned index.
    List(crate::entry_edit::StateArgs),
    /// Decrypt and review an existing draft without revealing passwords.
    Review(crate::entry_edit::ReviewArgs),
    /// Stage an encrypted entry create/replacement without submitting it.
    Put(crate::entry_edit::PutArgs),
    /// Stage an encrypted deletion; IDs remain permanently tombstoned.
    Delete(crate::entry_edit::DeleteArgs),
    /// Confirm/reconcile one existing draft; never rebases or discards it.
    Submit(crate::entry_edit::SubmitArgs),
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
        #[command(flatten)]
        unlock: UnlockArgs,
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
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        pin: PathBuf,
        #[arg(long)]
        cache: PathBuf,
    },
}
pub(crate) fn read_object(path: &Path) -> Result<HistoryObject> {
    let object: HistoryObject = serde_json::from_slice(&StoreFile::lock(path)?.read()?)?;
    object.head.digest()?;
    Ok(object)
}
pub(crate) fn cache_object(directory: &Path, object: &HistoryObject) -> Result<()> {
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
pub(crate) fn unlock(
    args: &UnlockArgs,
    object: &HistoryObject,
    trusted: &TrustedCheckpoint,
    stdin: bool,
) -> Result<(RootKey, VerifiedIndex)> {
    if let Some(handoff_path) = &args.handoff {
        let handoff =
            petika_core::identity::EntryHandoff::parse(&StoreFile::lock(handoff_path)?.read()?)?;
        if handoff.checkpoint.digest()? != trusted.checkpoint().digest()? {
            return Err("Recipient handoff differs from confirmed checkpoint; no automatic trust replacement".into());
        }
        let path = args
            .recipient_identity
            .as_ref()
            .ok_or("Recipient identity is required")?;
        // Keep the file locked across unlock, contact checks and resealing so a
        // concurrent process cannot overwrite a changed/suspended contact pin.
        let file = StoreFile::lock(path)?;
        let bytes = file.read()?;
        let backup: serde_json::Value = serde_json::from_slice(&bytes)?;
        let fingerprint = backup["public_identity"]["fingerprint"]
            .as_str()
            .ok_or("Invalid local identity")?;
        // Do not silently migrate old identity bundles in this new path.
        if backup["backup_version"].as_u64() != Some(2) {
            return Err(
                "Update the identity bundle with the keys workflow before recipient entry unlock"
                    .into(),
            );
        }
        let passphrase = crate::secret("Identity unlock passphrase (local only): ", stdin)?;
        let mut identity =
            petika_core::identity::UnlockedIdentity::open(&bytes, &passphrase, fingerprint)?;
        let result = identity.open_entry_key_package(
            handoff.package.as_bytes(),
            &handoff.checkpoint.authority,
            trusted,
            &handoff.wrappers,
        );
        // Persist contact suspension even when opening the package fails.
        file.write(&identity.seal(&passphrase)?, false)?;
        let root = result?;
        let verified = VerifiedIndex::open(&root, object.head.clone(), object.envelope.as_bytes())?;
        if petika_core::entry_format::checkpoint::wrapper_set_digest(&verified.index().wrappers)?
            != trusted.checkpoint().wrapper_set_digest
        {
            return Err("Active wrapper set differs from checkpoint".into());
        }
        return Ok((root, verified));
    }
    let recovery = args
        .recovery
        .as_ref()
        .ok_or("Choose recovery or recipient unlock")?;
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
        Command::List(args) => return crate::entry_edit::list(session, args, stdin),
        Command::Review(args) => return crate::entry_edit::review(session, args, stdin),
        Command::Put(args) => return crate::entry_edit::put(session, args, stdin),
        Command::Delete(args) => return crate::entry_edit::delete(session, args, stdin),
        Command::Submit(args) => return crate::entry_edit::submit(session, args, stdin),
        Command::Trust {
            checkpoint,
            checkpoint_digest,
            authority_fingerprint,
            confirm,
            index,
            unlock: unlock_args,
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
            let (_, verified) = unlock(unlock_args, &object, &trusted, stdin)?;
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
            unlock: unlock_args,
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
            let (root, mut previous) = unlock(unlock_args, &object, &trusted, stdin)?;
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
