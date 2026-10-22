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
    #[arg(long, required_unless_present = "recipient_identity", conflicts_with_all = ["handoff", "recipient_identity"])]
    pub recovery: Option<PathBuf>,
    /// Active recipient handoff for the already confirmed checkpoint.
    #[arg(long, requires = "recipient_identity")]
    pub handoff: Option<PathBuf>,
    /// Protected local identity bundle; unlocks locally with its own passphrase.
    #[arg(long, required_unless_present = "recovery")]
    pub recipient_identity: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Stage an encrypted migration from a live legacy snapshot; no cutover.
    MigrateStage(crate::entry_migrate::StageArgs),
    /// Review a migration against the current API source; no cutover.
    MigrateReview(crate::entry_migrate::ReviewArgs),
    /// Submit/reconcile an exact migration and initialize its verified local pin.
    MigrateSubmit(crate::entry_migrate::SubmitArgs),
    /// Stage a complete encrypted key rotation; nothing is submitted.
    Rotate(crate::entry_rotate::StageArgs),
    /// Verify and review the recipients and recovery policy of a rotation draft.
    RotateReview(crate::entry_rotate::DraftArgs),
    /// Submit/reconcile an exact rotation draft and advance its verified pin.
    RotateSubmit(crate::entry_rotate::SubmitArgs),
    /// Verify the next server epoch; --confirm durably accepts it.
    AdvanceEpoch(crate::entry_rotate::AdvanceArgs),
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
    cache: &Path,
) -> Result<(RootKey, VerifiedIndex)> {
    if let Some(path) = &args.recipient_identity {
        let root = with_identity(path, stdin, |identity| {
            if let Some(handoff_path) = &args.handoff {
                let handoff = petika_core::identity::EntryHandoff::parse(
                    &StoreFile::lock(handoff_path)?.read()?,
                )?;
                if handoff.checkpoint.digest()? != trusted.checkpoint().digest()? {
                    return Err("Recipient handoff differs from confirmed checkpoint; no automatic trust replacement".into());
                }
                Ok(identity.open_entry_key_package(
                    handoff.package.as_bytes(),
                    &handoff.checkpoint.authority,
                    trusted,
                    &handoff.wrappers,
                )?)
            } else {
                let state = serde_json::from_slice(
                    &StoreFile::lock(
                        cache.join(format!("epoch-{}.json", trusted.checkpoint().digest()?)),
                    )?
                    .read()?,
                )?;
                open_recipient(identity, &state, trusted)
            }
        })?;
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
pub(crate) fn with_identity<T>(
    path: &Path,
    stdin: bool,
    run: impl FnOnce(&mut petika_core::identity::UnlockedIdentity) -> Result<T>,
) -> Result<T> {
    let file = StoreFile::lock(path)?;
    let bytes = file.read()?;
    let backup: serde_json::Value = serde_json::from_slice(&bytes)?;
    let fingerprint = backup["public_identity"]["fingerprint"]
        .as_str()
        .ok_or("Invalid local identity")?;
    if backup["backup_version"].as_u64() != Some(2) {
        return Err("Update the identity bundle with the keys workflow before entry unlock".into());
    }
    let passphrase = crate::secret("Identity unlock passphrase (local only): ", stdin)?;
    let mut identity =
        petika_core::identity::UnlockedIdentity::open(&bytes, &passphrase, fingerprint)?;
    let result = run(&mut identity);
    // Keep the file locked throughout; persist changed-contact suspensions on
    // rejection as well as success. No rollback to an earlier contact state.
    file.write(&identity.seal(&passphrase)?, false)?;
    result
}
pub(crate) fn open_recipient(
    identity: &mut petika_core::identity::UnlockedIdentity,
    state: &petika_core::entry_format::epoch_transaction::EpochState,
    trusted: &TrustedCheckpoint,
) -> Result<RootKey> {
    use petika_core::{entry_format::epoch_transaction::EpochWrapper, identity::EntryKeyPackage};
    let refs = state.references(trusted)?;
    let mut selected = None;
    for wrapper in &state.wrappers {
        if let EpochWrapper::Recipient(bytes) = wrapper {
            let package = EntryKeyPackage::parse(bytes.as_bytes())?;
            let public = identity.public_identity();
            if package.recipient_user_id == public.user_id
                && package.recipient_identity_version == public.identity_version
                && package.recipient_fingerprint == public.fingerprint
                && selected.replace(bytes).is_some()
            {
                return Err("Ambiguous recipient wrappers".into());
            }
        }
    }
    let bytes = selected.ok_or("No active wrapper for this identity; no recovery fallback")?;
    Ok(identity.open_entry_key_package(
        bytes.as_bytes(),
        &state.checkpoint.authority,
        trusted,
        &refs,
    )?)
}
pub fn run(session: &Path, command: &Command, stdin: bool) -> Result<()> {
    match command {
        Command::MigrateSubmit(args) => return crate::entry_migrate::submit(session, args, stdin),
        Command::MigrateStage(args) => return crate::entry_migrate::stage(session, args, stdin),
        Command::MigrateReview(args) => return crate::entry_migrate::review(session, args, stdin),
        Command::Rotate(args) => return crate::entry_rotate::stage(session, args, stdin),
        Command::RotateReview(args) => return crate::entry_rotate::review(session, args, stdin),
        Command::RotateSubmit(args) => return crate::entry_rotate::submit(session, args, stdin),
        Command::AdvanceEpoch(args) => return crate::entry_rotate::advance(session, args, stdin),
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
            let (_, verified) = unlock(unlock_args, &object, &trusted, stdin, cache)?;
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
            let head = store.collection_head(
                &anchor.head.context.deployment_id,
                &anchor.head.context.collection_id,
            )?;
            let cached = cache.join(format!("{}.json", head.digest()?));
            let object = read_object(&cached).map_err(|_| "Pinned encrypted index is missing or invalid; restore its cache from backup. Do not reset the checkpoint.")?;
            if object.head != head {
                return Err("Pinned cache mismatch; reconcile without resetting trust".into());
            }
            let trusted = store.trusted(&object.head.context)?;
            let (root, mut previous) = unlock(unlock_args, &object, &trusted, stdin, cache)?;
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
