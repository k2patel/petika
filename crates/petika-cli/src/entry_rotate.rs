//! Complete encrypted rotation drafts and explicit adjacent epoch acceptance.
use crate::{
    Result, account,
    entry_edit::{self, StateArgs, hex, random_id},
    entry_sync::{self, cache_object, open_recipient, read_object, with_identity},
};
use clap::{Args, ValueEnum};
use petika_core::{
    StoreFile,
    entry_format::{
        checkpoint::*,
        checkpoint_store::CheckpointStore,
        epoch_transaction::*,
        index::*,
        rotation::RotationSnapshot,
        transaction::{CommitResponse, EntryVersion, MAX_TRANSACTION_BYTES, ReceiptLookup},
        transport::*,
        *,
    },
    identity::{CheckpointTarget, EntryKeyPackage, PublicIdentity},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
const MAX_DRAFT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, ValueEnum)]
pub enum RecoveryPolicy {
    Replace,
    Omit,
}
#[derive(Args)]
pub struct StageArgs {
    #[command(flatten)]
    pub state: StateArgs,
    #[arg(long)]
    pub authority_identity: PathBuf,
    /// Replace all recovery paths with one new passphrase wrapper, or omit them.
    #[arg(long, value_enum)]
    pub recovery_policy: RecoveryPolicy,
    #[arg(long)]
    pub draft: PathBuf,
}
#[derive(Args)]
pub struct DraftArgs {
    #[command(flatten)]
    pub state: StateArgs,
    #[arg(long)]
    pub authority_identity: PathBuf,
    #[arg(long)]
    pub draft: PathBuf,
}
#[derive(Args)]
pub struct SubmitArgs {
    #[command(flatten)]
    pub draft: DraftArgs,
    #[arg(long)]
    pub confirm: bool,
}
#[derive(Args)]
pub struct AdvanceArgs {
    #[command(flatten)]
    pub state: StateArgs,
    #[arg(
        long,
        required_unless_present = "next_recovery",
        conflicts_with = "next_recovery"
    )]
    pub next_identity: Option<PathBuf>,
    #[arg(long, required_unless_present = "next_identity")]
    pub next_recovery: Option<PathBuf>,
    /// Without this flag, verify and review without changing the local pin.
    #[arg(long)]
    pub confirm: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    version: u32,
    server: String,
    writer: String,
    previous_checkpoint: Checkpoint,
    previous: HistoryObject,
    previous_objects: BTreeMap<String, String>,
    transaction: EpochTransaction,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Roster {
    version: u32,
    membership_generation: u64,
    recipients: Vec<PublicIdentity>,
}
fn bytes(objects: &BTreeMap<String, String>) -> BTreeMap<String, Vec<u8>> {
    objects
        .iter()
        .map(|(id, value)| (id.clone(), value.as_bytes().to_vec()))
        .collect()
}
fn fetch_objects(
    client: &account::Client,
    root: &RootKey,
    index: &VerifiedIndex,
) -> Result<BTreeMap<String, String>> {
    let mut objects = BTreeMap::new();
    let mut total = 0usize;
    for entry in &index.index().entries {
        let value = client.entry_call(&root.context().collection_id, "entry-object", &serde_json::to_vec(&serde_json::json!({"context":root.context(),"root":Cursor::from_head(index.head())?,"id":entry.id,"digest":entry.digest}))?, 512 * 1024)?;
        total = total
            .checked_add(value.len())
            .ok_or("Entry size overflow")?;
        if total > MAX_TRANSACTION_BYTES {
            return Err("Rotation payloads exceed the bounded draft limit".into());
        }
        index.open_entry(root, &entry.id, &value)?;
        objects.insert(entry.id.clone(), String::from_utf8(value)?);
    }
    Ok(objects)
}
fn wire(root: &RootKey, index: &Index) -> Result<HistoryObject> {
    let envelope = root.seal(
        &Header {
            entry_format_version: 1,
            suite: SUITE.into(),
            context: root.context().clone(),
            kind: Kind::Index,
            object_id: String::new(),
            revision: index.revision,
        },
        &zeroize::Zeroizing::new(serde_json::to_vec(index)?),
    )?;
    Ok(HistoryObject {
        head: Head {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: index.revision,
            parent_digest: index.parent_digest.clone(),
            index_digest: hex(&digest(&envelope)),
            wrapper_set_digest: wrapper_set_digest(&index.wrappers)?,
            membership_generation: index.membership_generation,
        },
        envelope: String::from_utf8(envelope)?,
    })
}
fn material(tx: &EpochTransaction) -> EpochState {
    EpochState {
        checkpoint: tx.transition.next.clone(),
        wrappers: tx.wrappers.clone(),
    }
}
fn summary(tx: &EpochTransaction) -> Result<()> {
    println!(
        "Rotation {}: epoch {} -> {}, revision {} -> {}; {} live entries.",
        tx.operation,
        tx.object.head.context.key_epoch - 1,
        tx.object.head.context.key_epoch,
        tx.expected.revision,
        tx.object.head.revision,
        tx.entries.len()
    );
    let mut recovery = 0;
    for wrapper in &tx.wrappers {
        match wrapper {
            EpochWrapper::Recovery(_) => recovery += 1,
            EpochWrapper::Recipient(value) => {
                let package = EntryKeyPackage::parse(value.as_bytes())?;
                println!(
                    "Recipient {} identity {} fingerprint {}",
                    package.recipient_user_id,
                    package.recipient_identity_version,
                    package.recipient_fingerprint
                );
            }
        }
    }
    println!(
        "New recovery wrappers: {recovery}. Previous-epoch wrappers do not unlock the new epoch. Passwords remain hidden."
    );
    Ok(())
}
pub fn stage(session: &Path, args: &StageArgs, stdin: bool) -> Result<()> {
    let file = StoreFile::lock(&args.draft)?;
    if file.exists() {
        return Err("Draft exists; choose a new path".into());
    }
    let (store, root, previous) = entry_edit::load(&args.state, stdin)?;
    let trusted = store.trusted(root.context())?;
    let (client, writer) = entry_edit::client(session, &args.state, root.context(), true)?;
    if writer != trusted.checkpoint().authority.user_id {
        return Err("Only the pinned authority can stage rotation".into());
    }
    if previous.index().entries.len() > petika_core::entry_format::transaction::MAX_CHANGES {
        return Err("Too many entries for one atomic rotation".into());
    }
    let roster: Roster = serde_json::from_slice(&client.entry_call(
        &root.context().collection_id,
        "entry-roster",
        b"{}",
        4 * 1024 * 1024,
    )?)?;
    if roster.version != 1
        || roster.recipients.is_empty()
        || roster.recipients.len() > MAX_WRAPPERS
        || roster.membership_generation < previous.head().membership_generation
        || roster.membership_generation > MAX_COUNTER
    {
        return Err("Invalid rotation roster".into());
    }
    let mut seen = BTreeSet::new();
    for recipient in &roster.recipients {
        recipient.validate()?;
        if recipient.deployment_id != root.context().deployment_id
            || !seen.insert(&recipient.user_id)
        {
            return Err("Foreign or duplicate recipient".into());
        }
    }
    if !roster.recipients.contains(&trusted.checkpoint().authority) {
        return Err("Authority missing or changed in recipient roster".into());
    }
    let old_objects = fetch_objects(&client, &root, &previous)?;
    let old_bytes = bytes(&old_objects);
    let new_root = RootKey::generate(
        root.context().deployment_id.clone(),
        root.context().collection_id.clone(),
        root.context()
            .key_epoch
            .checked_add(1)
            .ok_or("Epoch overflow")?,
    )?;
    let tx = with_identity(&args.authority_identity, stdin, |identity| {
        if identity.public_identity() != &trusted.checkpoint().authority {
            return Err("Identity differs from the pinned authority".into());
        }
        let mut wrappers = vec![];
        let mut refs = vec![];
        for recipient in &roster.recipients {
            // Existing independently verified contact pins are mandatory; never
            // trust a new or changed key merely because the API returned it.
            let package = identity.create_entry_key_package(
                &new_root,
                recipient,
                roster.membership_generation,
                trusted.checkpoint().delivery_profile.clone(),
            )?;
            refs.push(package.reference()?);
            wrappers.push(EpochWrapper::Recipient(serde_json::to_string(&package)?));
        }
        if matches!(args.recovery_policy, RecoveryPolicy::Replace) {
            let passphrase = crate::secret("New epoch recovery passphrase (local only): ", stdin)?;
            let confirm = crate::secret("Confirm new epoch recovery passphrase: ", stdin)?;
            if passphrase != confirm {
                return Err("Recovery passphrases differ; no draft saved".into());
            }
            let value = new_root.wrap_recovery(&passphrase)?;
            let opened = RootKey::open_recovery(new_root.context(), &passphrase, &value)?;
            if opened.commitment() != new_root.commitment() {
                return Err("Recovery verification failed".into());
            }
            let parsed: serde_json::Value = serde_json::from_slice(&value)?;
            refs.push(WrapperRef {
                wrapper_id: parsed["wrapper_id"]
                    .as_str()
                    .ok_or("Invalid recovery wrapper")?
                    .into(),
                digest: hex(&digest(&value)),
            });
            wrappers.push(EpochWrapper::Recovery(String::from_utf8(value)?));
        }
        let mut index = previous.index().clone();
        index.context = new_root.context().clone();
        index.revision = index.revision.checked_add(1).ok_or("Revision overflow")?;
        index.parent_digest = previous.head().digest()?;
        index.membership_generation = roster.membership_generation;
        index.wrappers = refs;
        let mut entries = vec![];
        for entry in &mut index.entries {
            let plaintext = previous.open_entry(&root, &entry.id, &old_bytes[&entry.id])?;
            let expected = EntryVersion {
                revision: entry.revision,
                digest: entry.digest.clone(),
            };
            entry.revision = entry
                .revision
                .checked_add(1)
                .ok_or("Entry revision overflow")?;
            let envelope = new_root.seal(
                &Header {
                    entry_format_version: 1,
                    suite: SUITE.into(),
                    context: new_root.context().clone(),
                    kind: Kind::Entry,
                    object_id: entry.id.clone(),
                    revision: entry.revision,
                },
                &plaintext,
            )?;
            entry.digest = hex(&digest(&envelope));
            entries.push(RotatedEntry {
                id: entry.id.clone(),
                expected,
                revision: entry.revision,
                envelope: String::from_utf8(envelope)?,
            });
        }
        let object = wire(&new_root, &index)?;
        let checkpoint = identity.sign_entry_checkpoint(
            &new_root,
            CheckpointTarget {
                head_revision: index.revision,
                head_digest: object.head.digest()?,
                membership_generation: roster.membership_generation,
                delivery_profile: trusted.checkpoint().delivery_profile.clone(),
            },
            &index.wrappers,
        )?;
        let transition =
            identity.authorize_entry_transition(&trusted, checkpoint, previous.head().revision)?;
        let tx = EpochTransaction {
            version: 1,
            operation: random_id()?,
            expected: Cursor::from_head(previous.head())?,
            transition,
            object,
            entries,
            wrappers,
        };
        tx.verify(
            &trusted,
            RotationSnapshot {
                index: &previous,
                root: &root,
                objects: &old_bytes,
            },
            &new_root,
        )?;
        let next = trusted.advance(&tx.transition, previous.head().revision)?;
        // Round-trip the authority's package before saving a key that only lives
        // in memory. Other recipients still need their own delivery verification.
        let delivered = open_recipient(identity, &material(&tx), &next)?;
        if delivered.commitment() != new_root.commitment() {
            return Err("Authority delivery verification failed".into());
        }
        Ok(tx)
    })?;
    let previous_object = read_object(
        &args
            .state
            .cache
            .join(format!("{}.json", previous.head().digest()?)),
    )?;
    let draft = Draft {
        version: 1,
        server: client.server.clone(),
        writer,
        previous_checkpoint: trusted.checkpoint().clone(),
        previous: previous_object,
        previous_objects: old_objects,
        transaction: tx,
    };
    let encoded = serde_json::to_vec(&draft)?;
    if encoded.len() > MAX_DRAFT_BYTES {
        return Err("Complete rotation draft exceeds 16 MiB; nothing submitted".into());
    }
    file.write(&encoded, true)?;
    summary(&draft.transaction)?;
    println!(
        "Encrypted rotation draft saved. Review the recipient list and recovery policy before rotate-submit --confirm. Nothing submitted."
    );
    Ok(())
}

struct Loaded {
    draft: Draft,
    store: CheckpointStore,
    client: account::Client,
    old: Option<(RootKey, VerifiedIndex)>,
    new_root: RootKey,
    next_trust: TrustedCheckpoint,
}
fn load_draft(session: &Path, args: &DraftArgs, file: &StoreFile, stdin: bool) -> Result<Loaded> {
    let draft: Draft = serde_json::from_slice(&file.read()?)?;
    EpochTransaction::parse(&serde_json::to_vec(&draft.transaction)?)?;
    let anchor = read_object(&args.state.anchor)?;
    let store = CheckpointStore::lock(&args.state.pin)?;
    let head = store.collection_head(
        &anchor.head.context.deployment_id,
        &anchor.head.context.collection_id,
    )?;
    let trusted = store.trusted(&head.context)?;
    let (client, writer) = entry_edit::client(session, &args.state, &head.context, false)?;
    if draft.version != 1 || draft.server != client.server || draft.writer != writer {
        return Err("Rotation draft server/account mismatch".into());
    }
    let tx = &draft.transaction;
    let pinned = Cursor::from_head(&head)?;
    let accepted = Cursor::from_head(&tx.object.head)?;
    let (old, next_trust) = if pinned == tx.expected {
        if draft.previous.head != head
            || draft.previous_checkpoint.digest()? != trusted.checkpoint().digest()?
        {
            return Err("Rotation base differs from the local pin".into());
        }
        let next = tx.verify_public(&trusted, &head)?;
        let old = entry_sync::unlock(
            &args.state.unlock,
            &draft.previous,
            &trusted,
            stdin,
            &args.state.cache,
        )?;
        (Some(old), next)
    } else if pinned == accepted && trusted.checkpoint().digest()? == tx.transition.next.digest()? {
        // Local acceptance already advanced this exact pin. Do not resurrect
        // old trust from a draft or require a now-retired recovery credential.
        (None, trusted.clone())
    } else {
        return Err("Local head changed; rotation draft retained. No rebase or trust reset".into());
    };
    let new_root = with_identity(&args.authority_identity, stdin, |identity| {
        if identity.public_identity() != &next_trust.checkpoint().authority {
            return Err("Rotation authority identity mismatch".into());
        }
        open_recipient(identity, &material(tx), &next_trust)
    })?;
    if let Some((root, previous)) = &old {
        tx.verify(
            &trusted,
            RotationSnapshot {
                index: previous,
                root,
                objects: &bytes(&draft.previous_objects),
            },
            &new_root,
        )?;
    } else {
        VerifiedIndex::open(
            &new_root,
            tx.object.head.clone(),
            tx.object.envelope.as_bytes(),
        )?
        .matches_checkpoint(&trusted)?;
    }
    Ok(Loaded {
        draft,
        store,
        client,
        old,
        new_root,
        next_trust,
    })
}
pub fn review(session: &Path, args: &DraftArgs, stdin: bool) -> Result<()> {
    let file = StoreFile::lock(&args.draft)?;
    let loaded = load_draft(session, args, &file, stdin)?;
    summary(&loaded.draft.transaction)?;
    println!("Verified rotation draft. Nothing submitted and local pin unchanged.");
    Ok(())
}
fn immutable(path: &Path, bytes: &[u8]) -> Result<()> {
    let file = StoreFile::lock(path)?;
    if file.exists() {
        if file.read()? != bytes {
            return Err("Cached rotation artifact mismatch; preserve evidence".into());
        }
    } else {
        file.write(bytes, true)?;
    }
    Ok(())
}
fn cache_rotation(
    cache: &Path,
    tx: &EpochTransaction,
    previous: &BTreeMap<String, String>,
    trust: &TrustedCheckpoint,
) -> Result<()> {
    cache_object(cache, &tx.object)?;
    immutable(
        &cache.join(format!("epoch-{}.json", tx.transition.next.digest()?)),
        &serde_json::to_vec(&material(tx))?,
    )?;
    immutable(
        &cache.join(format!("rotation-{}.json", tx.object.head.digest()?)),
        &serde_json::to_vec(tx)?,
    )?;
    for envelope in previous
        .values()
        .map(String::as_bytes)
        .chain(tx.entries.iter().map(|e| e.envelope.as_bytes()))
    {
        immutable(
            &cache.join(format!("entry-{}.json", hex(&digest(envelope)))),
            envelope,
        )?;
    }
    for wrapper in &tx.wrappers {
        if let EpochWrapper::Recovery(envelope) = wrapper {
            let reference = wrapper.reference(trust)?;
            immutable(
                &cache.join(format!("recovery-{}.json", reference.wrapper_id)),
                envelope.as_bytes(),
            )?;
        }
    }
    Ok(())
}
pub fn submit(session: &Path, args: &SubmitArgs, stdin: bool) -> Result<()> {
    if !args.confirm {
        return Err("Review the rotation and supply --confirm; draft retained".into());
    }
    let args = &args.draft;
    let file = StoreFile::lock(&args.draft)?;
    let loaded = load_draft(session, args, &file, stdin)?;
    let draft = &loaded.draft;
    let tx = &draft.transaction;
    let collection = &tx.object.head.context.collection_id;
    let lookup: ReceiptLookup = serde_json::from_slice(&loaded.client.entry_call(
        collection,
        "entry-receipt",
        &serde_json::to_vec(
            &serde_json::json!({"context":draft.previous.head.context,"operation":tx.operation}),
        )?,
        4096,
    )?)?;
    let receipt = if let Some(receipt) = lookup.receipt {
        receipt
    } else {
        if loaded.old.is_none() {
            return Err("Server withheld the accepted receipt; draft retained".into());
        }
        account::collection(&loaded.client, &args.state.collection, true)?;
        let response: CommitResponse = serde_json::from_slice(&loaded.client.entry_call(
            collection,
            "entry-rotations",
            &serde_json::to_vec(tx)?,
            4096,
        )?)?;
        if !matches!(response.replication.as_str(), "pending" | "unavailable") {
            return Err("Unexpected replication acknowledgement".into());
        }
        response.receipt
    };
    tx.verify_receipt(&draft.writer, &receipt)?;
    cache_rotation(
        &args.state.cache,
        tx,
        &draft.previous_objects,
        &loaded.next_trust,
    )?;
    if let Some((root, previous)) = &loaded.old {
        loaded.store.accept_epoch_transaction(
            tx,
            RotationSnapshot {
                index: previous,
                root,
                objects: &bytes(&draft.previous_objects),
            },
            &loaded.new_root,
        )?;
    }
    immutable(
        &args.draft.with_extension("accepted.json"),
        &serde_json::to_vec(&receipt)?,
    )?;
    println!(
        "API rotation acceptance verified at revision {}. Draft and receipt retained; remote Git completion is not confirmed.",
        receipt.accepted.revision
    );
    println!(
        "New epoch artifacts are in {}. Use --recipient-identity without the old --handoff, or the cached recovery-<wrapper-id>.json file.",
        args.state.cache.display()
    );
    Ok(())
}
pub fn advance(session: &Path, args: &AdvanceArgs, stdin: bool) -> Result<()> {
    let (store, root, previous) = entry_edit::load(&args.state, stdin)?;
    let trusted = store.trusted(root.context())?;
    let (client, _) = entry_edit::client(session, &args.state, root.context(), false)?;
    let lookup: EpochLookup = serde_json::from_slice(&client.entry_call(&root.context().collection_id, "entry-epoch", &serde_json::to_vec(&serde_json::json!({"context":root.context(),"after":Cursor::from_head(previous.head())?}))?, MAX_TRANSACTION_BYTES + 32)?)?;
    let Some(tx) = lookup.transaction else {
        println!(
            "No adjacent rotation reported. Sync same-epoch history first; this does not prove global freshness."
        );
        return Ok(());
    };
    let next = tx.verify_public(&trusted, previous.head())?;
    let state = material(&tx);
    let new_root = if let Some(path) = &args.next_identity {
        with_identity(path, stdin, |identity| {
            open_recipient(identity, &state, &next)
        })?
    } else {
        let path = args
            .next_recovery
            .as_ref()
            .ok_or("Choose the next epoch unlock method")?;
        let value = StoreFile::lock(path)?.read()?;
        let passphrase = crate::secret("Next epoch recovery passphrase (local only): ", stdin)?;
        next.open_recovery(&value, &passphrase, &state.references(&next)?)?
    };
    let objects = fetch_objects(&client, &root, &previous)?;
    let old_bytes = bytes(&objects);
    tx.verify(
        &trusted,
        RotationSnapshot {
            index: &previous,
            root: &root,
            objects: &old_bytes,
        },
        &new_root,
    )?;
    summary(&tx)?;
    if !args.confirm {
        println!("Verified adjacent epoch. Run again with --confirm to advance the local pin.");
        return Ok(());
    }
    cache_rotation(&args.state.cache, &tx, &objects, &next)?;
    store.accept_epoch_transaction(
        &tx,
        RotationSnapshot {
            index: &previous,
            root: &root,
            objects: &old_bytes,
        },
        &new_root,
    )?;
    println!(
        "Verified epoch {} saved. New wrappers and ciphertexts were cached before advancing trust.",
        tx.object.head.context.key_epoch
    );
    Ok(())
}
