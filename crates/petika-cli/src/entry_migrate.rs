//! Explicit migration staging, review and receipt-confirmed local acceptance.
use crate::{
    Result, account,
    entry_rotate::RecoveryPolicy,
    entry_sync::{open_recipient, with_identity},
    keys,
};
use clap::Args;
use petika_core::{
    StoreFile,
    entry_format::{
        checkpoint::MAX_WRAPPERS,
        migration_draft::{MigrationDraft, Recovery, SourceBinding},
    },
    identity::PublicIdentity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

#[derive(Args)]
pub struct ReviewArgs {
    #[arg(long, default_value = "personal")]
    pub collection: String,
    #[arg(long)]
    pub authority_identity: PathBuf,
    #[arg(long)]
    pub draft: PathBuf,
}
#[derive(Args)]
pub struct StageArgs {
    #[command(flatten)]
    pub review: ReviewArgs,
    #[arg(long, value_enum)]
    pub recovery_policy: RecoveryPolicy,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u32,
    server: String,
    writer: String,
    draft: MigrationDraft,
}
struct Captured {
    server: String,
    writer: String,
    source: SourceBinding,
    encrypted: String,
    recipients: Vec<PublicIdentity>,
}
fn identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn capture(session: &Path, collection: &str) -> Result<Captured> {
    let client = account::client(session)?;
    let id = account::collection(&client, collection, true)?;
    let user = client.json("GET", "/v1/auth/status", Value::Null)?;
    let writer = user["user"]["id"]
        .as_str()
        .ok_or("Session unavailable")?
        .to_owned();
    if !identifier(&writer) {
        return Err("Invalid account ID".into());
    }
    let deployment = client.json("GET", "/v1/keys/deployment", Value::Null)?;
    let deployment = deployment["deployment_id"]
        .as_str()
        .ok_or("Invalid deployment")?;
    let prefix = format!("/v1/collections/{id}");
    // Legacy key-access is group-only. Personal vaults have one recipient and
    // generation 1, matching server entry authorization; never invent a group.
    if id == writer {
        let identity_path = format!("/v1/keys/users/{writer}");
        let public: PublicIdentity =
            serde_json::from_value(client.json("GET", &identity_path, Value::Null)?)?;
        public.validate()?;
        if public.user_id != writer || public.deployment_id != deployment {
            return Err("Personal identity mismatch".into());
        }
        let (_, revision, encrypted) =
            client.request("GET", &format!("{prefix}/snapshot"), None, None)?;
        let after: PublicIdentity =
            serde_json::from_value(client.json("GET", &identity_path, Value::Null)?)?;
        let (_, after_revision, after_encrypted) =
            client.request("GET", &format!("{prefix}/snapshot"), None, None)?;
        if public != after
            || revision != after_revision
            || encrypted != after_encrypted
            || account::collection(&client, collection, true)? != id
        {
            return Err("Personal source or enrollment changed during capture".into());
        }
        let source = SourceBinding::capture(
            deployment.into(),
            id,
            revision.ok_or("Missing source revision")?,
            1,
            encrypted.as_bytes(),
        )?;
        return Ok(Captured {
            server: client.server.clone(),
            writer,
            source,
            encrypted,
            recipients: vec![public],
        });
    }
    let access = keys::access_state(&client, &prefix)?;
    let rows = access["deliveries"]
        .as_array()
        .ok_or("Invalid recipient roster")?;
    if rows.is_empty() || rows.len() > MAX_WRAPPERS {
        return Err("Recipient roster exceeds migration limits".into());
    }
    let mut seen = BTreeSet::new();
    let mut recipients = vec![];
    for row in rows {
        let user = row["user_id"].as_str().ok_or("Invalid recipient")?;
        if !identifier(user) || !seen.insert(user) {
            return Err("Invalid or duplicate recipient".into());
        }
        let version = row["identity_version"]
            .as_u64()
            .filter(|v| *v > 0)
            .ok_or("Every recipient must enroll before migration")?;
        let public: PublicIdentity = serde_json::from_value(client.json(
            "GET",
            &format!("/v1/keys/users/{user}"),
            Value::Null,
        )?)?;
        public.validate()?;
        if public.user_id != user
            || public.identity_version != version
            || public.deployment_id != deployment
        {
            return Err("Recipient identity changed; fetch again".into());
        }
        recipients.push(public);
    }
    recipients.sort_by(|a, b| a.user_id.cmp(&b.user_id));
    let (_, revision, encrypted) =
        client.request("GET", &format!("{prefix}/snapshot"), None, None)?;
    let revision = revision.ok_or("Missing source revision")?;
    if access["snapshot_revision"].as_u64() != Some(revision)
        || keys::access_state(&client, &prefix)? != access
    {
        return Err("Source or membership changed during capture; nothing staged".into());
    }
    let source = SourceBinding::capture(
        deployment.into(),
        id,
        revision,
        access["membership_generation"]
            .as_u64()
            .ok_or("Missing membership generation")?,
        encrypted.as_bytes(),
    )?;
    if access["key_epoch"].as_u64() != Some(source.key_epoch) {
        return Err("Source epoch mismatch".into());
    }
    // Permission changes may not alter the snapshot; recheck edit access too.
    if account::collection(&client, collection, true)? != source.collection_id {
        return Err("Collection changed".into());
    }
    Ok(Captured {
        server: client.server.clone(),
        writer,
        source,
        encrypted,
        recipients,
    })
}
fn summary(saved: &Saved) -> Result<()> {
    let draft = &saved.draft;
    println!(
        "Migration for {}: source revision {}, membership {}, epoch {} -> {}. {} entries; recovery {:?}.",
        draft.source.collection_id,
        draft.source.snapshot_revision,
        draft.source.membership_generation,
        draft.source.key_epoch,
        draft.state.checkpoint.context.key_epoch,
        draft.entries.len(),
        draft.recovery_policy
    );
    println!("Server: {}", saved.server);
    for recipient in &draft.recipients {
        println!(
            "Recipient {} identity {} fingerprint {}",
            recipient.user_id, recipient.identity_version, recipient.fingerprint
        );
    }
    println!("Candidate checkpoint: {}", draft.state.checkpoint.digest()?);
    println!(
        "Passwords remain hidden. No API write, format switch or local trust-pin change occurred."
    );
    Ok(())
}
pub fn stage(session: &Path, args: &StageArgs, stdin: bool) -> Result<()> {
    let args_common = &args.review;
    let file = StoreFile::lock(&args_common.draft)?;
    if file.exists() {
        return Err("Draft exists; choose a new path".into());
    }
    let captured = capture(session, &args_common.collection)?;
    let source_passphrase = crate::secret("Source recovery passphrase (local only): ", stdin)?;
    let draft = with_identity(&args_common.authority_identity, stdin, |identity| {
        if identity.public_identity().user_id != captured.writer
            || !captured.recipients.contains(identity.public_identity())
        {
            return Err("Authority identity differs from current account enrollment".into());
        }
        let passphrase = if matches!(args.recovery_policy, RecoveryPolicy::Replace) {
            eprintln!("Choose a recovery passphrase for the new entry-format vault.");
            Some(crate::new_passphrase(stdin)?)
        } else {
            None
        };
        Ok(MigrationDraft::stage(
            captured.source,
            captured.encrypted.as_bytes(),
            &source_passphrase,
            identity,
            &captured.recipients,
            passphrase
                .as_ref()
                .map_or(Recovery::Omit, |p| Recovery::Replace(p)),
        )?)
    })?;
    let saved = Saved {
        version: 1,
        server: captured.server,
        writer: captured.writer,
        draft,
    };
    file.write(&serde_json::to_vec(&saved)?, true)?;
    summary(&saved)?;
    println!(
        "Encrypted draft saved. Run migrate-review against the API before proceeding. Submission requires migrate-submit --confirm."
    );
    Ok(())
}
pub fn review(session: &Path, args: &ReviewArgs, stdin: bool) -> Result<()> {
    let file = StoreFile::lock(&args.draft)?;
    let saved: Saved = serde_json::from_slice(&file.read()?)?;
    MigrationDraft::parse(&serde_json::to_vec(&saved.draft)?)?;
    let captured = capture(session, &args.collection)?;
    if saved.version != 1
        || saved.server != captured.server
        || saved.writer != captured.writer
        || saved.draft.source != captured.source
        || saved.draft.recipients != captured.recipients
        || saved.draft.source_encrypted != captured.encrypted
    {
        return Err("Migration source, account, server or recipients changed; draft retained. No rebase or cutover".into());
    }
    let source_passphrase = crate::secret("Source recovery passphrase (local only): ", stdin)?;
    with_identity(&args.authority_identity, stdin, |identity| {
        if identity.public_identity().user_id != captured.writer {
            return Err("Authority account mismatch".into());
        }
        let trusted = saved
            .draft
            .verify_public(&captured.source, identity.public_identity())?;
        let root = open_recipient(identity, &saved.draft.state, &trusted)?;
        saved.draft.verify(
            &captured.source,
            identity.public_identity(),
            &source_passphrase,
            &root,
        )?;
        Ok(())
    })?;
    summary(&saved)?;
    println!(
        "Verified against the captured API state. A later change still requires cutover CAS; this is not proof of global freshness."
    );
    Ok(())
}

#[derive(Args)]
pub struct SubmitArgs {
    #[command(flatten)]
    pub review: ReviewArgs,
    /// New local trust file; an existing different pin is never replaced.
    #[arg(long)]
    pub pin: PathBuf,
    #[arg(long)]
    pub cache: PathBuf,
    /// Authorize this exact reviewed migration and initial local trust acceptance.
    #[arg(long)]
    pub confirm: bool,
}
fn immutable(path: &Path, bytes: &[u8]) -> Result<()> {
    let file = StoreFile::lock(path)?;
    if file.exists() {
        if file.read()? != bytes {
            return Err("Migration artifact differs; preserve evidence".into());
        }
    } else {
        file.write(bytes, true)?;
    }
    Ok(())
}
fn cache_migration(
    cache: &Path,
    draft: &MigrationDraft,
    trusted: &petika_core::entry_format::checkpoint::TrustedCheckpoint,
) -> Result<()> {
    use petika_core::entry_format::{digest, epoch_transaction::EpochWrapper};
    crate::entry_sync::cache_object(cache, &draft.object)?;
    immutable(
        &cache.join(format!("epoch-{}.json", draft.state.checkpoint.digest()?)),
        &serde_json::to_vec(&draft.state)?,
    )?;
    immutable(
        &cache.join(format!("migration-{}.json", draft.operation)),
        &serde_json::to_vec(draft)?,
    )?;
    for entry in &draft.entries {
        let digest: String = digest(entry.envelope.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        immutable(
            &cache.join(format!("entry-{digest}.json")),
            entry.envelope.as_bytes(),
        )?;
    }
    for wrapper in &draft.state.wrappers {
        if let EpochWrapper::Recovery(envelope) = wrapper {
            immutable(
                &cache.join(format!(
                    "recovery-{}.json",
                    wrapper.reference(trusted)?.wrapper_id
                )),
                envelope.as_bytes(),
            )?;
        }
    }
    Ok(())
}
pub fn submit(session: &Path, args: &SubmitArgs, stdin: bool) -> Result<()> {
    use petika_core::entry_format::{
        checkpoint_store::CheckpointStore,
        epoch_transaction::EpochWrapper,
        index::VerifiedIndex,
        transaction::{CommitResponse, ReceiptLookup},
    };
    if !args.confirm {
        return Err("Review the migration and supply --confirm; draft retained".into());
    }
    let file = StoreFile::lock(&args.review.draft)?;
    let saved: Saved = serde_json::from_slice(&file.read()?)?;
    let draft = MigrationDraft::parse(&serde_json::to_vec(&saved.draft)?)?;
    let client = account::client(session)?;
    let collection = account::collection(&client, &args.review.collection, false)?;
    let user = client.json("GET", "/v1/auth/status", Value::Null)?;
    if saved.version != 1
        || saved.server != client.server
        || user["user"]["id"].as_str() != Some(saved.writer.as_str())
        || collection != draft.source.collection_id
    {
        return Err("Migration server/account/collection mismatch; draft retained".into());
    }
    let status = client.json(
        "GET",
        &format!("/v1/collections/{collection}/status"),
        Value::Null,
    )?;
    let active = status["format"].as_str() == Some("entry-v1");
    let store = CheckpointStore::lock(&args.pin)?;
    let existing = args.pin.exists();
    if existing
        && (store.head(&draft.object.head.context)? != draft.object.head
            || store.trusted(&draft.object.head.context)?.checkpoint() != &draft.state.checkpoint)
    {
        return Err("Local pin changed; no migration reset or rebase".into());
    }
    // A missing pin always requires full source/candidate content verification,
    // even when the server already accepted the migration before a lost response.
    let source_passphrase = if existing {
        None
    } else {
        Some(crate::secret(
            "Source recovery passphrase (local only): ",
            stdin,
        )?)
    };
    let (trusted, index) = with_identity(&args.review.authority_identity, stdin, |identity| {
        if identity.public_identity().user_id != saved.writer {
            return Err("Authority account mismatch".into());
        }
        if !active {
            for recipient in &draft.recipients {
                if recipient != identity.public_identity() {
                    identity.require_verified_contact(&recipient.user_id, recipient)?;
                }
            }
        }
        let trusted = draft.verify_public(&draft.source, identity.public_identity())?;
        let root = open_recipient(identity, &draft.state, &trusted)?;
        let index = if let Some(passphrase) = &source_passphrase {
            let verified =
                draft.verify(&draft.source, identity.public_identity(), passphrase, &root)?;
            // Prove the newly selected recovery path is usable before first local
            // acceptance. No alternate wrapper or password is tried automatically.
            for wrapper in &draft.state.wrappers {
                if let EpochWrapper::Recovery(envelope) = wrapper {
                    let passphrase =
                        crate::secret("New recovery passphrase (local only): ", stdin)?;
                    let recovered = trusted.open_recovery(
                        envelope.as_bytes(),
                        &passphrase,
                        &draft.state.references(&trusted)?,
                    )?;
                    VerifiedIndex::open(
                        &recovered,
                        draft.object.head.clone(),
                        draft.object.envelope.as_bytes(),
                    )?
                    .matches_checkpoint(&trusted)?;
                }
            }
            verified
        } else {
            let verified = VerifiedIndex::open(
                &root,
                draft.object.head.clone(),
                draft.object.envelope.as_bytes(),
            )?;
            verified.matches_checkpoint(&trusted)?;
            verified
        };
        Ok((trusted, index))
    })?;
    let receipt = if active {
        let lookup: ReceiptLookup = serde_json::from_slice(&client.entry_call(&collection, "entry-receipt",
            &serde_json::to_vec(&serde_json::json!({"context":draft.object.head.context,"operation":draft.operation}))?, 4096)?)?;
        lookup.receipt.ok_or(
            "Active server has no matching migration receipt; draft retained, no resubmission",
        )?
    } else {
        if existing {
            return Err("Server no longer reports the accepted format; do not reset trust".into());
        }
        if !status["format"].is_null() {
            return Err("Unsupported server format".into());
        }
        let captured = capture(session, &args.review.collection)?;
        if captured.source != draft.source
            || captured.recipients != draft.recipients
            || captured.encrypted != draft.source_encrypted
            || captured.writer != saved.writer
            || captured.server != saved.server
        {
            return Err("Migration source or recipients changed; draft retained, no rebase".into());
        }
        if collection != saved.writer && user["user"]["admin"].as_bool() != Some(true) {
            return Err("Shared migration requires an administrator with edit access".into());
        }
        // Catch local cache conflicts before asking the server to switch formats.
        cache_migration(&args.cache, &draft, &trusted)?;
        let response: CommitResponse = serde_json::from_slice(&client.entry_call(
            &collection,
            "entry-migrations",
            &serde_json::to_vec(&draft)?,
            4096,
        )?)?;
        if !matches!(response.replication.as_str(), "pending" | "unavailable") {
            return Err("Unexpected replication acknowledgement".into());
        }
        response.receipt
    };
    draft.verify_receipt(&saved.writer, &receipt)?;
    cache_migration(&args.cache, &draft, &trusted)?;
    immutable(
        &args.review.draft.with_extension("accepted.json"),
        &serde_json::to_vec(&receipt)?,
    )?;
    if !existing {
        store.initialize(&trusted, &index)?;
    }
    println!(
        "Migration accepted at revision {}. Verified ciphertexts, wrappers and receipt saved before local trust acceptance. Draft retained.",
        receipt.accepted.revision
    );
    println!(
        "Anchor: {}",
        args.cache
            .join(format!("{}.json", draft.object.head.digest()?))
            .display()
    );
    println!("Use --recipient-identity with this cache. Remote Git completion is not confirmed.");
    Ok(())
}
