//! Live-source migration staging and review. No publication or pin mutation.
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
        "Encrypted draft saved. Run migrate-review against the API before proceeding. Submission is not implemented."
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
