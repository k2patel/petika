//! Experimental account-only routing with explicit, authenticated migration cutover.
use crate::{
    Result,
    accounts::Accounts,
    entry_journal::Journal,
    entry_transaction::{MAX_TRANSACTION_BYTES, Transaction},
};
use petika_core::entry_format::{
    Context,
    epoch_transaction::{EpochTransaction, EpochWrapper},
    transport::*,
};
use serde::Deserialize;
use std::{io::Read, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryRead {
    context: Context,
    root: Cursor,
    id: String,
    digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptRead {
    context: Context,
    operation: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochRead {
    context: Context,
    after: Cursor,
}

/// Returned bytes are bounded before callers form an HTTP response. Account
/// denial and missing journals use the same generic error at the HTTP boundary.
pub fn dispatch(
    accounts: &mut Accounts,
    directory: &Path,
    token: &str,
    collection: &str,
    action: &str,
    mut body: impl Read,
) -> Result<Vec<u8>> {
    if !super::entry_journal::identifier(collection) {
        return Err("collection access denied".into());
    }
    let write = matches!(
        action,
        "entry-transactions" | "entry-rotations" | "entry-migrations"
    );
    // Check access before observing even existence/lock state of the journal.
    accounts.with_entry_access(token, collection, write, |_| Ok(()))?;
    let limit = if action == "entry-migrations" {
        petika_core::entry_format::migration_draft::MAX_MIGRATION_BYTES
    } else if write {
        MAX_TRANSACTION_BYTES
    } else {
        4096
    };
    let mut bytes = Vec::new();
    body.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("entry request too large".into());
    }
    let path = directory.join("collections").join(collection);
    // Explicit migration is required. Never serve two authoritative formats.
    if action != "entry-migrations" && !path.join("entries/committed-root").is_file() {
        return Err("entry format not active; explicit migration required".into());
    }
    let mut journal = Journal::open(path.join("entries"))?;
    accounts.with_entry_access(token, collection, write, |auth| {
        let bind = |context: &Context| -> Result<()> {
            if context.collection_id != collection || context.deployment_id != auth.deployment_id {
                return Err("entry context mismatch".into());
            }
            Ok(())
        };
        match action {
            "entry-migrations" => {
                use petika_core::entry_format::migration_draft::{MigrationDraft, SourceBinding};
                if !auth.may_migrate { return Err("migration authority denied".into()); }
                let draft = MigrationDraft::parse(&bytes)?;
                let authority = auth.recipient_identities.get(&auth.writer)
                    .and_then(Option::as_ref).ok_or("authority not enrolled")?;
                let recipients = auth.recipient_identities.values().cloned()
                    .collect::<Option<Vec<_>>>().ok_or("recipient not enrolled")?;
                if draft.recipients != recipients { return Err("migration recipients changed".into()); }
                // Journal -> accounts -> snapshot lock order. Keep all three
                // through the single root publication; legacy bytes are retained.
                let source_file = petika_core::StoreFile::lock(path.join("snapshot.json"))?;
                let source: crate::Snapshot = serde_json::from_slice(&source_file.read()?)?;
                let binding = SourceBinding::capture(auth.deployment_id.clone(), collection.into(),
                    source.revision, auth.membership_generation, source.encrypted.as_bytes())?;
                let trusted = draft.verify_public(&binding, authority)?;
                if draft.source_encrypted != source.encrypted { return Err("migration source changed".into()); }
                let receipt = journal.migrate(&auth.writer, draft, &trusted)?;
                Ok(serde_json::to_vec(&serde_json::json!({"receipt":receipt,"replication":"unavailable"}))?)
            }
            "entry-roster" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Empty {}
                let _: Empty = serde_json::from_slice(&bytes)?;
                if auth.recipient_identities.len() > petika_core::entry_format::checkpoint::MAX_WRAPPERS {
                    return Err("recipient quota exceeded".into());
                }
                let recipients = auth.recipient_identities.values().cloned()
                    .collect::<Option<Vec<_>>>().ok_or("recipient identity not enrolled")?;
                let bytes = serde_json::to_vec(&serde_json::json!({"version":1,"membership_generation":auth.membership_generation,"recipients":recipients}))?;
                if bytes.len() > 4 * 1024 * 1024 { return Err("recipient roster too large".into()); }
                Ok(bytes)
            }
            "entry-history" => {
                let request = HistoryRequest::parse(&bytes)?;
                bind(&request.context)?;
                journal.history(&request)
            }
            "entry-object" => {
                let request: EntryRead = serde_json::from_slice(&bytes)?;
                bind(&request.context)?;
                journal.check_root_context(&request.context, &request.root)?;
                Ok(journal
                    .entry(&request.root, &request.id, &request.digest)?
                    .into_bytes())
            }
            "entry-receipt" => {
                let request: ReceiptRead = serde_json::from_slice(&bytes)?;
                if !super::entry_journal::identifier(&request.operation) {
                    return Err("invalid operation ID".into());
                }
                bind(&request.context)?;
                journal.check_retained_context(&request.context)?;
                let receipt = journal.receipt(&auth.writer, &request.operation);
                Ok(serde_json::to_vec(
                    &petika_core::entry_format::transaction::ReceiptLookup { receipt },
                )?)
            }
            "entry-transactions" => {
                let transaction = Transaction::parse(&bytes)?;
                bind(&transaction.object.head.context)?;
                if transaction.object.head.membership_generation != auth.membership_generation {
                    return Err("membership changed; preserve draft and refetch".into());
                }
                if auth.rotation_required
                    && journal
                        .epoch_state(&journal.current().ok_or("missing entry root")?)?
                        .is_none_or(|s| {
                            s.checkpoint.membership_generation != auth.membership_generation
                        })
                {
                    return Err("membership requires an accepted epoch rotation".into());
                }
                let receipt = journal.transact(&auth.writer, transaction)?;
                Ok(serde_json::to_vec(
                    &serde_json::json!({"receipt": receipt, "replication": "unavailable"}),
                )?)
            }
            "entry-rotations" => {
                let transaction = EpochTransaction::parse(&bytes)?;
                bind(&transaction.object.head.context)?;
                let state = journal
                    .epoch_state(&transaction.expected)?
                    .ok_or("rotation requires anchored journal")?;
                let authority = &state.checkpoint.authority;
                if auth.writer != authority.user_id
                    || auth
                        .recipient_identities
                        .get(&auth.writer)
                        .and_then(Option::as_ref)
                        != Some(authority)
                    || transaction.transition.next.authority != *authority
                    || transaction.object.head.membership_generation != auth.membership_generation
                {
                    return Err("rotation authority or membership mismatch".into());
                }
                let mut delivered = std::collections::BTreeSet::new();
                for wrapper in &transaction.wrappers {
                    if let EpochWrapper::Recipient(bytes) = wrapper {
                        let package =
                            petika_core::identity::EntryKeyPackage::parse(bytes.as_bytes())?;
                        let recipient = auth
                            .recipient_identities
                            .get(&package.recipient_user_id)
                            .and_then(Option::as_ref)
                            .ok_or("recipient unavailable or revoked")?;
                        if package.recipient_identity_version != recipient.identity_version
                            || package.recipient_fingerprint != recipient.fingerprint
                            || !delivered.insert(package.recipient_user_id)
                        {
                            return Err("recipient identity mismatch or duplicate delivery".into());
                        }
                    }
                }
                if delivered.len() != auth.recipient_identities.len() {
                    return Err("rotation must deliver to every current recipient".into());
                }
                let receipt = journal.rotate(&auth.writer, transaction)?;
                Ok(serde_json::to_vec(
                    &serde_json::json!({"receipt":receipt,"replication":"unavailable"}),
                )?)
            }
            "entry-epoch" => {
                let request: EpochRead = serde_json::from_slice(&bytes)?;
                bind(&request.context)?;
                journal.check_root_context(&request.context, &request.after)?;
                let transaction = journal.next_epoch(&request.after)?;
                Ok(serde_json::to_vec(&petika_core::entry_format::epoch_transaction::EpochLookup { transaction })?)
            }
            _ => Err("unknown entry action".into()),
        }
    })
}
