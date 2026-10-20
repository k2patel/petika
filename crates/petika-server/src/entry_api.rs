//! Experimental account-only routing. No journal initialization or legacy cutover.
use crate::{
    Result,
    accounts::Accounts,
    entry_journal::Journal,
    entry_transaction::{MAX_TRANSACTION_BYTES, Transaction},
};
use petika_core::entry_format::{Context, transport::*};
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
    let write = action == "entry-transactions";
    // Check access before observing even existence/lock state of the journal.
    accounts.with_entry_access(token, collection, write, |_| Ok(()))?;
    let limit = if write { MAX_TRANSACTION_BYTES } else { 4096 };
    let mut bytes = Vec::new();
    body.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("entry request too large".into());
    }
    let path = directory.join("collections").join(collection);
    // Explicit migration is required. Never serve two authoritative formats.
    if path.join("snapshot.json").exists() || !path.join("entries/committed-root").is_file() {
        return Err("entry format not active; migration is unavailable".into());
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
            "entry-history" => {
                let request = HistoryRequest::parse(&bytes)?;
                bind(&request.context)?;
                journal.history(&request)
            }
            "entry-object" => {
                let request: EntryRead = serde_json::from_slice(&bytes)?;
                bind(&request.context)?;
                journal.check_context(&request.context)?;
                Ok(journal
                    .entry(&request.root, &request.id, &request.digest)?
                    .into_bytes())
            }
            "entry-receipt" => {
                let request: ReceiptRead = serde_json::from_slice(&bytes)?;
                bind(&request.context)?;
                journal.check_context(&request.context)?;
                let receipt = journal
                    .receipt(&auth.writer, &request.operation)
                    .ok_or("receipt unavailable")?;
                Ok(serde_json::to_vec(&receipt)?)
            }
            "entry-transactions" => {
                let transaction = Transaction::parse(&bytes)?;
                bind(&transaction.object.head.context)?;
                if transaction.object.head.membership_generation != auth.membership_generation {
                    return Err("membership changed; preserve draft and refetch".into());
                }
                let receipt = journal.transact(&auth.writer, transaction)?;
                Ok(serde_json::to_vec(
                    &serde_json::json!({"receipt": receipt, "replication": "unavailable"}),
                )?)
            }
            _ => Err("unknown entry action".into()),
        }
    })
}
