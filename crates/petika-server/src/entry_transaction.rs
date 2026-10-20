//! Public entry preconditions. Names and index semantics remain client-verified.
use crate::Result;
use petika_core::entry_format::{Header, Kind, MAX_COUNTER, inspect_envelope, transport::*};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_CHANGES: usize = 256;
pub const MAX_ENTRY_IDS: usize = 4096;
pub const MAX_TRANSACTION_BYTES: usize = 12 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryVersion {
    pub revision: u64,
    pub digest: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
pub enum EntryChange {
    Put {
        id: String,
        expected: Option<EntryVersion>,
        revision: u64,
        envelope: String,
    },
    Delete {
        id: String,
        expected: EntryVersion,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub version: u32,
    pub operation: String,
    pub expected: Cursor,
    pub object: HistoryObject,
    pub changes: Vec<EntryChange>,
}
impl Transaction {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_TRANSACTION_BYTES {
            return Err("transaction too large".into());
        }
        let transaction: Self = serde_json::from_slice(bytes)?;
        if transaction.version != 1 {
            return Err("unsupported transaction".into());
        }
        Ok(transaction)
    }
}
// None permanently reserves a deleted ID. Public tombstone revision is retained
// in committed Delete records; the encrypted index must agree on the client.
pub(crate) type Entries = BTreeMap<String, Option<EntryVersion>>;
pub(crate) fn apply(
    entries: &Entries,
    object: &HistoryObject,
    changes: &[EntryChange],
) -> Result<Entries> {
    if changes.len() > MAX_CHANGES {
        return Err("too many entry changes".into());
    }
    let mut result = entries.clone();
    let mut seen = BTreeSet::new();
    for change in changes {
        let id = match change {
            EntryChange::Put { id, .. } | EntryChange::Delete { id, .. } => id,
        };
        if !super::entry_journal::identifier(id) || !seen.insert(id) {
            return Err("invalid or duplicate entry ID".into());
        }
        match change {
            EntryChange::Put {
                expected,
                revision,
                envelope,
                ..
            } => {
                let next = match entries.get(id) {
                    None if expected.is_none() => 1,
                    Some(Some(current)) if expected.as_ref() == Some(current) => current
                        .revision
                        .checked_add(1)
                        .ok_or("entry revision overflow")?,
                    _ => return Err("entry precondition conflict or tombstone resurrection".into()),
                };
                if *revision != next || next > MAX_COUNTER || next > object.head.revision {
                    return Err("invalid entry revision".into());
                }
                inspect_envelope(
                    envelope.as_bytes(),
                    &Header {
                        entry_format_version: 1,
                        suite: object.head.suite.clone(),
                        context: object.head.context.clone(),
                        kind: Kind::Entry,
                        object_id: id.clone(),
                        revision: *revision,
                    },
                )?;
                result.insert(
                    id.clone(),
                    Some(EntryVersion {
                        revision: *revision,
                        digest: super::entry_journal::hash(envelope.as_bytes()),
                    }),
                );
            }
            EntryChange::Delete { expected, .. } => {
                if entries.get(id) != Some(&Some(expected.clone()))
                    || expected.revision >= MAX_COUNTER
                {
                    return Err("delete precondition conflict".into());
                }
                result.insert(id.clone(), None);
            }
        }
    }
    if result.len() > MAX_ENTRY_IDS {
        return Err("entry ID quota exceeded".into());
    }
    Ok(result)
}
