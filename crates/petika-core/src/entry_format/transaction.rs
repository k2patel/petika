//! Experimental transaction wire types and client authentication gates.
use super::{index::VerifiedIndex, transport::*, *};
use std::collections::BTreeSet;
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
            return Err(Error::Format);
        }
        let transaction: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        if transaction.version != 1 {
            return Err(Error::Format);
        }
        Ok(transaction)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub writer: String,
    pub operation: String,
    pub request_digest: String,
    pub accepted: Cursor,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptLookup {
    #[serde(deserialize_with = "required_receipt")]
    pub receipt: Option<Receipt>,
}
fn required_receipt<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Receipt>, D::Error> {
    Option::<Receipt>::deserialize(deserializer)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitResponse {
    pub receipt: Receipt,
    pub replication: String,
}

/// Retain the original empty-delta encoding used by the first journal version.
pub fn submission_digest(
    expected: Option<&Cursor>,
    writer: &str,
    operation: &str,
    object: &HistoryObject,
    changes: &[EntryChange],
) -> Result<String> {
    let bytes = if changes.is_empty() {
        serde_json::to_vec(&(1u32, expected, writer, operation, object))
    } else {
        serde_json::to_vec(&(1u32, expected, writer, operation, object, changes))
    }
    .map_err(|_| Error::Format)?;
    Ok(hex(&digest(&bytes)))
}
impl Transaction {
    pub fn verify_receipt(&self, writer: &str, receipt: &Receipt) -> Result<()> {
        if receipt.writer != writer
            || receipt.operation != self.operation
            || receipt.accepted != Cursor::from_head(&self.object.head)?
            || receipt.request_digest
                != submission_digest(
                    Some(&self.expected),
                    writer,
                    &self.operation,
                    &self.object,
                    &self.changes,
                )?
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    /// Decrypt the candidate index and every changed payload. Public delta IDs,
    /// revisions and hashes must describe exactly the authenticated entry changes.
    pub fn verify(&self, root: &RootKey, previous: &VerifiedIndex) -> Result<VerifiedIndex> {
        if self.version != 1
            || !id(&self.operation)
            || self.changes.len() > MAX_CHANGES
            || serde_json::to_vec(self).map_err(|_| Error::Format)?.len() > MAX_TRANSACTION_BYTES
            || Cursor::from_head(previous.head())? != self.expected
        {
            return Err(Error::Authentication);
        }
        let next = VerifiedIndex::open(
            root,
            self.object.head.clone(),
            self.object.envelope.as_bytes(),
        )?;
        next.follows(previous)?;
        let mut seen = BTreeSet::new();
        for change in &self.changes {
            let target = match change {
                EntryChange::Put { id, .. } | EntryChange::Delete { id, .. } => id,
            };
            if !id(target) || !seen.insert(target.clone()) {
                return Err(Error::Format);
            }
            let old = previous.index().entries.iter().find(|e| &e.id == target);
            let new = next.index().entries.iter().find(|e| &e.id == target);
            match change {
                EntryChange::Put {
                    expected,
                    revision,
                    envelope,
                    ..
                } => {
                    let prior = old.map(|e| EntryVersion {
                        revision: e.revision,
                        digest: e.digest.clone(),
                    });
                    let new = new.ok_or(Error::Authentication)?;
                    if *expected != prior
                        || new.revision != *revision
                        || new.digest != hex(&digest(envelope.as_bytes()))
                        || old.is_some_and(|e| e.digest == new.digest)
                    {
                        return Err(Error::Authentication);
                    }
                    next.open_entry(root, target, envelope.as_bytes())?;
                }
                EntryChange::Delete { expected, .. } => {
                    let old = old.ok_or(Error::Authentication)?;
                    if new.is_some()
                        || old.revision != expected.revision
                        || old.digest != expected.digest
                    {
                        return Err(Error::Authentication);
                    }
                }
            }
        }
        for entry in &previous.index().entries {
            let changed = next
                .index()
                .entries
                .iter()
                .find(|e| e.id == entry.id)
                .is_none_or(|e| e.digest != entry.digest);
            if changed && !seen.contains(&entry.id) {
                return Err(Error::Authentication);
            }
        }
        for entry in &next.index().entries {
            if !previous.index().entries.iter().any(|e| e.id == entry.id)
                && !seen.contains(&entry.id)
            {
                return Err(Error::Authentication);
            }
        }
        Ok(next)
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    #[test]
    fn receipt_absence_must_be_explicit_and_unambiguous() {
        assert!(serde_json::from_slice::<ReceiptLookup>(b"{}").is_err());
        assert!(
            serde_json::from_slice::<ReceiptLookup>(br#"{"receipt":null,"receipt":null}"#).is_err()
        );
        assert!(
            serde_json::from_slice::<ReceiptLookup>(br#"{"receipt":null,"extra":true}"#).is_err()
        );
        assert!(
            serde_json::from_slice::<ReceiptLookup>(br#"{"receipt":null}"#)
                .unwrap()
                .receipt
                .is_none()
        );
    }
}
