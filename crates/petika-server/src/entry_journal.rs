//! Isolated, single-writer committed index/entry history. No legacy snapshot import.
//! Authorization belongs to the account API layer; encrypted semantics to clients.
use crate::Result;
use crate::entry_transaction::{self, Entries, EntryChange, Transaction};
use petika_core::{
    StoreFile,
    entry_format::{digest, history::MAX_HISTORY_BYTES, transport::*},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

// Experimental retained-history quotas; no automatic pruning of receipts.
const MAX_RECORDS: usize = 1024;
const MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn hash(bytes: &[u8]) -> String {
    digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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
struct Record {
    version: u32,
    parent: Option<String>,
    object: HistoryObject,
    receipt: Receipt,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    changes: Vec<EntryChange>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    version: u32,
    record: String,
}

/// Retain the handle for the entire read/write operation. A second writer fails
/// to open it. The server also holds its instance lock for the process lifetime.
/// All reads use the captured committed chain; orphan files are never enumerated.
pub struct Journal {
    directory: PathBuf,
    root: StoreFile,
    records: BTreeMap<u64, (String, Record)>,
    uncertain: bool,
    retained_bytes: usize,
    entries: Entries,
}
impl Journal {
    pub fn open(directory: PathBuf) -> Result<Self> {
        let root = StoreFile::lock(directory.join("committed-root"))?;
        let mut journal = Self {
            directory,
            root,
            records: BTreeMap::new(),
            uncertain: false,
            retained_bytes: 0,
            entries: Entries::new(),
        };
        if journal.root.exists() {
            let root: Root = serde_json::from_slice(&journal.root.read()?)?;
            if root.version != 1 {
                return Err("unsupported journal root".into());
            }
            let mut next = Some(root.record);
            let mut child: Option<HistoryObject> = None;
            while let Some(address) = next {
                if journal.records.len() >= MAX_RECORDS {
                    return Err("journal record quota exceeded".into());
                }
                if !identifier(&address) {
                    return Err("invalid journal address".into());
                }
                let file = StoreFile::lock(journal.directory.join(format!("{address}.json")))?;
                let bytes = file.read()?;
                journal.retained_bytes = journal
                    .retained_bytes
                    .checked_add(bytes.len())
                    .ok_or("journal byte overflow")?;
                if journal.retained_bytes > MAX_JOURNAL_BYTES {
                    return Err("journal byte quota exceeded".into());
                }
                if hash(&bytes) != address {
                    return Err("journal digest mismatch".into());
                }
                let record: Record = serde_json::from_slice(&bytes)?;
                validate(&record.object)?;
                if record.version != 1
                    || record.receipt.accepted != Cursor::from_head(&record.object.head)?
                    || !identifier(&record.receipt.writer)
                    || !identifier(&record.receipt.operation)
                    || !identifier(&record.receipt.request_digest)
                {
                    return Err("invalid committed receipt".into());
                }
                if let Some(child) = &child {
                    adjacent(&record.object, child)?;
                }
                if journal
                    .receipt(&record.receipt.writer, &record.receipt.operation)
                    .is_some()
                {
                    return Err("duplicate committed operation".into());
                }
                if record.parent.is_none() && record.object.head.revision != 1 {
                    return Err("incomplete journal ancestry".into());
                }
                next = record.parent.clone();
                child = Some(record.object.clone());
                if journal
                    .records
                    .insert(record.object.head.revision, (address, record))
                    .is_some()
                {
                    return Err("cyclic journal ancestry".into());
                }
            }
        }
        for (_, record) in journal.records.values() {
            journal.entries =
                entry_transaction::apply(&journal.entries, &record.object, &record.changes)?;
        }
        Ok(journal)
    }
    pub fn current(&self) -> Option<Cursor> {
        self.records
            .last_key_value()
            .map(|(_, (_, r))| r.receipt.accepted.clone())
    }
    pub fn check_context(&self, context: &petika_core::entry_format::Context) -> Result<()> {
        if self.uncertain
            || self
                .records
                .last_key_value()
                .is_none_or(|(_, (_, r))| &r.object.head.context != context)
        {
            return Err("journal context mismatch or uncertain root".into());
        }
        Ok(())
    }
    /// Caller must check current access before every receipt lookup, including retries.
    pub fn receipt(&self, writer: &str, operation: &str) -> Option<Receipt> {
        self.records
            .values()
            .find(|(_, r)| r.receipt.writer == writer && r.receipt.operation == operation)
            .map(|(_, r)| r.receipt.clone())
    }
    pub fn history(&self, request: &HistoryRequest) -> Result<Vec<u8>> {
        if self.uncertain {
            return Err("reopen journal after uncertain publication".into());
        }
        let current = self.current().ok_or("uninitialized journal")?;
        Ok(crate::entry_history::build_page(
            request,
            current,
            |revision| {
                self.records
                    .get(&revision)
                    .map(|(_, r)| r.object.clone())
                    .ok_or(petika_core::Error::Authentication)
            },
        )?)
    }
    /// The journal computes its request digest over the complete index submission.
    /// After any error reopen the journal before retrying: publication may have
    /// succeeded even if the final directory sync or acknowledgement failed.
    pub fn append(
        &mut self,
        expected: Option<&Cursor>,
        writer: &str,
        operation: &str,
        object: HistoryObject,
    ) -> Result<Receipt> {
        self.append_checked(expected, writer, operation, object, |_| Ok(()))
    }
    /// Complete same-epoch entry update. API callers must authorize again after
    /// acquiring the journal lock and bind collection/deployment/membership.
    pub fn transact(&mut self, writer: &str, transaction: Transaction) -> Result<Receipt> {
        use petika_core::entry_format::{Header, Kind, inspect_envelope};
        if transaction.version != 1
            || serde_json::to_vec(&transaction)?.len() > entry_transaction::MAX_TRANSACTION_BYTES
        {
            return Err("invalid or oversized transaction".into());
        }
        let head = &transaction.object.head;
        inspect_envelope(
            transaction.object.envelope.as_bytes(),
            &Header {
                entry_format_version: 1,
                suite: head.suite.clone(),
                context: head.context.clone(),
                kind: Kind::Index,
                object_id: String::new(),
                revision: head.revision,
            },
        )?;
        self.commit(
            Some(&transaction.expected),
            writer,
            &transaction.operation,
            transaction.object,
            transaction.changes,
            |_| Ok(()),
        )
    }
    /// Fetch exact ciphertext under a committed immutable root, including old
    /// roots retained for readers. Never resolve an unversioned latest object.
    pub fn entry(&self, root: &Cursor, id: &str, digest: &str) -> Result<String> {
        if self.uncertain || !identifier(id) || !identifier(digest) {
            return Err("invalid entry read".into());
        }
        let record = self
            .records
            .get(&root.revision)
            .ok_or("unknown read root")?;
        if record.1.receipt.accepted != *root {
            return Err("read root mismatch".into());
        }
        for (_, (_, record)) in self.records.range(..=root.revision).rev() {
            for change in &record.changes {
                match change {
                    EntryChange::Put {
                        id: candidate,
                        envelope,
                        ..
                    } if candidate == id => {
                        if hash(envelope.as_bytes()) != digest {
                            return Err("entry digest mismatch".into());
                        }
                        return Ok(envelope.clone());
                    }
                    EntryChange::Delete { id: candidate, .. } if candidate == id => {
                        return Err("entry deleted at read root".into());
                    }
                    _ => {}
                }
            }
        }
        Err("entry absent at read root".into())
    }
    fn append_checked(
        &mut self,
        expected: Option<&Cursor>,
        writer: &str,
        operation: &str,
        object: HistoryObject,
        boundary: impl FnMut(u8) -> petika_core::Result<()>,
    ) -> Result<Receipt> {
        self.commit(expected, writer, operation, object, vec![], boundary)
    }
    fn commit(
        &mut self,
        expected: Option<&Cursor>,
        writer: &str,
        operation: &str,
        object: HistoryObject,
        changes: Vec<EntryChange>,
        mut boundary: impl FnMut(u8) -> petika_core::Result<()>,
    ) -> Result<Receipt> {
        if !identifier(writer) || !identifier(operation) {
            return Err("invalid operation identifiers".into());
        }
        if self.uncertain {
            return Err("reopen journal after uncertain publication".into());
        }
        validate(&object)?;
        let request_digest = if changes.is_empty() {
            hash(&serde_json::to_vec(&(
                1u32, expected, writer, operation, &object,
            ))?)
        } else {
            hash(&serde_json::to_vec(&(
                1u32, expected, writer, operation, &object, &changes,
            ))?)
        };
        if let Some(receipt) = self.receipt(writer, operation) {
            if receipt.request_digest != request_digest
                || receipt.accepted != Cursor::from_head(&object.head)?
            {
                return Err("operation ID reused with different request".into());
            }
            return Ok(receipt);
        }
        if self.current().as_ref() != expected {
            return Err("entry root conflict".into());
        }
        let entries = entry_transaction::apply(&self.entries, &object, &changes)?;
        let parent = if let Some((_, (address, previous))) = self.records.last_key_value() {
            adjacent(&previous.object, &object)?;
            Some(address.clone())
        } else {
            if object.head.revision != 1 {
                return Err("initial revision must be one".into());
            }
            None
        };
        let receipt = Receipt {
            writer: writer.into(),
            operation: operation.into(),
            request_digest,
            accepted: Cursor::from_head(&object.head)?,
        };
        let record = Record {
            version: 1,
            parent,
            object,
            receipt: receipt.clone(),
            changes,
        };
        let bytes = serde_json::to_vec(&record)?;
        let retained_bytes = self
            .retained_bytes
            .checked_add(bytes.len())
            .ok_or("journal byte overflow")?;
        if self.records.len() >= MAX_RECORDS || retained_bytes > MAX_JOURNAL_BYTES {
            return Err("journal quota exceeded; receipts cannot be pruned".into());
        }
        let address = hash(&bytes);
        let file = StoreFile::lock(self.directory.join(format!("{address}.json")))?;
        if file.exists() {
            if file.read()? != bytes {
                return Err("immutable record collision".into());
            }
        } else {
            file.write_observed(&bytes, true, &mut boundary)?;
        }
        self.uncertain = true;
        self.root.write_observed(
            &serde_json::to_vec(&Root {
                version: 1,
                record: address.clone(),
            })?,
            !self.root.exists(),
            |stage| boundary(stage + 4),
        )?;
        self.records
            .insert(record.object.head.revision, (address, record));
        self.retained_bytes = retained_bytes;
        self.entries = entries;
        self.uncertain = false;
        Ok(receipt)
    }
}

fn validate(object: &HistoryObject) -> Result<()> {
    if object.size()? > MAX_HISTORY_BYTES
        || hash(object.envelope.as_bytes()) != object.head.index_digest
    {
        return Err("invalid index record".into());
    }
    Ok(())
}
fn adjacent(previous: &HistoryObject, next: &HistoryObject) -> Result<()> {
    if next.head.revision
        != previous
            .head
            .revision
            .checked_add(1)
            .ok_or("revision overflow")?
        || next.head.parent_digest != previous.head.digest()?
        || next.head.context != previous.head.context
        || next.head.membership_generation != previous.head.membership_generation
        || next.head.wrapper_set_digest != previous.head.wrapper_set_digest
    {
        return Err("discontinuous index history; rotation requires separate protocol".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use petika_core::entry_format::{RootKey, SUITE, index::Head};
    fn object(revision: u64, parent: String) -> HistoryObject {
        let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
        // Fixed public context across process restarts; payload is opaque here.
        let mut context = root.context().clone();
        context.epoch_salt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        let envelope = format!("opaque encrypted test index {revision}");
        HistoryObject {
            head: Head {
                version: 1,
                context,
                suite: SUITE.into(),
                revision,
                parent_digest: parent,
                index_digest: hash(envelope.as_bytes()),
                wrapper_set_digest: "d".repeat(64),
                membership_generation: 1,
            },
            envelope,
        }
    }
    fn append(j: &mut Journal, revision: u64) -> Receipt {
        let expected = j.current();
        let object = object(
            revision,
            expected
                .as_ref()
                .map(|c| c.digest.clone())
                .unwrap_or_default(),
        );
        j.append(
            expected.as_ref(),
            &"a".repeat(64),
            &format!("{revision:064x}"),
            object,
        )
        .unwrap()
    }
    #[test]
    fn retries_conflicts_lock_and_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = Journal::open(dir.path().into()).unwrap();
        assert!(Journal::open(dir.path().into()).is_err());
        let first = append(&mut j, 1);
        let candidate = object(2, first.accepted.digest.clone());
        let receipt = append(&mut j, 2);
        assert_eq!(
            j.append(
                Some(&first.accepted),
                &"a".repeat(64),
                &format!("{:064x}", 2),
                candidate.clone()
            )
            .unwrap(),
            receipt
        );
        assert!(
            j.append(
                Some(&first.accepted),
                &"a".repeat(64),
                &"e".repeat(64),
                candidate
            )
            .is_err()
        );
        assert!(j.receipt(&"b".repeat(64), &format!("{:064x}", 2)).is_none());
        drop(j);
        let j = Journal::open(dir.path().into()).unwrap();
        assert_eq!(j.current(), Some(receipt.accepted));
    }
    #[test]
    fn changed_request_quota_and_uncertain_publication_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = Journal::open(dir.path().into()).unwrap();
        let first = append(&mut j, 1);
        let candidate = object(2, first.accepted.digest.clone());
        let operation = "e".repeat(64);
        let writer = "a".repeat(64);
        let retained = j.retained_bytes;
        j.retained_bytes = MAX_JOURNAL_BYTES;
        assert!(
            j.append(
                Some(&first.accepted),
                &writer,
                &operation,
                candidate.clone()
            )
            .is_err()
        );
        assert_eq!(j.current(), Some(first.accepted.clone()));
        j.retained_bytes = retained;
        assert!(
            j.append_checked(
                Some(&first.accepted),
                &writer,
                &operation,
                candidate.clone(),
                |stage| {
                    if stage == 7 {
                        Err(petika_core::Error::Io(std::io::Error::other(
                            "injected sync uncertainty",
                        )))
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        assert!(
            j.append(
                Some(&first.accepted),
                &writer,
                &operation,
                candidate.clone()
            )
            .is_err()
        );
        drop(j);
        let mut j = Journal::open(dir.path().into()).unwrap();
        let receipt = j
            .append(
                Some(&first.accepted),
                &writer,
                &operation,
                candidate.clone(),
            )
            .unwrap();
        assert_eq!(receipt.accepted.revision, 2);
        // Even changing only the expected root changes the request digest.
        assert!(
            j.append(Some(&receipt.accepted), &writer, &operation, candidate)
                .is_err()
        );
    }
    #[test]
    fn corrupted_committed_ancestry_is_never_replaced_by_staging() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = Journal::open(dir.path().into()).unwrap();
        append(&mut j, 1);
        append(&mut j, 2);
        let address = j.records[&1].0.clone();
        drop(j);
        let file = StoreFile::lock(dir.path().join(format!("{address}.json"))).unwrap();
        file.write(b"corrupted", false).unwrap();
        drop(file);
        assert!(Journal::open(dir.path().into()).is_err());
    }
    #[test]
    fn termination_worker() {
        let Ok(directory) = std::env::var("PETIKA_JOURNAL_CRASH_DIR") else {
            return;
        };
        let stop: u8 = std::env::var("PETIKA_JOURNAL_CRASH_STAGE")
            .unwrap()
            .parse()
            .unwrap();
        let mut j = Journal::open(directory.into()).unwrap();
        let expected = j.current().unwrap();
        let transaction: Transaction = serde_json::from_slice(
            &std::fs::read(j.directory.join("test-candidate.json")).unwrap(),
        )
        .unwrap();
        let _ = j.commit(
            Some(&expected),
            &"a".repeat(64),
            &"e".repeat(64),
            transaction.object,
            transaction.changes,
            |stage| {
                if stage == stop {
                    std::process::exit(73);
                }
                Ok(())
            },
        );
        panic!("crash boundary not reached");
    }
    #[test]
    fn process_termination_never_promotes_orphan_records() {
        for stage in 1..=8 {
            let dir = tempfile::tempdir().unwrap();
            let mut j = Journal::open(dir.path().into()).unwrap();
            let key = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
            let mut initial = object(1, String::new());
            initial.head.context = key.context().clone();
            j.append(None, &"a".repeat(64), &"1".repeat(64), initial)
                .unwrap();
            let expected = j.current().unwrap();
            let mut candidate = object(2, expected.digest.clone());
            candidate.head.context = key.context().clone();
            let id = "8".repeat(64);
            let envelope = String::from_utf8(
                key.seal(
                    &petika_core::entry_format::Header {
                        entry_format_version: 1,
                        suite: SUITE.into(),
                        context: key.context().clone(),
                        kind: petika_core::entry_format::Kind::Entry,
                        object_id: id.clone(),
                        revision: 1,
                    },
                    b"synthetic crash-test secret",
                )
                .unwrap(),
            )
            .unwrap();
            let digest = hash(envelope.as_bytes());
            let transaction = Transaction {
                version: 1,
                operation: "e".repeat(64),
                expected: expected.clone(),
                object: candidate,
                changes: vec![EntryChange::Put {
                    id: id.clone(),
                    expected: None,
                    revision: 1,
                    envelope: envelope.clone(),
                }],
            };
            StoreFile::lock(dir.path().join("test-candidate.json"))
                .unwrap()
                .write(&serde_json::to_vec(&transaction).unwrap(), true)
                .unwrap();
            drop(j);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "entry_journal::tests::termination_worker"])
                .env("PETIKA_JOURNAL_CRASH_DIR", dir.path())
                .env("PETIKA_JOURNAL_CRASH_STAGE", stage.to_string())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(73));
            let mut j = Journal::open(dir.path().into()).unwrap();
            assert_eq!(j.current().unwrap().revision, if stage < 7 { 1 } else { 2 });
            assert_eq!(
                j.receipt(&"a".repeat(64), &"e".repeat(64)).is_some(),
                stage >= 7
            );
            if stage >= 7 {
                assert_eq!(
                    j.entry(&j.current().unwrap(), &id, &digest).unwrap(),
                    envelope
                );
            } else {
                assert!(j.entry(&expected, &id, &digest).is_err());
            }
            if stage < 7 {
                j.commit(
                    Some(&expected),
                    &"a".repeat(64),
                    &"e".repeat(64),
                    transaction.object,
                    transaction.changes,
                    |_| Ok(()),
                )
                .unwrap();
                assert_eq!(
                    j.entry(&j.current().unwrap(), &id, &digest).unwrap(),
                    envelope
                );
            }
        }
    }
}
