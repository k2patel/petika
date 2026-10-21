//! Rotation records share the journal's one durable publication point.
use super::*;
use petika_core::entry_format::{
    Header, Kind,
    checkpoint::{Checkpoint, Transition, TrustedCheckpoint, wrapper_set_digest},
    epoch_transaction::{EpochTransaction, EpochWrapper, RotatedEntry},
    inspect_envelope,
    transaction::submission_digest,
};
#[cfg(test)]
mod tests;

pub use petika_core::entry_format::epoch_transaction::EpochState;
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub(super) enum EpochRecord {
    Anchor {
        state: EpochState,
    },
    Rotation {
        transition: Transition,
        wrappers: Vec<EpochWrapper>,
    },
}
fn trusted(cp: &Checkpoint) -> Result<TrustedCheckpoint> {
    // Only for an already committed local anchor, or an explicitly initialized
    // anchor supplied as TrustedCheckpoint. Never bootstrap from a rotation body.
    Ok(TrustedCheckpoint::bootstrap(
        cp.clone(),
        &cp.digest()?,
        &cp.authority.fingerprint,
    )?)
}
fn anchor_digest(
    writer: &str,
    operation: &str,
    object: &HistoryObject,
    changes: &[EntryChange],
    state: &EpochState,
) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&(
        "petika:entry-anchor:v1",
        writer,
        operation,
        object,
        changes,
        state,
    ))?))
}
fn validate_anchor(state: &EpochState, object: &HistoryObject) -> Result<TrustedCheckpoint> {
    let trust = trusted(&state.checkpoint)?;
    let cp = trust.checkpoint();
    let head = &object.head;
    if head.revision != 1
        || head.context != cp.context
        || head.suite != cp.data_suite
        || head.revision != cp.head_revision
        || head.digest()? != cp.head_digest
        || head.membership_generation != cp.membership_generation
        || head.wrapper_set_digest != cp.wrapper_set_digest
    {
        return Err("anchor mismatch".into());
    }
    let refs = state
        .wrappers
        .iter()
        .map(|w| w.reference(&trust))
        .collect::<petika_core::Result<Vec<_>>>()?;
    if wrapper_set_digest(&refs)? != cp.wrapper_set_digest {
        return Err("anchor wrappers mismatch".into());
    }
    inspect_envelope(
        object.envelope.as_bytes(),
        &Header {
            entry_format_version: 1,
            suite: head.suite.clone(),
            context: head.context.clone(),
            kind: Kind::Index,
            object_id: String::new(),
            revision: head.revision,
        },
    )?;
    Ok(trust)
}
fn transaction(
    record: &Record,
    previous: &HistoryObject,
    transition: &Transition,
    wrappers: &[EpochWrapper],
) -> Result<EpochTransaction> {
    let entries = record
        .changes
        .iter()
        .map(|change| match change {
            EntryChange::Put {
                id,
                expected: Some(expected),
                revision,
                envelope,
            } => Ok(RotatedEntry {
                id: id.clone(),
                expected: expected.clone(),
                revision: *revision,
                envelope: envelope.clone(),
            }),
            _ => Err("rotation contains ordinary entry changes".into()),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(EpochTransaction {
        version: 1,
        operation: record.receipt.operation.clone(),
        expected: Cursor::from_head(&previous.head)?,
        transition: transition.clone(),
        object: record.object.clone(),
        entries,
        wrappers: wrappers.to_vec(),
    })
}
pub(super) fn validate_record(
    record: &Record,
    previous: Option<&HistoryObject>,
    old: Option<&TrustedCheckpoint>,
    entries: &Entries,
) -> Result<(Entries, Option<TrustedCheckpoint>)> {
    let expected = previous.map(|p| Cursor::from_head(&p.head)).transpose()?;
    let (digest, next) = match &record.epoch {
        None => {
            if let Some(previous) = previous {
                adjacent(previous, &record.object)?;
            }
            (
                submission_digest(
                    expected.as_ref(),
                    &record.receipt.writer,
                    &record.receipt.operation,
                    &record.object,
                    &record.changes,
                )?,
                old.cloned(),
            )
        }
        Some(EpochRecord::Anchor { state }) => {
            if previous.is_some() || old.is_some() {
                return Err("anchor replacement forbidden".into());
            }
            let next = validate_anchor(state, &record.object)?;
            (
                anchor_digest(
                    &record.receipt.writer,
                    &record.receipt.operation,
                    &record.object,
                    &record.changes,
                    state,
                )?,
                Some(next),
            )
        }
        Some(EpochRecord::Rotation {
            transition,
            wrappers,
        }) => {
            let previous = previous.ok_or("missing rotation parent")?;
            let old = old.ok_or("rotation requires committed authority")?;
            let tx = transaction(record, previous, transition, wrappers)?;
            let next = tx.verify_public(old, &previous.head)?;
            if tx.entries.len() != entries.values().filter(|e| e.is_some()).count()
                || tx
                    .entries
                    .iter()
                    .any(|e| entries.get(&e.id) != Some(&Some(e.expected.clone())))
            {
                return Err("rotation must replace every live entry exactly once".into());
            }
            (tx.submission_digest(&record.receipt.writer)?, Some(next))
        }
    };
    if record.receipt.request_digest != digest {
        return Err("committed request digest mismatch".into());
    }
    Ok((
        entry_transaction::apply(entries, &record.object, &record.changes)?,
        next,
    ))
}
impl Journal {
    pub fn check_retained_context(
        &self,
        context: &petika_core::entry_format::Context,
    ) -> Result<()> {
        if self.uncertain
            || !self
                .records
                .values()
                .any(|(_, r)| &r.object.head.context == context)
        {
            return Err("unknown or uncertain epoch context".into());
        }
        Ok(())
    }
    pub fn check_root_context(
        &self,
        context: &petika_core::entry_format::Context,
        root: &Cursor,
    ) -> Result<()> {
        if self.uncertain
            || self.records.get(&root.revision).is_none_or(|(_, r)| {
                r.receipt.accepted != *root || &r.object.head.context != context
            })
        {
            return Err("read root context mismatch".into());
        }
        Ok(())
    }
    pub fn next_epoch(&self, after: &Cursor) -> Result<Option<EpochTransaction>> {
        if self.uncertain
            || self
                .records
                .get(&after.revision)
                .is_none_or(|(_, r)| r.receipt.accepted != *after)
        {
            return Err("unknown epoch base".into());
        }
        let Some((_, record)) = after
            .revision
            .checked_add(1)
            .and_then(|r| self.records.get(&r))
        else {
            return Ok(None);
        };
        if matches!(record.epoch, Some(EpochRecord::Rotation { .. })) {
            return Ok(Some(self.epoch_transaction(&record.receipt.accepted)?));
        }
        Ok(None)
    }
    /// Offline/provisioning primitive only. Caller independently confirms the
    /// authority and verifies encrypted semantics before initializing a new store.
    /// Existing journals cannot acquire or replace an anchor through this method.
    pub fn initialize_anchored(
        &mut self,
        writer: &str,
        operation: &str,
        object: HistoryObject,
        changes: Vec<EntryChange>,
        checkpoint: &TrustedCheckpoint,
        wrappers: Vec<EpochWrapper>,
    ) -> Result<Receipt> {
        if !self.records.is_empty()
            || self.uncertain
            || !identifier(writer)
            || !identifier(operation)
        {
            return Err("journal already initialized or invalid anchor operation".into());
        }
        validate(&object)?;
        let state = EpochState {
            checkpoint: checkpoint.checkpoint().clone(),
            wrappers,
        };
        let receipt = Receipt {
            writer: writer.into(),
            operation: operation.into(),
            accepted: Cursor::from_head(&object.head)?,
            request_digest: anchor_digest(writer, operation, &object, &changes, &state)?,
        };
        let record = Record {
            version: 1,
            parent: None,
            object,
            receipt,
            changes,
            epoch: Some(EpochRecord::Anchor { state }),
        };
        let (entries, _) = validate_record(&record, None, None, &self.entries)?;
        self.publish(record, entries, |_| Ok(()))
    }
    /// Exact committed epoch state at a reader's immutable root, never staging.
    pub fn epoch_state(&self, root: &Cursor) -> Result<Option<EpochState>> {
        if self.uncertain
            || self
                .records
                .get(&root.revision)
                .is_none_or(|(_, r)| r.receipt.accepted != *root)
        {
            return Err("unknown or uncertain epoch root".into());
        }
        for (_, (_, record)) in self.records.range(..=root.revision).rev() {
            match &record.epoch {
                Some(EpochRecord::Anchor { state }) => return Ok(Some(state.clone())),
                Some(EpochRecord::Rotation {
                    transition,
                    wrappers,
                }) => {
                    return Ok(Some(EpochState {
                        checkpoint: transition.next.clone(),
                        wrappers: wrappers.clone(),
                    }));
                }
                None => (),
            }
        }
        Ok(None)
    }
    /// Returns a complete accepted transition for a known target cursor.
    pub fn epoch_transition(&self, root: &Cursor) -> Result<Option<Transition>> {
        if self.uncertain {
            return Err("uncertain journal root".into());
        }
        let (_, record) = self
            .records
            .get(&root.revision)
            .ok_or("unknown epoch root")?;
        if record.receipt.accepted != *root {
            return Err("epoch root mismatch".into());
        }
        Ok(match &record.epoch {
            Some(EpochRecord::Rotation { transition, .. }) => Some(transition.clone()),
            _ => None,
        })
    }
    /// Complete ciphertext bundle for the accepted transition at this cursor.
    pub fn epoch_transaction(&self, root: &Cursor) -> Result<EpochTransaction> {
        if self.uncertain {
            return Err("uncertain journal root".into());
        }
        let (_, record) = self
            .records
            .get(&root.revision)
            .ok_or("unknown epoch root")?;
        if record.receipt.accepted != *root {
            return Err("epoch root mismatch".into());
        }
        let Some(EpochRecord::Rotation {
            transition,
            wrappers,
        }) = &record.epoch
        else {
            return Err("not an epoch transaction".into());
        };
        let (_, previous) = self
            .records
            .get(&(root.revision - 1))
            .ok_or("missing epoch parent")?;
        transaction(record, &previous.object, transition, wrappers)
    }
    pub fn rotate(&mut self, writer: &str, tx: EpochTransaction) -> Result<Receipt> {
        self.rotate_observed(writer, tx, |_| Ok(()))
    }
    pub(super) fn rotate_observed(
        &mut self,
        writer: &str,
        tx: EpochTransaction,
        boundary: impl FnMut(u8) -> petika_core::Result<()>,
    ) -> Result<Receipt> {
        if self.uncertain || !identifier(writer) {
            return Err("uncertain root or invalid writer".into());
        }
        let request_digest = tx.submission_digest(writer)?;
        if let Some(receipt) = self.receipt(writer, &tx.operation) {
            tx.verify_receipt(writer, &receipt)?;
            return Ok(receipt);
        }
        if self.current().as_ref() != Some(&tx.expected) {
            return Err("rotation root conflict".into());
        }
        let state = self
            .epoch_state(&tx.expected)?
            .ok_or("journal has no authority anchor")?;
        let old = trusted(&state.checkpoint)?;
        let (address, previous) = &self
            .records
            .last_key_value()
            .ok_or("uninitialized journal")?
            .1;
        let receipt = Receipt {
            writer: writer.into(),
            operation: tx.operation.clone(),
            request_digest,
            accepted: Cursor::from_head(&tx.object.head)?,
        };
        let record = Record {
            version: 1,
            parent: Some(address.clone()),
            object: tx.object,
            receipt,
            changes: tx
                .entries
                .into_iter()
                .map(|e| EntryChange::Put {
                    id: e.id,
                    expected: Some(e.expected),
                    revision: e.revision,
                    envelope: e.envelope,
                })
                .collect(),
            epoch: Some(EpochRecord::Rotation {
                transition: tx.transition,
                wrappers: tx.wrappers,
            }),
        };
        let (entries, _) =
            validate_record(&record, Some(&previous.object), Some(&old), &self.entries)?;
        self.publish(record, entries, boundary)
    }
}
