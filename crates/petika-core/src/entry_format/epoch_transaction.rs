//! Complete, bounded epoch candidates. No server authorization or persistence is
//! implied by these types. Same-epoch wrapper replacement is deliberately absent.
use super::{
    checkpoint::{Transition, TrustedCheckpoint, WrapperRef, wrapper_set_digest},
    index::VerifiedIndex,
    rotation::{RotationSnapshot, VerifiedRotation},
    transaction::{EntryVersion, MAX_CHANGES, MAX_TRANSACTION_BYTES, Receipt},
    transport::{Cursor, HistoryObject},
    *,
};
use crate::identity::EntryKeyPackage;
use std::collections::{BTreeMap, BTreeSet};

/// Exact serialized bytes are retained: wrapper references hash these bytes,
/// including whitespace, rather than a parsed/re-encoded representation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "envelope",
    rename_all = "lowercase",
    deny_unknown_fields
)]
pub enum EpochWrapper {
    Recovery(String),
    Recipient(String),
}
impl EpochWrapper {
    pub fn reference(&self, trusted: &TrustedCheckpoint) -> Result<WrapperRef> {
        let cp = trusted.checkpoint();
        let (wrapper_id, bytes) = match self {
            Self::Recovery(bytes) => {
                if bytes.len() > MAX_WRAPPER_BYTES {
                    return Err(Error::Format);
                }
                let wrapper: RecoveryWrapper =
                    serde_json::from_slice(bytes.as_bytes()).map_err(|_| Error::Format)?;
                wrapper.validate()?;
                if wrapper.context != cp.context {
                    return Err(Error::Authentication);
                }
                if decode(&wrapper.ciphertext, ROOT_TAG.len() + 32 + 16)?.len()
                    != ROOT_TAG.len() + 32 + 16
                {
                    return Err(Error::Format);
                }
                (wrapper.wrapper_id, bytes)
            }
            Self::Recipient(bytes) => {
                let package = EntryKeyPackage::parse(bytes.as_bytes())?;
                package.verify_checkpoint(cp)?;
                (package.wrapper_id, bytes)
            }
        };
        Ok(WrapperRef {
            wrapper_id,
            digest: hex(&digest(bytes.as_bytes())),
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotatedEntry {
    pub id: String,
    pub expected: EntryVersion,
    pub revision: u64,
    pub envelope: String,
}

/// A single epoch candidate includes every live entry and every active wrapper.
/// It cannot contain ordinary edits, deletions, renames or profile downgrades.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochTransaction {
    pub version: u32,
    pub operation: String,
    pub expected: Cursor,
    pub transition: Transition,
    pub object: HistoryObject,
    pub entries: Vec<RotatedEntry>,
    pub wrappers: Vec<EpochWrapper>,
}
impl EpochTransaction {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(Error::Format);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        value.validate_limits()?;
        Ok(value)
    }
    fn validate_limits(&self) -> Result<()> {
        if self.version != 1
            || !id(&self.operation)
            || self.entries.len() > MAX_CHANGES
            || self.wrappers.is_empty()
            || self.wrappers.len() > checkpoint::MAX_WRAPPERS
            || serde_json::to_vec(self).map_err(|_| Error::Format)?.len() > MAX_TRANSACTION_BYTES
        {
            return Err(Error::Format);
        }
        Ok(())
    }
    /// Separate digest domain prevents an epoch acknowledgement from being
    /// confused with an ordinary entry transaction's receipt.
    pub fn submission_digest(&self, writer: &str) -> Result<String> {
        self.validate_limits()?;
        if !id(writer) {
            return Err(Error::Format);
        }
        let bytes = serde_json::to_vec(&("petika:entry-epoch-transaction:v1", writer, self))
            .map_err(|_| Error::Format)?;
        Ok(hex(&digest(&bytes)))
    }
    pub fn verify_receipt(&self, writer: &str, receipt: &Receipt) -> Result<()> {
        if receipt.writer != writer
            || receipt.operation != self.operation
            || receipt.accepted != Cursor::from_head(&self.object.head)?
            || receipt.request_digest != self.submission_digest(writer)?
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    /// Caller supplies its already authenticated current index and old objects.
    /// Public wrapper checks establish format/binding/signatures, not successful
    /// recovery or recipient decryption; those require the respective credentials.
    pub fn verify(
        &self,
        trusted: &TrustedCheckpoint,
        old: RotationSnapshot<'_>,
        new_root: &RootKey,
    ) -> Result<VerifiedIndex> {
        self.validate_limits()?;
        trusted.validate_root(old.root)?;
        old.index.validate_root(old.root)?;
        let cp = trusted.checkpoint();
        let head = old.index.head();
        if Cursor::from_head(head)? != self.expected
            || head.revision < cp.head_revision
            || head.membership_generation != cp.membership_generation
            || head.wrapper_set_digest != cp.wrapper_set_digest
            || (head.revision == cp.head_revision && head.digest()? != cp.head_digest)
        {
            return Err(Error::Authentication);
        }
        let next_trust = trusted.advance(&self.transition, head.revision)?;
        next_trust.validate_root(new_root)?;
        let next = VerifiedIndex::open(
            new_root,
            self.object.head.clone(),
            self.object.envelope.as_bytes(),
        )?;
        next.matches_checkpoint(&next_trust)?;
        let refs = self
            .wrappers
            .iter()
            .map(|w| w.reference(&next_trust))
            .collect::<Result<Vec<_>>>()?;
        if wrapper_set_digest(&refs)? != next.head().wrapper_set_digest {
            return Err(Error::Authentication);
        }
        let mut seen = BTreeSet::new();
        let mut objects = BTreeMap::new();
        for entry in &self.entries {
            if !id(&entry.id) || !seen.insert(&entry.id) {
                return Err(Error::Format);
            }
            let previous = old
                .index
                .index()
                .entries
                .iter()
                .find(|e| e.id == entry.id)
                .ok_or(Error::Authentication)?;
            let replacement = next
                .index()
                .entries
                .iter()
                .find(|e| e.id == entry.id)
                .ok_or(Error::Authentication)?;
            if entry.expected.revision != previous.revision
                || entry.expected.digest != previous.digest
                || entry.revision != replacement.revision
                || hex(&digest(entry.envelope.as_bytes())) != replacement.digest
            {
                return Err(Error::Authentication);
            }
            objects.insert(entry.id.clone(), entry.envelope.as_bytes().to_vec());
        }
        VerifiedRotation::verify(
            old,
            RotationSnapshot {
                index: &next,
                root: new_root,
                objects: &objects,
            },
        )?;
        Ok(next)
    }
}
