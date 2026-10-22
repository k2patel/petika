//! Signed ciphertext-only migration staging; no server publication or trust reset.
use super::{
    checkpoint::{DeliveryProfile, TrustedCheckpoint, WrapperRef, wrapper_set_digest},
    epoch_transaction::{EpochState, EpochWrapper},
    index::{EntryRef, Head, Index, VerifiedIndex},
    migration::VerifiedMigration,
    rotation::RotationSnapshot,
    transaction::MAX_CHANGES,
    transport::HistoryObject,
    *,
};
use crate::{
    EncryptionMode, UnlockedStore,
    identity::{CheckpointTarget, EntryKeyPackage, PublicIdentity, UnlockedIdentity},
};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_MIGRATION_BYTES: usize = 16 * 1024 * 1024;

/// Expected API state. The caller must capture these counters through an
/// authenticated API read; a signature does not prove server freshness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBinding {
    pub deployment_id: String,
    pub collection_id: String,
    pub snapshot_revision: u64,
    pub membership_generation: u64,
    pub key_epoch: u64,
    pub encrypted_digest: String,
}
impl SourceBinding {
    pub fn capture(
        deployment: String,
        collection: String,
        revision: u64,
        generation: u64,
        encrypted: &[u8],
    ) -> Result<Self> {
        if !id(&deployment) || !id(&collection) || !counter(revision) || !counter(generation) {
            return Err(Error::Format);
        }
        let (_, context) = crate::envelope_metadata(encrypted)?;
        if let Some(context) = &context
            && (context.deployment_id != deployment || context.collection_id != collection)
        {
            return Err(Error::Authentication);
        }
        Ok(Self {
            deployment_id: deployment,
            collection_id: collection,
            snapshot_revision: revision,
            membership_generation: generation,
            key_epoch: context.map_or(0, |c| c.key_epoch),
            encrypted_digest: hex(&digest(encrypted)),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryPolicy {
    Replace,
    Omit,
}
/// A passphrase is borrowed only during staging, never included in a draft.
pub enum Recovery<'a> {
    Replace(&'a str),
    Omit,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationEntry {
    pub id: String,
    pub envelope: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationDraft {
    pub version: u32,
    pub operation: String,
    pub source: SourceBinding,
    pub source_encrypted: String,
    pub recipients: Vec<PublicIdentity>,
    pub recovery_policy: RecoveryPolicy,
    pub state: EpochState,
    pub object: HistoryObject,
    pub entries: Vec<MigrationEntry>,
    pub signature: String,
}
fn profile(mode: EncryptionMode) -> DeliveryProfile {
    match mode {
        EncryptionMode::Standard => DeliveryProfile::Standard,
        EncryptionMode::HybridPostQuantum => DeliveryProfile::ExperimentalXwingDraft06,
    }
}
fn header(root: &RootKey, kind: Kind, id: String) -> Header {
    Header {
        entry_format_version: 1,
        suite: SUITE.into(),
        context: root.context().clone(),
        kind,
        object_id: id,
        revision: 1,
    }
}
impl MigrationDraft {
    /// Exact signed submission identity shared by client and server receipts.
    pub fn submission_digest(&self, writer: &str) -> Result<String> {
        self.limits()?;
        if !id(writer) {
            return Err(Error::Format);
        }
        let bytes = serde_json::to_vec(&("petika:entry-migration-submission:v1", writer, self))
            .map_err(|_| Error::Format)?;
        Ok(hex(&digest(&bytes)))
    }
    pub fn verify_receipt(&self, writer: &str, receipt: &transaction::Receipt) -> Result<()> {
        if receipt.writer != writer
            || receipt.operation != self.operation
            || receipt.request_digest != self.submission_digest(writer)?
            || receipt.accepted != transport::Cursor::from_head(&self.object.head)?
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MIGRATION_BYTES {
            return Err(Error::Format);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        value.limits()?;
        Ok(value)
    }
    fn limits(&self) -> Result<()> {
        if self.version != 1
            || !id(&self.operation)
            || self.entries.len() > MAX_CHANGES
            || self.recipients.is_empty()
            || self.recipients.len() > checkpoint::MAX_WRAPPERS
            || self.state.wrappers.len() > checkpoint::MAX_WRAPPERS
            || serde_json::to_vec(self).map_err(|_| Error::Format)?.len() > MAX_MIGRATION_BYTES
        {
            return Err(Error::Format);
        }
        Ok(())
    }
    pub(crate) fn message(&self) -> Result<Vec<u8>> {
        self.limits()?;
        serde_json::to_vec(&(
            "petika:entry-migration-draft:v1",
            self.version,
            &self.operation,
            &self.source,
            &self.source_encrypted,
            &self.recipients,
            self.recovery_policy,
            &self.state,
            &self.object,
            &self.entries,
        ))
        .map_err(|_| Error::Format)
    }
    /// The pinned authority and expected source are external inputs, never
    /// adopted from the draft itself. Does not authenticate encrypted plaintext.
    pub fn verify_public(
        &self,
        expected: &SourceBinding,
        authority: &PublicIdentity,
    ) -> Result<TrustedCheckpoint> {
        self.limits()?;
        if &self.source != expected || &self.state.checkpoint.authority != authority {
            return Err(Error::Authentication);
        }
        let actual = SourceBinding::capture(
            self.source.deployment_id.clone(),
            self.source.collection_id.clone(),
            self.source.snapshot_revision,
            self.source.membership_generation,
            self.source_encrypted.as_bytes(),
        )?;
        if actual != self.source {
            return Err(Error::Authentication);
        }
        checkpoint::verify(authority, &self.message()?, &self.signature)?;
        let cp = &self.state.checkpoint;
        let (mode, _) = crate::envelope_metadata(self.source_encrypted.as_bytes())?;
        let head = &self.object.head;
        if cp.context.deployment_id != self.source.deployment_id
            || cp.context.collection_id != self.source.collection_id
            || cp.context.key_epoch != self.source.key_epoch.checked_add(1).ok_or(Error::Format)?
            || cp.delivery_profile != profile(mode)
            || cp.membership_generation != self.source.membership_generation
            || head.context != cp.context
            || head.suite != cp.data_suite
            || head.revision != 1
            || cp.head_revision != 1
            || !head.parent_digest.is_empty()
            || head.digest()? != cp.head_digest
            || head.membership_generation != cp.membership_generation
            || head.wrapper_set_digest != cp.wrapper_set_digest
            || hex(&digest(self.object.envelope.as_bytes())) != head.index_digest
        {
            return Err(Error::Authentication);
        }
        // Authority authentication above binds this initial checkpoint to the
        // exact source. This derives a candidate anchor, never persists a pin.
        let trusted =
            TrustedCheckpoint::bootstrap(cp.clone(), &cp.digest()?, &authority.fingerprint)?;
        self.state.references(&trusted)?;
        let mut recipients = BTreeMap::new();
        let mut last = None;
        for recipient in &self.recipients {
            recipient.validate()?;
            if recipient.deployment_id != self.source.deployment_id
                || last.is_some_and(|id: &String| id >= &recipient.user_id)
                || recipients.insert(&recipient.user_id, recipient).is_some()
            {
                return Err(Error::Format);
            }
            last = Some(&recipient.user_id);
        }
        if recipients.get(&authority.user_id) != Some(&authority) {
            return Err(Error::Authentication);
        }
        let mut delivered = BTreeSet::new();
        let mut recovery = 0;
        for wrapper in &self.state.wrappers {
            match wrapper {
                EpochWrapper::Recovery(_) => recovery += 1,
                EpochWrapper::Recipient(bytes) => {
                    let package = EntryKeyPackage::parse(bytes.as_bytes())?;
                    let recipient = recipients
                        .get(&package.recipient_user_id)
                        .ok_or(Error::Authentication)?;
                    if recipient.identity_version != package.recipient_identity_version
                        || recipient.fingerprint != package.recipient_fingerprint
                        || !delivered.insert(package.recipient_user_id)
                    {
                        return Err(Error::Authentication);
                    }
                }
            }
        }
        if delivered.len() != recipients.len()
            || recovery != usize::from(self.recovery_policy == RecoveryPolicy::Replace)
        {
            return Err(Error::Authentication);
        }
        let expected_header = |kind, object_id| Header {
            entry_format_version: 1,
            suite: SUITE.into(),
            context: cp.context.clone(),
            kind,
            object_id,
            revision: 1,
        };
        inspect_envelope(
            self.object.envelope.as_bytes(),
            &expected_header(Kind::Index, String::new()),
        )?;
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if !id(&entry.id) || !seen.insert(&entry.id) {
                return Err(Error::Format);
            }
            inspect_envelope(
                entry.envelope.as_bytes(),
                &expected_header(Kind::Entry, entry.id.clone()),
            )?;
        }
        Ok(trusted)
    }
    /// Reopen both encrypted representations and prove exact field/name
    /// preservation. No files, API state, identity state or pins are changed.
    pub fn verify(
        &self,
        expected: &SourceBinding,
        authority: &PublicIdentity,
        source_passphrase: &str,
        new_root: &RootKey,
    ) -> Result<VerifiedIndex> {
        let trusted = self.verify_public(expected, authority)?;
        let source = UnlockedStore::open(self.source_encrypted.as_bytes(), source_passphrase)?;
        let index = VerifiedIndex::open(
            new_root,
            self.object.head.clone(),
            self.object.envelope.as_bytes(),
        )?;
        let objects = self
            .entries
            .iter()
            .map(|e| (e.id.clone(), e.envelope.as_bytes().to_vec()))
            .collect();
        VerifiedMigration::verify(
            &source,
            &self.source.deployment_id,
            &self.source.collection_id,
            RotationSnapshot {
                index: &index,
                root: new_root,
                objects: &objects,
            },
            &trusted,
        )?;
        Ok(index)
    }
    /// Build entirely in memory. Persist with the caller's protected no-overwrite
    /// storage only after success; source remains untouched on every failure.
    /// The identity may record contact suspension on failure. Native callers must
    /// lock and reseal it on success AND rejection, as in CLI recipient unlock.
    pub fn stage(
        expected: SourceBinding,
        encrypted: &[u8],
        source_passphrase: &str,
        authority: &mut UnlockedIdentity,
        recipients: &[PublicIdentity],
        recovery: Recovery<'_>,
    ) -> Result<Self> {
        if encrypted.len() > MAX_MIGRATION_BYTES
            || recipients.is_empty()
            || recipients.len() > checkpoint::MAX_WRAPPERS
            || recipients.len() + usize::from(matches!(&recovery, Recovery::Replace(_)))
                > checkpoint::MAX_WRAPPERS
        {
            return Err(Error::Format);
        }
        let actual = SourceBinding::capture(
            expected.deployment_id.clone(),
            expected.collection_id.clone(),
            expected.snapshot_revision,
            expected.membership_generation,
            encrypted,
        )?;
        if expected != actual {
            return Err(Error::Authentication);
        }
        let source = UnlockedStore::open(encrypted, source_passphrase)?;
        if source.names().count() > MAX_CHANGES {
            return Err(Error::Format);
        }
        let root = RootKey::generate(
            expected.deployment_id.clone(),
            expected.collection_id.clone(),
            expected.key_epoch.checked_add(1).ok_or(Error::Format)?,
        )?;
        let mut roster = recipients.to_vec();
        roster.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        for recipient in &roster {
            recipient.validate()?;
            if recipient.deployment_id != expected.deployment_id {
                return Err(Error::Authentication);
            }
        }
        if roster
            .windows(2)
            .any(|pair| pair[0].user_id == pair[1].user_id)
        {
            return Err(Error::Format);
        }
        if !roster.contains(authority.public_identity()) {
            return Err(Error::Authentication);
        }
        let mut wrappers = vec![];
        let mut refs = vec![];
        for recipient in &roster {
            let package = authority.create_entry_key_package(
                &root,
                recipient,
                expected.membership_generation,
                profile(source.encryption()),
            )?;
            refs.push(package.reference()?);
            wrappers.push(EpochWrapper::Recipient(
                serde_json::to_string(&package).map_err(|_| Error::Format)?,
            ));
        }
        let policy = match recovery {
            Recovery::Omit => RecoveryPolicy::Omit,
            Recovery::Replace(passphrase) => {
                let bytes = root.wrap_recovery(passphrase)?;
                let recovered = RootKey::open_recovery(root.context(), passphrase, &bytes)?;
                if recovered.commitment() != root.commitment() {
                    return Err(Error::Authentication);
                }
                let wrapper: RecoveryWrapper =
                    serde_json::from_slice(&bytes).map_err(|_| Error::Format)?;
                refs.push(WrapperRef {
                    wrapper_id: wrapper.wrapper_id,
                    digest: hex(&digest(&bytes)),
                });
                wrappers.push(EpochWrapper::Recovery(
                    String::from_utf8(bytes).map_err(|_| Error::Format)?,
                ));
                RecoveryPolicy::Replace
            }
        };
        let mut index = Index {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: 1,
            parent_digest: String::new(),
            membership_generation: expected.membership_generation,
            wrappers: refs,
            root_folder: String::new(),
            folders: vec![],
            entries: vec![],
            tombstones: vec![],
        };
        let mut entries = vec![];
        for name in source.names() {
            let id = hex(&crypto::random::<32>()?);
            let bytes = root.seal(
                &header(&root, Kind::Entry, id.clone()),
                &Zeroizing::new(serde_json::to_vec(source.get(name)?).map_err(|_| Error::Format)?),
            )?;
            index.entries.push(EntryRef {
                id: id.clone(),
                folder: String::new(),
                name: name.into(),
                revision: 1,
                digest: hex(&digest(&bytes)),
            });
            entries.push(MigrationEntry {
                id,
                envelope: String::from_utf8(bytes).map_err(|_| Error::Format)?,
            });
        }
        let bytes = root.seal(
            &header(&root, Kind::Index, String::new()),
            &Zeroizing::new(serde_json::to_vec(&index).map_err(|_| Error::Format)?),
        )?;
        let object = HistoryObject {
            head: Head {
                version: 1,
                context: root.context().clone(),
                suite: SUITE.into(),
                revision: 1,
                parent_digest: String::new(),
                index_digest: hex(&digest(&bytes)),
                wrapper_set_digest: wrapper_set_digest(&index.wrappers)?,
                membership_generation: expected.membership_generation,
            },
            envelope: String::from_utf8(bytes).map_err(|_| Error::Format)?,
        };
        let checkpoint = authority.sign_entry_checkpoint(
            &root,
            CheckpointTarget {
                head_revision: 1,
                head_digest: object.head.digest()?,
                membership_generation: expected.membership_generation,
                delivery_profile: profile(source.encryption()),
            },
            &index.wrappers,
        )?;
        let mut draft = Self {
            version: 1,
            operation: hex(&crypto::random::<32>()?),
            source: expected,
            source_encrypted: String::from_utf8(encrypted.to_vec()).map_err(|_| Error::Format)?,
            recipients: roster,
            recovery_policy: policy,
            state: EpochState {
                checkpoint,
                wrappers,
            },
            object,
            entries,
            signature: String::new(),
        };
        authority.sign_entry_migration(&mut draft)?;
        let trusted = draft.verify_public(&draft.source, authority.public_identity())?;
        let package = draft
            .state
            .wrappers
            .iter()
            .find_map(|w| match w {
                EpochWrapper::Recipient(value) => EntryKeyPackage::parse(value.as_bytes())
                    .ok()
                    .filter(|p| p.recipient_user_id == authority.public_identity().user_id)
                    .map(|_| value),
                _ => None,
            })
            .ok_or(Error::Authentication)?;
        let public = authority.public_identity().clone();
        let restored = authority.open_entry_key_package(
            package.as_bytes(),
            &public,
            &trusted,
            &index.wrappers,
        )?;
        draft.verify(&draft.source, &public, source_passphrase, &restored)?;
        Ok(draft)
    }
}
