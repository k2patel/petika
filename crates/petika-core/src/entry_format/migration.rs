//! Local migration preservation gate, not authorization or a cutover protocol.
use super::{checkpoint::TrustedCheckpoint, index::VerifiedIndex, rotation::RotationSnapshot, *};
use crate::{EncryptionMode, Entry, UnlockedStore};

/// Borrows an authenticated source and candidate. No plaintext/key export and no
/// persistence. Callers still need source-revision/membership CAS, wrapper restore
/// checks, independently confirmed authority and an atomic format switch.
pub struct VerifiedMigration<'a> {
    source: &'a UnlockedStore,
    target: &'a VerifiedIndex,
}
impl<'a> VerifiedMigration<'a> {
    pub fn source(&self) -> &UnlockedStore {
        self.source
    }
    pub fn target(&self) -> &VerifiedIndex {
        self.target
    }

    /// `deployment` and `collection` must come from the caller's authenticated
    /// source selection, especially for unbound legacy snapshots. This function
    /// cannot authenticate API metadata or prove the source is still current.
    pub fn verify(
        source: &'a UnlockedStore,
        deployment: &str,
        collection: &str,
        target: RotationSnapshot<'a>,
        trusted: &TrustedCheckpoint,
    ) -> Result<Self> {
        target.index.validate_root(target.root)?;
        target.index.matches_checkpoint(trusted)?;
        trusted.validate_root(target.root)?;
        let context = target.root.context();
        let epoch = if let Some(old) = source.context() {
            old.validate()?;
            if old.deployment_id != deployment || old.collection_id != collection {
                return Err(Error::Authentication);
            }
            old.key_epoch.checked_add(1).ok_or(Error::Format)?
        } else {
            1
        };
        let profile = match source.encryption() {
            EncryptionMode::Standard => checkpoint::DeliveryProfile::Standard,
            EncryptionMode::HybridPostQuantum => {
                checkpoint::DeliveryProfile::ExperimentalXwingDraft06
            }
        };
        let index = target.index.index();
        if context.deployment_id != deployment
            || context.collection_id != collection
            || context.key_epoch != epoch
            || target.root.material() == source.access_material()
            || trusted.checkpoint().delivery_profile != profile
            || index.revision != 1
            || !index.parent_digest.is_empty()
            || !index.folders.is_empty()
            || !index.tombstones.is_empty()
            || index.entries.len() != source.names().count()
            || target.objects.len() != index.entries.len()
        {
            return Err(Error::Authentication);
        }
        // Index validation guarantees unique (folder,name) pairs. Literal names
        // remain at the implicit root: no slash splitting or Unicode folding.
        for entry in &index.entries {
            if !entry.folder.is_empty() || entry.revision != 1 {
                return Err(Error::Authentication);
            }
            let original = source.get(&entry.name).map_err(|_| Error::Authentication)?;
            let bytes = target.index.open_entry(
                target.root,
                &entry.id,
                target.objects.get(&entry.id).ok_or(Error::Authentication)?,
            )?;
            let migrated: Entry = serde_json::from_slice(&bytes).map_err(|_| Error::Format)?;
            if original.username != migrated.username
                || original.password != migrated.password
                || original.url != migrated.url
                || original.notes != migrated.notes
                || original.otp != migrated.otp
            {
                return Err(Error::Authentication);
            }
        }
        Ok(Self {
            source,
            target: target.index,
        })
    }
}
