//! Content-preserving rotations. Authorization remains a separate signed proof.
use super::{index::VerifiedIndex, *};
use std::collections::BTreeMap;

pub struct RotationSnapshot<'a> {
    pub index: &'a VerifiedIndex,
    pub root: &'a RootKey,
    pub objects: &'a BTreeMap<String, Vec<u8>>,
}
/// Only produced after checking metadata and decrypting every live entry on both
/// sides. Holds no plaintext or keys; borrowed indexes cannot change underneath it.
pub struct VerifiedRotation<'a> {
    pub(crate) previous: &'a VerifiedIndex,
    pub(crate) next: &'a VerifiedIndex,
}
impl<'a> VerifiedRotation<'a> {
    pub fn previous(&self) -> &VerifiedIndex {
        self.previous
    }
    pub fn next(&self) -> &VerifiedIndex {
        self.next
    }

    pub fn verify(old: RotationSnapshot<'a>, new: RotationSnapshot<'a>) -> Result<Self> {
        old.index.validate_root(old.root)?;
        new.index.validate_root(new.root)?;
        if old.root.material() == new.root.material() {
            return Err(Error::Authentication);
        }
        let a = old.index.head();
        let b = new.index.head();
        if a.context.deployment_id != b.context.deployment_id
            || a.context.collection_id != b.context.collection_id
            || a.context.key_epoch.checked_add(1) != Some(b.context.key_epoch)
            || a.context.epoch_salt == b.context.epoch_salt
            || a.suite != b.suite
            || a.revision.checked_add(1) != Some(b.revision)
            || b.parent_digest != a.digest()?
            || b.membership_generation < a.membership_generation
            || old.root.context() != &a.context
            || new.root.context() != &b.context
        {
            return Err(Error::Authentication);
        }
        let before = old.index.index();
        let after = new.index.index();
        let folders = |i: &'a super::index::Index| {
            i.folders
                .iter()
                .map(|f| (&f.id, f))
                .collect::<BTreeMap<_, _>>()
        };
        let tombstones = |i: &'a super::index::Index| {
            i.tombstones
                .iter()
                .map(|t| (&t.id, t))
                .collect::<BTreeMap<_, _>>()
        };
        if before.root_folder != after.root_folder
            || folders(before) != folders(after)
            || tombstones(before) != tombstones(after)
            || before.entries.len() != after.entries.len()
            || old.objects.len() != before.entries.len()
            || new.objects.len() != after.entries.len()
        {
            return Err(Error::Authentication);
        }
        let next: BTreeMap<_, _> = after.entries.iter().map(|e| (&e.id, e)).collect();
        for entry in &before.entries {
            let replacement = next.get(&entry.id).ok_or(Error::Authentication)?;
            // Rotation reseals each live object exactly once; it cannot rename,
            // move, add, delete, edit, or reset a revision in the same transaction.
            if replacement.name != entry.name
                || replacement.folder != entry.folder
                || entry.revision.checked_add(1) != Some(replacement.revision)
                || entry.digest == replacement.digest
            {
                return Err(Error::Authentication);
            }
            let original = old.index.open_entry(
                old.root,
                &entry.id,
                old.objects.get(&entry.id).ok_or(Error::Format)?,
            )?;
            let rotated = new.index.open_entry(
                new.root,
                &entry.id,
                new.objects.get(&entry.id).ok_or(Error::Format)?,
            )?;
            if original.as_slice() != rotated.as_slice() {
                return Err(Error::Authentication);
            }
        }
        Ok(Self {
            previous: old.index,
            next: new.index,
        })
    }
}
