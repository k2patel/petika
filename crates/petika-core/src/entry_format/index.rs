//! Authenticated index semantics. A verified index is not a freshness proof.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub version: u32,
    pub context: Context,
    pub suite: String,
    pub revision: u64,
    /// Empty only for collection revision one.
    pub parent_digest: String,
    pub index_digest: String,
    pub wrapper_set_digest: String,
    pub membership_generation: u64,
}
impl Head {
    pub fn digest(&self) -> Result<String> {
        self.context.validate()?;
        if self.version != 1
            || self.suite != SUITE
            || !counter(self.revision)
            || !counter(self.membership_generation)
            || !id(&self.index_digest)
            || !id(&self.wrapper_set_digest)
            || if self.revision == 1 {
                !self.parent_digest.is_empty()
            } else {
                !id(&self.parent_digest)
            }
        {
            return Err(Error::Format);
        }
        let mut bytes = Vec::new();
        field(&mut bytes, b"petika:entry-head:v1");
        bytes.extend_from_slice(&self.version.to_be_bytes());
        self.context.append(&mut bytes);
        field(&mut bytes, &fixed::<32>(&self.context.epoch_salt)?);
        for value in [
            &self.suite,
            &self.parent_digest,
            &self.index_digest,
            &self.wrapper_set_digest,
        ] {
            field(&mut bytes, value.as_bytes());
        }
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        bytes.extend_from_slice(&self.membership_generation.to_be_bytes());
        Ok(hex(&digest(&bytes)))
    }
    fn header(&self, kind: Kind, object_id: String, revision: u64) -> Header {
        Header {
            entry_format_version: 1,
            suite: self.suite.clone(),
            context: self.context.clone(),
            kind,
            object_id,
            revision,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Folder {
    pub id: String,
    pub parent: String,
    pub name: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryRef {
    pub id: String,
    pub folder: String,
    pub name: String,
    pub revision: u64,
    pub digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    pub id: String,
    pub final_revision: u64,
    pub deletion_revision: u64,
    pub prior_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    pub version: u32,
    pub context: Context,
    pub suite: String,
    pub revision: u64,
    pub parent_digest: String,
    pub membership_generation: u64,
    pub wrappers: Vec<checkpoint::WrapperRef>,
    /// Empty string denotes the implicit root; every named folder has an opaque ID.
    pub root_folder: String,
    pub folders: Vec<Folder>,
    pub entries: Vec<EntryRef>,
    pub tombstones: Vec<Tombstone>,
}
fn name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.contains('\0')
}
impl Index {
    pub fn validate(&self, head: &Head) -> Result<()> {
        head.digest()?;
        if self.version != 1
            || self.context != head.context
            || self.suite != head.suite
            || self.revision != head.revision
            || self.parent_digest != head.parent_digest
            || self.membership_generation != head.membership_generation
            || !self.root_folder.is_empty()
            || checkpoint::wrapper_set_digest(&self.wrappers)? != head.wrapper_set_digest
            || self.folders.len() + self.entries.len() + self.tombstones.len() > 10_000
        {
            return Err(Error::Format);
        }
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let folders: BTreeMap<_, _> = self.folders.iter().map(|f| (f.id.as_str(), f)).collect();
        for f in &self.folders {
            if !id(&f.id)
                || !ids.insert(&f.id)
                || !name(&f.name)
                || !paths.insert((&f.parent, &f.name))
            {
                return Err(Error::Format);
            }
            let mut parent = f.parent.as_str();
            let mut visited = BTreeSet::from([f.id.as_str()]);
            while !parent.is_empty() {
                if !visited.insert(parent) || visited.len() > 128 {
                    return Err(Error::Format);
                }
                parent = folders.get(parent).ok_or(Error::Format)?.parent.as_str();
            }
        }
        for e in &self.entries {
            if !id(&e.id)
                || !ids.insert(&e.id)
                || !name(&e.name)
                || !counter(e.revision)
                || e.revision > self.revision
                || !id(&e.digest)
                || (!e.folder.is_empty() && !folders.contains_key(e.folder.as_str()))
                || !paths.insert((&e.folder, &e.name))
            {
                return Err(Error::Format);
            }
        }
        for t in &self.tombstones {
            if !id(&t.id)
                || !ids.insert(&t.id)
                || !counter(t.final_revision)
                || t.final_revision < 2
                || !counter(t.deletion_revision)
                || t.final_revision > t.deletion_revision
                || t.deletion_revision > self.revision
                || !id(&t.prior_digest)
            {
                return Err(Error::Format);
            }
        }
        Ok(())
    }
}
/// Constructed only after decrypting and validating the complete index. Names are
/// sensitive; intentionally no Debug implementation. Freshness requires a local pin.
pub struct VerifiedIndex {
    head: Head,
    index: Index,
    root_commitment: String,
}
impl VerifiedIndex {
    pub fn open(root: &RootKey, head: Head, envelope: &[u8]) -> Result<Self> {
        head.digest()?;
        let expected: [u8; 32] = hex_bytes(&head.index_digest)?;
        let bytes = root.open(
            &head.header(Kind::Index, String::new(), head.revision),
            &expected,
            envelope,
        )?;
        let index: Index = serde_json::from_slice(&bytes).map_err(|_| Error::Format)?;
        index.validate(&head)?;
        Ok(Self {
            head,
            index,
            root_commitment: root.commitment(),
        })
    }
    pub fn head(&self) -> &Head {
        &self.head
    }
    pub fn index(&self) -> &Index {
        &self.index
    }
    pub fn matches_checkpoint(&self, trusted: &checkpoint::TrustedCheckpoint) -> Result<()> {
        let cp = trusted.checkpoint();
        if self.root_commitment != cp.root_commitment
            || self.head.context != cp.context
            || self.head.suite != cp.data_suite
            || self.head.revision != cp.head_revision
            || self.head.digest()? != cp.head_digest
            || self.head.membership_generation != cp.membership_generation
            || self.head.wrapper_set_digest != cp.wrapper_set_digest
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub fn follows(&self, old: &Self) -> Result<()> {
        if self.root_commitment != old.root_commitment
            || self.head.context != old.head.context
            || self.head.revision != old.head.revision + 1
            || self.head.parent_digest != old.head.digest()?
            || self.head.membership_generation != old.head.membership_generation
            || self.head.wrapper_set_digest != old.head.wrapper_set_digest
        {
            return Err(Error::Authentication);
        }
        let entries: BTreeMap<_, _> = self.index.entries.iter().map(|e| (&e.id, e)).collect();
        let tombstones: BTreeMap<_, _> = self.index.tombstones.iter().map(|t| (&t.id, t)).collect();
        let previous: BTreeMap<_, _> = old.index.entries.iter().map(|e| (&e.id, e)).collect();
        for e in &old.index.entries {
            if let Some(next) = entries.get(&e.id) {
                let expected = if next.digest == e.digest {
                    e.revision
                } else {
                    e.revision + 1
                };
                if next.revision != expected {
                    return Err(Error::Authentication);
                }
            } else {
                let t = tombstones.get(&e.id).ok_or(Error::Authentication)?;
                if t.final_revision != e.revision + 1
                    || t.deletion_revision != self.head.revision
                    || t.prior_digest != e.digest
                {
                    return Err(Error::Authentication);
                }
            }
        }
        for t in &old.index.tombstones {
            if tombstones.get(&t.id).copied() != Some(t) {
                return Err(Error::Authentication);
            }
        }
        for e in &self.index.entries {
            if !previous.contains_key(&e.id) && e.revision != 1 {
                return Err(Error::Authentication);
            }
        }
        let old_tombstones: BTreeMap<_, _> =
            old.index.tombstones.iter().map(|t| (&t.id, t)).collect();
        for t in &self.index.tombstones {
            if old_tombstones.get(&t.id).copied() != Some(t) && !previous.contains_key(&t.id) {
                return Err(Error::Authentication);
            }
        }
        Ok(())
    }
    pub fn open_entry(
        &self,
        root: &RootKey,
        entry_id: &str,
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let e = self
            .index
            .entries
            .iter()
            .find(|e| e.id == entry_id)
            .ok_or(Error::Format)?;
        root.open(
            &self.head.header(Kind::Entry, e.id.clone(), e.revision),
            &hex_bytes(&e.digest)?,
            bytes,
        )
    }
    /// Restore/export gate: exact live coverage, including AEAD checks. Historical
    /// deleted payloads are not required. Callers handle decrypted payload schemas.
    pub fn verify_objects(
        &self,
        root: &RootKey,
        objects: &BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        if objects.len() != self.index.entries.len() {
            return Err(Error::Format);
        }
        for e in &self.index.entries {
            self.open_entry(root, &e.id, objects.get(&e.id).ok_or(Error::Format)?)?;
        }
        Ok(())
    }
}
fn hex_bytes(value: &str) -> Result<[u8; 32]> {
    if !id(value) {
        return Err(Error::Format);
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| Error::Format)?;
    }
    Ok(bytes)
}
