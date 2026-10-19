#![cfg(feature = "experimental-entry-format")]
use petika_core::{
    entry_format::{checkpoint::*, checkpoint_store::CheckpointStore, index::*, *},
    identity::{CheckpointTarget, UnlockedIdentity},
};
use std::collections::BTreeMap;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn initial(root: &RootKey) -> (Index, Vec<u8>) {
    let bytes = root
        .seal(
            &Header {
                entry_format_version: 1,
                suite: SUITE.into(),
                context: root.context().clone(),
                kind: Kind::Entry,
                object_id: "c".repeat(64),
                revision: 1,
            },
            b"synthetic password",
        )
        .unwrap();
    (
        Index {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: 1,
            parent_digest: String::new(),
            membership_generation: 1,
            wrappers: vec![WrapperRef {
                wrapper_id: "d".repeat(64),
                digest: "e".repeat(64),
            }],
            root_folder: String::new(),
            folders: vec![],
            entries: vec![EntryRef {
                id: "c".repeat(64),
                folder: String::new(),
                name: "literal/name".into(),
                revision: 1,
                digest: hex(&digest(&bytes)),
            }],
            tombstones: vec![],
        },
        bytes,
    )
}
fn seal(root: &RootKey, index: &Index) -> petika_core::Result<VerifiedIndex> {
    let bytes = root.seal(
        &Header {
            entry_format_version: 1,
            suite: SUITE.into(),
            context: root.context().clone(),
            kind: Kind::Index,
            object_id: String::new(),
            revision: index.revision,
        },
        &serde_json::to_vec(index).unwrap(),
    )?;
    VerifiedIndex::open(
        root,
        Head {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: index.revision,
            parent_digest: index.parent_digest.clone(),
            membership_generation: index.membership_generation,
            wrapper_set_digest: wrapper_set_digest(&index.wrappers)?,
            index_digest: hex(&digest(&bytes)),
        },
        &bytes,
    )
}
fn pin(root: &RootKey, index: &VerifiedIndex) -> TrustedCheckpoint {
    let authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
    let cp = authority
        .sign_entry_checkpoint(
            root,
            CheckpointTarget {
                head_revision: index.head().revision,
                head_digest: index.head().digest().unwrap(),
                membership_generation: 1,
                delivery_profile: DeliveryProfile::Standard,
            },
            &index.index().wrappers,
        )
        .unwrap();
    let digest = cp.digest().unwrap();
    let fp = cp.authority.fingerprint.clone();
    TrustedCheckpoint::bootstrap(cp, &digest, &fp).unwrap()
}
#[test]
fn malformed_authenticated_indexes_and_missing_objects_are_rejected() {
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let (index, payload) = initial(&root);
    let verified = seal(&root, &index).unwrap();
    let mut objects = BTreeMap::from([("c".repeat(64), payload)]);
    verified.verify_objects(&root, &objects).unwrap();
    objects.get_mut(&"c".repeat(64)).unwrap().push(0);
    assert!(verified.verify_objects(&root, &objects).is_err());
    assert!(verified.verify_objects(&root, &BTreeMap::new()).is_err());
    let mut bad = index.clone();
    bad.entries.push(bad.entries[0].clone());
    assert!(seal(&root, &bad).is_err());
    let mut bad = index.clone();
    bad.entries[0].folder = "9".repeat(64);
    assert!(seal(&root, &bad).is_err());
    let mut bad = index.clone();
    bad.folders.push(Folder {
        id: "8".repeat(64),
        parent: "8".repeat(64),
        name: "cycle".into(),
    });
    assert!(seal(&root, &bad).is_err());
    let mut bad = index;
    bad.folders.push(Folder {
        id: "8".repeat(64),
        parent: String::new(),
        name: "literal/name".into(),
    });
    assert!(seal(&root, &bad).is_err());
}
#[test]
fn continuity_deletions_and_durable_local_floor() {
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let (mut index, _) = initial(&root);
    let first = seal(&root, &index).unwrap();
    let trusted = pin(&root, &first);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.json");
    let store = CheckpointStore::lock(&path).unwrap();
    assert!(store.trusted(root.context()).is_err());
    store.initialize(&trusted, &first).unwrap();
    assert!(store.initialize(&trusted, &first).is_err());
    assert!(CheckpointStore::lock(&path).is_err());
    index.revision = 2;
    index.parent_digest = first.head().digest().unwrap();
    index.entries[0].name = "renamed".into();
    let second = seal(&root, &index).unwrap();
    second.follows(&first).unwrap();
    let mut bad = index.clone();
    bad.entries[0].revision = 2;
    assert!(seal(&root, &bad).unwrap().follows(&first).is_err());
    store.observe(&first, &second).unwrap();
    let durable = std::fs::read(&path).unwrap();
    assert!(store.observe(&first, &second).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), durable);
    drop(store);
    // An abandoned pre-rename temporary write never replaces the committed pin.
    std::fs::write(dir.path().join(".interrupted-write"), b"partial").unwrap();
    let store = CheckpointStore::lock(&path).unwrap();
    assert_eq!(store.head(root.context()).unwrap(), *second.head());
    index.revision = 3;
    index.parent_digest = second.head().digest().unwrap();
    let deleted = index.entries.remove(0);
    index.tombstones.push(Tombstone {
        id: deleted.id,
        final_revision: 2,
        deletion_revision: 3,
        prior_digest: deleted.digest,
    });
    let third = seal(&root, &index).unwrap();
    store.observe(&second, &third).unwrap();
    index.revision = 4;
    index.parent_digest = third.head().digest().unwrap();
    index.tombstones.clear();
    assert!(seal(&root, &index).unwrap().follows(&third).is_err());
    drop(store);
    std::fs::write(&path, b"{").unwrap();
    let store = CheckpointStore::lock(&path).unwrap();
    assert!(store.trusted(root.context()).is_err());
    assert!(store.initialize(&trusted, &first).is_err());
}

#[test]
fn persisted_epoch_transition_uses_local_revision_floor() {
    let mut authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let (mut index, _) = initial(&root);
    let first = seal(&root, &index).unwrap();
    let sign = |root: &RootKey, index: &VerifiedIndex, authority: &UnlockedIdentity| {
        let cp = authority
            .sign_entry_checkpoint(
                root,
                CheckpointTarget {
                    head_revision: index.head().revision,
                    head_digest: index.head().digest().unwrap(),
                    membership_generation: 1,
                    delivery_profile: DeliveryProfile::Standard,
                },
                &index.index().wrappers,
            )
            .unwrap();
        let d = cp.digest().unwrap();
        let f = cp.authority.fingerprint.clone();
        TrustedCheckpoint::bootstrap(cp, &d, &f).unwrap()
    };
    let trusted = sign(&root, &first, &authority);
    let dir = tempfile::tempdir().unwrap();
    let store = CheckpointStore::lock(dir.path().join("pin")).unwrap();
    store.initialize(&trusted, &first).unwrap();
    index.revision = 2;
    index.parent_digest = first.head().digest().unwrap();
    let second = seal(&root, &index).unwrap();
    store.observe(&first, &second).unwrap();
    let new_root = RootKey::generate("a".repeat(64), "b".repeat(64), 2).unwrap();
    let (mut next_index, _) = initial(&new_root);
    next_index.revision = 2;
    next_index.parent_digest = first.head().digest().unwrap();
    let stale = seal(&new_root, &next_index).unwrap();
    let stale_cp = sign(&new_root, &stale, &authority);
    let proof = authority
        .authorize_entry_transition(&trusted, stale_cp.checkpoint().clone(), 1)
        .unwrap();
    assert!(store.advance(root.context(), &proof, &stale).is_err());
    assert_eq!(store.head(root.context()).unwrap(), *second.head());
    next_index.revision = 3;
    next_index.parent_digest = second.head().digest().unwrap();
    let next = seal(&new_root, &next_index).unwrap();
    let next_cp = sign(&new_root, &next, &authority);
    let proof = authority
        .authorize_entry_transition(&trusted, next_cp.checkpoint().clone(), 2)
        .unwrap();
    store.advance(root.context(), &proof, &next).unwrap();
    assert!(store.head(root.context()).is_err());
    assert_eq!(store.head(new_root.context()).unwrap(), *next.head());
    assert!(store.advance(new_root.context(), &proof, &next).is_err());
}
