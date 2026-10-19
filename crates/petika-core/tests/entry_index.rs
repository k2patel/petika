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
    let (head, bytes) = wire(root, index)?;
    VerifiedIndex::open(root, head, &bytes)
}
fn wire(root: &RootKey, index: &Index) -> petika_core::Result<(Head, Vec<u8>)> {
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
    Ok((
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
        bytes,
    ))
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
    let (mut index, payload) = initial(&root);
    let old_objects = BTreeMap::from([("c".repeat(64), payload)]);
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
    use petika_core::entry_format::rotation::*;
    let (mut next_index, _) = initial(&new_root);
    let encrypted = new_root
        .seal(
            &Header {
                entry_format_version: 1,
                suite: SUITE.into(),
                context: new_root.context().clone(),
                kind: Kind::Entry,
                object_id: "c".repeat(64),
                revision: 2,
            },
            b"synthetic password",
        )
        .unwrap();
    next_index.entries[0].revision = 2;
    next_index.entries[0].digest = hex(&digest(&encrypted));
    let new_objects = BTreeMap::from([("c".repeat(64), encrypted)]);
    next_index.revision = 2;
    next_index.parent_digest = first.head().digest().unwrap();
    let stale = seal(&new_root, &next_index).unwrap();
    let stale_cp = sign(&new_root, &stale, &authority);
    let proof = authority
        .authorize_entry_transition(&trusted, stale_cp.checkpoint().clone(), 1)
        .unwrap();
    let stale_rotation = VerifiedRotation::verify(
        RotationSnapshot {
            index: &first,
            root: &root,
            objects: &old_objects,
        },
        RotationSnapshot {
            index: &stale,
            root: &new_root,
            objects: &new_objects,
        },
    )
    .unwrap();
    assert!(store.advance(&proof, &stale_rotation).is_err());
    assert_eq!(store.head(root.context()).unwrap(), *second.head());
    next_index.revision = 3;
    next_index.parent_digest = second.head().digest().unwrap();
    let next = seal(&new_root, &next_index).unwrap();
    let next_cp = sign(&new_root, &next, &authority);
    let proof = authority
        .authorize_entry_transition(&trusted, next_cp.checkpoint().clone(), 2)
        .unwrap();
    let rotation = VerifiedRotation::verify(
        RotationSnapshot {
            index: &second,
            root: &root,
            objects: &old_objects,
        },
        RotationSnapshot {
            index: &next,
            root: &new_root,
            objects: &new_objects,
        },
    )
    .unwrap();
    store.advance(&proof, &rotation).unwrap();
    assert!(store.head(root.context()).is_err());
    assert_eq!(store.head(new_root.context()).unwrap(), *next.head());
    assert!(store.advance(&proof, &rotation).is_err());
}

#[test]
fn independent_head_vectors() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/entry-head-v1.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let head: Head = serde_json::from_value(case["head"].clone()).unwrap();
        assert_eq!(head.digest().unwrap(), case["digest"].as_str().unwrap());
        let mut altered = head.clone();
        altered.membership_generation += 1;
        assert_ne!(altered.digest().unwrap(), head.digest().unwrap());
    }
}

#[test]
fn bounded_history_is_all_or_nothing_and_resumes_after_restart() {
    use petika_core::entry_format::history::*;
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let (mut index, _) = initial(&root);
    let first = seal(&root, &index).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pin");
    let store = CheckpointStore::lock(&path).unwrap();
    store.initialize(&pin(&root, &first), &first).unwrap();
    index.revision = 2;
    index.parent_digest = first.head().digest().unwrap();
    let (second, second_bytes) = wire(&root, &index).unwrap();
    index.revision = 3;
    index.parent_digest = second.digest().unwrap();
    let (third, third_bytes) = wire(&root, &index).unwrap();
    let page = [
        HistoryItem {
            head: &second,
            envelope: &second_bytes,
        },
        HistoryItem {
            head: &third,
            envelope: &third_bytes,
        },
    ];
    let before = std::fs::read(&path).unwrap();
    let mut fork_index = index.clone();
    fork_index.parent_digest = first.head().digest().unwrap();
    let (fork, fork_bytes) = wire(&root, &fork_index).unwrap();
    assert!(
        store
            .catch_up(
                &root,
                &first,
                &[
                    HistoryItem {
                        head: &second,
                        envelope: &second_bytes
                    },
                    HistoryItem {
                        head: &fork,
                        envelope: &fork_bytes
                    },
                ]
            )
            .is_err()
    );
    let mut invalid_index = index.clone();
    invalid_index.entries[0].revision = 2; // unchanged ciphertext cannot increment
    let (invalid, invalid_bytes) = wire(&root, &invalid_index).unwrap();
    assert!(
        store
            .catch_up(
                &root,
                &first,
                &[
                    HistoryItem {
                        head: &second,
                        envelope: &second_bytes
                    },
                    HistoryItem {
                        head: &invalid,
                        envelope: &invalid_bytes
                    },
                ]
            )
            .is_err()
    );
    assert!(store.catch_up(&root, &first, &[]).is_err());
    assert!(store.catch_up(&root, &first, &page[1..]).is_err());
    let oversized: Vec<_> = (0..=MAX_HISTORY_HEADS)
        .map(|_| HistoryItem {
            head: &second,
            envelope: &second_bytes,
        })
        .collect();
    assert!(store.catch_up(&root, &first, &oversized).is_err());
    let large = vec![0; MAX_HISTORY_BYTES];
    assert!(
        store
            .catch_up(
                &root,
                &first,
                &[HistoryItem {
                    head: &second,
                    envelope: &large
                }]
            )
            .is_err()
    );
    let mut bad = third_bytes.clone();
    bad.push(0);
    assert!(
        store
            .catch_up(
                &root,
                &first,
                &[
                    HistoryItem {
                        head: &second,
                        envelope: &second_bytes
                    },
                    HistoryItem {
                        head: &third,
                        envelope: &bad
                    }
                ]
            )
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let accepted = store.catch_up(&root, &first, &page).unwrap();
    assert_eq!(accepted.head(), &third);
    assert!(store.catch_up(&root, &first, &page).is_err());
    drop(store);
    let store = CheckpointStore::lock(&path).unwrap();
    index.revision = 4;
    index.parent_digest = third.digest().unwrap();
    let (fourth, bytes) = wire(&root, &index).unwrap();
    store
        .catch_up(
            &root,
            &accepted,
            &[HistoryItem {
                head: &fourth,
                envelope: &bytes,
            }],
        )
        .unwrap();
    assert_eq!(store.head(root.context()).unwrap(), fourth);
}

#[test]
fn rotation_rejects_content_loss_and_metadata_changes() {
    use petika_core::entry_format::rotation::*;
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let new_root = RootKey::generate("a".repeat(64), "b".repeat(64), 2).unwrap();
    let (mut index, payload) = initial(&root);
    index.revision = 3;
    index.parent_digest = "9".repeat(64);
    index.folders.push(Folder {
        id: "8".repeat(64),
        parent: String::new(),
        name: "private".into(),
    });
    index.tombstones.push(Tombstone {
        id: "7".repeat(64),
        final_revision: 2,
        deletion_revision: 2,
        prior_digest: "6".repeat(64),
    });
    let old = seal(&root, &index).unwrap();
    let old_objects = BTreeMap::from([("c".repeat(64), payload)]);
    let mut rotated = index.clone();
    rotated.context = new_root.context().clone();
    rotated.revision = 4;
    rotated.parent_digest = old.head().digest().unwrap();
    let encrypt = |plaintext: &[u8]| {
        new_root
            .seal(
                &Header {
                    entry_format_version: 1,
                    suite: SUITE.into(),
                    context: new_root.context().clone(),
                    kind: Kind::Entry,
                    object_id: "c".repeat(64),
                    revision: 2,
                },
                plaintext,
            )
            .unwrap()
    };
    let ciphertext = encrypt(b"synthetic password");
    rotated.entries[0].revision = 2;
    rotated.entries[0].digest = hex(&digest(&ciphertext));
    let objects = BTreeMap::from([("c".repeat(64), ciphertext)]);
    let check = |candidate: &Index, blobs: &BTreeMap<String, Vec<u8>>| {
        let new = seal(&new_root, candidate).unwrap();
        VerifiedRotation::verify(
            RotationSnapshot {
                index: &old,
                root: &root,
                objects: &old_objects,
            },
            RotationSnapshot {
                index: &new,
                root: &new_root,
                objects: blobs,
            },
        )
        .is_ok()
    };
    assert!(check(&rotated, &objects));
    assert!(!check(&rotated, &BTreeMap::new()));
    let mut bad = rotated.clone();
    bad.entries.clear();
    assert!(!check(&bad, &BTreeMap::new()));
    let mut bad = rotated.clone();
    bad.entries[0].name = "changed".into();
    assert!(!check(&bad, &objects));
    let mut bad = rotated.clone();
    bad.entries[0].folder = "8".repeat(64);
    assert!(!check(&bad, &objects));
    let mut bad = rotated.clone();
    bad.entries[0].revision = 1;
    assert!(!check(&bad, &objects));
    let mut bad = rotated.clone();
    bad.folders.clear();
    assert!(!check(&bad, &objects));
    let mut bad = rotated.clone();
    bad.tombstones.clear();
    assert!(!check(&bad, &objects));
    let mut bad = rotated.clone();
    bad.tombstones[0].prior_digest = "5".repeat(64);
    assert!(!check(&bad, &objects));
    let mut bad = rotated.clone();
    bad.parent_digest = "4".repeat(64);
    assert!(!check(&bad, &objects));
    let mut bad = rotated.clone();
    bad.revision = 5;
    assert!(!check(&bad, &objects));
    let altered = encrypt(b"silently changed password");
    let mut bad = rotated;
    bad.entries[0].digest = hex(&digest(&altered));
    assert!(!check(&bad, &BTreeMap::from([("c".repeat(64), altered)])));
}
