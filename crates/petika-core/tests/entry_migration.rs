#![cfg(feature = "experimental-entry-format")]
use petika_core::{
    CollectionContext, EncryptionMode, Entry, UnlockedStore,
    entry_format::{
        checkpoint::*, index::*, migration::VerifiedMigration, rotation::RotationSnapshot, *,
    },
    identity::{CheckpointTarget, UnlockedIdentity},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const PASSWORD: &str = "synthetic migration recovery";
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn entry() -> Entry {
    Entry {
        username: "alice".into(),
        password: "synthetic secret".into(),
        url: "https://example.org".into(),
        notes: "notes\nwith unicode 雪".into(),
        otp: Some("JBSWY3DPEHPK3PXP".into()),
    }
}
fn records(source: &UnlockedStore) -> BTreeMap<String, Value> {
    source
        .names()
        .map(|name| {
            (
                name.into(),
                serde_json::to_value(source.get(name).unwrap()).unwrap(),
            )
        })
        .collect()
}
fn source(mode: EncryptionMode, bound: bool, empty: bool) -> UnlockedStore {
    let mut source = UnlockedStore::create_with_mode(PASSWORD, mode).unwrap();
    if !empty {
        for name in ["a/b", "a", "A", "é", "e\u{301}", "雪", "folder/../literal"] {
            let mut value = entry();
            if name == "A" {
                value.otp = None;
            }
            source.put(name.into(), value, false).unwrap();
        }
    }
    if bound {
        source
            .bind_collection(
                CollectionContext {
                    deployment_id: "a".repeat(64),
                    collection_id: "b".repeat(64),
                    key_epoch: 1,
                },
                PASSWORD,
            )
            .unwrap();
    }
    // Exercise the real encrypted legacy format rather than only an in-memory map.
    UnlockedStore::open(&source.seal().unwrap(), PASSWORD).unwrap()
}
struct Candidate {
    root: RootKey,
    index: VerifiedIndex,
    objects: BTreeMap<String, Vec<u8>>,
    trusted: TrustedCheckpoint,
}
impl Candidate {
    fn new(entries: &BTreeMap<String, Value>, epoch: u64, profile: DeliveryProfile) -> Self {
        Self::changed(entries, epoch, profile, |_| {})
    }
    fn changed(
        entries: &BTreeMap<String, Value>,
        epoch: u64,
        profile: DeliveryProfile,
        alter: impl FnOnce(&mut Index),
    ) -> Self {
        let root = RootKey::generate("a".repeat(64), "b".repeat(64), epoch).unwrap();
        let authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
        let recovery = root.wrap_recovery(PASSWORD).unwrap();
        let value: Value = serde_json::from_slice(&recovery).unwrap();
        let wrappers = vec![WrapperRef {
            wrapper_id: value["wrapper_id"].as_str().unwrap().into(),
            digest: hex(&digest(&recovery)),
        }];
        let mut index = Index {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: 1,
            parent_digest: String::new(),
            membership_generation: 1,
            wrappers: wrappers.clone(),
            root_folder: String::new(),
            folders: vec![],
            entries: vec![],
            tombstones: vec![],
        };
        let mut objects = BTreeMap::new();
        for (number, (name, entry)) in entries.iter().enumerate() {
            let id = format!("{:064x}", number + 1);
            let bytes = root
                .seal(
                    &Header {
                        entry_format_version: 1,
                        suite: SUITE.into(),
                        context: root.context().clone(),
                        kind: Kind::Entry,
                        object_id: id.clone(),
                        revision: 1,
                    },
                    &serde_json::to_vec(entry).unwrap(),
                )
                .unwrap();
            index.entries.push(EntryRef {
                id: id.clone(),
                name: name.clone(),
                folder: String::new(),
                revision: 1,
                digest: hex(&digest(&bytes)),
            });
            objects.insert(id, bytes);
        }
        alter(&mut index);
        let bytes = root
            .seal(
                &Header {
                    entry_format_version: 1,
                    suite: SUITE.into(),
                    context: root.context().clone(),
                    kind: Kind::Index,
                    object_id: String::new(),
                    revision: index.revision,
                },
                &serde_json::to_vec(&index).unwrap(),
            )
            .unwrap();
        let head = Head {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: index.revision,
            parent_digest: index.parent_digest.clone(),
            index_digest: hex(&digest(&bytes)),
            wrapper_set_digest: wrapper_set_digest(&wrappers).unwrap(),
            membership_generation: 1,
        };
        let checkpoint = authority
            .sign_entry_checkpoint(
                &root,
                CheckpointTarget {
                    head_revision: index.revision,
                    head_digest: head.digest().unwrap(),
                    membership_generation: 1,
                    delivery_profile: profile,
                },
                &wrappers,
            )
            .unwrap();
        let trusted = TrustedCheckpoint::bootstrap(
            checkpoint.clone(),
            &checkpoint.digest().unwrap(),
            &checkpoint.authority.fingerprint,
        )
        .unwrap();
        let index = VerifiedIndex::open(&root, head, &bytes).unwrap();
        // Recovery opens independently and verifies the same authenticated view.
        let recovered = trusted
            .open_recovery(&recovery, PASSWORD, &wrappers)
            .unwrap();
        assert_eq!(recovered.commitment(), root.commitment());
        Self {
            root,
            index,
            objects,
            trusted,
        }
    }
    fn verify(&self, source: &UnlockedStore, deployment: &str, collection: &str) -> bool {
        VerifiedMigration::verify(
            source,
            deployment,
            collection,
            RotationSnapshot {
                root: &self.root,
                index: &self.index,
                objects: &self.objects,
            },
            &self.trusted,
        )
        .is_ok()
    }
}
fn profile(mode: EncryptionMode) -> DeliveryProfile {
    match mode {
        EncryptionMode::Standard => DeliveryProfile::Standard,
        EncryptionMode::HybridPostQuantum => DeliveryProfile::ExperimentalXwingDraft06,
    }
}

#[test]
fn legacy_modes_preserve_empty_and_literal_named_records() {
    for mode in [EncryptionMode::Standard, EncryptionMode::HybridPostQuantum] {
        for bound in [false, true] {
            for empty in [false, true] {
                let source = source(mode, bound, empty);
                let candidate =
                    Candidate::new(&records(&source), if bound { 2 } else { 1 }, profile(mode));
                assert!(candidate.verify(&source, &"a".repeat(64), &"b".repeat(64)));
                assert!(!candidate.verify(&source, &"c".repeat(64), &"b".repeat(64)));
                assert!(!candidate.verify(&source, &"a".repeat(64), &"c".repeat(64)));
            }
        }
    }
}

#[test]
fn validly_encrypted_content_changes_and_missing_objects_fail_migration() {
    let source = source(EncryptionMode::Standard, true, false);
    let original = records(&source);
    for field in ["username", "password", "url", "notes", "otp"] {
        let mut changed = original.clone();
        changed.get_mut("a").unwrap()[field] = json!("changed");
        let candidate = Candidate::new(&changed, 2, DeliveryProfile::Standard);
        assert!(
            !candidate.verify(&source, &"a".repeat(64), &"b".repeat(64)),
            "{field}"
        );
    }
    for change in ["remove", "rename", "extra-field", "remove-otp"] {
        let mut changed = original.clone();
        match change {
            "remove" => {
                changed.remove("a");
            }
            "rename" => {
                let value = changed.remove("a/b").unwrap();
                changed.insert("b".into(), value);
            }
            "extra-field" => {
                changed.get_mut("a").unwrap()["unrecognized"] = json!(true);
            }
            _ => {
                changed
                    .get_mut("a")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove("otp");
            }
        }
        assert!(
            !Candidate::new(&changed, 2, DeliveryProfile::Standard).verify(
                &source,
                &"a".repeat(64),
                &"b".repeat(64)
            ),
            "{change}"
        );
    }
    let mut candidate = Candidate::new(&original, 2, DeliveryProfile::Standard);
    let id = candidate.objects.keys().next().unwrap().clone();
    let bytes = candidate.objects.remove(&id).unwrap();
    assert!(!candidate.verify(&source, &"a".repeat(64), &"b".repeat(64)));
    candidate.objects.insert("f".repeat(64), bytes);
    assert!(!candidate.verify(&source, &"a".repeat(64), &"b".repeat(64)));
    assert_eq!(records(&source), original);
}

#[test]
fn migration_rejects_epoch_reuse_skips_and_profile_changes() {
    for mode in [EncryptionMode::Standard, EncryptionMode::HybridPostQuantum] {
        let source = source(mode, true, true);
        for epoch in [1, 3] {
            assert!(
                !Candidate::new(&records(&source), epoch, profile(mode)).verify(
                    &source,
                    &"a".repeat(64),
                    &"b".repeat(64)
                )
            );
        }
        let other = if mode == EncryptionMode::Standard {
            DeliveryProfile::ExperimentalXwingDraft06
        } else {
            DeliveryProfile::Standard
        };
        assert!(!Candidate::new(&records(&source), 2, other).verify(
            &source,
            &"a".repeat(64),
            &"b".repeat(64)
        ));
    }
}

#[test]
fn migration_cannot_invent_folders_tombstones_or_history() {
    let source = source(EncryptionMode::Standard, false, false);
    for change in ["folder", "tombstone", "history", "entry-revision"] {
        let candidate = Candidate::changed(
            &records(&source),
            1,
            DeliveryProfile::Standard,
            |index| match change {
                "folder" => {
                    index.folders.push(Folder {
                        id: "d".repeat(64),
                        parent: String::new(),
                        name: "invented".into(),
                    });
                    index.entries[0].folder = "d".repeat(64);
                }
                "tombstone" => {
                    index.revision = 2;
                    index.parent_digest = "e".repeat(64);
                    index.tombstones.push(Tombstone {
                        id: "d".repeat(64),
                        final_revision: 2,
                        deletion_revision: 2,
                        prior_digest: "e".repeat(64),
                    });
                }
                "history" => {
                    index.revision = 2;
                    index.parent_digest = "e".repeat(64);
                }
                _ => {
                    index.revision = 2;
                    index.parent_digest = "e".repeat(64);
                    index.entries[0].revision = 2;
                }
            },
        );
        assert!(
            !candidate.verify(&source, &"a".repeat(64), &"b".repeat(64)),
            "{change}"
        );
    }
}
