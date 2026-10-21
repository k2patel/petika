#![cfg(feature = "experimental-entry-format")]
use petika_core::{
    entry_format::{
        checkpoint::*, checkpoint_store::CheckpointStore, epoch_transaction::*, index::*,
        rotation::RotationSnapshot, transaction::*, transport::*, *,
    },
    identity::{CheckpointTarget, UnlockedIdentity},
};
use std::collections::BTreeMap;

const PASSWORD: &str = "synthetic recovery passphrase";
#[test]
fn epoch_lookup_requires_explicit_transaction_or_null() {
    assert!(
        serde_json::from_str::<EpochLookup>(r#"{"transaction":null}"#)
            .unwrap()
            .transaction
            .is_none()
    );
    for invalid in [
        r#"{}"#,
        r#"{"transaction":null,"transaction":null}"#,
        r#"{"transaction":null,"extra":1}"#,
    ] {
        assert!(serde_json::from_str::<EpochLookup>(invalid).is_err());
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn wire(root: &RootKey, index: &Index) -> HistoryObject {
    let envelope = String::from_utf8(
        root.seal(
            &Header {
                entry_format_version: 1,
                suite: SUITE.into(),
                context: root.context().clone(),
                kind: Kind::Index,
                object_id: String::new(),
                revision: index.revision,
            },
            &serde_json::to_vec(index).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    HistoryObject {
        head: Head {
            version: 1,
            context: index.context.clone(),
            suite: SUITE.into(),
            revision: index.revision,
            parent_digest: index.parent_digest.clone(),
            index_digest: hex(&digest(envelope.as_bytes())),
            wrapper_set_digest: wrapper_set_digest(&index.wrappers).unwrap(),
            membership_generation: index.membership_generation,
        },
        envelope,
    }
}
fn checkpoint(
    authority: &UnlockedIdentity,
    root: &RootKey,
    object: &HistoryObject,
    index: &Index,
) -> Checkpoint {
    authority
        .sign_entry_checkpoint(
            root,
            CheckpointTarget {
                head_revision: object.head.revision,
                head_digest: object.head.digest().unwrap(),
                membership_generation: index.membership_generation,
                delivery_profile: DeliveryProfile::Standard,
            },
            &index.wrappers,
        )
        .unwrap()
}
fn trust(cp: Checkpoint) -> TrustedCheckpoint {
    let digest = cp.digest().unwrap();
    let fingerprint = cp.authority.fingerprint.clone();
    TrustedCheckpoint::bootstrap(cp, &digest, &fingerprint).unwrap()
}
struct Fixture {
    authority: UnlockedIdentity,
    recipient: UnlockedIdentity,
    old_root: RootKey,
    new_root: RootKey,
    old: VerifiedIndex,
    old_objects: BTreeMap<String, Vec<u8>>,
    trusted: TrustedCheckpoint,
    index: Index,
    transaction: EpochTransaction,
}
impl Fixture {
    fn new(empty: bool) -> Self {
        let mut authority =
            UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
        let mut recipient =
            UnlockedIdentity::generate(&"a".repeat(64), &"e".repeat(64), 1).unwrap();
        let public = recipient.public_identity();
        authority
            .verify_contact(&public.user_id, public, &public.fingerprint, None)
            .unwrap();
        let public = authority.public_identity();
        recipient
            .verify_contact(&public.user_id, public, &public.fingerprint, None)
            .unwrap();
        let old_root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
        let new_root = RootKey::generate("a".repeat(64), "b".repeat(64), 2).unwrap();
        let old_package = authority
            .create_entry_key_package(
                &old_root,
                recipient.public_identity(),
                1,
                DeliveryProfile::Standard,
            )
            .unwrap();
        let mut index = Index {
            version: 1,
            context: old_root.context().clone(),
            suite: SUITE.into(),
            revision: 3,
            parent_digest: "9".repeat(64),
            membership_generation: 1,
            wrappers: vec![old_package.reference().unwrap()],
            root_folder: String::new(),
            folders: vec![Folder {
                id: "8".repeat(64),
                parent: String::new(),
                name: "Private".into(),
            }],
            entries: vec![],
            tombstones: vec![Tombstone {
                id: "7".repeat(64),
                final_revision: 2,
                deletion_revision: 2,
                prior_digest: "6".repeat(64),
            }],
        };
        let mut old_objects = BTreeMap::new();
        let mut entries = vec![];
        for n in 0..if empty { 0 } else { 2 } {
            let id = format!("{n:064x}");
            let payload = format!("synthetic password and TOTP {n}");
            let header = Header {
                entry_format_version: 1,
                suite: SUITE.into(),
                context: old_root.context().clone(),
                kind: Kind::Entry,
                object_id: id.clone(),
                revision: 1,
            };
            let old_bytes = old_root.seal(&header, payload.as_bytes()).unwrap();
            let digest = hex(&digest(&old_bytes));
            index.entries.push(EntryRef {
                id: id.clone(),
                name: format!("Entry {n}"),
                folder: "8".repeat(64),
                revision: 1,
                digest: digest.clone(),
            });
            let new_bytes = new_root
                .seal(
                    &Header {
                        context: new_root.context().clone(),
                        revision: 2,
                        ..header
                    },
                    payload.as_bytes(),
                )
                .unwrap();
            entries.push(RotatedEntry {
                id: id.clone(),
                expected: EntryVersion {
                    revision: 1,
                    digest,
                },
                revision: 2,
                envelope: String::from_utf8(new_bytes).unwrap(),
            });
            old_objects.insert(id, old_bytes);
        }
        let object = wire(&old_root, &index);
        let trusted = trust(checkpoint(&authority, &old_root, &object, &index));
        let old = VerifiedIndex::open(&old_root, object.head, object.envelope.as_bytes()).unwrap();
        let recovery = String::from_utf8(new_root.wrap_recovery(PASSWORD).unwrap()).unwrap();
        let recovery_id =
            serde_json::from_str::<serde_json::Value>(&recovery).unwrap()["wrapper_id"]
                .as_str()
                .unwrap()
                .to_owned();
        let package = authority
            .create_entry_key_package(
                &new_root,
                recipient.public_identity(),
                2,
                DeliveryProfile::Standard,
            )
            .unwrap();
        index.context = new_root.context().clone();
        index.revision = 4;
        index.parent_digest = old.head().digest().unwrap();
        index.membership_generation = 2;
        index.wrappers = vec![
            WrapperRef {
                wrapper_id: recovery_id,
                digest: hex(&digest(recovery.as_bytes())),
            },
            package.reference().unwrap(),
        ];
        for (e, replacement) in index.entries.iter_mut().zip(&entries) {
            e.revision = 2;
            e.digest = hex(&digest(replacement.envelope.as_bytes()));
        }
        let object = wire(&new_root, &index);
        let next = checkpoint(&authority, &new_root, &object, &index);
        let transition = authority
            .authorize_entry_transition(&trusted, next, 3)
            .unwrap();
        let transaction = EpochTransaction {
            version: 1,
            operation: "5".repeat(64),
            expected: Cursor::from_head(old.head()).unwrap(),
            transition,
            object,
            entries,
            wrappers: vec![
                EpochWrapper::Recovery(recovery),
                EpochWrapper::Recipient(serde_json::to_string(&package).unwrap()),
            ],
        };
        Self {
            authority,
            recipient,
            old_root,
            new_root,
            old,
            old_objects,
            trusted,
            index,
            transaction,
        }
    }
    fn snapshot(&self) -> RotationSnapshot<'_> {
        RotationSnapshot {
            index: &self.old,
            root: &self.old_root,
            objects: &self.old_objects,
        }
    }
    fn resign(&mut self, tx: &mut EpochTransaction, index: &Index) {
        tx.object = wire(&self.new_root, index);
        let next = checkpoint(&self.authority, &self.new_root, &tx.object, index);
        tx.transition = self
            .authority
            .authorize_entry_transition(&self.trusted, next, 3)
            .unwrap();
    }
}

#[test]
fn complete_epoch_bundle_unlocks_and_advances_exact_local_pin() {
    for empty in [false, true] {
        let mut f = Fixture::new(empty);
        let tx = EpochTransaction::parse(&serde_json::to_vec(&f.transaction).unwrap()).unwrap();
        let next = tx.verify(&f.trusted, f.snapshot(), &f.new_root).unwrap();
        let trusted = f.trusted.advance(&tx.transition, 3).unwrap();
        let EpochWrapper::Recovery(recovery) = &tx.wrappers[0] else {
            panic!()
        };
        let recovered = trusted
            .open_recovery(recovery.as_bytes(), PASSWORD, &next.index().wrappers)
            .unwrap();
        assert_eq!(recovered.commitment(), f.new_root.commitment());
        let EpochWrapper::Recipient(package) = &tx.wrappers[1] else {
            panic!()
        };
        let received = f
            .recipient
            .open_entry_key_package(
                package.as_bytes(),
                &tx.transition.next.authority,
                &trusted,
                &next.index().wrappers,
            )
            .unwrap();
        assert_eq!(received.commitment(), recovered.commitment());
        for e in &tx.entries {
            assert!(
                next.open_entry(&f.old_root, &e.id, e.envelope.as_bytes())
                    .is_err()
            );
            f.old
                .open_entry(&f.old_root, &e.id, &f.old_objects[&e.id])
                .unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pin.json");
        let store = CheckpointStore::lock(&path).unwrap();
        store.initialize(&f.trusted, &f.old).unwrap();
        store
            .accept_epoch_transaction(&tx, f.snapshot(), &f.new_root)
            .unwrap();
        let saved = std::fs::read(&path).unwrap();
        assert!(
            store
                .accept_epoch_transaction(&tx, f.snapshot(), &f.new_root)
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), saved);
        drop(store);
        let store = CheckpointStore::lock(&path).unwrap();
        assert_eq!(store.head(f.new_root.context()).unwrap(), *next.head());
    }
}

#[test]
fn incomplete_or_substituted_epoch_bundle_leaves_pin_unchanged() {
    let f = Fixture::new(false);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pin.json");
    let store = CheckpointStore::lock(&path).unwrap();
    store.initialize(&f.trusted, &f.old).unwrap();
    let saved = std::fs::read(&path).unwrap();
    let mut bad = vec![];
    let mut tx = f.transaction.clone();
    tx.entries.pop();
    bad.push(tx);
    let mut tx = f.transaction.clone();
    tx.entries.push(tx.entries[0].clone());
    bad.push(tx);
    let mut tx = f.transaction.clone();
    tx.entries[0].expected.digest = "0".repeat(64);
    bad.push(tx);
    let mut tx = f.transaction.clone();
    tx.entries[0].revision = 1;
    bad.push(tx);
    let mut tx = f.transaction.clone();
    tx.entries[0].envelope = String::from_utf8(f.old_objects[&tx.entries[0].id].clone()).unwrap();
    bad.push(tx);
    let mut tx = f.transaction.clone();
    tx.wrappers.pop();
    bad.push(tx);
    let mut tx = f.transaction.clone();
    tx.wrappers.push(tx.wrappers[0].clone());
    bad.push(tx);
    let mut tx = f.transaction.clone();
    tx.expected.digest = "0".repeat(64);
    bad.push(tx);
    let mut tx = f.transaction.clone();
    tx.transition.previous_checkpoint_digest = "0".repeat(64);
    bad.push(tx);
    for tx in bad {
        assert!(
            store
                .accept_epoch_transaction(&tx, f.snapshot(), &f.new_root)
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), saved);
    }
    // A candidate from an earlier authenticated head cannot reset a newer pin.
    let mut newer = f.old.index().clone();
    newer.revision += 1;
    newer.parent_digest = f.old.head().digest().unwrap();
    let wire = wire(&f.old_root, &newer);
    let newer = VerifiedIndex::open(&f.old_root, wire.head, wire.envelope.as_bytes()).unwrap();
    store.observe(&f.old, &newer).unwrap();
    let saved = std::fs::read(&path).unwrap();
    assert!(
        store
            .accept_epoch_transaction(&f.transaction, f.snapshot(), &f.new_root)
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), saved);
}

#[test]
fn signed_rotation_cannot_hide_content_changes_or_invalid_wrappers() {
    let mut f = Fixture::new(false);
    let mut tx = f.transaction.clone();
    let mut index = f.index.clone();
    index.entries[0].name = "silently renamed".into();
    f.resign(&mut tx, &index);
    assert!(tx.verify(&f.trusted, f.snapshot(), &f.new_root).is_err());
    let mut tx = f.transaction.clone();
    let mut index = f.index.clone();
    let entry = &mut tx.entries[0];
    entry.envelope = String::from_utf8(
        f.new_root
            .seal(
                &Header {
                    entry_format_version: 1,
                    suite: SUITE.into(),
                    context: f.new_root.context().clone(),
                    kind: Kind::Entry,
                    object_id: entry.id.clone(),
                    revision: 2,
                },
                b"silently changed password",
            )
            .unwrap(),
    )
    .unwrap();
    index.entries[0].digest = hex(&digest(entry.envelope.as_bytes()));
    f.resign(&mut tx, &index);
    assert!(tx.verify(&f.trusted, f.snapshot(), &f.new_root).is_err());
    for mutation in ["recovery", "issuer", "signature"] {
        let mut tx = f.transaction.clone();
        let mut index = f.index.clone();
        let n = usize::from(mutation != "recovery");
        let bytes = match &mut tx.wrappers[n] {
            EpochWrapper::Recovery(b) | EpochWrapper::Recipient(b) => b,
        };
        let mut value: serde_json::Value = serde_json::from_str(bytes).unwrap();
        if mutation == "issuer" {
            value["issuer_fingerprint"] = serde_json::json!("0".repeat(64));
        } else if mutation == "signature" {
            let mut signature = value["signature"].as_str().unwrap().to_owned();
            let first = if signature.starts_with('A') { "B" } else { "A" };
            signature.replace_range(..1, first);
            value["signature"] = signature.into();
        } else {
            value["memory_kib"] = serde_json::json!(8);
        }
        *bytes = serde_json::to_string(&value).unwrap();
        index.wrappers[n].digest = hex(&digest(bytes.as_bytes()));
        f.resign(&mut tx, &index);
        assert!(tx.verify(&f.trusted, f.snapshot(), &f.new_root).is_err());
    }
    // Whitespace is allowed only when the signed active references bind the
    // actual bytes; no parse/reserialize operation may silently change hashes.
    let mut tx = f.transaction.clone();
    let mut index = f.index.clone();
    for (wrapper, reference) in tx.wrappers.iter_mut().zip(&mut index.wrappers) {
        let bytes = match wrapper {
            EpochWrapper::Recovery(b) | EpochWrapper::Recipient(b) => b,
        };
        bytes.push('\n');
        reference.digest = hex(&digest(bytes.as_bytes()));
    }
    f.resign(&mut tx, &index);
    tx.verify(&f.trusted, f.snapshot(), &f.new_root).unwrap();
}

#[test]
fn epoch_wire_and_receipts_bind_the_complete_request() {
    let f = Fixture::new(false);
    let tx = &f.transaction;
    let writer = "c".repeat(64);
    let receipt = Receipt {
        writer: writer.clone(),
        operation: tx.operation.clone(),
        request_digest: tx.submission_digest(&writer).unwrap(),
        accepted: Cursor::from_head(&tx.object.head).unwrap(),
    };
    tx.verify_receipt(&writer, &receipt).unwrap();
    assert!(tx.verify_receipt(&"d".repeat(64), &receipt).is_err());
    let mut changed = tx.clone();
    let EpochWrapper::Recovery(bytes) = &mut changed.wrappers[0] else {
        panic!()
    };
    bytes.push(' ');
    assert!(changed.verify_receipt(&writer, &receipt).is_err());
    let mut changed = tx.clone();
    changed.operation = "0".repeat(64);
    assert!(changed.verify_receipt(&writer, &receipt).is_err());
    let mut changed = tx.clone();
    changed.expected.digest = "0".repeat(64);
    assert!(changed.verify_receipt(&writer, &receipt).is_err());
    let mut changed = receipt.clone();
    changed.accepted.revision += 1;
    assert!(tx.verify_receipt(&writer, &changed).is_err());
    assert_ne!(
        receipt.request_digest,
        submission_digest(Some(&tx.expected), &writer, &tx.operation, &tx.object, &[]).unwrap()
    );
    let mut value = serde_json::to_value(tx).unwrap();
    value["unexpected"] = true.into();
    assert!(EpochTransaction::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let wire = serde_json::to_string(tx).unwrap();
    assert!(
        EpochTransaction::parse(
            wire.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
                .as_bytes()
        )
        .is_err()
    );
    assert!(EpochTransaction::parse(&vec![b' '; MAX_TRANSACTION_BYTES + 1]).is_err());
    let mut changed = tx.clone();
    changed.entries = vec![changed.entries[0].clone(); MAX_CHANGES + 1];
    assert!(EpochTransaction::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
}
