use super::*;
use petika_core::{
    entry_format::{
        checkpoint::*, checkpoint_store::CheckpointStore, epoch_transaction::*, index::*,
        transaction::Receipt, transport::*, *,
    },
    identity::{CheckpointTarget, UnlockedIdentity},
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn save(path: impl AsRef<Path>, bytes: &[u8]) {
    StoreFile::lock(path).unwrap().write(bytes, false).unwrap();
}

#[test]
fn rotation_drafts_reconcile_lost_ack_and_clients_verify_before_advancing() {
    for policy in ["omit", "replace"] {
        workflow(policy);
    }
}

fn workflow(policy: &str) {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let recovery = root.wrap_recovery(PASSWORD).unwrap();
    let value: Value = serde_json::from_slice(&recovery).unwrap();
    let refs = vec![WrapperRef {
        wrapper_id: value["wrapper_id"].as_str().unwrap().into(),
        digest: hex(&digest(&recovery)),
    }];
    let mut authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
    let mut recipient = UnlockedIdentity::generate(&"a".repeat(64), &"e".repeat(64), 1).unwrap();
    let public = recipient.public_identity();
    authority
        .verify_contact(&public.user_id, public, &public.fingerprint, None)
        .unwrap();
    let public = authority.public_identity();
    recipient
        .verify_contact(&public.user_id, public, &public.fingerprint, None)
        .unwrap();
    let roster = json!({"version":1,"membership_generation":2,"recipients":[authority.public_identity(),recipient.public_identity()]});
    save(
        base.join("authority.json"),
        &authority.seal(PASSWORD).unwrap(),
    );
    save(
        base.join("recipient.json"),
        &recipient.seal(PASSWORD).unwrap(),
    );
    let id = "1".repeat(64);
    let mut original = entry();
    original.otp = Some("JBSWY3DPEHPK3PXP".into());
    let plaintext = serde_json::to_vec(&original).unwrap();
    let payload = root
        .seal(
            &Header {
                entry_format_version: 1,
                suite: SUITE.into(),
                context: root.context().clone(),
                kind: Kind::Entry,
                object_id: id.clone(),
                revision: 1,
            },
            &plaintext,
        )
        .unwrap();
    let index = Index {
        version: 1,
        context: root.context().clone(),
        suite: SUITE.into(),
        revision: 1,
        parent_digest: String::new(),
        membership_generation: 1,
        wrappers: refs.clone(),
        root_folder: String::new(),
        folders: vec![],
        entries: vec![EntryRef {
            id: id.clone(),
            folder: String::new(),
            name: "Hidden entry name".into(),
            revision: 1,
            digest: hex(&digest(&payload)),
        }],
        tombstones: vec![],
    };
    let envelope = root
        .seal(
            &Header {
                entry_format_version: 1,
                suite: SUITE.into(),
                context: root.context().clone(),
                kind: Kind::Index,
                object_id: String::new(),
                revision: 1,
            },
            &serde_json::to_vec(&index).unwrap(),
        )
        .unwrap();
    let initial = HistoryObject {
        head: Head {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: 1,
            parent_digest: String::new(),
            index_digest: hex(&digest(&envelope)),
            wrapper_set_digest: wrapper_set_digest(&refs).unwrap(),
            membership_generation: 1,
        },
        envelope: String::from_utf8(envelope).unwrap(),
    };
    let cp = authority
        .sign_entry_checkpoint(
            &root,
            CheckpointTarget {
                head_revision: 1,
                head_digest: initial.head.digest().unwrap(),
                membership_generation: 1,
                delivery_profile: DeliveryProfile::Standard,
            },
            &refs,
        )
        .unwrap();
    let trusted =
        TrustedCheckpoint::bootstrap(cp.clone(), &cp.digest().unwrap(), &cp.authority.fingerprint)
            .unwrap();
    let previous =
        VerifiedIndex::open(&root, initial.head.clone(), initial.envelope.as_bytes()).unwrap();
    for (pin, cache) in [("pin.json", "cache"), ("reader-pin.json", "reader-cache")] {
        std::fs::create_dir(base.join(cache)).unwrap();
        save(
            base.join(cache)
                .join(format!("{}.json", initial.head.digest().unwrap())),
            &serde_json::to_vec(&initial).unwrap(),
        );
        CheckpointStore::lock(base.join(pin))
            .unwrap()
            .initialize(&trusted, &previous)
            .unwrap();
    }
    save(
        base.join("anchor.json"),
        &serde_json::to_vec(&initial).unwrap(),
    );
    save(base.join("recovery.json"), &recovery);
    let old_pin = std::fs::read(base.join("pin.json")).unwrap();
    struct State {
        tx: Option<EpochTransaction>,
        writes: usize,
        forge: bool,
        bad_epoch: bool,
        bad_roster: bool,
    }
    let shared = Arc::new(Mutex::new(State {
        tx: None,
        writes: 0,
        forge: false,
        bad_epoch: false,
        bad_roster: false,
    }));
    let state = shared.clone();
    let initial_head = initial.head.clone();
    let api = Api::new(move |request| {
        if request.path == "/v1/collections" {
            return Some(response(
                json!([{"id":"b".repeat(64),"group":false,"edit":true}]),
            ));
        }
        if request.path == "/v1/auth/status" {
            return Some(response(json!({"user":{"id":"f".repeat(64)}})));
        }
        if request.path.ends_with("/entry-roster") {
            let mut roster = roster.clone();
            if state.lock().unwrap().bad_roster {
                let stranger =
                    UnlockedIdentity::generate(&"a".repeat(64), &"d".repeat(64), 1).unwrap();
                roster["recipients"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(stranger.public_identity()));
            }
            return Some(response(roster));
        }
        let mut state = state.lock().unwrap();
        if request.path.ends_with("/entry-object") {
            let body: Value = serde_json::from_str(&request.body).unwrap();
            assert_eq!(body["root"]["digest"], initial_head.digest().unwrap());
            return Some(Response {
                status: 200,
                revision: None,
                body: String::from_utf8(payload.clone()).unwrap(),
            });
        }
        if request.path.ends_with("/entry-epoch") {
            let mut value = json!({"transaction":state.tx});
            if state.bad_epoch {
                value["transaction"]["entries"] = json!([]);
            }
            return Some(response(value));
        }
        if request.path.ends_with("/entry-receipt") {
            let receipt = state.tx.as_ref().map(|tx| Receipt {
                writer: "f".repeat(64),
                operation: tx.operation.clone(),
                request_digest: if state.forge {
                    "0".repeat(64)
                } else {
                    tx.submission_digest(&"f".repeat(64)).unwrap()
                },
                accepted: Cursor::from_head(&tx.object.head).unwrap(),
            });
            return Some(response(json!({"receipt":receipt})));
        }
        assert!(request.path.ends_with("/entry-rotations"));
        let tx = EpochTransaction::parse(request.body.as_bytes()).unwrap();
        tx.verify_public(&trusted, &initial_head).unwrap();
        state.tx = Some(tx);
        state.writes += 1;
        None // Server accepted; acknowledgement lost.
    });
    api.session(base);
    let invoke = |command: &str, reader: bool, extra: &[&str], input: &str| {
        let anchor = base.join("anchor.json");
        let pin = base.join(if reader {
            "reader-pin.json"
        } else {
            "pin.json"
        });
        let cache = base.join(if reader { "reader-cache" } else { "cache" });
        let recovery = base.join("recovery.json");
        let authority = base.join("authority.json");
        let draft = base.join("draft.json");
        let mut args = vec![
            "entries",
            command,
            "--anchor",
            anchor.to_str().unwrap(),
            "--pin",
            pin.to_str().unwrap(),
            "--cache",
            cache.to_str().unwrap(),
            "--recovery",
            recovery.to_str().unwrap(),
        ];
        if command.starts_with("rotate") {
            args.extend([
                "--authority-identity",
                authority.to_str().unwrap(),
                "--draft",
                draft.to_str().unwrap(),
            ]);
        }
        args.extend(extra);
        run(base, &args, input)
    };
    let two = format!("{PASSWORD}\n{PASSWORD}\n");
    let stage_input = if policy == "replace" {
        two.repeat(2)
    } else {
        two.clone()
    };
    assert!(
        !invoke(
            "rotate",
            false,
            &["--recovery-policy", policy],
            &format!("{PASSWORD}\nwrong\n")
        )
        .status
        .success()
    );
    assert!(!base.join("draft.json").exists());
    shared.lock().unwrap().bad_roster = true;
    assert!(
        !invoke(
            "rotate",
            false,
            &["--recovery-policy", policy],
            &stage_input
        )
        .status
        .success()
    );
    assert!(!base.join("draft.json").exists());
    assert_eq!(std::fs::read(base.join("pin.json")).unwrap(), old_pin);
    shared.lock().unwrap().bad_roster = false;
    ok(&invoke(
        "rotate",
        false,
        &["--recovery-policy", policy],
        &stage_input,
    ));
    assert_eq!(shared.lock().unwrap().writes, 0);
    assert_eq!(std::fs::read(base.join("pin.json")).unwrap(), old_pin);
    let draft = std::fs::read(base.join("draft.json")).unwrap();
    let text = String::from_utf8(draft.clone()).unwrap();
    for secret in [
        PASSWORD,
        "Hidden entry name",
        entry().password.as_str(),
        "JBSWY3DPEHPK3PXP",
    ] {
        assert!(!text.contains(secret));
    }
    assert!(
        !invoke(
            "rotate",
            false,
            &["--recovery-policy", policy],
            &stage_input
        )
        .status
        .success()
    );
    ok(&invoke("rotate-review", false, &[], &two));
    assert!(!invoke("rotate-submit", false, &[], "").status.success());
    // Lost acknowledgement leaves the old pin and exact encrypted draft.
    assert!(
        !invoke("rotate-submit", false, &["--confirm"], &two)
            .status
            .success()
    );
    assert_eq!(std::fs::read(base.join("pin.json")).unwrap(), old_pin);
    assert_eq!(std::fs::read(base.join("draft.json")).unwrap(), draft);
    shared.lock().unwrap().forge = true;
    assert!(
        !invoke("rotate-submit", false, &["--confirm"], &two)
            .status
            .success()
    );
    assert_eq!(std::fs::read(base.join("pin.json")).unwrap(), old_pin);
    shared.lock().unwrap().forge = false;
    let tx = shared.lock().unwrap().tx.clone().unwrap();
    let next_trust =
        TrustedCheckpoint::bootstrap(cp.clone(), &cp.digest().unwrap(), &cp.authority.fingerprint)
            .unwrap()
            .advance(&tx.transition, 1)
            .unwrap();
    let next_state = EpochState {
        checkpoint: tx.transition.next.clone(),
        wrappers: tx.wrappers.clone(),
    };
    let next_refs = next_state.references(&next_trust).unwrap();
    let package = tx
        .wrappers
        .iter()
        .find_map(|w| match w {
            EpochWrapper::Recipient(value)
                if serde_json::from_str::<Value>(value).unwrap()["recipient_user_id"]
                    == "e".repeat(64) =>
            {
                Some(value)
            }
            _ => None,
        })
        .unwrap();
    let new_root = recipient
        .open_entry_key_package(package.as_bytes(), &cp.authority, &next_trust, &next_refs)
        .unwrap();
    let new_index = VerifiedIndex::open(
        &new_root,
        tx.object.head.clone(),
        tx.object.envelope.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        &*new_index
            .open_entry(&new_root, &id, tx.entries[0].envelope.as_bytes())
            .unwrap(),
        &plaintext
    );
    assert!(
        VerifiedIndex::open(&root, tx.object.head.clone(), tx.object.envelope.as_bytes()).is_err()
    );
    let recovery_count = tx
        .wrappers
        .iter()
        .filter(|w| matches!(w, EpochWrapper::Recovery(_)))
        .count();
    assert_eq!(recovery_count, usize::from(policy == "replace"));
    // A cache conflict after server acceptance must not advance trust.
    let cached = base.join("cache").join(format!(
        "epoch-{}.json",
        tx.transition.next.digest().unwrap()
    ));
    save(&cached, b"{}");
    assert!(
        !invoke("rotate-submit", false, &["--confirm"], &two)
            .status
            .success()
    );
    assert_eq!(std::fs::read(base.join("pin.json")).unwrap(), old_pin);
    save(
        &cached,
        &serde_json::to_vec(&EpochState {
            checkpoint: tx.transition.next.clone(),
            wrappers: tx.wrappers.clone(),
        })
        .unwrap(),
    );
    ok(&invoke("rotate-submit", false, &["--confirm"], &two));
    let accepted = std::fs::read(base.join("pin.json")).unwrap();
    assert_ne!(accepted, old_pin);
    // Replay uses the already accepted local pin and only the identity password.
    ok(&invoke(
        "rotate-submit",
        false,
        &["--confirm"],
        &format!("{PASSWORD}\n"),
    ));
    assert_eq!(shared.lock().unwrap().writes, 1);
    assert_eq!(std::fs::read(base.join("pin.json")).unwrap(), accepted);
    let recipient_path = base.join("recipient.json");
    let next = ["--next-identity", recipient_path.to_str().unwrap()];
    shared.lock().unwrap().bad_epoch = true;
    assert!(!invoke("advance-epoch", true, &next, &two).status.success());
    assert_eq!(
        std::fs::read(base.join("reader-pin.json")).unwrap(),
        old_pin
    );
    shared.lock().unwrap().bad_epoch = false;
    if policy == "replace" {
        let recovery = tx
            .wrappers
            .iter()
            .find_map(|w| match w {
                EpochWrapper::Recovery(value) => Some(value),
                _ => None,
            })
            .unwrap();
        let path = base.join("next-recovery.json");
        save(&path, recovery.as_bytes());
        ok(&invoke(
            "advance-epoch",
            true,
            &["--next-recovery", path.to_str().unwrap()],
            &two,
        ));
        assert_eq!(
            std::fs::read(base.join("reader-pin.json")).unwrap(),
            old_pin
        );
    }
    assert!(
        !invoke(
            "advance-epoch",
            true,
            &next,
            &format!("{PASSWORD}\nwrong\n")
        )
        .status
        .success()
    );
    ok(&invoke("advance-epoch", true, &next, &two));
    assert_eq!(
        std::fs::read(base.join("reader-pin.json")).unwrap(),
        old_pin
    );
    ok(&invoke(
        "advance-epoch",
        true,
        &[next[0], next[1], "--confirm"],
        &two,
    ));
    let store = CheckpointStore::lock(base.join("reader-pin.json")).unwrap();
    let head = store
        .collection_head(&"a".repeat(64), &"b".repeat(64))
        .unwrap();
    assert_eq!(head.context.key_epoch, 2);
    assert!(
        store
            .collection_head(&"c".repeat(64), &"b".repeat(64))
            .is_err()
    );
    assert!(
        store
            .collection_head(&"a".repeat(64), &"c".repeat(64))
            .is_err()
    );
    drop(store);
    // Original anchor locates the accepted epoch; cached recipient material unlocks it.
    let output = run(
        base,
        &[
            "entries",
            "list",
            "--anchor",
            base.join("anchor.json").to_str().unwrap(),
            "--pin",
            base.join("reader-pin.json").to_str().unwrap(),
            "--cache",
            base.join("reader-cache").to_str().unwrap(),
            "--recipient-identity",
            recipient_path.to_str().unwrap(),
        ],
        &format!("{PASSWORD}\n"),
    );
    ok(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("Hidden entry name"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&entry().password));
}
