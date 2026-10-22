use super::*;
use petika_core::{EncryptionMode, identity::UnlockedIdentity};
const NEW: &str = "synthetic new migration recovery";

#[test]
fn personal_migration_uses_own_enrollment_without_group_access_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let mut store = UnlockedStore::create(PASSWORD).unwrap();
    store.put("personal-name".into(), entry(), false).unwrap();
    let encrypted = String::from_utf8(store.seal().unwrap()).unwrap();
    let identity = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
    let path = base.join("identity.json");
    StoreFile::lock(&path)
        .unwrap()
        .write(&identity.seal(PASSWORD).unwrap(), true)
        .unwrap();
    let public = identity.public_identity().clone();
    let api = Api::new(move |request| {
        assert_eq!(request.method, "GET");
        if request.path == "/v1/collections" {
            return Some(response(
                json!([{"id":"f".repeat(64),"group":false,"edit":true}]),
            ));
        }
        if request.path == "/v1/auth/status" {
            return Some(response(json!({"user":{"id":"f".repeat(64)}})));
        }
        if request.path == "/v1/keys/deployment" {
            return Some(response(json!({"deployment_id":"a".repeat(64)})));
        }
        if request.path == format!("/v1/keys/users/{}", "f".repeat(64)) {
            return Some(response(json!(public)));
        }
        assert_eq!(
            request.path,
            format!("/v1/collections/{}/snapshot", "f".repeat(64))
        );
        Some(Response {
            status: 200,
            revision: Some(4),
            body: encrypted.clone(),
        })
    });
    api.session(base);
    let draft = base.join("draft.json");
    let input = format!("{PASSWORD}\n{PASSWORD}\n");
    for command in ["migrate-stage", "migrate-review"] {
        let mut args = vec![
            "entries",
            command,
            "--authority-identity",
            path.to_str().unwrap(),
            "--draft",
            draft.to_str().unwrap(),
        ];
        if command == "migrate-stage" {
            args.extend(["--recovery-policy", "omit"]);
        }
        ok(&run(base, &args, &input));
    }
    let saved: Value = serde_json::from_slice(&std::fs::read(draft).unwrap()).unwrap();
    assert_eq!(saved["draft"]["source"]["membership_generation"], 1);
    assert_eq!(saved["draft"]["recipients"].as_array().unwrap().len(), 1);
}

#[test]
fn migration_cli_captures_live_source_and_retains_stale_drafts_without_writes() {
    for (mode, policy) in [
        (EncryptionMode::Standard, "omit"),
        (EncryptionMode::HybridPostQuantum, "replace"),
    ] {
        workflow(mode, policy);
    }
}
fn workflow(mode: EncryptionMode, policy: &str) {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let mut source = UnlockedStore::create_with_mode(PASSWORD, mode).unwrap();
    let mut value = entry();
    value.otp = Some("JBSWY3DPEHPK3PXP".into());
    source
        .put("private/literal-name".into(), value, false)
        .unwrap();
    let encrypted = String::from_utf8(source.seal().unwrap()).unwrap();
    let mut authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
    let recipient = UnlockedIdentity::generate(&"a".repeat(64), &"e".repeat(64), 1).unwrap();
    let public = recipient.public_identity();
    authority
        .verify_contact(&public.user_id, public, &public.fingerprint, None)
        .unwrap();
    let identity_path = base.join("identity.json");
    StoreFile::lock(&identity_path)
        .unwrap()
        .write(&authority.seal(PASSWORD).unwrap(), true)
        .unwrap();
    let authority_public = authority.public_identity().clone();
    let recipient_public = recipient.public_identity().clone();
    struct State {
        revision: u64,
        generation: u64,
        change_during_read: bool,
        read_only: bool,
        bad_identity: bool,
    }
    let shared = Arc::new(Mutex::new(State {
        revision: 7,
        generation: 2,
        change_during_read: false,
        read_only: false,
        bad_identity: false,
    }));
    let state = shared.clone();
    let old_encrypted = encrypted.clone();
    let api = Api::new(move |request| {
        assert_eq!(
            request.method, "GET",
            "Migration must never publish API writes"
        );
        let mut state = state.lock().unwrap();
        if request.path == "/v1/collections" {
            return Some(response(
                json!([{"id":"b".repeat(64),"group":true,"edit":!state.read_only}]),
            ));
        }
        if request.path == "/v1/auth/status" {
            return Some(response(json!({"user":{"id":"f".repeat(64),"admin":true}})));
        }
        if request.path == "/v1/keys/deployment" {
            return Some(response(json!({"deployment_id":"a".repeat(64)})));
        }
        if request.path.starts_with("/v1/keys/users/") {
            let mut value = if request.path.ends_with(&"f".repeat(64)) {
                json!(authority_public)
            } else {
                json!(recipient_public)
            };
            if state.bad_identity {
                value["user_id"] = json!("c".repeat(64));
            }
            return Some(response(value));
        }
        if request.path.ends_with("/status") {
            return Some(response(json!({"revision":state.revision})));
        }
        if request.path.contains("/key-access") {
            let second = request.path.ends_with("?cursor=ab");
            return Some(response(
                json!({"snapshot_revision":state.revision,"key_epoch":0,"membership_generation":state.generation,"rotation_required":false,"recipient_enabled":false,"deliveries":[{"user_id":if second {"e".repeat(64)}else{"f".repeat(64)},"identity_version":1,"state":"missing-package"}],"next_cursor":if second {""}else{"ab"}}),
            ));
        }
        assert!(request.path.ends_with("/snapshot"));
        if state.change_during_read {
            state.revision += 1;
        }
        Some(Response {
            status: 200,
            revision: Some(state.revision),
            body: old_encrypted.clone(),
        })
    });
    api.session(base);
    let path = base.join("migration.json");
    let invoke = |command: &str, input: &str| {
        let collection = "b".repeat(64);
        let mut args = vec![
            "entries",
            command,
            "--collection",
            &collection,
            "--authority-identity",
            identity_path.to_str().unwrap(),
            "--draft",
            path.to_str().unwrap(),
        ];
        if command == "migrate-stage" {
            args.extend(["--recovery-policy", policy]);
        }
        run(base, &args, input)
    };
    let two = format!("{PASSWORD}\n{PASSWORD}\n");
    let input = if policy == "replace" {
        format!("{two}{NEW}\n{NEW}\n")
    } else {
        two.clone()
    };
    shared.lock().unwrap().read_only = true;
    assert!(!invoke("migrate-stage", &input).status.success());
    assert!(!path.exists());
    shared.lock().unwrap().read_only = false;
    shared.lock().unwrap().change_during_read = true;
    assert!(!invoke("migrate-stage", &input).status.success());
    assert!(!path.exists());
    {
        let mut state = shared.lock().unwrap();
        state.change_during_read = false;
        state.revision = 7;
        state.bad_identity = true;
    }
    assert!(!invoke("migrate-stage", &input).status.success());
    assert!(!path.exists());
    shared.lock().unwrap().bad_identity = false;
    assert!(
        !invoke(
            "migrate-stage",
            &format!("wrong\n{PASSWORD}\n{NEW}\n{NEW}\n")
        )
        .status
        .success()
    );
    assert!(!path.exists());
    let output = invoke("migrate-stage", &input);
    ok(&output);
    for secret in ["private/literal-name", "initial-secret", "JBSWY3DPEHPK3PXP"] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    }
    let saved = std::fs::read(&path).unwrap();
    let value: Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(value["draft"]["source_encrypted"], encrypted);
    assert_eq!(value["draft"]["source"]["snapshot_revision"], 7);
    assert_eq!(value["draft"]["recipients"].as_array().unwrap().len(), 2);
    for secret in [
        PASSWORD,
        NEW,
        "private/literal-name",
        "initial-secret",
        "JBSWY3DPEHPK3PXP",
    ] {
        assert!(!String::from_utf8_lossy(&saved).contains(secret));
    }
    assert!(!invoke("migrate-stage", &input).status.success());
    ok(&invoke("migrate-review", &two));
    assert!(
        !invoke("migrate-review", &format!("{PASSWORD}\nwrong\n"))
            .status
            .success()
    );
    shared.lock().unwrap().revision = 8;
    assert!(!invoke("migrate-review", &two).status.success());
    {
        let mut state = shared.lock().unwrap();
        state.revision = 7;
        state.generation = 3;
    }
    assert!(!invoke("migrate-review", &two).status.success());
    shared.lock().unwrap().generation = 2;
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    let mut foreign = value.clone();
    foreign["server"] = json!("https://different.example.org");
    StoreFile::lock(&path)
        .unwrap()
        .write(&serde_json::to_vec(&foreign).unwrap(), false)
        .unwrap();
    assert!(!invoke("migrate-review", &two).status.success());
    StoreFile::lock(&path)
        .unwrap()
        .write(&saved, false)
        .unwrap();
    ok(&invoke("migrate-review", &two));
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    assert!(!base.join("unused.petika").exists());
    assert!(!base.join("pin.json").exists());
    let changed = UnlockedIdentity::generate(&"a".repeat(64), &"e".repeat(64), 2).unwrap();
    authority
        .observe_contact(&"e".repeat(64), changed.public_identity())
        .unwrap();
    StoreFile::lock(&identity_path)
        .unwrap()
        .write(&authority.seal(PASSWORD).unwrap(), false)
        .unwrap();
    let rejected = run(
        base,
        &[
            "entries",
            "migrate-submit",
            "--collection",
            &"b".repeat(64),
            "--authority-identity",
            identity_path.to_str().unwrap(),
            "--draft",
            path.to_str().unwrap(),
            "--pin",
            base.join("pin.json").to_str().unwrap(),
            "--cache",
            base.join("cache").to_str().unwrap(),
            "--confirm",
        ],
        &two,
    );
    assert!(!rejected.status.success());
    assert!(!base.join("pin.json").exists());
    assert_eq!(std::fs::read(&path).unwrap(), saved);
}

#[test]
fn migration_submit_reconciles_lost_ack_and_initializes_only_verified_pins() {
    use petika_core::entry_format::{
        migration_draft::MigrationDraft, transaction::Receipt, transport::Cursor,
    };
    for (mode, policy) in [
        (EncryptionMode::Standard, "omit"),
        (EncryptionMode::HybridPostQuantum, "replace"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let mut source = UnlockedStore::create_with_mode(PASSWORD, mode).unwrap();
        source
            .put("literal/private-name".into(), entry(), false)
            .unwrap();
        let encrypted = String::from_utf8(source.seal().unwrap()).unwrap();
        let identity = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
        let public = identity.public_identity().clone();
        let identity_path = base.join("identity.json");
        StoreFile::lock(&identity_path)
            .unwrap()
            .write(&identity.seal(PASSWORD).unwrap(), true)
            .unwrap();
        struct State {
            revision: u64,
            receipt: Option<Receipt>,
            writes: usize,
            bad_receipt: bool,
            missing_receipt: bool,
            edit: bool,
        }
        let shared = Arc::new(Mutex::new(State {
            revision: 4,
            receipt: None,
            writes: 0,
            bad_receipt: false,
            missing_receipt: false,
            edit: true,
        }));
        let state = shared.clone();
        let committed = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let server_committed = committed.clone();
        let server_release = release.clone();
        let api = Api::new(move |request| {
            assert!(!request.body.contains(NEW));
            let mut state = state.lock().unwrap();
            let prefix = format!("/v1/collections/{}", "f".repeat(64));
            if request.path == "/v1/collections" {
                return Some(response(
                    json!([{"id":"f".repeat(64),"group":false,"edit":state.edit}]),
                ));
            }
            if request.path == "/v1/auth/status" {
                return Some(response(json!({"user":{"id":"f".repeat(64)}})));
            }
            if request.path == "/v1/keys/deployment" {
                return Some(response(json!({"deployment_id":"a".repeat(64)})));
            }
            if request.path == format!("/v1/keys/users/{}", "f".repeat(64)) {
                return Some(response(json!(public)));
            }
            if request.path == format!("{prefix}/status") {
                return Some(response(if state.receipt.is_some() {
                    json!({"format":"entry-v1"})
                } else {
                    json!({"revision":state.revision})
                }));
            }
            if request.path == format!("{prefix}/snapshot") {
                assert!(
                    state.receipt.is_none(),
                    "Never fetch legacy snapshots after acceptance"
                );
                return Some(Response {
                    status: 200,
                    revision: Some(state.revision),
                    body: encrypted.clone(),
                });
            }
            if request.path == format!("{prefix}/entry-receipt") {
                let mut receipt = state.receipt.clone();
                if state.missing_receipt {
                    receipt = None;
                }
                if state.bad_receipt {
                    receipt.as_mut().unwrap().request_digest = "0".repeat(64);
                }
                return Some(response(json!({"receipt":receipt})));
            }
            assert_eq!(request.path, format!("{prefix}/entry-migrations"));
            assert_eq!(request.method, "POST");
            assert!(state.receipt.is_none());
            let draft = MigrationDraft::parse(request.body.as_bytes()).unwrap();
            draft.verify_public(&draft.source, &public).unwrap();
            assert_eq!(draft.source.snapshot_revision, state.revision);
            state.writes += 1;
            state.receipt = Some(Receipt {
                writer: public.user_id.clone(),
                operation: draft.operation.clone(),
                request_digest: draft.submission_digest(&public.user_id).unwrap(),
                accepted: Cursor::from_head(&draft.object.head).unwrap(),
            });
            drop(state);
            server_committed.store(true, Ordering::SeqCst);
            while !server_release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            None // Client was terminated after acceptance, before acknowledgement.
        });
        api.session(base);
        let draft_path = base.join("draft.json");
        let pin = base.join("pin.json");
        let cache = base.join("cache");
        let common = [
            "--authority-identity",
            identity_path.to_str().unwrap(),
            "--draft",
            draft_path.to_str().unwrap(),
        ];
        let mut stage = vec!["entries", "migrate-stage"];
        stage.extend(common);
        stage.extend(["--recovery-policy", policy]);
        let mut input = format!("{PASSWORD}\n{PASSWORD}\n");
        let stage_input = if policy == "replace" {
            format!("{input}{NEW}\n{NEW}\n")
        } else {
            input.clone()
        };
        ok(&run(base, &stage, &stage_input));
        let original = std::fs::read(&draft_path).unwrap();
        let saved: Value = serde_json::from_slice(&original).unwrap();
        let draft: MigrationDraft = serde_json::from_value(saved["draft"].clone()).unwrap();
        let mut submit = vec!["entries", "migrate-submit"];
        submit.extend(common);
        submit.extend([
            "--pin",
            pin.to_str().unwrap(),
            "--cache",
            cache.to_str().unwrap(),
        ]);
        assert!(!run(base, &submit, "").status.success());
        submit.push("--confirm");
        if policy == "replace" {
            assert!(
                !run(base, &submit, &format!("{input}wrong recovery\n"))
                    .status
                    .success()
            );
            assert_eq!(shared.lock().unwrap().writes, 0);
            input.push_str(&format!("{NEW}\n"));
        }
        shared.lock().unwrap().revision += 1;
        assert!(!run(base, &submit, &input).status.success());
        shared.lock().unwrap().revision -= 1;
        assert_eq!(shared.lock().unwrap().writes, 0);
        let mut child = Command::new(env!("CARGO_BIN_EXE_petika"))
            .args(["--no-config", "--passphrase-stdin", "--session-file"])
            .arg(base.join("session.json"))
            .args(&submit)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !committed.load(Ordering::SeqCst)
            && std::time::Instant::now() < deadline
            && child.try_wait().unwrap().is_none()
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        let accepted = committed.load(Ordering::SeqCst);
        let _ = child.kill();
        let failed = child.wait_with_output().unwrap();
        release.store(true, Ordering::SeqCst);
        assert!(accepted, "{}", String::from_utf8_lossy(&failed.stderr));
        assert!(!failed.status.success());
        assert!(!pin.exists());
        assert_eq!(shared.lock().unwrap().writes, 1);
        assert_eq!(std::fs::read(&draft_path).unwrap(), original);
        shared.lock().unwrap().bad_receipt = true;
        assert!(!run(base, &submit, &input).status.success());
        assert!(!pin.exists());
        shared.lock().unwrap().bad_receipt = false;
        shared.lock().unwrap().missing_receipt = true;
        assert!(!run(base, &submit, &input).status.success());
        assert!(!pin.exists());
        shared.lock().unwrap().missing_receipt = false;
        // A local artifact conflict after API acceptance must not publish a pin.
        let receipt_path = draft_path.with_extension("accepted.json");
        std::fs::write(&receipt_path, b"conflicting receipt").unwrap();
        assert!(!run(base, &submit, &input).status.success());
        assert!(!pin.exists());
        std::fs::remove_file(&receipt_path).unwrap();
        shared.lock().unwrap().edit = false; // Receipt reconciliation needs only read access.
        let result = run(base, &submit, &input);
        ok(&result);
        assert!(!String::from_utf8_lossy(&result.stdout).contains("literal/private-name"));
        let original_pin = std::fs::read(&pin).unwrap();
        let pinned =
            petika_core::entry_format::checkpoint_store::CheckpointStore::lock(&pin).unwrap();
        assert_eq!(
            pinned.head(&draft.object.head.context).unwrap(),
            draft.object.head
        );
        drop(pinned);
        assert!(
            cache
                .join(format!(
                    "epoch-{}.json",
                    draft.state.checkpoint.digest().unwrap()
                ))
                .exists()
        );
        // Already accepted retry only unlocks the identity, not retired source/recovery.
        ok(&run(base, &submit, &format!("{PASSWORD}\n")));
        assert_eq!(std::fs::read(&pin).unwrap(), original_pin);
        assert_eq!(shared.lock().unwrap().writes, 1);
        assert_eq!(std::fs::read(&draft_path).unwrap(), original);
        let anchor = cache.join(format!("{}.json", draft.object.head.digest().unwrap()));
        let list = run(
            base,
            &[
                "entries",
                "list",
                "--anchor",
                anchor.to_str().unwrap(),
                "--pin",
                pin.to_str().unwrap(),
                "--cache",
                cache.to_str().unwrap(),
                "--recipient-identity",
                identity_path.to_str().unwrap(),
            ],
            &format!("{PASSWORD}\n"),
        );
        ok(&list);
        assert!(String::from_utf8_lossy(&list.stdout).contains("literal/private-name"));
        // A corrupt existing pin is retained, never replaced with the draft's pin.
        std::fs::write(&pin, b"corrupt pin").unwrap();
        assert!(
            !run(base, &submit, &format!("{PASSWORD}\n"))
                .status
                .success()
        );
        assert_eq!(std::fs::read(&pin).unwrap(), b"corrupt pin");
        assert_eq!(shared.lock().unwrap().writes, 1);
    }
}
