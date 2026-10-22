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
            return Some(response(json!({"user":{"id":"f".repeat(64)}})));
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
}
