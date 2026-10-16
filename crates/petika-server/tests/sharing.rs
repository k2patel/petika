use petika_core::identity::UnlockedIdentity;
use petika_server::accounts::{Accounts, KeyError, KeyOperation, Membership};
use serde_json::{Value, json};
const PASSWORD: &str = "synthetic account password";
fn request(deployment: &str, user: &str, version: u64) -> Value {
    let identity = UnlockedIdentity::generate(deployment, user, version).unwrap();
    let mut body: Value =
        serde_json::from_slice(&identity.seal("synthetic local unlock phrase").unwrap()).unwrap();
    let object = body.as_object_mut().unwrap();
    object.retain(|key, _| key == "public_identity" || key == "encrypted_bundle");
    object.insert("expected_bundle_revision".into(), json!(0));
    object.insert("current_password".into(), json!(PASSWORD));
    body
}
fn call(
    accounts: &mut Accounts,
    token: &str,
    op: KeyOperation,
    body: &Value,
) -> Result<Value, KeyError> {
    accounts.key_operation(token, op, &serde_json::to_vec(body).unwrap())
}
#[test]
fn enrollment_directory_cas_replacement_and_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.json");
    let mut accounts = Accounts::new(path.clone());
    accounts.migrate().unwrap();
    let owner = accounts
        .create_user("owner", "Owner", PASSWORD.into(), true, true)
        .unwrap();
    let member = accounts
        .create_user("member", "Member", PASSWORD.into(), false, false)
        .unwrap();
    let outsider = accounts
        .create_user("outsider", "Outsider", PASSWORD.into(), true, false)
        .unwrap();
    let (a, _) = accounts.login("owner", PASSWORD.into()).unwrap();
    let (b, _) = accounts.login("member", PASSWORD.into()).unwrap();
    let (c, _) = accounts.login("outsider", PASSWORD.into()).unwrap();
    let deployment =
        call(&mut accounts, &a, KeyOperation::Deployment, &Value::Null).unwrap()["deployment_id"]
            .as_str()
            .unwrap()
            .to_owned();
    let group = accounts
        .save_group(
            None,
            "Team",
            vec![
                Membership {
                    user_id: owner.id.clone(),
                    edit: true,
                },
                Membership {
                    user_id: member.id.clone(),
                    edit: false,
                },
            ],
        )
        .unwrap();
    let body = request(&deployment, &owner.id, 1);
    let mut wrong = body.clone();
    wrong["current_password"] = json!("incorrect account password");
    assert_eq!(
        call(&mut accounts, &a, KeyOperation::Enroll, &wrong),
        Err(KeyError::Unauthenticated)
    );
    wrong = body.clone();
    wrong["public_identity"]["deployment_id"] = json!("0".repeat(64));
    assert_eq!(
        call(&mut accounts, &a, KeyOperation::Enroll, &wrong),
        Err(KeyError::Invalid)
    );
    let initial = call(&mut accounts, &a, KeyOperation::Enroll, &body).unwrap();
    assert_eq!(initial["bundle_revision"], 1);
    assert_eq!(
        call(&mut accounts, &a, KeyOperation::Enroll, &body),
        Err(KeyError::Conflict)
    );
    assert_eq!(
        call(
            &mut accounts,
            &c,
            KeyOperation::Lookup(owner.id.clone()),
            &Value::Null
        ),
        Err(KeyError::NotFound)
    );
    let public = call(
        &mut accounts,
        &b,
        KeyOperation::Lookup(owner.id.clone()),
        &Value::Null,
    )
    .unwrap();
    assert_eq!(public, body["public_identity"]);
    assert!(public.get("encrypted_bundle").is_none());
    assert_eq!(
        call(&mut accounts, &b, KeyOperation::Own, &Value::Null),
        Err(KeyError::NotFound)
    );
    let update = json!({"expected_bundle_revision":1,"encrypted_bundle":body["encrypted_bundle"]});
    assert_eq!(
        call(&mut accounts, &a, KeyOperation::UpdateBundle, &update).unwrap()["bundle_revision"],
        2
    );
    assert_eq!(
        call(&mut accounts, &a, KeyOperation::UpdateBundle, &update),
        Err(KeyError::Conflict)
    );
    let mut replacement = request(&deployment, &owner.id, 2);
    replacement["expected_bundle_revision"] = json!(2);
    replacement["expected_identity_version"] = json!(1);
    let replaced = call(&mut accounts, &a, KeyOperation::Replace, &replacement).unwrap();
    assert_eq!(replaced["bundle_revision"], 3);
    assert_eq!(
        call(&mut accounts, &a, KeyOperation::Replace, &replacement),
        Err(KeyError::Conflict)
    );
    assert_eq!(
        call(
            &mut accounts,
            &b,
            KeyOperation::Lookup(owner.id.clone()),
            &Value::Null
        )
        .unwrap(),
        replacement["public_identity"]
    );
    let changed = &accounts.groups().unwrap()[0];
    assert_eq!(
        changed.membership_generation,
        group.membership_generation + 2
    );
    assert!(changed.rotation_required);
    accounts
        .save_group(Some(&group.id), "Team", vec![])
        .unwrap();
    assert_eq!(
        call(
            &mut accounts,
            &b,
            KeyOperation::Lookup(owner.id.clone()),
            &Value::Null
        ),
        Err(KeyError::NotFound)
    );
    accounts.set_disabled(&owner, &outsider.id, true).unwrap();
    assert_eq!(
        call(&mut accounts, &c, KeyOperation::Deployment, &Value::Null),
        Err(KeyError::Unauthenticated)
    );
    accounts.logout(&a);
    assert_eq!(
        call(&mut accounts, &a, KeyOperation::Own, &Value::Null),
        Err(KeyError::Unauthenticated)
    );
    let disk = std::fs::read_to_string(path).unwrap();
    assert!(!disk.contains(PASSWORD));
    assert!(!disk.contains("synthetic local unlock phrase"));
}
#[test]
fn invalid_requests_and_storage_lock_preserve_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.json");
    let mut accounts = Accounts::new(path.clone());
    let user = accounts
        .create_user("owner", "Owner", PASSWORD.into(), true, true)
        .unwrap();
    let (token, _) = accounts.login("owner", PASSWORD.into()).unwrap();
    let deployment = call(
        &mut accounts,
        &token,
        KeyOperation::Deployment,
        &Value::Null,
    )
    .unwrap()["deployment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut body = request(&deployment, &user.id, 1);
    let before = std::fs::read(&path).unwrap();
    let duplicate = format!(
        "{{\"expected_bundle_revision\":0,{}",
        &body.to_string()[1..]
    );
    assert_eq!(
        accounts.key_operation(&token, KeyOperation::Enroll, duplicate.as_bytes()),
        Err(KeyError::Invalid)
    );
    body["encrypted_bundle"]["nonce"] = json!("invalid");
    assert_eq!(
        call(&mut accounts, &token, KeyOperation::Enroll, &body),
        Err(KeyError::Invalid)
    );
    assert_eq!(
        accounts.key_operation(&token, KeyOperation::Enroll, &vec![0; 128 * 1024 + 1]),
        Err(KeyError::TooLarge)
    );
    let _lock = petika_core::StoreFile::lock(&path).unwrap();
    assert_eq!(
        call(
            &mut accounts,
            &token,
            KeyOperation::Deployment,
            &Value::Null
        ),
        Err(KeyError::Unavailable)
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}
#[test]
fn schema_one_backup_retry_and_stable_deployment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.json");
    let old = br#"{"schema_version":1,"users":[],"groups":[]}"#;
    petika_core::StoreFile::lock(&path)
        .unwrap()
        .write(old, true)
        .unwrap();
    let backup = path.with_extension("schema-1.backup");
    petika_core::StoreFile::lock(&backup)
        .unwrap()
        .write(b"conflicting backup", true)
        .unwrap();
    let accounts = Accounts::new(path.clone());
    assert!(accounts.migrate().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), old);
    petika_core::StoreFile::lock(&backup)
        .unwrap()
        .write(old, false)
        .unwrap();
    accounts.migrate().unwrap();
    let migrated = std::fs::read(&path).unwrap();
    accounts.migrate().unwrap();
    assert_eq!(std::fs::read(path).unwrap(), migrated);
    assert_eq!(std::fs::read(backup).unwrap(), old);
}
