use petika_core::{EncryptionMode, UnlockedStore};
use petika_server::{
    Repository,
    accounts::{Accounts, KeyError, Membership},
};
use serde_json::{Value, json};

const PASSWORD: &str = "synthetic account password";
fn key(accounts: &mut Accounts, session: &str) -> Value {
    accounts
        .backup_manage(
            session,
            false,
            "POST",
            "keys",
            json!({
                "name":"Off-site runner", "expires_in_days":30, "current_password":PASSWORD
            }),
        )
        .unwrap()
}
#[test]
fn backup_keys_are_read_only_user_scoped_durable_and_revocable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.json");
    let mut accounts = Accounts::new(path.clone());
    accounts.migrate().unwrap();
    let alice = accounts
        .create_user("alice", "Alice", PASSWORD.into(), true, true)
        .unwrap();
    let bob = accounts
        .create_user("bob", "Bob", PASSWORD.into(), false, false)
        .unwrap();
    let (a, _) = accounts.login("alice", PASSWORD.into()).unwrap();
    let (b, _) = accounts.login("bob", PASSWORD.into()).unwrap();
    let shared = accounts
        .save_group(
            None,
            "Shared",
            vec![
                Membership {
                    user_id: alice.id.clone(),
                    edit: true,
                },
                Membership {
                    user_id: bob.id.clone(),
                    edit: false,
                },
            ],
        )
        .unwrap();
    let secret_group = accounts
        .save_group(
            None,
            "Bob only",
            vec![Membership {
                user_id: bob.id.clone(),
                edit: true,
            }],
        )
        .unwrap();
    let created = key(&mut accounts, &a);
    let token = created["token"].as_str().unwrap();
    let id = created["key"]["id"].as_str().unwrap();
    let bytes = std::fs::read_to_string(dir.path().join("backups.json")).unwrap();
    assert!(!bytes.contains(token));
    assert!(!bytes.contains(PASSWORD));
    assert!(accounts.authenticate(token).unwrap().is_none());
    assert!(matches!(
        accounts.backup_manage(token, false, "GET", "keys", Value::Null),
        Err(KeyError::Unauthenticated)
    ));
    let index = accounts.backup_export(token, None).unwrap();
    assert_eq!(index["user"]["id"], alice.id);
    assert_eq!(index["collections"].as_array().unwrap().len(), 2);
    assert!(!index.to_string().contains("password_hash"));
    for id in [&bob.id, &secret_group.id] {
        assert!(matches!(
            accounts.backup_export(token, Some(id)),
            Err(KeyError::Forbidden)
        ));
        for part in [vec!["manifest"], vec!["entries", "head", "id", "digest"]] {
            assert!(matches!(
                accounts.backup_part(token, id, &part),
                Err(KeyError::Forbidden)
            ));
        }
    }
    assert!(matches!(
        accounts.backup_export(token, Some("../accounts.json")),
        Err(KeyError::NotFound)
    ));
    for mode in [EncryptionMode::Standard, EncryptionMode::HybridPostQuantum] {
        let mut vault =
            UnlockedStore::create_with_mode("synthetic vault passphrase", mode).unwrap();
        let encrypted = String::from_utf8(vault.seal().unwrap()).unwrap();
        let repository = Repository::new(
            dir.path()
                .join("collections")
                .join(&shared.id)
                .join("snapshot.json"),
        );
        let revision = repository.read().unwrap().map_or(0, |s| s.revision);
        repository.update(revision, encrypted).unwrap();
        let backup = accounts.backup_export(token, Some(&shared.id)).unwrap();
        assert_eq!(
            accounts
                .backup_part(token, &shared.id, &["manifest"])
                .unwrap(),
            backup
        );
        UnlockedStore::open(
            backup["snapshot"]["encrypted"].as_str().unwrap().as_bytes(),
            "synthetic vault passphrase",
        )
        .unwrap();
        assert!(backup.get("transactions").is_none());
    }
    // Admin is still denied group data immediately after membership removal.
    accounts
        .save_group(
            Some(&shared.id),
            "Shared",
            vec![Membership {
                user_id: bob.id.clone(),
                edit: true,
            }],
        )
        .unwrap();
    assert!(matches!(
        accounts.backup_export(token, Some(&shared.id)),
        Err(KeyError::Forbidden)
    ));
    assert!(matches!(
        accounts.backup_part(token, &shared.id, &["manifest"]),
        Err(KeyError::Forbidden)
    ));
    assert!(matches!(
        accounts.backup_manage(&b, false, "DELETE", &format!("keys/{id}"), Value::Null),
        Err(KeyError::NotFound)
    ));
    let restarted = Accounts::new(path);
    assert!(restarted.backup_export(token, None).is_ok());
    accounts
        .backup_manage(&a, false, "DELETE", &format!("keys/{id}"), Value::Null)
        .unwrap();
    assert!(matches!(
        restarted.backup_export(token, None),
        Err(KeyError::Unauthenticated)
    ));
    assert!(matches!(
        restarted.backup_part(token, &alice.id, &["manifest"]),
        Err(KeyError::Unauthenticated)
    ));
}

#[test]
fn destinations_have_separate_user_and_operator_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    accounts.migrate().unwrap();
    accounts
        .create_user("alice", "Alice", PASSWORD.into(), true, true)
        .unwrap();
    accounts
        .create_user("bob", "Bob", PASSWORD.into(), false, false)
        .unwrap();
    let (a, _) = accounts.login("alice", PASSWORD.into()).unwrap();
    let (b, _) = accounts.login("bob", PASSWORD.into()).unwrap();
    let payload = json!({"name":"S3 backup", "kind":"s3", "repository":"s3:https://s3.example.com/private-bucket/petika"});
    let saved = accounts
        .backup_manage(&a, false, "POST", "destinations", payload.clone())
        .unwrap();
    accounts
        .backup_manage(&a, true, "POST", "destinations", payload)
        .unwrap();
    let ssh = json!({"name":"SSH backup", "kind":"sftp", "repository":"sftp://backup@host.example//srv/petika"});
    accounts
        .backup_manage(&a, false, "POST", "destinations", ssh)
        .unwrap();
    assert!(
        accounts
            .backup_manage(&b, true, "GET", "destinations", Value::Null)
            .is_err()
    );
    assert_eq!(
        accounts
            .backup_manage(&b, false, "GET", "destinations", Value::Null)
            .unwrap()["destinations"],
        json!([])
    );
    assert!(
        accounts
            .backup_manage(
                &b,
                false,
                "DELETE",
                &format!("destinations/{}", saved["id"].as_str().unwrap()),
                Value::Null
            )
            .is_err()
    );
    for repository in [
        "s3:http://host/bucket",
        "s3:https://key:secret@host/bucket",
        "s3:https://host/bucket?secret=hello",
    ] {
        assert!(
            accounts
                .backup_manage(
                    &a,
                    false,
                    "POST",
                    "destinations",
                    json!({"name":"bad","kind":"s3","repository":repository})
                )
                .is_err()
        );
    }
    let mut payload = json!({"name":"bad","kind":"s3","repository":"s3:https://host/bucket"});
    payload["secret_key"] = json!("must not be accepted");
    assert!(
        accounts
            .backup_manage(&a, false, "POST", "destinations", payload)
            .is_err()
    );
    let generated = key(&mut accounts, &a);
    assert_eq!(
        accounts
            .backup_export(generated["token"].as_str().unwrap(), None)
            .unwrap()["destinations"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn expiry_password_changes_and_disabled_accounts_invalidate_backup_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.json");
    let mut accounts = Accounts::new(path);
    accounts.migrate().unwrap();
    let admin = accounts
        .create_user("alice", "Alice", PASSWORD.into(), true, true)
        .unwrap();
    let bob = accounts
        .create_user("bob", "Bob", PASSWORD.into(), false, false)
        .unwrap();
    let (a, _) = accounts.login("alice", PASSWORD.into()).unwrap();
    let (b, _) = accounts.login("bob", PASSWORD.into()).unwrap();
    assert!(
        accounts
            .backup_manage(
                &a,
                false,
                "POST",
                "keys",
                json!({"name":"bad","expires_in_days":366,"current_password":PASSWORD})
            )
            .is_err()
    );
    assert!(
        accounts
            .backup_manage(
                &a,
                false,
                "POST",
                "keys",
                json!({"name":"bad","expires_in_days":30,"current_password":"wrong"})
            )
            .is_err()
    );
    let one = key(&mut accounts, &b);
    accounts.set_disabled(&admin, &bob.id, true).unwrap();
    assert!(
        accounts
            .backup_export(one["token"].as_str().unwrap(), None)
            .is_err()
    );
    accounts.set_disabled(&admin, &bob.id, false).unwrap();
    assert!(
        accounts
            .backup_export(one["token"].as_str().unwrap(), None)
            .is_err()
    );
    let two = key(&mut accounts, &a);
    accounts
        .change_password(
            &admin,
            PASSWORD.into(),
            "different synthetic password".into(),
            &a,
        )
        .unwrap();
    assert!(
        accounts
            .backup_export(two["token"].as_str().unwrap(), None)
            .is_err()
    );
    // Validly encoded persisted expiry in the past is denied after restart too.
    let (b, _) = accounts.login("bob", PASSWORD.into()).unwrap();
    let three = key(&mut accounts, &b);
    let file = petika_core::StoreFile::lock(dir.path().join("backups.json")).unwrap();
    let mut db: Value = serde_json::from_slice(&file.read().unwrap()).unwrap();
    for key in db["keys"].as_array_mut().unwrap() {
        key["created_at"] = json!(1);
        key["expires_at"] = json!(2);
    }
    file.write(&serde_json::to_vec(&db).unwrap(), false)
        .unwrap();
    drop(file);
    assert!(
        accounts
            .backup_export(three["token"].as_str().unwrap(), None)
            .is_err()
    );
}

#[test]
fn push_credentials_are_sealed_and_never_returned_and_blank_updates_preserve_them() {
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    accounts.migrate().unwrap();
    accounts
        .create_user("alice", "Alice", PASSWORD.into(), true, true)
        .unwrap();
    let (session, _) = accounts.login("alice", PASSWORD.into()).unwrap();
    let payload = json!({"name":"S3","kind":"s3","repository":"s3:https://offsite.example/bucket",
        "enabled":true,"interval_hours":24,"initialize_repository":true,
        "credentials":{"repository_password":"synthetic repository password","access_key":"synthetic-access-key","secret_key":"synthetic-secret-key"}});
    let result = accounts
        .backup_manage(&session, false, "POST", "destinations", payload)
        .unwrap();
    assert_eq!(result["credentials_configured"], true);
    assert!(result.get("credentials").is_none());
    assert!(result.get("push").is_none());
    let disk = std::fs::read_to_string(dir.path().join("backups.json")).unwrap();
    for secret in [
        "synthetic repository password",
        "synthetic-access-key",
        "synthetic-secret-key",
    ] {
        assert!(!disk.contains(secret));
    }
    assert_eq!(
        std::fs::read(dir.path().join("backup-master.key"))
            .unwrap()
            .len(),
        32
    );
    let updated=accounts.backup_manage(&session,false,"POST","destinations",json!({"id":result["id"],"name":"Renamed","kind":"s3","repository":"s3:https://offsite.example/bucket"})).unwrap();
    assert_eq!(updated["credentials_configured"], true);
    let api_key = key(&mut accounts, &session);
    let index = accounts
        .backup_export(api_key["token"].as_str().unwrap(), None)
        .unwrap();
    assert!(index["destinations"][0].get("push").is_none());
    assert!(!index.to_string().contains("synthetic-secret-key"));
    let changed=accounts.backup_manage(&session,false,"POST","destinations",json!({"id":result["id"],"name":"Other bucket","kind":"s3","repository":"s3:https://different.example/bucket"})).unwrap();
    assert_eq!(changed["credentials_configured"], false);
    assert_eq!(changed["enabled"], false);
    assert!(
        accounts
            .backup_manage(
                &session,
                false,
                "POST",
                &format!("destinations/{}/run", result["id"].as_str().unwrap()),
                json!({})
            )
            .is_err()
    );
}
