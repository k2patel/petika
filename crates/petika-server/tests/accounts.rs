use petika_server::accounts::{Accounts, Membership};

#[test]
fn identities_permissions_revocation_and_public_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    accounts.migrate().unwrap();
    let owner = accounts
        .create_user(
            "owner",
            "Owner",
            "owner synthetic password".into(),
            true,
            true,
        )
        .unwrap();
    assert!(
        accounts
            .create_user(
                "second",
                "Second",
                "another synthetic password".into(),
                true,
                true
            )
            .is_err()
    );
    let member = accounts
        .create_user(
            "member",
            "Member",
            "member synthetic password".into(),
            false,
            false,
        )
        .unwrap();
    assert!(
        accounts
            .login("member", "incorrect password".into())
            .is_err()
    );
    let (token, _) = accounts
        .login("member", "member synthetic password".into())
        .unwrap();
    assert!(accounts.authenticate(&token).unwrap().is_some());
    assert!(!accounts.access(&member, &owner.id, false).unwrap());
    let group = accounts
        .save_group(
            None,
            "Team",
            vec![Membership {
                user_id: member.id.clone(),
                edit: false,
            }],
        )
        .unwrap();
    assert!(accounts.access(&member, &group.id, false).unwrap());
    assert!(!accounts.access(&member, &group.id, true).unwrap());
    assert!(!accounts.access(&owner, &group.id, false).unwrap());
    accounts
        .save_group(
            Some(&group.id),
            "Team",
            vec![Membership {
                user_id: member.id.clone(),
                edit: true,
            }],
        )
        .unwrap();
    assert!(accounts.access(&member, &group.id, true).unwrap());
    accounts
        .save_group(Some(&group.id), "Team", vec![])
        .unwrap();
    assert!(!accounts.access(&member, &group.id, false).unwrap());
    assert!(accounts.set_disabled(&owner, &owner.id, true).is_err());
    accounts.set_disabled(&owner, &member.id, true).unwrap();
    assert!(accounts.authenticate(&token).unwrap().is_none());
    assert!(
        accounts
            .login("member", "member synthetic password".into())
            .is_err()
    );
    let public = serde_json::to_string(&accounts.users().unwrap()).unwrap();
    assert!(!public.contains("password_hash"));
    assert!(!public.contains("synthetic password"));
    let disk = std::fs::read_to_string(dir.path().join("accounts.json")).unwrap();
    assert!(!disk.contains("synthetic password"));
    assert!(disk.contains("\"schema_version\":2"));
}

#[test]
fn schema_upgrade_preserves_backup_and_rejects_future_versions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.json");
    let old = b"{\"users\":[],\"groups\":[]}";
    petika_core::StoreFile::lock(&path)
        .unwrap()
        .write(old, true)
        .unwrap();
    let accounts = Accounts::new(path.clone());
    accounts.migrate().unwrap();
    assert_eq!(
        std::fs::read(path.with_extension("schema-0.backup")).unwrap(),
        old
    );
    assert!(!accounts.initialized().unwrap());
    accounts.migrate().unwrap();
    let future = b"{\"schema_version\":999,\"users\":[],\"groups\":[]}";
    petika_core::StoreFile::lock(&path)
        .unwrap()
        .write(future, false)
        .unwrap();
    assert!(accounts.migrate().is_err());
    assert!(accounts.initialized().is_err());
    assert_eq!(std::fs::read(path).unwrap(), future);
}

#[test]
fn account_password_change_revokes_other_sessions_only() {
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    let owner = accounts
        .create_user(
            "owner",
            "Owner",
            "original synthetic password".into(),
            true,
            true,
        )
        .unwrap();
    let (current, _) = accounts
        .login("owner", "original synthetic password".into())
        .unwrap();
    let (other, _) = accounts
        .login("owner", "original synthetic password".into())
        .unwrap();
    assert!(
        accounts
            .change_password(
                &owner,
                "incorrect current password".into(),
                "new synthetic password".into(),
                &current
            )
            .is_err()
    );
    assert!(accounts.authenticate(&other).unwrap().is_some());
    accounts
        .change_password(
            &owner,
            "original synthetic password".into(),
            "new synthetic password".into(),
            &current,
        )
        .unwrap();
    assert!(accounts.authenticate(&current).unwrap().is_some());
    assert!(accounts.authenticate(&other).unwrap().is_none());
    assert!(
        accounts
            .login("owner", "original synthetic password".into())
            .is_err()
    );
    assert!(
        accounts
            .login("owner", "new synthetic password".into())
            .is_ok()
    );
}

#[test]
fn device_approval_is_single_use_and_revocable() {
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    let owner = accounts
        .create_user(
            "owner",
            "Owner",
            "synthetic owner password".into(),
            true,
            true,
        )
        .unwrap();
    let (browser, _) = accounts
        .login("owner", "synthetic owner password".into())
        .unwrap();
    let start = accounts.device_start().unwrap();
    let code = start["user_code"].as_str().unwrap();
    let device = start["device_code"].as_str().unwrap();
    assert!(
        accounts
            .device_approve(&browser, code, "wrong password".into(), true)
            .is_err()
    );
    accounts
        .device_approve(&browser, code, "synthetic owner password".into(), true)
        .unwrap();
    assert!(
        accounts
            .device_approve(&browser, code, "synthetic owner password".into(), true)
            .is_err()
    );
    let approved = accounts.device_poll(device).unwrap();
    let token = approved["token"].as_str().unwrap();
    assert_eq!(accounts.authenticate(token).unwrap().unwrap().id, owner.id);
    assert_eq!(accounts.device_poll(device).unwrap()["status"], "expired");
    let pending = accounts.device_start().unwrap();
    assert!(
        accounts
            .device_approve(
                token,
                pending["user_code"].as_str().unwrap(),
                "synthetic owner password".into(),
                true
            )
            .is_err()
    );
    accounts
        .change_password(
            &owner,
            "synthetic owner password".into(),
            "replacement synthetic password".into(),
            &browser,
        )
        .unwrap();
    assert!(accounts.authenticate(token).unwrap().is_none());
    accounts
        .device_approve(
            &browser,
            pending["user_code"].as_str().unwrap(),
            "replacement synthetic password".into(),
            true,
        )
        .unwrap();
    accounts.logout(&browser);
    assert_eq!(
        accounts
            .device_poll(pending["device_code"].as_str().unwrap())
            .unwrap()["status"],
        "expired_or_denied"
    );
}

#[test]
fn device_pending_denial_and_throttling() {
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    accounts
        .create_user(
            "owner",
            "Owner",
            "synthetic owner password".into(),
            true,
            true,
        )
        .unwrap();
    let (browser, _) = accounts
        .login("owner", "synthetic owner password".into())
        .unwrap();
    let pending = accounts.device_start().unwrap();
    let device = pending["device_code"].as_str().unwrap();
    assert_eq!(accounts.device_poll(device).unwrap()["status"], "pending");
    assert_eq!(accounts.device_poll(device).unwrap()["status"], "slow_down");
    accounts
        .device_approve(
            &browser,
            pending["user_code"].as_str().unwrap(),
            "synthetic owner password".into(),
            false,
        )
        .unwrap();
    assert_eq!(
        accounts.device_poll(device).unwrap()["status"],
        "expired_or_denied"
    );
    for _ in 0..29 {
        accounts.device_start().unwrap();
    }
    assert!(accounts.device_start().is_err());
}

#[test]
fn appearance_is_account_scoped_persistent_and_validated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.json");
    let accounts = Accounts::new(path.clone());
    accounts.migrate().unwrap();
    let first = accounts
        .create_user(
            "first",
            "First",
            "synthetic password one".into(),
            true,
            true,
        )
        .unwrap();
    let second = accounts
        .create_user(
            "second",
            "Second",
            "synthetic password two".into(),
            false,
            false,
        )
        .unwrap();
    assert_eq!(first.appearance, "system");
    accounts.appearance(&first, "dark").unwrap();
    accounts.profile(&first, "Renamed").unwrap();
    assert!(accounts.appearance(&first, "invalid").is_err());
    let mut reopened = Accounts::new(path.clone());
    assert_eq!(
        reopened
            .login("first", "synthetic password one".into())
            .unwrap()
            .1
            .appearance,
        "dark"
    );
    assert_eq!(
        reopened
            .login("second", "synthetic password two".into())
            .unwrap()
            .1
            .appearance,
        "system"
    );
    assert_eq!(
        reopened.appearance(&second, "light").unwrap().appearance,
        "light"
    );
    assert_eq!(
        reopened.appearance(&first, "system").unwrap().appearance,
        "system"
    );
    // Existing account databases without a preference retain System appearance.
    let mut old: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for user in old["users"].as_array_mut().unwrap() {
        user.as_object_mut().unwrap().remove("appearance");
    }
    std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
    assert_eq!(
        reopened
            .login("first", "synthetic password one".into())
            .unwrap()
            .1
            .appearance,
        "system"
    );
}

#[test]
fn clients_and_website_permissions_are_user_scoped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.json");
    let mut accounts = Accounts::new(path.clone());
    accounts.migrate().unwrap();
    let first = accounts
        .create_user(
            "first",
            "First",
            "synthetic password one".into(),
            true,
            true,
        )
        .unwrap();
    let second = accounts
        .create_user(
            "second",
            "Second",
            "synthetic password two".into(),
            false,
            false,
        )
        .unwrap();
    let (token, _) = accounts
        .login("first", "synthetic password one".into())
        .unwrap();
    let (other_token, _) = accounts
        .login("first", "synthetic password one".into())
        .unwrap();
    let (second_token, _) = accounts
        .login("second", "synthetic password two".into())
        .unwrap();
    let clients = accounts.clients(&first, &token);
    assert_eq!(clients.len(), 2);
    assert_eq!(accounts.clients(&second, &second_token).len(), 1);
    let encoded = serde_json::to_string(&clients).unwrap();
    assert!(!encoded.contains(&token));
    assert!(!encoded.contains(&other_token));
    assert!(!encoded.contains(&second_token));
    let other_id = clients.iter().find(|c| c["current"] == false).unwrap()["id"]
        .as_str()
        .unwrap();
    assert!(accounts.revoke_client(&second, other_id).is_err());
    accounts.revoke_client(&first, other_id).unwrap();
    assert!(accounts.authenticate(&other_token).unwrap().is_none());
    assert!(accounts.authenticate(&token).unwrap().is_some());
    assert!(accounts.authenticate(&second_token).unwrap().is_some());
    assert_eq!(
        accounts
            .website_permission(&first, "https://EXAMPLE.com:443/", true)
            .unwrap(),
        vec!["https://example.com"]
    );
    assert_eq!(
        accounts
            .website_permission(&first, "https://example.com", true)
            .unwrap()
            .len(),
        1
    );
    assert!(accounts.website_permissions(&second).unwrap().is_empty());
    for invalid in [
        "http://example.com",
        "https://*.example.com",
        "https://example.com/login",
        "https://user:pass@example.com",
        "https://example.com?x=y",
        "https://example.com/#secret",
    ] {
        assert!(
            accounts.website_permission(&first, invalid, true).is_err(),
            "{invalid}"
        );
    }
    assert_eq!(
        Accounts::new(path).website_permissions(&first).unwrap(),
        vec!["https://example.com"]
    );
    assert!(
        accounts
            .website_permission(&first, "https://example.com", false)
            .unwrap()
            .is_empty()
    );
}
