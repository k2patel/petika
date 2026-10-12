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
    assert!(disk.contains("\"schema_version\":1"));
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
