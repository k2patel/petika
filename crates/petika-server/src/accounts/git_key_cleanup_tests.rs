use super::*;
fn fixture() -> (tempfile::TempDir, Accounts, String, User) {
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    accounts.lease_cleanup = true;
    let user = accounts
        .create_user(
            "owner",
            "Owner",
            "synthetic event password".into(),
            true,
            true,
        )
        .unwrap();
    let token = accounts
        .login("owner", "synthetic event password".into())
        .unwrap()
        .0;
    (dir, accounts, token, user)
}
fn pending(dir: &std::path::Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(dir.join("git-key-events.json")).unwrap()).unwrap()
}
#[test]
fn logout_expiry_and_client_revocation_queue_non_bearer_session_ids() {
    let (dir, mut accounts, token, user) = fixture();
    let id = accounts.sessions[&token].id.clone();
    accounts.revoke_client(&user, &id).unwrap();
    assert!(!accounts.sessions.contains_key(&token));
    let value = pending(dir.path());
    assert_eq!(value["pending"][0]["session"], id);
    assert!(!value.to_string().contains(&token));
    let token = accounts
        .login("owner", "synthetic event password".into())
        .unwrap()
        .0;
    accounts.sessions.get_mut(&token).unwrap().expires = Instant::now() - Duration::from_secs(1);
    assert!(accounts.authenticate(&token).unwrap().is_none());
    assert_eq!(pending(dir.path())["pending"].as_array().unwrap().len(), 2);
}
#[test]
fn event_failure_prevents_false_logout_success_and_keeps_session_for_retry() {
    let (dir, mut accounts, token, _) = fixture();
    std::fs::write(dir.path().join("git-key-events.json"), b"{").unwrap();
    assert!(accounts.logout(&token).is_err());
    assert!(accounts.sessions.contains_key(&token));
}
#[test]
fn password_change_queues_other_sessions_and_preserves_current_session() {
    let (dir, mut accounts, token, user) = fixture();
    let other = accounts
        .login("owner", "synthetic event password".into())
        .unwrap()
        .0;
    let id = accounts.sessions[&other].id.clone();
    accounts
        .change_password(
            &user,
            "synthetic event password".into(),
            "synthetic replacement password".into(),
            &token,
        )
        .unwrap();
    assert!(accounts.sessions.contains_key(&token));
    assert!(!accounts.sessions.contains_key(&other));
    assert_eq!(pending(dir.path())["pending"][0]["session"], id);
}

#[test]
fn disabling_account_queues_all_its_sessions() {
    let (dir, mut accounts, _, actor) = fixture();
    let user = accounts
        .create_user(
            "other",
            "Other",
            "synthetic event password".into(),
            false,
            false,
        )
        .unwrap();
    let token = accounts
        .login("other", "synthetic event password".into())
        .unwrap()
        .0;
    let id = accounts.sessions[&token].id.clone();
    accounts.set_disabled(&actor, &user.id, true).unwrap();
    assert!(!accounts.sessions.contains_key(&token));
    assert_eq!(pending(dir.path())["pending"][0]["session"], id);
}
