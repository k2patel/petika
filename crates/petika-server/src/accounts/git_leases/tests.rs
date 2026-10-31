use super::*;
use crate::accounts::device_keys::tests::Fixture;
use crate::git_key_leases::registration::tests::{FakeHost, ssh_public, ssh_seed};
use petika_core::device_keys::{DeviceIdentity, TrustedDeviceRoster};
const PASSWORD: &str = "synthetic device account password";
fn fixture() -> (Fixture, DeviceIdentity, TrustedDeviceRoster, FakeHost) {
    let mut f = Fixture::new();
    f.initialize().unwrap();
    let device = DeviceIdentity::generate(
        &f.bootstrap.legacy_identity.deployment_id,
        &f.bootstrap.legacy_identity.user_id,
    )
    .unwrap();
    let roster = f
        .authority
        .sign_roster(
            2,
            f.bootstrap.initial_roster.digest().unwrap(),
            vec![device.public_record().unwrap()],
            vec![],
        )
        .unwrap();
    f.publish(&"1".repeat(64), &roster).unwrap();
    let current = f.pin(&roster);
    f.accounts.lease_cleanup = true;
    let mut host = FakeHost::new();
    host.allowed_user = Some(f.bootstrap.legacy_identity.user_id.clone());
    host.ledger_path = Some(
        f.accounts
            .path
            .parent()
            .unwrap()
            .join("git-key-leases.json"),
    );
    (f, device, current, host)
}
fn request(device: &DeviceIdentity) -> Value {
    json!({"current_password":PASSWORD,"operation_id":"d".repeat(64),"device_id":device.public_record().unwrap().device_id,
        "repository":{"provider":"gitea","management_origin":"https://git.example/","repository":"synthetic/vault"},
        "ssh_public_key":ssh_public(),"read_only":true,"ttl":300})
}
fn run(
    f: &mut Fixture,
    operation: GitLeaseOperation,
    body: Value,
    host: &mut FakeHost,
    now: u64,
) -> Result<Value> {
    f.accounts.git_lease_operation_with(
        &f.token,
        operation,
        &serde_json::to_vec(&body).unwrap(),
        host,
        now,
    )
}
#[test]
fn admitted_device_and_ssh_proof_register_once_status_and_completion_cleanup_work() {
    let (mut f, device, current, mut host) = fixture();
    let context = run(
        &mut f,
        GitLeaseOperation::Context,
        Value::Null,
        &mut host,
        100,
    )
    .unwrap();
    assert_eq!(context["user_id"], f.bootstrap.legacy_identity.user_id);
    assert_eq!(
        context["deployment_id"],
        f.bootstrap.legacy_identity.deployment_id
    );
    assert!(valid_id(context["session_id"].as_str().unwrap()));
    let input = request(&device);
    let response = run(
        &mut f,
        GitLeaseOperation::Challenge,
        input.clone(),
        &mut host,
        100,
    )
    .unwrap();
    let challenge: GitLeaseChallenge =
        serde_json::from_value(response["challenge"].clone()).unwrap();
    assert_eq!(
        run(&mut f, GitLeaseOperation::Challenge, input, &mut host, 101).unwrap(),
        response
    );
    let found = run(
        &mut f,
        GitLeaseOperation::LookupOperation(challenge.operation_id.clone()),
        Value::Null,
        &mut host,
        101,
    )
    .unwrap();
    assert_eq!(found["lease_id"], challenge.lease_id);
    assert_eq!(found["state"], "pending_registration");
    assert_eq!(
        found["challenge"],
        serde_json::to_value(&challenge).unwrap()
    );
    // Public metadata dispatcher must work without loading host credentials.
    assert_eq!(
        f.accounts
            .git_lease_operation(&f.token, GitLeaseOperation::Context, &[])
            .unwrap(),
        context
    );
    assert_eq!(
        f.accounts
            .git_lease_operation(
                &f.token,
                GitLeaseOperation::LookupOperation(challenge.operation_id.clone()),
                &[]
            )
            .unwrap(),
        found
    );
    assert_eq!(
        f.accounts
            .git_lease_operation("invalid synthetic token", GitLeaseOperation::Context, &[]),
        Err(KeyError::Unauthenticated)
    );
    assert_eq!(
        run(
            &mut f,
            GitLeaseOperation::LookupOperation("invalid".into()),
            Value::Null,
            &mut host,
            101
        ),
        Err(KeyError::Invalid)
    );
    let proof = device
        .authorize_git_lease(
            challenge.clone(),
            &current,
            "https://git.example/",
            "synthetic/vault",
            &ssh_seed(),
            101,
        )
        .unwrap();
    let body = json!({"current_password":PASSWORD,"proof":proof});
    let result = run(
        &mut f,
        GitLeaseOperation::Register,
        body.clone(),
        &mut host,
        101,
    )
    .unwrap();
    assert_eq!(result["state"], "active");
    run(&mut f, GitLeaseOperation::Register, body, &mut host, 102).unwrap();
    assert_eq!(host.creates, 1);
    assert_eq!(
        run(
            &mut f,
            GitLeaseOperation::Status(challenge.lease_id.clone()),
            Value::Null,
            &mut host,
            102
        )
        .unwrap()["state"],
        "active"
    );
    run(
        &mut f,
        GitLeaseOperation::Complete(challenge.lease_id.clone()),
        json!({}),
        &mut host,
        103,
    )
    .unwrap();
    LeaseStore::lock(
        f.accounts
            .path
            .parent()
            .unwrap()
            .join("git-key-leases.json"),
    )
    .unwrap()
    .sweep(104, &mut host)
    .unwrap();
    assert!(host.keys.is_empty());
    assert_eq!(
        run(
            &mut f,
            GitLeaseOperation::Status(challenge.lease_id),
            Value::Null,
            &mut host,
            104
        )
        .unwrap()["state"],
        "removed"
    );
}
#[test]
fn wrong_password_unadmitted_device_scope_write_and_expired_proof_cannot_issue() {
    let (mut f, device, current, mut host) = fixture();
    let mut body = request(&device);
    body["current_password"] = json!("incorrect synthetic password");
    assert_eq!(
        run(&mut f, GitLeaseOperation::Challenge, body, &mut host, 100),
        Err(KeyError::Unauthenticated)
    );
    let mut body = request(&device);
    body["device_id"] = json!("f".repeat(64));
    assert_eq!(
        run(&mut f, GitLeaseOperation::Challenge, body, &mut host, 100),
        Err(KeyError::Forbidden)
    );
    let mut body = request(&device);
    body["repository"]["repository"] = json!("other/vault");
    assert_eq!(
        run(&mut f, GitLeaseOperation::Challenge, body, &mut host, 100),
        Err(KeyError::Forbidden)
    );
    let mut body = request(&device);
    body["read_only"] = json!(false);
    assert_eq!(
        run(&mut f, GitLeaseOperation::Challenge, body, &mut host, 100),
        Err(KeyError::Forbidden)
    );
    let response = run(
        &mut f,
        GitLeaseOperation::Challenge,
        request(&device),
        &mut host,
        100,
    )
    .unwrap();
    let challenge: GitLeaseChallenge =
        serde_json::from_value(response["challenge"].clone()).unwrap();
    let proof = device
        .authorize_git_lease(
            challenge,
            &current,
            "https://git.example/",
            "synthetic/vault",
            &ssh_seed(),
            101,
        )
        .unwrap();
    assert_eq!(
        run(
            &mut f,
            GitLeaseOperation::Register,
            json!({"current_password":PASSWORD,"proof":proof}),
            &mut host,
            160
        ),
        Err(KeyError::Forbidden)
    );
    assert_eq!(host.creates, 0);
}
#[test]
fn proof_cannot_move_to_another_session_or_a_changed_roster() {
    let (mut f, device, current, mut host) = fixture();
    let response = run(
        &mut f,
        GitLeaseOperation::Challenge,
        request(&device),
        &mut host,
        100,
    )
    .unwrap();
    let challenge: GitLeaseChallenge =
        serde_json::from_value(response["challenge"].clone()).unwrap();
    let proof = device
        .authorize_git_lease(
            challenge.clone(),
            &current,
            "https://git.example/",
            "synthetic/vault",
            &ssh_seed(),
            101,
        )
        .unwrap();
    let original = f.token.clone();
    f.token = f.accounts.login("owner", PASSWORD.into()).unwrap().0;
    assert_eq!(
        run(
            &mut f,
            GitLeaseOperation::Register,
            json!({"current_password":PASSWORD,"proof":proof}),
            &mut host,
            101
        ),
        Err(KeyError::Conflict)
    );
    assert_eq!(
        run(
            &mut f,
            GitLeaseOperation::Status(challenge.lease_id.clone()),
            Value::Null,
            &mut host,
            101
        ),
        Err(KeyError::NotFound)
    );
    assert_eq!(
        run(
            &mut f,
            GitLeaseOperation::LookupOperation(challenge.operation_id.clone()),
            Value::Null,
            &mut host,
            101
        ),
        Err(KeyError::NotFound)
    );
    f.token = original;
    let next = f.candidate(current.roster());
    f.publish(&"2".repeat(64), &next).unwrap();
    assert_eq!(
        run(
            &mut f,
            GitLeaseOperation::Register,
            json!({"current_password":PASSWORD,"proof":proof}),
            &mut host,
            102
        ),
        Err(KeyError::Forbidden)
    );
    assert_eq!(host.creates, 0);
}
#[test]
fn disabled_registration_gate_and_oversized_or_unknown_fields_are_rejected() {
    let (mut f, device, _, mut host) = fixture();
    f.accounts.lease_cleanup = false;
    assert_eq!(
        run(
            &mut f,
            GitLeaseOperation::Challenge,
            request(&device),
            &mut host,
            100
        ),
        Err(KeyError::NotFound)
    );
    f.accounts.lease_cleanup = true;
    let mut body = request(&device);
    body["private_key"] = json!("prohibited");
    assert_eq!(
        run(&mut f, GitLeaseOperation::Challenge, body, &mut host, 100),
        Err(KeyError::Invalid)
    );
    assert_eq!(
        f.accounts.git_lease_operation_with(
            &f.token,
            GitLeaseOperation::Challenge,
            &vec![b' '; 16385],
            &mut host,
            100
        ),
        Err(KeyError::TooLarge)
    );
}
