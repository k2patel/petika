use super::*;
use crate::accounts::KeyOperation;
use petika_core::{
    device_keys::{DeviceAuthorityKey, DeviceIdentity, PublicationReceipt},
    identity::UnlockedIdentity,
};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

const PASSWORD: &str = "synthetic device account password";

#[test]
fn later_legacy_identity_replacement_cannot_replace_the_committed_authority() {
    let mut f = Fixture::new();
    f.initialize().unwrap();
    let old = f.bootstrap.legacy_identity.clone();
    let replacement = UnlockedIdentity::generate(&old.deployment_id, &old.user_id, 2).unwrap();
    let sealed: Value = serde_json::from_slice(
        &replacement
            .seal("synthetic replacement unlock password")
            .unwrap(),
    )
    .unwrap();
    f.accounts.key_operation(&f.token, KeyOperation::Replace, &serde_json::to_vec(&json!({
        "current_password":PASSWORD,"expected_bundle_revision":1,"expected_identity_version":1,
        "public_identity":sealed["public_identity"],"encrypted_bundle":sealed["encrypted_bundle"]
    })).unwrap()).unwrap();
    // A committed root is independent of later legacy password/identity operations.
    f.initialize().unwrap();
    let authority = DeviceAuthorityKey::generate(&old.deployment_id, &old.user_id).unwrap();
    let initial = authority
        .sign_roster(1, String::new(), vec![], vec![])
        .unwrap();
    let bootstrap = replacement
        .authorize_device_authority(initial.clone(), 2, &initial.authority.fingerprint)
        .unwrap();
    assert_eq!(
        f.run(
            DeviceKeyOperation::Initialize,
            json!({"current_password":PASSWORD,"bootstrap":bootstrap})
        ),
        Err(KeyError::Conflict)
    );
    let candidate = f.candidate(&f.bootstrap.initial_roster);
    f.publish(&"1".repeat(64), &candidate).unwrap();
}
struct Fixture {
    _directory: tempfile::TempDir,
    accounts: Accounts,
    token: String,
    identity: UnlockedIdentity,
    authority: DeviceAuthorityKey,
    bootstrap: DeviceAuthorityBootstrap,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut accounts = Accounts::new(directory.path().join("accounts.json"));
        let user = accounts
            .create_user("owner", "Owner", PASSWORD.into(), true, true)
            .unwrap();
        let (token, _) = accounts.login("owner", PASSWORD.into()).unwrap();
        let deployment = accounts
            .key_operation(&token, KeyOperation::Deployment, &[])
            .unwrap();
        let deployment = deployment["deployment_id"].as_str().unwrap();
        let identity = UnlockedIdentity::generate(deployment, &user.id, 1).unwrap();
        let sealed: Value =
            serde_json::from_slice(&identity.seal("synthetic private unlock password").unwrap())
                .unwrap();
        accounts.key_operation(&token, KeyOperation::Enroll, &serde_json::to_vec(&json!({
            "current_password":PASSWORD,"expected_bundle_revision":0,
            "public_identity":sealed["public_identity"],"encrypted_bundle":sealed["encrypted_bundle"]
        })).unwrap()).unwrap();
        let authority = DeviceAuthorityKey::generate(deployment, &user.id).unwrap();
        let roster = authority
            .sign_roster(1, String::new(), vec![], vec![])
            .unwrap();
        let bootstrap = identity
            .authorize_device_authority(roster.clone(), 1, &roster.authority.fingerprint)
            .unwrap();
        Self {
            _directory: directory,
            accounts,
            token,
            identity,
            authority,
            bootstrap,
        }
    }
    fn run(&mut self, operation: DeviceKeyOperation, body: Value) -> Result<Value> {
        self.accounts.device_key_operation(
            &self.token,
            operation,
            &serde_json::to_vec(&body).unwrap(),
        )
    }
    fn initialize(&mut self) -> Result<Value> {
        self.run(
            DeviceKeyOperation::Initialize,
            json!({"current_password":PASSWORD,"bootstrap":self.bootstrap}),
        )
    }
    fn publish(&mut self, id: &str, candidate: &DeviceRoster) -> Result<Value> {
        self.run(DeviceKeyOperation::Publish, json!({"current_password":PASSWORD,"operation_id":id,"expected_parent":candidate.parent_digest,"roster":candidate}))
    }
    fn pin(&self, roster: &DeviceRoster) -> TrustedDeviceRoster {
        TrustedDeviceRoster::bootstrap(
            roster.clone(),
            &roster.authority.fingerprint,
            &roster.digest().unwrap(),
        )
        .unwrap()
    }
    fn candidate(&self, roster: &DeviceRoster) -> DeviceRoster {
        let current = self.pin(roster);
        let device =
            DeviceIdentity::generate(&roster.authority.deployment_id, &roster.authority.user_id)
                .unwrap();
        let request = device.enrollment_request(&current, 100).unwrap();
        let fingerprint = request.device.fingerprint.clone();
        let mut pending = self
            .authority
            .challenge_enrollment(request, &current, &fingerprint, 101)
            .unwrap();
        let proof = device
            .answer_enrollment(
                pending.challenge(),
                &current,
                &roster.authority.fingerprint,
                102,
            )
            .unwrap();
        pending
            .approve(&self.authority, &proof, &current, &fingerprint, 103)
            .unwrap()
    }
    fn path(&self, name: &str) -> PathBuf {
        self.accounts
            .device_key_directory(&self.bootstrap.legacy_identity.user_id)
            .join(name)
    }
}

#[test]
fn authenticated_enrollment_history_and_historical_retry_survive_restart() {
    let mut f = Fixture::new();
    assert_eq!(
        f.run(DeviceKeyOperation::Own, Value::Null),
        Err(KeyError::NotFound)
    );
    f.initialize().unwrap();
    let first = f.candidate(&f.bootstrap.initial_roster);
    let first_response = f.publish(&"1".repeat(64), &first).unwrap();
    let receipt: PublicationReceipt =
        serde_json::from_value(first_response["receipt"].clone()).unwrap();
    receipt.verify_candidate(&"1".repeat(64), &first).unwrap();
    let second = f.candidate(&first);
    f.publish(&"2".repeat(64), &second).unwrap();
    assert_eq!(f.publish(&"1".repeat(64), &first).unwrap(), first_response);
    assert_eq!(
        f.run(DeviceKeyOperation::Receipt("1".repeat(64)), Value::Null)
            .unwrap(),
        first_response
    );
    assert_eq!(
        f.run(DeviceKeyOperation::Receipt("3".repeat(64)), Value::Null),
        Err(KeyError::NotFound)
    );
    let history = f
        .run(
            DeviceKeyOperation::History(f.bootstrap.initial_roster.digest().unwrap()),
            Value::Null,
        )
        .unwrap();
    let mut pin = f.pin(&f.bootstrap.initial_roster);
    for roster in serde_json::from_value::<Vec<DeviceRoster>>(history["rosters"].clone()).unwrap() {
        pin.accept(roster).unwrap();
    }
    assert_eq!(pin.roster(), &second);
    assert_eq!(history["head_digest"], second.digest().unwrap());
    assert_eq!(
        f.run(DeviceKeyOperation::History("f".repeat(64)), Value::Null),
        Err(KeyError::Conflict)
    );
    let path = f.accounts.path.clone();
    f.accounts = Accounts::new(path);
    f.token = f.accounts.login("owner", PASSWORD.into()).unwrap().0;
    assert_eq!(
        f.run(DeviceKeyOperation::Own, Value::Null).unwrap()["roster"],
        json!(second)
    );
    assert_eq!(f.initialize().unwrap()["roster"], json!(second));
    assert_eq!(f.publish(&"1".repeat(64), &first).unwrap(), first_response);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["bootstrap.json", "roster.json"] {
            assert_eq!(
                fs::metadata(f.path(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    let stored = fs::read_to_string(f.path("bootstrap.json")).unwrap();
    assert!(!stored.contains(PASSWORD));
    assert!(!stored.contains("encrypted_bundle"));
}

#[test]
fn bootstrap_checks_password_current_identity_revision_signature_and_scope() {
    let mut f = Fixture::new();
    assert_eq!(
        f.run(
            DeviceKeyOperation::Initialize,
            json!({"current_password":"incorrect synthetic password","bootstrap":f.bootstrap})
        ),
        Err(KeyError::Unauthenticated)
    );
    let mut changed = f.bootstrap.clone();
    changed.source_bundle_revision += 1;
    assert_eq!(
        f.run(
            DeviceKeyOperation::Initialize,
            json!({"current_password":PASSWORD,"bootstrap":changed})
        ),
        Err(KeyError::Invalid)
    );
    let stale = f
        .identity
        .authorize_device_authority(
            f.bootstrap.initial_roster.clone(),
            2,
            &f.bootstrap.initial_roster.authority.fingerprint,
        )
        .unwrap();
    assert_eq!(
        f.run(
            DeviceKeyOperation::Initialize,
            json!({"current_password":PASSWORD,"bootstrap":stale})
        ),
        Err(KeyError::Conflict)
    );
    let other_identity = UnlockedIdentity::generate(
        &f.bootstrap.legacy_identity.deployment_id,
        &f.bootstrap.legacy_identity.user_id,
        1,
    )
    .unwrap();
    let forged = other_identity
        .authorize_device_authority(
            f.bootstrap.initial_roster.clone(),
            1,
            &f.bootstrap.initial_roster.authority.fingerprint,
        )
        .unwrap();
    assert_eq!(
        f.run(
            DeviceKeyOperation::Initialize,
            json!({"current_password":PASSWORD,"bootstrap":forged})
        ),
        Err(KeyError::Conflict)
    );
    assert!(!f.path("roster.json").exists());
    let actor = f
        .accounts
        .create_user("admin2", "Other admin", PASSWORD.into(), true, false)
        .unwrap();
    let other_token = f.accounts.login("admin2", PASSWORD.into()).unwrap().0;
    let body =
        serde_json::to_vec(&json!({"current_password":PASSWORD,"bootstrap":f.bootstrap})).unwrap();
    assert_eq!(
        f.accounts
            .device_key_operation(&other_token, DeviceKeyOperation::Initialize, &body),
        Err(KeyError::Forbidden)
    );
    assert!(
        !f.accounts
            .device_key_directory(&actor.id)
            .join("roster.json")
            .exists()
    );
    let duplicate = String::from_utf8(body).unwrap().replacen(
        '{',
        "{\"current_password\":\"synthetic duplicate\",",
        1,
    );
    assert_eq!(
        f.accounts.device_key_operation(
            &f.token,
            DeviceKeyOperation::Initialize,
            duplicate.as_bytes()
        ),
        Err(KeyError::Invalid)
    );
    f.initialize().unwrap();
    let replacement = DeviceAuthorityKey::generate(
        &f.bootstrap.legacy_identity.deployment_id,
        &f.bootstrap.legacy_identity.user_id,
    )
    .unwrap();
    let roster = replacement
        .sign_roster(1, String::new(), vec![], vec![])
        .unwrap();
    let different = f
        .identity
        .authorize_device_authority(roster.clone(), 1, &roster.authority.fingerprint)
        .unwrap();
    assert_eq!(
        f.run(
            DeviceKeyOperation::Initialize,
            json!({"current_password":PASSWORD,"bootstrap":different})
        ),
        Err(KeyError::Conflict)
    );
}

#[test]
fn publication_rejects_competing_candidates_reused_ids_removals_and_forgery() {
    let mut f = Fixture::new();
    f.initialize().unwrap();
    let first = f.candidate(&f.bootstrap.initial_roster);
    let competing = f.candidate(&f.bootstrap.initial_roster);
    let mut forged = first.clone();
    forged.signature.replace_range(0..4, "AAAA");
    assert_eq!(f.publish(&"1".repeat(64), &forged), Err(KeyError::Invalid));
    f.publish(&"1".repeat(64), &first).unwrap();
    let saved = fs::read(f.path("roster.json")).unwrap();
    assert_eq!(
        f.publish(&"1".repeat(64), &competing),
        Err(KeyError::Conflict)
    );
    assert_eq!(
        f.publish(&"2".repeat(64), &competing),
        Err(KeyError::Conflict)
    );
    let removal = f
        .authority
        .sign_roster(
            3,
            first.digest().unwrap(),
            vec![],
            vec![first.devices[0].device_id.clone()],
        )
        .unwrap();
    assert_eq!(
        f.publish(&"3".repeat(64), &removal),
        Err(KeyError::Forbidden)
    );
    assert_eq!(fs::read(f.path("roster.json")).unwrap(), saved);
    assert_eq!(
        f.run(
            DeviceKeyOperation::Receipt("../bootstrap.json".into()),
            Value::Null
        ),
        Err(KeyError::Invalid)
    );
    assert_eq!(
        f.accounts.device_key_operation(
            &f.token,
            DeviceKeyOperation::Publish,
            &vec![b' '; MAX_DEVICE_KEY_BODY + 1]
        ),
        Err(KeyError::TooLarge)
    );
}

#[test]
fn interrupted_bootstrap_only_resumes_identical_empty_journal() {
    let mut f = Fixture::new();
    let journal = open_journal(&f.path("roster.json"), &f.bootstrap).unwrap();
    journal
        .initialize(&f.pin(&f.bootstrap.initial_roster))
        .unwrap();
    drop(journal);
    assert_eq!(
        f.run(DeviceKeyOperation::Own, Value::Null),
        Err(KeyError::NotFound)
    );
    let authority = DeviceAuthorityKey::generate(
        &f.bootstrap.legacy_identity.deployment_id,
        &f.bootstrap.legacy_identity.user_id,
    )
    .unwrap();
    let initial = authority
        .sign_roster(1, String::new(), vec![], vec![])
        .unwrap();
    let other = f
        .identity
        .authorize_device_authority(initial.clone(), 1, &initial.authority.fingerprint)
        .unwrap();
    assert_eq!(
        f.run(
            DeviceKeyOperation::Initialize,
            json!({"current_password":PASSWORD,"bootstrap":other})
        ),
        Err(KeyError::Conflict)
    );
    f.initialize().unwrap();
    let first = f.candidate(&f.bootstrap.initial_roster);
    f.publish(&"1".repeat(64), &first).unwrap();
    fs::remove_file(f.path("bootstrap.json")).unwrap();
    let saved = fs::read(f.path("roster.json")).unwrap();
    assert_eq!(f.initialize(), Err(KeyError::Conflict));
    assert_eq!(fs::read(f.path("roster.json")).unwrap(), saved);
}

#[test]
fn missing_or_corrupt_committed_state_never_reinitializes() {
    let mut f = Fixture::new();
    f.initialize().unwrap();
    let anchor = fs::read(f.path("bootstrap.json")).unwrap();
    fs::write(f.path("bootstrap.json"), b"{").unwrap();
    assert_eq!(f.initialize(), Err(KeyError::Unavailable));
    assert_eq!(
        f.run(DeviceKeyOperation::Own, Value::Null),
        Err(KeyError::Unavailable)
    );
    fs::write(f.path("bootstrap.json"), anchor).unwrap();
    fs::write(f.path("roster.json"), b"{").unwrap();
    assert_eq!(f.initialize(), Err(KeyError::Unavailable));
    assert_eq!(
        f.run(DeviceKeyOperation::Own, Value::Null),
        Err(KeyError::Unavailable)
    );
    fs::remove_file(f.path("roster.json")).unwrap();
    assert_eq!(f.initialize(), Err(KeyError::Unavailable));
    assert!(!f.path("roster.json").exists());
}

#[test]
fn sessions_disable_and_shared_rate_limits_are_rechecked() {
    let mut f = Fixture::new();
    f.initialize().unwrap();
    assert_eq!(
        f.accounts
            .device_key_operation("static-token", DeviceKeyOperation::Own, &[]),
        Err(KeyError::Unauthenticated)
    );
    let user = f.bootstrap.legacy_identity.user_id.clone();
    f.accounts
        .key_attempts
        .insert(user, vec![Instant::now(); 120]);
    assert_eq!(
        f.run(DeviceKeyOperation::Own, Value::Null),
        Err(KeyError::RateLimited)
    );
    f.accounts.key_attempts.clear();
    f.accounts.attempts = vec![Instant::now(); 20];
    assert_eq!(f.initialize(), Err(KeyError::RateLimited));
    f.accounts.attempts.clear();
    f.accounts.sessions.get_mut(&f.token).unwrap().expires =
        Instant::now() - Duration::from_secs(1);
    assert_eq!(
        f.run(DeviceKeyOperation::Own, Value::Null),
        Err(KeyError::Unauthenticated)
    );
    f.token = f.accounts.login("owner", PASSWORD.into()).unwrap().0;
    // A different process can disable a user without changing this process's session map.
    let file = StoreFile::lock(&f.accounts.path).unwrap();
    let mut db = Accounts::load(&file).unwrap();
    db.users[0].disabled = true;
    file.write(&serde_json::to_vec(&db).unwrap(), false)
        .unwrap();
    drop(file);
    assert_eq!(
        f.run(DeviceKeyOperation::Own, Value::Null),
        Err(KeyError::Unauthenticated)
    );
    assert_eq!(f.initialize(), Err(KeyError::Unauthenticated));
}
