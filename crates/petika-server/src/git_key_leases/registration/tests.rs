use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use petika_core::device_keys::{DeviceAuthorityKey, DeviceIdentity};
use sha2::{Digest, Sha256};

pub(crate) struct FakeHost {
    pub keys: Vec<RemoteKey>,
    pub creates: usize,
    pub fail_after: bool,
    pub fail_before: bool,
    pub wrong_permission: bool,
    pub allowed_user: Option<String>,
    pub ledger_path: Option<std::path::PathBuf>,
}
impl FakeHost {
    pub fn new() -> Self {
        Self {
            keys: vec![],
            creates: 0,
            fail_after: false,
            fail_before: false,
            wrong_permission: false,
            allowed_user: None,
            ledger_path: None,
        }
    }
}
impl KeyHost for FakeHost {
    fn inventory(&mut self, _: &Repository) -> std::result::Result<Inventory, Failure> {
        Ok(Inventory {
            keys: self.keys.clone(),
            complete: true,
        })
    }
    fn delete(&mut self, _: &Repository, id: &str) -> std::result::Result<(), Failure> {
        self.keys.retain(|k| k.id != id);
        Ok(())
    }
}
impl KeyRegistrar for FakeHost {
    fn authorized(&self, repo: &Repository, user: &str, read_only: bool, ttl: u64) -> bool {
        self.allowed_user.as_deref() == Some(user)
            && repo.management_origin == "https://git.example/"
            && repo.repository == "synthetic/vault"
            && read_only
            && ttl <= 300
    }
    fn create(
        &mut self,
        _: &Repository,
        marker: &str,
        public: &str,
        read_only: bool,
    ) -> std::result::Result<RemoteKey, Failure> {
        self.creates += 1;
        if let Some(path) = &self.ledger_path {
            let ledger: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert!(
                ledger["leases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|l| l["state"] == "registering"
                        && l["id"].as_str() == Some(marker.trim_start_matches("petika-lease:v1:")))
            );
        }
        if self.fail_before {
            return Err(Failure::Registration);
        }
        let wire = STANDARD
            .decode(public.split_whitespace().nth(1).unwrap())
            .unwrap();
        let key = RemoteKey {
            id: format!("{}", self.creates),
            marker: marker.into(),
            fingerprint: Sha256::digest(wire)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            read_only: Some(if self.wrong_permission {
                !read_only
            } else {
                read_only
            }),
        };
        self.keys.push(key.clone());
        if self.fail_after {
            Err(Failure::Registration)
        } else {
            Ok(key)
        }
    }
}
pub(crate) fn ssh_public() -> String {
    let value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../petika-core/tests/fixtures/git-lease-v1.json"
    )))
    .unwrap();
    value["proof"]["challenge"]["ssh_public_key"]
        .as_str()
        .unwrap()
        .into()
}
pub(crate) fn ssh_seed() -> [u8; 32] {
    Sha256::digest(b"PUBLIC PETIKA DEVICE FORMAT TEST ONLY: temporary-ssh").into()
}
fn fixture() -> (
    tempfile::TempDir,
    LeaseStore,
    DeviceIdentity,
    TrustedDeviceRoster,
    GitLeaseChallenge,
    FakeHost,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.json");
    let store = LeaseStore::lock(&path).unwrap();
    let device = DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    let authority = DeviceAuthorityKey::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    let roster = authority
        .sign_roster(
            1,
            String::new(),
            vec![device.public_record().unwrap()],
            vec![],
        )
        .unwrap();
    let current = TrustedDeviceRoster::bootstrap(
        roster.clone(),
        &roster.authority.fingerprint,
        &roster.digest().unwrap(),
    )
    .unwrap();
    let repo = Repository {
        provider: Provider::Gitea,
        management_origin: "https://git.example/".into(),
        repository: "synthetic/vault".into(),
    };
    let challenge = GitLeaseChallenge {
        version: 1,
        lease_id: "0".repeat(64),
        operation_id: "d".repeat(64),
        deployment_id: "a".repeat(64),
        user_id: "b".repeat(64),
        session_id: "e".repeat(64),
        device_id: roster.devices[0].device_id.clone(),
        device_fingerprint: roster.devices[0].fingerprint.clone(),
        roster_digest: roster.digest().unwrap(),
        management_origin: repo.management_origin.clone(),
        repository: repo.repository.clone(),
        ssh_public_key: ssh_public(),
        read_only: true,
        issued_at: 100,
        challenge_expires_at: 160,
        lease_expires_at: 400,
    };
    let challenge = store.prepare_authorization(challenge, repo).unwrap();
    let mut host = FakeHost::new();
    host.ledger_path = Some(path);
    (dir, store, device, current, challenge, host)
}
fn proof(
    device: &DeviceIdentity,
    current: &TrustedDeviceRoster,
    challenge: GitLeaseChallenge,
) -> GitLeaseProof {
    device
        .authorize_git_lease(
            challenge,
            current,
            "https://git.example/",
            "synthetic/vault",
            &ssh_seed(),
            101,
        )
        .unwrap()
}
#[test]
fn intent_precedes_create_and_exact_retry_never_creates_twice() {
    let (_dir, store, device, current, challenge, mut host) = fixture();
    let proof = proof(&device, &current, challenge.clone());
    assert_eq!(
        store
            .register(&proof, &current, &challenge.session_id, 101, &mut host)
            .unwrap()
            .state,
        State::Active
    );
    store
        .register(&proof, &current, &challenge.session_id, 102, &mut host)
        .unwrap();
    assert_eq!(host.creates, 1);
    store
        .request_cleanup(Cleanup::Lease(&challenge.lease_id))
        .unwrap();
    store.sweep(103, &mut host).unwrap();
    assert!(host.keys.is_empty());
    assert!(
        store
            .register(&proof, &current, &challenge.session_id, 104, &mut host)
            .is_err()
    );
    assert_eq!(host.creates, 1);
}
#[test]
fn lost_create_reply_survives_restart_and_reconciles_one_key() {
    let (dir, store, device, current, challenge, mut host) = fixture();
    let proof = proof(&device, &current, challenge.clone());
    host.fail_after = true;
    assert!(
        store
            .register(&proof, &current, &challenge.session_id, 101, &mut host)
            .is_err()
    );
    assert_eq!(store.leases().unwrap()[0].state, State::Registering);
    drop(store);
    let store = LeaseStore::lock(dir.path().join("leases.json")).unwrap();
    assert_eq!(
        store
            .register(&proof, &current, &challenge.session_id, 102, &mut host)
            .unwrap()
            .state,
        State::Active
    );
    assert_eq!(host.creates, 1);
}
#[test]
fn unknown_empty_outcome_cannot_repeat_post_and_ownership_proof_is_required() {
    let (_dir, store, device, current, challenge, mut host) = fixture();
    let mut proof = proof(&device, &current, challenge.clone());
    proof.ssh_signature = STANDARD.encode([0; 64]);
    assert!(
        store
            .register(&proof, &current, &challenge.session_id, 101, &mut host)
            .is_err()
    );
    assert_eq!(host.creates, 0);
    let proof = super::tests::proof(&device, &current, challenge.clone());
    host.fail_before = true;
    assert!(
        store
            .register(&proof, &current, &challenge.session_id, 101, &mut host)
            .is_err()
    );
    host.fail_before = false;
    assert!(
        store
            .register(&proof, &current, &challenge.session_id, 102, &mut host)
            .is_err()
    );
    assert_eq!(host.creates, 1);
    assert!(
        store
            .register(&proof, &current, &"f".repeat(64), 103, &mut host)
            .is_err()
    );
}
#[test]
fn challenge_operation_binding_and_wrong_host_permission_fail_closed() {
    let (_dir, store, device, current, challenge, mut host) = fixture();
    let repo = store.leases().unwrap()[0].repository.clone();
    let mut retry = challenge.clone();
    retry.issued_at = 101;
    retry.challenge_expires_at = 161;
    retry.lease_expires_at = 401;
    assert_eq!(
        store.prepare_authorization(retry, repo.clone()).unwrap(),
        challenge
    );
    let mut changed = challenge.clone();
    changed.read_only = false;
    assert!(store.prepare_authorization(changed, repo).is_err());
    let proof = proof(&device, &current, challenge.clone());
    host.wrong_permission = true;
    assert!(
        store
            .register(&proof, &current, &challenge.session_id, 101, &mut host)
            .is_err()
    );
    assert_eq!(store.leases().unwrap()[0].state, State::Revoking);
    store.sweep(102, &mut host).unwrap();
    assert!(host.keys.is_empty());
}

#[test]
fn uncertain_wrong_permission_is_durably_revoked_before_cleanup_deletes() {
    let (dir, store, device, current, challenge, mut host) = fixture();
    let proof = proof(&device, &current, challenge.clone());
    host.fail_after = true;
    host.wrong_permission = true;
    assert!(
        store
            .register(&proof, &current, &challenge.session_id, 101, &mut host)
            .is_err()
    );
    store.sweep(102, &mut host).unwrap();
    assert_eq!(store.leases().unwrap()[0].state, State::Revoking);
    assert_eq!(host.keys.len(), 1);
    let retry = store.leases().unwrap()[0].retry_at;
    drop(store);
    let store = LeaseStore::lock(dir.path().join("leases.json")).unwrap();
    store.sweep(retry, &mut host).unwrap();
    assert!(host.keys.is_empty());
}

#[test]
fn a_new_operation_cannot_extend_a_previous_ssh_key_lease() {
    let (_dir, store, _, _, mut challenge, _) = fixture();
    let repository = store.leases().unwrap()[0].repository.clone();
    challenge.operation_id = "a".repeat(64);
    assert!(store.prepare_authorization(challenge, repository).is_err());
    assert_eq!(store.leases().unwrap().len(), 1);
}
