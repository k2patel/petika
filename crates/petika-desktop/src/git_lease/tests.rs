use super::*;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use petika_core::device_keys::DeviceAuthorityKey;
use std::cell::Cell;
use std::rc::Rc;

// Test-only wrapping key. No software custodian is exported by the library.
struct TestCustody {
    fail: Rc<Cell<bool>>,
}
impl TestCustody {
    fn new() -> Self {
        Self {
            fail: Rc::new(Cell::new(false)),
        }
    }
}
impl DraftCustody for TestCustody {
    fn seal(&mut self, purpose: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.fail.get() {
            return Err(Error::Storage);
        }
        let nonce = random()?;
        let mut bytes = nonce[..12].to_vec();
        bytes.extend(
            ChaCha20Poly1305::new(&[7; 32].into())
                .encrypt(
                    (&nonce[..12]).into(),
                    Payload {
                        msg: plaintext,
                        aad: purpose,
                    },
                )
                .map_err(|_| Error::Storage)?,
        );
        Ok(bytes)
    }
    fn open(&mut self, purpose: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if bytes.len() < 28 {
            return Err(Error::Invalid);
        }
        ChaCha20Poly1305::new(&[7; 32].into())
            .decrypt(
                (&bytes[..12]).into(),
                Payload {
                    msg: &bytes[12..],
                    aad: purpose,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::Invalid)
    }
}
struct FakeService {
    origin: String,
    status: Option<Status>,
    challenges: usize,
    registrations: usize,
    completions: usize,
    lost_challenge: bool,
    lost_registration: bool,
    fail_cleanup: bool,
}
impl FakeService {
    fn new() -> Self {
        Self {
            origin: "https://petika.example".into(),
            status: None,
            challenges: 0,
            registrations: 0,
            completions: 0,
            lost_challenge: false,
            lost_registration: false,
            fail_cleanup: false,
        }
    }
}
impl LeaseService for FakeService {
    fn origin(&self) -> &str {
        &self.origin
    }
    fn challenge(&mut self, i: &Intent) -> Result<GitLeaseChallenge> {
        self.challenges += 1;
        let s = &i.scope;
        let c = GitLeaseChallenge {
            version: 1,
            lease_id: "e".repeat(64),
            operation_id: i.operation_id.clone(),
            deployment_id: s.session.deployment_id.clone(),
            user_id: s.session.user_id.clone(),
            session_id: s.session.session_id.clone(),
            device_id: s.device_id.clone(),
            device_fingerprint: s.device_fingerprint.clone(),
            roster_digest: s.roster_digest.clone(),
            management_origin: s.management_origin.clone(),
            repository: s.repository.clone(),
            ssh_public_key: i.ssh_public_key.clone(),
            read_only: s.read_only,
            issued_at: i.created_at,
            challenge_expires_at: i.created_at + 60,
            lease_expires_at: i.created_at + s.ttl,
        };
        self.status = Some(Status {
            lease_id: c.lease_id.clone(),
            operation_id: c.operation_id.clone(),
            state: RemoteState::PendingRegistration,
            expires_at: c.lease_expires_at,
            challenge: c.clone(),
            last_error: None,
        });
        if self.lost_challenge {
            self.lost_challenge = false;
            return Err(Error::Service);
        }
        Ok(c)
    }
    fn lookup(&mut self, _: &str) -> Result<Option<Status>> {
        Ok(self.status.clone())
    }
    fn register(&mut self, p: &GitLeaseProof) -> Result<()> {
        self.registrations += 1;
        assert_eq!(self.status.as_ref().unwrap().challenge, p.challenge);
        self.status.as_mut().unwrap().state = RemoteState::Active;
        if self.lost_registration {
            self.lost_registration = false;
            return Err(Error::Service);
        }
        Ok(())
    }
    fn complete(&mut self, id: &str) -> Result<()> {
        self.completions += 1;
        if self.fail_cleanup {
            return Err(Error::Service);
        }
        assert_eq!(id, self.status.as_ref().unwrap().lease_id);
        self.status.as_mut().unwrap().state = RemoteState::Revoking;
        Ok(())
    }
}
fn setup() -> (
    tempfile::TempDir,
    Operation<TestCustody>,
    DeviceIdentity,
    TrustedDeviceRoster,
    FakeService,
) {
    let directory = tempfile::tempdir().unwrap();
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
    let pin = TrustedDeviceRoster::bootstrap(
        roster.clone(),
        &roster.authority.fingerprint,
        &roster.digest().unwrap(),
    )
    .unwrap();
    let d = device.public_record().unwrap();
    let scope = Scope {
        server_origin: "https://petika.example".into(),
        session: SessionContext {
            deployment_id: "a".repeat(64),
            user_id: "b".repeat(64),
            session_id: "c".repeat(64),
        },
        device_id: d.device_id,
        device_fingerprint: d.fingerprint,
        roster_digest: roster.digest().unwrap(),
        provider: Provider::Gitea,
        management_origin: "https://git.example/".into(),
        repository: "synthetic/vault".into(),
        read_only: true,
        ttl: 300,
    };
    let op = Operation::create(
        directory.path().join("draft"),
        TestCustody::new(),
        scope,
        100,
    )
    .unwrap();
    (directory, op, device, pin, FakeService::new())
}
fn admit(
    op: &mut Operation<TestCustody>,
    device: &DeviceIdentity,
    pin: &TrustedDeviceRoster,
    service: &mut FakeService,
) {
    op.request_challenge(service, 100).unwrap();
    op.authorize(device, pin, 101).unwrap();
    service
        .status
        .as_ref()
        .unwrap()
        .challenge
        .canonical_bytes()
        .unwrap();
    op.draft.proof.as_ref().unwrap().verify(pin, 101).unwrap();
    op.register(service, 102).unwrap();
}
#[test]
fn encrypted_resume_recovers_lost_challenge_and_registration_without_duplicate_issue() {
    let (dir, mut op, device, pin, mut service) = setup();
    let intent = op.intent().clone();
    service.lost_challenge = true;
    assert_eq!(op.request_challenge(&mut service, 100), Err(Error::Service));
    drop(op);
    let bytes = std::fs::read(dir.path().join("draft")).unwrap();
    assert!(
        !bytes
            .windows(intent.operation_id.len())
            .any(|w| w == intent.operation_id.as_bytes())
    );
    let mut op = Operation::resume(dir.path().join("draft"), TestCustody::new()).unwrap();
    assert_eq!(&intent, op.intent());
    op.request_challenge(&mut service, 101).unwrap();
    assert_eq!(service.challenges, 1);
    op.authorize(&device, &pin, 101).unwrap();
    service.lost_registration = true;
    assert_eq!(op.register(&mut service, 102), Err(Error::Service));
    assert_eq!(op.phase(), Phase::RegistrationStarted);
    drop(op);
    let mut op = Operation::resume(dir.path().join("draft"), TestCustody::new()).unwrap();
    op.register(&mut service, 103).unwrap();
    assert_eq!(op.phase(), Phase::Active);
    assert_eq!(service.registrations, 1);
}
#[test]
fn every_retained_challenge_binding_is_checked_before_authorization() {
    let (_dir, mut op, _, _, mut service) = setup();
    let c = service.challenge(op.intent()).unwrap();
    let mut variants = Vec::new();
    macro_rules! change {
        ($field:ident,$value:expr) => {{
            let mut altered = c.clone();
            altered.$field = $value;
            variants.push(altered);
        }};
    }
    change!(operation_id, "1".repeat(64));
    change!(deployment_id, "1".repeat(64));
    change!(user_id, "1".repeat(64));
    change!(session_id, "1".repeat(64));
    change!(device_id, "1".repeat(64));
    change!(device_fingerprint, "1".repeat(64));
    change!(roster_digest, "1".repeat(64));
    change!(management_origin, "https://wrong.example/".into());
    change!(repository, "other/vault".into());
    change!(
        ssh_public_key,
        STANDARD.encode(SigningKey::from_bytes(&[8; 32]).verifying_key().as_bytes())
    );
    change!(read_only, false);
    change!(lease_expires_at, 401);
    change!(issued_at, 99);
    for altered in variants {
        assert_eq!(op.intent().check(&altered), Err(Error::Invalid));
    }
    // An authenticated response cannot move this operation to another origin.
    service.origin = "https://wrong.example".into();
    assert_eq!(op.request_challenge(&mut service, 100), Err(Error::Invalid));
    assert_eq!(op.phase(), Phase::Prepared);
}
#[test]
fn in_flight_registration_is_not_reissued_and_transfer_is_never_replayed() {
    let (dir, mut op, device, pin, mut service) = setup();
    admit(&mut op, &device, &pin, &mut service);
    op.draft.phase = Phase::RegistrationStarted;
    op.persist(false).unwrap();
    service.status.as_mut().unwrap().state = RemoteState::Registering;
    assert_eq!(op.register(&mut service, 103), Err(Error::Phase));
    assert_eq!(service.registrations, 1);
    service.status.as_mut().unwrap().state = RemoteState::Active;
    op.register(&mut service, 103).unwrap();
    op.mark_transfer_started(&mut service, 103).unwrap();
    drop(op);
    let mut op = Operation::resume(dir.path().join("draft"), TestCustody::new()).unwrap();
    assert_eq!(
        op.mark_transfer_started(&mut service, 104),
        Err(Error::Phase)
    );
    assert_eq!(op.register(&mut service, 104), Err(Error::Phase));
    service.fail_cleanup = true;
    assert_eq!(op.cleanup(&mut service), Err(Error::Service));
    assert_eq!(op.phase(), Phase::CleanupPending);
    service.fail_cleanup = false;
    op.cleanup(&mut service).unwrap();
    service.status.as_mut().unwrap().state = RemoteState::Removed;
    op.cleanup(&mut service).unwrap();
    assert_eq!(op.phase(), Phase::Removed);
    assert!(op.draft.seed.is_none());
    drop(op);
    assert_eq!(
        Operation::resume(dir.path().join("draft"), TestCustody::new())
            .unwrap()
            .phase(),
        Phase::Removed
    );
}
#[test]
fn custody_failure_poisons_instance_and_tampered_ciphertext_cannot_resume() {
    let (dir, mut op, _, _, mut service) = setup();
    op.custody.fail.set(true);
    assert_eq!(op.request_challenge(&mut service, 100), Err(Error::Storage));
    op.custody.fail.set(false);
    assert_eq!(op.request_challenge(&mut service, 100), Err(Error::Storage));
    assert_eq!(service.challenges, 0);
    drop(op);
    let path = dir.path().join("draft");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[20] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        Operation::resume(path, TestCustody::new()),
        Err(Error::Invalid)
    ));
}
#[test]
fn expired_unadmitted_changed_scope_and_rollback_states_deny_use() {
    let (_dir, mut op, device, pin, mut service) = setup();
    op.request_challenge(&mut service, 100).unwrap();
    let other = DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    assert_eq!(op.authorize(&other, &pin, 101), Err(Error::Invalid));
    op.authorize(&device, &pin, 101).unwrap();
    service.status.as_mut().unwrap().state = RemoteState::Active;
    // A local phase that says proof never sent cannot adopt a remote active key.
    assert_eq!(op.register(&mut service, 102), Err(Error::Phase));
    service.status.as_mut().unwrap().state = RemoteState::PendingRegistration;
    assert_eq!(op.register(&mut service, 160), Err(Error::Expired));
    op.register(&mut service, 102).unwrap();
    assert_eq!(
        op.mark_transfer_started(&mut service, 400),
        Err(Error::Expired)
    );
    service.status.as_mut().unwrap().challenge.read_only = false;
    assert_eq!(
        op.mark_transfer_started(&mut service, 103),
        Err(Error::Invalid)
    );
}
#[cfg(unix)]
#[test]
fn isolated_real_agent_signs_without_private_key_files_and_is_killed_on_drop() {
    use ed25519_dalek::{Signature, Verifier};
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    fn field(v: &mut Vec<u8>, b: &[u8]) {
        v.extend_from_slice(&(b.len() as u32).to_be_bytes());
        v.extend_from_slice(b)
    }
    fn take(v: &mut &[u8]) -> Vec<u8> {
        let n = u32::from_be_bytes(v[..4].try_into().unwrap()) as usize;
        let out = v[4..4 + n].to_vec();
        *v = &v[4 + n..];
        out
    }
    let (_dir, mut op, device, pin, mut service) = setup();
    admit(&mut op, &device, &pin, &mut service);
    let mut socket = None;
    op.transfer(&mut service, 103, |path, _| {
        socket = Some(path.to_owned());
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        let mut stream = UnixStream::connect(path).unwrap();
        // Ask for identities; the agent contains exactly the temporary public key.
        stream.write_all(&[0, 0, 0, 1, 11]).unwrap();
        let mut len = [0; 4];
        stream.read_exact(&mut len).unwrap();
        let mut reply = vec![0; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..5], &[12, 0, 0, 0, 1]);
        let mut contents = &reply[5..];
        let blob = take(&mut contents);
        let _comment = take(&mut contents);
        assert!(contents.is_empty());
        let mut packet = vec![13];
        field(&mut packet, &blob);
        field(&mut packet, b"synthetic Git transport authentication test");
        packet.extend_from_slice(&0u32.to_be_bytes());
        stream
            .write_all(&(packet.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&packet).unwrap();
        stream.read_exact(&mut len).unwrap();
        let mut response = vec![0; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(response[0], 14);
        let sig = take(&mut &response[1..]);
        let mut sig = &sig[..];
        assert_eq!(take(&mut sig), b"ssh-ed25519");
        let signature = take(&mut sig);
        let mut key_blob = &blob[..];
        assert_eq!(take(&mut key_blob), b"ssh-ed25519");
        let public: [u8; 32] = take(&mut key_blob).try_into().unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify(
                b"synthetic Git transport authentication test",
                &Signature::from_slice(&signature).unwrap(),
            )
            .unwrap();
        Ok(())
    })
    .unwrap();
    assert!(!socket.unwrap().exists());
    assert_eq!(op.phase(), Phase::CleanupPending);
    assert_eq!(service.completions, 1);
}

fn http_fixture(
    responses: Vec<(u16, Vec<u8>)>,
) -> (
    String,
    std::thread::JoinHandle<Vec<(String, serde_json::Value)>>,
) {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::{Duration, Instant},
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let deadline = Instant::now() + Duration::from_secs(4);
            let mut stream = loop {
                if let Ok((stream, _)) = listener.accept() {
                    break stream;
                }
                assert!(
                    Instant::now() < deadline,
                    "HTTP test request did not arrive"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                stream.read_exact(&mut b).unwrap();
                headers.push(b[0]);
                assert!(headers.len() <= 4096);
            }
            let headers = String::from_utf8(headers).unwrap();
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("authorization: bearer cli_synthetic")
            );
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(|v| v.parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut payload = vec![0; length];
            stream.read_exact(&mut payload).unwrap();
            let value = if payload.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_slice(&payload).unwrap()
            };
            requests.push((headers, value));
            write!(stream,"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
        requests
    });
    (origin, handle)
}
#[test]
fn http_adapter_sends_only_public_material_and_reauthenticates_each_admission() {
    let (_dir, mut op, device, pin, mut fake) = setup();
    let c = fake.challenge(op.intent()).unwrap();
    let pending = fake.status.clone().unwrap();
    let mut active = pending.clone();
    active.state = RemoteState::Active;
    let json = |v: serde_json::Value| serde_json::to_vec(&v).unwrap();
    let responses = vec![
        (200, serde_json::to_vec(&op.intent().scope.session).unwrap()),
        (200, json(serde_json::json!({"challenge":c}))),
        (200, serde_json::to_vec(&pending).unwrap()),
        (
            200,
            json(serde_json::json!({"lease_id":c.lease_id,"state":"active"})),
        ),
        (200, serde_json::to_vec(&active).unwrap()),
        (200, serde_json::to_vec(&active).unwrap()),
        (
            200,
            json(serde_json::json!({"lease_id":c.lease_id,"cleanup":"pending"})),
        ),
    ];
    let (origin, server) = http_fixture(responses);
    op.draft.intent.scope.server_origin = origin.clone();
    op.persist(false).unwrap();
    let mut prompts = 0;
    let mut service =
        http::HttpService::new(&origin, Zeroizing::new("cli_synthetic".into()), || {
            prompts += 1;
            Ok(Zeroizing::new("synthetic account password".into()))
        })
        .unwrap();
    assert_eq!(service.context().unwrap(), op.intent().scope.session);
    op.request_challenge(&mut service, 100).unwrap();
    op.authorize(&device, &pin, 101).unwrap();
    op.register(&mut service, 102).unwrap();
    op.cleanup(&mut service).unwrap();
    drop(service);
    assert_eq!(prompts, 2);
    let requests = server.join().unwrap();
    assert!(
        requests[0]
            .0
            .starts_with("GET /v1/device-keys/git-leases/context ")
    );
    assert!(
        requests[1]
            .0
            .starts_with("POST /v1/device-keys/git-leases/challenges ")
    );
    for (headers, body) in requests.iter().filter(|(_, v)| !v.is_null()) {
        assert!(headers.to_ascii_lowercase().contains("x-petika-request: 1"));
        assert!(body.get("private_key").is_none());
        assert!(body.get("seed").is_none());
    }
    assert_eq!(
        requests[1].1["current_password"],
        "synthetic account password"
    );
    assert_eq!(
        requests[3].1["current_password"],
        "synthetic account password"
    );
    assert!(requests[3].1["proof"]["device_signature"].is_string());
}
#[test]
fn http_adapter_distinguishes_absence_from_failures_and_bounds_responses() {
    for (code, payload, expected) in [
        (404, b"{}".to_vec(), Ok(None)),
        (401, b"{}".to_vec(), Err(Error::Service)),
        (302, b"{}".to_vec(), Err(Error::Service)),
        (200, vec![b' '; LIMIT + 1], Err(Error::Service)),
        (200, b"{\"unexpected\":true}".to_vec(), Err(Error::Invalid)),
    ] {
        let (origin, server) = http_fixture(vec![(code, payload)]);
        let mut service =
            http::HttpService::new(&origin, Zeroizing::new("cli_synthetic".into()), || {
                Err(Error::Phase)
            })
            .unwrap();
        assert_eq!(service.lookup(&"a".repeat(64)), expected);
        assert_eq!(server.join().unwrap().len(), 1);
    }
    for bad in [
        "http://untrusted.example",
        "https://user:secret@example.com",
        "https://example.com/prefix",
        "https://example.com?token=bad",
    ] {
        assert!(
            http::HttpService::new(bad, Zeroizing::new("cli_synthetic".into()), || Err(
                Error::Phase
            ))
            .is_err()
        );
    }
}

#[cfg(unix)]
#[test]
fn real_agent_key_expires_and_failed_job_still_queues_cleanup() {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::{Duration, Instant},
    };
    let guard = agent::Agent::start(&[9; 32], 2).unwrap();
    let identities = || {
        let mut stream = UnixStream::connect(guard.socket()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&[0, 0, 0, 1, 11]).unwrap();
        let mut len = [0; 4];
        stream.read_exact(&mut len).unwrap();
        let n = u32::from_be_bytes(len) as usize;
        assert!(n <= 1024);
        let mut bytes = vec![0; n];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes[0], 12);
        u32::from_be_bytes(bytes[1..5].try_into().unwrap())
    };
    assert_eq!(identities(), 1);
    let deadline = Instant::now() + Duration::from_secs(3);
    while identities() != 0 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(guard);
    let (_dir, mut op, device, pin, mut service) = setup();
    admit(&mut op, &device, &pin, &mut service);
    let mut socket = None;
    let result: Result<()> = op.transfer(&mut service, 103, |path, _| {
        socket = Some(path.to_owned());
        Err(Error::Transfer)
    });
    assert_eq!(result, Err(Error::Transfer));
    assert_eq!(service.completions, 1);
    assert_eq!(op.phase(), Phase::CleanupPending);
    assert!(!socket.unwrap().exists());
}
