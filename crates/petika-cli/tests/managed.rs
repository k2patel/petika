use petika_core::{Entry, StoreFile, UnlockedStore};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
const PASSWORD: &str = "synthetic collection passphrase";
fn entry() -> Entry {
    Entry {
        username: "alice".into(),
        password: "initial-secret".into(),
        url: "https://example.com".into(),
        notes: "keep notes".into(),
        otp: None,
    }
}
struct Request {
    path: String,
    method: String,
    headers: String,
    body: String,
}
struct Response {
    status: u16,
    revision: Option<u64>,
    body: String,
}
fn response(value: Value) -> Response {
    Response {
        status: 200,
        revision: None,
        body: value.to_string(),
    }
}
struct Api {
    origin: String,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Api {
    fn new(mut handler: impl FnMut(Request) -> Option<Response> + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let worker = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let (mut socket, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let mut headers = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(size) = line.to_lowercase().strip_prefix("content-length:") {
                        length = size.trim().parse::<usize>().unwrap();
                    }
                    headers.push_str(&line.to_lowercase());
                }
                assert!(length < 12 * 1024 * 1024);
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                let body = String::from_utf8(bytes).unwrap();
                assert!(!body.contains(PASSWORD));
                assert!(headers.contains(&format!("authorization: bearer cli_{}", "a".repeat(64))));
                let mut parts = first.split_whitespace();
                let request = Request {
                    method: parts.next().unwrap().into(),
                    path: parts.next().unwrap().into(),
                    headers,
                    body,
                };
                if let Some(reply) = handler(request) {
                    let tag = reply
                        .revision
                        .map(|r| format!("ETag: \"{r}\"\r\n"))
                        .unwrap_or_default();
                    write!(socket, "HTTP/1.1 {} Test\r\nContent-Length: {}\r\n{tag}Connection: close\r\n\r\n{}", reply.status, reply.body.len(), reply.body).unwrap();
                }
            }
        });
        Self {
            origin,
            stop,
            worker: Some(worker),
        }
    }
    fn session(&self, directory: &Path) {
        StoreFile::lock(directory.join("session.json")).unwrap().write(&serde_json::to_vec(&json!({"version":1,"server":self.origin,"token":format!("cli_{}", "a".repeat(64))})).unwrap(), false).unwrap();
    }
}
impl Drop for Api {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}
fn run(dir: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_petika"))
        .args(["--no-config", "--passphrase-stdin", "--session-file"])
        .arg(dir.join("session.json"))
        .arg("--store")
        .arg(dir.join("unused.petika"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Commands may reject access before reading stdin.
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    child.wait_with_output().unwrap()
}
fn ok(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn drafts(dir: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("petika-draft-")
        })
        .collect()
}
struct State {
    encrypted: String,
    revision: u64,
    writes: usize,
    edit: bool,
    failure: u16,
}
#[test]
fn managed_crud_totp_conflicts_and_uncertain_ack_preserve_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = UnlockedStore::create(PASSWORD).unwrap();
    store.put("existing".into(), entry(), false).unwrap();
    let state = Arc::new(Mutex::new(State {
        encrypted: String::from_utf8(store.seal().unwrap()).unwrap(),
        revision: 4,
        writes: 0,
        edit: true,
        failure: 0,
    }));
    let shared = state.clone();
    let api = Api::new(move |request| {
        let mut state = shared.lock().unwrap();
        if request.path == "/v1/collections" {
            return Some(response(
                json!([{"id":"b".repeat(64),"group":false,"edit":state.edit}]),
            ));
        }
        assert_eq!(
            request.path,
            format!("/v1/collections/{}/snapshot", "b".repeat(64))
        );
        if request.method == "GET" {
            return Some(Response {
                status: 200,
                revision: Some(state.revision),
                body: state.encrypted.clone(),
            });
        }
        assert_eq!(request.method, "PUT");
        assert!(
            request
                .headers
                .contains(&format!("if-match: \"{}\"", state.revision))
        );
        UnlockedStore::open(request.body.as_bytes(), PASSWORD).unwrap();
        assert!(!request.body.contains("changed-secret"));
        state.writes += 1;
        match state.failure {
            409 => Some(Response {
                status: 409,
                revision: Some(state.revision + 1),
                body: "{}".into(),
            }),
            500 => {
                state.encrypted = request.body;
                state.revision += 1;
                None // Accepted, but no acknowledgement reaches the client.
            }
            failure => {
                state.encrypted = request.body;
                state.revision += 1;
                Some(Response {
                    status: 200,
                    revision: if failure == 200 {
                        None
                    } else {
                        Some(state.revision)
                    },
                    body: "{}".into(),
                })
            }
        }
    });
    api.session(dir.path());
    let unlock = format!("{PASSWORD}\n");
    ok(&run(
        dir.path(),
        &["ls", "--collection", "personal"],
        &unlock,
    ));
    let put = run(
        dir.path(),
        &[
            "put",
            "existing",
            "--collection",
            "personal",
            "--replace",
            "--password-stdin",
        ],
        &format!("{unlock}changed-secret\n"),
    );
    ok(&put);
    assert!(!String::from_utf8_lossy(&put.stdout).contains("changed-secret"));
    let reveal = run(
        dir.path(),
        &["get", "existing", "--collection", "personal", "--reveal"],
        &unlock,
    );
    ok(&reveal);
    assert_eq!(
        String::from_utf8_lossy(&reveal.stdout).trim(),
        "changed-secret"
    );
    ok(&run(
        dir.path(),
        &[
            "generate",
            "new",
            "--collection",
            "personal",
            "--length",
            "32",
        ],
        &unlock,
    ));
    ok(&run(
        dir.path(),
        &[
            "otp",
            "set",
            "existing",
            "--collection",
            "personal",
            "--secret-stdin",
        ],
        &format!("{unlock}JBSWY3DPEHPK3PXP\n"),
    ));
    let totp = run(
        dir.path(),
        &["show", "existing", "--collection", "personal", "--totp"],
        &unlock,
    );
    ok(&totp);
    assert!(String::from_utf8_lossy(&totp.stdout).contains("expires in"));
    {
        let state = state.lock().unwrap();
        let store = UnlockedStore::open(state.encrypted.as_bytes(), PASSWORD).unwrap();
        assert_eq!(store.get("existing").unwrap().notes, "keep notes");
        assert_eq!(store.get("new").unwrap().password.len(), 32);
    }
    ok(&run(
        dir.path(),
        &[
            "otp",
            "--collection",
            "personal",
            "remove",
            "existing",
            "--yes",
        ],
        &unlock,
    ));
    ok(&run(
        dir.path(),
        &["rm", "new", "--collection", "personal", "--yes"],
        &unlock,
    ));
    assert!(drafts(dir.path()).is_empty());
    assert!(!dir.path().join("unused.petika").exists());
    let writes = state.lock().unwrap().writes;
    let bad_unlock = run(
        dir.path(),
        &["generate", "no-write", "--collection", "personal"],
        "wrong passphrase\n",
    );
    assert!(!bad_unlock.status.success());
    let bad_otp = run(
        dir.path(),
        &[
            "otp",
            "set",
            "existing",
            "--collection",
            "personal",
            "--secret-stdin",
        ],
        &format!("{unlock}invalid setup\n"),
    );
    assert!(!bad_otp.status.success());
    assert_eq!(state.lock().unwrap().writes, writes);

    state.lock().unwrap().edit = false;
    let denied = run(
        dir.path(),
        &["generate", "denied", "--collection", "personal"],
        "",
    );
    assert!(!denied.status.success());
    assert_eq!(state.lock().unwrap().writes, writes);
    state.lock().unwrap().edit = true;
    for failure in [409, 500, 200] {
        state.lock().unwrap().failure = failure;
        let output = run(
            dir.path(),
            &[
                "put",
                "draft",
                "--collection",
                "personal",
                "--password-stdin",
                "--replace",
            ],
            &format!("{unlock}draft-secret\n"),
        );
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Saved"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("Encrypted draft preserved"));
    }
    assert_eq!(state.lock().unwrap().writes, writes + 3);
    let preserved = drafts(dir.path());
    assert_eq!(preserved.len(), 3);
    for draft in preserved {
        let encrypted = std::fs::read(draft.join("snapshot.petika")).unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains("draft-secret"));
        assert_eq!(
            UnlockedStore::open(&encrypted, PASSWORD)
                .unwrap()
                .get("draft")
                .unwrap()
                .password,
            "draft-secret"
        );
        let context: Value =
            serde_json::from_slice(&std::fs::read(draft.join("context.json")).unwrap()).unwrap();
        assert_eq!(context["server"], api.origin);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(draft.join("snapshot.petika"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
    }
}

#[test]
fn recipient_live_unlock_writes_and_trust_failures() {
    use petika_core::{CollectionContext, identity::UnlockedIdentity};
    let dir = tempfile::tempdir().unwrap();
    let deployment = "d".repeat(64);
    let user = "c".repeat(64);
    let id = "b".repeat(64);
    let mut identity = UnlockedIdentity::generate(&deployment, &user, 1).unwrap();
    let public = identity.public_identity().clone();
    let mut store = UnlockedStore::create(PASSWORD).unwrap();
    store.put("existing".into(), entry(), false).unwrap();
    store
        .bind_collection(
            CollectionContext {
                deployment_id: deployment.clone(),
                collection_id: id.clone(),
                key_epoch: 1,
            },
            PASSWORD,
        )
        .unwrap();
    let package = identity.create_key_package(&store, &public, 3).unwrap();
    let identity_path = dir.path().join("identity.json");
    StoreFile::lock(&identity_path)
        .unwrap()
        .write(&identity.seal(PASSWORD).unwrap(), true)
        .unwrap();
    StoreFile::lock(identity_path.with_extension("bundle-revision.json"))
        .unwrap()
        .write(b"1", true)
        .unwrap();
    let state = Arc::new(Mutex::new(State {
        encrypted: String::from_utf8(store.seal().unwrap()).unwrap(),
        revision: 8,
        writes: 0,
        edit: true,
        failure: 0,
    }));
    let shared = state.clone();
    let own_public = public.clone();
    let package = Arc::new(Mutex::new(serde_json::to_value(package).unwrap()));
    let grant = package.clone();
    let api = Api::new(move |request| {
        let mut state = shared.lock().unwrap();
        let prefix = format!("/v1/collections/{}", "b".repeat(64));
        if request.path == "/v1/collections" {
            return Some(response(
                json!([{"id":"b".repeat(64),"group":true,"edit":true}]),
            ));
        }
        if request.path == format!("{prefix}/snapshot") {
            return Some(Response {
                status: 200,
                revision: Some(state.revision),
                body: state.encrypted.clone(),
            });
        }
        if request.path == format!("{prefix}/key-access") {
            return Some(response(
                json!({"snapshot_revision":state.revision,"key_epoch":1,"membership_generation":3,"rotation_required":false}),
            ));
        }
        if request.path == "/v1/auth/status" {
            return Some(response(json!({"user":{"id":"c".repeat(64)}})));
        }
        if request.path == "/v1/keys/deployment" {
            return Some(response(json!({"deployment_id":"d".repeat(64)})));
        }
        if request.path == "/v1/keys/identity" {
            return Some(response(
                json!({"public_identity":own_public,"bundle_revision":if state.failure == 400 { 2 } else { 1 }}),
            ));
        }
        if request.path == format!("{prefix}/key-packages") {
            return Some(response(
                json!({"packages":[grant.lock().unwrap().clone()]}),
            ));
        }
        if request.path == format!("/v1/keys/users/{}", "c".repeat(64)) {
            return Some(response(serde_json::to_value(&own_public).unwrap()));
        }
        assert_eq!(request.path, format!("{prefix}/recipient-snapshot"));
        assert_eq!(request.method, "POST");
        let body: Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(body["expected_snapshot_revision"], state.revision);
        assert_eq!(body["expected_key_epoch"], 1);
        assert_eq!(body["expected_membership_generation"], 3);
        assert_eq!(body["packages"], json!([]));
        state.writes += 1;
        if state.failure == 409 {
            return Some(Response {
                status: 409,
                revision: None,
                body: "{}".into(),
            });
        }
        state.encrypted = body["encrypted_snapshot"].as_str().unwrap().into();
        state.revision += 1;
        Some(response(
            json!({"snapshot_revision":state.revision,"key_epoch":1,"membership_generation":3}),
        ))
    });
    api.session(dir.path());
    StoreFile::lock(identity_path.with_extension("origin.json"))
        .unwrap()
        .write(&serde_json::to_vec(&api.origin).unwrap(), true)
        .unwrap();
    let unlock = format!("{PASSWORD}\n");
    let identity_arg = identity_path.to_str().unwrap();
    let show = [
        "--identity-file",
        identity_arg,
        "show",
        "existing",
        "--collection",
        &id,
    ];
    let result = run(dir.path(), &show, &unlock);
    ok(&result);
    assert!(String::from_utf8_lossy(&result.stdout).contains("initial-secret"));
    ok(&run(
        dir.path(),
        &[
            "--identity-file",
            identity_arg,
            "put",
            "existing",
            "--replace",
            "--collection",
            &id,
            "--password-stdin",
        ],
        &format!("{unlock}recipient-secret\n"),
    ));
    let result = run(dir.path(), &show, &unlock);
    ok(&result);
    assert!(String::from_utf8_lossy(&result.stdout).contains("recipient-secret"));
    state.lock().unwrap().failure = 409;
    let failed = run(
        dir.path(),
        &[
            "--identity-file",
            identity_arg,
            "generate",
            "draft",
            "--collection",
            &id,
        ],
        &unlock,
    );
    assert!(!failed.status.success());
    let preserved = drafts(dir.path());
    assert_eq!(preserved.len(), 1);
    let access: Value =
        serde_json::from_slice(&std::fs::read(preserved[0].join("snapshot.access.json")).unwrap())
            .unwrap();
    let draft = std::fs::read(preserved[0].join("snapshot.petika")).unwrap();
    let (mode, context) = petika_core::envelope_metadata(&draft).unwrap();
    let opened = identity
        .open_key_package(
            &serde_json::from_value(access["package"].clone()).unwrap(),
            &public,
            &draft,
            &context.unwrap(),
            mode,
        )
        .unwrap();
    assert_eq!(opened.get("draft").unwrap().password.len(), 24);
    state.lock().unwrap().failure = 400; // Trust bundle changed: never use stale local pins silently.
    let rejected = run(dir.path(), &show, &unlock);
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    state.lock().unwrap().failure = 0;

    let no_identity = run(
        dir.path(),
        &["show", "existing", "--collection", &id],
        &unlock,
    );
    assert!(!no_identity.status.success());
    assert!(no_identity.stdout.is_empty());
    StoreFile::lock(identity_path.with_extension("epochs.json"))
        .unwrap()
        .write(
            &serde_json::to_vec(&json!({format!("{}:{}", "d".repeat(64), id):2})).unwrap(),
            false,
        )
        .unwrap();
    let rollback = run(dir.path(), &show, &unlock);
    assert!(!rollback.status.success());
    assert!(rollback.stdout.is_empty());
    StoreFile::lock(identity_path.with_extension("epochs.json"))
        .unwrap()
        .write(b"{}", false)
        .unwrap();
    StoreFile::lock(identity_path.with_extension("origin.json"))
        .unwrap()
        .write(b"\"https://another.example\"", false)
        .unwrap();
    let origin = run(dir.path(), &show, &unlock);
    assert!(!origin.status.success());
    assert!(origin.stdout.is_empty());
    StoreFile::lock(identity_path.with_extension("origin.json"))
        .unwrap()
        .write(&serde_json::to_vec(&api.origin).unwrap(), false)
        .unwrap();
    package.lock().unwrap()["signature"] = "invalid".into();
    let rejected = run(dir.path(), &show, &unlock);
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(state.lock().unwrap().writes, 2);
    assert!(!dir.path().join("unused.petika").exists());
}
