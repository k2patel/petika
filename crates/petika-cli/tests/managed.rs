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

#[cfg(feature = "experimental-entry-format")]
#[path = "managed/migration.rs"]
mod migration;
#[cfg(feature = "experimental-entry-format")]
#[path = "managed/rotation.rs"]
mod rotation;

#[cfg(feature = "experimental-entry-format")]
#[test]
fn confirmed_entry_history_resumes_after_partial_sync_without_resetting_pin() {
    use petika_core::{
        entry_format::{
            checkpoint::*, checkpoint_store::CheckpointStore, index::*, transport::*, *,
        },
        identity::{CheckpointTarget, UnlockedIdentity},
    };
    let dir = tempfile::tempdir().unwrap();
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let recovery_bytes = root.wrap_recovery(PASSWORD).unwrap();
    let recovery_value: Value = serde_json::from_slice(&recovery_bytes).unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let wrappers = vec![WrapperRef {
        wrapper_id: recovery_value["wrapper_id"].as_str().unwrap().into(),
        digest: hex(&digest(&recovery_bytes)),
    }];
    let mut objects = Vec::new();
    let mut parent = String::new();
    for revision in 1..=35 {
        let index = Index {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision,
            parent_digest: parent.clone(),
            membership_generation: 1,
            wrappers: wrappers.clone(),
            root_folder: String::new(),
            folders: vec![],
            entries: vec![],
            tombstones: vec![],
        };
        let envelope = root
            .seal(
                &Header {
                    entry_format_version: 1,
                    suite: SUITE.into(),
                    context: root.context().clone(),
                    kind: Kind::Index,
                    object_id: String::new(),
                    revision,
                },
                &serde_json::to_vec(&index).unwrap(),
            )
            .unwrap();
        let head = Head {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision,
            parent_digest: parent,
            index_digest: hex(&digest(&envelope)),
            wrapper_set_digest: wrapper_set_digest(&wrappers).unwrap(),
            membership_generation: 1,
        };
        parent = head.digest().unwrap();
        objects.push(HistoryObject {
            head,
            envelope: String::from_utf8(envelope).unwrap(),
        });
    }
    let authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
    let checkpoint = authority
        .sign_entry_checkpoint(
            &root,
            CheckpointTarget {
                head_revision: 1,
                head_digest: objects[0].head.digest().unwrap(),
                membership_generation: 1,
                delivery_profile: DeliveryProfile::Standard,
            },
            &wrappers,
        )
        .unwrap();
    let checkpoint_digest = checkpoint.digest().unwrap();
    let fingerprint = checkpoint.authority.fingerprint.clone();
    let anchor = dir.path().join("anchor.json");
    let cp = dir.path().join("checkpoint.json");
    let recovery = dir.path().join("recovery.json");
    let pin = dir.path().join("pin.json");
    let cache = dir.path().join("cache");
    for (path, bytes) in [
        (&anchor, serde_json::to_vec(&objects[0]).unwrap()),
        (&cp, serde_json::to_vec(&checkpoint).unwrap()),
        (&recovery, recovery_bytes.clone()),
    ] {
        StoreFile::lock(path).unwrap().write(&bytes, true).unwrap();
    }
    let mut trust = vec![
        "entries",
        "trust",
        "--checkpoint",
        cp.to_str().unwrap(),
        "--checkpoint-digest",
        &checkpoint_digest,
        "--authority-fingerprint",
        &fingerprint,
        "--index",
        anchor.to_str().unwrap(),
        "--recovery",
        recovery.to_str().unwrap(),
        "--pin",
        pin.to_str().unwrap(),
        "--cache",
        cache.to_str().unwrap(),
    ];
    assert!(!run(dir.path(), &trust, "").status.success());
    assert!(!pin.exists());
    trust.push("--confirm");
    // Another valid wrapper for the same root is not an authorized fallback.
    StoreFile::lock(&recovery)
        .unwrap()
        .write(&root.wrap_recovery(PASSWORD).unwrap(), false)
        .unwrap();
    assert!(
        !run(dir.path(), &trust, &format!("{PASSWORD}\n"))
            .status
            .success()
    );
    assert!(!pin.exists());
    StoreFile::lock(&recovery)
        .unwrap()
        .write(&recovery_bytes, false)
        .unwrap();
    ok(&run(dir.path(), &trust, &format!("{PASSWORD}\n")));
    let original_pin = std::fs::read(&pin).unwrap();
    assert!(
        !run(dir.path(), &trust, &format!("{PASSWORD}\n"))
            .status
            .success()
    );
    assert_eq!(std::fs::read(&pin).unwrap(), original_pin);
    let context = root.context().clone();
    let api = Api::new(move |request| {
        if request.path == "/v1/collections" {
            return Some(response(
                json!([{"id":"b".repeat(64), "group":false, "edit":true}]),
            ));
        }
        assert_eq!(
            request.path,
            format!("/v1/collections/{}/entry-history", "b".repeat(64))
        );
        assert!(request.headers.contains("x-petika-request: 1"));
        let input = HistoryRequest::parse(request.body.as_bytes()).unwrap();
        assert_eq!(input.context, context);
        // First process accepts one page, then loses the connection. A new
        // process starts from its saved head, without an ad hoc trust reset.
        if input.target.is_some() {
            return None;
        }
        let target = Cursor::from_head(&objects[34].head).unwrap();
        let items = objects
            .iter()
            .skip(input.after.revision as usize)
            .take(input.limit)
            .cloned()
            .collect();
        let page = HistoryPage {
            version: 1,
            context: context.clone(),
            after: input.after.clone(),
            target,
            items,
        };
        Some(Response {
            status: 200,
            revision: None,
            body: String::from_utf8(page.encode(&input).unwrap()).unwrap(),
        })
    });
    api.session(dir.path());
    let sync = [
        "entries",
        "sync",
        "--anchor",
        anchor.to_str().unwrap(),
        "--recovery",
        recovery.to_str().unwrap(),
        "--pin",
        pin.to_str().unwrap(),
        "--cache",
        cache.to_str().unwrap(),
    ];
    assert!(
        !run(dir.path(), &sync, &format!("{PASSWORD}\n"))
            .status
            .success()
    );
    assert_eq!(
        CheckpointStore::lock(&pin)
            .unwrap()
            .head(root.context())
            .unwrap()
            .revision,
        33
    );
    ok(&run(dir.path(), &sync, &format!("{PASSWORD}\n")));
    assert_eq!(
        CheckpointStore::lock(&pin)
            .unwrap()
            .head(root.context())
            .unwrap()
            .revision,
        35
    );
    let pinned = std::fs::read(&pin).unwrap();
    ok(&run(dir.path(), &sync, &format!("{PASSWORD}\n")));
    assert_eq!(std::fs::read(&pin).unwrap(), pinned);
}
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

#[cfg(feature = "experimental-entry-format")]
#[test]
fn encrypted_entry_drafts_reconcile_lost_receipts_and_reject_conflicts() {
    entry_draft_workflow(false);
}
#[cfg(feature = "experimental-entry-format")]
#[test]
fn recipient_entry_drafts_reconcile_lost_receipts_and_reject_conflicts() {
    entry_draft_workflow(true);
}
#[cfg(feature = "experimental-entry-format")]
fn entry_draft_workflow(recipient_unlock: bool) {
    use petika_core::{
        entry_format::{
            checkpoint::*, checkpoint_store::CheckpointStore, index::*, transaction::*,
            transport::*, *,
        },
        identity::{CheckpointTarget, UnlockedIdentity},
    };
    use std::collections::BTreeMap;
    let dir = tempfile::tempdir().unwrap();
    let root = Arc::new(RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap());
    let recovery_bytes = root.wrap_recovery(PASSWORD).unwrap();
    let wrapper: Value = serde_json::from_slice(&recovery_bytes).unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut wrappers = vec![WrapperRef {
        wrapper_id: wrapper["wrapper_id"].as_str().unwrap().into(),
        digest: hex(&digest(&recovery_bytes)),
    }];
    let mut authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
    let mut recipient = UnlockedIdentity::generate(&"a".repeat(64), &"2".repeat(64), 1).unwrap();
    let public = recipient.public_identity();
    authority
        .verify_contact(&public.user_id, public, &public.fingerprint, None)
        .unwrap();
    let public = authority.public_identity();
    recipient
        .verify_contact(&public.user_id, public, &public.fingerprint, None)
        .unwrap();
    let package = authority
        .create_entry_key_package(
            &root,
            recipient.public_identity(),
            1,
            DeliveryProfile::Standard,
        )
        .unwrap();
    wrappers.push(package.reference().unwrap());
    let id = "1".repeat(64);
    let original = Entry {
        username: "original-user".into(),
        password: "old synthetic password".into(),
        url: "https://example.com".into(),
        notes: "preserve these notes".into(),
        otp: Some("JBSWY3DPEHPK3PXP".into()),
    };
    let payload = String::from_utf8(
        root.seal(
            &Header {
                entry_format_version: 1,
                suite: SUITE.into(),
                context: root.context().clone(),
                kind: Kind::Entry,
                object_id: id.clone(),
                revision: 1,
            },
            &serde_json::to_vec(&original).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let index = Index {
        version: 1,
        context: root.context().clone(),
        suite: SUITE.into(),
        revision: 1,
        parent_digest: String::new(),
        membership_generation: 1,
        wrappers: wrappers.clone(),
        root_folder: String::new(),
        folders: vec![],
        entries: vec![EntryRef {
            id: id.clone(),
            folder: String::new(),
            name: "Original name".into(),
            revision: 1,
            digest: hex(&digest(payload.as_bytes())),
        }],
        tombstones: vec![],
    };
    let envelope = String::from_utf8(
        root.seal(
            &Header {
                entry_format_version: 1,
                suite: SUITE.into(),
                context: root.context().clone(),
                kind: Kind::Index,
                object_id: String::new(),
                revision: 1,
            },
            &serde_json::to_vec(&index).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let initial = HistoryObject {
        head: Head {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: 1,
            parent_digest: String::new(),
            index_digest: hex(&digest(envelope.as_bytes())),
            wrapper_set_digest: wrapper_set_digest(&wrappers).unwrap(),
            membership_generation: 1,
        },
        envelope,
    };
    let checkpoint = authority
        .sign_entry_checkpoint(
            &root,
            CheckpointTarget {
                head_revision: 1,
                head_digest: initial.head.digest().unwrap(),
                membership_generation: 1,
                delivery_profile: DeliveryProfile::Standard,
            },
            &wrappers,
        )
        .unwrap();
    let trusted = TrustedCheckpoint::bootstrap(
        checkpoint.clone(),
        &checkpoint.digest().unwrap(),
        &checkpoint.authority.fingerprint,
    )
    .unwrap();
    let handoff_path = dir.path().join("handoff.json");
    let identity_path = dir.path().join("recipient.json");
    let verified =
        VerifiedIndex::open(&root, initial.head.clone(), initial.envelope.as_bytes()).unwrap();
    let handoff = authority
        .prepare_entry_handoff(
            &trusted,
            &verified,
            recipient.public_identity(),
            &serde_json::to_vec(&package).unwrap(),
            &wrappers,
        )
        .unwrap();
    StoreFile::lock(&handoff_path)
        .unwrap()
        .write(&serde_json::to_vec(&handoff).unwrap(), true)
        .unwrap();
    StoreFile::lock(&identity_path)
        .unwrap()
        .write(&recipient.seal(PASSWORD).unwrap(), true)
        .unwrap();
    let pin = dir.path().join("pin.json");
    let anchor = dir.path().join("anchor.json");
    let recovery = dir.path().join("recovery.json");
    let cache = dir.path().join("cache");
    std::fs::create_dir(&cache).unwrap();
    let initial_bytes = serde_json::to_vec(&initial).unwrap();
    for (path, bytes) in [
        (anchor.clone(), initial_bytes.clone()),
        (
            cache.join(format!("{}.json", initial.head.digest().unwrap())),
            initial_bytes,
        ),
        (recovery.clone(), recovery_bytes),
    ] {
        StoreFile::lock(path).unwrap().write(&bytes, true).unwrap();
    }
    CheckpointStore::lock(&pin)
        .unwrap()
        .initialize(
            &trusted,
            &VerifiedIndex::open(&root, initial.head.clone(), initial.envelope.as_bytes()).unwrap(),
        )
        .unwrap();
    struct State {
        current: HistoryObject,
        payloads: BTreeMap<String, String>,
        receipts: BTreeMap<String, Receipt>,
        writes: usize,
        drop_ack: bool,
        forge: bool,
    }
    let state = Arc::new(Mutex::new(State {
        current: initial,
        payloads: BTreeMap::from([(id.clone(), payload)]),
        receipts: BTreeMap::new(),
        writes: 0,
        drop_ack: true,
        forge: false,
    }));
    let shared = state.clone();
    let server_root = root.clone();
    let api = Api::new(move |request| {
        if request.path == "/v1/collections" {
            return Some(response(
                json!([{"id":"b".repeat(64),"group":false,"edit":true}]),
            ));
        }
        if request.path == "/v1/auth/status" {
            return Some(response(json!({"user":{"id":"f".repeat(64)}})));
        }
        let mut state = shared.lock().unwrap();
        assert!(
            !request.body.contains("Original name")
                && !request.body.contains("preserve these notes")
                && !request.body.contains("replacement synthetic password")
        );
        if request.path.ends_with("/entry-object") {
            let body: Value = serde_json::from_str(&request.body).unwrap();
            assert_eq!(body["root"]["digest"], state.current.head.digest().unwrap());
            return Some(Response {
                status: 200,
                revision: None,
                body: state.payloads[body["id"].as_str().unwrap()].clone(),
            });
        }
        if request.path.ends_with("/entry-receipt") {
            let body: Value = serde_json::from_str(&request.body).unwrap();
            return Some(response(
                json!({"receipt":state.receipts.get(body["operation"].as_str().unwrap())}),
            ));
        }
        assert!(request.path.ends_with("/entry-transactions"));
        let tx = Transaction::parse(request.body.as_bytes()).unwrap();
        let previous = VerifiedIndex::open(
            &server_root,
            state.current.head.clone(),
            state.current.envelope.as_bytes(),
        )
        .unwrap();
        if tx.verify(&server_root, &previous).is_err() {
            return Some(Response {
                status: 409,
                revision: None,
                body: "{}".into(),
            });
        }
        for change in &tx.changes {
            match change {
                EntryChange::Put { id, envelope, .. } => {
                    state.payloads.insert(id.clone(), envelope.clone());
                }
                EntryChange::Delete { id, .. } => {
                    state.payloads.remove(id);
                }
            }
        }
        let receipt = Receipt {
            writer: "f".repeat(64),
            operation: tx.operation.clone(),
            request_digest: submission_digest(
                Some(&tx.expected),
                &"f".repeat(64),
                &tx.operation,
                &tx.object,
                &tx.changes,
            )
            .unwrap(),
            accepted: Cursor::from_head(&tx.object.head).unwrap(),
        };
        state.current = tx.object;
        state.writes += 1;
        state.receipts.insert(tx.operation, receipt.clone());
        if state.drop_ack {
            state.drop_ack = false;
            return None;
        }
        let mut ack = receipt;
        if state.forge {
            ack.operation = "0".repeat(64);
            state.forge = false;
        }
        Some(response(json!({"receipt":ack,"replication":"pending"})))
    });
    api.session(dir.path());
    let mut common = vec![
        "--anchor",
        anchor.to_str().unwrap(),
        "--pin",
        pin.to_str().unwrap(),
        "--cache",
        cache.to_str().unwrap(),
    ];
    if recipient_unlock {
        common.extend([
            "--handoff",
            handoff_path.to_str().unwrap(),
            "--recipient-identity",
            identity_path.to_str().unwrap(),
        ]);
    } else {
        common.extend(["--recovery", recovery.to_str().unwrap()]);
    }
    if recipient_unlock {
        let mut args = vec!["entries", "list"];
        args.extend(common.iter().copied());
        let saved_identity = std::fs::read(&identity_path).unwrap();
        let saved_pin = std::fs::read(&pin).unwrap();
        assert!(
            !run(dir.path(), &args, "wrong identity passphrase\n")
                .status
                .success()
        );
        assert_eq!(std::fs::read(&identity_path).unwrap(), saved_identity);
        let stranger = UnlockedIdentity::generate(&"a".repeat(64), &"3".repeat(64), 1).unwrap();
        StoreFile::lock(&identity_path)
            .unwrap()
            .write(&stranger.seal(PASSWORD).unwrap(), false)
            .unwrap();
        assert!(
            !run(dir.path(), &args, &format!("{PASSWORD}\n"))
                .status
                .success()
        );
        assert_eq!(std::fs::read(&pin).unwrap(), saved_pin);
        StoreFile::lock(&identity_path)
            .unwrap()
            .write(&saved_identity, false)
            .unwrap();
        args.extend(["--recovery", recovery.to_str().unwrap()]);
        assert!(!run(dir.path(), &args, "").status.success());
    }
    let one = dir.path().join("one.draft");
    let two = dir.path().join("two.draft");
    for draft in [&one, &two] {
        let mut args = vec![
            "entries",
            "put",
            "--password-stdin",
            "--id",
            &id,
            "--draft",
            draft.to_str().unwrap(),
        ];
        args.extend(common.iter().copied());
        ok(&run(
            dir.path(),
            &args,
            &format!("{PASSWORD}\nreplacement synthetic password\n"),
        ));
        let raw = std::fs::read_to_string(draft).unwrap();
        assert!(
            !raw.contains("Original name")
                && !raw.contains("replacement synthetic password")
                && !raw.contains("preserve these notes")
        );
    }
    let mut review = vec!["entries", "review", "--draft", one.to_str().unwrap()];
    review.extend(common.iter().copied());
    let reviewed = run(dir.path(), &review, &format!("{PASSWORD}\n"));
    ok(&reviewed);
    assert!(String::from_utf8_lossy(&reviewed.stdout).contains("Original name"));
    assert!(!String::from_utf8_lossy(&reviewed.stdout).contains("replacement synthetic password"));
    let submit = |draft: &Path| {
        let mut args = vec![
            "entries",
            "submit",
            "--confirm",
            "--draft",
            draft.to_str().unwrap(),
        ];
        args.extend(common.iter().copied());
        run(dir.path(), &args, &format!("{PASSWORD}\n"))
    };
    assert!(!submit(&one).status.success());
    assert_eq!(state.lock().unwrap().writes, 1);
    assert_eq!(
        CheckpointStore::lock(&pin)
            .unwrap()
            .head(root.context())
            .unwrap()
            .revision,
        1
    );
    assert!(!submit(&two).status.success());
    assert!(one.exists() && two.exists());
    assert_eq!(state.lock().unwrap().writes, 1);
    ok(&submit(&one));
    assert_eq!(state.lock().unwrap().writes, 1);
    assert_eq!(
        CheckpointStore::lock(&pin)
            .unwrap()
            .head(root.context())
            .unwrap()
            .revision,
        2
    );
    ok(&submit(&one));
    assert_eq!(state.lock().unwrap().writes, 1);
    let current = state.lock().unwrap();
    let verified = VerifiedIndex::open(
        &root,
        current.current.head.clone(),
        current.current.envelope.as_bytes(),
    )
    .unwrap();
    let payload: Entry = serde_json::from_slice(
        &verified
            .open_entry(&root, &id, current.payloads[&id].as_bytes())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(payload.notes, original.notes);
    assert_eq!(payload.otp, original.otp);
    assert_eq!(payload.password, "replacement synthetic password");
    drop(current);
    let deletion = dir.path().join("delete.draft");
    let mut args = vec![
        "entries",
        "delete",
        "--id",
        &id,
        "--draft",
        deletion.to_str().unwrap(),
    ];
    args.extend(common.iter().copied());
    ok(&run(dir.path(), &args, &format!("{PASSWORD}\n")));
    state.lock().unwrap().forge = true;
    assert!(!submit(&deletion).status.success());
    assert_eq!(
        CheckpointStore::lock(&pin)
            .unwrap()
            .head(root.context())
            .unwrap()
            .revision,
        2
    );
    assert!(deletion.exists());
    ok(&submit(&deletion));
    assert_eq!(
        CheckpointStore::lock(&pin)
            .unwrap()
            .head(root.context())
            .unwrap()
            .revision,
        3
    );
    assert_eq!(state.lock().unwrap().writes, 2);
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
