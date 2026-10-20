#![cfg(feature = "experimental-entry-format")]
use petika_core::{
    entry_format::{checkpoint::*, checkpoint_store::CheckpointStore, index::*, transport::*, *},
    identity::{CheckpointTarget, UnlockedIdentity},
};
use petika_server::entry_history::build_page;
use petika_server::entry_journal::Journal;
use std::collections::BTreeMap;

#[test]
fn account_entry_api_binds_access_context_receipts_and_legacy_boundary() {
    use petika_server::{
        accounts::{Accounts, KeyOperation, Membership},
        entry_api::dispatch,
        entry_transaction::{EntryChange, Transaction},
    };
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    accounts.migrate().unwrap();
    let password = "synthetic entry account password";
    let owner = accounts
        .create_user("owner", "Owner", password.into(), true, true)
        .unwrap();
    let reader = accounts
        .create_user("reader", "Reader", password.into(), false, false)
        .unwrap();
    let (owner_token, _) = accounts.login("owner", password.into()).unwrap();
    let (reader_token, _) = accounts.login("reader", password.into()).unwrap();
    let group = accounts
        .save_group(
            None,
            "Team",
            vec![
                Membership {
                    user_id: owner.id.clone(),
                    edit: true,
                },
                Membership {
                    user_id: reader.id.clone(),
                    edit: false,
                },
            ],
        )
        .unwrap();
    let deployment = accounts
        .key_operation(&owner_token, KeyOperation::Deployment, b"")
        .unwrap()["deployment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let root = RootKey::generate(deployment, group.id.clone(), 1).unwrap();
    let path = dir
        .path()
        .join("collections")
        .join(&group.id)
        .join("entries");
    let mut journal = Journal::open(path.clone()).unwrap();
    let first = record(&root, 1, String::new());
    let cursor = journal
        .append(None, &owner.id, &"0".repeat(64), first.clone())
        .unwrap()
        .accepted;
    let request = HistoryRequest {
        version: 1,
        context: root.context().clone(),
        after: cursor.clone(),
        target: None,
        limit: 32,
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    // Existing handle prevents a second writer; no state changes while locked.
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-history",
            bytes.as_slice()
        )
        .is_err()
    );
    drop(journal);
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            "invalid",
            &group.id,
            "entry-history",
            bytes.as_slice()
        )
        .is_err()
    );
    let page = dispatch(
        &mut accounts,
        dir.path(),
        &reader_token,
        &group.id,
        "entry-history",
        bytes.as_slice(),
    )
    .unwrap();
    HistoryPage::parse(&page, &request).unwrap();
    let entry_id = "8".repeat(64);
    let envelope = String::from_utf8(
        root.seal(
            &Header {
                entry_format_version: 1,
                suite: SUITE.into(),
                context: root.context().clone(),
                kind: Kind::Entry,
                object_id: entry_id.clone(),
                revision: 1,
            },
            b"synthetic API entry",
        )
        .unwrap(),
    )
    .unwrap();
    let entry_digest = hex(&digest(envelope.as_bytes()));
    let object = record_entries(
        &root,
        2,
        cursor.digest.clone(),
        vec![EntryRef {
            id: entry_id.clone(),
            folder: String::new(),
            name: "Synthetic".into(),
            revision: 1,
            digest: entry_digest.clone(),
        }],
        vec![],
    );
    let read_cursor = Cursor::from_head(&object.head).unwrap();
    let tx = Transaction {
        version: 1,
        operation: "1".repeat(64),
        expected: cursor,
        object,
        changes: vec![EntryChange::Put {
            id: entry_id.clone(),
            expected: None,
            revision: 1,
            envelope: envelope.clone(),
        }],
    };
    let tx_bytes = serde_json::to_vec(&tx).unwrap();
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-transactions",
            tx_bytes.as_slice()
        )
        .is_err()
    );
    let accepted = dispatch(
        &mut accounts,
        dir.path(),
        &owner_token,
        &group.id,
        "entry-transactions",
        tx_bytes.as_slice(),
    )
    .unwrap();
    let entry_request = serde_json::to_vec(&serde_json::json!({"context": root.context(), "root":read_cursor,"id":entry_id,"digest":entry_digest})).unwrap();
    assert_eq!(
        dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-object",
            entry_request.as_slice()
        )
        .unwrap(),
        envelope.as_bytes()
    );
    assert_eq!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-transactions",
            tx_bytes.as_slice()
        )
        .unwrap(),
        accepted
    );
    let receipt_bytes = serde_json::to_vec(
        &serde_json::json!({"context": root.context(), "operation": tx.operation}),
    )
    .unwrap();
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-receipt",
            receipt_bytes.as_slice()
        )
        .is_err()
    );
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-receipt",
            receipt_bytes.as_slice()
        )
        .is_ok()
    );
    let mut foreign = request.clone();
    foreign.context.collection_id = owner.id.clone();
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-history",
            serde_json::to_vec(&foreign).unwrap().as_slice()
        )
        .is_err()
    );
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-history",
            &vec![b' '; 4097][..]
        )
        .is_err()
    );
    accounts
        .with_entry_access(&owner_token, &group.id, true, |_| {
            assert!(petika_core::StoreFile::lock(dir.path().join("accounts.json")).is_err());
            Ok(())
        })
        .unwrap();
    accounts
        .save_group(
            Some(&group.id),
            "Team",
            vec![Membership {
                user_id: owner.id.clone(),
                edit: true,
            }],
        )
        .unwrap();
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-history",
            bytes.as_slice()
        )
        .is_err()
    );
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-transactions",
            tx_bytes.as_slice()
        )
        .is_err()
    );
    // A legacy file prevents any dual-format serving or implicit cutover.
    petika_core::StoreFile::lock(path.parent().unwrap().join("snapshot.json"))
        .unwrap()
        .write(b"legacy marker", true)
        .unwrap();
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-history",
            bytes.as_slice()
        )
        .is_err()
    );
    accounts.logout(&owner_token);
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-receipt",
            receipt_bytes.as_slice()
        )
        .is_err()
    );
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn real_http_entry_routes_require_runtime_gate_session_and_request_headers() {
    use petika_server::accounts::{Accounts, KeyOperation};
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    struct Running(Child);
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn request(
        address: std::net::SocketAddr,
        method: &str,
        path: &str,
        headers: &str,
        body: &str,
    ) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    accounts.migrate().unwrap();
    let password = "synthetic HTTP entry password";
    let user = accounts
        .create_user("owner", "Owner", password.into(), true, true)
        .unwrap();
    let (token, _) = accounts.login("owner", password.into()).unwrap();
    let deployment = accounts
        .key_operation(&token, KeyOperation::Deployment, b"")
        .unwrap()["deployment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let root = RootKey::generate(deployment, user.id.clone(), 1).unwrap();
    let first = record(&root, 1, String::new());
    let cursor = Journal::open(
        dir.path()
            .join("collections")
            .join(&user.id)
            .join("entries"),
    )
    .unwrap()
    .append(None, &user.id, &"0".repeat(64), first)
    .unwrap()
    .accepted;
    let history = HistoryRequest {
        version: 1,
        context: root.context().clone(),
        after: cursor.clone(),
        target: None,
        limit: 32,
    };
    let history_body = serde_json::to_string(&history).unwrap();
    let token_file = dir.path().join("server-token");
    petika_core::StoreFile::lock(&token_file)
        .unwrap()
        .write("a".repeat(64).as_bytes(), true)
        .unwrap();
    drop(accounts);
    for enabled in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut server = Running(
            Command::new(env!("CARGO_BIN_EXE_petika-server"))
                .env("PETIKA_TOKEN_FILE", &token_file)
                .env("PETIKA_DATA_DIR", dir.path())
                .env("PETIKA_LISTEN", address.to_string())
                .env("PETIKA_COOKIE_SECURE", "false")
                .env(
                    "PETIKA_EXPERIMENTAL_ENTRIES",
                    if enabled { "1" } else { "0" },
                )
                .env_remove("PETIKA_GIT_MIRROR")
                .env_remove("PETIKA_INITIAL_SNAPSHOT_FILE")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(address).is_err() {
            assert!(
                Instant::now() < deadline && server.0.try_wait().unwrap().is_none(),
                "server did not start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let login = request(
            address,
            "POST",
            "/v1/auth/login",
            "Content-Type: application/json\r\nX-Petika-Request: 1\r\n",
            &serde_json::json!({"username":"owner", "password":password}).to_string(),
        );
        assert!(login.starts_with("HTTP/1.1 200"), "{login}");
        let cookie = login
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
                    .map(|(_, value)| value.trim().split(';').next().unwrap().to_owned())
            })
            .unwrap();
        let headers = format!(
            "Cookie: {cookie}\r\nContent-Type: application/json\r\nX-Petika-Request: 1\r\n"
        );
        let prefix = format!("/v1/collections/{}", user.id);
        let response = request(
            address,
            "POST",
            &format!("{prefix}/entry-history"),
            &headers,
            &history_body,
        );
        assert!(
            response.starts_with(if enabled {
                "HTTP/1.1 200"
            } else {
                "HTTP/1.1 404"
            }),
            "{response}"
        );
        let legacy = request(address, "GET", &format!("{prefix}/snapshot"), &headers, "");
        assert!(legacy.starts_with("HTTP/1.1 426"));
        let delivery = request(
            address,
            "POST",
            &format!("{prefix}/recipient-snapshot"),
            &headers,
            "{}",
        );
        assert!(delivery.starts_with("HTTP/1.1 426"));
        let status = request(address, "GET", &format!("{prefix}/status"), &headers, "");
        assert!(status.starts_with("HTTP/1.1 200") && status.contains("entry-v1"));
        if enabled {
            for invalid in [
                "".to_owned(),
                format!("Cookie: {cookie}\r\nContent-Type: application/json\r\n"),
                format!("{headers}Sec-Fetch-Site: cross-site\r\n"),
            ] {
                assert!(
                    request(
                        address,
                        "POST",
                        &format!("{prefix}/entry-history"),
                        &invalid,
                        &history_body
                    )
                    .starts_with("HTTP/1.1 403")
                );
            }
            assert!(
                request(
                    address,
                    "POST",
                    &format!("{prefix}/entry-history"),
                    &headers,
                    &" ".repeat(4097)
                )
                .starts_with("HTTP/1.1 409")
            );
        }
        drop(server);
    }
    assert_eq!(
        Journal::open(dir.path().join("collections").join(user.id).join("entries"))
            .unwrap()
            .current(),
        Some(cursor)
    );
}
fn record(root: &RootKey, revision: u64, parent: String) -> HistoryObject {
    record_entries(root, revision, parent, vec![], vec![])
}
fn record_entries(
    root: &RootKey,
    revision: u64,
    parent: String,
    entries: Vec<EntryRef>,
    tombstones: Vec<Tombstone>,
) -> HistoryObject {
    let wrappers = vec![WrapperRef {
        wrapper_id: "d".repeat(64),
        digest: "e".repeat(64),
    }];
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
        entries,
        tombstones,
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
    HistoryObject {
        head: Head {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision,
            parent_digest: parent,
            index_digest: hex(&digest(&envelope)),
            wrapper_set_digest: wrapper_set_digest(&wrappers).unwrap(),
            membership_generation: 1,
        },
        envelope: String::from_utf8(envelope).unwrap(),
    }
}
#[test]
fn entry_transactions_preserve_other_ciphertexts_and_tombstones() {
    use petika_server::entry_transaction::{EntryChange, EntryVersion, Transaction};
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(dir.path().into()).unwrap();
    let initial = record(&root, 1, String::new());
    journal
        .append(None, &"f".repeat(64), &"0".repeat(64), initial)
        .unwrap();
    let seal = |id: &str, revision| {
        String::from_utf8(
            root.seal(
                &Header {
                    entry_format_version: 1,
                    suite: SUITE.into(),
                    context: root.context().clone(),
                    kind: Kind::Entry,
                    object_id: id.into(),
                    revision,
                },
                b"synthetic secret",
            )
            .unwrap(),
        )
        .unwrap()
    };
    let ids = ["1".repeat(64), "2".repeat(64)];
    let payloads = [seal(&ids[0], 1), seal(&ids[1], 1)];
    let refs: Vec<_> = ids
        .iter()
        .zip(&payloads)
        .map(|(id, payload)| EntryRef {
            id: id.clone(),
            folder: String::new(),
            name: id.clone(),
            revision: 1,
            digest: hex(&digest(payload.as_bytes())),
        })
        .collect();
    let prior = journal.current().unwrap();
    let object = record_entries(&root, 2, prior.digest.clone(), refs.clone(), vec![]);
    let tx = Transaction {
        version: 1,
        operation: "3".repeat(64),
        expected: prior,
        object: object.clone(),
        changes: ids
            .iter()
            .zip(&payloads)
            .map(|(id, payload)| EntryChange::Put {
                id: id.clone(),
                expected: None,
                revision: 1,
                envelope: payload.clone(),
            })
            .collect(),
    };
    let receipt = journal.transact(&"f".repeat(64), tx.clone()).unwrap();
    assert_eq!(
        journal.transact(&"f".repeat(64), tx.clone()).unwrap(),
        receipt
    );
    let mut changed = tx.clone();
    changed.changes.reverse();
    assert!(journal.transact(&"f".repeat(64), changed).is_err());
    let version = EntryVersion {
        revision: 1,
        digest: refs[0].digest.clone(),
    };
    let payload = seal(&ids[0], 2);
    let mut next_refs = refs.clone();
    next_refs[0].revision = 2;
    next_refs[0].digest = hex(&digest(payload.as_bytes()));
    let object3 = record_entries(
        &root,
        3,
        receipt.accepted.digest.clone(),
        next_refs.clone(),
        vec![],
    );
    let valid_change = EntryChange::Put {
        id: ids[0].clone(),
        expected: Some(version.clone()),
        revision: 2,
        envelope: payload.clone(),
    };
    for changes in [
        vec![valid_change.clone(), valid_change.clone()],
        vec![EntryChange::Put {
            id: ids[0].clone(),
            expected: None,
            revision: 2,
            envelope: payload.clone(),
        }],
        vec![EntryChange::Put {
            id: ids[0].clone(),
            expected: Some(version.clone()),
            revision: 3,
            envelope: payload.clone(),
        }],
        vec![EntryChange::Put {
            id: ids[1].clone(),
            expected: Some(EntryVersion {
                revision: 1,
                digest: refs[1].digest.clone(),
            }),
            revision: 2,
            envelope: payload.clone(),
        }],
        vec![EntryChange::Put {
            id: ids[0].clone(),
            expected: Some(version.clone()),
            revision: 2,
            envelope: "{}".into(),
        }],
        vec![EntryChange::Delete {
            id: ids[1].clone(),
            expected: EntryVersion {
                revision: 1,
                digest: "0".repeat(64),
            },
        }],
    ] {
        assert!(
            journal
                .transact(
                    &"f".repeat(64),
                    Transaction {
                        version: 1,
                        operation: "9".repeat(64),
                        expected: receipt.accepted.clone(),
                        object: object3.clone(),
                        changes
                    }
                )
                .is_err()
        );
        assert_eq!(journal.current(), Some(receipt.accepted.clone()));
    }
    let third = journal
        .transact(
            &"f".repeat(64),
            Transaction {
                version: 1,
                operation: "4".repeat(64),
                expected: receipt.accepted.clone(),
                object: object3.clone(),
                changes: vec![EntryChange::Put {
                    id: ids[0].clone(),
                    expected: Some(version),
                    revision: 2,
                    envelope: payload.clone(),
                }],
            },
        )
        .unwrap();
    assert_eq!(
        journal
            .entry(&third.accepted, &ids[1], &refs[1].digest)
            .unwrap(),
        payloads[1]
    );
    assert_eq!(
        journal
            .entry(&receipt.accepted, &ids[0], &refs[0].digest)
            .unwrap(),
        payloads[0]
    );
    assert!(
        journal
            .entry(&third.accepted, &ids[0], &refs[0].digest)
            .is_err()
    );
    let before = VerifiedIndex::open(&root, object.head, object.envelope.as_bytes()).unwrap();
    let after = VerifiedIndex::open(&root, object3.head, object3.envelope.as_bytes()).unwrap();
    after.follows(&before).unwrap();
    let fourth_object = record_entries(
        &root,
        4,
        third.accepted.digest.clone(),
        vec![refs[1].clone()],
        vec![Tombstone {
            id: ids[0].clone(),
            final_revision: 3,
            deletion_revision: 4,
            prior_digest: next_refs[0].digest.clone(),
        }],
    );
    let fourth = journal
        .transact(
            &"f".repeat(64),
            Transaction {
                version: 1,
                operation: "5".repeat(64),
                expected: third.accepted.clone(),
                object: fourth_object.clone(),
                changes: vec![EntryChange::Delete {
                    id: ids[0].clone(),
                    expected: EntryVersion {
                        revision: 2,
                        digest: next_refs[0].digest.clone(),
                    },
                }],
            },
        )
        .unwrap();
    VerifiedIndex::open(&root, fourth_object.head, fourth_object.envelope.as_bytes())
        .unwrap()
        .follows(&after)
        .unwrap();
    assert!(
        journal
            .entry(&fourth.accepted, &ids[0], &next_refs[0].digest)
            .is_err()
    );
    drop(journal);
    let mut journal = Journal::open(dir.path().into()).unwrap();
    assert_eq!(
        journal
            .entry(&third.accepted, &ids[0], &next_refs[0].digest)
            .unwrap(),
        payload
    );
    let resurrection = Transaction {
        version: 1,
        operation: "6".repeat(64),
        expected: fourth.accepted.clone(),
        object: record_entries(&root, 5, fourth.accepted.digest, refs.clone(), vec![]),
        changes: vec![EntryChange::Put {
            id: ids[0].clone(),
            expected: None,
            revision: 1,
            envelope: payloads[0].clone(),
        }],
    };
    assert!(journal.transact(&"f".repeat(64), resurrection).is_err());
    let mut stale = tx;
    stale.operation = "7".repeat(64);
    assert!(journal.transact(&"f".repeat(64), stale).is_err());
}
#[test]
fn committed_journal_pages_authenticate_after_restart() {
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(dir.path().into()).unwrap();
    let first = record(&root, 1, String::new());
    let previous =
        VerifiedIndex::open(&root, first.head.clone(), first.envelope.as_bytes()).unwrap();
    for revision in 1..=3 {
        let expected = journal.current();
        let object = if revision == 1 {
            first.clone()
        } else {
            record(
                &root,
                revision,
                expected
                    .as_ref()
                    .map(|c| c.digest.clone())
                    .unwrap_or_default(),
            )
        };
        journal
            .append(
                expected.as_ref(),
                &"f".repeat(64),
                &format!("{revision:064x}"),
                object,
            )
            .unwrap();
    }
    drop(journal);
    let journal = Journal::open(dir.path().into()).unwrap();
    let request = HistoryRequest {
        version: 1,
        context: root.context().clone(),
        after: Cursor::from_head(&first.head).unwrap(),
        target: None,
        limit: 32,
    };
    let bytes = journal.history(&request).unwrap();
    let page = HistoryPage::parse(&bytes, &request).unwrap();
    assert_eq!(page.items.len(), 2);
    page.verify(&request, &root, &previous).unwrap();
}
#[test]
fn server_pages_round_trip_to_durable_client_and_keep_a_fixed_target() {
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let mut journal = BTreeMap::new();
    let mut parent = String::new();
    for revision in 1..=4 {
        let item = record(&root, revision, parent);
        parent = item.head.digest().unwrap();
        journal.insert(revision, item);
    }
    let first = &journal[&1];
    let previous =
        VerifiedIndex::open(&root, first.head.clone(), first.envelope.as_bytes()).unwrap();
    let authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
    let cp = authority
        .sign_entry_checkpoint(
            &root,
            CheckpointTarget {
                head_revision: 1,
                head_digest: first.head.digest().unwrap(),
                membership_generation: 1,
                delivery_profile: DeliveryProfile::Standard,
            },
            &previous.index().wrappers,
        )
        .unwrap();
    let digest = cp.digest().unwrap();
    let fingerprint = cp.authority.fingerprint.clone();
    let trusted = TrustedCheckpoint::bootstrap(cp, &digest, &fingerprint).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pin");
    let store = CheckpointStore::lock(&path).unwrap();
    store.initialize(&trusted, &previous).unwrap();
    let request = HistoryRequest {
        version: 1,
        context: root.context().clone(),
        after: Cursor::from_head(&first.head).unwrap(),
        target: None,
        limit: 1,
    };
    let read = |revision| {
        journal
            .get(&revision)
            .cloned()
            .ok_or(petika_core::Error::Format)
    };
    let bytes = build_page(
        &request,
        Cursor::from_head(&journal[&3].head).unwrap(),
        read,
    )
    .unwrap();
    let page = HistoryPage::parse(&bytes, &request).unwrap();
    let next_request = page.next_request(&request).unwrap().unwrap();
    let accepted = store
        .accept_history_response(&request, &bytes, &root, &previous)
        .unwrap()
        .unwrap();
    assert_eq!(accepted.head(), &journal[&2].head);
    let saved = std::fs::read(&path).unwrap();
    assert!(
        store
            .accept_history_response(&request, &bytes, &root, &previous)
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    drop(store);
    let store = CheckpointStore::lock(&path).unwrap();
    // Server advanced to four, but this catch-up remains pinned to target three.
    let bytes = build_page(
        &next_request,
        Cursor::from_head(&journal[&4].head).unwrap(),
        read,
    )
    .unwrap();
    let page = HistoryPage::parse(&bytes, &next_request).unwrap();
    assert_eq!(page.target.revision, 3);
    assert!(page.next_request(&next_request).unwrap().is_none());
    let final_index = store
        .accept_history_response(&next_request, &bytes, &root, &accepted)
        .unwrap()
        .unwrap();
    assert_eq!(final_index.head(), &journal[&3].head);
    let done = HistoryRequest {
        after: Cursor::from_head(final_index.head()).unwrap(),
        target: Some(page.target),
        ..next_request
    };
    let bytes = build_page(&done, Cursor::from_head(&journal[&4].head).unwrap(), read).unwrap();
    assert!(
        store
            .accept_history_response(&done, &bytes, &root, &final_index)
            .unwrap()
            .is_none()
    );
    assert_eq!(store.head(root.context()).unwrap(), journal[&3].head);
    assert!(
        build_page(
            &request,
            Cursor::from_head(&journal[&3].head).unwrap(),
            |_| Err(petika_core::Error::Format)
        )
        .is_err()
    );
}
#[test]
fn transport_rejects_ambiguous_mismatched_and_oversized_responses() {
    let root = RootKey::generate("a".repeat(64), "b".repeat(64), 1).unwrap();
    let first = record(&root, 1, String::new());
    let second = record(&root, 2, first.head.digest().unwrap());
    let request = HistoryRequest {
        version: 1,
        context: root.context().clone(),
        after: Cursor::from_head(&first.head).unwrap(),
        target: Some(Cursor::from_head(&second.head).unwrap()),
        limit: 1,
    };
    let page = HistoryPage {
        version: 1,
        context: root.context().clone(),
        after: request.after.clone(),
        target: request.target.clone().unwrap(),
        items: vec![second],
    };
    let bytes = page.encode(&request).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for field in ["after", "target"] {
        let mut bad = value.clone();
        bad[field]["digest"] = "0".repeat(64).into();
        assert!(HistoryPage::parse(&serde_json::to_vec(&bad).unwrap(), &request).is_err());
    }
    let mut bad = value.clone();
    bad["items"] = serde_json::json!([]);
    assert!(HistoryPage::parse(&serde_json::to_vec(&bad).unwrap(), &request).is_err());
    let mut bad = value.clone();
    bad["items"][0]["envelope"] = "tampered".into();
    assert!(HistoryPage::parse(&serde_json::to_vec(&bad).unwrap(), &request).is_err());
    let mut bad = value;
    bad["context"]["collection_id"] = "0".repeat(64).into();
    assert!(HistoryPage::parse(&serde_json::to_vec(&bad).unwrap(), &request).is_err());
    let duplicate = format!(
        "{{\"version\":1,{}",
        std::str::from_utf8(&bytes).unwrap().trim_start_matches('{')
    );
    assert!(HistoryPage::parse(duplicate.as_bytes(), &request).is_err());
    assert!(HistoryPage::parse(&vec![b' '; MAX_HISTORY_WIRE_BYTES + 1], &request).is_err());
    let mut bad_request = request.clone();
    bad_request.limit = 33;
    assert!(bad_request.validate().is_err());
    assert!(HistoryRequest::parse(&vec![b' '; 4097]).is_err());
    assert!(HistoryRequest::parse(&serde_json::to_vec(&request).unwrap()).is_ok());
}
