#![cfg(feature = "experimental-entry-format")]
use petika_core::{
    entry_format::{checkpoint::*, checkpoint_store::CheckpointStore, index::*, transport::*, *},
    identity::{CheckpointTarget, UnlockedIdentity},
};
use petika_server::entry_history::build_page;
use std::collections::BTreeMap;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn record(root: &RootKey, revision: u64, parent: String) -> HistoryObject {
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
