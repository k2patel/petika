use super::*;
#[derive(Default)]
struct Host {
    keys: Vec<RemoteKey>,
    deleted: Vec<String>,
    failures: BTreeSet<String>,
    inventory_error: bool,
    incomplete: bool,
    lost_delete_reply: bool,
    acknowledge_without_delete: bool,
}
impl KeyHost for Host {
    fn inventory(&mut self, _: &Repository) -> std::result::Result<Inventory, Failure> {
        if self.inventory_error {
            return Err(Failure::Inventory);
        }
        Ok(Inventory {
            keys: self.keys.clone(),
            complete: !self.incomplete,
        })
    }
    fn delete(&mut self, _: &Repository, id: &str) -> std::result::Result<(), Failure> {
        if self.failures.contains(id) {
            return Err(Failure::Delete);
        }
        if self.acknowledge_without_delete {
            return Ok(());
        }
        self.keys.retain(|k| k.id != id);
        self.deleted.push(id.into());
        if self.lost_delete_reply {
            Err(Failure::Delete)
        } else {
            Ok(())
        }
    }
}
fn repo() -> Repository {
    Repository {
        provider: Provider::Gitea,
        management_origin: "https://git.example/".into(),
        repository: "synthetic/vault".into(),
    }
}
fn prepare(store: &LeaseStore) -> Lease {
    store
        .prepare(
            repo(),
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            100,
            100,
        )
        .unwrap()
}
fn key(lease: &Lease, id: &str) -> RemoteKey {
    RemoteKey {
        id: id.into(),
        marker: lease.marker(),
        fingerprint: lease.fingerprint.clone(),
        read_only: Some(true),
    }
}
#[test]
fn all_managed_copies_expire_and_unrelated_keys_survive() {
    let dir = tempfile::tempdir().unwrap();
    let store = LeaseStore::lock(dir.path().join("leases.json")).unwrap();
    let lease = prepare(&store);
    let permanent = RemoteKey {
        id: "permanent".into(),
        marker: format!("petika-lease:v1:{}", "d".repeat(64)),
        fingerprint: "d".repeat(64),
        read_only: Some(true),
    };
    let mut host = Host {
        keys: vec![key(&lease, "one"), key(&lease, "duplicate"), permanent],
        ..Host::default()
    };
    store.sweep(150, &mut host).unwrap();
    assert!(host.deleted.is_empty());
    assert_eq!(store.leases().unwrap()[0].state, State::Active);
    store.sweep(200, &mut host).unwrap();
    assert_eq!(host.deleted, vec!["one", "duplicate"]);
    assert_eq!(host.keys[0].id, "permanent");
    assert_eq!(store.leases().unwrap()[0].state, State::Removed);
}
#[test]
fn a_failed_key_does_not_block_other_leases_and_retries_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.json");
    let store = LeaseStore::lock(&path).unwrap();
    let first = prepare(&store);
    let second = prepare(&store);
    let mut host = Host {
        keys: vec![key(&first, "fails"), key(&second, "works")],
        failures: BTreeSet::from(["fails".into()]),
        ..Host::default()
    };
    store.sweep(200, &mut host).unwrap();
    let leases = store.leases().unwrap();
    assert_eq!(leases[0].state, State::Revoking);
    assert_eq!(leases[0].last_error, Some(Failure::Delete));
    assert_eq!(leases[1].state, State::Removed);
    drop(store);
    host.failures.clear();
    let store = LeaseStore::lock(&path).unwrap();
    store.sweep(leases[0].retry_at, &mut host).unwrap();
    assert!(host.keys.is_empty());
    assert!(
        store
            .leases()
            .unwrap()
            .iter()
            .all(|l| l.state == State::Removed)
    );
}
#[test]
fn lost_registration_reply_and_late_registration_after_removal_are_reconciled() {
    let dir = tempfile::tempdir().unwrap();
    let store = LeaseStore::lock(dir.path().join("leases.json")).unwrap();
    let lease = prepare(&store);
    let mut host = Host::default();
    // Cancellation wins before an in-flight remote create finishes.
    store.request_cleanup(Cleanup::All).unwrap();
    store.sweep(110, &mut host).unwrap();
    assert_eq!(store.leases().unwrap()[0].state, State::Removed);
    host.keys.push(key(&lease, "late"));
    store.sweep(111, &mut host).unwrap();
    assert_eq!(host.deleted, vec!["late"]);
    // Tombstones remain scanned; an uncertain create cannot resurrect transport access.
    host.keys.push(key(&lease, "later"));
    store.sweep(112, &mut host).unwrap();
    assert_eq!(host.deleted, vec!["late", "later"]);
}
#[test]
fn lost_delete_ack_reconciles_without_duplicate_delete() {
    let dir = tempfile::tempdir().unwrap();
    let store = LeaseStore::lock(dir.path().join("leases.json")).unwrap();
    let lease = prepare(&store);
    let mut host = Host {
        keys: vec![key(&lease, "one")],
        lost_delete_reply: true,
        ..Host::default()
    };
    store.sweep(200, &mut host).unwrap();
    let retry = store.leases().unwrap()[0].retry_at;
    assert_eq!(store.leases().unwrap()[0].last_error, Some(Failure::Delete));
    store.sweep(retry, &mut host).unwrap();
    assert_eq!(host.deleted, vec!["one"]);
    assert_eq!(store.leases().unwrap()[0].state, State::Removed);
}
#[test]
fn incomplete_inventory_and_marker_collisions_never_delete_keys() {
    let dir = tempfile::tempdir().unwrap();
    let store = LeaseStore::lock(dir.path().join("leases.json")).unwrap();
    let lease = prepare(&store);
    let mut host = Host {
        keys: vec![key(&lease, "one")],
        incomplete: true,
        ..Host::default()
    };
    store.sweep(200, &mut host).unwrap();
    assert!(host.deleted.is_empty());
    let retry = store.leases().unwrap()[0].retry_at;
    host.incomplete = false;
    host.keys[0].fingerprint = "d".repeat(64);
    store.sweep(retry, &mut host).unwrap();
    assert!(host.deleted.is_empty());
    assert_eq!(
        store.leases().unwrap()[0].last_error,
        Some(Failure::OwnershipMismatch)
    );
}
#[test]
fn session_device_and_all_cleanup_are_scoped() {
    let dir = tempfile::tempdir().unwrap();
    let store = LeaseStore::lock(dir.path().join("leases.json")).unwrap();
    let first = prepare(&store);
    let second = store
        .prepare(
            repo(),
            &"d".repeat(64),
            &"e".repeat(64),
            &"f".repeat(64),
            100,
            100,
        )
        .unwrap();
    let mut host = Host {
        keys: vec![key(&first, "one"), key(&second, "two")],
        ..Host::default()
    };
    assert_eq!(
        store
            .request_cleanup(Cleanup::Session(&first.session))
            .unwrap(),
        1
    );
    store.sweep(110, &mut host).unwrap();
    assert_eq!(host.keys[0].id, "two");
    assert_eq!(
        store
            .request_cleanup(Cleanup::Device(&second.device))
            .unwrap(),
        1
    );
    store.sweep(111, &mut host).unwrap();
    assert!(host.keys.is_empty());
    assert_eq!(store.request_cleanup(Cleanup::All).unwrap(), 0);
}
#[test]
fn corrupt_ledger_and_invalid_scopes_fail_closed_and_lock_is_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.json");
    let store = LeaseStore::lock(&path).unwrap();
    assert!(LeaseStore::lock(&path).is_err());
    let mut invalid = repo();
    invalid.management_origin = "https://user:secret@git.example/".into();
    assert!(
        store
            .prepare(
                invalid,
                &"a".repeat(64),
                &"b".repeat(64),
                &"c".repeat(64),
                100,
                100
            )
            .is_err()
    );
    assert!(
        store
            .prepare(
                repo(),
                &"a".repeat(64),
                &"b".repeat(64),
                &"c".repeat(64),
                100,
                3601
            )
            .is_err()
    );
    prepare(&store);
    let bytes = std::fs::read(&path).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record["version"], 1);
    assert!(!String::from_utf8(bytes).unwrap().contains("private_key"));
    std::fs::write(&path, b"{").unwrap();
    let mut host = Host::default();
    assert!(store.sweep(200, &mut host).is_err());
    assert!(host.deleted.is_empty());
    assert!(store.request_cleanup(Cleanup::All).is_err());
}
#[test]
fn inventory_failure_is_visible_and_key_not_recreated() {
    let dir = tempfile::tempdir().unwrap();
    let store = LeaseStore::lock(dir.path().join("leases.json")).unwrap();
    prepare(&store);
    let mut host = Host {
        inventory_error: true,
        ..Host::default()
    };
    store.sweep(200, &mut host).unwrap();
    assert_eq!(
        store.leases().unwrap()[0].last_error,
        Some(Failure::Inventory)
    );
    assert!(host.deleted.is_empty());
}

#[test]
fn successful_delete_reply_is_not_enough_without_verified_absence() {
    let dir = tempfile::tempdir().unwrap();
    let store = LeaseStore::lock(dir.path().join("leases.json")).unwrap();
    let lease = prepare(&store);
    let mut host = Host {
        keys: vec![key(&lease, "retained")],
        acknowledge_without_delete: true,
        ..Host::default()
    };
    store.sweep(200, &mut host).unwrap();
    assert_eq!(store.leases().unwrap()[0].state, State::Revoking);
    assert_eq!(
        store.leases().unwrap()[0].last_error,
        Some(Failure::StillPresent)
    );
}

#[test]
fn bounded_sweeps_continue_after_restart_instead_of_starving_later_leases() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.json");
    let store = LeaseStore::lock(&path).unwrap();
    let first = prepare(&store);
    let second = prepare(&store);
    let mut host = Host {
        keys: vec![key(&first, "one"), key(&second, "two")],
        ..Host::default()
    };
    store.sweep_batch(200, &mut host, 1).unwrap();
    assert_eq!(host.deleted, vec!["one"]);
    drop(store);
    let store = LeaseStore::lock(&path).unwrap();
    store.sweep_batch(201, &mut host, 1).unwrap();
    assert_eq!(host.deleted, vec!["one", "two"]);
}
