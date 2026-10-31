use super::*;
#[test]
fn queued_session_and_device_events_survive_restart_and_drain_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    let store = LeaseStore::lock(ledger(dir.path())).unwrap();
    let repo = Repository {
        provider: Provider::Gitea,
        management_origin: "https://git.example/".into(),
        repository: "synthetic/vault".into(),
    };
    let first = store
        .prepare(
            repo.clone(),
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            100,
            100,
        )
        .unwrap();
    let second = store
        .prepare(
            repo,
            &"d".repeat(64),
            &"e".repeat(64),
            &"f".repeat(64),
            100,
            100,
        )
        .unwrap();
    enqueue_session(dir.path(), &first.session).unwrap();
    enqueue_session(dir.path(), &first.session).unwrap();
    enqueue_device(dir.path(), &second.device).unwrap();
    assert_eq!(
        read_events(&StoreFile::lock(events(dir.path())).unwrap())
            .unwrap()
            .pending
            .len(),
        2
    );
    drop(store);
    let store = LeaseStore::lock(ledger(dir.path())).unwrap();
    drain(dir.path(), &store).unwrap();
    assert!(
        store
            .leases()
            .unwrap()
            .iter()
            .all(|l| l.state == State::Revoking)
    );
    drain(dir.path(), &store).unwrap();
    assert!(
        read_events(&StoreFile::lock(events(dir.path())).unwrap())
            .unwrap()
            .pending
            .is_empty()
    );
}
#[test]
fn corrupt_events_block_processing_without_reset() {
    let dir = tempfile::tempdir().unwrap();
    enqueue_session(dir.path(), &"b".repeat(64)).unwrap();
    std::fs::write(events(dir.path()), b"{").unwrap();
    let store = LeaseStore::lock(ledger(dir.path())).unwrap();
    assert!(drain(dir.path(), &store).is_err());
    assert!(enqueue_device(dir.path(), &"a".repeat(64)).is_err());
}

#[test]
fn startup_revokes_every_previous_process_lease() {
    let dir = tempfile::tempdir().unwrap();
    let repository = Repository {
        provider: Provider::Gitea,
        management_origin: "https://git.example/".into(),
        repository: "synthetic/vault".into(),
    };
    let store = LeaseStore::lock(ledger(dir.path())).unwrap();
    store
        .prepare(
            repository,
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            100,
            100,
        )
        .unwrap();
    drop(store);
    startup_cleanup(dir.path()).unwrap();
    assert_eq!(
        LeaseStore::lock(ledger(dir.path()))
            .unwrap()
            .leases()
            .unwrap()[0]
            .state,
        State::Revoking
    );
}

#[test]
fn only_one_worker_can_claim_the_data_directory() {
    let dir = tempfile::tempdir().unwrap();
    let first = worker_claim(dir.path()).unwrap();
    assert!(worker_claim(dir.path()).is_err());
    drop(first);
    assert!(worker_claim(dir.path()).is_ok());
}
