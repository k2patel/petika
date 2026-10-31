use super::*;
use std::fs;

#[test]
fn history_pages_require_an_existing_pin_and_keep_adjacent_order() {
    let f = Fixture::new();
    let journal = f.lock();
    journal.initialize(&f.baseline).unwrap();
    let baseline_digest = f.baseline.roster().digest().unwrap();
    let mut current = f.baseline;
    for index in 1..=17 {
        let device = DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
        let mut devices = current.roster().devices.clone();
        devices.push(device.public_record().unwrap());
        devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let candidate = f
            .authority
            .sign_roster(
                current.roster().generation + 1,
                current.roster().digest().unwrap(),
                devices,
                vec![],
            )
            .unwrap();
        journal
            .publish(
                &format!("{index:064x}"),
                &candidate.parent_digest,
                &candidate,
            )
            .unwrap();
        current.accept(candidate).unwrap();
    }
    let first = journal.successors(&baseline_digest).unwrap();
    assert_eq!(first.len(), 16);
    assert_eq!(first[0].parent_digest, baseline_digest);
    for pair in first.windows(2) {
        assert_eq!(pair[1].parent_digest, pair[0].digest().unwrap());
    }
    let last = journal.successors(&first[15].digest().unwrap()).unwrap();
    assert_eq!(last, vec![current.roster().clone()]);
    assert!(
        journal
            .successors(&last[0].digest().unwrap())
            .unwrap()
            .is_empty()
    );
    assert!(journal.successors(&"f".repeat(64)).is_err());
    assert!(journal.successors("bad pin").is_err());
}

struct Fixture {
    directory: tempfile::TempDir,
    authority: DeviceAuthorityKey,
    baseline: TrustedDeviceRoster,
}
impl Fixture {
    fn new() -> Self {
        let authority = DeviceAuthorityKey::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
        let roster = authority
            .sign_roster(1, String::new(), vec![], vec![])
            .unwrap();
        let baseline = TrustedDeviceRoster::bootstrap(
            roster.clone(),
            &roster.authority.fingerprint,
            &roster.digest().unwrap(),
        )
        .unwrap();
        Self {
            directory: tempfile::tempdir().unwrap(),
            authority,
            baseline,
        }
    }
    fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("device-roster.json")
    }
    fn lock(&self) -> DeviceRosterJournal {
        DeviceRosterJournal::lock(
            self.path(),
            &self.baseline.roster().authority.fingerprint,
            &self.baseline.roster().digest().unwrap(),
        )
        .unwrap()
    }
    fn candidate(&self, current: &TrustedDeviceRoster) -> DeviceRoster {
        let device = DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
        let request = device.enrollment_request(current, 100).unwrap();
        let fingerprint = request.device.fingerprint.clone();
        let mut pending = self
            .authority
            .challenge_enrollment(request, current, &fingerprint, 101)
            .unwrap();
        let proof = device
            .answer_enrollment(
                pending.challenge(),
                current,
                &current.roster().authority.fingerprint,
                102,
            )
            .unwrap();
        pending
            .approve(&self.authority, &proof, current, &fingerprint, 103)
            .unwrap()
    }
}

#[test]
fn enrollment_publication_survives_reopen_and_exact_retry_after_a_later_commit() {
    let f = Fixture::new();
    let journal = f.lock();
    journal.initialize(&f.baseline).unwrap();
    let initial = f.baseline.roster().digest().unwrap();
    let first = f.candidate(&f.baseline);
    let receipt = journal.publish(&"1".repeat(64), &initial, &first).unwrap();
    let wire = serde_json::to_vec(&receipt).unwrap();
    PublicationReceipt::parse(&wire)
        .unwrap()
        .verify_candidate(&"1".repeat(64), &first)
        .unwrap();
    assert!(journal.initialize(&f.baseline).is_err());
    drop(journal);
    let journal = f.lock();
    assert_eq!(journal.current().unwrap().roster(), &first);
    assert_eq!(
        journal.lookup(&"1".repeat(64)).unwrap(),
        Some(receipt.clone())
    );
    let second = f.candidate(&journal.current().unwrap());
    journal
        .publish(&"2".repeat(64), &first.digest().unwrap(), &second)
        .unwrap();
    let saved = fs::read(f.path()).unwrap();
    assert_eq!(
        journal.publish(&"1".repeat(64), &initial, &first).unwrap(),
        receipt
    );
    assert_eq!(fs::read(f.path()).unwrap(), saved);
    assert_eq!(journal.current().unwrap().roster(), &second);
    assert!(journal.lookup(&"f".repeat(64)).unwrap().is_none());
}

#[test]
fn competing_candidates_operation_id_reuse_and_forged_receipts_fail_without_mutation() {
    let f = Fixture::new();
    let journal = f.lock();
    journal.initialize(&f.baseline).unwrap();
    let parent = f.baseline.roster().digest().unwrap();
    let first = f.candidate(&f.baseline);
    let competing = f.candidate(&f.baseline);
    let receipt = journal.publish(&"1".repeat(64), &parent, &first).unwrap();
    let saved = fs::read(f.path()).unwrap();
    for op in ["1".repeat(64), "2".repeat(64)] {
        assert!(journal.publish(&op, &parent, &competing).is_err());
    }
    assert!(
        journal
            .publish(&"2".repeat(64), &"f".repeat(64), &first)
            .is_err()
    );
    assert!(journal.publish("short", &parent, &first).is_err());
    let mut forged = receipt.clone();
    forged.roster_digest = "f".repeat(64);
    assert!(
        forged
            .verify_candidate(&receipt.operation_id, &first)
            .is_err()
    );
    assert!(receipt.verify_candidate(&"2".repeat(64), &first).is_err());
    assert_eq!(fs::read(f.path()).unwrap(), saved);
}

#[test]
fn exclusive_lock_and_wrong_initial_anchor_fail_closed() {
    let f = Fixture::new();
    let journal = f.lock();
    journal.initialize(&f.baseline).unwrap();
    assert!(matches!(
        DeviceRosterJournal::lock(
            f.path(),
            &f.baseline.roster().authority.fingerprint,
            &f.baseline.roster().digest().unwrap()
        ),
        Err(Error::Busy)
    ));
    drop(journal);
    let wrong = DeviceRosterJournal::lock(
        f.path(),
        &f.baseline.roster().authority.fingerprint,
        &"f".repeat(64),
    )
    .unwrap();
    assert!(wrong.current().is_err());
    drop(wrong);
    let wrong = DeviceRosterJournal::lock(
        f.path(),
        &"f".repeat(64),
        &f.baseline.roster().digest().unwrap(),
    )
    .unwrap();
    assert!(wrong.current().is_err());
    drop(wrong);
    let journal = f.lock();
    assert_eq!(journal.current().unwrap().roster(), f.baseline.roster());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(f.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn interruption_boundaries_preserve_either_old_state_or_complete_retryable_publication() {
    for boundary in 1..=4 {
        let f = Fixture::new();
        let journal = f.lock();
        journal.initialize(&f.baseline).unwrap();
        let parent = f.baseline.roster().digest().unwrap();
        let candidate = f.candidate(&f.baseline);
        let original = fs::read(f.path()).unwrap();
        let op = "1".repeat(64);
        let result = journal.publish_observed(&op, &parent, &candidate, |point| {
            if point == boundary {
                Err(Error::Io(std::io::Error::other(
                    "synthetic interrupted write",
                )))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        drop(journal);
        let reopened = f.lock();
        let receipt = reopened.lookup(&op).unwrap();
        if boundary < 3 {
            assert!(receipt.is_none());
            assert_eq!(fs::read(f.path()).unwrap(), original);
            assert_eq!(reopened.current().unwrap().roster(), f.baseline.roster());
        } else {
            receipt.unwrap().verify_candidate(&op, &candidate).unwrap();
            assert_eq!(reopened.current().unwrap().roster(), &candidate);
        }
        reopened.publish(&op, &parent, &candidate).unwrap();
        assert_eq!(reopened.current().unwrap().roster(), &candidate);
    }
}

#[test]
fn truncated_tampered_and_duplicate_journal_records_are_never_reinitialized() {
    let f = Fixture::new();
    let journal = f.lock();
    journal.initialize(&f.baseline).unwrap();
    let candidate = f.candidate(&f.baseline);
    journal
        .publish(
            &"1".repeat(64),
            &f.baseline.roster().digest().unwrap(),
            &candidate,
        )
        .unwrap();
    let original = fs::read(f.path()).unwrap();
    drop(journal);
    for kind in 0..5 {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        match kind {
            0 => value["version"] = serde_json::json!(99),
            1 => {
                value["publications"][0]["roster"]["signature"] =
                    serde_json::json!(STANDARD.encode([0; 64]))
            }
            2 => {
                let repeated = value["publications"][0].clone();
                value["publications"].as_array_mut().unwrap().push(repeated);
            }
            3 => value["extra"] = serde_json::json!(true),
            _ => {
                value["publications"] = serde_json::json!(vec![
                    value["publications"][0].clone();
                    MAX_ROSTER_PUBLICATIONS + 1
                ])
            }
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(f.path(), &bytes).unwrap();
        let journal = f.lock();
        assert!(journal.current().is_err());
        assert!(journal.lookup(&"1".repeat(64)).is_err());
        assert!(journal.initialize(&f.baseline).is_err());
        assert_eq!(fs::read(f.path()).unwrap(), bytes);
        drop(journal);
    }
    fs::write(f.path(), &original[..original.len() / 2]).unwrap();
    let journal = f.lock();
    assert!(journal.current().is_err());
}

#[test]
fn restoring_old_complete_state_requires_an_independent_newer_pin() {
    let f = Fixture::new();
    let journal = f.lock();
    journal.initialize(&f.baseline).unwrap();
    let old_copy = fs::read(f.path()).unwrap();
    let candidate = f.candidate(&f.baseline);
    journal
        .publish(
            &"1".repeat(64),
            &f.baseline.roster().digest().unwrap(),
            &candidate,
        )
        .unwrap();
    let mut newest = journal.current().unwrap();
    drop(journal);
    fs::write(f.path(), old_copy).unwrap();
    let restored = f.lock();
    // A coherent old journal is valid at its own anchor; newer evidence detects it.
    let older = restored.current().unwrap();
    assert!(newest.accept(older.roster().clone()).is_err());
    assert_eq!(newest.roster(), &candidate);
}
