use super::*;
use crate::{
    accounts::{Accounts, KeyOperation, Membership},
    entry_api::dispatch,
};
use petika_core::{
    entry_format::{
        RootKey, SUITE, checkpoint::DeliveryProfile, index::*, rotation::RotationSnapshot,
    },
    identity::{CheckpointTarget, PublicIdentity, UnlockedIdentity},
};

const PASSWORD: &str = "synthetic epoch test password";
fn wire(root: &RootKey, index: &Index) -> HistoryObject {
    let envelope = String::from_utf8(
        root.seal(
            &Header {
                entry_format_version: 1,
                suite: SUITE.into(),
                context: root.context().clone(),
                kind: Kind::Index,
                object_id: String::new(),
                revision: index.revision,
            },
            &serde_json::to_vec(index).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    HistoryObject {
        head: Head {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: index.revision,
            parent_digest: index.parent_digest.clone(),
            index_digest: hash(envelope.as_bytes()),
            wrapper_set_digest: wrapper_set_digest(&index.wrappers).unwrap(),
            membership_generation: index.membership_generation,
        },
        envelope,
    }
}
fn sign(
    authority: &UnlockedIdentity,
    root: &RootKey,
    object: &HistoryObject,
    index: &Index,
) -> Checkpoint {
    authority
        .sign_entry_checkpoint(
            root,
            CheckpointTarget {
                head_revision: index.revision,
                head_digest: object.head.digest().unwrap(),
                membership_generation: index.membership_generation,
                delivery_profile: DeliveryProfile::Standard,
            },
            &index.wrappers,
        )
        .unwrap()
}
struct Fixture {
    authority: UnlockedIdentity,
    root: RootKey,
    next_root: RootKey,
    index: Index,
    initial: HistoryObject,
    wrappers: Vec<EpochWrapper>,
    trusted: TrustedCheckpoint,
    objects: BTreeMap<String, Vec<u8>>,
}
impl Fixture {
    fn new(
        mut authority: UnlockedIdentity,
        collection: String,
        recipients: &[PublicIdentity],
        generation: u64,
    ) -> Self {
        let deployment = authority.public_identity().deployment_id.clone();
        let root = RootKey::generate(deployment.clone(), collection.clone(), 1).unwrap();
        let next_root = RootKey::generate(deployment, collection, 2).unwrap();
        let mut wrappers = vec![];
        let mut refs = vec![];
        for recipient in recipients {
            if recipient != authority.public_identity() {
                authority
                    .verify_contact(&recipient.user_id, recipient, &recipient.fingerprint, None)
                    .unwrap();
            }
            let package = authority
                .create_entry_key_package(&root, recipient, generation, DeliveryProfile::Standard)
                .unwrap();
            refs.push(package.reference().unwrap());
            wrappers.push(EpochWrapper::Recipient(
                serde_json::to_string(&package).unwrap(),
            ));
        }
        let mut index = Index {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: 1,
            parent_digest: String::new(),
            membership_generation: generation,
            wrappers: refs,
            root_folder: String::new(),
            folders: vec![],
            entries: vec![],
            tombstones: vec![],
        };
        let mut objects = BTreeMap::new();
        for n in 0..2 {
            let id = format!("{n:064x}");
            let bytes = root
                .seal(
                    &Header {
                        entry_format_version: 1,
                        suite: SUITE.into(),
                        context: root.context().clone(),
                        kind: Kind::Entry,
                        object_id: id.clone(),
                        revision: 1,
                    },
                    format!("synthetic secret {n}").as_bytes(),
                )
                .unwrap();
            index.entries.push(EntryRef {
                id: id.clone(),
                folder: String::new(),
                name: format!("Entry {n}"),
                revision: 1,
                digest: hash(&bytes),
            });
            objects.insert(id, bytes);
        }
        let initial = wire(&root, &index);
        let trusted = trusted(&sign(&authority, &root, &initial, &index)).unwrap();
        Self {
            authority,
            root,
            next_root,
            index,
            initial,
            wrappers,
            trusted,
            objects,
        }
    }
    fn basic() -> Self {
        let authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
        let public = authority.public_identity().clone();
        Self::new(authority, "b".repeat(64), &[public], 1)
    }
    fn initialize(&self, journal: &mut Journal) -> Receipt {
        journal
            .initialize_anchored(
                &self.authority.public_identity().user_id,
                &"1".repeat(64),
                self.initial.clone(),
                self.index
                    .entries
                    .iter()
                    .map(|e| EntryChange::Put {
                        id: e.id.clone(),
                        expected: None,
                        revision: 1,
                        envelope: String::from_utf8(self.objects[&e.id].clone()).unwrap(),
                    })
                    .collect(),
                &self.trusted,
                self.wrappers.clone(),
            )
            .unwrap()
    }
    fn rotation(&mut self, recipients: &[PublicIdentity], generation: u64) -> EpochTransaction {
        let mut index = self.index.clone();
        index.context = self.next_root.context().clone();
        index.revision = 2;
        index.parent_digest = self.initial.head.digest().unwrap();
        index.membership_generation = generation;
        index.wrappers.clear();
        let mut wrappers = vec![];
        for recipient in recipients {
            let package = self
                .authority
                .create_entry_key_package(
                    &self.next_root,
                    recipient,
                    generation,
                    DeliveryProfile::Standard,
                )
                .unwrap();
            index.wrappers.push(package.reference().unwrap());
            wrappers.push(EpochWrapper::Recipient(
                serde_json::to_string(&package).unwrap(),
            ));
        }
        let previous = VerifiedIndex::open(
            &self.root,
            self.initial.head.clone(),
            self.initial.envelope.as_bytes(),
        )
        .unwrap();
        let mut entries = vec![];
        for e in &mut index.entries {
            let plaintext = previous
                .open_entry(&self.root, &e.id, &self.objects[&e.id])
                .unwrap();
            let envelope = String::from_utf8(
                self.next_root
                    .seal(
                        &Header {
                            entry_format_version: 1,
                            suite: SUITE.into(),
                            context: self.next_root.context().clone(),
                            kind: Kind::Entry,
                            object_id: e.id.clone(),
                            revision: 2,
                        },
                        &plaintext,
                    )
                    .unwrap(),
            )
            .unwrap();
            entries.push(RotatedEntry {
                id: e.id.clone(),
                expected: crate::entry_transaction::EntryVersion {
                    revision: 1,
                    digest: e.digest.clone(),
                },
                revision: 2,
                envelope: envelope.clone(),
            });
            e.revision = 2;
            e.digest = hash(envelope.as_bytes());
        }
        let object = wire(&self.next_root, &index);
        let next = sign(&self.authority, &self.next_root, &object, &index);
        let transition = self
            .authority
            .authorize_entry_transition(&self.trusted, next, 1)
            .unwrap();
        let tx = EpochTransaction {
            version: 1,
            operation: "2".repeat(64),
            expected: Cursor::from_head(&self.initial.head).unwrap(),
            transition,
            object,
            entries,
            wrappers,
        };
        tx.verify(
            &self.trusted,
            RotationSnapshot {
                index: &previous,
                root: &self.root,
                objects: &self.objects,
            },
            &self.next_root,
        )
        .unwrap();
        tx
    }
}

#[test]
fn epoch_journal_replays_complete_rotation_and_preserves_old_reads() {
    let mut f = Fixture::basic();
    let writer = f.authority.public_identity().user_id.clone();
    let tx = f.rotation(&[f.authority.public_identity().clone()], 1);
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(dir.path().into()).unwrap();
    let first = f.initialize(&mut journal);
    let mut bad = tx.clone();
    bad.entries.pop();
    assert!(journal.rotate(&writer, bad).is_err());
    let mut bad = tx.clone();
    bad.transition.previous_checkpoint_digest = "0".repeat(64);
    assert!(journal.rotate(&writer, bad).is_err());
    let mut bad = tx.clone();
    bad.wrappers.clear();
    assert!(journal.rotate(&writer, bad).is_err());
    assert_eq!(journal.current(), Some(first.accepted.clone()));
    let receipt = journal.rotate(&writer, tx.clone()).unwrap();
    tx.verify_receipt(&writer, &receipt).unwrap();
    assert_eq!(journal.rotate(&writer, tx.clone()).unwrap(), receipt);
    let mut changed = tx.clone();
    changed.expected.digest = "0".repeat(64);
    assert!(journal.rotate(&writer, changed).is_err());
    drop(journal);
    let journal = Journal::open(dir.path().into()).unwrap();
    assert_eq!(journal.current(), Some(receipt.accepted.clone()));
    assert_eq!(
        journal
            .epoch_state(&receipt.accepted)
            .unwrap()
            .unwrap()
            .checkpoint
            .context
            .key_epoch,
        2
    );
    for e in &tx.entries {
        assert_eq!(
            journal
                .entry(&receipt.accepted, &e.id, &hash(e.envelope.as_bytes()))
                .unwrap(),
            e.envelope
        );
        assert_eq!(
            journal
                .entry(&first.accepted, &e.id, &e.expected.digest)
                .unwrap()
                .as_bytes(),
            f.objects[&e.id]
        );
    }
    let request = HistoryRequest {
        version: 1,
        context: f.root.context().clone(),
        after: first.accepted.clone(),
        target: None,
        limit: 32,
    };
    let page = HistoryPage::parse(&journal.history(&request).unwrap(), &request).unwrap();
    assert_eq!(page.target, first.accepted);
    let fetched = journal.next_epoch(&first.accepted).unwrap().unwrap();
    assert_eq!(
        fetched.submission_digest(&writer).unwrap(),
        tx.submission_digest(&writer).unwrap()
    );
    assert!(journal.next_epoch(&receipt.accepted).unwrap().is_none());
    // Anchors cannot be inferred from a request or attached to an existing store.
    let unanchored = tempfile::tempdir().unwrap();
    let mut legacy = Journal::open(unanchored.path().into()).unwrap();
    legacy
        .append(None, &writer, &"1".repeat(64), f.initial.clone())
        .unwrap();
    assert!(legacy.rotate(&writer, tx).is_err());
}

#[test]
fn epoch_termination_worker() {
    let Ok(directory) = std::env::var("PETIKA_EPOCH_CRASH_DIR") else {
        return;
    };
    let stage: u8 = std::env::var("PETIKA_EPOCH_CRASH_STAGE")
        .unwrap()
        .parse()
        .unwrap();
    let mut journal = Journal::open(directory.into()).unwrap();
    let tx =
        EpochTransaction::parse(&std::fs::read(journal.directory.join("candidate.json")).unwrap())
            .unwrap();
    journal
        .rotate_observed(&"f".repeat(64), tx, |at| {
            if at == stage {
                std::process::exit(73);
            }
            Ok(())
        })
        .unwrap();
    panic!("crash boundary not reached");
}

#[test]
fn epoch_uncertain_publication_requires_reopen_and_receipt_tampering_is_rejected() {
    let mut f = Fixture::basic();
    let tx = f.rotation(&[f.authority.public_identity().clone()], 1);
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(dir.path().into()).unwrap();
    f.initialize(&mut journal);
    assert!(
        journal
            .rotate_observed(&"f".repeat(64), tx.clone(), |stage| {
                if stage == 7 {
                    Err(petika_core::Error::Io(std::io::Error::other(
                        "synthetic uncertain sync",
                    )))
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    assert!(journal.epoch_state(&tx.expected).is_err());
    assert!(journal.rotate(&"f".repeat(64), tx.clone()).is_err());
    drop(journal);
    let mut journal = Journal::open(dir.path().into()).unwrap();
    let receipt = journal.rotate(&"f".repeat(64), tx).unwrap();
    assert_eq!(receipt.accepted.revision, 2);
    // Even a record with a matching address must have a valid request receipt.
    let record = &mut journal.records.get_mut(&2).unwrap().1;
    record.receipt.request_digest = "0".repeat(64);
    let bytes = serde_json::to_vec(record).unwrap();
    let address = hash(&bytes);
    StoreFile::lock(dir.path().join(format!("{address}.json")))
        .unwrap()
        .write(&bytes, true)
        .unwrap();
    journal
        .root
        .write(
            &serde_json::to_vec(&Root {
                version: 1,
                record: address,
            })
            .unwrap(),
            false,
        )
        .unwrap();
    drop(journal);
    assert!(Journal::open(dir.path().into()).is_err());
}

#[test]
fn epoch_process_exit_never_exposes_mixed_keys_wrappers_or_entries() {
    let mut f = Fixture::basic();
    let tx = f.rotation(&[f.authority.public_identity().clone()], 1);
    for stage in 1..=8 {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(dir.path().into()).unwrap();
        f.initialize(&mut journal);
        StoreFile::lock(dir.path().join("candidate.json"))
            .unwrap()
            .write(&serde_json::to_vec(&tx).unwrap(), true)
            .unwrap();
        drop(journal);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "entry_journal::epochs::tests::epoch_termination_worker",
            ])
            .env("PETIKA_EPOCH_CRASH_DIR", dir.path())
            .env("PETIKA_EPOCH_CRASH_STAGE", stage.to_string())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        let mut journal = Journal::open(dir.path().into()).unwrap();
        let current = journal.current().unwrap();
        let state = journal.epoch_state(&current).unwrap().unwrap();
        assert_eq!(
            journal.receipt(&"f".repeat(64), &tx.operation).is_some(),
            stage >= 7
        );
        assert_eq!(
            &state.checkpoint,
            if stage < 7 {
                f.trusted.checkpoint()
            } else {
                &tx.transition.next
            }
        );
        assert_eq!(
            state.checkpoint.context.key_epoch,
            if stage < 7 { 1 } else { 2 }
        );
        assert_eq!(current.revision, state.checkpoint.context.key_epoch);
        assert_eq!(
            serde_json::to_vec(&state.wrappers).unwrap(),
            serde_json::to_vec(if stage < 7 { &f.wrappers } else { &tx.wrappers }).unwrap()
        );
        for e in &tx.entries {
            let expected = if stage < 7 {
                &f.objects[&e.id][..]
            } else {
                e.envelope.as_bytes()
            };
            assert_eq!(
                journal
                    .entry(&current, &e.id, &hash(expected))
                    .unwrap()
                    .as_bytes(),
                expected
            );
        }
        let receipt = journal.rotate(&"f".repeat(64), tx.clone()).unwrap();
        tx.verify_receipt(&"f".repeat(64), &receipt).unwrap();
        assert_eq!(journal.current().unwrap().revision, 2);
    }
}

fn enroll(accounts: &mut Accounts, token: &str, deployment: &str, user: &str) -> UnlockedIdentity {
    let identity = UnlockedIdentity::generate(deployment, user, 1).unwrap();
    let backup: serde_json::Value =
        serde_json::from_slice(&identity.seal(PASSWORD).unwrap()).unwrap();
    accounts.key_operation(token, KeyOperation::Enroll, &serde_json::to_vec(&serde_json::json!({"expected_bundle_revision":0,"current_password":PASSWORD,"public_identity":backup["public_identity"],"encrypted_bundle":backup["encrypted_bundle"]})).unwrap()).unwrap();
    identity
}
#[test]
fn epoch_api_enforces_authority_roster_membership_and_reconciles_after_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    accounts.migrate().unwrap();
    let owner = accounts
        .create_user("owner", "Owner", PASSWORD.into(), true, true)
        .unwrap();
    let reader = accounts
        .create_user("reader", "Reader", PASSWORD.into(), false, false)
        .unwrap();
    let (owner_token, _) = accounts.login("owner", PASSWORD.into()).unwrap();
    let (reader_token, _) = accounts.login("reader", PASSWORD.into()).unwrap();
    let deployment = accounts
        .key_operation(&owner_token, KeyOperation::Deployment, b"")
        .unwrap()["deployment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let authority = enroll(&mut accounts, &owner_token, &deployment, &owner.id);
    let recipient = enroll(&mut accounts, &reader_token, &deployment, &reader.id);
    let own = authority.public_identity().clone();
    let recipients = vec![own.clone(), recipient.public_identity().clone()];
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
    let mut f = Fixture::new(
        authority,
        group.id.clone(),
        &recipients,
        group.membership_generation,
    );
    let path = dir
        .path()
        .join("collections")
        .join(&group.id)
        .join("entries");
    let mut journal = Journal::open(path.clone()).unwrap();
    let first = f.initialize(&mut journal);
    drop(journal);
    let tx = f.rotation(&recipients, 1);
    let roster: serde_json::Value = serde_json::from_slice(
        &dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-roster",
            &b"{}"[..],
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(roster["membership_generation"], group.membership_generation);
    assert_eq!(roster["recipients"].as_array().unwrap().len(), 2);
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-roster",
            &b"{\"extra\":1}"[..]
        )
        .is_err()
    );
    let bytes = serde_json::to_vec(&tx).unwrap();
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-rotations",
            bytes.as_slice()
        )
        .is_err()
    );
    let missing = serde_json::to_vec(&f.rotation(std::slice::from_ref(&own), 1)).unwrap();
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-rotations",
            missing.as_slice()
        )
        .is_err()
    );
    let editors = accounts
        .save_group(
            Some(&group.id),
            "Team",
            vec![
                Membership {
                    user_id: owner.id.clone(),
                    edit: true,
                },
                Membership {
                    user_id: reader.id.clone(),
                    edit: true,
                },
            ],
        )
        .unwrap();
    let delegated =
        serde_json::to_vec(&f.rotation(&recipients, editors.membership_generation)).unwrap();
    // Edit permission and a valid signed candidate do not make its submitter
    // the designated authority.
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-rotations",
            delegated.as_slice()
        )
        .is_err()
    );
    let changed = accounts
        .save_group(
            Some(&group.id),
            "Team",
            vec![Membership {
                user_id: owner.id.clone(),
                edit: true,
            }],
        )
        .unwrap();
    assert!(changed.rotation_required);
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-roster",
            &b"{}"[..]
        )
        .is_err()
    );
    let roster: serde_json::Value = serde_json::from_slice(
        &dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-roster",
            &b"{}"[..],
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        roster["membership_generation"],
        changed.membership_generation
    );
    assert_eq!(roster["recipients"].as_array().unwrap().len(), 1);
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-rotations",
            bytes.as_slice()
        )
        .is_err()
    );
    let revoked =
        serde_json::to_vec(&f.rotation(&recipients, changed.membership_generation)).unwrap();
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-rotations",
            revoked.as_slice()
        )
        .is_err()
    );
    let tx = f.rotation(&[own], changed.membership_generation);
    let bytes = serde_json::to_vec(&tx).unwrap();
    let accepted = dispatch(
        &mut accounts,
        dir.path(),
        &owner_token,
        &group.id,
        "entry-rotations",
        bytes.as_slice(),
    )
    .unwrap();
    let response: petika_core::entry_format::transaction::CommitResponse =
        serde_json::from_slice(&accepted).unwrap();
    tx.verify_receipt(&owner.id, &response.receipt).unwrap();
    assert_eq!(
        dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-rotations",
            bytes.as_slice()
        )
        .unwrap(),
        accepted
    );
    let lookup = serde_json::to_vec(
        &serde_json::json!({"context":f.root.context(),"operation":tx.operation}),
    )
    .unwrap();
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-receipt",
            lookup.as_slice()
        )
        .is_err()
    );
    let found = dispatch(
        &mut accounts,
        dir.path(),
        &owner_token,
        &group.id,
        "entry-receipt",
        lookup.as_slice(),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<petika_core::entry_format::transaction::ReceiptLookup>(&found)
            .unwrap()
            .receipt,
        Some(response.receipt)
    );
    let query =
        serde_json::to_vec(&serde_json::json!({"context":f.root.context(),"after":first.accepted}))
            .unwrap();
    assert!(
        dispatch(
            &mut accounts,
            dir.path(),
            &reader_token,
            &group.id,
            "entry-epoch",
            query.as_slice()
        )
        .is_err()
    );
    let found: serde_json::Value = serde_json::from_slice(
        &dispatch(
            &mut accounts,
            dir.path(),
            &owner_token,
            &group.id,
            "entry-epoch",
            query.as_slice(),
        )
        .unwrap(),
    )
    .unwrap();
    let found: EpochTransaction = serde_json::from_value(found["transaction"].clone()).unwrap();
    assert_eq!(
        found.submission_digest(&owner.id).unwrap(),
        tx.submission_digest(&owner.id).unwrap()
    );
    // Account flag is left intact; the committed epoch proves this generation's
    // rotation was satisfied without a second account-database publication.
    let next = VerifiedIndex::open(
        &f.next_root,
        tx.object.head.clone(),
        tx.object.envelope.as_bytes(),
    )
    .unwrap();
    let mut index = next.index().clone();
    index.revision += 1;
    index.parent_digest = next.head().digest().unwrap();
    let ordinary = Transaction {
        version: 1,
        operation: "3".repeat(64),
        expected: Cursor::from_head(next.head()).unwrap(),
        object: wire(&f.next_root, &index),
        changes: vec![],
    };
    dispatch(
        &mut accounts,
        dir.path(),
        &owner_token,
        &group.id,
        "entry-transactions",
        serde_json::to_vec(&ordinary).unwrap().as_slice(),
    )
    .unwrap();
    assert_eq!(Journal::open(path).unwrap().current().unwrap().revision, 3);
}

#[test]
fn epoch_git_tree_contains_exact_wrappers_and_signed_transition() {
    let mut f = Fixture::basic();
    let tx = f.rotation(&[f.authority.public_identity().clone()], 1);
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(dir.path().join("journal")).unwrap();
    f.initialize(&mut journal);
    journal.rotate(&"f".repeat(64), tx.clone()).unwrap();
    let mirror = dir.path().join("mirror");
    crate::entry_replication::mirror_local(&journal, &mirror).unwrap();
    let show = |spec: &str| {
        let output = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(mirror.join("repository.git"))
            .args(["show", spec])
            .output()
            .unwrap();
        assert!(output.status.success());
        output.stdout
    };
    let epoch: EpochState = serde_json::from_slice(&show("HEAD:epoch.json")).unwrap();
    assert_eq!(epoch.checkpoint, tx.transition.next);
    assert_eq!(
        serde_json::to_vec(&epoch.wrappers).unwrap(),
        serde_json::to_vec(&tx.wrappers).unwrap()
    );
    let transition: Transition = serde_json::from_slice(&show("HEAD:transition.json")).unwrap();
    assert_eq!(transition, tx.transition);
    let old: EpochState = serde_json::from_slice(&show("HEAD^:epoch.json")).unwrap();
    assert_eq!(old.checkpoint, *f.trusted.checkpoint());
    for entry in &tx.entries {
        assert_eq!(
            show(&format!("HEAD:entries/{}.json", entry.id)),
            entry.envelope.as_bytes()
        );
    }
}

fn migration_draft(
    authority: &mut UnlockedIdentity,
    collection: &str,
    recipients: &[PublicIdentity],
    generation: u64,
) -> petika_core::entry_format::migration_draft::MigrationDraft {
    use petika_core::entry_format::migration_draft::*;
    let mut source = petika_core::UnlockedStore::create(PASSWORD).unwrap();
    source
        .put(
            "literal/path".into(),
            petika_core::Entry {
                username: "test".into(),
                password: "synthetic migration secret".into(),
                url: String::new(),
                notes: String::new(),
                otp: Some("JBSWY3DPEHPK3PXP".into()),
            },
            false,
        )
        .unwrap();
    let encrypted = source.seal().unwrap();
    let binding = SourceBinding::capture(
        authority.public_identity().deployment_id.clone(),
        collection.into(),
        1,
        generation,
        &encrypted,
    )
    .unwrap();
    MigrationDraft::stage(
        binding,
        &encrypted,
        PASSWORD,
        authority,
        recipients,
        Recovery::Omit,
    )
    .unwrap()
}

#[test]
fn migration_api_cas_authority_retained_source_and_exact_retry() {
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    accounts.migrate().unwrap();
    let owner = accounts
        .create_user("owner", "Owner", PASSWORD.into(), true, true)
        .unwrap();
    let editor = accounts
        .create_user("editor", "Editor", PASSWORD.into(), false, false)
        .unwrap();
    let (owner_token, _) = accounts.login("owner", PASSWORD.into()).unwrap();
    let (editor_token, _) = accounts.login("editor", PASSWORD.into()).unwrap();
    let deployment = accounts
        .key_operation(&owner_token, KeyOperation::Deployment, b"")
        .unwrap()["deployment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut authority = enroll(&mut accounts, &owner_token, &deployment, &owner.id);
    let mut editor_identity = enroll(&mut accounts, &editor_token, &deployment, &editor.id);
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
                    user_id: editor.id.clone(),
                    edit: true,
                },
            ],
        )
        .unwrap();
    let recipients = vec![
        authority.public_identity().clone(),
        editor_identity.public_identity().clone(),
    ];
    authority
        .verify_contact(
            &editor.id,
            editor_identity.public_identity(),
            &editor_identity.public_identity().fingerprint,
            None,
        )
        .unwrap();
    // Personal owner and shared administrator both use the same publication path.
    for collection in [&owner.id, &group.id] {
        let roster = if collection == &owner.id {
            &recipients[..1]
        } else {
            &recipients[..]
        };
        let generation = if collection == &owner.id {
            1
        } else {
            group.membership_generation
        };
        let draft = migration_draft(&mut authority, collection, roster, generation);
        let path = dir.path().join("collections").join(collection);
        let source = crate::Snapshot {
            schema_version: 1,
            revision: 1,
            encrypted: draft.source_encrypted.clone(),
            delivery: None,
        };
        let original = serde_json::to_vec(&source).unwrap();
        StoreFile::lock(path.join("snapshot.json"))
            .unwrap()
            .write(&original, true)
            .unwrap();
        let body = serde_json::to_vec(&draft).unwrap();
        let submit = |accounts: &mut Accounts, token: &str, body: &[u8]| {
            dispatch(
                accounts,
                dir.path(),
                token,
                collection,
                "entry-migrations",
                body,
            )
        };
        assert!(submit(&mut accounts, "invalid", &body).is_err());
        if collection == &group.id {
            assert!(submit(&mut accounts, &editor_token, &body).is_err());
        }
        // Snapshot revision, ciphertext and recipient enrollment are all CAS inputs.
        let mut changed: crate::Snapshot = serde_json::from_slice(&original).unwrap();
        changed.revision += 1;
        StoreFile::lock(path.join("snapshot.json"))
            .unwrap()
            .write(&serde_json::to_vec(&changed).unwrap(), false)
            .unwrap();
        assert!(submit(&mut accounts, &owner_token, &body).is_err());
        assert!(!path.join("entries/committed-root").exists());
        StoreFile::lock(path.join("snapshot.json"))
            .unwrap()
            .write(&original, false)
            .unwrap();
        let mut wrong_source: crate::Snapshot = serde_json::from_slice(&original).unwrap();
        wrong_source.encrypted.push('\n'); // valid framing, different exact ciphertext digest
        StoreFile::lock(path.join("snapshot.json"))
            .unwrap()
            .write(&serde_json::to_vec(&wrong_source).unwrap(), false)
            .unwrap();
        assert!(submit(&mut accounts, &owner_token, &body).is_err());
        StoreFile::lock(path.join("snapshot.json"))
            .unwrap()
            .write(&original, false)
            .unwrap();
        let mut stale = draft.clone();
        stale.source.membership_generation += 1;
        authority.sign_entry_migration(&mut stale).unwrap();
        assert!(
            submit(
                &mut accounts,
                &owner_token,
                &serde_json::to_vec(&stale).unwrap()
            )
            .is_err()
        );
        if collection == &group.id {
            let mut wrong_roster = draft.clone();
            wrong_roster.recipients.retain(|r| r.user_id == owner.id);
            authority.sign_entry_migration(&mut wrong_roster).unwrap();
            assert!(
                submit(
                    &mut accounts,
                    &owner_token,
                    &serde_json::to_vec(&wrong_roster).unwrap()
                )
                .is_err()
            );
        }
        assert!(!path.join("entries/committed-root").exists());
        assert!(
            accounts
                .backup_owner_export(&owner.id, Some(collection))
                .is_ok()
        );
        let first = submit(&mut accounts, &owner_token, &body).unwrap();
        assert_eq!(first, submit(&mut accounts, &owner_token, &body).unwrap());
        for recipient in if collection == &group.id {
            vec![&owner.id, &editor.id]
        } else {
            vec![&owner.id]
        } {
            let exported = accounts
                .backup_owner_export(recipient, Some(collection))
                .unwrap();
            assert_eq!(exported["backup_version"], 2);
            assert_eq!(exported["owner_id"], *recipient);
            assert_eq!(exported["entries"].as_object().unwrap().len(), 1);
            let handoff: petika_core::identity::EntryHandoff =
                serde_json::from_value(exported["handoff"].clone()).unwrap();
            let package =
                petika_core::identity::EntryKeyPackage::parse(handoff.package.as_bytes()).unwrap();
            assert_eq!(package.recipient_user_id, *recipient);
            assert!(exported.get("snapshot").is_none());
            assert!(exported.get("wrappers").is_none());
        }
        assert_eq!(std::fs::read(path.join("snapshot.json")).unwrap(), original);
        let journal = Journal::open(path.join("entries")).unwrap();
        let root = journal.current().unwrap();
        assert_eq!(
            journal.epoch_state(&root).unwrap().unwrap().checkpoint,
            draft.state.checkpoint
        );
        assert_eq!(journal.committed_tree(1).unwrap().1.len(), 1);
        drop(journal);
        // Direct legacy storage is protected as well as HTTP routing.
        assert!(
            crate::Repository::new(path.join("snapshot.json"))
                .update(1, draft.source_encrypted.clone())
                .is_err()
        );
        let mut other = draft.clone();
        other.operation = "0".repeat(64);
        authority.sign_entry_migration(&mut other).unwrap();
        assert!(
            submit(
                &mut accounts,
                &owner_token,
                &serde_json::to_vec(&other).unwrap()
            )
            .is_err()
        );
        other.operation = draft.operation.clone();
        other.entries.clear();
        authority.sign_entry_migration(&mut other).unwrap();
        assert!(
            submit(
                &mut accounts,
                &owner_token,
                &serde_json::to_vec(&other).unwrap()
            )
            .is_err()
        );
    }
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
        accounts
            .backup_owner_export(&editor.id, Some(&group.id))
            .is_err()
    );
    assert!(
        accounts
            .backup_owner_export(&owner.id, Some(&group.id))
            .is_ok()
    );
    // A non-admin editor may migrate their own personal vault.
    let own = editor_identity.public_identity().clone();
    let draft = migration_draft(&mut editor_identity, &editor.id, &[own], 1);
    let path = dir
        .path()
        .join("collections")
        .join(&editor.id)
        .join("snapshot.json");
    StoreFile::lock(&path)
        .unwrap()
        .write(
            &serde_json::to_vec(&crate::Snapshot {
                schema_version: 1,
                revision: 1,
                encrypted: draft.source_encrypted.clone(),
                delivery: None,
            })
            .unwrap(),
            true,
        )
        .unwrap();
    dispatch(
        &mut accounts,
        dir.path(),
        &editor_token,
        &editor.id,
        "entry-migrations",
        serde_json::to_vec(&draft).unwrap().as_slice(),
    )
    .unwrap();
}

#[test]
fn migration_termination_worker() {
    let Ok(directory) = std::env::var("PETIKA_MIGRATION_CRASH_DIR") else {
        return;
    };
    let stage: u8 = std::env::var("PETIKA_MIGRATION_CRASH_STAGE")
        .unwrap()
        .parse()
        .unwrap();
    let path = std::path::PathBuf::from(directory);
    let draft = petika_core::entry_format::migration_draft::MigrationDraft::parse(
        &std::fs::read(path.join("candidate.json")).unwrap(),
    )
    .unwrap();
    let authority = draft.state.checkpoint.authority.clone();
    let trusted = draft.verify_public(&draft.source, &authority).unwrap();
    let mut journal = Journal::open(path.join("entries")).unwrap();
    journal
        .migrate_observed(&authority.user_id, draft, &trusted, |at| {
            if at == stage {
                std::process::exit(73);
            }
            Ok(())
        })
        .unwrap();
    panic!("crash boundary not reached");
}

#[test]
fn migration_process_exit_exposes_only_complete_format_switch() {
    let mut authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
    let public = authority.public_identity().clone();
    let draft = migration_draft(
        &mut authority,
        &"b".repeat(64),
        std::slice::from_ref(&public),
        1,
    );
    let trusted = draft.verify_public(&draft.source, &public).unwrap();
    for stage in 1..=8 {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("snapshot.json"),
            draft.source_encrypted.as_bytes(),
        )
        .unwrap();
        StoreFile::lock(dir.path().join("candidate.json"))
            .unwrap()
            .write(&serde_json::to_vec(&draft).unwrap(), true)
            .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "entry_journal::epochs::tests::migration_termination_worker",
            ])
            .env("PETIKA_MIGRATION_CRASH_DIR", dir.path())
            .env("PETIKA_MIGRATION_CRASH_STAGE", stage.to_string())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        assert_eq!(
            std::fs::read(dir.path().join("snapshot.json")).unwrap(),
            draft.source_encrypted.as_bytes()
        );
        let mut journal = Journal::open(dir.path().join("entries")).unwrap();
        assert_eq!(journal.current().is_some(), stage >= 7);
        if let Some(root) = journal.current() {
            assert_eq!(
                journal.epoch_state(&root).unwrap().unwrap().checkpoint,
                draft.state.checkpoint
            );
            assert_eq!(
                journal.committed_tree(1).unwrap().1.len(),
                draft.entries.len()
            );
            assert!(journal.receipt(&public.user_id, &draft.operation).is_some());
        }
        journal
            .migrate(&public.user_id, draft.clone(), &trusted)
            .unwrap();
        assert_eq!(journal.current().unwrap().revision, 1);
    }
}
