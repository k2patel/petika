#![cfg(feature = "experimental-entry-format")]
use petika_core::{
    CollectionContext, EncryptionMode, Entry, StoreFile, UnlockedStore,
    entry_format::{epoch_transaction::EpochWrapper, migration_draft::*, *},
    identity::{EntryKeyPackage, PublicIdentity, UnlockedIdentity},
};
use serde_json::{Value, json};

const OLD: &str = "synthetic source recovery phrase";
const NEW: &str = "synthetic new recovery phrase";

#[test]
fn empty_migration_draft_has_a_complete_recoverable_index() {
    let mut source = UnlockedStore::create(OLD).unwrap();
    let encrypted = source.seal().unwrap();
    let expected =
        SourceBinding::capture("a".repeat(64), "b".repeat(64), 1, 1, &encrypted).unwrap();
    let mut authority = UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
    let public = authority.public_identity().clone();
    let draft = MigrationDraft::stage(
        expected.clone(),
        &encrypted,
        OLD,
        &mut authority,
        std::slice::from_ref(&public),
        Recovery::Replace(NEW),
    )
    .unwrap();
    let trusted = draft.verify_public(&expected, &public).unwrap();
    let wrapper = draft
        .state
        .wrappers
        .iter()
        .find_map(|w| {
            if let EpochWrapper::Recovery(value) = w {
                Some(value)
            } else {
                None
            }
        })
        .unwrap();
    let root = trusted
        .open_recovery(
            wrapper.as_bytes(),
            NEW,
            &draft.state.references(&trusted).unwrap(),
        )
        .unwrap();
    let index = draft.verify(&expected, &public, OLD, &root).unwrap();
    assert!(index.index().entries.is_empty());
    assert!(draft.entries.is_empty());
    assert_eq!(draft.source_encrypted.as_bytes(), encrypted);
}
struct Fixture {
    encrypted: Vec<u8>,
    source: SourceBinding,
    authority: UnlockedIdentity,
    recipient: UnlockedIdentity,
    roster: Vec<PublicIdentity>,
}
impl Fixture {
    fn new(mode: EncryptionMode, bound: bool) -> Self {
        let mut store = UnlockedStore::create_with_mode(OLD, mode).unwrap();
        for name in ["literal/name", "é", "e\u{301}"] {
            store
                .put(
                    name.into(),
                    Entry {
                        username: "migration-user".into(),
                        password: "migration-secret".into(),
                        url: "https://example.org".into(),
                        notes: "retain these notes".into(),
                        otp: Some("JBSWY3DPEHPK3PXP".into()),
                    },
                    false,
                )
                .unwrap();
        }
        if bound {
            store
                .bind_collection(
                    CollectionContext {
                        deployment_id: "a".repeat(64),
                        collection_id: "b".repeat(64),
                        key_epoch: 1,
                    },
                    OLD,
                )
                .unwrap();
        }
        let encrypted = store.seal().unwrap();
        let source =
            SourceBinding::capture("a".repeat(64), "b".repeat(64), 7, 3, &encrypted).unwrap();
        let mut authority =
            UnlockedIdentity::generate(&"a".repeat(64), &"f".repeat(64), 1).unwrap();
        let mut recipient =
            UnlockedIdentity::generate(&"a".repeat(64), &"e".repeat(64), 1).unwrap();
        let public = recipient.public_identity();
        authority
            .verify_contact(&public.user_id, public, &public.fingerprint, None)
            .unwrap();
        let public = authority.public_identity();
        recipient
            .verify_contact(&public.user_id, public, &public.fingerprint, None)
            .unwrap();
        let roster = vec![
            authority.public_identity().clone(),
            recipient.public_identity().clone(),
        ];
        Self {
            encrypted,
            source,
            authority,
            recipient,
            roster,
        }
    }
    fn stage(&mut self, recovery: Recovery<'_>) -> MigrationDraft {
        MigrationDraft::stage(
            self.source.clone(),
            &self.encrypted,
            OLD,
            &mut self.authority,
            &self.roster,
            recovery,
        )
        .unwrap()
    }
    fn open(&mut self, draft: &MigrationDraft) -> RootKey {
        let trusted = draft
            .verify_public(&self.source, self.authority.public_identity())
            .unwrap();
        let refs = draft.state.references(&trusted).unwrap();
        let package = draft
            .state
            .wrappers
            .iter()
            .find_map(|w| match w {
                EpochWrapper::Recipient(bytes)
                    if EntryKeyPackage::parse(bytes.as_bytes())
                        .unwrap()
                        .recipient_user_id
                        == self.recipient.public_identity().user_id =>
                {
                    Some(bytes)
                }
                _ => None,
            })
            .unwrap();
        self.recipient
            .open_entry_key_package(
                package.as_bytes(),
                self.authority.public_identity(),
                &trusted,
                &refs,
            )
            .unwrap()
    }
}

#[test]
fn migration_drafts_restore_from_disk_in_both_profiles_and_recovery_policies() {
    for mode in [EncryptionMode::Standard, EncryptionMode::HybridPostQuantum] {
        for bound in [false, true] {
            let mut f = Fixture::new(mode, bound);
            let draft = f.stage(if bound {
                Recovery::Replace(NEW)
            } else {
                Recovery::Omit
            });
            let encoded = serde_json::to_vec(&draft).unwrap();
            let text = std::str::from_utf8(&encoded).unwrap();
            for secret in [
                OLD,
                NEW,
                "literal/name",
                "migration-user",
                "migration-secret",
                "retain these notes",
                "JBSWY3DPEHPK3PXP",
            ] {
                assert!(!text.contains(secret));
            }
            assert_eq!(draft.source_encrypted.as_bytes(), f.encrypted);
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("migration.json");
            {
                let file = StoreFile::lock(&path).unwrap();
                file.write(&encoded, true).unwrap();
                assert!(file.write(&encoded, true).is_err());
            }
            let restored =
                MigrationDraft::parse(&StoreFile::lock(&path).unwrap().read().unwrap()).unwrap();
            let root = f.open(&restored);
            let index = restored
                .verify(&f.source, f.authority.public_identity(), OLD, &root)
                .unwrap();
            assert_eq!(index.index().entries.len(), 3);
            assert_eq!(index.head().revision, 1);
            assert_eq!(index.head().context.key_epoch, if bound { 2 } else { 1 });
            for entry in &restored.entries {
                let bytes = index
                    .open_entry(&root, &entry.id, entry.envelope.as_bytes())
                    .unwrap();
                let value: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(value["password"], "migration-secret");
                assert_eq!(value["otp"], "JBSWY3DPEHPK3PXP");
            }
            let recovery = restored.state.wrappers.iter().find_map(|w| {
                if let EpochWrapper::Recovery(value) = w {
                    Some(value)
                } else {
                    None
                }
            });
            assert_eq!(recovery.is_some(), bound);
            if let Some(value) = recovery {
                let trusted = restored
                    .verify_public(&f.source, f.authority.public_identity())
                    .unwrap();
                let root = trusted
                    .open_recovery(
                        value.as_bytes(),
                        NEW,
                        &restored.state.references(&trusted).unwrap(),
                    )
                    .unwrap();
                restored
                    .verify(&f.source, f.authority.public_identity(), OLD, &root)
                    .unwrap();
                assert!(
                    trusted
                        .open_recovery(
                            value.as_bytes(),
                            OLD,
                            &restored.state.references(&trusted).unwrap()
                        )
                        .is_err()
                );
            }
            assert_eq!(StoreFile::lock(&path).unwrap().read().unwrap(), encoded);
        }
    }
}

#[test]
fn migration_draft_binds_source_roster_policy_and_every_ciphertext() {
    let mut f = Fixture::new(EncryptionMode::Standard, true);
    let draft = f.stage(Recovery::Omit);
    let root = f.open(&draft);
    for field in [
        "snapshot_revision",
        "membership_generation",
        "encrypted_digest",
        "key_epoch",
        "collection_id",
    ] {
        let mut value = serde_json::to_value(&f.source).unwrap();
        value[field] = if field.ends_with("id") || field.ends_with("digest") {
            json!("c".repeat(64))
        } else {
            json!(99)
        };
        let stale: SourceBinding = serde_json::from_value(value).unwrap();
        assert!(
            draft
                .verify_public(&stale, f.authority.public_identity())
                .is_err(),
            "{field}"
        );
    }
    for field in [
        "operation",
        "source_encrypted",
        "recovery_policy",
        "recipients",
        "entries",
    ] {
        let mut value = serde_json::to_value(&draft).unwrap();
        value[field] = match field {
            "operation" => json!("c".repeat(64)),
            "source_encrypted" => json!(format!("{} ", draft.source_encrypted)),
            "recovery_policy" => json!("replace"),
            _ => json!([]),
        };
        let changed: MigrationDraft = serde_json::from_value(value).unwrap();
        assert!(
            changed
                .verify_public(&f.source, f.authority.public_identity())
                .is_err(),
            "{field}"
        );
    }
    // A valid authority signature alone cannot prove completeness of an encrypted index.
    let mut incomplete = draft.clone();
    incomplete.entries.pop();
    f.authority.sign_entry_migration(&mut incomplete).unwrap();
    incomplete
        .verify_public(&f.source, f.authority.public_identity())
        .unwrap();
    assert!(
        incomplete
            .verify(&f.source, f.authority.public_identity(), OLD, &root)
            .is_err()
    );
    assert!(
        draft
            .verify(
                &f.source,
                f.authority.public_identity(),
                "wrong recovery",
                &root
            )
            .is_err()
    );
    let wrong = RootKey::generate("a".repeat(64), "b".repeat(64), 2).unwrap();
    assert!(
        draft
            .verify(&f.source, f.authority.public_identity(), OLD, &wrong)
            .is_err()
    );
    let foreign = UnlockedIdentity::generate(&"a".repeat(64), &"d".repeat(64), 1).unwrap();
    assert!(
        draft
            .verify_public(&f.source, foreign.public_identity())
            .is_err()
    );
    let mut missing = draft.clone();
    missing.state.wrappers.pop();
    f.authority.sign_entry_migration(&mut missing).unwrap();
    assert!(
        missing
            .verify_public(&f.source, f.authority.public_identity())
            .is_err()
    );
    assert_eq!(draft.source_encrypted.as_bytes(), f.encrypted);
}

#[test]
fn migration_staging_rejects_unverified_recipients_wrong_source_and_ambiguous_wire() {
    let mut f = Fixture::new(EncryptionMode::Standard, false);
    let stranger = UnlockedIdentity::generate(&"a".repeat(64), &"d".repeat(64), 1).unwrap();
    let mut roster = f.roster.clone();
    roster.push(stranger.public_identity().clone());
    assert!(
        MigrationDraft::stage(
            f.source.clone(),
            &f.encrypted,
            OLD,
            &mut f.authority,
            &roster,
            Recovery::Omit
        )
        .is_err()
    );
    let mut duplicate = f.roster.clone();
    duplicate.push(f.roster[0].clone());
    assert!(
        MigrationDraft::stage(
            f.source.clone(),
            &f.encrypted,
            OLD,
            &mut f.authority,
            &duplicate,
            Recovery::Omit
        )
        .is_err()
    );
    assert!(
        MigrationDraft::stage(
            f.source.clone(),
            &f.encrypted,
            "wrong",
            &mut f.authority,
            &f.roster,
            Recovery::Omit
        )
        .is_err()
    );
    let mut changed = f.source.clone();
    changed.encrypted_digest = "0".repeat(64);
    assert!(
        MigrationDraft::stage(
            changed,
            &f.encrypted,
            OLD,
            &mut f.authority,
            &f.roster,
            Recovery::Omit
        )
        .is_err()
    );
    let draft = f.stage(Recovery::Omit);
    let encoded = serde_json::to_vec(&draft).unwrap();
    let mut unknown: Value = serde_json::from_slice(&encoded).unwrap();
    unknown["unknown"] = json!(true);
    assert!(MigrationDraft::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let duplicate = format!(
        "{{\"version\":1,{}",
        std::str::from_utf8(&encoded)
            .unwrap()
            .trim_start_matches('{')
    );
    assert!(MigrationDraft::parse(duplicate.as_bytes()).is_err());
    assert!(MigrationDraft::parse(b"{}").is_err());
    assert!(MigrationDraft::parse(&vec![b' '; MAX_MIGRATION_BYTES + 1]).is_err());
}
