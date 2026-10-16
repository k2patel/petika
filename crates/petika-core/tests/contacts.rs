use petika_core::{
    Error, StoreFile,
    identity::{ContactStatus, IdentityFile, UnlockedIdentity},
};
use serde_json::{Value, json};

const PASS: &str = "synthetic identity unlock phrase";
const LEGACY: &[u8] = include_bytes!("fixtures/identity-backup-v1.json");

fn identity(user: char, version: u64) -> UnlockedIdentity {
    UnlockedIdentity::generate(&"a".repeat(64), &user.to_string().repeat(64), version).unwrap()
}

fn verify(owner: &mut UnlockedIdentity, recipient: &UnlockedIdentity) {
    let public = recipient.public_identity();
    let prior = owner.contact_pin(&public.user_id).cloned();
    owner
        .verify_contact(&public.user_id, public, &public.fingerprint, prior.as_ref())
        .unwrap();
}

#[test]
fn first_contact_requires_independent_confirmation_and_is_idempotent() {
    let mut owner = identity('b', 1);
    let peer = identity('c', 1);
    let public = peer.public_identity();
    assert_eq!(
        owner.observe_contact(&public.user_id, public).unwrap(),
        ContactStatus::Unverified
    );
    assert!(owner.contact_pin(&public.user_id).is_none());
    assert!(matches!(
        owner.require_verified_contact(&public.user_id, public),
        Err(Error::UnverifiedContact)
    ));
    assert!(matches!(
        owner.verify_contact(&public.user_id, public, &"d".repeat(64), None),
        Err(Error::Authentication)
    ));
    assert!(owner.contact_pin(&public.user_id).is_none());
    verify(&mut owner, &peer);
    let pin = owner.contact_pin(&public.user_id).unwrap().clone();
    assert_eq!(pin.revision(), 1);
    assert_eq!(pin.fingerprint(), public.fingerprint);
    assert!(
        owner
            .require_verified_contact(&public.user_id, public)
            .is_ok()
    );
    verify(&mut owner, &peer);
    assert_eq!(owner.contact_pin(&public.user_id), Some(&pin));
}

#[test]
fn changed_key_suspension_survives_directory_reversion_and_encrypted_restore() {
    let mut owner = identity('b', 1);
    let original = identity('c', 1);
    let replacement = identity('c', 2);
    verify(&mut owner, &original);
    let public = replacement.public_identity();
    assert!(matches!(
        owner.require_verified_contact(&public.user_id, public),
        Err(Error::ContactKeyChanged)
    ));
    let pin = owner.contact_pin(&public.user_id).unwrap().clone();
    assert!(pin.suspended());
    assert_eq!(pin.fingerprint(), original.public_identity().fingerprint);
    assert_eq!(
        owner
            .observe_contact(&public.user_id, original.public_identity())
            .unwrap(),
        ContactStatus::Suspended
    );
    let bytes = owner.seal(PASS).unwrap();
    let json = std::str::from_utf8(&bytes).unwrap();
    assert!(!json.contains(&public.user_id));
    assert!(!json.contains(&public.fingerprint));
    assert!(!json.contains(&original.public_identity().fingerprint));
    let owner_fp = owner.public_identity().fingerprint.clone();
    drop(owner);
    let mut recovered = UnlockedIdentity::open(&bytes, PASS, &owner_fp).unwrap();
    assert_eq!(recovered.contact_pin(&public.user_id), Some(&pin));
    assert!(matches!(
        recovered.require_verified_contact(&public.user_id, original.public_identity()),
        Err(Error::ContactKeyChanged)
    ));
    verify(&mut recovered, &replacement);
    assert!(
        recovered
            .require_verified_contact(&public.user_id, public)
            .is_ok()
    );
    assert_eq!(
        recovered
            .contact_pin(&public.user_id)
            .unwrap()
            .identity_version(),
        2
    );
}

#[test]
fn old_or_same_version_different_keys_cannot_replace_verified_identity() {
    let mut owner = identity('b', 1);
    let peer = identity('c', 2);
    let rollback = identity('c', 1);
    let equivocation = identity('c', 2);
    verify(&mut owner, &peer);
    let old = rollback.public_identity();
    assert!(matches!(
        owner.require_verified_contact(&old.user_id, old),
        Err(Error::ContactRollback)
    ));
    let pin = owner.contact_pin(&old.user_id).unwrap().clone();
    assert!(matches!(
        owner.verify_contact(&old.user_id, old, &old.fingerprint, Some(&pin)),
        Err(Error::ContactRollback)
    ));
    let alternate = equivocation.public_identity();
    assert!(matches!(
        owner.verify_contact(
            &alternate.user_id,
            alternate,
            &alternate.fingerprint,
            Some(&pin)
        ),
        Err(Error::ContactKeyChanged)
    ));
    assert_eq!(owner.contact_pin(&old.user_id), Some(&pin));
    // Independent re-verification can restore the original trusted identity after a
    // false alarm. Unverified high version numbers never poison the trusted version.
    verify(&mut owner, &peer);
    assert!(
        owner
            .require_verified_contact(&old.user_id, peer.public_identity())
            .is_ok()
    );
}

#[test]
fn stale_verification_cannot_overwrite_a_newer_pin_or_suspension() {
    let mut owner = identity('b', 1);
    let peer = identity('c', 1);
    let newer = identity('c', 2);
    verify(&mut owner, &peer);
    let original_pin = owner
        .contact_pin(&peer.public_identity().user_id)
        .unwrap()
        .clone();
    let public = newer.public_identity();
    owner.observe_contact(&public.user_id, public).unwrap();
    let suspended = owner.contact_pin(&public.user_id).unwrap().clone();
    assert!(matches!(
        owner.verify_contact(
            &public.user_id,
            public,
            &public.fingerprint,
            Some(&original_pin)
        ),
        Err(Error::ContactConflict)
    ));
    assert_eq!(owner.contact_pin(&public.user_id), Some(&suspended));
    verify(&mut owner, &newer);
    let current = owner.contact_pin(&public.user_id).unwrap().clone();
    assert!(matches!(
        owner.verify_contact(&public.user_id, public, &public.fingerprint, None),
        Err(Error::ContactConflict)
    ));
    assert_eq!(owner.contact_pin(&public.user_id), Some(&current));
}

#[test]
fn cross_deployment_wrong_user_self_and_forged_records_are_rejected() {
    let mut owner = identity('b', 1);
    let peer = identity('c', 1);
    verify(&mut owner, &peer);
    let public = peer.public_identity();
    let prior = owner.contact_pin(&public.user_id).unwrap().clone();
    let foreign = UnlockedIdentity::generate(&"f".repeat(64), &public.user_id, 1).unwrap();
    assert!(
        owner
            .observe_contact(&public.user_id, foreign.public_identity())
            .is_err()
    );
    assert!(owner.observe_contact(&"d".repeat(64), public).is_err());
    let own_public = owner.public_identity().clone();
    assert!(
        owner
            .observe_contact(&own_public.user_id, &own_public)
            .is_err()
    );
    let mut forged = public.clone();
    forged.signature = "AAAA".into();
    assert!(owner.observe_contact(&public.user_id, &forged).is_err());
    assert_eq!(owner.contact_pin(&public.user_id), Some(&prior));
}

#[test]
fn verified_contacts_survive_rewrap_and_new_device_restore() {
    let mut owner = identity('b', 1);
    let peer = identity('c', 1);
    verify(&mut owner, &peer);
    let old_pin = owner
        .contact_pin(&peer.public_identity().user_id)
        .unwrap()
        .clone();
    let bytes = owner.seal(PASS).unwrap();
    let fingerprint = owner.public_identity().fingerprint.clone();
    let restored = UnlockedIdentity::open(&bytes, PASS, &fingerprint).unwrap();
    let rewrapped = restored.seal("another synthetic passphrase").unwrap();
    let mut second =
        UnlockedIdentity::open(&rewrapped, "another synthetic passphrase", &fingerprint).unwrap();
    assert_eq!(second.contact_pin(old_pin.user_id()), Some(&old_pin));
    assert!(
        second
            .require_verified_contact(old_pin.user_id(), peer.public_identity())
            .is_ok()
    );
}

#[test]
fn legacy_identity_upgrades_only_on_save_and_preserves_exact_backup() {
    let fixture: Value = serde_json::from_slice(LEGACY).unwrap();
    let public = &fixture["public_identity"];
    let fingerprint = public["fingerprint"].as_str().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recipient.identity");
    StoreFile::lock(&path).unwrap().write(LEGACY, true).unwrap();
    let file = IdentityFile::lock(&path).unwrap();
    let mut restored = file.open(PASS, fingerprint).unwrap();
    assert_eq!(
        serde_json::to_value(restored.public_identity()).unwrap(),
        *public
    );
    assert_eq!(std::fs::read(&path).unwrap(), LEGACY);
    let peer = identity('c', 1);
    verify(&mut restored, &peer);
    file.save(&restored, PASS, false).unwrap();
    let backup_path = directory.path().join("recipient.identity.v1.backup");
    assert_eq!(std::fs::read(&backup_path).unwrap(), LEGACY);
    let current: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(current["backup_version"], 2);
    assert_eq!(current["encrypted_bundle"]["bundle_version"], 2);
    let mut reopened = file.open(PASS, fingerprint).unwrap();
    assert!(
        reopened
            .require_verified_contact(&peer.public_identity().user_id, peer.public_identity())
            .is_ok()
    );
    file.save(&reopened, PASS, false).unwrap();
    assert_eq!(std::fs::read(&backup_path).unwrap(), LEGACY);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn conflicting_migration_backup_never_overwrites_current_or_backup() {
    let fixture: Value = serde_json::from_slice(LEGACY).unwrap();
    let fingerprint = fixture["public_identity"]["fingerprint"].as_str().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recipient.identity");
    let backup_path = directory.path().join("recipient.identity.v1.backup");
    StoreFile::lock(&path).unwrap().write(LEGACY, true).unwrap();
    StoreFile::lock(&backup_path)
        .unwrap()
        .write(b"a different original", true)
        .unwrap();
    let file = IdentityFile::lock(&path).unwrap();
    let restored = file.open(PASS, fingerprint).unwrap();
    assert!(matches!(
        file.save(&restored, PASS, false),
        Err(Error::AlreadyExists)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), LEGACY);
    assert_eq!(
        std::fs::read(&backup_path).unwrap(),
        b"a different original"
    );
}

#[test]
fn version_relabeling_cannot_strip_contact_pins() {
    let mut owner = identity('b', 1);
    verify(&mut owner, &identity('c', 1));
    let bytes = owner.seal(PASS).unwrap();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["backup_version"] = json!(1);
    value["encrypted_bundle"]["bundle_version"] = json!(1);
    assert!(matches!(
        UnlockedIdentity::open(
            &serde_json::to_vec(&value).unwrap(),
            PASS,
            &owner.public_identity().fingerprint
        ),
        Err(Error::Authentication)
    ));
    value["encrypted_bundle"]["bundle_version"] = json!(2);
    assert!(matches!(
        UnlockedIdentity::open(
            &serde_json::to_vec(&value).unwrap(),
            PASS,
            &owner.public_identity().fingerprint
        ),
        Err(Error::Format)
    ));
}

#[test]
fn contact_limit_is_enforced_without_losing_existing_pins() {
    use petika_core::identity::MAX_VERIFIED_CONTACTS;
    let mut owner = identity('b', 1);
    let mut last = None;
    for i in 0..MAX_VERIFIED_CONTACTS {
        let peer = UnlockedIdentity::generate(&"a".repeat(64), &format!("{i:064x}"), 1).unwrap();
        verify(&mut owner, &peer);
        last = Some(peer);
    }
    let rejected = identity('e', 1);
    let public = rejected.public_identity();
    assert!(matches!(
        owner.verify_contact(&public.user_id, public, &public.fingerprint, None),
        Err(Error::ContactLimit)
    ));
    assert!(owner.contact_pin(&public.user_id).is_none());
    let peer = last.unwrap();
    let fingerprint = owner.public_identity().fingerprint.clone();
    let bytes = owner.seal(PASS).unwrap();
    let mut restored = UnlockedIdentity::open(&bytes, PASS, &fingerprint).unwrap();
    assert!(
        restored
            .require_verified_contact(&peer.public_identity().user_id, peer.public_identity())
            .is_ok()
    );
}

#[test]
fn explicit_replacement_refuses_a_different_local_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recipient.identity");
    let file = IdentityFile::lock(&path).unwrap();
    file.save(&identity('b', 1), PASS, true).unwrap();
    let original = std::fs::read(&path).unwrap();
    assert!(matches!(
        file.save(&identity('b', 2), PASS, false),
        Err(Error::Authentication)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), original);
}
