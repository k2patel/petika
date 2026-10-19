#![cfg(feature = "experimental-entry-format")]
use petika_core::{
    entry_format::{
        Header, Kind, RootKey, SUITE,
        checkpoint::{
            Checkpoint, DeliveryProfile, Transition, TrustedCheckpoint, WrapperRef,
            wrapper_set_digest,
        },
        digest,
    },
    identity::{CheckpointTarget, EntryKeyPackage, UnlockedIdentity},
};
use serde_json::{Value, json};
const PASS: &str = "synthetic recovery passphrase";
fn root_for_epoch(epoch: u64) -> RootKey {
    RootKey::generate("a".repeat(64), "b".repeat(64), epoch).unwrap()
}
fn identity(user: char) -> UnlockedIdentity {
    UnlockedIdentity::generate(&"a".repeat(64), &user.to_string().repeat(64), 1).unwrap()
}
fn verify(a: &mut UnlockedIdentity, b: &UnlockedIdentity) {
    let p = b.public_identity();
    a.verify_contact(&p.user_id, p, &p.fingerprint, None)
        .unwrap();
}
fn target(revision: u64, profile: DeliveryProfile) -> CheckpointTarget {
    CheckpointTarget {
        head_revision: revision,
        head_digest: "d".repeat(64),
        membership_generation: 3,
        delivery_profile: profile,
    }
}
fn pin(cp: Checkpoint) -> TrustedCheckpoint {
    let d = cp.digest().unwrap();
    let f = cp.authority.fingerprint.clone();
    TrustedCheckpoint::bootstrap(cp, &d, &f).unwrap()
}
fn dummy_refs() -> Vec<WrapperRef> {
    vec![WrapperRef {
        wrapper_id: "e".repeat(64),
        digest: "f".repeat(64),
    }]
}
#[test]
fn entry_recipients_require_checkpoint_membership_and_verified_issuer_in_both_profiles() {
    for profile in [
        DeliveryProfile::Standard,
        DeliveryProfile::ExperimentalXwingDraft06,
    ] {
        let mut alice = identity('c');
        let mut bob = identity('d');
        let mut eve = identity('e');
        let root = root_for_epoch(1);
        assert!(
            alice
                .create_entry_key_package(&root, bob.public_identity(), 3, profile.clone())
                .is_err()
        );
        verify(&mut alice, &bob);
        let package = alice
            .create_entry_key_package(&root, bob.public_identity(), 3, profile.clone())
            .unwrap();
        let bytes = serde_json::to_vec(&package).unwrap();
        let refs = vec![package.reference().unwrap()];
        let trusted = pin(alice
            .sign_entry_checkpoint(&root, target(1, profile.clone()), &refs)
            .unwrap());
        assert!(
            bob.open_entry_key_package(&bytes, alice.public_identity(), &trusted, &refs)
                .is_err()
        );
        verify(&mut bob, &alice);
        let opened = bob
            .open_entry_key_package(&bytes, alice.public_identity(), &trusted, &refs)
            .unwrap();
        let h = Header {
            entry_format_version: 1,
            suite: SUITE.into(),
            context: root.context().clone(),
            kind: Kind::Entry,
            object_id: "f".repeat(64),
            revision: 1,
        };
        let encrypted = root.seal(&h, b"shared synthetic password").unwrap();
        assert_eq!(
            opened
                .open(&h, &digest(&encrypted), &encrypted)
                .unwrap()
                .as_slice(),
            b"shared synthetic password"
        );
        verify(&mut eve, &alice);
        assert!(
            eve.open_entry_key_package(&bytes, alice.public_identity(), &trusted, &refs)
                .is_err()
        );
        assert!(
            bob.open_entry_key_package(&bytes, alice.public_identity(), &trusted, &dummy_refs())
                .is_err()
        );
        // Even an authority-approved reference cannot authenticate a forged issuer signature.
        let mut bad = package.clone();
        bad.ciphertext.replace_range(
            0..1,
            if bad.ciphertext.starts_with('A') {
                "B"
            } else {
                "A"
            },
        );
        let bad_refs = vec![bad.reference().unwrap()];
        let bad_checkpoint = pin(alice
            .sign_entry_checkpoint(&root, target(1, profile.clone()), &bad_refs)
            .unwrap());
        assert!(
            bob.open_entry_key_package(
                &serde_json::to_vec(&bad).unwrap(),
                alice.public_identity(),
                &bad_checkpoint,
                &bad_refs
            )
            .is_err()
        );
        let mut wrong = target(1, profile.clone());
        wrong.membership_generation = 4;
        let wrong = pin(alice.sign_entry_checkpoint(&root, wrong, &refs).unwrap());
        assert!(
            bob.open_entry_key_package(&bytes, alice.public_identity(), &wrong, &refs)
                .is_err()
        );
        let different = match profile {
            DeliveryProfile::Standard => DeliveryProfile::ExperimentalXwingDraft06,
            _ => DeliveryProfile::Standard,
        };
        let wrong = pin(alice
            .sign_entry_checkpoint(&root, target(1, different), &refs)
            .unwrap());
        assert!(
            bob.open_entry_key_package(&bytes, alice.public_identity(), &wrong, &refs)
                .is_err()
        );

        let fresh = root_for_epoch(2);
        let allowed = alice
            .create_entry_key_package(
                &fresh,
                &alice.public_identity().clone(),
                4,
                package.profile.clone(),
            )
            .unwrap();
        let allowed_refs = vec![allowed.reference().unwrap()];
        let mut next_target = target(2, package.profile.clone());
        next_target.membership_generation = 4;
        let next = alice
            .sign_entry_checkpoint(&fresh, next_target, &allowed_refs)
            .unwrap();
        let transition = alice.authorize_entry_transition(&trusted, next, 1).unwrap();
        let advanced = trusted.advance(&transition, 1).unwrap();
        assert!(
            bob.open_entry_key_package(&bytes, alice.public_identity(), &advanced, &allowed_refs)
                .is_err()
        );
        let mut next_header = h.clone();
        next_header.context = fresh.context().clone();
        let new_ciphertext = fresh.seal(&next_header, b"new epoch secret").unwrap();
        assert!(
            opened
                .open(&next_header, &digest(&new_ciphertext), &new_ciphertext)
                .is_err()
        );
        assert!(petika_core::identity::KeyPackage::parse(&bytes).is_err());
    }
}
#[test]
fn explicit_authority_handover_replay_and_old_reader_cannot_authorize_rotation() {
    let mut alice = identity('c');
    let mut bob = identity('d');
    let old = root_for_epoch(1);
    let next = root_for_epoch(2);
    let trusted = pin(alice
        .sign_entry_checkpoint(&old, target(5, DeliveryProfile::Standard), &dummy_refs())
        .unwrap());
    // Bob may possess the vault root, but is not the checkpoint authority.
    let next_cp = bob
        .sign_entry_checkpoint(&next, target(9, DeliveryProfile::Standard), &dummy_refs())
        .unwrap();
    assert!(
        bob.authorize_entry_transition(&trusted, next_cp.clone(), 8)
            .is_err()
    );
    assert!(
        alice
            .authorize_entry_transition(&trusted, next_cp.clone(), 8)
            .is_err()
    );
    verify(&mut alice, &bob);
    let transition = alice
        .authorize_entry_transition(&trusted, next_cp.clone(), 8)
        .unwrap();
    let encoded = serde_json::to_vec(&transition).unwrap();
    let parsed = Transition::parse(&encoded).unwrap();
    let advanced = trusted.advance(&parsed, 8).unwrap();
    advanced.validate_root(&next).unwrap();
    assert!(advanced.validate_root(&old).is_err());
    assert!(advanced.advance(&parsed, 9).is_err());
    assert!(trusted.advance(&parsed, 9).is_err());
    assert!(trusted.advance(&parsed, 4).is_err());
    let mut forged = transition.clone();
    forged.signature.replace_range(
        0..1,
        if forged.signature.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    assert!(trusted.advance(&forged, 8).is_err());
    let third = root_for_epoch(3);
    let third_cp = bob
        .sign_entry_checkpoint(&third, target(10, DeliveryProfile::Standard), &dummy_refs())
        .unwrap();
    assert!(
        alice
            .authorize_entry_transition(&advanced, third_cp.clone(), 9)
            .is_err()
    );
    let third_transition = bob
        .authorize_entry_transition(&advanced, third_cp, 9)
        .unwrap();
    advanced.advance(&third_transition, 9).unwrap();
    // No unsigned epoch skip or profile switch.
    let skip = root_for_epoch(4);
    let cp = alice
        .sign_entry_checkpoint(&skip, target(12, DeliveryProfile::Standard), &dummy_refs())
        .unwrap();
    assert!(alice.authorize_entry_transition(&trusted, cp, 8).is_err());
    let cp = alice
        .sign_entry_checkpoint(
            &next,
            target(9, DeliveryProfile::ExperimentalXwingDraft06),
            &dummy_refs(),
        )
        .unwrap();
    assert!(alice.authorize_entry_transition(&trusted, cp, 8).is_err());
    let digest = next_cp.digest().unwrap();
    let fingerprint = next_cp.authority.fingerprint.clone();
    assert!(TrustedCheckpoint::bootstrap(next_cp.clone(), &"0".repeat(64), &fingerprint).is_err());
    assert!(TrustedCheckpoint::bootstrap(next_cp, &digest, &"0".repeat(64)).is_err());
    let mut lost = transition;
    lost.previous_checkpoint_digest = "0".repeat(64);
    assert!(trusted.advance(&lost, 8).is_err());
}
#[test]
fn pinned_recovery_requires_active_wrapper_and_matches_the_root() {
    let authority = identity('c');
    let key = root_for_epoch(1);
    let bytes = key.wrap_recovery(PASS).unwrap();
    let wrapper: Value = serde_json::from_slice(&bytes).unwrap();
    let refs = vec![WrapperRef {
        wrapper_id: wrapper["wrapper_id"].as_str().unwrap().into(),
        digest: digest(&bytes).iter().map(|b| format!("{b:02x}")).collect(),
    }];
    let cp = authority
        .sign_entry_checkpoint(&key, target(1, DeliveryProfile::Standard), &refs)
        .unwrap();
    let trusted = pin(cp.clone());
    trusted.open_recovery(&bytes, PASS, &refs).unwrap();
    assert!(trusted.open_recovery(&bytes, "wrong", &refs).is_err());
    assert!(trusted.open_recovery(&bytes, PASS, &dummy_refs()).is_err());
    let replacement = root_for_epoch(2);
    let new = pin(authority
        .sign_entry_checkpoint(&replacement, target(2, DeliveryProfile::Standard), &refs)
        .unwrap());
    assert!(new.open_recovery(&bytes, PASS, &refs).is_err());
    let mut duplicates = refs.clone();
    duplicates.push(refs[0].clone());
    assert!(wrapper_set_digest(&duplicates).is_err());
    assert!(wrapper_set_digest(&[]).is_err());
    let mut invalid = serde_json::to_value(&cp).unwrap();
    invalid["head_revision"] = json!(0);
    assert!(Checkpoint::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    let encoded = serde_json::to_string(&cp)
        .unwrap()
        .replacen("{", "{\"signature\":\"\",", 1);
    assert!(Checkpoint::parse(encoded.as_bytes()).is_err());
    assert!(Checkpoint::parse(&vec![b' '; 16 * 1024 + 1]).is_err());
    assert!(EntryKeyPackage::parse(&vec![b' '; 16 * 1024 + 1]).is_err());
}
