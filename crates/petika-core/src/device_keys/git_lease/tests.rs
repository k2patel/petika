use super::*;
fn fixture() -> (GitLeaseProof, TrustedDeviceRoster, serde_json::Value) {
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../tests/fixtures/git-lease-v1.json"))
            .unwrap();
    let source: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/device-keys-v1.json"
    ))
    .unwrap();
    let roster: DeviceRoster =
        serde_json::from_value(source["chain"][0]["roster"].clone()).unwrap();
    let pin = TrustedDeviceRoster::bootstrap(
        roster.clone(),
        &roster.authority.fingerprint,
        &roster.digest().unwrap(),
    )
    .unwrap();
    let proof = GitLeaseProof::parse(&serde_json::to_vec(&fixture["proof"]).unwrap()).unwrap();
    (proof, pin, fixture)
}
#[test]
fn independent_two_signatures_and_exact_transcript_match() {
    let (proof, pin, fixture) = fixture();
    proof.verify(&pin, 100).unwrap();
    assert_eq!(
        STANDARD.encode(proof.challenge.canonical_bytes().unwrap()),
        fixture["canonical"]
    );
    assert_eq!(proof.challenge.digest().unwrap(), fixture["digest"]);
    assert_eq!(
        proof.challenge.openssh_public_key().unwrap(),
        fixture["openssh_public_key"]
    );
    assert_eq!(
        proof.challenge.ssh_fingerprint().unwrap(),
        fixture["ssh_fingerprint"]
    );
    assert!(proof.verify(&pin, 99).is_err());
    assert!(proof.verify(&pin, 160).is_err());
    let mut altered = proof.clone();
    altered.device_signature = STANDARD.encode([0; 64]);
    assert!(altered.verify(&pin, 100).is_err());
    let mut altered = proof.clone();
    altered.ssh_signature = STANDARD.encode([0; 64]);
    assert!(altered.verify(&pin, 100).is_err());
    let mut altered = proof;
    altered.challenge.read_only = false;
    assert!(altered.verify(&pin, 100).is_err());
}
#[test]
fn client_requires_active_device_remote_confirmation_and_matching_ssh_private_key() {
    let (proof, _, _) = fixture();
    let device = DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    let authority = DeviceAuthorityKey::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    let roster = authority
        .sign_roster(
            1,
            String::new(),
            vec![device.public_record().unwrap()],
            vec![],
        )
        .unwrap();
    let pin = TrustedDeviceRoster::bootstrap(
        roster.clone(),
        &roster.authority.fingerprint,
        &roster.digest().unwrap(),
    )
    .unwrap();
    let mut challenge = proof.challenge;
    challenge.device_id = roster.devices[0].device_id.clone();
    challenge.device_fingerprint = roster.devices[0].fingerprint.clone();
    challenge.roster_digest = roster.digest().unwrap();
    let seed: [u8; 32] =
        Sha256::digest(b"PUBLIC PETIKA DEVICE FORMAT TEST ONLY: temporary-ssh").into();
    let proof = device
        .authorize_git_lease(
            challenge.clone(),
            &pin,
            "https://git.example/",
            "synthetic/vault",
            &seed,
            101,
        )
        .unwrap();
    proof.verify(&pin, 101).unwrap();
    assert!(
        device
            .authorize_git_lease(
                challenge.clone(),
                &pin,
                "https://other.example/",
                "synthetic/vault",
                &seed,
                101
            )
            .is_err()
    );
    assert!(
        device
            .authorize_git_lease(
                challenge.clone(),
                &pin,
                "https://git.example/",
                "synthetic/vault",
                &[9; 32],
                101
            )
            .is_err()
    );
    let other = DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    assert!(
        other
            .authorize_git_lease(
                challenge,
                &pin,
                "https://git.example/",
                "synthetic/vault",
                &seed,
                101
            )
            .is_err()
    );
}
#[test]
fn wire_bounds_unknown_fields_bad_keys_and_excessive_lifetime_fail() {
    let (proof, _, _) = fixture();
    let mut value = serde_json::to_value(&proof).unwrap();
    value["private_key"] = serde_json::json!("prohibited");
    assert!(GitLeaseProof::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(GitLeaseProof::parse(&vec![b' '; 16385]).is_err());
    let mut challenge = proof.challenge.clone();
    challenge.lease_expires_at = challenge.issued_at + 3601;
    assert!(challenge.canonical_bytes().is_err());
    let mut challenge = proof.challenge;
    challenge.ssh_public_key = STANDARD.encode([0; 32]);
    assert!(challenge.canonical_bytes().is_err());
}
