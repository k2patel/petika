use super::*;
use serde_json::{Value, json};

fn pin(roster: DeviceRoster) -> TrustedDeviceRoster {
    let digest = roster.digest().unwrap();
    let fingerprint = roster.authority.fingerprint.clone();
    TrustedDeviceRoster::bootstrap(roster, &fingerprint, &digest).unwrap()
}
fn setup() -> (DeviceAuthorityKey, DeviceIdentity, TrustedDeviceRoster) {
    let authority = DeviceAuthorityKey::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    let device = DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    let current = pin(authority
        .sign_roster(1, String::new(), vec![], vec![])
        .unwrap());
    (authority, device, current)
}
fn pending(
    authority: &DeviceAuthorityKey,
    device: &DeviceIdentity,
    current: &TrustedDeviceRoster,
) -> PendingEnrollment {
    let request = device.enrollment_request(current, 100).unwrap();
    let fingerprint = request.device.fingerprint.clone();
    authority
        .challenge_enrollment(request, current, &fingerprint, 101)
        .unwrap()
}
fn answer(
    device: &DeviceIdentity,
    p: &PendingEnrollment,
    current: &TrustedDeviceRoster,
) -> EnrollmentProof {
    device
        .answer_enrollment(
            p.challenge(),
            current,
            &current.roster().authority.fingerprint,
            102,
        )
        .unwrap()
}
fn resign(proof: &mut EnrollmentProof, device: &DeviceIdentity) {
    proof.signature = STANDARD.encode(
        SigningKey::from_bytes(&device.signing_seed)
            .sign(&proof.canonical_bytes().unwrap())
            .to_bytes(),
    );
}
fn synthetic_seed(label: &str) -> [u8; 32] {
    Sha256::digest(format!("PUBLIC PETIKA DEVICE FORMAT TEST ONLY: {label}")).into()
}

#[test]
fn independent_hpke_requests_challenges_and_proofs_match_python() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/device-enrollment-v1.json"
    ))
    .unwrap();
    let records: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/device-keys-v1.json")).unwrap();
    let kats: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/xwing-draft06.json")).unwrap();
    let hybrid_seed: Vec<u8> = kats[1]["sk"]
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    let device = DeviceIdentity {
        standard_secret: synthetic_seed("standard-1"),
        hybrid_seed: hybrid_seed.try_into().unwrap(),
        signing_seed: synthetic_seed("device-1"),
        deployment_id: "a".repeat(64),
        user_id: "b".repeat(64),
        device_id: "2".repeat(64),
    };
    let authority = DeviceAuthorityKey {
        seed: synthetic_seed("separate-authority"),
        deployment_id: "a".repeat(64),
        user_id: "b".repeat(64),
    };
    let baseline =
        DeviceRoster::parse(&serde_json::to_vec(&records["chain"][0]["roster"]).unwrap()).unwrap();
    let current = pin(baseline);
    let request =
        EnrollmentRequest::parse(&serde_json::to_vec(&vectors["request"]).unwrap()).unwrap();
    assert_eq!(request.device, device.public_record().unwrap());
    assert_eq!(
        STANDARD.encode(request.canonical_bytes().unwrap()),
        vectors["request_canonical"]
    );
    assert_eq!(request.digest().unwrap(), vectors["request_digest"]);
    let challenge =
        EnrollmentChallenge::parse(&serde_json::to_vec(&vectors["challenge"]).unwrap()).unwrap();
    assert_eq!(
        STANDARD.encode(challenge.canonical_bytes().unwrap()),
        vectors["challenge_canonical"]
    );
    assert_eq!(challenge.digest().unwrap(), vectors["challenge_digest"]);
    let proof = device
        .answer_enrollment(
            &challenge,
            &current,
            &current.roster().authority.fingerprint,
            102,
        )
        .unwrap();
    assert_eq!(serde_json::to_value(&proof).unwrap(), vectors["proof"]);
    assert_eq!(
        STANDARD.encode(proof.canonical_bytes().unwrap()),
        vectors["proof_canonical"]
    );
    let expected = response(
        &challenge.digest().unwrap(),
        &synthetic_seed("challenge-standard"),
        &synthetic_seed("challenge-hybrid"),
    );
    let mut pending = PendingEnrollment {
        challenge,
        expected,
        used: false,
    };
    let next = pending
        .approve(
            &authority,
            &proof,
            &current,
            &request.device.fingerprint,
            103,
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(next).unwrap(),
        records["chain"][1]["roster"]
    );
    assert!(pending.expected.iter().all(|b| *b == 0));
}

#[test]
fn ceremony_prepares_one_successor_without_advancing_the_pin_and_rejects_replay() {
    let (authority, device, mut current) = setup();
    let before = current.roster().digest().unwrap();
    let mut pending = pending(&authority, &device, &current);
    let challenge =
        EnrollmentChallenge::parse(&serde_json::to_vec(pending.challenge()).unwrap()).unwrap();
    let proof = device
        .answer_enrollment(
            &challenge,
            &current,
            &current.roster().authority.fingerprint,
            102,
        )
        .unwrap();
    let proof = EnrollmentProof::parse(&serde_json::to_vec(&proof).unwrap()).unwrap();
    let fingerprint = device.public_record().unwrap().fingerprint;
    let candidate = pending
        .approve(&authority, &proof, &current, &fingerprint, 103)
        .unwrap();
    assert_eq!(current.roster().digest().unwrap(), before);
    assert!(
        pending
            .approve(&authority, &proof, &current, &fingerprint, 103)
            .is_err()
    );
    current.accept(candidate.clone()).unwrap();
    current.accept(candidate).unwrap(); // publication receipt retry is separate from proof replay
    assert_eq!(
        current.roster().devices,
        vec![device.public_record().unwrap()]
    );
    assert!(device.enrollment_request(&current, 104).is_err());
}

#[test]
fn wrong_confirmations_authorities_devices_and_time_windows_fail_closed() {
    let (authority, device, current) = setup();
    let request = device.enrollment_request(&current, 100).unwrap();
    let fingerprint = request.device.fingerprint.clone();
    let wrong_authority = DeviceAuthorityKey::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    assert!(
        wrong_authority
            .challenge_enrollment(request.clone(), &current, &fingerprint, 101)
            .is_err()
    );
    assert!(
        authority
            .challenge_enrollment(request.clone(), &current, &"f".repeat(64), 101)
            .is_err()
    );
    for now in [99, 400, MAX_GENERATION] {
        assert!(
            authority
                .challenge_enrollment(request.clone(), &current, &fingerprint, now)
                .is_err()
        );
    }
    assert!(device.enrollment_request(&current, 0).is_err());
    assert!(device.enrollment_request(&current, MAX_GENERATION).is_err());
    let mut p = pending(&authority, &device, &current);
    let proof = answer(&device, &p, &current);
    assert!(
        device
            .answer_enrollment(p.challenge(), &current, &"f".repeat(64), 102)
            .is_err()
    );
    let other = DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    assert!(
        other
            .answer_enrollment(
                p.challenge(),
                &current,
                &current.roster().authority.fingerprint,
                102
            )
            .is_err()
    );
    for now in [99, 400] {
        assert!(
            device
                .answer_enrollment(
                    p.challenge(),
                    &current,
                    &current.roster().authority.fingerprint,
                    now
                )
                .is_err()
        );
        assert!(
            p.approve(&authority, &proof, &current, &fingerprint, now)
                .is_err()
        );
    }
    assert!(
        p.approve(&wrong_authority, &proof, &current, &fingerprint, 103)
            .is_err()
    );
    assert!(
        p.approve(&authority, &proof, &current, &"f".repeat(64), 103)
            .is_err()
    );
    assert!(!p.used);
    p.approve(&authority, &proof, &current, &fingerprint, 399)
        .unwrap();
}

#[test]
fn signed_response_requires_both_independent_decryption_results() {
    let (authority, device, current) = setup();
    let mut p = pending(&authority, &device, &current);
    let original = answer(&device, &p, &current);
    let digest = p.challenge.request.digest().unwrap();
    let first = open::<X25519HkdfSha256>(
        &device.standard_secret,
        &p.challenge.standard,
        &hpke_binding(&digest, b"standard"),
    )
    .unwrap();
    let second = open::<XWing>(
        &device.hybrid_seed,
        &p.challenge.hybrid,
        &hpke_binding(&digest, b"experimental-xwing-draft06"),
    )
    .unwrap();
    for (a, b) in [(&[0u8; 32][..], &second[..]), (&first[..], &[0u8; 32][..])] {
        let mut forged = original.clone();
        forged.response = STANDARD.encode(response(&forged.challenge_digest, a, b).as_slice());
        resign(&mut forged, &device);
        assert!(
            p.approve(
                &authority,
                &forged,
                &current,
                &p.challenge.request.device.fingerprint.clone(),
                103
            )
            .is_err()
        );
    }
    let mut forged = original.clone();
    forged.signature = STANDARD.encode([0; 64]);
    assert!(
        p.approve(
            &authority,
            &forged,
            &current,
            &device.public_record().unwrap().fingerprint,
            103
        )
        .is_err()
    );
    assert!(!p.used);
    p.approve(
        &authority,
        &original,
        &current,
        &device.public_record().unwrap().fingerprint,
        103,
    )
    .unwrap();
}

#[test]
fn modified_packets_fail_decryption_even_if_the_authority_resigns_them() {
    let (authority, device, current) = setup();
    let p = pending(&authority, &device, &current);
    for hybrid in [false, true] {
        let mut challenge = p.challenge.clone();
        let packet = if hybrid {
            &mut challenge.hybrid
        } else {
            &mut challenge.standard
        };
        let mut ciphertext = STANDARD.decode(&packet.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        packet.ciphertext = STANDARD.encode(ciphertext);
        challenge.signature = STANDARD.encode(
            SigningKey::from_bytes(&authority.seed)
                .sign(&challenge.canonical_bytes().unwrap())
                .to_bytes(),
        );
        challenge.validate().unwrap();
        assert!(
            device
                .answer_enrollment(
                    &challenge,
                    &current,
                    &current.roster().authority.fingerprint,
                    102
                )
                .is_err()
        );
    }
    let mut foreign = p.challenge.clone();
    foreign.request.nonce = "f".repeat(64);
    assert!(foreign.validate().is_err());
    let other = pending(&authority, &device, &current);
    let proof = answer(&device, &other, &current);
    let mut original = p;
    assert!(
        original
            .approve(
                &authority,
                &proof,
                &current,
                &device.public_record().unwrap().fingerprint,
                103
            )
            .is_err()
    );
}

#[test]
fn stale_roster_revocation_and_competing_enrollments_cannot_publish_against_a_new_pin() {
    let (authority, device, mut current) = setup();
    let mut p = pending(&authority, &device, &current);
    let proof = answer(&device, &p, &current);
    let other = DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    let mut competitor = pending(&authority, &other, &current);
    let other_proof = answer(&other, &competitor, &current);
    let candidate = competitor
        .approve(
            &authority,
            &other_proof,
            &current,
            &other.public_record().unwrap().fingerprint,
            103,
        )
        .unwrap();
    current.accept(candidate).unwrap();
    let before = current.roster().digest().unwrap();
    assert!(
        p.approve(
            &authority,
            &proof,
            &current,
            &device.public_record().unwrap().fingerprint,
            103
        )
        .is_err()
    );
    assert!(
        device
            .answer_enrollment(
                p.challenge(),
                &current,
                &current.roster().authority.fingerprint,
                103
            )
            .is_err()
    );
    assert_eq!(before, current.roster().digest().unwrap());
    let request = device.enrollment_request(&current, 104).unwrap();
    let revoked = authority
        .sign_roster(
            3,
            before,
            vec![],
            vec![other.public_record().unwrap().device_id],
        )
        .unwrap();
    current.accept(revoked).unwrap();
    assert!(
        authority
            .challenge_enrollment(
                request,
                &current,
                &device.public_record().unwrap().fingerprint,
                105
            )
            .is_err()
    );
    assert!(other.enrollment_request(&current, 105).is_err());
}

#[test]
fn wire_parsers_reject_unknown_duplicate_oversized_or_invalid_fields() {
    let (authority, device, current) = setup();
    let p = pending(&authority, &device, &current);
    let request = &p.challenge.request;
    for (key, value) in [
        ("request_version", json!(2)),
        ("issued_at", json!(0)),
        ("expires_at", json!(401)),
        ("expires_at", json!(100)),
        ("nonce", json!("C".repeat(64))),
        ("extra", json!(0)),
        ("signature", Value::Null),
    ] {
        let mut bad = serde_json::to_value(request).unwrap();
        bad[key] = value;
        assert!(EnrollmentRequest::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let raw = serde_json::to_string(request)
        .unwrap()
        .replacen('{', "{\"request_version\":1,", 1);
    assert!(EnrollmentRequest::parse(raw.as_bytes()).is_err());
    let raw = serde_json::to_string(p.challenge()).unwrap().replacen(
        "\"enc\":",
        "\"extra\":0,\"enc\":",
        1,
    );
    assert!(EnrollmentChallenge::parse(raw.as_bytes()).is_err());
    let proof = answer(&device, &p, &current);
    for (key, value) in [
        ("proof_version", json!(9)),
        ("response", json!("AAAA")),
        ("challenge_digest", json!("")),
        ("extra", json!(true)),
    ] {
        let mut bad = serde_json::to_value(&proof).unwrap();
        bad[key] = value;
        assert!(EnrollmentProof::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    assert!(EnrollmentRequest::parse(&vec![b' '; MAX_ENROLLMENT_REQUEST_BYTES + 1]).is_err());
    assert!(EnrollmentChallenge::parse(&vec![b' '; MAX_ENROLLMENT_CHALLENGE_BYTES + 1]).is_err());
    assert!(EnrollmentProof::parse(&vec![b' '; MAX_ENROLLMENT_PROOF_BYTES + 1]).is_err());
}
