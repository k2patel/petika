#![cfg(feature = "experimental-device-keys")]
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use petika_core::device_keys::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/device-keys-v1.json")).unwrap()
}
fn roster(index: usize) -> DeviceRoster {
    DeviceRoster::parse(&serde_json::to_vec(&fixtures()["chain"][index]["roster"]).unwrap())
        .unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn pin(value: DeviceRoster) -> TrustedDeviceRoster {
    let authority = value.authority.fingerprint.clone();
    let digest = value.digest().unwrap();
    TrustedDeviceRoster::bootstrap(value, &authority, &digest).unwrap()
}
fn authority() -> DeviceAuthorityKey {
    DeviceAuthorityKey::generate(&"a".repeat(64), &"b".repeat(64)).unwrap()
}
fn device() -> DeviceRecord {
    DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64))
        .unwrap()
        .public_record()
        .unwrap()
}
fn sorted(mut devices: Vec<DeviceRecord>) -> Vec<DeviceRecord> {
    devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    devices
}

#[test]
fn independent_python_transcripts_signatures_and_roster_chain_match() {
    let vectors = fixtures();
    let first = roster(0);
    let second = roster(1);
    let third = roster(2);
    assert_eq!(
        hex(&first.authority.canonical_bytes().unwrap()),
        vectors["authority_transcript_hex"]
    );
    for (i, d) in second.devices.iter().enumerate() {
        assert_eq!(
            hex(&d.canonical_bytes().unwrap()),
            vectors["device_transcripts_hex"][i]
        );
        assert_eq!(
            DeviceRecord::parse(&serde_json::to_vec(d).unwrap()).unwrap(),
            *d
        );
    }
    for (i, r) in [&first, &second, &third].into_iter().enumerate() {
        assert_eq!(
            hex(&r.canonical_bytes().unwrap()),
            vectors["chain"][i]["canonical_hex"]
        );
        assert_eq!(r.digest().unwrap(), vectors["chain"][i]["digest"]);
        // JSON field order/whitespace have no cryptographic meaning.
        let bytes = serde_json::to_vec_pretty(&serde_json::to_value(r).unwrap()).unwrap();
        assert_eq!(
            DeviceRoster::parse(&bytes).unwrap().digest().unwrap(),
            r.digest().unwrap()
        );
    }
    let mut trusted = pin(first.clone());
    trusted.accept(first).unwrap(); // exact retry
    trusted.accept(second.clone()).unwrap();
    trusted.accept(third.clone()).unwrap();
    assert!(trusted.accept(second).is_err());
    assert_eq!(trusted.roster(), &third);
}

#[test]
fn new_devices_have_distinct_same_account_keys_and_a_separate_authority() {
    let a = device();
    let b = device();
    let auth = authority();
    assert_eq!(a.user_id, b.user_id);
    assert_ne!(a.device_id, b.device_id);
    assert_ne!(a.standard_public_key, b.standard_public_key);
    assert_ne!(a.hybrid_public_key, b.hybrid_public_key);
    assert_ne!(a.signing_public_key, b.signing_public_key);
    let start = auth
        .sign_roster(1, String::new(), vec![a.clone()], vec![])
        .unwrap();
    assert_ne!(start.authority.signing_public_key, a.signing_public_key);
    let next = auth
        .sign_roster(2, start.digest().unwrap(), sorted(vec![a, b]), vec![])
        .unwrap();
    let mut trusted = pin(start);
    trusted.accept(next).unwrap();
    assert!(DeviceIdentity::generate("invalid", &"b".repeat(64)).is_err());
    assert!(DeviceAuthorityKey::generate(&"a".repeat(64), "invalid").is_err());
}

#[test]
fn parsers_reject_ambiguous_unknown_oversized_and_invalid_json() {
    let d = roster(0).devices.remove(0);
    let value = serde_json::to_value(&d).unwrap();
    for (key, replacement) in [
        ("record_version", json!(2)),
        ("record_version", json!(1.0)),
        ("device_id", json!("C".repeat(64))),
        ("user_id", Value::Null),
        ("extra", json!(true)),
        ("standard_public_key", json!("A".repeat(10000))),
        ("signature", json!("AAAA")),
    ] {
        let mut bad = value.clone();
        bad[key] = replacement;
        assert!(
            DeviceRecord::parse(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{key}"
        );
    }
    let original = serde_json::to_string(&d).unwrap();
    for text in [
        original.replacen('{', "{\"record_version\":1,", 1),
        format!("{original}{{}}"),
        "{}".into(),
        "null".into(),
    ] {
        assert!(DeviceRecord::parse(text.as_bytes()).is_err());
    }
    assert!(DeviceRecord::parse(&vec![b' '; MAX_DEVICE_RECORD_BYTES + 1]).is_err());
    assert!(DeviceAuthority::parse(&vec![b' '; MAX_AUTHORITY_BYTES + 1]).is_err());
    assert!(DeviceRoster::parse(&vec![b' '; MAX_ROSTER_BYTES + 1]).is_err());
    let r = roster(1);
    let value = serde_json::to_value(&r).unwrap();
    for (key, replacement) in [
        ("roster_version", json!(99)),
        ("generation", json!(0)),
        ("generation", json!(MAX_GENERATION + 1)),
        ("generation", json!(-1)),
        ("devices", Value::Null),
        ("revoked_device_ids", Value::Null),
        ("parent_digest", json!("")),
        ("extra", json!(0)),
    ] {
        let mut bad = value.clone();
        bad[key] = replacement;
        assert!(
            DeviceRoster::parse(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{key}"
        );
    }
    let raw = serde_json::to_string(&r).unwrap().replacen(
        "\"authority_version\":1",
        "\"authority_version\":1,\"authority_version\":1",
        1,
    );
    assert!(DeviceRoster::parse(raw.as_bytes()).is_err());
    let mut unknown = value;
    unknown["authority"]["untrusted"] = json!(true);
    assert!(DeviceRoster::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn invalid_keys_and_tampered_records_are_rejected() {
    let original = roster(0).devices.remove(0);
    for field in ["deployment_id", "user_id", "device_id", "fingerprint"] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[field] = json!("f".repeat(64));
        assert!(DeviceRecord::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    for field in [
        "standard_public_key",
        "hybrid_public_key",
        "signing_public_key",
        "signature",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        let mut bytes = STANDARD.decode(value[field].as_str().unwrap()).unwrap();
        bytes[0] ^= 1;
        value[field] = json!(STANDARD.encode(bytes));
        assert!(DeviceRecord::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    for bad in [[0; 32], [0xff; 32], {
        let mut b = [0; 32];
        b[0] = 1;
        b
    }] {
        let mut record = original.clone();
        record.standard_public_key = STANDARD.encode(bad);
        assert!(record.canonical_bytes().is_err());
        let mut record = original.clone();
        let mut hybrid = STANDARD.decode(&record.hybrid_public_key).unwrap();
        hybrid[1184..].copy_from_slice(&bad);
        record.hybrid_public_key = STANDARD.encode(hybrid);
        assert!(record.canonical_bytes().is_err());
    }
    let mut record = original.clone();
    record.signing_public_key = STANDARD.encode([0; 32]);
    assert!(record.canonical_bytes().is_err());
    let mut record = original;
    record.standard_public_key.pop();
    assert!(record.canonical_bytes().is_err());
    let mut auth = roster(0).authority;
    auth.user_id = "f".repeat(64);
    assert!(auth.validate().is_err());
}

#[test]
fn sorted_unique_bounded_rosters_and_tombstones_are_required() {
    let auth = authority();
    let a = device();
    let b = device();
    let pair = sorted(vec![a.clone(), b.clone()]);
    let mut reversed = pair.clone();
    reversed.reverse();
    let parent = "c".repeat(64);
    assert!(
        auth.sign_roster(2, parent.clone(), reversed, vec![])
            .is_err()
    );
    assert!(
        auth.sign_roster(2, parent.clone(), vec![a.clone(), a.clone()], vec![])
            .is_err()
    );
    assert!(
        auth.sign_roster(
            2,
            parent.clone(),
            vec![a.clone(); MAX_ACTIVE_DEVICES + 1],
            vec![]
        )
        .is_err()
    );
    assert!(
        auth.sign_roster(
            2,
            parent.clone(),
            vec![a.clone()],
            vec![a.device_id.clone()]
        )
        .is_err()
    );
    assert!(
        auth.sign_roster(
            2,
            parent.clone(),
            pair.clone(),
            vec!["f".repeat(64), "e".repeat(64)]
        )
        .is_err()
    );
    assert!(auth.sign_roster(1, String::new(), pair, vec![]).is_err());
    assert!(auth.sign_roster(1, parent.clone(), vec![], vec![]).is_err());
    assert!(
        auth.sign_roster(1, String::new(), vec![], vec!["f".repeat(64)])
            .is_err()
    );
    let revoked: Vec<_> = (0..MAX_REVOKED_DEVICES)
        .map(|i| format!("{i:064x}"))
        .collect();
    let at_limit = auth
        .sign_roster(MAX_GENERATION, parent.clone(), vec![], revoked.clone())
        .unwrap();
    let bytes = serde_json::to_vec(&at_limit).unwrap();
    assert!(bytes.len() <= MAX_ROSTER_BYTES);
    DeviceRoster::parse(&bytes).unwrap();
    let mut too_many = revoked;
    too_many.push("f".repeat(64));
    assert!(auth.sign_roster(2, parent, vec![], too_many).is_err());
    let foreign = DeviceIdentity::generate(&"f".repeat(64), &"b".repeat(64))
        .unwrap()
        .public_record()
        .unwrap();
    assert!(
        auth.sign_roster(1, String::new(), vec![foreign], vec![])
            .is_err()
    );
}

// Build a valid self-signed alternate using the published synthetic fixture recipe.
// This deliberately reuses keys to test authority-side rejection; never production input.
fn alternate_with_id(id: String) -> DeviceRecord {
    let mut record = roster(1).devices.remove(1);
    record.device_id = id;
    let canonical = record.canonical_bytes().unwrap();
    record.fingerprint = hex(&Sha256::digest(&canonical));
    let mut message = Vec::new();
    for part in [
        b"petika:device-self-signature:experimental-v1".as_slice(),
        &canonical,
        record.fingerprint.as_bytes(),
    ] {
        message.extend_from_slice(&(part.len() as u32).to_be_bytes());
        message.extend_from_slice(part);
    }
    let seed = Sha256::digest(b"PUBLIC PETIKA DEVICE FORMAT TEST ONLY: device-1");
    record.signature = STANDARD.encode(
        SigningKey::from_bytes(&seed.into())
            .sign(&message)
            .to_bytes(),
    );
    record.validate().unwrap();
    record
}

#[test]
fn valid_signatures_do_not_allow_rekey_erased_revocations_forks_or_batched_changes() {
    let auth = authority();
    let a = roster(0).devices.remove(0);
    let b = device();
    let start = auth
        .sign_roster(1, String::new(), vec![a.clone()], vec![])
        .unwrap();
    let parent = start.digest().unwrap();
    let mut trusted = pin(start);
    let rekey = alternate_with_id(a.device_id.clone());
    let rewritten = auth
        .sign_roster(2, parent.clone(), vec![rekey], vec![])
        .unwrap();
    assert!(trusted.accept(rewritten).is_err());
    let batched = auth
        .sign_roster(
            2,
            parent.clone(),
            sorted(vec![a.clone(), b.clone(), device()]),
            vec![],
        )
        .unwrap();
    assert!(trusted.accept(batched).is_err());
    let no_op = auth
        .sign_roster(2, parent.clone(), vec![a.clone()], vec![])
        .unwrap();
    assert!(trusted.accept(no_op).is_err());
    let wrong_parent = auth
        .sign_roster(
            2,
            "e".repeat(64),
            sorted(vec![a.clone(), b.clone()]),
            vec![],
        )
        .unwrap();
    assert!(trusted.accept(wrong_parent).is_err());
    let skipped = auth
        .sign_roster(
            3,
            parent.clone(),
            sorted(vec![a.clone(), b.clone()]),
            vec![],
        )
        .unwrap();
    assert!(trusted.accept(skipped).is_err());
    let other_auth = authority()
        .sign_roster(
            2,
            parent.clone(),
            sorted(vec![a.clone(), b.clone()]),
            vec![],
        )
        .unwrap();
    assert!(trusted.accept(other_auth).is_err());
    assert_eq!(trusted.roster().digest().unwrap(), parent);
    let added = auth
        .sign_roster(2, parent, sorted(vec![a.clone(), b.clone()]), vec![])
        .unwrap();
    trusted.accept(added.clone()).unwrap();
    let removed = auth
        .sign_roster(
            3,
            added.digest().unwrap(),
            vec![b.clone()],
            vec![a.device_id.clone()],
        )
        .unwrap();
    trusted.accept(removed.clone()).unwrap();
    let erased = auth
        .sign_roster(
            4,
            removed.digest().unwrap(),
            sorted(vec![a.clone(), b.clone()]),
            vec![],
        )
        .unwrap();
    assert!(trusted.accept(erased).is_err());
    let removed_without_tombstone = auth
        .sign_roster(4, removed.digest().unwrap(), vec![], vec![a.device_id])
        .unwrap();
    assert!(trusted.accept(removed_without_tombstone).is_err());
    assert_eq!(trusted.roster(), &removed);
    assert!(
        TrustedDeviceRoster::bootstrap(
            removed.clone(),
            &"f".repeat(64),
            &removed.digest().unwrap()
        )
        .is_err()
    );
    assert!(
        TrustedDeviceRoster::bootstrap(
            removed.clone(),
            &removed.authority.fingerprint,
            &"f".repeat(64)
        )
        .is_err()
    );
}

#[test]
fn duplicated_active_key_material_is_rejected_even_with_valid_self_signatures() {
    let auth = authority();
    let second = roster(1).devices.remove(1);
    let duplicate = alternate_with_id("3".repeat(64));
    assert!(
        auth.sign_roster(2, "c".repeat(64), sorted(vec![second, duplicate]), vec![])
            .is_err()
    );
}

#[test]
fn maximum_active_roster_fits_input_bound_and_separate_authority_is_enforced() {
    let auth = authority();
    let devices = sorted((0..MAX_ACTIVE_DEVICES).map(|_| device()).collect());
    let roster = auth
        .sign_roster(2, "c".repeat(64), devices, vec![])
        .unwrap();
    let bytes = serde_json::to_vec(&roster).unwrap();
    assert!(bytes.len() < MAX_ROSTER_BYTES);
    assert_eq!(DeviceRoster::parse(&bytes).unwrap(), roster);
    let mut invalid = roster;
    invalid.authority.signing_public_key = invalid.devices[0].signing_public_key.clone();
    invalid.authority.fingerprint = hex(&Sha256::digest(
        invalid.authority.canonical_bytes().unwrap(),
    ));
    assert!(invalid.canonical_bytes().is_err());
}
