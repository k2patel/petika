use super::*;
use crate::device_keys::{DeviceAuthorityKey, DeviceIdentity};

#[test]
fn independent_bootstrap_signature_and_transcript() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/device-bootstrap-v1.json"
    ))
    .unwrap();
    let value =
        DeviceAuthorityBootstrap::parse(&serde_json::to_vec(&fixture["bootstrap"]).unwrap())
            .unwrap();
    assert_eq!(
        STANDARD.encode(value.canonical_bytes().unwrap()),
        fixture["canonical"]
    );
    assert_eq!(
        value.initial_roster.digest().unwrap(),
        fixture["initial_digest"]
    );
    for field in ["bootstrap_version", "source_bundle_revision", "signature"] {
        let mut changed = fixture["bootstrap"].clone();
        changed[field] = if field == "signature" {
            serde_json::json!(STANDARD.encode([0u8; 64]))
        } else {
            serde_json::json!(8)
        };
        assert!(DeviceAuthorityBootstrap::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let mut unknown = fixture["bootstrap"].clone();
    unknown["private_key"] = serde_json::json!("synthetic prohibited field");
    assert!(DeviceAuthorityBootstrap::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let duplicate =
        serde_json::to_string(&value)
            .unwrap()
            .replacen('{', "{\"bootstrap_version\":1,", 1);
    assert!(DeviceAuthorityBootstrap::parse(duplicate.as_bytes()).is_err());
    assert!(DeviceAuthorityBootstrap::parse(&vec![b' '; MAX_DEVICE_BOOTSTRAP_BYTES + 1]).is_err());
}

#[test]
fn authority_bootstrap_requires_confirmation_scope_empty_baseline_and_legacy_key() {
    let legacy = UnlockedIdentity::generate(&"a".repeat(64), &"b".repeat(64), 1).unwrap();
    let key = DeviceAuthorityKey::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    let initial = key.sign_roster(1, String::new(), vec![], vec![]).unwrap();
    let fp = initial.authority.fingerprint.clone();
    let bootstrap = legacy
        .authorize_device_authority(initial.clone(), 1, &fp)
        .unwrap();
    bootstrap.validate().unwrap();
    assert!(
        legacy
            .authorize_device_authority(initial.clone(), 1, &"c".repeat(64))
            .is_err()
    );
    assert!(
        legacy
            .authorize_device_authority(initial.clone(), 0, &fp)
            .is_err()
    );
    let other = UnlockedIdentity::generate(&"a".repeat(64), &"c".repeat(64), 1).unwrap();
    assert!(
        other
            .authorize_device_authority(initial.clone(), 1, &fp)
            .is_err()
    );
    let device = DeviceIdentity::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    let nonempty = key
        .sign_roster(
            1,
            String::new(),
            vec![device.public_record().unwrap()],
            vec![],
        )
        .unwrap();
    assert!(legacy.authorize_device_authority(nonempty, 1, &fp).is_err());
    let replacement = DeviceAuthorityKey::generate(&"a".repeat(64), &"b".repeat(64)).unwrap();
    let mut substituted = bootstrap.clone();
    substituted.initial_roster = replacement
        .sign_roster(1, String::new(), vec![], vec![])
        .unwrap();
    assert!(substituted.validate().is_err());
    let mut substituted = bootstrap;
    substituted.legacy_identity = UnlockedIdentity::generate(&"a".repeat(64), &"b".repeat(64), 1)
        .unwrap()
        .public
        .clone();
    assert!(substituted.validate().is_err());
}
