use base64::{Engine, engine::general_purpose::STANDARD};
use petika_core::{
    Error,
    identity::{IdentityFile, MAX_IDENTITY_BYTES, PublicIdentity, UnlockedIdentity},
};
use serde_json::{Value, json};

const PASS: &str = "synthetic identity unlock phrase";
const NEW_PASS: &str = "a different synthetic unlock phrase";

fn identity() -> UnlockedIdentity {
    UnlockedIdentity::generate(&"a".repeat(64), &"b".repeat(64), 1).unwrap()
}

#[test]
fn independent_keys_and_signed_identity_records() {
    let first = identity();
    let second = identity();
    let a = first.public_identity();
    let b = second.public_identity();
    a.validate().unwrap();
    b.validate().unwrap();
    assert_ne!(a.fingerprint, b.fingerprint);
    assert_ne!(a.standard_public_key, b.standard_public_key);
    assert_ne!(a.hybrid_public_key, b.hybrid_public_key);
    assert_ne!(a.signing_public_key, b.signing_public_key);
    assert_ne!(a.standard_public_key, a.signing_public_key);
    let public_json = serde_json::to_string(a).unwrap();
    for secret_field in ["standard_secret", "hybrid_seed", "signing_seed"] {
        assert!(!public_json.contains(secret_field));
    }
    assert_eq!(STANDARD.decode(&a.standard_public_key).unwrap().len(), 32);
    assert_eq!(STANDARD.decode(&a.hybrid_public_key).unwrap().len(), 1216);
    assert_eq!(STANDARD.decode(&a.signing_public_key).unwrap().len(), 32);
}

#[test]
fn identity_recovery_and_rewrap_preserve_all_public_keys() {
    let first = identity();
    let public = first.public_identity().clone();
    let backup = first.seal(PASS).unwrap();
    let randomized = first.seal(PASS).unwrap();
    assert_ne!(backup, randomized);
    let serialized = std::str::from_utf8(&backup).unwrap();
    assert!(!serialized.contains(PASS));
    for field in ["standard_secret", "hybrid_seed", "signing_seed"] {
        assert!(!serialized.contains(field));
    }
    drop(first); // Simulate loss of the original unlocked session.
    let recovered = UnlockedIdentity::open(&backup, PASS, &public.fingerprint).unwrap();
    assert_eq!(recovered.public_identity(), &public);
    let rewrapped = recovered.seal(NEW_PASS).unwrap();
    drop(recovered);
    assert!(matches!(
        UnlockedIdentity::open(&rewrapped, PASS, &public.fingerprint),
        Err(Error::Authentication)
    ));
    assert_eq!(
        UnlockedIdentity::open(&rewrapped, NEW_PASS, &public.fingerprint)
            .unwrap()
            .public_identity(),
        &public
    );
    // Rewrapping never rewrites independently retained recovery material.
    assert!(UnlockedIdentity::open(&backup, PASS, &public.fingerprint).is_ok());
}

#[test]
fn wrong_passphrase_and_untrusted_identity_fail() {
    let original = identity();
    let other = identity();
    let backup = original.seal(PASS).unwrap();
    assert!(matches!(
        UnlockedIdentity::open(
            &backup,
            "incorrect",
            &original.public_identity().fingerprint
        ),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        UnlockedIdentity::open(&backup, PASS, &other.public_identity().fingerprint),
        Err(Error::Authentication)
    ));
    let mut swapped: Value = serde_json::from_slice(&backup).unwrap();
    swapped["public_identity"] = serde_json::to_value(other.public_identity()).unwrap();
    assert!(
        UnlockedIdentity::open(
            &serde_json::to_vec(&swapped).unwrap(),
            PASS,
            &original.public_identity().fingerprint
        )
        .is_err()
    );
}

#[test]
fn public_record_changes_invalidate_fingerprint_or_signature() {
    let original = identity();
    let public = original.public_identity();
    for field in ["deployment_id", "user_id", "fingerprint"] {
        let mut value = serde_json::to_value(public).unwrap();
        value[field] = json!("c".repeat(64));
        let changed: PublicIdentity = serde_json::from_value(value).unwrap();
        assert!(changed.validate().is_err(), "{field}");
    }
    for field in [
        "standard_public_key",
        "hybrid_public_key",
        "signing_public_key",
        "signature",
    ] {
        let mut value = serde_json::to_value(public).unwrap();
        let mut decoded = STANDARD.decode(value[field].as_str().unwrap()).unwrap();
        decoded[0] ^= 1;
        value[field] = json!(STANDARD.encode(decoded));
        let changed: PublicIdentity = serde_json::from_value(value).unwrap();
        assert!(changed.validate().is_err(), "{field}");
    }
    let mut changed = public.clone();
    changed.identity_version += 1;
    assert!(changed.validate().is_err());
}

#[test]
fn encrypted_bundle_tampering_fails_authentication() {
    let original = identity();
    let backup = original.seal(PASS).unwrap();
    for field in ["ciphertext", "salt", "nonce"] {
        let mut value: Value = serde_json::from_slice(&backup).unwrap();
        let mut decoded = STANDARD
            .decode(value["encrypted_bundle"][field].as_str().unwrap())
            .unwrap();
        decoded[0] ^= 1;
        value["encrypted_bundle"][field] = json!(STANDARD.encode(decoded));
        assert!(
            matches!(
                UnlockedIdentity::open(
                    &serde_json::to_vec(&value).unwrap(),
                    PASS,
                    &original.public_identity().fingerprint
                ),
                Err(Error::Authentication)
            ),
            "{field}"
        );
    }
}

#[test]
fn malformed_and_resource_exhausting_records_fail_before_unlock() {
    let original = identity();
    let backup = original.seal(PASS).unwrap();
    for (field, replacement) in [
        ("bundle_version", json!(999)),
        ("kdf", json!("argon2id-v19-m999999999-t3-p1")),
        ("salt", json!("AAAA")),
        ("nonce", json!("AAAA")),
        ("ciphertext", json!("A".repeat(90000))),
        ("extra", json!(1)),
    ] {
        let mut value: Value = serde_json::from_slice(&backup).unwrap();
        value["encrypted_bundle"][field] = replacement;
        assert!(
            matches!(
                UnlockedIdentity::open(
                    &serde_json::to_vec(&value).unwrap(),
                    PASS,
                    &original.public_identity().fingerprint
                ),
                Err(Error::Format)
            ),
            "{field}"
        );
    }
    let duplicate =
        std::str::from_utf8(&backup)
            .unwrap()
            .replacen('{', "{\"backup_version\":1,", 1);
    assert!(matches!(
        UnlockedIdentity::open(
            duplicate.as_bytes(),
            PASS,
            &original.public_identity().fingerprint
        ),
        Err(Error::Format)
    ));
    assert!(matches!(
        UnlockedIdentity::open(
            &vec![0; MAX_IDENTITY_BYTES + 1],
            PASS,
            &original.public_identity().fingerprint
        ),
        Err(Error::Format)
    ));
    for (deployment, user, version) in [
        ("short".into(), "b".repeat(64), 1),
        ("a".repeat(64), "B".repeat(64), 1),
        ("a".repeat(64), "b".repeat(64), 0),
        ("a".repeat(64), "b".repeat(64), 1 << 53),
    ] {
        assert!(matches!(
            UnlockedIdentity::generate(&deployment, &user, version),
            Err(Error::Format)
        ));
    }
    assert!(matches!(original.seal("short"), Err(Error::WeakPassphrase)));
    assert!(matches!(
        original.seal(&"a".repeat(4097)),
        Err(Error::Format)
    ));
}

#[test]
fn identity_file_is_exclusive_and_never_overwrites_on_create() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recipient.identity");
    let original = identity();
    let public = original.public_identity();
    let file = IdentityFile::lock(&path).unwrap();
    file.save(&original, PASS, true).unwrap();
    let saved = std::fs::read(&path).unwrap();
    assert!(matches!(IdentityFile::lock(&path), Err(Error::Busy)));
    assert!(matches!(
        file.save(&original, PASS, true),
        Err(Error::AlreadyExists)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    assert!(file.open("incorrect", &public.fingerprint).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    assert!(matches!(
        file.save(&original, "short", false),
        Err(Error::WeakPassphrase)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    file.save(&original, NEW_PASS, false).unwrap();
    drop(file);
    drop(original);
    let recovered = IdentityFile::lock(&path).unwrap();
    let parsed: Value = serde_json::from_slice(&saved).unwrap();
    let fingerprint = parsed["public_identity"]["fingerprint"].as_str().unwrap();
    recovered.open(NEW_PASS, fingerprint).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn identity_storage_rejects_symlinks_and_shared_permissions() {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("real.identity");
    let link = directory.path().join("link.identity");
    std::fs::write(&target, b"synthetic").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &link).unwrap();
    assert!(matches!(IdentityFile::lock(&link), Err(Error::Permissions)));
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        IdentityFile::lock(&target),
        Err(Error::Permissions)
    ));
}
