use petika_core::{Entry, Error, StoreFile, UnlockedStore, generate_password};
use serde_json::Value;

const PASS: &str = "correct test horse battery staple";
fn entry() -> Entry {
    Entry {
        otp: None,
        username: "alice@example.test".into(),
        password: "distinctive-secret-value".into(),
        url: "https://example.test".into(),
        notes: "private note".into(),
    }
}

#[test]
fn encryption_roundtrip_hides_all_fields_and_randomizes_saves() {
    let mut store = UnlockedStore::create(PASS).unwrap();
    store.put("private-name".into(), entry(), false).unwrap();
    let first = store.seal().unwrap();
    let second = store.seal().unwrap();
    assert_ne!(first, second);
    let serialized = String::from_utf8(first.clone()).unwrap();
    for value in [
        "private-name",
        "alice@example.test",
        "distinctive-secret-value",
        "https://example.test",
        "private note",
    ] {
        assert!(!serialized.contains(value));
    }
    let recovered = UnlockedStore::open(&first, PASS).unwrap();
    assert_eq!(
        recovered.get("private-name").unwrap().password,
        "distinctive-secret-value"
    );
    assert_eq!(recovered.get("private-name").unwrap().notes, "private note");
    assert!(matches!(
        UnlockedStore::open(&first, "wrong passphrase"),
        Err(Error::Authentication)
    ));
}

#[test]
fn tampered_ciphertexts_nonces_and_salt_are_rejected() {
    let mut store = UnlockedStore::create(PASS).unwrap();
    let bytes = store.seal().unwrap();
    for field in [
        "ciphertext",
        "wrapped_key",
        "data_nonce",
        "key_nonce",
        "salt",
    ] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let original = value[field][0].as_u64().unwrap();
        value[field][0] = Value::from(original ^ 1);
        assert!(
            UnlockedStore::open(&serde_json::to_vec(&value).unwrap(), PASS).is_err(),
            "{field}"
        );
    }
}

#[test]
fn reject_unsupported_or_resource_exhausting_headers() {
    let mut store = UnlockedStore::create(PASS).unwrap();
    let bytes = store.seal().unwrap();
    for (field, new) in [
        ("version", 99),
        ("memory_kib", u64::MAX),
        ("iterations", 0),
        ("lanes", 0),
    ] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value[field] = Value::from(new);
        assert!(matches!(
            UnlockedStore::open(&serde_json::to_vec(&value).unwrap(), PASS),
            Err(Error::Format)
        ));
    }
    assert!(matches!(
        UnlockedStore::open(b"{}", PASS),
        Err(Error::Format)
    ));
    assert!(matches!(
        UnlockedStore::open(&vec![0; 16 * 1024 * 1024 + 1], PASS),
        Err(Error::Format)
    ));
}

#[test]
fn record_operations_require_explicit_replacement() {
    let mut store = UnlockedStore::create(PASS).unwrap();
    store.put("entry".into(), entry(), false).unwrap();
    assert!(matches!(
        store.put("entry".into(), entry(), false),
        Err(Error::Duplicate)
    ));
    assert!(matches!(
        store.put("bad\nname".into(), entry(), false),
        Err(Error::InvalidName)
    ));
    store.put("entry".into(), entry(), true).unwrap();
    store.remove("entry").unwrap();
    assert!(matches!(store.get("entry"), Err(Error::NotFound)));
    assert!(matches!(store.remove("entry"), Err(Error::NotFound)));
}

#[test]
fn passphrase_change_rewraps_keys_and_preserves_records() {
    let mut store = UnlockedStore::create(PASS).unwrap();
    store.put("entry".into(), entry(), false).unwrap();
    let old = store.seal().unwrap();
    let new_pass = "another long passphrase for testing";
    store.change_passphrase(new_pass).unwrap();
    let new = store.seal().unwrap();
    assert!(UnlockedStore::open(&new, PASS).is_err());
    assert_eq!(
        UnlockedStore::open(&new, new_pass)
            .unwrap()
            .get("entry")
            .unwrap()
            .password,
        "distinctive-secret-value"
    );
    assert!(UnlockedStore::open(&old, PASS).is_ok());
    assert!(matches!(
        store.change_passphrase("short"),
        Err(Error::WeakPassphrase)
    ));
}

#[test]
fn persistence_is_exclusive_and_create_does_not_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.petika");
    let file = StoreFile::lock(&path).unwrap();
    assert!(matches!(StoreFile::lock(&path), Err(Error::Busy)));
    let mut store = UnlockedStore::create(PASS).unwrap();
    file.save(&mut store, true).unwrap();
    let original = std::fs::read(&path).unwrap();
    assert!(matches!(
        file.save(&mut store, true),
        Err(Error::AlreadyExists)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    store.put("entry".into(), entry(), false).unwrap();
    file.save(&mut store, false).unwrap();
    drop(file);
    let file = StoreFile::lock(&path).unwrap();
    assert_eq!(
        file.open(PASS).unwrap().get("entry").unwrap().username,
        "alice@example.test"
    );
}

#[test]
fn generated_passwords_have_requested_size_and_bounds() {
    for length in [16, 24, 64, 256] {
        let first = generate_password(length).unwrap();
        let second = generate_password(length).unwrap();
        assert_eq!(first.len(), length);
        assert!(first.is_ascii());
        assert_ne!(*first, *second);
    }
    assert!(generate_password(0).is_err());
    assert!(generate_password(257).is_err());
}

#[cfg(unix)]
#[test]
fn reject_symlinks_and_open_permissions() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    std::fs::write(&target, "test").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(StoreFile::lock(&target), Err(Error::Permissions)));
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path().join("link");
    symlink(&target, &link).unwrap();
    assert!(matches!(StoreFile::lock(&link), Err(Error::Permissions)));
}

#[test]
fn hybrid_recovery_rewrap_and_downgrade_rejection() {
    use petika_core::EncryptionMode;
    let mut store =
        UnlockedStore::create_with_mode(PASS, EncryptionMode::HybridPostQuantum).unwrap();
    store
        .put("private/folder/entry".into(), entry(), false)
        .unwrap();
    let original = store.seal().unwrap();
    let mut recovered = UnlockedStore::open(&original, PASS).unwrap();
    assert_eq!(
        recovered.get("private/folder/entry").unwrap().password,
        "distinctive-secret-value"
    );
    assert_eq!(recovered.encryption(), EncryptionMode::HybridPostQuantum);
    let changed_pass = "another long synthetic passphrase";
    recovered.change_passphrase(changed_pass).unwrap();
    let changed = recovered.seal().unwrap();
    assert!(UnlockedStore::open(&changed, PASS).is_err());
    assert!(UnlockedStore::open(&changed, changed_pass).is_ok());
    let mut tampered: Value = serde_json::from_slice(&original).unwrap();
    tampered["kem_ciphertext"][0] =
        Value::from(tampered["kem_ciphertext"][0].as_u64().unwrap() ^ 1);
    assert!(UnlockedStore::open(&serde_json::to_vec(&tampered).unwrap(), PASS).is_err());
    tampered["encryption"] = Value::from("standard");
    tampered["kem_ciphertext"] = serde_json::json!([]);
    assert!(UnlockedStore::open(&serde_json::to_vec(&tampered).unwrap(), PASS).is_err());
}
