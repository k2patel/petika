use petika_core::{CollectionContext, EncryptionMode, Entry, UnlockedStore, validate_envelope};

const OLD: &str = "original recovery passphrase";
const NEW: &str = "replacement recovery passphrase";
fn context() -> CollectionContext {
    CollectionContext {
        deployment_id: "a".repeat(64),
        collection_id: "b".repeat(64),
        key_epoch: 1,
    }
}

#[test]
fn migration_binding_rotation_and_recovery_in_both_modes() {
    for mode in [EncryptionMode::Standard, EncryptionMode::HybridPostQuantum] {
        let mut store = UnlockedStore::create_with_mode(OLD, mode).unwrap();
        store
            .put(
                "example".into(),
                Entry {
                    username: "user".into(),
                    password: "secret".into(),
                    url: "".into(),
                    notes: "".into(),
                    otp: None,
                },
                false,
            )
            .unwrap();
        let legacy = store.seal().unwrap();
        store.bind_collection(context(), OLD).unwrap();
        let bound = store.seal().unwrap();
        assert!(
            UnlockedStore::open(&legacy, OLD)
                .unwrap()
                .context()
                .is_none()
        );
        let opened = UnlockedStore::open(&bound, OLD).unwrap();
        assert_eq!(opened.context(), Some(&context()));
        assert_eq!(opened.get("example").unwrap().password, "secret");
        for field in ["deployment_id", "collection_id", "key_epoch"] {
            let mut changed: serde_json::Value = serde_json::from_slice(&bound).unwrap();
            changed["context"][field] = if field == "key_epoch" {
                2.into()
            } else {
                "c".repeat(64).into()
            };
            let changed = serde_json::to_vec(&changed).unwrap();
            validate_envelope(&changed).unwrap();
            assert!(UnlockedStore::open(&changed, OLD).is_err());
        }
        let mut rotated = opened.rotated(NEW).unwrap();
        let fresh = rotated.seal().unwrap();
        assert!(UnlockedStore::open(&fresh, OLD).is_err());
        assert_eq!(
            UnlockedStore::open(&fresh, NEW)
                .unwrap()
                .context()
                .unwrap()
                .key_epoch,
            2
        );
        assert_eq!(rotated.encryption(), mode);
        assert_eq!(rotated.get("example").unwrap().password, "secret");
        // Even a retained old wrapper cannot recover the new data key/seed.
        let old: serde_json::Value = serde_json::from_slice(&bound).unwrap();
        let mut attack: serde_json::Value = serde_json::from_slice(&fresh).unwrap();
        for field in ["context", "salt", "key_nonce", "wrapped_key"] {
            attack[field] = old[field].clone();
        }
        assert!(UnlockedStore::open(&serde_json::to_vec(&attack).unwrap(), OLD).is_err());
        assert!(UnlockedStore::open(&bound, OLD).is_ok());
    }
}

#[test]
fn malformed_context_and_downgrade_are_rejected() {
    let mut store = UnlockedStore::create(OLD).unwrap();
    let mut invalid = context();
    invalid.key_epoch = 0;
    assert!(store.bind_collection(invalid, OLD).is_err());
    assert!(store.context().is_none());
    assert!(store.bind_collection(context(), "short").is_err());
    assert!(store.context().is_none());
    store.bind_collection(context(), OLD).unwrap();
    assert!(store.bind_collection(context(), OLD).is_err());
    let bytes = store.seal().unwrap();
    for (field, value) in [("version", 1.into()), ("context", serde_json::Value::Null)] {
        let mut altered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        altered[field] = value;
        assert!(validate_envelope(&serde_json::to_vec(&altered).unwrap()).is_err());
    }
}
