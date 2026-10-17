use petika_core::{
    CollectionContext, EncryptionMode, UnlockedStore,
    identity::{KeyPackage, UnlockedIdentity},
};
#[test]
fn independently_enrolled_recipient_unlocks_both_modes_with_verified_packages() {
    let mut alice = UnlockedIdentity::generate(&"a".repeat(64), &"b".repeat(64), 1).unwrap();
    let mut bob = UnlockedIdentity::generate(&"a".repeat(64), &"c".repeat(64), 1).unwrap();
    let ap = alice.public_identity().clone();
    let bp = bob.public_identity().clone();
    let context = CollectionContext {
        deployment_id: "a".repeat(64),
        collection_id: "d".repeat(64),
        key_epoch: 1,
    };
    for mode in [EncryptionMode::Standard, EncryptionMode::HybridPostQuantum] {
        let mut store = UnlockedStore::create_with_mode("owner recovery passphrase", mode).unwrap();
        store
            .bind_collection(context.clone(), "owner recovery passphrase")
            .unwrap();
        let bytes = store.seal().unwrap();
        if mode == EncryptionMode::Standard {
            assert!(alice.create_key_package(&store, &bp, 1).is_err());
            alice
                .verify_contact(&bp.user_id, &bp, &bp.fingerprint, None)
                .unwrap();
        }
        let package = alice.create_key_package(&store, &bp, 1).unwrap();
        if mode == EncryptionMode::Standard {
            assert!(
                bob.open_key_package(&package, &ap, &bytes, &context, mode)
                    .is_err()
            );
            bob.verify_contact(&ap.user_id, &ap, &ap.fingerprint, None)
                .unwrap();
        }
        let restored = bob
            .open_key_package(&package, &ap, &bytes, &context, mode)
            .unwrap();
        assert_eq!(restored.context(), Some(&context));
        let json = serde_json::to_vec(&package).unwrap();
        assert_eq!(KeyPackage::parse(&json).unwrap(), package);
        // Every authenticated field is covered by the issuer signature.
        let value = serde_json::to_value(&package).unwrap();
        for (field, original) in value.as_object().unwrap() {
            let mut mutated = value.clone();
            mutated[field] = if original.is_number() {
                (original.as_u64().unwrap() + 1).into()
            } else {
                format!("{}x", original.as_str().unwrap()).into()
            };
            if let Ok(changed) = serde_json::from_value::<KeyPackage>(mutated) {
                assert!(
                    bob.open_key_package(&changed, &ap, &bytes, &context, mode)
                        .is_err(),
                    "{field}"
                );
            }
        }
        let mut rotated = restored.rotated("new recovery passphrase").unwrap();
        assert!(
            bob.open_key_package(
                &package,
                &ap,
                &rotated.seal().unwrap(),
                rotated.context().unwrap(),
                mode
            )
            .is_err()
        );
        let mut stranger = UnlockedIdentity::generate(&"a".repeat(64), &"e".repeat(64), 1).unwrap();
        assert!(
            stranger
                .open_key_package(&package, &ap, &bytes, &context, mode)
                .is_err()
        );
    }
}

#[test]
fn package_parser_rejects_oversize_unknown_duplicate_and_noncanonical_fields() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/key-packages-v1.json")).unwrap();
    let package = &fixtures[0]["package"];
    let encoded = serde_json::to_string(package).unwrap();
    assert!(KeyPackage::parse(encoded.as_bytes()).is_ok());
    assert!(KeyPackage::parse(&vec![b' '; 16 * 1024 + 1]).is_err());
    let duplicate = encoded.replacen('{', "{\"package_version\":1,", 1);
    assert!(KeyPackage::parse(duplicate.as_bytes()).is_err());
    let mut unknown = package.clone();
    unknown["future"] = true.into();
    assert!(KeyPackage::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let mut unpadded = package.clone();
    unpadded["enc"] = unpadded["enc"]
        .as_str()
        .unwrap()
        .trim_end_matches('=')
        .into();
    assert!(KeyPackage::parse(&serde_json::to_vec(&unpadded).unwrap()).is_err());
}
