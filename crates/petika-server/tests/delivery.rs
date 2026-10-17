use petika_core::{CollectionContext, EncryptionMode, UnlockedStore, identity::UnlockedIdentity};
use petika_server::{
    Repository, Update,
    accounts::{Accounts, DeliveryOperation as Op, KeyError, KeyOperation, Membership},
};
use serde_json::{Value, json};
const PASSWORD: &str = "synthetic account password";
fn call(a: &mut Accounts, token: &str, id: &str, op: Op, body: &Value) -> Result<Value, KeyError> {
    let schema = match &op {
        Op::Access | Op::AccessPage(_) => "AccessState",
        Op::Packages => "PackagePage",
        _ => "CommitResult",
    };
    let input_schema = match &op {
        Op::Migrate => Some("MigrationRequest"),
        Op::Rotate => Some("RotationRequest"),
        Op::Publish => Some("PublishRequest"),
        Op::Snapshot => Some("RecipientSnapshotRequest"),
        _ => None,
    };
    let result = a.delivery_operation(token, id, op, &serde_json::to_vec(body).unwrap());
    if let (Ok(path), Ok(value)) = (std::env::var("PETIKA_CONTRACT_CAPTURE"), &result) {
        let mut fixtures: Vec<Value> = std::fs::read(&path)
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap())
            .unwrap_or_default();
        fixtures.push(json!({"name":format!("runtime response {}",fixtures.len()),"schema":schema,"value":value,"valid":true}));
        if let Some(schema) = input_schema {
            fixtures.push(json!({"name":format!("runtime request {}",fixtures.len()),"schema":schema,"value":body,"valid":true}));
        }
        std::fs::write(path, serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
    }
    result
}
fn enroll(a: &mut Accounts, token: &str, deployment: &str, user: &str) -> UnlockedIdentity {
    let identity = UnlockedIdentity::generate(deployment, user, 1).unwrap();
    let backup: Value = serde_json::from_slice(&identity.seal(PASSWORD).unwrap()).unwrap();
    a.key_operation(token, KeyOperation::Enroll, &serde_json::to_vec(&json!({"expected_bundle_revision":0,"current_password":PASSWORD,"public_identity":backup["public_identity"],"encrypted_bundle":backup["encrypted_bundle"]})).unwrap()).unwrap();
    identity
}
#[test]
fn migration_delivery_permissions_retry_rotation_and_restart() {
    for mode in [EncryptionMode::Standard, EncryptionMode::HybridPostQuantum] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.json");
        let mut a = Accounts::new(path.clone());
        a.migrate().unwrap();
        let owner = a
            .create_user("owner", "Owner", PASSWORD.into(), true, true)
            .unwrap();
        let member = a
            .create_user("member", "Member", PASSWORD.into(), false, false)
            .unwrap();
        let outsider = a
            .create_user("outsider", "Outsider", PASSWORD.into(), true, false)
            .unwrap();
        let (at, _) = a.login("owner", PASSWORD.into()).unwrap();
        let (bt, _) = a.login("member", PASSWORD.into()).unwrap();
        let (ct, _) = a.login("outsider", PASSWORD.into()).unwrap();
        let deployment =
            a.key_operation(&at, KeyOperation::Deployment, b"").unwrap()["deployment_id"]
                .as_str()
                .unwrap()
                .to_owned();
        let group = a
            .save_group(
                None,
                "Team",
                vec![
                    Membership {
                        user_id: owner.id.clone(),
                        edit: true,
                    },
                    Membership {
                        user_id: member.id.clone(),
                        edit: false,
                    },
                ],
            )
            .unwrap();
        let mut alice = enroll(&mut a, &at, &deployment, &owner.id);
        let mut bob = enroll(&mut a, &bt, &deployment, &member.id);
        let ap = alice.public_identity().clone();
        let bp = bob.public_identity().clone();
        alice
            .verify_contact(&bp.user_id, &bp, &bp.fingerprint, None)
            .unwrap();
        bob.verify_contact(&ap.user_id, &ap, &ap.fingerprint, None)
            .unwrap();
        let repository = Repository::new(
            dir.path()
                .join("collections")
                .join(&group.id)
                .join("snapshot.json"),
        );
        let mut store = UnlockedStore::create_with_mode(PASSWORD, mode).unwrap();
        let legacy = String::from_utf8(store.seal().unwrap()).unwrap();
        assert!(matches!(
            repository.update(0, legacy.clone()).unwrap(),
            Update::Saved(1)
        ));
        let access = call(&mut a, &at, &group.id, Op::Access, &Value::Null).unwrap();
        assert_eq!(
            call(&mut a, &ct, &group.id, Op::Access, &Value::Null),
            Err(KeyError::Forbidden)
        );
        let context = CollectionContext {
            deployment_id: deployment.clone(),
            collection_id: group.id.clone(),
            key_epoch: 1,
        };
        store.bind_collection(context.clone(), PASSWORD).unwrap();
        let bytes = store.seal().unwrap();
        let generation = access["membership_generation"].as_u64().unwrap();
        let own = alice.create_key_package(&store, &ap, generation).unwrap();
        let grant = alice.create_key_package(&store, &bp, generation).unwrap();
        let body = json!({"expected_snapshot_revision":1,"expected_key_epoch":0,"expected_membership_generation":generation,"packages":[own, grant],"encrypted_snapshot":String::from_utf8(bytes.clone()).unwrap()});
        assert_eq!(
            call(&mut a, &bt, &group.id, Op::Migrate, &body),
            Err(KeyError::Forbidden)
        );
        // Journal failure must not acknowledge or replace the current snapshot.
        let journal_path = dir
            .path()
            .join("collections")
            .join(&group.id)
            .join("revisions")
            .join("00000000000000000002.json");
        let held = petika_core::StoreFile::lock(&journal_path).unwrap();
        assert_eq!(
            call(&mut a, &at, &group.id, Op::Migrate, &body),
            Err(KeyError::Unavailable)
        );
        assert_eq!(repository.read().unwrap().unwrap().revision, 1);
        // An uncommitted tail is ignored and safely replaced on retry.
        held.write(b"uncommitted tail", true).unwrap();
        drop(held);
        let committed = call(&mut a, &at, &group.id, Op::Migrate, &body).unwrap();
        assert_eq!(committed["snapshot_revision"], 2);
        let backup: petika_server::Snapshot = serde_json::from_slice(
            &std::fs::read(
                dir.path()
                    .join("collections")
                    .join(&group.id)
                    .join("snapshot.v1.backup.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(backup.revision, 1);
        assert_eq!(backup.encrypted, legacy);

        assert_eq!(
            call(&mut a, &at, &group.id, Op::Migrate, &body).unwrap(),
            committed
        );
        assert!(repository.update(2, legacy).is_err());
        let formatted = serde_json::to_vec_pretty(&body).unwrap();
        assert_eq!(
            a.delivery_operation(&at, &group.id, Op::Migrate, &formatted)
                .unwrap(),
            committed
        );
        let mut invalid = body.clone();
        invalid["packages"][0]["key_epoch"] = 9.into();
        assert!(call(&mut a, &at, &group.id, Op::Migrate, &invalid).is_err());
        assert_eq!(repository.read().unwrap().unwrap().revision, 2);
        let delivered = call(&mut a, &bt, &group.id, Op::Packages, &Value::Null).unwrap();
        assert_eq!(delivered["packages"].as_array().unwrap().len(), 1);
        let package = serde_json::from_value(delivered["packages"][0].clone()).unwrap();
        bob.open_key_package(&package, &ap, &bytes, &context, mode)
            .unwrap();
        a.save_group(
            Some(&group.id),
            "Team",
            vec![Membership {
                user_id: owner.id.clone(),
                edit: true,
            }],
        )
        .unwrap();
        assert_eq!(
            call(&mut a, &bt, &group.id, Op::Packages, &Value::Null),
            Err(KeyError::Forbidden)
        );
        let access = call(&mut a, &at, &group.id, Op::Access, &Value::Null).unwrap();
        assert_eq!(access["rotation_required"], true);
        let generation = access["membership_generation"].as_u64().unwrap();
        let mut rotated = store.rotated("new recovery passphrase").unwrap();
        let bytes = rotated.seal().unwrap();
        let own = alice.create_key_package(&rotated, &ap, generation).unwrap();
        let rotation = json!({"expected_snapshot_revision":2,"expected_key_epoch":1,"expected_membership_generation":generation,"packages":[own],"encrypted_snapshot":String::from_utf8(bytes.clone()).unwrap()});
        call(&mut a, &at, &group.id, Op::Rotate, &rotation).unwrap();
        assert!(
            bob.open_key_package(&package, &ap, &bytes, rotated.context().unwrap(), mode)
                .is_err()
        );
        assert_eq!(
            call(&mut a, &at, &group.id, Op::Access, &Value::Null).unwrap()["rotation_required"],
            false
        );
        drop(a);
        let mut restarted = Accounts::new(path);
        let (token, _) = restarted.login("owner", PASSWORD.into()).unwrap();
        assert_eq!(
            call(&mut restarted, &token, &group.id, Op::Rotate, &rotation).unwrap()["snapshot_revision"],
            3
        );
        assert_eq!(repository.read().unwrap().unwrap().revision, 3);
        let replacement_grant = alice.create_key_package(&rotated, &ap, generation).unwrap();
        let publish = json!({"expected_snapshot_revision":3,"expected_key_epoch":2,"expected_membership_generation":generation,"packages":[replacement_grant]});
        assert_eq!(
            call(&mut restarted, &token, &group.id, Op::Publish, &publish).unwrap()["snapshot_revision"],
            4
        );
        // A retry of an earlier transaction still returns its original receipt.
        assert_eq!(
            call(&mut restarted, &token, &group.id, Op::Rotate, &rotation).unwrap()["snapshot_revision"],
            3
        );
        let mut snapshot = json!({"expected_snapshot_revision":3,"expected_key_epoch":2,"expected_membership_generation":generation,"packages":[],"encrypted_snapshot":String::from_utf8(bytes.clone()).unwrap()});
        assert_eq!(
            call(&mut restarted, &token, &group.id, Op::Snapshot, &snapshot),
            Err(KeyError::Conflict)
        );
        snapshot["expected_snapshot_revision"] = 4.into();
        assert_eq!(
            call(&mut restarted, &token, &group.id, Op::Snapshot, &snapshot).unwrap()["snapshot_revision"],
            5
        );
        snapshot["expected_key_epoch"] = 1.into();
        assert_eq!(
            call(&mut restarted, &token, &group.id, Op::Snapshot, &snapshot),
            Err(KeyError::Conflict)
        );
        let mirror = dir.path().join("mirror");
        petika_server::mirror_once(&repository, &mirror).unwrap();
        let mirrored = std::process::Command::new("git")
            .arg("-C")
            .arg(mirror.join("repository.git"))
            .args(["show", "HEAD:snapshot.json"])
            .output()
            .unwrap();
        assert!(mirrored.status.success());
        let mirror_value: Value = serde_json::from_slice(&mirrored.stdout).unwrap();
        assert!(mirror_value.get("delivery").is_none());
        assert!(
            !String::from_utf8(mirrored.stdout)
                .unwrap()
                .contains("recipient_fingerprint")
        );
        assert_ne!(outsider.id, owner.id);
    }
}
