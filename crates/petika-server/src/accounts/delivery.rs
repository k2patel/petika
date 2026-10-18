//! Account-then-collection locking, with one journaled snapshot/grant transaction.
use super::{
    Accounts, MAX_COUNTER,
    keys::{KeyError, valid_id},
};
use crate::{DeliveryReceipt, DeliveryState, Snapshot};
use petika_core::{StoreFile, envelope_metadata, identity::KeyPackage};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, KeyError>;
#[derive(Debug)]
pub enum DeliveryOperation {
    Access,
    AccessPage(String),
    Packages,
    Publish,
    Migrate,
    Rotate,
    Snapshot,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    expected_snapshot_revision: u64,
    expected_key_epoch: u64,
    expected_membership_generation: u64,
    packages: Vec<KeyPackage>,
    #[serde(default)]
    encrypted_snapshot: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackagePublication {
    expected_snapshot_revision: u64,
    expected_key_epoch: u64,
    expected_membership_generation: u64,
    packages: Vec<KeyPackage>,
}
impl Accounts {
    pub fn delivery_operation(
        &mut self,
        token: &str,
        collection: &str,
        operation: DeliveryOperation,
        body: &[u8],
    ) -> Result<Value> {
        let limit = if matches!(operation, DeliveryOperation::Publish) {
            2 * 1024 * 1024
        } else {
            20 * 1024 * 1024
        };
        if body.len() > limit {
            return Err(KeyError::TooLarge);
        }
        if !valid_id(collection) {
            return Err(KeyError::NotFound);
        }
        let (_account_lock, db, user) = self.key_context(token)?;
        let group = db
            .groups
            .iter()
            .find(|g| g.id == collection)
            .ok_or(KeyError::NotFound)?;
        let member = group
            .members
            .iter()
            .find(|m| m.user_id == user.id)
            .ok_or(KeyError::Forbidden)?;
        let path = self
            .path
            .parent()
            .ok_or(KeyError::Unavailable)?
            .join("collections")
            .join(collection)
            .join("snapshot.json");
        let file = StoreFile::lock(&path).map_err(|_| KeyError::Unavailable)?;
        if !file.exists() {
            return Err(KeyError::NotFound);
        }
        let original_bytes = file.read().map_err(|_| KeyError::Unavailable)?;
        let mut saved: Snapshot =
            serde_json::from_slice(&original_bytes).map_err(|_| KeyError::Unavailable)?;
        let (mode, context) =
            envelope_metadata(saved.encrypted.as_bytes()).map_err(|_| KeyError::Unavailable)?;
        let epoch = context.as_ref().map_or(0, |c| c.key_epoch);
        let rotation_required = group.rotation_required
            && saved
                .delivery
                .as_ref()
                .is_none_or(|d| d.rotation_generation < group.membership_generation);
        let current_package = |id: &str| {
            let identity = db.identities.get(id)?;
            saved.delivery.as_ref()?.packages.iter().find(|p| {
                p.recipient_user_id == id
                    && p.recipient_fingerprint == identity.public_identity.fingerprint
                    && p.key_epoch == epoch
                    && db
                        .identities
                        .get(&p.issuer_user_id)
                        .is_some_and(|i| i.public_identity.fingerprint == p.issuer_fingerprint)
            })
        };
        match &operation {
            DeliveryOperation::Access | DeliveryOperation::AccessPage(_) => {
                let roster: Vec<Value> = group.members.iter().filter(|m| member.edit || m.user_id == user.id).filter(|m| db.users.iter().any(|u| u.id == m.user_id && !u.disabled)).map(|m| json!({"user_id": m.user_id, "identity_version": db.identities.get(&m.user_id).map_or(0, |s| s.public_identity.identity_version), "state": if !db.identities.contains_key(&m.user_id) { "not-enrolled" } else if current_package(&m.user_id).is_some() { "package-available" } else { "missing-package" }})).collect();
                let cursor_for = |offset: usize| {
                    let binding = format!(
                        "petika:delivery-page:v1:{}:{}:{}:{}:{}",
                        user.id, collection, saved.revision, group.membership_generation, offset
                    );
                    let digest: String = Sha256::digest(binding.as_bytes())
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    format!("{offset:016x}{digest}")
                };
                let offset = if let DeliveryOperation::AccessPage(cursor) = &operation {
                    if cursor.len() != 80 || !cursor.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(KeyError::Conflict);
                    }
                    let offset =
                        usize::from_str_radix(&cursor[..16], 16).map_err(|_| KeyError::Conflict)?;
                    if cursor_for(offset) != *cursor || offset >= roster.len() {
                        return Err(KeyError::Conflict);
                    }
                    offset
                } else {
                    0
                };
                let end = offset.saturating_add(100).min(roster.len());
                let next_cursor = if end < roster.len() {
                    cursor_for(end)
                } else {
                    String::new()
                };
                let roster = &roster[offset..end];
                return Ok(
                    json!({"snapshot_revision":saved.revision,"key_epoch":epoch,"membership_generation":group.membership_generation,"rotation_required":rotation_required,"recipient_enabled":epoch > 0,"deliveries":roster,"next_cursor":next_cursor}),
                );
            }
            DeliveryOperation::Packages => {
                let packages: Vec<_> = current_package(&user.id).into_iter().collect();
                return Ok(json!({"packages":packages,"next_cursor":""}));
            }
            _ => {}
        }
        if !member.edit {
            return Err(KeyError::Forbidden);
        }
        let mut request: Publication = if matches!(operation, DeliveryOperation::Publish) {
            let p: PackagePublication =
                serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
            Publication {
                expected_snapshot_revision: p.expected_snapshot_revision,
                expected_key_epoch: p.expected_key_epoch,
                expected_membership_generation: p.expected_membership_generation,
                packages: p.packages,
                encrypted_snapshot: None,
            }
        } else {
            serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?
        };
        if request.packages.len() > 100 || request.expected_snapshot_revision > MAX_COUNTER {
            return Err(KeyError::TooLarge);
        }
        request
            .packages
            .sort_by(|a, b| a.package_id.cmp(&b.package_id));
        let mut digest = Sha256::new();
        digest.update(format!("{operation:?}"));
        digest.update(serde_json::to_vec(&request).map_err(|_| KeyError::Invalid)?);
        let digest: String = digest
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let receipt = saved
            .delivery
            .as_ref()
            .and_then(|d| {
                d.transactions
                    .iter()
                    .find(|r| r.digest == digest && r.key_epoch == epoch)
            })
            .cloned();
        let replay = receipt.is_some();
        if !replay
            && (request.expected_membership_generation != group.membership_generation
                || request.expected_key_epoch != epoch)
        {
            return Err(KeyError::Conflict);
        }
        let migrating = matches!(operation, DeliveryOperation::Migrate);
        let rotating = matches!(operation, DeliveryOperation::Rotate);
        let snapshot_update = matches!(operation, DeliveryOperation::Snapshot);
        if rotation_required && !rotating && !migrating && !replay {
            return Err(KeyError::Conflict);
        }
        if !replay && (migrating && epoch != 0 || !migrating && epoch == 0) {
            return Err(KeyError::Conflict);
        }
        let target_epoch = if (migrating || rotating) && !replay {
            epoch
                .checked_add(1)
                .filter(|e| *e <= MAX_COUNTER)
                .ok_or(KeyError::Conflict)?
        } else {
            epoch
        };
        let issuer = &db
            .identities
            .get(&user.id)
            .ok_or(KeyError::Conflict)?
            .public_identity;
        let mut ids = std::collections::BTreeSet::new();
        let mut recipients = std::collections::BTreeSet::new();
        for package in &request.packages {
            if serde_json::to_vec(package)
                .map_err(|_| KeyError::Invalid)?
                .len()
                > 16 * 1024
            {
                return Err(KeyError::TooLarge);
            }
            if !ids.insert(&package.package_id) || !recipients.insert(&package.recipient_user_id) {
                return Err(KeyError::Invalid);
            }
            if !group
                .members
                .iter()
                .any(|m| m.user_id == package.recipient_user_id)
                || !db
                    .users
                    .iter()
                    .any(|u| u.id == package.recipient_user_id && !u.disabled)
            {
                return Err(KeyError::Forbidden);
            }
            let recipient = &db
                .identities
                .get(&package.recipient_user_id)
                .ok_or(KeyError::Conflict)?
                .public_identity;
            package
                .validate(issuer, recipient)
                .map_err(|_| KeyError::Invalid)?;
            if package.collection_id != collection
                || package.deployment_id != db.deployment_id
                || package.collection_mode != mode
                || package.key_epoch != target_epoch
                || package.membership_generation != request.expected_membership_generation
            {
                return Err(KeyError::Conflict);
            }
        }
        if snapshot_update && !request.packages.is_empty()
            || !snapshot_update && request.packages.is_empty()
        {
            return Err(KeyError::Invalid);
        }
        if (migrating || rotating) && !recipients.contains(&user.id) {
            return Err(KeyError::Invalid);
        }
        if migrating || rotating || snapshot_update {
            let encrypted = request
                .encrypted_snapshot
                .as_ref()
                .ok_or(KeyError::Invalid)?;
            let (new_mode, new_context) =
                envelope_metadata(encrypted.as_bytes()).map_err(|_| KeyError::Invalid)?;
            let binding = new_context.ok_or(KeyError::Invalid)?;
            if new_mode != mode
                || binding.deployment_id != db.deployment_id
                || binding.collection_id != collection
                || binding.key_epoch != target_epoch
            {
                return Err(KeyError::Invalid);
            }
        } else if request.encrypted_snapshot.is_some() {
            return Err(KeyError::Invalid);
        }
        if let Some(receipt) = receipt {
            return Ok(
                json!({"snapshot_revision":receipt.revision,"key_epoch":receipt.key_epoch,"membership_generation":receipt.membership_generation}),
            );
        }
        if let Some(delivery) = &saved.delivery {
            if delivery.transactions.len() >= 4096 && !rotating {
                return Err(KeyError::Conflict);
            }
            if request.packages.iter().any(|p| {
                delivery
                    .transactions
                    .iter()
                    .any(|r| r.package_ids.contains(&p.package_id))
            }) {
                return Err(KeyError::Conflict);
            }
        }
        if saved.revision != request.expected_snapshot_revision {
            return Err(KeyError::Conflict);
        }
        if let Some(encrypted) = request.encrypted_snapshot {
            saved.encrypted = encrypted;
        }
        let mut delivery = if migrating || rotating {
            DeliveryState {
                packages: vec![],
                rotation_generation: if rotating {
                    group.membership_generation
                } else {
                    0
                },
                transactions: Vec::new(),
            }
        } else {
            saved.delivery.take().ok_or(KeyError::Conflict)?
        };
        let package_ids = request
            .packages
            .iter()
            .map(|p| p.package_id.clone())
            .collect();
        for package in request.packages {
            delivery
                .packages
                .retain(|p| p.recipient_user_id != package.recipient_user_id);
            delivery.packages.push(package);
        }
        // Discard revoked/obsolete grants from active state; journal history remains encrypted.
        delivery.packages.retain(|p| {
            group
                .members
                .iter()
                .any(|m| m.user_id == p.recipient_user_id)
                && db
                    .users
                    .iter()
                    .any(|u| u.id == p.recipient_user_id && !u.disabled)
                && db
                    .identities
                    .get(&p.recipient_user_id)
                    .is_some_and(|i| i.public_identity.fingerprint == p.recipient_fingerprint)
        });
        let next_revision = saved
            .revision
            .checked_add(1)
            .filter(|r| *r <= MAX_COUNTER)
            .ok_or(KeyError::Conflict)?;
        delivery.transactions.push(DeliveryReceipt {
            digest,
            revision: next_revision,
            key_epoch: target_epoch,
            membership_generation: group.membership_generation,
            package_ids,
        });
        saved.schema_version = 2;
        saved.delivery = Some(delivery);
        saved.revision = next_revision;
        let bytes = serde_json::to_vec(&saved).map_err(|_| KeyError::Unavailable)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(KeyError::TooLarge);
        }
        if migrating {
            let backup = StoreFile::lock(path.with_file_name("snapshot.v1.backup.json"))
                .map_err(|_| KeyError::Unavailable)?;
            if backup.exists() {
                if backup.read().map_err(|_| KeyError::Unavailable)? != original_bytes {
                    return Err(KeyError::Conflict);
                }
            } else {
                backup
                    .write(&original_bytes, true)
                    .map_err(|_| KeyError::Unavailable)?;
            }
        }
        let journal = StoreFile::lock(
            path.parent()
                .ok_or(KeyError::Unavailable)?
                .join("revisions")
                .join(format!("{:020}.json", saved.revision)),
        )
        .map_err(|_| KeyError::Unavailable)?;
        journal
            .write(&bytes, false)
            .map_err(|_| KeyError::Unavailable)?;
        file.write(&bytes, false)
            .map_err(|_| KeyError::Unavailable)?;
        Ok(
            json!({"snapshot_revision":saved.revision,"key_epoch":target_epoch,"membership_generation":group.membership_generation}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{Membership, User};
    #[test]
    fn delivery_pages_are_bounded_and_bound_to_caller_and_revision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.json");
        let mut accounts = Accounts::new(path.clone());
        let owner = accounts
            .create_user(
                "owner",
                "Owner",
                "synthetic account password".into(),
                true,
                true,
            )
            .unwrap();
        let reader = accounts
            .create_user(
                "reader",
                "Reader",
                "synthetic account password".into(),
                false,
                false,
            )
            .unwrap();
        let group = accounts
            .save_group(
                None,
                "Group",
                vec![
                    Membership {
                        user_id: owner.id.clone(),
                        edit: true,
                    },
                    Membership {
                        user_id: reader.id.clone(),
                        edit: false,
                    },
                ],
            )
            .unwrap();
        {
            let file = StoreFile::lock(&path).unwrap();
            let mut db = Accounts::load(&file).unwrap();
            // Synthetic directory rows; these users are never authenticated in this test.
            for n in 0..100 {
                let id = format!("{n:064x}");
                db.users.push(User {
                    id: id.clone(),
                    username: format!("fixture{n}"),
                    name: "Fixture".into(),
                    admin: false,
                    disabled: false,
                    password_hash: "unused test fixture".into(),
                    appearance: "system".into(),
                    autofill_origins: Vec::new(),
                });
                db.groups[0].members.push(Membership {
                    user_id: id,
                    edit: false,
                });
            }
            file.write(&serde_json::to_vec(&db).unwrap(), false)
                .unwrap();
        }
        let (owner_token, _) = accounts
            .login("owner", "synthetic account password".into())
            .unwrap();
        let (reader_token, _) = accounts
            .login("reader", "synthetic account password".into())
            .unwrap();
        let repository = crate::Repository::new(
            dir.path()
                .join("collections")
                .join(&group.id)
                .join("snapshot.json"),
        );
        let mut store =
            petika_core::UnlockedStore::create("synthetic recovery passphrase").unwrap();
        repository
            .update(0, String::from_utf8(store.seal().unwrap()).unwrap())
            .unwrap();
        let first = accounts
            .delivery_operation(&owner_token, &group.id, DeliveryOperation::Access, b"")
            .unwrap();
        assert_eq!(first["deliveries"].as_array().unwrap().len(), 100);
        let cursor = first["next_cursor"].as_str().unwrap().to_owned();
        let second = accounts
            .delivery_operation(
                &owner_token,
                &group.id,
                DeliveryOperation::AccessPage(cursor.clone()),
                b"",
            )
            .unwrap();
        assert_eq!(second["deliveries"].as_array().unwrap().len(), 2);
        assert_eq!(second["next_cursor"], "");
        assert_eq!(
            accounts.delivery_operation(
                &reader_token,
                &group.id,
                DeliveryOperation::AccessPage(cursor.clone()),
                b""
            ),
            Err(KeyError::Conflict)
        );
        repository
            .update(1, String::from_utf8(store.seal().unwrap()).unwrap())
            .unwrap();
        assert_eq!(
            accounts.delivery_operation(
                &owner_token,
                &group.id,
                DeliveryOperation::AccessPage(cursor),
                b""
            ),
            Err(KeyError::Conflict)
        );
        accounts.set_disabled(&owner, &reader.id, true).unwrap();
        assert_eq!(
            accounts.delivery_operation(&reader_token, &group.id, DeliveryOperation::Packages, b""),
            Err(KeyError::Unauthenticated)
        );
    }
}
