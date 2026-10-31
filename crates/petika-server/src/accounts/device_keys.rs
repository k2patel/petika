//! Opt-in, account-owned device roster publication. No collection or session cutover.
use super::{Accounts, KeyError, keys::valid_id};
use petika_core::{
    Error, StoreFile,
    device_keys::{DeviceRoster, DeviceRosterJournal, MAX_ROSTER_BYTES, TrustedDeviceRoster},
    identity::{DeviceAuthorityBootstrap, MAX_DEVICE_BOOTSTRAP_BYTES},
};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub const MAX_DEVICE_KEY_BODY: usize = MAX_ROSTER_BYTES + 16 * 1024;
type Result<T> = std::result::Result<T, KeyError>;

pub enum DeviceKeyOperation {
    Own,
    Initialize,
    Publish,
    Receipt(String),
    History(String),
}

fn password<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Initialize {
    #[serde(deserialize_with = "password")]
    current_password: Zeroizing<String>,
    bootstrap: DeviceAuthorityBootstrap,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Publish {
    #[serde(deserialize_with = "password")]
    current_password: Zeroizing<String>,
    operation_id: String,
    expected_parent: String,
    roster: DeviceRoster,
}
fn scoped(bootstrap: &DeviceAuthorityBootstrap, deployment: &str, user: &str) -> Result<()> {
    if bootstrap.legacy_identity.deployment_id != deployment
        || bootstrap.legacy_identity.user_id != user
    {
        return Err(KeyError::Forbidden);
    }
    bootstrap.validate().map_err(|_| KeyError::Invalid)
}
fn open_journal(
    path: &std::path::Path,
    bootstrap: &DeviceAuthorityBootstrap,
) -> Result<DeviceRosterJournal> {
    DeviceRosterJournal::lock(
        path,
        &bootstrap.initial_roster.authority.fingerprint,
        &bootstrap
            .initial_roster
            .digest()
            .map_err(|_| KeyError::Unavailable)?,
    )
    .map_err(|_| KeyError::Unavailable)
}
fn state(bootstrap: &DeviceAuthorityBootstrap, journal: &DeviceRosterJournal) -> Result<Value> {
    let current = journal.current().map_err(|_| KeyError::Unavailable)?;
    Ok(json!({"bootstrap":bootstrap,"roster":current.roster()}))
}

impl Accounts {
    fn device_key_directory(&self, user: &str) -> std::path::PathBuf {
        let mut path = self.path.as_os_str().to_os_string();
        path.push(".device-keys");
        std::path::PathBuf::from(path).join(user)
    }
    /// Lock order: accounts -> immutable bootstrap -> roster journal. The account lock
    /// remains held through publication, so disable/key changes cannot race admission.
    /// Do not call collection/entry operations while holding these locks.
    pub fn device_key_operation(
        &mut self,
        token: &str,
        operation: DeviceKeyOperation,
        body: &[u8],
    ) -> Result<Value> {
        if body.len() > MAX_DEVICE_KEY_BODY {
            return Err(KeyError::TooLarge);
        }
        let (_account_lock, db, user) = self.key_context(token)?;
        match &operation {
            DeviceKeyOperation::Receipt(id) | DeviceKeyOperation::History(id) if !valid_id(id) => {
                return Err(KeyError::Invalid);
            }
            _ => {}
        }
        // User-controlled paths are never accepted: scope comes only from the session.
        let directory = self.device_key_directory(&user.id);
        let anchor =
            StoreFile::lock(directory.join("bootstrap.json")).map_err(|_| KeyError::Unavailable)?;
        let journal_path = directory.join("roster.json");
        let stored = if anchor.exists() {
            let bytes = anchor
                .read_limited(MAX_DEVICE_BOOTSTRAP_BYTES)
                .map_err(|_| KeyError::Unavailable)?;
            let value =
                DeviceAuthorityBootstrap::parse(&bytes).map_err(|_| KeyError::Unavailable)?;
            scoped(&value, &db.deployment_id, &user.id).map_err(|_| KeyError::Unavailable)?;
            Some(value)
        } else {
            None
        };

        if matches!(operation, DeviceKeyOperation::Initialize) {
            let request: Initialize =
                serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
            self.reauthenticate_key(&user, &request.current_password)?;
            scoped(&request.bootstrap, &db.deployment_id, &user.id)?;
            if let Some(stored) = stored {
                if stored != request.bootstrap {
                    return Err(KeyError::Conflict);
                }
                // Exact retry never overwrites the anchor or recreates a missing journal.
                return state(&stored, &open_journal(&journal_path, &stored)?);
            }
            let enrolled = db.identities.get(&user.id).ok_or(KeyError::NotFound)?;
            if request.bootstrap.legacy_identity != enrolled.public_identity
                || request.bootstrap.source_bundle_revision != enrolled.bundle_revision
            {
                return Err(KeyError::Conflict);
            }
            let baseline = &request.bootstrap.initial_roster;
            let pinned = TrustedDeviceRoster::bootstrap(
                baseline.clone(),
                &baseline.authority.fingerprint,
                &baseline.digest().map_err(|_| KeyError::Invalid)?,
            )
            .map_err(|_| KeyError::Invalid)?;
            let journal = open_journal(&journal_path, &request.bootstrap)?;
            // Journal first, anchor last. An interrupted initialization can only resume
            // the exact empty baseline; later history is never silently reinitialized.
            match journal.initialize(&pinned) {
                Ok(()) => {}
                Err(Error::AlreadyExists) => {
                    let current = journal.current().map_err(|_| KeyError::Conflict)?;
                    if current.roster() != baseline {
                        return Err(KeyError::Conflict);
                    }
                }
                Err(_) => return Err(KeyError::Unavailable),
            }
            let bytes = serde_json::to_vec(&request.bootstrap).map_err(|_| KeyError::Invalid)?;
            if bytes.len() > MAX_DEVICE_BOOTSTRAP_BYTES {
                return Err(KeyError::TooLarge);
            }
            anchor
                .write(&bytes, true)
                .map_err(|_| KeyError::Unavailable)?;
            return state(&request.bootstrap, &journal);
        }
        let stored = stored.ok_or(KeyError::NotFound)?;
        let journal = open_journal(&journal_path, &stored)?;
        // Distinguish corrupt/unavailable persisted history from invalid new input.
        let current = journal.current().map_err(|_| KeyError::Unavailable)?;
        match operation {
            DeviceKeyOperation::Own => Ok(json!({"bootstrap":stored,"roster":current.roster()})),
            DeviceKeyOperation::Receipt(id) => {
                let receipt = journal
                    .lookup(&id)
                    .map_err(|_| KeyError::Unavailable)?
                    .ok_or(KeyError::NotFound)?;
                Ok(json!({"receipt":receipt}))
            }
            DeviceKeyOperation::History(digest) => {
                let rosters = journal
                    .successors(&digest)
                    .map_err(|_| KeyError::Conflict)?;
                Ok(
                    json!({"rosters":rosters,"head_digest":current.roster().digest().map_err(|_| KeyError::Unavailable)?,"head_generation":current.roster().generation}),
                )
            }
            DeviceKeyOperation::Publish => {
                let request: Publish =
                    serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
                self.reauthenticate_key(&user, &request.current_password)?;
                if !valid_id(&request.operation_id) || !valid_id(&request.expected_parent) {
                    return Err(KeyError::Invalid);
                }
                request.roster.validate().map_err(|_| KeyError::Invalid)?;
                if request.roster.authority != stored.initial_roster.authority {
                    return Err(KeyError::Forbidden);
                }
                // Receipt reconciliation precedes current-head checks, including after
                // later additions. A reused ID cannot select another signed candidate.
                let prior = journal
                    .lookup(&request.operation_id)
                    .map_err(|_| KeyError::Unavailable)?;
                if prior.is_none() {
                    if request.expected_parent
                        != current
                            .roster()
                            .digest()
                            .map_err(|_| KeyError::Unavailable)?
                    {
                        return Err(KeyError::Conflict);
                    }
                    // This transport milestone is add-only. Removals need device-bound
                    // session revocation and collection rotation before API exposure.
                    if request.roster.revoked_device_ids != current.roster().revoked_device_ids
                        || request.roster.devices.len() != current.roster().devices.len() + 1
                    {
                        return Err(KeyError::Forbidden);
                    }
                }
                let receipt = journal
                    .publish(
                        &request.operation_id,
                        &request.expected_parent,
                        &request.roster,
                    )
                    .map_err(|e| match e {
                        Error::Authentication => KeyError::Conflict,
                        Error::Format => KeyError::Invalid,
                        _ => KeyError::Unavailable,
                    })?;
                Ok(json!({"receipt":receipt}))
            }
            DeviceKeyOperation::Initialize => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests;
