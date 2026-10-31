use super::{Accounts, KeyError, keys::valid_id};
use crate::git_key_leases::{
    Cleanup, ConfiguredHosts, KeyRegistrar, LeaseStore, Repository, State,
};
use petika_core::device_keys::{GitLeaseChallenge, GitLeaseProof};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, KeyError>;

pub enum GitLeaseOperation {
    Context,
    Challenge,
    Register,
    Status(String),
    LookupOperation(String),
    Complete(String),
}
fn password<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    #[serde(deserialize_with = "password")]
    current_password: Zeroizing<String>,
    operation_id: String,
    device_id: String,
    repository: Repository,
    ssh_public_key: String,
    read_only: bool,
    ttl: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    #[serde(deserialize_with = "password")]
    current_password: Zeroizing<String>,
    proof: GitLeaseProof,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {}
impl Accounts {
    pub(super) fn git_lease_operation(
        &mut self,
        token: &str,
        operation: GitLeaseOperation,
        body: &[u8],
    ) -> Result<Value> {
        if !self.lease_cleanup {
            return Err(KeyError::NotFound);
        }
        if self
            .authenticate(token)
            .map_err(|_| KeyError::Unavailable)?
            .is_none()
        {
            return Err(KeyError::Unauthenticated);
        }
        if matches!(
            &operation,
            GitLeaseOperation::Context
                | GitLeaseOperation::Status(_)
                | GitLeaseOperation::LookupOperation(_)
                | GitLeaseOperation::Complete(_)
        ) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| KeyError::Unavailable)?
                .as_secs();
            return self.git_lease_operation_with(
                token,
                operation,
                body,
                &mut ConfiguredHosts::metadata_only(),
                now,
            );
        }
        let path = std::env::var_os("PETIKA_GIT_KEY_HOSTS_FILE").ok_or(KeyError::Unavailable)?;
        let mut host = ConfiguredHosts::load(std::path::Path::new(&path))
            .map_err(|_| KeyError::Unavailable)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyError::Unavailable)?
            .as_secs();
        self.git_lease_operation_with(token, operation, body, &mut host, now)
    }
    fn git_lease_operation_with(
        &mut self,
        token: &str,
        operation: GitLeaseOperation,
        body: &[u8],
        host: &mut impl KeyRegistrar,
        now: u64,
    ) -> Result<Value> {
        let started = Instant::now();
        if !self.lease_cleanup {
            return Err(KeyError::NotFound);
        }
        if body.len() > 16384 {
            return Err(KeyError::TooLarge);
        }
        let (_account_lock, db, user) = self.key_context(token)?;
        let session = self.sessions.get(token).ok_or(KeyError::Unauthenticated)?;
        let session_id = session.id.clone();
        let remaining = session
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs();
        let data = self
            .path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();
        if matches!(operation, GitLeaseOperation::Context) {
            return Ok(
                json!({"deployment_id":db.deployment_id,"user_id":user.id,"session_id":session_id}),
            );
        }
        match &operation {
            GitLeaseOperation::Status(id)
            | GitLeaseOperation::LookupOperation(id)
            | GitLeaseOperation::Complete(id)
                if !valid_id(id) =>
            {
                return Err(KeyError::Invalid);
            }
            _ => {}
        }
        if let GitLeaseOperation::Status(id)
        | GitLeaseOperation::LookupOperation(id)
        | GitLeaseOperation::Complete(id) = &operation
        {
            let store = LeaseStore::lock(data.join("git-key-leases.json"))
                .map_err(|_| KeyError::Unavailable)?;
            let lease = store
                .leases()
                .map_err(|_| KeyError::Unavailable)?
                .into_iter()
                .find(|l| {
                    (if matches!(operation, GitLeaseOperation::LookupOperation(_)) {
                        l.authorization
                            .as_ref()
                            .is_some_and(|a| a.operation_id == *id)
                    } else {
                        l.id == *id
                    }) && l.session == session_id
                        && l.authorization.as_ref().is_some_and(|a| {
                            a.user_id == user.id && a.deployment_id == db.deployment_id
                        })
                })
                .ok_or(KeyError::NotFound)?;
            if matches!(operation, GitLeaseOperation::Complete(_)) {
                let _: Completion = serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
                store
                    .request_cleanup(Cleanup::Lease(id))
                    .map_err(|_| KeyError::Unavailable)?;
                return Ok(json!({"lease_id":id,"cleanup":"pending"}));
            }
            return Ok(
                json!({"lease_id":lease.id,"operation_id":lease.authorization.as_ref().map(|a|&a.operation_id),
                "state":lease.state,"expires_at":lease.expires_at,"last_error":lease.last_error,
                "challenge":lease.authorization}),
            );
        }
        // Keep account and signed-roster locks through admission/host creation. This
        // serializes disablement and roster mutation against issuance. Network is bounded.
        let (_anchor, _journal, current) =
            self.locked_device_roster(&db.deployment_id, &user.id)?;
        match operation {
            GitLeaseOperation::Challenge => {
                let request: ChallengeRequest =
                    serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
                self.reauthenticate_key(&user, &request.current_password)?;
                if !valid_id(&request.operation_id)
                    || !valid_id(&request.device_id)
                    || !(60..=3600).contains(&request.ttl)
                {
                    return Err(KeyError::Invalid);
                }
                if remaining < request.ttl {
                    return Err(KeyError::Unauthenticated);
                }
                if !host.authorized(
                    &request.repository,
                    &user.id,
                    request.read_only,
                    request.ttl,
                ) {
                    return Err(KeyError::Forbidden);
                }
                let device = current
                    .roster()
                    .devices
                    .iter()
                    .find(|d| d.device_id == request.device_id)
                    .ok_or(KeyError::Forbidden)?;
                let challenge = GitLeaseChallenge {
                    version: 1,
                    lease_id: "0".repeat(64),
                    operation_id: request.operation_id,
                    deployment_id: db.deployment_id,
                    user_id: user.id,
                    session_id,
                    device_id: device.device_id.clone(),
                    device_fingerprint: device.fingerprint.clone(),
                    roster_digest: current
                        .roster()
                        .digest()
                        .map_err(|_| KeyError::Unavailable)?,
                    management_origin: request.repository.management_origin.clone(),
                    repository: request.repository.repository.clone(),
                    ssh_public_key: request.ssh_public_key,
                    read_only: request.read_only,
                    issued_at: now,
                    challenge_expires_at: now.checked_add(60).ok_or(KeyError::Invalid)?,
                    lease_expires_at: now.checked_add(request.ttl).ok_or(KeyError::Invalid)?,
                };
                challenge.canonical_bytes().map_err(|_| KeyError::Invalid)?;
                let store = LeaseStore::lock(data.join("git-key-leases.json"))
                    .map_err(|_| KeyError::Unavailable)?;
                let challenge = store
                    .prepare_authorization(challenge, request.repository)
                    .map_err(|error| {
                        if error.is::<crate::git_key_leases::registration::OperationConflict>() {
                            KeyError::Conflict
                        } else {
                            KeyError::Unavailable
                        }
                    })?;
                Ok(json!({"challenge":challenge}))
            }
            GitLeaseOperation::Register => {
                let request: Registration =
                    serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
                self.reauthenticate_key(&user, &request.current_password)?;
                request
                    .proof
                    .verify(&current, now)
                    .map_err(|_| KeyError::Forbidden)?;
                let store = LeaseStore::lock(data.join("git-key-leases.json"))
                    .map_err(|_| KeyError::Unavailable)?;
                let lease = store
                    .leases()
                    .map_err(|_| KeyError::Unavailable)?
                    .into_iter()
                    .find(|l| {
                        l.id == request.proof.challenge.lease_id
                            && l.session == session_id
                            && l.authorization.as_ref() == Some(&request.proof.challenge)
                    })
                    .ok_or(KeyError::Conflict)?;
                if matches!(lease.state, State::Revoking | State::Removed) {
                    return Err(KeyError::Conflict);
                }
                let auth = &request.proof.challenge;
                if auth.user_id != user.id
                    || auth.deployment_id != db.deployment_id
                    || auth.session_id != session_id
                    || !host.authorized(
                        &lease.repository,
                        &user.id,
                        auth.read_only,
                        auth.lease_expires_at - auth.issued_at,
                    )
                {
                    return Err(KeyError::Forbidden);
                }
                let result = store
                    .register(&request.proof, &current, &session_id, now, host)
                    .map_err(|_| KeyError::Unavailable)?;
                if now.saturating_add(started.elapsed().as_secs()) >= result.expires_at
                    || self
                        .sessions
                        .get(token)
                        .is_none_or(|s| s.expires <= Instant::now())
                {
                    store
                        .request_cleanup(Cleanup::Lease(&result.id))
                        .map_err(|_| KeyError::Unavailable)?;
                    return Err(KeyError::Conflict);
                }
                if result.state != State::Active {
                    return Err(KeyError::Unavailable);
                }
                Ok(
                    json!({"lease_id":result.id,"operation_id":auth.operation_id,"state":result.state,
                    "expires_at":result.expires_at,"read_only":auth.read_only,"ssh_public_key":auth.openssh_public_key().map_err(|_|KeyError::Invalid)?}),
                )
            }
            GitLeaseOperation::Context
            | GitLeaseOperation::Status(_)
            | GitLeaseOperation::LookupOperation(_)
            | GitLeaseOperation::Complete(_) => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests;
