//! Authenticated public identity directory and ciphertext-only bundle synchronization.
use super::{Accounts, Database, MAX_COUNTER, User};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use petika_core::{
    StoreFile,
    identity::{EncryptedIdentityBundle, PublicIdentity},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

pub const MAX_KEY_BODY: usize = 128 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityState {
    pub bundle_revision: u64,
    pub public_identity: PublicIdentity,
    pub encrypted_bundle: EncryptedIdentityBundle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    Invalid,
    Unauthenticated,
    Forbidden,
    NotFound,
    Conflict,
    TooLarge,
    RateLimited,
    Unavailable,
    MethodNotAllowed,
    UnsupportedMediaType,
}
impl KeyError {
    pub fn status(self) -> u16 {
        match self {
            Self::Invalid => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::TooLarge => 413,
            Self::RateLimited => 429,
            Self::Unavailable => 503,
            Self::MethodNotAllowed => 405,
            Self::UnsupportedMediaType => 415,
        }
    }
    pub fn code(self) -> &'static str {
        match self {
            Self::Invalid => "invalid_request",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::TooLarge => "too_large",
            Self::RateLimited => "rate_limited",
            Self::Unavailable => "unavailable",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::UnsupportedMediaType => "unsupported_media_type",
        }
    }
    pub fn body(self) -> serde_json::Value {
        serde_json::json!({"code":self.code(),"message":self.to_string()})
    }
}
impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "Invalid identity request",
            Self::Unauthenticated => "Authentication required",
            Self::Forbidden => "Request not permitted",
            Self::NotFound => "Identity not found",
            Self::Conflict => "State changed; refresh and retry",
            Self::TooLarge => "Request too large",
            Self::RateLimited => "Too many requests; try again later",
            Self::Unavailable => "Identity storage unavailable",
            Self::MethodNotAllowed => "Method not allowed",
            Self::UnsupportedMediaType => "JSON content type required",
        })
    }
}
impl std::error::Error for KeyError {}
type Result<T> = std::result::Result<T, KeyError>;

pub enum KeyOperation {
    Deployment,
    Own,
    Enroll,
    UpdateBundle,
    Replace,
    Lookup(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    expected_bundle_revision: u64,
    current_password: String,
    public_identity: PublicIdentity,
    encrypted_bundle: EncryptedIdentityBundle,
}
impl Drop for Enrollment {
    fn drop(&mut self) {
        self.current_password.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    expected_bundle_revision: u64,
    expected_identity_version: u64,
    current_password: String,
    public_identity: PublicIdentity,
    encrypted_bundle: EncryptedIdentityBundle,
}
impl Drop for Replacement {
    fn drop(&mut self) {
        self.current_password.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleUpdate {
    expected_bundle_revision: u64,
    encrypted_bundle: EncryptedIdentityBundle,
}

pub(super) fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn counter(value: u64) -> Result<()> {
    if (1..=MAX_COUNTER).contains(&value) {
        Ok(())
    } else {
        Err(KeyError::Invalid)
    }
}
fn next(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .filter(|v| *v <= MAX_COUNTER)
        .ok_or(KeyError::Conflict)
}
fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| KeyError::Invalid)
}
fn json<T: Serialize>(value: &T) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| KeyError::Unavailable)
}
fn validate_identity(
    db: &Database,
    user: &User,
    public: &PublicIdentity,
    bundle: &EncryptedIdentityBundle,
) -> Result<()> {
    if public.user_id != user.id || public.deployment_id != db.deployment_id {
        return Err(KeyError::Invalid);
    }
    public.validate().map_err(|_| KeyError::Invalid)?;
    bundle
        .validate(&public.fingerprint)
        .map_err(|_| KeyError::Invalid)
}

impl Accounts {
    fn key_context(&mut self, token: &str) -> Result<(StoreFile, Database, User)> {
        let session = self
            .sessions
            .get(token)
            .filter(|s| s.expires > Instant::now())
            .ok_or(KeyError::Unauthenticated)?;
        let user_id = session.user_id.clone();
        self.key_attempts.retain(|_, times| {
            times.retain(|t| t.elapsed() < Duration::from_secs(60));
            !times.is_empty()
        });
        let times = self.key_attempts.entry(user_id.clone()).or_default();
        if times.len() >= 120 {
            return Err(KeyError::RateLimited);
        }
        times.push(Instant::now());
        let file = StoreFile::lock(&self.path).map_err(|_| KeyError::Unavailable)?;
        let db = Self::load(&file).map_err(|_| KeyError::Unavailable)?;
        let user = db
            .users
            .iter()
            .find(|u| u.id == user_id && !u.disabled)
            .cloned()
            .ok_or(KeyError::Unauthenticated)?;
        Ok((file, db, user))
    }
    fn reauthenticate_key(&mut self, user: &User, password: &str) -> Result<()> {
        self.reserve_reauthentication()?;
        if !(12..=1024).contains(&password.chars().count()) {
            return Err(KeyError::Invalid);
        }
        let encoded = PasswordHash::new(&user.password_hash).map_err(|_| KeyError::Unavailable)?;
        Argon2::default()
            .verify_password(password.as_bytes(), &encoded)
            .map_err(|_| KeyError::Unauthenticated)
    }
    /// All operations recheck current session/user state under the exclusive account
    /// lock. Parsing directly into strict structs retains duplicate-field rejection.
    pub fn key_operation(
        &mut self,
        token: &str,
        operation: KeyOperation,
        body: &[u8],
    ) -> Result<serde_json::Value> {
        if body.len() > MAX_KEY_BODY {
            return Err(KeyError::TooLarge);
        }
        let (file, mut db, user) = self.key_context(token)?;
        match operation {
            KeyOperation::Deployment => {
                return Ok(serde_json::json!({"deployment_id":db.deployment_id}));
            }
            KeyOperation::Own => {
                return json(db.identities.get(&user.id).ok_or(KeyError::NotFound)?);
            }
            KeyOperation::Lookup(target) => {
                if !valid_id(&target) {
                    return Err(KeyError::NotFound);
                }
                let active = db.users.iter().any(|u| u.id == target && !u.disabled);
                let related = target == user.id
                    || db.groups.iter().any(|g| {
                        g.members.iter().any(|m| m.user_id == target)
                            && g.members.iter().any(|m| m.user_id == user.id)
                    });
                if !active || !related {
                    return Err(KeyError::NotFound);
                }
                return json(
                    &db.identities
                        .get(&target)
                        .ok_or(KeyError::NotFound)?
                        .public_identity,
                );
            }
            KeyOperation::Enroll => {
                let request: Enrollment = parse(body)?;
                if request.expected_bundle_revision != 0
                    || request.public_identity.identity_version != 1
                {
                    return Err(KeyError::Invalid);
                }
                self.reauthenticate_key(&user, &request.current_password)?;
                validate_identity(
                    &db,
                    &user,
                    &request.public_identity,
                    &request.encrypted_bundle,
                )?;
                if db.identities.contains_key(&user.id) {
                    return Err(KeyError::Conflict);
                }
                db.identity_changed(&user.id, false)
                    .map_err(|_| KeyError::Conflict)?;
                db.identities.insert(
                    user.id.clone(),
                    IdentityState {
                        bundle_revision: 1,
                        public_identity: request.public_identity.clone(),
                        encrypted_bundle: request.encrypted_bundle.clone(),
                    },
                );
            }
            KeyOperation::UpdateBundle => {
                let request: BundleUpdate = parse(body)?;
                counter(request.expected_bundle_revision)?;
                let state = db.identities.get_mut(&user.id).ok_or(KeyError::NotFound)?;
                if state.bundle_revision != request.expected_bundle_revision {
                    return Err(KeyError::Conflict);
                }
                request
                    .encrypted_bundle
                    .validate(&state.public_identity.fingerprint)
                    .map_err(|_| KeyError::Invalid)?;
                if request.encrypted_bundle.bundle_version < state.encrypted_bundle.bundle_version {
                    return Err(KeyError::Conflict);
                }
                state.bundle_revision = next(state.bundle_revision)?;
                state.encrypted_bundle = request.encrypted_bundle;
            }
            KeyOperation::Replace => {
                let request: Replacement = parse(body)?;
                counter(request.expected_bundle_revision)?;
                counter(request.expected_identity_version)?;
                self.reauthenticate_key(&user, &request.current_password)?;
                let state = db.identities.get(&user.id).ok_or(KeyError::NotFound)?;
                if state.bundle_revision != request.expected_bundle_revision
                    || state.public_identity.identity_version != request.expected_identity_version
                {
                    return Err(KeyError::Conflict);
                }
                if request.public_identity.identity_version
                    != next(state.public_identity.identity_version)?
                    || request.encrypted_bundle.bundle_version != 2
                {
                    return Err(KeyError::Invalid);
                }
                let revision = next(state.bundle_revision)?;
                validate_identity(
                    &db,
                    &user,
                    &request.public_identity,
                    &request.encrypted_bundle,
                )?;
                db.identity_changed(&user.id, true)
                    .map_err(|_| KeyError::Conflict)?;
                db.identities.insert(
                    user.id.clone(),
                    IdentityState {
                        bundle_revision: revision,
                        public_identity: request.public_identity.clone(),
                        encrypted_bundle: request.encrypted_bundle.clone(),
                    },
                );
            }
        }
        // Identity and membership generation changes become durable together.
        let response = json(db.identities.get(&user.id).ok_or(KeyError::Unavailable)?)?;
        let bytes = serde_json::to_vec(&db).map_err(|_| KeyError::Unavailable)?;
        file.write(&bytes, false)
            .map_err(|_| KeyError::Unavailable)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_rate_limit_and_shared_reauthentication_budget_expire() {
        let dir = tempfile::tempdir().unwrap();
        let mut accounts = Accounts::new(dir.path().join("accounts.json"));
        accounts
            .create_user(
                "owner",
                "Owner",
                "synthetic owner password".into(),
                true,
                true,
            )
            .unwrap();
        let (token, _) = accounts
            .login("owner", "synthetic owner password".into())
            .unwrap();
        for _ in 0..120 {
            accounts
                .key_operation(&token, KeyOperation::Deployment, b"")
                .unwrap();
        }
        assert_eq!(
            accounts
                .key_operation(&token, KeyOperation::Deployment, b"")
                .unwrap_err(),
            KeyError::RateLimited
        );
        for times in accounts.key_attempts.values_mut() {
            for t in times {
                *t = Instant::now() - Duration::from_secs(61);
            }
        }
        accounts
            .key_operation(&token, KeyOperation::Deployment, b"")
            .unwrap();
        accounts.attempts = vec![Instant::now(); 20];
        assert_eq!(
            accounts.reserve_reauthentication(),
            Err(KeyError::RateLimited)
        );
        assert!(
            accounts
                .login("owner", "synthetic owner password".into())
                .is_err()
        );
        accounts.attempts = vec![Instant::now() - Duration::from_secs(61); 20];
        accounts.reserve_reauthentication().unwrap();
        accounts.sessions.get_mut(&token).unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        assert_eq!(
            accounts
                .key_operation(&token, KeyOperation::Deployment, b"")
                .unwrap_err(),
            KeyError::Unauthenticated
        );
    }
}
