//! Password-authenticated account + independently verified WebAuthn ceremonies.
//! All stored credential material is public; PRF output never belongs on the server.
use super::{Accounts, KeyError, keys::valid_id};
use crate::{Repository, Snapshot, Update};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use petika_core::{
    StoreFile,
    passkey_vault::{AccessPolicy, BrowserVault},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use webauthn_rs::prelude::*;
type Result<T> = std::result::Result<T, KeyError>;

#[derive(Default)]
pub(super) struct State {
    service: Option<Webauthn>,
    origin: String,
    pending: HashMap<String, Pending>,
    grants: HashMap<String, Grant>,
}
impl State {
    pub(super) fn for_origin(origin: &str) -> Self {
        let Ok(url) = Url::parse(origin) else {
            return Self::default();
        };
        if !(url.scheme() == "https"
            || (url.scheme() == "http" && url.host_str() == Some("localhost")))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Self::default();
        }
        let service = url
            .host_str()
            .and_then(|host| WebauthnBuilder::new(host, &url).ok())
            .and_then(|builder| {
                builder
                    .rp_name("Petika")
                    .timeout(Duration::from_secs(60))
                    .build()
                    .ok()
            });
        Self {
            service,
            origin: url.origin().ascii_serialization(),
            ..Self::default()
        }
    }
}
pub fn settings(origin: &str) -> std::result::Result<Value, &'static str> {
    let enabled = State::for_origin(origin).service.is_some();
    let policy = std::env::var("PETIKA_FRESH_VAULT_POLICY").unwrap_or_else(|_| {
        if enabled {
            "browser-passkey".into()
        } else {
            "legacy".into()
        }
    });
    if !matches!(
        policy.as_str(),
        "legacy" | "browser-passkey" | "strict-biometric"
    ) {
        return Err("Invalid PETIKA_FRESH_VAULT_POLICY");
    }
    if policy == "browser-passkey" && !enabled {
        return Err(
            "Browser passkeys require a configured HTTPS endpoint or http://localhost endpoint",
        );
    }
    Ok(json!({"enabled":enabled,"fresh_policy":policy,"strict_biometric_available":false}))
}
pub enum Operation {
    Info,
    RegistrationStart,
    RegistrationFinish,
    AuthenticationStart,
    AuthenticationFinish,
    Vault(String),
    MigrationSource(String),
    Write(String),
}
struct Pending {
    user: String,
    session: String,
    expires: Instant,
    kind: Ceremony,
}
enum Ceremony {
    Registration {
        state: PasskeyRegistration,
        label: String,
    },
    Authentication {
        state: PasskeyAuthentication,
        request: ActionRequest,
        credential_revision: u64,
    },
}
struct Grant {
    session: String,
    user: String,
    expires: Instant,
    request: ActionRequest,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    revision: u64,
    user: String,
    label: String,
    passkey: Passkey,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    credentials: Vec<Credential>,
}
impl Ledger {
    fn read(file: &StoreFile) -> Result<Self> {
        if !file.exists() {
            return Ok(Self {
                version: 1,
                credentials: vec![],
            });
        }
        let ledger: Self = serde_json::from_slice(
            &file
                .read_limited(4 * 1024 * 1024)
                .map_err(|_| KeyError::Unavailable)?,
        )
        .map_err(|_| KeyError::Unavailable)?;
        if ledger.version != 1
            || ledger.credentials.len() > 4096
            || ledger.credentials.iter().any(|c| {
                !valid_id(&c.user)
                    || c.label.is_empty()
                    || c.label.len() > 80
                    || c.revision == 0
                    || c.revision > super::MAX_COUNTER
            })
        {
            return Err(KeyError::Unavailable);
        }
        let mut ids = std::collections::HashSet::new();
        if ledger
            .credentials
            .iter()
            .any(|c| !ids.insert(credential_id(&c.passkey)))
        {
            return Err(KeyError::Unavailable);
        }
        Ok(ledger)
    }
    fn save(&self, file: &StoreFile) -> Result<()> {
        file.write(
            &serde_json::to_vec(self).map_err(|_| KeyError::Unavailable)?,
            !file.exists(),
        )
        .map_err(|_| KeyError::Unavailable)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Create,
    Migrate,
    PrepareKey,
    Generate,
    AuthorizeCopy,
    Open,
    List,
    View,
    RevealPassword,
    CopyPassword,
    CopyUsername,
    Otp,
    Edit,
    Put,
    Remove,
    AddKey,
}
impl Action {
    fn writes(&self) -> bool {
        matches!(
            self,
            Self::Create | Self::Migrate | Self::Put | Self::Remove | Self::AddKey
        )
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequest {
    collection_id: String,
    credential_id: String,
    action: Action,
    revision: u64,
    operation_id: String,
    #[serde(default)]
    new_credential_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationStart {
    current_password: String,
    label: String,
}
impl Drop for RegistrationStart {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.current_password.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationFinish {
    ceremony_id: String,
    credential: RegisterPublicKeyCredential,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationFinish {
    ceremony_id: String,
    credential: PublicKeyCredential,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Write {
    grant_id: String,
    vault: BrowserVault,
}
fn credential_id(key: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(key.cred_id().as_slice())
}
fn snapshot(data: &std::path::Path, collection: &str) -> Repository {
    Repository::new(
        data.join("collections")
            .join(collection)
            .join("snapshot.json"),
    )
}
fn current(repository: &Repository) -> Result<Option<(Snapshot, BrowserVault)>> {
    repository
        .read()
        .map_err(|_| KeyError::Unavailable)?
        .map(|s| {
            BrowserVault::parse(s.encrypted.as_bytes())
                .map(|v| (s, v))
                .map_err(|_| KeyError::Conflict)
        })
        .transpose()
}
fn legacy(repository: &Repository) -> Result<Snapshot> {
    let value = repository
        .read()
        .map_err(|_| KeyError::Unavailable)?
        .ok_or(KeyError::Conflict)?;
    if value.schema_version != 1
        || value.delivery.is_some()
        || repository
            .path
            .parent()
            .is_some_and(|p| p.join("entries/committed-root").exists())
        || petika_core::envelope_metadata(value.encrypted.as_bytes())
            .map_err(|_| KeyError::Conflict)?
            .1
            .is_some()
    {
        return Err(KeyError::Conflict);
    }
    Ok(value)
}
impl Accounts {
    pub fn browser_passkeys_available(&self) -> bool {
        self.passkeys.service.is_some()
    }
    pub fn passkey_operation(
        &mut self,
        token: &str,
        operation: Operation,
        body: &[u8],
    ) -> Result<Value> {
        if body.len() > 16 * 1024 * 1024 {
            return Err(KeyError::TooLarge);
        }
        let (_lock, db, user) = self.key_context(token)?;
        let session = self
            .sessions
            .get(token)
            .ok_or(KeyError::Unauthenticated)?
            .id
            .clone();
        let data = self
            .path
            .parent()
            .ok_or(KeyError::Unavailable)?
            .to_path_buf();
        if self.passkeys.service.is_none() {
            return Err(KeyError::Unavailable);
        }
        let now = Instant::now();
        self.passkeys.pending.retain(|_, p| p.expires > now);
        self.passkeys.grants.retain(|_, g| g.expires > now);
        let ledger_file =
            StoreFile::lock(data.join("passkeys.json")).map_err(|_| KeyError::Unavailable)?;
        let mut ledger = Ledger::read(&ledger_file)?;
        let public_list = |ledger: &Ledger| -> Vec<Value> {
            ledger.credentials.iter().filter(|c|c.user==user.id).map(|c|json!({"id":credential_id(&c.passkey),"label":c.label,"policy":"browser-passkey"})).collect()
        };
        match operation {
            Operation::Info => Ok(
                json!({"user_id":user.id,"deployment_id":db.deployment_id,"origin":self.passkeys.origin,
                "credentials":public_list(&ledger),"policies":{"browser-passkey":true,"strict-biometric":false}}),
            ),
            Operation::RegistrationStart => {
                let request: RegistrationStart =
                    serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
                self.reauthenticate_key(&user, &request.current_password)?;
                if request.label.is_empty()
                    || request.label.len() > 80
                    || request.label.chars().any(char::is_control)
                {
                    return Err(KeyError::Invalid);
                }
                let existing: Vec<_> = ledger
                    .credentials
                    .iter()
                    .filter(|c| c.user == user.id)
                    .map(|c| c.passkey.cred_id().clone())
                    .collect();
                if existing.len() >= 16
                    || ledger.credentials.len() >= 4096
                    || self.passkeys.pending.len() >= 256
                {
                    return Err(KeyError::RateLimited);
                }
                let mut bytes = [0u8; 16];
                for (i, chunk) in user.id.as_bytes()[..32].chunks_exact(2).enumerate() {
                    bytes[i] = u8::from_str_radix(
                        std::str::from_utf8(chunk).map_err(|_| KeyError::Invalid)?,
                        16,
                    )
                    .map_err(|_| KeyError::Invalid)?;
                }
                let (options, state) = self
                    .passkeys
                    .service
                    .as_ref()
                    .ok_or(KeyError::Unavailable)?
                    .start_passkey_registration(
                        Uuid::from_bytes(bytes),
                        &user.username,
                        &user.name,
                        Some(existing),
                    )
                    .map_err(|_| KeyError::Invalid)?;
                let id = super::random_id().map_err(|_| KeyError::Unavailable)?;
                self.passkeys.pending.insert(
                    id.clone(),
                    Pending {
                        user: user.id,
                        session,
                        expires: now + Duration::from_secs(120),
                        kind: Ceremony::Registration {
                            state,
                            label: request.label.clone(),
                        },
                    },
                );
                Ok(json!({"ceremony_id":id,"options":options}))
            }
            Operation::RegistrationFinish => {
                let request: RegistrationFinish =
                    serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
                let pending = self.take_ceremony(&request.ceremony_id, &user.id, &session)?;
                let Ceremony::Registration { state, label } = pending.kind else {
                    return Err(KeyError::Invalid);
                };
                let key = self
                    .passkeys
                    .service
                    .as_ref()
                    .ok_or(KeyError::Unavailable)?
                    .finish_passkey_registration(&request.credential, &state)
                    .map_err(|_| KeyError::Forbidden)?;
                let id = credential_id(&key);
                if ledger
                    .credentials
                    .iter()
                    .any(|c| credential_id(&c.passkey) == id)
                {
                    return Err(KeyError::Conflict);
                }
                if ledger
                    .credentials
                    .iter()
                    .filter(|c| c.user == user.id)
                    .count()
                    >= 16
                    || ledger.credentials.len() >= 4096
                {
                    return Err(KeyError::RateLimited);
                }
                ledger.credentials.push(Credential {
                    revision: 1,
                    user: user.id,
                    label,
                    passkey: key,
                });
                ledger.save(&ledger_file)?;
                Ok(json!({"credential_id":id,"policy":"browser-passkey"}))
            }
            Operation::AuthenticationStart => {
                let request: ActionRequest =
                    serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
                if request.collection_id != user.id
                    || !valid_id(&request.operation_id)
                    || request.revision > (1u64 << 53) - 1
                {
                    return Err(KeyError::Forbidden);
                }
                if matches!(request.action, Action::Create | Action::Migrate)
                    && settings(&self.passkeys.origin).map_err(|_| KeyError::Unavailable)?["fresh_policy"]
                        == "strict-biometric"
                {
                    return Err(KeyError::Forbidden);
                }
                let repository = snapshot(&data, &request.collection_id);
                let migrating = request.action == Action::Migrate;
                let stored = if migrating {
                    let source = legacy(&repository)?;
                    if source.revision != request.revision {
                        return Err(KeyError::Conflict);
                    }
                    None
                } else {
                    current(&repository)?
                };
                if let Some((ref saved, ref vault)) = stored {
                    if saved.revision != request.revision || request.action == Action::Create {
                        return Err(KeyError::Conflict);
                    }
                    if request.action != Action::PrepareKey
                        && !vault
                            .protection
                            .wrappers
                            .iter()
                            .any(|w| w.credential_id == request.credential_id)
                    {
                        return Err(KeyError::Forbidden);
                    }
                    if vault.protection.owner_user_id != user.id
                        || vault.protection.context.deployment_id != db.deployment_id
                        || vault.protection.origin != self.passkeys.origin
                    {
                        return Err(KeyError::Forbidden);
                    }
                } else if !migrating && (request.revision != 0 || request.action != Action::Create)
                {
                    return Err(KeyError::Conflict);
                }
                if request.action == Action::AddKey {
                    let Some(id) = request.new_credential_id.as_ref() else {
                        return Err(KeyError::Invalid);
                    };
                    if !ledger
                        .credentials
                        .iter()
                        .any(|c| c.user == user.id && credential_id(&c.passkey) == *id)
                    {
                        return Err(KeyError::Forbidden);
                    }
                } else if request.new_credential_id.is_some() {
                    return Err(KeyError::Invalid);
                }
                let key = ledger
                    .credentials
                    .iter()
                    .find(|c| {
                        c.user == user.id && credential_id(&c.passkey) == request.credential_id
                    })
                    .ok_or(KeyError::Forbidden)?;
                if self.passkeys.pending.len() >= 256 {
                    return Err(KeyError::RateLimited);
                }
                let (options, state) = self
                    .passkeys
                    .service
                    .as_ref()
                    .ok_or(KeyError::Unavailable)?
                    .start_passkey_authentication(std::slice::from_ref(&key.passkey))
                    .map_err(|_| KeyError::Invalid)?;
                let id = super::random_id().map_err(|_| KeyError::Unavailable)?;
                self.passkeys.pending.insert(
                    id.clone(),
                    Pending {
                        user: user.id,
                        session,
                        expires: now + Duration::from_secs(120),
                        kind: Ceremony::Authentication {
                            state,
                            request,
                            credential_revision: key.revision,
                        },
                    },
                );
                Ok(json!({"ceremony_id":id,"options":options}))
            }
            Operation::AuthenticationFinish => {
                let request: AuthenticationFinish =
                    serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
                let pending = self.take_ceremony(&request.ceremony_id, &user.id, &session)?;
                let Ceremony::Authentication {
                    state,
                    request: action,
                    credential_revision,
                } = pending.kind
                else {
                    return Err(KeyError::Invalid);
                };
                let result = self
                    .passkeys
                    .service
                    .as_ref()
                    .ok_or(KeyError::Unavailable)?
                    .finish_passkey_authentication(&request.credential, &state)
                    .map_err(|_| KeyError::Forbidden)?;
                if !result.user_verified() {
                    return Err(KeyError::Forbidden);
                }
                let key = ledger
                    .credentials
                    .iter_mut()
                    .find(|c| {
                        c.user == user.id && credential_id(&c.passkey) == action.credential_id
                    })
                    .ok_or(KeyError::Forbidden)?;
                if key.revision != credential_revision || key.revision >= super::MAX_COUNTER {
                    return Err(KeyError::Conflict);
                }
                key.revision += 1;
                key.passkey
                    .update_credential(&result)
                    .ok_or(KeyError::Forbidden)?;
                ledger.save(&ledger_file)?;
                let repository = snapshot(&data, &action.collection_id);
                let revision = if action.action == Action::Migrate {
                    legacy(&repository)?.revision
                } else {
                    current(&repository)?
                        .as_ref()
                        .map_or(0, |(s, _)| s.revision)
                };
                if revision != action.revision {
                    return Err(KeyError::Conflict);
                }
                let grant_id = if action.action.writes() {
                    if self.passkeys.grants.len() >= 256 {
                        return Err(KeyError::RateLimited);
                    }
                    let id = super::random_id().map_err(|_| KeyError::Unavailable)?;
                    self.passkeys.grants.insert(
                        id.clone(),
                        Grant {
                            user: user.id,
                            session,
                            expires: Instant::now() + Duration::from_secs(30),
                            request: action.clone(),
                        },
                    );
                    Some(id)
                } else {
                    None
                };
                Ok(
                    json!({"verified":true,"operation_id":action.operation_id,"grant_id":grant_id,"policy":"browser-passkey"}),
                )
            }
            Operation::MigrationSource(id) => {
                if id != user.id {
                    return Err(KeyError::Forbidden);
                }
                let repository = snapshot(&data, &id);
                if let Ok(source) = legacy(&repository) {
                    Ok(json!({"revision":source.revision,"legacy":source.encrypted,"vault":null}))
                } else {
                    let (saved, vault) = current(&repository)?.ok_or(KeyError::Conflict)?;
                    Ok(json!({"revision":saved.revision,"legacy":null,"vault":vault}))
                }
            }
            Operation::Vault(id) => {
                if id != user.id {
                    return Err(KeyError::Forbidden);
                }
                let value = current(&snapshot(&data, &id))?;
                Ok(match value {
                    None => json!({"revision":0,"vault":null}),
                    Some((s, v)) => json!({"revision":s.revision,"vault":v}),
                })
            }
            Operation::Write(id) => {
                let request: Write = serde_json::from_slice(body).map_err(|_| KeyError::Invalid)?;
                // A wrong session cannot consume another session's grant.
                let g = self
                    .passkeys
                    .grants
                    .get(&request.grant_id)
                    .ok_or(KeyError::Forbidden)?;
                if g.session != session || g.user != user.id {
                    return Err(KeyError::Forbidden);
                }
                let grant = self
                    .passkeys
                    .grants
                    .remove(&request.grant_id)
                    .ok_or(KeyError::Forbidden)?;
                if id != user.id
                    || grant.request.collection_id != id
                    || request.vault.operation_id != grant.request.operation_id
                {
                    return Err(KeyError::Forbidden);
                }
                request.vault.validate().map_err(|_| KeyError::Invalid)?;
                let p = &request.vault.protection;
                if p.owner_user_id != user.id
                    || p.context.collection_id != id
                    || p.context.deployment_id != db.deployment_id
                    || p.origin != self.passkeys.origin
                    || p.policy != AccessPolicy::BrowserPasskey
                {
                    return Err(KeyError::Forbidden);
                }
                let repository = snapshot(&data, &id);
                let migrating = grant.request.action == Action::Migrate;
                let (prior, revision) = if migrating {
                    (None, legacy(&repository)?.revision)
                } else {
                    let prior = current(&repository)?;
                    let revision = prior.as_ref().map_or(0, |(s, _)| s.revision);
                    (prior, revision)
                };
                if revision != grant.request.revision {
                    return Err(KeyError::Conflict);
                }
                match (&grant.request.action, prior.as_ref()) {
                    (Action::Create | Action::Migrate, None)
                        if p.context.key_epoch == 1
                            && p.wrappers.len() == 1
                            && p.wrappers[0].credential_id == grant.request.credential_id => {}
                    (Action::Put | Action::Remove, Some((_, old))) if old.protection == *p => {}
                    (Action::AddKey, Some((_, old))) => {
                        let mut expected = old.protection.clone();
                        let new_id = grant
                            .request
                            .new_credential_id
                            .as_ref()
                            .ok_or(KeyError::Invalid)?;
                        let w = p
                            .wrappers
                            .iter()
                            .find(|w| w.credential_id == *new_id)
                            .ok_or(KeyError::Invalid)?;
                        if expected
                            .wrappers
                            .iter()
                            .any(|old| old.credential_id == *new_id)
                        {
                            return Err(KeyError::Conflict);
                        }
                        expected.wrappers.push(w.clone());
                        if expected != *p
                            || old.encrypted_snapshot != request.vault.encrypted_snapshot
                        {
                            return Err(KeyError::Forbidden);
                        }
                    }
                    _ => return Err(KeyError::Forbidden),
                }
                if p.wrappers.iter().any(|w| {
                    !ledger
                        .credentials
                        .iter()
                        .any(|c| c.user == user.id && credential_id(&c.passkey) == w.credential_id)
                }) {
                    return Err(KeyError::Forbidden);
                }
                let encoded =
                    serde_json::to_string(&request.vault).map_err(|_| KeyError::Invalid)?;
                let updated = if migrating {
                    repository.migrate_browser(grant.request.revision, encoded)
                } else {
                    repository.update_browser(grant.request.revision, encoded)
                };
                match updated.map_err(|_| KeyError::Unavailable)? {
                    Update::Saved(revision) => {
                        let replication = if let Some(root) = std::env::var_os("PETIKA_GIT_MIRROR")
                        {
                            if crate::mirror_once(
                                &repository,
                                &std::path::PathBuf::from(root).join(&id),
                            )
                            .is_ok()
                            {
                                "mirrored"
                            } else {
                                "pending"
                            }
                        } else {
                            "disabled"
                        };
                        Ok(
                            json!({"revision":revision,"operation_id":request.vault.operation_id,"replication":replication}),
                        )
                    }
                    Update::Conflict(_) => Err(KeyError::Conflict),
                }
            }
        }
    }
    fn take_ceremony(&mut self, id: &str, user: &str, session: &str) -> Result<Pending> {
        let p = self.passkeys.pending.get(id).ok_or(KeyError::Forbidden)?;
        if p.user != user || p.session != session || p.expires <= Instant::now() {
            return Err(KeyError::Forbidden);
        }
        self.passkeys.pending.remove(id).ok_or(KeyError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        sign::Signer,
    };
    use serde_cbor_2::Value as Cbor;
    use sha2::{Digest, Sha256};
    const ORIGIN: &str = "https://vault.example";
    struct Fixture {
        _dir: tempfile::TempDir,
        accounts: Accounts,
        token: String,
        other: String,
        id: String,
        key: PKey<Private>,
        cred: Vec<u8>,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mut accounts = Accounts::new(dir.path().join("accounts.json"));
            accounts.passkeys = State::for_origin(ORIGIN);
            accounts
                .create_user(
                    "owner",
                    "Owner",
                    "synthetic owner password".into(),
                    true,
                    true,
                )
                .unwrap();
            let (token, user) = accounts
                .login("owner", "synthetic owner password".into())
                .unwrap();
            let (other, _) = accounts
                .login("owner", "synthetic owner password".into())
                .unwrap();
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
            Self {
                _dir: dir,
                accounts,
                token,
                other,
                id: user.id,
                key,
                cred: vec![42; 32],
            }
        }
        fn call(&mut self, operation: Operation, body: Value) -> Result<Value> {
            self.accounts.passkey_operation(
                &self.token,
                operation,
                &serde_json::to_vec(&body).unwrap(),
            )
        }
        fn register(&mut self) {
            let start = self.call(Operation::RegistrationStart, json!({"current_password":"synthetic owner password","label":"Synthetic test key"})).unwrap();
            let ec = self.key.ec_key().unwrap();
            let mut x = openssl::bn::BigNum::new().unwrap();
            let mut y = openssl::bn::BigNum::new().unwrap();
            let mut ctx = openssl::bn::BigNumContext::new().unwrap();
            ec.public_key()
                .affine_coordinates_gfp(ec.group(), &mut x, &mut y, &mut ctx)
                .unwrap();
            let cose = Cbor::Map(
                [
                    (Cbor::Integer(1), Cbor::Integer(2)),
                    (Cbor::Integer(3), Cbor::Integer(-7)),
                    (Cbor::Integer(-1), Cbor::Integer(1)),
                    (Cbor::Integer(-2), Cbor::Bytes(x.to_vec_padded(32).unwrap())),
                    (Cbor::Integer(-3), Cbor::Bytes(y.to_vec_padded(32).unwrap())),
                ]
                .into(),
            );
            let mut auth = Sha256::digest(b"vault.example").to_vec();
            auth.push(0x45);
            auth.extend(0u32.to_be_bytes());
            auth.extend([0; 16]);
            auth.extend((self.cred.len() as u16).to_be_bytes());
            auth.extend(&self.cred);
            auth.extend(serde_cbor_2::to_vec(&cose).unwrap());
            let att = Cbor::Map(
                [
                    (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                    (Cbor::Text("authData".into()), Cbor::Bytes(auth)),
                    (Cbor::Text("attStmt".into()), Cbor::Map(Default::default())),
                ]
                .into(),
            );
            let client = json!({"type":"webauthn.create","challenge":start["options"]["publicKey"]["challenge"],"origin":ORIGIN,"crossOrigin":false});
            self.call(Operation::RegistrationFinish,json!({"ceremony_id":start["ceremony_id"],"credential":{
                "id":URL_SAFE_NO_PAD.encode(&self.cred),"rawId":URL_SAFE_NO_PAD.encode(&self.cred),"type":"public-key",
                "response":{"attestationObject":URL_SAFE_NO_PAD.encode(serde_cbor_2::to_vec(&att).unwrap()),"clientDataJSON":URL_SAFE_NO_PAD.encode(serde_json::to_vec(&client).unwrap()),"transports":["internal"]},"clientExtensionResults":{}
            }})).unwrap();
        }
        fn start(&mut self) -> Value {
            self.call(Operation::AuthenticationStart,json!({"collection_id":self.id,"credential_id":URL_SAFE_NO_PAD.encode(&self.cred),"action":"create","revision":0,"operation_id":"c".repeat(64)})).unwrap()
        }
        fn assertion(&self, start: &Value, flags: u8, counter: u32, origin: &str) -> Value {
            let client=serde_json::to_vec(&json!({"type":"webauthn.get","challenge":start["options"]["publicKey"]["challenge"],"origin":origin,"crossOrigin":false})).unwrap();
            let mut auth = Sha256::digest(b"vault.example").to_vec();
            auth.push(flags);
            auth.extend(counter.to_be_bytes());
            let mut signed = auth.clone();
            signed.extend(Sha256::digest(&client));
            let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
            signer.update(&signed).unwrap();
            json!({"ceremony_id":start["ceremony_id"],"credential":{"id":URL_SAFE_NO_PAD.encode(&self.cred),"rawId":URL_SAFE_NO_PAD.encode(&self.cred),"type":"public-key","response":{"authenticatorData":URL_SAFE_NO_PAD.encode(auth),"clientDataJSON":URL_SAFE_NO_PAD.encode(client),"signature":URL_SAFE_NO_PAD.encode(signer.sign_to_vec().unwrap()),"userHandle":null},"clientExtensionResults":{}}})
        }
    }
    #[test]
    fn verifies_signatures_uv_origin_and_consumes_challenges() {
        let mut f = Fixture::new();
        f.register();
        for (flags, origin) in [(1, ORIGIN), (5, "https://evil.example")] {
            let start = f.start();
            let body = f.assertion(&start, flags, 1, origin);
            assert_eq!(
                f.call(Operation::AuthenticationFinish, body.clone())
                    .unwrap_err(),
                KeyError::Forbidden
            );
            assert!(f.call(Operation::AuthenticationFinish, body).is_err());
        }
        let start = f.start();
        let mut body = f.assertion(&start, 5, 1, ORIGIN);
        body["credential"]["response"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0; 70]));
        assert_eq!(
            f.call(Operation::AuthenticationFinish, body).unwrap_err(),
            KeyError::Forbidden
        );
        let start = f.start();
        let body = f.assertion(&start, 5, 1, ORIGIN);
        let result = f
            .call(Operation::AuthenticationFinish, body.clone())
            .unwrap();
        assert_eq!(result["verified"], true);
        assert!(result["grant_id"].is_string());
        assert!(f.call(Operation::AuthenticationFinish, body).is_err());
        let start = f.start();
        let rollback = f.assertion(&start, 5, 1, ORIGIN);
        assert_eq!(
            f.call(Operation::AuthenticationFinish, rollback)
                .unwrap_err(),
            KeyError::Forbidden
        );
    }
    #[test]
    fn challenges_are_session_bound_expiring_and_counter_state_cannot_race() {
        let mut f = Fixture::new();
        f.register();
        let a = f.start();
        let b = f.start();
        let proof_a = f.assertion(&a, 5, 1, ORIGIN);
        let proof_b = f.assertion(&b, 5, 2, ORIGIN);
        assert_eq!(
            f.accounts
                .passkey_operation(
                    &f.other,
                    Operation::AuthenticationFinish,
                    &serde_json::to_vec(&proof_a).unwrap()
                )
                .unwrap_err(),
            KeyError::Forbidden
        );
        f.call(Operation::AuthenticationFinish, proof_a).unwrap();
        assert_eq!(
            f.call(Operation::AuthenticationFinish, proof_b)
                .unwrap_err(),
            KeyError::Conflict
        );
        let start = f.start();
        let proof = f.assertion(&start, 5, 3, ORIGIN);
        f.accounts
            .passkeys
            .pending
            .get_mut(start["ceremony_id"].as_str().unwrap())
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        assert!(f.call(Operation::AuthenticationFinish, proof).is_err());
    }
    fn candidate(f: &mut Fixture) -> BrowserVault {
        use petika_core::{
            CollectionContext, UnlockedStore,
            passkey_vault::{BrowserProtection, PasskeyWrapper},
        };
        let info = f.call(Operation::Info, json!({})).unwrap();
        let context = CollectionContext {
            deployment_id: info["deployment_id"].as_str().unwrap().into(),
            collection_id: f.id.clone(),
            key_epoch: 1,
        };
        let mut store = UnlockedStore::create("public synthetic fixture passphrase").unwrap();
        store
            .bind_collection(context.clone(), "public synthetic fixture passphrase")
            .unwrap();
        BrowserVault {
            version: 3,
            kind: petika_core::passkey_vault::KIND.into(),
            operation_id: "c".repeat(64),
            encrypted_snapshot: String::from_utf8(store.seal().unwrap()).unwrap(),
            protection: BrowserProtection {
                version: 1,
                policy: AccessPolicy::BrowserPasskey,
                context,
                owner_user_id: f.id.clone(),
                origin: ORIGIN.into(),
                wrappers: vec![PasskeyWrapper {
                    credential_id: URL_SAFE_NO_PAD.encode(&f.cred),
                    prf_input: URL_SAFE_NO_PAD.encode([1; 32]),
                    kdf_salt: URL_SAFE_NO_PAD.encode([2; 32]),
                    nonce: URL_SAFE_NO_PAD.encode([3; 12]),
                    wrapped_key: URL_SAFE_NO_PAD.encode([4; 48]),
                }],
            },
        }
    }
    #[test]
    fn writes_require_one_use_grants_preserve_cas_and_deny_legacy_downgrade() {
        use petika_core::UnlockedStore;
        let mut f = Fixture::new();
        f.register();
        let mut vault = candidate(&mut f);
        let id = f.id.clone();
        let start = f.start();
        let proof = f.assertion(&start, 5, 1, ORIGIN);
        let grant = f.call(Operation::AuthenticationFinish, proof).unwrap();
        let body = json!({"grant_id":grant["grant_id"],"vault":vault});
        assert_eq!(
            f.accounts
                .passkey_operation(
                    &f.other,
                    Operation::Write(id.clone()),
                    &serde_json::to_vec(&body).unwrap()
                )
                .unwrap_err(),
            KeyError::Forbidden
        );
        assert_eq!(
            f.call(Operation::Write(id.clone()), body.clone()).unwrap()["revision"],
            1
        );
        assert_eq!(
            f.call(Operation::Write(id.clone()), body).unwrap_err(),
            KeyError::Forbidden
        );
        let repository = snapshot(f._dir.path(), &id);
        let legacy = String::from_utf8(
            UnlockedStore::create("public legacy fixture passphrase")
                .unwrap()
                .seal()
                .unwrap(),
        )
        .unwrap();
        assert!(repository.update(1, legacy).is_err());
        assert!(
            repository
                .update(1, serde_json::to_string(&vault).unwrap())
                .is_err()
        );
        let request = json!({"collection_id":id,"credential_id":URL_SAFE_NO_PAD.encode(&f.cred),"action":"put","revision":1,"operation_id":"d".repeat(64)});
        let start = f.call(Operation::AuthenticationStart, request).unwrap();
        let proof = f.assertion(&start, 5, 2, ORIGIN);
        let grant = f.call(Operation::AuthenticationFinish, proof).unwrap();
        // Another accepted writer advances the repository after approval.
        assert!(matches!(
            repository
                .update_browser(1, serde_json::to_string(&vault).unwrap())
                .unwrap(),
            Update::Saved(2)
        ));
        vault.operation_id = "d".repeat(64);
        assert_eq!(
            f.call(
                Operation::Write(id.clone()),
                json!({"grant_id":grant["grant_id"],"vault":vault})
            )
            .unwrap_err(),
            KeyError::Conflict
        );
        assert_eq!(repository.read().unwrap().unwrap().revision, 2);
        let start=f.call(Operation::AuthenticationStart,json!({"collection_id":id,"credential_id":URL_SAFE_NO_PAD.encode(&f.cred),"action":"put","revision":2,"operation_id":"e".repeat(64)})).unwrap();
        let proof = f.assertion(&start, 5, 3, ORIGIN);
        let grant = f.call(Operation::AuthenticationFinish, proof).unwrap();
        f.accounts
            .passkeys
            .grants
            .get_mut(grant["grant_id"].as_str().unwrap())
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        vault.operation_id = "e".repeat(64);
        assert_eq!(
            f.call(
                Operation::Write(id),
                json!({"grant_id":grant["grant_id"],"vault":vault})
            )
            .unwrap_err(),
            KeyError::Forbidden
        );
    }
    #[test]
    fn migration_is_explicit_cas_bound_and_retains_exact_original_snapshot() {
        let mut f = Fixture::new();
        f.register();
        let vault = candidate(&mut f);
        let id = f.id.clone();
        let mut old =
            petika_core::UnlockedStore::create("public old synthetic passphrase").unwrap();
        let encrypted = String::from_utf8(old.seal().unwrap()).unwrap();
        let repository = snapshot(f._dir.path(), &id);
        repository.update(0, encrypted.clone()).unwrap();
        assert!(
            repository
                .update_browser(1, serde_json::to_string(&vault).unwrap())
                .is_err()
        );
        assert!(f.call(Operation::Vault(id.clone()), json!({})).is_err());
        assert_eq!(
            f.call(Operation::MigrationSource(id.clone()), json!({}))
                .unwrap()["legacy"],
            encrypted
        );
        let action = |revision| json!({"collection_id":id,"credential_id":URL_SAFE_NO_PAD.encode(&f.cred),"action":"migrate","revision":revision,"operation_id":"c".repeat(64)});
        let body1 = action(1);
        let body2 = action(2);
        let body3 = action(3);
        let start = f.call(Operation::AuthenticationStart, body1).unwrap();
        let proof = f.assertion(&start, 5, 1, ORIGIN);
        repository.update(1, encrypted.clone()).unwrap();
        assert_eq!(
            f.call(Operation::AuthenticationFinish, proof).unwrap_err(),
            KeyError::Conflict
        );
        let start = f.call(Operation::AuthenticationStart, body2).unwrap();
        let proof = f.assertion(&start, 5, 2, ORIGIN);
        let grant = f.call(Operation::AuthenticationFinish, proof).unwrap();
        repository.update(2, encrypted.clone()).unwrap();
        assert_eq!(
            f.call(
                Operation::Write(id.clone()),
                json!({"grant_id":grant["grant_id"],"vault":vault})
            )
            .unwrap_err(),
            KeyError::Conflict
        );
        let backup = repository
            .path
            .parent()
            .unwrap()
            .join("snapshot.passphrase-backup.json");
        assert!(!backup.exists());
        let original = std::fs::read(&repository.path).unwrap();
        let start = f
            .call(Operation::AuthenticationStart, body3.clone())
            .unwrap();
        let proof = f.assertion(&start, 5, 3, ORIGIN);
        let grant = f.call(Operation::AuthenticationFinish, proof).unwrap();
        let write = json!({"grant_id":grant["grant_id"],"vault":vault});
        assert_eq!(
            f.call(Operation::Write(id.clone()), write.clone()).unwrap()["revision"],
            4
        );
        assert_eq!(std::fs::read(&backup).unwrap(), original);
        assert_eq!(repository.read().unwrap().unwrap().revision, 4);
        assert!(repository.update(4, encrypted).is_err());
        assert!(f.call(Operation::Write(id.clone()), write).is_err());
        assert!(f.call(Operation::AuthenticationStart, body3).is_err());
        let status = f.call(Operation::MigrationSource(id), json!({})).unwrap();
        assert!(status["legacy"].is_null());
        assert_eq!(status["vault"]["operation_id"], "c".repeat(64));
    }
    #[test]
    fn migration_rejects_other_owners_recipient_authority_entry_authority_and_mode_downgrade() {
        let mut f = Fixture::new();
        f.register();
        let vault = candidate(&mut f);
        let id = f.id.clone();
        let action = json!({"collection_id":"d".repeat(64),"credential_id":URL_SAFE_NO_PAD.encode(&f.cred),"action":"migrate","revision":1,"operation_id":"c".repeat(64)});
        assert_eq!(
            f.call(Operation::AuthenticationStart, action).unwrap_err(),
            KeyError::Forbidden
        );
        let repository = snapshot(f._dir.path(), &id);
        let mut old = petika_core::UnlockedStore::create_with_mode(
            "public hybrid old passphrase",
            petika_core::EncryptionMode::HybridPostQuantum,
        )
        .unwrap();
        repository
            .update(0, String::from_utf8(old.seal().unwrap()).unwrap())
            .unwrap();
        assert!(
            repository
                .migrate_browser(1, serde_json::to_string(&vault).unwrap())
                .is_err()
        );
        assert!(
            !repository
                .path
                .parent()
                .unwrap()
                .join("snapshot.passphrase-backup.json")
                .exists()
        );
        std::fs::create_dir_all(repository.path.parent().unwrap().join("entries")).unwrap();
        std::fs::write(
            repository
                .path
                .parent()
                .unwrap()
                .join("entries/committed-root"),
            b"test marker",
        )
        .unwrap();
        assert!(legacy(&repository).is_err());
        std::fs::remove_file(
            repository
                .path
                .parent()
                .unwrap()
                .join("entries/committed-root"),
        )
        .unwrap();
        let bound = old
            .fresh_bound_draft(
                petika_core::CollectionContext {
                    deployment_id: "a".repeat(64),
                    collection_id: id.clone(),
                    key_epoch: 1,
                },
                "public bound synthetic passphrase",
            )
            .unwrap()
            .seal()
            .unwrap();
        let file = StoreFile::lock(&repository.path).unwrap();
        file.write(
            &serde_json::to_vec(&Snapshot {
                schema_version: 2,
                revision: 1,
                encrypted: String::from_utf8(bound).unwrap(),
                delivery: Some(crate::DeliveryState {
                    packages: vec![],
                    rotation_generation: 0,
                    transactions: vec![],
                }),
            })
            .unwrap(),
            false,
        )
        .unwrap();
        drop(file);
        assert!(legacy(&repository).is_err());
    }
    #[test]
    fn conflicting_migration_backup_denies_cutover_without_overwriting_either_copy() {
        let mut f = Fixture::new();
        f.register();
        let vault = candidate(&mut f);
        let id = f.id.clone();
        let encrypted = String::from_utf8(
            petika_core::UnlockedStore::create("public synthetic old passphrase")
                .unwrap()
                .seal()
                .unwrap(),
        )
        .unwrap();
        let repository = snapshot(f._dir.path(), &id);
        repository.update(0, encrypted).unwrap();
        let original = std::fs::read(&repository.path).unwrap();
        let backup = StoreFile::lock(
            repository
                .path
                .parent()
                .unwrap()
                .join("snapshot.passphrase-backup.json"),
        )
        .unwrap();
        backup.write(b"existing unrelated backup", true).unwrap();
        drop(backup);
        assert!(
            repository
                .migrate_browser(1, serde_json::to_string(&vault).unwrap())
                .is_err()
        );
        assert_eq!(std::fs::read(&repository.path).unwrap(), original);
        assert_eq!(
            std::fs::read(
                repository
                    .path
                    .parent()
                    .unwrap()
                    .join("snapshot.passphrase-backup.json")
            )
            .unwrap(),
            b"existing unrelated backup"
        );
    }
    #[test]
    fn invalid_origins_never_enable_browser_provider() {
        for origin in [
            "http://vault.example",
            "https://user@vault.example",
            "https://vault.example/other",
            "https://vault.example?x=1",
            "https://vault.example#fragment",
        ] {
            assert!(State::for_origin(origin).service.is_none());
        }
        assert!(State::for_origin(ORIGIN).service.is_some());
        assert!(State::for_origin("http://localhost:8080").service.is_some());
    }
}
