//! Read-only user backup credentials and credential-free destination profiles.
//! Full-server archives are operator jobs, never available through user backup keys.
use super::{
    Accounts, Argon2, Database, KeyError, PasswordHash, PasswordVerifier, User, keys, label,
    random_id,
};
use crate::Repository;
use petika_core::StoreFile;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type Result<T> = std::result::Result<T, KeyError>;
const OPERATOR: &str = "operator";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupKey {
    id: String,
    user_id: String,
    name: String,
    token_hash: String,
    password_fingerprint: String,
    created_at: u64,
    expires_at: u64,
}
impl BackupKey {
    fn public(&self) -> Value {
        json!({"id":self.id,"name":self.name,"created_at":self.created_at,
            "expires_at":self.expires_at,"scope":"backup:read"})
    }
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Destination {
    id: String,
    name: String,
    kind: String,
    repository: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupDatabase {
    schema_version: u32,
    keys: Vec<BackupKey>,
    destinations: BTreeMap<String, Vec<Destination>>,
}
impl BackupDatabase {
    fn load(file: &StoreFile) -> Result<Self> {
        let db: Self = if file.exists() {
            serde_json::from_slice(&file.read().map_err(|_| KeyError::Unavailable)?)
                .map_err(|_| KeyError::Unavailable)?
        } else {
            Self {
                schema_version: 1,
                keys: Vec::new(),
                destinations: BTreeMap::new(),
            }
        };
        if db.schema_version != 1
            || db.keys.len() > 4096
            || db.destinations.len() > 4096
            || db.keys.iter().any(|k| {
                !keys::valid_id(&k.id)
                    || !keys::valid_id(&k.user_id)
                    || !keys::valid_id(&k.token_hash)
                    || !keys::valid_id(&k.password_fingerprint)
                    || !label(&k.name)
                    || k.expires_at <= k.created_at
            })
            || db.destinations.iter().any(|(owner, entries)| {
                (owner != OPERATOR && !keys::valid_id(owner))
                    || entries.len() > 8
                    || entries.iter().any(|d| {
                        !keys::valid_id(&d.id)
                            || !valid_destination(&d.name, &d.kind, &d.repository)
                    })
            })
        {
            return Err(KeyError::Unavailable);
        }
        Ok(db)
    }
    fn save(&self, file: &StoreFile) -> Result<()> {
        file.write(
            &serde_json::to_vec(self).map_err(|_| KeyError::Unavailable)?,
            !file.exists(),
        )
        .map_err(|_| KeyError::Unavailable)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateKey {
    name: String,
    expires_in_days: u64,
    current_password: String,
}
impl Drop for CreateKey {
    fn drop(&mut self) {
        self.current_password.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveDestination {
    id: Option<String>,
    name: String,
    kind: String,
    repository: String,
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| KeyError::Unavailable)
}
fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn valid_destination(name: &str, kind: &str, repository: &str) -> bool {
    if !label(name) || repository.len() > 2048 || repository.chars().any(char::is_whitespace) {
        return false;
    }
    let source = match kind {
        "s3" => match repository.strip_prefix("s3:") {
            Some(v) => v,
            None => return false,
        },
        "sftp" => repository,
        _ => return false,
    };
    let Ok(url) = url::Url::parse(source) else {
        return false;
    };
    if url.host_str().is_none()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match kind {
        "s3" => {
            url.scheme() == "https"
                && url.username().is_empty()
                && url.path().trim_matches('/').len() >= 3
        }
        "sftp" => {
            url.scheme() == "sftp"
                && url.path().starts_with("//")
                && url.path().len() > 2
                && !url.username().is_empty()
                && !url.username().starts_with('-')
                && url
                    .username()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        }
        _ => false,
    }
}

impl Accounts {
    fn backup_file(&self) -> Result<StoreFile> {
        StoreFile::lock(self.path.with_file_name("backups.json")).map_err(|_| KeyError::Unavailable)
    }
    pub(super) fn revoke_backup_keys(&self, user_id: &str) -> crate::Result<()> {
        let file = self.backup_file()?;
        if !file.exists() {
            return Ok(());
        }
        let mut db = BackupDatabase::load(&file)?;
        db.keys.retain(|key| key.user_id != user_id);
        db.save(&file)?;
        Ok(())
    }
    /// Session-only management. Backup bearer keys are deliberately not accepted here.
    pub fn backup_manage(
        &mut self,
        session: &str,
        operator: bool,
        method: &str,
        path: &str,
        payload: Value,
    ) -> Result<Value> {
        let user = self
            .authenticate(session)
            .map_err(|_| KeyError::Unavailable)?
            .ok_or(KeyError::Unauthenticated)?;
        if operator && (!user.admin || !path.starts_with("destinations")) {
            return Err(KeyError::Forbidden);
        }
        let owner = if operator { OPERATOR } else { &user.id };
        if method == "POST" && path == "keys" {
            self.reserve_reauthentication()?;
        }
        let file = self.backup_file()?;
        let mut db = BackupDatabase::load(&file)?;
        match (method, path) {
            ("GET", "keys") => Ok(
                json!({"keys":db.keys.iter().filter(|k| k.user_id == user.id).map(BackupKey::public).collect::<Vec<_>>()}),
            ),
            ("POST", "keys") => {
                let request: CreateKey =
                    serde_json::from_value(payload).map_err(|_| KeyError::Invalid)?;
                if !label(&request.name) || !(1..=365).contains(&request.expires_in_days) {
                    return Err(KeyError::Invalid);
                }
                let parsed =
                    PasswordHash::new(&user.password_hash).map_err(|_| KeyError::Unavailable)?;
                Argon2::default()
                    .verify_password(request.current_password.as_bytes(), &parsed)
                    .map_err(|_| KeyError::Forbidden)?;
                let created = now()?;
                db.keys.retain(|k| k.expires_at > created);
                if db.keys.iter().filter(|k| k.user_id == user.id).count() >= 8
                    || db.keys.len() >= 4096
                {
                    return Err(KeyError::TooLarge);
                }
                let id = random_id().map_err(|_| KeyError::Unavailable)?;
                let token = zeroize::Zeroizing::new(format!(
                    "pbk_{id}_{}",
                    random_id().map_err(|_| KeyError::Unavailable)?
                ));
                let key = BackupKey {
                    id,
                    user_id: user.id,
                    name: request.name.trim().into(),
                    token_hash: digest(&token),
                    password_fingerprint: digest(&user.password_hash),
                    created_at: created,
                    expires_at: created + request.expires_in_days * 86400,
                };
                let result = json!({"key":key.public(),"token":token.as_str()});
                db.keys.push(key);
                db.save(&file)?;
                Ok(result)
            }
            ("GET", "destinations") => Ok(
                json!({"scope":if operator {"operator"} else {"user"},"destinations":db.destinations.get(owner).cloned().unwrap_or_default()}),
            ),
            ("POST", "destinations") => {
                let request: SaveDestination =
                    serde_json::from_value(payload).map_err(|_| KeyError::Invalid)?;
                if !valid_destination(&request.name, &request.kind, &request.repository) {
                    return Err(KeyError::Invalid);
                }
                if !db.destinations.contains_key(owner) && db.destinations.len() >= 4096 {
                    return Err(KeyError::TooLarge);
                }
                let entries = db.destinations.entry(owner.into()).or_default();
                let id = if let Some(id) = request.id {
                    if !entries.iter().any(|d| d.id == id) {
                        return Err(KeyError::NotFound);
                    }
                    id
                } else {
                    if entries.len() >= 8 {
                        return Err(KeyError::TooLarge);
                    }
                    random_id().map_err(|_| KeyError::Unavailable)?
                };
                let saved = Destination {
                    id,
                    name: request.name.trim().into(),
                    kind: request.kind,
                    repository: request.repository,
                };
                entries.retain(|d| d.id != saved.id);
                entries.push(saved.clone());
                db.save(&file)?;
                Ok(json!(saved))
            }
            ("DELETE", _) => {
                let (kind, id) = path.split_once('/').ok_or(KeyError::NotFound)?;
                if !keys::valid_id(id) {
                    return Err(KeyError::NotFound);
                }
                let removed = match kind {
                    "keys" if !operator => {
                        let before = db.keys.len();
                        db.keys.retain(|k| !(k.id == id && k.user_id == user.id));
                        before != db.keys.len()
                    }
                    "destinations" => {
                        let entries = db.destinations.entry(owner.into()).or_default();
                        let before = entries.len();
                        entries.retain(|d| d.id != id);
                        before != entries.len()
                    }
                    _ => return Err(KeyError::MethodNotAllowed),
                };
                if !removed {
                    return Err(KeyError::NotFound);
                }
                db.save(&file)?;
                Ok(json!({"ok":true}))
            }
            _ => Err(KeyError::MethodNotAllowed),
        }
    }

    fn backup_user<'a>(&self, token: &str, accounts: &'a Database) -> Result<&'a User> {
        let rest = token
            .strip_prefix("pbk_")
            .ok_or(KeyError::Unauthenticated)?;
        let (id, secret) = rest.split_once('_').ok_or(KeyError::Unauthenticated)?;
        if !keys::valid_id(id) || !keys::valid_id(secret) {
            return Err(KeyError::Unauthenticated);
        }
        let db = BackupDatabase::load(&self.backup_file()?)?;
        let key = db
            .keys
            .iter()
            .find(|k| k.id == id)
            .ok_or(KeyError::Unauthenticated)?;
        if !bool::from(key.token_hash.as_bytes().ct_eq(digest(token).as_bytes()))
            || key.expires_at <= now()?
        {
            return Err(KeyError::Unauthenticated);
        }
        accounts
            .users
            .iter()
            .find(|u| {
                u.id == key.user_id
                    && !u.disabled
                    && digest(&u.password_hash) == key.password_fingerprint
            })
            .ok_or(KeyError::Unauthenticated)
    }

    /// Every export holds the account lock while rechecking membership and reading data.
    /// Metadata and snapshots are separate bounded requests, not an unbounded server dump.
    pub fn backup_export(&self, token: &str, collection: Option<&str>) -> Result<Value> {
        let file = StoreFile::lock(&self.path).map_err(|_| KeyError::Unavailable)?;
        let accounts = Self::load(&file).map_err(|_| KeyError::Unavailable)?;
        let user = self.backup_user(token, &accounts)?;
        let identity = accounts.identities.get(&user.id);
        if let Some(id) = collection {
            if !keys::valid_id(id) {
                return Err(KeyError::NotFound);
            }
            let group = accounts
                .groups
                .iter()
                .find(|g| g.id == id && g.members.iter().any(|m| m.user_id == user.id));
            if id != user.id && group.is_none() {
                return Err(KeyError::Forbidden);
            }
            let path = self
                .path
                .parent()
                .ok_or(KeyError::Unavailable)?
                .join("collections")
                .join(id)
                .join("snapshot.json");
            let saved = Repository::new(path)
                .read()
                .map_err(|_| KeyError::Unavailable)?;
            let Some(saved) = saved else {
                return Ok(json!({"backup_version":1,"collection_id":id,"snapshot":null}));
            };
            // Never export other recipients' grants or server retry receipts.
            let packages = saved
                .delivery
                .as_ref()
                .map(|d| {
                    d.packages
                        .iter()
                        .filter(|p| p.recipient_user_id == user.id)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let issuers = packages
                .iter()
                .filter_map(|p| {
                    accounts
                        .identities
                        .get(&p.issuer_user_id)
                        .map(|i| &i.public_identity)
                })
                .collect::<Vec<_>>();
            Ok(
                json!({"backup_version":1,"deployment_id":accounts.deployment_id,"owner_id":user.id,"collection_id":id,
                "snapshot":{"schema_version":saved.schema_version,"revision":saved.revision,"encrypted":saved.encrypted},
                "packages":packages,"issuers":issuers,
                "membership_generation":group.map(|g| g.membership_generation),"rotation_required":group.map(|g| g.rotation_required)}),
            )
        } else {
            let mut collections = vec![json!({"id":user.id,"name":"Personal","group":false})];
            for group in &accounts.groups {
                if group.members.iter().any(|m| m.user_id == user.id) {
                    collections.push(json!({"id":group.id,"name":group.name,"group":true}));
                }
            }
            if collections.len() > 1000 {
                return Err(KeyError::TooLarge);
            }
            let destinations = BackupDatabase::load(&self.backup_file()?)?
                .destinations
                .remove(&user.id)
                .unwrap_or_default();
            Ok(
                json!({"backup_version":1,"kind":"user","deployment_id":accounts.deployment_id,"user":user.public(),
                "identity":identity,"collections":collections,"destinations":destinations,"exported_at":now()?}),
            )
        }
    }
}
