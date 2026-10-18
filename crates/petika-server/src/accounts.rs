//! Local identities and collection authorization. Plaintext private and collection keys never enter this module.
mod backups;
mod delivery;
mod keys;
use crate::Result;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
pub use delivery::DeliveryOperation;
pub use keys::{IdentityState, KeyError, KeyOperation};
use petika_core::StoreFile;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub id: String,
    pub username: String,
    pub name: String,
    pub admin: bool,
    pub disabled: bool,
    pub password_hash: String,
}
impl User {
    pub fn public(&self) -> serde_json::Value {
        serde_json::json!({"id": self.id, "username": self.username, "name": self.name, "admin": self.admin, "disabled": self.disabled})
    }
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Membership {
    pub user_id: String,
    pub edit: bool,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub members: Vec<Membership>,
    pub membership_generation: u64,
    pub rotation_required: bool,
}
const MAX_COUNTER: u64 = (1 << 53) - 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Database {
    schema_version: u32,
    deployment_id: String,
    users: Vec<User>,
    groups: Vec<Group>,
    identities: BTreeMap<String, IdentityState>,
}
impl Database {
    fn empty() -> Result<Self> {
        Ok(Self {
            schema_version: 2,
            deployment_id: random_id()?,
            users: Vec::new(),
            groups: Vec::new(),
            identities: BTreeMap::new(),
        })
    }
    fn validate(&self) -> Result<()> {
        if self.schema_version != 2
            || !keys::valid_id(&self.deployment_id)
            || self
                .groups
                .iter()
                .any(|g| !(1..=MAX_COUNTER).contains(&g.membership_generation))
            || self.identities.iter().any(|(id, state)| {
                state.public_identity.user_id != *id
                    || state.public_identity.deployment_id != self.deployment_id
                    || !(1..=MAX_COUNTER).contains(&state.bundle_revision)
                    || !self.users.iter().any(|u| u.id == *id)
            })
        {
            return Err("Unsupported or invalid account database; migration required".into());
        }
        Ok(())
    }
    fn identity_changed(&mut self, user_id: &str, rotation: bool) -> Result<()> {
        for group in &mut self.groups {
            if group.members.iter().any(|m| m.user_id == user_id) {
                group.membership_generation = next_generation(group.membership_generation)?;
                group.rotation_required |= rotation;
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyGroup {
    id: String,
    name: String,
    members: Vec<Membership>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDatabase {
    #[serde(default)]
    schema_version: u32,
    users: Vec<User>,
    groups: Vec<LegacyGroup>,
}
fn next_generation(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .filter(|v| *v <= MAX_COUNTER)
        .ok_or("Membership generation exhausted".into())
}
struct Session {
    user_id: String,
    expires: Instant,
}
struct DeviceGrant {
    code: String,
    expires: Instant,
    last_poll: Option<Instant>,
    approval: Option<String>,
    denied: bool,
}
pub struct Accounts {
    path: PathBuf,
    sessions: HashMap<String, Session>,
    attempts: Vec<Instant>,
    initial_snapshot: Option<String>,
    devices: HashMap<String, DeviceGrant>,
    device_attempts: Vec<Instant>,
    key_attempts: HashMap<String, Vec<Instant>>,
}
fn random_id() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| "random generator failed")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn hash(password: &str) -> Result<String> {
    if !(12..=1024).contains(&password.chars().count()) {
        return Err("Use a password between 12 and 1024 characters".into());
    }
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|_| "random generator failed")?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| "salt failed")?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| "password hashing failed")?
        .to_string())
}
fn label(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 100 && !value.chars().any(char::is_control)
}
impl Accounts {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            sessions: HashMap::new(),
            attempts: Vec::new(),
            initial_snapshot: None,
            devices: HashMap::new(),
            device_attempts: Vec::new(),
            key_attempts: HashMap::new(),
        }
    }
    pub fn initial_snapshot(&mut self, encrypted: String) -> Result<()> {
        petika_core::validate_envelope(encrypted.as_bytes())?;
        self.initial_snapshot = Some(encrypted);
        Ok(())
    }
    fn load(file: &StoreFile) -> Result<Database> {
        if file.exists() {
            let db: Database = serde_json::from_slice(&file.read()?)?;
            db.validate()?;
            Ok(db)
        } else {
            Database::empty()
        }
    }
    /// Sequential upgrades with exact original backups. Failed/repeated attempts never
    /// overwrite a conflicting backup or regenerate a committed deployment ID.
    pub fn migrate(&self) -> Result<()> {
        let file = StoreFile::lock(&self.path)?;
        if !file.exists() {
            return file
                .write(&serde_json::to_vec(&Database::empty()?)?, true)
                .map_err(Into::into);
        }
        loop {
            let bytes = file.read()?;
            let header: serde_json::Value = serde_json::from_slice(&bytes)?;
            let version = header
                .get("schema_version")
                .map(|v| v.as_u64().ok_or("Invalid schema version"))
                .transpose()?
                .unwrap_or(0);
            if version == 2 {
                Self::load(&file)?;
                return Ok(());
            }
            if version > 1 {
                return Err("Account database was created by a newer schema version".into());
            }
            let mut old: LegacyDatabase = serde_json::from_slice(&bytes)?;
            let backup =
                StoreFile::lock(self.path.with_extension(format!("schema-{version}.backup")))?;
            if backup.exists() {
                if backup.read()? != bytes {
                    return Err("Conflicting account migration backup".into());
                }
            } else {
                backup.write(&bytes, true)?;
            }
            if version == 0 {
                old.schema_version = 1;
                file.write(&serde_json::to_vec(&old)?, false)?;
            } else {
                let mut db = Database::empty()?;
                db.users = old.users;
                db.groups = old
                    .groups
                    .into_iter()
                    .map(|g| Group {
                        id: g.id,
                        name: g.name,
                        members: g.members,
                        membership_generation: 1,
                        rotation_required: false,
                    })
                    .collect();
                db.validate()?;
                file.write(&serde_json::to_vec(&db)?, false)?;
                return Ok(());
            }
        }
    }
    pub fn initialized(&self) -> Result<bool> {
        Ok(!Self::load(&StoreFile::lock(&self.path)?)?.users.is_empty())
    }
    pub fn create_user(
        &self,
        username: &str,
        name: &str,
        password: String,
        admin: bool,
        bootstrap: bool,
    ) -> Result<User> {
        let password = Zeroizing::new(password);
        let username = username.trim().to_lowercase();
        if !label(name)
            || username.len() < 3
            || username.len() > 100
            || !username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._-".contains(&b))
        {
            return Err("Use a valid username and display name".into());
        }
        let file = StoreFile::lock(&self.path)?;
        let mut db = Self::load(&file)?;
        if bootstrap != db.users.is_empty() {
            return Err("Account setup is unavailable".into());
        }
        if db.users.iter().any(|u| u.username == username) {
            return Err("Username already exists".into());
        }
        let user = User {
            id: random_id()?,
            username,
            name: name.trim().into(),
            admin,
            disabled: false,
            password_hash: hash(&password)?,
        };
        if bootstrap && let Some(encrypted) = &self.initial_snapshot {
            let repository = crate::Repository::new(
                self.path
                    .parent()
                    .ok_or("Invalid account path")?
                    .join("collections")
                    .join(&user.id)
                    .join("snapshot.json"),
            );
            repository.update(0, encrypted.clone())?;
        }
        db.users.push(user.clone());
        file.write(&serde_json::to_vec(&db)?, false)?;
        Ok(user)
    }
    fn reserve_reauthentication(&mut self) -> std::result::Result<(), KeyError> {
        self.attempts
            .retain(|t| t.elapsed() < Duration::from_secs(60));
        if self.attempts.len() >= 20 {
            return Err(KeyError::RateLimited);
        }
        self.attempts.push(Instant::now());
        Ok(())
    }
    pub fn login(&mut self, username: &str, password: String) -> Result<(String, User)> {
        let password = Zeroizing::new(password);
        self.reserve_reauthentication()
            .map_err(|_| "Too many sign-in attempts. Try again in a minute")?;
        let db = Self::load(&StoreFile::lock(&self.path)?)?;
        let user = db
            .users
            .iter()
            .find(|u| u.username == username.trim().to_lowercase());
        // Spend one Argon2 operation for unknown accounts as well.
        let Some(found) = user else {
            let _ = hash("unknown-account-dummy-password")?;
            return Err("Incorrect username or password".into());
        };
        let encoded = &found.password_hash;
        let parsed = PasswordHash::new(encoded).map_err(|_| "Sign-in unavailable")?;
        let valid = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        let user = user
            .filter(|u| valid && !u.disabled)
            .ok_or("Incorrect username or password")?
            .clone();
        self.sessions.retain(|_, s| s.expires > Instant::now());
        if self.sessions.len() >= 1000 {
            return Err("Too many active sessions".into());
        }
        let token = random_id()?;
        self.sessions.insert(
            token.clone(),
            Session {
                user_id: user.id.clone(),
                expires: Instant::now() + Duration::from_secs(8 * 3600),
            },
        );
        Ok((token, user))
    }
    pub fn authenticate(&mut self, token: &str) -> Result<Option<User>> {
        let Some(session) = self.sessions.get(token) else {
            return Ok(None);
        };
        if session.expires <= Instant::now() {
            self.sessions.remove(token);
            return Ok(None);
        }
        let db = Self::load(&StoreFile::lock(&self.path)?)?;
        Ok(db
            .users
            .into_iter()
            .find(|u| u.id == session.user_id && !u.disabled))
    }
    pub fn logout(&mut self, token: &str) {
        self.sessions.remove(token);
    }
    /// Petika device approval, not an OAuth/OIDC endpoint. No decryption keys are issued.
    pub fn device_start(&mut self) -> Result<serde_json::Value> {
        self.device_attempts
            .retain(|t| t.elapsed() < Duration::from_secs(60));
        self.devices.retain(|_, g| g.expires > Instant::now());
        if self.device_attempts.len() >= 30 || self.devices.len() >= 100 {
            return Err("Too many CLI sign-in requests; try again later".into());
        }
        self.device_attempts.push(Instant::now());
        let device = random_id()?;
        let code = random_id()?[..10].to_uppercase();
        if self.devices.values().any(|g| g.code == code) {
            return Err("Please retry sign-in".into());
        }
        self.devices.insert(
            device.clone(),
            DeviceGrant {
                code: code.clone(),
                expires: Instant::now() + Duration::from_secs(600),
                last_poll: None,
                approval: None,
                denied: false,
            },
        );
        Ok(serde_json::json!({"device_code":device,"user_code":code,"expires_in":600,"interval":5}))
    }
    pub fn device_approve(
        &mut self,
        browser_session: &str,
        code: &str,
        password: String,
        approve: bool,
    ) -> Result<()> {
        if browser_session.starts_with("cli_") {
            return Err("Approve from your browser".into());
        }
        let user = self
            .authenticate(browser_session)?
            .ok_or("Sign in to continue")?;
        // Reauthentication is rate-limited through the same path as normal login.
        let (temporary, _) = self.login(&user.username, password)?;
        self.logout(&temporary);
        let code = code.trim().replace('-', "").to_uppercase();
        let grant = self
            .devices
            .values_mut()
            .find(|g| g.code == code && g.expires > Instant::now())
            .ok_or("Invalid or expired CLI code")?;
        if grant.approval.is_some() || grant.denied {
            return Err("CLI request already answered".into());
        }
        grant.denied = !approve;
        if approve {
            grant.approval = Some(browser_session.into());
        }
        Ok(())
    }
    pub fn device_poll(&mut self, device: &str) -> Result<serde_json::Value> {
        let Some(grant) = self.devices.get_mut(device) else {
            return Ok(serde_json::json!({"status":"expired"}));
        };
        if grant.expires <= Instant::now() || grant.denied {
            self.devices.remove(device);
            return Ok(serde_json::json!({"status":"expired_or_denied"}));
        }
        if grant
            .last_poll
            .is_some_and(|t| t.elapsed() < Duration::from_secs(5))
        {
            return Ok(serde_json::json!({"status":"slow_down"}));
        }
        grant.last_poll = Some(Instant::now());
        let Some(approval) = grant.approval.clone() else {
            return Ok(serde_json::json!({"status":"pending"}));
        };
        let user = self.authenticate(&approval)?;
        self.devices.remove(device);
        let Some(user) = user else {
            return Ok(serde_json::json!({"status":"expired_or_denied"}));
        };
        self.sessions.retain(|_, s| s.expires > Instant::now());
        if self.sessions.len() >= 1000 {
            return Err("Too many active sessions".into());
        }
        let token = format!("cli_{}", random_id()?);
        self.sessions.insert(
            token.clone(),
            Session {
                user_id: user.id.clone(),
                expires: Instant::now() + Duration::from_secs(8 * 3600),
            },
        );
        Ok(
            serde_json::json!({"status":"approved","token":token,"user":user.public(),"expires_in":28800}),
        )
    }
    pub fn users(&self) -> Result<Vec<serde_json::Value>> {
        Ok(Self::load(&StoreFile::lock(&self.path)?)?
            .users
            .iter()
            .map(User::public)
            .collect())
    }
    pub fn groups(&self) -> Result<Vec<Group>> {
        Ok(Self::load(&StoreFile::lock(&self.path)?)?.groups)
    }
    pub fn save_group(
        &self,
        id: Option<&str>,
        name: &str,
        mut members: Vec<Membership>,
    ) -> Result<Group> {
        if !label(name) {
            return Err("Enter a group name".into());
        }
        let file = StoreFile::lock(&self.path)?;
        let mut db = Self::load(&file)?;
        if members
            .iter()
            .any(|m| !db.users.iter().any(|u| u.id == m.user_id && !u.disabled))
        {
            return Err("Select active users only".into());
        }
        members.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        if members
            .windows(2)
            .any(|pair| pair[0].user_id == pair[1].user_id)
        {
            return Err("Duplicate group member".into());
        }
        let previous = id.and_then(|id| db.groups.iter().find(|g| g.id == id));
        let changed = previous.is_some_and(|g| {
            g.members.len() != members.len()
                || g.members.iter().any(|old| {
                    !members
                        .iter()
                        .any(|m| m.user_id == old.user_id && m.edit == old.edit)
                })
        });
        let removed = previous.is_some_and(|g| {
            g.members
                .iter()
                .any(|old| !members.iter().any(|m| m.user_id == old.user_id))
        });
        let generation = match previous {
            Some(g) if changed => next_generation(g.membership_generation)?,
            Some(g) => g.membership_generation,
            None => 1,
        };
        let rotation_required = removed || previous.is_some_and(|g| g.rotation_required);
        let group = Group {
            id: match id {
                Some(id) => id.into(),
                None => random_id()?,
            },
            name: name.trim().into(),
            members,
            membership_generation: generation,
            rotation_required,
        };
        if let Some(id) = id {
            let previous = db
                .groups
                .iter_mut()
                .find(|g| g.id == id)
                .ok_or("Group not found")?;
            *previous = group.clone();
        } else {
            db.groups.push(group.clone());
        }
        file.write(&serde_json::to_vec(&db)?, false)?;
        Ok(group)
    }
    pub fn set_disabled(&mut self, actor: &User, id: &str, disabled: bool) -> Result<()> {
        if actor.id == id {
            return Err("You cannot disable your own account".into());
        }
        let file = StoreFile::lock(&self.path)?;
        let mut db = Self::load(&file)?;
        let user = db
            .users
            .iter_mut()
            .find(|u| u.id == id)
            .ok_or("User not found")?;
        let changed = user.disabled != disabled;
        user.disabled = disabled;
        if changed {
            db.identity_changed(id, disabled)?;
            self.revoke_backup_keys(id)?;
        }
        file.write(&serde_json::to_vec(&db)?, false)?;
        self.sessions.retain(|_, s| s.user_id != id);
        Ok(())
    }
    pub fn change_password(
        &mut self,
        user: &User,
        current: String,
        replacement: String,
        keep_session: &str,
    ) -> Result<()> {
        let current = Zeroizing::new(current);
        let replacement = Zeroizing::new(replacement);
        let file = StoreFile::lock(&self.path)?;
        let mut db = Self::load(&file)?;
        let saved = db
            .users
            .iter_mut()
            .find(|u| u.id == user.id)
            .ok_or("User not found")?;
        let parsed =
            PasswordHash::new(&saved.password_hash).map_err(|_| "Password change unavailable")?;
        Argon2::default()
            .verify_password(current.as_bytes(), &parsed)
            .map_err(|_| "Current password is incorrect")?;
        saved.password_hash = hash(&replacement)?;
        file.write(&serde_json::to_vec(&db)?, false)?;
        self.sessions
            .retain(|token, s| s.user_id != user.id || token == keep_session);
        Ok(())
    }
    pub fn profile(&self, user: &User, name: &str) -> Result<User> {
        if !label(name) {
            return Err("Enter a display name".into());
        }
        let file = StoreFile::lock(&self.path)?;
        let mut db = Self::load(&file)?;
        let saved = db
            .users
            .iter_mut()
            .find(|u| u.id == user.id)
            .ok_or("User not found")?;
        saved.name = name.trim().into();
        let saved = saved.clone();
        file.write(&serde_json::to_vec(&db)?, false)?;
        Ok(saved)
    }
    pub fn collections(&self, user: &User) -> Result<Vec<serde_json::Value>> {
        let mut result = vec![
            serde_json::json!({"id": user.id, "name": "Personal", "group": false, "edit": true}),
        ];
        for group in self.groups()? {
            if let Some(member) = group.members.iter().find(|m| m.user_id == user.id) {
                result.push(serde_json::json!({"id": group.id, "name": group.name, "group": true, "edit": member.edit}));
            }
        }
        Ok(result)
    }
    pub fn access(&self, user: &User, id: &str, write: bool) -> Result<bool> {
        if user.id == id {
            return Ok(true);
        }
        Ok(self.groups()?.iter().any(|g| {
            g.id == id
                && g.members
                    .iter()
                    .any(|m| m.user_id == user.id && (!write || m.edit))
        }))
    }
}

#[cfg(test)]
mod device_expiry_tests {
    use super::*;
    #[test]
    fn expired_device_cannot_be_approved_or_redeemed() {
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
        let (browser, _) = accounts
            .login("owner", "synthetic owner password".into())
            .unwrap();
        let grant = accounts.device_start().unwrap();
        let device = grant["device_code"].as_str().unwrap();
        accounts.devices.get_mut(device).unwrap().expires = Instant::now() - Duration::from_secs(1);
        assert!(
            accounts
                .device_approve(
                    &browser,
                    grant["user_code"].as_str().unwrap(),
                    "synthetic owner password".into(),
                    true
                )
                .is_err()
        );
        assert_eq!(
            accounts.device_poll(device).unwrap()["status"],
            "expired_or_denied"
        );
        assert!(!accounts.devices.contains_key(device));
    }
}
