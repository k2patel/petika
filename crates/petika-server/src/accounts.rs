//! Local identities and collection authorization. Encryption keys never enter this module.
use crate::Result;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use petika_core::StoreFile;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
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
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Database {
    #[serde(default)]
    schema_version: u32,
    users: Vec<User>,
    groups: Vec<Group>,
}
impl Default for Database {
    fn default() -> Self {
        Self {
            schema_version: 1,
            users: Vec::new(),
            groups: Vec::new(),
        }
    }
}
struct Session {
    user_id: String,
    expires: Instant,
}
pub struct Accounts {
    path: PathBuf,
    sessions: HashMap<String, Session>,
    attempts: Vec<Instant>,
    initial_snapshot: Option<String>,
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
        }
    }
    pub fn initial_snapshot(&mut self, encrypted: String) -> Result<()> {
        petika_core::validate_envelope(encrypted.as_bytes())?;
        self.initial_snapshot = Some(encrypted);
        Ok(())
    }
    fn load(file: &StoreFile) -> Result<Database> {
        if file.exists() {
            {
                let db: Database = serde_json::from_slice(&file.read()?)?;
                if db.schema_version != 1 {
                    return Err("Unsupported account schema; migration required".into());
                }
                Ok(db)
            }
        } else {
            Ok(Database::default())
        }
    }
    /// Run once before serving requests. A failed migration leaves the original intact.
    pub fn migrate(&self) -> Result<()> {
        let file = StoreFile::lock(&self.path)?;
        if !file.exists() {
            return Ok(());
        }
        let bytes = file.read()?;
        let mut db: Database = serde_json::from_slice(&bytes)?;
        match db.schema_version {
            1 => Ok(()),
            0 => {
                let backup = StoreFile::lock(self.path.with_extension("schema-0.backup"))?;
                if !backup.exists() {
                    backup.write(&bytes, true)?;
                }
                db.schema_version = 1;
                file.write(&serde_json::to_vec(&db)?, false)?;
                Ok(())
            }
            _ => Err("Account database was created by a newer schema version".into()),
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
    pub fn login(&mut self, username: &str, password: String) -> Result<(String, User)> {
        let password = Zeroizing::new(password);
        self.attempts
            .retain(|t| t.elapsed() < Duration::from_secs(60));
        if self.attempts.len() >= 20 {
            return Err("Too many sign-in attempts. Try again in a minute".into());
        }
        self.attempts.push(Instant::now());
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
        members: Vec<Membership>,
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
        let group = Group {
            id: match id {
                Some(id) => id.into(),
                None => random_id()?,
            },
            name: name.trim().into(),
            members,
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
        user.disabled = disabled;
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
