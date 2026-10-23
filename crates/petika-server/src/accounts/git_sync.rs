//! Administrator-owned outbound Git copies. Session credentials never reach Git.
use super::{Accounts, Argon2, PasswordHash, PasswordVerifier, User, random_id};
use crate::Result;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use petika_core::StoreFile;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env, fs,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Default, Serialize, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    generation: String,
    remote: String,
    username: String,
    enabled: bool,
    schedule: String,
    interval_minutes: u64,
    nonce: Vec<u8>,
    sealed: Vec<u8>,
    pending: String,
    status: String,
    last_attempt: u64,
    last_success: u64,
    last_test: u64,
    next_run: u64,
    mirrored_fingerprint: String,
    repositories: u64,
}
#[derive(Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Credentials {
    #[serde(default)]
    token: String,
    #[serde(default)]
    ssh_private_key: String,
    #[serde(default)]
    ssh_known_hosts: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Save {
    remote: String,
    username: String,
    enabled: bool,
    schedule: String,
    interval_minutes: u64,
    credentials: Option<Credentials>,
    current_password: String,
}
impl Drop for Save {
    fn drop(&mut self) {
        self.current_password.zeroize();
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn available() -> bool {
    env::var_os("PETIKA_GIT_SYNC_SCRIPT").is_some()
        && env::var_os("PETIKA_GIT_MIRROR").is_some()
        && env::var("PETIKA_GIT_EXTERNAL_PUSH").as_deref() != Ok("1")
}
fn validate(remote: &str, username: &str) -> Result<url::Url> {
    let url = url::Url::parse(remote).map_err(|_| "Use an HTTPS or ssh:// repository URL")?;
    if remote.len() > 2048
        || remote
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
        || !matches!(url.scheme(), "https" | "ssh")
        || url.host_str().is_none_or(|host| {
            host.starts_with('-')
                || host.len() > 253
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-:[]".contains(&b))
        })
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().trim_matches('/').is_empty()
        || username.is_empty()
        || username.len() > 100
        || !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-@".contains(&b))
        || username.starts_with('-')
        || (url.scheme() == "https" && !url.username().is_empty())
        || (url.scheme() == "ssh" && url.username() != username)
    {
        return Err(
            "Use a credential-free HTTPS URL, or ssh://username@host/path; check the Git username"
                .into(),
        );
    }
    Ok(url)
}
impl Settings {
    fn load(file: &StoreFile) -> Result<Self> {
        if !file.exists() {
            return Ok(Self {
                remote: env::var("PETIKA_GIT_LEGACY_REMOTE").unwrap_or_default(),
                username: env::var("PETIKA_GIT_LEGACY_USERNAME").unwrap_or_default(),
                schedule: "change".into(),
                interval_minutes: 60,
                status: "not_configured".into(),
                ..Self::default()
            });
        }
        let s: Self = serde_json::from_slice(&file.read()?)?;
        if !s.remote.is_empty() {
            validate(&s.remote, &s.username)?;
        }
        Ok(s)
    }
    fn save(&self, file: &StoreFile) -> Result<()> {
        file.write(&serde_json::to_vec(self)?, !file.exists())?;
        Ok(())
    }
    fn public(&self) -> Value {
        json!({"remote":self.remote,"username":self.username,"enabled":self.enabled,
          "schedule":self.schedule,"interval_minutes":self.interval_minutes,"credentials_configured":!self.sealed.is_empty(),
          "available":available(),"legacy_push":env::var_os("PETIKA_GIT_LEGACY_REMOTE").is_some() && self.generation.is_empty(),"external_push":env::var("PETIKA_GIT_EXTERNAL_PUSH").as_deref()==Ok("1"),
          "status":if self.status=="running" && !self.busy() {"interrupted"} else {&self.status},"last_attempt":self.last_attempt,"last_success":self.last_success,
          "last_test":self.last_test,"repositories":self.repositories,"next_run":self.next_run})
    }
    fn busy(&self) -> bool {
        self.status == "running" && now() < self.last_attempt + 360
    }
    fn aad(&self) -> String {
        format!(
            "petika-git-credentials-v1:{}:{}",
            self.remote, self.username
        )
    }
}
impl Accounts {
    fn git_file(&self) -> Result<StoreFile> {
        Ok(StoreFile::lock(self.path.with_file_name("git-sync.json"))?)
    }
    pub fn git_manage(
        &mut self,
        user: &User,
        method: &str,
        action: &str,
        payload: Value,
    ) -> Result<Value> {
        if !user.admin || user.disabled {
            return Err("Administrator access required".into());
        }
        let file = self.git_file()?;
        let mut s = Settings::load(&file)?;
        if method == "GET" && action.is_empty() {
            return Ok(s.public());
        }
        if method != "POST" {
            return Err("Unsupported Git settings request".into());
        }
        if !available() {
            return Err("Git transfers are not enabled in this deployment; ask the operator to enable the Git worker and retire any external push job".into());
        }
        if s.busy() {
            return Err(
                "A Git operation is running. Wait for it to finish before changing settings".into(),
            );
        }
        match action {
            "" => {
                let mut request: Save =
                    serde_json::from_value(payload).map_err(|_| "Invalid Git settings")?;
                self.reserve_reauthentication()?;
                let hash = PasswordHash::new(&user.password_hash)
                    .map_err(|_| "Account verification unavailable")?;
                Argon2::default()
                    .verify_password(request.current_password.as_bytes(), &hash)
                    .map_err(|_| "Current account password is incorrect")?;
                let url = validate(&request.remote, &request.username)?;
                if !matches!(request.schedule.as_str(), "change" | "periodic" | "manual")
                    || !(1..=1440).contains(&request.interval_minutes)
                {
                    return Err(
                        "Choose a sync schedule and an interval from 1 to 1440 minutes".into(),
                    );
                }
                let changed = s.remote != request.remote || s.username != request.username;
                if changed && request.credentials.is_none() {
                    return Err("Enter credentials for the new repository or username".into());
                }
                s.remote = request.remote.clone();
                s.username = request.username.clone();
                if let Some(credentials) = request.credentials.take() {
                    let valid = if url.scheme() == "https" {
                        !credentials.token.is_empty()
                            && credentials.token.len() <= 4096
                            && !credentials.token.chars().any(char::is_control)
                            && credentials.ssh_private_key.is_empty()
                            && credentials.ssh_known_hosts.is_empty()
                    } else {
                        credentials.token.is_empty()
                            && credentials
                                .ssh_private_key
                                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
                            && credentials.ssh_private_key.len() <= 16384
                            && !credentials.ssh_known_hosts.trim().is_empty()
                            && credentials.ssh_known_hosts.len() <= 16384
                    };
                    if !valid {
                        return Err("Provide a Git token for HTTPS, or an OpenSSH private key and verified known-hosts entry for SSH".into());
                    }
                    let key = self.backup_master_key()?;
                    let cipher = XChaCha20Poly1305::new_from_slice(&key)
                        .map_err(|_| "Credential encryption unavailable")?;
                    s.nonce = vec![0; 24];
                    getrandom::getrandom(&mut s.nonce).map_err(|_| "Random source unavailable")?;
                    let plain = Zeroizing::new(serde_json::to_vec(&credentials)?);
                    s.sealed = cipher
                        .encrypt(
                            XNonce::from_slice(&s.nonce),
                            Payload {
                                msg: &plain,
                                aad: s.aad().as_bytes(),
                            },
                        )
                        .map_err(|_| "Credential encryption unavailable")?;
                    s.last_test = 0;
                }
                if s.sealed.is_empty() {
                    return Err("Configure Git authentication first".into());
                }
                if changed {
                    s.last_success = 0;
                    s.repositories = 0;
                    s.mirrored_fingerprint.clear();
                }
                s.generation = random_id()?;
                s.enabled = request.enabled;
                s.schedule = request.schedule.clone();
                s.interval_minutes = request.interval_minutes;
                s.pending.clear();
                s.status = "saved".into();
                s.next_run = now();
            }
            "test" | "sync" => {
                if s.remote.is_empty() || s.sealed.is_empty() {
                    return Err("Save repository settings and credentials first".into());
                }
                if !s.pending.is_empty() {
                    return Err("A Git operation is already queued".into());
                }
                s.pending = action.into();
                s.status = "queued".into();
            }
            _ => return Err("Unknown Git settings operation".into()),
        }
        s.save(&file)?;
        // The bundled legacy sidecar observes this marker and stops scheduling pushes.
        let mirror =
            PathBuf::from(env::var_os("PETIKA_GIT_MIRROR").ok_or("Git mirror unavailable")?);
        let marker = StoreFile::lock(mirror.join("ui-managed"))?;
        if !marker.exists() {
            marker.write(b"UI-managed Git sync\n", true)?;
        }
        Ok(s.public())
    }
    fn git_credentials(&self, s: &Settings) -> Result<Credentials> {
        if s.nonce.len() != 24 {
            return Err("Invalid credential envelope".into());
        }
        let key = self.backup_master_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| "Credential encryption unavailable")?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&s.nonce),
                    Payload {
                        msg: &s.sealed,
                        aad: s.aad().as_bytes(),
                    },
                )
                .map_err(|_| "Credential decryption failed")?,
        );
        Ok(serde_json::from_slice(&plain)?)
    }
    pub fn start_git_worker(
        data: PathBuf,
        mirror: Option<PathBuf>,
        gate: Arc<crate::maintenance_gate::MaintenanceGate>,
    ) {
        let (Some(script), Some(mirror)) = (env::var_os("PETIKA_GIT_SYNC_SCRIPT"), mirror) else {
            return;
        };
        if !available() {
            return;
        }
        thread::spawn(move || {
            let accounts = Accounts::new(data.join("accounts.json"));
            loop {
                let result = (|| -> Result<()> {
                    let guard = gate.operation().map_err(|_| "Backup capture running")?;
                    let file = accounts.git_file()?;
                    let mut s = Settings::load(&file)?;
                    if s.sealed.is_empty()
                        || s.remote.is_empty()
                        || s.busy()
                        || (s.pending.is_empty()
                            && (!s.enabled || s.schedule == "manual" || now() < s.next_run))
                    {
                        return Ok(());
                    }
                    let action = if s.pending == "test" { "test" } else { "sync" };
                    let force = !s.pending.is_empty() || s.schedule != "change";
                    s.pending.clear();
                    s.status = "running".into();
                    s.last_attempt = now();
                    s.save(&file)?;
                    drop(file);
                    let outcome=(|| -> Result<Value> {
                        let marker=StoreFile::lock(mirror.join("ui-managed"))?;
                        if !marker.exists() {marker.write(b"UI-managed Git sync\n",true)?;}
                        drop(marker);
                        let credentials=accounts.git_credentials(&s)?;
                        let root=tempfile::tempdir()?;
                        drop(guard);
                        let payload=json!({"action":action,"remote":s.remote,"username":s.username,"credentials":credentials,
                            "mirror":mirror,"fingerprint":if force {""} else {&s.mirrored_fingerprint}});
                        super::backups::push::run_script(&PathBuf::from(&script),"git",root.path(),&payload)?;
                        let bytes=fs::read(root.path().join("result.json"))?;
                        if bytes.len()>8192 {return Err("Invalid Git result".into());}
                        Ok(serde_json::from_slice(&bytes)?)
                    })().unwrap_or(json!({"status":"failed"}));
                    let _guard = gate.operation().map_err(|_| "Backup capture running")?;
                    let file = accounts.git_file()?;
                    let mut current = Settings::load(&file)?;
                    if current.generation != s.generation {
                        return Ok(());
                    }
                    let status = outcome["status"].as_str().unwrap_or("failed");
                    current.status = match status {
                        "synced" | "tested" | "unchanged" | "empty" | "connection_failed"
                        | "push_rejected" => status,
                        _ => "failed",
                    }
                    .into();
                    if status == "synced" {
                        current.last_success = now();
                        current.repositories = outcome["repositories"].as_u64().unwrap_or(0);
                        current.mirrored_fingerprint =
                            outcome["fingerprint"].as_str().unwrap_or("").into();
                    }
                    if status == "tested" {
                        current.last_test = now();
                    }
                    current.next_run = now()
                        + if current.schedule == "change" {
                            60
                        } else {
                            current.interval_minutes * 60
                        };
                    current.save(&file)
                })();
                if result.is_err() {
                    eprintln!("Git settings worker unavailable; retrying.");
                }
                thread::sleep(Duration::from_secs(5));
            }
        });
    }
}
