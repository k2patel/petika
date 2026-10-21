//! Server-owned push jobs. Credentials never appear in destination API responses.
use super::*;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Sealed {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct PushSettings {
    pub enabled: bool,
    pub interval_hours: u64,
    pub repository_id: String,
    pub initialize_repository: bool,
    pub sealed: Option<Sealed>,
    pub status: String,
    pub last_attempt: u64,
    pub last_success: u64,
    pub next_run: u64,
    pub snapshot_id: String,
}
impl Default for PushSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_hours: 24,
            repository_id: String::new(),
            initialize_repository: false,
            sealed: None,
            status: "disabled".into(),
            last_attempt: 0,
            last_success: 0,
            next_run: 0,
            snapshot_id: String::new(),
        }
    }
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub(super) struct Secrets {
    #[serde(default)]
    repository_password: String,
    #[serde(default)]
    access_key: String,
    #[serde(default)]
    secret_key: String,
    #[serde(default)]
    session_token: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    ssh_private_key: String,
    #[serde(default)]
    ssh_known_hosts: String,
}
impl Secrets {
    pub fn validate(&self, kind: &str) -> Result<()> {
        if !(16..=1024).contains(&self.repository_password.len())
            || self.repository_password.contains(['\n', '\r'])
        {
            return Err(KeyError::Invalid);
        }
        let valid = match kind {
            "s3" => {
                !self.access_key.is_empty()
                    && !self.secret_key.is_empty()
                    && self.ssh_private_key.is_empty()
                    && self.ssh_known_hosts.is_empty()
                    && [
                        &self.access_key,
                        &self.secret_key,
                        &self.session_token,
                        &self.region,
                    ]
                    .iter()
                    .all(|s| s.len() <= 4096 && !s.chars().any(char::is_control))
            }
            "sftp" => {
                self.ssh_private_key
                    .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
                    && !self.ssh_known_hosts.trim().is_empty()
                    && self.ssh_private_key.len() <= 16384
                    && self.ssh_known_hosts.len() <= 16384
                    && self.access_key.is_empty()
                    && self.secret_key.is_empty()
                    && self.session_token.is_empty()
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(KeyError::Invalid)
        }
    }
}
impl Accounts {
    fn backup_master_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = if let Some(path) = env::var_os("PETIKA_BACKUP_MASTER_KEY_FILE") {
            fs::read(path).map_err(|_| KeyError::Unavailable)?
        } else {
            let file = StoreFile::lock(self.path.with_file_name("backup-master.key"))
                .map_err(|_| KeyError::Unavailable)?;
            if !file.exists() {
                let mut key = Zeroizing::new(vec![0u8; 32]);
                getrandom::getrandom(&mut key).map_err(|_| KeyError::Unavailable)?;
                file.write(&key, true).map_err(|_| KeyError::Unavailable)?;
            }
            file.read().map_err(|_| KeyError::Unavailable)?
        };
        let bytes = Zeroizing::new(bytes);
        if bytes.len() != 32 {
            return Err(KeyError::Unavailable);
        }
        Ok(bytes)
    }
    pub(super) fn seal_backup_credentials(
        &self,
        owner: &str,
        id: &str,
        value: &Secrets,
    ) -> Result<Sealed> {
        let key = self.backup_master_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| KeyError::Unavailable)?;
        let mut nonce = vec![0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| KeyError::Unavailable)?;
        let plain = Zeroizing::new(serde_json::to_vec(value).map_err(|_| KeyError::Unavailable)?);
        let aad = format!("petika-push-v1:{owner}:{id}");
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| KeyError::Unavailable)?;
        Ok(Sealed { nonce, ciphertext })
    }
    fn open_backup_credentials(&self, owner: &str, id: &str, value: &Sealed) -> Result<Secrets> {
        if value.nonce.len() != 24 {
            return Err(KeyError::Unavailable);
        }
        let key = self.backup_master_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| KeyError::Unavailable)?;
        let aad = format!("petika-push-v1:{owner}:{id}");
        let bytes = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&value.nonce),
                    Payload {
                        msg: &value.ciphertext,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| KeyError::Unavailable)?,
        );
        serde_json::from_slice(&bytes).map_err(|_| KeyError::Unavailable)
    }

    /// Called by one server worker while the API and local mirror gate is held.
    fn claim_backup(&self) -> Result<Option<(String, Destination)>> {
        let accounts_file = StoreFile::lock(&self.path).map_err(|_| KeyError::Unavailable)?;
        let accounts = Self::load(&accounts_file).map_err(|_| KeyError::Unavailable)?;
        let file = self.backup_file()?;
        let mut db = BackupDatabase::load(&file)?;
        let current = now()?;
        for (owner, entries) in &mut db.destinations {
            if owner != OPERATOR && !accounts.users.iter().any(|u| u.id == *owner && !u.disabled) {
                continue;
            }
            for destination in entries {
                let settings = &mut destination.push;
                // A crash leaves a running lease; retry only after the maximum job deadline.
                if settings.status == "running"
                    && current.saturating_sub(settings.last_attempt) < 7200
                {
                    continue;
                }
                if settings.sealed.is_none()
                    || settings.next_run > current
                    || (!settings.enabled
                        && settings.status != "queued"
                        && settings.status != "running")
                {
                    continue;
                }
                settings.status = "running".into();
                settings.last_attempt = current;
                settings.next_run = current + settings.interval_hours.clamp(1, 720) * 3600;
                let result = (owner.clone(), destination.clone());
                db.save(&file)?;
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
    fn finish_backup(&self, owner: &str, id: &str, result: &Value) -> Result<()> {
        let file = self.backup_file()?;
        let mut db = BackupDatabase::load(&file)?;
        let destination = db
            .destinations
            .get_mut(owner)
            .and_then(|v| v.iter_mut().find(|d| d.id == id))
            .ok_or(KeyError::NotFound)?;
        let push = &mut destination.push;
        if let Some(repository_id) = result["repository_id"]
            .as_str()
            .filter(|id| keys::valid_id(id))
            && push.repository_id.is_empty()
        {
            push.repository_id = repository_id.into();
            push.initialize_repository = false;
        }
        let snapshot = result["snapshot_id"]
            .as_str()
            .filter(|id| keys::valid_id(id));
        if let Some(snapshot) = snapshot.filter(|_| result["verified"] == true) {
            push.status = "verified".into();
            push.last_success = now()?;
            push.snapshot_id = snapshot.into();
        } else {
            push.status = "failed".into();
        }
        db.save(&file)
    }

    fn capture_push(
        &self,
        owner: &str,
        root: &Path,
        script: &Path,
        data: &Path,
        mirror: Option<&Path>,
    ) -> crate::Result<()> {
        if owner == OPERATOR {
            let mirror = mirror.ok_or("Full backup requires the local mirror")?;
            fs::create_dir_all(mirror)?;
            let release = env::var("PETIKA_BACKUP_RELEASE")
                .map_err(|_| "Full backup requires PETIKA_BACKUP_RELEASE")?;
            if release.is_empty() {
                return Err("Empty backup release".into());
            }
            let config = root.join("configuration");
            fs::create_dir(&config)?;
            StoreFile::lock(config.join("backup-master.key"))?
                .write(&self.backup_master_key()?, true)?;
            let token_path = env::var_os("PETIKA_TOKEN_FILE").ok_or("Token file missing")?;
            let token = Zeroizing::new(fs::read(token_path)?);
            StoreFile::lock(config.join("token"))?.write(&token, true)?;
            let settings: BTreeMap<_, _> = [
                "PETIKA_ENDPOINT",
                "PETIKA_COOKIE_SECURE",
                "PETIKA_LISTEN",
                "PETIKA_SETUP_MODE",
                "PETIKA_BACKUP_RELEASE",
            ]
            .iter()
            .filter_map(|name| env::var(name).ok().map(|v| (name.to_string(), v)))
            .collect();
            write_private(&config.join("server-settings.json"), &json!(settings))?;
            run_script(
                script,
                "capture-server",
                root,
                &json!({"data":data,"mirror":mirror,"config":config,"release":release}),
            )?;
        } else {
            let bundle = root.join("bundle");
            fs::create_dir(&bundle)?;
            fs::create_dir(bundle.join("collections"))?;
            let index = self.backup_owner_export(owner, None)?;
            write_private(&bundle.join("index.json"), &index)?;
            for collection in index["collections"]
                .as_array()
                .ok_or("Invalid collection list")?
            {
                let id = collection["id"].as_str().ok_or("Invalid collection ID")?;
                let value = self.backup_owner_export(owner, Some(id))?;
                write_private(
                    &bundle.join("collections").join(format!("{id}.json")),
                    &value,
                )?;
            }
            run_script(script, "capture-user", root, &json!({}))?;
        }
        Ok(())
    }

    /// Same-process scheduler; no external runner or user API credential is required.
    pub fn start_backup_worker(
        data: PathBuf,
        mirror: Option<PathBuf>,
        gate: Arc<crate::maintenance_gate::MaintenanceGate>,
    ) {
        let Some(script) = env::var_os("PETIKA_BACKUP_SCRIPT").map(PathBuf::from) else {
            return;
        };
        thread::spawn(move || {
            let accounts = Accounts::new(data.join("accounts.json"));
            loop {
                let outcome = (|| -> crate::Result<()> {
                    let guard = gate.capture().map_err(|_| "Backup gate unavailable")?;
                    let Some((owner, destination)) = accounts.claim_backup()? else {
                        return Ok(());
                    };
                    // Record every failure, including staging/credential failures, without secret diagnostics.
                    let result=(|| -> crate::Result<Value> {
                        let root=if let Some(parent)=env::var_os("PETIKA_BACKUP_WORK_DIR") { tempfile::tempdir_in(parent)? } else { tempfile::tempdir()? };
                        let credentials=accounts.open_backup_credentials(&owner,&destination.id,destination.push.sealed.as_ref().ok_or("Credentials missing")?)?;
                        accounts.capture_push(&owner,root.path(),&script,&data,mirror.as_deref())?;
                        drop(guard); // Network transfer never holds the API/mirror gate.
                        let payload=json!({"owner":owner,"destination":destination.public(),"credentials":credentials});
                        let run=run_script(&script,"push",root.path(),&payload);
                        // Even a failed publish can have initialized a repository; preserve its ID.
                        let result=fs::read(root.path().join("result.json")).ok().and_then(|v|serde_json::from_slice(&v).ok()).unwrap_or(json!({"verified":false}));
                        let _=run;
                        Ok(result)
                    })().unwrap_or(json!({"verified":false}));
                    let _guard = gate.capture().map_err(|_| "Backup gate unavailable")?;
                    accounts.finish_backup(&owner, &destination.id, &result)?;
                    Ok(())
                })();
                if outcome.is_err() {
                    eprintln!("Backup worker retry pending; check destination status.");
                }
                thread::sleep(Duration::from_secs(5));
            }
        });
    }
}
fn write_private(path: &Path, value: &Value) -> crate::Result<()> {
    // StoreFile leaves a lock file, which is harmless for server state but not a user bundle.
    use std::fs::OpenOptions;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    Ok(())
}
fn run_script(script: &Path, action: &str, root: &Path, value: &Value) -> crate::Result<()> {
    let mut command =
        Command::new(env::var_os("PETIKA_BACKUP_PYTHON").unwrap_or_else(|| "python3".into()));
    command
        .arg(script)
        .arg(action)
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let bytes = Zeroizing::new(serde_json::to_vec(value)?);
    // Payloads contain credentials, never command-line arguments or logs.
    let written = child
        .stdin
        .take()
        .ok_or("Missing worker stdin")?
        .write_all(&bytes);
    if written.is_err() {
        stop_worker(&mut child);
        return Err("Backup worker input failed".into());
    }
    let deadline = Instant::now() + Duration::from_secs(if action == "push" { 6900 } else { 300 });
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err("Backup worker failed".into())
            };
        }
        if Instant::now() >= deadline {
            stop_worker(&mut child);
            return Err("Backup worker timed out".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn stop_worker(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // Child starts a dedicated process group; stop Python and its restic/SSH descendants.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_credentials_reject_other_owners_destinations_and_corruption() {
        let root = tempfile::tempdir().unwrap();
        let accounts = Accounts::new(root.path().join("accounts.json"));
        let secrets = Secrets {
            repository_password: "synthetic repository password".into(),
            access_key: "access".into(),
            secret_key: "secret".into(),
            session_token: String::new(),
            region: String::new(),
            ssh_private_key: String::new(),
            ssh_known_hosts: String::new(),
        };
        let mut sealed = accounts
            .seal_backup_credentials("alice", "destination-a", &secrets)
            .unwrap();
        assert!(
            accounts
                .open_backup_credentials("alice", "destination-a", &sealed)
                .is_ok()
        );
        assert!(
            accounts
                .open_backup_credentials("bob", "destination-a", &sealed)
                .is_err()
        );
        assert!(
            accounts
                .open_backup_credentials("alice", "destination-b", &sealed)
                .is_err()
        );
        sealed.ciphertext[0] ^= 1;
        assert!(
            accounts
                .open_backup_credentials("alice", "destination-a", &sealed)
                .is_err()
        );
    }

    #[test]
    fn scheduler_skips_disabled_users_and_holds_a_running_lease() {
        let root = tempfile::tempdir().unwrap();
        let mut accounts = Accounts::new(root.path().join("accounts.json"));
        accounts.migrate().unwrap();
        let alice = accounts
            .create_user(
                "alice",
                "Alice",
                "synthetic account password".into(),
                true,
                true,
            )
            .unwrap();
        let bob = accounts
            .create_user(
                "bob",
                "Bob",
                "synthetic account password".into(),
                false,
                false,
            )
            .unwrap();
        let (session, _) = accounts
            .login("bob", "synthetic account password".into())
            .unwrap();
        let saved=accounts.backup_manage(&session,false,"POST","destinations",json!({"name":"S3","kind":"s3","repository":"s3:https://offsite.example/bucket","enabled":true,"initialize_repository":true,"credentials":{"repository_password":"synthetic repository password","access_key":"access","secret_key":"secret"}})).unwrap();
        assert!(accounts.claim_backup().unwrap().is_none());
        accounts
            .backup_manage(
                &session,
                false,
                "POST",
                &format!("destinations/{}/run", saved["id"].as_str().unwrap()),
                json!({}),
            )
            .unwrap();
        accounts.set_disabled(&alice, &bob.id, true).unwrap();
        assert!(accounts.claim_backup().unwrap().is_none());
        accounts.set_disabled(&alice, &bob.id, false).unwrap();
        let (_, claimed) = accounts.claim_backup().unwrap().unwrap();
        assert_eq!(claimed.push.status, "running");
        assert!(accounts.claim_backup().unwrap().is_none());
        let (session, _) = accounts
            .login("bob", "synthetic account password".into())
            .unwrap();
        assert!(accounts.backup_manage(&session,false,"POST","destinations",json!({"id":saved["id"],"name":"Other","kind":"s3","repository":"s3:https://different.example/bucket"})).is_err());
        accounts
            .finish_backup(&bob.id, &claimed.id, &json!({"verified":false}))
            .unwrap();
        assert!(accounts.claim_backup().unwrap().is_none());
    }
}
