//! Experimental durable cleanup engine with opt-in HTTP adapters and worker wiring.
//! Key registration APIs remain pending.
//! All remote inventory pages must be obtained before claiming absence or deleting keys.
mod host;
pub(crate) mod registration;
pub mod runtime;
pub use host::ConfiguredHosts;
use petika_core::StoreFile;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

const LIMIT: usize = 4096;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_TIME: u64 = (1 << 53) - 1;
type Result<T> = crate::Result<T>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub provider: Provider,
    pub management_origin: String,
    pub repository: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Github,
    Gitea,
    ManagedSsh,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    PendingRegistration,
    Registering,
    Active,
    Revoking,
    Removed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub id: String,
    pub repository: Repository,
    pub device: String,
    pub session: String,
    pub fingerprint: String,
    pub expires_at: u64,
    pub state: State,
    pub attempts: u32,
    pub retry_at: u64,
    pub last_error: Option<Failure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<petika_core::device_keys::GitLeaseChallenge>,
}
impl Lease {
    pub fn marker(&self) -> String {
        format!("petika-lease:v1:{}", self.id)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Inventory,
    Incomplete,
    OwnershipMismatch,
    Delete,
    StillPresent,
    Registration,
}
#[derive(Clone, Debug)]
pub struct RemoteKey {
    pub id: String,
    pub marker: String,
    pub fingerprint: String,
    pub read_only: Option<bool>,
}
pub struct Inventory {
    pub keys: Vec<RemoteKey>,
    pub complete: bool,
}
/// Adapters must normalize public-key fingerprints, authenticate/pin the configured
/// host, enforce deadlines, collect all pages, and never follow credentialed redirects.
/// Error details are intentionally excluded from durable state (may contain credentials).
pub trait KeyHost {
    fn inventory(&mut self, repository: &Repository) -> std::result::Result<Inventory, Failure>;
    fn delete(&mut self, repository: &Repository, id: &str) -> std::result::Result<(), Failure>;
}
pub trait KeyRegistrar: KeyHost {
    fn authorized(&self, _repo: &Repository, _user: &str, _read_only: bool, _ttl: u64) -> bool {
        false
    }
    fn create(
        &mut self,
        repo: &Repository,
        marker: &str,
        public_key: &str,
        read_only: bool,
    ) -> std::result::Result<RemoteKey, Failure>;
}
pub enum Cleanup<'a> {
    All,
    Lease(&'a str),
    Device(&'a str),
    Session(&'a str),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    leases: Vec<Lease>,
    #[serde(default)]
    cursor: usize,
}
pub struct LeaseStore {
    file: StoreFile,
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn repository_valid(value: &Repository) -> bool {
    let Ok(url) = url::Url::parse(&value.management_origin) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/"
        && value.repository.len() <= 256
        && value.repository.split('/').count() == 2
        && value.repository.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}
impl LeaseStore {
    pub fn lock(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            file: StoreFile::lock(path)?,
        })
    }
    fn read(&self) -> Result<Ledger> {
        if !self.file.exists() {
            return Ok(Ledger {
                version: 1,
                leases: vec![],
                cursor: 0,
            });
        }
        let ledger: Ledger = serde_json::from_slice(&self.file.read_limited(MAX_BYTES)?)?;
        let mut ids = BTreeSet::new();
        if ledger.version != 1
            || ledger.leases.len() > LIMIT
            || ledger.leases.iter().any(|l| {
                !hex(&l.id)
                    || !ids.insert(&l.id)
                    || !hex(&l.device)
                    || !hex(&l.session)
                    || !hex(&l.fingerprint)
                    || !repository_valid(&l.repository)
                    || l.expires_at == 0
                    || l.expires_at > MAX_TIME
                    || l.retry_at > MAX_TIME
            })
        {
            return Err("Invalid SSH lease ledger".into());
        }
        for lease in &ledger.leases {
            if let Some(auth) = &lease.authorization
                && (auth.lease_id != lease.id
                    || auth.session_id != lease.session
                    || auth.device_id != lease.device
                    || auth.lease_expires_at != lease.expires_at
                    || auth.management_origin != lease.repository.management_origin
                    || auth.repository != lease.repository.repository
                    || auth.ssh_fingerprint()? != lease.fingerprint)
            {
                return Err("Invalid lease authorization binding".into());
            }
        }
        Ok(ledger)
    }
    fn save(&self, ledger: &Ledger) -> Result<()> {
        let bytes = serde_json::to_vec(ledger)?;
        if bytes.len() > MAX_BYTES {
            return Err("SSH lease ledger full".into());
        }
        self.file.write(&bytes, false)?;
        Ok(())
    }
    pub fn leases(&self) -> Result<Vec<Lease>> {
        Ok(self.read()?.leases)
    }
    /// Persist before the registration API is called. The remote title must be marker().
    /// Lease TTL is at most one hour; no private key or host credential is accepted here.
    pub fn prepare(
        &self,
        repository: Repository,
        device: &str,
        session: &str,
        fingerprint: &str,
        now: u64,
        ttl: u64,
    ) -> Result<Lease> {
        if !repository_valid(&repository)
            || ![device, session, fingerprint].iter().all(|s| hex(s))
            || now == 0
            || ttl == 0
            || ttl > 3600
            || now > MAX_TIME - ttl
        {
            return Err("Invalid SSH lease request".into());
        }
        let mut ledger = self.read()?;
        if ledger.leases.len() == LIMIT {
            return Err("SSH lease ledger full".into());
        }
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| "Randomness unavailable")?;
        let lease = Lease {
            id: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            repository,
            device: device.into(),
            session: session.into(),
            fingerprint: fingerprint.into(),
            expires_at: now + ttl,
            state: State::PendingRegistration,
            attempts: 0,
            retry_at: 0,
            last_error: None,
            authorization: None,
        };
        ledger.leases.push(lease.clone());
        self.save(&ledger)?;
        Ok(lease)
    }
    /// Caller must authorize this selector. It does not modify unrelated repository keys.
    pub fn request_cleanup(&self, scope: Cleanup<'_>) -> Result<usize> {
        self.request_cleanups(&[scope])
    }
    fn request_cleanups(&self, scopes: &[Cleanup<'_>]) -> Result<usize> {
        let mut ledger = self.read()?;
        let mut count = 0;
        for lease in &mut ledger.leases {
            let selected = scopes.iter().any(|scope| match scope {
                Cleanup::All => true,
                Cleanup::Lease(id) => lease.id == *id,
                Cleanup::Device(id) => lease.device == *id,
                Cleanup::Session(id) => lease.session == *id,
            });
            if selected && lease.state != State::Removed {
                lease.state = State::Revoking;
                lease.retry_at = 0;
                count += 1;
            }
        }
        self.save(&ledger)?;
        Ok(count)
    }
    /// Startup/periodic worker: examines every retained lease and reconciles registrations
    /// that succeeded remotely before a lost reply or process crash. No key is recreated.
    pub fn sweep(&self, now: u64, host: &mut impl KeyHost) -> Result<()> {
        self.sweep_batch(now, host, LIMIT)
    }
    pub fn sweep_batch(&self, now: u64, host: &mut impl KeyHost, budget: usize) -> Result<()> {
        if now == 0 || now > MAX_TIME {
            return Err("Invalid clock".into());
        }
        let mut ledger = self.read()?;
        let total = ledger.leases.len();
        let start = if total == 0 { 0 } else { ledger.cursor % total };
        for offset in 0..total.min(budget) {
            let index = (start + offset) % total;
            ledger.cursor = (index + 1) % total;
            if ledger.leases[index].retry_at > now {
                continue;
            }
            if ledger.leases[index].expires_at <= now {
                ledger.leases[index].state = State::Revoking
            }
            // Save revocation intent before any destructive remote operation.
            self.save(&ledger)?;
            let result = reconcile(&mut ledger.leases[index], host);
            match result {
                Ok(()) => {
                    ledger.leases[index].last_error = None;
                    ledger.leases[index].retry_at = 0;
                }
                Err(error) => {
                    let lease = &mut ledger.leases[index];
                    lease.attempts = lease.attempts.saturating_add(1);
                    lease.retry_at = now
                        .saturating_add(5u64 << lease.attempts.min(9))
                        .min(MAX_TIME);
                    lease.last_error = Some(error);
                }
            }
            // A write failure after deletion is uncertain; reopen and inventory on retry.
            self.save(&ledger)?;
        }
        self.save(&ledger)?;
        Ok(())
    }
}
fn inventory(
    host: &mut impl KeyHost,
    repo: &Repository,
) -> std::result::Result<Vec<RemoteKey>, Failure> {
    let snapshot = host.inventory(repo).map_err(|_| Failure::Inventory)?;
    if !snapshot.complete || snapshot.keys.len() > LIMIT {
        return Err(Failure::Incomplete);
    }
    let mut ids = BTreeSet::new();
    if snapshot
        .keys
        .iter()
        .any(|k| k.id.is_empty() || k.id.len() > 256 || !ids.insert(&k.id))
    {
        return Err(Failure::Incomplete);
    }
    Ok(snapshot.keys)
}
fn reconcile(lease: &mut Lease, host: &mut impl KeyHost) -> std::result::Result<(), Failure> {
    let keys = inventory(host, &lease.repository)?;
    let matches: Vec<_> = keys.iter().filter(|k| k.marker == lease.marker()).collect();
    // Never delete a marker collision with different key material.
    if matches.iter().any(|k| k.fingerprint != lease.fingerprint) {
        return Err(Failure::OwnershipMismatch);
    }
    if !matches!(lease.state, State::Revoking | State::Removed)
        && lease
            .authorization
            .as_ref()
            .is_some_and(|auth| matches.iter().any(|k| k.read_only != Some(auth.read_only)))
    {
        // Persist newly detected revocation before a later destructive call.
        lease.state = State::Revoking;
        return Err(Failure::Registration);
    }
    if lease.state != State::Revoking && lease.state != State::Removed {
        if !matches.is_empty() {
            lease.state = State::Active;
        }
        // An absent pending key can still be in flight; keep intent until expiry/revoke.
        // An externally removed active key is not restored; retain it for expiry cleanup.
        return Ok(());
    }
    // All matching managed copies are removed, not just the first result.
    for key in matches {
        host.delete(&lease.repository, &key.id)
            .map_err(|_| Failure::Delete)?;
    }
    if inventory(host, &lease.repository)?
        .iter()
        .any(|k| k.marker == lease.marker())
    {
        return Err(Failure::StillPresent);
    }
    lease.state = State::Removed;
    Ok(())
}

#[cfg(test)]
mod tests;
