//! Candidate native transport coordinator, disabled by default.
//!
//! A custodian must authenticate and encrypt the draft. No production custodian,
//! vault-secret access, native IPC, or biometric guarantee is supplied here.
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use petika_core::{
    StoreFile,
    device_keys::{DeviceIdentity, GitLeaseChallenge, GitLeaseProof, TrustedDeviceRoster},
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
mod agent;
pub mod http;
pub mod ssh;

const LIMIT: usize = 16384;
const PURPOSE: &[u8] = b"petika:native-git-lease-draft:experimental-v1";
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid or mismatched lease data")]
    Invalid,
    #[error("Lease storage unavailable; reopen and reconcile before continuing")]
    Storage,
    #[error("Lease service unavailable; reconcile before retrying")]
    Service,
    #[error("Lease phase does not permit this action")]
    Phase,
    #[error("Lease expired or challenge no longer valid")]
    Expired,
    #[error("Native SSH agent unavailable")]
    Agent,
    #[error("Transfer result uncertain; reconcile Git before another attempt")]
    Transfer,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Trusted native boundary: authenticated encryption with purpose separation,
/// protected wrapping-key custody, fresh approval when policy requires it, and
/// bounded output. Implementations must never persist plaintext or use passwords
/// as an alternative to the required biometric policy. There is no default impl.
pub trait DraftCustody {
    fn seal(&mut self, purpose: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    fn open(&mut self, purpose: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContext {
    pub deployment_id: String,
    pub user_id: String,
    pub session_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Canonical HTTPS Petika origin, independent of the Git management origin.
    pub server_origin: String,
    pub session: SessionContext,
    pub device_id: String,
    pub device_fingerprint: String,
    pub roster_digest: String,
    pub provider: Provider,
    pub management_origin: String,
    pub repository: String,
    pub read_only: bool,
    pub ttl: u64,
    /// Independently confirmed SSH endpoint/host key, retained before admission.
    /// Older drafts can be reconciled/cleaned up but cannot fetch without it.
    #[serde(default)]
    pub ssh_remote: Option<ssh::PinnedRemote>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Github,
    Gitea,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub operation_id: String,
    pub scope: Scope,
    pub ssh_public_key: String,
    pub created_at: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteState {
    PendingRegistration,
    Registering,
    Active,
    Revoking,
    Removed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub lease_id: String,
    pub operation_id: String,
    pub state: RemoteState,
    pub expires_at: u64,
    pub challenge: GitLeaseChallenge,
    // Server diagnostic is metadata, never displayed as trusted instructions.
    pub last_error: Option<String>,
}
/// Calls must use the same authenticated session and fixed HTTPS origin. A
/// missing operation is distinct from network/authentication failure. Passwords
/// are requested only for challenge/registration, never kept in a draft.
pub trait LeaseService {
    fn origin(&self) -> &str;
    fn challenge(&mut self, intent: &Intent) -> Result<GitLeaseChallenge>;
    fn lookup(&mut self, operation_id: &str) -> Result<Option<Status>>;
    fn register(&mut self, proof: &GitLeaseProof) -> Result<()>;
    fn complete(&mut self, lease_id: &str) -> Result<()>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    ChallengeRequested,
    ChallengeAccepted,
    Authorized,
    RegistrationStarted,
    Active,
    TransferStarted,
    CleanupPending,
    Removed,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    version: u32,
    intent: Intent,
    seed: Option<[u8; 32]>,
    challenge: Option<GitLeaseChallenge>,
    proof: Option<GitLeaseProof>,
    phase: Phase,
}
impl Drop for Draft {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}
/// Holds an exclusive local lock for one operation. A failed write poisons the
/// instance, including errors after atomic replacement; reopen to learn outcome.
pub struct Operation<C: DraftCustody> {
    file: StoreFile,
    custody: C,
    draft: Draft,
    poisoned: bool,
}
fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn random() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Storage)?;
    Ok(bytes)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl Intent {
    fn check(&self, c: &GitLeaseChallenge) -> Result<()> {
        c.canonical_bytes().map_err(|_| Error::Invalid)?;
        let s = &self.scope;
        if c.operation_id != self.operation_id
            || c.deployment_id != s.session.deployment_id
            || c.user_id != s.session.user_id
            || c.session_id != s.session.session_id
            || c.device_id != s.device_id
            || c.device_fingerprint != s.device_fingerprint
            || c.roster_digest != s.roster_digest
            || c.management_origin != s.management_origin
            || c.repository != s.repository
            || c.ssh_public_key != self.ssh_public_key
            || c.read_only != s.read_only
            || c.lease_expires_at - c.issued_at != s.ttl
            || c.issued_at < self.created_at
            || c.issued_at > self.created_at.saturating_add(60)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        // Management origins also become public server-side authorization
        // metadata; never retain/send credentials embedded in their URL.
        http::origin(&self.scope.management_origin)?;
        if let Some(remote) = &self.scope.ssh_remote {
            remote.validate(&self.scope.repository)?;
        }
        if !id(&self.operation_id)
            || !(60..=3600).contains(&self.scope.ttl)
            || http::origin(&self.scope.server_origin)? != self.scope.server_origin
        {
            return Err(Error::Invalid);
        }
        // Reuse the wire validator for all account/scope/key bounds.
        let s = &self.scope;
        self.check(&GitLeaseChallenge {
            version: 1,
            lease_id: "0".repeat(64),
            operation_id: self.operation_id.clone(),
            deployment_id: s.session.deployment_id.clone(),
            user_id: s.session.user_id.clone(),
            session_id: s.session.session_id.clone(),
            device_id: s.device_id.clone(),
            device_fingerprint: s.device_fingerprint.clone(),
            roster_digest: s.roster_digest.clone(),
            management_origin: s.management_origin.clone(),
            repository: s.repository.clone(),
            ssh_public_key: self.ssh_public_key.clone(),
            read_only: s.read_only,
            issued_at: self.created_at,
            challenge_expires_at: self.created_at.checked_add(60).ok_or(Error::Invalid)?,
            lease_expires_at: self.created_at.checked_add(s.ttl).ok_or(Error::Invalid)?,
        })
    }
}
impl<C: DraftCustody> Operation<C> {
    pub fn create(path: impl AsRef<Path>, custody: C, scope: Scope, now: u64) -> Result<Self> {
        let seed = Zeroizing::new(random()?);
        let intent = Intent {
            operation_id: hex(&random()?),
            scope,
            ssh_public_key: STANDARD
                .encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes()),
            created_at: now,
        };
        intent.validate()?;
        let file = StoreFile::lock(path).map_err(|_| Error::Storage)?;
        let mut op = Self {
            file,
            custody,
            draft: Draft {
                version: 1,
                intent,
                seed: Some(*seed),
                challenge: None,
                proof: None,
                phase: Phase::Prepared,
            },
            poisoned: false,
        };
        op.persist(true)?;
        Ok(op)
    }
    pub fn resume(path: impl AsRef<Path>, mut custody: C) -> Result<Self> {
        let file = StoreFile::lock(path).map_err(|_| Error::Storage)?;
        let ciphertext = file.read_limited(LIMIT * 2).map_err(|_| Error::Storage)?;
        let plaintext = custody.open(PURPOSE, &ciphertext)?;
        if plaintext.len() > LIMIT {
            return Err(Error::Invalid);
        }
        let draft: Draft = serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
        draft.intent.validate()?;
        if draft.version != 1 || (draft.phase == Phase::Removed) != draft.seed.is_none() {
            return Err(Error::Invalid);
        }
        if let Some(seed) = &draft.seed
            && STANDARD.encode(SigningKey::from_bytes(seed).verifying_key().as_bytes())
                != draft.intent.ssh_public_key
        {
            return Err(Error::Invalid);
        }
        if let Some(challenge) = &draft.challenge {
            draft.intent.check(challenge)?;
        }
        if let Some(proof) = &draft.proof
            && draft.challenge.as_ref() != Some(&proof.challenge)
        {
            return Err(Error::Invalid);
        }
        if matches!(
            draft.phase,
            Phase::Authorized | Phase::RegistrationStarted | Phase::Active | Phase::TransferStarted
        ) && draft.proof.is_none()
        {
            return Err(Error::Invalid);
        }
        if matches!(draft.phase, Phase::ChallengeAccepted) && draft.challenge.is_none() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            file,
            custody,
            draft,
            poisoned: false,
        })
    }
    pub fn intent(&self) -> &Intent {
        &self.draft.intent
    }
    pub fn phase(&self) -> Phase {
        self.draft.phase
    }
    fn usable(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::Storage)
        } else {
            Ok(())
        }
    }
    fn persist(&mut self, create: bool) -> Result<()> {
        self.usable()?;
        // Poison before serialization/sealing/writing: a custody/write failure
        // cannot leave an in-memory phase ahead of the durable phase.
        self.poisoned = true;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(LIMIT));
        serde_json::to_writer(&mut *plaintext, &self.draft).map_err(|_| Error::Storage)?;
        if plaintext.len() > LIMIT {
            return Err(Error::Storage);
        }
        let ciphertext = Zeroizing::new(self.custody.seal(PURPOSE, &plaintext)?);
        if ciphertext.len() > LIMIT * 2 {
            return Err(Error::Storage);
        }
        self.file
            .write(&ciphertext, create)
            .map_err(|_| Error::Storage)?;
        self.poisoned = false;
        Ok(())
    }
    fn service(&self, service: &impl LeaseService) -> Result<()> {
        self.usable()?;
        if service.origin() != self.draft.intent.scope.server_origin {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn checked_status(&self, service: &mut impl LeaseService) -> Result<Option<Status>> {
        self.service(service)?;
        let status = service.lookup(&self.draft.intent.operation_id)?;
        if let Some(s) = &status {
            self.draft.intent.check(&s.challenge)?;
            if s.lease_id != s.challenge.lease_id
                || s.operation_id != self.draft.intent.operation_id
                || s.expires_at != s.challenge.lease_expires_at
                || self
                    .draft
                    .challenge
                    .as_ref()
                    .is_some_and(|c| c != &s.challenge)
            {
                return Err(Error::Invalid);
            }
        }
        Ok(status)
    }
    /// Lost challenge replies are looked up before retrying the same operation.
    pub fn request_challenge(&mut self, service: &mut impl LeaseService, now: u64) -> Result<()> {
        let started = std::time::Instant::now();
        self.service(service)?;
        if !matches!(self.phase(), Phase::Prepared | Phase::ChallengeRequested) {
            return Err(Error::Phase);
        }
        if now < self.draft.intent.created_at
            || now > self.draft.intent.created_at.saturating_add(60)
        {
            return Err(Error::Expired);
        }
        let challenge = if self.phase() == Phase::ChallengeRequested {
            match self.checked_status(service)? {
                Some(s) if s.state == RemoteState::PendingRegistration => s.challenge,
                Some(_) => return Err(Error::Phase),
                None => service.challenge(&self.draft.intent)?,
            }
        } else {
            self.draft.phase = Phase::ChallengeRequested;
            self.persist(false)?;
            service.challenge(&self.draft.intent)?
        };
        self.draft.intent.check(&challenge)?;
        let latest = now.saturating_add(started.elapsed().as_secs().saturating_add(1));
        if latest < challenge.issued_at || latest >= challenge.challenge_expires_at {
            return Err(Error::Expired);
        }
        self.draft.challenge = Some(challenge);
        self.draft.phase = Phase::ChallengeAccepted;
        self.persist(false)
    }
    /// Device custody/approval is a separate trusted boundary. This method proves
    /// possession; it does not certify biometric approval or access vault data.
    pub fn authorize(
        &mut self,
        device: &DeviceIdentity,
        current: &TrustedDeviceRoster,
        now: u64,
    ) -> Result<()> {
        self.usable()?;
        if self.phase() != Phase::ChallengeAccepted {
            return Err(Error::Phase);
        }
        let c = self.draft.challenge.clone().ok_or(Error::Invalid)?;
        self.draft.intent.check(&c)?;
        let scope = &self.draft.intent.scope;
        let proof = device
            .authorize_git_lease(
                c,
                current,
                &scope.management_origin,
                &scope.repository,
                self.draft.seed.as_ref().ok_or(Error::Invalid)?,
                now,
            )
            .map_err(|_| Error::Invalid)?;
        self.draft.proof = Some(proof);
        self.draft.phase = Phase::Authorized;
        self.persist(false)
    }
    /// Always reconcile first. A registering/unknown remote result is never
    /// blindly reissued. Only an exact pending intent can be submitted again.
    pub fn register(&mut self, service: &mut impl LeaseService, now: u64) -> Result<()> {
        let started = std::time::Instant::now();
        self.service(service)?;
        if !matches!(
            self.phase(),
            Phase::Authorized | Phase::RegistrationStarted | Phase::Active
        ) {
            return Err(Error::Phase);
        }
        let s = self.checked_status(service)?.ok_or(Error::Invalid)?;
        if now.saturating_add(started.elapsed().as_secs().saturating_add(1)) >= s.expires_at {
            return Err(Error::Expired);
        }
        match s.state {
            RemoteState::Active if self.phase() != Phase::Authorized => {
                self.draft.phase = Phase::Active;
                self.persist(false)
            }
            RemoteState::PendingRegistration if self.phase() != Phase::Active => {
                let proof = self.draft.proof.as_ref().ok_or(Error::Invalid)?;
                if now < proof.challenge.issued_at
                    || now.saturating_add(started.elapsed().as_secs().saturating_add(1))
                        >= proof.challenge.challenge_expires_at
                {
                    return Err(Error::Expired);
                }
                self.draft.phase = Phase::RegistrationStarted;
                self.persist(false)?;
                service.register(self.draft.proof.as_ref().ok_or(Error::Invalid)?)?;
                let s = self.checked_status(service)?.ok_or(Error::Invalid)?;
                if s.state != RemoteState::Active {
                    return Err(Error::Phase);
                }
                if now.saturating_add(started.elapsed().as_secs().saturating_add(1)) >= s.expires_at
                {
                    return Err(Error::Expired);
                }
                self.draft.phase = Phase::Active;
                self.persist(false)
            }
            _ => Err(Error::Phase),
        }
    }
    /// Record BEFORE starting an external transfer. A reopened TransferStarted
    /// operation is deliberately not reusable: reconcile Git and clean it up.
    fn mark_transfer_started(&mut self, service: &mut impl LeaseService, now: u64) -> Result<()> {
        let started = std::time::Instant::now();
        self.service(service)?;
        if self.phase() != Phase::Active {
            return Err(Error::Phase);
        }
        let s = self.checked_status(service)?.ok_or(Error::Invalid)?;
        if s.state != RemoteState::Active {
            return Err(Error::Phase);
        }
        if now < s.challenge.issued_at
            || now.saturating_add(started.elapsed().as_secs().saturating_add(1)) >= s.expires_at
        {
            return Err(Error::Expired);
        }
        self.draft.phase = Phase::TransferStarted;
        self.persist(false)
    }
    /// Persist cleanup intent before the call, including when the original
    /// challenge reply was lost. Retain the encrypted key until Removed observed.
    pub fn cleanup(&mut self, service: &mut impl LeaseService) -> Result<()> {
        self.service(service)?;
        if self.phase() == Phase::Removed {
            return Ok(());
        }
        self.draft.phase = Phase::CleanupPending;
        self.persist(false)?;
        let status = self.checked_status(service)?;
        match status {
            Some(s) if s.state == RemoteState::Removed => self.forget(),
            Some(s) => service.complete(&s.lease_id),
            // No known challenge does not prove a delayed in-flight challenge
            // cannot arrive. Retain intent; server expiry handles orphan intents.
            None => Err(Error::Service),
        }
    }
    fn forget(&mut self) -> Result<()> {
        self.draft.seed.zeroize();
        self.draft.seed = None;
        self.draft.proof = None;
        self.draft.phase = Phase::Removed;
        self.persist(false)
    }
    /// A private, short-lived SSH agent receives the seed over its Unix socket.
    /// The callback sees only the socket and public identity. It MUST enforce
    /// explicit SSH host-key pins and ciphertext-only Git protocol rules. This
    /// reference seam does not implement or validate Git-authoritative history.
    #[cfg(unix)]
    pub(crate) fn transfer<T>(
        &mut self,
        service: &mut impl LeaseService,
        now: u64,
        job: impl FnOnce(&Path, &str) -> Result<T>,
    ) -> Result<T> {
        let started = std::time::Instant::now();
        self.mark_transfer_started(service, now)?;
        let result = (|| {
            let c = self.draft.challenge.as_ref().ok_or(Error::Invalid)?;
            let agent = agent::Agent::start(
                self.draft.seed.as_ref().ok_or(Error::Invalid)?,
                c.lease_expires_at
                    .saturating_sub(now)
                    .saturating_sub(started.elapsed().as_secs().saturating_add(1)),
            )?;
            job(
                agent.socket(),
                &c.openssh_public_key().map_err(|_| Error::Invalid)?,
            )
        })();
        // Agent is gone before remote cleanup. Preserve the transfer outcome,
        // but never allow another transfer when cleanup is uncertain.
        let cleanup = self.cleanup(service);
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            _ => Err(Error::Transfer),
        }
    }
}

#[cfg(test)]
mod tests;
