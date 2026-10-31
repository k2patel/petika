//! Candidate transport-lease authorization. A signature is not biometric evidence.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitLeaseChallenge {
    pub version: u32,
    pub lease_id: String,
    pub operation_id: String,
    pub deployment_id: String,
    pub user_id: String,
    pub session_id: String,
    pub device_id: String,
    pub device_fingerprint: String,
    pub roster_digest: String,
    pub management_origin: String,
    pub repository: String,
    /// Raw Ed25519 verification key, canonical base64. Private SSH keys stay local.
    pub ssh_public_key: String,
    pub read_only: bool,
    pub issued_at: u64,
    pub challenge_expires_at: u64,
    pub lease_expires_at: u64,
}
impl GitLeaseChallenge {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.version != 1
            || [
                &self.lease_id,
                &self.operation_id,
                &self.deployment_id,
                &self.user_id,
                &self.session_id,
                &self.device_id,
                &self.device_fingerprint,
                &self.roster_digest,
            ]
            .iter()
            .any(|s| !id(s))
            || self.issued_at == 0
            || self.lease_expires_at > MAX_GENERATION
            || self.challenge_expires_at <= self.issued_at
            || self.challenge_expires_at - self.issued_at > 60
            || self.lease_expires_at < self.challenge_expires_at
            || self.lease_expires_at - self.issued_at > 3600
            || !self.management_origin.starts_with("https://")
            || self.management_origin.len() > 2048
            || self
                .management_origin
                .bytes()
                .any(|b| !b.is_ascii_graphic())
            || self.repository.len() > 256
            || self.repository.split('/').count() != 2
            || self.repository.split('/').any(|p| {
                p.is_empty()
                    || p == "."
                    || p == ".."
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            return Err(Error::Format);
        }
        signing_key(&self.ssh_public_key)?;
        let mut out = Vec::new();
        field(&mut out, b"petika:git-ssh-lease:experimental-v1");
        out.extend_from_slice(&self.version.to_be_bytes());
        for value in [
            &self.lease_id,
            &self.operation_id,
            &self.deployment_id,
            &self.user_id,
            &self.session_id,
            &self.device_id,
            &self.device_fingerprint,
            &self.roster_digest,
            &self.management_origin,
            &self.repository,
        ] {
            field(&mut out, value.as_bytes());
        }
        field(&mut out, &decode(&self.ssh_public_key, 32)?);
        out.push(u8::from(self.read_only));
        for value in [
            self.issued_at,
            self.challenge_expires_at,
            self.lease_expires_at,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        Ok(out)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hash(&self.canonical_bytes()?))
    }
    pub fn ssh_wire(&self) -> Result<Vec<u8>> {
        self.canonical_bytes()?;
        let mut out = Vec::new();
        field(&mut out, b"ssh-ed25519");
        field(&mut out, &decode(&self.ssh_public_key, 32)?);
        Ok(out)
    }
    pub fn openssh_public_key(&self) -> Result<String> {
        Ok(format!("ssh-ed25519 {}", STANDARD.encode(self.ssh_wire()?)))
    }
    pub fn ssh_fingerprint(&self) -> Result<String> {
        Ok(hash(&self.ssh_wire()?))
    }
    fn active<'a>(&self, current: &'a TrustedDeviceRoster, now: u64) -> Result<&'a DeviceRecord> {
        self.canonical_bytes()?;
        let roster = current.roster();
        if self.deployment_id != roster.authority.deployment_id
            || self.user_id != roster.authority.user_id
            || self.roster_digest != roster.digest()?
            || now < self.issued_at
            || now >= self.challenge_expires_at
        {
            return Err(Error::Authentication);
        }
        if roster.authority.signing_public_key == self.ssh_public_key
            || roster
                .devices
                .iter()
                .any(|d| d.signing_public_key == self.ssh_public_key)
        {
            return Err(Error::Authentication);
        }
        roster
            .devices
            .iter()
            .find(|d| d.device_id == self.device_id && d.fingerprint == self.device_fingerprint)
            .ok_or(Error::Authentication)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitLeaseProof {
    pub challenge: GitLeaseChallenge,
    pub device_signature: String,
    pub ssh_signature: String,
}
fn message(domain: &[u8], challenge: &GitLeaseChallenge) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    field(&mut out, domain);
    field(&mut out, challenge.digest()?.as_bytes());
    Ok(out)
}
impl GitLeaseProof {
    pub fn verify(&self, current: &TrustedDeviceRoster, now: u64) -> Result<()> {
        let device = self.challenge.active(current, now)?;
        verify(
            &device.signing_public_key,
            &message(
                b"petika:git-ssh-lease-device-proof:experimental-v1",
                &self.challenge,
            )?,
            &self.device_signature,
        )?;
        verify(
            &self.challenge.ssh_public_key,
            &message(
                b"petika:git-ssh-lease-key-proof:experimental-v1",
                &self.challenge,
            )?,
            &self.ssh_signature,
        )
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        parse(bytes, 16384)
    }
}
impl DeviceIdentity {
    /// Call only after the user confirms the configured remote scope. Transport proof
    /// does not decrypt vault data and does not establish biometric-only execution.
    pub fn authorize_git_lease(
        &self,
        challenge: GitLeaseChallenge,
        current: &TrustedDeviceRoster,
        confirmed_origin: &str,
        confirmed_repository: &str,
        ssh_seed: &[u8; 32],
        now: u64,
    ) -> Result<GitLeaseProof> {
        let active = challenge.active(current, now)?;
        let ssh = SigningKey::from_bytes(ssh_seed);
        if active != &self.public_record()?
            || challenge.management_origin != confirmed_origin
            || challenge.repository != confirmed_repository
            || STANDARD.encode(ssh.verifying_key().as_bytes()) != challenge.ssh_public_key
        {
            return Err(Error::Authentication);
        }
        let proof = GitLeaseProof {
            device_signature: STANDARD.encode(
                SigningKey::from_bytes(&self.signing_seed)
                    .sign(&message(
                        b"petika:git-ssh-lease-device-proof:experimental-v1",
                        &challenge,
                    )?)
                    .to_bytes(),
            ),
            ssh_signature: STANDARD.encode(
                ssh.sign(&message(
                    b"petika:git-ssh-lease-key-proof:experimental-v1",
                    &challenge,
                )?)
                .to_bytes(),
            ),
            challenge,
        };
        proof.verify(current, now)?;
        Ok(proof)
    }
}

#[cfg(test)]
mod tests;
