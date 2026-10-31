//! Explicit continuity from an enrolled legacy identity to a separate device authority.
use super::*;
use crate::device_keys::DeviceRoster;

pub const MAX_DEVICE_BOOTSTRAP_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorityBootstrap {
    pub bootstrap_version: u32,
    pub source_bundle_revision: u64,
    pub legacy_identity: PublicIdentity,
    pub initial_roster: DeviceRoster,
    pub signature: String,
}
impl DeviceAuthorityBootstrap {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let legacy = &self.legacy_identity;
        let roster = &self.initial_roster;
        legacy.validate()?;
        roster.validate()?;
        if self.bootstrap_version != 1
            || !(1..=MAX_COUNTER).contains(&self.source_bundle_revision)
            || roster.generation != 1
            || !roster.devices.is_empty()
            || !roster.revoked_device_ids.is_empty()
            || !roster.parent_digest.is_empty()
            || roster.authority.deployment_id != legacy.deployment_id
            || roster.authority.user_id != legacy.user_id
            || roster.authority.signing_public_key == legacy.signing_public_key
        {
            return Err(Error::Authentication);
        }
        let mut bytes = Vec::new();
        field(
            &mut bytes,
            b"petika:device-authority-bootstrap:experimental-v1",
        );
        bytes.extend_from_slice(&self.bootstrap_version.to_be_bytes());
        field(&mut bytes, legacy.deployment_id.as_bytes());
        field(&mut bytes, legacy.user_id.as_bytes());
        bytes.extend_from_slice(&self.source_bundle_revision.to_be_bytes());
        bytes.extend_from_slice(&legacy.identity_version.to_be_bytes());
        field(&mut bytes, legacy.fingerprint.as_bytes());
        field(&mut bytes, roster.authority.fingerprint.as_bytes());
        field(&mut bytes, roster.digest()?.as_bytes());
        Ok(bytes)
    }
    /// Signature consistency only. Callers must independently confirm the new authority
    /// and compare the source identity/revision with the authenticated enrolled state.
    pub fn validate(&self) -> Result<()> {
        let message = self.canonical_bytes()?;
        let key: [u8; 32] = decode(&self.legacy_identity.signing_public_key, 32)?
            .try_into()
            .map_err(|_| Error::Format)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| Error::Format)?;
        if key.is_weak() {
            return Err(Error::Authentication);
        }
        let signature =
            Signature::from_slice(&decode(&self.signature, 64)?).map_err(|_| Error::Format)?;
        key.verify_strict(&message, &signature)
            .map_err(|_| Error::Authentication)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_DEVICE_BOOTSTRAP_BYTES {
            return Err(Error::Format);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        value.validate()?;
        Ok(value)
    }
}
impl UnlockedIdentity {
    pub fn authorize_device_authority(
        &self,
        initial_roster: DeviceRoster,
        source_bundle_revision: u64,
        confirmed_authority_fingerprint: &str,
    ) -> Result<DeviceAuthorityBootstrap> {
        if initial_roster.authority.fingerprint != confirmed_authority_fingerprint {
            return Err(Error::Authentication);
        }
        let mut value = DeviceAuthorityBootstrap {
            bootstrap_version: 1,
            source_bundle_revision,
            legacy_identity: self.public.clone(),
            initial_roster,
            signature: String::new(),
        };
        value.signature = STANDARD.encode(
            SigningKey::from_bytes(&self.private.signing_seed)
                .sign(&value.canonical_bytes()?)
                .to_bytes(),
        );
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
