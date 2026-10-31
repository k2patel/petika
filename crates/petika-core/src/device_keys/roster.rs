use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ACTIVE_DEVICES: usize = 64;
pub const MAX_REVOKED_DEVICES: usize = 4096;
pub const MAX_ROSTER_BYTES: usize = 1024 * 1024;
const ROSTER_DOMAIN: &[u8] = b"petika:device-roster:experimental-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRoster {
    pub roster_version: u32,
    pub authority: DeviceAuthority,
    pub generation: u64,
    pub parent_digest: String,
    pub devices: Vec<DeviceRecord>,
    pub revoked_device_ids: Vec<String>,
    pub signature: String,
}
impl DeviceRoster {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.authority.validate()?;
        if self.roster_version != 1
            || !(1..=MAX_GENERATION).contains(&self.generation)
            || self.devices.len() > MAX_ACTIVE_DEVICES
            || self.revoked_device_ids.len() > MAX_REVOKED_DEVICES
            || if self.generation == 1 {
                !self.parent_digest.is_empty()
                    || !self.revoked_device_ids.is_empty()
                    || self.devices.len() > 1
            } else {
                !id(&self.parent_digest)
            }
        {
            return Err(Error::Format);
        }
        let mut active = BTreeSet::new();
        let mut standard = BTreeSet::new();
        let mut hybrid = BTreeSet::new();
        let mut signing = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for device in &self.devices {
            device.validate()?;
            if device.deployment_id != self.authority.deployment_id
                || device.user_id != self.authority.user_id
                || previous.is_some_and(|p| p >= device.device_id.as_str())
                || !standard.insert(&device.standard_public_key)
                || !hybrid.insert(&device.hybrid_public_key)
                || !signing.insert(&device.signing_public_key)
                || device.signing_public_key == self.authority.signing_public_key
            {
                return Err(Error::Authentication);
            }
            previous = Some(&device.device_id);
            active.insert(&device.device_id);
        }
        previous = None;
        for revoked in &self.revoked_device_ids {
            if !id(revoked)
                || active.contains(revoked)
                || previous.is_some_and(|p| p >= revoked.as_str())
            {
                return Err(Error::Format);
            }
            previous = Some(revoked);
        }
        let mut out = Vec::new();
        field(&mut out, ROSTER_DOMAIN);
        out.extend_from_slice(&self.roster_version.to_be_bytes());
        field(&mut out, &self.authority.canonical_bytes()?);
        field(&mut out, self.authority.fingerprint.as_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        field(&mut out, self.parent_digest.as_bytes());
        out.extend_from_slice(&(self.devices.len() as u32).to_be_bytes());
        for device in &self.devices {
            field(&mut out, &device.canonical_bytes()?);
            field(&mut out, device.fingerprint.as_bytes());
            field(&mut out, &decode(&device.signature, 64)?);
        }
        out.extend_from_slice(&(self.revoked_device_ids.len() as u32).to_be_bytes());
        for revoked in &self.revoked_device_ids {
            field(&mut out, revoked.as_bytes());
        }
        Ok(out)
    }
    pub fn validate(&self) -> Result<()> {
        verify(
            &self.authority.signing_public_key,
            &self.canonical_bytes()?,
            &self.signature,
        )
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let mut bytes = self.canonical_bytes()?;
        field(&mut bytes, &decode(&self.signature, 64)?);
        Ok(hash(&bytes))
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse(bytes, MAX_ROSTER_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}
impl DeviceAuthorityKey {
    /// Low-level signing only. The caller must separately approve enrollment and
    /// verify encryption-key possession. Not a server enrollment API.
    pub fn sign_roster(
        &self,
        generation: u64,
        parent_digest: String,
        devices: Vec<DeviceRecord>,
        revoked_device_ids: Vec<String>,
    ) -> Result<DeviceRoster> {
        let mut roster = DeviceRoster {
            roster_version: 1,
            authority: self.public_record()?,
            generation,
            parent_digest,
            devices,
            revoked_device_ids,
            signature: String::new(),
        };
        roster.signature = STANDARD.encode(
            SigningKey::from_bytes(&self.seed)
                .sign(&roster.canonical_bytes()?)
                .to_bytes(),
        );
        Ok(roster)
    }
}

/// In-memory trusted state only; no untrusted deserialization or persistence path.
pub struct TrustedDeviceRoster {
    roster: DeviceRoster,
}
impl TrustedDeviceRoster {
    pub fn bootstrap(
        roster: DeviceRoster,
        confirmed_authority_fingerprint: &str,
        confirmed_roster_digest: &str,
    ) -> Result<Self> {
        if !id(confirmed_authority_fingerprint)
            || !id(confirmed_roster_digest)
            || roster.authority.fingerprint != confirmed_authority_fingerprint
            || roster.digest()? != confirmed_roster_digest
        {
            return Err(Error::Authentication);
        }
        Ok(Self { roster })
    }
    pub fn roster(&self) -> &DeviceRoster {
        &self.roster
    }
    /// Accept an exact retry or one add/remove transition. Rejects forks, missing
    /// history, modified retained records and erased tombstones without mutation.
    pub fn accept(&mut self, next: DeviceRoster) -> Result<()> {
        next.validate()?;
        let old = &self.roster;
        let old_digest = old.digest()?;
        if next.digest()? == old_digest {
            return Ok(());
        }
        if next.authority != old.authority
            || next.parent_digest != old_digest
            || old.generation.checked_add(1) != Some(next.generation)
        {
            return Err(Error::Authentication);
        }
        let before: BTreeMap<_, _> = old.devices.iter().map(|d| (&d.device_id, d)).collect();
        let after: BTreeMap<_, _> = next.devices.iter().map(|d| (&d.device_id, d)).collect();
        let removed: Vec<_> = before
            .keys()
            .filter(|id| !after.contains_key(*id))
            .copied()
            .collect();
        let added: Vec<_> = after
            .keys()
            .filter(|id| !before.contains_key(*id))
            .copied()
            .collect();
        if removed.len() + added.len() != 1
            || before
                .iter()
                .any(|(id, value)| after.get(id).is_some_and(|next| value != next))
        {
            return Err(Error::Authentication);
        }
        let mut revoked: BTreeSet<_> = old.revoked_device_ids.iter().collect();
        if added.iter().any(|id| revoked.contains(id)) {
            return Err(Error::Authentication);
        }
        revoked.extend(removed);
        if revoked.into_iter().ne(next.revoked_device_ids.iter()) {
            return Err(Error::Authentication);
        }
        self.roster = next;
        Ok(())
    }
}
