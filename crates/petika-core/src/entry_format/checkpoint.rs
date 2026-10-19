//! Explicit trust anchors for experimental epochs. No TOFU or automatic rotation.
use super::*;
use crate::identity::PublicIdentity;
use ed25519_dalek::{Signature, VerifyingKey};

pub const MAX_CHECKPOINT_BYTES: usize = 16 * 1024;
pub const MAX_WRAPPERS: usize = 1000;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryProfile {
    Standard,
    ExperimentalXwingDraft06,
}
impl DeliveryProfile {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Standard => "entry-hpke-x25519-sha256-chacha20poly1305-v1",
            Self::ExperimentalXwingDraft06 => "entry-hpke-xwing-draft06-sha256-chacha20poly1305-v1",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrapperRef {
    pub wrapper_id: String,
    pub digest: String,
}
pub fn wrapper_set_digest(wrappers: &[WrapperRef]) -> Result<String> {
    if wrappers.is_empty() || wrappers.len() > MAX_WRAPPERS {
        return Err(Error::Format);
    }
    let mut sorted = wrappers.to_vec();
    sorted.sort_by(|a, b| a.wrapper_id.cmp(&b.wrapper_id));
    let mut bytes = Vec::new();
    field(&mut bytes, b"petika:entry-wrapper-set:v1");
    let mut previous = None;
    for wrapper in &sorted {
        if !id(&wrapper.wrapper_id) || !id(&wrapper.digest) || previous == Some(&wrapper.wrapper_id)
        {
            return Err(Error::Format);
        }
        field(&mut bytes, wrapper.wrapper_id.as_bytes());
        field(&mut bytes, wrapper.digest.as_bytes());
        previous = Some(&wrapper.wrapper_id);
    }
    Ok(hex(&digest(&bytes)))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub checkpoint_version: u32,
    pub context: Context,
    pub data_suite: String,
    pub delivery_profile: DeliveryProfile,
    pub root_commitment: String,
    pub head_revision: u64,
    pub head_digest: String,
    pub membership_generation: u64,
    pub wrapper_set_digest: String,
    /// An explicitly designated identity, not every reader/editor of the vault.
    pub authority: PublicIdentity,
    pub signature: String,
}
impl Checkpoint {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::Format);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        value.verify()?;
        Ok(value)
    }
    pub(crate) fn message(&self) -> Result<Vec<u8>> {
        self.context.validate()?;
        self.authority.validate()?;
        if self.checkpoint_version != 1
            || self.data_suite != SUITE
            || self.authority.deployment_id != self.context.deployment_id
            || !counter(self.head_revision)
            || !counter(self.membership_generation)
            || [
                &self.root_commitment,
                &self.head_digest,
                &self.wrapper_set_digest,
            ]
            .iter()
            .any(|s| !id(s))
        {
            return Err(Error::Format);
        }
        let mut bytes = Vec::new();
        field(&mut bytes, b"petika:entry-checkpoint:v1");
        bytes.extend_from_slice(&self.checkpoint_version.to_be_bytes());
        self.context.append(&mut bytes);
        field(&mut bytes, &fixed::<32>(&self.context.epoch_salt)?);
        for value in [
            &self.data_suite,
            self.delivery_profile.name(),
            &self.root_commitment,
            &self.head_digest,
            &self.wrapper_set_digest,
            &self.authority.fingerprint,
        ] {
            field(&mut bytes, value.as_bytes());
        }
        bytes.extend_from_slice(&self.head_revision.to_be_bytes());
        bytes.extend_from_slice(&self.membership_generation.to_be_bytes());
        Ok(bytes)
    }
    pub fn verify(&self) -> Result<()> {
        verify(&self.authority, &self.message()?, &self.signature)
    }
    pub fn digest(&self) -> Result<String> {
        self.verify()?;
        let mut bytes = self.message()?;
        field(&mut bytes, &fixed::<64>(&self.signature)?);
        Ok(hex(&digest(&bytes)))
    }
}
pub(crate) fn verify(identity: &PublicIdentity, message: &[u8], signature: &str) -> Result<()> {
    identity.validate()?;
    VerifyingKey::from_bytes(&fixed::<32>(&identity.signing_public_key)?)
        .map_err(|_| Error::Format)?
        .verify_strict(message, &Signature::from_bytes(&fixed::<64>(signature)?))
        .map_err(|_| Error::Authentication)
}
/// Construct only by matching an independently obtained exact checkpoint digest
/// and authority fingerprint, or by verifying a transition from an existing pin.
#[derive(Clone)]
pub struct TrustedCheckpoint {
    checkpoint: Checkpoint,
}
impl TrustedCheckpoint {
    pub fn bootstrap(
        checkpoint: Checkpoint,
        expected_digest: &str,
        authority_fingerprint: &str,
    ) -> Result<Self> {
        if !id(expected_digest)
            || !id(authority_fingerprint)
            || checkpoint.authority.fingerprint != authority_fingerprint
            || checkpoint.digest()? != expected_digest
        {
            return Err(Error::Authentication);
        }
        Ok(Self { checkpoint })
    }
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }
    /// Caller supplies its locally persisted highest authenticated head revision,
    /// never a counter supplied by the server as proof of freshness.
    pub fn advance(&self, transition: &Transition, highest_observed_revision: u64) -> Result<Self> {
        let old = &self.checkpoint;
        let new = &transition.next;
        old.verify()?;
        new.verify()?;
        if transition.transition_version != 1
            || transition.previous_checkpoint_digest != old.digest()?
            || old.context.deployment_id != new.context.deployment_id
            || old.context.collection_id != new.context.collection_id
            || old.context.key_epoch.checked_add(1) != Some(new.context.key_epoch)
            || old.context.epoch_salt == new.context.epoch_salt
            || old.root_commitment == new.root_commitment
            || highest_observed_revision < old.head_revision
            || highest_observed_revision > MAX_COUNTER
            || new.head_revision <= highest_observed_revision
            || new.membership_generation < old.membership_generation
            || new.delivery_profile != old.delivery_profile
        {
            return Err(Error::Authentication);
        }
        verify(
            &old.authority,
            &transition.message()?,
            &transition.signature,
        )?;
        Ok(Self {
            checkpoint: new.clone(),
        })
    }
    /// Recovery remains an explicit active wrapper, not a fallback around trust.
    pub fn open_recovery(
        &self,
        bytes: &[u8],
        passphrase: &str,
        wrappers: &[WrapperRef],
    ) -> Result<RootKey> {
        if bytes.len() > MAX_WRAPPER_BYTES {
            return Err(Error::Format);
        }
        let wrapper: RecoveryWrapper = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        self.validate_wrapper(wrappers, &wrapper.wrapper_id, bytes)?;
        let root = RootKey::open_recovery(&self.checkpoint.context, passphrase, bytes)?;
        self.validate_root(&root)?;
        Ok(root)
    }
    pub fn validate_root(&self, root: &RootKey) -> Result<()> {
        if root.context() != &self.checkpoint.context
            || root.commitment() != self.checkpoint.root_commitment
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub fn validate_wrapper(
        &self,
        wrappers: &[WrapperRef],
        wrapper_id: &str,
        bytes: &[u8],
    ) -> Result<()> {
        if wrapper_set_digest(wrappers)? != self.checkpoint.wrapper_set_digest
            || !wrappers
                .iter()
                .any(|w| w.wrapper_id == wrapper_id && w.digest == hex(&digest(bytes)))
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub transition_version: u32,
    pub previous_checkpoint_digest: String,
    pub next: Checkpoint,
    pub signature: String,
}
impl Transition {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CHECKPOINT_BYTES + 4096 {
            return Err(Error::Format);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        value.message()?;
        fixed::<64>(&value.signature)?;
        Ok(value)
    }
    pub(crate) fn message(&self) -> Result<Vec<u8>> {
        if self.transition_version != 1 || !id(&self.previous_checkpoint_digest) {
            return Err(Error::Format);
        }
        let mut bytes = Vec::new();
        field(&mut bytes, b"petika:entry-epoch-transition:v1");
        bytes.extend_from_slice(&self.transition_version.to_be_bytes());
        field(&mut bytes, self.previous_checkpoint_digest.as_bytes());
        field(&mut bytes, self.next.digest()?.as_bytes());
        Ok(bytes)
    }
}
