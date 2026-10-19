//! Explicit new-recipient bootstrap, not an epoch-continuity bypass.
use super::*;
use crate::entry_format::{
    RootKey,
    checkpoint::{Checkpoint, TrustedCheckpoint, WrapperRef},
    index::VerifiedIndex,
};
const MAX_HANDOFF_BYTES: usize = 256 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryHandoff {
    pub handoff_version: u32,
    pub checkpoint: Checkpoint,
    /// Exact serialized package bytes as UTF-8, never parsed/reserialized for hashing.
    pub package: String,
    pub wrappers: Vec<WrapperRef>,
}
impl EntryHandoff {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_HANDOFF_BYTES {
            return Err(Error::Format);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<EntryKeyPackage> {
        if self.handoff_version != 1 {
            return Err(Error::Format);
        }
        self.checkpoint.verify()?;
        let package = EntryKeyPackage::parse(self.package.as_bytes())?;
        let cp = &self.checkpoint;
        let trusted =
            TrustedCheckpoint::bootstrap(cp.clone(), &cp.digest()?, &cp.authority.fingerprint)?;
        // This temporary object checks binding only, not trust. Acceptance below
        // additionally requires an independently confirmed complete handoff digest.
        trusted.validate_wrapper(&self.wrappers, &package.wrapper_id, self.package.as_bytes())?;
        if package.context != cp.context
            || package.data_suite != cp.data_suite
            || package.root_commitment != cp.root_commitment
            || package.profile != cp.delivery_profile
            || package.membership_generation != cp.membership_generation
            || package.issuer_user_id != cp.authority.user_id
            || package.issuer_identity_version != cp.authority.identity_version
            || package.issuer_fingerprint != cp.authority.fingerprint
        {
            return Err(Error::Authentication);
        }
        crate::entry_format::checkpoint::verify(
            &cp.authority,
            &package.message()?,
            &package.signature,
        )?;
        Ok(package)
    }
    /// Compare the entire value over an independently authenticated channel.
    /// Receiving this digest beside the bundle from the server is not confirmation.
    pub fn confirmation_digest(&self) -> Result<String> {
        self.validate()?;
        let mut bytes = Vec::new();
        field(&mut bytes, b"petika:entry-handoff:v1");
        bytes.extend_from_slice(&self.handoff_version.to_be_bytes());
        field(&mut bytes, self.checkpoint.digest()?.as_bytes());
        field(&mut bytes, &Sha256::digest(self.package.as_bytes()));
        Ok(hex(&Sha256::digest(bytes)))
    }
}
impl UnlockedIdentity {
    /// The designated authority exports an already active recipient package at
    /// the exact checkpoint head. No implicit membership change or new package.
    pub fn prepare_entry_handoff(
        &mut self,
        checkpoint: &TrustedCheckpoint,
        index: &VerifiedIndex,
        recipient: &PublicIdentity,
        package: &[u8],
        wrappers: &[WrapperRef],
    ) -> Result<EntryHandoff> {
        if package.len() > 16 * 1024
            || wrappers.len() > crate::entry_format::checkpoint::MAX_WRAPPERS
        {
            return Err(Error::Format);
        }
        if checkpoint.checkpoint().authority != self.public {
            return Err(Error::Authentication);
        }
        index.matches_checkpoint(checkpoint)?;
        self.trust_package_peer(recipient)?;
        let handoff = EntryHandoff {
            handoff_version: 1,
            checkpoint: checkpoint.checkpoint().clone(),
            package: std::str::from_utf8(package)
                .map_err(|_| Error::Format)?
                .to_owned(),
            wrappers: wrappers.to_vec(),
        };
        let package = handoff.validate()?;
        if recipient.deployment_id != handoff.checkpoint.context.deployment_id
            || package.recipient_user_id != recipient.user_id
            || package.recipient_identity_version != recipient.identity_version
            || package.recipient_fingerprint != recipient.fingerprint
        {
            return Err(Error::Authentication);
        }
        if serde_json::to_vec(&handoff)
            .map_err(|_| Error::Format)?
            .len()
            > MAX_HANDOFF_BYTES
        {
            return Err(Error::Format);
        }
        Ok(handoff)
    }
    /// Does not persist or replace any local trust. The caller must authenticate
    /// the index and initialize a *new* checkpoint file before exposing the vault.
    pub fn accept_entry_handoff(
        &mut self,
        bytes: &[u8],
        independently_confirmed_digest: &str,
        authority_fingerprint: &str,
    ) -> Result<(TrustedCheckpoint, RootKey)> {
        let handoff = EntryHandoff::parse(bytes)?;
        if !valid_id(independently_confirmed_digest)
            || handoff.confirmation_digest()? != independently_confirmed_digest
            || handoff.checkpoint.authority.fingerprint != authority_fingerprint
        {
            return Err(Error::Authentication);
        }
        self.trust_package_peer(&handoff.checkpoint.authority)?;
        let checkpoint = TrustedCheckpoint::bootstrap(
            handoff.checkpoint.clone(),
            &handoff.checkpoint.digest()?,
            authority_fingerprint,
        )?;
        let root = self.open_entry_key_package(
            handoff.package.as_bytes(),
            &handoff.checkpoint.authority,
            &checkpoint,
            &handoff.wrappers,
        )?;
        Ok((checkpoint, root))
    }
}
