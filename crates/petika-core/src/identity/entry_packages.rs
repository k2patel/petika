//! Experimental root delivery, distinct from snapshot key-package v1.
use super::hybrid_hpke::XWing;
use super::*;
use crate::entry_format::{
    Context, RootKey, SUITE,
    checkpoint::{
        Checkpoint, DeliveryProfile, Transition, TrustedCheckpoint, WrapperRef, wrapper_set_digest,
    },
};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, rand_core::SeedableRng,
};
use rand_chacha::ChaCha20Rng;
const TAG: &[u8] = b"petika:entry-root:v1\0";
const MAX_BYTES: usize = 16 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryKeyPackage {
    pub package_version: u32,
    pub profile: DeliveryProfile,
    pub context: Context,
    pub data_suite: String,
    pub root_commitment: String,
    pub membership_generation: u64,
    pub wrapper_id: String,
    pub recipient_user_id: String,
    pub recipient_identity_version: u64,
    pub recipient_fingerprint: String,
    pub issuer_user_id: String,
    pub issuer_identity_version: u64,
    pub issuer_fingerprint: String,
    pub enc: String,
    pub ciphertext: String,
    pub signature: String,
}
fn domain(label: &[u8], header: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    field(&mut bytes, label);
    field(&mut bytes, header);
    bytes
}
impl EntryKeyPackage {
    /// Verify public delivery metadata and the designated checkpoint authority's
    /// signature. This does not prove recipient possession or decrypt the payload.
    pub fn verify_checkpoint(&self, checkpoint: &Checkpoint) -> Result<()> {
        checkpoint.verify()?;
        let issuer = &checkpoint.authority;
        if self.context != checkpoint.context
            || self.data_suite != checkpoint.data_suite
            || self.profile != checkpoint.delivery_profile
            || self.root_commitment != checkpoint.root_commitment
            || self.membership_generation != checkpoint.membership_generation
            || self.issuer_user_id != issuer.user_id
            || self.issuer_identity_version != issuer.identity_version
            || self.issuer_fingerprint != issuer.fingerprint
        {
            return Err(Error::Authentication);
        }
        crate::entry_format::checkpoint::verify(issuer, &self.message()?, &self.signature)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Format);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        value.message()?;
        decode(&value.signature, 64)?;
        Ok(value)
    }
    fn header(&self) -> Result<Vec<u8>> {
        self.context.validate()?;
        if self.package_version != 1
            || self.data_suite != SUITE
            || [
                &self.root_commitment,
                &self.wrapper_id,
                &self.recipient_user_id,
                &self.recipient_fingerprint,
                &self.issuer_user_id,
                &self.issuer_fingerprint,
            ]
            .iter()
            .any(|s| !valid_id(s))
            || [
                self.membership_generation,
                self.recipient_identity_version,
                self.issuer_identity_version,
            ]
            .iter()
            .any(|n| !(1..=MAX_COUNTER).contains(n))
        {
            return Err(Error::Format);
        }
        let mut bytes = Vec::new();
        field(&mut bytes, b"petika:entry-package:header:v1");
        bytes.extend_from_slice(&self.package_version.to_be_bytes());
        field(&mut bytes, self.profile.name().as_bytes());
        field(&mut bytes, self.data_suite.as_bytes());
        self.context.append(&mut bytes);
        field(&mut bytes, &decode(&self.context.epoch_salt, 32)?);
        field(&mut bytes, self.root_commitment.as_bytes());
        bytes.extend_from_slice(&self.membership_generation.to_be_bytes());
        field(&mut bytes, self.wrapper_id.as_bytes());
        for (user, version, fingerprint) in [
            (
                &self.recipient_user_id,
                self.recipient_identity_version,
                &self.recipient_fingerprint,
            ),
            (
                &self.issuer_user_id,
                self.issuer_identity_version,
                &self.issuer_fingerprint,
            ),
        ] {
            field(&mut bytes, user.as_bytes());
            bytes.extend_from_slice(&version.to_be_bytes());
            field(&mut bytes, fingerprint.as_bytes());
        }
        Ok(bytes)
    }
    pub(super) fn message(&self) -> Result<Vec<u8>> {
        let mut bytes = domain(b"petika:entry-package:signature:v1", &self.header()?);
        field(
            &mut bytes,
            &decode(
                &self.enc,
                match self.profile {
                    DeliveryProfile::Standard => 32,
                    DeliveryProfile::ExperimentalXwingDraft06 => 1120,
                },
            )?,
        );
        field(&mut bytes, &decode(&self.ciphertext, TAG.len() + 32 + 16)?);
        Ok(bytes)
    }
    pub fn reference(&self) -> Result<WrapperRef> {
        self.message()?;
        decode(&self.signature, 64)?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Format)?;
        Ok(WrapperRef {
            wrapper_id: self.wrapper_id.clone(),
            digest: hex(&Sha256::digest(bytes)),
        })
    }
}
fn seal<K: Kem>(public: &[u8], header: &[u8], payload: &[u8]) -> Result<(String, String)> {
    let mut rng = ChaCha20Rng::from_seed(crypto::random()?);
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, K, _>(
        &OpModeS::Base,
        &K::PublicKey::from_bytes(public).map_err(|_| Error::Format)?,
        &domain(b"petika:entry-package:info:v1", header),
        payload,
        &domain(b"petika:entry-package:aad:v1", header),
        &mut rng,
    )
    .map_err(|_| Error::Authentication)?;
    Ok((STANDARD.encode(enc.to_bytes()), STANDARD.encode(ct)))
}
fn open<K: Kem>(secret: &[u8], package: &EntryKeyPackage) -> Result<Zeroizing<Vec<u8>>> {
    let header = package.header()?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Base,
        &K::PrivateKey::from_bytes(secret).map_err(|_| Error::Format)?,
        &K::EncappedKey::from_bytes(&STANDARD.decode(&package.enc).map_err(|_| Error::Format)?)
            .map_err(|_| Error::Format)?,
        &domain(b"petika:entry-package:info:v1", &header),
        &decode(&package.ciphertext, TAG.len() + 32 + 16)?,
        &domain(b"petika:entry-package:aad:v1", &header),
    )
    .map(Zeroizing::new)
    .map_err(|_| Error::Authentication)
}
/// Public commit data which the designated authority must verify independently
/// before signing. Constructing this value is not validation of a vault index.
pub struct CheckpointTarget {
    pub head_revision: u64,
    pub head_digest: String,
    pub membership_generation: u64,
    pub delivery_profile: DeliveryProfile,
}
impl UnlockedIdentity {
    pub fn create_entry_key_package(
        &mut self,
        root: &RootKey,
        recipient: &PublicIdentity,
        membership_generation: u64,
        profile: DeliveryProfile,
    ) -> Result<EntryKeyPackage> {
        self.trust_package_peer(recipient)?;
        if self.public.deployment_id != root.context().deployment_id
            || recipient.deployment_id != root.context().deployment_id
        {
            return Err(Error::Authentication);
        }
        let mut package = EntryKeyPackage {
            package_version: 1,
            profile,
            context: root.context().clone(),
            data_suite: SUITE.into(),
            root_commitment: root.commitment(),
            membership_generation,
            wrapper_id: hex(&crypto::random::<32>()?),
            recipient_user_id: recipient.user_id.clone(),
            recipient_identity_version: recipient.identity_version,
            recipient_fingerprint: recipient.fingerprint.clone(),
            issuer_user_id: self.public.user_id.clone(),
            issuer_identity_version: self.public.identity_version,
            issuer_fingerprint: self.public.fingerprint.clone(),
            enc: String::new(),
            ciphertext: String::new(),
            signature: String::new(),
        };
        let mut payload = Zeroizing::new(TAG.to_vec());
        payload.extend_from_slice(root.material());
        let header = package.header()?;
        (package.enc, package.ciphertext) = match package.profile {
            DeliveryProfile::Standard => seal::<X25519HkdfSha256>(
                &decode(&recipient.standard_public_key, 32)?,
                &header,
                &payload,
            )?,
            DeliveryProfile::ExperimentalXwingDraft06 => seal::<XWing>(
                &decode(&recipient.hybrid_public_key, 1216)?,
                &header,
                &payload,
            )?,
        };
        package.signature = STANDARD.encode(
            SigningKey::from_bytes(&self.private.signing_seed)
                .sign(&package.message()?)
                .to_bytes(),
        );
        Ok(package)
    }
    pub fn open_entry_key_package(
        &mut self,
        bytes: &[u8],
        issuer: &PublicIdentity,
        checkpoint: &TrustedCheckpoint,
        wrappers: &[WrapperRef],
    ) -> Result<RootKey> {
        let package = EntryKeyPackage::parse(bytes)?;
        let trusted = checkpoint.checkpoint();
        checkpoint.validate_wrapper(wrappers, &package.wrapper_id, bytes)?;
        issuer.validate()?;
        if package.context != trusted.context
            || package.data_suite != trusted.data_suite
            || package.profile != trusted.delivery_profile
            || package.root_commitment != trusted.root_commitment
            || package.membership_generation != trusted.membership_generation
            || package.recipient_user_id != self.public.user_id
            || package.recipient_identity_version != self.public.identity_version
            || package.recipient_fingerprint != self.public.fingerprint
            || package.issuer_user_id != issuer.user_id
            || package.issuer_identity_version != issuer.identity_version
            || package.issuer_fingerprint != issuer.fingerprint
            || issuer.deployment_id != package.context.deployment_id
            || self.public.deployment_id != package.context.deployment_id
        {
            return Err(Error::Authentication);
        }
        crate::entry_format::checkpoint::verify(issuer, &package.message()?, &package.signature)?;
        self.trust_package_peer(issuer)?;
        let payload = match package.profile {
            DeliveryProfile::Standard => {
                open::<X25519HkdfSha256>(&self.private.standard_secret, &package)?
            }
            DeliveryProfile::ExperimentalXwingDraft06 => {
                open::<XWing>(&self.private.hybrid_seed, &package)?
            }
        };
        if payload.len() != TAG.len() + 32 || !payload.starts_with(TAG) {
            return Err(Error::Authentication);
        }
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&payload[TAG.len()..]);
        let root = RootKey::from_material(package.context, key)?;
        checkpoint.validate_root(&root)?;
        Ok(root)
    }
    pub fn sign_entry_checkpoint(
        &self,
        root: &RootKey,
        target: CheckpointTarget,
        wrappers: &[WrapperRef],
    ) -> Result<Checkpoint> {
        if self.public.deployment_id != root.context().deployment_id {
            return Err(Error::Authentication);
        }
        let mut checkpoint = Checkpoint {
            checkpoint_version: 1,
            context: root.context().clone(),
            data_suite: SUITE.into(),
            delivery_profile: target.delivery_profile,
            root_commitment: root.commitment(),
            head_revision: target.head_revision,
            head_digest: target.head_digest,
            membership_generation: target.membership_generation,
            wrapper_set_digest: wrapper_set_digest(wrappers)?,
            authority: self.public.clone(),
            signature: String::new(),
        };
        checkpoint.signature = STANDARD.encode(
            SigningKey::from_bytes(&self.private.signing_seed)
                .sign(&checkpoint.message()?)
                .to_bytes(),
        );
        Ok(checkpoint)
    }
    /// Sign a migration candidate after caller review. This signature binds the
    /// source preconditions and full ciphertext bundle, not server authorization.
    pub fn sign_entry_migration(
        &self,
        draft: &mut crate::entry_format::migration_draft::MigrationDraft,
    ) -> Result<()> {
        if draft.state.checkpoint.authority != self.public {
            return Err(Error::Authentication);
        }
        draft.signature = STANDARD.encode(
            SigningKey::from_bytes(&self.private.signing_seed)
                .sign(&draft.message()?)
                .to_bytes(),
        );
        Ok(())
    }
    /// Requires the old designated authority; the new checkpoint is also signed
    /// by its own authority, making explicit authority handover a two-signature act.
    pub fn authorize_entry_transition(
        &mut self,
        previous: &TrustedCheckpoint,
        next: Checkpoint,
        highest_observed_revision: u64,
    ) -> Result<Transition> {
        if previous.checkpoint().authority != self.public {
            return Err(Error::Authentication);
        }
        // A new authority's self-signature is not independent identity verification.
        self.trust_package_peer(&next.authority)?;
        let mut transition = Transition {
            transition_version: 1,
            previous_checkpoint_digest: previous.checkpoint().digest()?,
            next,
            signature: String::new(),
        };
        transition.signature = STANDARD.encode(
            SigningKey::from_bytes(&self.private.signing_seed)
                .sign(&transition.message()?)
                .to_bytes(),
        );
        previous.advance(&transition, highest_observed_revision)?;
        Ok(transition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    fn unhex(value: &str) -> [u8; 32] {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
    #[test]
    fn independent_checkpoint_transition_and_entry_hpke_vectors() {
        let vector: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/entry-trust-v1.json")).unwrap();
        let seeds: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/identity-v1.json")).unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let first: Checkpoint =
                serde_json::from_value(case["snapshots"][0]["checkpoint"].clone()).unwrap();
            let public = first.authority.clone();
            let mut identity = UnlockedIdentity {
                public: public.clone(),
                private: PrivateIdentity {
                    standard_secret: unhex(seeds["standard_secret_hex"].as_str().unwrap()),
                    hybrid_seed: unhex(seeds["hybrid_seed_hex"].as_str().unwrap()),
                    signing_seed: unhex(seeds["signing_seed_hex"].as_str().unwrap()),
                    fingerprint: public.fingerprint.clone(),
                },
                contacts: vec![],
            };
            let trusted = TrustedCheckpoint::bootstrap(
                first,
                case["snapshots"][0]["checkpoint_digest"].as_str().unwrap(),
                &public.fingerprint,
            )
            .unwrap();
            for snapshot in case["snapshots"].as_array().unwrap() {
                let checkpoint: Checkpoint =
                    serde_json::from_value(snapshot["checkpoint"].clone()).unwrap();
                assert_eq!(checkpoint.digest().unwrap(), snapshot["checkpoint_digest"]);
                assert_eq!(
                    STANDARD.encode(checkpoint.message().unwrap()),
                    snapshot["message"]
                );
                let pin = TrustedCheckpoint::bootstrap(
                    checkpoint,
                    snapshot["checkpoint_digest"].as_str().unwrap(),
                    &public.fingerprint,
                )
                .unwrap();
                let bytes = snapshot["package"].as_str().unwrap().as_bytes();
                let package = EntryKeyPackage::parse(bytes).unwrap();
                assert_eq!(
                    STANDARD.encode(package.header().unwrap()),
                    snapshot["header"]
                );
                let wrappers: Vec<WrapperRef> =
                    serde_json::from_value(snapshot["wrappers"].clone()).unwrap();
                let root = identity
                    .open_entry_key_package(bytes, &public, &pin, &wrappers)
                    .unwrap();
                assert_eq!(STANDARD.encode(root.material()), snapshot["root"]);
            }
            let transition: Transition =
                serde_json::from_value(case["transition"].clone()).unwrap();
            assert_eq!(
                STANDARD.encode(transition.message().unwrap()),
                case["transition_message"]
            );
            trusted
                .advance(&transition, trusted.checkpoint().head_revision)
                .unwrap();
        }
    }
}
