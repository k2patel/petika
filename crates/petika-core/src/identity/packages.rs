//! Signed, recipient-addressed collection access. Raw collection secrets stay in core.
use super::hybrid_hpke::XWing;
use super::*;
use crate::{CollectionContext, EncryptionMode, UnlockedStore};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, rand_core::SeedableRng,
};
use rand_chacha::ChaCha20Rng;

const STANDARD_SUITE: &str = "hpke-x25519-sha256-chacha20poly1305-v1";
const HYBRID_SUITE: &str = "hpke-xwing-draft06-sha256-chacha20poly1305-v1";
pub const MAX_PACKAGE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackage {
    pub package_version: u32,
    pub suite: String,
    pub deployment_id: String,
    pub collection_id: String,
    pub collection_mode: EncryptionMode,
    pub key_epoch: u64,
    pub membership_generation: u64,
    pub recipient_user_id: String,
    pub recipient_identity_version: u64,
    pub recipient_fingerprint: String,
    pub issuer_user_id: String,
    pub issuer_identity_version: u64,
    pub issuer_fingerprint: String,
    pub package_id: String,
    pub enc: String,
    pub ciphertext: String,
    pub signature: String,
}
impl KeyPackage {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err(Error::Format);
        }
        let package: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        package.header()?;
        package.message()?;
        decode(&package.signature, 64)?;
        Ok(package)
    }
    fn header(&self) -> Result<Vec<u8>> {
        if self.package_version != 1
            || self.suite != suite(self.collection_mode)
            || [
                self.key_epoch,
                self.recipient_identity_version,
                self.issuer_identity_version,
            ]
            .iter()
            .any(|v| !(1..=MAX_COUNTER).contains(v))
            || !(1..=MAX_COUNTER).contains(&self.membership_generation)
            || [
                &self.deployment_id,
                &self.collection_id,
                &self.recipient_user_id,
                &self.recipient_fingerprint,
                &self.issuer_user_id,
                &self.issuer_fingerprint,
                &self.package_id,
            ]
            .iter()
            .any(|s| !valid_id(s))
        {
            return Err(Error::Format);
        }
        let mut bytes = Vec::new();
        field(&mut bytes, b"petika:key-package:header:v1");
        bytes.extend_from_slice(&self.package_version.to_be_bytes());
        for value in [&self.suite, &self.deployment_id, &self.collection_id] {
            field(&mut bytes, value.as_bytes());
        }
        field(
            &mut bytes,
            match self.collection_mode {
                EncryptionMode::Standard => b"standard",
                EncryptionMode::HybridPostQuantum => b"hybrid-post-quantum",
            },
        );
        bytes.extend_from_slice(&self.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.membership_generation.to_be_bytes());
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
        field(&mut bytes, self.package_id.as_bytes());
        Ok(bytes)
    }
    fn message(&self) -> Result<Vec<u8>> {
        let mut bytes = domain(b"petika:key-package:signature:v1", &self.header()?);
        field(
            &mut bytes,
            &decode(
                &self.enc,
                if self.collection_mode == EncryptionMode::Standard {
                    32
                } else {
                    1120
                },
            )?,
        );
        field(&mut bytes, &decode(&self.ciphertext, 49)?);
        Ok(bytes)
    }
    /// Public validation only: the server cannot authenticate the encrypted payload.
    pub fn validate(&self, issuer: &PublicIdentity, recipient: &PublicIdentity) -> Result<()> {
        issuer.validate()?;
        recipient.validate()?;
        if self.deployment_id != issuer.deployment_id
            || self.deployment_id != recipient.deployment_id
            || self.issuer_user_id != issuer.user_id
            || self.issuer_identity_version != issuer.identity_version
            || self.issuer_fingerprint != issuer.fingerprint
            || self.recipient_user_id != recipient.user_id
            || self.recipient_identity_version != recipient.identity_version
            || self.recipient_fingerprint != recipient.fingerprint
        {
            return Err(Error::Authentication);
        }
        let key = VerifyingKey::from_bytes(
            &decode(&issuer.signing_public_key, 32)?
                .try_into()
                .map_err(|_| Error::Format)?,
        )
        .map_err(|_| Error::Format)?;
        key.verify_strict(
            &self.message()?,
            &Signature::from_slice(&decode(&self.signature, 64)?).map_err(|_| Error::Format)?,
        )
        .map_err(|_| Error::Authentication)
    }
}
fn suite(mode: EncryptionMode) -> &'static str {
    match mode {
        EncryptionMode::Standard => STANDARD_SUITE,
        EncryptionMode::HybridPostQuantum => HYBRID_SUITE,
    }
}
fn domain(label: &[u8], header: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    field(&mut bytes, label);
    field(&mut bytes, header);
    bytes
}
fn seal<K: Kem>(public: &[u8], header: &[u8], payload: &[u8]) -> Result<(String, String)> {
    let mut rng = ChaCha20Rng::from_seed(crypto::random()?);
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, K, _>(
        &OpModeS::Base,
        &K::PublicKey::from_bytes(public).map_err(|_| Error::Format)?,
        &domain(b"petika:key-package:info:v1", header),
        payload,
        &domain(b"petika:key-package:aad:v1", header),
        &mut rng,
    )
    .map_err(|_| Error::Authentication)?;
    Ok((STANDARD.encode(enc.to_bytes()), STANDARD.encode(ct)))
}
fn open<K: Kem>(secret: &[u8], package: &KeyPackage, header: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let enc = STANDARD.decode(&package.enc).map_err(|_| Error::Format)?;
    let ct = decode(&package.ciphertext, 49)?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Base,
        &K::PrivateKey::from_bytes(secret).map_err(|_| Error::Format)?,
        &K::EncappedKey::from_bytes(&enc).map_err(|_| Error::Format)?,
        &domain(b"petika:key-package:info:v1", header),
        &ct,
        &domain(b"petika:key-package:aad:v1", header),
    )
    .map(Zeroizing::new)
    .map_err(|_| Error::Authentication)
}
impl UnlockedIdentity {
    pub(super) fn trust_package_peer(&mut self, peer: &PublicIdentity) -> Result<()> {
        if peer == &self.public {
            return Ok(());
        }
        self.require_verified_contact(&peer.user_id, peer)
    }
    pub fn create_key_package(
        &mut self,
        store: &UnlockedStore,
        recipient: &PublicIdentity,
        membership_generation: u64,
    ) -> Result<KeyPackage> {
        self.trust_package_peer(recipient)?;
        let context = store.context().ok_or(Error::Format)?;
        if context.deployment_id != self.public.deployment_id {
            return Err(Error::Authentication);
        }
        let mut package = KeyPackage {
            package_version: 1,
            suite: suite(store.encryption()).into(),
            deployment_id: context.deployment_id.clone(),
            collection_id: context.collection_id.clone(),
            collection_mode: store.encryption(),
            key_epoch: context.key_epoch,
            membership_generation,
            recipient_user_id: recipient.user_id.clone(),
            recipient_identity_version: recipient.identity_version,
            recipient_fingerprint: recipient.fingerprint.clone(),
            issuer_user_id: self.public.user_id.clone(),
            issuer_identity_version: self.public.identity_version,
            issuer_fingerprint: self.public.fingerprint.clone(),
            package_id: hex(&crypto::random::<32>()?),
            enc: String::new(),
            ciphertext: String::new(),
            signature: String::new(),
        };
        let header = package.header()?;
        let mut payload = Zeroizing::new([0; 33]);
        payload[0] = if store.encryption() == EncryptionMode::Standard {
            1
        } else {
            2
        };
        payload[1..].copy_from_slice(store.access_material());
        (package.enc, package.ciphertext) = match store.encryption() {
            EncryptionMode::Standard => seal::<X25519HkdfSha256>(
                &decode(&recipient.standard_public_key, 32)?,
                &header,
                payload.as_ref(),
            )?,
            EncryptionMode::HybridPostQuantum => seal::<XWing>(
                &decode(&recipient.hybrid_public_key, 1216)?,
                &header,
                payload.as_ref(),
            )?,
        };
        package.signature = STANDARD.encode(
            SigningKey::from_bytes(&self.private.signing_seed)
                .sign(&package.message()?)
                .to_bytes(),
        );
        Ok(package)
    }
    pub fn open_key_package(
        &mut self,
        package: &KeyPackage,
        issuer: &PublicIdentity,
        snapshot: &[u8],
        expected: &CollectionContext,
        mode: EncryptionMode,
    ) -> Result<UnlockedStore> {
        expected.validate()?;
        package.validate(issuer, &self.public)?;
        if package.deployment_id != expected.deployment_id
            || package.collection_id != expected.collection_id
            || package.key_epoch != expected.key_epoch
            || package.collection_mode != mode
        {
            return Err(Error::Authentication);
        }
        self.trust_package_peer(issuer)?;
        let header = package.header()?;
        let payload = match mode {
            EncryptionMode::Standard => {
                open::<X25519HkdfSha256>(&self.private.standard_secret, package, &header)?
            }
            EncryptionMode::HybridPostQuantum => {
                open::<XWing>(&self.private.hybrid_seed, package, &header)?
            }
        };
        if payload.len() != 33
            || payload[0]
                != if mode == EncryptionMode::Standard {
                    1
                } else {
                    2
                }
        {
            return Err(Error::Format);
        }
        let mut material = Zeroizing::new([0; 32]);
        material.copy_from_slice(&payload[1..]);
        UnlockedStore::open_access(snapshot, material, expected, mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(value: &serde_json::Value, field: &str) -> Vec<u8> {
        value[field]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn independent_python_hpke_and_canonical_encoding_vectors() {
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../../tests/fixtures/key-packages-v1.json"))
                .unwrap();
        for vector in vectors {
            let package: KeyPackage = serde_json::from_value(vector["package"].clone()).unwrap();
            let header = package.header().unwrap();
            assert_eq!(header, bytes(&vector, "header_hex"));
            let secret = bytes(&vector, "private_key_hex");
            let payload = if package.collection_mode == EncryptionMode::Standard {
                open::<X25519HkdfSha256>(&secret, &package, &header)
            } else {
                open::<XWing>(&secret, &package, &header)
            }
            .unwrap();
            assert_eq!(*payload, bytes(&vector, "payload_hex"));
            let key =
                VerifyingKey::from_bytes(&bytes(&vector, "signing_public_hex").try_into().unwrap())
                    .unwrap();
            key.verify_strict(
                &package.message().unwrap(),
                &Signature::from_slice(&decode(&package.signature, 64).unwrap()).unwrap(),
            )
            .unwrap();
        }
    }
}
