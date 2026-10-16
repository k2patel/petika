//! Client-only recipient identities. Account authentication never unlocks this material.
//!
//! This module supplies the local foundation, not enrollment, group-key delivery, or
//! a trust directory. An enrollment self-signature does not verify a person's identity.
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x_wing::{Decapsulate, Decapsulator, Encapsulate, KeyExport};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result, crypto};

pub const MAX_IDENTITY_BYTES: usize = 128 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_COUNTER: u64 = (1 << 53) - 1;
const KDF: &str = "argon2id-v19-m65536-t3-p1";
const IDENTITY_DOMAIN: &[u8] = b"petika:recipient-identity:v1";
const SIGNATURE_DOMAIN: &[u8] = b"petika:recipient-enrollment:v1";
const BUNDLE_DOMAIN: &[u8] = b"petika:recipient-private-bundle:v1";
const SUITES: [&[u8]; 3] = [b"x25519", b"xwing-draft06", b"ed25519"];

/// Public transport record only. Validate before trusting its framing or signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdentity {
    pub deployment_id: String,
    pub user_id: String,
    pub identity_version: u64,
    pub fingerprint: String,
    pub standard_public_key: String,
    pub hybrid_public_key: String,
    pub signing_public_key: String,
    pub signature: String,
}

/// Ciphertext transport record, separate from an account password or password entry.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedIdentityBundle {
    pub bundle_version: u32,
    pub identity_fingerprint: String,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
    pub kdf: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    backup_version: u32,
    public_identity: PublicIdentity,
    encrypted_bundle: EncryptedIdentityBundle,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct PrivateIdentity {
    standard_secret: [u8; 32],
    hybrid_seed: [u8; 32],
    signing_seed: [u8; 32],
    fingerprint: String,
}

/// Owns zeroizing private seeds. Deliberately has no Debug, Clone, or Serialize impl.
pub struct UnlockedIdentity {
    public: PublicIdentity,
    private: PrivateIdentity,
}

fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn decode(value: &str, expected: usize) -> Result<Vec<u8>> {
    if value.len() != expected.div_ceil(3) * 4 {
        return Err(Error::Format);
    }
    let bytes = STANDARD.decode(value).map_err(|_| Error::Format)?;
    if bytes.len() != expected || STANDARD.encode(&bytes) != value {
        return Err(Error::Format);
    }
    Ok(bytes)
}

fn field(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

impl PublicIdentity {
    /// Canonical public encoding, independent of JSON ordering and whitespace.
    fn transcript(&self) -> Result<Vec<u8>> {
        if !valid_id(&self.deployment_id)
            || !valid_id(&self.user_id)
            || !(1..=MAX_COUNTER).contains(&self.identity_version)
        {
            return Err(Error::Format);
        }
        let standard = decode(&self.standard_public_key, 32)?;
        let standard_array: [u8; 32] = standard.as_slice().try_into().map_err(|_| Error::Format)?;
        let probe = x25519_dalek::StaticSecret::from([0x42; 32]);
        if !probe
            .diffie_hellman(&x25519_dalek::PublicKey::from(standard_array))
            .was_contributory()
        {
            return Err(Error::Format);
        }
        let hybrid = decode(&self.hybrid_public_key, x_wing::ENCAPSULATION_KEY_SIZE)?;
        let signing = decode(&self.signing_public_key, 32)?;
        // Reject malformed hybrid public keys before any encapsulation attempt.
        x_wing::EncapsulationKey::try_from(hybrid.as_slice()).map_err(|_| Error::Format)?;
        let mut bytes = Vec::new();
        field(&mut bytes, IDENTITY_DOMAIN);
        field(&mut bytes, self.deployment_id.as_bytes());
        field(&mut bytes, self.user_id.as_bytes());
        bytes.extend_from_slice(&self.identity_version.to_be_bytes());
        for (suite, public) in SUITES.iter().zip([&standard, &hybrid, &signing]) {
            field(&mut bytes, suite);
            field(&mut bytes, public);
        }
        Ok(bytes)
    }

    fn signature_message(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        field(&mut bytes, SIGNATURE_DOMAIN);
        field(&mut bytes, &self.transcript()?);
        field(&mut bytes, self.fingerprint.as_bytes());
        Ok(bytes)
    }

    /// Checks framing, fingerprint, and self-signature, not human identity/trust.
    pub fn validate(&self) -> Result<()> {
        let fingerprint = hex(&Sha256::digest(self.transcript()?));
        if self.fingerprint != fingerprint {
            return Err(Error::Authentication);
        }
        let key: [u8; 32] = decode(&self.signing_public_key, 32)?
            .try_into()
            .map_err(|_| Error::Format)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| Error::Format)?;
        let signature =
            Signature::from_slice(&decode(&self.signature, 64)?).map_err(|_| Error::Format)?;
        key.verify_strict(&self.signature_message()?, &signature)
            .map_err(|_| Error::Authentication)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl PrivateIdentity {
    fn public(&self, deployment: &str, user: &str, version: u64) -> Result<PublicIdentity> {
        let standard = x25519_dalek::StaticSecret::from(self.standard_secret);
        let hybrid = x_wing::DecapsulationKey::from(self.hybrid_seed);
        let signing = SigningKey::from_bytes(&self.signing_seed);
        let mut public = PublicIdentity {
            deployment_id: deployment.into(),
            user_id: user.into(),
            identity_version: version,
            fingerprint: String::new(),
            standard_public_key: STANDARD
                .encode(x25519_dalek::PublicKey::from(&standard).as_bytes()),
            hybrid_public_key: STANDARD.encode(hybrid.encapsulation_key().to_bytes()),
            signing_public_key: STANDARD.encode(signing.verifying_key().as_bytes()),
            signature: String::new(),
        };
        public.fingerprint = hex(&Sha256::digest(public.transcript()?));
        public.signature = STANDARD.encode(signing.sign(&public.signature_message()?).to_bytes());
        Ok(public)
    }

    fn self_check(&self) -> Result<()> {
        let standard = x25519_dalek::StaticSecret::from(self.standard_secret);
        let peer_seed = Zeroizing::new(crypto::random()?);
        let peer = x25519_dalek::StaticSecret::from(*peer_seed);
        let ours = standard.diffie_hellman(&x25519_dalek::PublicKey::from(&peer));
        let theirs = peer.diffie_hellman(&x25519_dalek::PublicKey::from(&standard));
        if !ours.was_contributory() || ours.as_bytes() != theirs.as_bytes() {
            return Err(Error::Authentication);
        }
        let hybrid = x_wing::DecapsulationKey::from(self.hybrid_seed);
        let (ciphertext, mut shared) = hybrid.encapsulation_key().encapsulate();
        let mut restored = hybrid.decapsulate(&ciphertext);
        let matches = shared == restored;
        shared.zeroize();
        restored.zeroize();
        if !matches {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

fn bundle_aad(fingerprint: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    field(&mut bytes, BUNDLE_DOMAIN);
    bytes.extend_from_slice(&1u32.to_be_bytes());
    field(&mut bytes, fingerprint.as_bytes());
    field(&mut bytes, KDF.as_bytes());
    bytes
}

impl UnlockedIdentity {
    pub fn generate(deployment: &str, user: &str, version: u64) -> Result<Self> {
        if !valid_id(deployment) || !valid_id(user) || !(1..=MAX_COUNTER).contains(&version) {
            return Err(Error::Format);
        }
        let mut private = PrivateIdentity {
            standard_secret: [0; 32],
            hybrid_seed: [0; 32],
            signing_seed: [0; 32],
            fingerprint: String::new(),
        };
        // Construct the zeroizing owner before any fallible random generation.
        // A later RNG failure then also clears seeds already generated.
        getrandom::getrandom(&mut private.standard_secret).map_err(|_| Error::Random)?;
        getrandom::getrandom(&mut private.hybrid_seed).map_err(|_| Error::Random)?;
        getrandom::getrandom(&mut private.signing_seed).map_err(|_| Error::Random)?;
        let public = private.public(deployment, user, version)?;
        private.fingerprint = public.fingerprint.clone();
        private.self_check()?;
        public.validate()?;
        Ok(Self { public, private })
    }

    pub fn public_identity(&self) -> &PublicIdentity {
        &self.public
    }

    /// Re-encrypts the same identity with fresh salt/nonce; does not rotate its keys.
    pub fn seal(&self, passphrase: &str) -> Result<Vec<u8>> {
        crypto::check_passphrase(passphrase)?;
        // Bound input as well as stored KDF parameters before expensive work.
        if passphrase.len() > 4096 {
            return Err(Error::Format);
        }
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&self.private).map_err(|_| Error::Format)?);
        let salt = crypto::random::<16>()?;
        let nonce = crypto::random::<24>()?;
        let wrapping_key = crypto::derive(passphrase, &salt)?;
        let ciphertext = crypto::encrypt(
            &wrapping_key,
            &nonce,
            &plaintext,
            &bundle_aad(&self.public.fingerprint),
        )?;
        let backup = Backup {
            backup_version: 1,
            public_identity: self.public.clone(),
            encrypted_bundle: EncryptedIdentityBundle {
                bundle_version: 1,
                identity_fingerprint: self.public.fingerprint.clone(),
                salt: STANDARD.encode(salt),
                nonce: STANDARD.encode(nonce),
                ciphertext: STANDARD.encode(ciphertext),
                kdf: KDF.into(),
            },
        };
        serde_json::to_vec(&backup).map_err(|_| Error::Format)
    }

    /// Restores only the independently expected identity. A server-supplied fingerprint
    /// is not a trust anchor; use a verified pin or separately retained recovery record.
    pub fn open(bytes: &[u8], passphrase: &str, expected_fingerprint: &str) -> Result<Self> {
        if bytes.len() > MAX_IDENTITY_BYTES
            || passphrase.len() > 4096
            || !valid_id(expected_fingerprint)
        {
            return Err(Error::Format);
        }
        let backup: Backup = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        let bundle = &backup.encrypted_bundle;
        if backup.backup_version != 1
            || bundle.bundle_version != 1
            || bundle.kdf != KDF
            || bundle.ciphertext.len() > MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4
        {
            return Err(Error::Format);
        }
        if backup.public_identity.fingerprint != expected_fingerprint
            || bundle.identity_fingerprint != expected_fingerprint
        {
            return Err(Error::Authentication);
        }
        backup.public_identity.validate()?;
        let salt: [u8; 16] = decode(&bundle.salt, 16)?
            .try_into()
            .map_err(|_| Error::Format)?;
        let nonce: [u8; 24] = decode(&bundle.nonce, 24)?
            .try_into()
            .map_err(|_| Error::Format)?;
        let ciphertext = STANDARD
            .decode(&bundle.ciphertext)
            .map_err(|_| Error::Format)?;
        if ciphertext.len() < 16
            || ciphertext.len() > MAX_CIPHERTEXT_BYTES
            || STANDARD.encode(&ciphertext) != bundle.ciphertext
        {
            return Err(Error::Format);
        }
        let wrapping_key = crypto::derive(passphrase, &salt)?;
        let plaintext = crypto::decrypt(
            &wrapping_key,
            &nonce,
            &ciphertext,
            &bundle_aad(expected_fingerprint),
        )?;
        let private: PrivateIdentity =
            serde_json::from_slice(&plaintext).map_err(|_| Error::Format)?;
        let public = &backup.public_identity;
        if private.fingerprint != expected_fingerprint
            || private.public(
                &public.deployment_id,
                &public.user_id,
                public.identity_version,
            )? != *public
        {
            return Err(Error::Authentication);
        }
        private.self_check()?;
        Ok(Self {
            public: backup.public_identity,
            private,
        })
    }
}

/// Native encrypted identity storage using the same exclusive lock and atomic-write
/// protections as collections. No server enrollment or automatic overwrite is implied.
#[cfg(not(target_arch = "wasm32"))]
pub struct IdentityFile(crate::StoreFile);

#[cfg(not(target_arch = "wasm32"))]
impl IdentityFile {
    pub fn lock(path: impl AsRef<std::path::Path>) -> Result<Self> {
        crate::StoreFile::lock(path).map(Self)
    }

    pub fn open(&self, passphrase: &str, fingerprint: &str) -> Result<UnlockedIdentity> {
        UnlockedIdentity::open(
            &self.0.read_limited(MAX_IDENTITY_BYTES)?,
            passphrase,
            fingerprint,
        )
    }

    pub fn save(&self, identity: &UnlockedIdentity, passphrase: &str, create: bool) -> Result<()> {
        self.0.write(&identity.seal(passphrase)?, create)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn public_derivation_and_fingerprint_match_independent_vectors() {
        let vector: Value =
            serde_json::from_str(include_str!("../tests/fixtures/identity-v1.json")).unwrap();
        let private = PrivateIdentity {
            standard_secret: unhex(vector["standard_secret_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            hybrid_seed: unhex(vector["hybrid_seed_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            signing_seed: unhex(vector["signing_seed_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            fingerprint: String::new(),
        };
        let public = private.public(&"a".repeat(64), &"b".repeat(64), 1).unwrap();
        assert_eq!(public.fingerprint, vector["fingerprint"]);
        for (actual, field) in [
            (&public.standard_public_key, "standard_public_hex"),
            (&public.hybrid_public_key, "hybrid_public_hex"),
            (&public.signing_public_key, "signing_public_hex"),
        ] {
            assert_eq!(
                STANDARD.decode(actual).unwrap(),
                unhex(vector[field].as_str().unwrap())
            );
        }
        public.validate().unwrap();
    }

    #[test]
    fn authenticated_but_inconsistent_private_keys_are_rejected() {
        let identity = UnlockedIdentity::generate(&"a".repeat(64), &"b".repeat(64), 1).unwrap();
        let passphrase = "synthetic identity passphrase";
        let bytes = identity.seal(passphrase).unwrap();
        let mut backup: Backup = serde_json::from_slice(&bytes).unwrap();
        let bundle = &mut backup.encrypted_bundle;
        let salt: [u8; 16] = decode(&bundle.salt, 16).unwrap().try_into().unwrap();
        let nonce: [u8; 24] = decode(&bundle.nonce, 24).unwrap().try_into().unwrap();
        let key = crypto::derive(passphrase, &salt).unwrap();
        let aad = bundle_aad(&bundle.identity_fingerprint);
        let ciphertext = STANDARD.decode(&bundle.ciphertext).unwrap();
        let plaintext = crypto::decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
        let mut private: PrivateIdentity = serde_json::from_slice(&plaintext).unwrap();
        private.signing_seed[0] ^= 1;
        let changed = Zeroizing::new(serde_json::to_vec(&private).unwrap());
        // Synthetic corruption fixture; use a fresh nonce even in the test.
        let new_nonce = crypto::random().unwrap();
        bundle.nonce = STANDARD.encode(new_nonce);
        bundle.ciphertext =
            STANDARD.encode(crypto::encrypt(&key, &new_nonce, &changed, &aad).unwrap());
        let changed_backup = serde_json::to_vec(&backup).unwrap();
        assert!(matches!(
            UnlockedIdentity::open(&changed_backup, passphrase, &identity.public.fingerprint),
            Err(Error::Authentication)
        ));
    }
}
