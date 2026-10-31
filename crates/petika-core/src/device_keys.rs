//! Candidate device enrollment core for draft ADR 0005. No account API or vault access.
//! Public signatures prove consistency/possession of a signing key, not human trust.
mod enrollment;
#[cfg(not(target_arch = "wasm32"))]
mod journal;
mod roster;
pub use enrollment::{
    ENROLLMENT_LIFETIME_SECONDS, EnrollmentChallenge, EnrollmentPacket, EnrollmentProof,
    EnrollmentRequest, MAX_ENROLLMENT_CHALLENGE_BYTES, MAX_ENROLLMENT_PROOF_BYTES,
    MAX_ENROLLMENT_REQUEST_BYTES, PendingEnrollment,
};
#[cfg(not(target_arch = "wasm32"))]
pub use journal::{
    DeviceRosterJournal, MAX_ROSTER_JOURNAL_BYTES, MAX_ROSTER_PUBLICATIONS, PublicationReceipt,
};
pub use roster::{
    DeviceRoster, MAX_ACTIVE_DEVICES, MAX_REVOKED_DEVICES, MAX_ROSTER_BYTES, TrustedDeviceRoster,
};

use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x_wing::{Decapsulator, KeyExport};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_DEVICE_RECORD_BYTES: usize = 8192;
pub const MAX_AUTHORITY_BYTES: usize = 2048;
pub const MAX_GENERATION: u64 = (1 << 53) - 1;
const RECORD_DOMAIN: &[u8] = b"petika:device-record:experimental-v1";
const SELF_DOMAIN: &[u8] = b"petika:device-self-signature:experimental-v1";
const AUTHORITY_DOMAIN: &[u8] = b"petika:device-authority:experimental-v1";

fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash(value: &[u8]) -> String {
    hex(&Sha256::digest(value))
}
fn decode(value: &str, length: usize) -> Result<Vec<u8>> {
    if value.len() != length.div_ceil(3) * 4 {
        return Err(Error::Format);
    }
    let bytes = STANDARD.decode(value).map_err(|_| Error::Format)?;
    if bytes.len() != length || STANDARD.encode(&bytes) != value {
        return Err(Error::Format);
    }
    Ok(bytes)
}
fn signing_key(value: &str) -> Result<VerifyingKey> {
    let key: [u8; 32] = decode(value, 32)?.try_into().map_err(|_| Error::Format)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| Error::Format)?;
    if key.is_weak() {
        return Err(Error::Format);
    }
    Ok(key)
}
fn verify(key: &str, message: &[u8], signature: &str) -> Result<()> {
    let signature = Signature::from_slice(&decode(signature, 64)?).map_err(|_| Error::Format)?;
    signing_key(key)?
        .verify_strict(message, &signature)
        .map_err(|_| Error::Authentication)
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T> {
    if bytes.len() > limit {
        return Err(Error::Format);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Format)
}
fn validate_x25519(bytes: &[u8]) -> Result<()> {
    let public: [u8; 32] = bytes.try_into().map_err(|_| Error::Format)?;
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    if public.iter().rev().cmp(prime.iter().rev()) != std::cmp::Ordering::Less {
        return Err(Error::Format);
    }
    let probe = x25519_dalek::StaticSecret::from([0x42; 32]);
    if !probe
        .diffie_hellman(&x25519_dalek::PublicKey::from(public))
        .was_contributory()
    {
        return Err(Error::Format);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    pub record_version: u32,
    pub deployment_id: String,
    pub user_id: String,
    pub device_id: String,
    pub standard_public_key: String,
    pub hybrid_public_key: String,
    pub signing_public_key: String,
    pub fingerprint: String,
    pub signature: String,
}
impl DeviceRecord {
    /// Canonical transcript, not JSON bytes. Does not establish trust or possession.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.record_version != 1
            || [&self.deployment_id, &self.user_id, &self.device_id]
                .iter()
                .any(|v| !id(v))
        {
            return Err(Error::Format);
        }
        let standard = decode(&self.standard_public_key, 32)?;
        // Reject noncanonical u-coordinates (RFC 7748 decoders otherwise reduce/mask).
        validate_x25519(&standard)?;
        let hybrid = decode(&self.hybrid_public_key, 1216)?;
        x_wing::EncapsulationKey::try_from(hybrid.as_slice()).map_err(|_| Error::Format)?;
        validate_x25519(&hybrid[1184..])?;
        let signing = signing_key(&self.signing_public_key)?;
        let mut out = Vec::new();
        field(&mut out, RECORD_DOMAIN);
        out.extend_from_slice(&self.record_version.to_be_bytes());
        for value in [&self.deployment_id, &self.user_id, &self.device_id] {
            field(&mut out, value.as_bytes());
        }
        for (suite, key) in [
            (b"x25519".as_slice(), standard.as_slice()),
            (b"xwing-draft06", hybrid.as_slice()),
            (b"ed25519", signing.as_bytes()),
        ] {
            field(&mut out, suite);
            field(&mut out, key);
        }
        Ok(out)
    }
    fn signature_message(&self) -> Result<Vec<u8>> {
        let transcript = self.canonical_bytes()?;
        if self.fingerprint != hash(&transcript) {
            return Err(Error::Authentication);
        }
        let mut out = Vec::new();
        field(&mut out, SELF_DOMAIN);
        field(&mut out, &transcript);
        field(&mut out, self.fingerprint.as_bytes());
        Ok(out)
    }
    pub fn validate(&self) -> Result<()> {
        verify(
            &self.signing_public_key,
            &self.signature_message()?,
            &self.signature,
        )
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let record: Self = parse(bytes, MAX_DEVICE_RECORD_BYTES)?;
        record.validate()?;
        Ok(record)
    }
}

/// Seeds are zeroized on drop; no serialization, cloning or debug output.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceIdentity {
    standard_secret: [u8; 32],
    hybrid_seed: [u8; 32],
    signing_seed: [u8; 32],
    deployment_id: String,
    user_id: String,
    device_id: String,
}
impl DeviceIdentity {
    pub fn generate(deployment_id: &str, user_id: &str) -> Result<Self> {
        if !id(deployment_id) || !id(user_id) {
            return Err(Error::Format);
        }
        let mut value = Self {
            standard_secret: [0; 32],
            hybrid_seed: [0; 32],
            signing_seed: [0; 32],
            deployment_id: deployment_id.into(),
            user_id: user_id.into(),
            device_id: String::new(),
        };
        getrandom::getrandom(&mut value.standard_secret).map_err(|_| Error::Random)?;
        getrandom::getrandom(&mut value.hybrid_seed).map_err(|_| Error::Random)?;
        getrandom::getrandom(&mut value.signing_seed).map_err(|_| Error::Random)?;
        value.device_id = hex(&crate::crypto::random::<32>()?);
        value.public_record()?.validate()?;
        Ok(value)
    }
    pub fn public_record(&self) -> Result<DeviceRecord> {
        let standard = x25519_dalek::StaticSecret::from(self.standard_secret);
        let hybrid = x_wing::DecapsulationKey::from(self.hybrid_seed);
        let signer = SigningKey::from_bytes(&self.signing_seed);
        let mut record = DeviceRecord {
            record_version: 1,
            deployment_id: self.deployment_id.clone(),
            user_id: self.user_id.clone(),
            device_id: self.device_id.clone(),
            standard_public_key: STANDARD
                .encode(x25519_dalek::PublicKey::from(&standard).as_bytes()),
            hybrid_public_key: STANDARD.encode(hybrid.encapsulation_key().to_bytes()),
            signing_public_key: STANDARD.encode(signer.verifying_key().as_bytes()),
            fingerprint: String::new(),
            signature: String::new(),
        };
        record.fingerprint = hash(&record.canonical_bytes()?);
        record.signature = STANDARD.encode(signer.sign(&record.signature_message()?).to_bytes());
        Ok(record)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthority {
    pub authority_version: u32,
    pub deployment_id: String,
    pub user_id: String,
    pub signing_public_key: String,
    pub fingerprint: String,
}
impl DeviceAuthority {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.authority_version != 1 || !id(&self.deployment_id) || !id(&self.user_id) {
            return Err(Error::Format);
        }
        let key = signing_key(&self.signing_public_key)?;
        let mut out = Vec::new();
        field(&mut out, AUTHORITY_DOMAIN);
        out.extend_from_slice(&self.authority_version.to_be_bytes());
        field(&mut out, self.deployment_id.as_bytes());
        field(&mut out, self.user_id.as_bytes());
        field(&mut out, b"ed25519");
        field(&mut out, key.as_bytes());
        Ok(out)
    }
    pub fn validate(&self) -> Result<()> {
        if self.fingerprint != hash(&self.canonical_bytes()?) {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse(bytes, MAX_AUTHORITY_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceAuthorityKey {
    seed: [u8; 32],
    deployment_id: String,
    user_id: String,
}
impl DeviceAuthorityKey {
    pub fn generate(deployment_id: &str, user_id: &str) -> Result<Self> {
        if !id(deployment_id) || !id(user_id) {
            return Err(Error::Format);
        }
        let mut value = Self {
            seed: [0; 32],
            deployment_id: deployment_id.into(),
            user_id: user_id.into(),
        };
        getrandom::getrandom(&mut value.seed).map_err(|_| Error::Random)?;
        Ok(value)
    }
    pub fn public_record(&self) -> Result<DeviceAuthority> {
        let mut value = DeviceAuthority {
            authority_version: 1,
            deployment_id: self.deployment_id.clone(),
            user_id: self.user_id.clone(),
            signing_public_key: STANDARD.encode(
                SigningKey::from_bytes(&self.seed)
                    .verifying_key()
                    .as_bytes(),
            ),
            fingerprint: String::new(),
        };
        value.fingerprint = hash(&value.canonical_bytes()?);
        Ok(value)
    }
}
