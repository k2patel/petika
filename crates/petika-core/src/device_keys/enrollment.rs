//! Candidate request/challenge/proof protocol. Pending secrets are client-only.
use super::*;
use crate::identity::hybrid_hpke::XWing;
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, rand_core::SeedableRng,
};
use rand_chacha::ChaCha20Rng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

pub const ENROLLMENT_LIFETIME_SECONDS: u64 = 300;
pub const MAX_ENROLLMENT_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_ENROLLMENT_CHALLENGE_BYTES: usize = 24 * 1024;
pub const MAX_ENROLLMENT_PROOF_BYTES: usize = 2048;
const PAYLOAD_TAG: &[u8] = b"petika:device-possession:experimental-v1\0";

fn domain(name: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    field(&mut out, name);
    field(&mut out, body);
    out
}
fn eligible(record: &DeviceRecord, roster: &DeviceRoster) -> Result<()> {
    record.validate()?;
    if record.deployment_id != roster.authority.deployment_id
        || record.user_id != roster.authority.user_id
        || roster.generation == MAX_GENERATION
        || roster.devices.len() >= MAX_ACTIVE_DEVICES
        || roster.revoked_device_ids.contains(&record.device_id)
        || record.signing_public_key == roster.authority.signing_public_key
        || roster.devices.iter().any(|d| {
            d.device_id == record.device_id
                || d.standard_public_key == record.standard_public_key
                || d.hybrid_public_key == record.hybrid_public_key
                || d.signing_public_key == record.signing_public_key
        })
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub request_version: u32,
    pub authority: DeviceAuthority,
    pub device: DeviceRecord,
    pub roster_generation: u64,
    pub roster_digest: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
impl EnrollmentRequest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.authority.validate()?;
        self.device.validate()?;
        if self.request_version != 1
            || !(1..MAX_GENERATION).contains(&self.roster_generation)
            || !id(&self.roster_digest)
            || !id(&self.nonce)
            || self.issued_at == 0
            || self.expires_at > MAX_GENERATION
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > ENROLLMENT_LIFETIME_SECONDS
            || self.device.deployment_id != self.authority.deployment_id
            || self.device.user_id != self.authority.user_id
            || self.device.signing_public_key == self.authority.signing_public_key
        {
            return Err(Error::Format);
        }
        let mut out = Vec::new();
        field(
            &mut out,
            b"petika:device-enrollment-request:experimental-v1",
        );
        out.extend_from_slice(&self.request_version.to_be_bytes());
        field(&mut out, &self.authority.canonical_bytes()?);
        field(&mut out, self.authority.fingerprint.as_bytes());
        field(&mut out, &self.device.canonical_bytes()?);
        field(&mut out, self.device.fingerprint.as_bytes());
        field(&mut out, &decode(&self.device.signature, 64)?);
        out.extend_from_slice(&self.roster_generation.to_be_bytes());
        field(&mut out, self.roster_digest.as_bytes());
        field(&mut out, self.nonce.as_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(out)
    }
    pub fn validate(&self) -> Result<()> {
        verify(
            &self.device.signing_public_key,
            &self.canonical_bytes()?,
            &self.signature,
        )
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let mut out = self.canonical_bytes()?;
        field(&mut out, &decode(&self.signature, 64)?);
        Ok(hash(&out))
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse(bytes, MAX_ENROLLMENT_REQUEST_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    fn validate_for(&self, current: &TrustedDeviceRoster, now: u64) -> Result<()> {
        self.validate()?;
        let roster = current.roster();
        if self.authority != roster.authority
            || self.roster_generation != roster.generation
            || self.roster_digest != roster.digest()?
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(Error::Authentication);
        }
        eligible(&self.device, roster)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentPacket {
    pub enc: String,
    pub ciphertext: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentChallenge {
    pub challenge_version: u32,
    pub request: EnrollmentRequest,
    pub standard: EnrollmentPacket,
    pub hybrid: EnrollmentPacket,
    pub signature: String,
}
impl EnrollmentChallenge {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.challenge_version != 1 {
            return Err(Error::Format);
        }
        let mut out = Vec::new();
        field(
            &mut out,
            b"petika:device-enrollment-challenge:experimental-v1",
        );
        out.extend_from_slice(&self.challenge_version.to_be_bytes());
        field(&mut out, self.request.digest()?.as_bytes());
        for (suite, packet, enc_len) in [
            (b"standard".as_slice(), &self.standard, 32),
            (b"experimental-xwing-draft06", &self.hybrid, 1120),
        ] {
            field(&mut out, suite);
            field(&mut out, &decode(&packet.enc, enc_len)?);
            field(
                &mut out,
                &decode(&packet.ciphertext, PAYLOAD_TAG.len() + 32 + 16)?,
            );
        }
        Ok(out)
    }
    pub fn validate(&self) -> Result<()> {
        verify(
            &self.request.authority.signing_public_key,
            &self.canonical_bytes()?,
            &self.signature,
        )
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let mut out = self.canonical_bytes()?;
        field(&mut out, &decode(&self.signature, 64)?);
        Ok(hash(&out))
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse(bytes, MAX_ENROLLMENT_CHALLENGE_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentProof {
    pub proof_version: u32,
    pub request_digest: String,
    pub challenge_digest: String,
    pub response: String,
    pub signature: String,
}
impl EnrollmentProof {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.proof_version != 1 || !id(&self.request_digest) || !id(&self.challenge_digest) {
            return Err(Error::Format);
        }
        let mut out = Vec::new();
        field(&mut out, b"petika:device-enrollment-proof:experimental-v1");
        out.extend_from_slice(&self.proof_version.to_be_bytes());
        field(&mut out, self.request_digest.as_bytes());
        field(&mut out, self.challenge_digest.as_bytes());
        field(&mut out, &decode(&self.response, 32)?);
        Ok(out)
    }
    /// Structural parsing only; verify against the retained pending challenge.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse(bytes, MAX_ENROLLMENT_PROOF_BYTES)?;
        value.canonical_bytes()?;
        decode(&value.signature, 64)?;
        Ok(value)
    }
}

fn hpke_binding(request_digest: &str, suite: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    field(&mut out, request_digest.as_bytes());
    field(&mut out, suite);
    out
}
fn seal<K: Kem>(public: &[u8], secret: &[u8; 32], binding: &[u8]) -> Result<EnrollmentPacket> {
    let mut payload = Zeroizing::new(PAYLOAD_TAG.to_vec());
    payload.extend_from_slice(secret);
    let mut rng = ChaCha20Rng::from_seed(crate::crypto::random()?);
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, K, _>(
        &OpModeS::Base,
        &K::PublicKey::from_bytes(public).map_err(|_| Error::Format)?,
        &domain(
            b"petika:device-enrollment-hpke-info:experimental-v1",
            binding,
        ),
        &payload,
        &domain(
            b"petika:device-enrollment-hpke-aad:experimental-v1",
            binding,
        ),
        &mut rng,
    )
    .map_err(|_| Error::Authentication)?;
    Ok(EnrollmentPacket {
        enc: STANDARD.encode(enc.to_bytes()),
        ciphertext: STANDARD.encode(ct),
    })
}
fn open<K: Kem>(
    secret: &[u8; 32],
    packet: &EnrollmentPacket,
    binding: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let payload = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, K>(
            &OpModeR::Base,
            &K::PrivateKey::from_bytes(secret).map_err(|_| Error::Format)?,
            &K::EncappedKey::from_bytes(&STANDARD.decode(&packet.enc).map_err(|_| Error::Format)?)
                .map_err(|_| Error::Format)?,
            &domain(
                b"petika:device-enrollment-hpke-info:experimental-v1",
                binding,
            ),
            &decode(&packet.ciphertext, PAYLOAD_TAG.len() + 32 + 16)?,
            &domain(
                b"petika:device-enrollment-hpke-aad:experimental-v1",
                binding,
            ),
        )
        .map_err(|_| Error::Authentication)?,
    );
    if payload.len() != PAYLOAD_TAG.len() + 32 || !payload.starts_with(PAYLOAD_TAG) {
        return Err(Error::Authentication);
    }
    Ok(Zeroizing::new(payload[PAYLOAD_TAG.len()..].to_vec()))
}
fn response(challenge_digest: &str, first: &[u8], second: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new(Vec::new());
    field(
        &mut bytes,
        b"petika:device-enrollment-response:experimental-v1",
    );
    field(&mut bytes, challenge_digest.as_bytes());
    field(&mut bytes, first);
    field(&mut bytes, second);
    Zeroizing::new(Sha256::digest(&*bytes).into())
}

impl DeviceIdentity {
    /// Caller supplies an independently bootstrapped roster and trusted current time.
    pub fn enrollment_request(
        &self,
        current: &TrustedDeviceRoster,
        now: u64,
    ) -> Result<EnrollmentRequest> {
        let roster = current.roster();
        let device = self.public_record()?;
        eligible(&device, roster)?;
        let mut request = EnrollmentRequest {
            request_version: 1,
            authority: roster.authority.clone(),
            device,
            roster_generation: roster.generation,
            roster_digest: roster.digest()?,
            nonce: hex(&crate::crypto::random::<32>()?),
            issued_at: now,
            expires_at: now
                .checked_add(ENROLLMENT_LIFETIME_SECONDS)
                .ok_or(Error::Format)?,
            signature: String::new(),
        };
        request.signature = STANDARD.encode(
            SigningKey::from_bytes(&self.signing_seed)
                .sign(&request.canonical_bytes()?)
                .to_bytes(),
        );
        Ok(request)
    }
    pub fn answer_enrollment(
        &self,
        challenge: &EnrollmentChallenge,
        current: &TrustedDeviceRoster,
        confirmed_authority_fingerprint: &str,
        now: u64,
    ) -> Result<EnrollmentProof> {
        challenge.validate()?;
        challenge.request.validate_for(current, now)?;
        if challenge.request.device != self.public_record()?
            || confirmed_authority_fingerprint != current.roster().authority.fingerprint
        {
            return Err(Error::Authentication);
        }
        let request_digest = challenge.request.digest()?;
        let first = open::<X25519HkdfSha256>(
            &self.standard_secret,
            &challenge.standard,
            &hpke_binding(&request_digest, b"standard"),
        )?;
        let second = open::<XWing>(
            &self.hybrid_seed,
            &challenge.hybrid,
            &hpke_binding(&request_digest, b"experimental-xwing-draft06"),
        )?;
        let challenge_digest = challenge.digest()?;
        let mut proof = EnrollmentProof {
            proof_version: 1,
            request_digest,
            response: STANDARD.encode(response(&challenge_digest, &first, &second).as_slice()),
            challenge_digest,
            signature: String::new(),
        };
        proof.signature = STANDARD.encode(
            SigningKey::from_bytes(&self.signing_seed)
                .sign(&proof.canonical_bytes()?)
                .to_bytes(),
        );
        Ok(proof)
    }
}

/// Client-only expected response; not serializable, clonable or printable. Drop cancels.
pub struct PendingEnrollment {
    challenge: EnrollmentChallenge,
    expected: Zeroizing<[u8; 32]>,
    used: bool,
}
impl DeviceAuthorityKey {
    pub fn challenge_enrollment(
        &self,
        request: EnrollmentRequest,
        current: &TrustedDeviceRoster,
        confirmed_device_fingerprint: &str,
        now: u64,
    ) -> Result<PendingEnrollment> {
        request.validate_for(current, now)?;
        if self.public_record()? != request.authority
            || confirmed_device_fingerprint != request.device.fingerprint
        {
            return Err(Error::Authentication);
        }
        let first = Zeroizing::new(crate::crypto::random::<32>()?);
        let second = Zeroizing::new(crate::crypto::random::<32>()?);
        let digest = request.digest()?;
        let standard = seal::<X25519HkdfSha256>(
            &decode(&request.device.standard_public_key, 32)?,
            &first,
            &hpke_binding(&digest, b"standard"),
        )?;
        let hybrid = seal::<XWing>(
            &decode(&request.device.hybrid_public_key, 1216)?,
            &second,
            &hpke_binding(&digest, b"experimental-xwing-draft06"),
        )?;
        let mut challenge = EnrollmentChallenge {
            challenge_version: 1,
            request,
            standard,
            hybrid,
            signature: String::new(),
        };
        challenge.signature = STANDARD.encode(
            SigningKey::from_bytes(&self.seed)
                .sign(&challenge.canonical_bytes()?)
                .to_bytes(),
        );
        let expected = response(&challenge.digest()?, &*first, &*second);
        Ok(PendingEnrollment {
            challenge,
            expected,
            used: false,
        })
    }
}
impl PendingEnrollment {
    pub fn challenge(&self) -> &EnrollmentChallenge {
        &self.challenge
    }
    /// Returns an uncommitted signed successor. Does NOT advance the pin; preserve
    /// this candidate for submission retries, publish via CAS, then accept the receipt.
    /// A successful pending ceremony is consumed once. Failed checks do not mutate it.
    pub fn approve(
        &mut self,
        authority: &DeviceAuthorityKey,
        proof: &EnrollmentProof,
        current: &TrustedDeviceRoster,
        confirmed_device_fingerprint: &str,
        now: u64,
    ) -> Result<DeviceRoster> {
        if self.used {
            return Err(Error::Authentication);
        }
        let request = &self.challenge.request;
        request.validate_for(current, now)?;
        if authority.public_record()? != request.authority
            || confirmed_device_fingerprint != request.device.fingerprint
            || proof.request_digest != request.digest()?
            || proof.challenge_digest != self.challenge.digest()?
        {
            return Err(Error::Authentication);
        }
        verify(
            &request.device.signing_public_key,
            &proof.canonical_bytes()?,
            &proof.signature,
        )?;
        if !bool::from(
            self.expected
                .as_slice()
                .ct_eq(&decode(&proof.response, 32)?),
        ) {
            return Err(Error::Authentication);
        }
        let mut devices = current.roster().devices.clone();
        devices.push(request.device.clone());
        devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let candidate = authority.sign_roster(
            request.roster_generation + 1,
            request.roster_digest.clone(),
            devices,
            current.roster().revoked_device_ids.clone(),
        )?;
        // Also run the same adjacent-transition rules used after publication.
        let mut check = TrustedDeviceRoster::bootstrap(
            current.roster().clone(),
            &request.authority.fingerprint,
            &request.roster_digest,
        )?;
        check.accept(candidate.clone())?;
        self.used = true;
        self.expected.zeroize();
        Ok(candidate)
    }
}
