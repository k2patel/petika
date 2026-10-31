//! Synthetic, in-process model for ADR 0005. No file/network input or production keys.
#[path = "../../../crates/petika-core/src/identity/hybrid_hpke.rs"]
mod hybrid_hpke;

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, kdf::HkdfSha256, kem::X25519HkdfSha256,
    rand_core::SeedableRng,
};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

type Id = [u8; 32];
type Result<T> = std::result::Result<T, &'static str>;
fn random() -> Id {
    let mut b = [0; 32];
    getrandom::getrandom(&mut b).unwrap();
    b
}
fn bytes<T: Serialize>(domain: &str, value: &T) -> Vec<u8> {
    serde_json::to_vec(&("petika:synthetic-device-model:v1", domain, value)).unwrap()
}
fn digest<T: Serialize>(domain: &str, value: &T) -> Id {
    Sha256::digest(bytes(domain, value)).into()
}
fn verify(key: &Id, domain: &str, value: &impl Serialize, signature: &[u8]) -> Result<()> {
    VerifyingKey::from_bytes(key)
        .map_err(|_| "signing key")?
        .verify_strict(
            &bytes(domain, value),
            &Signature::from_slice(signature).map_err(|_| "signature")?,
        )
        .map_err(|_| "signature")
}
fn sign(key: &SigningKey, domain: &str, value: &impl Serialize) -> Vec<u8> {
    key.sign(&bytes(domain, value)).to_bytes().to_vec()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum Profile {
    Standard,
    HybridDraft06,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct DeviceRecord {
    deployment: Id,
    account: Id,
    device: Id,
    standard: Vec<u8>,
    hybrid: Vec<u8>,
    signing: Id,
}
impl DeviceRecord {
    fn fingerprint(&self) -> Id {
        digest("device", self)
    }
}
struct Device {
    record: DeviceRecord,
    standard: <X25519HkdfSha256 as Kem>::PrivateKey,
    hybrid: <hybrid_hpke::XWing as Kem>::PrivateKey,
    signing: SigningKey,
}
impl Device {
    fn new(deployment: Id, account: Id) -> Self {
        let seed = Zeroizing::new(random());
        let (standard, standard_public) = X25519HkdfSha256::derive_keypair(&*seed);
        let seed = Zeroizing::new(random());
        let (hybrid, hybrid_public) = hybrid_hpke::XWing::derive_keypair(&*seed);
        let seed = Zeroizing::new(random());
        let signing = SigningKey::from_bytes(&seed);
        let record = DeviceRecord {
            deployment,
            account,
            device: random(),
            standard: standard_public.to_bytes().to_vec(),
            hybrid: hybrid_public.to_bytes().to_vec(),
            signing: signing.verifying_key().to_bytes(),
        };
        Self {
            record,
            standard,
            hybrid,
            signing,
        }
    }
    fn open(
        &self,
        profile: Profile,
        packet: &Packet,
        binding: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        match profile {
            Profile::Standard => decapsulate::<X25519HkdfSha256>(&self.standard, packet, binding),
            Profile::HybridDraft06 => {
                decapsulate::<hybrid_hpke::XWing>(&self.hybrid, packet, binding)
            }
        }
    }
    fn answer(&self, pending: &Pending) -> Result<Proof> {
        if self.record != pending.record {
            return Err("device substitution");
        }
        let binding = pending.binding();
        let first = self.open(Profile::Standard, &pending.standard, &binding)?;
        let second = self.open(Profile::HybridDraft06, &pending.hybrid, &binding)?;
        // Prove possession of BOTH encryption keys, and sign the exact request.
        let response = digest("possession", &(&*first, &*second, &binding));
        Ok(Proof {
            response,
            signature: sign(&self.signing, "proof", &(response, binding)),
        })
    }
}
#[derive(Clone, Serialize)]
struct Packet {
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
}
fn encapsulate<K: Kem>(public: &[u8], payload: &[u8], binding: &[u8]) -> Result<Packet> {
    let mut rng = ChaCha20Rng::from_seed(random());
    let (enc, ciphertext) =
        hpke::single_shot_seal::<hpke::aead::ChaCha20Poly1305, HkdfSha256, K, _>(
            &OpModeS::Base,
            &K::PublicKey::from_bytes(public).map_err(|_| "public key")?,
            binding,
            payload,
            binding,
            &mut rng,
        )
        .map_err(|_| "encapsulation")?;
    Ok(Packet {
        enc: enc.to_bytes().to_vec(),
        ciphertext,
    })
}
fn decapsulate<K: Kem>(
    key: &K::PrivateKey,
    packet: &Packet,
    binding: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    hpke::single_shot_open::<hpke::aead::ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Base,
        key,
        &K::EncappedKey::from_bytes(&packet.enc).map_err(|_| "encapsulation")?,
        binding,
        &packet.ciphertext,
        binding,
    )
    .map(Zeroizing::new)
    .map_err(|_| "decrypt")
}
fn seal_for(
    record: &DeviceRecord,
    profile: Profile,
    payload: &[u8],
    binding: &[u8],
) -> Result<Packet> {
    match profile {
        Profile::Standard => encapsulate::<X25519HkdfSha256>(&record.standard, payload, binding),
        Profile::HybridDraft06 => {
            encapsulate::<hybrid_hpke::XWing>(&record.hybrid, payload, binding)
        }
    }
}

#[derive(Clone, Serialize)]
struct RosterBody {
    deployment: Id,
    account: Id,
    authority: Id,
    generation: u64,
    parent: Id,
    // Revoked IDs remain tombstones and cannot be re-enrolled.
    devices: BTreeMap<Id, DeviceRecord>,
    revoked: Vec<Id>,
}
#[derive(Clone)]
struct Roster {
    body: RosterBody,
    signature: Vec<u8>,
}
impl Roster {
    // BTreeMap array keys cannot be JSON object keys; encode as ordered pairs.
    fn transcript(&self) -> impl Serialize + '_ {
        (
            &self.body.deployment,
            &self.body.account,
            &self.body.authority,
            self.body.generation,
            &self.body.parent,
            self.body.devices.iter().collect::<Vec<_>>(),
            &self.body.revoked,
        )
    }
    fn hash(&self) -> Id {
        digest("roster", &self.transcript())
    }
    fn verify(&self, authority: &Id) -> Result<()> {
        if &self.body.authority != authority
            || self.body.generation == 0
            || self.body.devices.len() > 64
        {
            return Err("roster framing");
        }
        for (id, device) in &self.body.devices {
            if id != &device.device
                || device.deployment != self.body.deployment
                || device.account != self.body.account
                || self.body.revoked.contains(id)
            {
                return Err("roster binding");
            }
        }
        verify(authority, "roster", &self.transcript(), &self.signature)
    }
}
struct Pending {
    record: DeviceRecord,
    parent: Id,
    nonce: Id,
    expires: u64,
    standard: Packet,
    hybrid: Packet,
    // Kept only by the approving authority; not sent to server/new device.
    first: Zeroizing<Id>,
    second: Zeroizing<Id>,
}
impl Pending {
    fn binding(&self) -> Vec<u8> {
        bytes(
            "enrollment",
            &(&self.record, self.parent, self.nonce, self.expires),
        )
    }
}
struct Proof {
    response: Id,
    signature: Vec<u8>,
}
struct Authority {
    key: SigningKey,
    roster: Roster,
}
impl Authority {
    fn new(deployment: Id, account: Id) -> Self {
        let seed = Zeroizing::new(random());
        let key = SigningKey::from_bytes(&seed);
        let mut result = Self {
            roster: Roster {
                body: RosterBody {
                    deployment,
                    account,
                    authority: key.verifying_key().to_bytes(),
                    generation: 1,
                    parent: [0; 32],
                    devices: BTreeMap::new(),
                    revoked: vec![],
                },
                signature: vec![],
            },
            key,
        };
        result.sign_roster();
        result
    }
    fn sign_roster(&mut self) {
        let signature = sign(&self.key, "roster", &self.roster.transcript());
        self.roster.signature = signature;
    }
    fn challenge(&self, record: DeviceRecord, now: u64) -> Result<Pending> {
        if record.deployment != self.roster.body.deployment
            || record.account != self.roster.body.account
            || self.roster.body.devices.contains_key(&record.device)
            || self.roster.body.revoked.contains(&record.device)
            || self.roster.body.devices.len() >= 64
        {
            return Err("enrollment scope");
        }
        let empty = Packet {
            enc: vec![],
            ciphertext: vec![],
        };
        let mut p = Pending {
            record,
            parent: self.roster.hash(),
            nonce: random(),
            expires: now.checked_add(300).ok_or("clock overflow")?,
            standard: empty.clone(),
            hybrid: empty,
            first: Zeroizing::new(random()),
            second: Zeroizing::new(random()),
        };
        p.standard = seal_for(&p.record, Profile::Standard, &*p.first, &p.binding())?;
        p.hybrid = seal_for(&p.record, Profile::HybridDraft06, &*p.second, &p.binding())?;
        Ok(p)
    }
    fn enroll(
        &mut self,
        pending: &Pending,
        proof: &Proof,
        confirmed_fingerprint: Id,
        now: u64,
    ) -> Result<()> {
        if now >= pending.expires
            || pending.parent != self.roster.hash()
            || confirmed_fingerprint != pending.record.fingerprint()
        {
            return Err("stale or unconfirmed enrollment");
        }
        let expected = digest(
            "possession",
            &(&pending.first[..], &pending.second[..], pending.binding()),
        );
        if expected != proof.response {
            return Err("encryption possession");
        }
        verify(
            &pending.record.signing,
            "proof",
            &(proof.response, pending.binding()),
            &proof.signature,
        )?;
        let generation = self
            .roster
            .body
            .generation
            .checked_add(1)
            .ok_or("generation overflow")?;
        self.roster.body.parent = self.roster.hash();
        self.roster.body.generation = generation;
        self.roster
            .body
            .devices
            .insert(pending.record.device, pending.record.clone());
        self.sign_roster();
        Ok(())
    }
    fn revoke(&mut self, device: Id, expected: Id) -> Result<()> {
        if expected != self.roster.hash() || !self.roster.body.devices.contains_key(&device) {
            return Err("revoke conflict");
        }
        let generation = self
            .roster
            .body
            .generation
            .checked_add(1)
            .ok_or("generation overflow")?;
        self.roster.body.parent = expected;
        self.roster.body.generation = generation;
        self.roster.body.devices.remove(&device);
        self.roster.body.revoked.push(device);
        self.sign_roster();
        Ok(())
    }
}

struct Pin {
    roster: Roster,
}
impl Pin {
    fn bootstrap(roster: Roster, confirmed_hash: Id, confirmed_authority: Id) -> Result<Self> {
        roster.verify(&confirmed_authority)?;
        if roster.hash() != confirmed_hash {
            return Err("unconfirmed roster");
        }
        Ok(Self { roster })
    }
    fn accept(&mut self, next: Roster) -> Result<()> {
        next.verify(&self.roster.body.authority)?;
        if next.hash() == self.roster.hash() {
            return Ok(());
        }
        if next.body.deployment != self.roster.body.deployment
            || next.body.account != self.roster.body.account
            || next.body.parent != self.roster.hash()
            || Some(next.body.generation) != self.roster.body.generation.checked_add(1)
        {
            return Err("rollback, fork or missing history");
        }
        self.roster = next;
        Ok(())
    }
}

#[derive(Clone, Serialize)]
struct CollectionBody {
    deployment: Id,
    account: Id,
    collection: Id,
    epoch: u64,
    roster: Id,
    profile: Profile,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    wrappers: Vec<(Id, Packet)>,
}
#[derive(Clone)]
struct Collection {
    body: CollectionBody,
    signature: Vec<u8>,
}
impl CollectionBody {
    fn binding(&self) -> Vec<u8> {
        bytes(
            "collection",
            &(
                self.deployment,
                self.account,
                self.collection,
                self.epoch,
                self.roster,
                self.profile,
            ),
        )
    }
}
impl Collection {
    fn issue(
        authority: &Authority,
        collection: Id,
        epoch: u64,
        profile: Profile,
        plaintext: &[u8],
    ) -> Result<Self> {
        if epoch == 0 {
            return Err("epoch");
        }
        let key = Zeroizing::new(random());
        let mut body = CollectionBody {
            deployment: authority.roster.body.deployment,
            account: authority.roster.body.account,
            collection,
            epoch,
            roster: authority.roster.hash(),
            profile,
            nonce: random()[..12].try_into().unwrap(),
            ciphertext: vec![],
            wrappers: vec![],
        };
        let binding = body.binding();
        body.ciphertext = ChaCha20Poly1305::new_from_slice(&*key)
            .unwrap()
            .encrypt(
                (&body.nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &binding,
                },
            )
            .map_err(|_| "seal")?;
        for device in authority.roster.body.devices.values() {
            let recipient_binding = bytes("delivery", &(&binding, device.fingerprint()));
            body.wrappers.push((
                device.device,
                seal_for(device, profile, &*key, &recipient_binding)?,
            ));
        }
        Ok(Self {
            signature: sign(&authority.key, "collection", &body),
            body,
        })
    }
    fn open(
        &self,
        device: &Device,
        pin: &Pin,
        expected_collection: Id,
        expected_epoch: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let body = &self.body;
        if body.collection != expected_collection
            || body.epoch != expected_epoch
            || body.roster != pin.roster.hash()
            || body.deployment != pin.roster.body.deployment
            || body.account != pin.roster.body.account
            || pin.roster.body.devices.get(&device.record.device) != Some(&device.record)
        {
            return Err("collection scope or revoked device");
        }
        verify(
            &pin.roster.body.authority,
            "collection",
            body,
            &self.signature,
        )?;
        let packet = &body
            .wrappers
            .iter()
            .find(|(id, _)| id == &device.record.device)
            .ok_or("missing wrapper")?
            .1;
        let binding = body.binding();
        let key = device.open(
            body.profile,
            packet,
            &bytes("delivery", &(&binding, device.record.fingerprint())),
        )?;
        ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| "key length")?
            .decrypt(
                (&body.nonce).into(),
                Payload {
                    msg: &body.ciphertext,
                    aad: &binding,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| "decrypt")
    }
}

fn enroll(authority: &mut Authority, device: &Device) -> Result<()> {
    let pending = authority.challenge(device.record.clone(), 100)?;
    // Synthetic harness supplies an independently retained fingerprint, never directory trust.
    authority.enroll(
        &pending,
        &device.answer(&pending)?,
        device.record.fingerprint(),
        101,
    )
}
fn pin(roster: &Roster) -> Pin {
    Pin::bootstrap(roster.clone(), roster.hash(), roster.body.authority).unwrap()
}
fn scenario(profile: Profile) -> Result<()> {
    let deployment = random();
    let account = random();
    let collection = random();
    let mut authority = Authority::new(deployment, account);
    let a = Device::new(deployment, account);
    let b = Device::new(deployment, account);
    assert_ne!(a.record.fingerprint(), b.record.fingerprint());
    enroll(&mut authority, &a)?;
    enroll(&mut authority, &b)?;
    let old_pin = pin(&authority.roster);
    let mut current = pin(&authority.roster);
    let old = Collection::issue(&authority, collection, 1, profile, b"synthetic collection")?;
    for device in [&a, &b] {
        assert_eq!(
            &*old.open(device, &old_pin, collection, 1)?,
            b"synthetic collection"
        );
    }
    authority.revoke(a.record.device, authority.roster.hash())?;
    current.accept(authority.roster.clone())?;
    let next = Collection::issue(&authority, collection, 2, profile, b"new synthetic epoch")?;
    assert_eq!(
        &*next.open(&b, &current, collection, 2)?,
        b"new synthetic epoch"
    );
    assert!(next.open(&a, &current, collection, 2).is_err());
    // Bypass roster checks: retired private keys still cannot open B's new package.
    let binding = bytes("delivery", &(&next.body.binding(), b.record.fingerprint()));
    assert!(a.open(profile, &next.body.wrappers[0].1, &binding).is_err());
    assert!(old.open(&b, &current, collection, 2).is_err());
    assert_eq!(
        &*old.open(&a, &old_pin, collection, 1)?,
        b"synthetic collection"
    );
    assert!(current.accept(old_pin.roster).is_err());
    assert!(authority.challenge(a.record.clone(), 102).is_err());
    Ok(())
}
fn main() -> Result<()> {
    for profile in [Profile::Standard, Profile::HybridDraft06] {
        scenario(profile)?;
        println!(
            "{profile:?}: two same-account device keys, fresh-epoch exclusion, historical access and rollback rejection passed (software model only)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removal_invalidates_pending_enrollment_and_retained_authority_can_start_over() {
        let mut authority = Authority::new(random(), random());
        let first = Device::new(
            authority.roster.body.deployment,
            authority.roster.body.account,
        );
        let replacement = Device::new(
            authority.roster.body.deployment,
            authority.roster.body.account,
        );
        enroll(&mut authority, &first).unwrap();
        let pending = authority
            .challenge(replacement.record.clone(), 100)
            .unwrap();
        let proof = replacement.answer(&pending).unwrap();
        let mut trusted = pin(&authority.roster);
        authority
            .revoke(first.record.device, authority.roster.hash())
            .unwrap();
        trusted.accept(authority.roster.clone()).unwrap();
        assert!(authority.roster.body.devices.is_empty());
        assert!(
            authority
                .enroll(&pending, &proof, replacement.record.fingerprint(), 101)
                .is_err()
        );
        // Only the separately retained authority survives. This proves re-enrollment,
        // not recovery of a collection secret lost with every device.
        enroll(&mut authority, &replacement).unwrap();
        trusted.accept(authority.roster.clone()).unwrap();
        assert!(
            !trusted
                .roster
                .body
                .devices
                .contains_key(&first.record.device)
        );
        let mut fork = authority.roster.clone();
        fork.body.parent = random();
        fork.body.generation += 1;
        let signature = sign(&authority.key, "roster", &fork.transcript());
        fork.signature = signature;
        assert!(trusted.accept(fork).is_err());
    }
    #[test]
    fn two_devices_both_profiles() {
        for p in [Profile::Standard, Profile::HybridDraft06] {
            scenario(p).unwrap();
        }
    }
    #[test]
    fn enrollment_rejects_forgery_substitution_expiry_replay_and_concurrency() {
        let mut a = Authority::new(random(), random());
        let device = Device::new(a.roster.body.deployment, a.roster.body.account);
        let p = a.challenge(device.record.clone(), 100).unwrap();
        let proof = device.answer(&p).unwrap();
        let before = a.roster.hash();
        assert!(a.enroll(&p, &proof, random(), 101).is_err());
        assert!(
            a.enroll(&p, &proof, device.record.fingerprint(), 400)
                .is_err()
        );
        let forged = Proof {
            response: random(),
            signature: proof.signature.clone(),
        };
        assert!(
            a.enroll(&p, &forged, device.record.fingerprint(), 101)
                .is_err()
        );
        let forged = Proof {
            response: proof.response,
            signature: vec![0; 64],
        };
        assert!(
            a.enroll(&p, &forged, device.record.fingerprint(), 101)
                .is_err()
        );
        let other = Device::new(a.roster.body.deployment, a.roster.body.account);
        assert!(other.answer(&p).is_err());
        let concurrent = a.challenge(other.record.clone(), 100).unwrap();
        assert_eq!(before, a.roster.hash());
        a.enroll(&p, &proof, device.record.fingerprint(), 101)
            .unwrap();
        assert!(
            a.enroll(&p, &proof, device.record.fingerprint(), 101)
                .is_err()
        );
        assert!(
            a.enroll(
                &concurrent,
                &other.answer(&concurrent).unwrap(),
                other.record.fingerprint(),
                101
            )
            .is_err()
        );
        assert!(a.revoke(device.record.device, before).is_err());
        let foreign = Device::new(random(), a.roster.body.account);
        assert!(a.challenge(foreign.record, 100).is_err());
    }
    #[test]
    fn each_encryption_key_must_be_possessed() {
        let a = Authority::new(random(), random());
        for profile in [Profile::Standard, Profile::HybridDraft06] {
            let mut device = Device::new(a.roster.body.deployment, a.roster.body.account);
            let other = Device::new(a.roster.body.deployment, a.roster.body.account);
            match profile {
                Profile::Standard => device.record.standard = other.record.standard,
                Profile::HybridDraft06 => device.record.hybrid = other.record.hybrid,
            }
            let pending = a.challenge(device.record.clone(), 100).unwrap();
            assert!(device.answer(&pending).is_err());
        }
    }
    #[test]
    fn roster_and_collection_tamper_and_scope_are_rejected() {
        let mut a = Authority::new(random(), random());
        let device = Device::new(a.roster.body.deployment, a.roster.body.account);
        enroll(&mut a, &device).unwrap();
        let trusted = pin(&a.roster);
        let mut forged = a.roster.clone();
        forged.body.revoked.push(random());
        assert!(forged.verify(&a.roster.body.authority).is_err());
        assert!(Pin::bootstrap(a.roster.clone(), random(), a.roster.body.authority).is_err());
        for profile in [Profile::Standard, Profile::HybridDraft06] {
            let id = random();
            let original = Collection::issue(&a, id, 1, profile, b"synthetic").unwrap();
            assert!(original.open(&device, &trusted, random(), 1).is_err());
            assert!(original.open(&device, &trusted, id, 2).is_err());
            for field in 0..5 {
                let mut forged = original.clone();
                match field {
                    0 => forged.body.ciphertext[0] ^= 1,
                    1 => forged.body.wrappers[0].1.ciphertext[0] ^= 1,
                    2 => {
                        forged.body.profile = if profile == Profile::Standard {
                            Profile::HybridDraft06
                        } else {
                            Profile::Standard
                        }
                    }
                    3 => forged.body.wrappers[0].0 = random(),
                    _ => forged.signature[0] ^= 1,
                }
                assert!(forged.open(&device, &trusted, id, 1).is_err());
            }
        }
    }
}
