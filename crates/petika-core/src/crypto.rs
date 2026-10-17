use std::collections::BTreeMap;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use x_wing::{Decapsulate, Decapsulator, Encapsulate};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES: usize = 2 * 1024 * 1024;
const KEY_AAD: &[u8] = b"petika:local:v1:wrapping-key";
const DATA_AAD: &[u8] = b"petika:local:v1:records";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionMode {
    Standard,
    HybridPostQuantum,
}
impl EncryptionMode {
    fn key_aad(self) -> &'static [u8] {
        match self {
            Self::Standard => KEY_AAD,
            Self::HybridPostQuantum => b"petika:local:v1:xwing-draft06:seed",
        }
    }
    fn data_aad(self) -> &'static [u8] {
        match self {
            Self::Standard => DATA_AAD,
            Self::HybridPostQuantum => b"petika:local:v1:xwing-draft06:records",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("incorrect passphrase or modified encrypted data")]
    Authentication,
    #[error("invalid, oversized, or unsupported store format")]
    Format,
    #[error("a new passphrase must contain at least 12 characters")]
    WeakPassphrase,
    #[error("record name must be nonempty, at most 256 bytes, and contain no control characters")]
    InvalidName,
    #[error("record already exists; use explicit replacement")]
    Duplicate,
    #[error("record not found")]
    NotFound,
    #[error("contact identity has not been independently verified")]
    UnverifiedContact,
    #[error("contact key changed; explicit verification is required")]
    ContactKeyChanged,
    #[error("contact identity version is older than the verified version")]
    ContactRollback,
    #[error("contact trust state changed; review the current pin and retry")]
    ContactConflict,
    #[error("verified contact limit reached")]
    ContactLimit,
    #[error("store already exists")]
    AlreadyExists,
    #[error("store is busy in another process")]
    Busy,
    #[error("store and lock must be regular files with owner-only permissions on Unix")]
    Permissions,
    #[error("operating-system random generator failed")]
    Random,
    #[error("password length must be between 16 and 256")]
    PasswordLength,
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otp: Option<String>,
}

/// Authenticated location and key generation for recipient-enabled collections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionContext {
    pub deployment_id: String,
    pub collection_id: String,
    pub key_epoch: u64,
}
impl CollectionContext {
    pub fn validate(&self) -> Result<()> {
        let valid = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !valid(&self.deployment_id)
            || !valid(&self.collection_id)
            || !(1..=(1u64 << 53) - 1).contains(&self.key_epoch)
        {
            return Err(Error::Format);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<CollectionContext>,
    version: u32,
    encryption: EncryptionMode,
    kem_ciphertext: Vec<u8>,
    kdf: String,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    salt: [u8; 16],
    key_nonce: [u8; 24],
    wrapped_key: Vec<u8>,
    data_nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl Envelope {
    fn aad(&self, wrapping: bool) -> Vec<u8> {
        let legacy = if wrapping {
            self.encryption.key_aad()
        } else {
            self.encryption.data_aad()
        };
        let Some(context) = &self.context else {
            return legacy.to_vec();
        };
        let mut bytes = b"petika:collection:v2:".to_vec();
        bytes.extend_from_slice(legacy);
        bytes.extend_from_slice(context.deployment_id.as_bytes());
        bytes.extend_from_slice(context.collection_id.as_bytes());
        bytes.extend_from_slice(&context.key_epoch.to_be_bytes());
        bytes
    }
}

/// An unlocked store owns keys and records only for its lifetime. It never implements Debug.
pub struct UnlockedStore {
    envelope: Envelope,
    key: Zeroizing<[u8; 32]>,
    secret_material: Zeroizing<[u8; 32]>,
    entries: BTreeMap<String, Entry>,
}

impl Drop for UnlockedStore {
    fn drop(&mut self) {
        // BTreeMap keys need explicit wiping; Entry wipes its own fields.
        for (mut name, _) in std::mem::take(&mut self.entries) {
            name.zeroize();
        }
    }
}

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    Ok(bytes)
}

pub(crate) fn derive(passphrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| Error::Format)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Format)?;
    Ok(key)
}

pub(crate) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    message: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg: message, aad })
        .map_err(|_| Error::Format)
}

pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    message: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: message, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

fn parse(bytes: &[u8]) -> Result<Envelope> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Error::Format);
    }
    let e: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
    if !matches!((e.version, &e.context), (1, None) | (2, Some(_)))
        || e.kdf != "argon2id-v19"
        || e.memory_kib != 65536
        || e.iterations != 3
        || e.lanes != 1
        || e.wrapped_key.len() != 48
        || e.ciphertext.len() < 16
        || e.ciphertext.len() > MAX_PLAINTEXT_BYTES + 16
    {
        return Err(Error::Format);
    }
    if let Some(context) = &e.context {
        context.validate()?;
    }
    match e.encryption {
        EncryptionMode::Standard if !e.kem_ciphertext.is_empty() => return Err(Error::Format),
        EncryptionMode::HybridPostQuantum if e.kem_ciphertext.len() != x_wing::CIPHERTEXT_SIZE => {
            return Err(Error::Format);
        }
        _ => {}
    }
    Ok(e)
}

/// Returns validated public framing, without authenticating ciphertext.
pub fn envelope_metadata(bytes: &[u8]) -> Result<(EncryptionMode, Option<CollectionContext>)> {
    let envelope = parse(bytes)?;
    Ok((envelope.encryption, envelope.context))
}

/// Validate framing only. An untrusted server cannot authenticate client ciphertext.
pub fn validate_envelope(bytes: &[u8]) -> Result<()> {
    parse(bytes).map(|_| ())
}

impl UnlockedStore {
    pub fn create(passphrase: &str) -> Result<Self> {
        Self::create_with_mode(passphrase, EncryptionMode::Standard)
    }

    pub fn create_with_mode(passphrase: &str, encryption: EncryptionMode) -> Result<Self> {
        check_passphrase(passphrase)?;
        let secret_material = Zeroizing::new(random()?);
        let (key, kem_ciphertext) = match encryption {
            EncryptionMode::Standard => (Zeroizing::new(*secret_material), Vec::new()),
            EncryptionMode::HybridPostQuantum => {
                let identity = x_wing::DecapsulationKey::from(*secret_material);
                let (ciphertext, mut shared) = identity.encapsulation_key().encapsulate();
                let mut key = Zeroizing::new([0; 32]);
                key.copy_from_slice(&shared);
                shared.zeroize();
                (key, ciphertext.to_vec())
            }
        };
        let salt = random()?;
        let key_nonce = random()?;
        let wrapping_key = derive(passphrase, &salt)?;
        let wrapped_key = encrypt(
            &wrapping_key,
            &key_nonce,
            secret_material.as_ref(),
            encryption.key_aad(),
        )?;
        Ok(Self {
            envelope: Envelope {
                version: 1,
                context: None,
                encryption,
                kem_ciphertext,
                kdf: "argon2id-v19".into(),
                memory_kib: 65536,
                iterations: 3,
                lanes: 1,
                salt,
                key_nonce,
                wrapped_key,
                data_nonce: [0; 24],
                ciphertext: Vec::new(),
            },
            key,
            secret_material,
            entries: BTreeMap::new(),
        })
    }

    pub fn open(bytes: &[u8], passphrase: &str) -> Result<Self> {
        let envelope = parse(bytes)?;
        let wrapping_key = derive(passphrase, &envelope.salt)?;
        let unwrapped = decrypt(
            &wrapping_key,
            &envelope.key_nonce,
            &envelope.wrapped_key,
            &envelope.aad(true),
        )?;
        let mut secret_material = Zeroizing::new([0; 32]);
        if unwrapped.len() != secret_material.len() {
            return Err(Error::Format);
        }
        secret_material.copy_from_slice(&unwrapped);
        Self::open_material(envelope, secret_material)
    }

    pub(crate) fn access_material(&self) -> &[u8; 32] {
        &self.secret_material
    }

    pub(crate) fn open_access(
        bytes: &[u8],
        material: Zeroizing<[u8; 32]>,
        context: &CollectionContext,
        mode: EncryptionMode,
    ) -> Result<Self> {
        let envelope = parse(bytes)?;
        if envelope.context.as_ref() != Some(context) || envelope.encryption != mode {
            return Err(Error::Authentication);
        }
        Self::open_material(envelope, material)
    }

    fn open_material(envelope: Envelope, secret_material: Zeroizing<[u8; 32]>) -> Result<Self> {
        let key = match envelope.encryption {
            EncryptionMode::Standard => Zeroizing::new(*secret_material),
            EncryptionMode::HybridPostQuantum => {
                let identity = x_wing::DecapsulationKey::from(*secret_material);
                let mut shared = identity
                    .decapsulate_slice(&envelope.kem_ciphertext)
                    .map_err(|_| Error::Format)?;
                let mut key = Zeroizing::new([0; 32]);
                key.copy_from_slice(&shared);
                shared.zeroize();
                key
            }
        };
        let plaintext = decrypt(
            &key,
            &envelope.data_nonce,
            &envelope.ciphertext,
            &envelope.aad(false),
        )?;
        let entries: BTreeMap<String, Entry> =
            serde_json::from_slice(&plaintext).map_err(|_| Error::Format)?;
        for name in entries.keys() {
            check_name(name)?;
        }
        Ok(Self {
            envelope,
            key,
            secret_material,
            entries,
        })
    }

    /// Produces ciphertext only, with a fresh data nonce every time.
    pub fn seal(&mut self) -> Result<Vec<u8>> {
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&self.entries).map_err(|_| Error::Format)?);
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(Error::Format);
        }
        self.envelope.data_nonce = random()?;
        self.envelope.ciphertext = encrypt(
            &self.key,
            &self.envelope.data_nonce,
            &plaintext,
            &self.envelope.aad(false),
        )?;
        let encoded = serde_json::to_vec(&self.envelope).map_err(|_| Error::Format)?;
        if encoded.len() > MAX_FILE_BYTES {
            return Err(Error::Format);
        }
        Ok(encoded)
    }

    pub fn context(&self) -> Option<&CollectionContext> {
        self.envelope.context.as_ref()
    }

    /// Explicitly adopt collection binding, preserving the existing secret and mode.
    /// The caller retains the original ciphertext until its migration commits.
    pub fn migration_draft(
        &self,
        context: CollectionContext,
        recovery_passphrase: &str,
    ) -> Result<Self> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.entries).map_err(|_| Error::Format)?);
        let mut draft = Self {
            envelope: self.envelope.clone(),
            key: Zeroizing::new(*self.key),
            secret_material: Zeroizing::new(*self.secret_material),
            entries: serde_json::from_slice(&bytes).map_err(|_| Error::Format)?,
        };
        draft.bind_collection(context, recovery_passphrase)?;
        Ok(draft)
    }

    pub fn bind_collection(
        &mut self,
        context: CollectionContext,
        recovery_passphrase: &str,
    ) -> Result<()> {
        context.validate()?;
        if self.envelope.context.is_some() || context.key_epoch != 1 {
            return Err(Error::Format);
        }
        check_passphrase(recovery_passphrase)?;
        self.envelope.context = Some(context);
        self.envelope.version = 2;
        if let Err(error) = self.change_passphrase(recovery_passphrase) {
            self.envelope.context = None;
            self.envelope.version = 1;
            return Err(error);
        }
        Ok(())
    }

    /// Fresh secret material and a fresh recovery wrapper for the next epoch.
    /// Returns a separate draft so a failed server transaction preserves this session.
    pub fn rotated(&self, recovery_passphrase: &str) -> Result<Self> {
        let mut context = self.context().ok_or(Error::Format)?.clone();
        context.key_epoch = context.key_epoch.checked_add(1).ok_or(Error::Format)?;
        context.validate()?;
        let mut next = Self::create_with_mode(recovery_passphrase, self.encryption())?;
        next.envelope.context = Some(context);
        next.envelope.version = 2;
        next.change_passphrase(recovery_passphrase)?;
        let bytes = Zeroizing::new(serde_json::to_vec(&self.entries).map_err(|_| Error::Format)?);
        next.entries = serde_json::from_slice(&bytes).map_err(|_| Error::Format)?;
        Ok(next)
    }

    pub fn encryption(&self) -> EncryptionMode {
        self.envelope.encryption
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }
    pub fn get(&self, name: &str) -> Result<&Entry> {
        self.entries.get(name).ok_or(Error::NotFound)
    }
    pub fn put(&mut self, name: String, entry: Entry, replace: bool) -> Result<()> {
        check_name(&name)?;
        if self.entries.contains_key(&name) && !replace {
            return Err(Error::Duplicate);
        }
        self.entries.insert(name, entry);
        Ok(())
    }
    pub fn remove(&mut self, name: &str) -> Result<()> {
        let (mut name, _) = self.entries.remove_entry(name).ok_or(Error::NotFound)?;
        name.zeroize();
        Ok(())
    }
    pub fn change_passphrase(&mut self, passphrase: &str) -> Result<()> {
        check_passphrase(passphrase)?;
        let salt = random()?;
        let nonce = random()?;
        let wrapping_key = derive(passphrase, &salt)?;
        let wrapped = encrypt(
            &wrapping_key,
            &nonce,
            self.secret_material.as_ref(),
            &self.envelope.aad(true),
        )?;
        self.envelope.salt = salt;
        self.envelope.key_nonce = nonce;
        self.envelope.wrapped_key = wrapped;
        Ok(())
    }
}

pub(crate) fn check_passphrase(value: &str) -> Result<()> {
    if value.chars().count() < 12 {
        Err(Error::WeakPassphrase)
    } else {
        Ok(())
    }
}
fn check_name(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(Error::InvalidName)
    } else {
        Ok(())
    }
}

/// Uniform sampling through rejection, without modulo bias.
pub fn generate_password(length: usize) -> Result<Zeroizing<String>> {
    if !(16..=256).contains(&length) {
        return Err(Error::PasswordLength);
    }
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    let limit = 256 - (256 % ALPHABET.len());
    let mut password = Zeroizing::new(String::with_capacity(length));
    while password.len() < length {
        let byte = random::<1>()?[0] as usize;
        if byte < limit {
            password.push(ALPHABET[byte % ALPHABET.len()] as char);
        }
    }
    Ok(password)
}
