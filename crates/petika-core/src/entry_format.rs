//! Opt-in entry/index cryptographic prototype, not a vault storage format yet.
//! No automatic epoch transition, legacy package conversion, or format migration.
pub mod checkpoint;
#[cfg(not(target_arch = "wasm32"))]
pub mod checkpoint_store;
pub mod history;
pub mod index;
pub mod rotation;
pub mod transport;
use crate::{Error, Result, crypto};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const SUITE: &str = "xchacha20poly1305-hkdf-sha256-v1";
pub const MAX_COUNTER: u64 = (1u64 << 53) - 1;
pub const MAX_ENTRY_BYTES: usize = 256 * 1024;
pub const MAX_INDEX_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_WRAPPER_BYTES: usize = 4096;
const ROOT_TAG: &[u8] = b"petika:entry-root:v1\0";
const WRAPPER_PROFILE: &str = "argon2id-v19-xchacha20poly1305-entry-root-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub deployment_id: String,
    pub collection_id: String,
    pub key_epoch: u64,
    /// Canonical padded base64, exactly 32 bytes.
    pub epoch_salt: String,
}
pub(crate) fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn counter(value: u64) -> bool {
    (1..=MAX_COUNTER).contains(&value)
}
pub(crate) fn decode(value: &str, max: usize) -> Result<Vec<u8>> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err(Error::Format);
    }
    let decoded = STANDARD.decode(value).map_err(|_| Error::Format)?;
    if decoded.len() > max || STANDARD.encode(&decoded) != value {
        return Err(Error::Format);
    }
    Ok(decoded)
}
pub(crate) fn fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    decode(value, N)?.try_into().map_err(|_| Error::Format)
}
pub(crate) fn field(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}
impl Context {
    pub fn validate(&self) -> Result<()> {
        if !id(&self.deployment_id) || !id(&self.collection_id) || !counter(self.key_epoch) {
            return Err(Error::Format);
        }
        fixed::<32>(&self.epoch_salt)?;
        Ok(())
    }
    pub(crate) fn append(&self, out: &mut Vec<u8>) {
        field(out, self.deployment_id.as_bytes());
        field(out, self.collection_id.as_bytes());
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Entry,
    Index,
}
impl Kind {
    fn name(&self) -> &[u8] {
        match self {
            Self::Entry => b"entry",
            Self::Index => b"index",
        }
    }
    fn limit(&self) -> usize {
        match self {
            Self::Entry => MAX_ENTRY_BYTES,
            Self::Index => MAX_INDEX_BYTES,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub entry_format_version: u32,
    pub suite: String,
    pub context: Context,
    pub kind: Kind,
    /// Empty for the singleton index; 64 lowercase hex characters for an entry.
    pub object_id: String,
    pub revision: u64,
}
impl Header {
    pub fn validate(&self) -> Result<()> {
        self.context.validate()?;
        if self.entry_format_version != 1
            || self.suite != SUITE
            || !counter(self.revision)
            || match self.kind {
                Kind::Entry => !id(&self.object_id),
                Kind::Index => !self.object_id.is_empty(),
            }
        {
            return Err(Error::Format);
        }
        Ok(())
    }
    pub fn key_info(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        field(&mut out, b"petika:entry-format:kdf:v1");
        out.extend_from_slice(&self.entry_format_version.to_be_bytes());
        field(&mut out, self.suite.as_bytes());
        self.context.append(&mut out);
        field(&mut out, self.kind.name());
        field(&mut out, self.object_id.as_bytes());
        Ok(out)
    }
    pub fn aad(&self) -> Result<Vec<u8>> {
        let info = self.key_info()?;
        let mut out = Vec::new();
        field(&mut out, b"petika:entry-format:aead:v1");
        field(&mut out, &info);
        field(&mut out, &fixed::<32>(&self.context.epoch_salt)?);
        out.extend_from_slice(&self.revision.to_be_bytes());
        Ok(out)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    header: Header,
    nonce: String,
    ciphertext: String,
}

/// Checks bounded public encoding only; does not authenticate ciphertext or
/// encrypted index semantics. Servers must never treat this as decryption proof.
pub fn inspect_envelope(bytes: &[u8], expected: &Header) -> Result<()> {
    expected.validate()?;
    if bytes.len() > (expected.kind.limit() + 16).div_ceil(3) * 4 + 4096 {
        return Err(Error::Format);
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
    if envelope.header != *expected {
        return Err(Error::Authentication);
    }
    fixed::<24>(&envelope.nonce)?;
    if decode(&envelope.ciphertext, expected.kind.limit() + 16)?.len() < 16 {
        return Err(Error::Format);
    }
    Ok(())
}

/// Secret material is never serialized or exposed through Debug. Context is fixed
/// for the lifetime of this key: advancing an epoch requires a separately verified key.
pub struct RootKey {
    context: Context,
    key: Zeroizing<[u8; 32]>,
}
impl RootKey {
    pub fn generate(deployment_id: String, collection_id: String, key_epoch: u64) -> Result<Self> {
        let context = Context {
            deployment_id,
            collection_id,
            key_epoch,
            epoch_salt: STANDARD.encode(crypto::random::<32>()?),
        };
        context.validate()?;
        Ok(Self {
            context,
            key: Zeroizing::new(crypto::random()?),
        })
    }
    pub(crate) fn material(&self) -> &[u8; 32] {
        &self.key
    }
    pub(crate) fn from_material(context: Context, key: Zeroizing<[u8; 32]>) -> Result<Self> {
        context.validate()?;
        Ok(Self { context, key })
    }
    pub fn commitment(&self) -> String {
        let mut bytes = Zeroizing::new(Vec::new());
        field(&mut bytes, b"petika:entry-root:commitment:v1");
        self.context.append(&mut bytes);
        field(&mut bytes, self.context.epoch_salt.as_bytes());
        bytes.extend_from_slice(self.key.as_ref());
        hex(&digest(&bytes))
    }
    pub fn context(&self) -> &Context {
        &self.context
    }
    fn object_key(&self, header: &Header) -> Result<Zeroizing<[u8; 32]>> {
        if header.context != self.context {
            return Err(Error::Authentication);
        }
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(
            Some(&fixed::<32>(&self.context.epoch_salt)?),
            self.key.as_ref(),
        )
        .expand(&header.key_info()?, key.as_mut())
        .map_err(|_| Error::Format)?;
        Ok(key)
    }
    pub fn seal(&self, header: &Header, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal_nonce(header, plaintext, crypto::random()?)
    }
    fn seal_nonce(&self, header: &Header, plaintext: &[u8], nonce: [u8; 24]) -> Result<Vec<u8>> {
        header.validate()?;
        if plaintext.len() > header.kind.limit() {
            return Err(Error::Format);
        }
        let key = self.object_key(header)?;
        let ciphertext = crypto::encrypt(&key, &nonce, plaintext, &header.aad()?)?;
        serde_json::to_vec(&Envelope {
            header: header.clone(),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        })
        .map_err(|_| Error::Format)
    }
    /// Caller supplies an independently expected header and the envelope digest
    /// from an authenticated index. This alone does not authenticate index semantics.
    pub fn open(
        &self,
        expected: &Header,
        expected_digest: &[u8; 32],
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        expected.validate()?;
        if bytes.len() > (expected.kind.limit() + 16).div_ceil(3) * 4 + 4096 {
            return Err(Error::Format);
        }
        if &digest(bytes) != expected_digest {
            return Err(Error::Authentication);
        }
        let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        envelope.header.validate()?;
        if envelope.header != *expected {
            return Err(Error::Authentication);
        }
        let ciphertext = decode(&envelope.ciphertext, expected.kind.limit() + 16)?;
        if ciphertext.len() < 16 {
            return Err(Error::Format);
        }
        crypto::decrypt(
            &*self.object_key(expected)?,
            &fixed::<24>(&envelope.nonce)?,
            &ciphertext,
            &expected.aad()?,
        )
    }
    /// Explicit passphrase recovery only; no server wrapper or recipient fallback.
    pub fn wrap_recovery(&self, passphrase: &str) -> Result<Vec<u8>> {
        if passphrase.len() < 12 || passphrase.len() > 4096 {
            return Err(Error::Format);
        }
        let mut wrapper = RecoveryWrapper {
            wrapper_version: 1,
            profile: WRAPPER_PROFILE.into(),
            suite: SUITE.into(),
            context: self.context.clone(),
            wrapper_id: hex(&crypto::random::<32>()?),
            salt: STANDARD.encode(crypto::random::<16>()?),
            memory_kib: 65536,
            iterations: 3,
            lanes: 1,
            nonce: STANDARD.encode(crypto::random::<24>()?),
            ciphertext: String::new(),
        };
        let key = crypto::derive(passphrase, &fixed::<16>(&wrapper.salt)?)?;
        let mut payload = Zeroizing::new(ROOT_TAG.to_vec());
        payload.extend_from_slice(self.key.as_ref());
        wrapper.ciphertext = STANDARD.encode(crypto::encrypt(
            &key,
            &fixed::<24>(&wrapper.nonce)?,
            &payload,
            &wrapper.aad()?,
        )?);
        serde_json::to_vec(&wrapper).map_err(|_| Error::Format)
    }
    pub fn open_recovery(expected: &Context, passphrase: &str, bytes: &[u8]) -> Result<Self> {
        expected.validate()?;
        if bytes.len() > MAX_WRAPPER_BYTES || passphrase.len() > 4096 {
            return Err(Error::Format);
        }
        let wrapper: RecoveryWrapper = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        wrapper.validate()?;
        if wrapper.context != *expected {
            return Err(Error::Authentication);
        }
        let ciphertext = decode(&wrapper.ciphertext, ROOT_TAG.len() + 32 + 16)?;
        if ciphertext.len() != ROOT_TAG.len() + 32 + 16 {
            return Err(Error::Format);
        }
        let key = crypto::derive(passphrase, &fixed::<16>(&wrapper.salt)?)?;
        let payload = crypto::decrypt(
            &key,
            &fixed::<24>(&wrapper.nonce)?,
            &ciphertext,
            &wrapper.aad()?,
        )?;
        if payload.len() != ROOT_TAG.len() + 32 || !payload.starts_with(ROOT_TAG) {
            return Err(Error::Authentication);
        }
        let mut root = Zeroizing::new([0; 32]);
        root.copy_from_slice(&payload[ROOT_TAG.len()..]);
        Ok(Self {
            context: expected.clone(),
            key: root,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryWrapper {
    wrapper_version: u32,
    profile: String,
    suite: String,
    context: Context,
    wrapper_id: String,
    salt: String,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    nonce: String,
    ciphertext: String,
}
impl RecoveryWrapper {
    fn validate(&self) -> Result<()> {
        self.context.validate()?;
        if self.wrapper_version != 1
            || self.profile != WRAPPER_PROFILE
            || self.suite != SUITE
            || !id(&self.wrapper_id)
            || (self.memory_kib, self.iterations, self.lanes) != (65536, 3, 1)
        {
            return Err(Error::Format);
        }
        fixed::<16>(&self.salt)?;
        fixed::<24>(&self.nonce)?;
        Ok(())
    }
    fn aad(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        field(&mut out, b"petika:entry-format:recovery:v1");
        out.extend_from_slice(&self.wrapper_version.to_be_bytes());
        field(&mut out, self.profile.as_bytes());
        field(&mut out, self.suite.as_bytes());
        self.context.append(&mut out);
        field(&mut out, &fixed::<32>(&self.context.epoch_salt)?);
        field(&mut out, self.wrapper_id.as_bytes());
        field(&mut out, &fixed::<16>(&self.salt)?);
        for n in [self.memory_kib, self.iterations, self.lanes] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        field(&mut out, ROOT_TAG);
        Ok(out)
    }
}
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn root() -> RootKey {
        RootKey {
            context: Context {
                deployment_id: "a".repeat(64),
                collection_id: "b".repeat(64),
                key_epoch: 7,
                epoch_salt: STANDARD.encode([3; 32]),
            },
            key: Zeroizing::new([9; 32]),
        }
    }
    fn header(root: &RootKey, kind: Kind) -> Header {
        Header {
            entry_format_version: 1,
            suite: SUITE.into(),
            context: root.context.clone(),
            object_id: if kind == Kind::Entry {
                "c".repeat(64)
            } else {
                String::new()
            },
            kind,
            revision: 11,
        }
    }
    #[test]
    fn independent_python_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/fixtures/entry-format-v1.json")).unwrap();
        let root = root();
        for vector in vectors["objects"].as_array().unwrap() {
            let h: Header = serde_json::from_value(vector["header"].clone()).unwrap();
            let plaintext = STANDARD
                .decode(vector["plaintext"].as_str().unwrap())
                .unwrap();
            assert_eq!(STANDARD.encode(h.key_info().unwrap()), vector["key_info"]);
            assert_eq!(STANDARD.encode(h.aad().unwrap()), vector["aad"]);
            assert_eq!(
                STANDARD.encode(root.object_key(&h).unwrap().as_ref()),
                vector["object_key"]
            );
            let bytes = vector["envelope"].as_str().unwrap().as_bytes();
            assert_eq!(*root.open(&h, &digest(bytes), bytes).unwrap(), plaintext);
            let rust = root.seal_nonce(&h, &plaintext, [5; 24]).unwrap();
            let rust_value: Value = serde_json::from_slice(&rust).unwrap();
            let python_value: Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(rust_value, python_value);
        }
        let bytes = vectors["wrapper"].as_str().unwrap().as_bytes();
        let restored =
            RootKey::open_recovery(&root.context, "synthetic vector passphrase", bytes).unwrap();
        assert_eq!(restored.key.as_ref(), root.key.as_ref());
        let wrapper: RecoveryWrapper = serde_json::from_slice(bytes).unwrap();
        assert_eq!(
            STANDARD.encode(wrapper.aad().unwrap()),
            vectors["wrapper_aad"]
        );
    }
    #[test]
    fn nonce_separation_roundtrip_and_epoch_binding() {
        let root = root();
        let h = header(&root, Kind::Entry);
        let first = root.seal(&h, b"synthetic secret").unwrap();
        let second = root.seal(&h, b"synthetic secret").unwrap();
        assert_ne!(first, second);
        assert_eq!(
            root.open(&h, &digest(&first), &first).unwrap().as_slice(),
            b"synthetic secret"
        );
        assert!(root.open(&h, &digest(&second), &first).is_err());
        let mut other = h.clone();
        other.revision += 1;
        assert!(root.open(&other, &digest(&first), &first).is_err());
        other = h.clone();
        other.context.key_epoch += 1;
        assert!(root.seal(&other, b"no automatic rotation").is_err());
        other = h.clone();
        other.context.epoch_salt = STANDARD.encode([8; 32]);
        assert!(root.seal(&other, b"no salt replacement").is_err());
        assert_ne!(
            root.object_key(&h).unwrap().as_ref(),
            root.object_key(&header(&root, Kind::Index))
                .unwrap()
                .as_ref()
        );
        other = h.clone();
        other.object_id = "d".repeat(64);
        assert_ne!(
            root.object_key(&h).unwrap().as_ref(),
            root.object_key(&other).unwrap().as_ref()
        );
    }
    #[test]
    fn reject_tampering_even_with_recomputed_public_digest() {
        let root = root();
        let h = header(&root, Kind::Entry);
        let bytes = root.seal(&h, b"private").unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        // Supply the altered expected revision too: AEAD must reject it even when
        // public header equality and the recomputed envelope hash both pass.
        let mut altered = value.clone();
        altered["header"]["revision"] = json!(12);
        let altered = serde_json::to_vec(&altered).unwrap();
        let mut expected = h.clone();
        expected.revision = 12;
        assert!(root.open(&expected, &digest(&altered), &altered).is_err());
        for field in ["nonce", "ciphertext"] {
            let mut bad = value.clone();
            let mut raw = STANDARD.decode(bad[field].as_str().unwrap()).unwrap();
            raw[0] ^= 1;
            bad[field] = STANDARD.encode(raw).into();
            let bad = serde_json::to_vec(&bad).unwrap();
            assert!(root.open(&h, &digest(&bad), &bad).is_err());
        }
        for (name, replacement) in [
            ("suite", json!("aes")),
            ("entry_format_version", json!(2)),
            ("kind", json!("index")),
            ("revision", json!(0)),
            ("object_id", json!("../escape")),
        ] {
            let mut bad = value.clone();
            bad["header"][name] = replacement;
            let bytes = serde_json::to_vec(&bad).unwrap();
            assert!(root.open(&h, &digest(&bytes), &bytes).is_err());
        }
        let duplicate = String::from_utf8(bytes)
            .unwrap()
            .replacen("{", "{\"nonce\":\"\",", 1);
        assert!(
            root.open(&h, &digest(duplicate.as_bytes()), duplicate.as_bytes())
                .is_err()
        );
        let mut bad = value;
        bad["unknown"] = true.into();
        let bytes = serde_json::to_vec(&bad).unwrap();
        assert!(root.open(&h, &digest(&bytes), &bytes).is_err());
    }
    #[test]
    fn limits_and_canonical_decoding_fail_closed() {
        let root = root();
        let mut h = header(&root, Kind::Entry);
        assert!(root.seal(&h, &vec![0; MAX_ENTRY_BYTES + 1]).is_err());
        h.revision = MAX_COUNTER + 1;
        assert!(h.validate().is_err());
        h.revision = 1;
        h.context.deployment_id = "A".repeat(64);
        assert!(h.validate().is_err());
        assert!(fixed::<32>(STANDARD.encode([0; 32]).trim_end_matches('=')).is_err());
        assert!(fixed::<24>(&STANDARD.encode([0; 23])).is_err());
        assert!(decode(&"A".repeat(1_000_000), 24).is_err());
        assert!(
            RootKey::open_recovery(
                root.context(),
                "password",
                &vec![b' '; MAX_WRAPPER_BYTES + 1]
            )
            .is_err()
        );
    }
    #[test]
    fn recovery_roundtrip_and_wrapper_rejection() {
        let root = root();
        let pass = "synthetic recovery passphrase";
        let bytes = root.wrap_recovery(pass).unwrap();
        let restored = RootKey::open_recovery(root.context(), pass, &bytes).unwrap();
        let h = header(&root, Kind::Entry);
        let ciphertext = root.seal(&h, b"roundtrip").unwrap();
        assert_eq!(
            restored
                .open(&h, &digest(&ciphertext), &ciphertext)
                .unwrap()
                .as_slice(),
            b"roundtrip"
        );
        assert!(RootKey::open_recovery(root.context(), "wrong", &bytes).is_err());
        let mut expected = root.context.clone();
        expected.key_epoch += 1;
        assert!(RootKey::open_recovery(&expected, pass, &bytes).is_err());
        for (field, value) in [
            ("profile", json!("legacy")),
            ("memory_kib", json!(1)),
            ("wrapper_version", json!(2)),
            ("ciphertext", json!("AA==")),
        ] {
            let mut bad: Value = serde_json::from_slice(&bytes).unwrap();
            bad[field] = value;
            assert!(
                RootKey::open_recovery(root.context(), pass, &serde_json::to_vec(&bad).unwrap())
                    .is_err()
            );
        }
        let mut bad: Value = serde_json::from_slice(&bytes).unwrap();
        bad["wrapper_id"] = "d".repeat(64).into();
        assert!(
            RootKey::open_recovery(root.context(), pass, &serde_json::to_vec(&bad).unwrap())
                .is_err()
        );
    }
    #[test]
    fn current_vault_parser_never_accepts_prototype() {
        let root = root();
        let h = header(&root, Kind::Entry);
        assert!(crate::validate_envelope(&root.seal(&h, b"data").unwrap()).is_err());
    }
}
