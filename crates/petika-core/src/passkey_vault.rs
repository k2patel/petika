//! Browser-passkey vault framing. PRF output and unwrapped key material never
//! belong in this public wire format. This policy allows OS-managed PIN checks.
use crate::{CollectionContext, Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

pub const KIND: &str = "petika-passkey-vault";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessPolicy {
    BrowserPasskey,
    StrictBiometric,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyWrapper {
    pub credential_id: String,
    pub prf_input: String,
    pub kdf_salt: String,
    pub nonce: String,
    pub wrapped_key: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserProtection {
    pub version: u32,
    pub policy: AccessPolicy,
    pub context: CollectionContext,
    pub owner_user_id: String,
    pub origin: String,
    pub wrappers: Vec<PasskeyWrapper>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserVault {
    pub version: u32,
    pub kind: String,
    pub protection: BrowserProtection,
    pub encrypted_snapshot: String,
    /// Retained client operation for reconciliation after a lost write reply.
    pub operation_id: String,
}
fn id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode(value: &str, min: usize, max: usize) -> Result<Vec<u8>> {
    if value.len() > max * 2 {
        return Err(Error::Format);
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| Error::Format)?;
    if bytes.len() < min || bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::Format);
    }
    Ok(bytes)
}
impl PasskeyWrapper {
    pub fn validate(&self) -> Result<()> {
        decode(&self.credential_id, 1, 1024)?;
        decode(&self.prf_input, 32, 32)?;
        decode(&self.kdf_salt, 32, 32)?;
        decode(&self.nonce, 12, 12)?;
        decode(&self.wrapped_key, 48, 48)?;
        Ok(())
    }
}
impl BrowserProtection {
    pub fn validate(&self) -> Result<()> {
        self.context.validate()?;
        if self.version != 1
            || self.policy != AccessPolicy::BrowserPasskey
            || !id(&self.owner_user_id)
            || self.wrappers.is_empty()
            || self.wrappers.len() > 16
            || self.origin.len() > 2048
            || !(self.origin.starts_with("https://")
                || self.origin.starts_with("http://localhost:")
                || self.origin == "http://localhost")
            || self.origin.bytes().any(|b| !b.is_ascii_graphic())
            || self.origin.contains(['@', '?', '#'])
            || self
                .origin
                .split("://")
                .nth(1)
                .is_none_or(|s| s.is_empty() || s.contains('/'))
        {
            return Err(Error::Format);
        }
        for (i, wrapper) in self.wrappers.iter().enumerate() {
            wrapper.validate()?;
            if self.wrappers[..i]
                .iter()
                .any(|old| old.credential_id == wrapper.credential_id)
            {
                return Err(Error::Format);
            }
        }
        Ok(())
    }
    /// Canonical UTF-8 JSON array shared with the browser wrapper implementation.
    /// Signed WebAuthn challenges and the envelope validator provide separate checks.
    pub fn wrapper_binding(&self, wrapper: &PasskeyWrapper) -> Result<Vec<u8>> {
        self.validate()?;
        wrapper.validate()?;
        serde_json::to_vec(&serde_json::json!([
            "petika:browser-passkey-wrap:v1",
            self.origin,
            self.context.deployment_id,
            self.owner_user_id,
            self.context.collection_id,
            self.context.key_epoch,
            wrapper.credential_id,
            "browser-passkey",
            wrapper.prf_input
        ]))
        .map_err(|_| Error::Format)
    }
}
impl BrowserVault {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > crate::crypto::MAX_FILE_BYTES {
            return Err(Error::Format);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        self.protection.validate()?;
        if self.version != 3
            || self.kind != KIND
            || !id(&self.operation_id)
            || crate::envelope_metadata(self.encrypted_snapshot.as_bytes())?
                .1
                .as_ref()
                != Some(&self.protection.context)
        {
            return Err(Error::Format);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> BrowserVault {
        let context = CollectionContext {
            deployment_id: "a".repeat(64),
            collection_id: "b".repeat(64),
            key_epoch: 1,
        };
        let mut store =
            crate::UnlockedStore::create("public synthetic fixture passphrase").unwrap();
        store
            .bind_collection(context.clone(), "public synthetic fixture passphrase")
            .unwrap();
        BrowserVault {
            version: 3,
            kind: KIND.into(),
            operation_id: "c".repeat(64),
            protection: BrowserProtection {
                version: 1,
                policy: AccessPolicy::BrowserPasskey,
                context,
                owner_user_id: "b".repeat(64),
                origin: "https://vault.example".into(),
                wrappers: vec![PasskeyWrapper {
                    credential_id: URL_SAFE_NO_PAD.encode([1; 32]),
                    prf_input: URL_SAFE_NO_PAD.encode([2; 32]),
                    kdf_salt: URL_SAFE_NO_PAD.encode([3; 32]),
                    nonce: URL_SAFE_NO_PAD.encode([4; 12]),
                    wrapped_key: URL_SAFE_NO_PAD.encode([5; 48]),
                }],
            },
            encrypted_snapshot: String::from_utf8(store.seal().unwrap()).unwrap(),
        }
    }
    #[test]
    fn public_framing_is_distinct_from_legacy_unlock_and_strict_biometrics() {
        let mut vault = fixture();
        let wire = serde_json::to_vec(&vault).unwrap();
        crate::validate_envelope(&wire).unwrap();
        BrowserVault::parse(&wire).unwrap();
        assert!(crate::envelope_metadata(&wire).is_err());
        assert!(crate::UnlockedStore::open(&wire, "public synthetic fixture passphrase").is_err());
        vault.protection.policy = AccessPolicy::StrictBiometric;
        assert!(vault.validate().is_err());
    }
    #[test]
    fn wrapper_bindings_bounds_and_context_substitution_are_checked() {
        let mut vault = fixture();
        let protection = &vault.protection;
        let binding =
            String::from_utf8(protection.wrapper_binding(&protection.wrappers[0]).unwrap())
                .unwrap();
        assert!(
            binding.starts_with("[\"petika:browser-passkey-wrap:v1\",\"https://vault.example\"")
        );
        vault.protection.context.key_epoch = 2;
        assert!(vault.validate().is_err());
        vault.protection.context.key_epoch = 1;
        vault
            .protection
            .wrappers
            .push(vault.protection.wrappers[0].clone());
        assert!(vault.validate().is_err());
        vault.protection.wrappers.pop();
        vault.protection.wrappers[0].wrapped_key = "AA==".into();
        assert!(vault.validate().is_err());
    }
}
