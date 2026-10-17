//! Browser-only bindings. Secrets and cryptographic operations stay on the client.
use petika_core::{EncryptionMode, Entry, UnlockedStore};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn error(value: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&value.to_string())
}

#[wasm_bindgen]
pub struct Session(UnlockedStore);

#[wasm_bindgen]
impl Session {
    pub fn create(passphrase: String, hybrid: bool) -> Result<Session, JsValue> {
        let passphrase = Zeroizing::new(passphrase);
        UnlockedStore::create_with_mode(
            &passphrase,
            if hybrid {
                EncryptionMode::HybridPostQuantum
            } else {
                EncryptionMode::Standard
            },
        )
        .map(Session)
        .map_err(error)
    }
    pub fn open(encrypted: &[u8], passphrase: String) -> Result<Session, JsValue> {
        let passphrase = Zeroizing::new(passphrase);
        UnlockedStore::open(encrypted, &passphrase)
            .map(Session)
            .map_err(error)
    }
    pub fn list(&self) -> Result<String, JsValue> {
        let rows: Vec<_> = self.0.names().map(|name| {
            let entry = self.0.get(name).expect("existing entry");
            let reused = !entry.password.is_empty() && self.0.names().any(|other| other != name && self.0.get(other).is_ok_and(|e| e.password == entry.password));
            serde_json::json!({"name": name, "username": entry.username, "url": entry.url,
                "otp": entry.otp.is_some(), "weak": entry.password.chars().count() < 16, "reused": reused})
        }).collect();
        serde_json::to_string(&rows).map_err(error)
    }
    pub fn get(&self, name: &str) -> Result<String, JsValue> {
        serde_json::to_string(self.0.get(name).map_err(error)?).map_err(error)
    }
    pub fn put(&mut self, name: String, json: String, replace: bool) -> Result<(), JsValue> {
        let json = Zeroizing::new(json);
        let entry: Entry = serde_json::from_str(&json).map_err(|_| error("Invalid entry"))?;
        self.0.put(name, entry, replace).map_err(error)
    }
    pub fn remove(&mut self, name: &str) -> Result<(), JsValue> {
        self.0.remove(name).map_err(error)
    }
    pub fn seal(&mut self) -> Result<Vec<u8>, JsValue> {
        self.0.seal().map_err(error)
    }
    pub fn mode(&self) -> String {
        match self.0.encryption() {
            EncryptionMode::Standard => "standard",
            EncryptionMode::HybridPostQuantum => "hybrid-post-quantum",
        }
        .into()
    }
    pub fn change_passphrase(&mut self, passphrase: String) -> Result<(), JsValue> {
        self.0
            .change_passphrase(&Zeroizing::new(passphrase))
            .map_err(error)
    }
}
#[wasm_bindgen]
pub fn generate(length: usize) -> Result<String, JsValue> {
    petika_core::generate_password(length)
        .map(|p| p.to_string())
        .map_err(error)
}

/// Worker-owned identity; only public records and ciphertext cross the worker boundary.
#[wasm_bindgen]
pub struct RecipientIdentity(petika_core::identity::UnlockedIdentity);
#[wasm_bindgen]
impl RecipientIdentity {
    pub fn generate(deployment: &str, user: &str) -> Result<Self, JsValue> {
        petika_core::identity::UnlockedIdentity::generate(deployment, user, 1)
            .map(Self)
            .map_err(error)
    }
    pub fn open(bytes: &[u8], passphrase: String, fingerprint: &str) -> Result<Self, JsValue> {
        petika_core::identity::UnlockedIdentity::open(
            bytes,
            &Zeroizing::new(passphrase),
            fingerprint,
        )
        .map(Self)
        .map_err(error)
    }
    pub fn seal(&self, passphrase: String) -> Result<Vec<u8>, JsValue> {
        self.0.seal(&Zeroizing::new(passphrase)).map_err(error)
    }
    pub fn public_identity(&self) -> Result<String, JsValue> {
        serde_json::to_string(self.0.public_identity()).map_err(error)
    }
    pub fn verify(&mut self, public: &str, fingerprint: &str) -> Result<(), JsValue> {
        let candidate: petika_core::identity::PublicIdentity =
            serde_json::from_str(public).map_err(error)?;
        let pin = self.0.contact_pin(&candidate.user_id).cloned();
        self.0
            .verify_contact(&candidate.user_id, &candidate, fingerprint, pin.as_ref())
            .map_err(error)
    }
    pub fn package(
        &mut self,
        session: &Session,
        public: &str,
        generation: u64,
    ) -> Result<String, JsValue> {
        let candidate = serde_json::from_str(public).map_err(error)?;
        serde_json::to_string(
            &self
                .0
                .create_key_package(&session.0, &candidate, generation)
                .map_err(error)?,
        )
        .map_err(error)
    }
    pub fn unlock(
        &mut self,
        package: &str,
        issuer: &str,
        snapshot: &[u8],
        context: &str,
        hybrid: bool,
    ) -> Result<Session, JsValue> {
        let package =
            petika_core::identity::KeyPackage::parse(package.as_bytes()).map_err(error)?;
        self.0
            .open_key_package(
                &package,
                &serde_json::from_str(issuer).map_err(error)?,
                snapshot,
                &serde_json::from_str(context).map_err(error)?,
                if hybrid {
                    EncryptionMode::HybridPostQuantum
                } else {
                    EncryptionMode::Standard
                },
            )
            .map(Session)
            .map_err(error)
    }
}
#[wasm_bindgen]
impl Session {
    pub fn bind_collection(
        &self,
        deployment: String,
        collection: String,
        recovery: String,
    ) -> Result<Session, JsValue> {
        self.0
            .migration_draft(
                petika_core::CollectionContext {
                    deployment_id: deployment,
                    collection_id: collection,
                    key_epoch: 1,
                },
                &Zeroizing::new(recovery),
            )
            .map(Session)
            .map_err(error)
    }
    pub fn rotate(&self, recovery: String) -> Result<Session, JsValue> {
        self.0
            .rotated(&Zeroizing::new(recovery))
            .map(Session)
            .map_err(error)
    }
}
