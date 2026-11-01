//! Experimental local encrypted storage for Petika.
mod crypto;
/// Candidate device wire format; not connected to account APIs or vault storage.
#[cfg(feature = "experimental-device-keys")]
pub mod device_keys;
/// Opt-in prototype; not connected to production storage or APIs.
#[cfg(feature = "experimental-entry-format")]
pub mod entry_format;
pub mod identity;
pub mod passkey_vault;
#[cfg(not(target_arch = "wasm32"))]
mod storage;

pub use crypto::{
    CollectionContext, EncryptionMode, Entry, Error, Result, UnlockedStore, envelope_metadata,
    generate_password, validate_envelope,
};
#[cfg(not(target_arch = "wasm32"))]
pub use storage::StoreFile;

pub const STATUS: &str = "Experimental encrypted storage shared by CLI and web clients; managed accounts, group permissions, and snapshot sync are implemented. Verified per-user group-key delivery and explicit fresh-key rotation are implemented; native biometrics remain planned.";
