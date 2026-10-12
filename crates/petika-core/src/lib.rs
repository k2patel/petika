//! Experimental local encrypted storage for Petika.
mod crypto;
#[cfg(not(target_arch = "wasm32"))]
mod storage;

pub use crypto::{
    EncryptionMode, Entry, Error, Result, UnlockedStore, generate_password, validate_envelope,
};
#[cfg(not(target_arch = "wasm32"))]
pub use storage::StoreFile;

pub const STATUS: &str = "Experimental local encrypted storage; biometrics, account login, sharing, and automatic sync are not implemented.";
