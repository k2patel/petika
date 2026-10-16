//! Experimental local encrypted storage for Petika.
mod crypto;
pub mod identity;
#[cfg(not(target_arch = "wasm32"))]
mod storage;

pub use crypto::{
    EncryptionMode, Entry, Error, Result, UnlockedStore, generate_password, validate_envelope,
};
#[cfg(not(target_arch = "wasm32"))]
pub use storage::StoreFile;

pub const STATUS: &str = "Experimental encrypted storage shared by CLI and web clients; managed accounts, group permissions, and snapshot sync are implemented. Automatic per-user group-key delivery and native biometrics remain planned.";
