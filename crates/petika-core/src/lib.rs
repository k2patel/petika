//! Experimental local encrypted storage for Petika.
mod crypto;
mod storage;

pub use crypto::{
    EncryptionMode, Entry, Error, Result, UnlockedStore, generate_password, validate_envelope,
};
pub use storage::StoreFile;

pub const STATUS: &str = "Experimental local encrypted storage; biometrics, account login, sharing, and automatic sync are not implemented.";
