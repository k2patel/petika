//! Synthetic recovery-drill fixture only; never use this known passphrase for real keys.
use petika_core::{StoreFile, identity::UnlockedIdentity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: recovery_identity_fixture DEPLOYMENT USER NEW_OUTPUT".into());
    }
    let identity = UnlockedIdentity::generate(&args[1], &args[2], 2)?;
    StoreFile::lock(&args[3])?.write(&identity.seal("synthetic identity passphrase")?, true)?;
    Ok(())
}
