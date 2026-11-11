use crate::{Result, secret};
use clap::Subcommand;
use petika_core::{StoreFile, UnlockedStore};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

#[cfg(target_os = "windows")]
mod windows;

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Enroll this local vault for device unlock after verifying its passphrase.
    Enable,
    /// Remove this local vault's biometric enrollment.
    Disable,
}

pub(crate) fn configure(
    command: &Command,
    path: &Path,
    store: &StoreFile,
    passphrase_stdin: bool,
) -> Result<()> {
    let credential_path = credential_path(path);
    match command {
        Command::Enable => {
            platform::available()?;
            let credential = StoreFile::lock(&credential_path)?;
            if credential.exists() {
                return Err(
                    "biometric unlock is already enrolled; disable it before enrolling again"
                        .into(),
                );
            }
            let passphrase = secret("Current vault passphrase: ", passphrase_stdin)?;
            let key = UnlockedStore::local_unlock_key(&store.read()?, &passphrase)?;
            drop(passphrase);
            let wrapped = platform::run("enroll", key.as_ref())?;
            if wrapped.is_empty() || wrapped.len() > MAX_CREDENTIAL_BYTES {
                return Err("the biometric helper returned an invalid enrollment".into());
            }
            credential.write(&wrapped, true)?;
            println!("Biometric unlock enabled for this local vault.");
        }
        Command::Disable => {
            let credential = StoreFile::lock(&credential_path)?;
            if credential.exists() {
                fs::remove_file(credential_path)?;
            }
            println!("Biometric unlock disabled for this local vault.");
        }
    }
    Ok(())
}

pub(crate) fn open(path: &Path, store: &StoreFile) -> Result<UnlockedStore> {
    platform::available()?;
    let credential = StoreFile::lock(credential_path(path))?;
    if !credential.exists() {
        return Err(
            "biometric unlock is not enrolled for this local vault; run petika biometric enable"
                .into(),
        );
    }
    let wrapped = credential.read_limited(MAX_CREDENTIAL_BYTES)?;
    let key = platform::run("unlock", &wrapped)?;
    let key = <&[u8; 32]>::try_from(key.as_slice())
        .map_err(|_| "the biometric helper returned an invalid unlock key")?;
    UnlockedStore::open_with_local_unlock_key(&store.read()?, key).map_err(|error| {
        if matches!(error, petika_core::Error::Authentication) {
            "biometric enrollment no longer matches the vault; unlock with the passphrase and re-enroll".into()
        } else {
            error.into()
        }
    })
}

fn credential_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path);
    name.push(".biometric");
    name.into()
}

mod platform {
    use super::*;
    use zeroize::Zeroizing;

    #[cfg(target_os = "macos")]
    fn helper() -> Result<PathBuf> {
        let path = std::env::current_exe()?
            .canonicalize()?
            .with_file_name("petika-macos-unlock");
        if path.is_file() {
            return Ok(path);
        }
        Err("the Petika macOS biometric helper is missing from this installation".into())
    }

    pub(super) fn available() -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let status = run("status", &[])?;
            if status.as_slice() != b"available\n" {
                return Err(
                    "the macOS biometric helper returned an invalid capability response".into(),
                );
            }
            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            windows::available()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        Err("this Petika build does not support biometric unlock on this platform".into())
    }

    #[cfg(target_os = "macos")]
    pub(super) fn run(operation: &str, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };

        let mut child = Command::new(helper()?)
            .arg(operation)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let written = child.stdin.take().expect("piped stdin").write_all(input);
        let output = child.wait_with_output()?;
        let bytes = Zeroizing::new(output.stdout);
        if !output.status.success() {
            return Err(
                "Touch ID approval failed or is unavailable; use your vault passphrase".into(),
            );
        }
        written?;
        Ok(bytes)
    }

    #[cfg(target_os = "windows")]
    pub(super) fn run(operation: &str, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        windows::run(operation, input)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    pub(super) fn run(_operation: &str, _input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err("this Petika build does not support biometric unlock on this platform".into())
    }
}
