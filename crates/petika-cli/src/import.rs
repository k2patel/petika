use crate::Result;
use petika_core::{Entry, UnlockedStore};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

const MAX_ENTRY: u64 = 1024 * 1024;

pub fn gpg_store(
    store: &mut UnlockedStore,
    source: &Path,
    home: Option<&Path>,
    replace: bool,
) -> Result<usize> {
    import_with(store, source, replace, |path| decrypt(path, home))
}

fn import_with(
    store: &mut UnlockedStore,
    source: &Path,
    replace: bool,
    decrypt: impl Fn(&Path) -> Result<Zeroizing<String>>,
) -> Result<usize> {
    if !fs::symlink_metadata(source)?.file_type().is_dir() {
        return Err("import source must be a real directory, not a symlink".into());
    }
    let source = fs::canonicalize(source)?;
    let mut files = Vec::new();
    collect(&source, 0, &mut files)?;
    files.sort();
    for path in &files {
        let relative = path.strip_prefix(&source)?;
        let name = relative
            .with_extension("")
            .components()
            .map(|part| {
                part.as_os_str()
                    .to_str()
                    .ok_or("GPG entry name is not UTF-8")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join("/");
        let plaintext = decrypt(path)?;
        store.put(name, parse(&plaintext)?, replace)?;
    }
    Ok(files.len())
}

fn collect(directory: &Path, depth: usize, files: &mut Vec<PathBuf>) -> Result<()> {
    if depth > 64 {
        return Err("import nesting exceeds 64 directories".into());
    }
    for item in fs::read_dir(directory)? {
        let item = item?;
        if item.file_name() == ".git" || item.file_name() == ".extensions" {
            continue;
        }
        let kind = item.file_type()?;
        if kind.is_symlink() {
            return Err("symlinks are not allowed in GPG imports".into());
        }
        if kind.is_dir() {
            collect(&item.path(), depth + 1, files)?;
        } else if kind.is_file()
            && item
                .path()
                .extension()
                .is_some_and(|s| s.eq_ignore_ascii_case("gpg"))
        {
            if item.metadata()?.len() > 16 * 1024 * 1024 {
                return Err("GPG entry is too large".into());
            }
            files.push(item.path());
            if files.len() > 10_000 {
                return Err("import exceeds 10000 entries".into());
            }
        }
    }
    Ok(())
}

fn decrypt(path: &Path, home: Option<&Path>) -> Result<Zeroizing<String>> {
    let mut command = Command::new("gpg");
    command.arg("--no-options");
    if let Some(home) = home {
        command.arg("--homedir").arg(home);
    }
    command
        .args([
            "--batch",
            "--quiet",
            "--no-auto-key-retrieve",
            "--decrypt",
            "--",
        ])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| "cannot start GnuPG; install gpg and configure your local key")?;
    let mut plaintext = Zeroizing::new(String::new());
    let result = child
        .stdout
        .take()
        .ok_or("missing GPG output")?
        .take(MAX_ENTRY + 1)
        .read_to_string(&mut plaintext);
    if result.is_err() || plaintext.len() as u64 > MAX_ENTRY {
        let _ = child.kill();
        let _ = child.wait();
        return Err("GPG output is oversized or not UTF-8".into());
    }
    if !child.wait()?.success() {
        return Err("GPG decryption failed; check your local key and agent".into());
    }
    Ok(plaintext)
}

fn parse(text: &str) -> Result<Entry> {
    let (password, rest) = text.split_once('\n').unwrap_or((text, ""));
    let password = password.trim_end_matches('\r');
    if password.is_empty() {
        return Err("GPG entry has an empty first-line password".into());
    }
    let mut entry = Entry {
        password: password.into(),
        username: String::new(),
        url: String::new(),
        notes: rest.into(),
    };
    for line in rest.lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key.trim().to_ascii_lowercase().as_str() {
                "username" | "user" | "login" if entry.username.is_empty() => {
                    entry.username = value.trim().into()
                }
                "url" | "website" if entry.url.is_empty() => entry.url = value.trim().into(),
                _ => {}
            }
        }
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use petika_core::EncryptionMode;

    #[test]
    fn imports_hierarchy_in_both_modes_without_copying_it_to_ciphertext() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("private-folder")).unwrap();
        fs::write(
            source.path().join("private-folder/secret-site.gpg"),
            b"fake ciphertext fixture",
        )
        .unwrap();
        fs::create_dir(source.path().join(".git")).unwrap();
        fs::write(source.path().join(".git/ignored.gpg"), b"ignored").unwrap();
        for mode in [EncryptionMode::Standard, EncryptionMode::HybridPostQuantum] {
            let mut store =
                UnlockedStore::create_with_mode("synthetic testing passphrase", mode).unwrap();
            let count = import_with(&mut store, source.path(), false, |_| {
                Ok(Zeroizing::new(
                    "secret-password\nUsername: alice\nURL: https://example.test\ncustom note\n"
                        .into(),
                ))
            })
            .unwrap();
            assert_eq!(count, 1);
            let record = store.get("private-folder/secret-site").unwrap();
            assert_eq!(record.username, "alice");
            assert!(record.notes.contains("custom note"));
            let encrypted = String::from_utf8(store.seal().unwrap()).unwrap();
            for metadata in [
                "private-folder",
                "secret-site",
                "alice",
                "example.test",
                "custom note",
            ] {
                assert!(!encrypted.contains(metadata));
            }
            assert_eq!(
                fs::read(source.path().join("private-folder/secret-site.gpg")).unwrap(),
                b"fake ciphertext fixture"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_imports() {
        let source = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/nonexistent", source.path().join("bad.gpg")).unwrap();
        let mut files = Vec::new();
        assert!(collect(source.path(), 0, &mut files).is_err());
    }
}
