use crate::{Error, Result, UnlockedStore, crypto::MAX_FILE_BYTES};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Holds an exclusive advisory lock until drop; every cooperating reader/writer uses it.
pub struct StoreFile {
    path: PathBuf,
    _lock: File,
}

impl StoreFile {
    pub fn lock(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !parent.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent)?;
        }
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        check_file(&path)?;
        check_file(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&lock_path)?;
        check_file(&lock_path)?;
        lock.try_lock_exclusive().map_err(|err| {
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.raw_os_error() == fs2::lock_contended_error().raw_os_error()
            {
                Error::Busy
            } else {
                Error::Io(err)
            }
        })?;
        Ok(Self { path, _lock: lock })
    }
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
    pub fn open(&self, passphrase: &str) -> Result<UnlockedStore> {
        UnlockedStore::open(&self.read()?, passphrase)
    }
    pub fn read(&self) -> Result<Vec<u8>> {
        self.read_limited(MAX_FILE_BYTES)
    }
    pub(crate) fn read_limited(&self, limit: usize) -> Result<Vec<u8>> {
        check_file(&self.path)?;
        let mut bytes = Vec::new();
        File::open(&self.path)?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(Error::Format);
        }
        Ok(bytes)
    }
    pub fn save(&self, store: &mut UnlockedStore, create: bool) -> Result<()> {
        self.write(&store.seal()?, create)
    }
    pub fn write(&self, bytes: &[u8], create: bool) -> Result<()> {
        self.write_checked(bytes, create, |_| Ok(()))
    }
    /// Experimental persistence harness. Called after temporary-file write,
    /// file sync, atomic replacement and parent-directory sync, respectively.
    /// Errors after replacement represent an uncertain durable outcome.
    #[cfg(feature = "experimental-entry-format")]
    #[doc(hidden)]
    pub fn write_observed(
        &self,
        bytes: &[u8],
        create: bool,
        boundary: impl FnMut(u8) -> Result<()>,
    ) -> Result<()> {
        self.write_checked(bytes, create, boundary)
    }
    // The callback permits deterministic boundary failures in tests without
    // global failpoints or changing the on-disk protocol.
    fn write_checked(
        &self,
        bytes: &[u8],
        create: bool,
        mut boundary: impl FnMut(u8) -> Result<()>,
    ) -> Result<()> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Error::Format);
        }
        check_file(&self.path)?;
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(bytes)?;
        boundary(1)?;
        temporary.as_file().sync_all()?;
        boundary(2)?;
        let persisted = if create {
            temporary.persist_noclobber(&self.path)
        } else {
            temporary.persist(&self.path)
        };
        persisted.map_err(|err| {
            if err.error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::AlreadyExists
            } else {
                Error::Io(err.error)
            }
        })?;
        boundary(3)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        boundary(4)?;
        Ok(())
    }
}

fn check_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(Error::Permissions);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(Error::Permissions);
                }
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    #[test]
    fn atomic_write_failure_boundaries_preserve_whole_records() {
        for create in [false, true] {
            for stop in 1..=4 {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("pin");
                let file = StoreFile::lock(&path).unwrap();
                if !create {
                    file.write(b"old complete record", true).unwrap();
                }
                let result = file.write_checked(b"new complete record", create, |stage| {
                    if stage == stop {
                        Err(Error::Io(std::io::Error::other(
                            "injected boundary failure",
                        )))
                    } else {
                        Ok(())
                    }
                });
                assert!(result.is_err());
                drop(file);
                let reopened = StoreFile::lock(&path).unwrap();
                if stop < 3 && create {
                    assert!(!reopened.exists());
                } else {
                    let expected: &[u8] = if stop < 3 {
                        b"old complete record"
                    } else {
                        b"new complete record"
                    };
                    assert_eq!(reopened.read().unwrap(), expected);
                }
            }
        }
    }
}
