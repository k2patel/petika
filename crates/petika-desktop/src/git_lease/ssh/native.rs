use super::*;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{fs::OpenOptionsExt, io::AsRawFd, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_TREE: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 4096;
const OUTPUT: usize = 8192;
/// Disposable, unverified fetched objects. No working tree, vault decryption,
/// authority pin, or shared cache is updated. Drop removes this quarantine.
pub struct FetchedGit {
    directory: tempfile::TempDir,
    repository: PathBuf,
    head: String,
    branch: String,
    remote: PinnedRemote,
}
impl FetchedGit {
    pub fn repository_path(&self) -> &Path {
        &self.repository
    }
    pub fn head(&self) -> &str {
        &self.head
    }
    pub fn branch(&self) -> &str {
        &self.branch
    }
    pub fn remote(&self) -> &PinnedRemote {
        &self.remote
    }
    /// This directory contains unverified ciphertext/Git metadata, never a
    /// persisted agent socket or client private key.
    pub fn quarantine_path(&self) -> &Path {
        self.directory.path()
    }
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Error::Transfer)?;
    out.write_all(contents).map_err(|_| Error::Transfer)
}
fn wrapper(socket: &Path, identity: &Path, known: &Path) -> Result<String> {
    let mut args = vec!["-F".to_owned(), "/dev/null".to_owned(), "-T".to_owned()];
    for option in [
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "PreferredAuthentications=publickey",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "HostbasedAuthentication=no",
        "GSSAPIAuthentication=no",
        "NumberOfPasswordPrompts=0",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "Tunnel=no",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "HostKeyAlias=petika-pinned",
        "HostKeyAlgorithms=ssh-ed25519",
        "PubkeyAcceptedAlgorithms=ssh-ed25519",
        "UpdateHostKeys=no",
        "VerifyHostKeyDNS=no",
        "CheckHostIP=no",
        "CanonicalizeHostname=no",
        "ProxyCommand=none",
        "ProxyJump=none",
        "PermitLocalCommand=no",
        "ControlMaster=no",
        "ControlPath=none",
        "ControlPersist=no",
        "AddKeysToAgent=no",
        "PKCS11Provider=none",
        "RequestTTY=no",
        "EscapeChar=none",
        "ConnectionAttempts=1",
        "ConnectTimeout=5",
        "ServerAliveInterval=5",
        "ServerAliveCountMax=1",
        "LogLevel=ERROR",
    ] {
        args.push("-o".into());
        args.push(option.into());
    }
    for (name, path) in [("IdentityAgent", socket), ("UserKnownHostsFile", known)] {
        args.push("-o".into());
        args.push(format!("{name}={}", path.to_str().ok_or(Error::Invalid)?));
    }
    args.push("-i".into());
    args.push(identity.to_str().ok_or(Error::Invalid)?.to_owned());
    Ok(format!(
        "#!/bin/sh\nexec /usr/bin/ssh {} \"$@\"\n",
        args.iter().map(|s| quote(s)).collect::<Vec<_>>().join(" ")
    ))
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        // Kill the dedicated group, including SSH/index-pack descendants, before
        // removing their temporary files. No inherited application process group.
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn nonblocking(stream: &impl AsRawFd) -> Result<()> {
    let fd = stream.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Error::Transfer);
    }
    Ok(())
}
fn drain(stream: &mut impl Read, bytes: &mut Vec<u8>) -> Result<()> {
    let mut buffer = [0; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                if bytes.len() + n > OUTPUT {
                    return Err(Error::Transfer);
                }
                bytes.extend_from_slice(&buffer[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Transfer),
        }
    }
}
fn quota(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = 0usize;
    let mut bytes = 0u64;
    while let Some(path) = pending.pop() {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error::Transfer),
        };
        for entry in entries {
            let entry = entry.map_err(|_| Error::Transfer)?;
            files += 1;
            if files > MAX_FILES {
                return Err(Error::Transfer);
            }
            // Git atomically renames lock/pack files while this polling scan is
            // running. Disappearance is benign; symlinks and other I/O errors
            // still reject, and a final scan follows process completion.
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(Error::Transfer),
            };
            if kind.is_symlink() {
                return Err(Error::Transfer);
            }
            let m = match entry.metadata() {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(Error::Transfer),
            };
            if m.is_dir() {
                pending.push(entry.path());
            } else if m.is_file() {
                bytes = bytes.checked_add(m.len()).ok_or(Error::Transfer)?;
                if m.len() > MAX_FILE || bytes > MAX_TREE {
                    return Err(Error::Transfer);
                }
            } else {
                return Err(Error::Transfer);
            }
        }
    }
    Ok(())
}
fn git(root: &Path, script: &Path, args: &[&str], deadline: Instant) -> Result<Vec<u8>> {
    let mut cmd = Command::new("/usr/bin/git");
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("XDG_CONFIG_HOME", root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/usr/bin/false")
        .env("SSH_ASKPASS", "/usr/bin/false")
        .env("GIT_SSH", script)
        .env("GIT_SSH_VARIANT", "ssh")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .current_dir(root)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for setting in [
        "protocol.allow=never",
        "protocol.ssh.allow=always",
        "protocol.version=0",
        "core.hooksPath=/dev/null",
        "core.fsmonitor=false",
        "credential.helper=",
        "fetch.fsckObjects=true",
        "transfer.fsckObjects=true",
        "fetch.unpackLimit=1",
        "submodule.recurse=false",
        "fetch.recurseSubmodules=false",
        "transfer.bundleURI=false",
        "gc.auto=0",
        "maintenance.auto=false",
        "index.threads=1",
    ] {
        cmd.args(["-c", setting]);
    }
    cmd.args(args);
    // File-size cap is inherited by Git/SSH children. Aggregate size and file
    // count are additionally polled; these are not a hard memory/CPU sandbox.
    unsafe {
        cmd.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: MAX_FILE as libc::rlim_t,
                rlim_max: MAX_FILE as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    if Instant::now() >= deadline {
        return Err(Error::Expired);
    }
    let mut child = Process(cmd.spawn().map_err(|_| Error::Transfer)?);
    let mut stdout = child.0.stdout.take().ok_or(Error::Transfer)?;
    let mut stderr = child.0.stderr.take().ok_or(Error::Transfer)?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    loop {
        drain(&mut stdout, &mut out)?;
        drain(&mut stderr, &mut err)?;
        quota(root)?;
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        if let Some(status) = child.0.try_wait().map_err(|_| Error::Transfer)? {
            drain(&mut stdout, &mut out)?;
            drain(&mut stderr, &mut err)?;
            quota(root)?;
            return if status.success() {
                Ok(out)
            } else {
                Err(Error::Transfer)
            };
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub(super) fn fetch(
    remote: PinnedRemote,
    branch_name: &str,
    socket: &Path,
    public: &str,
    budget: Duration,
) -> Result<FetchedGit> {
    remote.validate(&remote.repository)?;
    if !branch(branch_name) || budget.is_zero() || budget > Duration::from_secs(30) {
        return Err(Error::Invalid);
    }
    let deadline = Instant::now() + budget;
    let directory = tempfile::Builder::new()
        .prefix("petika-fetch-")
        .tempdir()
        .map_err(|_| Error::Transfer)?;
    let root = directory.path();
    let identity = root.join("identity.pub");
    let known = root.join("known_hosts");
    let script = root.join("ssh");
    file(&identity, format!("{public}\n").as_bytes(), 0o600)?;
    file(
        &known,
        format!("petika-pinned {}\n", remote.host_key).as_bytes(),
        0o600,
    )?;
    file(
        &script,
        wrapper(socket, &identity, &known)?.as_bytes(),
        0o700,
    )?;
    let repository = root.join("objects.git");
    let path = repository.to_str().ok_or(Error::Invalid)?;
    git(
        root,
        &script,
        &[
            "init",
            "--bare",
            "--template=",
            "--initial-branch=unused",
            "--object-format=sha1",
            path,
        ],
        deadline,
    )?;
    let git_dir = format!("--git-dir={path}");
    let url = remote.url();
    let refspec = format!("refs/heads/{branch_name}:refs/petika/fetched");
    git(
        root,
        &script,
        &[
            &git_dir,
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-auto-maintenance",
            "--no-write-fetch-head",
            "--depth=128",
            "--",
            &url,
            &refspec,
        ],
        deadline,
    )?;
    git(
        root,
        &script,
        &[
            &git_dir,
            "fsck",
            "--strict",
            "--no-reflogs",
            "--no-dangling",
        ],
        deadline,
    )?;
    let head = git(
        root,
        &script,
        &[
            &git_dir,
            "rev-parse",
            "--verify",
            "refs/petika/fetched^{commit}",
        ],
        deadline,
    )?;
    let head = std::str::from_utf8(&head)
        .map_err(|_| Error::Invalid)?
        .trim()
        .to_owned();
    if head.len() != 40
        || !head
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    // These temporary invocation files contain no private key, but avoid leaving
    // an obsolete agent socket path available in a returned quarantine.
    for p in [&identity, &known, &script] {
        fs::remove_file(p).map_err(|_| Error::Transfer)?;
    }
    Ok(FetchedGit {
        directory,
        repository,
        head,
        branch: branch_name.into(),
        remote,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quote_handles_shell_metacharacters_without_interpolation() {
        let value = "/tmp/a'$(touch bad)`bad`";
        let output = Command::new("/bin/sh")
            .args(["-c", &format!("printf %s {}", quote(value))])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), value);
    }
    #[test]
    fn inherited_git_configuration_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        if std::env::var_os("PETIKA_CONFIG_ISOLATION_WORKER").is_some() {
            let out = git(
                dir.path(),
                &dir.path().join("unused"),
                &["config", "--list"],
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
            let text = String::from_utf8(out).unwrap();
            assert!(!text.contains("petika.poison"));
            assert!(text.contains("protocol.allow=never"));
            assert!(text.contains("protocol.ssh.allow=always"));
            return;
        }
        let config = dir.path().join("poison-config");
        fs::write(
            &config,
            "[petika]\npoison=from-global\n[url \"ext::false\"]\ninsteadOf=ssh://\n",
        )
        .unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "git_lease::ssh::native::tests::inherited_git_configuration_is_ignored",
            ])
            .env("PETIKA_CONFIG_ISOLATION_WORKER", "1")
            .env("GIT_CONFIG_GLOBAL", &config)
            .env("GIT_CONFIG_SYSTEM", &config)
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "petika.poison")
            .env("GIT_CONFIG_VALUE_0", "from-env")
            .env("GIT_CONFIG_PARAMETERS", "'petika.poison=from-parameters'")
            .status()
            .unwrap();
        assert!(status.success());
    }
    #[test]
    fn timeout_kills_process_group_and_quota_rejects_symlinks_and_large_files() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let script = root.join("unused");
        assert!(matches!(
            git(
                root,
                &script,
                &["--version"],
                Instant::now() - Duration::from_secs(1)
            ),
            Err(Error::Expired)
        ));
        let started = Instant::now();
        assert!(matches!(
            git(
                root,
                &script,
                &["-c", "alias.petika-timeout=!sleep 5", "petika-timeout"],
                Instant::now() + Duration::from_millis(75)
            ),
            Err(Error::Expired)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        symlink("/dev/null", root.join("link")).unwrap();
        assert!(quota(root).is_err());
        fs::remove_file(root.join("link")).unwrap();
        let large = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root.join("large"))
            .unwrap();
        large.set_len(MAX_FILE + 1).unwrap();
        assert!(quota(root).is_err());
    }
}
