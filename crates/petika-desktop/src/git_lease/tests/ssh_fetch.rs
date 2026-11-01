use super::*;
use crate::git_lease::ssh::PinnedRemote;
use std::{
    fs,
    io::Write,
    net::{TcpListener, TcpStream},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn command(program: &str, args: &[&str], input: Option<&[u8]>) -> Vec<u8> {
    let mut child = Command::new(program)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Public synthetic fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Public synthetic fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(bytes) = input {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    } else {
        drop(child.stdin.take());
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap().trim().to_owned()
}
fn private(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
struct Server {
    _dir: tempfile::TempDir,
    child: Child,
    pin: PinnedRemote,
    authorized: PathBuf,
    head: String,
    ciphertext: Vec<u8>,
}
impl Drop for Server {
    fn drop(&mut self) {
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Server {
    fn new(public: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("petika-sshd-test-")
            .tempdir_in("/private/tmp")
            .unwrap();
        let root = dir.path();
        let repository = root.join("remote.git");
        let path = repository.to_str().unwrap();
        command(
            "/usr/bin/git",
            &[
                "init",
                "--bare",
                "--template=",
                "--initial-branch=main",
                path,
            ],
            None,
        );
        // Generated authenticated ciphertext, never a real account/vault.
        let mut custody = TestCustody::new();
        let ciphertext = custody
            .seal(b"public SSH transport fixture", b"synthetic vault entry")
            .unwrap();
        let git_dir = format!("--git-dir={path}");
        let blob = text(command(
            "/usr/bin/git",
            &[&git_dir, "hash-object", "-w", "--stdin"],
            Some(&ciphertext),
        ));
        let tree = text(command(
            "/usr/bin/git",
            &[&git_dir, "mktree"],
            Some(format!("100644 blob {blob}\tentry.enc\n").as_bytes()),
        ));
        let head = text(command(
            "/usr/bin/git",
            &[
                &git_dir,
                "commit-tree",
                &tree,
                "-m",
                "Synthetic SSH fixture",
            ],
            None,
        ));
        command(
            "/usr/bin/git",
            &[&git_dir, "update-ref", "refs/heads/main", &head],
            None,
        );
        let host_key = root.join("host");
        command(
            "/usr/bin/ssh-keygen",
            &[
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                host_key.to_str().unwrap(),
            ],
            None,
        );
        let host_public = fs::read_to_string(root.join("host.pub"))
            .unwrap()
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let username = text(command("/usr/bin/id", &["-un"], None));
        let port = {
            let socket = TcpListener::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().port()
        };
        let authorized = root.join("authorized_keys");
        private(&authorized, format!("{public}\n").as_bytes(), 0o600);
        let forced = root.join("upload.sh");
        private(&forced,format!("#!/bin/sh\n[ \"$SSH_ORIGINAL_COMMAND\" = \"git-upload-pack '/synthetic/vault.git'\" ] || exit 97\nexec /usr/bin/git upload-pack '{}'\n",path.replace('\'',"'\\''")).as_bytes(),0o700);
        let config = root.join("sshd_config");
        // Fixture only: OpenSSH StrictModes rejects /private/tmp's sticky writable
        // ancestor. Actual files remain owner-only in this private test directory;
        // no system sshd configuration or existing account is modified.
        private(&config,format!("ListenAddress 127.0.0.1\nPort {port}\nHostKey {}\nPidFile {}/pid\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthenticationMethods publickey\nPubkeyAuthentication yes\nPermitRootLogin no\nAllowUsers {username}\nAllowAgentForwarding no\nAllowTcpForwarding no\nPermitTTY no\nUseDNS no\nLogLevel ERROR\nPerSourcePenalties no\nForceCommand /bin/sh {}\n",host_key.display(),root.display(),authorized.display(),forced.display()).as_bytes(),0o600);
        let log = root.join("sshd.log");
        let log_file = fs::File::create(&log).unwrap();
        let mut child = Command::new("/usr/sbin/sshd")
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log_file)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            if child.try_wait().unwrap().is_some() || Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("local sshd failed: {}", fs::read_to_string(&log).unwrap());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let pin = PinnedRemote {
            host: "127.0.0.1".into(),
            port,
            username,
            repository: "synthetic/vault".into(),
            host_key: host_public,
        };
        pin.validate("synthetic/vault").unwrap();
        Self {
            _dir: dir,
            child,
            pin,
            authorized,
            head,
            ciphertext,
        }
    }
    fn authorize(&self, public: &str) {
        private(&self.authorized, format!("{public}\n").as_bytes(), 0o600);
    }
}
fn public(op: &Operation<TestCustody>) -> String {
    let raw = STANDARD.decode(&op.intent().ssh_public_key).unwrap();
    let mut wire = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    wire.extend(raw);
    format!("ssh-ed25519 {}", STANDARD.encode(wire))
}
fn retain(op: &mut Operation<TestCustody>, pin: PinnedRemote) {
    op.draft.intent.scope.ssh_remote = Some(pin);
    op.draft.intent.validate().unwrap();
    op.persist(false).unwrap();
}
#[test]
#[ignore = "requires /usr/sbin/sshd and loopback sockets; uses generated keys/data only"]
fn actual_ssh_fetch_requires_retained_host_pin_and_returns_only_quarantined_objects() {
    let (_dir, mut op, device, pin, mut service) = setup();
    let server = Server::new(&public(&op));
    retain(&mut op, server.pin.clone());
    admit(&mut op, &device, &pin, &mut service);
    let fetched = op.fetch(&mut service, 103, "main").unwrap_or_else(|error| {
        panic!(
            "generated SSH fixture failed: {error}; {}",
            fs::read_to_string(server._dir.path().join("sshd.log")).unwrap()
        )
    });
    assert_eq!(fetched.head(), server.head);
    assert_eq!(fetched.branch(), "main");
    assert_eq!(fetched.remote(), &server.pin);
    let git_dir = format!("--git-dir={}", fetched.repository_path().display());
    assert_eq!(
        command(
            "/usr/bin/git",
            &[&git_dir, "show", "refs/petika/fetched:entry.enc"],
            None
        ),
        server.ciphertext
    );
    assert!(fetched.repository_path().join("objects").is_dir());
    assert!(!fetched.quarantine_path().join("identity.pub").exists());
    assert!(!fetched.quarantine_path().join("ssh").exists());
    assert!(!fetched.quarantine_path().join("known_hosts").exists());
    assert_eq!(op.phase(), Phase::CleanupPending);
    assert_eq!(service.completions, 1);
    let quarantine = fetched.quarantine_path().to_owned();
    drop(fetched);
    assert!(!quarantine.exists());

    // A different valid host key is not silently accepted, even though the same
    // endpoint accepts this client's independent transport key.
    let (_dir, mut op, device, pin, mut service) = setup();
    server.authorize(&public(&op));
    let mut wrong = server.pin.clone();
    let raw = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
    let mut wire = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    wire.extend(raw);
    wrong.host_key = format!("ssh-ed25519 {}", STANDARD.encode(wire));
    retain(&mut op, wrong);
    admit(&mut op, &device, &pin, &mut service);
    assert!(matches!(
        op.fetch(&mut service, 103, "main"),
        Err(Error::Transfer)
    ));
    assert_eq!(op.phase(), Phase::CleanupPending);
    assert_eq!(service.completions, 1);

    // Correct host pin is insufficient without the ephemeral transport key.
    let (_dir, mut op, device, pin, mut service) = setup();
    retain(&mut op, server.pin.clone());
    admit(&mut op, &device, &pin, &mut service);
    assert!(matches!(
        op.fetch(&mut service, 103, "main"),
        Err(Error::Transfer)
    ));
    assert_eq!(service.completions, 1);
}
#[test]
fn missing_or_mismatched_pin_and_invalid_branch_do_not_start_transfer() {
    let (_dir, mut op, device, pin, mut service) = setup();
    let mut invalid = op.intent().clone();
    invalid.scope.management_origin = "https://user:secret@git.example/".into();
    assert!(invalid.validate().is_err());
    admit(&mut op, &device, &pin, &mut service);
    assert!(matches!(
        op.fetch(&mut service, 103, "main"),
        Err(Error::Invalid)
    ));
    assert_eq!(op.phase(), Phase::Active);
    assert_eq!(service.completions, 0);
    let (dir, mut op, device, pin, mut service) = setup();
    let remote = PinnedRemote {
        host: "git.example".into(),
        port: 22,
        username: "git".into(),
        repository: "synthetic/vault".into(),
        host_key: public(&op),
    };
    retain(&mut op, remote.clone());
    drop(op);
    let mut op = Operation::resume(dir.path().join("draft"), TestCustody::new()).unwrap();
    assert_eq!(op.intent().scope.ssh_remote.as_ref(), Some(&remote));
    admit(&mut op, &device, &pin, &mut service);
    assert!(matches!(
        op.fetch(&mut service, 103, "main:refs/heads/other"),
        Err(Error::Invalid)
    ));
    assert_eq!(op.phase(), Phase::Active);
    op.draft
        .intent
        .scope
        .ssh_remote
        .as_mut()
        .unwrap()
        .repository = "other/vault".into();
    assert!(matches!(
        op.fetch(&mut service, 103, "main"),
        Err(Error::Invalid)
    ));
    assert_eq!(op.phase(), Phase::Active);
    assert_eq!(service.completions, 0);
}
