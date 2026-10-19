use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

#[test]
fn live_show_uses_api_without_reading_or_writing_local_vault() {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.petika");
    let password = "synthetic live passphrase\n";
    assert!(
        run(&source, &["init"], &password.repeat(2))
            .status
            .success()
    );
    assert!(
        run(
            &source,
            &["put", "example", "--password-stdin"],
            &format!("{password}live-secret\n")
        )
        .status
        .success()
    );
    let encrypted = std::fs::read_to_string(&source).unwrap();
    for (status, unlock, succeeds) in [
        (200, password, true),
        (200, "incorrect\n", false),
        (401, password, false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let session = dir.path().join("session.json");
        let token = format!("cli_{}", "a".repeat(64));
        petika_core::StoreFile::lock(&session).unwrap().write(serde_json::json!({"version":1,"server":format!("http://{}", listener.local_addr().unwrap()),"token":token}).to_string().as_bytes(), false).unwrap();
        let ciphertext = encrypted.clone();
        let worker = std::thread::spawn(move || {
            let id = "b".repeat(64);
            let responses = if status == 401 {
                vec![("/v1/collections".to_owned(), "{}".to_owned())]
            } else {
                vec![
                    (
                        "/v1/collections".to_owned(),
                        serde_json::json!([{"id":id,"group":false,"edit":false}]).to_string(),
                    ),
                    (format!("/v1/collections/{id}/snapshot"), ciphertext),
                ]
            };
            for (path, body) in responses {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let (mut socket, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "CLI never requested {path}"
                            );
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    request.push_str(&line);
                }
                assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
                assert!(
                    request
                        .to_lowercase()
                        .contains(&format!("authorization: bearer {token}"))
                );
                assert!(!request.contains("synthetic live passphrase"));
                write!(socket, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nETag: \"7\"\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let local = dir.path().join("unused.petika");
        let result = run(
            &local,
            &[
                "--session-file",
                session.to_str().unwrap(),
                "show",
                "example",
                "--collection",
                "personal",
            ],
            unlock,
        );
        worker.join().unwrap();
        assert_eq!(
            result.status.success(),
            succeeds,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&result.stdout).contains("live-secret"),
            succeeds
        );
        assert!(!local.exists());
        assert!(!local.with_extension("petika.lock").exists());
    }
}

fn run(path: &Path, args: &[&str], input: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_petika"));
    let mut child = command
        .arg("--no-config")
        .arg("--store")
        .arg(path)
        .arg("--passphrase-stdin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn cli_create_put_reveal_generate_remove_and_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.petika");
    let password = "synthetic test passphrase\n";
    assert!(run(&path, &["init"], &password.repeat(2)).status.success());
    assert!(!run(&path, &["init"], "").status.success());
    let put = run(
        &path,
        &["put", "example", "--username", "alice", "--password-stdin"],
        &format!("{password}synthetic-secret\n"),
    );
    assert!(
        put.status.success(),
        "{}",
        String::from_utf8_lossy(&put.stderr)
    );
    let get = run(&path, &["get", "example"], password);
    assert!(get.status.success());
    assert!(!String::from_utf8_lossy(&get.stdout).contains("synthetic-secret"));
    let reveal = run(&path, &["get", "example", "--reveal"], password);
    assert!(reveal.status.success());
    assert_eq!(
        String::from_utf8_lossy(&reveal.stdout).trim(),
        "synthetic-secret"
    );
    let before = std::fs::read(&path).unwrap();
    assert!(
        !run(&path, &["generate", "example"], password)
            .status
            .success()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!run(&path, &["list"], "incorrect\n").status.success());
    assert!(
        run(&path, &["generate", "other", "--length", "32"], password)
            .status
            .success()
    );
    assert!(!run(&path, &["remove", "other"], password).status.success());
    assert!(
        run(&path, &["remove", "other", "--yes"], password)
            .status
            .success()
    );
    let listed = run(&path, &["list", "exam"], password);
    assert!(listed.status.success());
    assert_eq!(String::from_utf8_lossy(&listed.stdout).trim(), "example");
}

#[test]
fn mismatched_or_short_passphrases_leave_no_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.petika");
    assert!(!run(&path, &["init"], "short\nshort\n").status.success());
    assert!(!path.exists());
    assert!(
        !run(
            &path,
            &["init"],
            "long passphrase here\ndifferent passphrase here\n"
        )
        .status
        .success()
    );
    assert!(!path.exists());
}

#[test]
fn show_validates_unlock_and_totp_setup_is_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.petika");
    let pass = "synthetic test passphrase\n";
    assert!(run(&path, &["init"], &pass.repeat(2)).status.success());
    assert!(
        run(
            &path,
            &["insert", "Email/example", "--password-stdin"],
            &format!("{pass}synthetic-secret\n")
        )
        .status
        .success()
    );
    let wrong = run(&path, &["show", "Email/example"], "wrong passphrase\n");
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
    let shown = run(&path, &["show", "Email/example"], pass);
    assert!(shown.status.success());
    assert_eq!(
        String::from_utf8(shown.stdout).unwrap(),
        "Password: synthetic-secret\n"
    );
    let before = std::fs::read(&path).unwrap();
    let bad = run(
        &path,
        &["otp", "set", "Email/example", "--secret-stdin"],
        &format!("{pass}invalid-sensitive-value\n"),
    );
    assert!(!bad.status.success());
    assert!(!String::from_utf8_lossy(&bad.stderr).contains("invalid-sensitive-value"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let setup = run(
        &path,
        &["otp", "set", "Email/example", "--secret-stdin"],
        &format!("{pass}JBSWY3DPEHPK3PXP\n"),
    );
    assert!(
        setup.status.success(),
        "{}",
        String::from_utf8_lossy(&setup.stderr)
    );
    let encrypted = std::fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&encrypted).contains("JBSWY3DPEHPK3PXP"));
    assert!(
        !run(
            &path,
            &["otp", "set", "Email/example", "--secret-stdin"],
            pass
        )
        .status
        .success()
    );
    let shown = run(&path, &["show", "Email/example", "--totp"], pass);
    assert!(shown.status.success());
    let text = String::from_utf8(shown.stdout).unwrap();
    assert!(text.contains("Password: synthetic-secret"));
    let otp = text
        .lines()
        .find(|line| line.starts_with("TOTP: "))
        .unwrap();
    let code = otp.split_whitespace().nth(1).unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|b| b.is_ascii_digit()));
    assert!(otp.contains("expires in "));
    assert!(!text.contains("JBSWY3DPEHPK3PXP"));
    assert_eq!(std::fs::read(&path).unwrap(), encrypted); // Reading never rewrites the vault.
    assert!(
        !run(&path, &["otp", "remove", "Email/example"], pass)
            .status
            .success()
    );
    assert!(
        run(&path, &["otp", "remove", "Email/example", "--yes"], pass)
            .status
            .success()
    );
    let missing = run(&path, &["show", "Email/example", "--totp"], pass);
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
}

#[test]
fn rc_defaults_and_explicit_store_override() {
    let dir = tempfile::tempdir().unwrap();
    let rc = dir.path().join(".petikarc");
    std::fs::write(&rc, "store = configured.petika\n").unwrap();
    let invoke = |extra: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_petika"));
        let mut child = cmd
            .arg("--config")
            .arg(&rc)
            .arg("--passphrase-stdin")
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"synthetic test passphrase\nsynthetic test passphrase\n")
            .unwrap();
        child.wait_with_output().unwrap()
    };
    assert!(invoke(&["init"]).status.success());
    assert!(dir.path().join("configured.petika").exists());
    let other = dir.path().join("override.petika");
    assert!(
        invoke(&["--store", other.to_str().unwrap(), "init"])
            .status
            .success()
    );
    assert!(other.exists());
    std::fs::write(&rc, "password = do-not-echo\n").unwrap();
    let invalid = invoke(&["list"]);
    assert!(!invalid.status.success());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("do-not-echo"));
}
