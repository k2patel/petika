use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

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
