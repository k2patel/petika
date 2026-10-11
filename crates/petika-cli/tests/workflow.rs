use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

fn run(path: &Path, args: &[&str], input: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_petika"));
    let mut child = command
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
