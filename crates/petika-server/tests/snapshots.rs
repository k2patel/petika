use petika_core::UnlockedStore;
use petika_server::{Repository, Update, mirror_once};

#[test]
fn compare_and_swap_persists_and_mirror_preserves_every_accepted_revision() {
    let dir = tempfile::tempdir().unwrap();
    let repository = Repository::new(dir.path().join("api/snapshot.json"));
    repository.ready().unwrap();
    assert!(repository.read().unwrap().is_none());
    let mut store = UnlockedStore::create("synthetic test passphrase").unwrap();
    let one = String::from_utf8(store.seal().unwrap()).unwrap();
    assert!(matches!(
        repository.update(0, one.clone()).unwrap(),
        Update::Saved(1)
    ));
    assert!(matches!(
        repository.update(0, one).unwrap(),
        Update::Conflict(1)
    ));
    let two = String::from_utf8(store.seal().unwrap()).unwrap();
    assert!(matches!(
        repository.update(1, two.clone()).unwrap(),
        Update::Saved(2)
    ));
    assert_eq!(repository.read().unwrap().unwrap().encrypted, two);
    assert!(repository.update(2, "plaintext".into()).is_err());
    assert_eq!(repository.read().unwrap().unwrap().revision, 2);
    let mirror = dir.path().join("mirror");
    assert_eq!(mirror_once(&repository, &mirror).unwrap(), Some(2));
    assert_eq!(mirror_once(&repository, &mirror).unwrap(), Some(2));
    let count = std::process::Command::new("git")
        .arg("-C")
        .arg(mirror.join("repository.git"))
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .unwrap();
    assert!(count.status.success());
    assert_eq!(String::from_utf8_lossy(&count.stdout).trim(), "2");
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(mirror.join("repository.git"))
        .args(["show", "HEAD:snapshot.json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let latest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(latest["revision"], 2);
}
