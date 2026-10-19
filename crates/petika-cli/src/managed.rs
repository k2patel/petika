//! Live API operations. Git transport and vault plaintext never meet here.
use crate::{Command, Result, account, keys};
use petika_core::{StoreFile, UnlockedStore};
use serde_json::{Value, json};
use std::path::Path;

pub fn selection(command: &Command) -> Option<&str> {
    match command {
        Command::List { collection, .. }
        | Command::Get { collection, .. }
        | Command::Show { collection, .. }
        | Command::Put { collection, .. }
        | Command::Generate { collection, .. }
        | Command::Remove { collection, .. }
        | Command::Otp { collection, .. } => collection.as_deref(),
        _ => None,
    }
}

pub fn run(
    session: &Path,
    identity: Option<&Path>,
    selected: &str,
    command: Command,
    stdin: bool,
) -> Result<()> {
    let write = matches!(
        command,
        Command::Put { .. }
            | Command::Generate { .. }
            | Command::Remove { .. }
            | Command::Otp { .. }
    );
    let client = account::client(session)?;
    let id = account::collection(&client, selected, write)?;
    let prefix = format!("/v1/collections/{id}");
    let (_, revision, encrypted) =
        client.request("GET", &format!("{prefix}/snapshot"), None, None)?;
    let revision = revision.ok_or("Missing server revision")?;
    let (_, context) = petika_core::envelope_metadata(encrypted.as_bytes())?;
    let mut access = None;
    let mut recipient = None;
    let mut store = if let Some(context) = context {
        if context.collection_id != id {
            return Err("Snapshot belongs to another collection".into());
        }
        let state = client.json("GET", &format!("{prefix}/key-access"), Value::Null)?;
        if state["snapshot_revision"].as_u64() != Some(revision)
            || state["key_epoch"].as_u64() != Some(context.key_epoch)
            || state["membership_generation"].as_u64().is_none()
        {
            return Err("Collection changed; retry before editing".into());
        }
        if write && state["rotation_required"] == true {
            return Err("Collection requires key rotation before editing".into());
        }
        let identity = identity
            .ok_or("Recipient collection requires --identity-file; no passphrase fallback")?;
        let (store, package) = keys::open_live(
            &client,
            identity,
            &prefix,
            encrypted.as_bytes(),
            &context,
            stdin,
        )?;
        access = Some(state);
        recipient = Some(package);
        store
    } else {
        let passphrase = crate::secret("Collection passphrase (local only): ", stdin)?;
        UnlockedStore::open(encrypted.as_bytes(), &passphrase)?
    };
    crate::operate(command, &mut store, stdin, |store| {
        let encrypted = String::from_utf8(store.seal()?)?;
        // Persist before submission: a lost response must not destroy the user's edit.
        let root = session
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let draft = tempfile::Builder::new()
            .prefix("petika-draft-")
            .tempdir_in(root)?;
        let path = draft.path().join("snapshot.petika");
        StoreFile::lock(&path)?.write(encrypted.as_bytes(), true)?;
        StoreFile::lock(draft.path().join("context.json"))?.write(&serde_json::to_vec(&json!({
            "server":client.server,"collection_id":id,"expected_revision":revision,
            "expected_key_epoch":access.as_ref().map(|v| &v["key_epoch"]),
            "expected_membership_generation":access.as_ref().map(|v| &v["membership_generation"])
        }))?, true)?;
        if let Some(package) = &recipient {
            StoreFile::lock(path.with_extension("access.json"))?
                .write(&serde_json::to_vec(package)?, true)?;
        }
        // Keep even on panic/interruption after this point. Remove only after a valid ack.
        let draft = draft.keep();
        let submitted = (|| -> Result<()> {
            #[cfg(unix)]
            std::fs::File::open(root)?.sync_all()?;
            let accepted = if let Some(access) = &access {
                let response = client.json("POST", &format!("{prefix}/recipient-snapshot"), json!({
                    "expected_snapshot_revision":revision,"expected_key_epoch":access["key_epoch"],
                    "expected_membership_generation":access["membership_generation"],
                    "packages":[],"encrypted_snapshot":encrypted
                }))?;
                if response["key_epoch"] != access["key_epoch"]
                    || response["membership_generation"] != access["membership_generation"]
                {
                    return Err("Save acknowledgement has unexpected key or membership state; acceptance is uncertain".into());
                }
                response["snapshot_revision"].as_u64()
            } else {
                client
                    .request(
                        "PUT",
                        &format!("{prefix}/snapshot"),
                        Some(&encrypted),
                        Some(revision),
                    )?
                    .1
            };
            if accepted != revision.checked_add(1) || accepted.is_none() {
                return Err(
                    "Save acknowledgement is missing or unexpected; acceptance is uncertain".into(),
                );
            }
            Ok(())
        })();
        if let Err(error) = submitted {
            return Err(format!("{error}. Encrypted draft preserved at {}. Fetch the latest state and compare explicitly; do not blindly retry or overwrite.", draft.display()).into());
        }
        if std::fs::remove_dir_all(&draft).is_err() {
            eprintln!(
                "API save accepted; encrypted draft cleanup failed at {}",
                draft.display()
            );
        }
        eprintln!(
            "API accepted revision {}. Remote Git replication is separate.",
            revision + 1
        );
        Ok(())
    })
}
