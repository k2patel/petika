use crate::{Result, account};
use clap::Subcommand;
use petika_core::{
    StoreFile, UnlockedStore,
    identity::{KeyPackage, PublicIdentity, UnlockedIdentity},
};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Subcommand)]
pub enum Command {
    /// Retry the preserved ciphertext transaction after an interrupted response.
    Retry {
        #[arg(long)]
        collection: String,
    },
    Enroll,
    RetryEnrollment,
    Restore {
        #[arg(long)]
        fingerprint: String,
    },
    Verify {
        #[arg(long)]
        user: String,
        #[arg(long)]
        fingerprint: String,
    },
    Status {
        #[arg(long)]
        collection: String,
    },
    Migrate {
        #[arg(long)]
        collection: String,
    },
    Deliver {
        #[arg(long)]
        collection: String,
    },
    Rotate {
        #[arg(long)]
        collection: String,
    },
    Pull {
        #[arg(long)]
        collection: String,
    },
    Push {
        #[arg(long)]
        collection: String,
        #[arg(long)]
        revision: u64,
    },
}
fn save_bundle_revision(path: &Path, revision: &Value) -> Result<()> {
    StoreFile::lock(path.with_extension("bundle-revision.json"))?
        .write(&serde_json::to_vec(revision)?, false)?;
    Ok(())
}
fn require_bundle_revision(path: &Path, revision: &Value) -> Result<()> {
    let file = StoreFile::lock(path.with_extension("bundle-revision.json"))?;
    if !file.exists() || serde_json::from_slice::<Value>(&file.read()?)? != *revision {
        return Err("Remote trust bundle changed; preserve this local identity and restore the remote bundle to a separate file before reconciling contacts".into());
    }
    Ok(())
}
fn open_identity(
    path: &Path,
    stdin: bool,
) -> Result<(UnlockedIdentity, zeroize::Zeroizing<String>)> {
    let bytes = StoreFile::lock(path)?.read()?;
    let backup: Value = serde_json::from_slice(&bytes)?;
    let fingerprint = backup["public_identity"]["fingerprint"]
        .as_str()
        .ok_or("Invalid local identity")?;
    let passphrase = crate::secret("Identity unlock passphrase (local only): ", stdin)?;
    Ok((
        UnlockedIdentity::open(&bytes, &passphrase, fingerprint)?,
        passphrase,
    ))
}
fn access_path(path: &Path) -> std::path::PathBuf {
    path.with_extension("access.json")
}
fn observe_epoch(identity_path: &Path, context: &petika_core::CollectionContext) -> Result<()> {
    let file = StoreFile::lock(identity_path.with_extension("epochs.json"))?;
    let mut epochs: std::collections::BTreeMap<String, u64> = if file.exists() {
        serde_json::from_slice(&file.read()?)?
    } else {
        Default::default()
    };
    let id = format!("{}:{}", context.deployment_id, context.collection_id);
    if epochs
        .get(&id)
        .is_some_and(|previous| *previous > context.key_epoch)
    {
        return Err("Collection key epoch rolled back; refusing old access".into());
    }
    epochs.insert(id, context.key_epoch);
    file.write(&serde_json::to_vec(&epochs)?, false)?;
    Ok(())
}
pub fn open_local(
    identity_path: &Path,
    encrypted: &[u8],
    store_path: &Path,
    stdin: bool,
) -> Result<UnlockedStore> {
    // All CLI identity read/modify/write sequences share this lock, including offline use.
    let _origin_lock = StoreFile::lock(identity_path.with_extension("origin.json"))?;
    let (mut identity, passphrase) = open_identity(identity_path, stdin)?;
    let result = open_local_with_identity(&mut identity, encrypted, store_path);
    petika_core::identity::IdentityFile::lock(identity_path)?.save(
        &identity,
        &passphrase,
        false,
    )?;
    let store = result?;
    observe_epoch(
        identity_path,
        store.context().ok_or("Not a recipient collection")?,
    )?;
    Ok(store)
}
fn open_local_with_identity(
    identity: &mut UnlockedIdentity,
    encrypted: &[u8],
    store_path: &Path,
) -> Result<UnlockedStore> {
    let access: Value = serde_json::from_slice(&StoreFile::lock(access_path(store_path))?.read()?)?;
    let package: KeyPackage = serde_json::from_value(access["package"].clone())?;
    let issuer: PublicIdentity = serde_json::from_value(access["issuer"].clone())?;
    let (mode, context) = petika_core::envelope_metadata(encrypted)?;
    let context = context.ok_or("Not a recipient collection")?;
    Ok(identity.open_key_package(&package, &issuer, encrypted, &context, mode)?)
}
fn access_state(client: &account::Client, prefix: &str) -> Result<Value> {
    let mut state = client.json("GET", &format!("{prefix}/key-access"), Value::Null)?;
    for _ in 0..100 {
        let cursor = state["next_cursor"].as_str().ok_or("Invalid cursor")?;
        if cursor.is_empty() {
            return Ok(state);
        }
        if !cursor.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid cursor".into());
        }
        let page = client.json(
            "GET",
            &format!("{prefix}/key-access?cursor={cursor}"),
            Value::Null,
        )?;
        if page["snapshot_revision"] != state["snapshot_revision"]
            || page["membership_generation"] != state["membership_generation"]
        {
            return Err("Collection changed while reading roster".into());
        }
        let rows = page["deliveries"].as_array().ok_or("Invalid roster")?;
        state["deliveries"]
            .as_array_mut()
            .ok_or("Invalid roster")?
            .extend(rows.iter().cloned());
        state["next_cursor"] = page["next_cursor"].clone();
    }
    Err("Roster limit exceeded".into())
}
pub fn run(
    session: &Path,
    identity_path: &Path,
    store_path: Option<&Path>,
    command: &Command,
    stdin: bool,
) -> Result<()> {
    let client = account::client(session)?;
    let origin_file = StoreFile::lock(identity_path.with_extension("origin.json"))?;
    let identity_file = StoreFile::lock(identity_path)?;
    if origin_file.exists() {
        if serde_json::from_slice::<String>(&origin_file.read()?)? != client.server {
            return Err("Identity is pinned to another server origin".into());
        }
    } else if identity_file.exists() {
        return Err(
            "Identity origin pin missing; restore to a new identity path explicitly".into(),
        );
    }
    if let Command::Status { collection } = command {
        let id = account::collection(&client, collection, false)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&client.json(
                "GET",
                &format!("/v1/collections/{id}/key-access"),
                Value::Null
            )?)?
        );
        return Ok(());
    }
    if let Command::Retry { collection } = command {
        let id = account::collection(&client, collection, true)?;
        let body: Value = serde_json::from_slice(
            &StoreFile::lock(identity_path.with_extension("delivery-draft.json"))?.read()?,
        )?;
        if !body["packages"]
            .as_array()
            .is_some_and(|p| !p.is_empty() && p.iter().all(|p| p["collection_id"] == id))
        {
            return Err("Draft belongs to another collection".into());
        }
        let action = if body.get("encrypted_snapshot").is_none() {
            "key-packages"
        } else if body["expected_key_epoch"] == 0 {
            "recipient-migration"
        } else {
            "key-rotation"
        };
        println!(
            "{}",
            client.json("POST", &format!("/v1/collections/{id}/{action}"), body)?
        );
        return Ok(());
    }
    let user = client.json("GET", "/v1/auth/status", Value::Null)?["user"]["id"]
        .as_str()
        .ok_or("Not signed in")?
        .to_owned();
    let deployment = client.json("GET", "/v1/keys/deployment", Value::Null)?["deployment_id"]
        .as_str()
        .ok_or("Invalid deployment")?
        .to_owned();
    if matches!(command, Command::RetryEnrollment) {
        let bytes = identity_file.read()?;
        let backup: Value = serde_json::from_slice(&bytes)?;
        if backup["public_identity"]["user_id"] != user
            || backup["public_identity"]["deployment_id"] != deployment
        {
            return Err("Saved enrollment belongs to another account/deployment".into());
        }
        let password = crate::secret("Confirm account password (sent to server): ", stdin)?;
        let request = json!({"expected_bundle_revision":0,"current_password":password.as_str(),"public_identity":backup["public_identity"],"encrypted_bundle":backup["encrypted_bundle"]});
        if let Err(error) = client.json("POST", "/v1/keys/identity", request) {
            let own = client.json("GET", "/v1/keys/identity", Value::Null)?;
            if own["public_identity"] != backup["public_identity"]
                || own["encrypted_bundle"] != backup["encrypted_bundle"]
            {
                return Err(error);
            }
        }
        save_bundle_revision(identity_path, &json!(1))?;
        println!("Saved enrollment confirmed.");
        return Ok(());
    }
    if matches!(command, Command::Enroll | Command::Restore { .. }) {
        if identity_file.exists() {
            return Err("Identity file exists; choose a new path to preserve it".into());
        }
        if let Command::Restore { fingerprint } = command {
            let own = client.json("GET", "/v1/keys/identity", Value::Null)?;
            let backup = json!({"backup_version":own["encrypted_bundle"]["bundle_version"],"public_identity":own["public_identity"],"encrypted_bundle":own["encrypted_bundle"]});
            let bytes = serde_json::to_vec(&backup)?;
            let passphrase = crate::secret("Identity unlock passphrase: ", stdin)?;
            let identity = UnlockedIdentity::open(&bytes, &passphrase, fingerprint)?;
            if identity.public_identity().user_id != user
                || identity.public_identity().deployment_id != deployment
            {
                return Err("Identity does not match this account/deployment".into());
            }
            origin_file.write(&serde_json::to_vec(&client.server)?, true)?;
            identity_file.write(&bytes, true)?;
            save_bundle_revision(identity_path, &own["bundle_revision"])?;
            println!("Restored encrypted identity and verified contacts.");
            return Ok(());
        }
        let identity = UnlockedIdentity::generate(&deployment, &user, 1)?;
        let passphrase = crate::new_passphrase(stdin)?;
        let bytes = identity.seal(&passphrase)?;
        let backup: Value = serde_json::from_slice(&bytes)?;
        // Preserve generated ciphertext before enrollment, including ambiguous network failures.
        origin_file.write(&serde_json::to_vec(&client.server)?, true)?;
        identity_file.write(&bytes, true)?;
        let password = crate::secret("Confirm account password (sent to server): ", stdin)?;
        client.json("POST", "/v1/keys/identity", json!({"expected_bundle_revision":0,"current_password":password.as_str(),"public_identity":backup["public_identity"],"encrypted_bundle":backup["encrypted_bundle"]}))?;
        save_bundle_revision(identity_path, &json!(1))?;
        println!(
            "Enrolled. Fingerprint: {}\nBack up the encrypted identity file and keep its passphrase separately.",
            identity.public_identity().fingerprint
        );
        return Ok(());
    }
    drop(identity_file);
    let (mut identity, passphrase) = open_identity(identity_path, stdin)?;
    if identity.public_identity().user_id != user
        || identity.public_identity().deployment_id != deployment
    {
        return Err("Identity does not match this account/deployment".into());
    }
    let own = client.json("GET", "/v1/keys/identity", Value::Null)?;
    if own["public_identity"] != serde_json::to_value(identity.public_identity())? {
        return Err("Server identity changed; restore or replace explicitly".into());
    }
    if let Command::Verify { user, fingerprint } = command {
        require_bundle_revision(identity_path, &own["bundle_revision"])?;
        let public: PublicIdentity = serde_json::from_value(client.json(
            "GET",
            &format!("/v1/keys/users/{user}"),
            Value::Null,
        )?)?;
        let pin = identity.contact_pin(user).cloned();
        identity.verify_contact(user, &public, fingerprint, pin.as_ref())?;
        petika_core::identity::IdentityFile::lock(identity_path)?.save(
            &identity,
            &passphrase,
            false,
        )?;
        let bytes = StoreFile::lock(identity_path)?.read()?;
        let backup: Value = serde_json::from_slice(&bytes)?;
        let updated = client.json("PUT", "/v1/keys/identity/bundle", json!({"expected_bundle_revision":own["bundle_revision"],"encrypted_bundle":backup["encrypted_bundle"]}))?;
        save_bundle_revision(identity_path, &updated["bundle_revision"])?;
        println!("Verified contact; encrypted pins saved and synchronized.");
        return Ok(());
    }
    let (selected, write) = match command {
        Command::Migrate { collection }
        | Command::Deliver { collection }
        | Command::Rotate { collection }
        | Command::Push { collection, .. } => (collection, true),
        Command::Pull { collection } => (collection, false),
        _ => unreachable!(),
    };
    let id = account::collection(&client, selected, write)?;
    let prefix = format!("/v1/collections/{id}");
    let access = access_state(&client, &prefix)?;
    let (_, revision, encrypted) =
        client.request("GET", &format!("{prefix}/snapshot"), None, None)?;
    if revision != access["snapshot_revision"].as_u64() {
        return Err("Collection changed; retry".into());
    }
    let mut store;
    if matches!(command, Command::Migrate { .. }) {
        store = UnlockedStore::open(
            encrypted.as_bytes(),
            &crate::secret("Current group recovery passphrase: ", stdin)?,
        )?;
        let recovery = crate::new_passphrase(stdin)?;
        store.bind_collection(
            petika_core::CollectionContext {
                deployment_id: deployment,
                collection_id: id,
                key_epoch: 1,
            },
            &recovery,
        )?;
    } else {
        let page = client.json("GET", &format!("{prefix}/key-packages"), Value::Null)?;
        let package: KeyPackage = serde_json::from_value(page["packages"].as_array().and_then(|p| p.first()).ok_or("Pending delivery: an unlocked editor must verify your identity and deliver access")?.clone())?;
        let issuer: PublicIdentity = serde_json::from_value(client.json(
            "GET",
            &format!("/v1/keys/users/{}", package.issuer_user_id),
            Value::Null,
        )?)?;
        let (mode, context) = petika_core::envelope_metadata(encrypted.as_bytes())?;
        let context = context.ok_or("Collection requires recipient migration")?;
        let opened =
            identity.open_key_package(&package, &issuer, encrypted.as_bytes(), &context, mode);
        petika_core::identity::IdentityFile::lock(identity_path)?.save(
            &identity,
            &passphrase,
            false,
        )?;
        store = opened?;
        observe_epoch(identity_path, &context)?;
        if let Command::Pull { .. } = command {
            let path = store_path.ok_or("Specify --store for the downloaded collection")?;
            let file = StoreFile::lock(path)?;
            if file.exists() {
                return Err("Local store exists; choose a new --store path".into());
            }
            StoreFile::lock(access_path(path))?.write(
                &serde_json::to_vec(&json!({"package":package,"issuer":issuer}))?,
                true,
            )?;
            file.write(encrypted.as_bytes(), true)?;
            println!(
                "Pulled verified revision {}. Use --identity-file with offline commands.",
                revision.unwrap()
            );
            return Ok(());
        }
    }
    if let Command::Push { revision, .. } = command {
        let path = store_path.ok_or("Specify --store")?;
        let bytes = StoreFile::lock(path)?.read()?;
        // Authenticate local data with the same current recipient package before publication.
        let opened = open_local_with_identity(&mut identity, &bytes, path);
        petika_core::identity::IdentityFile::lock(identity_path)?.save(
            &identity,
            &passphrase,
            false,
        )?;
        let local = opened?;
        observe_epoch(
            identity_path,
            local.context().ok_or("Not a recipient collection")?,
        )?;
        let result = client.json("POST", &format!("{prefix}/recipient-snapshot"), json!({"expected_snapshot_revision":revision,"expected_key_epoch":access["key_epoch"],"expected_membership_generation":access["membership_generation"],"packages":[],"encrypted_snapshot":String::from_utf8(bytes)?}))?;
        println!("{result}");
        return Ok(());
    }
    if matches!(command, Command::Rotate { .. }) {
        store = store.rotated(&crate::new_passphrase(stdin)?)?;
    }
    let generation = access["membership_generation"]
        .as_u64()
        .ok_or("Invalid generation")?;
    let mut packages = Vec::new();
    for delivery in access["deliveries"].as_array().ok_or("Invalid roster")? {
        let user = delivery["user_id"].as_str().ok_or("Invalid member")?;
        if delivery["identity_version"] == 0 {
            eprintln!("Pending enrollment: {user}");
            continue;
        }
        if matches!(command, Command::Deliver { .. }) && delivery["state"] == "package-available" {
            continue;
        }
        let recipient: PublicIdentity = serde_json::from_value(client.json(
            "GET",
            &format!("/v1/keys/users/{user}"),
            Value::Null,
        )?)?;
        match identity.create_key_package(&store, &recipient, generation) {
            Ok(p) => packages.push(p),
            Err(e) => eprintln!("Pending verification for {user}: {e}"),
        }
    }
    // Persist key-change suspensions even when delivery cannot proceed.
    petika_core::identity::IdentityFile::lock(identity_path)?.save(
        &identity,
        &passphrase,
        false,
    )?;
    if packages.is_empty() {
        println!("No new verified recipients ready for delivery.");
        return Ok(());
    }
    let migration = matches!(command, Command::Migrate { .. });
    let rotation = matches!(command, Command::Rotate { .. });
    packages.sort_by_key(|p| p.recipient_user_id != identity.public_identity().user_id);
    if packages.len() > 100 {
        eprintln!(
            "Delivering the first 100 recipients; run keys deliver again for the remaining members."
        );
        packages.truncate(100);
    }
    let mut body = json!({"expected_snapshot_revision":access["snapshot_revision"],"expected_key_epoch":access["key_epoch"],"expected_membership_generation":generation,"packages":packages});
    if migration || rotation {
        body["encrypted_snapshot"] = String::from_utf8(store.seal()?)?.into();
    }
    let action = if migration {
        "recipient-migration"
    } else if rotation {
        "key-rotation"
    } else {
        "key-packages"
    };
    // A durable ciphertext draft permits reconciliation/retry after a lost response.
    StoreFile::lock(identity_path.with_extension("delivery-draft.json"))?
        .write(&serde_json::to_vec(&body)?, false)?;
    println!(
        "{}",
        client.json("POST", &format!("{prefix}/{action}"), body)?
    );
    Ok(())
}
