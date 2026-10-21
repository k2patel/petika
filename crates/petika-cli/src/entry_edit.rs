//! Encrypted drafts survive conflicts, lost acknowledgements and local failures.
use crate::{
    Result, account,
    entry_sync::{cache_object, read_object, unlock},
};
use clap::Args;
use petika_core::{
    Entry, StoreFile,
    entry_format::{checkpoint_store::CheckpointStore, index::*, transaction::*, transport::*, *},
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct StateArgs {
    #[arg(long, default_value = "personal")]
    pub collection: String,
    #[arg(long)]
    pub anchor: PathBuf,
    #[command(flatten)]
    pub unlock: crate::entry_sync::UnlockArgs,
    #[arg(long)]
    pub pin: PathBuf,
    #[arg(long)]
    pub cache: PathBuf,
}
#[derive(Args)]
pub struct PutArgs {
    #[command(flatten)]
    pub state: StateArgs,
    /// Existing opaque ID; omit to create a new ID.
    #[arg(long)]
    pub id: Option<String>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub folder: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub password_stdin: bool,
    #[arg(long)]
    pub draft: PathBuf,
}
#[derive(Args)]
pub struct DeleteArgs {
    #[command(flatten)]
    pub state: StateArgs,
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub draft: PathBuf,
}
#[derive(Args)]
pub struct SubmitArgs {
    #[command(flatten)]
    pub state: StateArgs,
    #[arg(long)]
    pub draft: PathBuf,
    /// Approve this exact staged edit. Conflicts always retain the draft.
    #[arg(long)]
    pub confirm: bool,
}
#[derive(Args)]
pub struct ReviewArgs {
    #[command(flatten)]
    pub state: StateArgs,
    #[arg(long)]
    pub draft: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    version: u32,
    server: String,
    writer: String,
    transaction: Transaction,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn random_id() -> Result<String> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "random generator failed")?;
    Ok(hex(&bytes))
}
fn load(args: &StateArgs, stdin: bool) -> Result<(CheckpointStore, RootKey, VerifiedIndex)> {
    let anchor = read_object(&args.anchor)?;
    let store = CheckpointStore::lock(&args.pin)?;
    let head = store.head(&anchor.head.context)?;
    let object = read_object(&args.cache.join(format!("{}.json", head.digest()?)))?;
    if object.head != head {
        return Err("Pinned cache mismatch; do not reset trust".into());
    }
    let trusted = store.trusted(&head.context)?;
    let (root, index) = unlock(&args.unlock, &object, &trusted, stdin)?;
    Ok((store, root, index))
}
fn client(
    session: &Path,
    args: &StateArgs,
    context: &Context,
    write: bool,
) -> Result<(account::Client, String)> {
    let client = account::client(session)?;
    if account::collection(&client, &args.collection, write)? != context.collection_id {
        return Err("Selected collection differs from confirmed checkpoint".into());
    }
    let status = client.json("GET", "/v1/auth/status", serde_json::Value::Null)?;
    let writer = status["user"]["id"]
        .as_str()
        .ok_or("Session unavailable")?
        .to_owned();
    if writer.len() != 64
        || !writer
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid account ID in server response".into());
    }
    Ok((client, writer))
}
fn stage(
    file: &StoreFile,
    client: &account::Client,
    writer: String,
    root: &RootKey,
    previous: &VerifiedIndex,
    mut index: Index,
    changes: Vec<EntryChange>,
) -> Result<()> {
    index.revision = previous
        .head()
        .revision
        .checked_add(1)
        .ok_or("revision overflow")?;
    index.parent_digest = previous.head().digest()?;
    let envelope = root.seal(
        &Header {
            entry_format_version: 1,
            suite: SUITE.into(),
            context: root.context().clone(),
            kind: Kind::Index,
            object_id: String::new(),
            revision: index.revision,
        },
        &zeroize::Zeroizing::new(serde_json::to_vec(&index)?),
    )?;
    let object = HistoryObject {
        head: Head {
            version: 1,
            context: root.context().clone(),
            suite: SUITE.into(),
            revision: index.revision,
            parent_digest: index.parent_digest,
            index_digest: hex(&digest(&envelope)),
            wrapper_set_digest: previous.head().wrapper_set_digest.clone(),
            membership_generation: previous.head().membership_generation,
        },
        envelope: String::from_utf8(envelope)?,
    };
    let transaction = Transaction {
        version: 1,
        operation: random_id()?,
        expected: Cursor::from_head(previous.head())?,
        object,
        changes,
    };
    transaction.verify(root, previous)?;
    file.write(
        &serde_json::to_vec(&Draft {
            version: 1,
            server: client.server.clone(),
            writer,
            transaction,
        })?,
        true,
    )?;
    println!(
        "Encrypted draft saved. Review the intended edit, then submit this exact draft with --confirm. Nothing has been submitted."
    );
    Ok(())
}
pub fn put(session: &Path, args: &PutArgs, stdin: bool) -> Result<()> {
    let file = StoreFile::lock(&args.draft)?;
    if file.exists() {
        return Err("Draft exists; choose a new path".into());
    }
    let (_store, root, previous) = load(&args.state, stdin)?;
    let (client, writer) = client(session, &args.state, root.context(), true)?;
    let mut index = previous.index().clone();
    let (id, expected, revision, mut payload) = if let Some(id) = &args.id {
        let entry = index
            .entries
            .iter()
            .find(|e| &e.id == id)
            .ok_or("Entry ID is not live")?;
        let bytes = client.entry_call(&root.context().collection_id, "entry-object", &serde_json::to_vec(&serde_json::json!({"context":root.context(),"root":Cursor::from_head(previous.head())?,"id":id,"digest":entry.digest}))?, 512*1024)?;
        let payload = serde_json::from_slice::<Entry>(&previous.open_entry(&root, id, &bytes)?)?;
        (
            id.clone(),
            Some(EntryVersion {
                revision: entry.revision,
                digest: entry.digest.clone(),
            }),
            entry.revision.checked_add(1).ok_or("revision overflow")?,
            payload,
        )
    } else {
        let id = random_id()?;
        let name = args.name.clone().ok_or("New entries require --name")?;
        index.entries.push(EntryRef {
            id: id.clone(),
            folder: args.folder.clone().unwrap_or_default(),
            name,
            revision: 1,
            digest: String::new(),
        });
        (
            id,
            None,
            1,
            Entry {
                username: String::new(),
                password: String::new(),
                url: String::new(),
                notes: String::new(),
                otp: None,
            },
        )
    };
    let password = crate::secret("Entry password: ", args.password_stdin)?;
    if password.is_empty() {
        return Err("Entry password must not be empty".into());
    }
    payload.password = password.to_string();
    if let Some(username) = &args.username {
        payload.username = username.clone();
    }
    if let Some(url) = &args.url {
        payload.url = url.clone();
    }
    let envelope = root.seal(
        &Header {
            entry_format_version: 1,
            suite: SUITE.into(),
            context: root.context().clone(),
            kind: Kind::Entry,
            object_id: id.clone(),
            revision,
        },
        &zeroize::Zeroizing::new(serde_json::to_vec(&payload)?),
    )?;
    let entry = index
        .entries
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or("Entry not found")?;
    if let Some(name) = &args.name {
        entry.name = name.clone();
    }
    if let Some(folder) = &args.folder {
        entry.folder = folder.clone();
    }
    entry.revision = revision;
    entry.digest = hex(&digest(&envelope));
    stage(
        &file,
        &client,
        writer,
        &root,
        &previous,
        index,
        vec![EntryChange::Put {
            id,
            expected,
            revision,
            envelope: String::from_utf8(envelope)?,
        }],
    )
}

pub fn list(session: &Path, args: &StateArgs, stdin: bool) -> Result<()> {
    let (_store, root, view) = load(args, stdin)?;
    client(session, args, root.context(), false)?;
    for entry in &view.index().entries {
        println!("{}\t{}", entry.id, entry.name);
    }
    Ok(())
}
pub fn review(session: &Path, args: &ReviewArgs, stdin: bool) -> Result<()> {
    let draft: Draft = serde_json::from_slice(&StoreFile::lock(&args.draft)?.read()?)?;
    let (_store, root, _current) = load(&args.state, stdin)?;
    let (client, writer) = client(session, &args.state, root.context(), false)?;
    if draft.version != 1 || draft.server != client.server || draft.writer != writer {
        return Err("Draft server/account mismatch".into());
    }
    let tx = &draft.transaction;
    HistoryRequest {
        version: 1,
        context: root.context().clone(),
        after: tx.expected.clone(),
        target: None,
        limit: 1,
    }
    .validate()?;
    let base = read_object(
        &args
            .state
            .cache
            .join(format!("{}.json", tx.expected.digest)),
    )?;
    let previous = VerifiedIndex::open(&root, base.head, base.envelope.as_bytes())?;
    let next = tx.verify(&root, &previous)?;
    println!(
        "Operation {}: revision {} -> {}",
        tx.operation,
        tx.expected.revision,
        next.head().revision
    );
    for change in &tx.changes {
        match change {
            EntryChange::Put { id, .. } => {
                let entry = next
                    .index()
                    .entries
                    .iter()
                    .find(|e| &e.id == id)
                    .ok_or("Draft entry missing")?;
                println!("Put {}\t{}\tfolder {}", id, entry.name, entry.folder);
            }
            EntryChange::Delete { id, .. } => {
                let entry = previous
                    .index()
                    .entries
                    .iter()
                    .find(|e| &e.id == id)
                    .ok_or("Draft entry missing")?;
                println!("Delete {}\t{}", id, entry.name);
            }
        }
    }
    println!("Passwords remain hidden. This command does not submit the draft.");
    Ok(())
}
pub fn delete(session: &Path, args: &DeleteArgs, stdin: bool) -> Result<()> {
    let file = StoreFile::lock(&args.draft)?;
    if file.exists() {
        return Err("Draft exists; choose a new path".into());
    }
    let (_store, root, previous) = load(&args.state, stdin)?;
    let (client, writer) = client(session, &args.state, root.context(), true)?;
    let mut index = previous.index().clone();
    let entry = index
        .entries
        .iter()
        .find(|e| e.id == args.id)
        .cloned()
        .ok_or("Entry ID is not live")?;
    index.entries.retain(|e| e.id != args.id);
    index.tombstones.push(Tombstone {
        id: args.id.clone(),
        final_revision: entry.revision.checked_add(1).ok_or("revision overflow")?,
        deletion_revision: previous
            .head()
            .revision
            .checked_add(1)
            .ok_or("revision overflow")?,
        prior_digest: entry.digest.clone(),
    });
    stage(
        &file,
        &client,
        writer,
        &root,
        &previous,
        index,
        vec![EntryChange::Delete {
            id: args.id.clone(),
            expected: EntryVersion {
                revision: entry.revision,
                digest: entry.digest,
            },
        }],
    )
}
pub fn submit(session: &Path, args: &SubmitArgs, stdin: bool) -> Result<()> {
    if !args.confirm {
        return Err("Review the staged edit, then supply --confirm. Draft retained.".into());
    }
    let file = StoreFile::lock(&args.draft)?;
    let draft: Draft = serde_json::from_slice(&file.read()?)?;
    let (store, root, current) = load(&args.state, stdin)?;
    let (client, writer) = client(session, &args.state, root.context(), false)?;
    if draft.version != 1 || draft.server != client.server || draft.writer != writer {
        return Err("Draft server/account mismatch; draft retained".into());
    }
    let tx = &draft.transaction;
    HistoryRequest {
        version: 1,
        context: root.context().clone(),
        after: tx.expected.clone(),
        target: None,
        limit: 1,
    }
    .validate()?;
    let base = read_object(
        &args
            .state
            .cache
            .join(format!("{}.json", tx.expected.digest)),
    )?;
    let previous = VerifiedIndex::open(&root, base.head, base.envelope.as_bytes())?;
    let next = tx.verify(&root, &previous)?;
    let pinned = Cursor::from_head(current.head())?;
    let accepted = Cursor::from_head(next.head())?;
    if pinned != tx.expected && pinned != accepted {
        return Err("Local head changed; keep the draft and explicitly reconcile it. No rebase or submission performed.".into());
    }
    let lookup = client.entry_call(
        &root.context().collection_id,
        "entry-receipt",
        &serde_json::to_vec(
            &serde_json::json!({"context":root.context(),"operation":tx.operation}),
        )?,
        4096,
    )?;
    let lookup: ReceiptLookup = serde_json::from_slice(&lookup)?;
    let receipt = if let Some(receipt) = lookup.receipt {
        receipt
    } else {
        if pinned == accepted {
            return Err("Server withheld the expected receipt; draft retained".into());
        }
        account::collection(&client, &args.state.collection, true)?;
        let bytes = client.entry_call(
            &root.context().collection_id,
            "entry-transactions",
            &serde_json::to_vec(tx)?,
            4096,
        )?;
        let response: CommitResponse = serde_json::from_slice(&bytes)?;
        if !matches!(response.replication.as_str(), "unavailable" | "pending") {
            return Err("Unexpected replication acknowledgement; draft retained".into());
        }
        response.receipt
    };
    tx.verify_receipt(&writer, &receipt)?;
    cache_object(&args.state.cache, &tx.object)?;
    if pinned == tx.expected {
        store.observe(&previous, &next)?;
    }
    let receipt_file = StoreFile::lock(args.draft.with_extension("accepted.json"))?;
    let bytes = serde_json::to_vec(&receipt)?;
    if receipt_file.exists() {
        if receipt_file.read()? != bytes {
            return Err("Local receipt mismatch; draft retained".into());
        }
    } else {
        receipt_file.write(&bytes, true)?;
    }
    println!(
        "API acceptance verified at revision {}. Encrypted draft and receipt retained. Remote Git completion is not confirmed.",
        receipt.accepted.revision
    );
    Ok(())
}
