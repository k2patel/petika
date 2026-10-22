//! Offline structural verification of a stopped, restored entry-format server.
use petika_core::StoreFile;
use petika_server::{Result, accounts::Accounts, entry_journal::Journal};
use std::{path::Path, process::ExitCode};
#[path = "entry_recovery/compare.rs"]
mod compare;
fn verify(data: &Path) -> Result<serde_json::Value> {
    if !data.is_dir() || data.is_symlink() || !data.join("accounts.json").is_file() {
        return Err("missing recovery data/account database".into());
    }
    let (deployment, known) = Accounts::new(data.join("accounts.json")).recovery_collections()?;
    let mut result = Vec::new();
    let collections = data.join("collections");
    if collections.is_symlink() {
        return Err("linked collection directory".into());
    }
    if collections.exists() {
        for collection in std::fs::read_dir(collections)? {
            let collection = collection?;
            if !collection.file_type()?.is_dir() {
                return Err("invalid collection directory".into());
            }
            let id = collection
                .file_name()
                .into_string()
                .map_err(|_| "invalid collection ID")?;
            let entries = collection.path().join("entries");
            if entries.is_symlink() {
                return Err("linked entry directory".into());
            }
            if !entries.join("committed-root").exists() {
                continue;
            }
            if !known.contains(&id) {
                return Err("entry collection absent from account database".into());
            }
            let journal = Journal::open(entries)?;
            journal.verify_recovery_source()?;
            let cursor = journal.current().ok_or("missing committed entry root")?;
            let state = journal
                .epoch_state(&cursor)?
                .ok_or("missing entry authority anchor")?;
            if state.checkpoint.context.deployment_id != deployment
                || state.checkpoint.context.collection_id != id
            {
                return Err("restored account/journal context mismatch".into());
            }
            result.push(serde_json::json!({"collection_id":id,"accepted":cursor,
                "checkpoint_digest":state.checkpoint.digest()?,"epoch":state.checkpoint.context.key_epoch}));
        }
    }
    result.sort_by_key(|r| r["collection_id"].as_str().unwrap_or_default().to_owned());
    Ok(
        serde_json::json!({"version":1,"deployment_id":deployment,"collections":result,
        "verification":"structural-only; compare retained client pins and decrypt separately"}),
    )
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 && !(args.len() == 3 && (args[1] == "--expect" || args[1] == "--compare")) {
        eprintln!(
            "Usage: petika-entry-recovery /stopped/restored/data [--expect retained-report.json | --compare retained-report.json]"
        );
        return ExitCode::FAILURE;
    }
    let result = (|| -> Result<(serde_json::Value, bool)> {
        let data = Path::new(&args[0]);
        if !data.is_dir() || data.is_symlink() {
            return Err("missing recovery directory".into());
        }
        // Keep the instance lock through verification and all historical comparisons.
        let _instance = StoreFile::lock(data.join("server-instance"))?;
        let report = verify(data)?;
        if args.len() == 3 {
            let expected: serde_json::Value =
                serde_json::from_slice(&StoreFile::lock(Path::new(&args[2]))?.read()?)?;
            if args[1] == "--compare" {
                return compare::compare(data, report, expected);
            }
            if expected != report {
                return Err("restored entry heads differ from retained recovery report".into());
            }
        }
        Ok((report, true))
    })();
    match result {
        Ok((report, exact)) => {
            println!("{report}");
            if exact {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(_) => {
            eprintln!(
                "Entry recovery verification failed. Preserve the backup and restored files; do not start this server."
            );
            ExitCode::FAILURE
        }
    }
}
