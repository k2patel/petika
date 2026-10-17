mod account;
mod import;
mod keys;

use clap::{Parser, Subcommand, ValueEnum};
use petika_core::{EncryptionMode, Entry, StoreFile, UnlockedStore, generate_password};
use std::{
    io::{self, BufRead, Read},
    path::PathBuf,
    process::ExitCode,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "petika",
    version,
    about = "Petika — experimental encrypted password storage",
    after_help = "Every storage command unlocks locally with a passphrase and locks on exit. Use login for managed API access; collection passphrases never leave this device. Biometrics are not implemented."
)]
struct Cli {
    /// Saved managed session (sensitive bearer credential; defaults to user data directory).
    #[arg(long, global = true)]
    session_file: Option<PathBuf>,
    /// Encrypted recipient identity used for group access.
    #[arg(long, global = true)]
    identity_file: Option<PathBuf>,
    /// Encrypted store file (defaults to the OS user data directory).
    #[arg(long, global = true)]
    store: Option<PathBuf>,
    /// Read passphrases from stdin instead of the terminal. Never pass them as arguments.
    #[arg(long, global = true)]
    passphrase_stdin: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum SetupEncryption {
    Standard,
    HybridPostQuantum,
}
impl From<SetupEncryption> for EncryptionMode {
    fn from(value: SetupEncryption) -> Self {
        match value {
            SetupEncryption::Standard => Self::Standard,
            SetupEncryption::HybridPostQuantum => Self::HybridPostQuantum,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Enroll, verify, deliver, and rotate recipient access.
    Keys {
        #[command(subcommand)]
        command: keys::Command,
    },
    /// Sign in to a managed account by approving a code in your browser.
    Login {
        #[arg(long)]
        server: String,
    },
    /// Revoke the saved CLI session. --local only forgets it when offline.
    Logout {
        #[arg(long)]
        local: bool,
    },
    /// Show the currently authenticated account.
    Whoami,
    /// List accessible personal and group collection IDs and permissions.
    Collections,
    /// Show the remote revision and mirror state.
    Status {
        #[arg(long, default_value = "personal")]
        collection: String,
    },
    /// Download and locally verify an encrypted collection; refuses existing files by default.
    Pull {
        #[arg(long, default_value = "personal")]
        collection: String,
        #[arg(long)]
        replace: bool,
    },
    /// Upload ciphertext using an explicit expected revision (0 for a new collection).
    Push {
        #[arg(long, default_value = "personal")]
        collection: String,
        #[arg(long)]
        revision: u64,
    },
    /// Create a new encrypted store; never overwrite an existing store.
    Init {
        #[arg(long, value_enum, default_value = "standard")]
        encryption: SetupEncryption,
        /// Optional existing GPG password-store directory to import locally.
        #[arg(long)]
        import_gpg: Option<PathBuf>,
        /// GnuPG home to use for import; otherwise use the user's existing GnuPG home.
        #[arg(long, requires = "import_gpg")]
        gpg_home: Option<PathBuf>,
    },
    /// Import GPG entries locally into an existing Petika store, saving only if all succeed.
    ImportGpg {
        source: PathBuf,
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        #[arg(long)]
        replace: bool,
    },
    /// List entry names, optionally filtered by a case-insensitive substring.
    List { query: Option<String> },
    /// Show metadata; use --reveal explicitly to print the password only.
    Get {
        name: String,
        #[arg(long)]
        reveal: bool,
    },
    /// Save an entry, reading its password from a hidden prompt or stdin.
    Put {
        name: String,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long, default_value = "")]
        url: String,
        #[arg(long)]
        replace: bool,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Generate and save a password without printing it.
    Generate {
        name: String,
        #[arg(long, default_value_t = 24)]
        length: usize,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long, default_value = "")]
        url: String,
        #[arg(long)]
        replace: bool,
    },
    /// Delete an entry. Requires explicit --yes.
    Remove {
        name: String,
        #[arg(long, required = true)]
        yes: bool,
    },
    /// Change the local passphrase. Does not revoke copies encrypted with the old one.
    Passphrase,
}

fn secret(prompt: &str, from_stdin: bool) -> Result<Zeroizing<String>> {
    if !from_stdin {
        return Ok(Zeroizing::new(rpassword::prompt_password(prompt)?));
    }
    let mut line = Zeroizing::new(String::new());
    let bytes = io::stdin().lock().take(4098).read_line(&mut line)?;
    if bytes == 0 || line.len() > 4096 {
        return Err("missing or oversized secret on stdin".into());
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

fn new_passphrase(from_stdin: bool) -> Result<Zeroizing<String>> {
    let first = secret("New passphrase (12+ characters): ", from_stdin)?;
    let second = secret("Confirm passphrase: ", from_stdin)?;
    if *first != *second {
        return Err("passphrases do not match".into());
    }
    Ok(first)
}

fn default_store() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let root = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let root = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")));
    let root = root
        .filter(|path| path.is_absolute())
        .ok_or("cannot determine user data directory; use --store")?;
    Ok(root.join("petika/store.petika"))
}

fn run(cli: Cli) -> Result<()> {
    let session = || -> Result<PathBuf> {
        match &cli.session_file {
            Some(path) => Ok(path.clone()),
            None => Ok(default_store()?.with_file_name("session.json")),
        }
    };
    if let Command::Keys { command } = &cli.command {
        let session_path = session()?;
        let identity_path = cli
            .identity_file
            .clone()
            .unwrap_or_else(|| session_path.with_file_name("identity.json"));
        return keys::run(
            &session_path,
            &identity_path,
            cli.store.as_deref(),
            command,
            cli.passphrase_stdin,
        );
    }
    match &cli.command {
        Command::Login { server } => return account::login(&session()?, server),
        Command::Logout { local } => return account::logout(&session()?, *local),
        Command::Whoami => return account::whoami(&session()?),
        Command::Collections => return account::collections(&session()?),
        Command::Status { collection } => return account::status(&session()?, collection),
        _ => {}
    }
    let path = match cli.store.clone() {
        Some(path) => path,
        None => default_store()?,
    };
    match &cli.command {
        Command::Pull {
            collection,
            replace,
        } => {
            return account::pull(
                &session()?,
                collection,
                &path,
                *replace,
                cli.passphrase_stdin,
            );
        }
        Command::Push {
            collection,
            revision,
        } => {
            return account::push(
                &session()?,
                collection,
                &path,
                *revision,
                cli.passphrase_stdin,
            );
        }
        _ => {}
    }
    let file = StoreFile::lock(&path)?;
    if let Command::Init {
        encryption,
        ref import_gpg,
        ref gpg_home,
    } = cli.command
    {
        if file.exists() {
            return Err(petika_core::Error::AlreadyExists.into());
        }
        let passphrase = new_passphrase(cli.passphrase_stdin)?;
        let mut store = UnlockedStore::create_with_mode(&passphrase, encryption.into())?;
        if let Some(source) = import_gpg {
            let count = import::gpg_store(&mut store, source, gpg_home.as_deref(), false)?;
            println!("Imported {count} entries locally.");
        }
        file.save(&mut store, true)?;
        println!("Created encrypted Petika store.");
        return Ok(());
    }
    if !file.exists() {
        return Err("store does not exist; run petika init first".into());
    }
    let mut store = if let Some(identity) = &cli.identity_file {
        keys::open_local(identity, &file.read()?, &path, cli.passphrase_stdin)?
    } else {
        let passphrase = secret("Passphrase: ", cli.passphrase_stdin)?;
        file.open(&passphrase)?
    };
    match cli.command {
        Command::Keys { .. }
        | Command::Init { .. }
        | Command::Login { .. }
        | Command::Logout { .. }
        | Command::Whoami
        | Command::Collections
        | Command::Status { .. }
        | Command::Pull { .. }
        | Command::Push { .. } => unreachable!(),
        Command::ImportGpg {
            source,
            gpg_home,
            replace,
        } => {
            let count = import::gpg_store(&mut store, &source, gpg_home.as_deref(), replace)?;
            file.save(&mut store, false)?;
            println!("Imported {count} entries. Source store unchanged.");
        }
        Command::List { query } => {
            let query = query.unwrap_or_default().to_lowercase();
            for name in store
                .names()
                .filter(|name| name.to_lowercase().contains(&query))
            {
                println!("{name}");
            }
        }
        Command::Get { name, reveal } => {
            let entry = store.get(&name)?;
            if reveal {
                println!("{}", entry.password);
            } else {
                println!(
                    "Name: {name:?}\nUsername: {:?}\nURL: {:?}\nNotes: {:?}",
                    entry.username, entry.url, entry.notes
                );
                println!("Password: hidden (use --reveal to print it)");
            }
        }
        Command::Put {
            name,
            username,
            url,
            replace,
            password_stdin,
        } => {
            let password = secret("Entry password: ", password_stdin)?;
            if password.is_empty() {
                return Err("entry password must not be empty".into());
            }
            // Preserve imported notes when explicitly replacing an entry.
            let notes = store
                .get(&name)
                .map(|e| e.notes.clone())
                .unwrap_or_default();
            store.put(
                name.clone(),
                Entry {
                    otp: store.get(&name).ok().and_then(|e| e.otp.clone()),
                    username,
                    password: password.to_string(),
                    url,
                    notes,
                },
                replace,
            )?;
            file.save(&mut store, false)?;
            println!("Saved entry.");
        }
        Command::Generate {
            name,
            length,
            username,
            url,
            replace,
        } => {
            let password = generate_password(length)?;
            let notes = store
                .get(&name)
                .map(|e| e.notes.clone())
                .unwrap_or_default();
            store.put(
                name.clone(),
                Entry {
                    otp: store.get(&name).ok().and_then(|e| e.otp.clone()),
                    username,
                    password: password.to_string(),
                    url,
                    notes,
                },
                replace,
            )?;
            file.save(&mut store, false)?;
            println!("Generated and saved password. Use get --reveal to print it.");
        }
        Command::Remove { name, yes: _ } => {
            store.remove(&name)?;
            file.save(&mut store, false)?;
            println!("Removed entry.");
        }
        Command::Passphrase => {
            let new = new_passphrase(cli.passphrase_stdin)?;
            store.change_passphrase(&new)?;
            file.save(&mut store, false)?;
            println!("Changed local passphrase. Older copies still require their old passphrase.");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}
