mod account;
mod config;
#[cfg(feature = "experimental-entry-format")]
mod entry_edit;
#[cfg(feature = "experimental-entry-format")]
mod entry_migrate;
#[cfg(feature = "experimental-entry-format")]
mod entry_rotate;
#[cfg(feature = "experimental-entry-format")]
mod entry_sync;
mod import;
mod keys;
mod managed;
mod otp;

use clap::{Parser, Subcommand, ValueEnum};
use petika_core::{EncryptionMode, Entry, StoreFile, UnlockedStore, generate_password};
use std::{
    io::{self, BufRead, IsTerminal, Read, Write},
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
    /// Configuration file (defaults to ~/.petikarc). Command-line options take precedence.
    #[arg(long, global = true, conflicts_with = "no_config")]
    config: Option<PathBuf>,
    /// Ignore ~/.petikarc for an isolated invocation.
    #[arg(long, global = true)]
    no_config: bool,
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
    /// Experimental confirmed checkpoints and bounded encrypted index history.
    #[cfg(feature = "experimental-entry-format")]
    Entries {
        #[command(subcommand)]
        command: Box<entry_sync::Command>,
    },
    /// Enroll, verify, deliver, and rotate recipient access.
    Keys {
        #[command(subcommand)]
        command: keys::Command,
    },
    /// Sign in to a managed account by approving a code in your browser.
    Login {
        #[arg(long)]
        server: Option<String>,
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
    #[command(visible_alias = "ls")]
    List {
        query: Option<String>,
        /// Use this managed API collection instead of the local store.
        #[arg(long)]
        collection: Option<String>,
    },
    /// Show metadata; use --reveal explicitly to print the password only.
    Get {
        name: String,
        /// Use this managed API collection instead of the local store.
        #[arg(long)]
        collection: Option<String>,
        #[arg(long)]
        reveal: bool,
    },
    /// Unlock and print a password; Enter displays TOTP with a live expiry countdown.
    Show {
        name: String,
        /// Fetch a managed collection live through the API, without saving a local copy.
        #[arg(long)]
        collection: Option<String>,
        /// Print the current TOTP and remaining seconds once, without interactive prompts.
        #[arg(long)]
        totp: bool,
    },
    /// Configure or remove a login's encrypted TOTP setup key.
    Otp {
        /// Use this managed API collection instead of the local store.
        #[arg(long, global = true)]
        collection: Option<String>,
        #[command(subcommand)]
        command: OtpCommand,
    },
    /// Save an entry, reading its password from a hidden prompt or stdin.
    #[command(visible_alias = "insert")]
    Put {
        name: String,
        /// Use this managed API collection instead of the local store.
        #[arg(long)]
        collection: Option<String>,
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
        /// Use this managed API collection instead of the local store.
        #[arg(long)]
        collection: Option<String>,
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
    #[command(visible_alias = "rm")]
    Remove {
        name: String,
        /// Use this managed API collection instead of the local store.
        #[arg(long)]
        collection: Option<String>,
        #[arg(long, required = true)]
        yes: bool,
    },
    /// Change the local passphrase. Does not revoke copies encrypted with the old one.
    Passphrase,
}

#[derive(Subcommand)]
enum OtpCommand {
    /// Read a Base32 key or otpauth link from a hidden prompt and store it encrypted.
    Set {
        name: String,
        #[arg(long)]
        secret_stdin: bool,
        /// Allow replacing an existing TOTP configuration.
        #[arg(long)]
        replace: bool,
    },
    /// Remove the stored setup key; this does not disable MFA on the website.
    Remove {
        name: String,
        #[arg(long, required = true)]
        yes: bool,
    },
}

fn now_seconds() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn show_entry(entry: &Entry, include_totp: bool) -> Result<()> {
    // Validate before printing either secret when TOTP was explicitly requested.
    let config = entry.otp.as_deref().map(otp::Config::parse).transpose()?;
    if include_totp && config.is_none() {
        return Err("this entry has no TOTP setup".into());
    }
    println!("Password: {}", entry.password);
    let Some(config) = config else {
        return Ok(());
    };
    if include_totp {
        let code = config.at(now_seconds()?);
        println!(
            "TOTP: {} (expires in {}s)",
            code.value.as_str(),
            code.remaining
        );
        return Ok(());
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "TOTP is configured. Use show --totp to print the code and remaining seconds once."
        );
        return Ok(());
    }
    loop {
        eprint!("Press Enter for a verification code, or type q then Enter to finish: ");
        io::stderr().flush()?;
        let mut answer = Zeroizing::new(String::new());
        if io::stdin().lock().take(4098).read_line(&mut answer)? == 0 || !answer.trim().is_empty() {
            return Ok(());
        }
        let started = now_seconds()?;
        let code = config.at(started);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(code.remaining);
        loop {
            let now = now_seconds()?;
            if now / config.period != started / config.period
                || std::time::Instant::now() >= deadline
            {
                break;
            }
            print!(
                "\rTOTP: {} — expires in {:2}s (Ctrl+C to exit)",
                code.value.as_str(),
                config.period - now % config.period
            );
            io::stdout().flush()?;
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        println!("\rVerification code expired.                                  ");
    }
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

fn run(mut cli: Cli) -> Result<()> {
    let defaults = config::Config::load(cli.config.as_deref(), cli.no_config)?;
    cli.store = cli.store.or(defaults.store);
    cli.session_file = cli.session_file.or(defaults.session_file);
    cli.identity_file = cli.identity_file.or(defaults.identity_file);
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
    #[cfg(feature = "experimental-entry-format")]
    if let Command::Entries { command } = &cli.command {
        return entry_sync::run(&session()?, command, cli.passphrase_stdin);
    }
    match &cli.command {
        Command::Login { server } => {
            let server = server
                .as_deref()
                .or(defaults.server.as_deref())
                .ok_or("provide login --server or set server in ~/.petikarc")?;
            return account::login(&session()?, server);
        }
        Command::Logout { local } => return account::logout(&session()?, *local),
        Command::Whoami => return account::whoami(&session()?),
        Command::Collections => return account::collections(&session()?),
        Command::Status { collection } => return account::status(&session()?, collection),
        _ => {}
    }
    if let Some(selected) = managed::selection(&cli.command) {
        let selected = selected.to_owned();
        return managed::run(
            &session()?,
            cli.identity_file.as_deref(),
            &selected,
            cli.command,
            cli.passphrase_stdin,
        );
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
    operate(cli.command, &mut store, cli.passphrase_stdin, |store| {
        file.save(store, false)?;
        Ok(())
    })
}

fn operate(
    command: Command,
    store: &mut UnlockedStore,
    passphrase_stdin: bool,
    mut save: impl FnMut(&mut UnlockedStore) -> Result<()>,
) -> Result<()> {
    match command {
        #[cfg(feature = "experimental-entry-format")]
        Command::Entries { .. } => unreachable!(),
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
            let count = import::gpg_store(store, &source, gpg_home.as_deref(), replace)?;
            save(store)?;
            println!("Imported {count} entries. Source store unchanged.");
        }
        Command::List { query, .. } => {
            let query = query.unwrap_or_default().to_lowercase();
            for name in store
                .names()
                .filter(|name| name.to_lowercase().contains(&query))
            {
                println!("{name}");
            }
        }
        Command::Get { name, reveal, .. } => {
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
        Command::Show { name, totp, .. } => show_entry(store.get(&name)?, totp)?,
        Command::Otp { command, .. } => {
            let (name, value) = match command {
                OtpCommand::Set {
                    name,
                    secret_stdin,
                    replace,
                } => {
                    let entry = store.get(&name)?;
                    if entry.otp.is_some() && !replace {
                        return Err("TOTP already configured; use --replace explicitly".into());
                    }
                    let value = secret("TOTP setup key or link: ", secret_stdin)?;
                    otp::Config::parse(&value)?;
                    (name, Some(value))
                }
                OtpCommand::Remove { name, yes: _ } => {
                    store.get(&name)?;
                    (name, None)
                }
            };
            let current = store.get(&name)?;
            let entry = Entry {
                username: current.username.clone(),
                password: current.password.clone(),
                url: current.url.clone(),
                notes: current.notes.clone(),
                otp: value.as_deref().map(|v| v.to_string()),
            };
            store.put(name, entry, true)?;
            save(store)?;
            println!("Updated encrypted TOTP setup. Website MFA settings are unchanged.");
        }
        Command::Put {
            name,
            username,
            url,
            replace,
            password_stdin,
            ..
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
            save(store)?;
            println!("Saved entry.");
        }
        Command::Generate {
            name,
            length,
            username,
            url,
            replace,
            ..
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
            save(store)?;
            println!("Generated and saved password.");
        }
        Command::Remove { name, yes: _, .. } => {
            store.remove(&name)?;
            save(store)?;
            println!("Removed entry.");
        }
        Command::Passphrase => {
            let new = new_passphrase(passphrase_stdin)?;
            store.change_passphrase(&new)?;
            save(store)?;
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
