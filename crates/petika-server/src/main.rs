mod web;
use petika_server::{Repository, Result, Update, mirror_once};
use std::{
    env,
    fs::File,
    io::Read,
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Request, Response, Server};
use zeroize::Zeroizing;

const MAX_BODY: u64 = 12 * 1024 * 1024;

fn respond(request: Request, status: u16, body: &str, revision: Option<u64>) {
    let mut response = Response::from_string(body)
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
        .with_header(Header::from_bytes("X-Content-Type-Options", "nosniff").unwrap());
    if let Some(revision) = revision {
        response =
            response.with_header(Header::from_bytes("ETag", format!("\"{revision}\"")).unwrap());
    }
    let _ = request.respond(response);
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

fn handle(
    mut request: Request,
    repository: &Repository,
    token: &str,
    mirror_revision: &AtomicU64,
    mirror_enabled: bool,
    authenticated: bool,
) {
    if request.method() == &Method::Get && request.url() == "/healthz" {
        return respond(request, 200, "{\"status\":\"ok\"}", None);
    }
    if request.method() == &Method::Get && request.url() == "/readyz" {
        return match repository.ready() {
            Ok(()) => respond(request, 200, "{\"status\":\"ready\"}", None),
            Err(_) => respond(request, 503, "{\"error\":\"storage unavailable\"}", None),
        };
    }
    let provided = header(&request, "Authorization")
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if !authenticated && !bool::from(provided.as_bytes().ct_eq(token.as_bytes())) {
        return respond(request, 401, "{\"error\":\"unauthorized\"}", None);
    }
    if request.method() == &Method::Get && request.url().ends_with("/status") {
        return match repository.read() {
            Ok(snapshot) => respond(
                request,
                200,
                &serde_json::json!({
                    "revision": snapshot.map(|s| s.revision).unwrap_or(0),
                    "mirror_enabled": mirror_enabled,
                    "mirror_revision": mirror_revision.load(Ordering::Acquire),
                    "authentication": if authenticated { "managed-account" } else { "single-account-bearer-token" }
                })
                .to_string(),
                None,
            ),
            Err(_) => respond(request, 503, "{\"error\":\"storage unavailable\"}", None),
        };
    }
    if !request.url().ends_with("/snapshot") {
        return respond(request, 404, "{\"error\":\"not found\"}", None);
    }
    if request.method() == &Method::Get {
        return match repository.read() {
            Ok(Some(snapshot)) => {
                respond(request, 200, &snapshot.encrypted, Some(snapshot.revision))
            }
            Ok(None) => respond(request, 404, "{\"error\":\"no snapshot\"}", Some(0)),
            Err(_) => respond(request, 503, "{\"error\":\"storage unavailable\"}", None),
        };
    }
    if request.method() != &Method::Put {
        return respond(request, 405, "{\"error\":\"method not allowed\"}", None);
    }
    let expected = header(&request, "If-Match")
        .and_then(|s| s.strip_prefix('"'))
        .and_then(|s| s.strip_suffix('"'))
        .and_then(|s| s.parse::<u64>().ok());
    let Some(expected) = expected else {
        return respond(
            request,
            428,
            "{\"error\":\"quoted revision required in If-Match\"}",
            None,
        );
    };
    if header(&request, "Content-Type") != Some("application/json") {
        return respond(
            request,
            415,
            "{\"error\":\"application/json required\"}",
            None,
        );
    }
    if request
        .body_length()
        .is_some_and(|len| len as u64 > MAX_BODY)
    {
        return respond(request, 413, "{\"error\":\"snapshot too large\"}", None);
    }
    let mut body = String::new();
    if request
        .as_reader()
        .take(MAX_BODY + 1)
        .read_to_string(&mut body)
        .is_err()
    {
        return respond(request, 400, "{\"error\":\"invalid body\"}", None);
    }
    if body.len() as u64 > MAX_BODY {
        return respond(request, 413, "{\"error\":\"snapshot too large\"}", None);
    }
    if petika_core::validate_envelope(body.as_bytes()).is_err() {
        return respond(
            request,
            400,
            "{\"error\":\"invalid encrypted snapshot\"}",
            None,
        );
    }
    match repository.update(expected, body) {
        Ok(Update::Saved(revision)) => {
            respond(request, 200, "{\"status\":\"saved\"}", Some(revision))
        }
        Ok(Update::Conflict(revision)) => respond(
            request,
            409,
            "{\"error\":\"revision conflict\"}",
            Some(revision),
        ),
        Err(_) => respond(request, 503, "{\"error\":\"storage unavailable\"}", None),
    }
}

fn run() -> Result<()> {
    let token_file = env::var("PETIKA_TOKEN_FILE").map_err(|_| "PETIKA_TOKEN_FILE is required")?;
    let mut token = Zeroizing::new(String::new());
    File::open(token_file)?
        .take(258)
        .read_to_string(&mut token)?;
    let token = Zeroizing::new(token.trim().to_owned());
    if !(32..=256).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("token must contain 32–256 ASCII letters/digits; generate it randomly".into());
    }
    let endpoint = web::public_endpoint(&env::var("PETIKA_ENDPOINT").unwrap_or_default())?;
    let listen = env::var("PETIKA_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let data =
        PathBuf::from(env::var_os("PETIKA_DATA_DIR").unwrap_or_else(|| "./petika-data".into()));
    let _instance = petika_core::StoreFile::lock(data.join("server-instance"))?;
    let repository = Arc::new(Repository::new(data.join("snapshot.json")));
    repository.ready()?;
    let mirror_revision = Arc::new(AtomicU64::new(0));
    let mirror = env::var_os("PETIKA_GIT_MIRROR").map(PathBuf::from);
    let enabled = mirror.is_some();
    let backup_gate = Arc::new(Mutex::new(()));
    if let Some(directory) = mirror.clone() {
        let repository = Arc::clone(&repository);
        let mirrored = Arc::clone(&mirror_revision);
        let collection_root = data.join("collections");
        let gate = Arc::clone(&backup_gate);
        thread::spawn(move || {
            loop {
                let Ok(guard) = gate.lock() else {
                    return;
                };
                match mirror_once(&repository, &directory) {
                    Ok(Some(revision)) => {
                        mirrored.store(revision, Ordering::Release);
                    }
                    Ok(None) => {}
                    Err(_) => eprintln!("Git mirror retry pending; API data is retained."),
                }
                if let Ok(entries) = std::fs::read_dir(&collection_root) {
                    for entry in entries.flatten() {
                        let id = entry.file_name().to_string_lossy().into_owned();
                        if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                            let collection = Repository::new(entry.path().join("snapshot.json"));
                            let _ = mirror_once(&collection, &directory.join(&id));
                        }
                    }
                }
                drop(guard);
                thread::sleep(Duration::from_secs(5));
            }
        });
    }
    let mut accounts = petika_server::accounts::Accounts::new(data.join("accounts.json"));
    accounts.migrate()?;
    let setup_mode = env::var("PETIKA_SETUP_MODE").unwrap_or_else(|_| "auto".into());
    if !matches!(setup_mode.as_str(), "auto" | "manual" | "disabled") {
        return Err("PETIKA_SETUP_MODE must be auto, manual, or disabled".into());
    }
    if !accounts.initialized()? {
        if setup_mode == "disabled" {
            return Err("Setup is disabled but no administrator exists".into());
        }
        let username = env::var("PETIKA_ADMIN_USERNAME").ok();
        let password_env = env::var("PETIKA_ADMIN_PASSWORD").ok().map(Zeroizing::new);
        let password_file = env::var("PETIKA_ADMIN_PASSWORD_FILE").ok();
        if setup_mode == "auto"
            && (username.is_some()
                || password_env.is_some()
                || password_file.is_some()
                || env::var_os("PETIKA_INITIAL_SNAPSHOT_FILE").is_some())
        {
            if password_env.is_some() && password_file.is_some() {
                return Err("Set only one administrator password source".into());
            }
            let password = if let Some(path) = password_file {
                let mut value = Zeroizing::new(String::new());
                File::open(path)?.take(4097).read_to_string(&mut value)?;
                if value.len() > 4096 {
                    return Err("Administrator password file too large".into());
                }
                Zeroizing::new(value.trim_end_matches(['\r', '\n']).to_owned())
            } else {
                password_env
                    .ok_or("Complete PETIKA_ADMIN_PASSWORD or PETIKA_ADMIN_PASSWORD_FILE")?
            };
            if let Some(path) = env::var_os("PETIKA_INITIAL_SNAPSHOT_FILE") {
                let mut encrypted = String::new();
                File::open(path)?
                    .take(MAX_BODY + 1)
                    .read_to_string(&mut encrypted)?;
                if encrypted.len() as u64 > MAX_BODY {
                    return Err("Initial snapshot too large".into());
                }
                accounts.initial_snapshot(encrypted)?;
            }
            accounts.create_user(
                &username.ok_or("Complete PETIKA_ADMIN_USERNAME")?,
                &env::var("PETIKA_ADMIN_NAME").unwrap_or_else(|_| "Administrator".into()),
                password.to_string(),
                true,
                true,
            )?;
        }
    }
    let web_root =
        PathBuf::from(env::var_os("PETIKA_WEB_DIR").unwrap_or_else(|| "clients/web".into()));
    let secure_cookie = env::var("PETIKA_COOKIE_SECURE").as_deref() != Ok("false");
    let server = Server::http(&listen)?;
    eprintln!(
        "Petika experimental snapshot API listening on {listen}; use TLS termination for remote access."
    );
    petika_server::accounts::Accounts::start_backup_worker(
        data.clone(),
        mirror.clone(),
        Arc::clone(&backup_gate),
    );
    for request in server.incoming_requests() {
        let path = request.url().to_owned();
        if path == "/healthz" && request.method() == &Method::Get {
            respond(request, 200, "{\"status\":\"ok\"}", None);
            continue;
        }
        let _backup_guard = match backup_gate.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                respond(
                    request,
                    503,
                    "{\"error\":\"Backup capture in progress; retry shortly\"}",
                    None,
                );
                continue;
            }
            Err(_) => return Err("Backup gate unavailable".into()),
        };
        if !path.starts_with("/v1/") && path != "/healthz" && path != "/readyz" {
            web::static_file(request, &web_root, &endpoint);
        } else if path.starts_with("/v1/backup/") || path.starts_with("/v1/backup-settings/") {
            web::backup_route(request, &mut accounts);
        } else if path.starts_with("/v1/keys/") {
            web::key_route(request, &mut accounts);
        } else if path.starts_with("/v1/auth/")
            || path.starts_with("/v1/admin/")
            || path == "/v1/profile"
            || path == "/v1/appearance"
            || path == "/v1/collections"
        {
            web::account_route(request, &mut accounts, &token, secure_cookie);
        } else if let Some(rest) = path.strip_prefix("/v1/collections/") {
            let Some((id, action)) = rest.split_once('/') else {
                web::json(request, 404, serde_json::json!({"error":"Not found"}), None);
                continue;
            };
            let action = action.split('?').next().unwrap_or(action);
            // Recognize active entry collections even in default builds. Legacy
            // snapshot and delivery routes must never create a second authority.
            if action != "status"
                && !action.starts_with("entry-")
                && data
                    .join("collections")
                    .join(id)
                    .join("entries/committed-root")
                    .is_file()
            {
                let allowed = accounts
                    .authenticate(&web::session(&request))
                    .ok()
                    .flatten()
                    .is_some_and(|u| accounts.access(&u, id, false).unwrap_or(false));
                if allowed {
                    respond(
                        request,
                        426,
                        "{\"error\":\"Collection uses entry-v1; upgrade client\"}",
                        None,
                    );
                } else {
                    respond(
                        request,
                        403,
                        "{\"error\":\"Collection access denied\"}",
                        None,
                    );
                }
                continue;
            }
            #[cfg(feature = "experimental-entry-format")]
            if matches!(
                action,
                "entry-history" | "entry-object" | "entry-receipt" | "entry-transactions"
            ) {
                let mut request = request;
                if env::var("PETIKA_EXPERIMENTAL_ENTRIES").as_deref() != Ok("1") {
                    respond(
                        request,
                        404,
                        "{\"error\":\"Experimental entry API disabled\"}",
                        None,
                    );
                    continue;
                }
                if request.method() != &Method::Post || !web::csrf(&request) {
                    respond(request, 403, "{\"error\":\"Entry request denied\"}", None);
                    continue;
                }
                let session = web::session(&request);
                if accounts
                    .with_entry_access(&session, id, action == "entry-transactions", |_| Ok(()))
                    .is_err()
                {
                    respond(
                        request,
                        403,
                        "{\"error\":\"Collection access denied\"}",
                        None,
                    );
                    continue;
                }
                let result = petika_server::entry_api::dispatch(
                    &mut accounts,
                    &data,
                    &session,
                    id,
                    action,
                    request.as_reader(),
                );
                match result {
                    Ok(bytes) => respond(
                        request,
                        200,
                        std::str::from_utf8(&bytes).unwrap_or("{}"),
                        None,
                    ),
                    Err(_) => respond(
                        request,
                        409,
                        "{\"error\":\"Entry request unavailable or rejected; preserve draft and reconcile\"}",
                        None,
                    ),
                }
                continue;
            }
            if matches!(
                action,
                "key-access"
                    | "key-packages"
                    | "recipient-migration"
                    | "key-rotation"
                    | "recipient-snapshot"
            ) {
                web::delivery_route(request, &mut accounts, id, action);
                continue;
            }
            let write = request.method() != &Method::Get;
            let user = accounts
                .authenticate(&web::session(&request))
                .ok()
                .flatten();
            let allowed = user
                .as_ref()
                .is_some_and(|u| accounts.access(u, id, write).unwrap_or(false));
            if !allowed
                || (write && !web::csrf(&request))
                || !matches!(action, "snapshot" | "status")
            {
                web::json(
                    request,
                    403,
                    serde_json::json!({"error":"Collection access denied"}),
                    None,
                );
                continue;
            }
            let collection =
                Repository::new(data.join("collections").join(id).join("snapshot.json"));
            if data
                .join("collections")
                .join(id)
                .join("entries/committed-root")
                .is_file()
            {
                if action == "status" {
                    respond(request, 200, &serde_json::json!({
                        "format": "entry-v1",
                        "experimental": true,
                        "entry_api_enabled": cfg!(feature = "experimental-entry-format") && env::var("PETIKA_EXPERIMENTAL_ENTRIES").as_deref() == Ok("1"),
                        "capabilities": ["bounded-history", "exact-root-entry-read", "writer-scoped-receipts", "same-epoch-transactions"],
                        "migration": "unavailable",
                        "replication": "unavailable"
                    }).to_string(), None);
                    continue;
                }
                respond(
                    request,
                    426,
                    "{\"error\":\"Collection uses experimental entry format; upgrade client\",\"format\":\"entry-v1\"}",
                    None,
                );
                continue;
            }
            let mirrored = if let Some(root) = &mirror {
                mirror_once(&collection, &root.join(id))
                    .ok()
                    .flatten()
                    .unwrap_or(0)
            } else {
                0
            };
            handle(
                request,
                &collection,
                &token,
                &AtomicU64::new(mirrored),
                enabled,
                true,
            );
        } else {
            handle(
                request,
                &repository,
                &token,
                &mirror_revision,
                enabled,
                false,
            );
        }
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Server startup failed: {err}");
            ExitCode::FAILURE
        }
    }
}
