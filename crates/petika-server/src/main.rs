use petika_server::{Repository, Result, Update, mirror_once};
use std::{
    env,
    fs::File,
    io::Read,
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc,
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
    if !bool::from(provided.as_bytes().ct_eq(token.as_bytes())) {
        return respond(request, 401, "{\"error\":\"unauthorized\"}", None);
    }
    if request.method() == &Method::Get && request.url() == "/v1/status" {
        return match repository.read() {
            Ok(snapshot) => respond(
                request,
                200,
                &serde_json::json!({
                    "revision": snapshot.map(|s| s.revision).unwrap_or(0),
                    "mirror_enabled": mirror_enabled,
                    "mirror_revision": mirror_revision.load(Ordering::Acquire),
                    "authentication": "single-account-bearer-token"
                })
                .to_string(),
                None,
            ),
            Err(_) => respond(request, 503, "{\"error\":\"storage unavailable\"}", None),
        };
    }
    if request.url() != "/v1/snapshot" {
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
    let listen = env::var("PETIKA_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let data =
        PathBuf::from(env::var_os("PETIKA_DATA_DIR").unwrap_or_else(|| "./petika-data".into()));
    let repository = Arc::new(Repository::new(data.join("snapshot.json")));
    repository.ready()?;
    let mirror_revision = Arc::new(AtomicU64::new(0));
    let mirror = env::var_os("PETIKA_GIT_MIRROR").map(PathBuf::from);
    let enabled = mirror.is_some();
    if let Some(directory) = mirror {
        let repository = Arc::clone(&repository);
        let mirrored = Arc::clone(&mirror_revision);
        thread::spawn(move || {
            loop {
                match mirror_once(&repository, &directory) {
                    Ok(Some(revision)) => {
                        mirrored.store(revision, Ordering::Release);
                    }
                    Ok(None) => {}
                    Err(_) => eprintln!("Git mirror retry pending; API data is retained."),
                }
                thread::sleep(Duration::from_secs(5));
            }
        });
    }
    let server = Server::http(&listen)?;
    eprintln!(
        "Petika experimental snapshot API listening on {listen}; use TLS termination for remote access."
    );
    for request in server.incoming_requests() {
        handle(request, &repository, &token, &mirror_revision, enabled);
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
