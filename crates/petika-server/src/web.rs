use petika_server::{
    Result,
    accounts::{Accounts, Membership},
};
use std::{io::Read, path::Path};
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Request, Response};

pub fn json(request: Request, status: u16, value: serde_json::Value, cookie: Option<String>) {
    let mut response = Response::from_string(value.to_string())
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
        .with_header(Header::from_bytes("X-Content-Type-Options", "nosniff").unwrap());
    if let Some(cookie) = cookie {
        response = response.with_header(Header::from_bytes("Set-Cookie", cookie).unwrap());
    }
    let _ = request.respond(response);
}
pub fn session(request: &Request) -> String {
    if let Some(token) =
        super::header(request, "Authorization").and_then(|s| s.strip_prefix("Bearer cli_"))
    {
        return format!("cli_{token}");
    }
    super::header(request, "Cookie")
        .unwrap_or("")
        .split(';')
        .filter_map(|v| v.trim().split_once('='))
        .find(|(name, _)| *name == "petika_session")
        .map(|(_, value)| value.to_owned())
        .unwrap_or_default()
}
pub fn csrf(request: &Request) -> bool {
    // Browsers cannot set this header cross-origin without a successful preflight.
    // The API never grants CORS. Also reject explicit cross-site Fetch Metadata.
    super::header(request, "X-Petika-Request") == Some("1")
        && super::header(request, "Sec-Fetch-Site") != Some("cross-site")
        && super::header(request, "Content-Type") == Some("application/json")
}
fn cookie(token: &str, secure: bool) -> String {
    format!(
        "petika_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        if token.is_empty() { 0 } else { 28800 },
        if secure { "; Secure" } else { "" }
    )
}
fn body(request: &mut Request) -> Result<serde_json::Value> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    request.as_reader().take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("Request too large".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn text<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}

pub fn account_route(
    mut request: Request,
    accounts: &mut Accounts,
    bootstrap_token: &str,
    secure: bool,
) {
    let path = request.url().to_owned();
    let method = request.method().clone();
    if method != Method::Get && !csrf(&request) {
        return json(
            request,
            403,
            serde_json::json!({"error":"Same-origin JSON request required"}),
            None,
        );
    }
    let token = session(&request);
    let user = match accounts.authenticate(&token) {
        Ok(user) => user,
        Err(_) => {
            return json(
                request,
                503,
                serde_json::json!({"error":"Account storage unavailable"}),
                None,
            );
        }
    };
    if path == "/v1/auth/status" && method == Method::Get {
        return match accounts.initialized() {
            Ok(initialized) => json(
                request,
                200,
                serde_json::json!({"initialized":initialized,"user":user.map(|u| u.public())}),
                None,
            ),
            Err(_) => json(
                request,
                503,
                serde_json::json!({"error":"Account storage unavailable"}),
                None,
            ),
        };
    }
    if path == "/v1/auth/logout" && method == Method::Post {
        accounts.logout(&token);
        return json(
            request,
            200,
            serde_json::json!({"ok":true}),
            Some(cookie("", secure)),
        );
    }
    if path.starts_with("/v1/admin/") && !user.as_ref().is_some_and(|u| u.admin) {
        return json(
            request,
            403,
            serde_json::json!({"error":"Administrator access required"}),
            None,
        );
    }
    let payload = if method == Method::Get {
        serde_json::Value::Null
    } else {
        match body(&mut request) {
            Ok(body) => body,
            Err(_) => {
                return json(
                    request,
                    400,
                    serde_json::json!({"error":"Invalid request"}),
                    None,
                );
            }
        }
    };
    let result: Result<serde_json::Value> = (|| {
        if method == Method::Post {
            match path.as_str() {
                "/v1/auth/device/start" => return accounts.device_start(),
                "/v1/auth/device/poll" => {
                    return accounts.device_poll(text(&payload, "device_code"));
                }
                "/v1/auth/device/approve" => {
                    accounts.device_approve(
                        &token,
                        text(&payload, "user_code"),
                        text(&payload, "password").into(),
                        payload["approve"]
                            .as_bool()
                            .ok_or("Choose approve or deny")?,
                    )?;
                    return Ok(serde_json::json!({"ok":true}));
                }
                _ => {}
            }
        }
        if path == "/v1/auth/bootstrap" && method == Method::Post {
            if !bool::from(
                text(&payload, "token")
                    .as_bytes()
                    .ct_eq(bootstrap_token.as_bytes()),
            ) {
                return Err("Invalid setup token".into());
            }
            let user = accounts.create_user(
                text(&payload, "username"),
                text(&payload, "name"),
                text(&payload, "password").into(),
                true,
                true,
            )?;
            return Ok(user.public());
        }
        if path == "/v1/auth/login" && method == Method::Post {
            return Ok(serde_json::Value::Null);
        }
        let user = user.as_ref().ok_or("Sign in to continue")?;
        match (method.as_str(), path.as_str()) {
            ("GET", "/v1/collections") => Ok(serde_json::json!(accounts.collections(user)?)),
            ("POST", "/v1/auth/password") => {
                accounts.change_password(
                    user,
                    text(&payload, "current").into(),
                    text(&payload, "replacement").into(),
                    &token,
                )?;
                Ok(serde_json::json!({"ok":true}))
            }
            ("POST", "/v1/profile") => Ok(accounts.profile(user, text(&payload, "name"))?.public()),
            ("GET", "/v1/admin/users") if user.admin => Ok(serde_json::json!(accounts.users()?)),
            ("GET", "/v1/admin/groups") if user.admin => Ok(serde_json::json!(accounts.groups()?)),
            ("POST", "/v1/admin/users") if user.admin => Ok(accounts
                .create_user(
                    text(&payload, "username"),
                    text(&payload, "name"),
                    text(&payload, "password").into(),
                    payload["admin"].as_bool().unwrap_or(false),
                    false,
                )?
                .public()),
            ("POST", "/v1/admin/user-status") if user.admin => {
                accounts.set_disabled(
                    user,
                    text(&payload, "id"),
                    payload["disabled"].as_bool().ok_or("Invalid status")?,
                )?;
                Ok(serde_json::json!({"ok":true}))
            }
            ("POST", "/v1/admin/groups") if user.admin => {
                let members: Vec<Membership> = serde_json::from_value(payload["members"].clone())?;
                Ok(serde_json::to_value(accounts.save_group(
                    payload["id"].as_str(),
                    text(&payload, "name"),
                    members,
                )?)?)
            }
            _ => Err("Not authorized or endpoint unavailable".into()),
        }
    })();
    if path == "/v1/auth/login" && method == Method::Post {
        return match accounts.login(
            text(&payload, "username"),
            text(&payload, "password").into(),
        ) {
            Ok((token, user)) => json(request, 200, user.public(), Some(cookie(&token, secure))),
            Err(err) => json(
                request,
                401,
                serde_json::json!({"error":err.to_string()}),
                None,
            ),
        };
    }
    match result {
        Ok(value) => json(request, 200, value, None),
        Err(err) => json(
            request,
            if user.is_none() { 401 } else { 400 },
            serde_json::json!({"error":err.to_string()}),
            None,
        ),
    }
}

pub fn static_file(request: Request, root: &Path) {
    let (file, mime) = match request.url().split('?').next().unwrap_or("") {
        "/" => ("index.html", "text/html; charset=utf-8"),
        "/app.css" => ("app.css", "text/css"),
        "/app.js" => ("app.js", "text/javascript"),
        "/worker.js" => ("worker.js", "text/javascript"),
        "/otp.js" => ("otp.js", "text/javascript"),
        "/theme.js" => ("theme.js", "text/javascript"),
        "/brand.png" => ("brand.png", "image/png"),
        "/brand-dark.png" => ("brand-dark.png", "image/png"),
        "/wasm/petika_web.js" => ("wasm/petika_web.js", "text/javascript"),
        "/wasm/petika_web_bg.wasm" => ("wasm/petika_web_bg.wasm", "application/wasm"),
        _ => return json(request, 404, serde_json::json!({"error":"Not found"}), None),
    };
    if request.method() != &Method::Get {
        return json(
            request,
            405,
            serde_json::json!({"error":"Method not allowed"}),
            None,
        );
    }
    let Ok(bytes) = std::fs::read(root.join(file)) else {
        return json(
            request,
            404,
            serde_json::json!({"error":"Web assets missing; run scripts/build_web.sh"}),
            None,
        );
    };
    let mut response = Response::from_data(bytes);
    for (name, value) in [
        ("Content-Type", mime),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Frame-Options", "DENY"),
        (
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
        (
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        ),
    ] {
        response = response.with_header(Header::from_bytes(name, value).unwrap());
    }
    let _ = request.respond(response);
}

/// Separate strict contracts for identity endpoints; legacy account response shapes
/// are unchanged. No plaintext identity key or unlock passphrase is accepted here.
pub fn key_route(mut request: Request, accounts: &mut Accounts) {
    use petika_server::accounts::{KeyError, KeyOperation};
    let fail =
        |request: Request, error: KeyError| json(request, error.status(), error.body(), None);
    let token = if super::header(&request, "Authorization")
        .is_some_and(|h| !h.starts_with("Bearer cli_"))
    {
        String::new()
    } else {
        session(&request)
    };
    match accounts.authenticate(&token) {
        Ok(Some(_)) => {}
        Ok(None) => return fail(request, KeyError::Unauthenticated),
        Err(_) => return fail(request, KeyError::Unavailable),
    }
    let path = request.url();
    let method = request.method().as_str();
    let (operation, status) = match (path, method) {
        ("/v1/keys/deployment", "GET") => (KeyOperation::Deployment, 200),
        ("/v1/keys/identity", "GET") => (KeyOperation::Own, 200),
        ("/v1/keys/identity", "POST") => (KeyOperation::Enroll, 201),
        ("/v1/keys/identity/bundle", "PUT") => (KeyOperation::UpdateBundle, 200),
        ("/v1/keys/identity/replace", "POST") => (KeyOperation::Replace, 200),
        (path, "GET") if path.starts_with("/v1/keys/users/") => (
            KeyOperation::Lookup(path.trim_start_matches("/v1/keys/users/").into()),
            200,
        ),
        (
            "/v1/keys/deployment"
            | "/v1/keys/identity"
            | "/v1/keys/identity/bundle"
            | "/v1/keys/identity/replace",
            _,
        ) => return fail(request, KeyError::MethodNotAllowed),
        (path, _) if path.starts_with("/v1/keys/users/") => {
            return fail(request, KeyError::MethodNotAllowed);
        }
        _ => return fail(request, KeyError::NotFound),
    };
    let mut body = zeroize::Zeroizing::new(Vec::new());
    if request.method() != &Method::Get {
        if super::header(&request, "Content-Type") != Some("application/json") {
            return fail(request, KeyError::UnsupportedMediaType);
        }
        if !csrf(&request) {
            return fail(request, KeyError::Forbidden);
        }
        if request.body_length().is_some_and(|len| len > 128 * 1024) {
            return fail(request, KeyError::TooLarge);
        }
        if request
            .as_reader()
            .take(128 * 1024 + 1)
            .read_to_end(&mut body)
            .is_err()
        {
            return fail(request, KeyError::Invalid);
        }
        if body.len() > 128 * 1024 {
            return fail(request, KeyError::TooLarge);
        }
    }
    match accounts.key_operation(&token, operation, &body) {
        Ok(value) => json(request, status, value, None),
        Err(error) => fail(request, error),
    }
}

pub fn delivery_route(
    mut request: Request,
    accounts: &mut Accounts,
    collection: &str,
    action: &str,
) {
    use petika_server::accounts::{DeliveryOperation, KeyError};
    let fail =
        |request: Request, error: KeyError| json(request, error.status(), error.body(), None);
    let token = if super::header(&request, "Authorization")
        .is_some_and(|h| !h.starts_with("Bearer cli_"))
    {
        String::new()
    } else {
        session(&request)
    };
    match accounts.authenticate(&token) {
        Ok(Some(_)) => {}
        Ok(None) => return fail(request, KeyError::Unauthenticated),
        Err(_) => return fail(request, KeyError::Unavailable),
    }
    if action == "key-packages" && request.url().contains('?') {
        return fail(request, KeyError::Conflict);
    }
    let operation = match (action, request.method().as_str()) {
        ("key-access", "GET") => match request.url().split_once('?') {
            None => DeliveryOperation::Access,
            Some((_, query)) => match query.strip_prefix("cursor=") {
                Some(cursor) if cursor.len() <= 512 => DeliveryOperation::AccessPage(cursor.into()),
                _ => return fail(request, KeyError::Invalid),
            },
        },
        ("key-packages", "GET") => DeliveryOperation::Packages,
        ("key-packages", "POST") => DeliveryOperation::Publish,
        ("recipient-migration", "POST") => DeliveryOperation::Migrate,
        ("key-rotation", "POST") => DeliveryOperation::Rotate,
        ("recipient-snapshot", "POST") => DeliveryOperation::Snapshot,
        _ => return fail(request, KeyError::MethodNotAllowed),
    };
    let mut body = Vec::new();
    if request.method() != &Method::Get {
        if super::header(&request, "Content-Type") != Some("application/json") {
            return fail(request, KeyError::UnsupportedMediaType);
        }
        if !csrf(&request) {
            return fail(request, KeyError::Forbidden);
        }
        let limit = if action == "key-packages" {
            2 * 1024 * 1024
        } else {
            20 * 1024 * 1024
        };
        if request.body_length().is_some_and(|len| len > limit) {
            return fail(request, KeyError::TooLarge);
        }
        if request
            .as_reader()
            .take(limit as u64 + 1)
            .read_to_end(&mut body)
            .is_err()
        {
            return fail(request, KeyError::Invalid);
        }
        if body.len() > limit {
            return fail(request, KeyError::TooLarge);
        }
    }
    match accounts.delivery_operation(&token, collection, operation, &body) {
        Ok(value) => json(request, 200, value, None),
        Err(error) => fail(request, error),
    }
}

#[cfg(test)]
mod key_http_tests {
    use super::*;
    use serde_json::{Value, json};
    use std::{
        io::{Read, Write},
        net::TcpStream,
    };
    fn exchange(
        accounts: &mut Accounts,
        method: &str,
        path: &str,
        headers: &str,
        body: &str,
    ) -> (u16, Value) {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let address = server.server_addr().to_ip().unwrap();
        let wire = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        );
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            stream.write_all(wire.as_bytes()).unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        });
        key_route(server.recv().unwrap(), accounts);
        let response = client.join().unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.to_lowercase().contains("cache-control: no-store"));
        (
            head.split_whitespace().nth(1).unwrap().parse().unwrap(),
            serde_json::from_str(body).unwrap(),
        )
    }
    #[test]
    fn identity_http_routes_enforce_auth_headers_and_revisions() {
        let dir = tempfile::tempdir().unwrap();
        let mut accounts = Accounts::new(dir.path().join("accounts.json"));
        let password = "synthetic account password";
        let user = accounts
            .create_user("owner", "Owner", password.into(), true, true)
            .unwrap();
        let (token, _) = accounts.login("owner", password.into()).unwrap();
        let headers = format!(
            "Cookie: petika_session={token}\r\nContent-Type: application/json\r\nX-Petika-Request: 1\r\n"
        );
        assert_eq!(
            exchange(&mut accounts, "GET", "/v1/keys/identity", "", "").0,
            401
        );
        let static_headers = format!("{headers}Authorization: Bearer legacy-token\r\n");
        assert_eq!(
            exchange(
                &mut accounts,
                "GET",
                "/v1/keys/identity",
                &static_headers,
                ""
            )
            .0,
            401
        );
        let (status, deployment) =
            exchange(&mut accounts, "GET", "/v1/keys/deployment", &headers, "");
        assert_eq!(status, 200);
        assert_eq!(
            exchange(&mut accounts, "GET", "/v1/keys/identity", &headers, "").0,
            404
        );
        assert_eq!(
            exchange(&mut accounts, "DELETE", "/v1/keys/identity", &headers, "").0,
            405
        );
        assert_eq!(
            exchange(
                &mut accounts,
                "POST",
                "/v1/keys/identity",
                &format!("Cookie: petika_session={token}\r\n"),
                "{}"
            )
            .0,
            415
        );
        assert_eq!(
            exchange(
                &mut accounts,
                "POST",
                "/v1/keys/identity",
                &format!("Cookie: petika_session={token}\r\nContent-Type: application/json\r\n"),
                "{}"
            )
            .0,
            403
        );
        assert_eq!(
            exchange(&mut accounts, "POST", "/v1/keys/identity", &headers, "{").0,
            400
        );
        let grant = accounts.device_start().unwrap();
        accounts
            .device_approve(
                &token,
                grant["user_code"].as_str().unwrap(),
                password.into(),
                true,
            )
            .unwrap();
        let approved = accounts
            .device_poll(grant["device_code"].as_str().unwrap())
            .unwrap();
        let cli_headers = format!(
            "Authorization: Bearer {}\r\n",
            approved["token"].as_str().unwrap()
        );
        assert_eq!(
            exchange(
                &mut accounts,
                "GET",
                "/v1/keys/deployment",
                &cli_headers,
                ""
            )
            .0,
            200
        );
        let identity = petika_core::identity::UnlockedIdentity::generate(
            deployment["deployment_id"].as_str().unwrap(),
            &user.id,
            1,
        )
        .unwrap();
        let sealed: Value =
            serde_json::from_slice(&identity.seal("synthetic unlock password").unwrap()).unwrap();
        let enrollment = json!({"expected_bundle_revision":0,"current_password":password,"public_identity":sealed["public_identity"],"encrypted_bundle":sealed["encrypted_bundle"]});
        let (status, state) = exchange(
            &mut accounts,
            "POST",
            "/v1/keys/identity",
            &headers,
            &enrollment.to_string(),
        );
        assert_eq!(status, 201);
        assert_eq!(state["bundle_revision"], 1);
        assert_eq!(
            exchange(&mut accounts, "GET", "/v1/keys/identity", &headers, "").1,
            state
        );
        assert_eq!(
            exchange(
                &mut accounts,
                "GET",
                &format!("/v1/keys/users/{}", user.id),
                &headers,
                ""
            )
            .1,
            sealed["public_identity"]
        );
        let update =
            json!({"expected_bundle_revision":1,"encrypted_bundle":sealed["encrypted_bundle"]})
                .to_string();
        assert_eq!(
            exchange(
                &mut accounts,
                "PUT",
                "/v1/keys/identity/bundle",
                &headers,
                &update
            )
            .0,
            200
        );
        assert_eq!(
            exchange(
                &mut accounts,
                "PUT",
                "/v1/keys/identity/bundle",
                &headers,
                &update
            )
            .0,
            409
        );
        let identity = petika_core::identity::UnlockedIdentity::generate(
            deployment["deployment_id"].as_str().unwrap(),
            &user.id,
            2,
        )
        .unwrap();
        let sealed: Value =
            serde_json::from_slice(&identity.seal("synthetic unlock password").unwrap()).unwrap();
        let replacement = json!({"expected_bundle_revision":2,"expected_identity_version":1,"current_password":password,"public_identity":sealed["public_identity"],"encrypted_bundle":sealed["encrypted_bundle"]});
        assert_eq!(
            exchange(
                &mut accounts,
                "POST",
                "/v1/keys/identity/replace",
                &headers,
                &replacement.to_string()
            )
            .0,
            200
        );
    }
}
