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
