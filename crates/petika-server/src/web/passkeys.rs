use super::*;
#[cfg(not(feature = "browser-passkeys"))]
pub fn passkey_route(request: Request, _: &mut Accounts) {
    json(
        request,
        404,
        serde_json::json!({"error":"Passkeys unavailable"}),
        None,
    );
}
#[cfg(feature = "browser-passkeys")]
pub fn passkey_route(mut request: Request, accounts: &mut Accounts) {
    use petika_server::accounts::{KeyError, passkeys::Operation};
    use std::io::Read;
    let fail = |request, error: KeyError| json(request, error.status(), error.body(), None);
    let token = if crate::header(&request, "Authorization")
        .is_some_and(|s| !s.starts_with("Bearer cli_"))
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
    let operation = match (request.url(), request.method().as_str()) {
        ("/v1/passkeys", "GET") => Operation::Info,
        ("/v1/passkeys/registration/start", "POST") => Operation::RegistrationStart,
        ("/v1/passkeys/registration/finish", "POST") => Operation::RegistrationFinish,
        ("/v1/passkeys/authentication/start", "POST") => Operation::AuthenticationStart,
        ("/v1/passkeys/authentication/finish", "POST") => Operation::AuthenticationFinish,
        (path, "GET") if path.starts_with("/v1/passkey-vaults/") => {
            Operation::Vault(path.trim_start_matches("/v1/passkey-vaults/").into())
        }
        (path, "PUT") if path.starts_with("/v1/passkey-vaults/") => {
            Operation::Write(path.trim_start_matches("/v1/passkey-vaults/").into())
        }
        _ => return fail(request, KeyError::MethodNotAllowed),
    };
    let limit = if matches!(operation, Operation::Write(_)) {
        16 * 1024 * 1024
    } else {
        64 * 1024
    };
    let mut body = zeroize::Zeroizing::new(Vec::new());
    if request.method() != &Method::Get {
        if crate::header(&request, "Content-Type") != Some("application/json") {
            return fail(request, KeyError::UnsupportedMediaType);
        }
        if !csrf(&request) {
            return fail(request, KeyError::Forbidden);
        }
        if request.body_length().is_some_and(|n| n > limit) {
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
    match accounts.passkey_operation(&token, operation, &body) {
        Ok(value) => json(request, 200, value, None),
        Err(e) => fail(request, e),
    }
}

#[cfg(all(test, feature = "browser-passkeys"))]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpStream,
    };
    fn exchange(accounts: &mut Accounts, headers: &str, body: &str) -> u16 {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let address = server.server_addr().to_ip().unwrap();
        let wire = format!(
            "POST /v1/passkeys/registration/start HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
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
        passkey_route(server.recv().unwrap(), accounts);
        let response = client.join().unwrap();
        assert!(response.to_lowercase().contains("cache-control: no-store"));
        response.split_whitespace().nth(1).unwrap().parse().unwrap()
    }
    #[test]
    fn passkey_http_boundary_rejects_service_tokens_csrf_and_oversized_ceremonies() {
        let dir = tempfile::tempdir().unwrap();
        let mut accounts = Accounts::new(dir.path().join("accounts.json"));
        accounts
            .create_user(
                "owner",
                "Owner",
                "synthetic account password".into(),
                true,
                true,
            )
            .unwrap();
        let (token, _) = accounts
            .login("owner", "synthetic account password".into())
            .unwrap();
        assert_eq!(exchange(&mut accounts, "", "{}"), 401);
        let cookie = format!("Cookie: petika_session={token}\r\n");
        assert_eq!(
            exchange(
                &mut accounts,
                &format!("{cookie}Authorization: Bearer service-token\r\n"),
                "{}"
            ),
            401
        );
        assert_eq!(exchange(&mut accounts, &cookie, "{}"), 415);
        let json = format!("{cookie}Content-Type: application/json\r\n");
        assert_eq!(exchange(&mut accounts, &json, "{}"), 403);
        let headers = format!("{json}X-Petika-Request: 1\r\n");
        assert_eq!(
            exchange(
                &mut accounts,
                &format!("{headers}Sec-Fetch-Site: cross-site\r\n"),
                "{}"
            ),
            403
        );
        assert_eq!(
            exchange(&mut accounts, &headers, &" ".repeat(64 * 1024 + 1)),
            413
        );
    }
}
