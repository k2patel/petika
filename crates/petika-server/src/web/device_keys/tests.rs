use super::*;
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::TcpStream,
};

fn exchange(
    accounts: &mut Accounts,
    enabled: bool,
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
            .set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();
        stream.write_all(wire.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    });
    device_key_route(server.recv().unwrap(), accounts, enabled);
    let response = client.join().unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(head.to_lowercase().contains("cache-control: no-store"));
    assert!(!head.to_lowercase().contains("access-control-allow-origin"));
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        serde_json::from_str(body).unwrap(),
    )
}

#[test]
fn device_api_is_off_without_both_feature_and_runtime_gates() {
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    assert_eq!(
        exchange(&mut accounts, false, "GET", "/v1/device-keys", "", "").0,
        404
    );
    #[cfg(not(feature = "experimental-device-keys"))]
    assert_eq!(
        exchange(&mut accounts, true, "GET", "/v1/device-keys", "", "").0,
        404
    );
    assert!(!dir.path().join("accounts.json.device-keys").exists());
}

#[cfg(feature = "experimental-device-keys")]
#[test]
fn device_http_enforces_session_csrf_body_limits_and_signed_publication() {
    use petika_core::{
        device_keys::{DeviceAuthorityKey, DeviceIdentity},
        identity::UnlockedIdentity,
    };
    use petika_server::accounts::{KeyOperation, MAX_DEVICE_KEY_BODY};
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = Accounts::new(dir.path().join("accounts.json"));
    let password = "synthetic HTTP account password";
    let user = accounts
        .create_user("owner", "Owner", password.into(), true, true)
        .unwrap();
    let token = accounts.login("owner", password.into()).unwrap().0;
    let cookie = format!("Cookie: petika_session={token}\r\n");
    let headers = format!("{cookie}Content-Type: application/json\r\nX-Petika-Request: 1\r\n");
    assert_eq!(
        exchange(&mut accounts, true, "GET", "/v1/device-keys", "", "").0,
        401
    );
    assert_eq!(
        exchange(
            &mut accounts,
            true,
            "GET",
            "/v1/device-keys",
            &format!("{headers}Authorization: Bearer service-secret\r\n"),
            ""
        )
        .0,
        401
    );
    assert_eq!(
        exchange(&mut accounts, true, "GET", "/v1/device-keys", &headers, "").0,
        404
    );
    assert_eq!(
        exchange(
            &mut accounts,
            true,
            "DELETE",
            "/v1/device-keys",
            &headers,
            ""
        )
        .0,
        405
    );
    assert_eq!(
        exchange(
            &mut accounts,
            true,
            "POST",
            "/v1/device-keys/bootstrap",
            &cookie,
            "{}"
        )
        .0,
        415
    );
    assert_eq!(
        exchange(
            &mut accounts,
            true,
            "POST",
            "/v1/device-keys/bootstrap",
            &format!("{cookie}Content-Type: application/json\r\n"),
            "{}"
        )
        .0,
        403
    );
    assert_eq!(
        exchange(
            &mut accounts,
            true,
            "POST",
            "/v1/device-keys/bootstrap",
            &format!("{headers}Sec-Fetch-Site: cross-site\r\n"),
            "{}"
        )
        .0,
        403
    );
    assert_eq!(
        exchange(
            &mut accounts,
            true,
            "POST",
            "/v1/device-keys/bootstrap",
            &headers,
            "{"
        )
        .0,
        400
    );
    assert_eq!(
        exchange(
            &mut accounts,
            true,
            "POST",
            "/v1/device-keys/bootstrap",
            &headers,
            &" ".repeat(MAX_DEVICE_KEY_BODY + 1)
        )
        .0,
        413
    );
    let deployment = accounts
        .key_operation(&token, KeyOperation::Deployment, &[])
        .unwrap();
    let deployment = deployment["deployment_id"].as_str().unwrap();
    let legacy = UnlockedIdentity::generate(deployment, &user.id, 1).unwrap();
    let sealed: Value =
        serde_json::from_slice(&legacy.seal("synthetic HTTP unlock password").unwrap()).unwrap();
    accounts.key_operation(&token,KeyOperation::Enroll,&serde_json::to_vec(&json!({"current_password":password,"expected_bundle_revision":0,"public_identity":sealed["public_identity"],"encrypted_bundle":sealed["encrypted_bundle"]})).unwrap()).unwrap();
    let authority = DeviceAuthorityKey::generate(deployment, &user.id).unwrap();
    let initial = authority
        .sign_roster(1, String::new(), vec![], vec![])
        .unwrap();
    let bootstrap = legacy
        .authorize_device_authority(initial.clone(), 1, &initial.authority.fingerprint)
        .unwrap();
    let body = json!({"current_password":password,"bootstrap":bootstrap}).to_string();
    assert_eq!(
        exchange(
            &mut accounts,
            true,
            "POST",
            "/v1/device-keys/bootstrap",
            &headers,
            &body
        )
        .0,
        200
    );
    let device = DeviceIdentity::generate(deployment, &user.id).unwrap();
    let candidate = authority
        .sign_roster(
            2,
            initial.digest().unwrap(),
            vec![device.public_record().unwrap()],
            vec![],
        )
        .unwrap();
    let id = "d".repeat(64);
    let body = json!({"current_password":password,"operation_id":id,"expected_parent":candidate.parent_digest,"roster":candidate}).to_string();
    let response = exchange(
        &mut accounts,
        true,
        "POST",
        "/v1/device-keys/publications",
        &headers,
        &body,
    );
    assert_eq!(response.0, 200);
    assert_eq!(
        exchange(
            &mut accounts,
            true,
            "GET",
            &format!("/v1/device-keys/receipts/{id}"),
            &headers,
            ""
        ),
        response
    );
    let history = exchange(
        &mut accounts,
        true,
        "GET",
        &format!("/v1/device-keys/history/{}", initial.digest().unwrap()),
        &headers,
        "",
    );
    assert_eq!(history.0, 200);
    assert_eq!(history.1["rosters"], json!([candidate]));
    // Existing approved CLI sessions work; arbitrary static bearer credentials do not.
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
    let cli = format!(
        "Authorization: Bearer {}\r\n",
        approved["token"].as_str().unwrap()
    );
    assert_eq!(
        exchange(&mut accounts, true, "GET", "/v1/device-keys", &cli, "").0,
        200
    );
    accounts.logout(&token);
    assert_eq!(
        exchange(&mut accounts, true, "GET", "/v1/device-keys", &headers, "").0,
        401
    );
}
