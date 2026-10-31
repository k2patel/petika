use super::{Accounts, Request, json};

#[cfg(not(feature = "experimental-device-keys"))]
pub fn device_key_route(request: Request, _: &mut Accounts, _: bool) {
    let error = petika_server::accounts::KeyError::NotFound;
    json(request, error.status(), error.body(), None);
}

#[cfg(feature = "experimental-device-keys")]
pub fn device_key_route(mut request: Request, accounts: &mut Accounts, enabled: bool) {
    use petika_server::accounts::{DeviceKeyOperation, KeyError, MAX_DEVICE_KEY_BODY};
    use std::io::Read;
    let fail =
        |request: Request, error: KeyError| json(request, error.status(), error.body(), None);
    if !enabled {
        return fail(request, KeyError::NotFound);
    }
    let token = if crate::header(&request, "Authorization")
        .is_some_and(|h| !h.starts_with("Bearer cli_"))
    {
        String::new()
    } else {
        super::session(&request)
    };
    match accounts.authenticate(&token) {
        Ok(Some(_)) => {}
        Ok(None) => return fail(request, KeyError::Unauthenticated),
        Err(_) => return fail(request, KeyError::Unavailable),
    }
    let operation = match (request.url(), request.method().as_str()) {
        ("/v1/device-keys", "GET") => DeviceKeyOperation::Own,
        ("/v1/device-keys/bootstrap", "POST") => DeviceKeyOperation::Initialize,
        ("/v1/device-keys/publications", "POST") => DeviceKeyOperation::Publish,
        (path, "GET") if path.starts_with("/v1/device-keys/receipts/") => {
            DeviceKeyOperation::Receipt(path.trim_start_matches("/v1/device-keys/receipts/").into())
        }
        (path, "GET") if path.starts_with("/v1/device-keys/history/") => {
            DeviceKeyOperation::History(path.trim_start_matches("/v1/device-keys/history/").into())
        }
        ("/v1/device-keys" | "/v1/device-keys/bootstrap" | "/v1/device-keys/publications", _) => {
            return fail(request, KeyError::MethodNotAllowed);
        }
        (path, _)
            if path.starts_with("/v1/device-keys/receipts/")
                || path.starts_with("/v1/device-keys/history/") =>
        {
            return fail(request, KeyError::MethodNotAllowed);
        }
        _ => return fail(request, KeyError::NotFound),
    };
    let mut body = zeroize::Zeroizing::new(Vec::new());
    if request.method() != &tiny_http::Method::Get {
        if crate::header(&request, "Content-Type") != Some("application/json") {
            return fail(request, KeyError::UnsupportedMediaType);
        }
        if !super::csrf(&request) {
            return fail(request, KeyError::Forbidden);
        }
        if request
            .body_length()
            .is_some_and(|len| len > MAX_DEVICE_KEY_BODY)
        {
            return fail(request, KeyError::TooLarge);
        }
        if request
            .as_reader()
            .take(MAX_DEVICE_KEY_BODY as u64 + 1)
            .read_to_end(&mut body)
            .is_err()
        {
            return fail(request, KeyError::Invalid);
        }
        if body.len() > MAX_DEVICE_KEY_BODY {
            return fail(request, KeyError::TooLarge);
        }
    }
    match accounts.device_key_operation(&token, operation, &body) {
        Ok(value) => json(request, 200, value, None),
        Err(error) => fail(request, error),
    }
}

#[cfg(test)]
mod tests;
