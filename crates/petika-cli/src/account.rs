//! Managed-account transport. Never sends collection passphrases or follows redirects.
use crate::Result;
use petika_core::{StoreFile, UnlockedStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::Read,
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    version: u32,
    server: String,
    token: String,
}
impl Drop for Credential {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
    }
}

fn origin(input: &str) -> Result<String> {
    let url = url::Url::parse(input)?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("Use an HTTPS server origin without credentials, path, query, or fragment (HTTP is allowed only on loopback)".into());
    }
    Ok(url.origin().ascii_serialization())
}
pub(crate) struct Client {
    agent: ureq::Agent,
    pub(crate) server: String,
    token: String,
}
impl Drop for Client {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
    }
}
impl Client {
    #[cfg(feature = "experimental-entry-format")]
    pub(crate) fn entry_history(&self, collection: &str, body: &[u8]) -> Result<Vec<u8>> {
        use petika_core::entry_format::transport::{HistoryRequest, MAX_HISTORY_WIRE_BYTES};
        let request = HistoryRequest::parse(body)?;
        if request.context.collection_id != collection {
            return Err("History collection mismatch".into());
        }
        let auth = Zeroizing::new(format!("Bearer {}", self.token));
        let mut response = self
            .agent
            .post(format!(
                "{}/v1/collections/{collection}/entry-history",
                self.server
            ))
            .header("Authorization", auth.as_str())
            .header("Content-Type", "application/json")
            .header("X-Petika-Request", "1")
            .send(body)?;
        if response.status().as_u16() != 200 {
            return Err(format!(
                "History request rejected (HTTP {}); local checkpoint retained",
                response.status()
            )
            .into());
        }
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(MAX_HISTORY_WIRE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_HISTORY_WIRE_BYTES {
            return Err("History response exceeds wire limit".into());
        }
        Ok(bytes)
    }
    fn new(server: &str, token: String) -> Result<Self> {
        Ok(Self {
            server: origin(server)?,
            token,
            agent: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .timeout_global(Some(Duration::from_secs(30)))
                .build()
                .into(),
        })
    }
    pub(crate) fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        revision: Option<u64>,
    ) -> Result<(u16, Option<u64>, String)> {
        let url = format!("{}{path}", self.server);
        let auth = Zeroizing::new(format!("Bearer {}", self.token));
        let mut response = match method {
            "GET" => self
                .agent
                .get(&url)
                .header("Authorization", auth.as_str())
                .call()?,
            "POST" => self
                .agent
                .post(&url)
                .header("Authorization", auth.as_str())
                .header("Content-Type", "application/json")
                .header("X-Petika-Request", "1")
                .send(body.unwrap_or("{}"))?,
            "PUT" => self
                .agent
                .put(&url)
                .header("Authorization", auth.as_str())
                .header("Content-Type", "application/json")
                .header("X-Petika-Request", "1")
                .header("If-Match", format!("\"{}\"", revision.unwrap_or(0)))
                .send(body.ok_or("Snapshot required")?)?,
            _ => return Err("Unsupported method".into()),
        };
        let status = response.status().as_u16();
        let revision = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix('"'))
            .and_then(|s| s.strip_suffix('"'))
            .and_then(|s| s.parse().ok());
        let mut bytes = String::new();
        response
            .body_mut()
            .as_reader()
            .take(12 * 1024 * 1024 + 1)
            .read_to_string(&mut bytes)?;
        if bytes.len() > 12 * 1024 * 1024 {
            return Err("Server response too large".into());
        }
        match status {
            200..=299 => Ok((status, revision, bytes)),
            401 => Err("Session expired or revoked; run petika login again".into()),
            403 => Err("Access denied; check your session and collection permissions".into()),
            409 => Err("Revision conflict; server was not overwritten. Pull into a separate file to compare changes".into()),
            _ => Err(format!("Server returned HTTP {status}").into()),
        }
    }
    pub(crate) fn json(&self, method: &str, path: &str, body: Value) -> Result<Value> {
        let encoded = Zeroizing::new(body.to_string());
        let (_, _, text) = self.request(method, path, Some(&encoded), None)?;
        Ok(serde_json::from_str(&text)?)
    }
}
fn credential(file: &StoreFile) -> Result<Credential> {
    if !file.exists() {
        return Err("Not signed in; run petika login --server URL".into());
    }
    let bytes = Zeroizing::new(file.read()?);
    let saved: Credential =
        serde_json::from_slice(&bytes).map_err(|_| "No valid session; run petika login")?;
    if saved.version != 1 || !saved.token.starts_with("cli_") || saved.token.len() != 68 {
        return Err("Unsupported or invalid session file".into());
    }
    Ok(saved)
}
pub(crate) fn client(path: &Path) -> Result<Client> {
    let saved = credential(&StoreFile::lock(path)?)?;
    Client::new(&saved.server, saved.token.clone())
}
pub fn login(path: &Path, server: &str) -> Result<()> {
    let file = StoreFile::lock(path)?;
    if file.exists() {
        let bytes = Zeroizing::new(file.read()?);
        if serde_json::from_slice::<Value>(&bytes).ok() != Some(json!({})) {
            return Err(
                "Session file is occupied; log out first or choose a new --session-file".into(),
            );
        }
    }
    let client = Client::new(server, String::new())?;
    let start = client.json("POST", "/v1/auth/device/start", json!({}))?;
    let device = Zeroizing::new(
        start["device_code"]
            .as_str()
            .ok_or("Invalid device response")?
            .to_owned(),
    );
    let code = start["user_code"]
        .as_str()
        .ok_or("Invalid device response")?;
    if code.len() != 10 || !code.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid code".into());
    }
    println!(
        "Open {}/?cli=1 in your browser.\nEnter code: {}-{}\nApprove only this CLI request. Waiting up to 10 minutes…",
        client.server,
        &code[..5],
        &code[5..]
    );
    use std::io::Write;
    std::io::stdout().flush()?;
    let deadline = Instant::now() + Duration::from_secs(600);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(5));
        let poll = client.json(
            "POST",
            "/v1/auth/device/poll",
            json!({"device_code":device.as_str()}),
        )?;
        match poll["status"].as_str() {
            Some("pending" | "slow_down") => continue,
            Some("approved") => {
                let token = poll["token"].as_str().ok_or("Missing session")?;
                if token.len() != 68
                    || !token.starts_with("cli_")
                    || !token[4..].bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err("Invalid session".into());
                }
                let saved = Credential {
                    version: 1,
                    server: client.server.clone(),
                    token: token.into(),
                };
                let bytes = Zeroizing::new(serde_json::to_vec(&saved)?);
                if let Err(err) = file.write(&bytes, false) {
                    let cleanup = Client::new(&saved.server, saved.token.clone())?;
                    let _ = cleanup.json("POST", "/v1/auth/logout", json!({}));
                    return Err(err.into());
                }
                println!("Signed in. Session expires in 8 hours; collection unlock remains local.");
                return Ok(());
            }
            _ => return Err("CLI sign-in denied, expired, or already used".into()),
        }
    }
    Err("CLI sign-in timed out; run login again".into())
}
pub fn logout(path: &Path, local_only: bool) -> Result<()> {
    let file = StoreFile::lock(path)?;
    let saved = credential(&file)?;
    if !local_only {
        Client::new(&saved.server, saved.token.clone())?.json(
            "POST",
            "/v1/auth/logout",
            json!({}),
        )?;
    }
    file.write(b"{}", false)?;
    println!(
        "{}",
        if local_only {
            "Local session removed. Server session was not revoked; it expires within 8 hours."
        } else {
            "Signed out and server session revoked."
        }
    );
    Ok(())
}
pub fn whoami(path: &Path) -> Result<()> {
    let value = client(path)?.json("GET", "/v1/auth/status", Value::Null)?;
    if value["user"].is_null() {
        return Err("Session expired or revoked; run logout --local then login".into());
    }
    println!("{}", serde_json::to_string_pretty(&value["user"])?);
    Ok(())
}
pub fn collections(path: &Path) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&client(path)?.json(
            "GET",
            "/v1/collections",
            Value::Null
        )?)?
    );
    Ok(())
}
pub(crate) fn collection(client: &Client, selected: &str, write: bool) -> Result<String> {
    let list = client.json("GET", "/v1/collections", Value::Null)?;
    let item = list
        .as_array()
        .ok_or("Invalid collections response")?
        .iter()
        .find(|c| {
            if selected == "personal" {
                c["group"] == false
            } else {
                c["id"] == selected
            }
        })
        .ok_or("Collection unavailable; run petika collections")?;
    if write && item["edit"] != true {
        return Err("Collection is read-only".into());
    }
    let id = item["id"].as_str().ok_or("Invalid collection ID")?;
    if id.len() != 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid collection ID".into());
    }
    Ok(id.into())
}
pub fn status(path: &Path, selected: &str) -> Result<()> {
    let client = client(path)?;
    let id = collection(&client, selected, false)?;
    println!(
        "{}",
        client.json("GET", &format!("/v1/collections/{id}/status"), Value::Null)?
    );
    Ok(())
}
pub fn pull(path: &Path, selected: &str, store: &Path, replace: bool, stdin: bool) -> Result<()> {
    let file = StoreFile::lock(store)?;
    if file.exists() && !replace {
        return Err("Local store exists; use another --store path or explicitly --replace".into());
    }
    let client = client(path)?;
    let id = collection(&client, selected, false)?;
    let (_, revision, encrypted) =
        client.request("GET", &format!("/v1/collections/{id}/snapshot"), None, None)?;
    let revision = revision.ok_or("Missing server revision")?;
    let passphrase = crate::secret("Collection passphrase (local only): ", stdin)?;
    let _verified = UnlockedStore::open(encrypted.as_bytes(), &passphrase)?;
    file.write(encrypted.as_bytes(), !replace)?;
    println!(
        "Pulled and verified revision {revision}. Use --revision {revision} on the next push."
    );
    Ok(())
}
pub fn push(path: &Path, selected: &str, store: &Path, revision: u64, stdin: bool) -> Result<()> {
    let file = StoreFile::lock(store)?;
    let encrypted = String::from_utf8(file.read()?)?;
    let passphrase = crate::secret("Collection passphrase (local only): ", stdin)?;
    let _verified = UnlockedStore::open(encrypted.as_bytes(), &passphrase)?;
    let client = client(path)?;
    let id = collection(&client, selected, true)?;
    let (_, revision, _) = client.request(
        "PUT",
        &format!("/v1/collections/{id}/snapshot"),
        Some(&encrypted),
        Some(revision),
    )?;
    println!(
        "Pushed encrypted snapshot; revision {}.",
        revision.ok_or("Missing server revision")?
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_requires_safe_origin() {
        for value in [
            "http://example.com",
            "https://u:p@example.com",
            "https://example.com/path",
            "https://example.com?x=1",
            "file:///tmp/x",
            "https://example.com/#fragment",
        ] {
            assert!(origin(value).is_err(), "{value}");
        }
        for value in [
            "https://example.com",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
        ] {
            assert!(origin(value).is_ok(), "{value}");
        }
    }
}
