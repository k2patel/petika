use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    version: u32,
    hosts: Vec<Host>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Host {
    repository: Repository,
    api_prefix: String,
    #[serde(deserialize_with = "read_token")]
    token: Zeroizing<String>,
    #[serde(default)]
    auth_scheme: Scheme,
    #[serde(default)]
    owner_user_id: Option<String>,
    #[serde(default)]
    allow_write: bool,
    #[serde(default = "default_ttl")]
    max_lease_seconds: u64,
}
fn default_ttl() -> u64 {
    3600
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Scheme {
    Bearer,
    Token,
}
impl Default for Scheme {
    fn default() -> Self {
        Self::Bearer
    }
}
impl Host {
    fn authorization(&self) -> String {
        format!(
            "{} {}",
            match self.auth_scheme {
                Scheme::Bearer => "Bearer",
                Scheme::Token => "token",
            },
            self.token.as_str()
        )
    }
}
fn read_token<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
/// Protected operator configuration, never populated from an unauthenticated request.
pub struct ConfiguredHosts {
    config: Configuration,
    agent: ureq::Agent,
    deadline: Instant,
}
impl ConfiguredHosts {
    pub(crate) fn metadata_only() -> Self {
        Self::new(
            Configuration {
                version: 1,
                hosts: vec![],
            },
            true,
        )
    }
    pub fn load(path: &Path) -> Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > 65536 {
            return Err("Invalid Git host credential file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !matches!(metadata.mode() & 0o777, 0o400 | 0o600)
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err("Git host credentials require owner-only permissions".into());
            }
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err("Invalid Git host credential file".into());
        }
        let config: Configuration =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid Git key host configuration")?;
        if config.version != 1 || config.hosts.is_empty() || config.hosts.len() > 32 {
            return Err("Invalid Git key host configuration".into());
        }
        for (index, host) in config.hosts.iter().enumerate() {
            if !repository_valid(&host.repository)
                || host.token.is_empty()
                || host.token.len() > 4096
                || !host.token.bytes().all(|b| b.is_ascii_graphic())
                || !matches!(
                    (&host.repository.provider, host.api_prefix.as_str()),
                    (Provider::Github, "" | "/api/v3") | (Provider::Gitea, "/api/v1")
                )
                || !(60..=3600).contains(&host.max_lease_seconds)
                || host.owner_user_id.as_deref().is_some_and(|id| !hex(id))
                || config.hosts[..index]
                    .iter()
                    .any(|h| h.repository == host.repository)
            {
                return Err("Invalid Git key host configuration".into());
            }
        }
        Ok(Self::new(config, true))
    }
    fn new(config: Configuration, https: bool) -> Self {
        let options = ureq::Agent::config_builder()
            .https_only(https)
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(10)))
            .build();
        Self {
            config,
            agent: ureq::Agent::new_with_config(options),
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }
    pub(crate) fn authorize_repository(
        &self,
        repo: &Repository,
        user: &str,
        read_only: bool,
        ttl: u64,
    ) -> Result<()> {
        let host = self
            .host(repo)
            .map_err(|_| "Git repository is not configured")?;
        if host.owner_user_id.as_deref() != Some(user)
            || (!read_only && !host.allow_write)
            || ttl < 60
            || ttl > host.max_lease_seconds
        {
            return Err("Git repository access denied".into());
        }
        Ok(())
    }
    fn host(&self, repo: &Repository) -> std::result::Result<&Host, Failure> {
        if Instant::now() >= self.deadline {
            return Err(Failure::Inventory);
        }
        self.config
            .hosts
            .iter()
            .find(|h| h.repository == *repo)
            .ok_or(Failure::Inventory)
    }
    fn endpoint(host: &Host) -> String {
        format!(
            "{}{}/repos/{}/keys",
            host.repository.management_origin.trim_end_matches('/'),
            host.api_prefix,
            host.repository.repository
        )
    }
}
#[derive(Deserialize)]
struct ApiKey {
    id: u64,
    title: String,
    key: String,
    read_only: bool,
}
fn fingerprint(key: &str) -> std::result::Result<String, Failure> {
    if key.len() > 16384 {
        return Err(Failure::Inventory);
    }
    let mut parts = key.split_whitespace();
    let algorithm = parts.next().ok_or(Failure::Inventory)?;
    let encoded = parts.next().ok_or(Failure::Inventory)?;
    let bytes = STANDARD.decode(encoded).map_err(|_| Failure::Inventory)?;
    if bytes.len() < 4 {
        return Err(Failure::Inventory);
    }
    let length =
        u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Failure::Inventory)?) as usize;
    if length > 128 || bytes.len() <= 4 + length || &bytes[4..4 + length] != algorithm.as_bytes() {
        return Err(Failure::Inventory);
    }
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
impl KeyHost for ConfiguredHosts {
    fn inventory(&mut self, repository: &Repository) -> std::result::Result<Inventory, Failure> {
        let host = self.host(repository)?;
        let endpoint = Self::endpoint(host);
        let mut keys = Vec::new();
        let mut ids = BTreeSet::new();
        // Continue until an empty page, even when the host caps pages below 100.
        for page in 1..=42 {
            self.host(repository)?;
            let limit = if repository.provider == Provider::Github {
                "per_page"
            } else {
                "limit"
            };
            let mut response = self
                .agent
                .get(format!("{endpoint}?{limit}=100&page={page}"))
                .header("Authorization", host.authorization())
                .header("User-Agent", "Petika-key-cleanup")
                .header("Accept", "application/json")
                .call()
                .map_err(|_| Failure::Inventory)?;
            if response.status().as_u16() != 200 {
                return Err(Failure::Inventory);
            }
            let mut bytes = Vec::new();
            response
                .body_mut()
                .as_reader()
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Failure::Inventory)?;
            if bytes.len() > 1024 * 1024 {
                return Err(Failure::Incomplete);
            }
            let rows: Vec<ApiKey> =
                serde_json::from_slice(&bytes).map_err(|_| Failure::Inventory)?;
            if rows.is_empty() {
                return Ok(Inventory {
                    keys,
                    complete: true,
                });
            }
            if rows.len() > 100 {
                return Err(Failure::Incomplete);
            }
            for row in rows {
                if row.id == 0 || !ids.insert(row.id) || row.title.len() > 512 {
                    return Err(Failure::Incomplete);
                }
                keys.push(RemoteKey {
                    id: row.id.to_string(),
                    marker: row.title,
                    fingerprint: fingerprint(&row.key)?,
                    read_only: Some(row.read_only),
                });
                if keys.len() > LIMIT {
                    return Err(Failure::Incomplete);
                }
            }
        }
        Err(Failure::Incomplete)
    }
    fn delete(&mut self, repository: &Repository, id: &str) -> std::result::Result<(), Failure> {
        let host = self.host(repository)?;
        if id.parse::<u64>().ok().filter(|n| *n > 0).is_none() {
            return Err(Failure::Delete);
        }
        let response = self
            .agent
            .delete(format!("{}/{}", Self::endpoint(host), id))
            .header("Authorization", host.authorization())
            .header("User-Agent", "Petika-key-cleanup")
            .call()
            .map_err(|_| Failure::Delete)?;
        if matches!(response.status().as_u16(), 200 | 204 | 404) {
            Ok(())
        } else {
            Err(Failure::Delete)
        }
    }
}

#[cfg(test)]
mod tests;

impl KeyRegistrar for ConfiguredHosts {
    fn authorized(&self, repo: &Repository, user: &str, read_only: bool, ttl: u64) -> bool {
        self.authorize_repository(repo, user, read_only, ttl)
            .is_ok()
    }
    fn create(
        &mut self,
        repo: &Repository,
        marker: &str,
        public_key: &str,
        read_only: bool,
    ) -> std::result::Result<RemoteKey, Failure> {
        let host = self.host(repo)?;
        if !marker.starts_with("petika-lease:v1:")
            || !hex(marker.trim_start_matches("petika-lease:v1:"))
        {
            return Err(Failure::Registration);
        }
        if !read_only && !host.allow_write {
            return Err(Failure::Registration);
        }
        let expected = fingerprint(public_key)?;
        let payload = serde_json::to_vec(
            &serde_json::json!({"title":marker,"key":public_key,"read_only":read_only}),
        )
        .map_err(|_| Failure::Registration)?;
        let mut response = self
            .agent
            .post(Self::endpoint(host))
            .header("Authorization", host.authorization())
            .header("User-Agent", "Petika-key-registration")
            .header("Content-Type", "application/json")
            .send(payload.as_slice())
            .map_err(|_| Failure::Registration)?;
        if response.status().as_u16() != 201 {
            return Err(Failure::Registration);
        }
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Registration)?;
        if bytes.len() > 65536 {
            return Err(Failure::Registration);
        }
        let key: ApiKey = serde_json::from_slice(&bytes).map_err(|_| Failure::Registration)?;
        if key.id == 0
            || key.title != marker
            || fingerprint(&key.key)? != expected
            || key.read_only != read_only
        {
            return Err(Failure::Registration);
        }
        Ok(RemoteKey {
            id: key.id.to_string(),
            marker: key.title,
            fingerprint: expected,
            read_only: Some(key.read_only),
        })
    }
}
