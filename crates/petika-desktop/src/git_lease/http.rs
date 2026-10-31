//! Fixed-origin, bounded HTTP adapter. Management credentials never enter it.
use super::*;
use std::{io::Read, time::Duration};

pub(crate) fn origin(input: &str) -> Result<String> {
    let u = url::Url::parse(input).map_err(|_| Error::Invalid)?;
    let secure = u.scheme() == "https";
    #[cfg(test)]
    let secure = secure
        || (u.scheme() == "http"
            && matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")));
    if !secure
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
    {
        return Err(Error::Invalid);
    }
    Ok(u.origin().ascii_serialization())
}
pub struct HttpService<F> {
    server: String,
    token: Zeroizing<String>,
    password: F,
    agent: ureq::Agent,
}
impl<F: FnMut() -> Result<Zeroizing<String>>> HttpService<F> {
    /// Use an approved CLI bearer session, never a static service credential.
    /// The password callback must not cache or log its returned plaintext.
    pub fn new(server: &str, token: Zeroizing<String>, password: F) -> Result<Self> {
        if !token.starts_with("cli_")
            || token.len() > 4096
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(Error::Invalid);
        }
        let server = origin(server)?;
        Ok(Self {
            server,
            token,
            password,
            agent: ureq::Agent::config_builder()
                .https_only(!cfg!(test))
                .proxy(None)
                .max_redirects(0)
                .http_status_as_error(false)
                .timeout_global(Some(Duration::from_secs(10)))
                .build()
                .into(),
        })
    }
    fn call(&self, path: &str, body: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        if body.is_some_and(|b| b.len() > LIMIT) {
            return Err(Error::Invalid);
        }
        let auth = Zeroizing::new(format!("Bearer {}", self.token.as_str()));
        let uri = format!("{}/v1/device-keys/git-leases{path}", self.server);
        let mut response = match body {
            None => self
                .agent
                .get(&uri)
                .header("Authorization", auth.as_str())
                .call(),
            Some(bytes) => self
                .agent
                .post(&uri)
                .header("Authorization", auth.as_str())
                .header("Content-Type", "application/json")
                .header("X-Petika-Request", "1")
                .send(bytes),
        }
        .map_err(|_| Error::Service)?;
        let status = response.status().as_u16();
        // Only operation lookups interpret 404 as absence. Auth/transport errors
        // cannot be converted into permission to create another remote key.
        if status == 404 && body.is_none() && path.starts_with("/operations/") {
            return Ok(None);
        }
        if status != 200 {
            return Err(Error::Service);
        }
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Service)?;
        if bytes.len() > LIMIT {
            return Err(Error::Service);
        }
        Ok(Some(bytes))
    }
    pub fn context(&self) -> Result<SessionContext> {
        let c: SessionContext =
            serde_json::from_slice(&self.call("/context", None)?.ok_or(Error::Service)?)
                .map_err(|_| Error::Invalid)?;
        if !id(&c.deployment_id) || !id(&c.user_id) || !id(&c.session_id) {
            return Err(Error::Invalid);
        }
        Ok(c)
    }
}
impl<F: FnMut() -> Result<Zeroizing<String>>> LeaseService for HttpService<F> {
    fn origin(&self) -> &str {
        &self.server
    }
    fn challenge(&mut self, intent: &Intent) -> Result<GitLeaseChallenge> {
        #[derive(Serialize)]
        struct Repository<'a> {
            provider: Provider,
            management_origin: &'a str,
            repository: &'a str,
        }
        #[derive(Serialize)]
        struct Request<'a> {
            current_password: &'a str,
            operation_id: &'a str,
            device_id: &'a str,
            repository: Repository<'a>,
            ssh_public_key: &'a str,
            read_only: bool,
            ttl: u64,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Response {
            challenge: GitLeaseChallenge,
        }
        let password = (self.password)()?;
        let s = &intent.scope;
        let body = Zeroizing::new(
            serde_json::to_vec(&Request {
                current_password: &password,
                operation_id: &intent.operation_id,
                device_id: &s.device_id,
                repository: Repository {
                    provider: s.provider,
                    management_origin: &s.management_origin,
                    repository: &s.repository,
                },
                ssh_public_key: &intent.ssh_public_key,
                read_only: s.read_only,
                ttl: s.ttl,
            })
            .map_err(|_| Error::Invalid)?,
        );
        let response: Response = serde_json::from_slice(
            &self
                .call("/challenges", Some(&body))?
                .ok_or(Error::Service)?,
        )
        .map_err(|_| Error::Invalid)?;
        Ok(response.challenge)
    }
    fn lookup(&mut self, operation_id: &str) -> Result<Option<Status>> {
        if !id(operation_id) {
            return Err(Error::Invalid);
        }
        self.call(&format!("/operations/{operation_id}"), None)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| Error::Invalid))
            .transpose()
    }
    fn register(&mut self, proof: &GitLeaseProof) -> Result<()> {
        #[derive(Serialize)]
        struct Request<'a> {
            current_password: &'a str,
            proof: &'a GitLeaseProof,
        }
        let password = (self.password)()?;
        let body = Zeroizing::new(
            serde_json::to_vec(&Request {
                current_password: &password,
                proof,
            })
            .map_err(|_| Error::Invalid)?,
        );
        // Ignore admission receipt; independently look up the full bound status.
        self.call("", Some(&body))?.ok_or(Error::Service)?;
        Ok(())
    }
    fn complete(&mut self, lease_id: &str) -> Result<()> {
        if !id(lease_id) {
            return Err(Error::Invalid);
        }
        let bytes = self
            .call(&format!("/{lease_id}/complete"), Some(b"{}"))?
            .ok_or(Error::Service)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Response {
            lease_id: String,
            cleanup: String,
        }
        let result: Response = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if result.lease_id != lease_id || result.cleanup != "pending" {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
