//! SSH-only fetch into a new disposable bare repository. A pinned SSH host does
//! not authenticate a vault publication; callers must verify signed history next.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedRemote {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Exact owner/repo matching the lease; this candidate uses /owner/repo.git.
    pub repository: String,
    /// Independently verified canonical `ssh-ed25519 <base64-wire>`; no TOFU.
    pub host_key: String,
}
fn repository(value: &str) -> bool {
    value.len() <= 256
        && value.split('/').count() == 2
        && value.split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}
impl PinnedRemote {
    pub fn validate(&self, expected_repository: &str) -> Result<()> {
        let host_ok = self.host.parse::<std::net::IpAddr>().is_ok()
            || (self.host.len() <= 253
                && self.host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }));
        if !host_ok
            || self.port == 0
            || self.username.is_empty()
            || self.username.len() > 64
            || self.username.starts_with('-')
            || !self
                .username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || !repository(&self.repository)
            || self.repository != expected_repository
        {
            return Err(Error::Invalid);
        }
        let b64 = self
            .host_key
            .strip_prefix("ssh-ed25519 ")
            .ok_or(Error::Invalid)?;
        let bytes = STANDARD.decode(b64).map_err(|_| Error::Invalid)?;
        if STANDARD.encode(&bytes) != b64
            || bytes.len() != 51
            || &bytes[..19] != b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
        {
            return Err(Error::Invalid);
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            bytes[19..].try_into().map_err(|_| Error::Invalid)?,
        )
        .map_err(|_| Error::Invalid)?;
        if key.is_weak() {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    #[cfg(unix)]
    fn url(&self) -> String {
        let host = if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!(
            "ssh://{}@{}:{}/{}.git",
            self.username, host, self.port, self.repository
        )
    }
}
#[cfg(any(unix, test))]
fn branch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && !value.starts_with('-')
        && !value.contains("..")
        && value.split('/').all(|p| {
            !p.is_empty() && !p.starts_with('.') && !p.ends_with('.') && !p.ends_with(".lock")
        })
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
}
#[cfg(unix)]
mod native;
#[cfg(unix)]
pub use native::FetchedGit;

#[cfg(unix)]
impl<C: DraftCustody> Operation<C> {
    /// Only a previously retained endpoint can be used. Results remain untrusted
    /// until the application verifies its independent signed-history/epoch pins.
    /// This method never checks out files, decrypts, merges, or publishes.
    pub fn fetch(
        &mut self,
        service: &mut impl LeaseService,
        now: u64,
        branch_name: &str,
    ) -> Result<FetchedGit> {
        self.usable()?;
        let remote = self
            .intent()
            .scope
            .ssh_remote
            .clone()
            .ok_or(Error::Invalid)?;
        remote.validate(&self.intent().scope.repository)?;
        if !branch(branch_name) {
            return Err(Error::Invalid);
        }
        let started = std::time::Instant::now();
        let expires_at = self
            .draft
            .challenge
            .as_ref()
            .ok_or(Error::Phase)?
            .lease_expires_at;
        self.transfer(service, now, |socket, public| {
            let remaining = expires_at
                .saturating_sub(now)
                .saturating_sub(started.elapsed().as_secs().saturating_add(2));
            if remaining == 0 {
                return Err(Error::Expired);
            }
            native::fetch(
                remote,
                branch_name,
                socket,
                public,
                std::time::Duration::from_secs(remaining.min(30)),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pin() -> PinnedRemote {
        let public = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
        let mut wire = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        wire.extend_from_slice(&public);
        PinnedRemote {
            host: "git.example".into(),
            port: 2222,
            username: "git".into(),
            repository: "synthetic/vault".into(),
            host_key: format!("ssh-ed25519 {}", STANDARD.encode(wire)),
        }
    }
    #[test]
    fn retained_endpoint_and_host_pin_reject_ambiguous_or_injected_values() {
        let base = pin();
        base.validate("synthetic/vault").unwrap();
        let mut ip = base.clone();
        ip.host = "::1".into();
        ip.validate("synthetic/vault").unwrap();
        assert!(base.validate("other/vault").is_err());
        for host in [
            "-proxy",
            "git.example/extra",
            "evil\nHost *",
            "git.example%0a",
            "user@host",
            "[::1]",
        ] {
            let mut p = base.clone();
            p.host = host.into();
            assert!(p.validate("synthetic/vault").is_err());
        }
        for user in ["-oProxyCommand=evil", "user\nroot", "user@host"] {
            let mut p = base.clone();
            p.username = user.into();
            assert!(p.validate("synthetic/vault").is_err());
        }
        for key in [
            format!("{} comment", base.host_key),
            format!("{}\n", base.host_key),
            "ssh-rsa AAAA".into(),
            "ssh-ed25519 AA==".into(),
        ] {
            let mut p = base.clone();
            p.host_key = key;
            assert!(p.validate("synthetic/vault").is_err());
        }
        for name in [
            "",
            "-option",
            "../main",
            "main.lock",
            "heads//main",
            "a@{b}",
            "a:refs/heads/other",
            "main\nrefs/heads/other",
        ] {
            assert!(!branch(name));
        }
        assert!(branch("vault/main-v1"));
    }
}
