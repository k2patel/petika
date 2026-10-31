//! RFC 9987 sections 5.2.3/5.2.7: one constrained Ed25519 key in a new agent.
use super::*;
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub(super) struct Agent {
    child: Child,
    _directory: tempfile::TempDir,
    socket: PathBuf,
}
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The TempDir outlives agent termination and removes the private socket.
    }
}
fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
impl Agent {
    pub(super) fn start(seed: &[u8; 32], ttl: u64) -> Result<Self> {
        if ttl == 0 || ttl > 3600 {
            return Err(Error::Expired);
        }
        // Short fixed base avoids Unix-domain socket path limits on macOS.
        let directory = tempfile::Builder::new()
            .prefix("petika-agent-")
            .tempdir_in("/private/tmp")
            .or_else(|_| tempfile::tempdir())
            .map_err(|_| Error::Agent)?;
        let socket = directory.path().join("agent");
        let child = Command::new("/usr/bin/ssh-agent")
            .args(["-D", "-a"])
            .arg(&socket)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Agent)?;
        let mut agent = Self {
            child,
            _directory: directory,
            socket,
        };
        let started = Instant::now();
        let deadline = started + Duration::from_secs(2);
        let mut stream = loop {
            if let Ok(stream) = UnixStream::connect(&agent.socket) {
                break stream;
            }
            if Instant::now() >= deadline
                || agent.child.try_wait().map_err(|_| Error::Agent)?.is_some()
            {
                return Err(Error::Agent);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| Error::Agent)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| Error::Agent)?;
        let ttl = ttl.saturating_sub(started.elapsed().as_secs().saturating_add(1));
        if ttl == 0 {
            return Err(Error::Expired);
        }
        let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        let mut private = Zeroizing::new(Vec::with_capacity(64));
        private.extend_from_slice(seed);
        private.extend_from_slice(&public);
        // Reserve enough space once so a realloc cannot leave unwiped seed data.
        let mut packet = Zeroizing::new(Vec::with_capacity(256));
        packet.push(25); // SSH_AGENTC_ADD_ID_CONSTRAINED
        field(&mut packet, b"ssh-ed25519");
        field(&mut packet, &public);
        field(&mut packet, &private);
        field(&mut packet, b"Petika temporary transport");
        packet.push(1); // SSH_AGENT_CONSTRAIN_LIFETIME
        packet.extend_from_slice(&(ttl as u32).to_be_bytes());
        stream
            .write_all(&(packet.len() as u32).to_be_bytes())
            .map_err(|_| Error::Agent)?;
        stream.write_all(&packet).map_err(|_| Error::Agent)?;
        let mut reply = [0; 5];
        stream.read_exact(&mut reply).map_err(|_| Error::Agent)?;
        if reply != [0, 0, 0, 1, 6] {
            return Err(Error::Agent);
        }
        Ok(agent)
    }
    pub(super) fn socket(&self) -> &Path {
        &self.socket
    }
}
