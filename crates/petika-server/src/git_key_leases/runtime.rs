//! Durable event handoff. No account lock is held across host network requests.
use super::*;
use std::{
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Event {
    session: Option<String>,
    device: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Events {
    version: u32,
    pending: Vec<Event>,
}
fn events(data: &Path) -> PathBuf {
    data.join("git-key-events.json")
}
fn ledger(data: &Path) -> PathBuf {
    data.join("git-key-leases.json")
}
fn read_events(file: &StoreFile) -> Result<Events> {
    if !file.exists() {
        return Ok(Events {
            version: 1,
            pending: vec![],
        });
    }
    let value: Events = serde_json::from_slice(&file.read_limited(1024 * 1024)?)?;
    if value.version != 1
        || value.pending.len() > 4096
        || value.pending.iter().any(|e| match (&e.session, &e.device) {
            (Some(id), None) | (None, Some(id)) => !hex(id),
            _ => true,
        })
    {
        return Err("Invalid cleanup events".into());
    }
    Ok(value)
}
pub fn enqueue_session(data: &Path, id: &str) -> Result<()> {
    enqueue(data, Some(id), None)
}
/// Called by future cryptographic device-removal admission; caller must authorize ID.
pub fn enqueue_device(data: &Path, id: &str) -> Result<()> {
    enqueue(data, None, Some(id))
}
fn enqueue(data: &Path, session: Option<&str>, device: Option<&str>) -> Result<()> {
    let id = session.or(device).ok_or("Missing cleanup selector")?;
    if !hex(id) {
        return Err("Invalid cleanup selector".into());
    }
    let file = StoreFile::lock(events(data))?;
    let mut queue = read_events(&file)?;
    let event = Event {
        session: session.map(String::from),
        device: device.map(String::from),
    };
    if queue.pending.contains(&event) {
        return Ok(());
    }
    if queue.pending.len() == 4096 {
        return Err("Cleanup event queue full".into());
    }
    queue.pending.push(event);
    file.write(&serde_json::to_vec(&queue)?, false)?;
    Ok(())
}
pub(super) fn drain(data: &Path, store: &LeaseStore) -> Result<()> {
    let file = StoreFile::lock(events(data))?;
    let mut queue = read_events(&file)?;
    let selectors: Vec<_> = queue
        .pending
        .iter()
        .take(128)
        .map(
            |event| match (event.session.as_deref(), event.device.as_deref()) {
                (Some(id), None) => Ok(Cleanup::Session(id)),
                (None, Some(id)) => Ok(Cleanup::Device(id)),
                _ => Err("Invalid cleanup event"),
            },
        )
        .collect::<std::result::Result<_, _>>()?;
    store.request_cleanups(&selectors)?;
    queue.pending.drain(..queue.pending.len().min(128));
    file.write(&serde_json::to_vec(&queue)?, false)?;
    Ok(())
}
/// One bounded worker pass. Reload credentials on each pass for rotation/revocation.
pub fn tick(data: &Path, configuration: &Path, now: u64) -> Result<()> {
    let store = LeaseStore::lock(ledger(data))?;
    drain(data, &store)?;
    let mut host = ConfiguredHosts::load(configuration)?;
    store.sweep_batch(now, &mut host, 32)?;
    if store
        .leases()?
        .iter()
        .any(|lease| lease.last_error.is_some())
    {
        return Err("Remote Git key cleanup remains pending".into());
    }
    Ok(())
}
fn worker_claim(data: &Path) -> Result<StoreFile> {
    Ok(StoreFile::lock(data.join("git-key-worker.json"))?)
}
fn startup_cleanup(data: &Path) -> Result<()> {
    LeaseStore::lock(ledger(data))?.request_cleanup(Cleanup::All)?;
    Ok(())
}
pub fn start_worker(
    data: PathBuf,
    gate: Arc<crate::maintenance_gate::MaintenanceGate>,
) -> Result<()> {
    if std::env::var("PETIKA_EXPERIMENTAL_GIT_KEY_LEASES").as_deref() != Ok("1") {
        return Ok(());
    }
    let configuration = std::env::var_os("PETIKA_GIT_KEY_HOSTS_FILE")
        .ok_or("Git key host configuration required")?;
    let configuration = PathBuf::from(configuration);
    // Validate before starting. Account sessions are process-local: old leases must not survive restart.
    drop(ConfiguredHosts::load(&configuration)?);
    let worker_guard = worker_claim(&data)?;
    startup_cleanup(&data)?;
    thread::Builder::new()
        .name("petika-key-cleanup".into())
        .spawn(move || {
            let _worker_guard = worker_guard;
            loop {
                match gate.operation() {
                    Ok(_guard) => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs());
                        if now
                            .ok()
                            .and_then(|now| tick(&data, &configuration, now).ok())
                            .is_none()
                        {
                            eprintln!("Git key cleanup pending: retry required");
                        }
                    }
                    Err(_) => { /* Capture in progress: durable events remain queued. */ }
                }
                thread::sleep(Duration::from_secs(5));
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests;
