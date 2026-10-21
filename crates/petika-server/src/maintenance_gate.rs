//! Serialize local API/mirror work, but reserve immediate busy responses for
//! exclusive backup capture. Routine mirror work must not cause HTTP 503.
use std::sync::{
    LockResult, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError,
};

#[derive(Default)]
pub struct MaintenanceGate {
    capture: RwLock<()>,
    operations: Mutex<()>,
}
#[derive(Debug)]
pub enum GateError {
    Capturing,
    Poisoned,
}
pub struct OperationGuard<'a> {
    _operation: MutexGuard<'a, ()>,
    _capture: RwLockReadGuard<'a, ()>,
}
impl MaintenanceGate {
    pub fn operation(&self) -> Result<OperationGuard<'_>, GateError> {
        let capture = match self.capture.try_read() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(GateError::Capturing),
            Err(TryLockError::Poisoned(_)) => return Err(GateError::Poisoned),
        };
        // StoreFile uses nonblocking exclusive locks, so API and local mirror
        // operations still serialize. No network transfer belongs in this guard.
        let operation = self.operations.lock().map_err(|_| GateError::Poisoned)?;
        Ok(OperationGuard {
            _operation: operation,
            _capture: capture,
        })
    }
    pub fn capture(&self) -> LockResult<RwLockWriteGuard<'_, ()>> {
        self.capture.write()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;
    #[test]
    fn mirror_contention_waits_but_backup_capture_rejects_operations() {
        let gate = Arc::new(MaintenanceGate::default());
        let mirror = gate.operation().unwrap();
        let other = gate.clone();
        let (sent, received) = mpsc::channel();
        let request = std::thread::spawn(move || {
            let result = other.operation();
            sent.send(result.is_ok()).unwrap();
        });
        assert!(received.recv_timeout(Duration::from_millis(30)).is_err());
        drop(mirror);
        assert!(received.recv_timeout(Duration::from_secs(5)).unwrap());
        request.join().unwrap();
        let capture = gate.capture().unwrap();
        assert!(matches!(gate.operation(), Err(GateError::Capturing)));
        drop(capture);
        assert!(gate.operation().is_ok());
    }
}
