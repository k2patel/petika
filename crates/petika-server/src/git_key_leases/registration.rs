use super::*;
use petika_core::device_keys::{GitLeaseChallenge, GitLeaseProof, TrustedDeviceRoster};
#[derive(Debug)]
pub(crate) struct OperationConflict;
impl std::fmt::Display for OperationConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Lease operation conflict")
    }
}
impl std::error::Error for OperationConflict {}
impl LeaseStore {
    pub(crate) fn prepare_authorization(
        &self,
        mut challenge: GitLeaseChallenge,
        repository: Repository,
    ) -> Result<GitLeaseChallenge> {
        challenge.canonical_bytes()?;
        let ledger = self.read()?;
        if let Some(lease) = ledger.leases.iter().find(|l| {
            l.authorization.as_ref().is_some_and(|a| {
                a.operation_id == challenge.operation_id && a.session_id == challenge.session_id
            })
        }) {
            let saved = lease
                .authorization
                .as_ref()
                .ok_or("Missing authorization")?;
            if matches!(lease.state, State::Revoking | State::Removed)
                || challenge.lease_expires_at - challenge.issued_at
                    != saved.lease_expires_at - saved.issued_at
            {
                return Err(OperationConflict.into());
            }
            challenge.lease_id = saved.lease_id.clone();
            challenge.issued_at = saved.issued_at;
            challenge.challenge_expires_at = saved.challenge_expires_at;
            challenge.lease_expires_at = saved.lease_expires_at;
            if &challenge != saved || lease.repository != repository {
                return Err(OperationConflict.into());
            }
            return Ok(saved.clone());
        }
        let fingerprint = challenge.ssh_fingerprint()?;
        if ledger
            .leases
            .iter()
            .any(|lease| lease.repository == repository && lease.fingerprint == fingerprint)
        {
            return Err(OperationConflict.into());
        }
        let lease = self.prepare(
            repository,
            &challenge.device_id,
            &challenge.session_id,
            &challenge.ssh_fingerprint()?,
            challenge.issued_at,
            challenge.lease_expires_at - challenge.issued_at,
        )?;
        challenge.lease_id = lease.id.clone();
        let mut ledger = self.read()?;
        let saved = ledger
            .leases
            .iter_mut()
            .find(|l| l.id == lease.id)
            .ok_or("Lease missing")?;
        saved.authorization = Some(challenge.clone());
        self.save(&ledger)?;
        Ok(challenge)
    }
    /// A verified proof reserves the only create attempt durably BEFORE the host POST.
    /// After an uncertain POST, an empty inventory never authorizes another create.
    pub(crate) fn register(
        &self,
        proof: &GitLeaseProof,
        current: &TrustedDeviceRoster,
        session: &str,
        now: u64,
        host: &mut impl KeyRegistrar,
    ) -> Result<Lease> {
        proof.verify(current, now)?;
        let mut ledger = self.read()?;
        let index = ledger
            .leases
            .iter()
            .position(|l| l.id == proof.challenge.lease_id)
            .ok_or("Lease not found")?;
        let lease = &ledger.leases[index];
        if lease.authorization.as_ref() != Some(&proof.challenge)
            || lease.session != session
            || matches!(lease.state, State::Revoking | State::Removed)
            || lease.expires_at <= now
        {
            return Err("Lease authorization conflict".into());
        }
        let keys =
            inventory(host, &lease.repository).map_err(|_| "Git key inventory unavailable")?;
        let owned: Vec<_> = keys.iter().filter(|k| k.marker == lease.marker()).collect();
        if owned.iter().any(|k| k.fingerprint != lease.fingerprint) {
            return Err("Key ownership mismatch".into());
        }
        if !owned.is_empty() {
            if owned.len() != 1 || owned[0].read_only != Some(proof.challenge.read_only) {
                ledger.leases[index].state = State::Revoking;
                self.save(&ledger)?;
                return Err("Key permission or duplication mismatch; cleanup queued".into());
            }
            ledger.leases[index].state = State::Active;
            ledger.leases[index].last_error = None;
            self.save(&ledger)?;
            return Ok(ledger.leases[index].clone());
        }
        if lease.state != State::PendingRegistration {
            return Err("Registration outcome uncertain or key absent; reconcile or cancel".into());
        }
        ledger.leases[index].state = State::Registering;
        self.save(&ledger)?;
        let lease = &ledger.leases[index];
        let result = host.create(
            &lease.repository,
            &lease.marker(),
            &proof.challenge.openssh_public_key()?,
            proof.challenge.read_only,
        );
        // A failed/malformed response may still mean the key was created. Never reset to pending.
        if result.is_err() {
            ledger.leases[index].last_error = Some(Failure::Registration);
            self.save(&ledger)?;
            return Err("Registration outcome uncertain; reconcile or cancel".into());
        }
        let keys = inventory(host, &lease.repository)
            .map_err(|_| "Registration acknowledgement needs reconciliation")?;
        let matches: Vec<_> = keys.iter().filter(|k| k.marker == lease.marker()).collect();
        if matches.len() != 1
            || matches[0].fingerprint != lease.fingerprint
            || matches[0].read_only != Some(proof.challenge.read_only)
        {
            ledger.leases[index].state = State::Revoking;
            self.save(&ledger)?;
            return Err("Registration mismatch; cleanup queued".into());
        }
        ledger.leases[index].state = State::Active;
        ledger.leases[index].last_error = None;
        self.save(&ledger)?;
        Ok(ledger.leases[index].clone())
    }
}

#[cfg(test)]
pub(crate) mod tests;
