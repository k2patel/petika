//! Native reference publication journal. No account/session authorization or network API.
use super::*;
use crate::StoreFile;
use std::{collections::BTreeSet, path::Path};

pub const MAX_ROSTER_PUBLICATIONS: usize = 128;
pub const MAX_ROSTER_JOURNAL_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    pub receipt_version: u32,
    pub operation_id: String,
    pub authority_fingerprint: String,
    pub previous_digest: String,
    pub roster_digest: String,
    pub generation: u64,
}
impl PublicationReceipt {
    fn from_publication(value: &Publication) -> Result<Self> {
        Ok(Self {
            receipt_version: 1,
            operation_id: value.operation_id.clone(),
            authority_fingerprint: value.roster.authority.fingerprint.clone(),
            previous_digest: value.roster.parent_digest.clone(),
            roster_digest: value.roster.digest()?,
            generation: value.roster.generation,
        })
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse(bytes, 2048)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if self.receipt_version != 1
            || !(2..=MAX_GENERATION).contains(&self.generation)
            || [
                &self.operation_id,
                &self.authority_fingerprint,
                &self.previous_digest,
                &self.roster_digest,
            ]
            .iter()
            .any(|s| !id(s))
        {
            return Err(Error::Format);
        }
        Ok(())
    }
    /// Checks correspondence to a retained signed candidate, not transport trust
    /// or proof that a remote server committed it. Authenticate transport separately.
    pub fn verify_candidate(&self, operation_id: &str, candidate: &DeviceRoster) -> Result<()> {
        self.validate()?;
        if !id(operation_id)
            || self.receipt_version != 1
            || self.operation_id != operation_id
            || self.authority_fingerprint != candidate.authority.fingerprint
            || self.previous_digest != candidate.parent_digest
            || self.roster_digest != candidate.digest()?
            || self.generation != candidate.generation
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    operation_id: String,
    roster: DeviceRoster,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    baseline: DeviceRoster,
    publications: Vec<Publication>,
}

/// Holds an exclusive file lock until drop. Public signed metadata only is stored,
/// with restrictive native file permissions. Retain the initialization anchor
/// independently; restoring an older complete journal cannot prove global freshness.
pub struct DeviceRosterJournal {
    file: StoreFile,
    authority_fingerprint: String,
    initial_digest: String,
}
impl DeviceRosterJournal {
    pub fn lock(
        path: impl AsRef<Path>,
        confirmed_authority_fingerprint: &str,
        confirmed_initial_digest: &str,
    ) -> Result<Self> {
        if !id(confirmed_authority_fingerprint) || !id(confirmed_initial_digest) {
            return Err(Error::Format);
        }
        Ok(Self {
            file: StoreFile::lock(path)?,
            authority_fingerprint: confirmed_authority_fingerprint.into(),
            initial_digest: confirmed_initial_digest.into(),
        })
    }
    /// Create-if-absent. An existing journal can never be silently reinitialized.
    pub fn initialize(&self, baseline: &TrustedDeviceRoster) -> Result<()> {
        TrustedDeviceRoster::bootstrap(
            baseline.roster().clone(),
            &self.authority_fingerprint,
            &self.initial_digest,
        )?;
        let record = Record {
            version: 1,
            baseline: baseline.roster().clone(),
            publications: vec![],
        };
        self.file.write(&Self::encode(&record)?, true)
    }
    fn encode(record: &Record) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(record).map_err(|_| Error::Format)?;
        if bytes.len() > MAX_ROSTER_JOURNAL_BYTES {
            return Err(Error::Format);
        }
        Ok(bytes)
    }
    fn read(&self) -> Result<(Record, TrustedDeviceRoster)> {
        let record: Record = parse(
            &self.file.read_limited(MAX_ROSTER_JOURNAL_BYTES)?,
            MAX_ROSTER_JOURNAL_BYTES,
        )?;
        if record.version != 1 || record.publications.len() > MAX_ROSTER_PUBLICATIONS {
            return Err(Error::Format);
        }
        let mut current = TrustedDeviceRoster::bootstrap(
            record.baseline.clone(),
            &self.authority_fingerprint,
            &self.initial_digest,
        )?;
        let mut operations = BTreeSet::new();
        for entry in &record.publications {
            if !id(&entry.operation_id)
                || !operations.insert(&entry.operation_id)
                || current.roster().generation.checked_add(1) != Some(entry.roster.generation)
            {
                return Err(Error::Authentication);
            }
            current.accept(entry.roster.clone())?;
        }
        Ok((record, current))
    }
    pub fn current(&self) -> Result<TrustedDeviceRoster> {
        Ok(self.read()?.1)
    }
    /// Adjacent history after a previously pinned digest, bounded to sixteen updates.
    /// Unknown or conflicting pins fail instead of returning a replacement baseline.
    pub fn successors(&self, after_digest: &str) -> Result<Vec<DeviceRoster>> {
        if !id(after_digest) {
            return Err(Error::Format);
        }
        let (record, _) = self.read()?;
        let start = if record.baseline.digest()? == after_digest {
            0
        } else {
            record
                .publications
                .iter()
                .position(|p| p.roster.digest().ok().as_deref() == Some(after_digest))
                .ok_or(Error::Authentication)?
                + 1
        };
        Ok(record
            .publications
            .into_iter()
            .skip(start)
            .take(16)
            .map(|p| p.roster)
            .collect())
    }
    /// None means absent from this verified retained journal, not global absence.
    pub fn lookup(&self, operation_id: &str) -> Result<Option<PublicationReceipt>> {
        if !id(operation_id) {
            return Err(Error::Format);
        }
        let (record, _) = self.read()?;
        record
            .publications
            .iter()
            .find(|p| p.operation_id == operation_id)
            .map(PublicationReceipt::from_publication)
            .transpose()
    }
    pub fn publish(
        &self,
        operation_id: &str,
        expected_parent: &str,
        candidate: &DeviceRoster,
    ) -> Result<PublicationReceipt> {
        self.publish_observed(operation_id, expected_parent, candidate, |_| Ok(()))
    }
    fn publish_observed(
        &self,
        operation_id: &str,
        expected_parent: &str,
        candidate: &DeviceRoster,
        boundary: impl FnMut(u8) -> Result<()>,
    ) -> Result<PublicationReceipt> {
        if !id(operation_id) || !id(expected_parent) {
            return Err(Error::Format);
        }
        candidate.validate()?;
        if candidate.parent_digest != expected_parent {
            return Err(Error::Authentication);
        }
        let (mut record, mut current) = self.read()?;
        // Exact retries reconcile before CAS, even after later accepted operations.
        if let Some(previous) = record
            .publications
            .iter()
            .find(|p| p.operation_id == operation_id)
        {
            let receipt = PublicationReceipt::from_publication(previous)?;
            receipt.verify_candidate(operation_id, candidate)?;
            return Ok(receipt);
        }
        if record.publications.len() == MAX_ROSTER_PUBLICATIONS {
            return Err(Error::Format);
        }
        if current.roster().digest()? != expected_parent
            || current.roster().generation.checked_add(1) != Some(candidate.generation)
        {
            return Err(Error::Authentication);
        }
        current.accept(candidate.clone())?;
        let publication = Publication {
            operation_id: operation_id.into(),
            roster: candidate.clone(),
        };
        let receipt = PublicationReceipt::from_publication(&publication)?;
        record.publications.push(publication);
        // One atomic replacement publishes both history and retry receipt. A failure
        // after replacement has an uncertain result; callers must lookup/retry.
        self.file
            .write_observed(&Self::encode(&record)?, false, boundary)?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests;
