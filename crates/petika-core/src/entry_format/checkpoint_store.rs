//! Native local trust state. The protected local filesystem is a trust boundary;
//! restoring an older local file requires an independent freshness anchor.
use super::{
    checkpoint::{Checkpoint, Transition, TrustedCheckpoint},
    index::{Head, VerifiedIndex},
    *,
};
use crate::StoreFile;
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    checkpoint: Checkpoint,
    head: Head,
}
/// Exclusive lock is retained for the entire read/verify/update transaction.
/// Only public metadata is persisted, never index names or usable vault keys.
pub struct CheckpointStore {
    file: StoreFile,
}
impl CheckpointStore {
    pub fn lock(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            file: StoreFile::lock(path)?,
        })
    }
    pub fn initialize(&self, trusted: &TrustedCheckpoint, index: &VerifiedIndex) -> Result<()> {
        index.matches_checkpoint(trusted)?;
        self.save(trusted, index, true)
    }
    fn read(&self, expected: &Context) -> Result<Record> {
        let record: Record = serde_json::from_slice(&self.file.read_limited(32 * 1024)?)
            .map_err(|_| Error::Format)?;
        record.checkpoint.verify()?;
        record.head.digest()?;
        let cp = &record.checkpoint;
        if record.version != 1
            || &record.head.context != expected
            || cp.context != record.head.context
            || cp.data_suite != record.head.suite
            || record.head.revision < cp.head_revision
            || record.head.membership_generation != cp.membership_generation
            || record.head.wrapper_set_digest != cp.wrapper_set_digest
            || (record.head.revision == cp.head_revision && record.head.digest()? != cp.head_digest)
        {
            return Err(Error::Authentication);
        }
        Ok(record)
    }
    /// Loads an already initialized local pin; never bootstraps from network data.
    pub fn trusted(&self, expected: &Context) -> Result<TrustedCheckpoint> {
        let cp = self.read(expected)?.checkpoint;
        let digest = cp.digest()?;
        let fingerprint = cp.authority.fingerprint.clone();
        TrustedCheckpoint::bootstrap(cp, &digest, &fingerprint)
    }
    pub fn head(&self, expected: &Context) -> Result<Head> {
        Ok(self.read(expected)?.head)
    }
    pub fn observe(&self, previous: &VerifiedIndex, next: &VerifiedIndex) -> Result<()> {
        let record = self.read(&previous.head().context)?;
        if record.head != *previous.head() {
            return Err(Error::Authentication);
        }
        next.follows(previous)?;
        let trusted = self.trusted(&previous.head().context)?;
        self.save(&trusted, next, false)
    }
    /// Epoch changes require an authorized proof and a decrypted new checkpoint
    /// head, while the revision floor comes exclusively from the locked local file.
    pub fn advance(
        &self,
        expected: &Context,
        transition: &Transition,
        next: &VerifiedIndex,
    ) -> Result<()> {
        let record = self.read(expected)?;
        let trusted = self
            .trusted(expected)?
            .advance(transition, record.head.revision)?;
        next.matches_checkpoint(&trusted)?;
        self.save(&trusted, next, false)
    }
    fn save(&self, trusted: &TrustedCheckpoint, index: &VerifiedIndex, create: bool) -> Result<()> {
        let bytes = serde_json::to_vec(&Record {
            version: 1,
            checkpoint: trusted.checkpoint().clone(),
            head: index.head().clone(),
        })
        .map_err(|_| Error::Format)?;
        if bytes.len() > 32 * 1024 {
            return Err(Error::Format);
        }
        self.file.write(&bytes, create)
    }
}
