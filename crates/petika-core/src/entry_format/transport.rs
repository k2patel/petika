//! Experimental history wire contract; server metadata never establishes trust.
use super::{
    history::{HistoryItem, MAX_HISTORY_BYTES, MAX_HISTORY_HEADS},
    index::{Head, VerifiedIndex},
    *,
};
pub const MAX_HISTORY_WIRE_BYTES: usize = 32 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub revision: u64,
    pub digest: String,
}
impl Cursor {
    pub fn from_head(head: &Head) -> Result<Self> {
        Ok(Self {
            revision: head.revision,
            digest: head.digest()?,
        })
    }
    fn validate(&self) -> Result<()> {
        if !counter(self.revision) || !id(&self.digest) {
            return Err(Error::Format);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRequest {
    pub version: u32,
    pub context: Context,
    pub after: Cursor,
    /// First request may omit this; subsequent pages pin the returned target.
    pub target: Option<Cursor>,
    pub limit: usize,
}
impl HistoryRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err(Error::Format);
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        request.validate()?;
        Ok(request)
    }
    pub fn validate(&self) -> Result<()> {
        self.context.validate()?;
        self.after.validate()?;
        if self.version != 1 || self.limit == 0 || self.limit > MAX_HISTORY_HEADS {
            return Err(Error::Format);
        }
        if let Some(target) = &self.target {
            target.validate()?;
            if target.revision < self.after.revision
                || (target.revision == self.after.revision && target != &self.after)
            {
                return Err(Error::Authentication);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryObject {
    pub head: Head,
    pub envelope: String,
}
impl HistoryObject {
    pub fn size(&self) -> Result<usize> {
        self.head.digest()?;
        serde_json::to_vec(&self.head)
            .map_err(|_| Error::Format)?
            .len()
            .checked_add(self.envelope.len())
            .ok_or(Error::Format)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPage {
    pub version: u32,
    pub context: Context,
    pub after: Cursor,
    pub target: Cursor,
    pub items: Vec<HistoryObject>,
}
impl HistoryPage {
    pub fn parse(bytes: &[u8], request: &HistoryRequest) -> Result<Self> {
        if bytes.len() > MAX_HISTORY_WIRE_BYTES {
            return Err(Error::Format);
        }
        let page: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        page.validate(request)?;
        Ok(page)
    }
    pub fn encode(&self, request: &HistoryRequest) -> Result<Vec<u8>> {
        self.validate(request)?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Format)?;
        if bytes.len() > MAX_HISTORY_WIRE_BYTES {
            return Err(Error::Format);
        }
        Ok(bytes)
    }
    pub fn validate(&self, request: &HistoryRequest) -> Result<()> {
        request.validate()?;
        self.target.validate()?;
        if self.version != 1
            || self.context != request.context
            || self.after != request.after
            || self.items.len() > request.limit
            || self.target.revision < self.after.revision
            || request.target.as_ref().is_some_and(|t| t != &self.target)
        {
            return Err(Error::Authentication);
        }
        let mut cursor = self.after.clone();
        let mut bytes = 0usize;
        for item in &self.items {
            bytes = bytes.checked_add(item.size()?).ok_or(Error::Format)?;
            if bytes > MAX_HISTORY_BYTES
                || item.head.context != self.context
                || item.head.revision != cursor.revision + 1
                || item.head.parent_digest != cursor.digest
                || item.head.revision > self.target.revision
                || hex(&digest(item.envelope.as_bytes())) != item.head.index_digest
            {
                return Err(Error::Authentication);
            }
            cursor = Cursor::from_head(&item.head)?;
        }
        if (self.items.is_empty() || cursor.revision == self.target.revision)
            && cursor != self.target
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub fn next_request(&self, request: &HistoryRequest) -> Result<Option<HistoryRequest>> {
        self.validate(request)?;
        let after = match self.items.last() {
            Some(item) => Cursor::from_head(&item.head)?,
            None => self.after.clone(),
        };
        if after == self.target {
            return Ok(None);
        }
        Ok(Some(HistoryRequest {
            version: 1,
            context: self.context.clone(),
            after,
            target: Some(self.target.clone()),
            limit: request.limit,
        }))
    }
    pub(crate) fn borrowed(&self) -> Vec<HistoryItem<'_>> {
        self.items
            .iter()
            .map(|item| HistoryItem {
                head: &item.head,
                envelope: item.envelope.as_bytes(),
            })
            .collect()
    }
    /// Authenticates index contents only. Native clients should use the durable
    /// store adapter; WASM callers must persist their accepted pin separately.
    pub fn verify(
        &self,
        request: &HistoryRequest,
        root: &RootKey,
        previous: &VerifiedIndex,
    ) -> Result<Option<VerifiedIndex>> {
        self.validate(request)?;
        if Cursor::from_head(previous.head())? != self.after
            || previous.head().context != self.context
        {
            return Err(Error::Authentication);
        }
        previous.validate_root(root)?;
        if self.items.is_empty() {
            return Ok(None);
        }
        super::history::verify_page(root, previous, &self.borrowed()).map(Some)
    }
}
