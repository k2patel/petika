//! Bounded, same-epoch catch-up. Transport must enforce its own body-size limit
//! before allocating responses; these limits also apply to already decoded input.
use super::{
    index::{Head, VerifiedIndex},
    *,
};

pub const MAX_HISTORY_HEADS: usize = 32;
pub const MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;
/// Borrowed transport objects; no implicit fetching, skipping, or epoch changes.
pub struct HistoryItem<'a> {
    pub head: &'a Head,
    pub envelope: &'a [u8],
}
/// Verify the entire page before returning its final index. Any failure discards
/// progress. The previous index must match a local pin before accepting the result.
pub fn verify_page(
    root: &RootKey,
    previous: &VerifiedIndex,
    items: &[HistoryItem<'_>],
) -> Result<VerifiedIndex> {
    if items.is_empty() || items.len() > MAX_HISTORY_HEADS {
        return Err(Error::Format);
    }
    let mut total = 0usize;
    for item in items {
        item.head.digest()?;
        let head_bytes = serde_json::to_vec(item.head).map_err(|_| Error::Format)?;
        total = total
            .checked_add(head_bytes.len())
            .and_then(|n| n.checked_add(item.envelope.len()))
            .ok_or(Error::Format)?;
        if total > MAX_HISTORY_BYTES {
            return Err(Error::Format);
        }
    }
    let mut accepted: Option<VerifiedIndex> = None;
    for item in items {
        let next = VerifiedIndex::open(root, item.head.clone(), item.envelope)?;
        next.follows(accepted.as_ref().unwrap_or(previous))?;
        accepted = Some(next);
    }
    accepted.ok_or(Error::Format)
}
