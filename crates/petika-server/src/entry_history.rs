//! Bounded page construction for committed entry history.
//! Call only after collection authorization, under a stable journal read view.
use petika_core::{
    Error, Result,
    entry_format::{
        history::MAX_HISTORY_BYTES,
        transport::{Cursor, HistoryObject, HistoryPage, HistoryRequest},
    },
};

/// `read` must return committed records only, including the requested base and
/// pinned target. A missing/pruned record fails closed; never skip a revision.
pub fn build_page(
    request: &HistoryRequest,
    current: Cursor,
    mut read: impl FnMut(u64) -> Result<HistoryObject>,
) -> Result<Vec<u8>> {
    request.validate()?;
    HistoryRequest {
        target: Some(current.clone()),
        ..request.clone()
    }
    .validate()?;
    let target = request.target.clone().unwrap_or(current.clone());
    if target.revision > current.revision {
        return Err(Error::Authentication);
    }
    for cursor in [&request.after, &target, &current] {
        let object = read(cursor.revision)?;
        if object.head.context != request.context || Cursor::from_head(&object.head)? != *cursor {
            return Err(Error::Authentication);
        }
    }
    let mut page = HistoryPage {
        version: 1,
        context: request.context.clone(),
        after: request.after.clone(),
        target,
        items: vec![],
    };
    let mut size = 0usize;
    for revision in request.after.revision + 1..=page.target.revision {
        if page.items.len() == request.limit {
            break;
        }
        let item = read(revision)?;
        let next_size = size.checked_add(item.size()?).ok_or(Error::Format)?;
        if next_size > MAX_HISTORY_BYTES {
            break;
        }
        size = next_size;
        page.items.push(item);
    }
    page.encode(request)
}
