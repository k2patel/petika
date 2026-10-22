//! Read-only recovery evidence comparison; never authorizes replay or trust reset.
use petika_core::entry_format::transport::Cursor;
use petika_server::{Result, entry_journal::Journal};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    version: u32,
    deployment_id: String,
    collections: Vec<Head>,
    verification: String,
}
#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Head {
    collection_id: String,
    accepted: Cursor,
    checkpoint_digest: String,
    epoch: u64,
}
fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn parse(value: Value) -> Result<Report> {
    let report: Report = serde_json::from_value(value)?;
    let mut seen = std::collections::BTreeSet::new();
    if report.version != 1
        || !id(&report.deployment_id)
        || report.verification
            != "structural-only; compare retained client pins and decrypt separately"
        || report.collections.len() > 10000
        || report.collections.iter().any(|head| {
            !id(&head.collection_id)
                || !id(&head.accepted.digest)
                || !id(&head.checkpoint_digest)
                || head.accepted.revision == 0
                || head.epoch == 0
                || !seen.insert(&head.collection_id)
        })
    {
        return Err("invalid retained report".into());
    }
    Ok(report)
}
pub(super) fn compare(data: &Path, current: Value, retained: Value) -> Result<(Value, bool)> {
    let current = parse(current)?;
    let retained = parse(retained)?;
    if current.deployment_id != retained.deployment_id {
        return Err("reports belong to different deployments".into());
    }
    let mut rows = BTreeMap::new();
    for head in &current.collections {
        rows.insert(head.collection_id.as_str(), (Some(head), None));
    }
    for head in &retained.collections {
        rows.entry(&head.collection_id).or_insert((None, None)).1 = Some(head);
    }
    let mut exact = true;
    let mut output = Vec::new();
    for (collection, (local, external)) in rows {
        let (status, action) = match (local, external) {
            (Some(a), Some(b)) if a == b => ("matches", "verify-client-pins-and-decrypt"),
            (None, Some(_)) => (
                "missing-collection",
                "locate-complete-backup-containing-retained-head",
            ),
            (Some(_), None) => (
                "not-in-retained-report",
                "obtain-independent-evidence-for-collection",
            ),
            (Some(a), Some(b)) if a.accepted.revision < b.accepted.revision => (
                "newer-retained-head",
                "locate-newer-complete-journal-and-receipts; never-reset-client-pins",
            ),
            (Some(a), Some(b)) if a.accepted.revision > b.accepted.revision => {
                let journal =
                    Journal::open(data.join("collections").join(collection).join("entries"))?;
                let (object, _) = journal.committed_tree(b.accepted.revision)?;
                let cursor = Cursor::from_head(&object.head)?;
                let epoch = journal
                    .epoch_state(&cursor)?
                    .ok_or("missing historical epoch")?;
                if cursor == b.accepted
                    && epoch.checkpoint.digest()? == b.checkpoint_digest
                    && epoch.checkpoint.context.key_epoch == b.epoch
                {
                    (
                        "retained-head-in-local-history",
                        "verify-newer-client-evidence-and-decrypt; do-not-roll-back",
                    )
                } else {
                    (
                        "conflicting-history",
                        "isolate-both-copies; never-merge-or-force-push",
                    )
                }
            }
            (Some(_), Some(_)) => (
                "conflicting-history",
                "isolate-both-copies; never-merge-or-force-push",
            ),
            (None, None) => unreachable!(),
        };
        exact &= status == "matches";
        output.push(json!({"collection_id":collection,"status":status,"action":action,
            "local":local.map(|h| json!({"accepted":h.accepted,"epoch":h.epoch,"checkpoint_digest":h.checkpoint_digest})),
            "retained":external.map(|h| json!({"accepted":h.accepted,"epoch":h.epoch,"checkpoint_digest":h.checkpoint_digest}))}));
    }
    Ok((
        json!({"version":1,"deployment_id":current.deployment_id,"exact_match":exact,
        "requires_reconciliation":!exact,"collections":output,
        "verification":"structural-history-only; compare protected client pins and decrypt separately",
        "mutations":"none; no replay, merge, pin reset or start authorization"}),
        exact,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn report() -> Value {
        json!({"version":1,"deployment_id":"a".repeat(64),"collections":[{
            "collection_id":"b".repeat(64),"accepted":{"revision":2,"digest":"c".repeat(64)},
            "checkpoint_digest":"d".repeat(64),"epoch":1}],
            "verification":"structural-only; compare retained client pins and decrypt separately"})
    }
    #[test]
    fn comparison_rejects_ambiguous_evidence_and_classifies_without_trust_reset() {
        let original = report();
        let (_, exact) = compare(Path::new("unused"), original.clone(), original.clone()).unwrap();
        assert!(exact);
        let mut newer = original.clone();
        newer["collections"][0]["accepted"]["revision"] = json!(3);
        let (result, exact) = compare(Path::new("unused"), original.clone(), newer).unwrap();
        assert!(!exact);
        assert_eq!(result["collections"][0]["status"], "newer-retained-head");
        let mut conflict = original.clone();
        conflict["collections"][0]["accepted"]["digest"] = json!("e".repeat(64));
        assert_eq!(
            compare(Path::new("unused"), original.clone(), conflict)
                .unwrap()
                .0["collections"][0]["status"],
            "conflicting-history"
        );
        for alteration in ["duplicate", "deployment", "unknown", "path", "epoch"] {
            let mut bad = original.clone();
            match alteration {
                "duplicate" => {
                    let head = bad["collections"][0].clone();
                    bad["collections"].as_array_mut().unwrap().push(head);
                }
                "deployment" => bad["deployment_id"] = json!("e".repeat(64)),
                "unknown" => bad["unexpected"] = json!(true),
                "path" => bad["collections"][0]["collection_id"] = json!("../elsewhere"),
                _ => bad["collections"][0]["epoch"] = json!(0),
            }
            assert!(compare(Path::new("unused"), original.clone(), bad).is_err());
        }
    }
}
