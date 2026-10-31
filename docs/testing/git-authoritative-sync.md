# Git-authoritative sync acceptance plan

Date: 2026-10-31. Status: planned; rows below are not execution evidence.
Direction: [ADR 0006](../decisions/0006-git-authoritative-sync.md).
Use disposable synthetic vaults and private local remotes before actual host testing.

| Scenario | Required outcome |
| --- | --- |
| Online show/edit | Fetch and verify latest observed head before decrypting required data |
| One entry edited | Only changed entry and required metadata receive new ciphertext; unchanged blobs retain IDs |
| Password and key A / key B | Each independently authorized device key opens its own package for the same epoch secret |
| Password alone, unknown key, or wrong vault | No device enrollment shortcut, secret release or authorized publication |
| Shared vault | Account enrollment alone cannot mint a grant; independently verified authorized issuer required |
| Two writers at one base | Exactly one competing direct successor is accepted; stale submission cannot overwrite it |
| Conflict then retry | Encrypted user draft survives; fetch, user review/re-edit and fresh encryption precede resubmission |
| Repeated contention | Bounded attempts and actionable pending state; no endless automatic retry |
| Lost push reply / cancellation | Verified operation ID, candidate digest and ancestry reconcile accepted/absent/unknown outcome without duplicate edit |
| History tampering / missing parent / rollback | Verification fails or retained newer pin detects rollback; no silent trust reset |
| Deletes and old offline draft | Authenticated tombstone prevents resurrection; explicit review required |
| Credential expiration / revoked device | New online access/publication denied according to defined common authorization order |
| Key removal and rotation | Retained keys open fresh epoch; removed key fails on new epoch but historical access remains possible |
| Crash during cache/pin update | Restart retains a consistent verified pin and ciphertext; no plaintext draft persists |
| Offline or Git outage | Online show/edit reports refresh failure; explicit offline view identifies cached state; edits remain encrypted drafts |
| SSH / HTTPS / optional API | Real adapter tests establish atomic ref behavior, host identity verification, scope and expiry capabilities |
| Browser | Supported transport/gateway passes origin/CORS/auth tests; native SSH support is not assumed |
| Restore and cutover | Complete keys/pins/policy plus history restore; exactly one authority accepts writes after migration |

No production migration, platform compatibility, independent security review or power-loss
certification is implied by this plan. Existing test evidence remains scoped to existing
API, entry, device and journal implementations.
