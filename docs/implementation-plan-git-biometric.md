# Implementation plan: Git sync and mandatory per-action biometrics

> **Policy update, 2026-10-31:** Both browser passkey verification (biometric or OS PIN)
> and strict biometric-only protection are supported as explicit policy choices.
> The browser personal-vault implementation is described in [browser passkeys](browser-passkeys.md).
> Strict biometric-only creation remains blocked until a production provider exists.
> Earlier mandatory-biometric statements below apply to the strict policy; they do
> not describe the browser-passkey policy. Existing vaults are not auto-migrated.

Date: 2026-10-31. Status: work identified; no milestone below is complete.
Target: [ADR 0006](decisions/0006-git-authoritative-sync.md).
Validation: [acceptance scenarios](testing/git-authoritative-sync.md).
The current application continues to use API authority and outbound Git replication.
Changes stay experimental until explicit migration and validation.

## Browser-policy deliverable

Implemented separately from B01–B03: WebAuthn registration and fresh action ceremonies,
PRF-encrypted independent key wrappers, personal-vault framing and transient WASM
workers, add-key enrollment, encrypted conflict drafts and one-use CAS write grants.
The virtual-authenticator browser test covers two keys, UI controls and restart.
Hardware/browser-engine verification, strict provider, QR pairing, group support,
shared/recipient migration and key-removal rotation remain open.
[Legacy personal migration](passkey-migration.md) is implemented separately with fresh
encryption material, exact original backup and one-use CAS cutover. See [details](browser-passkeys.md).

## Existing foundations to reuse

| Foundation | Evidence / code | Actual boundary |
| --- | --- | --- |
| Local encryption and recipient packages | `crates/petika-core/src/identity.rs`, `identity/packages.rs` | Shared legacy user identity; not independent device package integration |
| Per-entry encryption, signed history and transactions | `crates/petika-core/src/entry_format`, [transport contract](research/entry-history-transport.md) | Gated API/journal authority, not direct Git authority |
| Drafts, receipts, conflict handling, Git replication | Entry CLI/server transaction and replication implementations | Reuse semantics, not old commit authority or automatic ciphertext rebase |
| Device records, roster and two-key enrollment proofs | `crates/petika-core/src/device_keys` | Experimental crypto/validation, no protected persistent client custody |
| Account device publication API | `crates/petika-server/src/accounts/device_keys.rs`, [API contract](device-account-api.md) | Bootstrap/additions/history/receipts; no device-bound sessions, QR relay or vault packages |
| Physical Touch ID capability | `experiments/biometric-unlock/apple.swift`, [evidence](testing/biometric-unlock-2026-10-31.json) | One ephemeral generated-data operation; not per-action or lifecycle enforcement |
| Browser PRF probe | `experiments/biometric-unlock/browser` | May authenticate with PIN; cannot establish strict biometric-only policy |

Passing older tests does not complete the new target's milestones. Legacy recovery R01–R08
remains complete within its original scope; these are new requirements.

## Ordered work packages

| ID | Work / deliverable | Depends on | Complete when |
| --- | --- | --- | --- |
| B01 | Specify exact secret actions, prompt scope, platform support and denial behavior; prove fresh per-use biometric-only key operation on this Mac | Existing probe | Two consecutive actions require two distinct successful biometric ceremonies; replay, cancellation, PIN fallback, context reuse, lockout and invalidation cases deny access; test gaps are recorded |
| B02 | Persistent device/authority custody adapter: protected key wrapper, scoped encrypted bundles, atomic save/reopen and recovery enrollment constraints | B01 | Restart reopens protected synthetic device identity; wrong origin/account/device, corrupt blob or biometric set change cannot unlock it; no reusable keys returned to UI |
| B03 | Native secret-operation broker: typed one-use actions, bounded plaintext lifetime, no unlocked-session key cache | B02 | Show then copy requires two approvals; changed action/entry/origin/epoch or replay fails; reveal, TOTP, edit/save, export and offline paths have positive and denial tests |
| G01 | Freeze Git authoritative tree/ref, canonical signed publication, expected-parent, policy evidence, operation ID/receipt and pin-persistence contract | Existing entry/device formats; B03 informs action binding | Independent fixtures and state machine define accepted/conflict/uncertain outcomes, atomic ordering of membership/revocation with publication, and supported direct-host versus gateway capabilities |
| G02 | Native Git sync engine against a disposable local bare remote | G01 | Two clients fetch/verify and conditionally publish; one competing successor wins; stale draft survives; user re-edit creates a fresh candidate; uncertain push reconciles without duplicate edits |
| K01 | Per-device vault-secret packages and durable trusted recipient/pin state | B02, G01 | Two independently enrolled keys open their own package for one vault epoch in both supported profiles; wrong/ungranted device fails; adding a device does not re-encrypt all entries |
| A01 | Password sessions plus enrolled-device proof and action-bound online authorization; temporary scoped sync credentials | B03, G01 | Password/token alone cannot authorize secret operations; nonces are single-use, scoped and expiring; disabled/revoked/stale-policy requests fail; tests establish the chosen publication ordering |
| Q01 | Web QR pairing relay and UI, new-device onboarding, authority confirmation and reconnect/receipt reconciliation | B02, K01, A01; existing enrollment proof/API | QR scan alone grants nothing; expiry/replay/cross-account/origin substitution fail; existing authority approves verified fingerprint and both encryption proofs; device ready only after durable custody and package verification |
| C01 | Wire real client secret actions through broker; native messaging bridge for browser/extension; CLI integration | B03, K01, A01 | Every supported entry point passes fresh-approval tests; direct worker/cache/legacy handler paths cannot bypass the policy; unsupported clients deny secret processing |
| T01 | Actual SSH/HTTPS Git host adapters and optional API/gateway adapters, scope/expiry/host identity and browser transport checks | G02, A01 | Real-host tests establish conditional update semantics, trust and credentials; insufficient host capabilities require gateway or are rejected; no universal token assumption |
| D01 | Device removal, session/credential denial, fresh-epoch rotation and biometric-compatible recovery | K01, A01, G02 | Removed key cannot open new epoch; retained keys can; old history remains explicitly accessible; recovery provisions a biometric-protected device with no raw-key/viewer shortcut; restore retains newest independent pins |
| M01 | Explicit per-vault migration, legacy-client exclusion, full restore, protocol/security review and release packaging | All required packages above | Exactly one authority accepts writes after cutover; original stores/backups survive; no legacy unlock bypass; complete failure matrix and required independent review pass before enablement |

`D01` belongs to this plan; the original recovery ledger R01–R08 remains separate.

## First milestone: one real protected action

Start B01 → B02 → B03 on macOS with generated data and a minimal native test harness.
The first reviewable result is a persistent synthetic device credential and **Show secret**
operation that invokes a fresh Touch ID ceremony every time. A second request must not
reuse the first approval. Add Copy as a separate operation to prove action isolation.
The harness must deny unavailable/failed biometrics and never accept a secret string or
OS passcode as a substitute. Hardware prompts require the user's presence; software
negative tests can run independently. Do not label this an iOS/Android proof.

No real vault migration, browser feature or QR enrollment is required to establish this
boundary. These depend on a proven protected operation rather than a decorative prompt.

## Second milestone: complete native vertical slice

Connect B03, G01/G02, K01 and A01 for one private synthetic vault and two independently
protected native clients. Demonstrate password login, biometric Show, fetch-before-edit,
biometric edit/save, per-entry object reuse, competing push rejection, encrypted draft,
review/re-edit, lost acknowledgement reconciliation and persistent verified pins.
A Git outage must not report a successful remote save. Every secret action still needs
its own approval even when a session or ciphertext cache is warm.

Use a local bare remote first so Git ordering and crypto can be tested separately from
host credentials. This validates logic, not SSH/HTTPS, hosted access control or browser
compatibility. G01 must resolve authorization/publication ordering before shared-vault
or credential-revocation claims.

## Product milestones after the native slice

1. Q01/C01: web QR pairing and a trusted browser/extension bridge, with real platform
   evidence. Plain WebAuthn user verification does not establish biometrics-only use.
2. T01: actual host adapters and optional gateway, including devices lacking native Git
   transport. Add Android/iOS custody adapters and test their biometric-only guarantees
   individually; passing macOS tests does not enable other platforms.
3. D01/M01: recovery/removal/rotation, sharing, migration, independent review and
   product release. No percentage or completion date is asserted without execution evidence.

## Decisions that must be closed during implementation

- Define action lifetime and whether a bounded batch export is supportable; disable
  unsupported actions rather than allowing an approval to expand its scope.
- Decide and prove per-operation platform evidence; ordinary device signatures/UV flags
  do not establish biometric-only use. State trusted client/OS assumptions honestly.
- Resolve atomic authorization versus external Git publication: select a compatible
  host/gateway contract, rather than relying on a stale server ACL checked before push.
- Specify safe enrollment/recovery when every protected device is lost or invalidated.
  Existing raw software recovery kits must not silently become a bypass of the new model.
- Define legacy-client cutoff and recovery artifact versioning before migration.

## Tracking and verification

Mark packages complete only with code, reproducible checks and recorded evidence scoped
to the actual platform and feature. Link evidence here as work lands. Keep CI checks local
until a deliberate batch push. The next code task is **B01**; this plan itself does not
implement any package or change the deployed runtime.

## First implementation slice (2026-10-31)

The [macOS synthetic broker](../experiments/biometric-unlock/broker/README.md) now
implements persistent enclave-wrapped generated state, typed Show/Copy requests, fresh
authentication contexts and five passing software tests. A separate process reopened
the stored credential and completed two hardware-protected operations with matching
generated results; user observation of prompt count is recorded separately in
[evidence](testing/device-broker-2026-10-31.json). B01–B03 remain in progress: lifecycle,
real recipient/account bindings, same-instance hardware coverage and product broker
isolation are not complete. Copy is an in-memory sink, not OS clipboard integration.

T01 also includes optional temporary repository SSH-key leases: device-local private key,
host-authorized public-key registration, durable lease/revocation ledger, lost-response
reconciliation, restart-safe cleanup and orphan auditing. Test cleanup-worker failure
explicitly. Plain API-deleted keys have cleanup-dependent lifetime; strict expiration
requires remote certificate enforcement or a lease-checking gateway. See
[credential architecture](decisions/0006-git-authoritative-sync.md#password-plus-any-one-authorized-key).

The native [lease cleanup engine](git-key-lease-cleanup.md) is now an implemented T01
subcomponent: durable ownership intent, session/device/all cleanup, all matching copies,
restart retry and late-registration scans. Nine deterministic host-interface tests pass.
T01 remains open: real host adapters, issuance, scheduler, logout/removal atomic wiring,
rate limiting and user-visible status/auditing have not been implemented.

Cleanup wiring update: GitHub/Gitea HTTP list/delete adapters, protected configuration,
a single restart-safe worker with bounded persistent round-robin sweeps, and durable
logout/session-expiry/client-revocation/account-disable/password-change events are wired.
Tests use local fake HTTP hosts. Key registration, cryptographic device removal, completion
hooks, real-host permissions and status UI remain open; see
[operational configuration](git-key-lease-cleanup.md#runtime-configuration-and-adapters).

Registration update: [challenge/registration/status/completion](git-key-registration.md)
now verifies a current admitted-device signer and independent SSH signer, owner-assigned
repository policy and server session binding. It persists intent before the only allowed
create attempt, reconciles unknown outcomes and queues completion cleanup. Independent
Python fixtures and fake-host tests cover the candidate protocol; native SSH agent/custody,
real-host trials and biometric product integration remain open.

Native client update: a gated [lease coordinator](native-git-lease-client.md) now persists
operation intent and encrypted private-key drafts through an injected custody interface,
compares all challenge bindings, reconciles lost replies through own-session operation
lookup and records transfer attempts before use. A new isolated system SSH agent accepts
the temporary key through a socket and is killed after success/error; generated-data
tests verify signatures, local expiry and cleanup. No production custodian or pinned-host
Git runner is supplied. B02/B03, G01/G02 and T01 remain open.

Pinned-host read update: public native `Operation::fetch` now requires a retained SSH
endpoint/Ed25519 host pin, uses the isolated agent with no credential fallback and returns
a temporary bare quarantine after structural fsck. Fifteen native tests pass, including
a real local SSH ciphertext fetch, wrong-host/client-key denial, inherited-config
isolation and bounded process cleanup. See [native contract](native-git-lease-client.md)
and [evidence](testing/pinned-ssh-fetch-2026-10-31.json). Fetched data still requires
independent signed-history/epoch/policy verification. Exact-parent conditional publication,
conflict/re-edit/lost-reply reconciliation and production platform custody remain open.
