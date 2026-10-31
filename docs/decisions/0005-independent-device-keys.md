# 0005: Independent device keys per account

Date: 2026-10-31. Status: **draft for review**, not an accepted wire protocol.
Evidence: [synthetic executable model](../../experiments/device-keys/README.md).
Extends [0002](0002-per-user-group-key-delivery.md) and preserves
[0003](0003-security-and-recovery-baseline.md). No production format changes yet.

## Proposed decision

Give each enrolled device a fresh encryption/signing identity under one immutable
account ID. A signed, versioned account device roster authorizes those identities.
Deliver each collection's current secret separately to each authorized device;
encrypt collection contents once per epoch. Account login and local biometric
unlock remain separate from permission to enroll devices or receive collections.

Start with a dedicated **account device authority** key held by the primary enrollment
client and an explicitly retained recovery kit. It signs device-roster transitions;
ordinary device keys cannot enroll another device or act as the authority. This is
a proposed single-authority policy, not a hidden server key or a quorum design.
Later delegation needs another reviewed policy. Do not repurpose the existing entry
checkpoint signing key as this account-wide enrollment authority.

The Apple wrapper experiment is the first local protection candidate. It protects
software recipient secrets; it does not put X25519/X-Wing inside the enclave.
Browser PRF remains a separate candidate with explicit PIN/sync limits. Local wrapping
must preserve an honest recovery path before biometric-enrollment invalidation ships.

## Identity, authorization and trust

A device record binds protocol version, deployment ID, immutable account ID, random
device ID, recipient key suites/public keys, signing key and a full fingerprint.
Labels are untrusted display metadata. In this proposal a changed key gets a new device
ID; revoked IDs are never reused. Every device has both supported recipient suites;
no silent Hybrid-to-Standard fallback. Suite retirement needs an explicit transition.

The account device authority's full public fingerprint is independently confirmed and
pinned. A roster binds the same account/deployment, its authority, generation, exact
parent digest, active device records and revoked tombstones. Sign the complete canonical
transcript with a distinct domain tag. Ordered records, size/counter limits and parser
rules must be frozen in a separate encoding specification before API implementation.
The executable model's typed JSON tuples are not that production encoding.

A separate [candidate record/roster encoding](../device-key-format.md) now has an
opt-in core parser/verifier and independently generated Python fixtures. It defines
the exact candidate bytes, limits and adjacent add/remove rules. The
[candidate enrollment format](../device-enrollment-format.md) adds independently checked
request/challenge/proof bytes and client-side encryption/signing possession verification.
Collection-package encodings, durable publication, integration and independent review remain open.

Enrollment requires all of the following:

1. An authenticated account session, explicit reauthentication and a user-started
   ceremony on the device-authority client. Password reset alone confers no authority.
2. A locally generated device identity and full fingerprint confirmation over a trusted
   channel, bound to the intended account, deployment, current roster and expiring nonce.
3. An authority-generated random challenge encrypted independently to each recipient
   key. The new device decrypts both and signs a domain-separated response binding the
   challenges and complete enrollment request. A self-signature alone is insufficient.
4. Authority verification against its locally retained challenges and exact current
   roster. Expired, replayed or superseded requests fail without changing state.
5. A signed successor roster, committed by exact predecessor compare-and-swap. A stale
   approval must restart; it must never overwrite an intervening enrollment or removal.

The challenge plaintext remains with the authority until successful decryption by the
candidate; server relay does not learn it. Production messages must separate public
challenge packets from the authority's local pending secret state. Trusted-clock
behavior, cancellation and secure disposal of pending challenges need platform tests.

Existing clients accept an identical roster as an idempotent retry, or a verified
adjacent successor. Gaps require the intervening history; rollback and conflicting
branches stop delivery. An authenticated handoff transfers the latest trusted roster
digest to a new client. A restored old pin cannot prove global freshness by itself;
signatures do not prevent a server from hiding newer history or isolating clients.

## Collection delivery and removal

Account enrollment never grants a collection by itself. An unlocked, authorized editor
checks current account membership and read permission, the separately verified account
device authority, and the latest accepted device roster before issuing device packages.
Group administrators without edit/decryption access cannot issue packages. Group
membership changes and device-roster changes have separate counters and CAS checks.

New device-package headers bind deployment, account, device ID and fingerprint, collection,
delivery suite, data suite, epoch, account roster generation/digest, group membership
generation, issuer and collection checkpoint. Both HPKE context/AAD and the issuer's
signature cover these bindings. The checkpoint commits the exact package set. The entry
collection authority remains the existing authority unless separately transitioned.

Removing a device first revokes its server sessions and denies package issuance. The
collection enters a rotation-required state. A remaining authorized client generates
a fresh collection secret, re-encrypts live contents and creates packages only for
retained recipients. Atomically commit ciphertext, package set, membership/roster pins
and the new checkpoint. Until that transaction completes, show **rotation pending**;
do not claim cryptographic removal or allow new writes under the compromised epoch.

Old keys, packages, backups and copied plaintext remain usable by their previous holders.
Revoking a synced browser credential is not necessarily revoking one physical device.
The inventory must identify that scope rather than promising hardware provenance.

## Recovery and migration requirements

Keep authority recovery distinct from collection-secret recovery. A retained device
authority kit can authorize a replacement, but cannot reconstruct a vault secret it
does not hold. After loss of every device, an explicitly retained collection recovery
kit/holder must supply collection access. Neither an administrator nor password reset
can synthesize either missing secret. If authority compromise is suspected, authority
replacement requires independent confirmation and fresh affected collection secrets.

Migration from today's shared recipient identity is explicit and resumable:

1. Inventory legacy identities, collections, clients and retained recovery material.
   Preserve the original encrypted bundles and backups unchanged.
2. Generate a separate account device authority and first device identity. Verify both
   recipient keys and prepare a separately retained recovery kit. Bind the authority
   transition to the old identity, new authority fingerprint and source revision; require
   explicit confirmation rather than treating an old-key signature as sufficient trust.
3. Publish the new roster through a separate versioned resource. Existing v1 clients
   keep their existing interpretation; never place device IDs in their user-ID fields.
4. Stage a new collection epoch and v2 device packages under the new checkpoint contract.
   Verify each required device/recovery recipient can open the staged secret before
   committing. Missing/unverified recipients remain explicit pending states.
5. Atomically commit only if source revision, membership and all device-roster digests
   still match. Preserve drafts on conflict and support exact receipt reconciliation.
6. After cutover, old clients receive an explicit upgrade requirement. Reject v1 writes
   to migrated collections. Do not retain a legacy wrapper to the new secret by default:
   every holder of the old shared identity could use it, defeating device removal.
7. Restore drills must retain the independently trusted newest device roster, collection
   head and revocation evidence. Never re-enable old sessions/devices solely from an older
   server backup. If current authorization evidence is missing, require recovery review.

First implementation should target experimental entry collections only. Snapshot-v1
collections require their existing entry migration first, or a separately reviewed
snapshot migration. No automatic bulk conversion of users' vaults is authorized here.

## Evidence, limits and review gates

The isolated model tests independent same-account software recipients, possession of
both encryption keys, signed enrollment/rosters, stale/replayed/forged requests, fresh
Standard/experimental X-Wing delivery, old-key exclusion and historical access. It
reuses Petika's draft-06 HPKE adapter and its upstream-vector tests.

It models one personal collection with the authority also acting as issuer. It does
not implement production group permissions, API sessions, wire parsers, atomic disk
journals, hardware storage or integration with Petika vault formats. Its symmetric
test payload is not a claim about either legacy Hybrid secret material or entry roots.

Before changing production formats: review authority custody/replacement, enrollment
UX, exact encodings/KDFs and independent fixtures, server/client CAS and transaction
rules, recovery custody, synced-passkey policy, platform lifecycle behavior and Hybrid
outer-wrapper limits. Obtain independent protocol review. This ADR remains draft until
those decisions and migration gates are accepted; passing the model does not accept it.
