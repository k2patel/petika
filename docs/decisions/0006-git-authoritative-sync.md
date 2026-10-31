# 0006: Git-authoritative, on-demand encrypted synchronization

Date: 2026-10-31. Status: accepted architecture direction; implementation and protocol review pending.
Supersedes the API-authoritative / sole Git writer target in ADR 0001 and the former
Git sync proposal. Existing deployed and experimental API paths remain current behavior
until an explicit migration. This decision does not approve a new wire encoding or deployment.

## Decision

Use a private Git data repository as the authoritative accepted encrypted vault history.
Support standard SSH and HTTPS Git transports, with optional host API adapters. Petika
provides account authentication, device admission and access coordination. Clients may
use a compatible Git transport directly or a gateway with the same publication rules;
Petika is no longer required to be the sole Git writer in the target architecture.
The public source-code repository remains separate and contains no vaults or credentials.

Before every online show or edit, fetch current history and verify it from the retained
trusted checkpoint. Decrypt only required entry/index material locally. Edit in memory,
encrypt with fresh nonces, and promptly attempt publication against the exact fetched
head. Successful remote acceptance is the synchronization commit point.

If another writer wins, discard the stale publication candidate, retain an encrypted
user draft, fetch and verify the new head, and have the user review/reapply the edit.
Create a fresh encrypted candidate against that head and retry. Never automatically
merge ciphertext, rebase stale signed records, or force-push around a conflict. Checking
before push is insufficient: the destination must atomically check the expected head
while updating the ref. Retry attempts are bounded; repeated contention returns control
to the user. A cancelled connection does not cancel an already accepted publication.

## Encrypted objects and trust

Store entries separately under opaque IDs, plus encrypted folder/index metadata,
authenticated deletions and signed history/checkpoint bindings. Unchanged entries retain
identical ciphertext and blob IDs; each changed entry is encrypted anew. Git transfers
missing objects and may delta-compress packfiles; useful binary compression of fresh
ciphertext is not assumed. Initial sync, rotation and migration can transfer many objects.

Git object hashes and ancestry alone do not authorize edits or prove global freshness.
Clients must verify signed history, collection/deployment context, writer authorization,
key epochs, membership/device state and continuity from an independently retained pin.
Invalid or missing history fails closed. A coherent old server view remains undetectable
without retained newer evidence. Required signatures and authorization proofs must be
specified and independently tested before enabling this target.

One repository is a Git read-permission boundary: branches and paths do not isolate
ciphertext from repository readers. Use repository separation or a gateway when vault
permissions differ. Git credentials must not permit shell access or bypass publication
policy through force updates/deletion. Ordinary hosting cannot be assumed to enforce
Petika's signed device/membership policy; trusted gateways/hooks or independently
verifiable authorization evidence are required where host controls are insufficient.
Revocation and publication must have a defined common ordering; a stale cached ACL is
insufficient. This remains an implementation gate for shared vaults.

## Password plus any one authorized key

The selected online access model has two requirements: authenticate the account with
its password, then use any one active enrolled device key authorized for the requested
vault. Each device normally retains its own key; multiple devices have independent keys.
The user does not need all enrolled keys together. This is not a choice between primary
and secondary authentication, and a Git token is not a substitute for either requirement.

Encrypt each vault's contents once under its collection/epoch secret. An authorized
client creates a separate authenticated encrypted package for each permitted device
recipient. Any one corresponding device private key can open its package locally and
obtain the secret needed to encrypt/decrypt entries. Adding a device adds its package;
it does not duplicate every entry. Keep authentication signing and recipient-encryption
keys in separate cryptographic roles within one logical device credential. Existing
Standard/Hybrid secret-material semantics and reviewed HPKE adapters still apply.

The password authenticates online account access; it is not transmitted as a vault
unlock passphrase or used to derive device private keys. Device admission requires the
existing independently confirmed authority ceremony; knowing the password alone cannot
silently enroll a replacement vault recipient. Account enrollment alone does not grant
a shared vault: each key needs a package authorized for that collection and current epoch.
Biometrics may authorize local use of the device key without becoming encryption material.
The server must verify device authentication proof before issuing scoped sync access;
Git transport credentials alone do not prove possession of the vault-decryption key.

These are two access gates, not a cryptographic construction that combines the account
password and device key into every decryption. A provisioned device can decrypt retained
ciphertext with its retained keys offline; mandatory password/server participation in
every decrypt would require a separate explicit design. Password reset alone cannot
recover vault contents. Loss of all device keys requires a deliberately retained recovery
path; the server cannot invent a missing collection secret. Removing a key denies future
access and requires fresh-key rotation with packages only for retained recipients.
Previous keys can still open previously downloaded historical packages/ciphertext.

Petika can issue short-lived access to its own gateway for any supported upstream host.
Direct short-lived Git access requires the host to accept the token/certificate issuer:
HTTPS tokens, trusted SSH certificates, or a host-specific API. No universal Git token
minting mechanism exists. Hosts with only long-lived credentials can be used through a
gateway retaining protected upstream credentials. Token expiry/revocation behavior and
scope are capability-tested; do not silently expose a long-lived upstream secret to clients.
Refresh or issuer credentials remain sensitive even when issued access tokens expire.

Requiring a server secret for every vault decryption is a separate, undecided policy
and cryptographic design. Authentication may gate online sync without preventing an
already provisioned device from decrypting cached data. Neither token expiry nor
revocation erases learned keys, historical ciphertext or plaintext.

## Registration methods and QR device enrollment

Users register a credential with a supported local unlock method: Touch ID/fingerprint,
Face ID, or a secret string/passphrase. Generate the actual recipient/signing key material
with cryptographic randomness. Biometrics authorize platform-protected key use locally;
never store biometric templates or derive encryption keys from a face/fingerprint. A
secret string protects the private bundle with the existing reviewed password-based
wrapping policy; it is distinct from the online account password. The server stores
public enrollment records and any permitted ciphertext, never plaintext private keys,
unlock strings or biometric data. Platform support must be detected and unsupported
methods reported explicitly, without silently choosing another unlock method.

A device normally has one independent logical credential. Several local unlock methods
may protect the same credential; that alone does not create independently revocable
recipients. Separate enrolled credentials have separate keys and vault-secret packages.
A method change can rewrap retained keys; enrolling a new key always requires admission.
Biometric reset/invalidation and loss of the unlock string require an explicit recovery
path before the method is enabled for real vaults.

The web UI must offer **Add device → Show QR code**. Planned flow:

1. An authenticated user starts an expiring, single-use pairing session in the web UI.
   Its QR contains a version, expected Petika HTTPS origin, opaque session reference and
   expiry. It carries no account password, vault secret or device private key. Treat
   pairing metadata as sensitive and never log it or commit it to Git.
2. The new device scans the QR, confirms the expected origin/account, selects an available
   unlock method and generates its own protected key material locally. A QR-supplied
   origin is not independently trusted; new-origin association needs explicit confirmation.
3. It submits the signed public enrollment request bound to that session and current
   account/deployment/roster. The QR/session reference alone grants no access or login.
4. The existing device-authority client displays the new device and full fingerprint;
   the user compares it through a trusted channel and explicitly approves. A logged-in
   web session without the authority key must obtain approval from an existing authority
   holder; the server cannot manufacture its signature.
5. Reuse the two-recipient-key challenge/decryption proof and device-signature checks.
   The authority signs the adjacent roster addition only after successful verification.
   Require current password reauthentication for admission. Expiry, cancellation, replay,
   mismatched account/origin/device, or a stale roster must fail and restart the ceremony.
6. Publish the addition conditionally, reconcile uncertain results, then have an unlocked
   authorized issuer create the new device's package for each permitted vault. Enrollment
   alone does not grant shared-vault access. Mark the device ready only after verified
   publication, package decryption and durable local custody/pin persistence.

The existing challenge lifetime is at most 300 seconds; the QR pairing session must not
outlive its enrollment authorization. Exact QR encoding, relay APIs, session consumption,
rate limits and reconnect behavior remain protocol/implementation gates. No secret-bearing
QR export or automatic approval on scan is implied. Pairing must not silently repoint Git
remotes or authenticate an arbitrary URL. Local unlock method choice does not change
vault permissions, the password-plus-key model, or Git conflict handling.

## Failure handling and custody

Plaintext belongs in client memory during use, never Git objects, commit messages,
temporary edit files, logs or crash reports. Ciphertext caches/drafts support recovery;
clear secret buffers on lock/exit with the existing best-effort memory protections.
Do not promise that OS/allocator copies are impossible.

A lost push acknowledgement is an uncertain result. Reconcile a stable operation ID,
signed candidate digest and verified remote ancestry before resubmission; discovering
another current head does not prove our earlier operation was absent. A verified accepted
operation must not be applied twice. Git head, retained signed checkpoint and receipt
semantics need one explicit transaction contract. Local pin advancement must survive crashes.

Refresh failure blocks the online show/edit path. Explicit offline viewing shows its
last verified state; offline edits remain drafts until a successful online refresh and
review. Show is read-only. Newest means the verified state observed during that request,
not a guarantee that another writer cannot advance it immediately afterward.

Git history retains previous ciphertext and exposes sizes/timing/object counts. Removing
a device requires session/credential denial and fresh-key rotation excluding it. Backups
must retain matching authority/device recovery material, newest independent pins and
account/policy state; a Git clone alone is not a complete recovery kit.

## Delivery and acceptance

Start with one disposable private vault and two native clients. Validate unchanged-object
reuse, show/edit refresh, same/different-entry races, repeated contention, uncertain push
success, encrypted draft recovery, invalid/rollback history, deletion and key rotation.
Then implement host capability adapters, browser-compatible gateway transport, device
custody and authentication policies. Browser SSH and cross-origin Git access require
an appropriate gateway or explicitly supported transport; desktop assumptions do not
establish browser compatibility.

Before shared vaults or migration: specify repository isolation, atomic authorization
ordering, publication signatures/receipts, revocation, recovery and compatibility. Preserve
legacy snapshots, backups and journals. Choose authority per migrated collection explicitly;
never let both the old API journal and Git independently accept authoritative writes.
No automatic production migration is authorized by this architecture decision.

Acceptance scenarios are tracked in the [validation plan](../testing/git-authoritative-sync.md).

See [sync plan](../research/git-vault-sync.md), [architecture](../architecture.md),
[roadmap](../roadmap.md), and [local encryption/recovery baseline](0003-security-and-recovery-baseline.md).
