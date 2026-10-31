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

Concrete credential issuer paths:

- GitHub adapter: owner installs a registered GitHub App with selected repository and
  contents permissions. The protected backend App private key authenticates a request
  for a scoped installation access token (one-hour lifetime). The App key itself is
  never distributed as a client credential.
- Gitea adapter: register an OAuth application and obtain user authorization; exchange
  the authorization code using the appropriate client/PKCE flow. Renew via a protected
  refresh credential where issued. Lifetime is instance-configured (documented default
  3,600 seconds); API scope and actual Git access must be tested for the installed version.
  This is delegated authorization, not arbitrary token minting for any account.
- SSH-only or non-delegating hosts: gateway retains the scoped upstream key/credential
  and issues temporary Petika access. Direct short-lived SSH certificates require explicit
  trust of the certificate issuer at the remote. There is no provider-neutral mint API.

Sources: [GitHub installation authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation),
[Gitea OAuth](https://docs.gitea.com/development/oauth2-provider/),
[Gitea token lifetime](https://docs.gitea.com/administration/config-cheat-sheet/#oauth2-oauth2).
These are planned adapters; the existing server credential settings do not implement them.

Temporary repository SSH-key leases are an additional planned adapter option. A device
generates a fresh transport key pair and keeps the private key locally; Petika registers
only the public key with the selected private data repository using explicitly granted
key-management permissions. Default to read-only for fetch; grant write only when the
host supports the needed policy. GitHub exposes create/delete deploy-key APIs and Gitea
exposes repository-key APIs. A generic SSH server needs an authorized management interface
or an administrator-controlled gateway; Git SSH transport alone cannot add/remove keys.

Persist a lease ledger with host/repository, device, public fingerprint, remote key ID,
permission, expiry, operation ID and lifecycle state. Register idempotently, reconcile
lost replies, revoke on completion/logout/expiry/device removal, retry failures across
restarts and periodically reconcile remote orphan keys. Never delete keys not owned by
Petika's lease ledger. Expose cleanup failures, audit without credential contents, and
protect the backend management credential: it may require broader rights than sync itself.
Key count/rate limits and rapid concurrent usage require host tests. Transport keys are
separate from vault encryption keys and do not bypass fresh biometric secret access.

An ordinary deploy key is not intrinsically expiring. Scheduled API deletion depends on
Petika and the host being available, so it is not a hard TTL guarantee. App/token removal
need not remove keys created by it. If strict expiry is required, use a remote-validated
short-lived SSH certificate or a gateway that checks leases for each permitted operation.
Removal/expiry must not be claimed to cancel an already established SSH operation; define
connection lifetimes and atomic publication policy separately. Repository key permissions
are not per-entry/vault ACLs and write grants may be broad. Prefer a gateway when the
host cannot restrict required operations or prevent bypass of publication policy.

Sources: [GitHub deploy-key lifecycle](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys),
[GitHub key-management API](https://docs.github.com/en/rest/deploy-keys/deploy-keys),
[Gitea repository API](https://docs.gitea.com/api/1.24/). The [cleanup implementation](../git-key-lease-cleanup.md) now includes host inventory/deletion
adapters, the bounded worker and durable session-event wiring. Registration/issuance and
actual-host validation remain pending; no real host keys were changed in this milestone.

Requiring a server secret for every vault decryption is a separate, undecided policy
and cryptographic design. Authentication may gate online sync without preventing an
already provisioned device from decrypting cached data. Neither token expiry nor
revocation erases learned keys, historical ciphertext or plaintext.

## Registration methods and QR device enrollment

Each active device credential must be protected by a supported biometric-only local
policy (Touch ID/fingerprint or Face ID). The per-action policy below supersedes the
earlier secret-string alternative for routine secret access. A string, account password,
OS PIN/passcode, recovery kit or Git token cannot substitute for biometric approval.
Generate recipient/signing key material with cryptographic randomness; never derive
keys from biometric templates or transmit biometric data. Enrollment must establish a
supported protected key-use path before marking a device ready. Unsupported devices
cannot perform secret actions. Biometric set changes/invalidation stop access until an
explicit authorized re-enrollment/recovery process restores a biometric-protected device.
Recovery may re-provision a supported device; it cannot provide an unrestricted secret
viewer or raw-key export bypass. Design and review this restriction before enabling
recovery/export in the new model. Legacy recovery tools remain legacy behavior, not
an implementation of the target policy.

Each device normally holds an independent logical credential with separate encryption
and signing roles. Any one permitted device can access the vault, but every secret action
on that device requires its own fresh biometric approval. No quorum or all-keys requirement.

The web UI must offer **Add device → Show QR code**. Planned flow:

1. An authenticated user starts an expiring, single-use pairing session in the web UI.
   Its QR contains a version, expected Petika HTTPS origin, opaque session reference and
   expiry. It carries no account password, vault secret or device private key. Treat
   pairing metadata as sensitive and never log it or commit it to Git.
2. The new device scans the QR, confirms the expected origin/account, checks biometric-only capability
   and generates its own protected key material locally. A QR-supplied
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

## Mandatory biometric approval for every secret action

Status: required target policy (2026-10-31); not implemented or enforced by the current
runtime. Password sign-in establishes an account session. Any active permitted device
credential is usable only after a new biometric approval for the exact secret action.

Require a fresh biometric for every reveal/show, copy, autofill, TOTP access, secret edit,
secret-bearing search/preview, import/export or other operation that consumes/decrypts
secret material. Do not exclude CLI, extensions, API-triggered actions, offline views,
background workers, accessibility paths or recovery flows. Editing is an explicit bounded
transaction: approval to open an editor does not authorize a later reveal/copy/export;
saving a secret-bearing mutation requires fresh approval bound to the final candidate.
A multi-secret export must explicitly describe its bounded scope; if this cannot be
safely supported with this policy, disable export. No silent batch expansion.

Ciphertext-only fetch/push, hash/history verification, pairing display and non-secret
account screens may run without a biometric. Each transition into secret processing
passes through the same broker; there is no cached unlocked-vault bypass. Metadata that
requires secret decryption is itself a protected action.

### Enforcement architecture

1. A trusted native credential broker owns protected key access and operation execution.
   UI/CLI/extension callers request a typed action bound to account, device, collection,
   entry/explicit object set, epoch/head and request nonce. A UI prompt alone is insufficient.
2. The broker verifies capability, local pins and current authorization before requesting
   biometric-only OS approval. Configure platform-protected key operations per use, without
   device-password/PIN fallback, reuse windows or reusable authentication contexts. A
   cancelled, failed, timed-out or locked-out prompt denies the operation. No downgrade.
3. Approval authorizes exactly the bound action once. Execute the protected unwrap/decrypt
   and operation inside the broker, keep transient collection/recipient secrets within
   its bounded lifetime, then clear/drop them. Never return raw keys or reusable decrypted
   bundles to UI, extension content scripts or a long-running worker. Do not cache usable
   collection keys across secret actions. Ciphertext and verified public pins can persist.
4. Return only the minimum requested output to the intended consumer. Bind autofill to
   the verified requesting origin/frame and fields; bind copy to the requested secret.
   End display/editor lifetimes explicitly and clear transient plaintext when complete,
   locked, backgrounded or cancelled. Clipboard cleanup is best effort and cannot revoke
   copies another process has already read.
5. Online protected operations also require a one-use server challenge/authorization
   bound to the same action/device/context, short expiry and fresh nonce. Verify device
   signatures, current membership/roster/epoch and consume authorization atomically with
   the relevant operation. A sync bearer token cannot satisfy this check on its own.
   The exact challenge/evidence format and ordering with Git publication remain a review
   gate. Do not claim that an arbitrary device signature proves a biometric was performed.
6. Direct Git readers already possess ciphertext and may bypass a server UI. Local key
   protection must therefore enforce biometric use even for cached/offline data. A
   participating client must not contain a raw-key, recovery or legacy unlock backdoor.
   Host adapters may transfer ciphertext without acquiring decryption capability.

### Platform feasibility and evidence gates

Apple candidates use biometric-only protected Keychain/Secure Enclave access and fresh
per-operation contexts, including current-biometric-set invalidation. Android candidates
use auth-per-use Keystore operations restricted to strong biometrics, without device
credential fallback. Hardware support and fresh-prompt behavior require real-device tests;
existing generated-data probes do not establish this per-action property.

Generic browser WebAuthn user verification can be satisfied by PIN or biometrics; the
UV flag is not proof of biometric-only approval. A plain browser/PRF implementation is
therefore insufficient evidence for this requirement. Browser and extension secret
operations need an explicitly verified native broker or a separately reviewed capability
that can enforce the same biometric-only per-action contract. Deny secret access on
unsupported platforms. Never label unsupported WebAuthn as compliant.

This is an enforced application/platform policy under trusted client and OS assumptions,
not a guarantee against a compromised unlocked process/OS or a user copying revealed
plaintext. Software X25519/X-Wing recipient material and epoch secrets necessarily exist
transiently during use; current hardware probes do not move those algorithms into secure
hardware. Independent review must assess that boundary. Server-delivered malicious web
code remains a threat; an independently distributed broker must constrain requested actions
and outputs. No documentation claim may describe the current application as enforcing
this policy until the complete path and negative tests pass.

Sources: [Apple current-set access control](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset),
[Android auth-per-use keys](https://developer.android.com/identity/sign-in/biometric-auth),
[WebAuthn user verification](https://www.w3.org/TR/webauthn-3/#user-verification).

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

Refresh failure blocks the online show/edit path. Explicit offline viewing requires a fresh biometric for each secret action and shows its
last verified state; offline edits remain drafts until a successful online refresh and
review. Show is read-only. Newest means the verified state observed during that request,
not a guarantee that another writer cannot advance it immediately afterward.

Git history retains previous ciphertext and exposes sizes/timing/object counts. Removing
a device requires session/credential denial and fresh-key rotation excluding it. Backups
must retain matching authority/device recovery material, newest independent pins and
account/policy state; a Git clone alone is not a complete recovery kit.

## Delivery and acceptance

First prove persistent per-action biometric custody and a native operation broker
(B01–B03 in the [ordered work plan](../implementation-plan-git-biometric.md)).
Then start with one disposable private vault and two native clients. Validate unchanged-object
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
