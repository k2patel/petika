# Experimental entry checkpoints and recipient access

Implemented only behind `petika-core/experimental-entry-format`. This extends the
[primitive prototype](entry-format-prototype.md); it is not enabled in clients or
API storage and has not received independent cryptographic review. Existing vault
formats and snapshot key-package v1 are unchanged.

## Trust model

A collection has one explicitly designated **rotation authority**, an existing
Petika recipient identity whose signing seed is independent of vault root keys.
The authority's existing encrypted identity backup provides its key recovery path.
A member who possesses a vault root is not thereby a rotation authority. Account
administrator privileges and server bearer tokens do not grant this signing key.
This prototype does not implement quorum approval, authority discovery or a setup UI.

`TrustedCheckpoint::bootstrap` requires both the authority fingerprint and the exact
signed checkpoint digest obtained independently from a trusted device or recovery
record. Do not compute those expected values from the untrusted server response and
call that verification. There is no trust-on-first-use fallback. A brand-new device
with no trusted checkpoint cannot prove that a valid signed checkpoint is current.

The authority signs an epoch checkpoint containing deployment/collection context,
root commitment, data and delivery profiles, head revision/digest, membership
generation, and the digest of the active wrapper set. Signing this structure does
not validate the encrypted index or prove its referenced objects exist. The caller
must verify those before requesting an authority signature; that integration is pending.

The root commitment is SHA-256 over:

```text
field("petika:entry-root:commitment:v1") || context_prefix ||
field(canonical_base64_epoch_salt) || root_key_32_bytes
```

The root is uniformly random; this public commitment does not contain a recoverable
root key. Fresh-key generation remains a requirement on rotation. Comparing context-
bound commitments alone cannot prove that a malicious authority used fresh entropy.

## Verified epoch transitions

A transition references the exact previous signed checkpoint digest and includes
the next signed checkpoint. The **old authority** signs the transition. The next
checkpoint must have a valid signature from its declared authority, so a change of
authority requires both old authorization and new-key possession. Before authorizing
a handover, the old authority must also independently verify the new authority as
a contact; a self-signed public identity alone is insufficient.

`TrustedCheckpoint::advance` returns a new immutable trusted value only when:

- Deployment and collection are unchanged; epoch increments by exactly one.
- Salt and root commitment differ; the data suite is supported and the delivery
  profile is unchanged. Profile upgrades/downgrades require a separate reviewed flow.
- Head revision exceeds the caller's **locally persisted highest authenticated
  revision**, which must itself be at least the old checkpoint revision.
- Membership generation does not decrease; both signatures and the predecessor
  checkpoint digest verify.

Replay, epoch skips, foreign collections, an unapproved authority, old head revisions
and an incorrect predecessor are rejected. A revoked reader holding only an old
vault root cannot create the required identity signature. Old ciphertext remains
readable to old key holders; this does not erase historical disclosures.

The verification needs only the trusted checkpoint's public authority, not old vault
root keys. It does not send the new root encrypted under the old root. Multiple
epochs can be checked sequentially; a production catch-up chain needs explicit
count/byte budgets and client integration. Atomic native pin persistence is now
available in the [index extension](entry-index.md); API catch-up is not implemented.

This is authorization of an epoch checkpoint, **not** a proof that every ordinary
edit since the previous checkpoint was preserved. Authenticated index/history
continuity remains required. A compromised/equivocating authority can sign competing
histories; isolated clients cannot discover every fork without comparison or an
independent witness. A revoked authority remains authoritative to clients pinned to
it until they receive an authorized handover; ordinary server membership removal
alone does not revoke a checkpoint signature.

For this prototype, changes to the pinned wrapper set or membership require a new
epoch checkpoint. Same-epoch access updates and authority-only updates are not
implemented. This conservative rule may require more re-encryption; optimize it only
after an explicit add/remove policy and transaction protocol have been reviewed.

## Recipient packages and recovery

`EntryKeyPackage` is a new, incompatible envelope with separate HPKE info/AAD/signature
domains. Its version field is 1 within the **entry-package family**, not snapshot
key-package v1. The payload is the explicit root tag plus 32 root bytes; it is never
interpreted as the old Hybrid X-Wing seed.

Supported delivery profiles are explicitly selected and checkpoint-bound:

| Profile | Key delivery | Status |
| --- | --- | --- |
| `standard` | HPKE X25519 / HKDF-SHA256 / ChaCha20Poly1305 | Experimental new root-envelope integration |
| `experimental-xwing-draft06` | Existing pinned X-Wing draft-06 HPKE adapter | Experimental, not reviewed ML-KEM production delivery |

Both retain Ed25519 issuer signatures; Hybrid does not imply post-quantum signature
authentication or a fully post-quantum system. Data encryption remains the prototype's
XChaCha20-Poly1305 suite. There is no implicit profile negotiation or fallback.

Packages bind the context/epoch salt, data and delivery suites, root commitment,
membership generation, wrapper ID, recipient and issuer user IDs, identity versions
and fingerprints. Creation requires a verified recipient contact (or the same identity).
Opening requires:

1. Exact package bytes referenced by the trusted checkpoint's active wrapper set.
2. Matching context, root commitment, delivery profile and membership generation.
3. The intended recipient identity, valid issuer signature and verified issuer contact.
4. Successful HPKE decryption, exact root payload type/length, and matching root commitment.

The existing trust-suspension behavior is reused. As with existing identity operations,
a future caller must persist changed identity/contact state even if opening fails.

`TrustedCheckpoint::open_recovery` similarly requires the exact active wrapper and
validates the recovered root against the checkpoint. The lower-level primitive unwrap
still exists, but it must not be used to bypass collection-level checkpoint policy.
A recovery passphrase recovers vault data; it does not restore the authority signing
seed. Restore the authority's encrypted identity backup for signing. If it is lost,
recover contents into a separately bootstrapped trust setup after explicit verification;
there is no automatic authority replacement or anti-rollback reset.

## Canonical bytes and strict parsing

Use the primitive prototype's `field`, counter and context encodings. All digests and
IDs below are 64 lowercase hex ASCII. JSON forbids unknown/duplicate fields and uses
canonical padded base64 for binary fields. Signature encoding is independent of JSON
order; wrapper references hash **exact stored bytes**. Serialize a newly created
package once and retain those bytes; do not reformat it after computing its reference.

Wrapper-set digest:

```text
SHA256(field("petika:entry-wrapper-set:v1") ||
       concatenation of field(wrapper_id) || field(exact_envelope_sha256_hex))
```

Sort by unique wrapper ID. Reject empty sets, duplicates and more than 1,000 wrappers.
Checkpoint and package input limits are 16 KiB; transition input limit is 20 KiB.
These bounds do not replace future transaction/staging/chain quotas.

Checkpoint signature message:

```text
field("petika:entry-checkpoint:v1") || u32be(1) || context_prefix ||
field(raw_epoch_salt) || field(data_suite) || field(delivery_suite_name) ||
field(root_commitment) || field(head_digest) || field(wrapper_set_digest) ||
field(authority_fingerprint) || u64be(head_revision) || u64be(membership_generation)
```

The checkpoint digest is SHA-256(message || field(raw_signature)). Its full authority
public identity must pass the existing fingerprint/self-signature validation.
Transition message:

```text
field("petika:entry-epoch-transition:v1") || u32be(1) ||
field(previous_checkpoint_digest) || field(next_checkpoint_digest)
```

Entry-package header:

```text
field("petika:entry-package:header:v1") || u32be(1) ||
field(delivery_suite_name) || field(data_suite) || context_prefix ||
field(raw_epoch_salt) || field(root_commitment) || u64be(membership_generation) ||
field(wrapper_id) ||
field(recipient_user_id) || u64be(recipient_identity_version) || field(recipient_fingerprint) ||
field(issuer_user_id) || u64be(issuer_identity_version) || field(issuer_fingerprint)
```

Delivery suite names are `entry-hpke-x25519-sha256-chacha20poly1305-v1` and
`entry-hpke-xwing-draft06-sha256-chacha20poly1305-v1`. HPKE info/AAD are
`field("petika:entry-package:info:v1") || field(header)` and the same construction
with `petika:entry-package:aad:v1`. The issuer signs
`field("petika:entry-package:signature:v1") || field(header) || field(enc) || field(ciphertext)`.
Payload is ASCII `petika:entry-root:v1`, a zero byte, then 32 root bytes. No root
material is serialized outside encrypted payloads or synthetic test fixtures.

## Evidence and next integration gates

Native tests cover both delivery profiles, unverified/wrong recipients, changed
membership/profile, active-wrapper substitution, ciphertext forgery, explicit
handover, stale/replayed/skipped transitions, rejected bootstrap pins, recovery,
strict parsing and old-format rejection. Revocation tests ensure old recipient
packages/roots cannot open the new epoch.

`generate_entry_trust_vectors.py` independently encodes/signs checkpoints and transitions
with Python cryptography and generates entry HPKE ciphertext. Hybrid fixtures reuse
the upstream X-Wing KAT encapsulation/shared secret; no new KEM is implemented in
Python. Rust verifies byte-exact headers/messages/digests and decrypts both profiles.
Run with `--check`; dependencies are the existing test-only requirements file.

Remaining: independent security review; actual WASM runtime vectors; integration of
index validation and persisted pins; authority bootstrap/handover/recovery UX;
network catch-up integration; server authorization/CAS and
receipt handling; migration and restore. The full acceptance matrix remains open.

## Native persistence and index validation update

The [index/checkpoint storage extension](entry-index.md) now provides decrypted
index semantics, bounded same-epoch page verification and locked atomic native pin
persistence. Earlier references to these as pending refer to client integration:
no production client calls these APIs yet. Independent head vectors and injected
write-boundary tests now run in CI. The index extension also requires a verified
content-preserving rotation before persisting an epoch transition. Network/client
integration and real power-loss tests remain pending. The explicit
[new-recipient handoff](entry-handoff.md) is now available as an opt-in core API.
