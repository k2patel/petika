# Explicit recipient trust handoff

Status: experimental core API only, off by default. No server endpoint, enrollment
UI, automatic contact verification, client sync or production vault changes.

A new recipient may not possess old epoch keys, so it cannot independently compare
old/new plaintext during rotation. It must explicitly bootstrap trust from a
confirmed current checkpoint. Existing clients still use content-preserving
rotation validation; this handoff cannot overwrite an existing local checkpoint.

## Workflow

1. The authority and recipient independently verify each other's identity
   fingerprints using the existing contact-pin workflow.
2. The authority prepares the recipient's encrypted key package and includes its
   exact-byte digest in the active wrapper set of a signed checkpoint. Membership
   changes still follow the explicit epoch design; handoff creates no new grant.
3. After verifying the exact checkpoint index, the authority calls
   `prepare_entry_handoff`. Only the designated checkpoint authority can prepare
   this profile, and the package must have been issued by that same authority.
4. The recipient independently confirms the full handoff confirmation digest and
   authority fingerprint. Values downloaded beside the bundle from the same
   server do not count as independent confirmation. The authority should confirm
   against its current accepted state; a previously saved digest alone does not
   prove the server is current.
5. `accept_entry_handoff` validates the bundle, verified contact, recipient
   binding, checkpoint and active wrapper, then decrypts the package. It returns
   a trusted checkpoint and root key. No old keys are required or disclosed.
6. The caller decrypts the exact checkpoint index with that key, matches it to the
   checkpoint, and uses `CheckpointStore::initialize` before exposing accepted
   vault content. The initializer refuses any existing file, including a corrupt
   file. Complete restore additionally verifies every live object.

Acceptance does not persist state itself. Callers must persist contact suspension
changes even when acceptance fails, as with existing recipient-package APIs.
Browser persistence and the user confirmation screen remain integration work.

## Encoding and limits

`EntryHandoff` is strict JSON with `handoff_version: 1`, signed `checkpoint`,
`package` containing the exact serialized package text, and `wrappers`. Parsing is
bounded to 256 KiB and rejects duplicate/unknown fields. Existing checkpoint,
package, wrapper count and encoding limits also apply. Package text must not be
reformatted after its digest enters the wrapper set.

The confirmation digest is lowercase SHA-256 hex of:

```text
field("petika:entry-handoff:v1") || u32be(1) ||
field(checkpoint_digest_ascii) || field(SHA256(exact_package_utf8))
```

`field` is the existing u32 big-endian length prefix. The signed checkpoint commits
to context, authority, head, membership, root commitment, profile and wrapper set.
The signed recipient package binds recipient identity and issuer identity; its
exact bytes are also committed by the confirmation digest. No additional signature
scheme or new encryption algorithm is introduced. Independent Python fixtures and
Rust checks cover both delivery profiles.

## Replay and trust limits

This is a confirmable bootstrap record, not an expiring bearer token or one-time
invitation. Re-parsing/re-decrypting it is allowed; replay cannot replace a local
pin through the initializer. An existing client must catch up or verify rotation.
Deleting local state and trusting an old confirmation again can restore stale
trust. The protocol does not prevent a trusted authority from confirming stale or
forked state, prove historical content to a new recipient, or provide global
freshness without an independent current comparison. It confers no server API
permissions; account authorization and membership checks remain separate.

Tests cover both profiles, absent authority contact trust, wrong recipient, wrong
confirmation/fingerprint, modified wrappers, unsupported version, duplicate fields,
oversize input, exact head matching and replay/no-overwrite persistence. UI/API
integration and independent security review remain release gates.
