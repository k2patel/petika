# Per-user group access

Petika supports recipient identities, verified encrypted group-key delivery, and explicit
fresh-key rotation in Standard and experimental X-Wing draft-06 modes. These are
experimental capabilities, not an independently audited cryptographic system.

## Browser

1. Sign in and open **Settings → Recipient identity**. Enroll once with a distinct local
   identity passphrase and confirm your account password. Download the encrypted identity
   backup and retain its passphrase separately.
2. On another device, choose **Restore enrolled identity** and enter the fingerprint
   obtained from your existing device or backup. Never treat the server directory alone
   as fingerprint verification.
3. Select a group. In **Settings → Group access**, verify the other person's immutable
   user ID and full fingerprint through an independent trusted channel. Both the issuing
   editor and recipient must verify each other.
4. An editor who can unlock the existing group chooses **Enable recipient access** and
   a recovery passphrase. This explicitly migrates that group; other stores stay unchanged.
5. Members choose **Unlock with identity**. An editor uses **Deliver to verified members**
   for later enrollments. The status list distinguishes missing enrollment from missing
   packages; verification is enforced locally, never asserted by the server.
6. After removal, disabling, or identity replacement, an unlocked remaining editor chooses
   **Rotate group keys** and a fresh recovery passphrase. New writes are blocked while
   rotation is pending. Rotation generates new secret material, re-encrypts records, and
   commits the snapshot and replacement grants together.

Lock, sign-out, navigation away, worker failure, and inactivity clear the worker's private
identity and collection keys. Only encrypted bundles, snapshots, access drafts, and public
highest-seen epochs persist locally. Changing collections also locks the worker.

## CLI

After `petika login --server https://your-server`, use a dedicated identity file:

```sh
petika --identity-file identity.json keys enroll
petika --identity-file identity.json keys verify --user USER_ID --fingerprint FINGERPRINT
petika --identity-file identity.json keys status --collection GROUP_ID
petika --identity-file identity.json keys migrate --collection GROUP_ID
petika --identity-file identity.json keys deliver --collection GROUP_ID
petika --identity-file identity.json --store group.petika keys pull --collection GROUP_ID
petika --identity-file identity.json --store group.petika list
petika --identity-file identity.json --store group.petika get example --reveal
petika --identity-file identity.json --store group.petika keys push --collection GROUP_ID --revision REVISION
petika --identity-file identity.json keys rotate --collection GROUP_ID
```

Passphrases are prompted locally, never command-line arguments. Enrollment and retry
also prompt for the account password, which is sent to the server for reauthentication.
`keys migrate` prompts for the old group passphrase, then a new recovery passphrase twice.
`keys rotate` prompts for a new recovery passphrase twice. Migration adds binding while
preserving group secret material; only rotation replaces that material.

`keys pull` refuses existing destinations. Keep its adjacent `group.access.json` with the
snapshot for offline access, and keep the encrypted identity file plus its origin, epoch,
and bundle-revision sidecars. Offline commands accept `--identity-file` and use the recipient package instead
of a group passphrase. Use `keys push` for recipient-enabled collections; legacy `push`
cannot downgrade or replace them. A membership/epoch/revision conflict preserves the draft. A newer remote identity-bundle
revision blocks stale local trust edits; restore into a separate file/profile to compare
and reconcile without silently overwriting either copy.

To restore on another device:

```sh
petika --identity-file new-device.json keys restore --fingerprint TRUSTED_FINGERPRINT
```

The identity's origin sidecar prevents silent reuse against another server. Fingerprints
and verified contact pins are inside the encrypted identity backup. Highest-seen epoch
sidecars protect this device against rollback, but a fresh device/old backup has no
independent proof of the newest server history.

## Interrupted operations and recovery

Generated enrollment ciphertext is saved before upload. If the response is lost, retry
that same identity with `keys retry-enrollment` or **Retry saved enrollment** in the browser.
Do not generate replacement keys as an enrollment retry.

Migration and rotation preserve a ciphertext-only transaction draft before publication.
Use `keys retry --collection GROUP_ID` or **Retry saved access update** after a lost response.
The server recognizes the same canonical transaction after restart and returns its original
receipt. Current membership, identity, and epoch checks still apply. Conflicts require
refreshing and reviewing current state; they never silently replace the draft.

The server keeps `snapshot.v1.backup.json` on explicit migration and retains journal
history. Back up the entire server data directory separately from the optional Git mirror.
Mirrors contain encrypted snapshots only; they exclude identity directories and packages.
Recovery therefore needs the appropriate recovery passphrase, or a separately retained
matching package and recipient identity.

A batch contains at most 100 grants. For a larger roster, repeat **Deliver to verified
members** / `keys deliver` until remaining verified members have packages. Recipients who
are unenrolled or unverified remain pending. The server cannot manufacture usable grants.
There are at most 4096 publication receipts per epoch; rotate before exceeding this limit.

Rotation cannot erase previously learned keys, copied secrets, old snapshots, or Git
history. Account-password reset does not recover identity keys or collection keys.
OS credential storage, identity replacement UI, independent security review, and exhaustive
power-loss fault injection remain separate work.

See [wire format](key-package-format.md), [API contract](api/group-key-delivery.md), and
[roadmap](roadmap.md).
