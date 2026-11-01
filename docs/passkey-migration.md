# Move a legacy personal vault to browser passkeys

An existing personal version-1 vault can explicitly adopt the
[browser-passkey policy](browser-passkeys.md). Nothing migrates automatically.
This does not recover a forgotten vault passphrase and does not enable strict
biometric-only protection, shared collections or QR enrollment.

## User flow

Open **Settings → Move to passkey protection**. Enter the current vault passphrase,
choose an enrolled passkey or register a new one, and acknowledge that older clients
will no longer open the current vault. Registering a key requires the current account
password. Approve the fresh passkey request to authorize migration.

The original vault is decrypted inside a dedicated worker. Petika generates fresh
vault encryption secret material and a random passkey-wrapped secret, preserves all
entries and the Standard/Hybrid encryption mode, then encrypts a bound version-2
snapshot inside the version-3 passkey framing. It does not reuse the legacy data key.
The passphrase and PRF output never go to the server or local storage.

After acceptance, each secret action requires fresh passkey approval. Add another
working key using **Add an authorized passkey**. Changing the account password does
not alter vault encryption or recover a lost key.

## Transaction and retry behavior

The migration source endpoint returns only the signed-in user's personal ciphertext
and revision. It rejects recipient-enabled, entry-format and shared collections.
A fresh session-bound `migrate` WebAuthn ceremony produces one expiring write grant.
The server checks the source again at approval and publication, then compares the
expected revision while holding the snapshot lock. A competing save aborts cutover.
The encryption mode cannot change during migration. The server verifies public
framing, authorization and the source revision; it cannot independently prove that
the client decrypted the original ciphertext. The trusted client performs that check
locally, and the exact original copy is retained for recovery.

Before publication the server preserves the exact source snapshot record as
`snapshot.passphrase-backup.json`, with owner-only storage protections. An existing
identical backup permits retry; a different backup blocks migration for operator
review. It never overwrites either the backup or current pointer on that conflict.
The accepted revision is journaled before the current pointer changes. Existing Git
mirroring retains the old encrypted history and the new ciphertext/key wrappers.

A failed publication retains only the encrypted candidate, source revision and a
migration marker in the local draft. A reload asks for fresh approval if publication
is still required. If the server accepted the candidate but its reply was lost, the
client reconciles its operation ID and exact candidate before asking for a new
secret action. It neither repeats the edit nor blindly replays the old grant.
A competing accepted version requires exporting the encrypted draft and reviewing
the latest version; there is no automatic merge.

## Recovery limits

Keep the old passphrase for historical recovery and retain a complete encrypted
backup, the public server passkey ledger, deployment identity and working authorized
passkeys. The original snapshot and older Git revisions remain decryptable by their
old passphrase. Migration protects new encryption material; it cannot revoke secrets
already copied or erase old history. The original file is not a fallback that opens
the new current ciphertext.

Legacy CLI uploads cannot replace or downgrade the current version-3 vault. The old
CLI can still open the separately retained version-1 ciphertext. Extract its
`encrypted` field from the backup snapshot into a separate private file for historical
recovery; never replace a live current snapshot with it. Migration is one-way in the
UI. Operator restore must preserve accepted journals and use a compatible release.
Strict biometric provider integration, shared-vault migration, passkey removal/rotation
and complete server restore drills remain separate release gates.

Validation uses generated data: core tests compare old/new secret material in both
modes; server tests cover grants, conflicts and exact backup preservation;
`scripts/test_passkey_migration.py` exercises wrong-passphrase denial, explicit UI
migration, interrupted reply/reload, preserved entries/mode and old-client rejection.
Virtual WebAuthn verification is not hardware-biometric evidence.

See [local validation evidence](testing/passkey-migration-2026-10-31.json).
