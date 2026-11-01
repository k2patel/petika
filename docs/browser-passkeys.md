# Browser passkeys and strict biometric protection

The October 31 policy update allows two explicit protection policies. An account
password authenticates the user to Petika. A separately authorized key unlocks a
vault. Any one enrolled vault key can unlock its own wrapper around the same random
vault secret; the keys are not combined.

| Policy | Approval | Availability |
| --- | --- | --- |
| Browser passkey | Fresh WebAuthn user verification for each secret action; the OS may offer fingerprint, face or PIN | Implemented for personal vaults with WebAuthn PRF support |
| Strict biometric | Fresh biometric-only protected-key operation; no PIN, password or recovery-string fallback | Explicit setup choice, blocked until a production protected-key provider is connected |

The browser policy deliberately permits PIN verification. Neither the WebAuthn UV
flag nor a platform-authenticator capability proves that a biometric was used.
A synced passkey may be usable on several devices; a credential is not proof of one
physical device. The strict native architecture remains a separate implementation
track. Selecting strict mode never creates a browser-policy vault.

## Setup and compatibility

The default server build includes `browser-passkeys`. Configure `PETIKA_ENDPOINT`
to the canonical HTTPS origin, or `http://localhost:port` for local development.
Fresh personal vault setup offers both policies and defaults to browser passkeys
when that endpoint is valid. `PETIKA_FRESH_VAULT_POLICY` accepts `legacy`,
`browser-passkey`, or `strict-biometric`. Strict mode blocks creation until a
compatible provider is available. Builds without the feature retain legacy setup.
Setup registers a passkey first, then waits for a separate **Verify passkey and
create vault** click. It never chains registration and verification behind one click.
If registration was saved but its reply or later verification failed, reload/setup
selects the existing public credential so retry does not recreate an excluded key.
New registration requests a discoverable, user-verified credential; duplicate-key
exclusion remains enforced. Existing credentials are never deleted during retry.

Existing collections retain their original protection and are never silently
converted. Legacy personal version-1 vaults can [explicitly migrate](passkey-migration.md)
with their current passphrase and a fresh passkey ceremony. Groups and QR enrollment
are not implemented in this browser flow.

The JavaScript client uses standard `navigator.credentials.create/get` APIs,
without browser-name detection or an extension. WebAuthn availability alone is
insufficient: the chosen browser and authenticator must provide the PRF extension
with a 32-byte result. Missing PRF, missing user verification, cancellation or a
mismatched credential denies the action. Browser engines must be tested with their
actual authenticators before claiming support; the automated Chromium test uses a
virtual authenticator and supplies no hardware-biometric evidence.

## Encryption and authorization

Registration requires the current account password and a server-verified WebAuthn
registration. The public credential ledger is stored in `passkeys.json` beside the
account database. It contains public verification keys and counters, never PRF
outputs, vault secrets or authenticator private keys.

Each secret action fetches the current API snapshot, then requests a fresh,
session-bound WebAuthn challenge scoped to action, credential, personal collection,
revision and operation ID. The maintained `webauthn-rs` verifier checks origin,
RP binding, challenge, signature and user verification. Challenges expire and are
consumed once. Credential revisions reject overlapping ceremonies based on stale
counter state. Write grants expire after 30 seconds and are consumed once before
candidate validation. Another session cannot consume them.

PRF output stays in the browser. HKDF-SHA256 derives a wrapping key; AES-256-GCM
wraps a random 32-byte vault secret separately for each authorized passkey.
Authenticated data binds the origin, deployment, account, collection, epoch,
credential, policy and PRF input. A version-3 `petika-passkey-vault` object contains
these public parameters, encrypted wrappers and the existing bound version-2
encrypted snapshot. Password login cannot decrypt this object.

One dedicated worker unwraps the key and executes one approved operation, then
frees the WASM session and terminates. No reusable vault key or PRF result is
returned to the page or persisted. The page receives the requested output, such as
a password or edit fields. Reveal and OTP displays expire; browser memory clearing
is best effort. A trusted page and origin remain part of this policy's security
boundary: compromised application JavaScript can misuse an approved PRF result.
Server action grants constrain publication but cannot cryptographically restrict
which plaintext a malicious client reads after obtaining the vault secret.

Adding a key verifies the new key, then requires an existing authorized vault key
to wrap the same secret. Both keys can subsequently unlock independently. Removing
or replacing keys requires epoch rotation and is not implemented; deleting public
metadata alone does not revoke a key's access to old ciphertext.

## Writes, recovery and boundaries

The current API remains authoritative. Version-3 framing travels in the existing
snapshot journal and ciphertext-only Git mirror. It does not enable the planned
Git-authoritative conditional push protocol or per-entry delta storage.

Writes use compare-and-swap against the fetched revision. A competing update keeps
the encrypted local draft for download and review; it never merges or overwrites
it automatically. A lost reply reconciles operation ID and candidate before asking
for another approval. Only ciphertext and revision are stored in local storage;
one-use grants are held in memory. Lock or page lifecycle cancellation rejects late
results. Legacy write routes cannot replace passkey vaults or downgrade them to a
passphrase envelope.

Keep another working enrolled passkey and a complete encrypted backup including
wrappers. Back up the server's public credential ledger with accounts and snapshots.
The legacy CLI cannot open version-3 vaults. Shared/recipient collection migration,
passkey removal/rotation, strict provider integration and complete restore drills
remain release gates. A lost passphrase is not recoverable by adding a new passkey;
migration first requires a working method to decrypt the old collection.

Tests: `node --test scripts/test_passkeys.mjs`, core `passkey_vault` tests,
server passkey tests, and `scripts/test_browser_passkeys.py` with Python Playwright.
All fixtures use generated data. No production vault, key or biometric is exercised.
See [local validation evidence](testing/browser-passkeys-2026-10-31.json).

Standards: [WebAuthn user verification](https://www.w3.org/TR/webauthn-3/#user-verification)
and [PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension).
