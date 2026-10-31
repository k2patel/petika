# Persistent synthetic macOS device-operation broker

Isolated first implementation slice for B01–B03 in the
[work plan](../../../docs/implementation-plan-git-biometric.md). No Petika account,
real vault, enrollment API, Git credential or user-supplied plaintext input is accepted.

## What is implemented

- Generates an enclave P-256 wrapping key with `whenUnlockedThisDeviceOnly`,
  `privateKeyUsage` and `biometryCurrentSet`. Stores its opaque hardware-wrapped
  representation, public bindings, an encrypted random device seed and one encrypted
  random test entry. This is not yet a Petika X25519/X-Wing device identity.
- Uses exclusive temporary file creation (0600), file sync, no-clobber hard-link
  publication and parent-directory sync. Loads only owner-held regular 0600 files
  within a 16 KiB limit and validates framing. Filesystem ancestors must be trusted.
- Show and Copy reconstruct the enclave key with a new `LAContext`, reuse duration
  zero, no fallback title and context invalidation after the protected ECDH operation.
  There is no cached seed, decrypted bundle or reusable biometric context.
- Internal requests bind action, device, ciphertext digest, nonce and monotonic age.
  Replays, mismatched scope, requests older than 30 seconds, clock reversal and busy
  reentrant access fail. Failed requests are consumed. At 1,024 consumed requests the
  broker fails closed; this harness is not an unbounded service.
- Transient Data buffers are reset on scope exit, with Swift/CryptoKit/OS copying
  limitations. The protected operation returns only a digest of generated test data
  to the harness. Copy uses an in-memory sink; it does not write the OS clipboard.

The broker is currently a library inside a synthetic executable, not an isolated IPC
service or a product enforcement boundary. Internal test injection is compiled into
its separate test target; there is no software-backend or passcode CLI mode.

## Build and test

```sh
swift test --package-path experiments/biometric-unlock/broker --scratch-path /tmp/petika-broker-build
```

Five software tests exercise actual wrapper/entry AEAD with software-only test keys:
per-action protection calls, replay and denial-after-success, action/device/digest/time
binding, persistence/no-clobber/private modes/unknown fields, and ciphertext/device
binding tampering. Software tests do not prove Touch ID prompting.

## Interactive generated-data checks

Only run when available to approve the prompts. Keep the file outside version control;
the repository's `.secrets` directory is ignored. The opaque enclave blob is sensitive
local credential state even though it is not a portable plaintext private key.

```sh
/tmp/petika-broker-build/debug/petika-broker-probe create .secrets/biometric-broker/credential.json
/tmp/petika-broker-build/debug/petika-broker-probe roundtrip .secrets/biometric-broker/credential.json
# Separate processes can also reopen it:
/tmp/petika-broker-build/debug/petika-broker-probe show .secrets/biometric-broker/credential.json
/tmp/petika-broker-build/debug/petika-broker-probe copy .secrets/biometric-broker/credential.json
```

Create refuses overwrite; it encrypts generated data to the public wrapping key and
needs no secret decryption. Roundtrip loads the persisted state in separately constructed
broker instances for Show and Copy and checks their generated-data digests match. Each
operation requests fresh biometric protection. Independently confirm that two prompts
actually appear; two successful cryptographic calls alone do not prove two visible prompts.
No secret bytes or digests are printed. Errors are generic and do not log private state.

## Remaining gates

Same-instance hardware prompting, user-cancelled prompts, lockout, enrollment-set changes,
reboot and unavailable-device lifecycle tests remain distinct checks. Product account,
deployment/collection/epoch bindings, real recipient material, shared-vault permissions,
authentication challenge evidence, IPC isolation, real clipboard/display lifetime and
browser/native bridge integration are not implemented. No iOS or Android claim follows
from this macOS harness. See [evidence](../../../docs/testing/device-broker-2026-10-31.json).
