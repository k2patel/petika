# Authentication and sharing

> **Policy update, 2026-10-31:** Both browser passkey verification (biometric or OS PIN)
> and strict biometric-only protection are supported as explicit policy choices.
> The browser personal-vault implementation is described in [browser passkeys](browser-passkeys.md).
> Strict biometric-only creation remains blocked until a production provider exists.
> Earlier mandatory-biometric statements below apply to the strict policy; they do
> not describe the browser-passkey policy. Existing vaults are not auto-migrated.

Petika-managed accounts, session cookies, administrator user/group management, and
collection read/edit permissions are implemented in the experimental web UI. See
[web authentication and sharing](web-ui.md#identity-and-group-boundaries) for the
current security model and limitations, and [setup](setup.md) for provisioning.
[Managed CLI browser approval](cli-accounts.md) is implemented. Optional OpenID Connect remains planned.

Keep server authentication distinct from local decryption. The CLI browser-approval
flow (including a code entered on another device for headless hosts) establishes a server session;
new-device enrollment must separately grant access to decryption keys.

Planned biometric clients will default on when supported and enrolled, with a local on/off control. Turning
biometrics off must not disable vault locking. An explicit passphrase fallback remains
available, including on headless Linux. Canceling a prompt leaves the client locked.
The web client already provides configurable inactivity locking and reauthentication
for CLI approval. Native unlock and security-setting reauthentication policies remain open. API hosting machines do not need biometric hardware.

Current sharing is at collection level with read/edit membership. Verified per-user
[group access](group-access.md) and explicit fresh-key rotation are implemented. Individual selected-password
sharing still requires a design for recipient accounts and cryptographic access grants.
Decide whether recipients can edit, whether changes remain linked, invitation expiry,
and how grants rotate when a recipient is removed. Do not assume a link alone safely
implements sharing. Explain that revocation cannot retract a password already read.
