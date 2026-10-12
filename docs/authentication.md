# Authentication and sharing

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
Choose reauthentication rules for security-setting changes and auto-lock defaults before
implementation. API hosting machines do not need biometric hardware.

Selected-password sharing requires recipient accounts and cryptographic access grants.
Decide whether recipients can edit, whether changes remain linked, invitation expiry,
and how grants rotate when a recipient is removed. Do not assume a link alone safely
implements sharing. Explain that revocation cannot retract a password already read.
