# Authentication and sharing

**Planned; no login or access-control API is implemented.**

Keep server authentication distinct from local decryption. A proposed CLI browser-login
flow (or a code entered on another device for headless hosts) establishes a server session;
new-device enrollment must separately grant access to decryption keys.

Biometrics default on when supported and enrolled, with a local on/off control. Turning
biometrics off must not disable vault locking. An explicit passphrase fallback remains
available, including on headless Linux. Canceling a prompt leaves the client locked.
Choose reauthentication rules for security-setting changes and auto-lock defaults before
implementation. API hosting machines do not need biometric hardware.

Selected-password sharing requires recipient accounts and cryptographic access grants.
Decide whether recipients can edit, whether changes remain linked, invitation expiry,
and how grants rotate when a recipient is removed. Do not assume a link alone safely
implements sharing. Explain that revocation cannot retract a password already read.
