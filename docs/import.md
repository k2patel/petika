# Existing GPG store import

**Planned; no importer is implemented.**

Import existing `.gpg` entries by decrypting on the user's machine using their authorized
GPG key. Generate Petika records locally and encrypt them before upload. No existing
`pass` implementation is copied or translated, and its files and Git history are not
modified or imported into the Petika source repository.

Before implementation, define field mapping for first-line passwords, usernames, URLs,
and arbitrary trailing notes; duplicate handling; and unsupported entry reporting.
Reject path escapes and unsafe symlinks. Do not execute store extensions or Git hooks.

Verification must cover missing keys, canceled prompts, corrupt ciphertext, nested
stores, Unicode names, duplicate entries, partial failures, and source preservation.
Plaintext must not be written to logs or left in intermediate files.
