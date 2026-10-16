# Existing GPG store import

The native CLI imports `.gpg` entries through the user's local GnuPG installation.
The distroless server image deliberately contains no GnuPG or private GPG keys.

```sh
petika init --encryption standard --import-gpg /path/to/password-store
petika init --encryption hybrid-post-quantum --import-gpg /path/to/password-store
petika import-gpg /path/to/password-store
```

Choose one init command for a new store. Both modes support import. Use `--gpg-home`
for a dedicated GnuPG home. GPG agent must be able to unlock the authorized key.
Existing names are rejected unless `--replace` is supplied to `import-gpg`.

Relative paths become encrypted entry names. The first line is the password;
remaining lines are retained as notes. Username/user/login and URL/website fields
are also extracted. Imports reject symlinks and skip `.git` and `.extensions`.
The importer saves only after every file succeeds, leaves source files unchanged,
and never imports source Git history. Decrypted bytes remain in memory.

Full GPG key management in the UI remains planned: creation, inspection,
public-key export, expiry changes, and revocation. No such UI exists yet.
