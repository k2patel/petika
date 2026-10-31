# Security policy

Petika is pre-release experimental software and has no production-supported versions.
Do not use it to store real secrets yet.

Report suspected vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/k2patel/petika/security/advisories/new)
if that feature is enabled. If unavailable, open an issue requesting a private reporting
channel without including vulnerability details or secrets. The maintainer must enable
private reporting before the first production-supported release.

Include affected revision, reproduction steps using synthetic data, and expected impact.
Never send actual passwords or private keys. No response-time commitment exists yet.

## Public repository and credentials

Keep deployment passwords, access tokens, signing keys, provisioning profiles,
service-account credentials, and real vault or recovery data out of Git, issue bodies,
logs, screenshots, and build artifacts. Use encrypted CI secrets, an OS credential
store, or private local storage. Existing mobile developer accounts can be reused;
their credentials and signing material must not be copied into this repository.

GitHub secret scanning and push protection cover recognized secret patterns. The
Secret scanning workflow also scans fetched Git history with checksum-pinned Gitleaks.
Local pre-push check with Gitleaks 8.30.1:

```sh
gitleaks git . --log-opts="--all" --redact --no-banner
gitleaks git . --staged --redact --no-banner
```

The four narrowly scoped exceptions in `.gitleaks.toml` match exact public
cryptographic test vectors in exact fixture files. They are synthetic HKDF outputs
or published RFC/X-Wing inputs; never use those values for a real identity or vault.
New fixture values require provenance review. Do not allowlist a real credential.

Ignore rules and scanners cannot guarantee that every secret is detected. Review
staged files before pushing. If a real credential reaches Git history, revoke or
rotate it first, then coordinate history cleanup; deleting the current file is
insufficient.
