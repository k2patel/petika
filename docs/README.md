# Documentation

Use the [implementation roadmap](roadmap.md) for completed milestones and remaining work. Feature guides document implemented behavior
and limitations.

- [User installation and everyday tasks](user-guide.md)
- [Administrator installation, buckets, backups and recovery](administrator-guide.md)
- [Chromium extension preview installation and build](../clients/extension/README.md)
- [Off-site backup configuration](offsite-backups.md)
- [Simple security configuration and UI contract](settings-experience.md)
- [Security and compliance alignment plan](security-alignment-plan.md)
- [Multi-device biometric-key research](research/multi-device-biometric-keys.md)
- [Cryptographic profile direction](decisions/0004-cryptographic-profile-direction.md)
- [Cryptographic profile assessment and wrapper review](research/cryptographic-profiles.md)
- [Client encryption and explicit recovery decision](decisions/0003-security-and-recovery-baseline.md)
- [Per-user group access and rotation](group-access.md)
- [Package and envelope wire formats](key-package-format.md)
- [Web UI](web-ui.md)
- [First-run and unattended setup](setup.md)
- [Schema and migrations](schema.md)
- [Product requirements](requirements.md)
- [Architecture and open decisions](architecture.md)
- [Per-user group-key delivery design](decisions/0002-per-user-group-key-delivery.md)
- [Group-key delivery API contract](api/group-key-delivery.md)
- [Group-key delivery test actions](testing/group-key-delivery.md)
- [Local recipient identity format](identity-format.md)
- [Development and verification](development.md)
- [Container and source deployment](deployment.md)
- [Reverse proxy and optional HTTPS](reverse-proxy.md)
- [Brand identity](branding.md)
- [Self-hosting](self-hosting.md)
- [GPG store import](import.md)
- [Authentication and sharing](authentication.md)
- [Sync, backup, and recovery](recovery.md)

Implemented: encrypted CLI and Rust/WASM web client, standard/hybrid setup modes,
local GPG import, managed accounts, user/group permissions, website OTP, encrypted
snapshot API and Git mirroring, first-run/environment provisioning, versioned storage,
distroless/push-runtime deployment, and an experimental Chromium toolbar extension. The shared core also implements local recipient identities
and encrypted recovery, plus verified contact pins and key-change suspension. CLI/browser enrollment, verified encrypted group delivery, explicit migration, and
fresh-key rotation are implemented.
See the roadmap for completed work, next actions, and remaining integrations.

- [Managed CLI accounts](cli-accounts.md): browser approval, sessions, and encrypted collection pull/push.
