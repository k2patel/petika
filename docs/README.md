# Documentation

Use the [implementation roadmap](roadmap.md) for the current checklist and next milestone:
automatic per-user group-key delivery. Feature guides document implemented behavior
and limitations.

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
- [Brand identity](branding.md)
- [Self-hosting](self-hosting.md)
- [GPG store import](import.md)
- [Authentication and sharing](authentication.md)
- [Sync, backup, and recovery](recovery.md)

Implemented: encrypted CLI and Rust/WASM web client, standard/hybrid setup modes,
local GPG import, managed accounts, user/group permissions, website OTP, encrypted
snapshot API and Git mirroring, first-run/environment provisioning, versioned storage,
and distroless deployment. The shared core also implements local recipient identities
and encrypted recovery, plus verified contact pins and key-change suspension. Their
enrollment and group-delivery interfaces remain pending.
See the roadmap for completed work, next actions, and remaining integrations.

- [Managed CLI accounts](cli-accounts.md): browser approval, sessions, and encrypted collection pull/push.
