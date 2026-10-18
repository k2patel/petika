# 0003 Client encryption and explicit recovery

Date: 2026-10-18.
Status: accepted architecture direction; recovery and assurance work is planned.

## Decision

Use client-side vault encryption by default, with usable decryption keys confined
to authorized clients and explicitly designated recovery holders. Keep encryption
method separate from key ownership, sharing authorization and recovery policy.
The same security baseline applies to personal, family and enterprise deployments.

Standard and experimental Hybrid remain the current vault protection choices.
GPG is import/interoperability tooling; it is not currently a vault encryption
backend. Adding one would require a separate format, migration and security review.

Personal vaults remain private. Shared vaults grant access to verified recipients.
Trusted-person recovery is opt-in. Organization recovery covers only explicitly
enrolled company vaults, with separate key custody, approval and audit controls.
Deployment administration does not automatically confer vault-decryption authority.
Account-password reset is distinct from recovery of vault contents.

S3/SSH backups are pushed by the server using server-stored protected destination
credentials. User-scoped backup API keys support external pull clients. The server's
backup master key protects destination credentials; it cannot decrypt users' vaults.

## Security objectives and limits

Protect stolen server storage and backup ciphertext without giving the application
server a universal vault-decryption key. Retain usable recovery after loss of devices
or authenticators through deliberately configured recovery material.

A compromised server can serve malicious browser code. Client-side cryptography
alone does not address this; independently distributed verified clients, trusted
updates, monitoring and response are separate controls. Compromised unlocked clients
and recipients who copy secrets remain outside a promise of retrospective revocation.

Additional recovery holders increase access and compromise risk. Specify policy
binding, recipient verification, custody, notification and revocation before enabling
recovery. Multiple approvals are not equivalent to cryptographic threshold control.
No silent administrator escrow or forced enrollment of existing private vaults is permitted.

## Consequences

The UI must distinguish vault protection, sharing/recovery, GPG interoperability,
and server backup credentials. It must identify planned features and show who may
recover a vault without implying that an account administrator can unlock it.

NIST, OWASP and other relevant controls are product goals irrespective of audience.
Implement and verify their applicable technical controls, record operational duties,
and track external assessment/validation gaps separately. Do not claim certification
from algorithm selection or successful functional tests.

Follow the [security and compliance alignment plan](../security-alignment-plan.md)
for ordering, evidence and release gates. Preserve the existing
[group delivery design](0002-per-user-group-key-delivery.md) until a separately
reviewed migration explicitly changes its key or trust model.
