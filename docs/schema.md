# Persisted schema and upgrades

The current persistence engine uses owner-only JSON files and atomic replacement,
not SQL. Every mutable account database and new snapshot journal record is versioned.
These version numbers are independent:

| Contract | Current version | Behavior |
| --- | --- | --- |
| Account database `schema_version` | 2 | Startup migration before requests; rejects newer schemas |
| Snapshot/journal `schema_version` | 1 | Validated on read; legacy unversioned records decode as v1 |
| Encrypted envelope `version` | 1 | Shared Rust parser; rejects unsupported encryption formats |
| Local recipient identity backup / encrypted bundle | 2 / 2 | Reads v1 without rewriting; explicit native save preserves `.v1.backup` before upgrading |
| HTTP API | `/v1` | Explicit route version |

The account database contains user IDs, password hashes, roles, group membership, a
persistent random deployment ID, signed public identities, and encrypted private bundles
with revision counters. Groups track membership generations and required rotation; a
rotation flag does not perform cryptographic rotation.
Names and memberships are server metadata and are not part of the encrypted Git mirror.
Secrets, including OTP seeds, are always inside the encrypted collection snapshot.

## Migration contract

1. Acquire the exclusive account database lock before reading or writing.
2. Parse and validate the version before serving requests.
3. For the initial unversioned account format (schema 0), preserve the original bytes
   in `accounts.schema-0.backup`, with the same owner-only storage protections.
4. Add schema version 1 and atomically replace the database. The backup is never
   overwritten by repeated startup.
5. Preserve schema 1 bytes in `accounts.schema-1.backup`, then atomically write schema 2
   with deployment ID, empty identity directory, and initial group generations. Matching
   backups allow retry; conflicting backups stop migration without overwriting them.
6. Reject unknown newer versions without modifying the database. Do not auto-downgrade.

Future changes must add explicit sequential migrations, backups, and tests for upgrade,
repeat startup, interrupted writes, and unsupported versions. The current schema-0
and schema-1 migrations are tested, including matching/conflicting backups and retries.
Immutable historical journal records are not rewritten simply to add a version field.

Before upgrading, stop writes and back up the **whole data directory**, Git mirror,
configuration, and client recovery material. Rolling back only an executable after a
schema upgrade is unsupported. Restore a matched backup with the compatible binary.
Account migration backups contain password hashes and must remain private.

Optional OTP fields are supported by this release's shared Rust core; earlier experimental
binaries may reject records containing them. Keep web assets and native clients on the
same release until a stable compatibility policy is published.

Recipient identity storage is a separate [local encrypted format](identity-format.md).
Local identity backup migration is independent of account migration. Enrollment APIs
store only encrypted bundles; group-key delivery remains pending.
