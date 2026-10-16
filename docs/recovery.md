# Sync, backup, and recovery

## Implemented

The API is authoritative and Git is a one-way encrypted mirror. Clients submit whole
collection snapshots against a known revision; stale writes are rejected. The web client
retains encrypted drafts for explicit conflict resolution, and the CLI supports explicit
pull/push with revision checks. There is no per-record merge or restore interface.

The server journals accepted revisions and retries local Git mirroring after failures.
Mirror status exposes progress. Remote Git pushes remain an operator task. Managed
collections have separate mirrors; account and group metadata is not mirrored. See
[deployment operations](deployment.md#operations) and [managed CLI accounts](cli-accounts.md).
Git edits are not imported automatically into the API.

## Backup requirements

Back up the complete server data directory, mirrors, configuration, and client recovery
material. Keep collection passphrases separately and securely; a Git clone without the
required decryption material cannot recover secrets. Future per-recipient key packages
and their recovery material must also be covered when implemented.

Maintain independent retained backups in addition to the local mirror. A mirror on the
same disk is not disaster recovery. Retention, remote replication, and recovery objectives
remain operator decisions. Follow the [schema backup/upgrade rules](schema.md); restoring
only ciphertext does not restore account identities or sharing permissions.

## Remaining validation and tooling

Automated account recovery, a historical restore UI, and a complete clean-host recovery
workflow remain unfinished. Existing encryption and mirror tests cover local round trips,
hybrid recovery, and accepted revision history; they do not establish disaster recovery.

Acceptance requires restoration onto a clean host and fresh client without the original
server/device, plus missing-key, incomplete-mirror, damaged-snapshot, and rollback tests.
A valid old encrypted snapshot can still authenticate; revision checks are not protection
against an operator restoring an older server database. Define how restoration creates
new current revisions without silently overwriting concurrent changes.
