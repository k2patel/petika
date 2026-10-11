# Sync, backup, and recovery

**Planned; sync transport and retention are not yet finalized.**

The recommended design makes the API authoritative and Git a one-way encrypted mirror.
Clients submit changes against a known record revision; stale edits preserve both versions
for explicit resolution. Restoring an old value creates a new revision, rather than
rewinding the whole vault. Mirror outages queue updates and expose backup lag.

If direct Git writes are required, adopt and document a two-way protocol before implementation;
do not silently treat a mirror as an independent source of truth.

Backups need encrypted records, required key packages, format versions, sharing metadata,
and server configuration needed for restoration. Recovery credentials are kept separately.
A Git clone without decryption recovery material is not a usable disaster-recovery plan.
Maintain independent retained snapshots as well as the mirror, with retention and recovery
objectives chosen before deployment.

Acceptance requires restoring onto a clean host and fresh client without the original
server/device, and testing missing keys, incomplete mirrors, damaged snapshots, and rollback.
