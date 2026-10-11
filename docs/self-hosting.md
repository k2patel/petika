# Self-hosting

**No deployable server exists yet.** `petika-server` exits unsuccessfully and does not
listen on a network port. There is no Docker image, Compose stack, or production guide
claiming otherwise.

The intended release will include a documented single-server deployment and native
server binary in this repository. Before release, select persistent storage and an
authentication provider, define HTTPS configuration, migrations, health checks, log
redaction, upgrade/rollback procedures, and the backup destination.

The guide must identify every persistent volume and required recovery artifact, show
how to restore on a fresh host, and explain offline client behavior during outages.
Never put real secrets, private keys, or deployment credentials in this repository.
