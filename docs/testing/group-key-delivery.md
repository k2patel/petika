# Group-key delivery development test actions

Status: contract validation and local recipient-identity Rust tests are executable.
Server API, package delivery, and client enrollment workflow tests remain **planned**.
Never mark a feature complete based on schema validation or a round-trip test alone.

## Development gates

| Step | Test action and expected evidence | Intended runner | Status |
| --- | --- | --- | --- |
| Design/API contract | Validate OpenAPI, positive/negative schema fixtures, operation-to-test mapping | `python scripts/check_api_contracts.py`; CI `API contracts` | Implemented |
| Recipient key generation/storage | Independent keys, encrypted bundle round trip, wrong passphrase, malformed keys, size/KDF limits, no plaintext serialization, owner-only persistence | `identity.rs` integration tests and identity module unit tests in workspace CI | Implemented; local macOS run, cross-platform CI pending |
| Identity verification | Stable fingerprint vectors, modified user/deployment/key changes fingerprint, unverified/changed identity blocks grants, encrypted pin conflicts retain drafts | Core tests plus CLI/web workflows | Partial: fingerprint vectors/tampering pass; contact pins and grant blocking pending |
| Package encryption | Upstream HPKE/X-Wing vectors, independent interoperability, both modes, wrong recipient, signature failure, mutation of every authenticated field, bad encoding/size | Core tests and WASM fixtures | Planned |
| Enrollment/directory APIs | Every operation in `group-key-delivery-cases.json`, real HTTP session/cookie/CLI token checks, atomic concurrent enrollment | Server unit + HTTP integration tests | Planned |
| Authorization/delivery | Read-only/admin-only/removed/disabled denials; own packages only; pending enrollment; membership/identity change between read and commit | Server integration tests | Planned |
| Durable updates/migration | v1 unchanged until explicit migration; v2 reopens in CLI/WASM; downgrade denied; crash before/after journal/pointer; idempotent restart retry | Core/server integration + fault injection | Planned |
| CLI integration | Two users unlock without shared group passphrase; headless login still works; wrong identity retains local store; offline use; no key material on stdout/stderr | CLI process integration tests | Planned |
| Web integration | Enrollment, verification, pending/ready states, worker lock clears identity, no plaintext localStorage, both modes, read-only denial | Existing Playwright runner extended | Planned |
| Recovery/new device | Export on client A, restore on fresh B, matching fingerprints and group unlock; lost passphrase/keys fail clearly; account reset does not recover keys | CLI/web end-to-end | Planned |
| Removal rotation (following milestone) | Removed user's cached keys fail against new epoch; remaining members decrypt; interrupted rotation preserves committed state | Core/server/CLI/web integration | Planned |

Implemented: `crates/petika-core/tests/identity.rs` and identity module unit tests, including
independent public-key/fingerprint vectors and authenticated private-key mismatch rejection.
The web CI job compiles the shared core to WASM; browser identity workflows are not yet exposed.

Proposed remaining runtime test files: `crates/petika-core/tests/sharing.rs`,
`crates/petika-server/tests/sharing.rs`, `crates/petika-cli/tests/sharing.rs`, and
`scripts/test_sharing_api.py`. These paths are a plan, not existing coverage.
Extend `scripts/test_web_ui.py` for browser flows. Existing workspace Cargo and web CI
jobs will run their respective tests; wire the new HTTP runner explicitly when added.

## Per-operation contracts

[group-key-delivery-cases.json](group-key-delivery-cases.json) enumerates each proposed
operation with required success and rejection cases. The contract checker fails for
missing/extra operation mappings or empty test requirements. HTTP implementation tests
must exercise these cases against a real isolated server, validate response bodies
against the OpenAPI schema, and assert status codes and unchanged durable state on error.
A passing schema check does not assert that those scenarios run.

All mutations must additionally test missing/expired/revoked sessions, disabled users,
legacy bearer rejection, missing custom header, cross-site request metadata, wrong media
type, duplicate fields, unknown fields, oversize bodies, storage failure, and secret-free
logs. Reads test resource enumeration and cross-user access. Parameterized tests must
cover every relevant route; only checking the happy path is insufficient.

Race tests use barriers/failpoints to force both orderings, not timing sleeps. Crash tests
restart from each durable-write boundary and inspect journals/current pointers. Crypto
fixtures contain synthetic data and known expected bytes; do not generate all expected
results with the code under test. Cross-client checks cover native and WASM for both modes.

## Run the available gate

```sh
python3 -m venv /tmp/petika-contract-tests
/tmp/petika-contract-tests/bin/pip install -r scripts/requirements-contracts.txt
/tmp/petika-contract-tests/bin/python scripts/check_api_contracts.py
```

The `API contracts` GitHub Actions job runs on pushes and pull requests. It validates the
proposed contract and fixtures only. The existing Rust, web/provisioning, and distroless
jobs continue to test implemented functionality. Runtime sharing coverage stays planned
until the associated behavior, assertions, and CI invocation are committed together.
