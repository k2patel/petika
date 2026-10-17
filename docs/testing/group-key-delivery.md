# Group-key delivery development test actions

Status: native identity, package, migration, and rotation tests are executable, as are
CLI/browser interoperability tests in both modes. Independent Python package fixtures
and upstream X-Wing draft-06 vectors validate the protocol beyond round trips.

## Executable gates

| Area | Runner | Evidence |
| --- | --- | --- |
| Identity and contact trust | Core identity/contact tests | Recovery, changed-key suspension, fingerprints, CAS, migration backups |
| Package crypto | Core packages tests and module fixtures | Bound-field mutations, wrong/unverified recipient, canonical headers, signatures, independent HPKE vectors |
| Envelope migration/rotation | Core collection-context tests | Both modes, authenticated bindings, old-wrapper rejection, legacy preservation |
| API authorization and durability | Server sharing/delivery tests | Editor/reader/admin-only denials, own grants, membership changes, stale epochs/revisions, journal failure, retry after restart, mirror exclusions |
| Real HTTP routing | Identity loopback tests and browser/CLI runner | Managed cookie and CLI sessions, headers and request limits, group operations |
| Native/WASM interop | `scripts/test_group_delivery.py` | Independent enrollments, mutual verification, native grants opened in WASM, browser rotation grants opened in CLI, both modes |
| Browser regressions | `scripts/test_web_ui.py` | Existing vault workflows, permissions, OTP, themes, mobile layout |
| Actual request/response shapes | `check_api_contracts.py --runtime` | Captured successful Rust delivery requests/responses checked against OpenAPI |

The browser CI job runs the cross-client workflow and captured-schema gate. Run locally:

```sh
cargo test --workspace --locked
PETIKA_CONTRACT_CAPTURE=target/delivery-contracts.json cargo test -p petika-server --test delivery --locked
python scripts/check_api_contracts.py --runtime target/delivery-contracts.json
python scripts/test_group_delivery.py
```

The browser runner requires built native binaries, built WASM assets, Python Playwright,
and Chromium. All fixtures are synthetic and servers use isolated temporary directories.
Exhaustive crash-boundary injection, all-route negative response schema validation, and
parallel multi-process membership race scheduling remain hardening work; tests of stale
state and held storage locks do not substitute for every power-loss boundary.

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

The `API contracts` job validates the contract and static positive/negative fixtures.
Rust, browser/provisioning, captured runtime schemas, and distroless jobs exercise actual
behavior separately. A passing schema gate does not establish cryptographic safety.
