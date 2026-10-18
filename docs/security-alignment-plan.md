# Security and compliance alignment plan

Date: 2026-10-18. Baseline: `b55fad4`. Status: implementation plan.

Petika will pursue the strongest practical alignment with recognized security and
privacy guidance across every supported deployment. Personal, family, and enterprise
use share the same security baseline. Audience size is not a reason to defer key
protection, strong authentication, auditability, recovery, or independent assessment.

The accepted architecture is [client-side vault encryption with explicit recovery](decisions/0003-security-and-recovery-baseline.md).
This plan turns that architecture into ordered work and measurable release gates.
Existing experimental capabilities are inputs to assessment, not completed compliance
controls. Runtime deployment and operating evidence must be verified separately from code.

## Standards and assessment targets

These are Petika planning targets. A source mapping identifies relevant guidance;
it does not establish equivalence or prove conformance. Freeze exact editions,
requirement identifiers, and assessment scope in the control register during Phase 0.
Review updates each quarter and before a supported release; track drafts separately
from adopted final requirements.

| Reference | Target for Petika | Evidence boundary |
| --- | --- | --- |
| [OWASP ASVS 5.0](https://owasp.org/projects/asvs) | Assess all applicable Level 1–3 requirements; reach Level 2 as an intermediate milestone and Level 3 as the application target. | Requirement-by-requirement results for the web/API surface. No level claim while required controls remain open. Native/mobile surfaces need additional platform assessments. |
| [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) | Target AAL2 authentication; design a hardware-backed AAL3 path for privileged and recovery operations. | Full authenticator, lifecycle, session, recovery, and cryptographic requirements. A passkey feature alone proves neither level. |
| [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) | Explicit lifecycle and custody for every key type. | Key inventory, policies, implementation, rotation and recovery exercises. |
| [FIPS 140-3 and CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules) | Investigate and implement a validated cryptographic path; start feasibility work now, regardless of audience. | Actual module certificate, security policy, approved mode, module boundary and supported operating environments. Algorithms alone do not confer validation. |
| [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) and [800-53A Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/a/r5/final) | Use the control catalog and assessment methods to cover technical and operational controls. Account for published catalog updates, including release 5.2.0. | Document selected controls/enhancements, parameters, applicability, and examination/testing results; do not assert an entire federal baseline by association. |
| [NIST CSF 2.0](https://www.nist.gov/itl/smallbusinesscyber/nist-cybersecurity-framework-0) and [SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | Cover governance, identification, protection, detection, response, and recovery. | Accountable owners, risk register, independently retained monitoring, and incident exercises. |
| [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) | Secure development and release lifecycle. | Reviewed changes, protected builds, dependency inventory, vulnerability response and verified releases. |
| [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) and [SOC 2](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services?visualEditor=convert) | Build the risk-management, change-control and operating evidence these assurance programs need. | ISO certification concerns a scoped management system; SOC 2 is a scoped service-organization examination. Product features alone establish neither. |
| [GDPR](https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/application-gdpr_en), [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html), and [NIST SP 800-171 Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final) | Map privacy, access, safeguards and accountability requirements into the same register, rather than postponing supporting controls. | Legal/contractual applicability, organizational duties and applicable editions still need a scoped determination. Encryption and self-hosting do not settle that determination. |

Not every control can be maximized simultaneously. For example, exhaustive logs can
expose private metadata; recovery availability introduces additional key holders.
Resolve conflicts through a recorded threat/privacy analysis and independently
reviewed safeguards. Preserve the agreed vault confidentiality boundary.

## Architecture constraints

- Encrypt and decrypt vault contents on authorized clients. Account login, vault
  unlocking, sharing authorization, recovery authorization and backup access are
  separate operations with separate credentials.
- Keep Standard and experimental Hybrid protection explicit. GPG remains import
  and interoperability tooling unless a separately reviewed vault format is added.
- Store only protected private-key bundles on the server. There is no universal
  server-held vault-decryption key. Organization recovery applies only to explicitly
  enrolled organization vaults, not personal vaults.
- Preserve user-scoped API pull backups and server-owned S3/SSH push backups.
  Server-held destination credentials and repository passwords cannot unlock vaults.
- Separate daily administration from recovery authority. Make enrollment into a
  recovery policy visible and cryptographically authorized by an existing client.
- Treat compromised clients, malicious server-delivered browser code, rollback,
  metadata disclosure, and previously copied secrets as distinct threats. Do not
  describe client-side encryption as complete protection against a malicious server.
- Retain safe migration and restore paths for existing formats. New policies must
  not silently discard ciphertext, weaken protection, or make old backups unreadable.

## Current position

This is the initial gap inventory, not a completed standards assessment. “Partial”
means relevant implementation exists but the target and operating evidence remain open.

| Area | Initial status and evidence | Remaining gap |
| --- | --- | --- |
| Client encryption and sharing | Partial: [core](../crates/petika-core/src/crypto.rs), [group design](decisions/0002-per-user-group-key-delivery.md), CLI/WASM interoperability tests. | Independent cryptographic review, device-specific revocation design, stronger rollback/trust guarantees, validated-mode feasibility. |
| Authentication | Partial: [accounts](../crates/petika-server/src/accounts.rs), sessions, reauthentication and CLI approval. Account passwords currently allow 12 characters. | Account MFA/passkeys, updated password policy, comprehensive authenticator recovery and lifecycle assessment. Website TOTP is not account MFA. |
| Transport and deployment | Partial: [proxy guidance](reverse-proxy.md), [deployment manifests](../deploy/kubernetes/deployment.yaml). | Enforced secure remote defaults and live deployment evidence. Last recorded homelab deployment used HTTP; recheck before rollout. |
| Backups | Partial: [push jobs](offsite-backups.md), API pull, synthetic encrypted round trips and [Kubernetes recovery evidence](testing/kubernetes-recovery-2026-10-18.json). | Real independent destinations, production alerting, immutable/isolated retention, master-key rotation and measured recovery objectives. |
| Recovery policies | Partial: encrypted identity backup, collection recovery passphrases and [restore tools](recovery.md). | Trusted-person and organization recovery with authorization, approvals, cancellation and abuse tests. |
| Audit and incident response | Planned: [roadmap](roadmap.md). | Event pipeline, external evidence, actionable alerts, containment and incident exercises. |
| Release assurance | Partial: [CI](../.github/workflows/ci.yml), locked dependencies, tests and license checks. | Signed artifacts, verifiable provenance, SBOM, vulnerability gates, protected update delivery and independent review. |
| Privacy and governance | Planned; [security policy](../SECURITY.md) remains experimental. | Data inventory, retention/deletion rules, control ownership, service commitments and assessment evidence. |

## Implementation phases

Phases are dependency ordered, not calendar promises. Assign named owners and size
work after Phase 0. FIPS feasibility and critical-risk fixes start early; they do
not wait for the final assessment. Work may run concurrently where dependencies allow.

### Phase 0 Establish the control and threat baseline

Deliver a versioned control register, threat model, data-flow diagrams and inventory
of components, secrets, public metadata, dependencies and deployment boundaries.
Include authentication bypass, malicious administrators, browser code substitution,
compromised build systems, stolen backups, recovery abuse, rollback, denial of service,
and attacker-controlled backup destinations.

Map exact source requirements to controls below. Record named implementation owners,
independent reviewers and operator responsibilities. Freeze an initial ASVS scope and
selected 800-53 controls/enhancements; crosswalk other sources without treating a
crosswalk as evidence. Record applicability and exceptions with rationale, reviewer
and expiry. “Personal use” is not an adequate exclusion reason.

Exit: every in-scope requirement has an owner, assessment method, current status,
implementation issue and evidence location. Unknowns remain visible, not marked passed.

### Phase 1 Secure transport and account access

Make HTTPS and secure cookies the remote deployment defaults, with explicit loopback
or development exceptions. Test proxy trust, origin checks, CSRF, headers, sessions,
CLI authorization and backup-token isolation together.

For account passwords, adopt a minimum of 15 characters, common/compromised-password
screening, long-password support, no arbitrary composition rules, and changes on
compromise rather than periodic expiry. Preserve a separate offline-threat-based
vault-passphrase policy. These choices align with the account-password guidance in
[SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html).

Implement WebAuthn/passkeys and authenticator enrollment, replacement, removal and
recovery. Require strong reauthentication for grants, recovery-policy changes,
backup credential changes and privileged administration. Target hardware-backed,
non-exportable authenticators for the stronger privileged path; synced passkeys
must not be labeled AAL3. Session and recovery details require the complete assessment.

Exit: automated negative tests cover replay, phishing-origin mismatch, session theft
containment, lost authenticators, bypass through legacy endpoints and privilege changes.
Existing-user migration is explicit and cannot silently lock users out of their vaults.

### Phase 2 Strengthen key custody and cryptographic evolution

Inventory vault, identity, device, recovery, signing, backup-repository, destination
master, API and TLS keys. Define purpose, generation, custody, storage, activation,
rotation triggers, compromise response, retirement and recovery for each.

Add OS-backed client key protection and a reviewed device-enrollment/revocation
model. Current identities are shared across a user's devices; removing a server
session alone does not cryptographically revoke copied keys. Specify and review
any device-key format change before implementation. Add crash-safe rewrapping and
rotation for server backup credentials, with independent master-key custody and
restart/restore tests.

Start the FIPS feasibility track: inventory every cryptographic operation and
candidate module; verify certificates, security policies and platform boundaries;
prototype approved-mode operation; identify migration and interoperability costs.
Explicitly assess native, server, browser/WASM and backup tooling separately. A
validated server module does not validate browser cryptography or restic. Publish
unsupported-platform gaps instead of claiming a universal validated mode.

Preserve format/suite identifiers and downgrade rejection. Keep experimental Hybrid
opt-in. Review its pinned construction against current standards and reviewed
implementations before proposing a new default. FIPS restrictions must not silently
fall back to an unvalidated provider. A future validated suite needs authenticated,
recoverable migration and independent review; adopting it does not authorize
server-side vault decryption.

Exit: reviewed key lifecycle and migration specifications, lost/compromised-key
exercises, authenticated migration tests, and a concrete FIPS feasibility report.
Unresolved validation gaps remain tracked through Phase 6.

### Phase 3 Implement explicit sharing and recovery policies

Provide a personal recovery kit, opt-in trusted-person recovery, and explicitly
scoped organization recovery. Keep private personal vaults separate from company
vaults even when the same person administers the deployment.

Specify protected recovery-key custody, recipient verification, policy enrollment,
notifications, cancellation, delays and multiple-person approval where configured.
Approvals must not be represented as cryptographic threshold protection unless the
reviewed protocol actually provides it. Prefer established reviewed constructions;
do not invent a new threshold scheme. Ordinary server administration must not grant
silent recovery access. Account reset must not be presented as vault recovery.

Exit: tests cover a lost device, lost authenticator, forgotten unlock secret, malicious
recovery requester, revoked guardian, compromised administrator, unavailable approver,
stale policy, offline access and restore to a fresh device. The UI names who can
recover each vault and what happens when all recovery material is lost.

### Phase 4 Add detection and operational resilience

Record authentication, authenticator changes, administration, grants, rotations,
recovery-policy changes, backup jobs, key changes, exports and release changes.
Exclude plaintext vault data, passwords, tokens and private keys; minimize identifying
metadata. Distinguish server-observed actions from client-reported local actions:
the server cannot prove every offline reveal or plaintext copy occurred.

Export audit evidence to an independently controlled destination. Detect missing
heartbeats, log gaps, repeated failures, unusual administrative changes and overdue
backups. Hash chaining alone cannot stop a server administrator deleting all logs.
Exercise external alert delivery and incident response, including compromised
server code, stolen signing keys, recovery abuse and restore from old account state.

Configure independent off-site copies; evaluate immutable or separately administered
retention. Measure recovery point and recovery time objectives and approve numerical
targets before declaring operational readiness. Test loss of the primary server,
loss of the backup master key, provider failure, ransomware deletion attempts, and
restores that might re-enable old API keys, sessions or push schedules.

Exit: independently retained exercise evidence, working alerts, verified restores,
defined operational ownership, and tested containment/revocation procedures.

### Phase 5 Establish release and privacy assurance

Protect source/build credentials, require reviewed security-sensitive changes, pin
build inputs, generate an SBOM, and scan dependencies and artifacts. Sign releases
and provenance; clients/operators must verify them before installation. Specify
rollback and signing-key compromise handling. Native updates must preserve the
trusted-client boundary; browser CSP and integrity controls do not prove protection
against a server that controls the root HTML and script delivery.

Define collection and retention of account metadata, logs, IP addresses, diagnostics
and backup metadata. Provide access/export/deletion workflows and explain delayed
deletion in retained backups. Encrypted personal data is not automatically anonymous.
Track applicable organizational/privacy obligations without collecting unnecessary
identity documents merely to claim stronger authentication.

Update vulnerability reporting, response ownership and supported-version policies.
Set measurable patch and response targets after staffing is assigned; until then,
record them as release blockers rather than inventing service guarantees.

Exit: release verification rejects tampered artifacts, dependency findings are
triaged, privacy/retention tests pass, and supply-chain compromise exercises succeed.

### Phase 6 Independently assess and maintain assurance

Commission an independent application penetration test and cryptographic design /
implementation review. Assess all applicable ASVS target requirements and selected
NIST controls against specific releases and configurations. Resolve critical/high
findings before production support; exceptions cannot preserve a conformance claim
when a required control is unmet. Retest fixes and document residual risks.

Complete validated-mode engineering and external validation work needed for any
FIPS claim, or publish the precise remaining gap. Prepare scoped ISO/SOC evidence
and organizational processes; formal assessment depends on completed implementation,
operating evidence, independent assessor availability and budget, not audience size.

Exit: independent reports, retest results, accurate public claims, a supported
configuration matrix, and funded recurring review. Reassess material changes,
incidents, new cryptographic guidance and dependency vulnerabilities.

## Initial implementation control register

The IDs below are Petika tracking IDs, not invented standards clause numbers. Phase 0
will attach exact external requirement IDs to each record and expand coverage.
Roles denote required responsibilities; named assignments are still pending.

| ID | Required outcome | Status | Phase | Responsible roles | Acceptance evidence |
| --- | --- | --- | --- | --- | --- |
| SEC-01 | Versioned threat model, source mappings and exception register | Planned | 0 | Maintainer, security reviewer | Reviewed scope and control inventory; no unowned in-scope requirements |
| SEC-02 | Secure remote transport and proxy configuration | Partial | 1 | Server maintainer, operator | Negative HTTP/origin/proxy tests and deployed TLS configuration |
| SEC-03 | Updated account password policy and abuse controls | Partial | 1 | Authentication maintainer | Boundary, screening, rate-limit, enumeration and migration tests |
| SEC-04 | MFA/passkeys, lifecycle and privileged step-up | Planned | 1 | Authentication maintainer, reviewer | Enrollment/recovery/removal tests; assessed assurance requirements |
| SEC-05 | Session, device and API credential isolation | Partial | 1–2 | Client/server maintainers | Revocation and cross-scope denial tests, including legacy routes |
| SEC-06 | Local vault confidentiality and verified recipient grants | Partial | 2 | Crypto/client maintainers | Cross-client negative tests and independent protocol review |
| SEC-07 | Key inventory, protected custody and crash-safe rotation | Partial | 2 | Crypto/server maintainers, operator | Key lifecycle records and failed-rotation/restart/restore exercises |
| SEC-08 | Validated cryptographic path and honest suite labeling | Planned | 2–6 | Crypto maintainer, independent specialist | Module/security-policy/platform matrix and validation evidence |
| SEC-09 | Explicit personal, trusted-person and organization recovery | Partial | 3 | Crypto/client maintainers, reviewer | Abuse, loss, cancellation and recovery-custody tests |
| SEC-10 | Administrative separation and scoped recovery authority | Partial | 3 | Authorization maintainer, operator | Personal/company boundary and approval-bypass tests |
| SEC-11 | Minimal, independently retained audit evidence and alerts | Planned | 4 | Server maintainer, operator | Redaction tests, external receipts, gap detection and alert exercise |
| SEC-12 | Tested independent backups and retention protection | Partial | 4 | Backup maintainer, operator | Real-provider restore reports and measured recovery objectives |
| SEC-13 | Incident response, containment and safe restored state | Planned | 4 | Maintainer, operator | Tabletop/technical exercises and credential-revocation evidence |
| SEC-14 | Signed releases, SBOM, provenance and update verification | Partial | 5 | Release maintainer, reviewer | Artifact tampering and signing-key compromise tests |
| SEC-15 | Privacy inventory, minimization and retention/deletion | Planned | 5 | Maintainer, privacy owner, operator | Data-flow inventory, deletion tests and scoped obligation mapping |
| SEC-16 | Vulnerability response and maintained dependencies | Partial | 5 | Security/release maintainers | Private reporting test, triage records and patch-target evidence |
| SEC-17 | Independent review and regression assessment | Planned | 6 | Independent assessors, maintainer | Scoped reports, remediations and retest results |
| SEC-18 | Operating ownership and organizational assurance | Planned | 0–6 | Maintainer, operator, assurance owner | Named owners, policies, operating records and assessor-ready scope |

Each record must retain: source edition/requirement; rationale; owner; affected
components and supported platforms; threat/data class; dependencies; implementation
issue/commit; test procedure; evidence link and date; reviewer; gaps/exceptions;
expiry/review date; and deployed configuration where relevant.

Use statuses **planned**, **partial**, **implemented**, **verified**, **blocked**, or
**not applicable with reviewed rationale**. Passing a unit test does not alone promote
a control to verified. Verification needs the complete assessment method and an
identified reviewer. Keep sensitive evidence in restricted storage; repository
summaries must never include production keys, personal records or exploitable details.
Report coverage counts and open findings rather than a misleading compliance percentage.

## Release gates and first work package

A controlled pilot requires Phase 0 scope, secure transport, strong administrative
authentication, tested key/backup recovery, protected release distribution, incident
ownership, and no unresolved critical/high findings in the pilot scope. Pilot status
does not remove the current [experimental security policy](../SECURITY.md).

A production-support claim requires all applicable target controls to be verified,
independent assessment and retest, realistic deployment evidence, and completed
operating responsibilities. State exact exceptions and unsupported platforms; do
not advertise ASVS levels, AALs, FIPS validation, ISO certification, SOC reports or
legal compliance beyond the evidence for their specific scope.

Start with Phase 0 and SEC-02/03/04: freeze the control mappings, threat model and
roles; establish HTTPS defaults; design the account-password migration and passkey
lifecycle. Start SEC-08 FIPS feasibility alongside this work. Recovery-authority and
new encryption-format changes require their own reviewed decision records before
implementation. This planning change itself does not change encryption formats,
production credentials, authentication requirements or running deployments.
