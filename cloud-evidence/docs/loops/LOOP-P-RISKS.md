# LOOP-P — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with `status=resolved` + resolution note. Severity: high = ship-blocking; med = should fix in-loop; low = file as follow-up.

> Authoritative companion to `docs/loops/LOOP-P-SPEC.md` and the per-slice docs at `docs/slices/P/P.P[1-5].md`. Read those for context before acting on any risk here.

> Last updated: 2026-06-07.

---

## Cross-cutting risks (apply to ALL slices in LOOP-P)

### P-X1 — NITTF Minimum Standards PDF gated behind dni.gov session

- **Description**: The NITTF Minimum Standards (Nov 2012) PDF — authoritative source for the six required ITP elements P.P1 + P.P5 cite — is hosted under dni.gov and returns 403 / session-redirect to anonymous HTTPS fetches. Operator must download manually into `cloud-evidence/docs/sources/nittf-minimum-standards.pdf` before P.P1 or P.P5 can pin verbatim citations.
- **Severity**: high (P.P1 blocker; P.P5 blocker for indicator catalogue cross-reference).
- **Mitigation**: Each affected slice (P.P1, P.P5) carries a `REQUIRES-OPERATOR-INPUT: confirm-against-nittf-pdf` marker on its six-element + indicator citations until the PDF is downloaded; `--strict-workforce` orchestrator mode fails the build if the marker remains; CHANGELOG entry for P.P1 quotes the six elements verbatim with PDF page + section, atomically once downloaded.
- **Status**: open.

### P-X2 — CISA Insider Threat Mitigation Guide PDF size + page-number drift

- **Description**: The CISA Mitigation Guide (Feb 2023, 508 PDF) is ~80 pages with 33 indicators across 4 categories. P.P5 rule library cites page + indicator code verbatim per rule. CISA periodically reissues the guide; page numbers shift; existing citations become stale.
- **Severity**: med (P.P5 only).
- **Mitigation**: Each rule docstring carries an explicit `cisa_guide_version: '2023-02'` field + page number; rule library cross-references the PDF SHA-256 (operator records on download); CHANGELOG updates when CISA reissues; future-rev migration tracked as a separate slice.
- **Status**: open.

### P-X3 — OPM Position Designation System policy URL times out

- **Description**: The OPM PDS policy URL (https://www.opm.gov/suitability/suitability-executive-agent/policy/position-designation/) returned a fetch timeout on 2026-06-07 during P.P2 spec authoring. P.P2 enum values (5 CFR 731 public-trust + 32 CFR 147 sensitivity) come from the underlying regulations, but operator-facing UI guidance benefits from the OPM policy text.
- **Severity**: low.
- **Mitigation**: Each affected slice (P.P2) cites the underlying regulations (5 CFR 731 + 32 CFR 147) verbatim; OPM policy is reference-only; operator downloads policy HTML to `cloud-evidence/docs/sources/opm-position-designation-policy.html` when needed; UI links to live OPM URL.
- **Status**: open.

### P-X4 — Tracker `hr` + `it` role mapping to operator IDP

- **Description**: P.P1 adds `hr` role; P.P3 adds `it` role. These map to the operator's identity provider (Okta / Azure AD / GitHub OIDC). If the IDP does not propagate group membership, the tracker rejects writes and the slices appear broken. Mirrors LOOP-B B-X5.
- **Severity**: med (impacts P.P1, P.P3, and indirectly P.P2/P.P4 RBAC).
- **Mitigation**: First-boot setup wizard prompts admin to assign at least one `hr` and one `it`; tracker UI "Settings → Roles" page documents the mapping; operator runbook explains IDP-side group configuration; CHANGELOG entries call out the role requirements per slice.
- **Status**: open.

### P-X5 — Subject identifier resolution table is sensitive

- **Description**: P.P1 + P.P3 + P.P5 use opaque `subject_user_ref` tokens to keep insider-threat case data + lifecycle sanction data separated from ordinary user_id refs. The resolver `token → user_id` lives in a `case_subject_index` table accessible to AO only. If that table leaks (DB backup misconfiguration, audit log of case access exposed, etc.), pre-adverse-action data is exposed.
- **Severity**: high.
- **Mitigation**: Resolver table sits in its own schema with separate access; all access logged in `audit_log` with elevated severity flag; backups encrypted at rest with separate key (LOOP-D.5 backup pipeline supports per-table key partitioning); operator runbook documents the threat model; quarterly access review under PM-12 self-assessment.
- **Status**: open.

### P-X6 — IAM-SUS inventory snapshot age drives correlation accuracy

- **Description**: P.P3 (lifecycle SLA correlation), P.P4 (signature × IAM presence correlation), and P.P5 (dormant + access-after-termination rules) all read `providers/*/iam.ts` inventory. If the inventory is stale, SLA breaches surface against IAM principals that have since been disabled, and dormancy detection lags. Tied to LOOP-B B-X4 (snapshot age skew).
- **Severity**: med.
- **Mitigation**: Each reader records `inventory_fetched_at` on emitted Findings; `--strict-workforce` requires ≤24h freshness; `core/orchestrator.ts` orders provider collection BEFORE workforce slices; CHANGELOG documents the dependency.
- **Status**: open.

### P-X7 — Cross-system snapshot age skew across P.P2 / P.P3 / P.P4

- **Description**: P.P5 reads four tracker snapshots (positions + screening + lifecycle + agreements) PLUS the IAM-SUS inventory PLUS the tracker audit_log. Each is pulled at a different time. If tracker is being actively edited during a run, the joined `WorkforceContext` could be inconsistent.
- **Severity**: med.
- **Mitigation**: Each reader records `fetched_at`; orchestrator's `--strict-workforce` mode requires all four tracker snapshots within a 5-minute window (same bound as LOOP-B); CHANGELOG entry for P.P5 documents the skew bound; UI surfaces "Stale snapshot" warning when bound exceeded.
- **Status**: open.

### P-X8 — Tracker schema migration on existing installs

- **Description**: LOOP-P adds 8 new tables: `insider_threat_program`, `insider_threat_team_roster`, `insider_threat_indicators`, `insider_threat_cases`, `personnel_positions`, `personnel_screening_records`, `personnel_lifecycle_events`, `access_agreements`, `access_agreement_signatures` (9 actually, plus optional `case_subject_index`). All migrations must be additive only. The repo uses idempotent `CREATE TABLE IF NOT EXISTS`; any non-additive change is breaking.
- **Severity**: high.
- **Mitigation**: All DDLs are additive; CHANGELOG documents the upgrade path per slice; smoke test on a copy of a production DB; no DROP / ALTER COLUMN under any circumstance in LOOP-P; future `H.H3` multi-tenant work batches all cross-loop migrations.
- **Status**: open.

### P-X9 — Submission bundle role count growth

- **Description**: LOOP-P adds 6-7 new roles to `submission-bundle.ts:WELL_KNOWN`: `insider-threat-program-docx`, `insider-threat-program-snapshot`, `position-risk-register-json`, `screening-records-snapshot`, `personnel-lifecycle-snapshot`, `access-agreements-docx`, `access-agreements-snapshot`, `workforce-indicators-json`. Each must have a stable canonical filename + description; collisions would corrupt the bundle.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the role table; per-slice tests assert presence; CHANGELOG entry for P.P5 lists the final role inventory at loop close.
- **Status**: open.

### P-X10 — Provenance schema drift

- **Description**: Every new emit artifact (`insider-threat-program.docx`, `KSI-PIY-ITP.json`, `position-risk-register.json`, `KSI-PIY-PSE.json`, `.personnel-lifecycle-snapshot.json`, `access-agreements.docx`, `KSI-PIY-AGM.json`, `workforce-indicators.json`) must carry a `provenance` block per REO Rule 2.6. `scripts/check-provenance.mjs` enforces the schema (emitter, emittedAt, sourceCalls, signingKeyId). A missed block fails the slice.
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via `check:provenance`; pattern reused from `core/inventory-coverage.ts`; CHANGELOG entry per slice cites the provenance block contents.
- **Status**: open.

### P-X11 — `process.env.NODE_ENV === 'test'` branch creep

- **Description**: REO Rule 1.8 prohibits this branch in production code. LOOP-P adds new cross-cutting infrastructure (.docx emitters, OOXML rendering, signing, HTTP fetch, snapshot writes, enforcer tasks) — exactly where developers reach for `if (NODE_ENV === 'test')` shortcuts.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal; tests inject seams via dependency-injected HTTP fetcher + filesystem helper + tracker-pull seam; CI gate is non-bypassable.
- **Status**: open.

### P-X12 — NISPOM (32 CFR 117) scope is conditional

- **Description**: 32 CFR 117.7 binds an ITP obligation on contractors handling NISP-scoped data. Most FedRAMP CSPs do NOT hold NISP-scoped data, but some hold CUI for national-security-customer agencies. The `applies_nispom` boolean in P.P1 lets the operator declare in/out of scope. If misdeclared (false when true), the .docx omits required sections + the SSP narrative under-cites; if true when false, the .docx renders extra sections that 3PAO may interpret as scope inflation.
- **Severity**: med.
- **Mitigation**: `applies_nispom` is operator-declared with a confirmation step (UI two-click); CHANGELOG documents the consequence of misdeclaration; runbook walks the operator through the decision tree (does the CSP handle NISP-scoped data? → consult contract).
- **Status**: open.

### P-X13 — RBAC role definitions drift between tracker and operator's IDP

- **Description**: Cross-ref P-X4 + LOOP-B B-X5. The new `hr` + `it` roles plus existing `iso`, `ao`, `assessor` roles must map to IDP group memberships. Drift means tracker users have wrong access; signed attestations come from the wrong role; audit log captures incorrect role-based actions.
- **Severity**: med.
- **Mitigation**: First-boot setup wizard validates IDP role mapping; runbook documents per-IDP configuration; quarterly role-review under PM-12 self-assessment; tracker UI surfaces "Role missing" warning at session start.
- **Status**: open.

### P-X14 — Workforce policy YAML schema drift between slices

- **Description**: P.P1 introduces `config/workforce-policy.yaml`; P.P2 + P.P3 + P.P4 + P.P5 all extend it. Five slices touching one config file → schema drift risk (P.P2 adds field, P.P3 expects different field name, etc.).
- **Severity**: med.
- **Mitigation**: `core/workforce-policy.ts` typed loader is the single source of truth; tests verify schema across slices; example yaml updated in lockstep with each slice; CHANGELOG entry per slice lists yaml fields added.
- **Status**: open.

### P-X15 — Notification fatigue from PS-4 SLA + PS-5 transfer + insider-threat indicator firing

- **Description**: P.P3 fires `termination-recorded`, `ps-4-sla-breach`, `transfer-recorded`; P.P5 fires `workforce-indicator-detected` (severity ≥ high). At org scale this could be dozens of notifications per day, leading to alert fatigue.
- **Severity**: low.
- **Mitigation**: `core/notify.ts` already supports per-rule throttling; default throttle = 1 notification per (event_type, subject) per 24h; severity-critical bypasses throttle; runbook documents the throttle.
- **Status**: open.

---

## Per-slice risks

### P.P1 — Insider Threat Program documentation + tracker workflow

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| P.P1-1 | high | NITTF Minimum Standards PDF gated (cross-ref P-X1) | REQUIRES-OPERATOR-INPUT marker; `--strict-workforce` blocks ship | open |
| P.P1-2 | med | 32 CFR 117 NISPOM scope is conditional (cross-ref P-X12) | `applies_nispom` operator-declared; documented | open |
| P.P1-3 | high | Subject identifier exposure in case table (cross-ref P-X5) | Opaque `subject_user_ref`; resolver table AO-only | open |
| P.P1-4 | med | ITSO designation is a single point of failure (departure invalidates attestation) | Notification at T-30 / T-7 / T-0; enforcer flags `requires-resign` | open |
| P.P1-5 | med | Cross-discipline team roster could be incomplete (<4 disciplines) | Server-side validator rejects < 4 active disciplines | open |
| P.P1-6 | low | KSI-PIY-ITP "all six attested" doesn't imply operationally effective | Prop description clarifies; 3PAO inspection still required | open |
| P.P1-7 | med | OOXML emitter must match existing pattern from roe-emit.ts exactly | Reuse `core/ooxml-helpers.ts`; tests round-trip the doc | open |
| P.P1-8 | low | Six-element narrative text for elements 3, 4, 6 likely long; .docx page breaks | OOXML page-break helpers tested | open |

### P.P2 — Position risk designation per role (PS-2 + PS-3 screening)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| P.P2-1 | low | OPM Position Designation Tool (PDT) JSON export schema is federal-internal | P.P2 doesn't integrate with PDT directly; optional CSV importer accepts PDT-flavoured layout | open |
| P.P2-2 | med | 5 CFR 731 public-trust enum could conflict with operator's internal taxonomy | Database enum fixed at 5 CFR 731 values; operator taxonomies mapped at UI; documented | open |
| P.P2-3 | med | 32 CFR 147 sensitivity levels typically don't apply to commercial CSPs | Schema requires explicit declaration (`not-applicable` allowed); REO Rule 4 enforces no silent default | open |
| P.P2-4 | med | IAM-SUS correlation requires inventory snapshot freshness (cross-ref P-X6) | Reader records `inventory_fetched_at`; `--strict-workforce` enforces ≤24h | open |
| P.P2-5 | high | User_id ↔ tracker-user vs cloud-identity mapping is ambiguous | Extend users table with `cloud_identity_arn` (LOOP-J.J1 precedent); document | open |
| P.P2-6 | low | Cadence enforcer race with manual operator update | Atomic SQL UPDATE WHERE clause; audit log captures both rows | open |
| P.P2-7 | med | PS-9 position description must include security_responsibilities verbiage | Server-side substring check; reject without | open |
| P.P2-8 | med | CSV bulk-import errors mid-transaction could leave partial state | All-or-nothing transaction (BEGIN/COMMIT); test validates rollback | open |

### P.P3 — Personnel transfer + termination procedures (PS-4 + PS-5)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| P.P3-1 | med | IAM-SUS snapshot vs SLA window timing (cross-ref P-X6) | Reader emits `psFindingKind: 'ps-4-iam-snapshot-stale'` when snapshot too old | open |
| P.P3-2 | high | cloud_identity_arn mapping on users table may be incomplete (cross-ref P.P2-5) | UI prompts operators per user; reader emits `ps-4-iam-unmapped` Finding when missing | open |
| P.P3-3 | med | IAM disable observation lags between snapshots | Acceptable for evidence-grade; documented in CHANGELOG | open |
| P.P3-4 | med | PS-5 transfer detection requires ≥2 LOOP-J.J1 roles snapshots in lookback | Reader emits `ps-5-snapshot-insufficient` when one snapshot; documented | open |
| P.P3-5 | high | PS-8 sanction events handle pre-adverse-action data (cross-ref P-X5) | Opaque `subject_user_ref`; resolver AO-only | open |
| P.P3-6 | low | Lifecycle event uniqueness on user_id (rehire after termination) | uuid unique, user_id not; UI shows history; documented | open |
| P.P3-7 | med | Contractor-end vs termination semantics differ (PS-4 partial) | Lighter checklist (3 of 5 PS-4 boxes); CHANGELOG documents | open |

### P.P4 — Access agreements + acknowledgments + NDA (PS-6)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| P.P4-1 | med | Body SHA-256 calculated server-side vs operator-supplied (operator could replay stale hash) | Server always recomputes; operator-supplied ignored on write, compared on read | open |
| P.P4-2 | med | ip_address spoofing via X-Forwarded-For header | Trusted proxy CIDR config; rightmost-trusted value; canonical-JSON signature includes recorded ip | open |
| P.P4-3 | low | Signature ledger grows unbounded | Indexes + pagination; LOOP-H.H1 cold-storage migration | open |
| P.P4-4 | med | Agreement markdown could include malicious links / scripts | DOMPurify allowlist on client; .docx emitter strips raw HTML | open |
| P.P4-5 | med | Retired-agreement-with-prior-signatures audit trail | Signature rows immutable; `signed_at` + `agreement_uuid` preserved; status reflects current applicability | open |
| P.P4-6 | low | PS-6(c)(2) "re-sign at frequency" + version-supersession trigger could conflict | OR'd: resign required when EITHER (a) superseded OR (b) age > cadence | open |
| P.P4-7 | med | AO approval workflow bypass via direct SQL | RBAC at HTTP layer; CHANGELOG warns; runbook documents manual-SQL audit cadence | open |

### P.P5 — Continuous workforce monitoring + behavioral analytics

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| P.P5-1 | high | CISA Mitigation Guide PDF requires manual download (cross-ref P-X2) | Operator downloads; rule docstrings carry REQUIRES-OPERATOR-INPUT confirm marker | open |
| P.P5-2 | med | False positives in CISA-CYBER-04 (dormant principal during legitimate leave) | Read lifecycle `event_type='leave-extended'` to suppress; UI "suppress" action for `iso` | open |
| P.P5-3 | med | CISA-CYBER-12 timing race (IAM snapshot pre-dates termination) | Filter `iam.last_used_at > termination.effective_at`; REQUIRES-OPERATOR-INPUT when snapshot stale | open |
| P.P5-4 | low | Bulk-download threshold could miss low-and-slow exfiltration | Tunable; documented; future rolling-7-day rule | open |
| P.P5-5 | high | Subject identifier resolution table sensitive (cross-ref P-X5) | Separate schema; AO only; audit log with elevated severity | open |
| P.P5-6 | med | Auto-case-open could flood queue | Opt-in default false; rate-limit 10 cases/hour/subject | open |
| P.P5-7 | med | LOOP-J.J1 roles matrix may not be fresh | Reader requires < 24h; emits `roles-matrix-stale` REQUIRES-OPERATOR-INPUT | open |
| P.P5-8 | low | Notification fatigue from high-severity rules (cross-ref P-X15) | notify.ts throttling; default 1/24h per (rule, subject) | open |
| P.P5-9 | med | Indicator rule library coverage incomplete (10 of 33 in first cut) | Documented; follow-up enhancements; CHANGELOG lists shipped rules | open |
| P.P5-10 | low | CISA guide version migration (2023 → next rev) | `cisa_guide_version` + SHA-256 pinned per rule; migration tracked separately | open |

---

## External dependencies that may change

### FedRAMP guidance updates that could affect LOOP-P

- **FedRAMP Rev5 SSP Template** — drives the PM-12 + PS-1..PS-9 implementation statement format. Format changes here ripple into LOOP-P slice SSP wiring. URL: https://www.fedramp.gov/assets/resources/templates/
- **FedRAMP Rules of Behavior + Access Agreement Template** — drives P.P4 .docx structural template. URL: https://www.fedramp.gov/assets/resources/templates/FedRAMP-Rules-of-Behavior-and-Access-Agreement-Template.docx
- **FedRAMP CSP Authorization Playbook — Personnel Security section** — references NIST 800-53 PS family verbatim; if FedRAMP reissues with parameter clarifications, LOOP-P SSP narrative blocks need re-cite. URL: https://www.fedramp.gov/docs/rev5/playbook/csp/
- **FedRAMP 20x Phase Two requirements** — published RFCs (RFC-0014 already incorporated) could redefine "process-artifact KSI" semantics, affecting P.P1 + P.P2 + P.P4 KSI envelope shape.

### NIST publication versions

- **NIST SP 800-53 Rev 5 (Sep 2020, errata Dec 2023)** — current source for PM-12 + PS-1..PS-9 control statements. Rev 6 is in the long-tail; would require catalog regeneration (`nist-r5-controls.generated.json`) + per-slice citation refresh. URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- **NIST SP 800-53A Rev 5 (errata Dec 2023, currently 5.2.0 → 5.3.0 in progress)** — assessment guide. Affects 3PAO procedures referenced from P.P2 + P.P3 audit trails. URL: https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final
- **NIST SP 800-37 Rev 2 (2018)** — RMF; cited in P.P1 + P.P2 for organizational context. Stable; very unlikely to change in LOOP-P horizon.
- **NIST SP 800-181 Rev 1 (NICE Workforce Framework)** — referenced in P.P1 ITP plan for team-role language. Stable.

### Federal regulations + executive policy

- **Executive Order 13587 (Oct 7, 2011)** — agency-side ITP obligation cited by P.P1. Stable since 2011; unlikely to change but a hypothetical successor EO could shift scope.
- **NITTF Minimum Standards (Nov 21, 2012)** — six-element framework cited by P.P1 + P.P5. Stable; NITTF could issue updated standards via dni.gov.
- **32 CFR Part 117 (NISPOM)** — contractor ITP obligation cited by P.P1 conditionally. 2021 rewrite is current; periodic eCFR updates.
- **5 CFR Part 731 (Suitability)** — public-trust risk levels cited by P.P2. Stable; OPM periodically clarifies risk-designation factors via supplemental guidance.
- **32 CFR Part 147 / 5 CFR Part 1400** — national-security sensitivity levels cited by P.P2. Stable.
- **CISA Insider Threat Mitigation Guide (Feb 2023, 508 PDF)** — CISA reissues periodically. P.P5 rule citations pin the guide version + SHA-256.

### Upstream library updates

- **rfc8785 (canonical JSON) library** — used by every signature pipeline; pin one library across cloud-evidence + tracker. Multiple JS implementations exist (e.g. `canonicalize`, `json-canonicalize`).
- **@noble/ed25519 (^2.x)** — Ed25519 signing. Stable API; performance improvements in minor releases.
- **better-sqlite3 (~9.x or ~11.x)** — tracker DB. SQL dialect stable; CREATE TABLE syntax compatible across versions.
- **React (^18.x)** — tracker UI. v19 ships routinely; pin major version within LOOP-P.
- **DOMPurify (^3.x)** — used by P.P4 sign-flow page to sanitize agreement markdown. Stable; allowlist policy locked.
- **Express (^4.x)** — tracker server. Stable.
- **ajv (^8.x)** — OSCAL JSON schema validation. Schema-validation behaviour rare-change.

### Cloud provider / infrastructure

- **AWS / GCP / Azure IAM SDKs** — `providers/*/iam.ts` collectors used by P.P3 + P.P5 correlation. Stable; new fields (e.g. `LastUsed`) handled by permissive parser.
- **OPM eApp / eQIP background-investigation endpoints** — federal-internal; LOOP-P does NOT integrate. CSV import path for completed-investigation evidence remains optional.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the appropriate per-slice section with a fresh ID (e.g. `P.P3-8`); commit alongside the slice's implementation log update.
2. Risks resolved during implementation: move the row to the "Resolved risks" table at the bottom with date + resolution note + responsible session/commit. Do NOT delete the original entry — historical record matters.
3. Severity bump (low → med → high): add a `note` line under the original entry describing why; do not edit history.
4. Cross-cutting risks that affect multiple slices: keep in the cross-cutting section; reference from per-slice tables via "(cross-ref P-X<n>)".

---

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-P-SPEC.md` §1 (why this loop), §2 (FedPy connection), §4 (authoritative sources), §7 (open questions).
3. Read the specific per-slice doc at `docs/slices/P/P.P<n>.md` for the slice you're implementing — risks here are the LIVE working set; risks in the per-slice docs are the spec snapshot.
4. Before shipping a slice, update this file's per-slice section + move any resolved risks to the resolved table atomically with the slice's commit (per SLICE-COMPLETION-PROCEDURE.md).
