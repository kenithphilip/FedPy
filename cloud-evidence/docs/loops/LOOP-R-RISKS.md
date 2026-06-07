# LOOP-R — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with `status=resolved` + resolution note. Severity: high = ship-blocking; med = should fix in-loop; low = file as follow-up.

> Authoritative companion to `docs/loops/LOOP-R-SPEC.md` and the per-slice docs at `docs/slices/R/R.R[1-3].md`. Read those for context before acting on any risk here.

> Last updated: 2026-06-07.

---

## Cross-cutting risks (apply to ALL slices in LOOP-R)

### R-X1 — Authoritative PDFs gated by 403 on anonymous fetch
- **Description**: The four canonical PDFs LOOP-R depends on — OMB M-23-02, NIST IR 8547 IPD, CNSA 2.0, FIPS 203/204/205 — either return HTTP 403 to anonymous HTTPS fetches or render only as PDF binary. The verbatim quote tables that R.R1 (`pqc-classification.ts`), R.R2 (default mappings + target dates), and R.R3 (annual report Authority section) need cannot be web-scraped. They must be downloaded manually by an operator into `cloud-evidence/docs/sources/` before any LOOP-R slice can pin verbatim quotes.
- **Severity**: high (R.R1, R.R2, R.R3 all blocked on verbatim citation).
- **Mitigation**: Each affected constant carries a `REQUIRES-OPERATOR-INPUT: confirm-against-<source>` marker on its docstring until the PDF is local; `--strict-pqc` orchestrator mode fails the build if the marker remains; CHANGELOG entry per slice quotes the table values verbatim with PDF page + section numbers, atomically with the slice's commit.
- **Status**: open.

### R-X2 — NIST IR 8547 is still in Initial Public Draft
- **Description**: NIST IR 8547 (Nov 2024) is the Initial Public Draft. The final ship (expected 2025/2026) may adjust the enumerated quantum-vulnerable list, the deprecation timeline (currently 2030 / 2035), or the FIPS 203/204/205 parameter-set guidance. R.R1's classification table, R.R2's default target dates, and R.R3's Authority citations all reference the IPD.
- **Severity**: med (correctness signal; not a ship-blocker because the IPD is the currently-authoritative reference).
- **Mitigation**: `core/pqc-classification.ts` carries an `ir_version = "8547-ipd-2024-11"` constant; when IR 8547 finalises, bump the constant + add deltas to the classification table; operator override via `pqc-config.yaml` lets early adopters opt in pre-final; CHANGELOG entry per IR update.
- **Status**: open.

### R-X3 — OSCAL POA&M v1.1.2 schema constraints on PQC props
- **Description**: R.R2 attaches 7 new props per PQC unplanned-migration POA&M item (`pqc-asset-id`, `pqc-current-algorithm`, `pqc-target-algorithm`, `pqc-target-date`, `pqc-target-fips-standard`, `pqc-deadline-source`, `pqc-purpose`). All 7 must carry `ns: CE_NS`; a typo would silently fail the bundle.
- **Severity**: high (R.R2 blocker).
- **Mitigation**: Test per-prop presence + `ns` value via `tests/core/oscal-poam.test.ts` extension; `core/oscal-validate.ts` runs after every POA&M re-emission; cross-references LOOP-B-X2.
- **Status**: open.

### R-X4 — Ed25519 signing-key registry cross-FY
- **Description**: R.R3 sign-offs are signed Ed25519 records persisting indefinitely. AO role-holder rotation, tracker resident-key rotation, or system-wide signing-key rotation across fiscal-year boundaries could invalidate prior-FY report signatures during R.R3 year-over-year delta computation.
- **Severity**: med.
- **Mitigation**: Tracker exposes `GET /api/sign/public-keys` returning all historical keys keyed by `key_id`; reader cross-references each report's `signing_key_id` against the registry. Pattern reused from LOOP-B-X3. Key rotation events written to `audit_log`; runbook documents.
- **Status**: open.

### R-X5 — Cross-loop ConMon delta impact when PQC POA&M items dominate
- **Description**: A CSP with 500 RSA keys generates 500 PQC POA&M items via R.R2. Existing ConMon monthly delta report (LOOP-E.E1) could surface the 500-item explosion as a regression.
- **Severity**: med (UX issue, not correctness).
- **Mitigation**: LOOP-E.E1 grouping by `pqc-deadline-source` prop; UI surfaces "PQC migration" as a filter facet; CHANGELOG entry for R.R2 explicitly notes the expected count delta the first time PQC POA&M emission runs.
- **Status**: open.

### R-X6 — `process.env.NODE_ENV === 'test'` branch creep
- **Description**: REO Rule 1.8 prohibits this branch in production code. New emit infrastructure (DOCX renderer, JSON emitter, tracker review snapshot reader, prior-FY reader) is exactly where developers reach for `if (NODE_ENV === 'test')` shortcuts.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal; tests inject seams via dependency-injected HTTP fetcher + filesystem helper; CI gate is non-bypassable. Cross-references LOOP-B-X6.
- **Status**: open.

### R-X7 — Existing `ProviderBlock` consumers must continue passing under extended type
- **Description**: R.R1 extends `ProviderBlock` with optional `crypto_inventory_entries?: CryptoInventoryEntry[]`. Backward compatible by design, but every collector (~200 files) silently inherits the field.
- **Severity**: med.
- **Mitigation**: Field is OPTIONAL; existing collectors don't reference it; R.R1's typecheck pass over the whole repo catches any breakage; tests `tests/core/envelope.test.ts` exercise the optional path. Cross-references LOOP-B-X7.
- **Status**: open.

### R-X8 — Submission bundle role count growth + filenamePattern support
- **Description**: LOOP-R adds 4-6 new roles to `submission-bundle.ts:WELL_KNOWN`. R.R3 introduces `filenamePattern` (regex) alongside the existing literal `filename` because annual reports are per-FY (`pqc-annual-report-FY2026.json`, FY2027, ...). The data structure extension is itself a small refactor.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins both literal-filename and filenamePattern role matches; per-slice tests assert presence; CHANGELOG entry for R.R3 lists the final role inventory.
- **Status**: open.

### R-X9 — Provenance schema drift across new emit artifacts
- **Description**: Every new emit artifact (`crypto-inventory.json`, `crypto-inventory.xlsx`, `pqc-migration-plan.docx`, `pqc-migration-plan.json`, `pqc-annual-report-FYNNNN.docx`, `pqc-annual-report-FYNNNN.json`) must carry a `provenance` block per REO Rule 2.6. `scripts/check-provenance.mjs` enforces the schema (emitter, emittedAt, sourceCalls, signingKeyId).
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via `check:provenance`; pattern reused from `core/inventory-coverage.ts`. Cross-references LOOP-B-X9.
- **Status**: open.

### R-X10 — Tracker schema migration on existing installs
- **Description**: R.R3 adds 3 new tables (`pqc_annual_report_reviews`, `pqc_migration_owners`, `pqc_algorithm_overrides`). Existing tracker installs have user data — migrations must be additive only. The repo uses idempotent `CREATE TABLE IF NOT EXISTS`; any non-additive change breaks installations.
- **Severity**: high.
- **Mitigation**: All three CREATEs are additive; CHANGELOG documents the upgrade path; smoke test on a copy of production DB; no DROP / ALTER COLUMN under any circumstance in LOOP-R; multi-tenant work batches all cross-loop migrations under LOOP-H.H3. Cross-references LOOP-B-X10.
- **Status**: open.

### R-X11 — Inventory tags absent on existing fleet
- **Description**: R.R1 enumerates crypto across AWS / GCP / Azure but relies on `inventory.json` for asset_id joins. Real CSPs have not back-tagged all assets; a large fraction will return `cross-cloud-discovery` markers — surfacing the gap visibly but inflating REQUIRES-OPERATOR-INPUT counts.
- **Severity**: med (correctness signal, not a blocker).
- **Mitigation**: `cross-cloud-discovery` is observable on every affected entry's `asset_source` field; coverage-regression CI guardrail tracks fill rates; documented in operator runbook with example tagging commands per provider. Cross-references LOOP-B-X11.
- **Status**: open.

### R-X12 — Cloud-provider PQC roadmap drift
- **Description**: R.R2 records inheritance from AWS KMS, GCP Cloud KMS, Azure Key Vault published PQC roadmaps. Those vendor roadmaps will update (likely in 2026-2028); R.R2's inheritance entries become stale unless operator re-runs `pqc-config.yaml` editing.
- **Severity**: low.
- **Mitigation**: `inheritance.upstream_target_date` records when the operator set the date; runbook documents quarterly review; R.R3 annual report's inheritance section surfaces upstream-date deltas year-over-year; future LOOP-Q.Q* marketplace integration could pull vendor public roadmaps automatically.
- **Status**: open.

### R-X13 — Test count expectations / CI thresholds
- **Description**: LOOP-R adds ≥75 new tests across cloud-evidence + tracker. Existing CI may have hard-coded "expected test count" assertions or coverage thresholds that need bumping.
- **Severity**: low.
- **Mitigation**: Per slice, the implementing session updates any test-count assertion; CHANGELOG entries cite the new totals; STATUS.md "Overall → tests" line bumped atomically with each slice ship. Cross-references LOOP-B-X13.
- **Status**: open.

### R-X14 — POA&M XML emitter coverage for PQC props
- **Description**: `core/oscal-xml.ts` projects POA&M JSON to XML. R.R2's 7 new PQC props must survive the JSON→XML pipeline; an unhandled prop would silently drop in XML output.
- **Severity**: med.
- **Mitigation**: Per-slice test re-emits POA&M XML; asserts presence of all 7 PQC prop names; pattern from LOOP-A.A1 + LOOP-B.B1 mirrored.
- **Status**: open.

### R-X15 — Multi-CSO tenant isolation deferred to H.H3
- **Description**: All three LOOP-R tracker tables omit a `tenant_id` column. When multi-CSO ships (H.H3), all three need migration in a single cross-loop sweep.
- **Severity**: med (long-tail).
- **Mitigation**: Documented in LOOP-R-SPEC.md §6.9; H.H3 spec must enumerate every LOOP-R table; LOOP-R ships in single-tenant deployments only (documented in runbook). Cross-references LOOP-B-X15.
- **Status**: open.

### R-X16 — Annual-report bootstrap (first FY emission)
- **Description**: R.R3 reads the prior FY's signed report to compute year-over-year delta. The first time R.R3 ships for a given CSP, no prior report exists. Naive implementation would silently emit zeros — a 3PAO seeing the report wouldn't know whether the CSP had 0 vulnerable algorithms or no prior data.
- **Severity**: med.
- **Mitigation**: `year_over_year_delta.prior_fiscal_year = undefined` block is explicit; `--first-fiscal-year` flag must be set in strict mode to opt into first-year emission; CHANGELOG entry documents the bootstrap; report DOCX section 7 includes a "First-year emission; no prior data" note when delta is undefined.
- **Status**: open.

### R-X17 — CISA Secure-by-Design / NSM-10 / NSA CNSA 2.0 scope confusion
- **Description**: NSM-10 + CNSA 2.0 strictly speaking apply to National Security Systems / DoD; OMB M-23-02 applies to civilian federal agencies. A CSP serving both could over-commit if R.R2 / R.R3 conflate the two timelines.
- **Severity**: low.
- **Mitigation**: `pqc-config.yaml cnsa_2_0: true` is opt-in (default false); R.R2's default target dates anchor on IR 8547 (civilian); R.R3 Authority section distinguishes binding scopes per source.
- **Status**: open.

### R-X18 — Algorithm canonicalisation collisions
- **Description**: R.R1's `canonicaliseAlgorithm()` converts provider-specific tokens (AWS `RSA_2048`, GCP `RSA_SIGN_PSS_2048_SHA256`, Azure `kty=RSA, key_size=2048`) to a single canonical `rsa-2048`. The collision drops padding (PSS) + hash (SHA256) information that R.R2 might need to disambiguate (RSA-PSS-SHA-256 → ML-DSA-65, but RSA-PKCS1-v1_5 → ml-dsa-44 maybe?).
- **Severity**: med.
- **Mitigation**: Extend `CryptoInventoryEntry` with optional `padding?: 'pss' | 'pkcs1' | 'oaep'` + `hash?: 'sha-256' | 'sha-384' | 'sha-512'` fields when SDK exposes them; R.R2 default-mapping table reads these as secondary inputs; current default mapping treats them as equivalent (single target per family).
- **Status**: open.

---

## Per-slice risks

### R.R1 — Cryptographic Inventory Collector

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| R.R1-1 | med | NIST IR 8547 IPD final ship may adjust the quantum-vulnerable list (cross-ref R-X2) | `ir_version` constant pins source version; `pqc-config.yaml classification_overrides{}` allows pre-final adjustment | open |
| R.R1-2 | med | Provider SDK algorithm enums evolve (AWS adds new `KeySpec`) | `canonicaliseAlgorithm()` returns `unknown`; entry surfaces `algorithm_source: REQUIRES-OPERATOR-INPUT` | open |
| R.R1-3 | med | HSM-backed keys have opaque purpose | `purpose_source: REQUIRES-OPERATOR-INPUT`; operator declares via `pqc-config.yaml` | open |
| R.R1-4 | med | Same logical asset surfaces multiple algorithm entries | De-dup key is `(asset_id, algorithm, purpose)` triple; multi-algo certs produce multiple entries intentionally | open |
| R.R1-5 | low | SSL policy + cipher suite enumeration runtime cost | Existing collectors already pull policies; this slice extends projection only; benchmark ≤ +15% | open |
| R.R1-6 | med | Azure Resource Graph 1000-row pagination | Existing `runKql()` paginates up to 50 pages = 50k rows; large CSPs need partition by subscription | open |
| R.R1-7 | low | `pqc-config.yaml` conflict with `risk-config.yaml` semantics | Distinct file names + namespaces; loader-level schema validation | open |
| R.R1-8 | med | Hybrid TLS suites (X25519MLKEM768) ambiguity | New class `quantum-resistant-pqc-hybrid`; R.R2 treats as pilot by default | open |
| R.R1-9 | low | Orphaned ACM certs (`InUseBy: []`) | Include in inventory with `purpose: 'other'`; operator may want to clean up | open |
| R.R1-10 | low | AWS-managed CMKs (KeyManager=AWS) included or excluded | Exclude from inventory; include in inheritance reporting | open |
| R.R1-11 | med | Algorithm canonicalisation collisions on padding + hash (cross-ref R-X18) | Extend entry schema with optional `padding` + `hash` fields | open |

### R.R2 — PQC Migration Plan Emitter

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| R.R2-1 | med | Default algorithm-mapping table is opinionated; operators may disagree | `algorithm_target_overrides{}` lets operator force any mapping; `target_algorithm_source` makes overrides auditable | open |
| R.R2-2 | med | Default target dates from IR 8547 IPD; finals may shift | `ir_version` constant tracks source; bump + CHANGELOG when IR finalises | open |
| R.R2-3 | low | CNSA 2.0 binding scope is NSS-only | `cnsa_2_0` opt-in; default OFF; .docx Authority section notes scope | open |
| R.R2-4 | med | Unplanned-migration POA&M items could swamp existing POA&M | LOOP-B.B5 risk register aggregates by severity; UI surfaces "PQC migration" filter facet; ConMon delta groups by deadline-source | open |
| R.R2-5 | high | Inheritance-blocked entries with upstream_target_date > 2035 are noncompliant | Emit separate POA&M with severity=critical; operator switches vendor or accepts via LOOP-B.B3 | open |
| R.R2-6 | med | LOOP-B.B2 deadline-engine cascade order may surprise (KEV wins over PQC) | Documented; tests pin order; CHANGELOG calls out | open |
| R.R2-7 | med | Hybrid TLS classification ambiguous | R.R1 classifies as hybrid; R.R2 treats as `pilot` status | open |
| R.R2-8 | low | Code-signing → SLH-DSA locks in slow signatures (SLH-DSA-128s ~ 8KB) | Operator can override to ML-DSA when signature size matters | open |
| R.R2-9 | med | Owner assignment depends on R.R3 tracker tables; R.R2 ships before R.R3 | Fallback to `pqc-config.yaml migration_targets[].owner_email`; `owner_source: REQUIRES-OPERATOR-INPUT` marker | open |
| R.R2-10 | low | .docx becomes unwieldy with > 500 unplanned entries | Render up to 500; for overflow, render summary + link to JSON twin | open |
| R.R2-11 | low | Status transitions (`unplanned → planned`) should flip OSCAL POA&M `risk.status` | Existing OSCAL POA&M status-transition logic handles | open |

### R.R3 — Annual PQC Report Emitter

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| R.R3-1 | med | Prior-FY report file may not exist on first run (cross-ref R-X16) | `--first-fiscal-year` flag opts out; empty delta block; CHANGELOG documents bootstrap | open |
| R.R3-2 | med | Signing key rotation across FY boundaries (cross-ref R-X4) | Tracker exposes `/api/sign/public-keys` historical registry | open |
| R.R3-3 | low | AO leaves org between sign-off + submission | Signed report retains historical key; only `submitted` action requires currently-active SO role | open |
| R.R3-4 | med | OMB M-23-02 §V exact field set evolves | Structured JSON forward-compatible; per-FY snapshot preserves historical schema | open |
| R.R3-5 | low | NSM-10 funding requirements may not apply to CSPs | `funding_requirements` optional; operator declares applicability via `pqc-config.yaml` | open |
| R.R3-6 | med | Risk register join could fail if LOOP-B.B5 not shipped | When `risk-register.json` missing, `risks[]` empty + warning; runbook documents soft dep | open |
| R.R3-7 | med | Tracker review snapshot drift vs cloud-evidence disk reads (cross-ref LOOP-B-X4) | `fetched_at` records; strict-pqc 1-hour window | open |
| R.R3-8 | low | 11-section DOCX large; Word PDF-export may lose formatting | Pattern proven on similar deliverables; runbook documents tested Word versions | open |
| R.R3-9 | med | Multi-CSO tenant isolation deferred (cross-ref R-X15) | LOOP-H.H3 sweep migrates; LOOP-R ships single-tenant only | open |
| R.R3-10 | med | YoY delta misleading on first inventory expansion (+100 vulnerable from tagging) | Executive summary includes `total_entries_delta` + `inventory_growth_note` | open |
| R.R3-11 | low | AO sign-off via WebAuthn vs server-side keys | Server-side R.R3 first cut; WebAuthn follow-up | open |
| R.R3-12 | low | Report file size cap | Warn at 10 MB, fail at 50 MB | open |
| R.R3-13 | med | Multiple systems under one CSP (multi-system authorization) | Per-system per-FY report; UNIQUE constraint on (fiscal_year, csp_name, system_id) | open |
| R.R3-14 | low | Very-large risks[] arrays (>200 entries) | Render top 50 by severity in DOCX; full list in JSON | open |
| R.R3-15 | med | Retroactive re-sign of signed report (AO change) | No; create new draft with `amends_uuid` cross-reference | open |

---

## External dependencies that may change

### NIST publication versions
- **NIST FIPS 203 / 204 / 205 (Aug 13 2024)** — current; potential errata in 2025-2026 horizon. R.R1 + R.R2 cite verbatim; CHANGELOG entry on errata. URLs:
  - https://csrc.nist.gov/pubs/fips/203/final
  - https://csrc.nist.gov/pubs/fips/204/final
  - https://csrc.nist.gov/pubs/fips/205/final
- **NIST IR 8547 (IPD, Nov 12 2024)** — currently in draft; final ship expected 2025-2026 will adjust quantum-vulnerable enumeration + timeline. Mitigation: `ir_version` constant tracks source version; bump + adjust on final. URL: https://csrc.nist.gov/pubs/ir/8547/ipd
- **NIST SP 800-53 Rev 5 (Sep 2020, errata Dec 2023)** — current source for SC-12, SC-13, SA-9, PM-15 control statements. Rev 6 is long-tail; would require catalog regeneration. URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- **NIST CSF v2.0 (Feb 2024)** — current source for GOVERN function GV.OC-02 + GV.RM-04. URL: https://csrc.nist.gov/projects/cybersecurity-framework

### Executive / OMB / NSA publications
- **OMB M-23-02 (Nov 18 2022)** — current source for §III inventory + §V annual report. Future OMB memos may supersede or extend; R.R3 schema is forward-compatible. URL: https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf
- **NSM-10 (May 4 2022)** — currently 404 to anonymous fetch; operator downloads canonical text. Stable executive direction; very unlikely to change in LOOP-R horizon. URL: https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/
- **NSA CNSA 2.0 (Sep 2022)** — current source for NSS-adjacent timeline; potential CNSA 2.1 horizon. URL: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF

### CISA guidance
- **CISA Post-Quantum Cryptography Initiative** — operational guidance for federal civilian agencies; R.R3 cites in References section. URL: https://www.cisa.gov/quantum
- **CISA "Quantum-Readiness: Migration to Post-Quantum Cryptography" Fact Sheet (Aug 2023)** — operator runbook references for inventory + migration prep. URL: https://www.cisa.gov/sites/default/files/2023-08/Quantum-Readiness-Migration-to-Post-Quantum-Cryptography_508_0.pdf

### FedRAMP guidance updates that could affect LOOP-R
- **FedRAMP 20x Phase Two RFCs (RFC-0014 + future)** — could redefine "validated KSI" semantics in ways that hard-gate PQC inventory at Moderate. Currently no hard PQC gate; consolidate-rules 2026 window may add. Mitigation: R.R1's `crypto-inventory.json` already structured to flow into the next-gen KSI envelope.
- **FedRAMP Marketplace `pqc_readiness_url` field (hypothetical)** — LOOP-Q.Q1 will surface from R.R3 sign-off records once Marketplace metadata extends.
- **FedRAMP Risk Management Strategy Template** (consumed by LOOP-C.C7) — format changes ripple into R.R3 risks[] join schema.

### Cloud-provider PQC roadmap updates
- **AWS KMS PQC roadmap** — https://aws.amazon.com/security/post-quantum-cryptography/ — AWS publishes which services have integrated PQC; R.R2 reads operator-supplied inheritance state. Roadmap updates quarterly.
- **GCP Cloud KMS PQC** — https://cloud.google.com/kms/docs — GCP publishes; operator records inheritance state.
- **Azure Key Vault PQC** — https://learn.microsoft.com/azure/key-vault/ — Azure publishes; operator records inheritance state.

### Upstream library updates
- **OSCAL JSON Schema v1.1.2** — committed at `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json`. v1.2.x in progress; migration is separate cross-loop refactor; LOOP-R pins v1.1.2.
- **ajv (^8.x)** — used by `core/oscal-validate.ts`. Schema behaviour changes rare; lock major version.
- **better-sqlite3 (~9.x or ~11.x)** — tracker. SQL dialect stable.
- **noble-ed25519 (^2.x) or @noble/ed25519** — Ed25519 signing. Stable API.
- **OOXML compose helpers** — used by `core/oscal-ssp-docx.ts`. No external dep; pure JS. Stable.
- **React (^18.x)** — tracker UI. v19 ships routinely; pin major version within LOOP-R.

### TLS / X.509 + IETF specs
- **TLS 1.3 hybrid key exchange draft** (IETF tls-westerbaan-x25519-mlkem768 + tls-ietf-hybrid-design) — defines hybrid suites R.R1 classifies as `quantum-resistant-pqc-hybrid`. Draft → RFC transition will stabilise naming; current naming pinned in `core/pqc-classification.ts`.

### Cloud provider / infrastructure
- **AWS KMS / ACM / IAM** — Algorithm enum additions (e.g. CNSA-1.0-aligned RSA-3072 already supported). Stable API; R.R1 extension uses existing read-only clients.
- **GCP Cloud KMS** — Asymmetric algorithm enum stable; HSM-backed `protectionLevel: HSM` field used by R.R1 for inheritance signal.
- **Azure Key Vault / Resource Graph** — `kty`, `crv`, `keyOps[]` Resource Graph projection stable.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the appropriate per-slice section with a fresh ID (e.g. `R.R2-12`); commit alongside the slice's implementation log update.
2. Risks resolved during implementation: move the row to the "Resolved risks" table at the bottom with date + resolution note + responsible session/commit. Do NOT delete the original entry — historical record matters.
3. Severity bump (low → med → high): add a `note` line under the original entry describing why; do not edit history.
4. Cross-cutting risks affecting multiple slices: keep in the cross-cutting section; reference from per-slice tables via "(cross-ref R-X<n>)".

---

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-R-SPEC.md` Section 6 (open questions) — overlaps with this register.
3. Read the specific per-slice doc at `docs/slices/R/R.R<n>.md` for the slice you're implementing — risks here are the LIVE working set; risks in the per-slice docs are the spec snapshot.
4. Before shipping a slice, update this file's per-slice section + move any resolved risks to the resolved table atomically with the slice's commit (per SLICE-COMPLETION-PROCEDURE.md).
