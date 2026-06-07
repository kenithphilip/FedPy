---
slice_id: R.R3
title: Annual PQC Report Emitter (OMB M-23-02 §V, fiscal-year cadence through 2035)
loop: R
status: pending
commit: —
completed_date: —
depends_on: [R.R1, R.R2, LOOP-A.A1, LOOP-A.A3, LOOP-A.A4, LOOP-B.B5]
blocks: [Q.Q1, C.C7]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
---

# R.R3 — Annual PQC Report Emitter

## TL;DR
Aggregate R.R1 inventory + R.R2 migration plan + prior fiscal year's report into the OMB M-23-02 §V-shape annual report. Emit `out/pqc-annual-report-FYNNNN.docx` + `out/pqc-annual-report-FYNNNN.json`. Tracker hosts a draft → reviewed → signed (Ed25519 by AO role) → submitted lifecycle with signed audit log. Year-over-year delta is computed off the prior FY's signed report on disk. The annual report cadence runs every federal fiscal year through 2035 per OMB M-23-02 §V.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
FedPy ships the OSCAL chain (LOOP-A) + risk pipeline (LOOP-B) + bundled submission package (LOOP-A.A4). R.R3 closes the PQC migration loop by emitting the OMB-shape annual report federal agency customers will pass-through to their CSPs from 2027. The report files flow through the existing submission bundle + Ed25519 + RFC 3161 signing pipeline; the review + sign-off UI reuses the LOOP-B.B3 risk-acceptance pattern (signed action records, AO role gates, audit log). No new signing infrastructure; only new domain semantics on top of existing infrastructure.

## Why this slice exists
- **OMB M-23-02 §V** obligates agencies to submit annual reports on PQC migration progress *through 2035*. CSPs whose authorization package includes an annual report pre-emptively meet the customer-facing obligation when federal customers pass-through.
- **R.R1 + R.R2 produce per-asset substrate** — they do not aggregate, compute deltas, or capture AO sign-off. Without R.R3, the operator must hand-roll the OMB submission every fiscal year — exactly the kind of manual artifact REO Rule 2.1 + LOOP-A's automated-OSCAL-chain philosophy was built to eliminate.
- **Year-over-year delta is the most meaningful signal** — "we had 312 quantum-vulnerable instances last FY; this FY we have 248; net migration complete = 64" is the headline OMB / 3PAO / AO wants. R.R3 computes it directly from prior-year signed reports on disk.
- **Tracker review + AO sign-off** is the operator's audit trail. The same Ed25519-over-canonical-JSON signing pattern LOOP-B.B3 + B.B4 use applies here for AO authentication.
- **Submission bundle integration** ensures the signed report is included in the OSCAL submission package alongside SSP / AP / AR / POA&M.

## Authoritative sources (with verbatim quotes)
- https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf — **OMB M-23-02 §V "Reporting Requirements"**:
  PDF returns 403 / binary to anonymous fetches; implementer downloads to `cloud-evidence/docs/sources/omb-m-23-02.pdf`. §V obligates annual reports through 2035 with required content (publicly-known structure captured in §3 above; exact field set confirmed verbatim post-PDF-download). The annual cadence aligns to federal FY (Oct 1 – Sep 30).

- https://csrc.nist.gov/pubs/ir/8547/ipd — **NIST IR 8547 IPD §4 Transition to Post-Quantum Cryptography Standards**:
  > "Under the transition timeline in NIST IR 8547, NIST will deprecate and ultimately remove quantum-vulnerable algorithms from its standards by 2035, with high-risk systems transitioning much earlier."
  Cited in the annual report's Authority section.

- https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/ — **NSM-10 (May 4 2022)**:
  Currently returns 404; implementer downloads canonical text. NSM-10 §3 anchors funding-requirements language that R.R3 captures as an optional report section.

- https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF — **NSA CNSA 2.0 (Sep 2022)**:
  PDF 403 to anonymous fetches; implementer downloads. Cited in the report Authority section for NSS-adjacent CSPs.

- https://csrc.nist.gov/pubs/fips/203/final + https://csrc.nist.gov/pubs/fips/204/final + https://csrc.nist.gov/pubs/fips/205/final — **FIPS 203 / 204 / 205**:
  Cited verbatim in the Authority section with parameter-set names (ML-KEM-512 / -768 / -1024; ML-DSA-44 / -65 / -87; SLH-DSA-{SHA2,SHAKE}-{128,192,256}-{s,f}).

- https://www.cisa.gov/quantum — **CISA Post-Quantum Cryptography Initiative**:
  URL currently 403 to anonymous fetches; implementer downloads / quotes the public text. Cited in the report References section.

- https://csrc.nist.gov/projects/cybersecurity-framework — **NIST CSF v2.0 (Govern function GV.OC-02 + GV.RM-04)**:
  > "The organization's cybersecurity risk management strategy is established, communicated, and monitored."
  Cited in the report — R.R3 is a partial implementation of CSF GOVERN outcomes.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, PM-15 (Security and Privacy Groups and Associations)** + **SC-12** + **SC-13**:
  > "PM-15. Establish and institutionalize contact with selected groups and associations within the security and privacy communities."
  R.R3's annual report submission cadence overlaps with PM-15's external reporting expectations.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-annual-report.ts` — pure builder + types. ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-annual-report-docx.ts` — OOXML renderer (11 sections per LOOP-R-SPEC.md §4.R3). ~700 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-annual-report-emit.ts` — disk emitter orchestrating builder + writers + tracker review snapshot pull.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-annual-report-reader.ts` — read-only client pulling prior-year signed report from disk; verifies sha256 + Ed25519 signature before computing delta.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/pqc-annual-report.ts` — Express route handler: `POST /api/pqc-annual-reports`, `GET /api/pqc-annual-reports`, `GET /api/pqc-annual-reports/:id`, `POST /api/pqc-annual-reports/:id/sign`, `POST /api/pqc-annual-reports/:id/submit`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/pqc-migration-owners.ts` — Express route handler: per-asset owner CRUD (consumed by R.R2's owner snapshot).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/pqc-algorithm-overrides.ts` — Express route handler: tracker-managed classification overrides (alternative to `pqc-config.yaml` for organisations preferring DB-backed config).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/PqcAnnualReport.tsx` — list + detail + sign-off UI.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/PqcMigrationOwners.tsx` — owner-assignment UI (per asset).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-annual-report.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-annual-report-docx.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-annual-report-emit.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-annual-report-reader.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/pqc-annual-report.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/pqc-migration-owners.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/PqcAnnualReport.test.tsx`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/pqc/annual-report/` — sample FY2026 + FY2027 inventories + plans + prior-FY signed report.

## Files to extend (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — append (idempotent CREATE TABLE IF NOT EXISTS pattern; no migrations dir):
  ```sql
  CREATE TABLE IF NOT EXISTS pqc_annual_report_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    fiscal_year TEXT NOT NULL,                       -- FY2026 / FY2027 etc.
    csp_name TEXT NOT NULL,
    system_id TEXT NOT NULL,
    submitted_by_user_id INTEGER NOT NULL REFERENCES users(id),
    submitted_at TEXT NOT NULL,
    report_sha256 TEXT NOT NULL,
    report_json TEXT NOT NULL,                       -- full PqcAnnualReport canonical-JSON
    status TEXT NOT NULL CHECK (status IN ('draft','reviewed','signed','submitted')),
    reviewed_by_user_id INTEGER REFERENCES users(id),
    reviewed_at TEXT,
    signed_off_by_user_id INTEGER REFERENCES users(id),
    signed_off_at TEXT,
    signature TEXT NOT NULL DEFAULT '',
    signing_key_id TEXT NOT NULL DEFAULT '',
    submitted_to_omb_at TEXT,
    notes TEXT
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_pqc_review_year ON pqc_annual_report_reviews(fiscal_year, csp_name, system_id);
  CREATE INDEX IF NOT EXISTS idx_pqc_review_status ON pqc_annual_report_reviews(status);

  CREATE TABLE IF NOT EXISTS pqc_migration_owners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    asset_id TEXT NOT NULL,
    algorithm_purpose TEXT NOT NULL,                 -- e.g. "rsa-2048|kms-signing"
    owner_user_id INTEGER NOT NULL REFERENCES users(id),
    assigned_by_user_id INTEGER NOT NULL REFERENCES users(id),
    assigned_at TEXT NOT NULL,
    notes TEXT,
    UNIQUE (asset_id, algorithm_purpose)
  );
  CREATE INDEX IF NOT EXISTS idx_pqc_owner_asset ON pqc_migration_owners(asset_id);

  CREATE TABLE IF NOT EXISTS pqc_algorithm_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    algorithm_token TEXT NOT NULL UNIQUE,
    quantum_vulnerable_class TEXT NOT NULL CHECK (quantum_vulnerable_class IN ('quantum-vulnerable-asymmetric','quantum-resistant-symmetric','quantum-resistant-pqc','quantum-resistant-pqc-hybrid','transitional-symmetric','unknown')),
    rationale TEXT NOT NULL,
    set_by_user_id INTEGER NOT NULL REFERENCES users(id),
    set_at TEXT NOT NULL
  );
  ```
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount routes:
  ```ts
  app.use('/api/pqc-annual-reports', requireAuth, requireRole(['so','iso','ao','assessor']), routes.pqcAnnualReport);
  app.use('/api/pqc-migration-owners', requireAuth, requireRole(['so','iso','ao']), routes.pqcMigrationOwners);
  app.use('/api/pqc-algorithm-overrides', requireAuth, requireRole(['so','iso','ao']), routes.pqcAlgorithmOverrides);
  ```
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/rbac.ts` — role permissions (reuses existing roles; no new role required):
  - `iso` can create draft + submit for review.
  - `ao` can sign off (transition `reviewed → signed`).
  - `assessor` can view but not create/sign.
  - `so` can mark `submitted` (after OMB / agency confirms receipt).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — routes `/pqc-annual-report` + `/pqc-migration-owners`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--pqc-annual-report` flag + env `CLOUD_EVIDENCE_PQC_REPORT`; requires `--fiscal-year FYYYYY` (or env `CLOUD_EVIDENCE_FISCAL_YEAR`). When `--strict-pqc` is also set, the previous FY's signed report must exist on disk (or `--first-fiscal-year` flag override is set).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — `WELL_KNOWN` adds:
  ```ts
  { role: 'pqc-annual-report-docx', filenamePattern: /^pqc-annual-report-FY\d{4}\.docx$/, description: 'Annual PQC report per OMB M-23-02 §V (LOOP-R.R3)' },
  { role: 'pqc-annual-report-json', filenamePattern: /^pqc-annual-report-FY\d{4}\.json$/, description: 'Structured twin of annual report (LOOP-R.R3)' },
  ```
  (extending `WELL_KNOWN` to support `filenamePattern` regex in addition to literal `filename` is part of this slice; existing literal-filename entries continue working).

## Schemas / standards
- **`PqcAnnualReport`** schema (see LOOP-R-SPEC.md §4.R3 step 1 for full definition):
  ```ts
  interface PqcAnnualReport {
    report_uuid: string;
    fiscal_year: string;                              // "FY2026"
    csp_name: string;
    system_id: string;
    generated_at: string;                             // ISO datetime
    inventory_summary: {
      total_entries: number;
      quantum_vulnerable_count: number;
      quantum_resistant_count: number;
      transitional_count: number;
      unknown_count: number;
      requires_operator_input_count: number;
    };
    migration_progress: {
      complete: number;
      in_progress: number;
      pilot: number;
      planned: number;
      unplanned: number;
    };
    year_over_year_delta: {
      prior_fiscal_year?: string;
      vulnerable_count_delta?: number;                // negative = progress
      migration_complete_delta?: number;
      net_new_quantum_resistant?: number;
    };
    inheritance_summary: Array<{
      upstream_provider: string;
      asset_count: number;
      upstream_target_date?: string;
      blocked_by_upstream_count: number;
    }>;
    risks: Array<{
      risk_uuid: string;
      title: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      mitigation: string;
      pqc_target_date?: string;
    }>;
    funding_requirements?: {
      estimated_cost_usd?: number;
      cost_year?: number;
      narrative?: string;
    };
    sign_off?: {
      signed_off_by_user_id: number;
      signed_off_by_user_name: string;
      signed_off_at: string;
      signature: string;
      signing_key_id: string;
    };
    authority_citations: string[];                    // verbatim from sources
    references: string[];                             // bibliography URLs
    provenance: ProvenanceBlock;
  }
  ```
- **Federal fiscal-year boundary** — Oct 1 of year N – Sep 30 of year N+1. FY2026 = Oct 1 2025 – Sep 30 2026. Orchestrator derives default FY from system clock; operator overrides via `--fiscal-year FY2026`.
- **Year-over-year delta computation** — `pqc-annual-report-reader.ts` reads `out/pqc-annual-report-FY{prior}.json` (or `cloud-evidence/docs/sources/historical-reports/...` for older years), verifies the embedded sha256 matches the file contents, verifies the Ed25519 signature against the signing key registry, then subtracts counts.
- **Ed25519 sign-off** — canonical-JSON encoding of `{report_uuid, fiscal_year, csp_name, system_id, report_sha256, signed_off_by_user_id, signed_off_at}` signed with the AO's tracker-resident key (same key infrastructure as LOOP-B.B3 sign-off).
- **Tracker DB tables** — see schema above; idempotent `CREATE TABLE IF NOT EXISTS`; additive only (no DROP, no ALTER COLUMN); multi-CSO `tenant_id` deferred to LOOP-H.H3.
- **OMB §V required content** (publicly-known structure):
  1. Agency / CSP identification.
  2. Fiscal year.
  3. Inventory totals.
  4. Quantum-vulnerable algorithm counts by class.
  5. Migration plan progress.
  6. Funding requirements (if applicable, per NSM-10 §3).
  7. Inheritance summary.
  8. Risks + mitigations.
  9. Sign-off (CIO + CISO equivalent — mapped to ao + iso tracker roles).

## Build steps (concrete, numbered)
1. Define `PqcAnnualReport` + helper types in `core/pqc-annual-report.ts`.
2. Pure builder `buildPqcAnnualReport(inventory: CryptoInventoryEntry[], plan: PqcMigrationPlanEntry[], priorReport: PqcAnnualReport | null, riskRegister: RiskRegisterEntry[], opts: PqcAnnualReportOpts) → PqcAnnualReport`:
   - Aggregates inventory totals by `quantum_vulnerable_class`.
   - Aggregates migration progress by `status`.
   - Computes year-over-year delta if `priorReport` present; else delta block undefined.
   - Aggregates inheritance summary by `upstream_provider`.
   - Joins risks from `riskRegister` filtered to entries whose POA&M item carries the `pqc-target-date` prop.
3. Default fiscal-year derivation: helper `fiscalYearFromDate(d: Date): string` — returns FY${y+1} for dates Oct 1 – Dec 31, FY${y} for Jan 1 – Sep 30.
4. **Prior-FY reader** `core/pqc-annual-report-reader.ts`:
   - `readPriorReport(outDir: string, currentFy: string): Promise<PqcAnnualReport | null>`:
     - Decrement currentFy by 1 (FY2027 → FY2026).
     - Look in `outDir/pqc-annual-report-FY{prior}.json` first, fall back to `cloud-evidence/docs/sources/historical-reports/`.
     - Verify embedded `provenance.signingKeyId` against `core/sign.ts` key registry.
     - Verify file sha256 matches `pqc_annual_report_reviews.report_sha256` (when tracker reachable; air-gapped run accepts file-self-sha256).
     - Verify Ed25519 signature.
     - Return parsed report or null when no prior report.
5. **DOCX emitter** in `core/pqc-annual-report-docx.ts` — 11 sections per LOOP-R-SPEC.md §4.R3 step 4:
   1. Cover (CSP name, FY, system identifier, classification line).
   2. Executive Summary (table of inventory totals + migration progress).
   3. Authority (verbatim citations from OMB M-23-02, NSM-10, IR 8547, CNSA 2.0, FIPS 203/204/205 — with PDF page numbers post-download).
   4. Scope (system boundary + components in scope, sourced from SSP).
   5. Inventory (per-purpose breakdown; reference to crypto-inventory.xlsx companion).
   6. Migration Plan Progress (per-status counts; per-asset progress sampled when > 50 entries).
   7. Year-over-Year Delta (prior FY's totals + this FY's totals + deltas; empty section + note when no prior).
   8. Inheritance (table of upstream-provider × CSP-side asset count × inherited target dates).
   9. Risks + Mitigations (joined from LOOP-B risk register entries tagged with pqc-target-date).
   10. Sign-off (AO name + date + signature reference + tracker review uuid).
   11. References (verbatim source URLs + downloaded-PDF references in `docs/sources/`).
   Reuse OOXML helpers from `core/oscal-ssp-docx.ts`.
6. **JSON emit**: `out/pqc-annual-report-FY{year}.json` with top-level `provenance` block (per REO Rule 2.6).
7. **Filename convention**: pinned `pqc-annual-report-FYYYYY.docx` / `.json`. Orchestrator validates the FY pattern.
8. **Tracker `pqc-annual-report.ts` route handler**:
   - `POST /api/pqc-annual-reports` — body: full PqcAnnualReport JSON + fiscal_year. Stores in DB with status='draft'. Returns uuid.
   - `GET /api/pqc-annual-reports` — list with filters.
   - `GET /api/pqc-annual-reports/:id` — detail view with full JSON + sign-off audit trail.
   - `POST /api/pqc-annual-reports/:id/review` — iso role only. Transitions draft → reviewed.
   - `POST /api/pqc-annual-reports/:id/sign` — ao role only. Body: signature string. Verifies signature against AO's published Ed25519 key. Transitions reviewed → signed.
   - `POST /api/pqc-annual-reports/:id/submit` — so role only. Body: `submitted_to_omb_at` datetime. Transitions signed → submitted.
9. **Tracker `pqc-migration-owners.ts` route handler** — CRUD for per-asset owner assignment (CSV-importable; bulk-set endpoint for fleet onboarding).
10. **UI** (`PqcAnnualReport.tsx`):
    - List view: all reviews sorted by fiscal_year desc; filters by status.
    - Detail view: report summary + sign-off audit trail + "Sign" / "Submit" buttons gated on role.
    - "Sign" flow: AO clicks button; client computes canonical JSON + signs with browser-resident key (or hardware key via WebAuthn — out of scope for R.R3 first cut); POST signature.
    - "Submit" flow: SO clicks button after OMB / agency confirms receipt; records `submitted_to_omb_at`.
11. **Strict mode**: `--strict-pqc` (shared flag across R.R1/R.R2/R.R3):
    - Exit non-zero if prior FY's report is missing AND `--first-fiscal-year` is not set.
    - Exit non-zero if prior FY's report signature is invalid.
    - Exit non-zero if any `risks[]` entry references an unresolved REQUIRES-OPERATOR-INPUT field.
12. **Submission bundle**: per-FY files added via filenamePattern-aware role match.
13. **Sign + timestamp**: report files flow through `core/sign.ts` glob + RFC 3161 manifest.
14. Validation:
    - `npm run check:provenance` — provenance block on the JSON.
    - `npm run check:reo` G1+G2+G3.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

| Field | Source | Behavior when missing |
|---|---|---|
| `fiscal_year` | `--fiscal-year FYYYYY` flag OR derived from system clock | Required; orchestrator fails on missing/malformed |
| `csp_name` / `system_id` | `org-profile.yaml` (LOOP-A.A1 already loads) | Inherits from OSCAL SSP; never auto-generated |
| `sign_off` | Tracker UI; AO role action; real Ed25519 signature | When draft is submitted but not yet signed, sign_off is undefined; UI shows "Awaiting AO sign-off" |
| `funding_requirements` | Operator-supplied via tracker UI or via `pqc-config.yaml funding{}` block | Optional per OMB M-23-02 §V; absent block surfaces a `funding_source: 'not-provided'` marker in the entry |
| `risks[].mitigation` | LOOP-B risk register (B.B5) joined by POA&M uuid with `pqc-target-date` prop | When no risk register exists, risks array is empty + log warning `pqc:risk-register-missing` |
| Prior-FY report | Disk read of `pqc-annual-report-FY{prior}.json` OR DB read of `pqc_annual_report_reviews` for prior FY | When missing: `year_over_year_delta.prior_fiscal_year = undefined`; first-year emission |

## Test specifications (≥12 tests)
### Cloud-evidence side
1. `it('aggregates inventory totals correctly')` — sample CryptoInventoryEntry[] → expected inventory_summary block.
2. `it('aggregates migration progress counts per status')` — sample PqcMigrationPlanEntry[] → expected migration_progress block.
3. `it('computes year-over-year delta when prior report exists')` — prior FY had 312 vulnerable, current FY has 248 → delta = -64.
4. `it('emits empty delta when no prior report')` — `year_over_year_delta.prior_fiscal_year === undefined`.
5. `it('joins risks from LOOP-B risk register filtered by pqc-target-date prop')`.
6. `it('aggregates inheritance summary by upstream_provider')` — counts assets per upstream.
7. `it('derives fiscal year from system clock — Nov 2025 → FY2026')`.
8. `it('respects --fiscal-year override flag')`.
9. `it('emits pqc-annual-report-FYNNNN.json with provenance.emitter + sourceCalls')`.
10. `it('emits pqc-annual-report-FYNNNN.docx with all 11 sections')`.
11. `it('reader verifies prior-FY report sha256 + Ed25519 signature before computing delta')`.
12. `it('reader returns null when no prior report on disk')`.
13. `it('strict-pqc fails when prior FY report missing AND --first-fiscal-year not set')`.
14. `it('strict-pqc passes when --first-fiscal-year set and no prior report')`.

### Tracker side
15. `it('creates a draft report when iso submits valid body')`.
16. `it('rejects sign-off without AO role')`.
17. `it('rejects sign-off when status != reviewed')`.
18. `it('records sign-off Ed25519 signature in pqc_annual_report_reviews')`.
19. `it('verifies sign-off signature against AO published Ed25519 key')`.
20. `it('rejects double sign-off attempt')`.
21. `it('owner-assignment route validates asset_id pattern')`.
22. `it('owner-assignment rejects duplicate (asset_id, algorithm_purpose) pair')`.
23. `it('algorithm-override route requires rationale ≥ 50 chars')`.
24. `it('algorithm-override route validates quantum_vulnerable_class enum')`.
25. `it('submission bundle includes both .docx and .json with filenamePattern-matched role')`.
26. `it('UI lists drafts in fiscal_year-descending order')`.
27. `it('UI Sign button gated on ao role + reviewed status')`.

## REO compliance
Per `cloud-evidence/CLAUDE.md`:
- **Rule 1.1** — every aggregated number traces to a real R.R1 / R.R2 input or operator config; no placeholder counts.
- **Rule 1.6** — Ed25519 sign-off is a real signature over canonical JSON; tracker verifies against AO's published public key; never auto-signed.
- **Rule 1.7** — `funding_requirements` is operator-supplied or absent (with marker); never synthesised.
- **Rule 1.10** — AO sign-off is a human action captured in tracker; the system never auto-signs.
- **Rule 2.1** — end-to-end flow: R.R1 + R.R2 + prior FY report → R.R3 aggregator → DOCX + JSON → tracker review → AO sign-off → submission bundle.
- **Rule 2.2** — signed + timestamped via existing pipeline.
- **Rule 2.6** — provenance block on `pqc-annual-report-FYNNNN.json`.
- **Rule 4** — `funding_requirements`, `risks[].mitigation`, `sign_off` are all operator-supplied through tracker or config; never auto-populated.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/pqc-annual-report.test.ts tests/core/pqc-annual-report-docx.test.ts tests/core/pqc-annual-report-emit.test.ts tests/core/pqc-annual-report-reader.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/pqc-annual-report.test.ts server/routes/pqc-migration-owners.test.ts client/src/pages/PqcAnnualReport.test.tsx
```

## Known risks / issues
- **Risk 1: Prior-FY report file may not exist on first-ever R.R3 run.** Mitigation: `--first-fiscal-year` flag opts out of the prior-year requirement; `year_over_year_delta.prior_fiscal_year = undefined` block; CHANGELOG entry documents the bootstrap procedure.
- **Risk 2: Signing key rotation across FY boundaries** could invalidate prior-FY report signature verification. Mitigation: tracker exposes `GET /api/sign/public-keys` returning all historical keys keyed by `key_id`; reader cross-references each report's `signing_key_id` against the registry. Pattern reused from LOOP-B-X3.
- **Risk 3: AO leaves the org between sign-off and submission.** Mitigation: signed report retains the historical signing key + key id; new AO does not need to re-sign; only `submitted` action requires currently-active so role.
- **Risk 4: OMB M-23-02 §V exact field set evolves.** Mitigation: structured `PqcAnnualReport` JSON makes field-add forward compatible; CHANGELOG entry per R.R3 update tracks deltas; per-FY snapshot preserves historical schema.
- **Risk 5: NSM-10 funding requirements may not apply to CSPs.** NSM-10 §3 obligates agency-side funding planning; CSP-side reporting is optional. Mitigation: `funding_requirements` block is optional; operator declares applicability via `pqc-config.yaml funding_required: true|false`.
- **Risk 6: Risk register join could fail if LOOP-B.B5 has not shipped.** Mitigation: when `out/risk-register.json` missing, `risks[]` array empty + log warning; runbook documents the soft dependency.
- **Risk 7: Tracker review snapshot drift** between cloud-evidence-side disk reads + tracker-side DB rows. Mitigation: reader records `fetched_at`; orchestrator's strict-pqc mode requires fetched_at within 1-hour window; reuses LOOP-B-X4 pattern.
- **Risk 8: 11-section DOCX is large; PDF export from Word could lose formatting.** Mitigation: `core/oscal-ssp-docx.ts` pattern proven on similar deliverables; CHANGELOG documents tested Word versions (Office 365, LibreOffice).
- **Risk 9: Multi-CSO tenant isolation deferred.** Mitigation: pqc_annual_report_reviews + pqc_migration_owners + pqc_algorithm_overrides all omit `tenant_id`; LOOP-H.H3 sweep migrates when multi-CSO ships; LOOP-R ships single-tenant only (runbook).
- **Risk 10: Year-over-year delta could be misleading on first inventory expansion.** A CSP that suddenly tags 100 new assets sees `vulnerable_count_delta = +100` even if no regression. Mitigation: report's executive summary includes `total_entries_delta` + `inventory_growth_note` so reviewers see the new-asset signal; runbook documents.

## Open questions (for implementation session to resolve)
- **Q1**: Should the AO sign-off be a server-side signature using a tracker-resident key (LOOP-B.B3 pattern) or client-side via WebAuthn? Recommend: server-side for R.R3 first cut; WebAuthn follow-up under a future security-hardening loop.
- **Q2**: Should the report be auto-resubmitted to the tracker every orchestrator run, or only on `--pqc-annual-report` flag? Recommend: only on flag.
- **Q3**: How do we handle multiple systems under one CSP (multi-system authorization)? Recommend: per-system per-FY report; `system_id` is the second join key on `pqc_annual_report_reviews.UNIQUE(fiscal_year, csp_name, system_id)`.
- **Q4**: Should the report file size be capped (e.g. fail if > 50 MB)? Recommend: warn at 10 MB, fail at 50 MB; very large reports likely indicate misconfigured inventory.
- **Q5**: When does `submitted_to_omb_at` get recorded? Recommend: operator manually after OMB / agency confirmation; never auto-set on file emission.
- **Q6**: For very-large risks[] arrays (>200 entries), do we render all in the DOCX or sample? Recommend: render top 50 by severity + total count; full list in JSON twin.
- **Q7**: Should an operator be able to retroactively re-sign a previously-signed report (e.g. AO change of role)? Recommend: no; create a new draft for the same FY with an `amends_uuid` cross-reference.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean both `cloud-evidence/` and `tracker/`
- [ ] tests passing 100% (count increased by ≥27 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] check:provenance green for `pqc-annual-report-FYNNNN.json`
- [ ] STATUS.md updated (slice row + Overall section; loop title appended "(COMPLETE)" since R.R3 closes LOOP-R)
- [ ] LOOP-R-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>, last_updated=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (cites OMB M-23-02 §V + IR 8547 §4 + tracker schema additions verbatim)
- [ ] Commit with slice ID `R.R3` in message
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-R-SPEC.md` §2 (Dependencies) + §3 (Authoritative sources) + §4.R3 for cross-loop context.
4. Read `cloud-evidence/docs/loops/LOOP-R-RISKS.md` cross-cutting section.
5. Read `cloud-evidence/docs/slices/R/R.R1.md` + `R.R2.md` — your input substrate.
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
7. Read `tracker/server/routes/risk-acceptance.ts` (LOOP-B.B3) — the signed-action-record route pattern your `pqc-annual-report.ts` mirrors.
8. Read `tracker/server/schema.sql` end-to-end — your new tables append at the end.
9. Read `cloud-evidence/core/oscal-ssp-docx.ts` for the OOXML 11-section pattern your `pqc-annual-report-docx.ts` mirrors.
10. Read `cloud-evidence/core/submission-bundle.ts` `WELL_KNOWN` — add two new filenamePattern entries; extend the data structure if needed.
11. Confirm the four PDFs (OMB M-23-02, IR 8547 IPD, CNSA 2.0, FIPS 203/204/205) are in `cloud-evidence/docs/sources/` from R.R1 ship; quote §V verbatim in the report's Authority section.
12. Begin implementation; update Implementation log section as you go.

---
