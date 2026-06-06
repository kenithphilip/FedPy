---
slice_id: K.K1
title: Penetration Test Report ingest schema + tracker display
loop: K
status: pending
commit: —
completed_date: —
depends_on: [A.A1, A.A3, A.A4]
blocks: [F.F1, F.F4, F.F7, E.E1]
estimated_effort: 4–5 days
last_updated: 2026-06-06
---

# K.K1 — Penetration Test Report ingest schema + tracker display

## TL;DR
Define a versioned JSON Schema for the FedRAMP-mandated penetration test
report, ship a tracker upload route + UI for the 3PAO to post the report,
and convert each PenTest finding into a synthetic `KSI-PENTEST.json`
evidence envelope so the existing POA&M (LOOP-A.A1) and AR (LOOP-A.A3)
emitters automatically incorporate per-finding CVSS, attack-vector, and
retest provenance without modifying their core loops. This is what
finally makes a PenTest report machine-readable inside the OSCAL chain
instead of an opaque PDF attached at submission time.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
The FedRAMP CSP Penetration Test Guidance v3.0 (2022-06-30) makes the
PenTest report a mandatory authorization deliverable. Today this codebase
ships nothing that surfaces those findings inside the OSCAL chain — they
live only in the 3PAO's PDF, which means:

1. The OSCAL POA&M (LOOP-A.A1) cannot reference PenTest findings as
   `poam-items[]`, so the chain "PenTest finding → POA&M → remediation"
   has no machine-readable basis.
2. The OSCAL AR (LOOP-A.A3) cannot embed PenTest findings as
   `assessment-results.findings[]`, so a reviewer cannot reproduce the
   determination chain from raw test evidence to AR.
3. ConMon monthly retests of Critical/High PenTest findings (Source 1
   30/90 day requirements) have no machine-trackable retest_status —
   the gap is invisible until the reviewer opens the PDF.

K.K1 closes this gap by defining a 1.0.0 ingest schema, an upload route
that maps each `report.findings[]` row into our existing `Finding` shape
(with a new optional `pentest` block), and a synthetic `KSI-PENTEST.json`
envelope that participates in the existing sign-and-timestamp pipeline.
Downstream OSCAL emitters require no changes beyond propagating the new
`pentest-*` props.

The specific NIST/FedRAMP gap closed: NIST SP 800-53A Rev 5 §CA-8
("Penetration Testing") and §RA-5 ("Vulnerability Monitoring and
Scanning") require the assessment-results artifact to surface the
methodology, scope, and findings of any executed penetration test. The
FedRAMP Rev5 Playbook §SAR Appendix A references the PenTest report as a
required SAR appendix. Without K.K1, our submission bundle (LOOP-A.A4)
emits a gap entry for the PenTest report role at every run.

## Authoritative sources (with verbatim quotes)

- `https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf`
  — FedRAMP CSP Penetration Test Guidance, Version 3.0 (2022-06-30):
  > "A 3PAO might see non-conformance to testing a particular attack
  > vector as a High Risk finding in the SAR Risk Exposure Table (RET)."

  > "Findings must include CVSS v3.1 base scores for standardized
  > severity assessment across all penetration test reports."

  > "The penetration test report must be submitted 3 weeks prior to the
  > SAR submission deadline to allow time for remediation review and
  > validation."

  Six required attack vectors (verbatim from §3): External to Corporate
  Network; External to CSP Target System; Tenant to CSP Management
  System; Tenant-to-Tenant; Mobile Application; Client-side / Social
  Engineering.

  Per-finding required fields (§4): vulnerability description and
  location; attack methodology used; business impact assessment; CVSS
  v3.1 severity rating; remediation steps; affected systems / components.

  Severity buckets (§4.2): 9.0–10.0 Critical, 7.0–8.9 High, 4.0–6.9
  Medium, 0.1–3.9 Low.

  Remediation timelines for PenTest findings (§5.1): Critical 30 days,
  High 90 days.

- `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-115.pdf`
  — NIST SP 800-115 "Technical Guide to Information Security Testing and
  Assessment" (September 2008), §5.2:
  > "Penetration testing typically consists of four phases: planning,
  > discovery, attack, and reporting."

  > "The reporting phase occurs simultaneously with the other three
  > phases of the penetration test."

  Each LOOP-K.K1 finding carries a `phase` field whose enum mirrors these
  four phases verbatim.

- `https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.2&number=CA-8`
  — NIST SP 800-53 Rev 5 §CA-8 "Penetration Testing":
  > "Conduct penetration testing [Assignment: organization-defined
  > frequency] on [Assignment: organization-defined systems or system
  > components]."

  Discussion (verbatim): "Penetration testing is a specialized type of
  assessment conducted on systems or individual system components to
  identify vulnerabilities that could be exploited by adversaries."

- `https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/`
  — OSCAL Assessment Results model v1.1.2, JSON reference. Relevant
  for K.K1 because each PenTest finding emits as one OSCAL
  `finding` with `target.type='objective-id'` and `target.target-id`
  set to the impacted control id (e.g. `AC-2`). K.K2 layers
  statement-id granularity on top.

- `https://www.first.org/cvss/v3.1/specification-document`
  — CVSS v3.1 specification, FIRST.org, June 2019. The schema requires
  `cvss_v31_vector` to match the official vector-string regex (CVSS:3.1/
  prefix + AV:/AC:/PR:/UI:/S:/C:/I:/A: tokens).

## Files to create (exact paths)
- `cloud-evidence/core/pentest-ingest.ts` — pure ingest module. Parses
  PenTest report JSON, validates against schema, converts to
  `EvidenceFile`, emits a synthetic `KSI-PENTEST.json` evidence envelope.
- `cloud-evidence/core/pentest-schema.ts` — TypeScript interfaces
  (`PenTestReport`, `PenTestFinding`, `PenTestRetestRecord`, the
  `AttackVector` and `PenTestPhase` enums) + a frozen JSON Schema
  constant. Exports `PENTEST_INGEST_SCHEMA_VERSION = "1.0.0"`.
- `cloud-evidence/docs/oscal/pentest-ingest.schema.v1.0.0.json` — the
  committed JSON Schema (draft-07) for external validators (3PAO tools
  outside this repo).
- `cloud-evidence/tests/core/pentest-ingest.test.ts` — ingest + envelope
  emission tests (12 cases listed below).
- `cloud-evidence/tests/core/pentest-schema.test.ts` — schema
  conformance tests (4 cases).
- `cloud-evidence/tests/fixtures/pentest/sample-report.json` —
  representative fixture: 6 findings covering all 6 attack vectors,
  mix of Critical/High/Medium/Low CVSS, 3PAO accreditation id present.
- `cloud-evidence/tests/fixtures/pentest/missing-attack-vector.json` —
  negative fixture: only 5 of 6 attack vectors.
- `cloud-evidence/tests/fixtures/pentest/overdue-critical-no-retest.json`
  — fixture with a Critical finding > 30 days past `engagement_end`
  and no retest record. Used to verify REQUIRES-OPERATOR-INPUT
  marker emission.
- `cloud-evidence/tests/fixtures/pentest/cvss-out-of-range.json` —
  fixture with `cvss_v31_base = 11.0`; used to verify schema rejection.
- `tracker/server/db/migrations/041_pentest_reports.sql` — schema for
  three tables (`pentest_reports`, `pentest_findings`,
  `pentest_evidence_attachments`), see SQL in LOOP-K-SPEC.md §4 K.K1.
- `tracker/server/routes/pentest-ingest.ts` — Express route handlers:
  POST upload, GET list, GET detail, PATCH retest update, POST
  evidence attachment.
- `tracker/server/services/pentest-ingest-service.ts` — server-side
  business logic separated from HTTP layer so it can be unit-tested
  without supertest.
- `tracker/server/__tests__/pentest-ingest.test.ts` — ~12 route tests
  using supertest + in-memory SQLite.
- `tracker/client/src/pages/PenTestReport.tsx` — React page: file
  uploader, findings table with attack-vector + CVSS + retest chips,
  per-finding detail panel with evidence-attachment thumbnails.
- `tracker/client/src/api/pentest.ts` — typed API client.
- `tracker/client/src/pages/__tests__/PenTestReport.test.tsx` — RTL
  component tests (6 cases listed below).

## Files to extend
- `cloud-evidence/core/envelope.ts` — add optional
  `pentest_envelope?: true` on `EvidenceFile`. Add the
  `KSI-PENTEST` string-literal-friendly typing pathway (no enum
  change; the existing `ksi_id: string` is sufficient).
- `cloud-evidence/core/findings.ts` — add optional `pentest?` block
  on `Finding`. Shape:
  ```ts
  pentest?: {
    attack_vector:
      | 'external-corporate'
      | 'external-target'
      | 'tenant-to-management'
      | 'tenant-to-tenant'
      | 'mobile'
      | 'client-social';
    cvss_v31_base: number;        // 0–10 inclusive
    cvss_v31_vector: string;      // 'CVSS:3.1/AV:N/...' regex-validated
    phase: 'planning' | 'discovery' | 'attack' | 'reporting';
    retest_status?: 'pending' | 'passed' | 'failed' | 'not-applicable';
    retest_date?: string;         // ISO-8601 date
    report_section_ref?: string;  // anchor inside the report PDF/JSON
    report_finding_id: string;    // stable identifier from the 3PAO's report
  };
  ```
- `cloud-evidence/core/oscal-poam.ts` — extend `findingProps()` (and the
  prop-array builder) to emit pentest-specific props under namespace
  `urn:fedramp:pentest`: `pentest-attack-vector`, `pentest-cvss-base`,
  `pentest-cvss-vector`, `pentest-retest-status`, `pentest-report-id`,
  `pentest-phase`. When the finding has no `pentest` block these props
  are omitted (deterministic).
- `cloud-evidence/core/oscal.ts` — mirror the prop addition on the AR
  finding builder.
- `cloud-evidence/core/submission-bundle.ts` — append to `WELL_KNOWN`:
  1. `{ role: 'pentest-report-pdf', filename: 'pentest-report.pdf', required: false, description: 'PenTest report PDF as authored by the 3PAO (Source 1 deliverable)' }`
  2. `{ role: 'pentest-ingest-json', filename: 'pentest-ingest.json', required: true_when_pdf_present, description: 'PenTest findings ingest JSON (LOOP-K.K1 schema v1.0.0)' }`
  3. The existing `KSI-PENTEST.json` envelope is auto-included via the
     existing ksi-evidence regex; the bundler annotates it with role
     `ksi-pentest-envelope` for INDEX.json clarity.
- `cloud-evidence/core/orchestrator.ts` — add `--pentest-report <path>`
  flag and `CLOUD_EVIDENCE_PENTEST_REPORT` env equivalent. The handler
  calls `emitPenTestEnvelope()` **before** `--oscal-poam` and
  `--oscal-ar` so the synthetic envelope is on disk when those emit.
  Console line: `[pentest] ingested N findings (M critical, K high, J medium, L low)`.
- `cloud-evidence/core/ksi-map.ts` — register `KSI-PENTEST` as
  `scope: 'PROCESS'`, family `AFR-PenTest`, so coverage reporting
  surfaces it as a known process-artifact KSI rather than an unknown
  envelope.
- `cloud-evidence/CHANGELOG.md` — `Unreleased > Added` entry per the
  7-step procedure.

## Schemas / standards
The JSON Schema (`docs/oscal/pentest-ingest.schema.v1.0.0.json`, draft-07)
MUST express:

- `$schema: "http://json-schema.org/draft-07/schema#"`
- `$id: "https://fedramp.kp.local/schemas/pentest-ingest/1.0.0"`
- `version: { type: string; const: "1.0.0" }`
- `executive_summary: { type: string; minLength: 1 }`
- `engagement_window: { type: object; required: [start, end]; properties: { start: { type: string; format: date }, end: { type: string; format: date } } }`
- `3pao: { type: object; required: [name, accreditation_id, lead_assessor_name] }`
- `attack_vectors_tested`: array, minItems=6, items enum of the 6
  vectors, uniqueItems=true. (Strict 6-of-6 enforces Source 1's
  "non-conformance to testing a particular attack vector".)
- `methodology_reference: string` (URL to NIST 800-115 or 3PAO
  methodology doc)
- `findings`: array of:
  - `report_finding_id: string` (unique within the report)
  - `title: string`
  - `description: string`
  - `attack_vector` enum (verbatim 6 above)
  - `phase` enum: `planning|discovery|attack|reporting`
  - `cvss_v31_base: number, minimum: 0, maximum: 10`
  - `cvss_v31_vector: string` matching CVSS v3.1 regex
  - `business_impact: string` (non-empty)
  - `remediation_steps: string` (non-empty)
  - `affected_systems: array<string>`
  - `impacted_controls: array<string>` (NIST 800-53 control IDs)
  - `report_section_ref?: string`
- `retest_findings: array<{ report_finding_id; retest_status; retest_date; retest_notes? }>`
- `additionalProperties: false`

Source 1 method-of-attack ↔ schema `attack_vector` enum mapping (verbatim
labels in slice spec, codified short names in code):

| Source 1 label | Schema enum |
|---|---|
| External to Corporate Network | `external-corporate` |
| External to CSP Target System | `external-target` |
| Tenant to CSP Management System | `tenant-to-management` |
| Tenant-to-Tenant | `tenant-to-tenant` |
| Mobile Application | `mobile` |
| Client-side / Social Engineering | `client-social` |

Severity bucketing (per Source 1 §4.2 verbatim):
- `cvss_v31_base >= 9.0` → `critical`
- `cvss_v31_base >= 7.0` → `high`
- `cvss_v31_base >= 4.0` → `medium`
- `cvss_v31_base >= 0.1` → `low`
- `cvss_v31_base === 0` → `info`

## Build steps (concrete, numbered)

1. **Define ingest types + schema** in `core/pentest-schema.ts`:
   ```ts
   export const PENTEST_INGEST_SCHEMA_VERSION = '1.0.0';
   export type AttackVector = 'external-corporate' | 'external-target' | 'tenant-to-management' | 'tenant-to-tenant' | 'mobile' | 'client-social';
   export type PenTestPhase = 'planning' | 'discovery' | 'attack' | 'reporting';
   export interface PenTestReport { /* ... */ }
   export interface PenTestFinding { /* ... */ }
   export interface PenTestRetestRecord { /* ... */ }
   export const PENTEST_INGEST_SCHEMA: object = { /* draft-07 inline */ };
   ```
   Also write the schema verbatim to
   `docs/oscal/pentest-ingest.schema.v1.0.0.json` so external tools can
   read it without TypeScript.
2. **Pure parser** in `core/pentest-ingest.ts`:
   `parsePenTestReport(raw: unknown): PenTestReport` — uses the existing
   ajv instance pattern from `core/oscal-validate.ts`. On schema
   mismatch, throws `PenTestIngestError` carrying `{ field, message, ajvErrors }`.
3. **Pure converter**:
   `pentestReportToEvidenceFile(report: PenTestReport, opts: { runId; frmrVersion; collectedAt; now? }): EvidenceFile`. Logic:
   - One `RawEvidence` per report top-level section (`executive_summary`,
     `engagement_window`, `attack_vectors_tested`, `methodology_reference`).
   - One `Finding` per `report.findings[i]`.
   - Each `Finding.pentest` block populated; `Finding.severity` derived
     from CVSS via Source 1 buckets.
   - `Finding.nist_controls = report.findings[i].impacted_controls`.
   - `Finding.passed = false` (any reported PenTest finding is a gap).
   - When `now - engagement_end > 30 days` AND severity in
     {critical, high} AND no matching retest_record →
     `Finding.pentest.retest_status` left undefined AND
     `Finding.note = 'REQUIRES-OPERATOR-INPUT: pentest-retest-status'`.
4. **Disk emitter**: `emitPenTestEnvelope(opts: PenTestEmitOptions): PenTestEmitResult`. Reads JSON from `pentestReportPath`, validates,
   converts, writes `outDir/KSI-PENTEST.json`. Result reports counts
   per severity + per attack vector. Provenance block names
   `core/pentest-ingest.ts` + report file path + its sha256 (computed via
   existing `crypto.createHash`).
5. **Wire to orchestrator**: add `--pentest-report` flag handler that
   calls `emitPenTestEnvelope()` BEFORE `--oscal-poam`/`--oscal-ar` so
   downstream emitters see the synthetic envelope. The envelope
   participates in the existing signing manifest via
   `core/sign.ts` — no special-casing.
6. **Add to `submission-bundle.ts` WELL_KNOWN catalogue**: 3 entries
   above. The bundler's role: `pentest-report-pdf` (optional but
   tracked as gap if missing), `pentest-ingest-json` (required when
   PDF present), `ksi-pentest-envelope` (auto-detected).
7. **Tracker DB migration `041_pentest_reports.sql`** — verbatim SQL
   from LOOP-K-SPEC.md §4 K.K1 lines 419–480. Adds three tables with
   foreign keys + audit-log triggers consistent with existing tracker
   migration patterns.
8. **Tracker server routes** in `tracker/server/routes/pentest-ingest.ts`:
   - `POST /api/pentest-reports` — accepts JSON (multipart for PDF).
     Validates via the same ajv instance. Computes PDF sha256 on
     upload. Inserts into `pentest_reports` + `pentest_findings`.
   - `GET /api/pentest-reports` — list, RBAC-scoped to user tenant.
   - `GET /api/pentest-reports/:id` — detail + findings + attachments.
   - `PATCH /api/pentest-reports/:id/findings/:fid` — update
     `retest_status`, `retest_date`, `retest_notes`. Requires
     `assessor` role.
   - `POST /api/pentest-reports/:id/attachments` — evidence upload
     (image/PDF/text MIME allow-list).
   - All endpoints emit audit-log entries via the existing trigger
     pattern.
9. **Tracker server service** in
   `tracker/server/services/pentest-ingest-service.ts`: business
   logic separated from HTTP. Functions:
   `insertReport(report, userId)`, `listReports(userScope)`,
   `getReport(id, userScope)`, `patchFinding(id, fid, patch, userId)`,
   `attachEvidence(id, fid, file, userId)`. Unit-tested without
   supertest.
10. **Tracker client page** `tracker/client/src/pages/PenTestReport.tsx`:
    file uploader with drag-and-drop, server-side validation feedback
    banner, findings table with chips for attack-vector + CVSS bucket +
    retest filter, per-finding detail panel including evidence
    thumbnails. RBAC-aware (assessor sees retest controls; reader does
    not).
11. **Tracker client API** `tracker/client/src/api/pentest.ts`: typed
    client mirroring server routes; uses existing fetch wrapper with
    CSRF token handling.
12. **CHANGELOG entry** in `cloud-evidence/CHANGELOG.md` under
    `Unreleased > Added`. Names every new file + verification counts +
    sha256 of `tests/fixtures/pentest/sample-report.json` emitted
    envelope.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 (`cloud-evidence/CLAUDE.md`): every field below is
operator-supplied. When missing, the system emits a
`REQUIRES-OPERATOR-INPUT` marker naming the field + the consumer
artifact, never a silent default.

| Field | Source | Behavior when missing |
|---|---|---|
| `report.3pao.accreditation_id` | JSON upload | Schema validation error citing the field path; ingest aborts. |
| `report.3pao.name` | JSON upload | Schema error. |
| `report.3pao.lead_assessor_name` | JSON upload | Schema error. |
| `report.engagement_window.start` | JSON upload | Schema error (required for Source 1 timeline math). |
| `report.engagement_window.end` | JSON upload | Schema error (also drives retest-due math). |
| `report.executive_summary` | JSON upload | Schema error (non-empty). |
| `report.attack_vectors_tested[]` (all 6) | JSON upload | Schema error per Source 1 §3 ("non-conformance to testing a particular attack vector"). |
| `report.methodology_reference` | JSON upload | Schema error (Source 4 requires explicit methodology). |
| `findings[i].cvss_v31_vector` | JSON upload | Schema regex error. |
| `findings[i].business_impact` | JSON upload | Schema error (3PAO writes verbatim per Source 1 §4). |
| `findings[i].remediation_steps` | JSON upload | Schema error. |
| `findings[i].impacted_controls[]` | JSON upload | Schema error (empty array fails). |
| `findings[i].retest_status` (only if Critical/High + >30d past `engagement_end`) | Tracker PATCH | Envelope emits `Finding.note = "REQUIRES-OPERATOR-INPUT: pentest-retest-status"` AND OSCAL props emit `pentest-retest-status: REQUIRES-OPERATOR-INPUT`. |
| PDF attachment file | Tracker upload | Submission bundler (LOOP-A.A4) emits a gap entry naming the missing `pentest-report-pdf` role; not a silent default. |
| CLI flag `--pentest-report <path>` | Operator invocation | If absent, the synthetic envelope is not emitted; the submission bundler emits a gap. The OSCAL emitters do not invent PenTest findings. |

## Test specifications (≥12 tests)
Tests in `tests/core/pentest-ingest.test.ts` (12 cases) +
`tests/core/pentest-schema.test.ts` (4 cases):

1. `it('parses a valid 6-vector report fixture')` — assertions: parse
   returns a `PenTestReport`; all 6 attack vectors present in
   `attack_vectors_tested[]`; findings array length matches fixture.
2. `it('rejects a report missing an attack vector')` — uses
   `missing-attack-vector.json`; asserts typed `PenTestIngestError`
   with `field === 'attack_vectors_tested'` and `ajvErrors[0].keyword === 'minItems'`.
3. `it('rejects a finding with CVSS > 10')` — uses
   `cvss-out-of-range.json`; assertion on `ajvErrors[0].keyword === 'maximum'`.
4. `it('rejects a finding with CVSS < 0')` — synthetic fixture; asserts
   `keyword === 'minimum'`.
5. `it('derives severity from CVSS using Source 1 buckets')` —
   parametric: 9.5→critical, 9.0→critical, 7.0→high, 6.9→medium, 4.0→
   medium, 3.9→low, 0.1→low, 0→info. Boundary verified.
6. `it('emits KSI-PENTEST.json envelope with pentest_envelope=true')` —
   reads disk output, asserts `pentest_envelope === true`, asserts
   `ksi_id === 'KSI-PENTEST'`.
7. `it('emits one RawEvidence per report section + one Finding per report finding')`
   — count assertions; raw_evidence.length === 4; findings.length === 6.
8. `it('carries impacted_controls[] onto Finding.nist_controls[]')` —
   assertion: every finding's `nist_controls` equals the source
   `impacted_controls`.
9. `it('populates Finding.pentest block with all required fields')` —
   asserts each Finding has `pentest.attack_vector`, `cvss_v31_base`,
   `cvss_v31_vector`, `phase`, `report_finding_id`.
10. `it('flags retest-required for Critical/High findings >30d past engagement_end without retest_status')`
    — uses `overdue-critical-no-retest.json` + frozen `now`; asserts
    `Finding.note` contains `REQUIRES-OPERATOR-INPUT: pentest-retest-status`.
11. `it('records phase enum from the report finding')` — asserts the
    four 800-115 phases all round-trip through the envelope.
12. `it('provenance block names pentest-ingest.ts + report sha256')` —
    REO compliance: asserts `envelope.provenance.module === 'core/pentest-ingest.ts'` and `envelope.provenance.input_sha256` matches a recomputed sha256.
13. (schema test) `it('schema rejects unknown attack_vector value')` —
    asserts ajv error on `enum`.
14. (schema test) `it('schema rejects unknown phase value')`.
15. (schema test) `it('schema version literal pinned to 1.0.0')` —
    asserts `const` keyword on `version`.
16. (schema test) `it('schema requires engagement_window with valid ISO dates')`
    — asserts ajv `format: date` failure on malformed.

Server tracker tests (`tracker/server/__tests__/pentest-ingest.test.ts`,
~12):

1. POST upload accepts a valid JSON.
2. POST returns 400 with ajv error array when invalid.
3. PATCH updates `retest_status` on a finding.
4. PATCH refuses when caller lacks assessor role (403).
5. GET list scopes to `user.tenant` when `--multi-cso` configured.
6. POST attachments enforces MIME allow-list (image/jpeg, image/png,
   application/pdf, text/plain).
7. Audit log records every PATCH event with `user_id` + `timestamp` +
   `before` + `after`.
8. Duplicate `report_uuid` returns 409 Conflict.
9. Deleting a report cascades to findings + attachments (foreign-key
   ON DELETE CASCADE verified via fresh in-memory DB).
10. Rejects upload with mismatched `schema_version` (e.g. "2.0.0"
    when only 1.0.0 is supported).
11. `signed_at` is set when assessor signs; `signature_blob` populated.
12. PDF sha256 computed + stored on multipart upload.

Client tests (`tracker/client/src/pages/__tests__/PenTestReport.test.tsx`,
~6):

1. Uploads a JSON file and displays the 6-finding table.
2. Filters findings by attack-vector chip.
3. Filters by retest status.
4. Shows REQUIRES-OPERATOR-INPUT badge on overdue retests.
5. Lets assessor mark a retest as passed (PATCH fired).
6. Renders a server-side validation error banner from POST 400 response.

## REO compliance specific to this slice
- **Every value** in the emitted KSI-PENTEST envelope traces to a real
  row in the uploaded `report.findings[]` — no synthetic findings.
- **CVSS values** taken verbatim from the report; the only derivation
  is severity-bucketing per Source 1 §4.2 (allowed under REO Rule 3 as
  a published-standard mapping).
- **No silent fallbacks**: missing attack vector → ingest error.
  Missing CVSS → schema error. Overdue retest → REQUIRES-OPERATOR-INPUT
  in OSCAL props (not a silent pass). Missing PDF → submission bundler
  gap entry.
- **Provenance fields populated**: `envelope.provenance.module = 'core/pentest-ingest.ts'`,
  `provenance.input_sha256`, `provenance.uploaded_by_user_id` (when
  via tracker), `provenance.collected_at`.
- **No mocked SDKs in production paths**: K.K1 input is operator-supplied
  JSON, not a cloud SDK — Rule 4 (operator-supplied data IS real data).
- **No NODE_ENV branches**: tests inject `now` via parameter.
- **Schema does not exceed implementation**: every field in
  `PENTEST_INGEST_SCHEMA` is populated by `pentestReportToEvidenceFile`
  + ingest tests verify each.
- **Signed by**: existing `core/sign.ts` pipeline (Ed25519 + RFC 3161)
  applies to the emitted `KSI-PENTEST.json` exactly as for any other
  envelope.

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/pentest-ingest.test.ts tests/core/pentest-schema.test.ts
npm run check:reo
```

Tracker:
```bash
cd tracker/server
npm test -- pentest-ingest
cd ../client
npm test -- PenTestReport
```

End-to-end smoke (after wiring):
```bash
cd cloud-evidence
node --import tsx/esm core/orchestrator.ts \
  --pentest-report tests/fixtures/pentest/sample-report.json \
  --oscal-poam --oscal-ar --strict-schema
# Expect: KSI-PENTEST.json written under outDir; poam.json includes
# pentest items with pentest-attack-vector + pentest-cvss-base props;
# assessment-results.json finding count includes 6 pentest findings.
```

## Known risks / issues
- **Risk 1 — CVSS vector regex drift.** CVSS v3.1 vectors carry optional
  Temporal + Environmental metric groups (e.g. `/E:X/RL:X/RC:X/...`).
  A 3PAO scanner may emit any subset. Mitigation: regex matches the
  mandatory Base group + allows optional Temporal/Environmental
  segments; if the regex rejects a real vector, the field is treated
  as REQUIRES-OPERATOR-INPUT with the malformed value preserved in the
  validation error message for operator correction. Do NOT silently
  truncate.
- **Risk 2 — Source 1 Version 4 draft.** A public-comment draft of
  Version 4.0 exists (`CSP_Penetration_Test_Guidance_public_comment.pdf`)
  but is not final. K.K1 implements Version 3.0 (final). When Version 4
  finalizes, schema v1.1.0 will add fields backward-compatibly; ingest
  module already keys on `schema_version` literal so old reports
  continue to validate.
- **Risk 3 — 3PAO accreditation_id format.** FedRAMP publishes
  accredited 3PAOs at `https://marketplace.fedramp.gov/assessors/list`
  but does not standardize an ID format. We accept any non-empty
  string; the tracker UI cross-checks against a configured allow-list
  if `config.yaml > pentest.allowed_3pao_ids[]` is populated, but
  defaults to permissive.
- **Risk 4 — Overdue-retest math relies on `engagement_end`.**
  If the operator records `engagement_end` after the actual test
  closure (e.g. used the report-publication date), the 30-day window
  starts later than reality. Mitigation: document in
  `tracker/client/src/pages/PenTestReport.tsx` that `engagement_end`
  MUST be the last test day, not the report-publish date. Schema can
  not enforce this semantic, so it is a documented operator
  obligation.
- **Risk 5 — Synthetic envelope conflicts with real KSI-PENTEST.** No
  cloud collector emits `KSI-PENTEST` today (it is process-artifact),
  so a real-vs-synthetic conflict is impossible. If a future cloud
  KSI is named PENTEST, rename to `KSI-PENTEST-3PAO`.
- **Risk 6 — Tracker storage of large PDF attachments.** The
  `pdf_attachment_path` is filesystem-relative; large reports (~20MB+)
  may exceed default body-parser limits. Mitigation: route uses
  multipart streaming (existing pattern from H.4 evidence file upload)
  with a 100MB cap; oversized uploads return 413 with operator
  guidance.
- **Risk 7 — Schema-version migration.** Bumping `schema_version` to
  1.1.0 in the future requires the parser to accept both versions and
  branch internally. K.K1 lays the groundwork (parser keys on the
  field) but does not implement the v1.1.0 branch.

## Open questions (for implementation session to resolve)
- **Q1**: Should the parser accept CVSS v3.0 vectors (older 3PAO tools)?
  Source 1 mandates v3.1; current plan rejects v3.0 explicitly with a
  helpful error pointing to upgrade docs. Confirm at implementation.
- **Q2**: When the uploaded PDF's filename is `pentest-report.pdf` AND
  the JSON ingest references `report_section_ref: '#finding-3'`, do
  we attempt to validate the anchor against the PDF? Recommended: NO
  for K.K1 (out-of-scope; PDF anchor validation would need a PDF
  parser). Document as out-of-scope.
- **Q3**: Should `report.findings[i].impacted_controls[]` be validated
  against the Moderate baseline control list? Recommended: YES (use
  `core/control-benchmark.ts` Moderate set; unknown control →
  validation error). Operator can override with
  `--allow-unknown-controls` flag.
- **Q4**: Where exactly does the existing ajv instance live?
  `core/oscal-validate.ts` — confirm the export name + how to register
  an additional schema with it without polluting the OSCAL schema
  registry. Suggested: a parallel `core/json-validate.ts` if isolation
  is preferred; or extend `oscal-validate.ts` with a `registerSchema()`
  function.
- **Q5**: For the `pentest_evidence_attachments` table, do we need
  per-attachment encryption-at-rest? Tracker existing convention says
  yes (DB column encryption); K.K1 inherits. Confirm at implementation.
- **Q6**: When the `--pentest-report` flag is supplied but the file is
  malformed JSON (not schema-mismatched, just unparseable), should
  orchestrator continue with remaining flags or hard-fail? Recommended:
  hard-fail (loud signal) — but record the failure in the run-ledger.

## Implementation log (running journal — implementing session updates)
This section is filled in DURING implementation. Leave it empty with a
single placeholder line:

```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥16 for this slice's new
  core tests, plus tracker server + client tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (K.K1 row + Overall section last-shipped +
  next-priority pointing to K.K2)
- [ ] LOOP-K-SPEC.md Section 7 status table updated (K.K1 row)
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
  completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-K.K1`
- [ ] Commit with `LOOP-K.K1: Penetration Test Report ingest schema + tracker display` in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file +
  LOOP-K-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here's everything it
needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded by harness).
2. This file gives you: source obligations + files to create + build
   steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-K-SPEC.md` Section 2
   (Dependencies) for cross-loop context and Section 3 (Authoritative
   sources) for additional verbatim citations.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/oscal-validate.ts` + `core/envelope.ts` +
   `core/findings.ts` + `core/oscal-poam.ts` + `core/oscal.ts` +
   `core/submission-bundle.ts` + `core/orchestrator.ts` to anchor the
   exact extension points.
6. Begin implementation; update Implementation log section as you go.
