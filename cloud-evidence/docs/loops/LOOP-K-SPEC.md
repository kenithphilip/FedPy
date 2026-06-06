# LOOP-K — Test Artifact Ingestion

> **Self-contained implementation spec.** Any future session can read this file
> top-to-bottom and ship every slice in LOOP-K without consulting the original
> planning conversation. Cite-by-default; verbatim quotes from authoritative
> sources; every file path is real; every test is concrete. Adheres to
> `cloud-evidence/CLAUDE.md` (REO standard).

---

## 1. Why this loop exists

FedRAMP authorization requires the 3PAO to produce **two test-artifact classes**
that today have no machine-readable ingest path in this codebase:

1. **Penetration Test Report** (mandated by the FedRAMP CSP Penetration Test
   Guidance v3.0, June 30 2022 — required deliverable in every initial
   authorization and on a recurring basis during ConMon). The report is a
   PDF authored by the 3PAO; downstream FedRAMP tooling (eMASS, Paramify,
   GoComply/fedramp) needs the findings inside it surfaced as OSCAL
   `assessment-results.findings[]` + POA&M items so the chain is complete.
2. **3PAO test results matrix** — the row-per-(control × procedure-object)
   spreadsheet a 3PAO maintains during assessment fieldwork. Each row carries
   the assessor's determination (Satisfied / Other-than-Satisfied / Not
   Applicable) per NIST SP 800-53A Rev 5 procedure-object granularity
   (assessment objectives + determination statements + methods + objects).
   Today our OSCAL AR (LOOP-A.A3) emits findings at the per-rule level only,
   not at the per-procedure-object level. This loses information the 3PAO
   captured and means downstream consumers cannot reproduce the determination
   chain that justifies each control's status.

LOOP-K closes both gaps. It adds:

- A **PenTest Report ingest schema** (JSON Schema versioned + signed) + a
  tracker upload UI. Findings from the report flow into the existing
  POA&M emitter (LOOP-A.A1) and the existing AR emitter (LOOP-A.A3) via
  new finding records that carry attack-vector + CVSS + retest-status props.
- A **test-results matrix → OSCAL AR test-result-objects** path that extends
  `core/oscal.ts` so `finding.target` resolves to a real
  `target-type: 'statement-id'` reference (per OSCAL v1.1.2) carrying the
  800-53A procedure-object identifier, AND adds matching OSCAL
  `local-definitions.activities[]` entries with `assessment-method=EXAMINE`
  / `INTERVIEW` / `TEST` describing how the assessor evaluated each object.

When LOOP-K ships, an authorization package's OSCAL chain is genuinely
audit-replayable: a reviewer can trace a single POA&M item back through the
AR finding → procedure-object → 3PAO determination → original PenTest
finding → raw evidence (screenshot, transcript, scan output) → and confirm
the chain of custody end-to-end. That is the standard FedRAMP Phase Two
explicitly requires (RFC-0014: "truly automated and opinionated validation").

---

## 2. Dependencies

### Loops/slices that must complete first

- **LOOP-A.A1** — POA&M emitter shape (done). PenTest findings feed
  `poam-items[]` via `core/oscal-poam.ts`.
- **LOOP-A.A2** — Assessment Plan (done). The PenTest report references the
  AP's `terms-and-conditions.parts[]` for scope-of-test acknowledgement.
- **LOOP-A.A3** — AR `import-ap` chain wiring (done). The AR must be valid
  before we extend `finding.target` granularity.
- **LOOP-A.A4** — Submission bundler (done). PenTest report + test-results
  matrix become well-known artifacts in the bundle's catalogue.
- **REO-0** — Real-Evidence-Only standard (done). No fabricated finding
  bodies; every test-result row must trace to an uploaded report or
  operator-supplied determination.

### Existing files this loop extends or reads from

- `core/oscal.ts` — extends `OscalFinding.target` to support
  `type: 'statement-id'` (currently only `'objective-id'`).
- `core/oscal-poam.ts` — extends `poam-item.props[]` with PenTest-specific
  props (attack-vector, retest-status).
- `core/oscal-ap.ts` — adds activity definitions for PenTest assessment
  methods so AR `local-definitions.activities[]` references resolve.
- `core/findings.ts` — extends `Finding` schema with optional `pentest`
  block.
- `core/envelope.ts` — extends `EvidenceFile` so a PenTest report manifests
  as a synthetic `KSI-PENTEST.json` envelope.
- `core/submission-bundle.ts` — adds PenTest report + test-results matrix
  to `WELL_KNOWN` artifact catalogue.
- `core/orchestrator.ts` — adds `--pentest-report <path>` and
  `--test-results-matrix <path>` flags.
- `core/control-benchmark.ts` — supplies the 800-53A control + procedure
  object identifiers for cross-referencing.
- `tracker/server/db/migrations/` — adds two new SQLite migrations.
- `tracker/server/routes/` — adds `pentest-ingest.ts` and
  `test-results-matrix.ts` route handlers.
- `tracker/client/src/pages/` — adds `PenTestReport.tsx` and
  `TestResultsMatrix.tsx` React pages.

### Loops unblocked by LOOP-K

- **LOOP-F.F1** (3PAO sign-off UI): can include sign-off on PenTest report
  ingest + per-procedure-object sign-off cells.
- **LOOP-F.F4** (Evidence walk-through artifacts): screenshots/transcripts
  uploaded against a PenTest finding flow through the K.K1 ingest schema.
- **LOOP-F.F7** (SAR draft generator): the SAR draft can pull the PenTest
  executive summary + the test-results matrix verbatim from K.K1/K.K2
  outputs.
- **LOOP-E.E1** (Monthly ConMon analysis report): monthly retests of
  PenTest findings flow through the K.K1 schema's retest fields.

---

## 3. Authoritative sources

Every URL below was fetched on 2026-06-06 during the spec authoring session.
Verbatim quotes are bracketed; cite as `[Source N]` in slice steps.

### Source 1: FedRAMP CSP Penetration Test Guidance, Version 3 (2022-06-30)

URL: `https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf`

Authoritative sections (from direct PDF fetch):

- **Six required attack vectors:**
  1. External to Corporate Network — external threat actors targeting
     CSP corporate infrastructure.
  2. External to CSP Target System — outside attacks targeting the
     production CSO.
  3. Tenant to CSP Management System — isolation between customer
     tenants and CSP management plane.
  4. Tenant-to-Tenant — data segregation between customer tenants.
  5. Mobile Application — security of mobile clients.
  6. Client-side / Social Engineering — user-focused attacks and
     phishing vectors.

  **Verbatim:** "A 3PAO might see non-conformance to testing a particular
  attack vector as a High Risk finding in the SAR Risk Exposure Table
  (RET)."

- **CVSS scheme** (verbatim): "Findings must include CVSS v3.1 base scores
  for standardized severity assessment across all penetration test
  reports." Severity buckets: 9.0–10.0 Critical, 7.0–8.9 High, 4.0–6.9
  Medium, 0.1–3.9 Low.

- **Required per-finding fields:**
  - Vulnerability description and location
  - Attack methodology used
  - Business impact assessment
  - CVSS v3.1 severity rating
  - Remediation steps
  - Affected systems / components

- **Report timing** (verbatim): "The penetration test report must be
  submitted 3 weeks prior to the SAR submission deadline to allow time
  for remediation review and validation."

- **Retest requirement**: Critical and High findings require retesting
  to verify remediation effectiveness before final authorization.

- **Remediation timelines under ConMon**: Critical 30 days, High 90 days
  (NB: the 30/60/90/180 scale used in LOOP-A.A1 is for general findings;
  PenTest findings follow the CSP Pen-Test Guidance scale).

### Source 2: NIST SP 800-53A Rev 5 — Assessing Security and Privacy Controls in Information Systems and Organizations

URL: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53Ar5.pdf` (PDF only — no public HTML view).
Catalog: `https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_A_5_2_0/home` (Release 5.2.0, August 2025).

Core concepts (verbatim from the 800-53A model documentation):

- **Assessment objective** — what must be true for the control to be
  satisfied. Per 800-53A: "Each assessment objective contains a set of
  determination statements related to the particular security or privacy
  control under assessment."
- **Determination statement** — atomic predicate evaluated by the
  assessor; the indivisible unit of conformance.
- **Assessment methods** — exactly three values, mirrored to OSCAL
  `method-type` enum:
  - **EXAMINE** — "the process of reviewing, inspecting, observing,
    studying, or analyzing assessment objects" (per OSCAL v1.1.2 metaschema).
  - **INTERVIEW** — "the process of holding discussions with individuals
    or groups within an organization" (per OSCAL v1.1.2 metaschema).
  - **TEST** — "the process of exercising one or more assessment objects
    under specified conditions" (per OSCAL v1.1.2 metaschema).
- **Assessment objects** — the targets of the method, classed as:
  - **Specifications** (policies, plans, procedures, system security
    plans, system requirements)
  - **Mechanisms** (hardware, software, firmware safeguards implementing
    the control)
  - **Activities** (operational actions involving humans, e.g. backups,
    monitoring)
  - **Individuals** (people serving in defined roles)

Per-control procedure layout (each control in 800-53A): control title →
control description → discussion → control assessment procedure (CAP)
section containing one or more assessment objectives, each with their
determination statements + methods + objects.

**Identifier convention** used by 800-53A Rev 5 (matches the
`SP_800_53_A_5_2_0` catalog identifiers, verifiable in the NIST CPRT JSON):
each procedure object is identified as `<CONTROL>.assessment-objective.<n>`
or `<CONTROL>_obj.<n>` (e.g. `AC-2_obj.1`). The OSCAL projection of these
identifiers is what `finding.target.target-id` must reference when
`target-type` is `statement-id`.

### Source 3: OSCAL Assessment Results model v1.1.2 — JSON Reference

URL: `https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/`

Relevant structural elements (from the v1.1.2 JSON outline + definitions
fetched 2026-06-06):

- **`finding.target`** — wrapper for `finding-target` with these required
  attributes:
  - `type` — enum: `"objective-id"` | `"statement-id"`. LOOP-A.A3
    currently emits only `"objective-id"`. LOOP-K.K2 adds
    `"statement-id"` emission for procedure-object granularity.
  - `target-id` — string; the identifier of the target objective or
    statement. For 800-53A procedure objects this is the
    `<CONTROL>_obj.<n>` token.
  - `title`, `description`, `props`, `links` — optional but populated.
  - `status` — required: `{ state: 'satisfied' | 'not-satisfied' | 'other'; reason?: string; remarks?: string }`.
  - `implementation-status` — optional `{ state: 'implemented' | 'partial' | 'planned' | 'alternative' | 'not-applicable' }`.
  - `objective-status` — optional, contains nested `objective-status`
    structure for sub-objectives.

- **`observation.methods[]`** — verbatim enum allowed values per the
  v1.1.2 schema: `"EXAMINE"`, `"INTERVIEW"`, `"TEST"`, `"UNKNOWN"`. These
  match the 800-53A method values 1:1 (with `"UNKNOWN"` reserved for
  cases where the method cannot be classified).

- **`observation.types[]`** — verbatim allowed values per the v1.1.2
  XML outline: `ssp-statement-issue`, `control-objective`, `mitigation`,
  `finding`, `historic`. LOOP-K.K1 PenTest findings use type `"finding"`;
  LOOP-K.K2 procedure-object observations use type `"control-objective"`.

- **`local-definitions.activities[]`** — array of `activity` objects, each
  with:
  - `uuid` (required)
  - `title`, `description` (optional)
  - `props`, `links` (optional)
  - `steps[]` — each step contains nested
    `reviewed-controls` + `responsible-roles[]`
  - `related-controls` — `reviewed-controls` structure with
    `include-all` | `include-control` | `exclude-control`
  - **Method semantics**: per the OSCAL metaschema, the method is
    expressed via a `prop` with `name="method"` and value in
    {EXAMINE, INTERVIEW, TEST, UNKNOWN}. Verbatim from the JSON
    definitions: "Assessment methods are constrained to three values:
    INTERVIEW: 'The process of holding discussions with individuals or
    groups within an organization'; EXAMINE: 'The process of reviewing,
    inspecting, observing, studying, or analyzing assessment objects';
    TEST: 'The process of exercising one or more assessment objects under
    specified conditions'."

- **`results.assessment-log.entries[]`** — array of timestamped log
  entries documenting the assessment events. Each entry: `uuid`, `title`,
  `description`, `start`, `end`, `logged-by[]`, `related-tasks[]`. LOOP-K
  uses this to record the PenTest engagement window (start = test kickoff,
  end = report-final date).

### Source 4: NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment

URL: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-115.pdf`

Penetration testing four-phase model (Section 5.2 of 800-115):

1. **Planning** — rules of engagement, scope finalization, management
   approvals signed.
2. **Discovery** — reconnaissance, vulnerability scanning, host
   enumeration, service identification.
3. **Attack** — gaining access, escalating privilege, system browsing,
   installing tools.
4. **Reporting** — concurrent with the other three phases; documents
   findings as they are confirmed.

Each LOOP-K.K1 PenTest finding carries a `phase` field naming which of
the four phases produced the evidence — this maps to OSCAL observation
provenance.

### Source 5: FedRAMP Rev5 Playbook — Authorization SAP

URL: `https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/`

Already cited in LOOP-A.A2 + LOOP-A.A5. The SAP's Appendix B
(Sampling Methodology) is the home of the test-results matrix; LOOP-F.F3
(separate slice) auto-derives the sampling plan, and LOOP-K.K2 ingests
the per-control determinations the 3PAO produces from running that plan.

---

## 4. Per-slice implementation specs

### Slice K.K1 — Penetration Test Report ingest schema + tracker display

**Why this slice**: The PenTest report is a mandatory authorization
deliverable but today has no ingest path in the OSCAL chain — findings
exist only in the 3PAO's PDF. K.K1 defines a JSON ingest schema, ships
a tracker upload route + UI, and converts each ingested finding into a
synthetic `KSI-PENTEST.json` evidence envelope so the existing POA&M
emitter (LOOP-A.A1) and AR emitter (LOOP-A.A3) consume it without
modification.

**Files to create** (exact paths, no abbreviation):

- `cloud-evidence/core/pentest-ingest.ts` — pure ingest module. Parses
  PenTest report JSON, validates against schema, emits a synthetic
  `KSI-PENTEST.json` evidence envelope into `outDir/`.
- `cloud-evidence/core/pentest-schema.ts` — TypeScript interfaces +
  the JSON Schema literal for the ingest format. Exports
  `PENTEST_INGEST_SCHEMA_VERSION = "1.0.0"`.
- `cloud-evidence/docs/oscal/pentest-ingest.schema.v1.0.0.json` —
  committed JSON Schema (draft-07) for external validators.
- `cloud-evidence/tests/core/pentest-ingest.test.ts` — ingest + envelope
  emission tests.
- `cloud-evidence/tests/core/pentest-schema.test.ts` — schema-conformance
  tests (ajv validation of representative fixtures).
- `cloud-evidence/tests/fixtures/pentest/sample-report.json` — fixture
  used by tests. Contains 6 findings covering all 6 attack vectors, mix
  of Critical/High/Medium/Low CVSS. (Fixtures are allowed under
  `tests/fixtures/` per REO Rule 1 scope.)
- `cloud-evidence/tests/fixtures/pentest/missing-attack-vector.json` —
  negative fixture (missing required field).
- `tracker/server/db/migrations/041_pentest_reports.sql` — DB schema:
  `pentest_reports`, `pentest_findings`, `pentest_evidence_attachments`.
- `tracker/server/routes/pentest-ingest.ts` — Express handlers for
  upload + finding CRUD + retest-status updates.
- `tracker/server/services/pentest-ingest-service.ts` — server-side
  business logic, separated for unit-testing without an HTTP layer.
- `tracker/client/src/pages/PenTestReport.tsx` — React page: file
  uploader, findings table, per-finding detail panel.
- `tracker/client/src/api/pentest.ts` — typed API client.
- `tracker/server/__tests__/pentest-ingest.test.ts` — server-side route
  tests (supertest).
- `tracker/client/src/pages/__tests__/PenTestReport.test.tsx` — RTL
  component tests.

**Files to extend**:

- `cloud-evidence/core/envelope.ts` — extend `EvidenceFile` with optional
  `pentest_envelope?: true` flag so `oscal-poam.ts` + `oscal.ts` know
  this envelope was synthesized from K.K1 (not from a cloud collector).
- `cloud-evidence/core/findings.ts` — extend `Finding` with optional
  `pentest?: { attack_vector: AttackVector; cvss_v31_base: number; cvss_v31_vector: string; phase: 'planning' | 'discovery' | 'attack' | 'reporting'; retest_status?: 'pending' | 'passed' | 'failed' | 'not-applicable'; retest_date?: string; report_section_ref?: string; report_finding_id: string }`.
- `cloud-evidence/core/oscal-poam.ts` — extend `findingProps()` to emit
  pentest-specific props (`pentest-attack-vector`, `pentest-cvss-base`,
  `pentest-cvss-vector`, `pentest-retest-status`, `pentest-report-id`)
  under namespace `urn:fedramp:pentest`.
- `cloud-evidence/core/oscal.ts` — same prop addition for AR findings.
- `cloud-evidence/core/submission-bundle.ts` — add to `WELL_KNOWN`:
  - `{ role: 'pentest-report-pdf', filename: 'pentest-report.pdf', description: 'PenTest report PDF as authored by the 3PAO (Source 1 deliverable)' }`
  - `{ role: 'pentest-ingest-json', filename: 'pentest-ingest.json', description: 'PenTest findings ingest JSON (LOOP-K.K1 schema v1.0.0)' }`
  - `{ role: 'ksi-evidence', filename: /^KSI-PENTEST\.json$/, description: 'Synthetic PenTest evidence envelope (LOOP-K.K1)' }` (the existing
    KSI-evidence regex catches this; the role label is recorded for
    INDEX.json clarity).
- `cloud-evidence/core/orchestrator.ts` — add `--pentest-report <path>`
  flag (+ `CLOUD_EVIDENCE_PENTEST_REPORT` env), runs BEFORE OSCAL
  emitters so the synthetic envelope is in `outDir/` when POA&M / AR
  emit. Logs `[pentest] ingested N findings (M critical, K high, J medium, L low)`.
- `cloud-evidence/CHANGELOG.md` — Unreleased entry per Section 8.

**Schemas / standards**:

- **Source 1** (FedRAMP CSP Penetration Test Guidance v3) — drives every
  required field. Schema MUST require: `executive_summary` (string),
  `engagement_window: { start: ISO-date; end: ISO-date }`, `3pao: { name; accreditation_id; lead_assessor_name }`, `attack_vectors_tested[]` (array of all 6 names), `findings[]`, `retest_findings[]`, `methodology_reference`. The schema enforces all 6 attack vectors are
  present in `attack_vectors_tested[]` (missing one = ingest error per
  Source 1's "non-conformance to testing a particular attack vector as
  a High Risk finding").
- **Source 4** (NIST 800-115) — drives `phase` enum.
- **Source 3** (OSCAL AR v1.1.2) — drives finding-target mapping;
  PenTest findings emit at `target-type: 'objective-id'` (same as
  existing AR findings) with `target-id` = the impacted NIST control
  ID (e.g. `AC-2`, `SC-7`). K.K2 layers procedure-object granularity
  on top of K.K1's output.

**Build steps**:

1. **Define ingest schema** (`pentest-schema.ts`): TypeScript interfaces
   `PenTestReport`, `PenTestFinding`, `PenTestRetestRecord`, plus the
   JSON Schema literal in `pentest-ingest.schema.v1.0.0.json`. Schema
   `version` field is required + must equal `"1.0.0"` (future bumps
   emit warnings via existing log infra).
2. **Pure parser**: `parsePenTestReport(raw: unknown): PenTestReport`
   throws typed `PenTestIngestError` on schema mismatch. Uses the
   existing ajv pattern from `core/oscal-validate.ts` (no new ajv
   instance).
3. **Pure converter**: `pentestReportToEvidenceFile(report: PenTestReport, opts: { runId; frmrVersion; collectedAt }): EvidenceFile`. Returns a synthetic envelope where:
   - `ksi_id = "KSI-PENTEST"` (constant; recognized by orchestrator
     reporting + matches a new entry in `core/ksi-map.ts` registered
     as `scope: 'PROCESS'`).
   - `pentest_envelope = true`.
   - `providers = [{ provider: 'pentest-3pao', account_id: report.3pao.accreditation_id, evidence: [<one RawEvidence per report section>], findings: [<one Finding per PenTestFinding>] }]`.
   - Each `Finding.pentest` block populated from the report finding.
   - `Finding.severity` derived from CVSS: ≥9.0 → critical, ≥7.0 →
     high, ≥4.0 → medium, ≥0.1 → low, 0 → info (matching Source 1
     buckets verbatim).
   - `Finding.nist_controls[]` carried from the report finding's
     `impacted_controls[]`.
4. **Disk emitter**: `emitPenTestEnvelope(opts: PenTestEmitOptions): PenTestEmitResult` reads the report JSON from `pentestReportPath`, validates, converts, and writes `outDir/KSI-PENTEST.json`. Result reports counts per severity + per attack vector. Provenance block names
   `core/pentest-ingest.ts` + the report file path + its sha256.
5. **Wire into orchestrator**: add `--pentest-report` flag handler that
   calls `emitPenTestEnvelope()` BEFORE `--oscal-poam` and `--oscal-ar`
   so downstream emitters see the envelope. The synthetic envelope
   participates in the existing signing manifest (no special-casing).
6. **Tracker DB migration**: SQL creates three tables (see Schemas section
   below), with foreign keys + audit-log triggers consistent with
   existing tracker patterns.
7. **Tracker server routes**:
   - `POST /api/pentest-reports` — upload report JSON + optional PDF.
   - `GET /api/pentest-reports` — list (RBAC-scoped).
   - `GET /api/pentest-reports/:id` — detail + findings.
   - `PATCH /api/pentest-reports/:id/findings/:fid` — retest update
     (assessor role only).
   - `POST /api/pentest-reports/:id/attachments` — evidence upload
     (image / transcript).
8. **Tracker client page**: file uploader, server-side validation
   feedback, findings table with attack-vector + CVSS + retest filter
   chips, per-finding detail with evidence-attachment thumbnails.
9. **Add to submission-bundle.ts well-known catalogue**: 3 entries
   listed above.
10. **CHANGELOG entry**: name slice + modules + verification counts.

**Tracker DB migration (`041_pentest_reports.sql`)** — full SQL:

```sql
CREATE TABLE pentest_reports (
  id TEXT PRIMARY KEY,
  report_uuid TEXT NOT NULL UNIQUE,
  schema_version TEXT NOT NULL,
  three_pao_name TEXT NOT NULL,
  three_pao_accreditation_id TEXT NOT NULL,
  lead_assessor_name TEXT NOT NULL,
  engagement_start TEXT NOT NULL,
  engagement_end TEXT NOT NULL,
  executive_summary TEXT NOT NULL,
  pdf_attachment_path TEXT,
  pdf_sha256 TEXT,
  uploaded_by_user_id INTEGER NOT NULL REFERENCES users(id),
  uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
  signed_at TEXT,
  signature_blob TEXT,
  status TEXT NOT NULL CHECK (status IN ('draft','submitted','accepted','rejected'))
);

CREATE TABLE pentest_findings (
  id TEXT PRIMARY KEY,
  report_id TEXT NOT NULL REFERENCES pentest_reports(id) ON DELETE CASCADE,
  report_finding_id TEXT NOT NULL,
  attack_vector TEXT NOT NULL CHECK (attack_vector IN (
    'external-corporate','external-target','tenant-to-management',
    'tenant-to-tenant','mobile','client-social')),
  phase TEXT NOT NULL CHECK (phase IN ('planning','discovery','attack','reporting')),
  cvss_v31_base REAL NOT NULL CHECK (cvss_v31_base >= 0 AND cvss_v31_base <= 10),
  cvss_v31_vector TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  business_impact TEXT NOT NULL,
  remediation_steps TEXT NOT NULL,
  affected_systems TEXT NOT NULL,
  impacted_controls TEXT NOT NULL,
  report_section_ref TEXT,
  retest_status TEXT CHECK (retest_status IN ('pending','passed','failed','not-applicable')),
  retest_date TEXT,
  retest_notes TEXT,
  UNIQUE(report_id, report_finding_id)
);

CREATE TABLE pentest_evidence_attachments (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES pentest_findings(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  storage_path TEXT NOT NULL,
  uploaded_by_user_id INTEGER NOT NULL REFERENCES users(id),
  uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_pentest_findings_report ON pentest_findings(report_id);
CREATE INDEX idx_pentest_findings_severity ON pentest_findings(severity);
CREATE INDEX idx_pentest_findings_retest ON pentest_findings(retest_status);
CREATE INDEX idx_pentest_attachments_finding ON pentest_evidence_attachments(finding_id);
```

**REQUIRES-OPERATOR-INPUT fields**:

- `report.3pao.accreditation_id` — operator-supplied via the JSON upload;
  if absent on parse, the schema-validation error names the field and
  points to the schema URL. No silent default.
- `report.engagement_window` — operator-supplied; required by Source 1
  for the report to be authoritative.
- `report.findings[].cvss_v31_vector` — required string; CVSS vector is
  emitted by every modern scanner and must be present.
- `report.findings[].retest_status` — optional at initial submission; the
  tracker PATCH endpoint records subsequent retests. When the OSCAL AR
  emits a PenTest finding that has no retest record yet AND the finding
  is Critical or High AND >30 days have passed since `engagement_end`,
  the props emit `pentest-retest-status: REQUIRES-OPERATOR-INPUT` —
  Source 1's retest-mandatory rule surfaces as an operator gap, never
  as a silent pass.
- `report.findings[].business_impact` — operator-supplied (3PAO writes
  this); no auto-narrative.
- PDF attachment is OPTIONAL at JSON upload — but if missing, the
  submission bundler (LOOP-A.A4) emits a gap entry naming the missing
  `pentest-report-pdf` role.

**Test specifications** (12 tests, all in
`tests/core/pentest-ingest.test.ts` + 4 in
`tests/core/pentest-schema.test.ts`):

1. `it('parses a valid 6-vector report fixture', ...)` — asserts
   parse returns a `PenTestReport` with 6 findings + all 6 attack
   vectors present.
2. `it('rejects a report missing an attack vector', ...)` — uses
   `missing-attack-vector.json` fixture; asserts typed
   `PenTestIngestError` with `field === 'attack_vectors_tested'`.
3. `it('rejects a finding with CVSS > 10', ...)` — schema validation
   error citing the upper bound.
4. `it('rejects a finding with CVSS < 0', ...)` — schema validation
   error citing the lower bound.
5. `it('derives severity from CVSS using Source 1 buckets', ...)` —
   asserts 9.5 → critical, 7.0 → high, 4.0 → medium, 0.1 → low, 0
   → info (boundary values).
6. `it('emits KSI-PENTEST.json envelope with pentest_envelope=true', ...)`
   — assertion on disk output structure.
7. `it('emits one RawEvidence per report section + one Finding per report finding', ...)` — count assertions.
8. `it('carries impacted_controls[] onto Finding.nist_controls[]', ...)`
   — verifies AR mapping wire is intact.
9. `it('populates Finding.pentest block with all required fields', ...)`
   — every Finding has `pentest.attack_vector`, `cvss_v31_base`,
   `cvss_v31_vector`, `phase`, `report_finding_id`.
10. `it('flags retest-required for Critical/High findings >30d past engagement_end without retest_status', ...)` — uses a frozen `now` parameter; verifies the REQUIRES-OPERATOR-INPUT marker in the
    emitted envelope's finding-level props.
11. `it('records phase enum from the report finding', ...)` — verifies
    the four 800-115 phases all round-trip.
12. `it('provenance block names pentest-ingest.ts + report sha256', ...)`
    — REO compliance.
13. (schema test) `it('schema rejects unknown attack_vector value', ...)`.
14. (schema test) `it('schema rejects unknown phase value', ...)`.
15. (schema test) `it('schema version literal pinned to 1.0.0', ...)`.
16. (schema test) `it('schema requires engagement_window with valid ISO dates', ...)`.

Server-side tracker tests (`tracker/server/__tests__/pentest-ingest.test.ts`),
~12 tests:

1. `it('POST /api/pentest-reports accepts a valid JSON upload', ...)`.
2. `it('POST returns 400 with schema errors when invalid', ...)`.
3. `it('PATCH /api/pentest-reports/:id/findings/:fid updates retest_status', ...)`.
4. `it('PATCH refuses when caller lacks assessor role', ...)` — RBAC.
5. `it('GET list scopes to user.tenant when --multi-cso is set', ...)` — LOOP-H.H3 hook.
6. `it('POST /attachments enforces MIME allow-list', ...)`.
7. `it('audit log records every PATCH event', ...)`.
8. `it('uploading a duplicate report_uuid returns 409', ...)`.
9. `it('deleting a report cascades to findings + attachments', ...)`.
10. `it('rejects upload with mismatched schema_version', ...)`.
11. `it('signed_at is set when assessor signs the report', ...)`.
12. `it('PDF SHA256 is computed + stored on upload', ...)`.

Client-side tests (`tracker/client/src/pages/__tests__/PenTestReport.test.tsx`),
~6 tests:

1. `it('uploads a JSON file and displays the 6-finding table', ...)`.
2. `it('filters findings by attack vector chip', ...)`.
3. `it('filters by retest status', ...)`.
4. `it('shows REQUIRES-OPERATOR-INPUT badge on overdue retests', ...)`.
5. `it('lets assessor mark a retest as passed', ...)`.
6. `it('renders a server-side validation error banner', ...)`.

**REO compliance checks specific to this slice**:

- Every emitted PenTest finding traces to a real row in
  `report.findings[]` (the parsed JSON) — no synthetic findings.
- CVSS values are taken verbatim from the report — no auto-computation
  beyond severity-bucketing per Source 1.
- Operator-input markers used for `retest_status` when overdue (Critical/
  High >30d) and missing PDF (bundler gap entry).
- No silent fallbacks: a report missing any of the 6 attack vectors
  fails ingest at the schema layer; a finding missing CVSS fails;
  retest gap surfaces in OSCAL props, not as a pass.
- Provenance: every emitted KSI-PENTEST envelope's provenance block
  names `core/pentest-ingest.ts`, the input report's sha256, and the
  uploading user_id (when run via tracker).
- Tracker DB constraints replicate the schema constraints — defense in
  depth.
- No fabricated 3PAO names / accreditation IDs — both are required
  fields with no defaults.

**Verification commands**:

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
# Expect: KSI-PENTEST.json written, poam.json includes pentest items,
# assessment-results.json finding count includes pentest findings.
```

**Estimated effort**: 4–5 days (1.5d ingest + schema; 1.5d tracker
server + DB; 1.5d tracker client; 0.5d wiring + verification).

---

### Slice K.K2 — 3PAO test results matrix → OSCAL AR test-result-objects per 800-53A procedure objects

**Why this slice**: The OSCAL AR (LOOP-A.A3) currently emits
`finding.target.type = 'objective-id'` with `target-id = ksi-id`. That
discards the assessor's per-procedure-object determination — the
indivisible unit of conformance in 800-53A. K.K2 ingests the 3PAO's
test-results matrix (one row per control × procedure-object × method)
and extends the AR so every assessor determination becomes its own
OSCAL `finding` with `target.type = 'statement-id'` referencing the
exact procedure-object identifier, plus a matching
`local-definitions.activities[]` entry recording the method (EXAMINE /
INTERVIEW / TEST) and the objects examined.

**Files to create**:

- `cloud-evidence/core/test-results-matrix.ts` — pure ingest + builder.
  Parses the matrix CSV/JSON, emits enriched OSCAL AR fragments.
- `cloud-evidence/core/test-results-schema.ts` — TypeScript interfaces +
  JSON Schema. Exports `MATRIX_SCHEMA_VERSION = "1.0.0"`.
- `cloud-evidence/docs/oscal/test-results-matrix.schema.v1.0.0.json` —
  committed JSON Schema.
- `cloud-evidence/core/procedure-objects.ts` — loader for 800-53A
  procedure-object identifiers per control, sourced from the existing
  `core/control-benchmark.ts` baseline + the NIST CPRT JSON
  (`scripts/extract-800-53a-procedure-objects.mjs`).
- `cloud-evidence/scripts/extract-800-53a-procedure-objects.mjs` —
  one-shot extractor (allowed by REO Rule 1 since it transforms an
  external catalog). Output:
  `cloud-evidence/docs/800-53a-procedure-objects.generated.json`.
- `cloud-evidence/docs/800-53a-procedure-objects.generated.json` —
  generated artifact; structure
  `{ controls: { "AC-2": { objectives: [{ id: "AC-2_obj.1", text: "...", methods: ["EXAMINE","INTERVIEW"], objects: ["Mechanisms","Activities"] }] } } }`.
- `cloud-evidence/tests/core/test-results-matrix.test.ts` — matrix
  ingest + AR-fragment emission tests.
- `cloud-evidence/tests/core/test-results-schema.test.ts` — schema
  conformance tests.
- `cloud-evidence/tests/core/procedure-objects.test.ts` — loader
  tests + invariant: every control referenced in
  `core/control-benchmark.ts` baselines has at least one
  procedure-object identifier in the extracted JSON.
- `cloud-evidence/tests/fixtures/test-results/sample-matrix.csv` —
  representative matrix.
- `cloud-evidence/tests/fixtures/test-results/sample-matrix.json` —
  same data as JSON.
- `cloud-evidence/tests/fixtures/test-results/sample-matrix-with-na.csv`
  — fixture with Not Applicable determinations.
- `tracker/server/db/migrations/042_test_results_matrix.sql` — DB
  schema: `test_results_matrices`, `test_results_rows`,
  `test_results_row_evidence`.
- `tracker/server/routes/test-results-matrix.ts` — Express handlers.
- `tracker/server/services/test-results-matrix-service.ts` — business
  logic.
- `tracker/client/src/pages/TestResultsMatrix.tsx` — React page: matrix
  uploader, per-row determination cells (Satisfied / Other-than-Satisfied
  / Not Applicable), method tag, evidence attachments per row.
- `tracker/client/src/api/test-results.ts` — typed client.
- `tracker/server/__tests__/test-results-matrix.test.ts` — route tests.
- `tracker/client/src/pages/__tests__/TestResultsMatrix.test.tsx` — RTL.

**Files to extend**:

- `cloud-evidence/core/oscal.ts`:
  - Extend `OscalFinding.target.type` to allow `'statement-id'`.
  - Add `OscalActivity` interface (uuid, title, description, props
    [`method`, `assessment-object-type`], `related-controls`, steps).
  - Extend `OscalAssessmentResults.results[].local-definitions` to
    carry `activities[]` (currently only has `remarks`).
  - Add `embedTestResultsMatrix(ar: OscalAssessmentResults, matrix: TestResultsMatrix): OscalAssessmentResults` — pure function that takes the built AR
    and overlays per-procedure-object findings + activities.
  - The existing per-rule findings remain (so the AR is still consumable
    by tools that only understand `objective-id`); the per-statement-id
    findings are appended with a prop `oscal-target-granularity: procedure-object` so a 3PAO can filter.
- `cloud-evidence/core/oscal-ap.ts`:
  - Extend AP `local-definitions.activities[]` to include a matching
    activity per (control × procedure-object), so the AP→AR reference
    chain by `activity-uuid` is sound. The activity is added only when
    `--test-results-matrix` is supplied (otherwise the AP keeps the
    LOOP-A.A2 per-KSI activities).
- `cloud-evidence/core/orchestrator.ts` — add `--test-results-matrix <path>`
  flag (+ `CLOUD_EVIDENCE_TEST_RESULTS_MATRIX` env), runs BEFORE
  `--oscal-ar` AND AFTER `--oscal-ap`. Console: `[matrix] N rows
  across M controls / K procedure-objects (S satisfied, O other-than-satisfied, N na)`.
- `cloud-evidence/core/submission-bundle.ts` — add to `WELL_KNOWN`:
  - `{ role: 'test-results-matrix-csv', filename: 'test-results-matrix.csv', description: 'Per-control × procedure-object × method assessor determinations (LOOP-K.K2)' }`
  - `{ role: 'test-results-matrix-json', filename: 'test-results-matrix.json', description: 'Test results matrix — JSON projection' }`
- `cloud-evidence/CHANGELOG.md` — Unreleased entry.

**Schemas / standards**:

- **Source 2** (800-53A Rev 5) — drives the procedure-object identifier
  scheme (`<CONTROL>_obj.<n>`) + the method enum + the object-type enum
  (`Specifications` | `Mechanisms` | `Activities` | `Individuals`).
- **Source 3** (OSCAL AR v1.1.2) — drives `finding.target.type`,
  `local-definitions.activities[]`, `observation.methods[]`, and
  `observation.types[]` enums. **Verbatim from the v1.1.2 metaschema**:
  "Assessment methods are constrained to three values: INTERVIEW: 'The
  process of holding discussions with individuals or groups within an
  organization'; EXAMINE: 'The process of reviewing, inspecting,
  observing, studying, or analyzing assessment objects'; TEST: 'The
  process of exercising one or more assessment objects under specified
  conditions'." These appear as `prop[@name='method']` on the
  `activity` per the OSCAL constraint definitions.
- **Source 5** (FedRAMP SAP Appendix B) — the test-results matrix is
  the structured artifact the SAP commits to producing.

**Build steps**:

1. **Extractor**: write `scripts/extract-800-53a-procedure-objects.mjs`
   that fetches the NIST CPRT JSON catalog for
   `SP_800_53_A_5_2_0` (URL committed in the script header) and emits
   the deduplicated procedure-object identifier set per control. The
   script writes
   `docs/800-53a-procedure-objects.generated.json` AND is wired into
   `npm run extract:catalogs` so the catalog is reproducibly
   regenerated.
2. **Loader**: `procedure-objects.ts` exports
   `loadProcedureObjects(): ProcedureObjectCatalog` reading the
   generated JSON. Invariant function:
   `assertAllBaselineControlsHaveObjects(baseline: ControlBenchmark): void` throws if any control in the Moderate baseline (LOOP-A.A2's
   149+ control list) lacks at least one procedure object — this is
   a build-time gate, not a runtime gate.
3. **Matrix schema** (`test-results-schema.ts`): defines
   `TestResultsMatrix = { schema_version: '1.0.0'; engagement_id: string; assessor_name: string; rows: TestResultsRow[] }` and
   `TestResultsRow = { control_id: string; procedure_object_id: string; method: 'EXAMINE'|'INTERVIEW'|'TEST'; objects_examined: ('Specifications'|'Mechanisms'|'Activities'|'Individuals')[]; determination: 'satisfied'|'other-than-satisfied'|'not-applicable'; rationale: string; assessor_uuid?: string; evidence_uuids?: string[]; observed_at: string }`.
4. **Pure parser**:
   `parseTestResultsMatrix(raw: string | object): TestResultsMatrix`.
   Accepts CSV (RFC 4180) or JSON. CSV column order: `control_id,
   procedure_object_id, method, objects_examined, determination,
   rationale, observed_at`. Throws `TestResultsIngestError` on
   schema mismatch.
5. **Pure validator**:
   `validateMatrixAgainstBaseline(matrix: TestResultsMatrix, baseline: ControlBenchmark, catalog: ProcedureObjectCatalog): ValidationReport`
   returns a structured report with `unknown_controls[]`,
   `unknown_procedure_objects[]`,
   `controls_missing_coverage[]` (every baseline control should be
   covered by at least one matrix row),
   `objects_missing_coverage[]` (every procedure-object referenced
   in the baseline catalog should appear). The orchestrator surfaces
   `coverage_missing > 0` as a NOTICE; `unknown_*` as an ERROR.
6. **Pure builder**:
   `buildOscalActivities(matrix: TestResultsMatrix): OscalActivity[]`
   — one activity per (control × procedure-object × method), with
   `props: [{ name: 'method', value: <enum> }, { name: 'assessment-object-type', value: <one per objects_examined> }]`.
   Deterministic UUIDs via existing `deterministicUuid()`.
7. **Pure builder**:
   `buildOscalFindingsFromMatrix(matrix: TestResultsMatrix, ksiToControlMap: Map<string,string[]>): OscalFinding[]` — one finding per matrix row, with `target.type = 'statement-id'`,
   `target.target-id = row.procedure_object_id`,
   `target.status.state` mapped from `determination` (satisfied →
   satisfied; other-than-satisfied → not-satisfied; not-applicable →
   other with `reason: 'not-applicable'`). Each finding carries
   `props: [{ name: 'assessor', value: matrix.assessor_name }, { name: 'oscal-target-granularity', value: 'procedure-object' }]`. `related-observations[]` cross-references the observation built in step 8.
8. **Pure builder**:
   `buildObservationsFromMatrix(matrix: TestResultsMatrix): OscalObservation[]` — one observation per row, `methods: [row.method]`, `types: ['control-objective']`, `description = row.rationale`,
   `collected = row.observed_at`.
9. **Compose**: `embedTestResultsMatrix(ar: OscalAssessmentResults, matrix: TestResultsMatrix): OscalAssessmentResults` returns a new
   AR with activities appended to each result's
   `local-definitions.activities[]`, observations + findings appended
   to `results[0]` (one assessment cycle per matrix; the matrix
   itself is single-engagement). Pure; no I/O.
10. **Disk emitter**:
    `emitTestResultsMatrixOscal(matrixPath: string, opts: { outDir; arPath?: string }): EmitResult`. When `arPath` is supplied (the LOOP-A.A3 AR
    just emitted), reads it, applies `embedTestResultsMatrix`, writes
    back. Else emits a standalone `test-results-fragment.json`
    intended to be merged later.
11. **Wire into orchestrator**: `--test-results-matrix` flag handler.
    Runs AFTER `--oscal-ar` so the AR exists to extend.
12. **AP extension**: when `--test-results-matrix` is set,
    `core/oscal-ap.ts` reads the matrix and augments its own
    `local-definitions.activities[]` to mirror the K.K2 activities,
    so the AP↔AR `activity-uuid` references resolve.
13. **Tracker DB migration `042_test_results_matrix.sql`**:

    ```sql
    CREATE TABLE test_results_matrices (
      id TEXT PRIMARY KEY,
      engagement_id TEXT NOT NULL,
      schema_version TEXT NOT NULL,
      assessor_name TEXT NOT NULL,
      uploaded_by_user_id INTEGER NOT NULL REFERENCES users(id),
      uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
      committed_at TEXT,
      committed_to_ar_path TEXT,
      UNIQUE(engagement_id)
    );

    CREATE TABLE test_results_rows (
      id TEXT PRIMARY KEY,
      matrix_id TEXT NOT NULL REFERENCES test_results_matrices(id) ON DELETE CASCADE,
      control_id TEXT NOT NULL,
      procedure_object_id TEXT NOT NULL,
      method TEXT NOT NULL CHECK (method IN ('EXAMINE','INTERVIEW','TEST')),
      objects_examined TEXT NOT NULL, -- JSON array
      determination TEXT NOT NULL CHECK (determination IN ('satisfied','other-than-satisfied','not-applicable')),
      rationale TEXT NOT NULL,
      assessor_uuid TEXT,
      observed_at TEXT NOT NULL,
      UNIQUE(matrix_id, control_id, procedure_object_id, method)
    );

    CREATE TABLE test_results_row_evidence (
      id TEXT PRIMARY KEY,
      row_id TEXT NOT NULL REFERENCES test_results_rows(id) ON DELETE CASCADE,
      evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('screenshot','transcript','log','file','external-url')),
      reference TEXT NOT NULL,
      sha256 TEXT,
      uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX idx_test_results_rows_matrix ON test_results_rows(matrix_id);
    CREATE INDEX idx_test_results_rows_control ON test_results_rows(control_id);
    CREATE INDEX idx_test_results_rows_determination ON test_results_rows(determination);
    ```

14. **Tracker server routes**:
    - `POST /api/test-results-matrices` — upload CSV/JSON, validate.
    - `GET /api/test-results-matrices` — list.
    - `GET /api/test-results-matrices/:id` — detail + rows.
    - `PATCH /api/test-results-matrices/:id/rows/:rid` — update
      determination (assessor role only).
    - `POST /api/test-results-matrices/:id/rows/:rid/evidence` — attach
      evidence.
    - `POST /api/test-results-matrices/:id/commit` — mark matrix
      committed → embed into the AR at the configured outDir.
15. **Tracker client page**: matrix grid editor; method-filter,
    coverage-gap banner ("X controls have no rows yet"), bulk
    upload, per-row evidence attachments.
16. **Add to submission-bundle.ts well-known catalogue**: 2 entries
    listed above.
17. **CHANGELOG entry**.

**REQUIRES-OPERATOR-INPUT fields**:

- `matrix.assessor_name` — operator-supplied via upload metadata. No
  default.
- `row.rationale` — required for every row; the schema rejects empty
  rationale strings. No silent default.
- `row.observed_at` — required ISO date; no default.
- `row.objects_examined[]` — required; empty array fails schema.
- When the validator detects baseline controls with no matrix coverage,
  the orchestrator emits one `REQUIRES-OPERATOR-INPUT` line per
  uncovered control naming the control + the procedure-object IDs that
  need rows.
- When a row's `method = TEST` AND `objects_examined` includes only
  `'Individuals'`, the validator emits a NOTICE — TEST against humans
  is methodologically suspect; the operator must justify or correct.

**Test specifications** (15 tests for the matrix module + 6 for
procedure-objects + 4 for schema + tracker tests):

1. `it('parses a 3-row CSV matrix', ...)` — round-trip.
2. `it('parses a 3-row JSON matrix', ...)`.
3. `it('rejects a row with unknown method', ...)`.
4. `it('rejects a row with unknown determination value', ...)`.
5. `it('rejects empty rationale', ...)`.
6. `it('detects unknown control_id against baseline', ...)`.
7. `it('detects unknown procedure_object_id against catalog', ...)`.
8. `it('reports baseline controls without coverage', ...)`.
9. `it('builds one OscalActivity per (control × procedure-object × method)', ...)` — count assertion.
10. `it('emits activity prop method=EXAMINE/INTERVIEW/TEST verbatim', ...)`.
11. `it('builds findings with target.type=statement-id', ...)` — asserts
    target.type literal.
12. `it('maps determination satisfied → status.state=satisfied', ...)`.
13. `it('maps other-than-satisfied → status.state=not-satisfied', ...)`.
14. `it('maps not-applicable → status.state=other with reason=not-applicable', ...)`.
15. `it('embeds activities + findings into an existing OSCAL AR without losing prior findings', ...)` — composition correctness.
16. (procedure-objects test) `it('loads procedure-object catalog from generated JSON', ...)`.
17. (procedure-objects test) `it('assertAllBaselineControlsHaveObjects throws on missing control', ...)`.
18. (procedure-objects test) `it('every Moderate-baseline control has ≥1 procedure object', ...)` — invariant against the committed catalog.
19. (procedure-objects test) `it('procedure-object identifiers match <CONTROL>_obj.<n> pattern', ...)`.
20. (procedure-objects test) `it('extractor script output is byte-stable across reruns', ...)`.
21. (procedure-objects test) `it('catalog contains methods + objects arrays per objective', ...)`.
22. (schema test) `it('schema version literal pinned to 1.0.0', ...)`.
23. (schema test) `it('CSV parser handles RFC 4180 quoted fields with commas', ...)`.
24. (schema test) `it('CSV parser rejects malformed rows', ...)`.
25. (schema test) `it('JSON schema rejects extra top-level fields', ...)`.

Tracker tests (~14):

1. POST upload accepts a valid CSV.
2. POST returns 400 with unknown control_id.
3. PATCH refuses when caller lacks assessor role.
4. PATCH updates determination + writes audit log.
5. POST commit embeds into AR at configured outDir.
6. POST commit refuses when uncovered controls exist (unless
   `?force=true`).
7. Bulk row evidence upload enforces MIME allow-list.
8. GET list scopes by engagement.
9. Duplicate matrix per engagement returns 409.
10. Foreign-key cascade deletes rows + evidence on matrix deletion.
11. Audit log captures the commit event.
12. Row update preserves audit history.
13. Coverage gap surfaces in the GET detail response.
14. Method TEST + objects=Individuals only emits a server warning.

Client tests (~5):

1. Matrix grid renders rows by control.
2. Coverage-gap banner shows uncovered controls.
3. Bulk upload CSV via file picker.
4. Row determination update calls PATCH.
5. Evidence attachment upload shows new row.

**REO compliance checks specific to this slice**:

- Every emitted OSCAL activity + finding traces to a real matrix row.
- Procedure-object identifiers are sourced ONLY from the
  generated catalog (which is sourced from NIST CPRT 800-53A Rev 5
  release 5.2.0). No invented IDs.
- The catalog generation script is committed + reproducible;
  `npm run check:reo` includes a check that the committed JSON's
  sha256 matches what re-extracting would produce (or warns on drift
  with explicit operator action required).
- Determination mappings (satisfied / other-than-satisfied /
  not-applicable) are the verbatim 800-53A terms — REO Rule 3 permits
  these as published-standard constants.
- Coverage gaps surface as `REQUIRES-OPERATOR-INPUT` diagnostics
  naming each uncovered control — never a silent omission.
- Embedded AR preserves all prior findings (the existing per-KSI
  per-rule findings remain); we ADD per-statement findings. A test
  asserts both granularities coexist.

**Verification commands**:

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/test-results-matrix.test.ts \
            tests/core/test-results-schema.test.ts \
            tests/core/procedure-objects.test.ts
npm run check:reo
```

Catalog extractor reproducibility:

```bash
cd cloud-evidence
node scripts/extract-800-53a-procedure-objects.mjs
git diff --exit-code docs/800-53a-procedure-objects.generated.json
# Expected: clean (byte-stable).
```

Tracker:

```bash
cd tracker/server
npm test -- test-results-matrix
cd ../client
npm test -- TestResultsMatrix
```

End-to-end smoke (after wiring):

```bash
cd cloud-evidence
node --import tsx/esm core/orchestrator.ts \
  --oscal-ssp --oscal-ap --oscal-ar --oscal-poam \
  --test-results-matrix tests/fixtures/test-results/sample-matrix.csv \
  --strict-schema --strict-chain
# Expect: assessment-results.json finding count includes per-statement
# findings; ap.json local-definitions.activities[] mirror the matrix;
# orchestrator log shows coverage banner.
```

**Estimated effort**: 5–6 days (1.5d catalog extractor + loader; 1.5d
matrix ingest + builders; 1d OSCAL AR/AP composition; 1.5d tracker
server + DB + client; 0.5d wiring + verification).

---

## 5. Loop-wide acceptance criteria

LOOP-K is complete when ALL of:

1. **Both slices shipped + green CI**: `npm run typecheck`, `npm test`,
   `npm run check:reo` all clean. Test count rises by ≥40 (≈20–25 per
   slice plus tracker tests).
2. **End-to-end smoke produces a fully chained submission package**:
   running `orchestrator.ts` with `--pentest-report <fixture> --test-results-matrix <fixture>` plus the existing LOOP-A flags
   produces a `submission-package.tar.gz` whose `INDEX.json` lists:
   - `pentest-report-pdf` (when supplied) OR a gap entry for it.
   - `pentest-ingest-json`.
   - `test-results-matrix-csv` + `test-results-matrix-json`.
   - The OSCAL AR contains BOTH `target.type=objective-id` (existing)
     AND `target.type=statement-id` (new) findings.
   - The OSCAL AP contains activities mirroring the matrix.
3. **Procedure-object catalog committed + invariant-passing**:
   `docs/800-53a-procedure-objects.generated.json` exists, the
   extractor is reproducible (byte-stable rerun), and every control
   in the Moderate baseline has ≥1 procedure object.
4. **Tracker integration verified**: tracker server tests pass,
   tracker client tests pass, DB migrations apply cleanly on a fresh
   database.
5. **PenTest retest gap surfaces correctly**: a fixture with a
   Critical finding from >30d ago and no retest causes the AR to
   emit `pentest-retest-status: REQUIRES-OPERATOR-INPUT` AND the
   submission bundler (LOOP-A.A4) emits a NOTICE.
6. **REO guardrails clean**: no new lint:no-stubs hits; provenance
   check passes for the new emitter outputs; coverage check does not
   regress.
7. **CHANGELOG updated** for both slices with module names + verification
   counts.
8. **STATUS.md updated** to mark both slices done.

---

## 6. Open questions / caveats

1. **800-53A procedure-object identifier exact format**. NIST CPRT
   JSON uses `<CONTROL>_obj.<n>` (e.g. `AC-2_obj.1`) but some legacy
   3PAO templates use `<CONTROL>.a`, `<CONTROL>.b` (sub-bullet
   identifiers). The extractor SHOULD normalize to `<CONTROL>_obj.<n>`
   AND emit a `legacy_ids[]` field per objective for backward
   compatibility with assessor tooling that ingests the AR.

2. **FedRAMP CSP Penetration Test Guidance Version 4.0 draft (2024)**
   is published for public comment
   (`https://www.fedramp.gov/resources/documents/CSP_Penetration_Test_Guidance_public_comment.pdf`).
   K.K1 schema v1.0.0 implements Version 3 (final, 2022-06-30). When
   Version 4 finalizes, schema v1.1.0 will add any new required fields
   in a backward-compatible way; the ingest module already keys on
   `schema_version` literal.

3. **OSCAL v1.1.2 `target-type: 'statement-id'` semantics**. The
   v1.1.2 metaschema allows the value but is silent on whether
   `target-id` MUST resolve to a control-statement (control body
   prose paragraph) vs an assessment-procedure objective. We adopt the
   FedRAMP-aligned interpretation: `target-id` references the 800-53A
   procedure-object identifier. If a future FedRAMP RFC clarifies
   otherwise, the K.K2 emitter accepts a CLI override
   `--statement-id-convention=fedramp-procedure-object|nist-control-paragraph`
   without schema migration.

4. **Retest evidence chain of custody**. K.K1 captures retest_status
   + retest_date but NOT signed retest attestations. LOOP-F.F1 (3PAO
   sign-off UI) will layer assessor signatures on top of K.K1
   findings. K.K1 leaves the signed_at/signature_blob columns NULL
   pending F.F1.

5. **CVSS v4.0 transition**. Source 1 mandates CVSS v3.1. NIST has
   published CVSS v4.0 (2023-11). K.K1 schema requires v3.1 today;
   when FedRAMP adopts v4.0, schema v1.1.0 will accept either with
   a discriminator.

---

## 7. Status tracking

| Slice ID | Status | Commit hash | Completed date |
|---|---|---|---|
| K.K1 | pending | — | — |
| K.K2 | pending | — | — |

---

## 8. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST:

1. Run all verification commands listed in the slice's "Verification
   commands" block; ensure `npm run typecheck && npm test && npm run check:reo`
   are all green AND the slice-specific smoke command succeeds against a
   fixture.
2. Update the Section 7 status table in this file: set
   `Status = done`, `Commit hash = <git short hash>`, `Completed date = <ISO 8601 date>`.
3. Add an entry to `cloud-evidence/../CHANGELOG.md` "Unreleased" section
   under `### Added` (or `### Changed` for K.K2 since it extends
   existing emitters). The entry MUST name:
   - The slice ID (`LOOP-K.K1` or `LOOP-K.K2`).
   - Every new module path under `cloud-evidence/core/`,
     `cloud-evidence/scripts/`, `cloud-evidence/tests/`,
     `tracker/server/`, `tracker/client/`.
   - Every extended file with a one-line summary of the extension.
   - Verification counts: typecheck status, total tests passing,
     `check:reo` exit code, sha256 of a representative emitted output.
4. Update `cloud-evidence/docs/STATUS.md` to mark the slice done
   (create this file if it does not exist — first writer mirrors the
   Section 7 table from this spec).
5. Commit with message exactly `LOOP-K.<slice-id>: <title>` where
   `<slice-id>` is `K1` or `K2`:
   - `LOOP-K.K1: Penetration Test Report ingest schema + tracker display`
   - `LOOP-K.K2: 3PAO test results matrix to OSCAL AR test-result-objects per 800-53A procedure objects`
6. Push to `origin/main` (no force, no skip-hooks, no amend per
   `cloud-evidence/CLAUDE.md`).
7. Verify the CI workflow goes green for the commit
   (`gh run watch` on the latest run id).

---

## 9. Appendix A — Cross-references to existing code

| Concern | Existing implementation | Why K.K1/K.K2 touches it |
|---|---|---|
| OSCAL AR finding emission | `core/oscal.ts:findingToOscal` | K.K2 extends `target.type` enum + adds statement-id path. |
| OSCAL POA&M emission | `core/oscal-poam.ts:findingProps` | K.K1 adds pentest props under `urn:fedramp:pentest` ns. |
| OSCAL AP activities | `core/oscal-ap.ts` (already emits one activity per KSI) | K.K2 layers procedure-object-granularity activities. |
| Submission bundle catalogue | `core/submission-bundle.ts:WELL_KNOWN` | K.K1 adds 3 entries; K.K2 adds 2. |
| Orchestrator flag wiring | `core/orchestrator.ts` (see `case '--oscal-poam':`) | K.K1 adds `--pentest-report`; K.K2 adds `--test-results-matrix`. |
| OSCAL schema validation | `core/oscal-validate.ts` (ajv) | Both slices reuse the existing ajv instance. |
| Determination → status mapping | `core/oscal.ts` (`passed ? 'satisfied' : 'not-satisfied'`) | K.K2 introduces `'other'` with `reason='not-applicable'`. |
| Deterministic UUIDs | `core/oscal.ts:deterministicUuid` | K.K2 reuses for activity + finding UUIDs. |
| Coverage contract | `core/inventory-coverage.ts` | K.K2 adds a parallel `procedure-object-coverage.json` per-run report (Section 5 acceptance). |
| Tracker auth | `tracker/server/auth` | K.K1/K.K2 routes wired under existing RBAC `assessor` role. |
| Tracker audit log | existing migration ecosystem | Migrations 041 + 042 emit audit entries through existing triggers. |

## 10. Appendix B — REO compliance summary per slice

| REO rule | K.K1 specifics | K.K2 specifics |
|---|---|---|
| No stubs / placeholders | All findings parsed from uploaded JSON; no synthetic findings. | All matrix rows + procedure-object IDs from real sources (uploaded CSV/JSON; NIST CPRT). |
| No hardcoded sample data | Fixtures live under `tests/fixtures/pentest/` (allowed). | Fixtures under `tests/fixtures/test-results/`. |
| No mocked SDKs in prod | N/A — input is operator-supplied JSON, not a cloud SDK. | N/A — input is operator-supplied CSV/JSON. |
| No silent fallbacks | Overdue retest → REQUIRES-OPERATOR-INPUT prop. Missing PDF → bundler gap. | Uncovered controls → REQUIRES-OPERATOR-INPUT diagnostic; unknown control_id → ingest error. |
| Real signatures only | Ed25519 signature flows through existing `core/sign.ts`. | Same; AR-with-matrix embeds are signed as part of AR file. |
| No synthetic emit fields | `pentest_envelope: true` flag is explicit, with `synthesized_fields` recording its presence. | Per-statement findings carry `oscal-target-granularity: procedure-object` prop. |
| No NODE_ENV branches | Tests inject seams via parameters (e.g. `now` for date-math). | Same. |
| Schema not exceeding implementation | Schema v1.0.0 covers every field the emitter emits; no claimed-but-unfilled fields. | Same. |
| No auto-signoffs | Tracker assessor route requires real human sign-in + RBAC role. | Same. |

---

End of LOOP-K specification.
