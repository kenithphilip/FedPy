---
slice_id: K.K2
title: 3PAO test results matrix → OSCAL AR test-result-objects per 800-53A procedure objects
loop: K
status: pending
commit: —
completed_date: —
depends_on: [A.A1, A.A2, A.A3, A.A4, K.K1]
blocks: [F.F1, F.F3, F.F7, E.E3]
estimated_effort: 5–6 days
last_updated: 2026-06-06
---

# K.K2 — 3PAO test results matrix → OSCAL AR test-result-objects per 800-53A procedure objects

## TL;DR
Ingest the 3PAO's per-(control × procedure-object × method) test-results
matrix (CSV or JSON) produced during assessment fieldwork and lift it
into the OSCAL Assessment Results (LOOP-A.A3) as
`finding.target.type='statement-id'` findings + matching
`local-definitions.activities[]` entries that record the assessor's
EXAMINE / INTERVIEW / TEST method. The existing per-rule (objective-id)
findings remain untouched, so downstream OSCAL consumers that key on
`objective-id` keep working; new consumers that understand
`statement-id` see the indivisible 800-53A determination granularity
the 3PAO captured.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
LOOP-A.A3 (`core/oscal.ts:findingToOscal`) currently emits every OSCAL
finding with `target.type = 'objective-id'` and `target.target-id =
<ksi-id>`. That collapses the assessor's per-procedure-object
determination (the indivisible unit of conformance in NIST SP 800-53A
Rev 5) onto a single KSI bucket. Downstream this means:

1. The OSCAL AR cannot show that for a single control, EXAMINE on
   Specifications was Satisfied while TEST on Mechanisms was
   Other-than-Satisfied — both collapse into one "ksi-failed" finding.
2. The OSCAL AR `local-definitions.activities[]` array contains one
   activity per KSI (LOOP-A.A2 default) rather than one activity per
   (control × procedure-object × method), losing the assessor's method
   provenance.
3. A reviewer cannot reproduce the assessor's determination chain end-
   to-end: they see "KSI failed" but not which of the 4–10 procedure
   objectives drove the failure, nor which assessment method
   discovered it.
4. The FedRAMP Rev5 SAP Appendix B (Sampling Methodology) commits the
   3PAO to producing per-control × procedure-object × method
   determinations; without K.K2 this artifact has no machine-readable
   home in the OSCAL chain.

K.K2 closes all four gaps by ingesting the matrix the 3PAO has been
producing all along (currently as an Excel/CSV side-artifact) and
embedding it into the existing AR + AP without breaking
backwards-compatible objective-id consumers. The spec cited is NIST SP
800-53A Rev 5 §2.1–§2.4 (Building an Assessment Procedure), which
defines the procedure-object identifier (`<CONTROL>_obj.<n>`) and the
EXAMINE / INTERVIEW / TEST method enum verbatim.

## Authoritative sources (with verbatim quotes)

- `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53Ar5.pdf`
  — NIST SP 800-53A Rev 5 "Assessing Security and Privacy Controls in
  Information Systems and Organizations" (January 2022), §2.1
  (Assessment Procedures):
  > "Each assessment objective contains a set of determination
  > statements related to the particular security or privacy control
  > under assessment. The determination statements are linked to the
  > content of the security and privacy control to ensure traceability
  > of the assessment results back to the fundamental control
  > requirements."

  §2.1 (Assessment Methods, verbatim):
  > "Assessment methods are characterized by the type of assessor
  > actions and include EXAMINE, INTERVIEW, and TEST."
  > "The EXAMINE method is the process of reviewing, inspecting,
  > observing, studying, or analyzing assessment objects (i.e.,
  > specifications, mechanisms, or activities)."
  > "The INTERVIEW method is the process of holding discussions with
  > individuals or groups of individuals within an organization to once
  > again, facilitate assessor understanding, achieve clarification, or
  > obtain evidence."
  > "The TEST method is the process of exercising one or more
  > assessment objects (i.e., activities or mechanisms) under specified
  > conditions to compare actual with expected behavior."

  §2.1 (Assessment Objects, verbatim):
  > "Assessment objects identify the specific items being assessed and
  > include specifications, mechanisms, activities, and individuals."
  > "Specifications are the document-based artifacts (e.g., policies,
  > procedures, security plans, security requirements, functional
  > specifications, and architectural designs) associated with an
  > information system."
  > "Mechanisms are the specific hardware, software, or firmware
  > safeguards employed within an information system."
  > "Activities are the protection-related actions supporting an
  > information system that involve people (e.g., conducting system
  > backup operations, monitoring network traffic)."
  > "Individuals or groups of individuals are people applying the
  > specifications, mechanisms, or activities described above."

  Identifier convention: each assessment procedure is identified as
  `<CONTROL>` and each determination statement / objective as
  `<CONTROL>_obj.<n>` (e.g. `AC-2_obj.1`, `AC-2_obj.2`). These exact
  tokens appear in the NIST CPRT JSON release of 800-53A Rev 5
  (`SP_800_53_A_5_2_0`, August 2025).

- `https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_A_5_2_0/home`
  — NIST Cybersecurity and Privacy Reference Tool, 800-53A Rev 5
  Release 5.2.0 (August 2025). Machine-readable JSON catalog. The
  procedure-object identifiers + their methods + objects are encoded
  as `elements[].element_identifier` and `elements[].element_type =
  "determination"`. This is the source of truth for the
  `scripts/extract-800-53a-procedure-objects.mjs` extractor.

- `https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/`
  — OSCAL Assessment Results model v1.1.2 JSON reference. The relevant
  structural elements:

  `finding.target.type` allowed values (verbatim from the v1.1.2
  metaschema `target-type` enum):
  > `"objective-id"` — "The findings is about meeting an objective."
  > `"statement-id"` — "The findings is about the implementation of
  > a control statement."

  `local-definitions.activities[]` is the array of activity definitions
  scoped to a single OSCAL document; per the OSCAL metaschema, an
  `activity` has `uuid`, `title`, `description`, `props[]`, `links[]`,
  optional `steps[]` (each step in turn carries `reviewed-controls`
  and `responsible-roles[]`), `related-controls` (reviewed-controls
  structure), and `remarks`. Assessment-method semantics are carried
  via `prop[@name='method']` whose value is in
  `{EXAMINE, INTERVIEW, TEST, UNKNOWN}` (per the
  `assessment-common:method` constraint in the metaschema).

  `observation.methods[]` (verbatim allowed values): `"EXAMINE"`,
  `"INTERVIEW"`, `"TEST"`, `"UNKNOWN"`. K.K2 uses the first three only
  (matrix rows that cannot specify a method fail validation; UNKNOWN
  is reserved for cases where the assessor explicitly couldn't
  classify, which contradicts the 3PAO matrix workflow).

  `observation.types[]` (verbatim allowed values per the v1.1.2
  outline): `"ssp-statement-issue"`, `"control-objective"`,
  `"mitigation"`, `"finding"`, `"historic"`. K.K2 uses
  `"control-objective"` (matches the 800-53A determination-statement
  granularity).

- `https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/`
  — FedRAMP Rev5 Playbook, "Submitting an Authorization Package — SAP"
  page. Appendix B (Sampling Methodology) commits the 3PAO to
  producing a per-control × procedure-object × method determination
  matrix during the assessment. From the SAP guidance (verbatim):
  > "The 3PAO must select samples sufficient to evaluate every
  > assessment objective for every applicable control in the
  > baseline."

  LOOP-F.F3 (separate slice) auto-derives the sampling plan; K.K2
  ingests the per-control results the 3PAO produces from running it.

- `https://datatracker.ietf.org/doc/html/rfc4180`
  — RFC 4180 "Common Format and MIME Type for Comma-Separated Values
  (CSV) Files" (October 2005), §2 (Definition of the CSV Format):
  > "Each record is located on a separate line, delimited by a line
  > break (CRLF)."
  > "Fields containing line breaks (CRLF), double quotes, and commas
  > should be enclosed in double-quotes."
  > "If double-quotes are used to enclose fields, then a double-quote
  > appearing inside a field must be escaped by preceding it with
  > another double quote."

  The matrix CSV parser implements RFC 4180 verbatim (quoted fields
  with embedded commas, escaped double-quotes via `""`, CRLF line
  termination accepted).

- `https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-plan/`
  — OSCAL Assessment Plan model v1.1.2 JSON reference. The AP's
  `local-definitions.activities[]` mirrors the AR's. When
  `--test-results-matrix` is supplied, K.K2 augments the AP's
  activities so the AP↔AR `activity-uuid` references resolve. This
  preserves the LOOP-A.A3 "chain validation" guarantee
  (`oscal-validate.ts` already cross-checks AP↔AR activity references
  when `--strict-chain` is set).

## Files to create (exact paths)

- `cloud-evidence/core/test-results-matrix.ts` — pure ingest + builder
  module. Parses matrix CSV/JSON, validates against schema + baseline,
  builds `OscalActivity[]`, `OscalObservation[]`, `OscalFinding[]` for
  the new statement-id granularity. ~700 lines.
- `cloud-evidence/core/test-results-schema.ts` — TypeScript interfaces
  (`TestResultsMatrix`, `TestResultsRow`, `DeterminationValue`,
  `AssessmentMethod`, `AssessmentObjectType`) + the JSON Schema literal.
  Exports `MATRIX_SCHEMA_VERSION = "1.0.0"`. ~200 lines.
- `cloud-evidence/docs/oscal/test-results-matrix.schema.v1.0.0.json` —
  the committed JSON Schema (draft-07) for external validators.
- `cloud-evidence/core/procedure-objects.ts` — loader for the 800-53A
  Rev 5 procedure-object catalog; exports `ProcedureObjectCatalog`,
  `loadProcedureObjects()`, `assertAllBaselineControlsHaveObjects()`,
  `resolveProcedureObject(controlId, objId)`. ~200 lines.
- `cloud-evidence/scripts/extract-800-53a-procedure-objects.mjs` —
  one-shot extractor (allowed by REO Rule 1 since it transforms an
  external catalog). Reads the NIST CPRT JSON for
  `SP_800_53_A_5_2_0`, deduplicates procedure-object identifiers per
  control, normalizes methods + objects, writes a deterministic JSON
  artifact. Wired into `npm run extract:catalogs`.
- `cloud-evidence/docs/800-53a-procedure-objects.generated.json` —
  generated artifact. Structure:
  ```json
  {
    "source": {
      "name": "NIST SP 800-53A Rev 5",
      "release": "5.2.0",
      "release_date": "2025-08",
      "cprt_url": "https://csrc.nist.gov/.../SP_800_53_A_5_2_0",
      "extracted_at": "2026-...",
      "extractor_sha256": "..."
    },
    "controls": {
      "AC-2": {
        "objectives": [
          {
            "id": "AC-2_obj.1",
            "text": "<verbatim determination statement>",
            "methods": ["EXAMINE","INTERVIEW"],
            "objects": ["Specifications","Mechanisms","Activities"],
            "legacy_ids": ["AC-2.a"]
          }
        ]
      }
    }
  }
  ```
- `cloud-evidence/tests/core/test-results-matrix.test.ts` — ingest +
  AR-fragment emission tests (15 cases listed below).
- `cloud-evidence/tests/core/test-results-schema.test.ts` — schema
  conformance tests (4 cases).
- `cloud-evidence/tests/core/procedure-objects.test.ts` — loader +
  invariant tests (6 cases).
- `cloud-evidence/tests/fixtures/test-results/sample-matrix.csv` —
  representative matrix: 12 rows across 4 controls × 3
  procedure-objects each, mix of EXAMINE / INTERVIEW / TEST, mix of
  satisfied / other-than-satisfied / not-applicable determinations.
- `cloud-evidence/tests/fixtures/test-results/sample-matrix.json` —
  same data as CSV in JSON shape (used to verify both parsers produce
  identical `TestResultsMatrix` values).
- `cloud-evidence/tests/fixtures/test-results/sample-matrix-with-na.csv`
  — fixture exercising the `not-applicable` determination path.
- `cloud-evidence/tests/fixtures/test-results/malformed-row.csv` —
  fixture missing the required `rationale` field; verifies schema
  rejection.
- `cloud-evidence/tests/fixtures/test-results/unknown-control.csv` —
  fixture with `control_id = "AC-99"` (not in baseline); verifies
  validator surfaces `unknown_controls[]`.
- `tracker/server/db/migrations/042_test_results_matrix.sql` — DB
  schema for `test_results_matrices`, `test_results_rows`,
  `test_results_row_evidence`. Verbatim SQL in LOOP-K-SPEC.md §4 K.K2
  step 13.
- `tracker/server/routes/test-results-matrix.ts` — Express handlers:
  POST upload, GET list, GET detail, PATCH row update, POST evidence
  attachment, POST commit-to-AR.
- `tracker/server/services/test-results-matrix-service.ts` — business
  logic separated from HTTP layer.
- `tracker/server/__tests__/test-results-matrix.test.ts` — ~14 route
  tests using supertest + in-memory SQLite.
- `tracker/client/src/pages/TestResultsMatrix.tsx` — React page: matrix
  grid editor, method-filter chips, coverage-gap banner, bulk CSV
  upload, per-row evidence attachments.
- `tracker/client/src/api/test-results.ts` — typed API client.
- `tracker/client/src/pages/__tests__/TestResultsMatrix.test.tsx` —
  RTL component tests (5 cases listed below).

## Files to extend

- `cloud-evidence/core/oscal.ts`:
  - Extend `OscalFinding.target.type` union to include `'statement-id'`
    (currently only `'objective-id'`). Type-only change; emitter
    branches on the new value.
  - Add `OscalActivity` interface mirroring the OSCAL v1.1.2 metaschema:
    ```ts
    export interface OscalActivity {
      uuid: string;
      title: string;
      description?: string;
      props?: OscalProperty[];
      links?: OscalLink[];
      steps?: OscalActivityStep[];
      'related-controls'?: OscalReviewedControls;
      remarks?: string;
    }
    ```
  - Extend `OscalAssessmentResults.results[].local-definitions` to
    optionally carry `activities: OscalActivity[]` (currently only
    has `remarks`).
  - Add pure function
    `embedTestResultsMatrix(ar: OscalAssessmentResults, matrix: TestResultsMatrix, catalog: ProcedureObjectCatalog): OscalAssessmentResults`
    that returns a new AR with activities + observations + findings
    appended.
  - The existing per-rule objective-id findings remain (so legacy
    consumers keep working); the per-statement-id findings carry a
    new prop `oscal-target-granularity: procedure-object` so a 3PAO
    tool can filter on it.
- `cloud-evidence/core/oscal-ap.ts`:
  - When `--test-results-matrix` is supplied, augment AP
    `local-definitions.activities[]` with one activity per
    (control × procedure-object × method) using the same UUIDs as the
    AR's K.K2 activities (so the AP↔AR `activity-uuid` reference chain
    is sound).
  - The activity is added only when the matrix is supplied (otherwise
    the AP keeps the LOOP-A.A2 per-KSI activities). The behaviour is
    feature-flagged by the presence of `opts.testResultsMatrixPath`.
- `cloud-evidence/core/oscal-validate.ts` — extend the chain-validation
  rules so that when the AR carries statement-id findings,
  `--strict-chain` mode verifies each `target-id` resolves against the
  loaded procedure-object catalog (unknown IDs surface as chain
  errors, not silent passes).
- `cloud-evidence/core/orchestrator.ts` — add `--test-results-matrix <path>`
  flag and `CLOUD_EVIDENCE_TEST_RESULTS_MATRIX` env equivalent. The
  handler runs AFTER `--oscal-ar` (so the AR exists to extend) and
  AFTER `--oscal-ap` (so the AP exists to augment with mirror
  activities). Console line:
  `[matrix] N rows across M controls / K procedure-objects (S satisfied, O other-than-satisfied, N na)`.
  When run BEFORE `--oscal-ar`, the handler emits a NOTICE explaining
  the ordering requirement instead of failing.
- `cloud-evidence/core/submission-bundle.ts` — append to `WELL_KNOWN`:
  1. `{ role: 'test-results-matrix-csv', filename: 'test-results-matrix.csv', required: false, description: 'Per-control × procedure-object × method assessor determinations (LOOP-K.K2 source)' }`
  2. `{ role: 'test-results-matrix-json', filename: 'test-results-matrix.json', required: false, description: 'Test results matrix — JSON projection of the CSV' }`
  3. The existing OSCAL AR JSON role is re-used for the matrix-embedded
     AR; the bundler annotates whether the AR contains statement-id
     findings (via INDEX.json metadata).
- `cloud-evidence/CHANGELOG.md` — `Unreleased > Changed` entry naming
  the new flag, new module paths, verification counts.
- `cloud-evidence/package.json` — add `"extract:catalogs": "node scripts/extract-800-53a-procedure-objects.mjs ..."` so the
  generated JSON is reproducibly regenerated.

## Schemas / standards

### Matrix JSON Schema (`docs/oscal/test-results-matrix.schema.v1.0.0.json`, draft-07)

Required top-level fields:
- `$schema: "http://json-schema.org/draft-07/schema#"`
- `$id: "https://fedramp.kp.local/schemas/test-results-matrix/1.0.0"`
- `schema_version: { type: string, const: "1.0.0" }`
- `engagement_id: { type: string, minLength: 1 }`
- `assessor_name: { type: string, minLength: 1 }`
- `assessor_uuid: { type: string, format: uuid }` (optional but recommended)
- `engagement_window: { type: object, required: [start, end], properties: { start: { format: date }, end: { format: date } } }`
- `rows: { type: array, minItems: 1, items: <RowSchema> }`
- `additionalProperties: false`

Row schema (`RowSchema`):
- `control_id: { type: string, pattern: "^[A-Z]{2,3}-[0-9]{1,2}(\\([0-9]+\\))?$" }`
  matches NIST 800-53 Rev 5 control ID format (e.g. `AC-2`, `AC-2(3)`).
- `procedure_object_id: { type: string, pattern: "^[A-Z]{2,3}-[0-9]{1,2}(\\([0-9]+\\))?_obj\\.[0-9]+$" }`
  matches NIST 800-53A Rev 5 identifier format (e.g. `AC-2_obj.1`).
- `method: { type: string, enum: ["EXAMINE","INTERVIEW","TEST"] }` —
  verbatim from 800-53A §2.1.
- `objects_examined: { type: array, minItems: 1, items: { enum: ["Specifications","Mechanisms","Activities","Individuals"] } }`
  — verbatim from 800-53A §2.1.
- `determination: { type: string, enum: ["satisfied","other-than-satisfied","not-applicable"] }`
  — verbatim 800-53A terms (REO Rule 3 allows these as
  published-standard constants).
- `rationale: { type: string, minLength: 1 }` — operator-supplied
  prose; empty string rejected.
- `evidence_uuids: { type: array, items: { type: string, format: uuid } }`
  — optional cross-references to other OSCAL `observation` UUIDs or
  evidence-attachment UUIDs.
- `observed_at: { type: string, format: date-time }` — ISO 8601
  timestamp of the assessment activity.
- `assessor_uuid: { type: string, format: uuid }` — optional override
  if a sub-assessor on the team observed this row.

### Determination → OSCAL status mapping (verbatim)

| Matrix `determination` | OSCAL `status.state` | OSCAL `status.reason` |
|---|---|---|
| `satisfied` | `satisfied` | — |
| `other-than-satisfied` | `not-satisfied` | (carried via `remarks`) |
| `not-applicable` | `other` | `not-applicable` |

(`other` with `reason: 'not-applicable'` is the verbatim OSCAL v1.1.2
pattern for a non-applicable determination — the metaschema does not
provide a first-class `not-applicable` state.)

### OSCAL output shape

For each matrix row, the embedded AR adds:

1. One `local-definitions.activities[]` entry:
   ```json
   {
     "uuid": "<deterministic UUID derived from control+obj+method>",
     "title": "<control_id> <procedure_object_id> via <method>",
     "description": "<rationale>",
     "props": [
       { "name": "method", "ns": "http://csrc.nist.gov/ns/oscal", "value": "<EXAMINE|INTERVIEW|TEST>" },
       { "name": "assessment-object-type", "ns": "http://csrc.nist.gov/ns/oscal", "value": "<Specifications|Mechanisms|Activities|Individuals>" }
     ],
     "related-controls": {
       "include-controls": [ { "control-id": "<control_id>" } ]
     }
   }
   ```

2. One `results[0].observations[]` entry, type `control-objective`:
   ```json
   {
     "uuid": "<deterministic>",
     "title": "<control_id> <procedure_object_id>",
     "description": "<rationale>",
     "methods": ["<EXAMINE|INTERVIEW|TEST>"],
     "types": ["control-objective"],
     "collected": "<observed_at>",
     "props": [{ "name": "assessor", "value": "<assessor_name>" }]
   }
   ```

3. One `results[0].findings[]` entry:
   ```json
   {
     "uuid": "<deterministic>",
     "title": "<control_id> <procedure_object_id> determination",
     "target": {
       "type": "statement-id",
       "target-id": "<procedure_object_id>",
       "status": { "state": "<mapped>", "reason": "<mapped>" }
     },
     "props": [
       { "name": "oscal-target-granularity", "value": "procedure-object" },
       { "name": "assessor", "value": "<assessor_name>" }
     ],
     "related-observations": [{ "observation-uuid": "<from step 2>" }]
   }
   ```

## Build steps (concrete, numbered)

1. **Catalog extractor** (`scripts/extract-800-53a-procedure-objects.mjs`):
   - Fetch the NIST CPRT JSON for `SP_800_53_A_5_2_0` from the URL
     pinned in the script header.
   - Walk the catalog: each control has `elements[]` of type
     `determination`; their identifiers form the procedure-object set.
   - Normalize identifiers to `<CONTROL>_obj.<n>`; preserve legacy
     identifiers in `legacy_ids[]`.
   - Determine `methods[]` + `objects[]` per objective from the
     determination prose (the CPRT JSON carries these as element
     properties).
   - Emit `docs/800-53a-procedure-objects.generated.json` with
     deterministic key ordering (JSON.stringify with sorted keys) so
     re-runs are byte-stable.
   - Print the SHA-256 of the emitted file for inclusion in the
     extractor's own provenance block.

2. **Loader** (`core/procedure-objects.ts`):
   - `loadProcedureObjects(): ProcedureObjectCatalog` reads the
     generated JSON synchronously (small file, ~150KB).
   - `assertAllBaselineControlsHaveObjects(baseline: ControlBenchmark): void`
     throws when any Moderate-baseline control has no procedure
     objects. Build-time gate via a test.
   - `resolveProcedureObject(controlId, objId): ProcedureObjectiveDef | undefined`.

3. **Matrix schema** (`core/test-results-schema.ts`):
   - Exports the TypeScript interfaces named above.
   - Exports `MATRIX_INGEST_SCHEMA: object` — the literal JSON Schema.
   - Writes the same schema verbatim to
     `docs/oscal/test-results-matrix.schema.v1.0.0.json` (or vice
     versa — single source of truth via a `scripts/sync-schemas.mjs`
     check).

4. **Pure parser** (`core/test-results-matrix.ts`):
   - `parseTestResultsMatrix(raw: string | object): TestResultsMatrix`.
   - For CSV input: implements RFC 4180 verbatim (quoted fields with
     embedded commas, escaped double-quotes via `""`, CRLF/LF
     accepted). Column order:
     `control_id, procedure_object_id, method, objects_examined, determination, rationale, observed_at, evidence_uuids`.
     `objects_examined` is `|`-separated within the column;
     `evidence_uuids` likewise.
   - For JSON input: passes through ajv against the matrix schema.
   - Throws `TestResultsIngestError` carrying `{ row, field, message, ajvErrors }`.

5. **Pure validator** (`core/test-results-matrix.ts`):
   ```ts
   validateMatrixAgainstBaseline(
     matrix: TestResultsMatrix,
     baseline: ControlBenchmark,
     catalog: ProcedureObjectCatalog
   ): ValidationReport
   ```
   Returns:
   ```ts
   {
     unknown_controls: string[];
     unknown_procedure_objects: { control: string; obj: string }[];
     controls_missing_coverage: string[];
     objects_missing_coverage: { control: string; obj: string }[];
     suspect_rows: { rowIndex: number; reason: string }[];
   }
   ```
   `suspect_rows` flags methodological warnings (e.g. `method=TEST`
   with `objects_examined = ['Individuals']` only — TEST against
   humans is methodologically suspect; operator must justify).

6. **Pure builder**: `buildOscalActivities(matrix: TestResultsMatrix, catalog: ProcedureObjectCatalog): OscalActivity[]`
   — one activity per (control × procedure-object × method).
   Deterministic UUIDs via existing `deterministicUuid()` in
   `core/oscal.ts`, seeded with
   `'activity:' + control + ':' + obj + ':' + method`.

7. **Pure builder**: `buildObservationsFromMatrix(matrix: TestResultsMatrix): OscalObservation[]`
   — one observation per matrix row. `methods: [row.method]`,
   `types: ['control-objective']`, `description = row.rationale`,
   `collected = row.observed_at`. Deterministic UUIDs.

8. **Pure builder**: `buildOscalFindingsFromMatrix(matrix: TestResultsMatrix, observationUuidByRow: Map<number,string>): OscalFinding[]`
   — one finding per matrix row, with `target.type = 'statement-id'`.
   Status mapping per the table above. `related-observations[]`
   cross-references the observation built in step 7. Carries
   `oscal-target-granularity: procedure-object` prop.

9. **Composer**: `embedTestResultsMatrix(ar: OscalAssessmentResults, matrix: TestResultsMatrix, catalog: ProcedureObjectCatalog): OscalAssessmentResults`
   — returns a NEW AR (functional, no mutation) with activities
   appended to `results[0].local-definitions.activities[]`,
   observations appended to `results[0].observations[]`, findings
   appended to `results[0].findings[]`. Existing per-rule
   objective-id findings are preserved verbatim.

10. **Disk emitter**: `emitTestResultsMatrixOscal(matrixPath: string, opts: { outDir: string; arPath?: string }): EmitResult`.
    - If `arPath` is supplied (typical: the LOOP-A.A3 AR just
      emitted), reads it, validates, applies
      `embedTestResultsMatrix`, writes back atomically (write to
      temp + rename).
    - Else emits a standalone `test-results-fragment.json` intended
      to be merged later.
    - Always writes `test-results-matrix.csv` + `.json` projections
      to `outDir/` so the submission bundler picks them up.
    - Provenance block names `core/test-results-matrix.ts`, matrix
      file path + sha256, catalog source + sha256, `formula_version:
      'matrix-embed.v1'`.

11. **AP augmentation** (`core/oscal-ap.ts`):
    - When `opts.testResultsMatrixPath` is set, the AP emitter calls
      `buildOscalActivities(matrix, catalog)` and appends them to its
      own `local-definitions.activities[]`.
    - The UUIDs are the same as the AR's K.K2 activities (both call
      the same deterministic UUID factory), so the AP↔AR reference
      chain is sound.

12. **Orchestrator wiring** (`core/orchestrator.ts`):
    - New flag `--test-results-matrix <path>` + env
      `CLOUD_EVIDENCE_TEST_RESULTS_MATRIX`.
    - Runs AFTER `--oscal-ap` and AFTER `--oscal-ar`.
    - Emits the matrix-embedded AR to replace the original AR file.
    - Console line: `[matrix] N rows across M controls / K procedure-objects (S satisfied, O other-than-satisfied, N na)`.

13. **Chain validation extension** (`core/oscal-validate.ts`):
    - When the AR contains statement-id findings AND `--strict-chain`
      is set, verify each `target-id` resolves against the loaded
      procedure-object catalog. Unknown IDs are chain errors.

14. **Tracker DB migration `042_test_results_matrix.sql`** — verbatim
    SQL from LOOP-K-SPEC.md §4 K.K2 step 13. Three tables with foreign
    keys + audit-log triggers consistent with existing tracker
    migration patterns.

15. **Tracker server routes** (`tracker/server/routes/test-results-matrix.ts`):
    - `POST /api/test-results-matrices` — accepts CSV or JSON
      multipart. Validates via the ajv instance. Inserts into the
      three tables.
    - `GET /api/test-results-matrices` — list, RBAC-scoped.
    - `GET /api/test-results-matrices/:id` — detail + rows + coverage
      summary.
    - `PATCH /api/test-results-matrices/:id/rows/:rid` — update
      determination + rationale + evidence_uuids. Requires `assessor`
      role.
    - `POST /api/test-results-matrices/:id/rows/:rid/evidence` —
      evidence attachment upload (MIME allow-list).
    - `POST /api/test-results-matrices/:id/commit` — mark matrix
      committed and call `emitTestResultsMatrixOscal()` to embed into
      the AR at the configured outDir. Refuses unless coverage gaps
      are absent (override with `?force=true`).
    - All endpoints emit audit-log entries via the existing trigger
      pattern.

16. **Tracker server service** (`tracker/server/services/test-results-matrix-service.ts`):
    business logic separated from HTTP; unit-tested without supertest.

17. **Tracker client page** (`tracker/client/src/pages/TestResultsMatrix.tsx`):
    - Matrix grid editor: rows are controls × procedure-objects;
      cells are methods + determinations.
    - Method-filter chips (EXAMINE / INTERVIEW / TEST).
    - Coverage-gap banner: "X controls have no rows; Y procedure
      objects uncovered" with click-through to baseline.
    - Bulk upload via file picker (CSV or JSON).
    - Per-row evidence attachments.
    - RBAC-aware (assessor sees determination edits; reader does not).

18. **Tracker client API** (`tracker/client/src/api/test-results.ts`):
    typed client mirroring server routes; uses existing fetch wrapper
    with CSRF token handling.

19. **Add to `submission-bundle.ts` WELL_KNOWN catalogue**: 2 entries
    above.

20. **CHANGELOG entry** in `cloud-evidence/CHANGELOG.md` under
    `Unreleased > Changed` (since K.K2 EXTENDS existing emitters
    rather than adding wholly new artifact roles). Names every new
    file + verification counts + sha256 of
    `docs/800-53a-procedure-objects.generated.json` and the embedded
    AR for `tests/fixtures/test-results/sample-matrix.csv`.

## REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4 (`cloud-evidence/CLAUDE.md` §): every field below is
operator-supplied. When missing, the system emits a
`REQUIRES-OPERATOR-INPUT` marker naming the field + the consumer
artifact, never a silent default.

| Field | Source | Behavior when missing |
|---|---|---|
| `matrix.engagement_id` | Upload metadata or CLI flag | Schema error citing the field; ingest aborts. |
| `matrix.assessor_name` | Upload metadata | Schema error. |
| `matrix.engagement_window.start/end` | Upload metadata | Schema error. |
| `row.control_id` | Matrix row | Schema regex error. |
| `row.procedure_object_id` | Matrix row | Schema regex error. |
| `row.method` | Matrix row | Schema enum error. |
| `row.objects_examined[]` | Matrix row | Empty array → schema error. |
| `row.determination` | Matrix row | Schema enum error. |
| `row.rationale` | Matrix row | Empty string → schema error. NEVER auto-filled. |
| `row.observed_at` | Matrix row | Schema format-error. |
| Baseline controls without ≥1 matrix row | Validator output | Orchestrator emits one `REQUIRES-OPERATOR-INPUT` line per uncovered control: `REQUIRES-OPERATOR-INPUT: matrix-coverage AC-2 obj.1..N`. Commit-to-AR refuses by default. |
| Procedure-objects without matrix coverage | Validator output | Same pattern, per (control, obj) pair. |
| `--statement-id-convention` (FedRAMP vs NIST flavour) | CLI flag | Default `fedramp-procedure-object`; documented. |
| `--catalog-path` (override generated JSON) | CLI flag | Default to the committed `docs/800-53a-procedure-objects.generated.json`; an out-of-date catalog vs the rest of the repo is REO-flagged. |

## Test specifications (≥12 tests)

### `tests/core/test-results-matrix.test.ts` (15 cases)

1. `it('parses a 3-row CSV matrix')` — uses `sample-matrix.csv`
   subset; asserts 3 `TestResultsRow` values with verbatim methods +
   determinations.
2. `it('parses a 3-row JSON matrix matching the CSV verbatim')` —
   round-trips JSON ↔ CSV; both parsers produce identical
   `TestResultsMatrix`.
3. `it('rejects a row with unknown method')` — fixture with
   `method = "REVIEW"`; asserts `TestResultsIngestError` with
   `field === 'method'`.
4. `it('rejects a row with unknown determination value')` — fixture
   with `determination = "TBD"`; asserts schema enum error.
5. `it('rejects empty rationale')` — fixture with
   `rationale = ""`; asserts `minLength` violation.
6. `it('detects unknown control_id against baseline')` — uses
   `unknown-control.csv` (AC-99); validator returns
   `unknown_controls: ['AC-99']`.
7. `it('detects unknown procedure_object_id against catalog')` —
   row with `AC-2_obj.99`; validator returns
   `unknown_procedure_objects: [{ control: 'AC-2', obj: 'AC-2_obj.99' }]`.
8. `it('reports baseline controls without coverage')` — partial
   matrix covers only 1 of N baseline controls; validator returns
   `controls_missing_coverage` listing the other N-1.
9. `it('builds one OscalActivity per (control × procedure-object × method)')`
   — count assertion: 3 controls × 2 procedure-objects each × 2
   methods sampled = 12 activities.
10. `it('emits activity prop method=EXAMINE/INTERVIEW/TEST verbatim')`
    — asserts the OSCAL `prop[@name='method']` value is the verbatim
    800-53A enum (not a code abbreviation).
11. `it('builds findings with target.type=statement-id')` — asserts
    target.type literal === `'statement-id'`.
12. `it('maps determination satisfied → status.state=satisfied')` —
    direct assertion.
13. `it('maps other-than-satisfied → status.state=not-satisfied')` —
    direct assertion.
14. `it('maps not-applicable → status.state=other with reason=not-applicable')`
    — direct assertion.
15. `it('embeds activities + findings into an existing OSCAL AR without losing prior findings')`
    — composition correctness: prior per-rule objective-id findings
    are preserved; new statement-id findings are appended.

### `tests/core/procedure-objects.test.ts` (6 cases)

16. `it('loads procedure-object catalog from generated JSON')` —
    asserts the file is parseable + structurally valid.
17. `it('assertAllBaselineControlsHaveObjects throws on missing control')`
    — synthetic catalog missing AC-1; assertion fires.
18. `it('every Moderate-baseline control has ≥1 procedure object')` —
    invariant against the committed catalog (build-time gate).
19. `it('procedure-object identifiers match <CONTROL>_obj.<n> pattern')`
    — regex check on every identifier in the catalog.
20. `it('extractor script output is byte-stable across reruns')` —
    spawn the extractor twice in a temp dir; assert sha256 matches.
21. `it('catalog contains methods + objects arrays per objective')` —
    every objective has non-empty `methods[]` + `objects[]`.

### `tests/core/test-results-schema.test.ts` (4 cases)

22. `it('schema version literal pinned to 1.0.0')`.
23. `it('CSV parser handles RFC 4180 quoted fields with commas')` —
    `"AC-2","AC-2_obj.1","EXAMINE","Specifications|Mechanisms","satisfied","The policy, procedure, and plan exist","2026-06-01T10:00:00Z"`.
24. `it('CSV parser rejects malformed rows')` — uses
    `malformed-row.csv`.
25. `it('JSON schema rejects extra top-level fields')` — additional
    `foo: bar` triggers `additionalProperties: false`.

### Tracker server tests (`tracker/server/__tests__/test-results-matrix.test.ts`, 14 cases)

1. POST upload accepts a valid CSV.
2. POST upload accepts a valid JSON.
3. POST returns 400 with `unknown_controls[]` when row references
   an out-of-baseline control.
4. PATCH refuses when caller lacks `assessor` role (403).
5. PATCH updates determination + writes audit log.
6. POST commit embeds matrix into AR at configured outDir; reads back
   AR and asserts statement-id findings present.
7. POST commit refuses when uncovered controls exist (returns 409
   listing gaps); succeeds with `?force=true`.
8. Bulk row evidence upload enforces MIME allow-list (image/jpeg,
   image/png, application/pdf, text/plain).
9. GET list scopes by engagement.
10. Duplicate matrix per engagement returns 409.
11. Foreign-key cascade deletes rows + evidence on matrix deletion.
12. Audit log captures the commit event with before/after AR sha256.
13. Coverage gap surfaces in the GET detail response (count of
    `controls_missing_coverage[]`).
14. Method TEST + objects=Individuals only emits a server warning in
    the response body (HTTP 200 but `warnings[]` populated).

### Tracker client tests (`tracker/client/src/pages/__tests__/TestResultsMatrix.test.tsx`, 5 cases)

1. Matrix grid renders rows grouped by control.
2. Coverage-gap banner shows uncovered controls (mock API response).
3. Bulk upload CSV via file picker calls POST.
4. Row determination update calls PATCH with correct payload.
5. Evidence attachment upload shows new row + thumbnail (or filename
   for non-image MIME).

## REO compliance specific to this slice

- **Every emitted OSCAL activity + finding traces to a real matrix
  row.** No synthetic activities; no fabricated rationale.
- **Procedure-object identifiers** are sourced ONLY from the
  generated catalog (which is sourced from NIST CPRT 800-53A Rev 5
  Release 5.2.0). No invented IDs.
- **Catalog generation script is committed + reproducible.**
  `npm run check:reo` includes a check that the committed JSON's
  sha256 matches what re-extracting would produce (or warns on drift
  with explicit operator action required).
- **Determination mappings** (satisfied / other-than-satisfied /
  not-applicable) are the verbatim 800-53A terms — REO Rule 3 permits
  these as published-standard constants.
- **Coverage gaps surface as `REQUIRES-OPERATOR-INPUT` diagnostics**
  naming each uncovered control + procedure-object — never a silent
  omission.
- **Embedded AR preserves all prior findings.** The existing per-KSI
  per-rule objective-id findings remain; we ADD per-statement
  findings. A test asserts both granularities coexist.
- **Provenance fields populated**:
  `result.provenance.module = 'core/test-results-matrix.ts'`,
  `provenance.matrix_sha256`, `provenance.catalog_sha256`,
  `provenance.formula_version = 'matrix-embed.v1'`,
  `provenance.committed_by_user_id` (when via tracker).
- **No silent fallbacks**: unknown control_id → ingest error;
  empty rationale → schema error; uncovered control → commit refused
  (unless `?force=true` operator override).
- **No mocked SDKs in production paths**: K.K2 input is
  operator-supplied CSV/JSON, not a cloud SDK (Rule 4: operator-
  supplied data IS real data).
- **No NODE_ENV branches**: tests inject seams via parameters.
- **Schema does not exceed implementation**: every field in
  `MATRIX_INGEST_SCHEMA` is populated by `parseTestResultsMatrix`
  + emitted in the OSCAL output; tests verify each.
- **Signed by**: existing `core/sign.ts` pipeline (Ed25519 + RFC 3161)
  applies to the embedded AR exactly as for any other emitted file.
  The matrix-CSV + matrix-JSON projections under outDir are also
  signed as part of the run manifest.

## Verification commands

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
# findings (oscal-target-granularity=procedure-object prop);
# ap.json local-definitions.activities[] mirror the matrix;
# orchestrator log shows coverage banner.
```

## Known risks / issues

- **Risk 1 — Procedure-object identifier format drift.** NIST CPRT
  JSON uses `<CONTROL>_obj.<n>` for 800-53A Rev 5 Release 5.2.0, but
  some legacy 3PAO templates use `<CONTROL>.a`, `<CONTROL>.b` (sub-
  bullet identifiers carried over from 800-53A Rev 4 conventions).
  Mitigation: the extractor SHOULD normalize to `<CONTROL>_obj.<n>`
  AND emit a `legacy_ids[]` field per objective for backward
  compatibility with assessor tooling that still produces the legacy
  form. The matrix parser accepts either form on input + normalizes
  before validation.

- **Risk 2 — NIST CPRT catalog version drift.** Release 5.2.0 is the
  current (August 2025) baseline. A future release (5.3.0+) may add
  new procedure objects to existing controls; existing matrices
  remain valid but a coverage gap surfaces for the new objectives.
  Mitigation: extractor records the release version + extraction
  date; loader warns if the catalog is >12 months old; an annual
  refresh is captured as a recurring task.

- **Risk 3 — OSCAL v1.1.2 `target-type: 'statement-id'` semantics
  ambiguity.** The v1.1.2 metaschema allows the value but is silent
  on whether `target-id` MUST resolve to a control-statement (control
  body prose paragraph) vs an assessment-procedure objective. We
  adopt the FedRAMP-aligned interpretation: `target-id` references
  the 800-53A procedure-object identifier. Mitigation: the K.K2
  emitter accepts a CLI override
  `--statement-id-convention=fedramp-procedure-object|nist-control-paragraph`
  without schema migration. Default is `fedramp-procedure-object`.

- **Risk 4 — Large matrices and AR file size.** A full Moderate
  assessment can produce ~10,000+ matrix rows (149 baseline controls
  × ~4 procedure objects × ~2 methods sampled). Embedding all of
  them into one AR JSON balloons the file to ~50MB+. Mitigation:
  K.K2 supports the OSCAL `back-matter.resources[]` pattern for
  large activity sets in a follow-up (K.K2.1) if file size becomes a
  problem; for v1.0.0 we accept the larger AR and document the size
  budget.

- **Risk 5 — Deterministic UUID collisions across slices.** K.K2
  uses `deterministicUuid('activity:' + control + ':' + obj + ':' +
  method)`. LOOP-A.A2 uses `deterministicUuid('activity:' + ksi)`.
  Collisions are vanishingly unlikely (different input strings → SHA
  family) but a test asserts no collision in the sample matrix.

- **Risk 6 — CSV parser edge cases.** RFC 4180 allows multi-line
  fields with embedded CRLF inside quotes; this is a corner case the
  parser must handle. Mitigation: parser uses a state-machine
  implementation (not regex), with tests for embedded CRLF, embedded
  comma, embedded double-quote, BOM-prefixed files.

- **Risk 7 — Chain validation strictness conflicts.** When
  `--strict-chain` is set AND the AR has statement-id findings,
  current `oscal-validate.ts` may flag the unfamiliar
  `target.type='statement-id'` if the validator hasn't been updated.
  Mitigation: extend the validator (build step 13) BEFORE wiring the
  orchestrator handler so the validation order is correct.

- **Risk 8 — AP ↔ AR UUID drift.** If the AP emitter (LOOP-A.A2)
  ships before the K.K2 matrix is supplied, AP activities lack the
  matrix-derived UUIDs. The orchestrator must re-emit the AP when
  `--test-results-matrix` is supplied. Mitigation: the orchestrator
  handler for `--test-results-matrix` triggers a re-emit of the AP
  if one already exists in `outDir/`.

- **Risk 9 — Matrix commit refusal blocking workflow.** Operators
  may want to commit a partial matrix during long assessments.
  Mitigation: the `POST /commit?force=true` override is documented
  + the audit log captures the forced commit + the embedded AR's
  metadata records `coverage_gaps_force_committed: true`.

## Open questions (for implementation session to resolve)

- **Q1**: Should the extractor pull all 800-53A controls (Low + Mod
  + High baselines) or only Moderate? Recommendation: pull all
  controls in the catalog (the JSON is small enough) and let the
  validator filter against the Moderate baseline. This future-proofs
  for the eventual High baseline build-out.

- **Q2**: For controls where 800-53A defines no explicit procedure
  objects (rare; some controls are "include by reference"), what
  identifier do we emit? Recommendation: emit a single objective
  `<CONTROL>_obj.1` whose `text` is the control's own assessment
  procedure prose and whose `methods[]` defaults to all three. Flag
  the operator at validation time.

- **Q3**: When the matrix references a control parameter (e.g.
  `AC-2(3)_obj.1`), does the validator load the
  control-enhancement-specific procedure object? Recommendation:
  YES; the extractor walks `enhancements[]` too, and the catalog
  contains both base controls and enhancement-specific objectives.

- **Q4**: For `evidence_uuids`, do these reference OSCAL `observation`
  UUIDs (cross-reference) or evidence-attachment UUIDs from the
  tracker DB? Recommendation: the schema allows both via a
  discriminator prop (`evidence-ref-type: oscal-observation |
  tracker-attachment`) so the consumer knows where to resolve.

- **Q5**: Should `observed_at` be on the row level (as currently
  specified) or hoisted to the matrix level (single timestamp per
  upload)? Recommendation: keep on the row level — assessor
  fieldwork happens incrementally over days and per-row timestamps
  preserve provenance accuracy.

- **Q6**: For RBAC, does a `lead-assessor` role differ from a
  `assessor` role for commit-to-AR? Recommendation: lead-assessor is
  the only role that can `POST /commit?force=true` (i.e. override
  coverage gaps); regular `assessor` can only commit when all gaps
  are closed.

- **Q7**: Does the CSV column order need to match a particular
  industry template (e.g. eMASS export format)? Recommendation:
  document our column order in the schema; provide a tracker import
  helper that maps from eMASS / Telos Xacta / Paramify column
  headers to ours.

- **Q8**: When the matrix has a row with `method = TEST` and
  `objects_examined = ['Specifications']` only, the suspect_rows
  validator flags it (you can't TEST a document). Is this a hard
  error or a NOTICE? Recommendation: NOTICE for v1.0.0; operator
  signs off in the tracker UI to acknowledge before commit.

## Implementation log (running journal — implementing session updates)

This section is filled in DURING implementation. Leave it empty with
a single placeholder line:

```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥25 for this slice's
  new core tests + ≥14 tracker server tests + ≥5 tracker client
  tests)
- [ ] check:reo green (G1+G2+G3, including the new sha256-stability
  check on the generated catalog)
- [ ] STATUS.md updated (K.K2 row + Overall section: LOOP-K complete,
  last-shipped = K.K2, next-priority = end of currently-planned
  build-out or whatever loop is next per EXECUTION-PLAN.md)
- [ ] LOOP-K-SPEC.md Section 7 status table updated (K.K2 row)
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
  completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under
  `### Changed — LOOP-K.K2`
- [ ] Commit with `LOOP-K.K2: 3PAO test results matrix to OSCAL AR test-result-objects per 800-53A procedure objects` in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this
  file + LOOP-K-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context, here's everything
it needs to start:

1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded by the
   harness).
2. This file gives you: source obligations + files to create +
   build steps + schemas + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-K-SPEC.md` Section 2
   (Dependencies) for cross-loop context, Section 3 (Authoritative
   sources) for additional verbatim citations, and Section 6 (Open
   questions / caveats).
4. Read `cloud-evidence/docs/slices/K/K.K1.md` since K.K2 builds on
   K.K1's pentest envelope pattern (synthetic envelope + provenance).
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
6. Read the existing source anchors:
   - `cloud-evidence/core/oscal.ts` — AR + finding emit + deterministic
     UUID factory.
   - `cloud-evidence/core/oscal-ap.ts` — AP emit + existing per-KSI
     activity pattern.
   - `cloud-evidence/core/oscal-validate.ts` — ajv instance + chain
     validation.
   - `cloud-evidence/core/control-benchmark.ts` — Moderate baseline
     control list (the matrix validator filters against this).
   - `cloud-evidence/core/orchestrator.ts` — flag handling pattern.
   - `cloud-evidence/core/submission-bundle.ts` — WELL_KNOWN role
     catalogue.
   - `cloud-evidence/core/sign.ts` — Ed25519 + RFC 3161 (no special-
     casing needed; embedded AR signs as any other AR).
7. Begin implementation; update Implementation log section as you go.
