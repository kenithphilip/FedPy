# LOOP-K — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status: resolved` + a resolution note.
> Severity rubric: **high** = blocks the slice from shipping or breaks
> downstream OSCAL chain; **med** = degrades artifact quality but
> doesn't break ingest; **low** = nice-to-have / future enhancement.

Last updated: 2026-06-07

---

## Cross-cutting risks (apply to ALL slices in this loop)

### K-X1: OSCAL v1.1.2 metaschema interpretation drift
- **Description**: The OSCAL Assessment Results v1.1.2 metaschema is
  the canonical source for `finding.target.type`,
  `local-definitions.activities[]`, `observation.methods[]`, and
  `observation.types[]`. NIST publishes corrigenda + v1.2.x updates
  on a rolling basis; our committed schemas under
  `cloud-evidence/docs/oscal/` may drift from upstream.
- **Severity**: high (a drift could invalidate every emitted AR).
- **Mitigation**: pin OSCAL schema version explicitly in
  `core/oscal-validate.ts`; CI guardrail compares our committed
  schema sha256 against the upstream NIST schema once per week via a
  scheduled action; failures open an issue.
- **Owner**: K.K1 + K.K2 implementing sessions both.
- **Status**: open.

### K-X2: NIST CPRT JSON catalog API changes
- **Description**: K.K2 depends on the NIST CPRT JSON catalog for
  `SP_800_53_A_5_2_0` procedure-object identifiers. NIST may change
  the URL structure, payload shape, or release ID at any time. K.K1
  does not directly depend on the catalog but does cite 800-53A
  identifiers in test fixtures.
- **Severity**: high.
- **Mitigation**: extractor pins the URL + schema in its header;
  generated JSON is committed to the repo so a NIST outage doesn't
  block builds; an annual review task verifies the extractor still
  produces identical output.
- **Owner**: K.K2 implementing session.
- **Status**: open.

### K-X3: FedRAMP CSP Penetration Test Guidance v4.0 finalization
- **Description**: A public-comment draft of Version 4.0 is published
  (`CSP_Penetration_Test_Guidance_public_comment.pdf`). K.K1 schema
  v1.0.0 implements Version 3.0 (final, 2022-06-30). When Version 4
  finalizes, schema v1.1.0 will need to add fields. K.K2 indirectly
  depends because PenTest findings feed into the AR via K.K1.
- **Severity**: med (forward migration path is documented; no break).
- **Mitigation**: ingest module already keys on `schema_version`
  literal; v1.1.0 will add fields backward-compatibly; CI guardrail
  checks both schemas validate the committed fixtures.
- **Owner**: K.K1 implementing session; K.K2 inherits.
- **Status**: open.

### K-X4: REO Rule 4 surface area (operator-supplied data is real data)
- **Description**: Both K.K1 + K.K2 rely heavily on operator-supplied
  input (3PAO uploads). The temptation to add a "default narrative
  if missing" or "auto-fill rationale" is real and would silently
  violate REO. Every empty rationale, every missing finding field,
  every uncovered baseline control must surface as
  REQUIRES-OPERATOR-INPUT — never a friendly default.
- **Severity**: high (REO violation → CI rejects).
- **Mitigation**: code review checklist explicitly forbids any
  fallback prose; tests assert REQUIRES-OPERATOR-INPUT marker emit
  on every required-but-missing field; `lint:no-stubs` greps for
  forbidden tokens.
- **Owner**: both slices.
- **Status**: open.

### K-X5: Tracker DB migration ordering vs concurrent slices
- **Description**: K.K1 owns migration `041_pentest_reports.sql`;
  K.K2 owns `042_test_results_matrix.sql`. If another loop ships a
  slice that uses migration 041 or 042 first, K.K1/K.K2 must
  renumber. The tracker has no central migration registry today.
- **Severity**: med (renumber + re-run is cheap but disrupts the
  PR).
- **Mitigation**: each slice's PR description includes the next
  available migration number; reviewer checks `ls
  tracker/server/db/migrations/` immediately before merge.
- **Owner**: both slices.
- **Status**: open.

### K-X6: Sign-and-timestamp pipeline coverage
- **Description**: Both slices emit new files (KSI-PENTEST.json,
  matrix-CSV, matrix-JSON, embedded AR). The existing
  `core/sign.ts` pipeline signs the manifest, but the manifest
  builder must include the new files. Forgetting to register the
  new emit targets means the signature manifest is incomplete and
  the submission bundle (LOOP-A.A4) flags it.
- **Severity**: high (unsigned artifacts violate FedRAMP 20x
  RFC-0014 + REO Rule 1.6).
- **Mitigation**: the disk emitter in each slice MUST call into the
  same manifest registration helper that other emitters use
  (`core/sign.ts:registerForSigning(path)`). Test asserts the
  manifest contains every new file.
- **Owner**: both slices.
- **Status**: open.

### K-X7: Provenance fields not propagated through OSCAL props
- **Description**: REO requires provenance for every new emit field.
  K.K1 emits `pentest-*` props; K.K2 emits `oscal-target-granularity`
  + `method` + `assessment-object-type` props. If `check:provenance`
  doesn't recognize these as new fields, it may miss the requirement
  to populate `coverage_source` entries in the registry.
- **Severity**: high (CI rejects).
- **Mitigation**: each slice updates
  `cloud-evidence/scripts/check-provenance.mjs` allowlist with the
  new field names + their coverage_source registry entries in
  `core/coverage-source-registry.ts`.
- **Owner**: both slices.
- **Status**: open.

### K-X8: Tracker RBAC role surface
- **Description**: K.K1 PATCH + K.K2 PATCH/commit endpoints require
  `assessor` role; K.K2 commit-with-force requires `lead-assessor`.
  The tracker currently has an `assessor` role; `lead-assessor` may
  need to be added. If added in K.K2 only, K.K1's PATCH would not
  benefit from the finer distinction.
- **Severity**: med.
- **Mitigation**: add `lead-assessor` as a sub-role in K.K2's RBAC
  changes; K.K1 ships with `assessor` for both PATCH + retest sign;
  document the upgrade path.
- **Owner**: K.K2 primarily; K.K1 inherits sub-role semantics.
- **Status**: open.

### K-X9: Submission bundler well-known role conflicts
- **Description**: Both slices add to `core/submission-bundle.ts`
  WELL_KNOWN. K.K1 adds 3 roles; K.K2 adds 2. If two roles use the
  same filename glob, the bundler may double-classify. The
  `pentest-ingest-json` role (filename `pentest-ingest.json`) and
  the `test-results-matrix-json` role (filename
  `test-results-matrix.json`) don't conflict, but a future slice
  could.
- **Severity**: low.
- **Mitigation**: test asserts each WELL_KNOWN entry has a unique
  filename pattern; `check:reo` could be extended to verify.
- **Owner**: both slices (defensive coding).
- **Status**: open.

### K-X10: Determinism under parallel orchestrator runs
- **Description**: Both slices add disk-write paths
  (`KSI-PENTEST.json`, `test-results-matrix.csv`, `embedded AR`).
  If two orchestrator runs target the same outDir concurrently, the
  emitters could race. K.K1's converter is deterministic but the
  disk write is not atomic by default.
- **Severity**: med (operators run sequentially in practice).
- **Mitigation**: both emitters use the existing `core/run-lock.ts`
  + atomic temp-file-and-rename pattern; tests assert the lock is
  taken before write.
- **Owner**: both slices.
- **Status**: open.

### K-X11: CHANGELOG drift between SPEC + STATUS + per-slice doc
- **Description**: The SLICE-COMPLETION-PROCEDURE.md requires updates
  to four locations on commit: per-slice MD frontmatter, STATUS.md,
  LOOP-K-SPEC.md Section 7, and CHANGELOG.md. Forgetting any one
  breaks the on-disk source of truth and future sessions reject
  the inconsistency.
- **Severity**: high (REO directive).
- **Mitigation**: the implementing session uses the
  SLICE-COMPLETION-PROCEDURE.md checklist as a hard gate; commit
  message MUST reference all four file paths.
- **Owner**: both slices.
- **Status**: open.

### K-X12: 800-53A method enum value mismatch (uppercase vs lowercase)
- **Description**: 800-53A Rev 5 uses `EXAMINE / INTERVIEW / TEST`
  (uppercase). OSCAL v1.1.2 metaschema constraint also uses
  uppercase. Some assessor tooling exports lowercase. If the matrix
  parser silently uppercases, the round-trip CSV ↔ JSON ↔ OSCAL is
  not idempotent.
- **Severity**: low.
- **Mitigation**: parser explicitly rejects lowercase + suggests
  uppercase in the error message; UI normalizes on input + warns
  the operator.
- **Owner**: K.K2 (matrix); K.K1 has no method enum.
- **Status**: open.

---

## Per-slice risks (slice-specific, not duplicated from cross-cutting)

### K.K1 — Penetration Test Report ingest schema + tracker display

#### K.K1-R1: CVSS v3.1 vector regex strictness
- **Description**: CVSS v3.1 vectors carry optional Temporal +
  Environmental metric groups (e.g. `/E:X/RL:X/RC:X/...`). A 3PAO
  scanner may emit any subset. A too-strict regex rejects valid
  vectors; a too-loose regex accepts malformed ones.
- **Severity**: med.
- **Mitigation**: regex matches the mandatory Base group + allows
  optional Temporal/Environmental segments; malformed input is
  treated as REQUIRES-OPERATOR-INPUT with the malformed value
  preserved in the validation error.

#### K.K1-R2: CVSS v3.0 backward compatibility
- **Description**: Some older 3PAO scanners emit CVSS v3.0 vectors
  (prefix `CVSS:3.0/`). Source 1 mandates v3.1.
- **Severity**: low.
- **Mitigation**: parser explicitly rejects v3.0 with a helpful
  error pointing to upgrade docs; document in the schema's
  description.

#### K.K1-R3: 3PAO accreditation_id format
- **Description**: FedRAMP publishes accredited 3PAOs at
  `https://marketplace.fedramp.gov/assessors/list` but does not
  standardize an ID format.
- **Severity**: low.
- **Mitigation**: accept any non-empty string; tracker UI
  cross-checks against a configured allow-list if
  `config.yaml > pentest.allowed_3pao_ids[]` is populated; default
  permissive.

#### K.K1-R4: Overdue-retest math relies on `engagement_end`
- **Description**: If the operator records `engagement_end` after
  the actual test closure (e.g. used the report-publication date),
  the 30-day window starts later than reality.
- **Severity**: med.
- **Mitigation**: document in `tracker/client/src/pages/PenTestReport.tsx`
  that `engagement_end` MUST be the last test day, not the
  report-publish date; schema cannot enforce this semantic, so
  it's a documented operator obligation.

#### K.K1-R5: Synthetic envelope conflicts with future real KSI
- **Description**: No cloud collector emits `KSI-PENTEST` today (it
  is process-artifact), so a real-vs-synthetic conflict is
  impossible. If a future cloud KSI is named PENTEST, the synthetic
  envelope would clash with the real envelope.
- **Severity**: low.
- **Mitigation**: register `KSI-PENTEST` in `core/ksi-map.ts` as
  `scope: 'PROCESS'`; if a future cloud KSI needs the same name,
  rename to `KSI-PENTEST-3PAO`; reserve the name now.

#### K.K1-R6: Tracker storage of large PDF attachments
- **Description**: Real PenTest reports (~20MB+) may exceed default
  body-parser limits.
- **Severity**: med.
- **Mitigation**: route uses multipart streaming (existing pattern
  from H.4 evidence file upload) with a 100MB cap; oversized
  uploads return 413 with operator guidance.

#### K.K1-R7: Schema-version migration
- **Description**: Bumping `schema_version` to 1.1.0 in the future
  requires the parser to accept both versions and branch internally.
- **Severity**: low.
- **Mitigation**: K.K1 lays the groundwork (parser keys on the
  field) but does not implement the v1.1.0 branch; documented in
  Open Q.

#### K.K1-R8: PDF anchor validation
- **Description**: When the uploaded PDF's filename is
  `pentest-report.pdf` AND the JSON ingest references
  `report_section_ref: '#finding-3'`, do we validate the anchor
  against the PDF?
- **Severity**: low.
- **Mitigation**: NO for K.K1 (out-of-scope; PDF anchor validation
  would need a PDF parser); document as out-of-scope.

#### K.K1-R9: Impacted-controls validation against baseline
- **Description**: Should `report.findings[i].impacted_controls[]`
  be validated against the Moderate baseline control list?
- **Severity**: med.
- **Mitigation**: YES (use `core/control-benchmark.ts` Moderate set;
  unknown control → validation error). Operator can override with
  `--allow-unknown-controls` flag.

#### K.K1-R10: Tracker DB encryption at rest
- **Description**: For the `pentest_evidence_attachments` table, do
  we need per-attachment encryption at rest?
- **Severity**: low.
- **Mitigation**: Tracker existing convention says yes (DB column
  encryption); K.K1 inherits. Confirm at implementation.

#### K.K1-R11: Malformed JSON file via orchestrator
- **Description**: When the `--pentest-report` flag is supplied but
  the file is malformed JSON (not schema-mismatched, just
  unparseable), should the orchestrator continue with remaining
  flags or hard-fail?
- **Severity**: med.
- **Mitigation**: hard-fail (loud signal) but record the failure in
  the run-ledger; document.

### K.K2 — 3PAO test results matrix → OSCAL AR test-result-objects

#### K.K2-R1: Procedure-object identifier format drift (legacy IDs)
- **Description**: NIST CPRT JSON uses `<CONTROL>_obj.<n>` for
  800-53A Rev 5 Release 5.2.0, but some legacy 3PAO templates use
  `<CONTROL>.a`, `<CONTROL>.b` (sub-bullet identifiers carried over
  from 800-53A Rev 4 conventions).
- **Severity**: med.
- **Mitigation**: extractor normalizes to `<CONTROL>_obj.<n>` AND
  emits a `legacy_ids[]` field per objective for backward
  compatibility with assessor tooling that still produces the
  legacy form. Matrix parser accepts either form on input +
  normalizes before validation.

#### K.K2-R2: NIST CPRT catalog version drift (annual refresh)
- **Description**: Release 5.2.0 is the current (August 2025)
  baseline. A future release (5.3.0+) may add new procedure objects
  to existing controls.
- **Severity**: med.
- **Mitigation**: extractor records release version + extraction
  date; loader warns if catalog is >12 months old; annual refresh
  is captured as a recurring task in EXECUTION-PLAN.md.

#### K.K2-R3: OSCAL `statement-id` semantics ambiguity
- **Description**: The OSCAL v1.1.2 metaschema allows
  `target.type='statement-id'` but is silent on whether `target-id`
  MUST resolve to a control-statement (control body prose
  paragraph) vs an assessment-procedure objective.
- **Severity**: med.
- **Mitigation**: K.K2 adopts FedRAMP-aligned interpretation
  (target-id = 800-53A procedure-object identifier); emitter
  accepts CLI override
  `--statement-id-convention=fedramp-procedure-object|nist-control-paragraph`
  without schema migration. Default fedramp-procedure-object.

#### K.K2-R4: Large matrices balloon AR file size
- **Description**: A full Moderate assessment can produce ~10,000+
  matrix rows (149 baseline controls × ~4 procedure objects × ~2
  methods sampled). Embedding all of them balloons the AR JSON to
  ~50MB+.
- **Severity**: med.
- **Mitigation**: K.K2 supports the OSCAL `back-matter.resources[]`
  pattern for large activity sets in a follow-up (K.K2.1) if file
  size becomes a problem; for v1.0.0 we accept the larger AR and
  document the size budget.

#### K.K2-R5: Deterministic UUID collisions across slices
- **Description**: K.K2 uses
  `deterministicUuid('activity:' + control + ':' + obj + ':' + method)`.
  LOOP-A.A2 uses `deterministicUuid('activity:' + ksi)`.
- **Severity**: low.
- **Mitigation**: collisions are vanishingly unlikely (different
  input strings → SHA family); test asserts no collision in the
  sample matrix.

#### K.K2-R6: CSV parser edge cases
- **Description**: RFC 4180 allows multi-line fields with embedded
  CRLF inside quotes; this is a corner case the parser must handle.
- **Severity**: med.
- **Mitigation**: parser uses a state-machine implementation (not
  regex), with tests for embedded CRLF, embedded comma, embedded
  double-quote, BOM-prefixed files.

#### K.K2-R7: Chain validation strictness conflicts
- **Description**: When `--strict-chain` is set AND the AR has
  statement-id findings, current `oscal-validate.ts` may flag the
  unfamiliar `target.type='statement-id'`.
- **Severity**: high (would break LOOP-A.A3 chain mode).
- **Mitigation**: extend the validator BEFORE wiring the
  orchestrator handler; the order is captured in build step 13 of
  the K.K2 slice doc.

#### K.K2-R8: AP ↔ AR UUID drift
- **Description**: If the AP emitter (LOOP-A.A2) ships before the
  K.K2 matrix is supplied, AP activities lack the matrix-derived
  UUIDs. The orchestrator must re-emit the AP when
  `--test-results-matrix` is supplied.
- **Severity**: med.
- **Mitigation**: orchestrator handler for `--test-results-matrix`
  triggers a re-emit of the AP if one already exists in `outDir/`.

#### K.K2-R9: Matrix commit refusal blocking workflow
- **Description**: Operators may want to commit a partial matrix
  during long assessments.
- **Severity**: low.
- **Mitigation**: `POST /commit?force=true` override is documented;
  audit log captures forced commit; embedded AR metadata records
  `coverage_gaps_force_committed: true`.

#### K.K2-R10: Method TEST against Specifications/Individuals only
- **Description**: A row with `method=TEST` and
  `objects_examined=['Specifications']` is methodologically
  inconsistent (you can't TEST a document).
- **Severity**: low.
- **Mitigation**: validator emits NOTICE in `suspect_rows[]`;
  operator signs off in the tracker UI to acknowledge before
  commit. Future enhancement: stricter rejection via flag.

#### K.K2-R11: eMASS / Telos Xacta / Paramify CSV format mapping
- **Description**: 3PAOs often produce matrices in vendor-specific
  CSV formats with different column orders + header names.
- **Severity**: low.
- **Mitigation**: document our column order in the schema; provide
  a tracker import helper that maps from common vendor headers to
  ours; the import-helper itself is out-of-scope for K.K2 v1.0.0
  but the documented mapping table ships in
  `cloud-evidence/docs/oscal/test-results-matrix-import-mapping.md`.

#### K.K2-R12: Control parameters (enhancements)
- **Description**: When the matrix references a control parameter
  (e.g. `AC-2(3)_obj.1`), the validator must load the
  control-enhancement-specific procedure object.
- **Severity**: med.
- **Mitigation**: extractor walks `enhancements[]` too; catalog
  contains both base controls and enhancement-specific objectives;
  validator test covers this.

#### K.K2-R13: Controls with no explicit procedure objects
- **Description**: Some 800-53A controls have no explicit procedure
  objects (rare; "include by reference"). What identifier do we
  emit?
- **Severity**: low.
- **Mitigation**: emit a single objective `<CONTROL>_obj.1` whose
  text is the control's own assessment procedure prose and whose
  `methods[]` defaults to all three; flag at validation.

---

## External dependencies that may change

### FedRAMP guidance updates
- **CSP Penetration Test Guidance v4.0** — public-comment draft
  exists (`CSP_Penetration_Test_Guidance_public_comment.pdf`);
  expected finalization 2026Q2-Q4. K.K1 schema v1.1.0 will add new
  fields backward-compatibly.
- **Rev5 Playbook SAP/SAR Appendix B updates** — could change the
  sampling-methodology shape; affects K.K2 commit-to-AR semantics.
- **FedRAMP 20x Phase Two final guidance** — RFC-0014 may pin
  specific OSCAL field requirements; both slices must monitor.

### NIST publication versions
- **800-53A Rev 5.3.0 (or later)** — annual catalog refresh expected;
  K.K2 catalog extractor must rerun.
- **800-53 Rev 6 (future)** — major version bump would invalidate
  all current procedure-object identifiers; out-of-scope for K.K2
  v1.0.0 but documented as a future migration.
- **800-115 Rev 1 (future)** — would change the PenTest four-phase
  model; K.K1 schema enum would need update.

### OSCAL version
- **OSCAL v1.2.x or v2.0** — would affect both
  `core/oscal-validate.ts` schemas + the `finding.target.type` enum;
  pinned to v1.1.2 currently with explicit migration path
  documented.

### Upstream library updates
- **ajv** — schema validator; pinned major version; minor bumps OK.
- **OSCAL schemas** — committed to repo; CI guardrail checks drift
  vs upstream NIST schemas weekly.
- **csv-parse** (or equivalent) — if K.K2 uses an off-the-shelf CSV
  parser instead of hand-rolled RFC 4180 state machine; pinned
  major version.
- **better-sqlite3** — tracker DB driver; pinned.
- **react-table** / **tanstack-table** — K.K1 + K.K2 matrix grids;
  pinned.
- **multer** / multipart parser — tracker file uploads (K.K1 PDF +
  K.K2 evidence); pinned.

### CISA / industry catalogs
- **CISA KEV catalog** — K.K1 PenTest findings carry `cve_ids` that
  may match KEV entries; the KEV-feed module is out-of-scope for
  K.K1 itself but downstream B.B1 (CVSS+EPSS+exposure scoring)
  consumes pentest findings.

---

## Resolved risks (historical)

(Empty initially — populated as risks are resolved.)

---

## Risk update protocol

When an implementing session encounters a risk:

1. **New risk discovered**: add a `K-X<n>` (cross-cutting) or
   `K.K<slice>-R<n>` (slice-specific) entry under the appropriate
   section with description + severity + mitigation + owner +
   status=open.
2. **Risk realized (caused a bug or workaround)**: change status to
   `realized` and add a `Resolution note` paragraph describing what
   happened + how it was contained.
3. **Risk resolved (mitigation applied + verified)**: change status
   to `resolved`, add a `Resolution note` with the commit hash that
   closed it, and move the entry to the `Resolved risks (historical)`
   section.
4. **Risk superseded by a different risk**: change status to
   `superseded`, link to the new risk ID, and move to historical.

The git history of this file IS the audit trail. Do not delete entries.
