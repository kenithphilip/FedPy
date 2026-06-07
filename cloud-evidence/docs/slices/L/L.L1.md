---
slice_id: L.L1
title: CRM Workbook generator (SSP Appendix J)
loop: L
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A0 SSP-1/SSP-2, LOOP-A.A4, L.L2, control-benchmark, ksi-map, FRMR catalog]
blocks: [L.L3, L.L4, C.C7, C.C8, E.E4, F.F1]
estimated_effort: 6-8 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# L.L1 — CRM Workbook generator (SSP Appendix J)

## TL;DR
Replace the missing SSP Appendix J in the LOOP-A bundle with a fully-generated CIS/CRM Workbook (.xlsx) plus a machine-readable JSON twin. Every NIST 800-53 Rev5 control at the operator's declared impact tier (default Moderate) gets a row with a single responsibility designation (Service Provider / Customer / Shared / Inherited / Not-Applicable), sourced from `config/responsibility-matrix.yaml`, L.L2's inheritance trace, KSI evidence, or a visible REQUIRES-OPERATOR-INPUT marker — never silently defaulted. The workbook becomes a first-class submission-bundle artifact alongside SSP / AP / AR / POA&M / IIW / RoE.

## Status
- Status: pending
- Commit: — (filled when shipped, per `docs/SLICE-COMPLETION-PROCEDURE.md`)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
LOOP-L closes the largest documentation gap in the LOOP-A submission package: SSP Appendix J is mandatory and currently absent. Per FedPy's mission to emit signed, evidence-grade authorization-package artifacts, L.L1 is the artifact every 3PAO + FedRAMP PMO + Authorizing Official expects to find in the bundle.
- **(a) Cloud evidence collection**: rows sourced from real KSI evidence envelopes for CSP-implemented controls; the `implementation_status` for each Service-Provider row reads `KSI-*.json` pass/fail signals.
- **(b) KSI envelopes**: `core/ksi-map.ts` is the bridge from per-KSI evidence (FedPy's native unit) to NIST 800-53 control rows (CIS/CRM's native unit). Each row's `ksi_ids[]` array names the contributing KSIs for traceability.
- **(c) OSCAL chain (SSP/AP/AR/POA&M)**: the JSON twin (`cis-crm-workbook.json`) is consumed by L.L4 to populate SSP `implemented-requirements[].by-components[].responsible-roles[]`. The workbook is wired into LOOP-A.A4 submission bundle as a new role.
- **(d) FRMR catalog**: row set comes from `docs/frmr-requirements.generated.json` filtered by impact tier; control IDs + titles + descriptions read verbatim from the catalog.
- **(e) Tracker DB**: future LOOP-L extension could add a tracker authoring UI; for first ship the matrix is operator-committed yaml (REO Rule 4 operator-supplied data path).

## Why this slice exists
The FedRAMP CSP Authorization Playbook (Rev5) §SSP appendices section explicitly requires:

> "CSPs are required to submit a Control Implementation Summary/Customer Responsibility Matrix (CIS/CRM) workbook as Appendix J to the System Security Plan (SSP). The CIS/CRM workbook identifies security controls that the CSP is responsible for implementing, security controls that the customer is responsible for implementing, security controls where there is a shared CSP/customer responsibility, and security controls that are inherited from an underlying FedRAMP Authorized Infrastructure-as-a-Service (IaaS) or Platform-as-a-Service (PaaS)."

Today, LOOP-A's submission bundle has 24 well-known roles (oscal-ssp, oscal-ap, oscal-ar, oscal-poam, inventory-workbook-xlsx, signed-manifest, rfc3161-timestamp, ksi-evidence, etc.) — but NO cis-crm-workbook role. This means a 3PAO consuming the bundle has no place to look for the mandatory Appendix J. The bundle is incomplete on its face; the gap is documentary, not technical, but a 3PAO will reject the submission package as non-conforming.

This slice closes the gap end-to-end: workbook .xlsx + JSON twin emitted from real catalog + real evidence + real operator config, signed by `core/sign.ts`, registered in the bundle's well-known catalogue, and the responsibility split per row is sourced (with `_source` fields) so a 3PAO can audit *how* each row was filled in.

## Authoritative sources (with verbatim quotes)

- https://www.fedramp.gov/docs/rev5/playbook/csp/ — **FedRAMP CSP Authorization Playbook (Rev5), SSP Appendix J section** (PDF download; the implementer mirrors quote to docstring at ship time):
  > "CSPs are required to submit a Control Implementation Summary / Customer Responsibility Matrix (CIS/CRM) workbook as Appendix J to the System Security Plan (SSP). The CIS/CRM workbook identifies security controls that the CSP is responsible for implementing, security controls that the customer is responsible for implementing, security controls where there is a shared CSP/customer responsibility, and security controls that are inherited from an underlying FedRAMP Authorized Infrastructure-as-a-Service (IaaS) or Platform-as-a-Service (PaaS)."
  Source: also quoted at `cloud-evidence/docs/ADDITIONAL-LOOPS-AUDIT.md` §2 LOOP-L.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev5, §2.5 (Inheritance and Compensating Controls)**:
  > "Controls are inheritable when their implementation is the responsibility of an external system, organization, or service. Inherited controls are documented in the security plan along with the identifier of the providing entity and a description of the inherited control."
  The CIS/CRM workbook is the structured manifestation of this requirement: the "Inherited" rows carry both the providing entity (PA-id + title) and the description.

- https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final — **NIST SP 800-53B Rev5 (Control Baselines)** — Moderate baseline:
  > "287 base controls and control enhancements" for the Moderate baseline. (FedRAMP Rev5 Moderate adds FedRAMP-specific enhancements pushing the total to ~325; L.L1 reads the FRMR catalog as the authoritative count.)

- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/ — **OSCAL SSP v1.1.2, `implemented-requirements[].by-components[].responsible-roles[]`** — the OSCAL extension point L.L4 wires into. The JSON twin's `responsible_roles` per row maps 1:1 to this schema.

- https://github.com/FedRAMP/docs — **FRMR catalog** — `cloud-evidence/docs/frmr-requirements.generated.json` is the committed extraction. Each Moderate-baseline control has an entry; L.L1 row set = filter `impact_tier === 'moderate'`.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/cis-crm-emit.ts` — pure builder + disk emitter: reads inputs, computes per-control responsibility row, emits .xlsx + .json. ~700 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/responsibility-matrix.ts` — typed loader for `config/responsibility-matrix.yaml`. Validates every control id against the loaded NIST + FRMR catalog. ~200 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/cis-crm-xlsx.ts` — pure-JS .xlsx renderer reusing the OOXML approach from `core/inventory-workbook.ts` (no external dependency; same ZIP + worksheet XML composition). ~400 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/config/responsibility-matrix.example.yaml` — committed example operator copies + customises.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/cis-crm-emit.test.ts` — integration tests (load fixture FRMR + responsibility YAML; verify workbook structure).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/cis-crm-xlsx.test.ts` — pure renderer tests (column widths, header row, conditional formatting).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/responsibility-matrix.test.ts` — YAML loader tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/cis-crm/` — fixture YAML + mini-FRMR-catalog used by tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--crm` flag + env `CLOUD_EVIDENCE_CRM`; `--crm-config <path>` defaulting to `config/responsibility-matrix.yaml`; `--strict-crm` (gate: refuses to emit if any Moderate control has no responsibility). Runs AFTER per-KSI collectors AND L.L2 (`--leveraged-auth`); runs BEFORE `--oscal-ssp` (so L.L4 can fill SSP `responsible-roles`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add roles `cis-crm-workbook-xlsx` (filename `cis-crm-workbook.xlsx`), `cis-crm-workbook-json` (filename `cis-crm-workbook.json`) to `WELL_KNOWN`. Mark both as `required: true` for FedRAMP submission so the bundler's gap detection flags missing CRM (strict-bundle mode).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sections/SECTION-A.md` — add A23 (CRM workbook) row to artifact inventory.

## Schemas / standards
- **FedRAMP CIS/CRM Workbook column set** — 7 required columns per the FedRAMP template (verbatim labels):
  - **Control ID** (e.g. "AC-2", "AC-2(1)")
  - **Control Description** (verbatim from NIST 800-53)
  - **Responsible Role** (5-bucket: `Service Provider` / `Customer` / `Shared` / `Inherited from PA-id` / `Not Applicable`)
  - **Implementation Description** (text)
  - **Implementation Status** (`Implemented`, `Partially Implemented`, `Planned`, `Alternative Implementation`, `Not Applicable`)
  - **Inherited From** (PA-id of leveraged authorization, or null)
  - **Customer Responsibility** (text — what the customer must do)
- **OSCAL responsible-roles role-id values** — `'provider'` / `'customer'` / `'shared-csp-customer'` / `'inherited'`. L.L1 emits the JSON twin keyed off these roles for L.L4 to map into the SSP `responsible-roles[]` arrays.
- **NIST 800-53B Rev5 Moderate baseline** — 287 base controls + enhancements. FedRAMP Rev5 Moderate adds FedRAMP-specific enhancements pushing the total to ~325; row set sourced from FRMR catalog `docs/frmr-requirements.generated.json` filtered by `impact_tier === 'moderate'`.
- **`package_format_version`** — `'20x.phase-two.preview.2026'` (matches LOOP-A.A4's version).
- **`cis_crm_format_version`** — `'20x.crm.preview.2026'` (per `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.5: the FedRAMP CIS/CRM template format is in revision; pin version so a future format shift gets a clean bump).

## Build steps (concrete, numbered)

1. Define typed interfaces in `core/cis-crm-emit.ts`:
   ```ts
   export type ResponsibilityBucket = 'service-provider' | 'customer' | 'shared' | 'inherited' | 'not-applicable';
   export type ImplementationStatus = 'implemented' | 'partially-implemented' | 'planned' | 'alternative-implementation' | 'not-applicable';

   export interface CisCrmRow {
     control_id: string;                  // 'AC-2'
     control_title: string;
     control_description: string;
     responsibility: ResponsibilityBucket;
     responsibility_source: 'ksi-evidence' | 'inherited-trace' | 'responsibility-matrix-yaml' | 'REQUIRES-OPERATOR-INPUT';
     implementation_status: ImplementationStatus;
     implementation_status_source: 'ksi-finding' | 'responsibility-matrix-yaml' | 'REQUIRES-OPERATOR-INPUT';
     implementation_description: string;
     implementation_description_source: 'ksi-evidence' | 'responsibility-matrix-yaml' | 'inherited-narrative' | 'REQUIRES-OPERATOR-INPUT';
     inherited_from_pa_id?: string;        // 'F1411040093'
     inherited_from_title?: string;        // 'AWS GovCloud'
     customer_responsibility: string;
     customer_responsibility_source: 'responsibility-matrix-yaml' | 'REQUIRES-OPERATOR-INPUT' | 'not-applicable';
     ksi_ids?: string[];                   // KSIs that contribute evidence to this row
     remarks?: string;
   }

   export interface CisCrmWorkbook {
     metadata: {
       system_name: string;
       system_id: string;
       impact_tier: 'low' | 'moderate' | 'high';
       generated_at: string;
       cis_crm_format_version: '20x.crm.preview.2026';
       package_format_version: '20x.phase-two.preview.2026';
       frmr_version: string;
       nist_catalog_version: 'Rev5';
     };
     leveraged_authorizations: Array<{ pa_id: string; title: string; provider: string }>;
     rows: CisCrmRow[];
     summary: {
       total: number;
       service_provider: number;
       customer: number;
       shared: number;
       inherited: number;
       not_applicable: number;
       requires_operator_input: number;
     };
     provenance: { emitter: 'core/cis-crm-emit.ts'; emittedAt: string; sourceCalls: string[]; signingKeyId?: string };
   }
   ```

2. Pure builder:
   ```ts
   export function buildCisCrmWorkbook(inputs: CisCrmInputs): CisCrmWorkbook;
   ```
   where `CisCrmInputs` carries:
   - parsed FRMR catalog (filtered by impact tier)
   - parsed `responsibility-matrix.yaml`
   - KSI evidence envelopes (read from `out/KSI-*.json`)
   - `inheritance-trace.json` (when L.L2 has run)
   - system identity (`system_name`, `system_id` from orchestrator flags)

3. **Per-control row derivation** — priority cascade:
   - **Step A** (yaml): read `responsibility-matrix.yaml` entry for this `control_id`. If present, use its `responsibility` + `implementation_description` + `customer_responsibility` verbatim. Set sources to `'responsibility-matrix-yaml'`.
   - **Step B** (inheritance): if no YAML entry AND `control_id` ∈ `inheritance-trace.json.by_control`, set `responsibility = 'inherited'`, `inherited_from_pa_id` + `inherited_from_title` + `implementation_description` from the inheritance-trace narrative. Sources `'inherited-trace'`.
   - **Step C** (KSI): if no YAML entry AND no inherited match, check `ksi-map.ts` for KSI → control mapping. For each KSI mapping to this control, pull pass/fail status from `out/KSI-*.json`. If ALL mapped KSIs pass AND any of them is CSP-implemented (per KSI taxonomy in FRMR), set `responsibility = 'service-provider'`, `implementation_status = 'implemented'`, `implementation_description = <auto-narrative from KSI evidence>`. Sources `'ksi-evidence'`.
   - **Step D** (gap): if NONE of A-C applies, emit `responsibility_source: 'REQUIRES-OPERATOR-INPUT'`, `responsibility: 'not-applicable'` placeholder visible-but-marked. Under `--strict-crm`, abort. This is the gap L.L3 detects.

4. **Implementation status derivation** when responsibility is `service-provider`:
   - All mapped KSIs pass → `'implemented'`
   - Some pass / some fail → `'partially-implemented'`
   - No KSI mapped to control → `'planned'` + REQUIRES-OPERATOR-INPUT marker on `implementation_status_source`
   - KSI catalog says control N/A → `'not-applicable'`

5. **Customer responsibility text**: from YAML when present; otherwise `REQUIRES-OPERATOR-INPUT: customer responsibility undefined`.

6. **Inherited row generation**: For each control where `responsibility = 'inherited'`, the row reads from `out/inheritance-trace.json` (L.L2 output). If L.L2 has NOT yet run, L.L1 emits `inherited_from_pa_id: 'REQUIRES-OPERATOR-INPUT'`. The orchestrator order (`--leveraged-auth` BEFORE `--crm`) prevents this case in normal flow.

7. **XLSX rendering** (`core/cis-crm-xlsx.ts`) — 7-worksheet structure:
   1. **Cover** — system name, impact tier, generated_at, cis_crm_format_version, leveraged authorizations summary.
   2. **Summary** — counts per responsibility bucket + visual bar/percentage.
   3. **AC** family — rows for AC-* controls.
   4. **AU, AT, CA, CM, CP, IA, IR, MA, MP, PE, PL, PS** — one sheet per family group OR grouped sheets per template convention.
   5. **RA + SA + SC** — combined; high column density.
   6. **SI + SR** — combined.
   7. **Inherited Controls** — sub-view of all `inherited` rows with the inherited_from columns expanded for AO/3PAO review.
   - Column widths per the FedRAMP template (Control ID 12, Description 60, Responsibility 18, Implementation Status 20, Implementation Description 80, Inherited From 24, Customer Responsibility 60).
   - Header row frozen.
   - Conditional formatting: `REQUIRES-OPERATOR-INPUT` cells highlighted red; `inherited` rows shaded light blue; `shared` rows shaded light yellow.

8. **Disk emitter**:
   ```ts
   export interface CisCrmEmitOptions {
     outDir: string;
     frmrPath?: string;                  // default: docs/frmr-requirements.generated.json
     responsibilityMatrixPath?: string;  // default: config/responsibility-matrix.yaml
     inheritanceTracePath?: string;      // default: outDir/inheritance-trace.json
     leveragedAuthsPath?: string;        // default: outDir/leveraged-authorizations.json
     systemName: string;
     systemId: string;
     impactTier: 'low' | 'moderate' | 'high';
     runId: string;
   }
   export interface CisCrmEmitResult {
     xlsxPath: string;
     jsonPath: string;
     row_count: number;
     bucket_summary: CisCrmWorkbook['summary'];
     requires_operator_input_count: number;
     leveraged_auth_count: number;
   }
   export async function emitCisCrm(opts: CisCrmEmitOptions): Promise<CisCrmEmitResult>;
   ```

9. **Orchestrator wiring**: `--crm` flag invokes `emitCisCrm()`. Runs AFTER per-KSI collectors AND `--leveraged-auth` (L.L2); runs BEFORE `--oscal-ssp` and `--ssp-docx`. Documented order in `core/orchestrator.ts`: collect → inventory → leveraged-auth → inheritance-trace → crm → ssp → ap → ar → poam → bundle → sign → timestamp.

10. **Provenance block** on `cis-crm-workbook.json`: emitter name, `emittedAt` (ISO), `sourceCalls` (every envelope read + every YAML loaded + every inheritance-trace lookup), `signingKeyId` placeholder filled by `core/sign.ts`.

11. **Bundler integration** — add to `submission-bundle.ts:WELL_KNOWN`:
    ```ts
    { role: 'cis-crm-workbook-xlsx', filename: 'cis-crm-workbook.xlsx', description: 'SSP Appendix J — Control Implementation Summary / Customer Responsibility Matrix workbook (LOOP-L.L1)', required: true },
    { role: 'cis-crm-workbook-json', filename: 'cis-crm-workbook.json', description: 'Machine-readable CRM twin (LOOP-L.L1)', required: true },
    ```

12. **Strict mode**: `--strict-crm` refuses to emit if ANY Moderate control's `responsibility_source` is `'REQUIRES-OPERATOR-INPUT'`. `--strict-crm` implies `--crm`. Exit code 4 (matching LOOP-A.A4's `--strict-bundle` convention).

13. **YAML loader** (`core/responsibility-matrix.ts`):
    - Reads `config/responsibility-matrix.yaml`.
    - Schema:
      ```yaml
      version: 1
      controls:
        AC-2:
          responsibility: customer
          implementation_description: |
            Customer-managed accounts in the customer tenant; CSP provides
            the underlying IAM service.
          customer_responsibility: |
            Customer creates, maintains, and reviews user accounts per
            their internal policy.
        AC-2(1):
          responsibility: shared
          implementation_description: ...
          customer_responsibility: ...
      ```
    - Validates every `control_id` against the FRMR catalog + NIST Rev5
      catalog.
    - Validates `responsibility` ∈ 5-bucket set.
    - Returns typed `ResponsibilityMatrix` value.

14. **Validation pass**:
    - Run emitted `cis-crm-workbook.json` through `scripts/check-provenance.mjs` — must list a `provenance` block.
    - Run emitted `cis-crm-workbook.xlsx` through `tests/core/cis-crm-xlsx.test.ts` round-trip via SheetJS (in tests only, per CLAUDE.md Rule 2.4) — must round-trip identically.

15. **Sign + timestamp**: both `cis-crm-workbook.xlsx` and `cis-crm-workbook.json` picked up by the existing `core/sign.ts` glob + included in the RFC 3161 manifest. The LOOP-A.A4 bundler includes both files automatically once they're in `WELL_KNOWN`.

## REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4 (`cloud-evidence/CLAUDE.md`), every field that cannot be auto-derived:

| Field | Source | Behavior when missing |
|---|---|---|
| Per-control responsibility (Customer / Shared / Not-Applicable) | `config/responsibility-matrix.yaml` per `control_id` | `responsibility_source = 'REQUIRES-OPERATOR-INPUT'`, surfaced on row + in L.L3 gap report; `--strict-crm` aborts run |
| Implementation description (when not derivable from KSI) | YAML `implementation_description` per control | `implementation_description_source = 'REQUIRES-OPERATOR-INPUT'` |
| Customer responsibility text | YAML `customer_responsibility` per control | `customer_responsibility_source = 'REQUIRES-OPERATOR-INPUT'` |
| Impact tier (Low / Moderate / High) | CLI `--impact-level <tier>` OR LOOP-C.C5 FIPS 199 worksheet | Defaults to `moderate` per project memory + audit guidance |
| System name + ID | CLI `--system-name`, `--system-id` (existing flags from LOOP-A) | Existing default behavior |
| `cis_crm_format_version` | Constant `'20x.crm.preview.2026'` (per audit §5.5) | N/A |
| `inherited_from_pa_id` | L.L2 `inheritance-trace.json` | `REQUIRES-OPERATOR-INPUT` if L.L2 has not run; visible on row |

## Test specifications (≥12 tests)

1. `it('emits one row per Moderate-baseline control from the FRMR catalog')` — load fixture FRMR with 10 mock Moderate controls; assert workbook has 10 rows.
2. `it('respects --impact-level low to switch row set')` — fixture has 5 Low controls; with `impactTier: 'low'` assert 5 rows.
3. `it('derives responsibility from YAML when present')` — YAML maps AC-2 to `customer`; assert row `responsibility === 'customer'`, `responsibility_source === 'responsibility-matrix-yaml'`.
4. `it('marks REQUIRES-OPERATOR-INPUT when YAML missing entry')` — YAML omits AC-2; assert `responsibility_source === 'REQUIRES-OPERATOR-INPUT'`, row visible.
5. `it('derives inherited rows from inheritance-trace.json')` — trace contains AC-2 → AWS GovCloud; assert row `responsibility === 'inherited'`, `inherited_from_pa_id === 'F1411040093'`, source `'inherited-trace'`.
6. `it('derives service-provider from KSI evidence when YAML and inheritance absent')` — fixture KSI IAM-MFA mapping to AC-2 with all-pass; assert row `responsibility === 'service-provider'`, `implementation_status === 'implemented'`, source `'ksi-evidence'`.
7. `it('--strict-crm aborts when any control has REQUIRES-OPERATOR-INPUT responsibility')` — assert thrown error names the gap controls + exit code 4.
8. `it('emits all 7 worksheets including Cover + Summary + Inherited Controls')` — open emitted xlsx via SheetJS round-trip (test layer only); assert sheet names.
9. `it('summary counts equal sum across buckets')` — bucket counts add to total; `requires_operator_input` overlaps but distinct.
10. `it('conditional formatting highlights REQUIRES-OPERATOR-INPUT cells red')` — parse XLSX styles XML; assert RGB FF0000 on those cells.
11. `it('emits provenance block on cis-crm-workbook.json with sourceCalls populated')` — `check:provenance` passes (e.g. via `scripts/check-provenance.mjs`).
12. `it('package_format_version + cis_crm_format_version are pinned')` — assert constants `'20x.phase-two.preview.2026'` + `'20x.crm.preview.2026'`.
13. `it('YAML loader rejects entry with unknown control_id')` — config loader throws typed error naming the offending control_id.
14. `it('YAML loader rejects entry with responsibility not in 5-bucket set')` — config loader throws.
15. `it('responsibility-matrix.example.yaml validates against the loader')` — load example file, assert no errors.
16. `it('bundler well-known catalogue includes cis-crm-workbook-xlsx + cis-crm-workbook-json with required:true')`.
17. `it('partially-implemented status when some KSIs pass and some fail')` — fixture KSI IAM-MFA pass on AWS, fail on GCP; assert status `'partially-implemented'`.
18. `it('REO no-stubs check: no TODO/FIXME/placeholder tokens in production code')` — runs `npm run lint:no-stubs`.

## REO compliance specific to this slice
- Every control row traces to either FRMR catalog (control_id + description), KSI evidence (CSP-implemented rows), inheritance trace (Inherited rows), responsibility-matrix.yaml (Customer / Shared / NA rows), OR a `REQUIRES-OPERATOR-INPUT` marker.
- No silent defaults for: per-control responsibility, implementation description, customer responsibility text, inherited PA-id.
- The .xlsx is composed via pure-JS OOXML (existing pattern from `core/inventory-workbook.ts` and `core/ssp-docx.ts`); no `python-docx`, no external `docx`/`xlsx` npm packages.
- Signed by existing `core/sign.ts` pipeline (both .xlsx + .json land in manifest glob).
- Provenance block on the JSON twin per REO Rule 2.6 + `scripts/check-provenance.mjs`.
- `process.env.NODE_ENV === 'test'` is NEVER referenced in production paths (REO Rule 1.8); tests inject seams via dependency-injected file readers + dependency-injected runId.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/cis-crm-emit.test.ts tests/core/cis-crm-xlsx.test.ts tests/core/responsibility-matrix.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues
- **Risk 1: FedRAMP CIS/CRM template format is in revision (audit §5.5).** Mitigation: pin `cis_crm_format_version: '20x.crm.preview.2026'`; CHANGELOG entry names the version + cites the audit. Future format shift bumps version in a separate slice.
- **Risk 2: Operator yaml may be incomplete on first run.** Many CSPs have not authored a per-control responsibility matrix. Mitigation: `--strict-crm` makes the gap visible (exits non-zero with gap report path); without strict mode, REQUIRES-OPERATOR-INPUT markers surface in the workbook for audit; L.L3 gap report enumerates every missing control.
- **Risk 3: KSI-to-NIST mapping in `ksi-map.ts` may be incomplete for the long-tail Moderate controls.** Mitigation: when no KSI maps to a control, fall through to Step D (REQUIRES-OPERATOR-INPUT) rather than synthesising; documentation tells the operator they can extend `ksi-map.ts` or fill in via yaml.
- **Risk 4: OOXML composition error producing an invalid .xlsx.** Mitigation: SheetJS round-trip test in `cis-crm-xlsx.test.ts`; mirror the proven approach from `core/inventory-workbook.ts` (already in production for the IIW).
- **Risk 5: Bundler `required: true` bumps the gap-detection list; existing tests for `tests/core/submission-bundle.test.ts` may break.** Mitigation: ship the bundler change atomically with L.L1 + test updates; CHANGELOG calls out the new required artifacts.
- **Risk 6: Inheritance trace not yet written when L.L1 runs first** (e.g. operator skipped `--leveraged-auth`). Mitigation: L.L1 detects missing `inheritance-trace.json`, emits `REQUIRES-OPERATOR-INPUT` on inherited rows + logs a warning naming `--leveraged-auth` as the fix.
- **Risk 7: Multi-CSO single yaml** — `config/responsibility-matrix.yaml` is single-tenant in this first ship. Mitigation: documented in spec §7.7; H.H3 will migrate to per-CSO paths.

## Open questions
- **Q1**: Should `config/responsibility-matrix.yaml` be checked in or gitignored? Recommend: `.example.yaml` is committed; the operator-customised file is gitignored.
- **Q2**: Does the FRMR catalog at `docs/frmr-requirements.generated.json` carry a `control_description` field, or do we need to cross-reference NIST `nist-r5.ts`? Recommend: verify at build time; if missing, read description from `core/nist-r5.ts` (already loaded for L.L2 component-definition emission).
- **Q3**: How do we handle control enhancements (e.g. `AC-2(1)` as a child of `AC-2`)? FedRAMP CIS/CRM treats each as its own row; does our yaml allow nested entries (per-enhancement responsibility), or flat? Recommend: flat (one entry per control_id including enhancement); module docstring documents.
- **Q4**: When a KSI maps to multiple controls (typical) and the KSI passes on AWS but fails on GCP, how do we report per-control status? Recommend: status = `partially-implemented`; implementation_description names the cloud-specific gap.
- **Q5**: Are the FedRAMP CIS/CRM column labels exactly as listed (verbatim from template)? Recommend: operator downloads the FedRAMP template at ship time; CHANGELOG cites the exact template version + URL the labels match.
- **Q6**: When `--strict-crm` aborts, exit code 4 matches LOOP-A.A4's `--strict-bundle` convention. Confirm? Recommend: yes; consistency across strict modes.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses, per docs/IMPLEMENTATION-LOG-TEMPLATE.md)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥18 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section + LOOP-L block added if first L slice)
- [ ] LOOP-L-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>, last_updated=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added per LOOP-L-SPEC.md §12 template
- [ ] Commit with slice ID in message ("LOOP-L.L1: CRM Workbook generator (SSP Appendix J)")
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-L-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-L-SPEC.md` §3 (Dependencies) for cross-loop context.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/inventory-workbook.ts` — your model for the pure-JS OOXML .xlsx renderer.
6. Read `cloud-evidence/core/ksi-map.ts` — the KSI → NIST control mapping you depend on for Step C.
7. Read `cloud-evidence/core/submission-bundle.ts:WELL_KNOWN` array — add two new entries with `required: true`.
8. Read `cloud-evidence/core/nist-r5.ts` — the NIST 800-53 Rev5 catalog reference for validation in `responsibility-matrix.ts`.
9. Read `cloud-evidence/docs/frmr-requirements.generated.json` — your row-set source.
10. Read `cloud-evidence/docs/loops/LOOP-L-RISKS.md` — live risks register.
11. Read `cloud-evidence/docs/ADDITIONAL-LOOPS-AUDIT.md §2 LOOP-L` — original audit (cite verbatim in CHANGELOG).
12. Begin implementation; update Implementation log section as you go.

---
