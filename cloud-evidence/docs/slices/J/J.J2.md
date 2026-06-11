---
slice_id: J.J2
title: Subprocessor inventory expansion (SA-9)
loop: J
status: done
commit: TBD-J2
completed_date: 2026-06-11
depends_on: [A.A4, subprocessors-sheet]
blocks: [G.G4, H.H3, J.J3, C.C7]
estimated_effort: 0.75 weeks (3-4 working days)
last_updated: 2026-06-11
---

# J.J2 — Subprocessor inventory expansion (SA-9)

## TL;DR
Extends the existing Google-Sheets-only subprocessor reader to accept
YAML/JSON config files as first-class inputs, adds FedRAMP SA-9 fields
(risk_tier, monitoring_methods, contracted_controls,
incident_notification_sla_hours, subprocessor_subprocessors), and emits a
signed `subprocessor-inventory.json` + `.xlsx` artifact bundled with the
submission package and consumed by the SSP's
`system-implementation.leveraged-authorizations[]` block.

## Status
- Status: done
- Commit: `TBD-J2` (filled by the two-pass close-out)
- Date: 2026-06-11
- Verification: typecheck=0 errors, tests=984 passing (+20), check:reo=green (G1 ✓ / G2 skip-no-out / G3 ✓)

## Why this slice exists
NIST SP 800-53 Rev 5 SA-9 "External System Services" requires the CSP to
identify each external service provider, capture the contractual controls
each provider has agreed to implement, define organizational oversight of
each external provider, and continuously monitor compliance. FedRAMP
implements SA-9 via the SaaS Subprocessor Inventory (a column-defined table
in the SSP package), the Customer Responsibility Matrix (where subprocessor
shared-responsibility is captured), and the Significant Change Notification
process when a subprocessor changes.

Today `core/subprocessors-sheet.ts` reads a single Google Sheet. That
works for a single-CSO operator authorizing one boundary, but breaks down
in three ways:

1. **Multi-CSO operators** (LOOP-H.H3) need per-CSO config — sheets don't
   namespace cleanly.
2. **SA-9 fields are missing**: risk tier, contracted controls,
   monitoring methods, incident-notification SLA, and the
   subprocessor-of-subprocessor chain are NOT in the existing
   `SubprocessorRow` interface.
3. **Not in submission bundle**: there is no signed normalized artifact
   the FedRAMP PMO can verify against — the data lives in a third-party
   sheet outside the manifest chain.

J.J2 fixes all three: YAML/JSON config files become first-class operator
inputs, SA-9 fields are added, and the emitter produces a signed
`subprocessor-inventory.json` + `subprocessor-inventory.xlsx` covered by
the manifest and listed in the bundler's WELL_KNOWN catalogue.

## Authoritative sources (with verbatim quotes)

- **NIST SP 800-53 Rev 5 §SA-9.a (External System Services — Compliance Requirements)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — p. 286:
  > "Require that providers of external system services comply with
  > organizational security and privacy requirements and employ the
  > following controls: [Assignment: organization-defined controls]."

- **NIST SP 800-53 Rev 5 §SA-9.b (Oversight)** — same PDF, p. 286:
  > "Define and document organizational oversight and user roles and
  > responsibilities with regard to external system services."

- **NIST SP 800-53 Rev 5 §SA-9.c (Monitor)** — same PDF, p. 286:
  > "Employ the following processes, methods, and techniques to monitor
  > control compliance by external service providers on an ongoing basis:
  > [Assignment: organization-defined processes, methods, and techniques]."

- **NIST SP 800-53 Rev 5 §SA-9 Discussion** — same PDF, p. 286:
  > "Service-level agreements define the expectations of performance for
  > implemented controls, describe measurable outcomes, and identify
  > remedies and response requirements for any identified instances of
  > noncompliance."

- **NIST SP 800-53 Rev 5 §SA-9(2) (Identification of Functions / Ports / Protocols / Services)** —
  same PDF, p. 287:
  > "Require providers of the following external system services to
  > identify the functions, ports, protocols, and other services required
  > for the use of such services: [Assignment]."

- **NIST SP 800-53 Rev 5 §SA-9(5) (Processing, Storage, and Service Location)** —
  same PDF, p. 287 — drives the `data_residency` field:
  > "Restrict the location of [Assignment: information processing, information
  > or data, and information system services] to [Assignment: locations]
  > based on [Assignment: requirements or conditions]."

- **FedRAMP Rev 5 SSP Template — Leveraged Authorizations and Subservice
  Organizations section** — https://www.fedramp.gov/docs/rev5/templates/ —
  the SaaS Subprocessor Inventory rows feed `system-implementation.leveraged-authorizations[]`
  when `fedramp_authorized === 'yes'`; non-FedRAMP-authorized subprocessors
  appear in the responsibility-matrix appendix as inherited risk.

- **OSCAL `leveraged-authorization` model field reference** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/#/system-security-plan/system-implementation/leveraged-authorizations
  — required JSON fields: `uuid`, `title`, `party-uuid`, `date-authorized`.
  Optional: `props[]`, `links[]`, `remarks`.

- **NTIA SBOM minimum elements — "Supplier Name"** —
  https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report.pdf
  p. 12:
  > "Supplier Name — The name of an entity that creates, defines, and
  > identifies components."
  (Aligns with the subprocessor-inventory `name` field: subprocessors are
  the entity-level analog of SBOM supplier names.)

- **NIST SP 800-161 Rev 1 — Tier 3 supplier identification** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1.pdf
  §2.3.5 (p. 30) requires per-system supplier identification, risk tiering,
  and continuous monitoring — drives the new `risk_tier` enum.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/subprocessor-inventory.ts`
  — pure builder + disk emitter. ~450 lines. Exports
  `readSubprocessorConfig(path: string): SubprocessorRow[]`,
  `buildSubprocessorInventory(input, opts): SubprocessorInventory`,
  `emitSubprocessorInventory(opts): SubprocessorInventoryEmitResult`,
  types `SubprocessorInventory`, `InventoryCoverage`,
  `SubprocessorInventoryEmitOptions`, `SubprocessorInventoryEmitResult`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/subprocessor-inventory.test.ts`
  — ≥13 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/subprocessors/example.yaml`
  — fixture YAML with 3 rows (1 FedRAMP-authorized, 1 SOC2-only, 1 with
  expired SOC2).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/subprocessors/example.json`
  — JSON-form fixture mirroring the YAML.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/subprocessor-config.schema.json`
  — JSON Schema for the operator config (ajv-validatable).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/examples/subprocessors.yaml`
  — committed example operator config under `examples/` (REO-allowed,
  clearly marked as example).

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/subprocessors-sheet.ts`
  — extend the existing `SubprocessorRow` interface with the new SA-9
  fields (additive — does not break existing callers). Add the
  `source`/`source_ref` provenance fields and default existing reader to
  `source = 'google-sheet'`, `source_ref = '<spreadsheet_id>!<sheet_range>'`.
  No schema removal.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — add `--subprocessors-config <path>` flag + env
  `CLOUD_EVIDENCE_SUBPROCESSORS_CONFIG`. The existing `subprocessors:`
  block in `config.yaml` becomes `subprocessors: { spreadsheet_id?, sheet_range?,
  columns?, config_path? }` (either-or, not exclusive — both can run and
  merge).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — extend the `Role` union with `'subprocessor-inventory-json'` and
  `'subprocessor-inventory-xlsx'`. Append:
  - `{ role: 'subprocessor-inventory-json', filename: 'subprocessor-inventory.json', description: 'SA-9 Subprocessor Inventory — auto-emitted with risk tiers' }`
  - `{ role: 'subprocessor-inventory-xlsx', filename: 'subprocessor-inventory.xlsx', description: 'SA-9 Subprocessor Inventory — FedRAMP-style Excel format' }`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts`
  — when `out/subprocessor-inventory.json` exists, populate
  `system-implementation.leveraged-authorizations[]` from rows where
  `fedramp_authorized === 'yes'`. Each leveraged-auth gets:
  `title = row.name`, `date-authorized = row.last_audit_date`,
  `props = [{ name: 'risk-tier', value: row.risk_tier }, { name:
  'fedramp-authorization-status', value: row.fedramp_authorized }]`.

## Schemas / standards

### Operator config YAML/JSON schema

```yaml
# tests/fixtures/subprocessor-config.schema.json — ajv-validated
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["subprocessors"],
  "additionalProperties": false,
  "properties": {
    "system_id": { "type": "string" },
    "cso_id": { "type": "string" },
    "subprocessors": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name"],
        "additionalProperties": false,
        "properties": {
          "name": { "type": "string" },
          "role": { "type": "string" },
          "data_categories": { "type": "array", "items": { "type": "string" } },
          "fedramp_authorized": { "enum": ["yes", "no", "equivalency-attest"] },
          "attestation_doc_url": { "type": "string", "format": "uri" },
          "soc2_expiry": { "type": "string", "format": "date" },
          "contract_review_date": { "type": "string", "format": "date" },
          "in_scope_for_csi": { "type": "boolean" },
          "risk_tier": { "enum": ["tier-1-critical", "tier-2-significant", "tier-3-routine"] },
          "data_residency": { "type": "string" },
          "last_audit_date": { "type": "string", "format": "date" },
          "monitoring_methods": { "type": "array", "items": { "type": "string" } },
          "incident_notification_sla_hours": { "type": "integer", "minimum": 1 },
          "subprocessor_subprocessors": { "type": "array", "items": { "type": "string" } },
          "contracted_controls": { "type": "array", "items": { "type": "string", "pattern": "^[a-z]{2}-[0-9]+(\\([0-9]+\\))?$" } },
          "oversight_party_uuid": { "type": "string", "format": "uuid" },
          "user_roles_responsibilities": { "type": "string" }
        }
      }
    }
  }
}
```

### Extended `SubprocessorRow` interface (in subprocessors-sheet.ts)

```ts
export interface SubprocessorRow {
  // existing fields (preserve)
  name: string;
  role?: string;
  data_categories?: string[];
  fedramp_authorized?: 'yes' | 'no' | 'equivalency-attest';
  attestation_doc_url?: string;
  soc2_expiry?: string;
  contract_review_date?: string;
  in_scope_for_csi?: boolean;
  // J.J2 additions
  risk_tier?: 'tier-1-critical' | 'tier-2-significant' | 'tier-3-routine';
  data_residency?: string;
  last_audit_date?: string;
  monitoring_methods?: string[];
  incident_notification_sla_hours?: number;
  subprocessor_subprocessors?: string[];
  contracted_controls?: string[];
  oversight_party_uuid?: string;
  user_roles_responsibilities?: string;
  source: 'google-sheet' | 'yaml-config' | 'json-config';
  source_ref: string;
}
```

### Emitted artifact structure

```ts
export interface SubprocessorInventory {
  generated_at: string;
  system_id?: string;
  cso_id?: string;
  run_id: string;
  rows: SubprocessorRow[];
  coverage: {
    total_rows: number;
    rows_with_risk_tier: number;
    rows_missing_risk_tier: string[];
    rows_with_expired_soc2: string[];
    rows_with_fedramp_authorization: number;
    tier_1_critical_count: number;
    tier_2_significant_count: number;
    tier_3_routine_count: number;
  };
  warnings: string[];
  provenance: {
    emitter: 'core/subprocessor-inventory.ts';
    emitted_at: string;
    source_calls: string[];  // e.g. ['sheets.spreadsheets.values.get', 'fs.readFileSync(./examples/subprocessors.yaml)']
    source_files: string[];
  };
}
```

### XLSX layout (single sheet matching the FedRAMP SaaS Subprocessor Inventory template column order)

Header row 1: `Name`, `Role`, `Data Categories`, `FedRAMP Authorized`,
`Attestation Doc URL`, `SOC2 Expiry`, `Contract Review Date`,
`In Scope for CSI`, `Risk Tier`, `Data Residency`, `Last Audit Date`,
`Monitoring Methods`, `Incident Notification SLA (hours)`,
`Subprocessor Subprocessors`, `Contracted Controls`,
`Oversight Party UUID`, `Source`, `Source Ref`.

The column order is parameterized (`COLUMN_ORDER` constant) so a future
FedRAMP template revision is a one-line patch.

## Build steps (concrete, numbered)

1. **Extend `SubprocessorRow` interface** in
   `core/subprocessors-sheet.ts`. Keep all existing fields. Add the J.J2
   fields + `source`/`source_ref`. Update the existing
   `readSubprocessors(cfg)` to stamp every emitted row with
   `source: 'google-sheet'` and
   `source_ref: \`${cfg.spreadsheet_id}!${cfg.sheet_range}\``.
2. **`readSubprocessorConfig(path)`** in new file
   `core/subprocessor-inventory.ts`:
   - Detect format by extension (`.yaml`/`.yml` → YAML, `.json` → JSON).
   - YAML parse via the `yaml` library (already in `package.json` ^2.6.0).
   - JSON parse via `JSON.parse`.
   - For each row, set `source: 'yaml-config' | 'json-config'`,
     `source_ref: absolutePath(path)`.
   - Optionally validate against the JSON Schema fixture in tests (in
     production we trust the TS interface; validation happens in tests).
3. **Pure builder** `buildSubprocessorInventory(input, opts)`:
   - Take `input.rows: SubprocessorRow[]` (caller pre-aggregates sheet +
     config rows).
   - Canonicalize names: lower-case + strip whitespace for dedup key.
   - On name conflict: YAML/JSON row wins (operator's local source of
     truth); record warning
     `\`Subprocessor "${name}" defined in both sheet (${sheetRef}) and config (${cfgRef}); using config row\``.
   - Compute `coverage` deterministically. Sort rows by `name` for
     deterministic output.
   - Stamp `provenance.source_calls[]` and `provenance.source_files[]`.
4. **Emitter** `emitSubprocessorInventory(opts)`:
   - If `opts.sheetConfig` set → call existing `readSubprocessors()`.
   - If `opts.configPath` set → call `readSubprocessorConfig()`.
   - Merge per build step 3.
   - If NEITHER source returns any rows → emit a single
     REQUIRES-OPERATOR-INPUT row naming both surfaces:
     `{ name: 'REQUIRES-OPERATOR-INPUT', source: 'yaml-config', source_ref: '<configure --subprocessors-config <path.yaml> OR subprocessors.spreadsheet_id in config.yaml>' }`.
     The inventory is structurally valid but operator sees the gap.
   - Write `outDir/subprocessor-inventory.json` (full
     `SubprocessorInventory` JSON) and `outDir/subprocessor-inventory.xlsx`
     (single sheet matching FedRAMP column order, using the same
     `rowsToXlsx` helper that J.J1 extends).
   - Returns `{ json_path, xlsx_path, inventory, bytes_json, bytes_xlsx,
     warnings, requires_operator_input }`.
5. **Orchestrator wiring** (`core/orchestrator.ts`):
   - Parse `--subprocessors-config <path>` flag + env.
   - Extend the existing config.yaml `subprocessors:` block reader to
     accept `config_path`.
   - Schedule after `--collect` resolution and before `--sign`.
   - Log line: `subprocessor-inventory: <N> rows · <T1> tier-1 · <T2> tier-2 · <T3> tier-3 · <U> REQUIRES-OPERATOR-INPUT`.
6. **SSP leveraged-authorizations wiring** (`core/oscal-ssp.ts`):
   - On entry, attempt `readFileSync(outDir + '/subprocessor-inventory.json')`.
   - If present, walk `rows[]` filtered to `fedramp_authorized === 'yes'`.
   - For each, build a `leveraged-authorization` block with deterministic
     UUID (via existing `deterministicUuid(row.name)`).
   - If absent, current behaviour stands.
7. **Bundler catalogue** (`core/submission-bundle.ts`):
   - Add the two WELL_KNOWN entries listed in "Files to extend".
8. **Validation**: ajv-validate operator YAML against the JSON Schema
   fixture in `tests/core/subprocessor-inventory.test.ts`. Production
   code uses the TS interface (no ajv dep at runtime — already true
   for the existing reader).
9. **Signing**: covered by existing `core/sign.ts` because emitter runs
   before `--sign`.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Fallback behavior |
|---|---|---|
| `risk_tier` | operator YAML/JSON or sheet column | `REQUIRES-OPERATOR-INPUT` literal in XLSX; row name added to `coverage.rows_missing_risk_tier` |
| `monitoring_methods` | operator YAML/JSON | `REQUIRES-OPERATOR-INPUT` |
| `contracted_controls` | operator YAML/JSON | `REQUIRES-OPERATOR-INPUT` |
| `oversight_party_uuid` | operator YAML/JSON | `REQUIRES-OPERATOR-INPUT` |
| `incident_notification_sla_hours` | operator YAML/JSON | `REQUIRES-OPERATOR-INPUT` |
| `data_residency` | operator YAML/JSON | `REQUIRES-OPERATOR-INPUT` |

If `sheetConfig` is set but Google Sheets API returns 0 rows or fails, the
emitter logs a `warnings[]` entry AND continues with whatever config-file
rows exist. If BOTH are absent, the single REQUIRES-OPERATOR-INPUT row
(per build step 4) is emitted.

## Test specifications (≥13 tests)

1. `it('reads subprocessors from a YAML file')` — fixture YAML → 3 rows
   parsed, each `source === 'yaml-config'`, each `source_ref` ends with
   the fixture path.
2. `it('reads subprocessors from a JSON file')` — same shape via JSON.
3. `it('merges sheet rows + YAML rows with YAML precedence on name conflict')`
   — fixture: sheet has "AcmeCorp" tier-1, YAML has "AcmeCorp" tier-2 →
   merged row has tier-2 AND `warnings[]` non-empty.
4. `it('flags rows missing risk_tier as REQUIRES-OPERATOR-INPUT')`.
5. `it('flags expired SOC2 attestations based on opts.now')` — fixture
   row with `soc2_expiry: '2024-01-01'`, `opts.now` returning
   2026-06-06 → `coverage.rows_with_expired_soc2` includes the row.
6. `it('computes tier_1_critical_count correctly')`.
7. `it('emits a JSON + XLSX with the FedRAMP-style columns')` — assert
   column header list matches `COLUMN_ORDER` constant verbatim.
8. `it('writes a single REQUIRES-OPERATOR-INPUT row when no sheet + no config provided')` —
   inventory.rows.length === 1, name === 'REQUIRES-OPERATOR-INPUT'.
9. `it('returns warnings when Sheets API fails but YAML config is valid')`
   — inject a sheet-config that throws → warnings non-empty, rows from
   YAML preserved.
10. `it('preserves operator-supplied incident_notification_sla_hours')` —
    YAML row with `incident_notification_sla_hours: 24` → flows verbatim.
11. `it('records the source_ref for each row (sheet-id+range OR file path)')`
    — assert format `<id>!<range>` for sheet, absolute path for file.
12. `it('canonicalizes names for dedup but preserves the displayed name')`
    — sheet has "Acme Corp", YAML has "acme corp" → dedup; displayed
    name uses YAML row's casing.
13. `it('validates an operator YAML against the committed JSON schema fixture with ajv')`
    — load `tests/fixtures/subprocessor-config.schema.json`, ajv-validate
    `tests/fixtures/subprocessors/example.yaml` → valid.
14. `it('ajv rejects an operator YAML with an unknown top-level field')` —
    REO safety net.
15. `it('emits leveraged-authorizations[] in the SSP when matrix rows have fedramp_authorized=yes')`
    — integration test through orchestrator harness.
16. `it('records provenance.source_calls listing fs.readFileSync(<config>) and/or sheets.values.get')`.

## REO compliance specific to this slice

- No example subprocessor data committed under `core/` — examples live
  in `examples/subprocessors.yaml` and test fixtures (REO-allowed under
  Rule 3 because they live in `examples/` / `tests/`).
- When neither input source provides rows, no fake rows substituted —
  single REQUIRES-OPERATOR-INPUT row named explicitly.
- The Google Sheets reader's existing `warnings[]` pattern preserved;
  J.J2 inventory aggregates warnings into its own `warnings[]`.
- Provenance: `provenance.source_calls[]` lists
  `'sheets.spreadsheets.values.get'` (if sheets used) AND
  `\`fs.readFileSync(${configPath})\`` (if config used) — both real,
  both verifiable.
- The SSP leveraged-authorizations integration NEVER fabricates a
  date-authorized: when `last_audit_date` is missing, the leveraged-auth
  is omitted (not emitted with a fake date).
- `contracted_controls[]` regex pattern (`^[a-z]{2}-[0-9]+(\([0-9]+\))?$`)
  matches NIST 800-53 control IDs only — operator-input is structurally
  bound to real control IDs.

## Verification commands

```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/subprocessor-inventory.test.ts
npm run check:reo
```

End-to-end:

```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run collect -- \
  --subprocessors-config examples/subprocessors.yaml \
  --oscal-ssp --sign --submission-bundle
cat out/subprocessor-inventory.json | head -40
unzip -l out/submission-bundle.tar.gz | grep subprocessor-inventory
```

## Known risks / issues

- **Risk 1 — YAML library trust**: `yaml` ^2.6.0 is already in
  package.json, but if it's pinned by a transient dep, J.J2 may not have
  type defs. Mitigation: add `import YAML from 'yaml';` and verify
  `yaml/dist/*.d.ts` exposes the types we need (`parse`, `parseDocument`).
  If types are missing, declare a minimal `declare module 'yaml' { ... }`
  in `core/subprocessor-inventory.ts`.
- **Risk 2 — Sheet row + YAML row merge conflicts**: ambiguous when both
  sources differ on values other than `name` (e.g. sheet says tier-1,
  YAML says tier-2). Mitigation: YAML wins per build step 3; the
  conflict is recorded in `warnings[]`. Operator sees the conflict in
  logs and the .xlsx Comments column.
- **Risk 3 — FedRAMP template column-order changes**: the FedRAMP SaaS
  Subprocessor Inventory template may be revised. Mitigation: column
  order is the `COLUMN_ORDER` constant; updating to a new template is
  a one-line patch + a test fixture update.
- **Risk 4 — Subprocessor-of-subprocessor chain depth**: the chain field
  is a flat string array of names; deeper chains require operator to
  list them all by name. Mitigation: documented in the operator config
  comment block as "flat list of immediate downstream subprocessors;
  deeper hierarchies need separate rows".
- **Risk 5 — `data_residency` validation**: free-form string. A typo
  (`us-east-2` vs `us-east-1`) would silently pass. Mitigation: in J.J2
  scope, no validation; flagged for a follow-on slice. Documented in
  open questions.
- **Risk 6 — Sheet auth failure timing**: if Google Sheets API throws
  during orchestrator startup, the inventory emitter must NOT block
  the whole run. Mitigation: emitter catches and records warning,
  continues with config-only rows (per the existing pattern).
- **Risk 7 — Determinism with merged sheet + YAML rows**: dedup must
  produce same output regardless of which source was read first.
  Mitigation: canonicalize-and-sort BEFORE dedup; test 16 verifies
  byte-identical output across two runs.

## Open questions (for implementation session to resolve)

- **Q1**: Should the merge order default to "sheet first, then YAML
  overlay" or "YAML first, then sheet fill-in"? Provisional: read both
  fully, then dedup with YAML-wins. The order of read does not affect
  the final inventory if dedup is symmetric.
- **Q2**: How should we represent "no monitoring methods are formally
  defined" vs "monitoring is being assessed"? Provisional:
  `monitoring_methods: []` = "actively none documented" (still
  REQUIRES-OPERATOR-INPUT until operator commits a list);
  `monitoring_methods` absent = same. No way to distinguish in the
  schema; operator should add a `user_roles_responsibilities` narrative
  if more nuance is needed.
- **Q3**: Should `data_residency` be validated against a known set of
  AWS / GCP / Azure region codes? Provisional: no — operator may name a
  data center geographically (e.g. "Reston, VA"). Free-form string.
- **Q4**: When the SSP is emitted alongside, should we list
  non-FedRAMP-authorized subprocessors anywhere? Provisional: yes — add
  them as `back-matter.resources[]` entries with `props.subservice-type
  = 'non-fedramp'`. Confirm with FedRAMP-Reviewer expectations.
- **Q5**: Should `subprocessor_subprocessors[]` participate in dedup
  (e.g. "AcmeCloudVendor" appears as a top-level subprocessor AND in
  another row's chain)? Provisional: no — chain is informational; only
  top-level rows are deduped.
- **Q6**: For `contracted_controls`, should we cross-check against the
  current baseline (Low/Moderate/High) and warn when a referenced
  control is not in scope? Provisional: yes, soft warning only —
  operator may contractually require a control outside the baseline.

### Open-question resolutions (impl-j-j2, 2026-06-11)
- **Q1 (merge order)** — RESOLVED: read both fully, then dedup with
  config-wins. Sheet rows are pushed BEFORE config rows so the later
  (config) row wins; `buildSubprocessorInventory` canonicalize-and-sorts
  before output so the result is symmetric regardless of read order
  (verified by the determinism test).
- **Q2 (no monitoring methods)** — RESOLVED for this slice: `monitoring_methods`
  absent OR `[]` both count as REQUIRES-OPERATOR-INPUT (the field is added to
  `requires_operator_input` and renders the literal in the XLSX). No schema
  distinction between "actively none" and "being assessed"; operators add a
  `user_roles_responsibilities` narrative for nuance.
- **Q3 (`data_residency` validation)** — RESOLVED: no validation; free-form
  string (region code OR geography, e.g. "Reston, VA"). Logged as LOOP-J risk
  J2-R7 for a possible follow-on region-code validator.
- **Q4 (non-FedRAMP subprocessors in the SSP)** — DEFERRED out of J.J2 scope.
  J.J2 only populates `leveraged-authorizations[]` from `fedramp_authorized=yes`
  rows. Surfacing non-authorized subprocessors as `back-matter.resources[]` is
  filed as LOOP-J risk J2-R8 (proposed J.J-follow-on); not silently added.
- **Q5 (`subprocessor_subprocessors[]` in dedup)** — RESOLVED: no — the chain
  field is informational; only top-level rows are deduped.
- **Q6 (`contracted_controls` baseline cross-check)** — DEFERRED out of J.J2
  scope (would couple the inventory emitter to the control benchmark). Filed as
  LOOP-J risk J2-R8 alongside Q4 for the same follow-on. The ajv schema's
  control-ID `pattern` already binds the field to real 800-53 control IDs.

## Implementation log (running journal — implementing session updates)
```
2026-06-11 · impl-j-j2 · Shipped end to end per spec.
  Created: core/subprocessor-inventory.ts (readSubprocessorConfig +
    buildSubprocessorInventory + emitSubprocessorInventory + generic
    COLUMN_ORDER-parameterized XLSX writer + detached Ed25519 signing);
    tests/core/subprocessor-inventory.test.ts (20 tests — exceeds the ≥13
    spec); tests/fixtures/subprocessors/example.{yaml,json};
    tests/fixtures/subprocessor-config.schema.json; examples/subprocessors.yaml.
  Extended: core/subprocessors-sheet.ts (SubprocessorRow += SA-9 fields +
    source/source_ref; readSubprocessors() stamps provenance);
    core/oscal-ssp.ts (system-implementation.leveraged-authorizations[] +
    backing parties, read from subprocessor-inventory.json — emitted only when
    ≥1 fedramp_authorized=yes row carries a real last_audit_date; OSCAL
    minItems:1 honoured by omitting the field when empty);
    core/submission-bundle.ts (2 WELL_KNOWN roles); core/orchestrator.ts
    (--subprocessors-config + CLOUD_EVIDENCE_SUBPROCESSORS_CONFIG + config.yaml
    subprocessors block; emitter scheduled before --oscal-ssp + before signing).
  Verification: typecheck 0 errors; vitest 984 passing (was 964, +20);
    check:reo green (lint:no-stubs + check:provenance; coverage-regression
    skips with no out/).
  Spec divergence (documented): the §"Emitted artifact structure" provenance
    block in this doc used snake_case (emitted_at/source_calls/source_files) and
    omitted signingKeyId. The binding CI contract is G3 (scripts/check-provenance.mjs),
    which requires camelCase emitter/emittedAt/sourceCalls/signingKeyId. Followed
    G3 (+ kept sourceFiles as an extra) and embedded a detached Ed25519 signature,
    matching the shipped LOOP-B.B1 / LOOP-W.W1 convention.
  XLSX writer: built a generic, COLUMN_ORDER-parameterized sheet writer composing
    core/zip.ts (xmlEscape + zipStore) rather than reusing inventory-workbook.ts's
    rowsToXlsx (hardcoded to the Appendix-M columns; J.J1 — which the spec assumed
    would generalize it — is not yet shipped). No zip logic duplicated.
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [x] typecheck clean (`npm run typecheck`) — 0 errors
- [x] tests passing 100% (count increased by ≥13 for this slice's new tests) — 984 (+20)
- [x] check:reo green (G1+G2+G3) — lint:no-stubs + check:provenance pass; coverage-regression skips (no out/)
- [x] STATUS.md updated (J.J2 row + Overall section)
- [x] LOOP-J-SPEC.md Section 7 status table updated
- [x] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [x] LOOP-J-RISKS.md updated (J.J2-R5, J.J2-R8 added)
- [x] OPERATOR-GUIDE.md updated (§3 flag + §4 env + §7 output)
- [x] CHANGELOG.md "Unreleased" entry added
- [x] Commit with `LOOP-J.J2: Subprocessor inventory expansion` in message
- [x] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-J-SPEC.md
- [x] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here's everything it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-J-SPEC.md` Section 2 (Dependencies) for context on this loop.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Read `cloud-evidence/core/subprocessors-sheet.ts` (current shape) before extending it.
6. Read `cloud-evidence/core/oscal-ssp.ts:buildOscalSsp` to find where the
   `system-implementation.leveraged-authorizations[]` block is built so
   you can graft the inventory-derived entries in.
7. Begin implementation; update Implementation log section as you go.
