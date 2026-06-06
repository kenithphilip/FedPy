---
slice_id: B.B5
title: Central Risk Register (RA-3 aggregated deliverable, JSON + XLSX + tracker UI)
loop: B
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A4, B.B1, B.B2, B.B3, B.B4]
blocks: [C.C7, I.I1, E.E1]
estimated_effort: 3-4 working days
last_updated: 2026-06-06
---

# B.B5 — Central Risk Register (RA-3 aggregated deliverable, JSON + XLSX + tracker UI)

## TL;DR
Aggregate per-finding risks (B.B1+B.B2), signed risk acceptances (B.B3), compensating controls (B.B4), and operator-entered organisational risks (new tracker `organisational_risks` table) into a single `out/risk-register.json` + `out/risk-register.xlsx` artifact. Likelihood/impact bands use NIST SP 800-30 Rev 1 §3.2 qualitative scale ("Very Low" through "Very High") verbatim. The artifact directly satisfies NIST SP 800-53 Rev 5 RA-3(a) "conduct a risk assessment" requirement and pre-fills the FedRAMP Risk Management Strategy document (LOOP-C.C7).

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
B.B1 produces per-finding numeric scores. B.B3 records signed risk acceptances. B.B4 maintains compensating controls. There is still NO single, exec-readable artifact that:
- Lists EVERY risk affecting the system (finding-sourced + acceptance-sourced + operator-sourced organisational risks).
- Uses the NIST SP 800-30 qualitative scale (likelihood × impact = inherent risk) the AO + 3PAO expect.
- Reflects WHICH compensating controls reduce residual risk (and by how much).
- Has owner + review date columns the AO and CISO sign on.
- Exports cleanly to XLSX for board-level distribution.

Without this artifact, RA-3 ("Conduct a risk assessment") and the FedRAMP Risk Management Strategy (RMS) deliverable have nothing to point to. The SSP narrative cannot truthfully cite the risk assessment. The executive dashboard (LOOP-I.I1) cannot show a "top 10 risks" panel that aggregates findings AND organisational risks. B.B5 closes all three gaps with a single aggregator + XLSX emitter + tracker UI for the organisational risks.

## Authoritative sources (with verbatim quotes)
- https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf — **NIST SP 800-30 Rev 1, §3.2 (Conducting the Assessment), Appendix G (Likelihood)**:
  > "Likelihood of Threat Event Initiation (Adversarial)" + "Likelihood of Threat Event Resulting in Adverse Impact" combine per §3.2 to "Overall Likelihood." Qualitative scale: **Very Low, Low, Moderate, High, Very High** (Appendix G, Table G-2).
  > "Step 2: Conduct the Risk Assessment. Determine the likelihood of occurrence considering: (i) the likelihood that threat events of concern will be initiated by adversarial sources or will occur as a result of non-adversarial sources; and (ii) the likelihood that initiated threat events will result in adverse impacts."
  B.B5 reuses these tokens VERBATIM in the schema enums + XLSX column values.

- https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf — **NIST SP 800-30 Rev 1, Appendix H (Impact)**, Table H-2:
  > "The level of impact from a threat event is the magnitude of harm that can be expected to result from the consequences of unauthorized disclosure, modification, loss, or destruction of information."
  Same 5-band qualitative scale used for the `impact` column.

- https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf — **NIST SP 800-30 Rev 1, Appendix I (Risk)**, Table I-2:
  > "Risk is a function of the likelihood of an event and its impact."
  Inherent risk = combine(likelihood, impact); residual risk = inherent reduced by compensating controls.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, RA-3 (Risk Assessment)**:
  > "Conduct a risk assessment, including: identifying threats to and vulnerabilities in the system; the likelihood and magnitude of harm from unauthorized access, use, disclosure, disruption, modification, or destruction of the system, the information it processes, stores, or transmits, and any related information; and determining the likelihood and impact of adverse effects on individuals arising from the processing of personally identifiable information."
  > "Document risk assessment results in [Selection: security and privacy plans; risk assessment report; [Assignment: organization-defined document]]."
  B.B5's `risk-register.json` + `risk-register.xlsx` IS the documented result.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-39.pdf — **NIST SP 800-39 (Managing Information Security Risk), §2.3 (Risk Management Hierarchy)**:
  > "Tier 1 — Organization Level, Tier 2 — Mission/Business Process Level, Tier 3 — Information System Level."
  B.B5's `category` enum (organisational, business-process, supply-chain, third-party, contractual, operational, system) maps to these tiers.

- https://www.fedramp.gov/assets/resources/documents/CSP_Risk_Management_Strategy_Template.docx — **FedRAMP Risk Management Strategy Template**:
  Lists the risk register as a required input artifact. LOOP-C.C7 will consume `risk-register.json` to pre-fill the document.

- https://www.iso.org/standard/65694.html — **ISO 31000:2018 (Risk Management Guidelines)**:
  Compatible framework; `treatment` enum (accept / mitigate / transfer / avoid) follows ISO 31000:2018 §6.5.3 nomenclature ("Risk treatment options").

- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/ — **OSCAL POA&M v1.1.2**:
  Per-finding entries in B.B5 reference back to OSCAL `poam-item.uuid` and `risk.uuid` so cross-traceability is preserved.

## Files to create (exact paths)

### cloud-evidence side
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/risk-register.ts` — pure aggregator:
  - `buildRiskRegister(inputs: RiskRegisterInputs): RiskRegisterEntry[]`
  - `emitRiskRegister(opts: RiskRegisterEmitOptions): Promise<RiskRegisterEmitResult>` (writes JSON + invokes XLSX renderer).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/risk-register-xlsx.ts` — pure-JS xlsx renderer (mirrors `core/inventory-workbook.ts` and `core/subprocessors-sheet.ts` pattern — no SheetJS dependency).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/organisational-risk-reader.ts` — read-only client pulling `organisational_risks` from tracker; writes `out/.organisational-risks.json` snapshot.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/risk-register.test.ts` — aggregator tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/risk-register-xlsx.test.ts` — XLSX roundtrip + structure tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/organisational-risk-reader.test.ts` — reader tests.

### Tracker side
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/risk-register.ts` — CRUD for organisational risks:
  - `POST /api/organisational-risks` — create.
  - `GET  /api/organisational-risks` — list, filter by category/status.
  - `GET  /api/organisational-risks/:uuid` — detail.
  - `PUT  /api/organisational-risks/:uuid` — update.
  - `POST /api/organisational-risks/:uuid/close` — close out a risk.
  - `GET  /api/risk-register` — aggregated read endpoint (joins findings via cached scores + acceptances + CCs + organisational risks).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/risk-register.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/RiskRegister.tsx` — list view + "Add organisational risk" CTA + "Export to XLSX" button (calls a server-side render via the same XLSX module).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/OrganisationalRiskCreate.tsx` — create form.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/OrganisationalRiskDetail.tsx` — detail + update + close-out flow.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/lib/risk-register-api.ts`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/RiskRegister.test.tsx`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/OrganisationalRiskCreate.test.tsx`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/OrganisationalRiskDetail.test.tsx`.

## Files to extend

### Tracker
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — append `organisational_risks` table.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount route:
  ```ts
  app.use('/api/organisational-risks', requireAuth, organisationalRisksRouter);
  app.use('/api/risk-register', requireAuth, riskRegisterRouter);
  ```
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add routes:
  ```tsx
  <Route path="/risk-register" element={<RiskRegister/>} />
  <Route path="/risk-register/organisational/new" element={<OrganisationalRiskCreate/>} />
  <Route path="/risk-register/organisational/:uuid" element={<OrganisationalRiskDetail/>} />
  ```
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/components/NavBar.tsx` — add "Risk Register" nav link.

### cloud-evidence
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`:
  - New `--risk-register` flag + env `CLOUD_EVIDENCE_RISK_REGISTER`.
  - New `--pull-organisational-risks <tracker-url>` flag (re-uses `CLOUD_EVIDENCE_TRACKER_URL`).
  - Runs AFTER `--oscal-poam` so it can read the just-emitted POA&M. Documented order in `orchestrator.ts`: collect → score (B.B1) → POA&M (with B.B2 deadlines + B.B3 acceptance status + B.B4 remediations) → AR → bundle → risk-register (B.B5) → sign → timestamp.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add roles:
  - `risk-register-json` (filename `risk-register.json`)
  - `risk-register-xlsx` (filename `risk-register.xlsx`)
  - `organisational-risks-snapshot` (filename `.organisational-risks.json`)

## Schemas / standards

### SQLite table (appended to `tracker/server/schema.sql`)

```sql
CREATE TABLE IF NOT EXISTS organisational_risks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,                             -- 5-200 chars
  description TEXT NOT NULL,                       -- ≥ 100 chars
  category TEXT NOT NULL CHECK (category IN ('third-party','supply-chain','environmental','contractual','operational','organisational','other')),
  likelihood TEXT NOT NULL CHECK (likelihood IN ('very-low','low','moderate','high','very-high')),
  impact TEXT NOT NULL CHECK (impact IN ('very-low','low','moderate','high','very-high')),
  inherent_risk TEXT NOT NULL CHECK (inherent_risk IN ('very-low','low','moderate','high','very-high')),
  residual_risk TEXT NOT NULL CHECK (residual_risk IN ('very-low','low','moderate','high','very-high')),
  treatment TEXT NOT NULL CHECK (treatment IN ('accept','mitigate','transfer','avoid')),
  owner_user_id INTEGER NOT NULL REFERENCES users(id),
  review_date TEXT NOT NULL,                       -- ISO datetime; quarterly or annual review
  nist_control_ids TEXT,                           -- JSON array, optional
  compensating_control_uuids TEXT,                 -- JSON array of B.B4 UUIDs, optional
  status TEXT NOT NULL CHECK (status IN ('open','closed')),
  closed_at TEXT,
  closed_by_user_id INTEGER REFERENCES users(id),
  closure_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_org_risk_category ON organisational_risks(category);
CREATE INDEX IF NOT EXISTS idx_org_risk_status ON organisational_risks(status);
CREATE INDEX IF NOT EXISTS idx_org_risk_review ON organisational_risks(review_date);
CREATE INDEX IF NOT EXISTS idx_org_risk_inherent ON organisational_risks(inherent_risk);
```

### Wire-format / aggregator types

```ts
// cloud-evidence/core/risk-register.ts
export type RiskBand = 'very-low' | 'low' | 'moderate' | 'high' | 'very-high';
export type RiskSource = 'finding' | 'acceptance' | 'organisational';
export type RiskTreatment = 'accept' | 'mitigate' | 'transfer' | 'avoid';

export interface RiskRegisterEntry {
  uuid: string;
  source: RiskSource;
  title: string;
  description: string;
  category: string;                                // matches OrganisationalRiskCategory or "ksi-finding"
  likelihood: RiskBand;
  impact: RiskBand;
  inherent_risk: RiskBand;
  residual_risk: RiskBand;
  treatment: RiskTreatment;
  owner: string;                                   // user name or role label
  review_date: string;                             // ISO datetime
  status: 'open' | 'closed';
  references: {
    finding_uuid?: string;
    poam_item_uuid?: string;
    risk_uuid?: string;                            // OSCAL risk.uuid
    acceptance_uuid?: string;
    organisational_risk_uuid?: string;
    compensating_control_uuids?: string[];
    nist_control_ids?: string[];
    cvss_base?: number;
    epss_score?: number;
    epss_percentile?: number;
  };
}

export interface RiskRegisterInputs {
  poamJsonPath: string;                            // out/poam.json
  riskScoresPath?: string;                         // out/risk-scores.json
  acceptancesPath?: string;                        // out/.risk-acceptances.json
  compensatingControlsPath?: string;               // out/.compensating-controls.json
  organisationalRisksPath?: string;                // out/.organisational-risks.json
  riskConfigPath?: string;                         // band-derivation thresholds
}

export interface RiskRegisterEmitOptions {
  outDir: string;
  inputs: RiskRegisterInputs;
  runId: string;
}

export interface RiskRegisterEmitResult {
  jsonPath: string;
  xlsxPath: string;
  entries_total: number;
  entries_by_source: Record<RiskSource, number>;
  open_count: number;
  high_inherent_count: number;                     // count of inherent ∈ {high, very-high}
}
```

### Band derivation (operator-tunable in `risk-config.yaml`)

From `RiskScore.epss.percentile` → likelihood:
- `≥ 0.95` → `very-high`
- `≥ 0.50` → `high`
- `≥ 0.05` → `moderate`
- `≥ 0.005` → `low`
- else → `very-low`

From `RiskScore.criticality` → impact:
- `≥ 0.90` → `very-high`
- `≥ 0.70` → `high`
- `≥ 0.40` → `moderate`
- `≥ 0.20` → `low`
- else → `very-low`

When B.B1 set `epss_source: 'REQUIRES-OPERATOR-INPUT'`, likelihood inherits the REQUIRES-OPERATOR-INPUT marker (literal token in the JSON; XLSX shows the same string). Same for criticality → impact.

Inherent risk = combine(likelihood, impact) via the standard 5×5 matrix from NIST SP 800-30 Rev 1 Appendix I, Table I-2 (verbatim values pinned in `risk-register.ts` as `INHERENT_RISK_MATRIX` constant).

Residual risk: when at least one ACTIVE compensating control is linked, drop one band (e.g. very-high → high). When acceptance status is `deviation-approved` with no CC, no reduction. When risk treatment is `accept`, residual = inherent (no reduction). When `mitigate` and at least one CC, reduce. When `transfer`/`avoid`, drop two bands (operator-tunable).

### XLSX structure (`risk-register-xlsx.ts`)

Single sheet "Risk Register" with header row at row 1, data rows from row 2:

| Col | Header | Source |
|---|---|---|
| A | Risk ID | `entry.uuid` |
| B | Source | `entry.source` |
| C | Title | `entry.title` |
| D | Category | `entry.category` |
| E | Likelihood | `entry.likelihood` (NIST 800-30 token) |
| F | Impact | `entry.impact` |
| G | Inherent Risk | `entry.inherent_risk` |
| H | Residual Risk | `entry.residual_risk` |
| I | Treatment | `entry.treatment` |
| J | Owner | `entry.owner` |
| K | Review Date | `entry.review_date` |
| L | Status | `entry.status` |
| M | Linked POA&M Item | `entry.references.poam_item_uuid` |
| N | Linked Acceptance | `entry.references.acceptance_uuid` |
| O | Compensating Controls | `entry.references.compensating_control_uuids.join(';')` |
| P | NIST Controls | `entry.references.nist_control_ids.join(';')` |
| Q | CVSS Base | `entry.references.cvss_base` |
| R | EPSS Score | `entry.references.epss_score` |
| S | EPSS Percentile | `entry.references.epss_percentile` |
| T | Description | `entry.description` (wrapped) |

Conditional formatting: rows with `inherent_risk ∈ {high, very-high}` get a red fill on column G; `residual_risk = very-high` gets bold red on H.

Render via the same pure-JS XLSX pattern as `core/inventory-workbook.ts` (no SheetJS dep). Output is OOXML-spec-compliant; SheetJS can round-trip.

## Build steps (concrete, numbered)
1. **Schema** — append `organisational_risks` to `tracker/server/schema.sql`.
2. **Server CRUD route** — write `tracker/server/routes/risk-register.ts`. Validation:
   - `title.length` ∈ [5, 200].
   - `description.length` ≥ 100.
   - `likelihood`, `impact`, `inherent_risk`, `residual_risk` ∈ NIST 800-30 enum.
   - `treatment` ∈ ISO 31000 enum.
   - `review_date` must be ≥ today + 30 days (force forward planning).
   - `nist_control_ids[]` each validates against the catalog (re-use B.B4 pattern).
   - `compensating_control_uuids[]` each exists in `compensating_controls` (cross-table check).
3. **Aggregated read endpoint** — `GET /api/risk-register` joins:
   - cached `risk-scores.json` upload (server stores latest collector run for visibility) OR computed live from `poam.json`.
   - `risk_acceptances` rows with `status='approved' AND expiration_date > now()`.
   - `compensating_controls` rows with `status='active'`.
   - `organisational_risks` rows.
   Returns a `RiskRegisterEntry[]` array.
4. **React UI**:
   - `RiskRegister.tsx` — sortable table; default sort by `inherent_risk` (very-high first). "Add organisational risk" CTA. "Export to XLSX" button calls the server-side render endpoint `GET /api/risk-register/export.xlsx`.
   - `OrganisationalRiskCreate.tsx` — form with NIST 800-30 enum dropdowns, treatment radio, owner picker, CC multi-select, review date picker.
   - `OrganisationalRiskDetail.tsx` — update + close-out flow.
5. **Reader** — `cloud-evidence/core/organisational-risk-reader.ts`:
   ```ts
   export async function pullOrganisationalRisks(
     trackerUrl: string,
     apiToken: string,
     outDir: string,
   ): Promise<OrganisationalRisk[]> { /* fetch + write .organisational-risks.json */ }
   ```
6. **Aggregator** — `cloud-evidence/core/risk-register.ts:buildRiskRegister(inputs)`:
   - For each OSCAL POA&M `risk` (read `inputs.poamJsonPath`): synthesise a RiskRegisterEntry with `source='finding'`, derive bands per the documented table, reference back to `poam_item.uuid` + `risk.uuid`.
   - For each active acceptance: emit an entry with `source='acceptance'`, treatment='accept', references include `acceptance_uuid` + linked CC UUIDs.
   - For each organisational risk: copy verbatim.
   - De-duplicate: when an acceptance covers a finding, prefer the acceptance entry (treatment='accept', explicit residual) over the finding entry (which would say 'mitigate' implicitly).
7. **JSON emit**: `out/risk-register.json` with structure:
   ```json
   {
     "provenance": { "emitter": "core/risk-register.ts", "emittedAt": "...", "sourceCalls": [...], "signingKeyId": "..." },
     "summary": { "entries_total": N, "by_source": {"finding": ..., "acceptance": ..., "organisational": ...}, "open_count": ..., "high_inherent_count": ... },
     "entries": [ RiskRegisterEntry, ... ]
   }
   ```
8. **XLSX emit** — `core/risk-register-xlsx.ts` renders the table; reuses the OOXML-compose helpers from `core/inventory-workbook.ts`. No new dependencies.
9. **Server-side XLSX export** — tracker's `GET /api/risk-register/export.xlsx` invokes the SAME XLSX module (the renderer is pure; runs in Node). Streams to client.
10. **Orchestrator wiring**: `--risk-register` flag invokes `emitRiskRegister()` AFTER POA&M emission.
11. **Bundler integration**:
    ```ts
    { role: 'risk-register-json', filename: 'risk-register.json', description: 'Aggregated risk register (LOOP-B.B5; satisfies NIST RA-3)' },
    { role: 'risk-register-xlsx', filename: 'risk-register.xlsx', description: 'Risk register XLSX export (LOOP-B.B5)' },
    { role: 'organisational-risks-snapshot', filename: '.organisational-risks.json', description: 'Operator-entered organisational risks snapshot' },
    ```
12. **Validation pass**:
    - `out/risk-register.json` provenance via `check:provenance`.
    - XLSX round-trip via SheetJS in test (`xlsx` is a dev dep).
13. **Signed + timestamped** by existing `core/sign.ts` pipeline.

## REQUIRES-OPERATOR-INPUT fields
| Field | Source | Behavior when missing |
|---|---|---|
| Organisational risks (title, description, likelihood, impact, treatment, owner, review_date) | Tracker UI | Server rejects POST; no defaults; absent rows do NOT appear in register. |
| Band-derivation thresholds (EPSS → likelihood; criticality → impact) | `risk-config.yaml` (operator-tunable) | Defaults used; documented in `risk-config.example.yaml`. |
| Per-finding entry likelihood when B.B1 set `epss_source: 'REQUIRES-OPERATOR-INPUT'` | Inherited from B.B1 | Likelihood column shows literal `REQUIRES-OPERATOR-INPUT` token in JSON + XLSX; visible, never silent. |
| Tracker URL + API token | CLI flag / env | Without snapshot, aggregator emits only finding-sourced entries + provenance notes the absence. |

## Test specifications (≥11 tests)

### Aggregator tests (`cloud-evidence/tests/core/risk-register.test.ts`)
1. `it('aggregates per-finding risks from POA&M into source=finding entries')`.
2. `it('aggregates active acceptances as source=acceptance entries with treatment=accept')`.
3. `it('aggregates organisational risks verbatim from snapshot')`.
4. `it('derives likelihood from EPSS percentile bands per documented table')`.
5. `it('derives impact from criticality bands per documented table')`.
6. `it('combines likelihood × impact per NIST 800-30 Table I-2 matrix')` — pin worked example.
7. `it('drops residual_risk one band when active compensating control linked')`.
8. `it('drops two bands for treatment=transfer or treatment=avoid')`.
9. `it('de-duplicates: acceptance entry preferred over finding entry for same poam_item')`.
10. `it('emits REQUIRES-OPERATOR-INPUT marker when underlying B.B1 source marker present')` — propagation, not silent zero.
11. `it('emits risk-register.json with provenance.emitter + sourceCalls + summary block')`.

### XLSX tests (`cloud-evidence/tests/core/risk-register-xlsx.test.ts`)
12. `it('emits risk-register.xlsx with 20 columns and one row per entry plus header')`.
13. `it('XLSX round-trips through SheetJS without data loss')`.
14. `it('conditional formatting flags high/very-high inherent rows')`.
15. `it('Description column wraps long text')`.

### Reader tests (`cloud-evidence/tests/core/organisational-risk-reader.test.ts`)
16. `it('pullOrganisationalRisks writes .organisational-risks.json snapshot')`.
17. `it('handles tracker unavailable gracefully — empty list, provenance notes outage')`.

### Tracker route tests (`tracker/server/routes/risk-register.test.ts`)
18. `it('organisational_risks table enforces 800-30 likelihood/impact enums via CHECK constraints')`.
19. `it('rejects POST when nist_control_ids include unknown id')`.
20. `it('rejects POST when compensating_control_uuids include unknown uuid')`.
21. `it('GET /api/risk-register returns aggregated entries')`.
22. `it('GET /api/risk-register/export.xlsx streams a valid XLSX')`.
23. `it('PUT updates open risk; rejects updates on closed risk')`.
24. `it('POST /:uuid/close transitions status; records closure_reason')`.

### UI tests
25. `it('renders risk register table sorted by inherent_risk descending')`.
26. `it('renders organisational risk create form with NIST 800-30 dropdowns')`.
27. `it('Export-to-XLSX button triggers download')`.

## REO compliance specific to this slice
- **Every per-finding entry traces to a real OSCAL risk in `poam.json`** — the aggregator joins by `poam_item.uuid` and `risk.uuid`; no synthesised entries.
- **Every acceptance entry traces to a signed `risk_acceptances` row** — verified signature on the snapshot.
- **Every organisational entry traces to a tracker row with audit trail** (`created_at` / `updated_at` / `closed_*` columns).
- **No synthetic risks**; the aggregator is a JOIN, not a generator. The only computed values are: bands (deterministic table), inherent (NIST matrix), residual (deterministic CC-count reduction).
- **NIST 800-30 enum tokens used VERBATIM** in both JSON and XLSX — no abbreviation, no re-casing.
- **Provenance block** on `risk-register.json`: emitter, emittedAt, sourceCalls (POA&M path, acceptance snapshot, CC snapshot, organisational snapshot), signingKeyId.
- **Signed by existing `core/sign.ts` pipeline** (Ed25519 + RFC 3161); both JSON and XLSX captured.
- **REQUIRES-OPERATOR-INPUT propagation**: when underlying B.B1 source markers exist, the derived likelihood/impact carry the same marker through to the register entry's JSON. XLSX shows the literal token in the cell so reviewers see the gap.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/risk-register.test.ts tests/core/risk-register-xlsx.test.ts tests/core/organisational-risk-reader.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs

cd /Users/kenith.philip/FedRAMP\ 20x/tracker
npm run typecheck
npm test -- server/routes/risk-register.test.ts client/src/pages/RiskRegister.test.tsx client/src/pages/OrganisationalRiskCreate.test.tsx client/src/pages/OrganisationalRiskDetail.test.tsx
```

## Known risks / issues
- **Risk 1: Band-derivation defaults differ from operator org policy.** The default EPSS → likelihood thresholds may not match an org's risk tolerance. Mitigation: thresholds are tunable in `risk-config.yaml` per slice B.B1; `formula_version` propagates from B.B1 into B.B5's per-entry references so re-scored entries are traceable.
- **Risk 2: Inherent matrix interpretation could differ across orgs.** NIST 800-30 Table I-2 is widely accepted but variants exist. Mitigation: the matrix is a typed constant `INHERENT_RISK_MATRIX[likelihood][impact]: RiskBand` with the NIST citation in the docstring. Override available via config; default is the published NIST table.
- **Risk 3: XLSX output not visually polished.** The pure-JS XLSX renderer produces a functional but plain workbook. Mitigation: conditional formatting on high/very-high inherent rows + bold residual very-high; matches inventory-workbook.ts visual baseline. Charting + pivot tables out of scope.
- **Risk 4: Aggregator could double-count a finding that has both an acceptance AND a compensating control.** Mitigation: de-duplication step prefers the acceptance entry; finding entry suppressed when a matching acceptance exists.
- **Risk 5: Organisational risks could grow unbounded over time.** Mitigation: list endpoint paginates; closed risks default-hidden in the UI list; XLSX export includes ALL (open + closed).
- **Risk 6: Review date enforcement.** Some orgs require quarterly review; others annual. Mitigation: server enforces minimum 30 days forward; org policy can set further constraints in `risk-config.yaml`.
- **Risk 7: Cross-system snapshot age skew.** The risk-acceptances snapshot may be older than the organisational-risks snapshot. Mitigation: aggregator records each snapshot's `fetched_at` in the entry's references; reviewer sees the timestamp.
- **Risk 8: NIST 800-30 versioning.** SP 800-30 is currently Rev 1 (2012); a hypothetical Rev 2 could redefine the bands. Mitigation: `nist-800-30-version: "Rev 1"` prop on every entry; future migration is a separate slice.
- **Risk 9: XLSX file signed but mutable on open.** A user opening + saving the XLSX in Excel invalidates the signature. Mitigation: documented in operator runbook — the signed file is the immutable archive; working copies are unsigned. Hash of the as-signed file recorded in manifest.

## Open questions (for implementation session to resolve)
- **Q1**: Should `risk-register.xlsx` include a second sheet "By Category" with category-grouped totals? Recommend: yes — gives the AO an at-a-glance summary. Tests pin column count for sheet 1; sheet 2 added separately.
- **Q2**: Where does the aggregated GET endpoint live: cloud-evidence orchestrator or tracker server? Recommend: tracker server (UI-facing); orchestrator just emits the offline artifact. Tracker imports the same `buildRiskRegister` function (shared module via npm workspace or copy).
- **Q3**: How does B.B5 handle findings that have been REMEDIATED (no longer failing)? Recommend: aggregator reads only OSCAL POA&M `risk.status != 'closed'`; remediated findings drop off automatically.
- **Q4**: Should the per-entry `owner` field be the user's display name, email, or role label? Recommend: role label (e.g. "ISO", "CISO") for organisational; user display name for individual ownership. UI shows both.
- **Q5**: When operator updates an organisational risk's `likelihood` / `impact`, do we recompute inherent + residual automatically or require explicit set? Recommend: server computes inherent (deterministic from likelihood+impact); residual is operator-set with a "Suggested: X" hint from the deterministic CC-count reduction.
- **Q6**: Should B.B5 generate a per-period (monthly / quarterly) snapshot for trend analysis? Recommend: out of scope here — LOOP-E.E1 monthly ConMon report consumes B.B5 snapshots over time.
- **Q7**: Does the XLSX renderer support frozen header rows? Recommend: yes — header row frozen via OOXML `<sheetView><pane>` element; tests pin the XML structure.
- **Q8**: How do we surface in the register that an acceptance is approaching expiration (e.g. 30 days out)? Recommend: add `expiration_warning` column or row-level conditional formatting (amber); out of scope for first ship.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (both workspaces)
- [ ] tests passing 100% (cloud-evidence +12 aggregator/xlsx/reader; tracker +13 routes/UI)
- [ ] check:reo green (G1+G2+G3) in cloud-evidence
- [ ] STATUS.md updated (B.B5 row + Overall section — LOOP-B becomes COMPLETE)
- [ ] LOOP-B-SPEC.md status table updated (Section 7); loop heading marked "(COMPLETE)"
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with slice ID `LOOP-B.B5: <title>` in message
- [ ] Commit amended with commit hash recorded
- [ ] Pushed to origin/main
- [ ] LOOP-B closeout: STATUS.md "Overall" line updated to next loop (LOOP-C.C1)
- [ ] Manual smoke test: orchestrator with `--risk-score --pull-risk-acceptances --pull-compensating-controls --risk-register` end-to-end produces `risk-register.json` + `risk-register.xlsx`

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: full schema + aggregator + XLSX renderer + tests + risks.
3. Read `cloud-evidence/docs/loops/LOOP-B-SPEC.md` §B.B5 + Section 5 (loop-wide acceptance criteria).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the commit pattern.
5. Read `docs/slices/B/B.B1.md`, `B.B2.md`, `B.B3.md`, `B.B4.md` — your inputs.
6. Read `cloud-evidence/core/inventory-workbook.ts` — the XLSX rendering pattern to mirror.
7. Read `cloud-evidence/core/oscal-poam.ts` — POA&M JSON output structure your aggregator parses.
8. Read `cloud-evidence/core/submission-bundle.ts` — add new roles to `WELL_KNOWN`.
9. Read `tracker/server/schema.sql` — append `organisational_risks` table at the end.
10. Read `tracker/client/src/pages/Items.tsx` — UI list pattern to mirror.
11. Read NIST SP 800-30 Rev 1 Appendix I Table I-2 (likelihood × impact matrix) — pin verbatim values in `INHERENT_RISK_MATRIX` constant.
12. Begin implementation; update Implementation log as you go.

---
