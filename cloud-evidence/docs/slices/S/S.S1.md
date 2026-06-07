---
slice_id: S.S1
title: NIST 800-171 Rev 3 → FedRAMP Moderate crosswalk emitter
loop: S
status: pending
commit: —
completed_date: —
applicable_conditional: true
condition: CSP has at least one DoD-prime customer (DFARS Subpart 204.73 applicable)
trigger_flag: "--dfars-equivalency"
trigger_env: CLOUD_EVIDENCE_DFARS_EQUIVALENCY
depends_on: [LOOP-A.A1, LOOP-A.A3, "core/control-benchmark.ts (existing)"]
blocks: [S.S3]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
---

# S.S1 — NIST 800-171 Rev 3 → FedRAMP Moderate crosswalk emitter

## TL;DR

Express the existing FedRAMP Moderate evidence (NIST 800-53 Rev 5 control
benchmark + POA&M + AR + inventory) in NIST 800-171 Rev 3 terms so a
DoD-prime customer evaluating the CSP for DFARS 252.204-7012 cloud
equivalency can see, for each 800-171 requirement, which Moderate
controls cover it and what the assessed status is. Extends the existing
`core/control-benchmark.ts` framework enum with `'800-171-r3'`, loads a
generated 800-171 Rev 3 catalog (extracted one-shot from NIST's
published Appendix C .xlsx into `docs/nist-800-171-r3.generated.json`),
projects benchmark results onto 800-171 requirements via NIST's
published mapping, and emits `out/dfars-crosswalk.json` +
`out/dfars-crosswalk.xlsx`. Conditional: only runs when
`--dfars-equivalency` is set AND at least one inventory asset carries
`data_classification === 'cui'`.

## Status

- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists

A DoD-prime contractor performing a contract subject to DFARS 252.204-7012
needs to demonstrate to its contracting officer that any cloud service
storing or processing Covered Defense Information / CUI on its behalf
meets FedRAMP Moderate equivalency PLUS the DFARS 7012(c)-(g)
operational obligations. The clarifying DoD CIO Memorandum (Dec 21,
2023) further requires that the CSP produce a **Body of Evidence (BoE)**
demonstrating implementation of every Moderate-baseline control.

The existing `core/control-benchmark.ts` produces a NIST 800-53 Rev 5
benchmark (per-control status across the Moderate baseline's 287
controls). That's perfect for FedRAMP package consumers but useless for
a DoD-prime customer who reads 800-171 Rev 3 requirements in their
contract — the prime needs a per-800-171-requirement view.

NIST publishes the mapping in **NIST SP 800-171 Rev 3 Appendix C**
(May 2024): each Rev 3 requirement lists the Rev 5 controls it derives
from. S.S1 reads that mapping (extracted one-shot from NIST's published
.xlsx) and projects the existing benchmark onto 800-171.

The same data also satisfies **DFARS 252.204-7019** (NIST SP 800-171
DoD Assessment) — the CSP can hand the prime the crosswalk + evidence
pointers and the prime can perform a self-assessment for SPRS posting.

This is a *crosswalk-only* slice. It introduces no new evidence
collection. Every requirement's status traces back to the existing
benchmark; every "satisfied" claim is backed by existing OSCAL observation
+ AR entries; every "not-satisfied" claim is backed by an existing POA&M
item. The crosswalk is the projection function — REO-compliant by
construction.

## Authoritative sources (with verbatim quotes)

- **DFARS 252.204-7012(b)(2)(ii)(D)** —
  https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting
  > "If the Contractor intends to use an external cloud service provider
  > to store, process, or transmit any covered defense information in
  > performance of this contract, the Contractor shall require and
  > ensure that the cloud service provider meets security requirements
  > equivalent to those established by the Government for the Federal
  > Risk and Authorization Management Program (FedRAMP) Moderate
  > baseline ... and that the cloud service provider complies with
  > requirements in paragraphs (c) through (g) of this clause."

- **DFARS 252.204-7019(b)** —
  https://www.acquisition.gov/dfars/252.204-7019
  > "the Offeror shall have a current assessment (i.e., not more than 3
  > years old unless a lesser time is specified in the solicitation)
  > (see 252.204-7020) for each covered contractor information system
  > that is relevant to the offer, contract, task order, or delivery
  > order."

- **NIST SP 800-171 Rev 3, May 2024** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf
  > "This publication provides federal agencies with recommended
  > security requirements for protecting the confidentiality of
  > Controlled Unclassified Information (CUI) when the information is
  > resident in nonfederal systems and organizations."
  > "The security requirements are organized into 17 families."
  Families (Rev 3): AC, AT, AU, CA, CM, IA, IR, MA, MP, PE, PS, PL, PM,
  RA, SC, SI, SR. 110 base requirements.

- **NIST SP 800-171 Rev 3 Appendix C — Tailoring Criteria and Mapping
  to NIST SP 800-53 Controls** — the .xlsx the extraction script reads.
  Each Rev 3 requirement lists derived Rev 5 controls + tailoring
  actions.

- **NIST SP 800-171A Rev 3 — Assessment Procedures** —
  https://csrc.nist.gov/pubs/sp/800/171/A/r3/final
  Referenced for assessment-objective vocabulary used in the runbook
  (not loaded at runtime).

- **DoD CIO Memorandum, "FedRAMP Moderate Equivalency for Cloud Service
  Providers"** — December 21, 2023.
  > "Body of Evidence (BoE) ... must include evidence that the CSP has
  > implemented each FedRAMP Moderate control."
  (Downloaded PDF to `docs/sources/dod-cio-memo-fedramp-equivalency-2023-12-21.pdf`
  per Section 6 of `LOOP-S-SPEC.md`.)

- **NARA CUI Registry** —
  https://www.archives.gov/cui/registry/category-list — authoritative
  list of CUI categories used to validate `fedramp_cui_category` tags.

- **DFARS 252.204-7020** —
  https://www.acquisition.gov/dfars/252.204-7020 — authorizes Medium /
  High DoD assessments; S.S1's evidence pointers (KSI IDs + observation
  UUIDs + POA&M item UUIDs) are designed for direct consumption by such
  an assessor.

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-crosswalk.ts`
  — pure module: loads 800-171 catalog, projects benchmark results,
  emits `out/dfars-crosswalk.json`. ~450 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-crosswalk-xlsx.ts`
  — xlsx renderer. ~200 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-800-171-r3.mjs`
  — one-shot catalog extractor reading
  `docs/sources/nist-sp-800-171r3-AppendixC.xlsx` and writing
  `docs/nist-800-171-r3.generated.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/nist-800-171-r3.generated.json`
  — generated catalog (committed; regenerated when NIST publishes a new
  Appendix C revision).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-crosswalk.test.ts`
  — ≥10 unit + integration tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-crosswalk-xlsx.test.ts`
  — ≥4 tests pinning the xlsx schema + a SheetJS round-trip.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/dfars-crosswalk/`
  — sample benchmark, sample inventory, expected crosswalk JSON for
  golden tests.

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/control-benchmark.ts`
  — extend `BenchmarkFramework` from `'rev5' | '20x'` to
  `'rev5' | '20x' | '800-171-r3'`. Re-export `ControlResult` +
  `ControlStatus` so `dfars-crosswalk.ts` doesn't redeclare. Header
  docstring documents that 800-171 is a *projected* framework.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — new `--dfars-equivalency` flag (env
  `CLOUD_EVIDENCE_DFARS_EQUIVALENCY`). New
  `--dod-prime-customer <name>` flag (repeatable). When
  `--dfars-equivalency` is set, AFTER `--control-benchmark` AND AFTER
  `--oscal-poam`, run `emitDfarsCrosswalk()`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add roles `dfars-crosswalk-json` (filename `dfars-crosswalk.json`),
  `dfars-crosswalk-xlsx` (filename `dfars-crosswalk.xlsx`) to
  `WELL_KNOWN`.

## Schemas / standards

- **NIST 800-171 Rev 3 catalog shape**:
  ```ts
  export interface Nist800171Requirement {
    requirement_id: string;        // "03.01.01" (Rev 3 numbering)
    family: string;                 // "AC"
    family_name: string;            // "Access Control"
    title: string;
    statement: string;              // verbatim requirement text
    discussion: string;             // verbatim discussion section
    derived_from: string[];         // ["ac-1", "ac-2", ...] Rev 5 control ids
    odp: Array<{                    // Organizationally-Defined Parameters
      id: string;
      label: string;
      type: 'organization-defined' | 'selection';
    }>;
    tailoring_action?: 'no-change' | 'modified-for-cui' | 'added-for-cui';
  }
  ```

- **Crosswalk entry shape** (per requirement):
  ```ts
  export interface CrosswalkEntry {
    requirement_id: string;
    family: string;
    family_name: string;
    title: string;
    statement: string;
    derived_from: string[];
    derived_results: ControlResult[];
    status: ControlStatus | 'requires-operator-input';
    evidence_pointers: {
      ksi_ids: string[];
      observation_uuids: string[];
      poam_item_uuids: string[];
    };
    cui_categories?: string[];
  }
  ```

- **Provenance block** (REO Rule 2.6):
  ```ts
  provenance: {
    emitter: 'dfars-crosswalk';
    emittedAt: string;
    sourceCalls: Array<{
      kind: 'control-benchmark' | 'inventory' | 'poam' | '800-171-catalog';
      path: string;
    }>;
    signingKeyId: string;
  }
  ```

## Build steps (concrete, numbered)

1. **Catalog extraction**: write `scripts/extract-800-171-r3.mjs`. Read
   `docs/sources/nist-sp-800-171r3-AppendixC.xlsx` via SheetJS (already
   a dependency for inventory-workbook). For each row in the "Mapping"
   sheet, parse: requirement id (column A), family (B), title (C),
   statement (D), discussion (E), derived 800-53 controls (F, comma-
   separated), tailoring action (G). Idempotent; safe to re-run.

2. **Verify catalog at load time**: `loadNist800171Catalog()` reads the
   generated JSON, asserts 110 requirements, asserts 17 distinct
   families. Throws typed error on mismatch (indicates the source
   xlsx was malformed at extraction time).

3. **Define types** in `core/dfars-crosswalk.ts` per § Schemas above.

4. **Pure builder**:
   ```ts
   export function buildDfarsCrosswalk(
     benchmark: ControlBenchmark,
     catalog: Nist800171Requirement[],
     inventory: InventorySnapshot,
     poam: OscalPoam,
     opts: { cspName: string; dodPrimeCustomers: string[] },
   ): DfarsCrosswalkResult;
   ```
   For each `Nist800171Requirement`:
   - Look up each id in `derived_from` against `benchmark.controls[]`.
   - Roll-up status per `rollupStatus()`:
     ```
     all satisfied              → satisfied
     all not-satisfied          → not-satisfied
     all not-assessed           → not-assessed
     all empty derived_from     → requires-operator-input
     otherwise                  → partially-satisfied
     ```
   - Walk POA&M JSON for `observation.uuid` + `poam-item.uuid` whose
     `related-observations[]` reference any control in `derived_from`.
   - Walk inventory for CUI-tagged assets; collect their
     `fedramp_cui_category` tags into a per-family-level distinct set.

5. **CUI scope gate**: count `inventory.assets[].data_classification === 'cui'`. If zero, log `coverage:skipped` with reason "no CUI-tagged assets — DFARS 7012 cloud-equivalency may not apply" and emit the
   crosswalk JSON ANYWAY (informational; `dod_prime_customers[]` may
   still be set). The xlsx is emitted regardless.

6. **JSON emit**: write `out/dfars-crosswalk.json` with provenance
   block listing every source path read.

7. **XLSX emit** in `core/dfars-crosswalk-xlsx.ts`. Columns:
   - A. Family (e.g. "AC — Access Control")
   - B. Requirement ID (e.g. "03.01.01")
   - C. Requirement Title
   - D. Status (one of: satisfied / partially-satisfied / not-satisfied / not-assessed / requires-operator-input)
   - E. Derived 800-53 Rev 5 Controls (comma-joined)
   - F. Per-Control Statuses (semicolon-joined)
   - G. CUI Categories (when applicable)
   - H. Evidence — KSI IDs (comma-joined)
   - I. Evidence — Observation UUIDs (comma-joined)
   - J. Evidence — POA&M Item UUIDs (comma-joined)
   - K. Statement (wrapped)
   - L. Discussion (wrapped)
   Header row + per-family group total rows + grand-total row.

8. **Bundler entries**: add to `submission-bundle.ts:WELL_KNOWN`:
   ```ts
   { role: 'dfars-crosswalk-json', filename: 'dfars-crosswalk.json', description: 'NIST 800-171 Rev 3 ↔ FedRAMP Moderate per-requirement coverage report (LOOP-S.S1)' },
   { role: 'dfars-crosswalk-xlsx', filename: 'dfars-crosswalk.xlsx', description: 'XLSX twin of dfars-crosswalk.json (LOOP-S.S1)' },
   ```

9. **Orchestrator wiring**: when `--dfars-equivalency` is set, AFTER
   `--control-benchmark` writes `out/control-benchmark.json` AND
   `--oscal-poam` writes `out/poam.json`, call:
   ```ts
   const result = await emitDfarsCrosswalk({
     outDir: opts.outDir,
     benchmarkPath: `${opts.outDir}/control-benchmark.json`,
     catalogPath: 'docs/nist-800-171-r3.generated.json',
     inventoryPath: `${opts.outDir}/inventory.json`,
     poamPath: `${opts.outDir}/poam.json`,
     cspName: config.csp_name,
     dodPrimeCustomers: config.dfars?.dod_prime_customers ?? cli.dodPrimeCustomers,
     runId: opts.runId,
   });
   logger.info({ result }, 'dfars-crosswalk: emitted');
   ```

10. **Sign + timestamp**: outputs flow through existing
    `core/sign.ts` glob + `core/timestamp.ts` RFC 3161 pipeline. JSON
    and xlsx land in the manifest.

11. **Validation pass**:
    - `npm run check:provenance` — must list a provenance block on the
      JSON.
    - `npm run lint:no-stubs` — no forbidden tokens introduced.

## REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4, every field that cannot be auto-derived:

| Field | Source | Behavior when missing |
|---|---|---|
| `dodPrimeCustomers[]` | `config.yaml` `dfars.dod_prime_customers` OR CLI `--dod-prime-customer <name>` (repeatable) | Empty list: log `coverage:skipped` with reason `no DoD-prime customers configured`; crosswalk JSON still emitted; `dod_prime_customers: []` is honest. |
| `inventory.assets[].data_classification === 'cui'` | Cloud tag `fedramp_data_classification=cui` (AWS) / label (GCP) / equivalent (Azure) | If zero, emit `coverage:skipped` with reason `no CUI-tagged assets — DFARS 7012 cloud-equivalency may not apply`. |
| `inventory.assets[].fedramp_cui_category` | Cloud tag set per NARA CUI Registry | If a CUI-tagged asset lacks a category, the entry's `cui_categories[]` carries `REQUIRES-OPERATOR-INPUT: missing-cui-category-for-<asset-id>`. |
| Requirements with empty `derived_from` | NIST 800-171 Rev 3 catalog | Per Build step 4, `status: 'requires-operator-input'`; the operator's tracker entry documents how the requirement is met (e.g. PL-2 SSP section reference). |
| `tailoring_action` field on a requirement | Extracted from NIST Appendix C | When absent, defaults to `'no-change'` (Rev 3 baseline). |

## Test specifications (≥10 tests)

1. `it('loads NIST 800-171 Rev 3 catalog with 110 requirements')` — load
   `docs/nist-800-171-r3.generated.json` (fixture), assert count.
2. `it('asserts 17 distinct families in the catalog')` — pin the family
   list (AC, AT, AU, CA, CM, IA, IR, MA, MP, PE, PS, PL, PM, RA, SC,
   SI, SR).
3. `it('rolls up satisfied when all derived controls satisfied')` —
   requirement with derived_from=[ac-1] and benchmark ac-1=satisfied.
4. `it('rolls up partially-satisfied when derived controls mixed')` —
   derived_from=[ac-1, ac-2] with one satisfied + one not-satisfied.
5. `it('rolls up not-satisfied when all derived controls not-satisfied')`.
6. `it('rolls up not-assessed when all derived controls not-assessed')`.
7. `it('rolls up requires-operator-input when derived_from empty')`.
8. `it('emits coverage:skipped when no CUI-tagged assets in inventory')`
   — fixture inventory with zero CUI assets; assert log line +
   crosswalk still emitted.
9. `it('attaches cui_categories[] from inventory tags')` — CUI asset
   tagged `fedramp_cui_category=CUI-CTI`; assert family entry includes
   `["CUI-CTI"]`.
10. `it('attaches REQUIRES-OPERATOR-INPUT marker for CUI asset without category')`.
11. `it('emits family-level roll-up with correct counts')` — fixture
    asserting per-family totals match sum of per-requirement statuses.
12. `it('emits evidence_pointers.observation_uuids from the POA&M')` —
    fixture POA&M with observations referencing ac-1; assert observation
    UUIDs propagate to the requirement entry.
13. `it('emits evidence_pointers.poam_item_uuids for failing requirements')`.
14. `it('emits provenance block per REO Rule 2.6')` — assert
    `provenance.emitter === 'dfars-crosswalk'`, sourceCalls non-empty.
15. `it('writes dfars-crosswalk.xlsx with the documented 12 columns')`.
16. `it('xlsx is openable by SheetJS round-trip')` — read back, verify
    cell A2 = expected family label.
17. `it('orchestrator emits crosswalk only when --dfars-equivalency set')`
    — without flag, no crosswalk emitted; with flag, both files appear.
18. `it('orchestrator respects CLOUD_EVIDENCE_DFARS_EQUIVALENCY env')`.

## REO compliance specific to this slice

- Catalog is loaded from a real extracted JSON, produced by a real
  one-shot extraction script reading a real published NIST source
  (Appendix C .xlsx). No hardcoded sample data; the script is committed
  but the catalog regenerates from the published source.
- 800-171 → 800-53 mapping is NIST-published; not synthesized.
- Coverage statuses are derived from the existing real
  `control-benchmark.json`; not invented.
- CUI scope is determined by real
  `inventory.assets[].data_classification` tags; absence is honestly
  surfaced as `coverage:skipped` with reason.
- No `process.env.NODE_ENV === 'test'` branches; tests inject seams
  via dependency-injected file readers.
- Provenance block populated end-to-end with real source paths.
- xlsx generator reuses the same pure-JS pattern as
  `core/inventory-workbook.ts`; no new dependency.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/dfars-crosswalk.test.ts tests/core/dfars-crosswalk-xlsx.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues

- **Risk 1: NIST Appendix C .xlsx column layout drift.** NIST publishes
  the source as .xlsx; column order or sheet names could change in a
  future revision. Mitigation: extraction script asserts expected
  column headers; throws typed error on mismatch with a clear
  remediation message.
- **Risk 2: Rev 3 vs Rev 2 ambiguity in prime contracts.** Some primes
  still reference 800-171 Rev 2 in their contracts. Mitigation: S.S1
  ships Rev 3 only; the operator's runbook documents manual gap when a
  prime requires Rev 2 mapping. A future enhancement could add Rev 2
  catalog + dual-rev output.
- **Risk 3: 800-53 control coverage gap.** A 800-171 requirement
  derived from a Rev 5 control that is `not-assessed` in the existing
  benchmark (e.g. a process-artifact-only control) cascades to the
  crosswalk as `not-assessed`. Mitigation: this is correct behavior
  (not a bug); the operator addresses the gap by completing the
  process-artifact tracker entry, which flips the benchmark to
  satisfied, which flips the crosswalk.
- **Risk 4: CUI categories vs NARA registry drift.** NARA updates the
  CUI registry; operator tags can drift. Mitigation: the tag value is
  carried verbatim into the xlsx; mismatches surface as
  `REQUIRES-OPERATOR-INPUT: unknown-cui-category-<value>` rather than
  silent error.
- **Risk 5: Operator forgets to set --dod-prime-customer.** If the flag
  isn't set but the CSP claims DFARS-equivalency in the LOOP-Q.Q1
  Marketplace metadata, the crosswalk is technically still valid but
  the audit trail is incomplete. Mitigation: emit `coverage:skipped`
  log line that surfaces in the run log; CHANGELOG entry for S.S1
  documents the requirement.

## Open questions (for implementation session to resolve)

- **Q1**: Should the extraction script also extract Appendix B (Tailoring
  Criteria) so the crosswalk can show WHY a control was tailored?
  Recommend: yes, optional field on the requirement; UI tooltip; not a
  ship-blocker.
- **Q2**: When a requirement has multiple ODPs (e.g. AC-2's account-
  monitor frequency), should S.S1 surface each ODP separately?
  Recommend: yes, in a separate ODPs column (column M); operator's
  tracker fills in the value.
- **Q3**: Should the xlsx include a separate "Family Summary" worksheet
  in addition to inline group totals? Recommend: yes, second sheet
  `Family Summary` with 17 rows + totals.
- **Q4**: Should S.S1 emit a `not-applicable` status when a requirement
  is entirely covered by FED-only controls (i.e. correctly excluded by
  NIST tailoring)? Recommend: yes, distinct status; visible in xlsx.
- **Q5**: How do we handle PM family (Program Management) — those
  controls are typically organization-wide, not system-specific?
  Recommend: roll-up status = "covered-by-organization" with a tracker
  pointer to the organization-wide artifact.

## Implementation log (running journal — implementing session updates)

```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

The implementing session MUST check every box:

- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥18 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section; LOOP-S conditional
  gate noted)
- [ ] LOOP-S-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
  completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (opens with conditional gate
  statement)
- [ ] Commit with slice ID in message
- [ ] Commit amended with commit hash recorded
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build
   steps + tests + risks + completion checklist + conditional gate.
3. Read `cloud-evidence/docs/loops/LOOP-S-SPEC.md` Section 2
   (Dependencies) for cross-loop context AND Section 1 for the
   conditional gate (LOOP-S applies ONLY when CSP has DoD-prime
   customers).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/control-benchmark.ts` (the extension point).
6. Read `cloud-evidence/core/inventory-workbook.ts` (the pattern S.S1's
   xlsx renderer mirrors).
7. Confirm `docs/sources/nist-sp-800-171r3-AppendixC.xlsx` exists; if
   not, download from NIST (https://csrc.nist.gov/pubs/sp/800/171/r3/final)
   before running the extraction script.
8. Begin implementation; update Implementation log section as you go.

---
