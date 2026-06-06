---
slice_id: F.F3
title: Sample selection methodology auto-derive
loop: F
status: pending
commit: —
completed_date: —
depends_on: [A.A2, INV-P1]
blocks: [F.F5, F.F7]
estimated_effort: 2 days
last_updated: 2026-06-06
---

# F.F3 — Sample selection methodology auto-derive

## TL;DR
Pure builder + disk emitter that reads `out/inventory.json` and emits
`out/sampling-methodology.json` + `out/sampling-methodology.md` as SAP
Appendix B. Encodes the FedRAMP Rev5 ConMon Vulnerability Scanning
Playbook 100% externally-accessible rule (hard-coded as FedRAMP-
published constant), stratifies the internal bucket by
`(asset_class, region)` with a configurable 10% floor, and surfaces
AO-approval id/timestamp as REQUIRES-OPERATOR-INPUT when missing.

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
**Gap closed**: Per pre-loop research R4 (see
`cloud-evidence/docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`), FedRAMP
requires a "Sampling Methodology" Appendix B in the SAP whenever
sampling is used. The Rev5 SAP Playbook says the appendix is required
and must align with the Rev5 ConMon Vulnerability Scanning Playbook
sampling rules. Today operators write this by hand — risking stale
inventory counts, missed externally-accessible assets, or fabricated
stratum percentages.

F.F3 derives every count from real `inventory.json` (which itself
flows from real cloud SDK calls per `core/inventory-emit.ts`), then
emits both a machine-readable JSON and a human-readable Markdown so
the 3PAO can attach the Markdown to the SAP and the bundler can ship
the JSON.

## Authoritative sources (with verbatim quotes)
- **FedRAMP Rev5 ConMon Vulnerability Scanning Playbook** —
  https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/
  > "FedRAMP vulnerability scanning guidelines require at least
  > monthly scans of 100% of inventory components."
  >
  > "Vulnerability scanning using sampling targets the same component
  > asset categories but instead requires scanning of a sample attested
  > to represent the unique inventory by an assessor and approved by
  > the AO."
  >
  > "FedRAMP recommends that externally accessible (outside of the
  > boundary, without the use of a VPN) system components do not use
  > this sampling methodology; 100% of externally accessible system
  > components should be scanned."
  >
  > "The entire inventory (or approved sampling percentage) within the
  > boundary must be scanned at the operating system (OS) level at
  > least once a month. All Web interfaces and services (or approved
  > sampling percentage) must be scanned. All databases (or approved
  > sampling percentage) must be scanned."
- **FedRAMP Rev5 SAP Playbook** —
  https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/
  > "the methodology must be included as an appendix to the SAP" and
  > must "align with FedRAMP's vulnerability scanning sampling
  > requirements."
  >
  > "Appendix B: Sampling Methodology" — required in the SAP when
  > sampling is used.
  >
  > "the CSP and 3PAO must sign the SAP, which indicates acknowledgement
  > of and agreement with the SAP and rules of engagement."
- **NIST SP 800-115 §3.3.2 — Sampling** —
  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf
  > "Random sampling should be performed to allow for unbiased
  > selection of devices and applications to test... It is important
  > to note that 100 percent testing is the only way to determine the
  > true security posture of a system."
- **NIST OSCAL Assessment Plan v1.1.2** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-plan/json-reference/
  > "`back-matter/resource` — A resource associated with content in
  > the containing document instance." (Used to attach the sampling
  > methodology JSON as a SAP back-matter resource.)

## Files to create (exact paths)
- `cloud-evidence/core/sampling-methodology.ts` — pure builder + disk
  emitter.
- `cloud-evidence/tests/core/sampling-methodology.test.ts`.

## Files to extend
- `cloud-evidence/core/orchestrator.ts` — flag `--sampling-methodology`
  + env `CLOUD_EVIDENCE_SAMPLING_METHODOLOGY`. Runs BEFORE
  `--oscal-ap` so the AP can link the resulting resource. Reads
  `out/inventory.json`, calls `buildSamplingMethodology`, writes both
  `.json` and `.md`.
- `cloud-evidence/core/oscal-ap.ts` — when
  `out/sampling-methodology.json` exists on disk, append a
  `back-matter.resources[]` entry pointing at it (`rel="reference"`,
  `title="SAP Appendix B — Sampling Methodology"`) and add a
  `terms-and-conditions.parts[]` entry titled `Sampling` whose `prose`
  cites the resource by uuid.
- `cloud-evidence/core/submission-bundle.ts` — well-known catalogue
  entries:
  - `{ role: 'sampling-methodology-json', filename: 'sampling-methodology.json', description: 'SAP Appendix B — Sampling Methodology (machine-readable)' }`
  - `{ role: 'sampling-methodology-md', filename: 'sampling-methodology.md', description: 'SAP Appendix B — Sampling Methodology (Markdown)' }`

## Schemas / standards
- FedRAMP Rev5 ConMon Vulnerability Scanning Playbook — 100% external
  rule is HARD-CODED in the builder. REO Rule 3 exception:
  FedRAMP-published constant.
- Sample plan JSON shape (schema id `cloud-evidence:sampling-methodology@1`):
  ```jsonc
  {
    "schema": "cloud-evidence:sampling-methodology@1",
    "runId": "...",
    "systemId": "...",
    "generatedAt": "ISO-8601",
    "inventory_source": "out/inventory.json",
    "inventory_count": 142,
    "externally_accessible": {
      "rule": "100%",
      "rule_source": "https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/",
      "count": 18,
      "strata": [
        { "asset_class": "ec2", "region": "us-east-1", "count": 6 }
      ]
    },
    "internal": {
      "strata": [
        { "asset_class": "ec2", "region": "us-east-1", "total": 40, "sampled": 4, "percentage": 10 }
      ],
      "floor_percent": 10,
      "operator_overrides": { "rds": 50 },
      "requires_operator_input": ["ao-approval-id", "ao-approval-at"]
    },
    "provenance": {
      "module": "core/sampling-methodology.ts",
      "sourceCalls": ["readFileSync(out/inventory.json)"]
    }
  }
  ```
- Markdown emit follows the section structure listed in build step 3.
- Ajv schema registered in `core/oscal-validate.ts` style; test #14
  validates the emitted JSON against it.

## Build steps (concrete, numbered)
1. **Interface signatures**:
   ```ts
   interface SamplingMethodologyOptions {
     runId: string;
     systemId: string;
     impactTier: ImpactTier;
     /** Override floor percentage per asset_class. Default 10. */
     internalSamplePercent?: Record<string, number>;
     /** ISO-8601 AO approval timestamp once obtained. */
     aoApprovalAt?: string;
     /** AO approval reference number/string. */
     aoApprovalId?: string;
     inventoryPath?: string;   // defaults to out/inventory.json
     outDir?: string;          // defaults to out/
   }

   interface SamplingMethodologyResult {
     jsonPath: string;
     mdPath: string;
     plan: SamplingPlan;
     requires_operator_input: string[];
   }
   ```
2. **Pure builder**
   `buildSamplingMethodology(inventory: Inventory, opts: Opts): SamplingPlan` —
   - No I/O, no clock dependency (`generatedAt` flows through opts or
     is derived deterministically from `runId`).
   - Partition inventory into `externally_accessible` (assets where
     `is_externally_accessible === true` OR `is_public === true` OR
     `network.exposure === 'internet'`) and `internal`.
   - External bucket: `rule: '100%'`; group strata by
     `(asset_class, region)`.
   - Internal bucket: group by `(asset_class, region)`. Per stratum,
     `sampled = max(ceil(total * percent / 100), 1)` where
     `percent = opts.internalSamplePercent[asset_class] ?? 10`. Cap
     `sampled <= total`.
   - Missing `opts.aoApprovalId` → push `'ao-approval-id'` into
     `requires_operator_input`.
   - Missing `opts.aoApprovalAt` → push `'ao-approval-at'`.
   - Empty inventory → return plan with
     `requires_operator_input: ['inventory-empty']` and zero strata.
3. **Disk emitter** `emitSamplingMethodology(opts): Result`:
   - Reads `inventory.json`, calls builder, writes both `.json` and
     `.md`.
   - Markdown structure (verbatim section titles):
     - §1 *Source rules* — verbatim quotes from §3.4 + §3.3 above with
       inline URL citations.
     - §2 *Externally-accessible components (100%)* — table of every
       external asset with id, asset_class, region.
     - §3 *Internal stratified plan* — table of strata with total /
       sampled / percentage / per-class override notes.
     - §4 *AO approval* — id + timestamp or REQUIRES-OPERATOR-INPUT.
     - §5 *Provenance* — module + sourceCalls.
4. **Orchestrator wire**: `--sampling-methodology` triggers
   `emitSamplingMethodology()` BEFORE `--oscal-ap`. Console reports
   inventory count, external count, internal stratum count,
   ready-for-AP-link.
5. **Bundler catalogue**: add both entries.
6. **AP integration** in `oscal-ap.ts`: after the existing
   `back-matter.resources` is built, append the sampling-methodology
   resource when the file exists on disk; uuid derived deterministically
   from the file sha256. Reference the resource from
   `terms-and-conditions.parts[]` titled `Sampling`.
7. **Validation pass**: emitted JSON validates against ajv schema
   `cloud-evidence:sampling-methodology@1` registered in
   `core/oscal-validate.ts` style.
8. **Sign + timestamp**: the JSON is covered by the existing
   `core/sign.ts` manifest + RFC 3161 chain (it appears in `outDir`
   and is hashed by the manifest builder; the same signing/timestamping
   covers it).

## REQUIRES-OPERATOR-INPUT fields
- `aoApprovalId`: source = CLI flag `--ao-approval-id <id>` or env
  `CLOUD_EVIDENCE_AO_APPROVAL_ID`.
- `aoApprovalAt`: source = CLI flag `--ao-approval-at <ISO>` or env
  `CLOUD_EVIDENCE_AO_APPROVAL_AT`.
- Per-asset-class override percentages: source = `config.yaml` key
  `sampling.internal_percent_by_class: { ec2: 25, rds: 50 }`.
- The 100%-external rule is **NOT** operator-overrideable (REO Rule 3
  allowed fixed data: FedRAMP-published constant).

## Test specifications (≥14 tests)
1. `it('partitions inventory into externally-accessible and internal buckets correctly')` — assert split based on `is_externally_accessible / is_public / network.exposure`.
2. `it('emits 100% rule for externally-accessible bucket')` — assert `external.rule === '100%'`.
3. `it('stratifies internal bucket by (asset_class, region) and applies default 10% floor')`.
4. `it('applies per-asset-class override when supplied via internalSamplePercent')`.
5. `it('rounds up to at least 1 sample per non-empty stratum')`.
6. `it('caps sampled <= total per stratum')`.
7. `it('emits ao-approval-id + ao-approval-at as REQUIRES-OPERATOR-INPUT when missing')`.
8. `it('handles empty inventory with requires_operator_input=["inventory-empty"]')`.
9. `it('emit writes both .json and .md files; .md cites the playbook URL verbatim')` — assert MD contains the URL string `https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/`.
10. `it('AP emit with sampling-methodology.json on disk appends a back-matter.resources entry')`.
11. `it('AP emit links the sampling resource from terms-and-conditions.parts')`.
12. `it('bundler well-known catalogue includes sampling-methodology-json + -md')`.
13. `it('plan is deterministic on identical input (byte-stable .json)')` — call builder twice with same input, assert outputs are identical.
14. `it('JSON output validates against the cloud-evidence:sampling-methodology@1 ajv schema')`.

## REO compliance specific to this slice
- Every count traces back to a row in `inventory.json` (real cloud
  SDK evidence per existing `core/inventory-emit.ts`).
- The 100%-external rule is cited verbatim with the FedRAMP playbook
  URL embedded in the output `.md` (REO Rule 3 allowed fixed data).
- Operator AO approval data is never defaulted; missing → explicit
  `REQUIRES-OPERATOR-INPUT` marker in both `.json` and `.md`.
- No silent inventory fallback: empty inventory → explicit
  `inventory-empty` marker AND `coverage:miss` line in run log.
- Provenance: `plan.provenance.module + plan.provenance.sourceCalls`
  populated; `npm run check:provenance` passes because every emit
  field traces to inventory or operator input.
- Signed by: existing `core/sign.ts` pipeline (the JSON + MD appear in
  `outDir`, get hashed in the manifest, and the manifest is signed +
  RFC 3161 timestamped).

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/sampling-methodology.test.ts
npm run check:reo
```

## Known risks / issues
- **Risk 1 — inventory completeness**: if `inventory.json` is missing
  externally-accessible assets (e.g. a non-Org member account not
  scanned by `INV-S5`), the 100% rule silently excludes them.
  Mitigation: cross-check inventory count against
  `inventory-coverage.json`; if `coverage_pct < 100%`, emit a
  `coverage:miss` and include a `requires_operator_input: ['inventory-incomplete', '<count>-assets-missing']`
  entry in the plan.
- **Risk 2 — `is_externally_accessible` field reliability**: depends on
  `INV-S5` field. False negatives in IPv6 / dual-stack configurations
  could let external assets fall into the internal bucket.
  Mitigation: also treat `network.exposure === 'internet'` as
  external; document the rules in the Markdown emit; trust the
  collector (operator can override via `inventory_external_override`
  config key).
- **Risk 3 — stratum granularity too coarse**: grouping by
  `(asset_class, region)` may produce strata too small to be
  statistically meaningful (e.g. 2 ec2 in us-west-2). Mitigation:
  emit a `requires_operator_input: ['small-stratum:<class>:<region>']`
  warning when `total < 5`; operator can adjust per-class %.
- **Risk 4 — `internalSamplePercent` lookup mismatch**: operator
  passes `EC2` but inventory has `ec2`. Mitigation: case-fold
  asset_class in lookups; document in the Markdown emit.
- **Risk 5 — deterministic uuid collision**: if two different
  inventories produce the same sha256, the AP back-matter uuid
  collides. Mitigation: extremely unlikely (sha256); but log the
  uuid + file size + content-hash in the AP emit log so the operator
  can audit.

## Open questions (for implementation session to resolve)
- **Q1**: Should the `.md` output use literal `> blockquote` Markdown
  for the verbatim playbook quotes, or numbered citation footnotes?
  Proposal: blockquotes (matches the SAP appendix style guides).
- **Q2**: Does the operator override require AO sign-off, or is the
  CSP free to lower the floor below 10%? FedRAMP playbook says AO
  approval — but at what percent floor does the slice prevent the
  emit entirely? Proposal: emit anyway, but the AO sign-off slot is
  REQUIRES-OPERATOR-INPUT until populated.
- **Q3**: Does `sampling-methodology.md` need to embed an actual
  table of every externally-accessible asset (potentially hundreds)
  or just the count per stratum?
- **Q4**: Should the `.md` be regenerated on every orchestrator run,
  or only when the inventory hash changes (idempotency)?

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥14)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-F-SPEC.md Section 7 status table updated
- [ ] This file's frontmatter updated (status=done, commit, date)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-F.F3: Sample selection methodology auto-derive`
- [ ] Commit amended with hash in STATUS.md + this file + LOOP-F-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: sources + files + build steps + tests + risks.
3. Read `cloud-evidence/docs/loops/LOOP-F-SPEC.md` §2 Dependencies.
4. Read `cloud-evidence/docs/PRE-LOOP-A-RESEARCH-FINDINGS.md` R4 for
   the source research that triggered this slice.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
6. Confirm A.A2 (`oscal-ap.ts`) and INV-P1 (`inventory-emit.ts`) are
   `done` in STATUS.md.
7. Begin implementation; update Implementation log as you go.
