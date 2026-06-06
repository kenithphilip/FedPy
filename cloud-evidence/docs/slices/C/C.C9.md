---
slice_id: C.C9
title: Baseline Configuration document (CM-2)
loop: C
status: pending
commit: —
completed_date: —
depends_on: [Pre-slice docx-primitives, INV-1..S6 inventory chain, providers/*/reference-arch.ts]
soft_depends_on: [LOOP-G.G5 AFR-SCG core/scg-comparator.ts]
blocks: [C.C1 CMP §5 cross-link, LOOP-E ConMon baseline-drift detection]
estimated_effort: 1.5 working days
last_updated: 2026-06-07
---

# C.C9 — Baseline Configuration document (CM-2)

## TL;DR
Ships `baseline-config.docx` — the CM-2 baseline configuration document distinct from CM-8 inventory. §3 Baseline Configuration Items derives from real `out/inventory.json`. §4 Reference Architecture grep-reads `providers/aws|gcp|azure/reference-arch.ts`. §5 Deviations from Baseline auto-computes via `core/scg-comparator.ts` (existing module). Distinct in scope from AFR-SCG (LOOP-G.G5) — this slice is the baseline-of-record; AFR-SCG is the recommended-secure-configuration.

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
NIST SP 800-53 Rev. 5 control **CM-2 (Baseline Configuration)** mandates a documented baseline configuration for every information system. Rev. 5 split CM-2 (baseline) from CM-8 (inventory) — inventory is "what assets exist"; baseline is "what configuration each asset is approved to run". 3PAOs sample both. **CM-2(2) (Automation Support for Accuracy and Currency)** mandates automated mechanisms; the LOOP-C emitter satisfies this by deriving baseline from inventory + reference-architecture source files. **CM-2(7) (Configure Systems and Components for High-Risk Areas)** is referenced for travelers/external-system deployments.

LOOP-G.G5 (AFR-SCG) shares the same `providers/<cloud>/reference-arch.ts` source — C.C9 establishes the structure both emitters consume.

## Authoritative sources (with verbatim quotes)
- **NIST SP 800-53 Rev. 5 — CM-2 Baseline Configuration** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  > "a. Develop, document, and maintain under configuration control, a current baseline configuration of the system; and b. Review and update the baseline configuration of the system: 1. [Assignment: organization-defined frequency]; 2. When required due to [Assignment: organization-defined circumstances]; and 3. When system components are installed or upgraded."

- **NIST SP 800-53 Rev. 5 — CM-2(2) Automation Support for Accuracy and Currency** — same URL
  > "Maintain the currency, completeness, accuracy, and availability of the baseline configuration of the system using [Assignment: organization-defined automated mechanisms]."

- **NIST SP 800-53 Rev. 5 — CM-2(7) Configure Systems and Components for High-Risk Areas** — same URL — cited as a Rev5 enhancement note.

- **NIST SP 800-128 (with Update 1, 2019-10) — Guide for Security-Focused Configuration Management of Information Systems** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-128.pdf
  > §3.2: "All configuration changes need to be formally identified, proposed, reviewed, analyzed for security impact, tested, and approved prior to implementation. A baseline configuration is a documented, formally reviewed and agreed-upon specification for a system or configuration item within a system."
  > §3.2 (continued): "A baseline configuration provides the basis for future builds, releases, and changes to systems."

- **CIS Benchmarks** — https://www.cisecurity.org/cis-benchmarks — referenced as the upstream standard the `providers/*/reference-arch.ts` files draw from (not copied verbatim — REO Rule 3 does not extend to CIS).

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/baseline-config-emit.ts` — pure renderer + disk emitter for `baseline-config.docx` (~600 lines).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/baseline-config-emit.test.ts` — 13 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/baseline/inventory.sample.json` — fixture with 6 components across 3 providers.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/baseline/config.sample.yaml` — operator config with approver + deviation log + cadence.

## Files to extend
- `core/submission-bundle.ts` — Role `'baseline-config-docx'`; `WellKnownArtifact` entry.
- `core/orchestrator.ts` — `--baseline-config` flag + env; dispatch block. ORDER NOTE: C.C9 must run BEFORE C.C1 so C.C1's `--cmp-baseline-config-href` auto-resolves.
- `CHANGELOG.md`, `docs/STATUS.md`, `docs/loops/LOOP-C-SPEC.md` — per SLICE-COMPLETION-PROCEDURE.md.

## Schemas / standards
- Baseline-row tuple: `{component:string; baseline_image:string; baseline_config:string; current_count:number; controls:string[]}`.
- Deviation-row tuple: `{component:string; baseline:string; current:string; deviation_description:string; severity:'low'|'moderate'|'high'}`.
- Reference-arch source schema: `providers/<cloud>/reference-arch.ts` exports arrays of `{component, baselineImage, baselineConfig, controls}` records that grep can pick up.

## Build steps (concrete, numbered)
1. Define `BaselineConfigOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; impactLevel; baselineApprover?:{name; role; org; date}; deviationLogLocation?:string; baselineReviewCadence?:'monthly'|'quarterly'|'annually'; configurationItemsOverride?:Array<{component; baseline; deviations:string[]}>`.
2. Auto-derive from three sources:
   - **Real inventory** (`out/inventory.json`): each asset's current `image`, `osVersion`, `instanceType`.
   - **Reference architecture** (`providers/aws|gcp|azure/reference-arch.ts`): grep source for documented expected-baseline entries.
   - **AFR-SCG comparator** (`core/scg-comparator.ts`): deviation summary inventory vs reference.
3. Implement `readReferenceArchitecturesAllProviders():Array<{provider; component; baselineImage; baselineConfig; controls:string[]}>` — grep-against-source technique (same as `roe-emit.ts:readKsiScope`); avoid pulling SDK clients at emit time.
4. Implement `readInventoryBaselineRows(outDir):Array<{uniqueId; provider; component; currentImage; currentConfig}>`.
5. Implement `diffInventoryVsReference(inv, ref):Array<{component; baseline; current; deviation}>` — pure.
6. Pure builder `buildBaselineConfigBodyXml(opts):{xml; stats}` producing 8 sections:
   - §1 Introduction (CM-2 + 800-128 §3.2 cite).
   - §2 Methodology (cite reference-arch.ts provenance + scg-comparator).
   - §3 Baseline Configuration Items (per `(provider,component-type)` group — current count + baseline image + baseline config summary).
   - §4 Reference Architecture (auto from `providers/<cloud>/reference-arch.ts`).
   - §5 Deviations from Baseline (auto from scg-comparator output).
   - §6 Baseline Maintenance (review cadence + on-change triggers).
   - §7 Deviation Approval Process (cross-link to C.C1 CMP §6 Change Control).
   - §8 Approval Signatures (`baselineApprover`).
7. `emitBaselineConfigDocx(opts):BaselineConfigResult` writes file + structured log.

## REQUIRES-OPERATOR-INPUT fields
- `baselineApprover` — `config.yaml:baseline_config.approver`.
- `deviationLogLocation` — `config.yaml:baseline_config.deviation_log` (URL or path).
- `baselineReviewCadence` — defaults to `annually` per CM-2; operator can tighten.
- `configurationItemsOverride` — rarely used; operator override when reference-arch is incomplete.

## Test specifications (13 tests)
1. `it('emits 8 sections')`.
2. `it('§3 component-group rows derived from inventory.json')`.
3. `it('§4 reference architecture rows derived from providers/*/reference-arch.ts source greps')`.
4. `it('§5 deviation rows from diffInventoryVsReference')`.
5. `it('REQUIRES-OPERATOR-INPUT when inventory.json absent')`.
6. `it('REQUIRES-OPERATOR-INPUT when no reference-arch.ts files readable')`.
7. `it('§7 cross-links to cmp.docx when present')`.
8. `it('renders baselineApprover signature block')`.
9. `it('quotes SP 800-128 §3.2 verbatim in §1')`.
10. `it('handles multi-cloud (AWS+GCP+Azure) reference-arch parsing')`.
11. `it('writes to outPath when supplied')`.
12. `it('deterministic output')`.
13. `it('ready_for_signature requires approver + deviation-log + cadence')`.

## REO compliance specific to this slice
- §3, §4, §5 trace to real inventory + reference-arch + scg-comparator output.
- NO fabricated baseline values; if reference-arch.ts has no entry for a component, document says so explicitly.
- Document footer cites sha256 of every source file read (inventory.json, reference-arch.ts × 3 clouds).
- Reference-arch.ts files contain published CIS Benchmark + cloud-vendor reference content; per REO Rule 3, the cloud-vendor service names are allowed fixed data, but baseline images / instance types come from real reference-arch.ts source greps (not hardcoded in the emitter).

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/baseline-config-emit.test.ts
npm run check:reo
npm run check:provenance
```

## Known risks / issues
- **Risk 1 — Reference-arch.ts schema drift.** If the provider reference-arch files are refactored (e.g. export shape changes), grep-based readers silently return empty. Mitigation: assert `min(1) reference-arch entries per provider`; throw typed error if not.
- **Risk 2 — AFR-SCG (LOOP-G.G5) not yet shipped.** `core/scg-comparator.ts` may not exist at C.C9 ship time. Mitigation: bundled in spec — `core/scg-comparator.ts` must ship in C.C9 (or earlier) for the comparator to work; if LOOP-G.G5 already added it, reuse; otherwise C.C9 ships the comparator with shared API for G.G5 to reuse.
- **Risk 3 — Multi-cloud component-type normalization.** AWS EC2 + Azure VM + GCP Compute Instance are conceptually similar but the inventory uses different `assetType` strings. Mitigation: §3 groups by `(provider, component_class)` where `component_class` is a normalized mapping (compute, db, storage, network); document the mapping in §2 Methodology.
- **Risk 4 — Deviation severity assignment.** §5 severity column may default to `moderate` per row, which is fabrication. Mitigation: severity must be operator-supplied or derived from scg-comparator output; never defaulted.
- **Risk 5 — Cross-cloud reference-arch coverage gaps.** AWS reference-arch.ts may cover 30 services; GCP only 20; Azure only 15. §4 must surface coverage delta. Mitigation: §4 footer notes per-cloud coverage count.
- **Risk 6 — Baseline drift between emit-time and 3PAO sample-time.** Same as C.C1 §4 risk. Mitigation: include emit timestamp + inventory sha256 in §3 footer; §6 cadence requires monthly review.
- **Risk 7 — CIS Benchmarks license.** CIS Benchmarks are licensed; cannot copy verbatim. Mitigation: cite CIS Benchmark version + URL but do not paste content; reference-arch.ts files describe the configuration in original prose.

## Open questions (for implementation session to resolve)
- **Q1**: Should §3 enumerate per-asset baseline (every individual EC2 with its AMI ID) or grouped? Grouped scales better; per-asset aids 3PAO sampling.
- **Q2**: Should `core/scg-comparator.ts` ship with this slice (C.C9) or with LOOP-G.G5? If C.C9 ships first, the comparator API must be designed to accommodate G.G5's future needs.
- **Q3**: Should §5 deviations include a "since when" timestamp (when did the deviation appear in inventory)? Requires historical inventory tracking; out of current scope.
- **Q4**: How should the baseline-config doc handle ephemeral assets (auto-scaling group instances)? They have no stable baseline. Mitigation: group by ASG/MIG, not per-instance.
- **Q5**: Should §7 link to the CMP (C.C1) by relative path or by anchor (cmp.docx#§6)? Anchor links are not well-supported in .docx.
- **Q6**: Should the emitter validate that the operator-supplied `baselineReviewCadence` matches the value in the SSP CM-2 control implementation entry? Cross-check adds robustness.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by 13)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (C.C9 row + Overall section)
- [ ] LOOP-C-SPEC.md Section 7 row updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-C.C9:` in the message
- [ ] Commit amended with commit hash recorded
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Auto-loaded: `cloud-evidence/CLAUDE.md`.
2. This file gives source obligations + files + build steps + tests + risks + checklist.
3. Read `cloud-evidence/docs/loops/LOOP-C-SPEC.md` Section 2 + Section 6 (especially Q2 + Q3 about LOOP-G.G5 shared scg-comparator).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for commit pattern.
5. Read `cloud-evidence/providers/aws/reference-arch.ts` + `providers/gcp/reference-arch.ts` + `providers/azure/reference-arch.ts` — the grep targets for §4.
6. Read `cloud-evidence/core/inventory-emit.ts` — for inventory.json shape.
7. Read existing `cloud-evidence/core/scg-comparator.ts` IF present (otherwise the slice ships it).
8. Read NIST SP 800-128 §3.2 (URL above) — quoted verbatim in §1.
9. Read `cloud-evidence/core/roe-emit.ts` for the grep-against-source pattern this slice replicates.
10. Begin implementation; update Implementation log as you go.
