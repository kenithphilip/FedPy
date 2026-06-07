---
slice_id: N.N4
title: MITRE ATT&CK technique mapping (techniques applicable to our boundary)
loop: N
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A3, B.B1, B.B2, N.N1, N.N2]
blocks: [E.E1, F.F7, I.I3, K.K1]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# N.N4 — MITRE ATT&CK technique mapping (techniques applicable to our boundary)

## TL;DR
Map MITRE ATT&CK Enterprise + Cloud techniques to FedPy KSIs + NIST 800-53 controls via committed pinned-version sources. Emit `out/attack-mapping.json` with a per-technique coverage row (`covered-full / covered-partial / covered-via-compensating / gap / not-applicable / REQUIRES-OPERATOR-INPUT`). Reconcile against the KEV catalog so a 3PAO can see which active CVEs map to which techniques. Extend `core/oscal-poam.ts:findingProps()` to append `attack-technique` + `attack-tactic` props per finding; emit one AR observation per technique row. Consumed by the LOOP-I.I3 dashboard heat-map, LOOP-E.E1 monthly ConMon report, LOOP-F.F7 SAR draft, and LOOP-K.K1 PenTest sample selection.

## Status
- Status: pending
- Commit: — (filled when shipped, per `docs/SLICE-COMPLETION-PROCEDURE.md`)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
FedPy already maps KEV CVEs → KSIs via the VDR pipeline. N.N4 closes the technique-level loop: technique → NIST control → KSI → finding. Reads `core/kev-feed.ts` output, the committed MITRE ATT&CK STIX 2.1 subset (`docs/sources/mitre-attack-cloud.subset.json`), the committed Center for Threat-Informed Defense ATT&CK→NIST mapping (`docs/sources/attack-nist-mappings.json`), the optional CTID `attack_to_cve` mapping, and the FRMR catalog (`docs/frmr-requirements.generated.json`). No new cloud SDK calls. Emits signed `out/attack-mapping.json` consumed by AR + POA&M extensions. The committed-pinned-version pattern matches the REO standard's "every byte traces to real evidence" requirement (no silent live-pulls at run time).

## Why this slice exists
- **NIST SP 800-53 Rev 5 RA-10 (Threat Hunting)** — requires an organisational baseline of known adversary techniques. Without a published technique map the baseline is informal.
- **NIST SP 800-53 Rev 5 CA-8 (Penetration Testing)** + **SI-3, SI-4** — reference technique-level coverage in scope-narrowing decisions. LOOP-K.K1 PenTest sample selection consumes the mapping.
- **MITRE ATT&CK Enterprise + Cloud** is the de-facto open standard for adversary techniques. FedRAMP 20x guidance (and the broader threat-informed-defense community) treats ATT&CK as the canonical technique catalog.
- The FedPy VDR pipeline maps CVE → KEV → KSI. N.N4 inserts the missing technique step: CVE → KEV → technique → KSI. A 3PAO reviewing a finding can now see "this maps to T1110 Brute Force under TA0006 Credential Access; mitigated by IAM-MFA + IAM-APM + IAM-AAM; covered-full at Moderate."

## Authoritative sources (with verbatim quotes)
- **MITRE ATT&CK Enterprise Tactics** — https://attack.mitre.org/tactics/enterprise/ — all 15 tactics quoted verbatim in `LOOP-N-SPEC.md §4`.
- **MITRE ATT&CK Cloud Matrix** — https://attack.mitre.org/matrices/enterprise/cloud/ — sub-matrices: Office Suite, Identity Provider, SaaS, IaaS.
- **MITRE ATT&CK STIX 2.1 data feed** — https://github.com/mitre/cti — official JSON STIX 2.1 representation. N.N4 pins a release tag (current at build time) and commits the Cloud-platform subset to `cloud-evidence/docs/sources/mitre-attack-cloud.subset.json`.
- **MITRE ATT&CK Mitigations** — https://attack.mitre.org/mitigations/enterprise/
- **Center for Threat-Informed Defense — ATT&CK→NIST 800-53 r5 Mappings** — https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/blob/main/frameworks/nist800-53-r5/mappings/nist800-53-r5-attack-mappings.json — N.N4 pins a release of this mapping file into `cloud-evidence/docs/sources/attack-nist-mappings.json`.
- **Center for Threat-Informed Defense — CWE-to-ATT&CK / attack_to_cve** — https://github.com/center-for-threat-informed-defense/attack_to_cve — N.N4 reuses for CVE → technique reconciliation; pinned subset committed at `cloud-evidence/docs/sources/attack-cve-mappings.json` (optional; rows without published mapping carry REQUIRES-OPERATOR-INPUT).
- **CISA KEV Catalog** — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json — already loaded by `core/kev-feed.ts`; each entry's `cveID` is reconciled against `attack-cve-mappings.json`.
- **NIST SP 800-53 Rev 5** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — RA-10, CA-8, SI-3, SI-4.
- **OSCAL AR `observation`** v1.1.2 — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/.
- **OSCAL POA&M `risk.props`** v1.1.2 — `core/oscal-poam.ts:findingProps()` extension point; namespace `CE_NS`.

## Files to create (exact paths under cloud-evidence/)
- `cloud-evidence/core/attack-mapping.ts` — pure builder.
- `cloud-evidence/core/attack-mapping-emit.ts` — disk emitter.
- `cloud-evidence/core/attack-stix-loader.ts` — STIX 2.1 reader for the committed subset; shape validator.
- `cloud-evidence/docs/sources/mitre-attack-cloud.subset.json` — pinned STIX subset (Cloud-platform sub-matrix entries; Office Suite / Identity Provider / SaaS / IaaS).
- `cloud-evidence/docs/sources/attack-nist-mappings.json` — pinned CTID mapping JSON.
- `cloud-evidence/docs/sources/attack-cve-mappings.json` — pinned CTID `attack_to_cve` mapping JSON (optional; CHANGELOG documents pinned version).
- `cloud-evidence/scripts/refresh-attack-mappings.mjs` — operator-run script that re-pulls upstream sources + versions the subset; not auto-run.
- `cloud-evidence/tests/core/attack-mapping.test.ts` — pure-builder tests.
- `cloud-evidence/tests/core/attack-mapping-emit.test.ts` — emitter tests.
- `cloud-evidence/tests/core/attack-stix-loader.test.ts` — loader tests.
- `cloud-evidence/tests/fixtures/attack-mapping/` — fixture inventory + KEV slice + POA&M.
- `tracker/client/src/pages/AttackMatrix.tsx` — heat-map view of techniques × coverage (reuses existing dashboard pattern, no new server route).
- `tracker/client/src/pages/AttackMatrix.test.tsx`.

## Files to extend
- `cloud-evidence/core/oscal-poam.ts` — `findingProps()` (line 377) appends `attack-technique` + `attack-tactic` props per finding's CVE list via `lookupTechniquesForCve()`.
- `cloud-evidence/core/oscal.ts` (AR builder) — per technique row, emit an `observation` with `methods: ['EXAMINE']`, `props["attack-technique"]`, `props["attack-tactic"]`, `relevant-evidence` → coverage row JSON Pointer.
- `cloud-evidence/core/orchestrator.ts` — `--attack-mapping` flag (env `CLOUD_EVIDENCE_ATTACK_MAPPING`); runs AFTER B.B1 + B.B2 + N.N1 (uses findings + KEV + threat-model).
- `cloud-evidence/core/submission-bundle.ts` — add role `attack-mapping-json` (filename `attack-mapping.json`).
- `tracker/client/src/App.tsx` — add `/attack-matrix` route.

## Schemas / standards
- **`TechniqueCoverageStatus`** enum: `covered-full | covered-partial | covered-via-compensating | gap | not-applicable | REQUIRES-OPERATOR-INPUT`.
- **`AttackTechniqueRow`** interface per `LOOP-N-SPEC.md §5 N.N4 build step 1`: `{ technique_id, technique_name, tactic_ids[], tactic_names[], platforms[], applicable_to_system, mitigating_nist_controls[], mitigating_ksis[], coverage_status, active_kev_cve_ids[], observed_findings[], sources: { stix_pinned_version, mapping_pinned_version, kev_fetched_at } }`.
- **`AttackMapping`** interface: `{ uuid, emittedAt, formula_version: 'attack-mapping.v1', system_id, impact_level, rows[], totals: Record<TechniqueCoverageStatus, number>, tactic_summary: Record<tactic_id, { tactic_id, tactic_name, technique_count, covered, gap }>, provenance }`.
- **MITRE ATT&CK STIX 2.1** — each `attack-pattern` carries `external_references[]` (T-id), `kill_chain_phases[]` (tactic mapping), `x_mitre_platforms[]`, `x_mitre_data_sources[]`, `x_mitre_detection`.
- **ATT&CK→NIST 800-53 Rev 5 Mapping** — each row: `{ technique_id, control_id, mapping_type }`.
- **OSCAL POA&M v1.1.2** — `risk.props[name=attack-technique,ns=CE_NS]`, `risk.props[name=attack-tactic,ns=CE_NS]`.
- **OSCAL AR v1.1.2** — `observation.methods: ['EXAMINE']`.

## Build steps (concrete, numbered)
1. Define typed interfaces in `core/attack-mapping.ts` per spec §5 N.N4 step 1.
2. STIX loader (`core/attack-stix-loader.ts`): reads pinned subset JSON; exposes `loadAttackCatalog(): { techniques, tactics, mitigations }`. Validates JSON-shape (presence of `type: "attack-pattern"`, `kill_chain_phases[]`, `external_references[]` with source_name `mitre-attack`). Strictly typed exports.
3. Pure builder (`core/attack-mapping.ts`): `buildAttackMapping(inventory, attackCatalog, attackToNistMapping, kevCatalog, attackCveMappings, ksiMap, controlBenchmark, poamFindings, impactLevel): AttackMapping`. Algorithm:
   - **Platform filter**: filter techniques to those with `x_mitre_platforms` overlapping the inventory's detected platforms. Derive inventory platforms from the inventory's provider mix (AWS / GCP / Azure / Containers / IaaS / SaaS / Identity Provider / Office Suite). For SaaS-only CSP, ignore host-only Linux/Windows/macOS techniques unless an inventory component matches.
   - **Mitigating controls**: for each applicable technique, resolve via the ATT&CK→NIST mapping; filter to controls in `controlBenchmark` at `impactLevel`.
   - **Mitigating KSIs**: resolve via `ksi-map.ts` (NIST control → KSI canonical name).
   - **Coverage status**:
     - `covered-full` if every mitigating control is "implemented" per benchmark.
     - `covered-partial` if some implemented, some open.
     - `covered-via-compensating` if all open but a B.B4 compensating control is linked.
     - `gap` if mappings exist but none implemented.
     - `not-applicable` if `applicable_to_system === false`.
     - `REQUIRES-OPERATOR-INPUT` if the mapping has zero rows at this impact level.
   - **KEV reconcile**: for each KEV entry, find which technique it maps to via `attackCveMappings`; missing mapping → REQUIRES-OPERATOR-INPUT: technique-classification. Append CVE to row's `active_kev_cve_ids[]`.
   - **POA&M reconcile**: for each POA&M finding whose `references[].cve_ids` overlaps `active_kev_cve_ids`, append finding uuid to row's `observed_findings[]`.
4. Disk emitter (`core/attack-mapping-emit.ts`): signature per spec §5 N.N4 step 4. Reads inventory + POA&M + pinned source files; writes `out/attack-mapping.json` with provenance block listing pinned versions.
5. POA&M prop emission (extend `core/oscal-poam.ts:findingProps()` at line 377): per spec §5 N.N4 step 5. For each CVE in finding.references, look up techniques via `attackCveMappings`; for each technique, append `attack-technique` + `attack-tactic` props. Each prop in namespace `CE_NS`.
6. AR observation emission (extend `core/oscal.ts`): one observation per technique row. `methods: ['EXAMINE']`. Props: `attack-technique`, `attack-tactic[]` (one prop per tactic), `attack-coverage-status`, `mitigating-ksi[]`, `mitigating-nist-control[]`. `relevant-evidence[].href` → `./attack-mapping.json#/rows/<idx>`.
7. Bundler integration: add role `attack-mapping-json` to `WELL_KNOWN`.
8. Refresh script (`scripts/refresh-attack-mappings.mjs`): operator runs manually. Fetches latest STIX from MITRE CTI repo at a release tag; fetches latest CTID mapping at a release tag; writes pinned Cloud-platform subset + `attack-nist-mappings.json` + `attack-cve-mappings.json`. CHANGELOG entry pins each version.
9. Tracker dashboard heat-map (`tracker/client/src/pages/AttackMatrix.tsx`): renders `out/attack-mapping.json#/rows[]` as a tactic × technique grid; cell color reflects `coverage_status`. Reads JSON via the existing tracker API for collector-run viewer.
10. Validation pass: emitted `out/attack-mapping.json` runs through `scripts/check-provenance.mjs`; modified `out/poam.json` + `out/ar.json` run through `core/oscal-validate.ts`.
11. Signing + timestamping: `attack-mapping.json` picked up by existing `core/sign.ts` glob + RFC 3161 manifest.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

| Field | Source | Behaviour when missing |
|---|---|---|
| `applicable_to_system` heuristic | inventory `platforms` derivation; tag overrides | ambiguous → operator confirms via tracker (e.g. SaaS CSP with Office Suite integrations) |
| `coverage_status: REQUIRES-OPERATOR-INPUT` | ATT&CK→NIST mapping zero rows at impact level | operator supplies compensating-control reference (B.B4) or marks N/A with justification |
| CVE → technique mapping | CTID `attack_to_cve` repo | not in repo → row's `active_kev_cve_ids` carries the CVE with `mapping_source: 'REQUIRES-OPERATOR-INPUT: technique-classification'`; operator supplies via tracker / config |
| Pinned subset version | `scripts/refresh-attack-mappings.mjs` (operator-run) | committed file always present; refresh is operator-cadence |

## Test specifications (≥12 tests)
1. `it('loads pinned STIX subset and exposes techniques + tactics + mitigations', ...)` — shape validation passes; expected counts.
2. `it('filters techniques by x_mitre_platforms vs inventory platforms', ...)` — AWS-only inventory drops Azure-only techniques.
3. `it('resolves mitigating NIST controls via ATT&CK→NIST mapping at Moderate baseline', ...)`.
4. `it('resolves mitigating KSIs via ksi-map.ts', ...)`.
5. `it('classifies coverage-full when all mitigating controls implemented', ...)`.
6. `it('classifies covered-via-compensating when B.B4 CC linked', ...)`.
7. `it('classifies gap when mappings exist but none implemented', ...)`.
8. `it('classifies REQUIRES-OPERATOR-INPUT when mapping has zero rows', ...)`.
9. `it('reconciles active_kev_cve_ids via attack_to_cve mapping', ...)`.
10. `it('emits REQUIRES-OPERATOR-INPUT for KEV CVE without a CTID mapping', ...)` — fixture CVE not in mapping fixture.
11. `it('reconciles observed_findings by CVE overlap with POA&M', ...)`.
12. `it('totals counts_by_status sum to rows.length', ...)`.
13. `it('produces tactic_summary with correct technique_count per tactic', ...)`.
14. `it('attack-mapping.json provenance block lists STIX + mapping pinned versions', ...)`.
15. `it('POA&M findingProps appends attack-technique + attack-tactic props', ...)` — re-emit POA&M; find props.
16. `it('AR observation per technique row emits attack-technique prop', ...)`.
17. `it('bundler includes attack-mapping-json role', ...)`.
18. `it('refresh script writes a new subset with updated pinned version', ...)` — mock the upstream fetch at the wire layer.
19. `it('STIX loader rejects malformed JSON with typed error', ...)` — shape validation.
20. `it('signs attack-mapping.json with Ed25519 + RFC 3161', ...)`.

## REO compliance
- ATT&CK subset + NIST mapping + CVE mapping JSONs are committed pinned-version artifacts under `docs/sources/`; NOT silently re-pulled at run time.
- KEV catalog read via existing `core/kev-feed.ts` (already real).
- Unmapped techniques emit `REQUIRES-OPERATOR-INPUT`; never silent `covered` default.
- POA&M prop additions go through `CE_NS` namespace + ajv validation.
- Provenance block lists pinned versions of every source: `stix_pinned_version`, `mapping_pinned_version`, `kev_fetched_at`, ATT&CK + CTID + NIST 800-53 citation refs.
- No `process.env.NODE_ENV === 'test'` branches anywhere.
- Refresh script writes new pinned versions atomically; CHANGELOG entry pins the version when refreshed.
- Signed by existing `core/sign.ts` pipeline.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/attack-mapping.test.ts tests/core/attack-mapping-emit.test.ts tests/core/attack-stix-loader.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd "../tracker"
npm run typecheck
npm test -- client/src/pages/AttackMatrix.test.tsx
```

## Known risks / issues
- **Risk 1: MITRE ATT&CK release cadence drift.** ATT&CK ships a release every ~6 months; pinned subset must be refreshed periodically or the catalog becomes stale. Mitigation: refresh script + operator runbook + CHANGELOG cadence; out-of-date warning if `stix_pinned_version` is > 9 months old (cross-ref `N-X6`).
- **Risk 2: CVE → technique mapping incomplete.** CTID `attack_to_cve` does not cover every CVE. Mitigation: unmapped CVEs emit REQUIRES-OPERATOR-INPUT; operator can supply via tracker; a future N.N4 follow-up could use NLP over CVE descriptions to suggest mappings.
- **Risk 3: Subset curation burden.** The Cloud sub-matrix has ≥100 techniques; the committed subset must be curated to platforms actually present in the CSP's inventory. Mitigation: refresh script accepts `--platforms <list>` to scope the subset; CHANGELOG documents which platforms are included.
- **Risk 4: STIX 2.1 schema drift in MITRE CTI.** MITRE may change field names in a future release. Mitigation: shape validator in `attack-stix-loader.ts` rejects unrecognised shapes with a typed error; pin major STIX version.
- **Risk 5: ATT&CK→NIST mapping deprecation.** CTID may publish breaking changes. Mitigation: pin mapping file version + commit hash; refresh script flags non-additive changes for operator review.
- **Risk 6: Heat-map UX overload.** A full ATT&CK matrix has 15 tactics × dozens of techniques; rendering can overwhelm the dashboard. Mitigation: heat-map defaults to top-level tactic summary; click-through expands per-tactic technique rows.
- **Risk 7: Coverage status double-counting.** A finding may map to multiple techniques; aggregation could over-count. Mitigation: `tactic_summary.covered` counts distinct techniques; pin with a test.
- **Risk 8: POA&M prop count growth.** A finding with 5 CVEs each mapping to 3 techniques yields 15 `attack-technique` props + 15 `attack-tactic` props. OSCAL accepts arrays, but downstream consumers may not paginate. Mitigation: deduplicate props (set semantics) per finding; pin with a test.

## Open questions
- **Q1**: Should the refresh script be a Make / npm script or a standalone GitHub Actions workflow? Recommend: npm script for first ship + a scheduled GitHub Actions workflow that opens a PR with the refreshed subset (operator reviews/merges).
- **Q2**: How do we treat techniques whose ATT&CK→NIST mapping has multiple `mapping_type` values (e.g. `mitigates` vs `detects`)? Recommend: use only `mitigates`; `detects` mappings inform LOOP-E.E1 + LOOP-I.I3 ConMon alerting (not the coverage matrix). Document in module docstring.
- **Q3**: When a technique has `x_mitre_platforms: ['Linux', 'Windows', 'macOS']` and our inventory has Containers running Linux, do we include the technique? Recommend: yes — container host OS counts. Pin with a test using an EKS-only fixture.
- **Q4**: Subset commit size — the Cloud sub-matrix STIX could be 500 KB - 2 MB. Recommend: commit the subset file (it's a source citation), use `--platforms` to keep it minimal, document size budget in operator runbook.

## Worked example — T1110 Brute Force coverage row

The slice's test suite encodes this exact row. Inputs:

- Inventory: AWS-only CSP with IAM Identity Center + Cognito + RDS instances. Platforms detected: `["AWS", "Identity Provider", "IaaS"]`.
- ATT&CK subset pinned at `attack-pattern--v15.1`. T1110 carries `x_mitre_platforms: ["AWS","Azure","GCP","Office Suite","SaaS","Identity Provider","Linux","Windows","macOS","Network","Containers"]` — overlaps inventory → applicable.
- ATT&CK→NIST mapping rows for T1110: `[{T1110, AC-7, mitigates}, {T1110, IA-5(1), mitigates}, {T1110, IA-2(1), mitigates}, {T1110, IA-2(2), mitigates}, {T1110, IA-2(11), mitigates}]`. Moderate baseline includes all five.
- `ksi-map.ts`: AC-7 → IAM-AAM; IA-5(1) → IAM-APM; IA-2(*) → IAM-MFA. Distinct KSIs: `[IAM-MFA, IAM-APM, IAM-AAM]`.
- Control benchmark says all five controls are implemented at Moderate → `coverage_status: 'covered-full'`.
- KEV catalog: no CVE-mapped-to-T1110 currently active. `active_kev_cve_ids: []`.
- POA&M: no finding overlaps. `observed_findings: []`.

Emitted row:
```json
{
  "technique_id": "T1110",
  "technique_name": "Brute Force",
  "tactic_ids": ["TA0006"],
  "tactic_names": ["Credential Access"],
  "platforms": ["AWS","Azure","GCP","Office Suite","SaaS","Identity Provider","Linux","Windows","macOS","Network","Containers"],
  "applicable_to_system": true,
  "mitigating_nist_controls": ["AC-7","IA-5(1)","IA-2(1)","IA-2(2)","IA-2(11)"],
  "mitigating_ksis": ["IAM-MFA","IAM-APM","IAM-AAM"],
  "coverage_status": "covered-full",
  "active_kev_cve_ids": [],
  "observed_findings": [],
  "sources": {
    "stix_pinned_version": "attack-pattern--v15.1",
    "mapping_pinned_version": "ctid-nist800-53r5-v1.2",
    "kev_fetched_at": "2026-06-07T00:00:00Z"
  }
}
```

AR observation:
```json
{
  "uuid": "<v5(system_id, 'T1110')>",
  "description": "ATT&CK technique T1110 Brute Force coverage row",
  "methods": ["EXAMINE"],
  "props": [
    { "name": "attack-technique", "ns": "CE_NS", "value": "T1110" },
    { "name": "attack-tactic", "ns": "CE_NS", "value": "TA0006" },
    { "name": "attack-coverage-status", "ns": "CE_NS", "value": "covered-full" },
    { "name": "mitigating-ksi", "ns": "CE_NS", "value": "IAM-MFA" },
    { "name": "mitigating-ksi", "ns": "CE_NS", "value": "IAM-APM" },
    { "name": "mitigating-ksi", "ns": "CE_NS", "value": "IAM-AAM" },
    { "name": "mitigating-nist-control", "ns": "CE_NS", "value": "AC-7" },
    { "name": "mitigating-nist-control", "ns": "CE_NS", "value": "IA-5(1)" },
    { "name": "mitigating-nist-control", "ns": "CE_NS", "value": "IA-2(1)" }
  ],
  "relevant-evidence": [
    { "href": "./attack-mapping.json#/rows/N" }
  ]
}
```

Downstream:
- LOOP-I.I3 dashboard heat-map renders the TA0006 column's T1110 cell green (`covered-full`).
- LOOP-E.E1 monthly ConMon delta reports `tactic_summary[TA0006].covered = N of M`.
- LOOP-F.F7 SAR §3.4 lists T1110 under "covered surfaces".
- LOOP-K.K1 PenTest sample selection considers T1110 covered-full → may de-prioritize for the sample (operator policy).

If tomorrow a KEV entry adds `CVE-2026-1234` mapped to T1110 via the CTID `attack_to_cve` repo, the next emit picks it up: `active_kev_cve_ids: ['CVE-2026-1234']`. If a POA&M finding cites that CVE, `observed_findings` lists the finding UUID. The POA&M finding's props gain `attack-technique: T1110` + `attack-tactic: TA0006` automatically via the extended `findingProps()`.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean in both `cloud-evidence/` and `tracker/`
- [ ] tests passing 100% (count increased by ≥20 cloud-evidence + ≥2 tracker for this slice)
- [ ] `out/attack-mapping.json` emitted; signed; provenance complete
- [ ] check:reo green (G1+G2+G3)
- [ ] check:provenance green for `out/attack-mapping.json`
- [ ] STATUS.md updated (slice row + Overall section; LOOP-N marked complete)
- [ ] LOOP-N-SPEC.md §8 status table updated (final slice — loop complete)
- [ ] This file's frontmatter updated (`status: done`, `commit: <hash>`, `completed_date: <ISO>`)
- [ ] LOOP-N-RISKS.md per-slice section updated; cross-cutting risks reviewed for closure
- [ ] CHANGELOG.md "Unreleased" entry added (cite pinned versions of all 3 source files)
- [ ] `docs/sources/mitre-attack-cloud.subset.json` committed with version pin
- [ ] `docs/sources/attack-nist-mappings.json` committed with version pin
- [ ] `docs/sources/attack-cve-mappings.json` committed with version pin
- [ ] Commit with `LOOP-N.N4` in message
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-N-SPEC.md` §5 N.N4 and §11 Appendix (worked example for T1110).
3. Read `cloud-evidence/docs/loops/LOOP-N-RISKS.md` cross-cutting + N.N4 sections.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Read `core/kev-feed.ts` (KEV fetcher), `core/oscal-poam.ts:377+` (findingProps extension point), `core/ksi-map.ts` (NIST control → KSI lookup), `core/control-benchmark.ts` (impact-level controls), `core/inventory-coverage.ts` (provenance block pattern).
6. Read `docs/sources/` directory — pinned source file pattern.
7. Read `docs/frmr-requirements.generated.json` for KSI canonical IDs.
8. Begin implementation; update Implementation log section as you go.

---
