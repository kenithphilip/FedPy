---
slice_id: B.B1
title: Per-finding CVSS+EPSS+criticality+exposure scoring
loop: B
status: done
commit: 22b6590
completed_date: 2026-06-10
depends_on: [LOOP-A.A1, INV-P1, INV-P2, INV-P3, INV-P4, INV-P5, INV-S1, INV-S2, INV-S3, INV-S4, INV-S5, INV-S6]
blocks: [B.B2, B.B5, I.I1, E.E1, C.C7]
estimated_effort: 4-5 working days
last_updated: 2026-06-10
---

# B.B1 — Per-finding CVSS+EPSS+criticality+exposure scoring

## TL;DR
Replace the LOOP-A.A1 severity-only POA&M sort with a defensible, per-Finding composite risk score combining FIRST CVSS (3.1 + 4.0), FIRST EPSS, inventory-derived criticality, and inventory-derived exposure. The result is `out/risk-scores.json` plus a `risk_score` block on every Finding in every `KSI-*.json` envelope, surfaced as OSCAL props on every POA&M risk and poam-item so a 3PAO can sort + filter on numeric severity, not just a 5-bucket enum.

## Status
- Status: done
- Commit: 22b6590 (filled by the two-pass amend in SLICE-COMPLETION-PROCEDURE.md Step 6)
- Date: 2026-06-10
- Verification: typecheck=clean, tests=939/939 (+36 new), check:reo=green (G1 0 violations, G2 skip [no local out/], G3 OK)

## Why this slice exists
LOOP-A.A1 (`core/oscal-poam.ts:84-90`) keys every POA&M deadline off the `Severity` enum and sorts the catalog by the same enum. NIST SP 800-30 Rev 1 §3.2 ("Risk = function of Threat × Vulnerability × Likelihood × Impact") and the FedRAMP Continuous Monitoring Strategy & Guide both demand a defensible *per-finding* risk score before a deadline is assigned. The current system has:
- No CVSS — so a "high" CVE with CVSS 8.0 and a "high" misconfiguration with CVSS-equivalent ~6.0 are indistinguishable on the POA&M.
- No EPSS — so a CVSS-9.8 RCE with EPSS 0.001 is treated the same as a CVSS-9.8 RCE with EPSS 0.97.
- No organisational criticality — so a finding on a tier-3 dev sandbox VM ranks alongside the same finding on a tier-0 production CUI store.
- No exposure dimension — so a finding behind 3 NACLs ranks alongside the same finding on a public-facing ALB.

B.B1 closes all four gaps with operator-tunable weights, real (not mocked) FIRST EPSS HTTPS calls, real CVSS vector parsing per the FIRST specifications, and real `inventory.json` reads.

## Authoritative sources (with verbatim quotes)
- https://www.first.org/cvss/v3.1/specification-document — **FIRST CVSS v3.1 Specification Document (June 2019, rev'd)**:
  > "The Base Score is a function of the Impact and Exploitability sub-score equations. The Base Score formula is: If Impact sub-score ≤ 0 then 0, else (Scope Unchanged): Roundup(Minimum[(Impact + Exploitability), 10]); (Scope Changed): Roundup(Minimum[1.08 × (Impact + Exploitability), 10])."
  > "Qualitative Severity Rating Scale: None=0.0, Low=0.1-3.9, Medium=4.0-6.9, High=7.0-8.9, Critical=9.0-10.0" (Table 14).
  Metric value constants (§7.4): AttackVector Network=0.85, Adjacent=0.62, Local=0.55, Physical=0.2; AttackComplexity Low=0.77, High=0.44; PrivilegesRequired (Scope Unchanged) None=0.85, Low=0.62, High=0.27; UserInteraction None=0.85, Required=0.62; C/I/A High=0.56, Low=0.22, None=0.

- https://www.first.org/cvss/v4.0/specification-document — **FIRST CVSS v4.0 Specification Document (Nov 2023)**:
  > "A MacroVector is one of the sets of CVSS vectors that the expert evaluation process … determined to be of comparable qualitative severity."
  > "CVSS v4.0 reflects the Impact to the Vulnerable System (VC, VI, VA) and Subsequent System(s) (SC, SI, SA), replacing the v3.x Scope metric."
  > "A new Base Metric, Attack Requirements (AT), specifies the prerequisite deployment and execution conditions or variables of the vulnerable system."
  Same qualitative bands as v3.1 (None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0). Vector prefix `CVSS:4.0/`.

- https://www.first.org/epss/ — **FIRST EPSS overview**:
  > "EPSS is a data-driven effort for estimating the likelihood (probability) that a software vulnerability will be exploited in the wild."
  > "The EPSS model produces a probability score between 0 and 1 (0 and 100%). The higher the score, the greater the probability that a vulnerability will be exploited."

- https://api.first.org/data/v1/epss — **FIRST EPSS API**:
  Endpoint accepts `?cve=<comma-separated-list>`. Response shape (verified live): `{ "status":"OK","status-code":200,"version":"...","access":"public","total":N,"offset":0,"limit":100,"data":[{"cve":"CVE-XXXX-YYYY","epss":"0.97214","percentile":"0.99876","date":"YYYY-MM-DD"}] }`.

- https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf — **NIST SP 800-30 Rev 1, §3.2, Step 2 (Conduct the Assessment) and Appendix G**:
  > "Likelihood of Threat Event Initiation (Adversarial)" + "Likelihood of Threat Event Resulting in Adverse Impact" combine per §3.2 to "Overall Likelihood". The qualitative scale {Very Low, Low, Moderate, High, Very High} is reused VERBATIM in B.B5's Risk Register schema downstream — B.B1 supplies the numeric likelihood signal (EPSS) and impact signal (criticality) the band derivation reads.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, RA-5 (Vulnerability Monitoring and Scanning)** + **RA-3 (Risk Assessment)**:
  > "RA-5a. Monitor and scan for vulnerabilities in the system and hosted applications … and when new vulnerabilities potentially affecting the system are identified and reported."
  > "RA-3a. Conduct a risk assessment, including: identifying threats to and vulnerabilities in the system; the likelihood and magnitude of harm …".
  The B.B1 composite score is the per-finding "magnitude of harm" intermediate signal RA-3a needs.

- https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01 — **CISA BOD 22-01** (referenced for the CVE → KEV downstream branch consumed by B.B2; B.B1 stores `cve_ids` so B.B2 can match): Federal agencies must remediate KEV-catalog vulnerabilities by the per-entry `dueDate` (typically 14 or 21 days from `dateAdded`).

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/risk-score.ts` — pure scoring library: CVSS 3.1 + 4.0 vector parsing, EPSS lookup with on-disk cache, criticality/exposure derivation from inventory metadata, composite formula. ~600 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/risk-config.ts` — typed loader for `risk-config.yaml`. Validates weights sum to 1.0 ± 0.01, validates band thresholds monotonic, returns a `RiskScoringOpts` value.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/risk-score-emit.ts` — disk emitter: walks `out/KSI-*.json`, computes scores, rewrites envelopes in place with `risk_score` blocks, writes `out/risk-scores.json` with provenance block. Reads inventory + risk-config; calls EPSS API through `core/retry.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/risk-config.example.yaml` — committed example operator copies and customises.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/risk-score.test.ts` — unit tests for pure scoring math.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/risk-config.test.ts` — config loader tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/risk-score-emit.test.ts` — integration tests (read sample KSI-*.json, write risk-scores.json, verify props on re-emitted POA&M).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/risk-score/` — directory containing sample envelopes + inventory + risk-config used by tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/envelope.ts` — add optional `risk_score?: RiskScore` to the `Finding` interface (backward compatible).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/findings.ts` — extend `FindingInput` with optional `risk_score` so collectors that natively know CVSS (e.g. `vdr-scan.ts`) can attach at construction time.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — in `findingProps()` (line 377), append `composite-score`, `cvss-version`, `cvss-base`, `cvss-vector`, `epss-score`, `epss-percentile`, `criticality`, `exposure`, `risk-score-source-*` props when `f.risk_score` is set.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--risk-score` flag + env `CLOUD_EVIDENCE_RISK_SCORE`; `--risk-config <path>` + env `CLOUD_EVIDENCE_RISK_CONFIG`; runs BEFORE `--oscal-poam`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add roles `risk-scores-json` (filename `risk-scores.json`) + `epss-cache` (filename `.epss-cache.json`) to `WELL_KNOWN`.

## Schemas / standards
- **CVSS 3.1** — full Equations 1-7 per https://www.first.org/cvss/v3.1/specification-document . Parse vector strings of the form `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Worked example from the spec: that vector yields base 9.8 (Critical). Tests pin this exact value.
- **CVSS 4.0** — vector prefix `CVSS:4.0/`. First-cut implementation uses the qualitative band table from the spec (§7) to derive a Base score from the parsed metrics; full MacroVector equivalence-class table is a future enhancement (documented as REQUIRES-OPERATOR-INPUT when not implemented). The `cvss-version` prop carries the honest version string.
- **EPSS API** — `GET https://api.first.org/data/v1/epss?cve=<csv>`. Batch up to 100 CVEs per request. On-disk cache at `out/.epss-cache.json` keyed `{cve}-{date}` with 24-hour TTL. Cache file is a JSON object `{ entries: Record<string, EpssScore>, fetched_at: ISO }` and survives across runs.
- **Inventory metadata** (from INV-P1..S6):
  - `inventory.assets[].data_classification` ∈ `{public, internal, confidential, cui, pii}` — set via cloud tag `fedramp_data_classification` (AWS) / labels (GCP) or operator-supplied config.
  - `inventory.assets[].asset_tier` ∈ `{tier-0, tier-1, tier-2, tier-3}` — operator-tagged or org-derived.
  - `inventory.assets[].public_facing` — boolean derived from ELB/ALB scheme, GCP LB type, public IP presence.
  - `inventory.assets[].internet_reachable` — boolean derived from security-group/NACL ingress + route-table analysis (already computed in INV-S2/S3).
- **OSCAL POA&M v1.1.2** — `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json` + https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/ . The `risk.props[]` and `observation.props[]` arrays are the extension points; namespace is `CE_NS = "https://cloud-evidence.example/oscal-ns"` (already declared in `core/oscal-poam.ts`).

## Build steps (concrete, numbered)
1. Define typed interfaces in `core/risk-score.ts`:
   ```ts
   export interface CvssVector { version: '3.1' | '4.0'; vector: string; base_score: number; severity_label: 'None'|'Low'|'Medium'|'High'|'Critical'; parsed_metrics: Record<string,string>; }
   export interface EpssScore { cve: string; score: number; percentile: number; date: string; source: 'api'|'cache'|'config'; }
   export interface RiskScore { composite_score: number; cvss?: CvssVector; epss?: EpssScore; criticality: number; exposure: number; sources: { cvss_source: 'finding-cited'|'inventory-derived'|'operator-supplied'|'REQUIRES-OPERATOR-INPUT'; epss_source: 'api'|'cache'|'operator-supplied'|'REQUIRES-OPERATOR-INPUT'; criticality_source: 'inventory-tag'|'data-classification'|'asset-tier'|'REQUIRES-OPERATOR-INPUT'; exposure_source: 'inventory-public-facing'|'inventory-internet-reachable'|'REQUIRES-OPERATOR-INPUT'; }; computed_at: string; formula_version: 'risk-score.v1'; }
   ```
2. Pure builder: `export function computeRiskScore(finding: Finding, ctx: RiskContext, opts: RiskScoringOpts): RiskScore` — no side effects, no IO. Reads CVE list from `finding.references[]` + `finding.gap.affected_resources[].attributes.cve_ids`. Reads CVSS vectors from `finding.references[].cvss_vector`. Resolves affected resources against `ctx.inventory.assets[]` by identifier match.
3. **Composite formula** (operator-tunable):
   ```
   composite = w_cvss × cvss_base + w_epss × (epss × 10) + w_criticality × (criticality × 10) + w_exposure × (exposure × 10)
   ```
   Default weights: `w_cvss=0.4, w_epss=0.3, w_criticality=0.2, w_exposure=0.1` (sum = 1.0). When any input is `REQUIRES-OPERATOR-INPUT`, that term is dropped and remaining weights are re-normalised to sum to 1.0; the source prop on the OSCAL risk records which term was dropped so a 3PAO sees the gap.
4. **CVSS source priority**: (a) `finding.references[].cvss_vector` if present; (b) operator-supplied via config; (c) severity-derived fallback (critical→9.5, high→7.5, medium→5.5, low→2.5, info→0.5) marked `cvss_source: 'REQUIRES-OPERATOR-INPUT'`. Branch (c) is observable on every affected OSCAL risk via prop `risk-score-source-cvss`.
5. **EPSS lookup**: when `ctx.cve_ids.length > 0` AND `opts.epss.enabled === true`, batch-query the FIRST API. Use `core/retry.ts` for transient HTTP failures. On persistent failure, set `epss_source: 'REQUIRES-OPERATOR-INPUT'` — never silently substitute `epss = 0`. Cache at `out/.epss-cache.json` (24-hour TTL); cache hit → `source: 'cache'`.
6. **Criticality derivation**: for each affected resource resolve to `inventory.assets[]` by identifier; derive `data_class_score` (cui=1.0, pii=0.9, confidential=0.7, internal=0.4, public=0.1) and `asset_tier_score` (tier-0=1.0, tier-1=0.75, tier-2=0.5, tier-3=0.25); criticality = `max(data_class_score, asset_tier_score)` across resources. When no asset matched OR both fields absent on the matched asset, `criticality_source: 'REQUIRES-OPERATOR-INPUT'`, criticality = 0.5 (mid-range placeholder visible in the prop).
7. **Exposure derivation**: per matched asset, `exposure = 1.0` if `public_facing === true || internet_reachable === true`, else 0.2. Aggregate via max across resources. When no asset matched OR fields absent, `exposure_source: 'REQUIRES-OPERATOR-INPUT'`, exposure = 0.5.
8. Disk emitter in `core/risk-score-emit.ts`:
   ```ts
   export interface RiskScoreEmitOptions { outDir: string; inventoryPath?: string; riskConfigPath?: string; epssEnabled?: boolean; epssCachePath?: string; runId: string; }
   export interface RiskScoreEmitResult { path: string; scored_findings: number; unscored_findings: number; cve_lookups: number; epss_cache_hits: number; epss_api_calls: number; }
   export function emitRiskScores(opts: RiskScoreEmitOptions): Promise<RiskScoreEmitResult>;
   ```
   The emitter also rewrites each `KSI-*.json` envelope in-place to attach `finding.risk_score` for downstream consumers (POA&M, AR, dashboard). Provenance block on `risk-scores.json` records: emitter name, emittedAt, sourceCalls (which envelopes read, EPSS endpoint, inventory path), signingKeyId placeholder.
9. Wire orchestrator: `--risk-score` flag invokes `emitRiskScores()` BEFORE the OSCAL POA&M emitter. Documented order in `core/orchestrator.ts`: collect → score → POA&M → AR → bundle → sign → timestamp.
10. Extend `core/oscal-poam.ts:findingProps()` (line 377) to append:
    ```ts
    if (f.risk_score) {
      const rs = f.risk_score;
      props.push({ name: 'composite-score', ns: CE_NS, value: rs.composite_score.toFixed(2) });
      if (rs.cvss) { props.push({ name: 'cvss-version', ns: CE_NS, value: rs.cvss.version }); props.push({ name: 'cvss-base', ns: CE_NS, value: rs.cvss.base_score.toFixed(1) }); props.push({ name: 'cvss-vector', ns: CE_NS, value: rs.cvss.vector }); }
      if (rs.epss) { props.push({ name: 'epss-score', ns: CE_NS, value: rs.epss.score.toFixed(5) }); props.push({ name: 'epss-percentile', ns: CE_NS, value: rs.epss.percentile.toFixed(5) }); }
      props.push({ name: 'criticality', ns: CE_NS, value: rs.criticality.toFixed(2) });
      props.push({ name: 'exposure', ns: CE_NS, value: rs.exposure.toFixed(2) });
      props.push({ name: 'risk-score-source-cvss', ns: CE_NS, value: rs.sources.cvss_source });
      props.push({ name: 'risk-score-source-epss', ns: CE_NS, value: rs.sources.epss_source });
      props.push({ name: 'risk-score-source-criticality', ns: CE_NS, value: rs.sources.criticality_source });
      props.push({ name: 'risk-score-source-exposure', ns: CE_NS, value: rs.sources.exposure_source });
      props.push({ name: 'risk-score-formula', ns: CE_NS, value: rs.formula_version });
    }
    ```
11. Add to `submission-bundle.ts:WELL_KNOWN` (after `oscal-poam-xml` entry, line ~114):
    ```ts
    { role: 'risk-scores-json', filename: 'risk-scores.json', description: 'Per-finding CVSS+EPSS+criticality+exposure scores (LOOP-B.B1)' },
    { role: 'epss-cache', filename: '.epss-cache.json', description: 'On-disk EPSS API response cache (24h TTL)' },
    ```
12. Validation pass:
    - Run emitted `out/risk-scores.json` through `scripts/check-provenance.mjs` — must list a `provenance` block.
    - Run modified `out/poam.json` through `core/oscal-validate.ts` — must still pass POA&M v1.1.2 ajv schema (new props are in `CE_NS` namespace, schema-legal).
13. Sign + timestamp: `risk-scores.json` is picked up by the existing `core/sign.ts` glob + included in the RFC 3161 manifest.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 (`cloud-evidence/CLAUDE.md`), every field that cannot be auto-derived:

| Field | Source | Behavior when missing |
|---|---|---|
| `cvss_source` | Collector populates `finding.references[].cvss_vector`; or `risk-config.yaml` operator-supplied CVE→vector map | `cvss_source = 'REQUIRES-OPERATOR-INPUT'`, base score uses severity-fallback (marked in prop) — never marketed as real CVSS |
| `epss_source` | FIRST EPSS API (live HTTPS); or on-disk cache; or operator-supplied via config | On API failure: `epss_source = 'REQUIRES-OPERATOR-INPUT'`, EPSS term dropped from composite, prop surfaces the gap |
| `criticality_source` | Inventory asset `data_classification` + `asset_tier` (set via cloud tag `fedramp_data_classification` / `fedramp_asset_tier`) | `criticality_source = 'REQUIRES-OPERATOR-INPUT'`, criticality = 0.5 placeholder, prop surfaces the gap |
| `exposure_source` | Inventory asset `public_facing` + `internet_reachable` (auto-derived in INV-S2/S3 but can be operator-overridden via tag `fedramp_exposure_override`) | `exposure_source = 'REQUIRES-OPERATOR-INPUT'`, exposure = 0.5 placeholder, prop surfaces the gap |
| Composite weights | `risk-config.yaml` (CLI `--risk-config <path>`) | Defaults used; defaults documented in `risk-config.example.yaml` + module docstring |
| EPSS feed enable/disable | `risk-config.yaml` `epss.enabled` (default true) | Operator can disable; when disabled, EPSS term dropped + every prop carries `epss_source = 'REQUIRES-OPERATOR-INPUT'` |

## Test specifications (≥12 tests)
1. `it('parses CVSS 3.1 vector with Scope Unchanged producing the spec example 9.8')` — input `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, expect base 9.8, severity 'Critical', vector preserved.
2. `it('parses CVSS 3.1 vector with Scope Changed applying the 1.08 multiplier')` — verifies Equation 5 Scope Changed branch produces the spec's published 6.4 example.
3. `it('parses CVSS 4.0 MacroVector vector and emits version=4.0')` — input prefixed `CVSS:4.0/`, asserts `cvss.version === '4.0'`.
4. `it('classifies severity label per Table 14')` — boundary cases: 0.0→None, 0.1→Low, 4.0→Medium, 7.0→High, 9.0→Critical.
5. `it('emits REQUIRES-OPERATOR-INPUT cvss_source when no CVSS data and no operator config')` — assert sources prop set, composite uses severity-fallback.
6. `it('honours operator-supplied CVSS via finding.references[].cvss_vector')` — collector-supplied vector wins over severity-fallback.
7. `it('looks up EPSS via batch API and caches the result with 24h TTL')` — mocks HTTP at the wire layer (CLAUDE.md Rule 2.4); production code never knows it's being tested.
8. `it('reads from .epss-cache.json on subsequent run within TTL')` — second call: zero API hits, `epss.source === 'cache'`.
9. `it('marks epss_source = REQUIRES-OPERATOR-INPUT on persistent API failure')` — mock 5xx, assert no silent fallback to zero.
10. `it('derives criticality from inventory.assets data_classification')` — cui asset → criticality 1.0; public asset → criticality 0.1.
11. `it('derives criticality from asset_tier when data_class absent')` — tier-0 with no data_class → criticality 1.0.
12. `it('derives exposure from public_facing + internet_reachable')` — public_facing=true → exposure 1.0; both false → 0.2.
13. `it('emits REQUIRES-OPERATOR-INPUT exposure_source when fields absent')` — no asset match → exposure=0.5 placeholder, source marker set.
14. `it('computes composite per documented formula with default weights')` — worked example from LOOP-B-SPEC.md §9 (CVSS 9.8, EPSS 0.972, criticality 1.0, exposure 1.0 → composite 9.84).
15. `it('respects operator-tuned weights from risk-config.yaml')` — operator sets w_cvss=1.0 → composite equals CVSS base only.
16. `it('re-normalises composite when epss missing')` — drop epss term; remaining weights scaled to sum to 1.0.
17. `it('attaches risk_score to every Finding in re-emitted KSI-*.json envelopes')` — read envelope before + after emitter run; assert finding has new block.
18. `it('writes risk-scores.json with provenance.emitter + provenance.sourceCalls')` — `check:provenance` script scans the file and exits 0.
19. `it('OSCAL POA&M findingProps emits composite-score + cvss-* + epss-* props')` — re-emit POA&M, parse, find prop names + values.
20. `it('rejects risk-config.yaml when weights do not sum to 1.0')` — config loader throws typed error with field path.

## REO compliance specific to this slice
- Every CVSS score traces to either a collector-cited vector, an operator-supplied vector, or carries `cvss_source: REQUIRES-OPERATOR-INPUT` — no silent severity-fallback marketed as "real CVSS".
- EPSS lookups go through real HTTPS GET to `api.first.org`; on-disk cache is real JSON; on failure → REQUIRES-OPERATOR-INPUT, never `epss=0`.
- Composite formula is constant + operator-tunable; `formula_version: "risk-score.v1"` lets future re-scoring trace lineage.
- Inventory matches go through real `inventory.json` reads (no mocks in production paths).
- No `process.env.NODE_ENV === 'test'` branches anywhere; tests inject seams via dependency-injected HTTP fetcher.
- Provenance block on `risk-scores.json` populated with: emitter name, emittedAt (ISO), sourceCalls (envelopes read, EPSS endpoint URL, inventory path), signingKeyId.
- Signed by existing `core/sign.ts` pipeline (Ed25519 + RFC 3161) — `risk-scores.json` and `.epss-cache.json` both land in the manifest glob.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/risk-score.test.ts tests/core/risk-config.test.ts tests/core/risk-score-emit.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues
- **Risk 1: CVSS 4.0 MacroVector table incomplete in first ship.** The FIRST CVSS v4.0 spec uses an equivalence-class lookup table that is large (270+ entries). Mitigation: ship qualitative-band-derived score for 4.0 vectors in the first cut, flag `cvss-version=4.0-approximate` in the prop, and treat the full MacroVector table as an enhancement issue (not a blocker). The `cvss_source` value is honest about the approximation.
- **Risk 2: FIRST EPSS API rate limits not published.** A large run with hundreds of CVEs could trip an unspecified rate limit. Mitigation: batch up to 100 CVEs/request; use `core/retry.ts` exponential backoff on 429; cap retries at 5; on persistent failure mark `epss_source: REQUIRES-OPERATOR-INPUT`. Cache survives across runs — second-day runs largely hit the cache.
- **Risk 3: Inventory may lack `data_classification` / `asset_tier` tags.** Many real CSPs have not back-tagged their fleet. Mitigation: emit REQUIRES-OPERATOR-INPUT visibly on every affected risk's prop so the gap is auditable + actionable (tag the asset, re-run); never substitute a "tier-2 default" that looks real.
- **Risk 4: Severity-fallback CVSS could be mistaken for real CVSS by a 3PAO.** Mitigation: the `cvss-source` prop carries `REQUIRES-OPERATOR-INPUT` verbatim — surfacing the gap on every poam-item that uses it. Documented in operator runbook.
- **Risk 5: Composite formula version drift.** Changing default weights mid-authorization-cycle would shift the POA&M sort. Mitigation: `formula_version` field carries the version string; CHANGELOG entry pins the version; weight changes bump version and are called out in monthly ConMon delta.
- **Risk 6: EPSS API spec drift.** FIRST may add fields or change schema. Mitigation: the parser is permissive about extra fields and strict about the four we use (`cve, epss, percentile, date`); a missing required field surfaces as `epss_source: REQUIRES-OPERATOR-INPUT`.

## Open questions (RESOLVED 2026-06-10 during implementation)
- **Q1 — RESOLVED**: Committed `risk-config.example.yaml`; the operator copies it to `risk-config.yaml` (kept out-of-tree) and customises. The orchestrator auto-discovers `./risk-config.yaml` or takes `--risk-config <path>` / `CLOUD_EVIDENCE_RISK_CONFIG`.
- **Q2 — RESOLVED**: A CVE not in the EPSS dataset is reported in `lookupEpss().missing[]` and resolves to `epss_source: 'REQUIRES-OPERATOR-INPUT'` with the EPSS term dropped from the composite (re-normalised). No silent `epss=0`. (We did not add a distinct `'not-yet-scored'` enum value — REQUIRES-OPERATOR-INPUT is the single honest signal the props already surface.)
- **Q3 — RESOLVED**: `max` across matched assets for both criticality and exposure. `resolveCriticality`/`resolveExposure` in `core/risk-score.ts` implement max with a code comment.
- **Q4 — RESOLVED (deferred)**: The NVD CVE→CVSS auto-lookup remains out of B.B1 scope. Logged as risk **B.B1-EXT-2** in `docs/loops/LOOP-B-RISKS.md` (untracked-work pointer) rather than creating a speculative B.B6 stub.
- **Q5 — RESOLVED**: `core/retry.ts` `withRetry()` is a generic async retry (transient classifier already covers HTTP 429/5xx + network errors), so it is reused directly for the EPSS fetch — no new wrapper. Retry attempts are injectable via `EpssLookupOptions.retryAttempts` (default 5).
- **Q6 — RESOLVED**: `.epss-cache.json` and `risk-scores.json` are both written pretty-printed on disk; the embedded detached Ed25519 signature covers the **signature-blanked canonical (RFC-8785-style) form** via `serializeUnsignedCanonical()` (JSON round-trip drops `undefined` optional keys so the signed bytes match the on-disk form). This matches the LOOP-W.W1 convention.

## Implementation log (running journal — implementing session updates)
```
2026-06-10 | session impl-b-b1 | Shipped B.B1 end to end.
  Context: auto-detect flagged W.W2 as next-priority but W.W2 is blocked
  (depends_on E.E2 + J.J3 + B.B1, all pending at session start). Operator
  chose to ship B.B1 (this slice) instead — it is unblocked (deps A.A1 done
  + INV-P1..S6 shipped base) and is itself a W.W2 dependency + the top
  enabler for I/F/E/N/O.

  Created: core/risk-score.ts (pure CVSS 3.1/4.0 parser + EPSS lookup/cache +
  criticality/exposure derivation + composite formula), core/risk-config.ts
  (typed risk-config.yaml loader/validator), core/risk-score-emit.ts (disk
  emitter: walks out/KSI-*.json, attaches finding.risk_score in place, writes
  signed+provenanced risk-scores.json + provenance-stamped .epss-cache.json),
  risk-config.example.yaml, and 3 test files + tests/fixtures/risk-score/.
  Extended: core/envelope.ts (Finding.risk_score? + references[].cve_id/
  cvss_vector), core/findings.ts (FindingInput.risk_score), core/oscal-poam.ts
  (findingProps() emits composite-score/cvss-*/epss-*/criticality/exposure/
  risk-score-source-* props), core/orchestrator.ts (--risk-score / --risk-config
  / --risk-no-epss + env vars; emit runs BEFORE OSCAL POA&M + signing),
  core/submission-bundle.ts (WELL_KNOWN: risk-scores-json + epss-cache roles).

  Spec divergences (both documented + benign):
   - CVSS namespace: used the real CE_NS constant 'urn:fedramp:cloud-evidence'
     from core/oscal-poam.ts, NOT the 'https://cloud-evidence.example/oscal-ns'
     string in the B.B1 spec §"Schemas" (the spec string was stale).
   - CVSS 4.0 base is a documented first-cut qualitative approximation
     (approximate:true; version stays an honest '4.0'); full MacroVector table
     deferred (Risk 1 / B.B1-EXT-2).

  Verification: typecheck clean; vitest 939/939 (was 903, +36 new across the
  3 B.B1 test files); npm run check:reo green (G1 0 violations / G2 skip,
  no local out/ / G3 OK). All §8 tests T1-T20 covered.

  Risks added to LOOP-B-RISKS.md: B.B1-EXT-1 (W.W2 dependency-metadata
  inconsistency), B.B1-EXT-2 (NVD CVE→CVSS auto-lookup untracked work).
  Open questions Q1-Q6 all resolved (see "Open questions" above).
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [x] typecheck clean (`npm run typecheck`)
- [x] tests passing 100% (count increased by ≥20 for this slice's new tests — +36)
- [x] check:reo green (G1+G2+G3)
- [x] STATUS.md updated (slice row + Overall section)
- [x] LOOP-B-SPEC.md status table updated
- [x] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [x] CHANGELOG.md "Unreleased" entry added
- [x] Commit with slice ID in message
- [x] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-B-SPEC.md
- [x] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-B-SPEC.md` Section 2 (Dependencies) for cross-loop context.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/oscal-poam.ts` lines 84-90 (REMEDIATION_DEADLINE_DAYS) and 377+ (findingProps) — these are your extension points.
6. Read `cloud-evidence/core/envelope.ts` for the `Finding` interface — you'll add `risk_score?: RiskScore` here.
7. Read `cloud-evidence/core/submission-bundle.ts` `WELL_KNOWN` array — add two new entries.
8. Read `risk-config.example.yaml` (after you write it) — that's your operator UX.
9. Begin implementation; update Implementation log section as you go.

---
