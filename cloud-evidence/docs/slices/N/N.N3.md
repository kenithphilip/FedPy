---
slice_id: N.N3
title: PASTA / red-team adversarial test framework (automated runs)
loop: N
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A3, LOOP-A.A4, B.B1, B.B2, N.N1, N.N2]
blocks: [N.N4, F.F4, RFC-0014-evidence]
estimated_effort: 7-9 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# N.N3 — PASTA / red-team adversarial test framework (automated runs)

## TL;DR
The trust basis of RFC-0014 "truly automated and opinionated validation" depends on adversarial evidence: when an envelope is tampered, a signature is replayed, a fixture is injected, a KEV reconcile is bypassed, an OSCAL chain is corrupted — does the pipeline detect and fail closed? N.N3 ships an adversarial-test framework that exercises real production code paths (no `NODE_ENV === 'test'` branches) under mutation. The runner emits a signed `out/adversarial-results.json` manifest; CI gates on `verdict: 'pass'` across ≥10 seed scenarios. AR observations cite each verdict so a 3PAO can audit pipeline resilience.

## Status
- Status: pending
- Commit: — (filled when shipped, per `docs/SLICE-COMPLETION-PROCEDURE.md`)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
FedPy mission asserts that every emitted artifact is signed, provenance-tracked, and resilient under adversarial mutation. N.N3 is the operational proof of that assertion — it is the FIRST FedPy artifact whose evidentiary value is "we attacked the pipeline and it held". Tests live entirely under `cloud-evidence/tests/adversarial/` (per CLAUDE.md Rule 1 boundary: production paths never know they're being tested). The mutators inject through public APIs only — `core/envelope.ts` verify, `core/sign.ts` verifySignature, `core/oscal.ts` import-ap chain check, `core/kev-feed.ts` parser, etc. Each adversarial run produces signed evidence consumed by AR `observation.props["adversarial-result"]` so a 3PAO can request the specific scenario verdict.

## Why this slice exists
- **RFC-0014 §3 ("Automated and Opinionated Validation")** — Phase Two Moderate requires automated validation. The trust claim depends on adversarial evidence demonstrating the pipeline detects tampering + fails closed.
- **NIST SP 800-53 Rev 5 SA-11(5) Penetration Testing** + **CA-8 Penetration Testing** — the framework provides ongoing internal red-team evidence between formal pen tests.
- **NIST SP 800-115 §6 Penetration Testing** — four-phase planning → discovery → attack → reporting. The runner emits a phase marker per scenario.
- **PASTA — Process for Attack Simulation and Threat Analysis** — Stage V (Threat Analysis), Stage VI (Vulnerability and Weakness Analysis), Stage VII (Attack Modeling), Stage VIII (Risk and Impact Analysis). Each scenario cites the PASTA stage exercised.

Without N.N3 the FedPy pipeline could ship a silently-broken signature verifier or a permissive OSCAL chain check, and nothing in the existing test suite would catch it (existing tests verify the happy path). A 3PAO reviewing the trust claim has no evidence to challenge.

## Authoritative sources (with verbatim quotes)
- **RFC-0014 (FedRAMP 20x Phase Two — Automated/Opinionated Validation)** — https://www.fedramp.gov/rfcs/0014/
  > "Phase Two Moderate explicitly mandates truly automated and opinionated validation of Key Security Indicators".
- **NIST SP 800-53 Rev 5** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - **SA-11(5) Penetration Testing**: developer + operational pen-test evidence.
  - **CA-8 Penetration Testing**: organisational baseline.
- **NIST SP 800-115 §6 Penetration Testing** — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf — four-phase model.
- **PASTA — Process for Attack Simulation and Threat Analysis** — https://www.versprite.com/blog/what-is-pasta-threat-modeling/ — seven-stage methodology.
- **OSCAL AR `observation.methods`** — v1.1.2 enumerated values `["EXAMINE","INTERVIEW","TEST"]`; N.N3 uses `"TEST"` per https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/.
- **OWASP Application Security Verification Standard (ASVS) §V14.1 — Build** — https://owasp.org/www-project-application-security-verification-standard/ — informs ADV-002 fixture-injection design.
- **CISA KEV Catalog** — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json — already loaded by `core/kev-feed.ts`; ADV-004 exercises bypass.
- **RFC 3161 — Time-Stamp Protocol** — https://datatracker.ietf.org/doc/html/rfc3161 — ADV-003 replay attack exercises timestamp validation.

## Files to create (exact paths under cloud-evidence/)
- `cloud-evidence/core/adversarial-test-runner.ts` — orchestrates scenarios; emits `out/adversarial-results.json` with signed provenance.
- `cloud-evidence/core/adversarial-scenarios.ts` — typed catalog of scenarios. Each scenario has id, title, pasta_stage, nist_800_115_phase, target, mutator (pure function), expected_outcome, citation. Minimum 10 seed scenarios (ADV-001 … ADV-010).
- `cloud-evidence/tests/adversarial/signature-tamper.test.ts` — ADV-001.
- `cloud-evidence/tests/adversarial/fixture-injection.test.ts` — ADV-002.
- `cloud-evidence/tests/adversarial/replay-attack.test.ts` — ADV-003.
- `cloud-evidence/tests/adversarial/kev-bypass.test.ts` — ADV-004.
- `cloud-evidence/tests/adversarial/oscal-chain-corruption.test.ts` — ADV-005.
- `cloud-evidence/tests/adversarial/epss-poisoning.test.ts` — ADV-006.
- `cloud-evidence/tests/adversarial/ksi-map-shadowing.test.ts` — ADV-007.
- `cloud-evidence/tests/adversarial/threat-model-tampering.test.ts` — ADV-008.
- `cloud-evidence/tests/adversarial/attack-surface-injection.test.ts` — ADV-009.
- `cloud-evidence/tests/adversarial/submission-bundle-collision.test.ts` — ADV-010.
- `cloud-evidence/tests/core/adversarial-test-runner.test.ts` — meta-tests of the runner itself.
- `cloud-evidence/tests/fixtures/adversarial/` — fixture envelopes + feeds + chain files used by mutators.
- `tracker/server/routes/adversarial-runs.ts` — read-only run viewer.
- `tracker/server/routes/adversarial-runs.test.ts`.
- `tracker/client/src/pages/AdversarialRuns.tsx` — UI listing past runs.
- `tracker/client/src/pages/AdversarialRuns.test.tsx`.

## Files to extend
- `cloud-evidence/core/oscal.ts` (AR builder) — per adversarial run, emit `observation` with `methods: ['TEST']`, `props[name=adversarial-scenario-id]`, `props[name=adversarial-verdict]`.
- `cloud-evidence/core/orchestrator.ts` — `--adversarial` flag (env `CLOUD_EVIDENCE_ADVERSARIAL`), `--strict-adversarial` (env `CLOUD_EVIDENCE_STRICT_ADVERSARIAL`), `--scenario-filter <id-list>`.
- `cloud-evidence/core/submission-bundle.ts` — add role `adversarial-results-json` (filename `adversarial-results.json`).
- `cloud-evidence/package.json` — add `"adversarial": "node --import tsx core/adversarial-test-runner.ts"` script.
- `.github/workflows/ci.yml` — add `npm run adversarial` job with `CLOUD_EVIDENCE_STRICT_ADVERSARIAL=1`; fails CI on any `verdict: 'fail'`.
- `tracker/server/schema.sql` — additive table `adversarial_test_runs` (append-only history).
- `tracker/server/index.ts` — mount `routes/adversarial-runs.ts`.
- `tracker/client/src/App.tsx` — add `/adversarial-runs` route.

## Schemas / standards
- **`AdversarialOutcome`** enum: `fail-closed | detected-diagnostic | fail-open-DEFECT | unexpected-pass-DEFECT | inconclusive`.
- **`AdversarialScenario`** interface per `LOOP-N-SPEC.md §5 N.N3 build step 1`: `{ id, title, pasta_stage, nist_800_115_phase, target, mutator, expected_outcome, citation }`.
- **`AdversarialRunResult`** interface: `{ uuid, ranAt, run_id, scenario_id, observed_outcome, observed_diagnostic?, verdict ('pass'|'fail'), pipeline_artifacts_hash (sha256), provenance }`.
- **`AdversarialResultsManifest`** interface: `{ uuid, emittedAt, formula_version: 'adversarial.v1', runs[], totals: { pass, fail, inconclusive }, provenance }`.
- **OSCAL AR `observation.methods`** — `'TEST'`.
- **`adversarial_test_runs` SQLite schema** — per `LOOP-N-SPEC.md §5 N.N3 build step 6`; columns: `id, uuid, run_id, scenario_id, expected_outcome, observed_outcome, verdict, pipeline_artifacts_hash, ran_at, signature, signing_key_id`. Indexes on run_id, scenario_id, verdict.

## Build steps (concrete, numbered)
1. Define typed interfaces in `core/adversarial-test-runner.ts` (per spec §5 N.N3 step 1).
2. Runner (`runAdversarialScenarios(opts): Promise<AdversarialResultsManifest>`): iterates `ADVERSARIAL_SCENARIOS` from `adversarial-scenarios.ts`; for each, applies the mutator to a fixture; invokes the REAL production code path on the mutated input; observes outcome (`fail-closed`, `detected-diagnostic`, or DEFECT). Mismatch → `verdict: 'fail'` + CI exit non-zero in strict mode.
3. Author the 10 seed scenarios in `core/adversarial-scenarios.ts`:
   - **ADV-001 Signature tamper** — flip a byte of envelope payload after signing; re-verify; expect `fail-closed` (signature check returns false). Target: `envelope-signing`. PASTA: V. NIST 800-115: attack.
   - **ADV-002 Fixture injection** — submit a `tests/fixtures/...` envelope through the production file-ingest path; expect `detected-diagnostic` (provenance block check fires REQUIRES-OPERATOR-INPUT; or hash mismatch fires manifest violation). Target: `envelope-parsing`. PASTA: V.
   - **ADV-003 Replay attack** — re-submit yesterday-timestamped envelope as today's evidence; expect `detected-diagnostic` (RFC 3161 timestamp skew check, OR run-ledger duplicate detection). Target: `rfc3161-timestamp`. PASTA: VII.
   - **ADV-004 KEV bypass** — strip CVE id from a finding referencing a KEV-listed CVE; expect `detected-diagnostic` (B.B2 deadline falls back to CMP table; `severity-fallback` source surfaces). Target: `kev-reconcile`. PASTA: VI.
   - **ADV-005 OSCAL chain corruption** — flip the AP UUID in AR `import-ap`; expect `fail-closed` (LOOP-A.A3 chain check). Target: `oscal-chain`. PASTA: VII.
   - **ADV-006 EPSS poisoning** — supply a forged EPSS cache entry with score 0.0 for a KEV-listed CVE; expect `detected-diagnostic` (B.B1 source mismatch; `epss.source: 'cache'` valid only with verifiable timestamp). Target: `epss-feed`. PASTA: VI.
   - **ADV-007 KSI-map shadowing** — register a duplicate KSI id with different mitigation; expect `fail-closed` (duplicate-id check in `core/ksi-map.ts:validate()`). Target: `ksi-map`. PASTA: VII.
   - **ADV-008 Threat-model tampering** — modify a row's `mitigating_ksis` after operator sign-off; expect `fail-closed` (signature verification on the tracker row). Target: `threat-model`. PASTA: VII.
   - **ADV-009 Attack-surface injection** — operator submits fake entry-point claiming `authentication: 'mtls'` for an internet-exposed port; expect `detected-diagnostic` (cross-check vs inventory shows no mtls config). Target: `attack-surface`. PASTA: VII.
   - **ADV-010 Submission-bundle role collision** — register two files under same role; expect `fail-closed` (bundler dedup). Target: `submission-bundle`. PASTA: VII.
4. Manifest emission: `out/adversarial-results.json` carries `AdversarialResultsManifest`. Signed by `core/sign.ts`. Provenance block: emitter `core/adversarial-test-runner.ts`, emittedAt, sourceCalls (scenario catalog hash, fixture dir SHA, RFC-0014 + NIST 800-115 + PASTA citation refs), signingKeyId.
5. AR observation emission: per run, emit object per `LOOP-N-SPEC.md §5 N.N3 build step 5`. Props: `adversarial-scenario-id`, `adversarial-expected-outcome`, `adversarial-observed-outcome`, `adversarial-verdict`, `pasta-stage`. `relevant-evidence[].href` → `./adversarial-results.json#/runs/<idx>`.
6. Tracker `adversarial_test_runs` table (append-only) per `LOOP-N-SPEC.md §5 N.N3 build step 6`. Indexes on `run_id`, `scenario_id`, `verdict`. Read-only UI page; no edit/delete.
7. CI integration: `.github/workflows/ci.yml` runs `npm run adversarial` after `npm test`; sets `CLOUD_EVIDENCE_STRICT_ADVERSARIAL=1`; any `verdict: 'fail'` exits non-zero; CI rejects the change.
8. Bundler integration: add role `adversarial-results-json` to `WELL_KNOWN`.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

| Field | Source | Behaviour when missing |
|---|---|---|
| Scenario catalog `ADVERSARIAL_SCENARIOS` | typed constant in `core/adversarial-scenarios.ts` | hard-coded; no operator input required to RUN the suite |
| `--scenario-filter` | CLI flag / env | optional; operator can skip flaky scenarios in a specific environment; flag is observable in manifest `provenance.sourceCalls` |
| Fixture envelopes / feeds | `tests/fixtures/adversarial/` (committed) | committed in repo; reproducible across runs |
| Operator narrative annotations | tracker UI (optional commentary on a particular failed run) | empty until operator provides |

## Test specifications (≥12 tests)
1. `it('runs every ADVERSARIAL_SCENARIO and emits one run per scenario', ...)` — assert `runs.length === ADVERSARIAL_SCENARIOS.length`.
2. `it('ADV-001 signature tamper produces fail-closed verdict pass', ...)` — mutated envelope rejected by `verifyEnvelope()`.
3. `it('ADV-002 fixture injection produces detected-diagnostic verdict pass', ...)` — production ingest path emits diagnostic.
4. `it('ADV-003 replay attack produces detected-diagnostic verdict pass', ...)` — RFC 3161 timestamp skew detected.
5. `it('ADV-004 KEV bypass produces fail-closed or detected-diagnostic verdict pass', ...)`.
6. `it('ADV-005 OSCAL chain corruption produces fail-closed verdict pass', ...)` — chain validator rejects.
7. `it('ADV-006 EPSS poisoning produces detected-diagnostic verdict pass', ...)`.
8. `it('ADV-007 KSI-map shadowing produces fail-closed verdict pass', ...)`.
9. `it('ADV-008 threat-model tampering produces fail-closed verdict pass', ...)`.
10. `it('ADV-009 attack-surface injection produces detected-diagnostic verdict pass', ...)`.
11. `it('ADV-010 submission-bundle role collision produces fail-closed verdict pass', ...)`.
12. `it('manifest carries provenance block with sourceCalls per scenario', ...)`.
13. `it('signs adversarial-results.json with Ed25519 + RFC 3161', ...)`.
14. `it('writes one row per run to adversarial_test_runs table', ...)` — verify SQLite insert.
15. `it('AR observation emits adversarial-scenario-id + adversarial-verdict props', ...)`.
16. `it('strict-adversarial exits non-zero when any verdict=fail', ...)` — inject a defect scenario; assert process.exitCode.
17. `it('scenario-filter skips listed scenarios and records in provenance', ...)`.
18. `it('runner does NOT use NODE_ENV === test branches anywhere in production paths', ...)` — grep test.
19. `it('pipeline_artifacts_hash differs between mutated and non-mutated runs', ...)` — sanity check the hashing is real.
20. `it('AdversarialOutcome enum covers the five canonical values', ...)`.

## REO compliance
- All adversarial fixtures live under `cloud-evidence/tests/fixtures/adversarial/` (REO Rule 1 boundary respected).
- Production code paths exercised under attack are the REAL paths — no `process.env.NODE_ENV === 'test'` branches; the runner injects mutators through PUBLIC APIs only (`verifyEnvelope`, `verifySignature`, `importAp`, `parseKevFeed`, etc.).
- Signatures real Ed25519; manifest hash real sha256.
- Failed verdicts are observable in `out/adversarial-results.json#/runs[].verdict` AND in `tracker.adversarial_test_runs.verdict`; CI rejects on any `'fail'`.
- Provenance block populated: emitter, emittedAt, sourceCalls (scenario catalog hash, fixture-dir SHA, citation refs), signingKeyId.
- No silent fallback: an `observed_outcome: 'inconclusive'` produces `verdict: 'fail'` in strict mode (a scenario the runner can't classify is an integrity failure).
- Operator-supplied `scenario-filter` records in manifest provenance; skipped scenarios visible to a 3PAO.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/adversarial tests/core/adversarial-test-runner.test.ts
CLOUD_EVIDENCE_STRICT_ADVERSARIAL=1 npm run adversarial
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd "../tracker"
npm run typecheck
npm test -- server/routes/adversarial-runs.test.ts client/src/pages/AdversarialRuns.test.tsx
```

## Known risks / issues
- **Risk 1: Scenario flakiness in CI.** ADV-003 (replay) depends on RFC 3161 timestamp behaviour; if the local trusted-timestamp authority is unreachable, the scenario can produce `inconclusive`. Mitigation: cached TSR for fixture envelopes committed alongside fixtures; CI uses cached path; live TSR run only in nightly scheduled job.
- **Risk 2: Production-path hardening exposes pre-existing bugs.** ADV-005 (OSCAL chain corruption) is likely to expose a missing chain check until LOOP-A.A3 is fully in. Mitigation: dependency frontmatter pins A.A3; spec-driven ordering.
- **Risk 3: Scenario catalog growth and maintenance.** Future loops (LOOP-B.B3 risk-acceptance replay; LOOP-C.C* doc-template tamper) need new scenarios. Mitigation: catalog is extensible; each new slice that touches a sign-off / signing path adds a scenario in the same commit (CLAUDE.md addendum can codify).
- **Risk 4: False-positive verdicts from upstream library changes.** A new ajv version could change how invalid props parse, producing different diagnostics. Mitigation: pin major versions; per-scenario test asserts the SPECIFIC diagnostic text; upstream changes surface as test failures.
- **Risk 5: Mutator purity drift.** A mutator that mutates shared state across scenarios produces order-dependent results. Mitigation: each mutator receives a deep-cloned input; scenarios run in a deterministic but configurable order; pin with a meta-test asserting clone semantics.
- **Risk 6: CI build time growth.** Adding ≥10 adversarial runs to CI plus the existing test suite could push total CI time over budget. Mitigation: scenarios run in parallel where possible; runner supports `--workers <n>`; CI job timeout documented in runbook.

## Open questions
- **Q1**: Should ADV-001 (signature tamper) test BOTH cloud-evidence-side Ed25519 AND tracker-side sign-off Ed25519 signatures, or only the canonical envelope signature? Recommend: both — two sub-scenarios ADV-001a + ADV-001b — to exercise both signing pipelines.
- **Q2**: What's the failure mode when a scenario's expected_outcome is `detected-diagnostic` but the production path emits a NEW diagnostic (different text than expected)? Recommend: match on diagnostic CODE (typed enum), not free text; pin in `core/diagnostics.ts` registry; cross-ref LOOP-A diagnostic catalog.
- **Q3**: Should ADV-010 also fire on bundle-merge between distinct CSO bundles (multi-tenant)? Recommend: defer — multi-tenant is LOOP-H.H3; cross-reference in CHANGELOG.
- **Q4**: Where does the adversarial-results.json land in monthly ConMon delta? (LOOP-E.E1 consumer.) Recommend: aggregate of `totals.pass / totals.fail` plus a list of regressed scenario_ids; deferred to LOOP-E.E1 implementation.

## Worked example — ADV-001 signature tamper

Concrete walk-through of the canonical scenario the test suite encodes verbatim.

**Fixture envelope** at `tests/fixtures/adversarial/envelopes/ksi-iam-mfa-good.json`:
```json
{
  "schema_version": "1.0",
  "ksi": "IAM-MFA",
  "collected_at": "2026-06-07T10:00:00Z",
  "provenance": { "emitter": "providers/aws/iam.ts", ... },
  "findings": [ { "id": "f1", "severity": "high", ... } ]
}
```
Plus a sidecar signature file `ksi-iam-mfa-good.json.sig` containing the Ed25519 signature of the canonical JSON.

**Mutator** (in `core/adversarial-scenarios.ts`):
```ts
{
  id: 'ADV-001',
  title: 'Envelope signature tamper',
  pasta_stage: 'V',
  nist_800_115_phase: 'attack',
  target: 'envelope-signing',
  mutator: (input) => {
    const cloned = structuredClone(input);
    // flip a single byte in the first finding's id
    cloned.envelope.findings[0].id = cloned.envelope.findings[0].id + 'X';
    return cloned;
  },
  expected_outcome: 'fail-closed',
  citation: { url: 'https://www.first.org/cvss/', section: 'envelope-signing' }
}
```

**Runner step**:
1. Load fixture envelope + signature.
2. Apply mutator → mutated envelope; signature unchanged (signature was over the ORIGINAL canonical bytes).
3. Invoke `core/sign.ts:verifyEnvelope(mutated, signature, publicKey)` — the PRODUCTION verifier.
4. `verifyEnvelope` returns `{ valid: false, reason: 'signature-mismatch' }`.
5. `observed_outcome = 'fail-closed'`. Matches `expected_outcome`. `verdict: 'pass'`.

**Manifest entry**:
```json
{
  "uuid": "<v5('ADV-001', run_id)>",
  "ranAt": "2026-06-07T10:05:00Z",
  "run_id": "run-2026-06-07T10",
  "scenario_id": "ADV-001",
  "observed_outcome": "fail-closed",
  "observed_diagnostic": "signature-mismatch",
  "verdict": "pass",
  "pipeline_artifacts_hash": "sha256:abc123...",
  "provenance": { ... }
}
```

**Failure mode example**: if a future refactor of `core/sign.ts` broke the byte-level canonicalization, `verifyEnvelope` would (incorrectly) return `{ valid: true }`. The runner would record `observed_outcome: 'unexpected-pass-DEFECT'`, `verdict: 'fail'`. CI strict mode exits non-zero. PR rejected. The pipeline's signature guarantee held only because ADV-001 caught the regression.

**AR observation**:
```json
{
  "uuid": "<run.uuid>",
  "description": "Adversarial scenario ADV-001 Envelope signature tamper",
  "methods": ["TEST"],
  "props": [
    { "name": "adversarial-scenario-id", "ns": "CE_NS", "value": "ADV-001" },
    { "name": "adversarial-expected-outcome", "ns": "CE_NS", "value": "fail-closed" },
    { "name": "adversarial-observed-outcome", "ns": "CE_NS", "value": "fail-closed" },
    { "name": "adversarial-verdict", "ns": "CE_NS", "value": "pass" },
    { "name": "pasta-stage", "ns": "CE_NS", "value": "V" }
  ],
  "relevant-evidence": [
    { "href": "./adversarial-results.json#/runs/0" }
  ]
}
```

3PAO reading the AR sees a TEST-method observation with verbatim verdict + scenario; can demand the runner output, the fixture, and the mutator source — every artifact is in-repo + signed.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean in both `cloud-evidence/` and `tracker/`
- [ ] tests passing 100% (count increased by ≥20 cloud-evidence + ≥4 tracker for this slice)
- [ ] `CLOUD_EVIDENCE_STRICT_ADVERSARIAL=1 npm run adversarial` exits 0 (every scenario `verdict: 'pass'`)
- [ ] check:reo green (G1+G2+G3)
- [ ] check:provenance green for `out/adversarial-results.json`
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-N-SPEC.md §8 status table updated
- [ ] This file's frontmatter updated (`status: done`, `commit: <hash>`, `completed_date: <ISO>`)
- [ ] LOOP-N-RISKS.md per-slice section updated
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] CI workflow updated and validated on a feature branch
- [ ] Commit with `LOOP-N.N3` in message
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-N-SPEC.md` §5 N.N3 (and §3 dependencies — N.N1 + N.N2 must be in).
3. Read `cloud-evidence/docs/loops/LOOP-N-RISKS.md` cross-cutting + N.N3 sections.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Read `core/envelope.ts` (verifyEnvelope), `core/sign.ts` (verifySignature), `core/oscal.ts` (importAp + chain check), `core/kev-feed.ts` (parser), `core/ksi-map.ts:validate()` (duplicate detection), `core/submission-bundle.ts` (role dedup) — the public APIs the mutators target.
6. Read existing `tests/core/envelope.test.ts` for the test scaffolding pattern.
7. Read `.github/workflows/ci.yml` for the CI job pattern.
8. Begin implementation; update Implementation log section as you go.

---
