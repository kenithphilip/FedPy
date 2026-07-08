---
slice_id: C.C7
title: Risk Management Strategy (RMS)
loop: C
status: done
commit: ea68fea
completed_date: 2026-07-08
depends_on: [Pre-slice docx-primitives, LOOP-A.A1 OSCAL POA&M for §10 summary]
soft_depends_on: [LOOP-B.B5 risk-register.json, LOOP-B.B3 risk-acceptances.json, LOOP-B.B4 compensating-controls.json]
blocks: [LOOP-I.I1 executive dashboard cross-reference, LOOP-F.F7 SAR reference]
estimated_effort: 1 working day
last_updated: 2026-07-08
---

# C.C7 — Risk Management Strategy (RMS)

## TL;DR
Ships `rms.docx` — the PM-9 organizational Risk Management Strategy. §5 Risk Register auto-links to `out/risk-register.json` from B.B5 (REQUIRES-OPERATOR-INPUT when LOOP-B not yet shipped). §6 Risk Acceptance Policy auto-derives from `out/risk-acceptances.json` (B.B3) + `out/compensating-controls.json` (B.B4) when present. §10 POA&M Summary auto-counts severities from `out/poam.json` (LOOP-A.A1).

## Status
- Status: done
- Commit: `ea68fea`
- Date: 2026-07-08
- Verification: typecheck=0 errors, tests=1533 passing (+19), check:reo=green (G1 0 violations / G3 OK / G2 SKIP-no-local-report / ssdf OK)

## Why this slice exists
NIST SP 800-53 Rev. 5 control **PM-9 (Risk Management Strategy)** mandates an organization-wide risk-management strategy that addresses framing risk, assessing risk, responding to risk, and monitoring risk. **NIST SP 800-39** defines the three-tier risk hierarchy (Organization → Mission/Business Process → Information System). **NIST SP 800-37 Rev. 2** defines the RMF steps the RMS supervises. The RMS sits above the per-finding POA&M (LOOP-A.A1) and the per-system SSP (SSP-1) in the risk hierarchy.

## Authoritative sources (with verbatim quotes)
- **NIST SP 800-39 (2011-03) — Managing Information Security Risk: Organization, Mission, and Information System View** — https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-39.pdf
  > §2 (p. 6): "The risk management process involves four components: (i) framing risk; (ii) assessing risk; (iii) responding to risk; (iv) monitoring risk."
  > §2.1 (p. 7): three-tier hierarchy (Tier 1 Organization / Tier 2 Mission-Business Process / Tier 3 Information System) — drives §2 RMS structure.

- **NIST SP 800-37 Rev. 2 (2018-12) — Risk Management Framework for Information Systems and Organizations** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
  > §3 — RMF steps (Prepare / Categorize / Select / Implement / Assess / Authorize / Monitor) — cited in §1.

- **NIST SP 800-30 Rev. 1 (2012-09) — Guide for Conducting Risk Assessments** — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf — §3.2 methodology cited in §3 RMS Methodology.

- **NIST SP 800-53 Rev. 5 — PM-9 Risk Management Strategy** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  > "a. Develops a comprehensive strategy to manage: 1. Security risk to organizational operations and assets, individuals, other organizations, and the Nation associated with the operation and use of organizational systems; and 2. Privacy risk to individuals resulting from the authorized processing of personally identifiable information; b. Implements the risk management strategy consistently across the organization; and c. Reviews and updates the risk management strategy [Assignment: organization-defined frequency] or as required, to address organizational changes."

- **NIST SP 800-53 Rev. 5 — PM-8 Critical Infrastructure Plan, RA-1 Policy & Procedures, RA-3 Risk Assessment** — same URL — cited as supporting controls.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/rms-emit.ts` — pure renderer + disk emitter for `rms.docx` (~500 lines).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/rms-emit.test.ts` — 12 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/rms/poam.sample.json` — fixture POA&M with severity mix.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/rms/risk-register.sample.json` — fixture risk register from B.B5 shape.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/rms/config.sample.yaml` — operator config.

## Files to extend
- `core/submission-bundle.ts` — Role `'rms-docx'`; `WellKnownArtifact` entry.
- `core/orchestrator.ts` — `--rms` flag + env; dispatch block; run-ledger entry. Console output: "if LOOP-B risk register not present, §5/§6/§10 sections require operator completion."
- `CHANGELOG.md`, `docs/STATUS.md`, `docs/loops/LOOP-C-SPEC.md` — per SLICE-COMPLETION-PROCEDURE.md.

## Schemas / standards
- Risk-tolerance schema: `{confidentiality: 'low'|'moderate'|'high'; integrity:...; availability:...}`.
- POA&M summary schema (derived from `poam.json`): `count_by_severity: {critical, high, moderate, low}`, `count_overdue: number`, `oldest_open_finding_age_days: number`.
- Risk register link/href: relative path to `risk-register.json`.

## Build steps (concrete, numbered)
1. Define `RmsEmitOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; impactLevel; riskTolerance?:{confidentiality; integrity; availability}; executiveOversight?:Array<{role:string; name:string; org:string}>; riskRegisterHref?:string; riskAcceptancePolicyHref?:string`.
2. Auto-read LOOP-B output:
   - `out/risk-register.json` → §5 row count + link.
   - `out/risk-acceptances.json` → §6 acceptance summary.
   - `out/compensating-controls.json` → §6 compensating controls summary.
   - All absent → REQUIRES-OPERATOR-INPUT marker + cross-link "Generate via LOOP-B before finalizing".
3. Auto-summarize from `out/poam.json`:
   - count by severity, count overdue (per `due_date < today`), oldest open finding age.
4. Pure builder `buildRmsBodyXml(opts):{xml; stats}` producing 11 sections:
   - §1 Introduction (PM-9 + 800-39 quote).
   - §2 Risk Framing (org context: SaaS CSP, impact level, agency customer count).
   - §3 Risk Assessment Methodology (cite RA-3 + 800-30).
   - §4 Risk Response Strategy (Accept / Avoid / Mitigate / Transfer matrix — 4-row NIST SP 800-39 standard table; REO Rule 3 allowed exception as NIST-published terminology).
   - §5 Risk Register Reference.
   - §6 Risk Acceptance Policy.
   - §7 Continuous Risk Monitoring (cite `conmon-strategy.docx` from C.C6).
   - §8 Risk Tolerance.
   - §9 Executive Oversight + Governance.
   - §10 POA&M Summary (auto from poam.json).
   - §11 Plan Maintenance.
5. `emitRmsDocx(opts):RmsResult` writes file + structured log.

## REQUIRES-OPERATOR-INPUT fields
- `riskTolerance` — `config.yaml:rms.tolerance`.
- `executiveOversight[]` — `config.yaml:rms.executive_oversight[]`.
- `riskRegisterHref` — defaults to `./risk-register.json` IFF that file exists; else REQUIRES-OPERATOR-INPUT.
- `riskAcceptancePolicyHref` — similar.

## Test specifications (12 tests)
1. `it('emits 11 sections')`.
2. `it('quotes SP 800-39 §2 four-component process verbatim')`.
3. `it('§5 risk register link present when risk-register.json exists')`.
4. `it('§5 REQUIRES-OPERATOR-INPUT when risk-register.json absent')`.
5. `it('§10 POA&M summary counts by severity from poam.json')`.
6. `it('§10 REQUIRES-OPERATOR-INPUT when poam.json absent')`.
7. `it('§8 renders riskTolerance verbatim')`.
8. `it('§9 renders executiveOversight roster')`.
9. `it('§4 risk-response matrix is 4-row hard-coded standard table')`.
10. `it('writes to outPath when supplied')`.
11. `it('deterministic output')`.
12. `it('ready_for_signature requires tolerance + executive + register link + acceptance policy')`.

## REO compliance specific to this slice
- §10 POA&M counts trace to real `out/poam.json`.
- §5/§6 links trace to real LOOP-B output files; never fabricated.
- §4 matrix uses NIST SP 800-39 terminology verbatim (REO Rule 3 allowed exception — NIST-published).
- Provenance footer cites: poam.json sha256, risk-register.json sha256 (if present), risk-acceptances.json sha256 (if present), compensating-controls.json sha256 (if present), runId, frmrVersion.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/rms-emit.test.ts
npm run check:reo
npm run check:provenance
```

## Known risks / issues
- **Risk 1 — LOOP-B not yet shipped.** §5/§6 degrade to REQUIRES-OPERATOR-INPUT. This is by-design (REO Rule 4) but may confuse first-time users. Mitigation: orchestrator console emits a clear "LOOP-B not present" warning when RMS is emitted standalone.
- **Risk 2 — POA&M severity bucketing drift.** If LOOP-A.A1 changes its severity enum, §10 counts may mis-bucket. Mitigation: define a `summarizePoamSeverities` helper with an explicit enum coercion; throw typed error if unknown severity encountered.
- **Risk 3 — `oldest_open_finding_age_days` non-determinism.** Computing from `new Date()` violates determinism. Mitigation: accept `now?:Date` in `RmsEmitOptions` for test injection; production reads from `runId` ISO timestamp (already deterministic per run).
- **Risk 4 — Risk-tolerance values overspecified.** Single tolerance per CIA may not capture multi-tier nuance. Mitigation: §8 emits a footer note that operators can append a free-text tolerance narrative via config.
- **Risk 5 — Cross-reference to ConMon Strategy (§7) may dangle.** If C.C6 not in same bundle, §7 link breaks. Mitigation: §7 link omitted when `conmon-strategy.docx` not present in `outDir`; replaced with REQUIRES-OPERATOR-INPUT.
- **Risk 6 — Executive oversight PII.** §9 lists real exec names. Mitigation: same as IRP §7 — config preferred over CLI flags, no logging of PII.

## Open questions (for implementation session to resolve)
- **Q1**: Should §5 embed the full risk-register summary (top N risks by score) or just link? Embedding bloats the doc but aids 3PAOs.
- **Q2**: When LOOP-B is absent, should the RMS refuse to emit (block) or proceed with REQUIRES-OPERATOR-INPUT (degrade)? Today: degrade with clear warning. Some auditors may prefer block.
- **Q3**: Should §4 matrix include FedRAMP-specific guidance on which response is preferred at Moderate vs High? FedRAMP is silent; default to NIST SP 800-39 generic matrix.
- **Q4**: §10 "oldest_open_finding_age_days" — should this consider closed-then-reopened findings? Today: no (only currently-open).
- **Q5**: Should the RMS cite a SHA256 of the SSP? Strengthens chain-of-custody.

## Implementation log (running journal — implementing session updates)
```
2026-07-08 | impl-c-c7 | Shipped C.C7 end to end per spec. Created core/rms-emit.ts
  (pure buildRmsBodyXml/renderRmsDocx + disk emitRmsDocx; exported readers
  readRiskRegister/readAcceptancePolicy/summarizePoam + PoamSeverityError) — an
  11-section PM-9 Risk Management Strategy (out/rms.docx). §5 auto-links
  out/risk-register.json (B.B5) + embeds its summary (Q1); §6 summarizes the
  .risk-acceptances.json (B.B3) + .compensating-controls.json (B.B4) snapshots;
  §10 summarizes out/poam.json (A.A1) — severity histogram + overdue + oldest-open
  age. §4 renders the NIST SP 800-39 Accept/Avoid/Mitigate/Transfer 4-row matrix.
  Extended core/submission-bundle.ts (Role 'rms-docx' + WELL_KNOWN entry),
  core/orchestrator.ts (--rms flag + CLOUD_EVIDENCE_RMS env + Config.rms type +
  dispatch after --conmon-strategy / before signing + usage text), config.yaml
  (rms: section), docs/OPERATOR-GUIDE.md (§3 flag / §4 env / §7 output). Created
  tests/core/rms-emit.test.ts (19 tests: 12 §8 + 6 extras + 1 typed-error) + 3
  fixtures (poam.sample.json, risk-register.sample.json, config.sample.yaml).
  Verification: typecheck clean; suite 1514→1533 (+19); check:reo green; smoke run
  emitted a valid rms.docx (6 OOXML parts, unzip -t clean, byte-identical re-emit).
  Open questions Q1–Q5 all resolved (see the C.C7 scope note in docs/STATUS.md).
  Spec reconciliation: real poam severity enum is critical/high/medium/low/info
  (envelope.ts — `medium`, not the §schema's `moderate`) and B.B3/B.B4 snapshots
  are the dotfiles .risk-acceptances.json / .compensating-controls.json —
  summarizePoam buckets by the honest enum, readAcceptancePolicy reads the dotfile
  first (C-C7-7); shared core/docx-primitives.ts still not extracted, now 13
  emitters to migrate (C-C7-8 / C-X-1). Commit ea68fea.
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [x] typecheck clean (`npm run typecheck`)
- [x] tests passing 100% (count increased by 19; §8 floor was 12)
- [x] check:reo green (G1 0 violations / G3 OK / G2 SKIP-no-local-report / ssdf OK)
- [x] STATUS.md updated (C.C7 row + Overall section + scope note)
- [x] LOOP-C-SPEC.md Section 7 row updated
- [x] This file's frontmatter updated (status=done, commit=<hash>, completed_date=2026-07-08)
- [x] LOOP-C-RISKS.md updated (C-C7-1..8 reconciliation entries)
- [x] OPERATOR-GUIDE.md updated (§3 flag / §4 env / §7 output)
- [x] CHANGELOG.md "Unreleased" entry added
- [x] Commit with `LOOP-C.C7:` in the message
- [x] Commit amended with commit hash recorded
- [x] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Auto-loaded: `cloud-evidence/CLAUDE.md`.
2. This file gives source obligations + files + build steps + tests + risks + checklist.
3. Read `cloud-evidence/docs/loops/LOOP-C-SPEC.md` Section 2 + Section 6 (especially Open Q5 about RMS without LOOP-B).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for commit pattern.
5. Read `cloud-evidence/docs/loops/LOOP-B-SPEC.md` — to know the shape of risk-register.json + risk-acceptances.json + compensating-controls.json that this slice reads.
6. Read `cloud-evidence/core/oscal-poam.ts` — for poam.json shape this slice reads.
7. Read NIST SP 800-39 §2 (URL above) — the four-component process quoted verbatim.
8. Read NIST SP 800-37 Rev. 2 §3 — the RMF step list cited in §1.
9. Read `cloud-evidence/core/roe-emit.ts` + `cloud-evidence/core/ssp-docx.ts` for emitter pattern.
10. Begin implementation; update Implementation log as you go.
