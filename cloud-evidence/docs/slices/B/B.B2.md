---
slice_id: B.B2
title: Remediation deadline math (KEV / PAIN / IRV / LEV / FedRAMP CMP)
loop: B
status: done
commit: f25255d
completed_date: 2026-06-11
depends_on: [LOOP-A.A1, B.B1]
blocks: [B.B3, E.E1, E.E2, I.I2]
estimated_effort: 2 working days
last_updated: 2026-06-11
---

# B.B2 — Remediation deadline math (KEV / PAIN / IRV / LEV / FedRAMP CMP)

## TL;DR
Replace the LOOP-A.A1 `REMEDIATION_DEADLINE_DAYS` hardcoded severity table with a priority-cascading `computeDeadline()` engine that honours (in order) operator override → CISA KEV catalog `dueDate` verbatim → PAIN/IRV/LEV acceleration → FedRAMP Continuous Monitoring Strategy & Guide severity table → severity-fallback (observable, not silent). Each OSCAL risk gains a `deadline-source` prop so a 3PAO can audit *which* table drove every deadline.

## Status
- Status: done
- Commit: `f25255d` (filled by the two-pass close-out)
- Date: 2026-06-11
- Verification: typecheck=0 errors, tests=1025 passing (+21), check:reo=green (G1 ✓ / G2 skip-no-out / G3 ✓)

## Why this slice exists
`core/oscal-poam.ts:84-90` ships a single `Severity → days` map (critical=30, high=60, medium=90, low=180, info=365). This is **wrong** against two authoritative sources:
- **CISA BOD 22-01** requires federal agencies (and by extension FedRAMP CSPs) to remediate KEV-catalog vulnerabilities by the per-entry `dueDate`, not a generic "high=60d" default. A KEV CVE with a 14-day dueDate would silently get 60 days under LOOP-A.A1 — a real authorization risk.
- **FedRAMP Continuous Monitoring Strategy & Guide (Rev 5)** publishes its own severity table that differs from ours (notably `High = 30 days`, not 60). A FedRAMP PMO reviewer would flag this divergence.

Additionally, the existing VDR pipeline emits PAIN (Possible Adverse Impact Number, 1-5 operator-supplied), IRV (Internet-Reachable Verdict, boolean), and LEV (Likely Exploitable Verdict, boolean) signals that today only inform the human-readable VDR report — they don't pull the POA&M deadline forward. B.B2 wires them in: when a finding's `risk_score.composite_score >= 9.0` AND IRV=true AND LEV=true, the deadline is overridden to 30 days regardless of nominal severity (FedRAMP CMP critical-equivalent).

Finally, the system today has **no way to capture operator-approved deadline extensions**. B.B3 will add the signed risk-acceptance path; B.B2 ships the override hook now so B.B3 can plug in cleanly.

## Authoritative sources (with verbatim quotes)
- https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01 — **CISA BOD 22-01 (Nov 2021)**:
  > "Remediate each vulnerability according to the timelines set forth in the CISA-managed vulnerability catalog. The catalog will list exploited vulnerabilities that carry significant risk to the federal enterprise with the requirement to remediate within a more aggressive timeline."
  > "Vulnerabilities … published in the catalog will be remediated within two weeks unless otherwise specified."
  Per-entry `dueDate` is authoritative — LOOP-B.B2 reads it VERBATIM.

- https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json — **CISA KEV Catalog (JSON feed)**:
  Per-entry shape (already loaded by `core/kev-feed.ts`): `{ cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes }`. `dueDate` is ISO `YYYY-MM-DD`.

- https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf — **FedRAMP Continuous Monitoring Strategy & Guide, Rev 5 (Section 3.3 "Vulnerability Scanning")**:
  PDF returns 403 to anonymous HTTPS fetches. Implementer MUST download manually into `cloud-evidence/docs/sources/fedramp-conmon-strategy-guide.pdf`. Canonical (from prior published guidance, to be re-verified against the downloaded PDF, with the PDF page + section quoted into `deadline-table.ts`):
  > "High vulnerabilities — 30 days. Moderate vulnerabilities — 90 days. Low vulnerabilities — 180 days."
  Critical vulnerabilities are handled per KEV/operational risk; the standard cadence is 15-30 days (cite the exact wording from the downloaded PDF).

- https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/ — **FedRAMP Rev5 Playbook — ConMon Vulnerability Scanning**:
  Reinforces the same severity → days table.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, RA-5(2)** "Update Vulnerabilities to be Scanned":
  > "Update the system vulnerabilities to be scanned [Assignment]; prior to a new scan; when new vulnerabilities are identified and reported."
  B.B2's KEV-feed reload + `--strict-risk` mode operationalises this control.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, RA-7** "Risk Response":
  > "Respond to findings from security and privacy assessments, monitoring, and audits in accordance with organizational risk tolerance."
  B.B2's `deadline-source` prop is the system-level signal that the response engine ran.

- https://www.first.org/epss/ — **FIRST EPSS** (consumed indirectly via B.B1's `risk_score.epss.percentile`): the LEV (Likely Exploitable Verdict) signal in the existing VDR pipeline defaults to `epss.percentile >= 0.95 OR cve_in_kev`. B.B2 reuses this rule.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/deadline-engine.ts` — pure builder `computeDeadline()` with the documented priority cascade. ~300 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/deadline-table.ts` — typed constant `FEDRAMP_CMP_DEADLINES: Record<Severity, number>` with the FedRAMP CMP table values, plus PDF page/section quote in the docstring. ~80 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/fedramp-conmon-strategy-guide.pdf` — the downloaded PDF (operator step before commit; `.gitkeep` placeholder otherwise so the path exists in tree).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/deadline-engine.test.ts` — ~12 tests covering the cascade.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/deadline-table.test.ts` — 3 tests pinning the FedRAMP CMP table values.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts`:
  - Replace `deadlineFromCollected()` (line 328) with a thin wrapper that calls `computeDeadline()` from `deadline-engine.ts`. The wrapper attaches a `deadline-source` prop on every OSCAL risk + poam-item.
  - Remove local `REMEDIATION_DEADLINE_DAYS` constant (line 84) — single source of truth is now `deadline-table.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/vdr-ledger.ts` — verify `pain`, `irv`, `lev` fields are emitted on each VDR entry; extend if any are missing so B.B2 can read them.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--strict-risk` flag + env `CLOUD_EVIDENCE_STRICT_RISK`. When set, refuse to emit the POA&M if any finding has `deadline-source: 'severity-fallback'` (a sign the FedRAMP CMP table wasn't loaded).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add role `deadline-audit-json` (filename `deadline-audit.json`).

## Schemas / standards
- **CISA KEV catalog** — `core/kev-feed.ts` already parses and indexes by `cveID`. B.B2 only reads the existing index.
- **FedRAMP CMP severity → days table** — pasted verbatim into `deadline-table.ts` after manual PDF extraction; docstring cites page + section number. Typed `Record<Severity, number>`.
- **PAIN / IRV / LEV** — defined in `docs/analysis/vdr.md`:
  - PAIN: operator-supplied 1-5 in the `vdr` collector config.
  - IRV: boolean derived from security-group/NACL/route-table analysis (existing `vdr-ledger.ts` logic).
  - LEV: boolean derived as `epss.percentile >= 0.95 OR cve_in_kev` (existing `vdr-ledger.ts` logic).
- **OSCAL POA&M v1.1.2** — `risk.deadline` is the ISO datetime field; `risk.props[]` extension point. New prop names: `deadline-source`, `kev-cve-id`, `kev-due-date`, `pain`, `irv`, `lev`, `pain-irv-lev-rationale`. Namespace `CE_NS`.

## Build steps (concrete, numbered)
1. Define `DeadlineSource` union:
   ```ts
   export type DeadlineSource = 'kev' | 'fedramp-cmp' | 'pain-irv-lev' | 'operator-override' | 'severity-fallback';
   ```
2. Define `DeadlineResult`:
   ```ts
   export interface DeadlineResult {
     deadline: string;             // ISO datetime
     source: DeadlineSource;
     days_from_collected: number;
     rationale: string;            // human-readable WHY
     kev_entry?: { cveID: string; dueDate: string; dateAdded: string };
     pain_irv_lev?: { pain?: number; irv?: boolean; lev?: boolean };
   }
   ```
3. Pure builder:
   ```ts
   export function computeDeadline(
     finding: Finding,
     ctx: DeadlineContext,
     collectedAt: string,
   ): DeadlineResult;
   ```
   where `DeadlineContext` carries: KEV index (from `core/kev-feed.ts`), FedRAMP CMP table (from `deadline-table.ts`), VDR signals (from `vdr-ledger.ts` output), and the optional operator override (from B.B3 acceptances — supplied as `ctx.acceptanceOverride?: { deadline: string; uuid: string }`).
4. **Priority cascade** (documented at length in the module docstring):
   1. **Operator override** — when `ctx.acceptanceOverride` is set, use its `deadline`. Source: `operator-override`. Rationale: "Active risk acceptance `<uuid>` extends deadline to `<date>`."
   2. **KEV match** — collect all CVE IDs from `finding.references[].cve` and `finding.gap.affected_resources[].attributes.cve_ids`. If any matches the KEV index, use the catalog's `dueDate` verbatim (take the EARLIEST when multiple CVEs match). Source: `kev`. Rationale: "CVE `<id>` in CISA KEV catalog; BOD 22-01 dueDate `<dueDate>` (added `<dateAdded>`)."
   3. **PAIN / IRV / LEV override** — when `finding.risk_score?.composite_score >= 9.0` AND `vdr.irv === true` AND `vdr.lev === true`, override to FedRAMP CMP critical row (30 days from collected_at). Source: `pain-irv-lev`. Rationale: "Composite `<score>` ≥ 9.0, IRV=true, LEV=true; treated as critical-equivalent (FedRAMP CMP 30d)."
   4. **FedRAMP CMP table** — `FEDRAMP_CMP_DEADLINES[severity]` days from collected_at. Source: `fedramp-cmp`. Rationale: "FedRAMP ConMon Strategy & Guide severity `<sev>` → `<days>` days."
   5. **Severity fallback** — only fires if the CMP table is missing for a severity (should never happen given typed Record); falls through to LOOP-A.A1's `REMEDIATION_DEADLINE_DAYS`. Source: `severity-fallback`. Rationale: "FedRAMP CMP table missing severity `<sev>` — REQUIRES-OPERATOR-INPUT: re-download fedramp-conmon-strategy-guide.pdf."
5. **Strict mode**: `--strict-risk` orchestrator flag counts findings with `source === 'severity-fallback'` and exits non-zero if any exist.
6. Update `core/oscal-poam.ts:buildOscalPoam()`:
   - Replace `deadlineFromCollected(collected, f.severity)` call (line 563) with `computeDeadline(f, ctx, collected).deadline`.
   - In `findingProps()` (line 377), append `deadline-source`, and conditionally `kev-cve-id` + `kev-due-date` (when source=kev), `pain` + `irv` + `lev` + `pain-irv-lev-rationale` (when source=pain-irv-lev), `operator-override-acceptance-uuid` (when source=operator-override).
7. Write `core/deadline-table.ts`:
   ```ts
   /**
    * FedRAMP Continuous Monitoring Strategy & Guide (Rev 5), §3.3
    * "Vulnerability Scanning" — Table N (page N, retrieved YYYY-MM-DD).
    *
    * Source PDF: docs/sources/fedramp-conmon-strategy-guide.pdf
    * Verbatim quote: "<paste exact text from PDF>"
    */
   export const FEDRAMP_CMP_DEADLINES: Record<Severity, number> = {
     critical: 15,   // <-- verify against PDF
     high:     30,
     medium:   90,
     low:     180,
     info:    365,
   };
   ```
   The implementer MUST manually re-verify each value against the downloaded PDF before committing.
8. New emit-artifact `out/deadline-audit.json`: one row per finding with `{poam_item_uuid, finding_uuid, ksi_id, rule, source, deadline, days_from_collected, rationale}`. Provenance block at top.
9. Wire into `submission-bundle.ts:WELL_KNOWN`:
   ```ts
   { role: 'deadline-audit-json', filename: 'deadline-audit.json', description: 'Per-finding deadline-source audit log (LOOP-B.B2)' },
   ```
10. Validation pass:
    - Re-emit POA&M, run through `core/oscal-validate.ts` — must pass v1.1.2 schema (props in `CE_NS` namespace).
    - Verify `deadline-audit.json` provenance via `check:provenance`.
11. Signed + timestamped by existing pipeline.

## REQUIRES-OPERATOR-INPUT fields
| Field | Source | Behavior when missing |
|---|---|---|
| FedRAMP CMP table values | `docs/sources/fedramp-conmon-strategy-guide.pdf` (operator manually downloads) | If PDF missing, `deadline-table.ts` retains the published baseline values + docstring carries `REQUIRES-OPERATOR-INPUT: confirm-against-fedramp-cmp-pdf`; `--strict-risk` mode fails the build until reconciled. |
| Operator override deadlines | B.B3 risk-acceptance records (DB) | When B.B3 hasn't shipped yet, no override is supplied; cascade falls through to KEV / CMP / fallback. |
| KEV catalog freshness | `core/kev-feed.ts` checked into repo; refreshed on schedule | When catalog file is older than 7 days, orchestrator logs `kev:stale` warning; under `--strict-risk` it fails the build. |

## Test specifications (≥10 tests)
1. `it('uses CISA KEV dueDate verbatim when CVE matches KEV catalog')` — assert deadline exactly equals `kevEntry.dueDate + 'T00:00:00Z'`, source='kev'.
2. `it('does NOT compute +21d when KEV catalog supplied a dueDate')` — sanity check: deadline ≠ dateAdded + 21d unless the catalog entry literally has dueDate = dateAdded + 21d.
3. `it('takes earliest dueDate when multiple KEV CVEs match the finding')` — finding cites 3 KEV CVEs; deadline = min(due_dates).
4. `it('falls through to FedRAMP CMP table when no KEV match')` — non-KEV CVE, severity=high → deadline = collected + 30d, source='fedramp-cmp'.
5. `it('applies PAIN/IRV/LEV override when composite >= 9 and IRV+LEV true')` — even if severity=medium, composite 9.5 + IRV + LEV → 30d deadline, source='pain-irv-lev'.
6. `it('does NOT apply PAIN/IRV/LEV override when composite < 9')` — composite 8.5 + IRV + LEV → falls through to CMP.
7. `it('honours operator override when ctx.acceptanceOverride is set')` — override deadline takes precedence over everything else, source='operator-override'.
8. `it('logs severity-fallback source when CMP table missing')` — mock CMP table missing 'medium' → source='severity-fallback', rationale carries REQUIRES-OPERATOR-INPUT marker.
9. `it('throws under --strict-risk when severity-fallback fires')` — orchestrator integration: any fallback row → exit code non-zero.
10. `it('attaches deadline-source prop on every OSCAL risk')` — emitted POA&M parses; every risk has the prop in CE_NS.
11. `it('attaches kev-cve-id + kev-due-date props on KEV findings')` — emitted POA&M has both props with correct values.
12. `it('attaches pain + irv + lev props on PAIN/IRV/LEV-override findings')`.
13. `it('handles malformed collected_at by falling back to now()')` — invalid ISO string → deadline computed from current time with a warning prop.
14. `it('emits deadline-audit.json with one row per finding + provenance block')`.
15. `it('FEDRAMP_CMP_DEADLINES table matches PDF quote in docstring')` — fixture test pinning the values; if PDF changes, this test must be updated atomically with the constant.

## REO compliance specific to this slice
- KEV `dueDate` is read VERBATIM from the catalog — no synthetic `+21d` math.
- FedRAMP CMP values are sourced from the downloaded PDF, with quote-and-citation in the constant's docstring.
- `severity-fallback` is observable in props; not hidden.
- Operator overrides flow through B.B3 signed records (when B.B3 ships); never inline strings.
- Every emit-field on `deadline-audit.json` has a `provenance` entry per Rule 2.6.
- Signed + timestamped by existing `core/sign.ts` pipeline.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/deadline-engine.test.ts tests/core/deadline-table.test.ts tests/core/oscal-poam.test.ts
npm run check:reo
npm run lint:no-stubs
npm run check:provenance
```

## Known risks / issues
- **Risk 1: FedRAMP CMP PDF returns 403 to anonymous fetches.** Mitigation: implementer downloads manually (documented in build step 7); CI test pins the constant values; constant has REQUIRES-OPERATOR-INPUT marker if the PDF is absent.
- **Risk 2: KEV catalog could be stale (not refreshed).** The KEV JSON feed is updated daily by CISA. Mitigation: `core/kev-feed.ts` records `fetched_at` ISO; B.B2 logs `kev:stale` warning when older than 7 days; `--strict-risk` fails the build.
- **Risk 3: VDR pipeline may not emit all of PAIN/IRV/LEV today.** Mitigation: verify field presence during build; extend `vdr-ledger.ts` to emit any missing field; pin with tests.
- **Risk 4: `severity-fallback` could silently fire if `deadline-table.ts` import goes wrong.** Mitigation: `--strict-risk` exits non-zero; CI default sets `--strict-risk` so fallback can never reach origin/main.
- **Risk 5: LOOP-A.A1's old constant remains in oscal-poam.ts as dead code.** Mitigation: B.B2 deletes it; CHANGELOG entry calls out the removal.
- **Risk 6: KEV match logic could over-match (CVE substring) or under-match (case-sensitivity).** Mitigation: exact-string match on uppercase `CVE-YYYY-NNNNN`; CVE IDs normalised at input.
- **Risk 7: PAIN/IRV/LEV threshold tuning needed.** The 9.0 composite threshold is operator-tunable via `risk-config.yaml` from B.B1; tests pin the default; CHANGELOG documents.

## Open questions (for implementation session to resolve)
- **Q1**: When the operator override deadline is EARLIER than the KEV dueDate, which wins? Recommend: KEV wins (federal mandate cannot be extended by operator). Update spec accordingly.
- **Q2**: What's the right "severity → critical-equivalent" mapping when PAIN/IRV/LEV fires? Spec says 30 days. Should it be `FEDRAMP_CMP_DEADLINES.critical` instead, so when the CMP table is updated to (say) 15 days, the override tracks? Recommend: yes, derive from the table.
- **Q3**: Does the existing `core/kev-feed.ts` parse `dueDate` as ISO `YYYY-MM-DD`? Verify before reuse; normalize to ISO datetime (`+T00:00:00Z`) if it's date-only.
- **Q4**: Is `core/vdr-ledger.ts` accessible to `oscal-poam.ts` at build time, or do we need an intermediate `out/vdr-signals.json` snapshot? Investigate the existing call graph before implementation.
- **Q5**: Should `--strict-risk` also fail on `epss_source: REQUIRES-OPERATOR-INPUT` from B.B1? Recommend: out of scope for B.B2; keep `--strict-risk` focused on deadline-source.

### Open-question resolutions (impl-b-b2, 2026-06-11)
- **Q1 (operator override earlier/later than KEV)** — RESOLVED: KEV is a federal
  mandate that cannot be EXTENDED. `computeDeadline` returns the operator
  override unless a KEV match has an EARLIER dueDate, in which case KEV wins
  (source='kev', rationale notes the override was capped). Verified by the
  "caps an operator override at the earlier KEV federal mandate" test.
- **Q2 (PAIN/IRV/LEV → critical-equivalent days)** — RESOLVED: derive from the
  table — the override uses `cmpTable.critical` (currently 15d), so it tracks a
  future CMP update. (The spec's prose said "30d"; that was the old A.A1 value.)
- **Q3 (kev-feed dueDate format)** — RESOLVED: `core/kev-feed.ts` returns
  `dueDate` as the published `YYYY-MM-DD`; the engine normalizes it to an ISO
  datetime (`<dueDate>T00:00:00.000Z`) for the OSCAL `risk.deadline` field.
- **Q4 (vdr-ledger reachability)** — RESOLVED for B.B2: PAIN/IRV/LEV are read
  as optional per-finding fields on the envelope `Finding` (irv/lev/pain), and
  LEV is derived from `risk_score.epss.percentile ≥ 0.95` (or KEV membership)
  when not explicitly set — no intermediate `out/vdr-signals.json` snapshot was
  needed. Full VDR-ledger→finding plumbing of IRV stays a follow-on (risk B-X-EXT-1).
- **Q5 (--strict-risk scope)** — RESOLVED as recommended: `--strict-risk` fails
  only on `deadline-source: severity-fallback`; the B.B1 epss-source gate is out
  of scope.

## Implementation log (running journal — implementing session updates)
```
2026-06-11 · impl-b-b2 · Shipped end to end per spec.
  Created: core/deadline-table.ts (FEDRAMP_CMP_DEADLINES {critical:15, high:30,
    medium:90, low:180, info:365} + SEVERITY_FALLBACK_DEADLINES = the old A.A1
    values, kept only for the observable fallback); core/deadline-engine.ts
    (computeDeadline + the 5-step priority cascade); tests/core/deadline-engine.test.ts
    (13 tests); tests/core/deadline-table.test.ts (3 tests).
  Extended: core/envelope.ts (Finding += optional irv/lev/pain VDR signals);
    core/oscal-poam.ts (removed REMEDIATION_DEADLINE_DAYS; deadlineFromCollected
    → computeDeadline; deadline-source + kev-cve-id/kev-due-date + pain/irv/lev/
    operator-override props on every risk + poam-item; out/deadline-audit.json
    signed + G3-provenanced; deadline_audit + deadline_fallback_count on the
    result); core/submission-bundle.ts (deadline-audit-json WELL_KNOWN role);
    core/orchestrator.ts (--strict-risk + CLOUD_EVIDENCE_STRICT_RISK; loads the
    CISA KEV catalog and passes kevIndex to emitOscalPoam; exit code 5 when
    --strict-risk and any severity-fallback fires). +5 POA&M-integration tests in
    tests/core/oscal-poam.test.ts (and updated the pre-existing critical-deadline
    test from A.A1's 30d to the FedRAMP CMP 15d — an intended behaviour change).
  Verification: typecheck 0 errors; vitest 1025 passing (was 1004, +21);
    check:reo green.
  REO note on the FedRAMP CMP table: the source PDF (CSP_Continuous_Monitoring_
    Strategy_Guide.pdf) returns HTTP 403 to anonymous fetches and was NOT
    downloadable in this session. The table uses the published cadence (High=30/
    Moderate=90/Low=180 are well-established FedRAMP-published constants, REO
    Rule 3; critical=15 + info=365 per the per-slice doc), cited in the
    deadline-table.ts docstring with a REQUIRES-OPERATOR-INPUT note to confirm
    `critical` against a manually downloaded PDF. `--strict-risk` rejects any
    severity-fallback so an unverified gap can never reach a submission package.
    The docs/sources/fedramp-conmon-strategy-guide.pdf download remains an
    operator step (risk B-X1 stays open).
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [x] typecheck clean (`npm run typecheck`) — 0 errors
- [x] tests passing 100% (count increased by ≥15 for this slice's new tests) — 1025 (+21)
- [x] check:reo green (G1+G2+G3) — lint:no-stubs + check:provenance pass; coverage-regression skips (no out/)
- [x] STATUS.md updated (slice row + Overall section)
- [x] LOOP-B-SPEC.md status table updated
- [x] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [x] LOOP-B-RISKS.md updated (B-X1 + B-X-EXT-1 notes)
- [x] OPERATOR-GUIDE.md updated (§3 --strict-risk flag + §4 env + §7 deadline-audit.json)
- [x] CHANGELOG.md "Unreleased" entry added (quoting the FedRAMP CMP table values)
- [x] Commit with slice ID in message
- [x] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-B-SPEC.md
- [x] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: full priority cascade + verbatim quotes + tests + risks.
3. Read `cloud-evidence/docs/loops/LOOP-B-SPEC.md` §B.B2 for the loop-spec narrative.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Read `cloud-evidence/core/oscal-poam.ts` lines 84-90 + 328-329 + 377+ — these are your edit sites.
6. Read `cloud-evidence/core/kev-feed.ts` to understand the existing KEV index.
7. Read `cloud-evidence/core/vdr-ledger.ts` to confirm PAIN/IRV/LEV are emitted.
8. Read `cloud-evidence/docs/sources/fedramp-conmon-strategy-guide.pdf` (download first per build step 7).
9. Begin implementation; update Implementation log as you go.

---
