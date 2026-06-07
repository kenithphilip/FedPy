---
slice_id: P.P5
title: Continuous workforce monitoring + behavioral analytics
loop: P
status: pending
commit: —
completed_date: —
depends_on: [P.P1, P.P2, P.P3, P.P4]
blocks: [E.E1, I.I1]
estimated_effort: 6-7 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# P.P5 — Continuous workforce monitoring + behavioral analytics

## TL;DR
Tie it all together. New pure correlator `core/workforce-monitor.ts`
plus typed rule library `core/workforce-indicator-rules.ts` (≥10 CISA
Insider Threat Mitigation Guide indicators in first ship, each citing
PDF page + indicator code verbatim) reads IAM-SUS + screening records
(P.P2) + lifecycle events (P.P3) + access agreement signatures (P.P4) +
tracker audit log; emits `out/workforce-indicators.json` with provenance.
When opted in via `workforce-policy.yaml: auto_open_critical_cases: true`,
auto-opens `insider_threat_cases` (P.P1 table) for severity=critical
findings. Drives LOOP-E.E1 monthly ConMon insider-threat-indicators
delta + tracker dashboard.

## Status
- Status: pending
- Commit: — (filled when shipped per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
P.P5 closes the loop between existing collectors (IAM-SUS in
`providers/*/iam.ts`) + tracker workforce data (P.P2 screening + P.P3
lifecycle + P.P4 agreements) + the ITP plan (P.P1). It does NOT add new
cloud SDK calls — it correlates existing evidence. The new
`workforce-indicators-json` role in `core/submission-bundle.ts:WELL_KNOWN`
makes the artifact a first-class submission output. `core/notify.ts`
fires `workforce-indicator-detected` per finding (severity ≥ high)
through Slack + PagerDuty. SSP PM-12 implementation statement (P.P1)
gets an addendum citing the indicator catalogue summary + count of
detections per category in the current cycle.

## Why this slice exists
NIST 800-53 PM-12 ("Implement an insider threat program that includes a
cross-discipline insider threat incident handling team") requires the
team to *detect + respond* — not just exist. EO 13587 §6 + NITTF
Minimum Standards specify six required program elements, including
(3) personnel access controls + monitoring and (4) information
integration + analysis. CISA's Insider Threat Mitigation Guide provides
a structured behavioral-indicator catalogue (33 indicators across 4
categories: Verbal, Behavioral, Cyber, Physical-access). Today FedPy
has IAM-SUS dormant-account detection but no correlation against HR
status, no behavioral-indicator pipeline, no signed case open/close
cadence. P.P5 is the slice that makes P.P1 (ITP plan) operational and
provides the real-evidence backbone for the PM-12 cross-discipline team.

## Authoritative sources (with verbatim quotes)

- **NIST SP 800-53 Rev5 — PM-12 (Insider Threat Program)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  Verbatim:
  > "Implement an insider threat program that includes a cross-discipline
  > insider threat incident handling team."

  Discussion (verbatim):
  > "Organizations that handle classified information are required, under
  > Executive Order 13587 and the National Insider Threat Policy, to
  > establish insider threat programs. The standards and guidelines that
  > apply to insider threat programs in classified environments can also
  > be employed effectively to improve the security of [Controlled
  > Unclassified Information] in non-national security systems."

- **EO 13587 §6** — NITTF mandate (verbatim, WebFetch 2026-06-07):
  > "The order establishes an interagency task force to 'develop a
  > Government-wide program (insider threat program) for deterring,
  > detecting, and mitigating insider threats.'"

- **NITTF Minimum Standards** — six elements; P.P5 implements
  Element #3 (monitoring) + Element #4 (information integration).

- **CISA Insider Threat Mitigation Guide (2023, 508 PDF)** —
  https://www.cisa.gov/sites/default/files/2023-02/Insider%20Threat%20Mitigation%20Guide_Final_508.pdf
  Operator downloads to
  `cloud-evidence/docs/sources/cisa-insider-threat-mitigation-guide.pdf`
  before P.P5 finalizes its behavioral-indicator rule library.

  Key concepts P.P5 imports verbatim:
  - "Pathway to Insider Threat" model — Personal Predispositions,
    Stressors, Concerning Behaviors, Problematic Organizational
    Responses.
  - 33 behavioral indicators across four categories (Verbal,
    Behavioral, Cyber, Physical-access).
  - Hub-and-spoke insider threat program model (intersects with NITTF
    cross-discipline team requirement).

  Each `core/workforce-indicator-rules.ts` rule docstring carries:
  ```
  /**
   * CISA Insider Threat Mitigation Guide (Feb 2023, 508 PDF)
   * Section: "Cyber Indicators"
   * Indicator code: CYBER-04 ("Dormant account belonging to current employee")
   * Page: <NN> (operator fills after downloading PDF)
   * Verbatim: "<quote>"
   */
  ```

- **CISA Insider Threat Mitigation page (HTML)** —
  https://www.cisa.gov/topics/physical-security/insider-threat-mitigation
  (Used for the IndicatorRule citations + as the canonical entry point
  for follow-up rule additions.)

## Files to create (exact paths under cloud-evidence/)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/workforce-monitor.ts`
  — pure correlator + emitter. Reads IAM-SUS + screening records +
  lifecycle events + access agreement signatures + tracker audit log;
  runs the CISA behavioral-indicator catalogue against the joined data;
  emits `out/workforce-indicators.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/workforce-indicator-rules.ts`
  — typed rule library. Each rule maps to a CISA indicator code with
  verbatim citation in docstring.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/workforce-context.ts`
  — typed loader joining all required snapshots into a single
  `WorkforceContext` value.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/workforce-monitoring.ts`
  — read-only routes for dashboard (counts + drill-in).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/WorkforceMonitoring.tsx`
  — dashboard: indicator counts by category × severity × 30-day window;
  case-creation queue.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/workforce-monitor.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/workforce-indicator-rules.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/workforce-context.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/workforce-monitoring.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/WorkforceMonitoring.test.tsx`

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  new `--workforce-monitoring` flag + env `CLOUD_EVIDENCE_WORKFORCE_MONITORING`.
  Runs LAST in the workforce chain (after P.P2 + P.P3 + P.P4 emits land).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add role `workforce-indicators-json` (filename
  `workforce-indicators.json`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/notify.ts` —
  fire `workforce-indicator-detected` per finding (severity ≥ high).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` —
  PM-12 implementation statement gets indicator-catalogue-summary
  addendum (read from `workforce-indicators.json`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/config/workforce-policy.example.yaml`
  — add:
  ```yaml
  auto_open_critical_cases: false
  dormant_threshold_days: 90
  bulk_event_window_hours: 1
  bulk_event_threshold: 50
  indicator_severity_overrides: {}  # operator can override per-indicator severity
  ```
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount
  workforce-monitoring route with `requireRole(['iso','ao','assessor'])`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add
  `/workforce-monitoring` route.

## Schemas / standards

- **NIST 800-53 Rev5 PM-12 + EO 13587 §6 + NITTF Minimum Standards** —
  verbatim above.
- **CISA Insider Threat Mitigation Guide (2023, 508 PDF)** — indicator
  catalogue, operator-downloaded; verbatim citation per rule.
- **OSCAL SSP** — extension prop `indicator-catalogue-snapshot-uuid`
  namespaced `CE_NS` carrying the snapshot reference.

## Build steps (concrete, numbered)

1. **Indicator rule shape** (`core/workforce-indicator-rules.ts`):
   ```ts
   export interface WorkforceIndicatorRule {
     code: string;                 // e.g. 'CISA-CYBER-04'
     category: 'verbal' | 'behavioral' | 'cyber' | 'physical-access';
     description: string;          // verbatim from CISA guide
     severity: 'low' | 'medium' | 'high' | 'critical';
     source_citation: string;      // e.g. 'CISA-Insider-Threat-Mitigation-Guide-2023 p.NN, Cyber Indicator 04'
     detect: (ctx: WorkforceContext) => DetectionResult[];
   }
   export interface WorkforceContext {
     iam_principals: IamPrincipal[];       // from providers/*/iam.ts inventory
     screening_records: ScreeningRecord[]; // from tracker (P.P2)
     lifecycle_events: LifecycleEvent[];   // from tracker (P.P3)
     agreements: SignatureRow[];           // from tracker (P.P4)
     audit_log: AuditEntry[];              // from tracker
     positions: Position[];                // from tracker (P.P2)
     policy: WorkforcePolicy;              // from workforce-policy.yaml
     fetched_at: string;
   }
   export interface DetectionResult {
     indicator_code: string;
     subject_user_ref: string;             // opaque token (NOT raw user_id)
     severity: 'low' | 'medium' | 'high' | 'critical';
     observation: string;
     evidence_refs: string[];              // paths to source snapshots
     detected_at: string;
   }
   ```

2. **Concrete rules** (≥10 ship in first cut, each with verbatim CISA
   citation in docstring):
   - `CISA-CYBER-04` — Dormant IAM principal (>`dormant_threshold_days`)
     for active employee. Correlates IAM-SUS `last_used_at` with
     screening `status='current'` + absence of termination event.
     Severity: medium.
   - `CISA-CYBER-12` — Access-after-termination. IAM principal observed
     `last_used_at > effective_at` of a termination event. Severity:
     critical.
   - `CISA-CYBER-07` — Privilege-escalation outside role baseline.
     Correlates with LOOP-J.J1 roles matrix delta. Severity: high.
   - `CISA-BEHAV-09` — Missed re-screening on high-risk position.
     `position.public_trust_level='high'` + `screening.status='overdue'`.
     Severity: high.
   - `CISA-CYBER-15` — Bulk download / mass operation in audit log
     (≥`bulk_event_threshold` events in `bulk_event_window_hours`).
     Severity: high.
   - `CISA-BEHAV-03` — Unrevoked credentials after exit interview
     completed (PS-4(b) breach). Severity: critical.
   - `CISA-CYBER-09` — Unattested agreement on user with elevated AC
     role. Joins P.P4 signatures × LOOP-J.J1 elevated-roles matrix.
     Severity: high.
   - `CISA-CYBER-21` — Multiple failed MFA attempts. Cross-ref IAM-MFA
     collector output. Severity: medium.
   - `CISA-BEHAV-17` — Rapid lifecycle event churn for same user
     (>3 events in 90 days). Severity: medium.
   - `CISA-PHYS-08` — Physical-access badge log mismatch (operator-
     supplied CSV; emits REQUIRES-OPERATOR-INPUT when CSV absent).
     Severity: medium.

3. **Correlator** (`core/workforce-monitor.ts`):
   ```ts
   export function correlate(ctx: WorkforceContext, rules: WorkforceIndicatorRule[]): DetectionResult[] {
     const all: DetectionResult[] = [];
     for (const rule of rules) {
       const results = rule.detect(ctx);
       all.push(...results);
     }
     return dedupePerSubjectPerCode(all);
   }
   ```
   - `dedupePerSubjectPerCode`: collapse duplicate firings for same
     (subject, code) within 24h window; keep the latest.
   - Emits `out/workforce-indicators.json` with provenance block:
     `emitter`, `emittedAt`, `sourceCalls` listing each source snapshot
     path + `fetched_at`, `signingKeyId`, `cisa_guide_path` (the
     downloaded PDF path).
   - Optionally auto-opens `insider_threat_cases` (P.P1 table) when
     `severity='critical'` AND operator opt-in via
     `workforce-policy.yaml: auto_open_critical_cases: true`. Each
     auto-opened case carries the indicator code in `indicators_json`
     and `opened_by_user_id = -1` (system marker).

4. **Tracker dashboard** (`WorkforceMonitoring.tsx`):
   - Aggregate counts: by category × severity × rolling-30-day window.
   - Drill-in: per-subject timeline of detected indicators.
   - Case-creation queue: high/critical findings not yet linked to a
     case; `iso` user can click "Open case" → creates row in
     `insider_threat_cases`.

5. **SSP integration** (`core/oscal-ssp.ts`): PM-12 implementation
   statement reads the latest `workforce-indicators.json`; appends an
   indicator-catalogue-summary addendum to
   `implementation-statement.description`:
   "Insider-threat indicators detected in current cycle: <N>
   (verbal=<n>, behavioral=<n>, cyber=<n>, physical-access=<n>).
   Cases opened in cycle: <M>." Adds prop
   `indicator-catalogue-snapshot-uuid`.

6. **Notify integration** (`core/notify.ts`): fire
   `workforce-indicator-detected` per finding when severity ≥ high
   (`high`, `critical`). Template includes indicator code +
   subject_user_ref (opaque) + observation summary.

7. **Orchestrator wiring**: `--workforce-monitoring` runs LAST in
   workforce chain (after P.P2 + P.P3 + P.P4 emits land). Order:
   collect → P.P2 personnel-evidence → P.P3 personnel-lifecycle → P.P4
   access-agreements → P.P5 workforce-monitoring → POA&M → bundle → sign.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| Indicator severity overrides | `config/workforce-policy.yaml: indicator_severity_overrides: {}` | Defaults from rule library; per-org tuning supported |
| `auto_open_critical_cases` | `config/workforce-policy.yaml` (default false) | Operator opt-in; defaults to manual case-opening via UI |
| Physical-access badge log CSV path | `config/workforce-policy.yaml: physical_badge_log_csv` | CISA-PHYS-08 rule emits `psFindingKind: 'phys-log-missing'` REQUIRES-OPERATOR-INPUT when absent (not silently skipped) |
| `dormant_threshold_days` | `config/workforce-policy.yaml` (default 90) | Defaults documented; must match existing IAM-SUS threshold |
| `bulk_event_window_hours` + `bulk_event_threshold` | `config/workforce-policy.yaml` (default 1h / 50 events) | Tunable per org policy |
| CISA Mitigation Guide PDF path | `cloud-evidence/docs/sources/cisa-insider-threat-mitigation-guide.pdf` | Each rule docstring carries `REQUIRES-OPERATOR-INPUT: confirm-against-cisa-guide-pdf-page` marker until operator downloads PDF + fills page numbers |

## Test specifications

1. `it('CISA-CYBER-04 fires on dormant IAM principal with active screening')` —
   fixture: IAM principal `last_used_at=120d ago`, screening
   `status='current'`, no termination → DetectionResult emitted.
2. `it('CISA-CYBER-04 does NOT fire on dormant principal of terminated user')` —
   fixture: above + termination event → no DetectionResult.
3. `it('CISA-CYBER-12 fires on access-after-termination')` — fixture:
   termination `effective_at=T`, IAM `last_used_at=T+1d` → severity critical.
4. `it('CISA-BEHAV-09 fires on missed re-screening + high position')` —
   fixture: position.public_trust_level=high, screening status=overdue
   → severity high.
5. `it('CISA-CYBER-15 fires on bulk download window threshold')` —
   fixture: 60 audit_log entries in 30 minutes → DetectionResult.
6. `it('CISA-CYBER-15 does NOT fire when below threshold')` —
   fixture: 30 entries / 30 minutes (threshold 50) → no result.
7. `it('CISA-CYBER-09 fires on unattested agreement + elevated role')`.
8. `it('correlator dedupes overlapping rule firings per subject within 24h')`.
9. `it('emits workforce-indicators.json with provenance block')` —
   `check:provenance` script exits 0.
10. `it('auto-opens insider_threat_cases when auto_open_critical_cases=true and severity=critical')`.
11. `it('does NOT auto-open cases when auto_open_critical_cases=false')`.
12. `it('respects workforce-policy.yaml severity overrides')` — override
    CISA-CYBER-04 from medium → critical, assert DetectionResult.severity.
13. `it('does NOT fire when no IAM principals + no audit log present')`
    — empty ctx → empty result.
14. `it('fires notify.ts on severity>=high')` — mock notify; assert call
    count equals high-severity result count.
15. `it('SSP PM-12 implementation statement reflects indicator catalogue summary')`.
16. `it('subject_user_ref is opaque (not a tracker user_id)')` —
    DetectionResult.subject_user_ref does not equal any user.id.
17. `it('detection_results signed under existing signing pipeline')` —
    workforce-indicators.json appears in signed manifest.
18. `it('CISA-PHYS-08 rule emits REQUIRES-OPERATOR-INPUT when badge log CSV absent')`
    — no silent skip.
19. `it('orchestrator --workforce-monitoring runs after P.P4 access-agreements')`.
20. `it('rules library carries verbatim CISA citation in each rule docstring')`
    — static check: every rule's `source_citation` matches pattern
    `CISA-Insider-Threat-Mitigation-Guide-2023 p\\.\\d+`.

## REO compliance specific to this slice

- Every rule cites verbatim from CISA Insider Threat Mitigation Guide
  (operator downloads PDF; spec page + indicator code recorded in
  rule docstring AND in DetectionResult.source_citation).
- Subject identifiers are opaque references (`subject_user_ref` = UUID
  minted at detection time; the resolver lives only in a separate
  table accessible to `iso` + `ao`) — per the data-protection guidance
  the ITP plan documents (P.P1).
- No synthesised indicators; every detection ties to a real evidence
  path (IAM-SUS snapshot + tracker row + audit log entry).
- Provenance block on `out/workforce-indicators.json` lists every input
  snapshot URL/path + the CISA guide PDF path.
- Auto-case-open is opt-in (default false); never auto-creates cases
  silently.
- No `process.env.NODE_ENV === 'test'` branches.
- Signed by existing `core/sign.ts` pipeline; lands in manifest.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/workforce-monitor.test.ts tests/core/workforce-indicator-rules.test.ts tests/core/workforce-context.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/workforce-monitoring.test.ts client/src/pages/WorkforceMonitoring.test.tsx
```

## Known risks / issues

- **Risk 1: CISA Mitigation Guide PDF returns 403 / requires manual
  download.** Mitigation: operator downloads to
  `cloud-evidence/docs/sources/cisa-insider-threat-mitigation-guide.pdf`
  before P.P5 ships; each rule docstring carries
  `REQUIRES-OPERATOR-INPUT: confirm-against-cisa-guide-pdf-page` marker
  until operator confirms the page numbers via UI; `--strict-workforce`
  exits non-zero if any marker remains.
- **Risk 2: False positives in CISA-CYBER-04 (dormant principal).**
  Some legitimate employees go on extended leave (medical, parental,
  sabbatical). Mitigation: rule reads `lifecycle_events` for
  `event_type='leave-extended'` (added in P.P3 enum extension) and
  suppresses the fire; UI surfaces a "suppress" action for `iso` users.
- **Risk 3: CISA-CYBER-12 (access-after-termination) timing race.** If
  IAM-SUS snapshot was pulled BEFORE the termination event, the
  observation could pre-date the termination by hours. Mitigation: rule
  filters `iam.last_used_at > termination.effective_at`; uses
  `inventory.snapshot_fetched_at` to verify snapshot freshness; emits
  REQUIRES-OPERATOR-INPUT if snapshot pre-dates termination by < 1h.
- **Risk 4: Bulk-download threshold could miss low-and-slow exfiltration.**
  Mitigation: `bulk_event_threshold` + `bulk_event_window_hours` tunable;
  documented in CHANGELOG with org-policy guidance; future enhancement
  could add a rolling-7-day moving-average rule.
- **Risk 5: Subject identifier resolution table is sensitive.**
  Mitigation: stored in separate `case_subject_index` table (created in
  P.P1 schema extension); AO role only; audit_log captures every access.
- **Risk 6: Auto-case-open could flood the queue.** Mitigation: opt-in
  default false; when enabled, rate-limit to 10 cases/hour/subject;
  documented in runbook.
- **Risk 7: LOOP-J.J1 roles matrix snapshot may not be fresh.**
  Mitigation: P.P5 reader requires roles matrix snapshot < 24h old;
  emits `REQUIRES-OPERATOR-INPUT: roles-matrix-stale` if absent.
- **Risk 8: Notification fatigue when high-severity rule fires across
  many users.** Mitigation: notify.ts already supports per-rule
  throttling; default throttle = 1 notification per (rule, subject)
  per 24h; documented in runbook.

## Open questions

- **Q1**: Should the 33 CISA indicators all ship in first cut, or just
  the 10 most directly cloud-evidence-actionable? Recommendation: ship
  10 in first cut (the cyber + behavioral indicators that join real
  evidence we already collect); follow-up enhancements add the rest.
- **Q2**: Should we expose the indicator rule library as a plugin
  surface (operator-authored rules)? Recommendation: yes, mirror the
  G.1 plugin architecture pattern; documented as a follow-up after
  first ship.
- **Q3**: How long do DetectionResult rows live? Recommendation: 90 days
  in hot storage (`workforce-indicators.json` is overwritten each run);
  archive via LOOP-H.H1 retention; resolved cases (P.P1) retain
  indicator history indefinitely.
- **Q4**: Should bulk-download detection look at AWS CloudTrail S3
  GetObject events specifically? Currently the rule operates on tracker
  audit_log entries only. Recommendation: tracker audit_log only in
  first ship; CloudTrail-side detection is a separate slice (LOOP-E.E3
  anomaly extension).

## Implementation log

```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist

- [ ] typecheck clean (cloud-evidence + tracker)
- [ ] tests passing 100% (≥20 new tests this slice)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (P.P5 slice row + Overall section)
- [ ] LOOP-P-SPEC.md §8 status table updated (P.P5 row)
- [ ] This file's frontmatter updated (status, commit, completed_date)
- [ ] CHANGELOG.md "Unreleased" entry added (cites PM-12 + CISA Mitigation Guide page + indicator codes)
- [ ] Commit with `LOOP-P.P5:` slice ID in message
- [ ] Commit amended hash recorded in STATUS.md + this file + LOOP-P-SPEC.md
- [ ] Pushed to origin/main
- [ ] LOOP-P loop-level acceptance criteria all met (see LOOP-P-SPEC §6)

## Resume-from-fresh-session checklist

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read this file (P.P5.md).
3. Read `cloud-evidence/docs/loops/LOOP-P-SPEC.md` §5 P.P5 + §4 sources
   (CISA Mitigation Guide entry).
4. Read `cloud-evidence/docs/loops/LOOP-P-RISKS.md` — live risks register.
5. Read `cloud-evidence/docs/slices/P/P.P1.md` — case table schema lives
   here; P.P5 reads from + writes to `insider_threat_cases`.
6. Read `cloud-evidence/docs/slices/P/P.P2.md`, `P.P3.md`, `P.P4.md` —
   schemas P.P5 reads from.
7. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
8. Confirm CISA PDF downloaded to
   `cloud-evidence/docs/sources/cisa-insider-threat-mitigation-guide.pdf`.
9. Read `cloud-evidence/core/notify.ts` — notification surface.
10. Begin implementation; update Implementation log section as you go.
