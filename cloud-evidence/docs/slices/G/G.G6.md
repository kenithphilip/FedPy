---
slice_id: G.G6
title: AFR-CCM (Continuous Monitoring per 20x)
loop: G
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A4, REO-0, R1, R2, R3]
blocks: [LOOP-E.E1, LOOP-F.F4, LOOP-I.I1]
estimated_effort: 6 working days
last_updated: 2026-06-07
---

# G.G6 — AFR-CCM (Continuous Monitoring per 20x)

## TL;DR
Ship the quarterly Ongoing Authorization Report (OAR) — machine-readable JSON + human-readable markdown — plus the asynchronous customer feedback mechanism (public tracker route + anonymized summary emitter) + the RFC-5545 `.ics` calendar file for the Quarterly Review meeting. Closes CCM-OAR-AVL, CCM-OAR-NRD, CCM-OAR-FBM, CCM-OAR-AFS, CCM-QTR-REG. Aggregates 3 months of POA&M counts + KSI coverage + inventory + incident summary from real data; feedback is anonymized at write-time (IP/UA stripped, timestamps bucketed by month) so no PII reaches archived ledger.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
FedRAMP 20x Phase Two for Moderate (per RFC-0014) replaced annual ConMon with a continuous, machine-validated cadence: quarterly OAR + monthly KSI re-validation + anonymous feedback channel. Today the codebase has the monthly POA&M emitter (LOOP-A.A1) but no quarterly aggregate, no public-facing feedback channel, and no Quarterly Review meeting packet.

Without G.G6:
- CCM-OAR-AVL is unmet (no 3-month rollup).
- CCM-OAR-NRD is unmet (no published next-report date — ADS-CSO-PUB's `oar_next_target_date` field has nothing to publish).
- CCM-OAR-FBM is unmet (no async feedback channel).
- CCM-OAR-AFS is unmet (no anonymized feedback summary).
- CCM-QTR-REG is unmet (no calendar file).

Continuous-ATO renewal is blocked. G.G6 closes the gap by:
1. Pure builders that aggregate 3 months of `out/poam.json` + `out/inventory-coverage.json` + the AFR-ICP `icp_incidents` table + AFR-FSI `fsi_message_log` into the 7 OAR summary sections required by FRR-CCM-01.
2. A pure `computeNextOarTargetDate` that handles Feb 29 / month-end correctly.
3. A hand-rolled RFC-5545 `.ics` emitter (no external dep — same philosophy as the rest of the project).
4. A public tracker route (no auth) accepting anonymous feedback, with rate limiting + IP/UA stripping at write time enforced by both DB constraint and route logic.
5. A pure anonymizer that bucket-rounds timestamps to month and groups by category.

This slice is intentionally tight-loop with LOOP-E.E1 (monthly ConMon report): LOOP-E.E1 emits the monthly internal delivery; G.G6 aggregates 3 of those into the customer-facing OAR.

## Authoritative sources (with verbatim quotes)

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **CCM-OAR-AVL / FRR-CCM-01**:
  > "Providers MUST make an Ongoing Authorization Report available to all necessary parties every 3 months, covering the entire period since the previous summary, in a consistent format that is human readable; this report MUST include high-level summaries of at least the following information: …"
  Sub-bullets enumerated as: posture, control assessment, vulnerability, incident, change, audit findings, planned activities — re-quoted in OAR JSON `summary_sections`.

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **CCM-OAR-NRD / FRR-CCM-03**:
  > "Providers MUST publicly include the target date for their next Ongoing Authorization Report with other public authorization data."

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **CCM-OAR-FBM / FRR-CCM-04**:
  > "Providers MUST establish and share an asynchronous mechanism for all necessary parties to provide feedback or ask questions about each Ongoing Authorization Report."

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **CCM-OAR-AFS / FRR-CCM-05**:
  > "Providers MUST maintain an anonymized and desensitized summary of the feedback, questions, and answers about each Ongoing Authorization Report as an addendum to the Ongoing Authorization Report."

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **CCM-QTR-REG / FRR-CCM-QR-05**:
  > "Providers MUST include either a registration link or a downloadable calendar file with meeting information for Quarterly Reviews in the authorization data available to all necessary parties required by ADS-CSL-UCP and ADS-CSO-FCT."

- https://www.fedramp.gov/rfcs/0014/ — **FedRAMP RFC-0014 (Key Security Indicators, Phase Two)**:
  > "FedRAMP 20x Phase Two for Moderate explicitly mandates truly automated and opinionated validation of Key Security Indicators."
  Anchors the automated-aggregation framing for the OAR posture section.

- https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/ — **FedRAMP Rev5 Playbook — ConMon Overview**:
  > "Continuous Monitoring is the maintenance of ongoing awareness of information security, vulnerabilities, and threats to support organizational risk management decisions."
  Anchors the CCM-OAR-AVL cadence + summary content list.

- https://datatracker.ietf.org/doc/html/rfc5545 — **RFC 5545 (Internet Calendaring and Scheduling Core Object Specification - iCalendar)**:
  > "BEGIN:VCALENDAR / VERSION:2.0 / PRODID:… / BEGIN:VEVENT / UID:… / DTSTAMP:… / DTSTART:… / DTEND:… / SUMMARY:… / END:VEVENT / END:VCALENDAR"
  Quoted §3.4 + §3.6.1; drives the `.ics` emitter.

- https://datatracker.ietf.org/doc/html/rfc5545#section-3.1 — **RFC 5545 §3.1 (Content Line Folding)**:
  > "Lines of text SHOULD NOT be longer than 75 octets, excluding the line break."
  Drives line-folding in the .ics emitter.

- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — **NIST SP 800-53 Rev 5 §CA-7 (Continuous Monitoring)**:
  > "Develop a system-level continuous monitoring strategy and implement continuous monitoring in accordance with the organization-level continuous monitoring strategy."
  Anchors the OAR as the CSP-side CA-7 evidence.

- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — **NIST SP 800-53 Rev 5 §PM-4 (POA&M Process)**:
  > "Implement a process to ensure that POA&Ms for the security and privacy programs and associated organizational systems are developed and maintained …"
  Anchors the POA&M aggregation leg.

- https://www.fedramp.gov/rfcs/0024/ — **FedRAMP RFC-0024 (Machine-Readable Submissions)**:
  > "Authorization data MUST be available in both human-readable and machine-readable formats."
  Drives the `.json` + `.md` dual emission.

- https://gdpr-info.eu/art-4-gdpr/ — **GDPR Art. 4(5) (Pseudonymisation)**:
  > "'pseudonymisation' means the processing of personal data in such a manner that the personal data can no longer be attributed to a specific data subject without the use of additional information …"
  Anchors anonymization-at-write-time semantics for the feedback channel.

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/afr-ccm.ts` — pure builders + disk emitter. Exports:
  - `buildOarJson(input: OarInput): OarJson`
  - `buildOarMarkdown(input: OarInput): string`
  - `computeNextOarTargetDate(lastOarDate: string): string`
  - `buildFeedbackSummary(input: FeedbackInput): AnonymizedFeedbackSummary`
  - `buildQuarterlyMeetingPacket(input: QuarterlyMeetingInput): { icsBytes: Uint8Array; registrationUrl: string; meetingInfoJson: object }`
  - `anonymizeFeedbackRow(row: RawFeedbackRow): AnonymizedFeedbackRow`
  - `emitAfrCcm(outDir: string, ctx: OrchestratorContext): Promise<CcmEmitResult>`
  ~700 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/afr-ccm.test.ts` — unit tests (≥13) for date math, OAR aggregation, anonymization, .ics generation, line-folding.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-ccm-feedback.ts` — REST: `POST /api/afr-ccm/feedback` (anonymous, rate-limited, no auth), `GET /api/afr-ccm/feedback?period=YYYY-Qn` (RBAC viewer).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-ccm-feedback.test.ts` — route tests + anonymization-enforcement tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-ccm-meetings.ts` — REST: `GET/POST /api/afr-ccm/quarterly-meetings` (RBAC security for POST). Returns `.ics` bytes on GET when path includes `:meeting_id/ics`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-ccm-meetings.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/CcmFeedback.tsx` — public, no-auth feedback form with category select + free-text + submit. Embedded as a tracker route at `/feedback`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/CcmFeedback.test.tsx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/CcmMeetings.tsx` — operator UI: schedule quarterly meeting, download .ics, view feedback summary.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/AFR-CCM-RUNBOOK.md` — operator runbook: OAR cadence, feedback channel deployment, quarterly meeting scheduling, anonymization audit.

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--afr-ccm` flag + `CLOUD_EVIDENCE_AFR_CCM` env. `--afr-ccm-period=YYYY-Qn` selects the report period (default: previous quarter). `--ccm-feedback-url <url>` to override the default feedback channel URL.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — well-known catalogue rows:
  - `{ role: 'afr-ccm-oar-json', filename: 'afr-ccm/oar-<YYYY-Qn>.json', required: true }`
  - `{ role: 'afr-ccm-oar-md', filename: 'afr-ccm/oar-<YYYY-Qn>.md', required: true }`
  - `{ role: 'afr-ccm-feedback-summary', filename: 'afr-ccm/feedback-summary-<YYYY-Qn>.json', required: true }`
  - `{ role: 'afr-ccm-quarterly-ics', filename: 'afr-ccm/quarterly-meeting-<YYYY-Qn>.ics', required: true }`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — expose a typed reader `loadPoamCounts({start, end}): { open_by_severity: Record<Severity, number>; closed_in_period: number; new_in_period: number }` so the OAR aggregates without re-emitting.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts` — expose `loadCoverageTrend({start, end}): { fill_rate_start: number; fill_rate_end: number; delta_pct: number }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/schema.sql` — additive migrations:
  - `CREATE TABLE IF NOT EXISTS afr_ccm_feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, period TEXT NOT NULL, category TEXT NOT NULL CHECK (category IN ('question','clarification','concern','suggestion','other')), feedback_summary TEXT NOT NULL, response TEXT, response_at TEXT, date_bucket TEXT NOT NULL, submitted_at_internal_only TEXT NOT NULL);`
  - `CREATE TABLE IF NOT EXISTS afr_ccm_quarterly_meetings (id INTEGER PRIMARY KEY AUTOINCREMENT, period TEXT NOT NULL UNIQUE, meeting_date TEXT NOT NULL, registration_url TEXT, description TEXT, created_at TEXT NOT NULL, created_by_user_id TEXT NOT NULL);`
  - Note: `submitted_at_internal_only` carries the raw timestamp ONLY for the rate-limiter's recent-history window (24h); a daily cron MUST round it to `date_bucket` (YYYY-MM) and NULL the internal column for retention. The anonymizer runs at every emit; rows older than 24h with non-null `submitted_at_internal_only` are flagged as a REO violation.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/App.tsx` — register `/feedback` (public) and `/ccm-meetings` (auth) routes.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/components/Nav.tsx` — nav entry for CcmMeetings.

## Schemas / standards

**`OarJson`** (machine-readable, OSCAL-friendly):

```ts
interface OarJson {
  $schema: 'https://fedramp.gov/schemas/afr-ccm/oar/2026.json';
  system_id: string;
  system_name: string;
  csp_name: string;
  period_id: string;                        // e.g. '2026-Q3'
  report_period: { start: string; end: string };
  next_report_target_date: string;          // per CCM-OAR-NRD
  summary_sections: {
    posture_summary: PostureSummary;
    control_assessment_summary: ControlAssessmentSummary;
    vulnerability_summary: VulnerabilitySummary;
    incident_summary: IncidentSummary;
    change_summary: ChangeSummary;
    audit_findings_summary: AuditFindingsSummary;
    planned_activities_summary: PlannedActivitiesSummary;
  };
  feedback_mechanism: { url: string; description: string };          // CCM-OAR-FBM
  feedback_summary_ref: string;                                       // pointer to .json
  quarterly_review: { date: string; registration_url: string; calendar_file: string };  // CCM-QTR-REG
  provenance: ProvenanceBlock;
}

interface PostureSummary { open_findings_by_severity: Record<'low'|'moderate'|'high'|'critical', number>; ksi_coverage_pct: number; inventory_coverage_pct: number; }
interface ControlAssessmentSummary { ksi_passes: number; ksi_fails: number; ksi_partial: number; }
interface VulnerabilitySummary { open_vulns_total: number; open_by_age_band: { '0-30d': number; '31-60d': number; '61-90d': number; '90d+': number }; kev_open: number; }
interface IncidentSummary { incidents_opened: number; incidents_closed: number; incidents_open_end_of_period: number; sla_breaches: number; }
interface ChangeSummary { scn_events: number; significant_changes: number; }
interface AuditFindingsSummary { findings_opened: number; findings_closed: number; }
interface PlannedActivitiesSummary { next_period_priorities: string[]; }   // REQUIRES-OPERATOR-INPUT
```

**`AnonymizedFeedbackSummary`** (per CCM-OAR-AFS):

```ts
interface AnonymizedFeedbackSummary {
  period_id: string;
  by_category: Record<'question'|'clarification'|'concern'|'suggestion'|'other', AnonymizedFeedbackRow[]>;
  by_month: Record<string, AnonymizedFeedbackRow[]>;                 // 'YYYY-MM'
  total_count: number;
  provenance: ProvenanceBlock;
}
interface AnonymizedFeedbackRow {
  category: string;
  feedback_summary: string;
  response: string | null;
  date_bucket: string;        // 'YYYY-MM'
  // EXPLICITLY absent: submitted_by, ip_address, user_agent, exact_timestamp.
}
```

**RFC-5545 .ics structure**:

```
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//FedRAMP 20x cloud-evidence//EN
CALSCALE:GREGORIAN
METHOD:PUBLISH
BEGIN:VEVENT
UID:<period_id>@<csp-domain>
DTSTAMP:<emit-time UTC>
DTSTART:<meeting-date UTC>
DTEND:<meeting-date + 1h UTC>
SUMMARY:FedRAMP Quarterly Review - <period_id>
DESCRIPTION:<description>\nRegistration: <registration_url>
URL:<registration_url>
END:VEVENT
END:VCALENDAR
```

Line folding: any line >75 octets is split on octet boundary; continuation line starts with a single space (per RFC-5545 §3.1).

**Period semantics**:
- Period ids are `YYYY-Qn` where `Qn ∈ {Q1,Q2,Q3,Q4}` (Q1 = Jan-Mar, Q2 = Apr-Jun, Q3 = Jul-Sep, Q4 = Oct-Dec).
- `computeNextOarTargetDate(d)`: adds 3 months; if target day > target month's last day (e.g. Jan 31 + 3 months = Apr 31 → Apr 30), clamp to last day.
- Feb 29 case: Feb 29 + 3 months = May 29 (no clamp).

## Build steps (concrete, numbered)

1. Define typed interfaces in `core/afr-ccm.ts`. Determinism: all arrays sorted; period_id-based filenames.
2. Pure `computeNextOarTargetDate(lastOarDate)`:
   - Parse RFC-3339; add 3 months via month-arithmetic; clamp day to target month's last day.
   - Unit-tested for Jan 31 + 3, Nov 30 + 3, Feb 29 (leap), Dec 1 + 3.
3. Pure `buildOarJson(input)`:
   - Aggregate POA&M counts from `core/oscal-poam.ts:loadPoamCounts({start, end})`.
   - Aggregate KSI coverage from `core/inventory-coverage.ts:loadCoverageTrend({start, end})`.
   - Aggregate incidents from `icp_incidents` table (sums by status + SLA breaches).
   - Aggregate SCN events from `core/scn-classifier.ts` log.
   - Aggregate audit findings from `out/audit-findings.json` if present.
   - `planned_activities_summary.next_period_priorities`: REQUIRES-OPERATOR-INPUT from tracker `afr_ccm_priorities` table OR `org-profile.yaml:ccm.next_priorities`.
   - Embed verbatim FRMR statements in `provenance.requirementTexts`.
4. Pure `buildOarMarkdown(input)`:
   - Render the JSON into human-readable markdown with 7 sections + provenance footer.
5. Pure `anonymizeFeedbackRow(row)`:
   - Strip `submitted_by`, `ip_address`, `user_agent`, `exact_timestamp`.
   - Compute `date_bucket = row.submitted_at.slice(0,7)` (YYYY-MM).
   - Return `AnonymizedFeedbackRow`.
6. Pure `buildFeedbackSummary(input)`:
   - For each row in input: anonymize.
   - Group by category + by date_bucket.
   - Sort each group's rows by `date_bucket` ASC.
7. Pure `buildQuarterlyMeetingPacket(input)`:
   - Build `.ics` string per RFC-5545.
   - Line-fold any line >75 octets.
   - Compute UID = `<period_id>@<csp-domain-from-SSP>`.
   - DTSTAMP = emit time UTC; DTSTART/DTEND from operator.
8. Disk emitter `emitAfrCcm(outDir, ctx)`:
   - Read SSP + tracker tables + poam + coverage + incidents.
   - Build OAR JSON + markdown + feedback summary + .ics.
   - Write all 4 artifacts to `out/afr-ccm/`.
   - Append provenance with the 5 verbatim CCM MUSTs.
9. Orchestrator wiring: `--afr-ccm` flag + env + period flag.
10. Submission bundle: 4 new role rows with period-id-templated filenames.
11. Tracker public feedback route:
    - No auth required.
    - Rate-limited by existing `core/rate-control.ts` pattern: 5 submissions / IP / hour.
    - Validates `category` enum, `feedback_summary` length 1-2000 chars.
    - On write: stores raw `submitted_at_internal_only` for 24h rate-limit window; `date_bucket = submitted_at.slice(0,7)`; never stores IP/UA.
    - A daily cron (`scripts/anonymize-feedback.mjs`) nulls `submitted_at_internal_only` for rows >24h old. The orchestrator pre-flight check raises REO violation when any row >24h has non-null internal column.
12. Tracker operator route: CRUD on `afr_ccm_quarterly_meetings` table; download `.ics` byte stream.
13. UI public feedback form: HTML form with category select + free-text textarea + submit button + success notice; no captcha required (rate limiter is sufficient).
14. UI operator pages: schedule meetings + view feedback summary per period.
15. Validation pass: `npm run typecheck`; `npm test`; `npm run check:reo`.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| `feedback_mechanism.url` | CLI `--ccm-feedback-url` (default = `<tracker-base-url>/feedback`) | resolves to default if tracker base URL is configured; marker if not |
| `quarterly_review.date` | tracker `afr_ccm_quarterly_meetings` | marker; .ics not emitted; CCM-QTR-REG unmet |
| `quarterly_review.registration_url` | tracker | marker; .ics emits without URL field |
| `planned_activities_summary.next_period_priorities` | tracker `afr_ccm_priorities` or `org-profile.yaml:ccm.next_priorities` | array empty; marker emitted; CCM-OAR-AVL "planned activities" sub-bullet unmet |
| `csp_domain` for ics UID | SSP `metadata.title` domain segment or operator-supplied `--csp-domain` | marker; UID falls back to `<period_id>@unknown.invalid` |
| `posture_summary.*` per-metric | derived from real `poam.json` + `inventory-coverage.json` + tracker tables | per-metric marker if underlying file missing |

## Test specifications (≥13 tests)

1. `it('computes next OAR target date as last + 3 months')` — assert Jan 15 + 3 = Apr 15; Feb 29 + 3 (2024 leap) = May 29; Jan 31 + 3 = Apr 30 (clamp); Nov 30 + 3 = Feb 28/29 (clamp).
2. `it('aggregates open POA&M counts for the report period')` — fixture poam.json with 3 open / 1 closed in period → counts match.
3. `it('renders all 7 summary sections in OAR markdown')` — assert each section heading present in markdown body.
4. `it('writes deterministic OAR JSON')` — same input twice → byte-identical output; key order stable.
5. `it('quotes verbatim CCM-OAR-AVL + NRD + FBM + AFS + QTR-REG statements in provenance')` — 5 keys; each value byte-equal to FRMR statement.
6. `it('strips IP + UA from feedback rows during anonymization')` — input row with `ip_address` / `user_agent` → output row has neither; output type interface enforces absence.
7. `it('buckets feedback by month (YYYY-MM) only')` — input timestamp `2026-06-07T14:32:11Z` → bucket `2026-06`; no exact-timestamp in output.
8. `it('groups feedback by category')` — input 4 rows across 3 categories → output `by_category` has 3 keys; counts add up to 4.
9. `it('emits valid RFC 5545 .ics with required properties')` — assert each property present: `BEGIN:VCALENDAR`, `VERSION:2.0`, `PRODID`, `BEGIN:VEVENT`, `UID`, `DTSTAMP`, `DTSTART`, `DTEND`, `SUMMARY`, `URL`, `END:VEVENT`, `END:VCALENDAR`.
10. `it('line-folds .ics at 75 octets')` — synthetic input with 200-char SUMMARY → output split into multiple lines each ≤75 octets; continuation lines start with single space.
11. `it('feedback POST does not require auth')` — POST with no Authorization header → 201 with anonymized row written.
12. `it('feedback POST is rate-limited per tracker config')` — 6 POST from same IP within 1h → 6th returns 429.
13. `it('emits REQUIRES-OPERATOR-INPUT for quarterly_review when no scheduled meeting')` — no row → marker; .ics not emitted; CCM-QTR-REG missing flagged.
14. `it('feedback DB rejects raw timestamps older than 24h')` — pre-flight check raises REO violation when `submitted_at_internal_only IS NOT NULL` and row age >24h.
15. `it('orchestrator with --afr-ccm-period=2026-Q3 selects Jul-Sep 2026 window')` — period parser; aggregation window matches.

## REO compliance specific to this slice

- OAR `summary_sections.*` sourced from real `out/poam.json` + KSI coverage + inventory + `icp_incidents` table; no fabricated metrics. Each summary block carries `source` references in provenance.
- Feedback anonymization enforced at write time: route strips IP/UA before INSERT; DB column for raw timestamp is short-lived (24h); daily cron nulls it; REO pre-flight check fails if cron missed.
- `.ics` constructed from operator-supplied date + URL only — never auto-scheduled. UID derives from SSP-domain + period_id (deterministic).
- `next_report_target_date` computed deterministically — no rounding to "approximately". Operator can override via tracker.
- Signed by: existing `core/sign.ts` Ed25519 + RFC 3161 pipeline. All 4 artifacts manifest-listed.
- No `if (process.env.NODE_ENV === 'test')` branches (REO Rule 1.8). Tests inject the DB + outDir via dependency injection.
- `provenance.requirementTexts` carries 5 verbatim CCM MUSTs.
- `feedback_mechanism.url` defaults to the tracker's own `/feedback` route; operator can override but never hardcoded to a fake URL.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/afr-ccm.test.ts
npm test -- tracker/server/routes/afr-ccm-feedback.test.ts
npm test -- tracker/server/routes/afr-ccm-meetings.test.ts
npm test -- tracker/client/src/pages/CcmFeedback.test.tsx
npm run check:reo
```

End-to-end smoke:
```bash
npm run collect -- --impact-level moderate --afr-ccm --afr-ccm-period=2026-Q2 --submission-bundle --sign
ls -la out/afr-ccm/
node -e "const j=JSON.parse(require('fs').readFileSync('out/afr-ccm/oar-2026-Q2.json','utf8')); console.log('next:', j.next_report_target_date)"
```

## Known risks / issues

- **Risk 1: OAR aggregation rules under-specified by FedRAMP.** RFC-0014 says "high-level summary" but does not prescribe a quantitative threshold for "significant". *Mitigation*: defaults are tunable via `org-profile.yaml:ccm.thresholds`; the aggregation function is exposed so it can be re-tuned without re-emitting prior periods.
- **Risk 2: OAR PDF rendering without an external dep.** FedRAMP customers may prefer PDF. *Mitigation*: ship `.md` + `.json` now; the operator can render via `pandoc` or `libreoffice --headless`; LOOP-E.E1 inheriting a pure-JS PDF emitter is a follow-up.
- **Risk 3: Feedback channel abuse / spam.** Public no-auth endpoint invites bots. *Mitigation*: rate limiter at 5/IP/hour; reject bodies > 2000 chars; daily cron deletes rows where feedback_summary matches a spam blocklist (operator-curated regex).
- **Risk 4: Anonymization cron failure leaves PII at rest.** If the daily cron crashes, raw timestamps remain on disk. *Mitigation*: REO pre-flight check fails the orchestrator run when rows >24h have non-null `submitted_at_internal_only`; the cron is monitored via tracker health check (HTTP 200 when cron last ran <26h ago).
- **Risk 5: `.ics` parsing differences across calendar clients.** Google Calendar, Outlook, Apple Calendar each interpret subtly different. *Mitigation*: test the emitted file against an RFC-5545 parser (one of `ical.js` or pure-JS regex in tests); document tested clients in runbook.
- **Risk 6: Period boundary ambiguity.** A bug-fix landed on the period-boundary day (e.g. Sep 30 23:55) could be counted in Q3 or Q4. *Mitigation*: period boundaries are inclusive-start / exclusive-end in UTC; documented in OAR markdown footer; tests pin the convention.
- **Risk 7: OAR + LOOP-E.E1 monthly delivery overlap.** Same data summarized at two cadences could diverge if computed separately. *Mitigation*: G.G6 calls the same `loadPoamCounts` + `loadCoverageTrend` exporters LOOP-E.E1 uses; integration test asserts Q3 OAR = Jul+Aug+Sep monthly reports when summed.
- **Risk 8: ISO month arithmetic edge cases.** Off-by-one on Feb 29 has bitten ConMon implementations before. *Mitigation*: explicit unit tests for Jan 31, Feb 29 leap, Nov 30, Dec 31; date arithmetic uses `Date.UTC` consistently.

## Open questions (for implementation session to resolve)

- **Q1**: Should `next_report_target_date` be exactly +3 months or "the first business day on or after +3 months"? Recommendation: exactly +3 months (clamped to last day-of-month). Business-day shifting is operator concern.
- **Q2**: Does the feedback channel need CAPTCHA for accessibility? Recommendation: no — rate limiter is sufficient; CAPTCHA harms accessibility; document blocklist process in runbook.
- **Q3**: How long to retain anonymized feedback rows? Recommendation: 3 years per ADS-CSO-HAD parallel.
- **Q4**: Should `afr_ccm_priorities` (next-period priorities) auto-derive from open POA&M deadlines? Recommendation: optional auto-suggestion; operator confirms; never auto-publish without confirmation.
- **Q5**: Does the OAR markdown need a customer-facing executive summary at the top? Recommendation: yes, 3-sentence summary from operator (tracker `afr_ccm_exec_summary` per period) OR auto-derived ("X open findings, Y% KSI coverage, Z incidents this period").
- **Q6**: Should `.ics` files be regenerated per emit, or only on meeting-schedule change? Recommendation: regenerate per emit but UID stable per period; calendar clients de-dup by UID.
- **Q7**: How do we handle a CSP without a quarterly review meeting (e.g. a brand-new CSO)? Recommendation: emit REQUIRES-OPERATOR-INPUT and document that CCM-QTR-REG is a MUST starting from period 2 onward.
- **Q8**: Where does the feedback summary live in the OAR markdown? Recommendation: appendix linked from the OAR `.md` body; never inlined raw.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~22 for this slice: 15 unit + 7 route/UI)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section: LOOP-G COMPLETE if final + Next priority = LOOP-H.H1)
- [ ] LOOP-G-SPEC.md §7 status table updated + "LOOP-G — AFR Family (20x deliverables)" section title set to "(COMPLETE)"
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-G.G6: AFR-CCM (Continuous Monitoring per 20x) (closes LOOP-G)`
- [ ] Commit with `LOOP-G.G6:` in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-G-SPEC.md
- [ ] Pushed to origin/main
- [ ] AFR-CCM-RUNBOOK.md authored
- [ ] End-to-end orchestrator smoke produces all 4 `out/afr-ccm/` artifacts + manifest entries
- [ ] LOOP-G-RISKS.md updated with any newly-resolved risks moved to the Resolved section

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context, here's everything it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-G-SPEC.md` §2 (Dependencies) + §4 G.G6 + §6 caveats (especially the OAR PDF rendering caveat).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Read `cloud-evidence/core/oscal-poam.ts` for `loadPoamCounts` integration; if exporter not present, add it as part of this slice.
6. Read `cloud-evidence/core/inventory-coverage.ts` for `loadCoverageTrend` integration.
7. Read `cloud-evidence/core/scn-classifier.ts` for SCN event aggregation.
8. Read `cloud-evidence/core/submission-bundle.ts` for catalogue-row pattern.
9. Read `cloud-evidence/core/sign.ts` for the signing wrapper.
10. Read `cloud-evidence/tracker/server/routes/` for an existing route to model `afr-ccm-feedback.ts` (especially the rate-limited one).
11. Read RFC-5545 §3.1, §3.4, §3.6.1 before implementing the .ics emitter.
12. Read GDPR Art. 4(5) (Pseudonymisation) before implementing the anonymizer.
13. Begin implementation; update Implementation log section as you go.
