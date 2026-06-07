---
slice_id: S.S2
title: DFARS 252.204-7012(c) cyber-incident reporting workflow
loop: S
status: pending
commit: —
completed_date: —
applicable_conditional: true
condition: CSP has at least one DoD-prime customer (DFARS Subpart 204.73 applicable) AND an incident affecting Covered Defense Information / CUI has been discovered
trigger_flag: "--dfars-incident-report <incident-uuid>"
trigger_env: CLOUD_EVIDENCE_DFARS_EQUIVALENCY
depends_on: [LOOP-G.G2, LOOP-M.M4, S.S1, "core/envelope.ts (existing)"]
blocks: [S.S3]
estimated_effort: 6-7 working days
last_updated: 2026-06-07
---

# S.S2 — DFARS 252.204-7012(c) cyber-incident reporting workflow

## TL;DR

When a cyber incident affects Covered Defense Information / CUI on the
CSP, DFARS 252.204-7012(c)(1)(ii) requires the CSP to "rapidly report"
the incident to the DoD Cyber Crime Center (DC3) via DIBNet
(https://dibnet.dod.mil/) within 72 hours of discovery using the DC3
Incident Collection Format (ICF) v3.0. S.S2 produces:

1. A signed tracker workflow that turns an existing G.G2 incident
   record into a DFARS-scoped report draft, computes the 72-hour
   deadline, validates the required ICF fields, and emits
   `out/dfars-incident-report-{uuid}.json` + `.docx` for the operator
   to upload to DIBNet.
2. Coordination with LOOP-M.M4 PII breach-notification logic — when an
   incident affects BOTH CUI and PII, BOTH reports are required to
   DIFFERENT authorities with DIFFERENT deadlines; the UI surfaces
   both flows so neither is missed.
3. A signed audit record of operator submission (DC3 tracking number +
   evidence URL) so the CSP can prove timely DC3 submission to a 3PAO
   or auditing prime contracting officer.

S.S2 does **not** auto-submit to DIBNet — the portal requires
DoD-approved Medium-Assurance ECA / CAC authentication; the operator
uploads via the portal and records the tracking number back into the
tracker as a signed human action per REO Rule 4.

## Status

- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists

DFARS 252.204-7012(c)(1)(ii) reads:

> "Rapidly report cyber incidents to DoD at https://dibnet.dod.mil/."

The DoD Mandatory Cyber Incident Reporting Procedures (cited in the DC3
ICF training materials) define "rapidly" as **within 72 hours of
discovery**. The clause further requires (c)(2):

> "Cyber incident report. The cyber incident report shall include, at
> a minimum, the required elements at https://dibnet.dod.mil/."

Today the existing LOOP-G.G2 incident-response collector captures
incident metadata in a generic FedRAMP IR-6 shape — good for the
FedRAMP package, but missing several DFARS-specific obligations:

1. No 72-hour deadline math anchored to discovery time.
2. No DC3 ICF v3.0 schema validation (the FedRAMP IR-6 record has
   different required fields).
3. No contract-number / contracting-officer / program-manager fields
   the ICF mandates.
4. No CUI/CDI scope flags — IR-6 records everything; DFARS reports
   only when CDI is affected.
5. No coordination with LOOP-M.M4 PII breach-notification logic — a
   single incident affecting both PII and CUI must trigger BOTH
   reports.
6. No malicious-software submission tracking per DFARS 7012(d).
7. No 90-day media-preservation tracking per DFARS 7012(e).
8. No DC3 tracking-number audit record post-submission.

S.S2 closes all eight gaps. It does NOT introduce a new incident
collector — it builds on the existing G.G2 schema, adds DFARS-specific
flags + fields, and emits DFARS-shaped artifacts.

## Authoritative sources (with verbatim quotes)

- **DFARS 252.204-7012(c)(1)** —
  https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting
  > "When the Contractor discovers a cyber incident that affects a
  > covered contractor information system or the covered defense
  > information residing therein, or that affects the contractor's
  > ability to perform the requirements of the contract that are
  > designated as operationally critical support and identified in the
  > contract, the Contractor shall — (i) Conduct a review for evidence
  > of compromise of covered defense information... (ii) Rapidly report
  > cyber incidents to DoD at https://dibnet.dod.mil/."

- **DFARS 252.204-7012(c)(2)** — minimum report content (referenced
  to the DC3 portal).

- **DFARS 252.204-7012(d) — Malicious software**:
  > "When the Contractor or subcontractors discover and isolate
  > malicious software in connection with a reported cyber incident,
  > submit the malicious software to DoD Cyber Crime Center (DC3) in
  > accordance with instructions provided by DC3 or the Contracting
  > Officer."

- **DFARS 252.204-7012(e) — Media preservation and protection**:
  > "When a Contractor discovers a cyber incident has occurred, the
  > Contractor shall preserve and protect images of all known affected
  > information systems identified in paragraph (c)(1)(i) of this
  > clause and all relevant monitoring/packet capture data for at
  > least 90 days from the submission of the cyber incident report to
  > allow DoD to request the media or decline interest."

- **DFARS 252.204-7012(f) — Access to additional information or
  equipment necessary for forensic analysis**:
  > "Upon request by DoD, the Contractor shall provide DoD with access
  > to additional information or equipment that is necessary to
  > conduct a forensic analysis."

- **DFARS 252.204-7012(g) — Cyber incident damage assessment
  activities**:
  > "If DoD elects to conduct a damage assessment, the Contracting
  > Officer will request that the Contractor provide all of the damage
  > assessment information gathered in accordance with paragraph (e)
  > of this clause."

- **DC3 Incident Collection Format (ICF) v3.0** — published with the
  DIBNet portal user guide. Required fields enumerated in
  `LOOP-S-SPEC.md` § Authoritative sources.

- **DIBNet portal** — https://dibnet.dod.mil/ — submission endpoint;
  authentication via DoD CAC / Medium-Assurance ECA.

- **32 CFR Part 236 (DIB CS Program)** —
  https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-M/part-236
  - §236.4 codifies the reporting required actions; cited in per-
    incident emitter docstring.

- **DoD CIO "Mandatory Cyber Incident Reporting Procedures"** —
  referenced via the DC3 portal training materials; defines "rapidly"
  as 72h.

- **NARA CUI Registry** — https://www.archives.gov/cui/registry/category-list
  — CUI categories used to populate `affected_defense_information`
  field.

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-incident-reporting.ts`
  — pure builder + emitter. ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-incident-icf.ts`
  — ICF v3.0 schema + ajv validator. ~250 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-incident-docx.ts`
  — OOXML docx renderer for the ICF report. ~300 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-incident-reporting.test.ts`
  — ≥12 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-incident-icf.test.ts`
  — ≥5 schema-pin tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/dfars-incidents.ts`
  — Express routes.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/dfars-incidents.test.ts`
  — ≥10 route tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/dfars-deadline-enforcer.ts`
  — recurring task scanning for incidents past the 48h-warn or 72h-due
  threshold; emits audit log + (optional) notification via existing
  `core/notify.ts` Slack/PagerDuty.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/dfars-deadline-enforcer.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/DfarsIncidents.tsx`
  — list + detail UI gated by `DFARS_ENABLED=true`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/DfarsIncidentDetail.tsx`
  — per-incident editor + DC3 tracking number capture form.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/DfarsIncidents.test.tsx`.

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/envelope.ts`
  — extend the existing `Incident` interface (added by LOOP-G.G2) with:
  ```ts
  cui_affected?: boolean;
  cdi_affected?: boolean;
  pii_affected?: boolean;       // coordination with M.M4
  affected_cui_categories?: string[]; // NARA CUI Registry category ids
  ```
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — new `--dfars-incident-report <incident-uuid>` flag (event-driven,
  not scheduled). When set, the orchestrator runs ONLY the DFARS
  incident emitter (skipping the full collection pipeline).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql`
  — append `dfars_incidents`, `dfars_incident_submissions`,
  `dfars_incident_artifacts` tables per `LOOP-S-SPEC.md` § S.S2.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts`
  — mount `routes/dfars-incidents.ts`; gated by `DFARS_ENABLED=true`
  config flag.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/rbac.ts`
  — `iso` and `so` roles can create/edit/submit DFARS incidents;
  `assessor` can view.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx`
  — add `/dfars/incidents` route + nav link, both hidden when
  `DFARS_ENABLED=false`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add `dfars-incident-report-bundle` role (directory glob:
  `dfars-incident-report-*.json` + `.docx`).

## Schemas / standards

- **DFARS Incident Collection Format (ICF) v3.0** typed interface —
  see `LOOP-S-SPEC.md` § S.S2 Build steps for the full shape.

- **Tracker `dfars_incidents` table** — see `LOOP-S-SPEC.md` § S.S2
  Files-to-extend.

- **Deadline math**:
  ```ts
  deadline_at = discovered_at + 72h          // ISO datetime
  warn_at     = discovered_at + 48h          // ISO datetime
  ```

- **Coordination flag matrix**:
  | `cui_affected` | `cdi_affected` | `pii_affected` | Required flows |
  |---|---|---|---|
  | true | false | false | DFARS S.S2 only |
  | true | true | false | DFARS S.S2 only |
  | false | true | false | DFARS S.S2 only |
  | true | false | true | DFARS S.S2 + M.M4 (both required) |
  | true | true | true | DFARS S.S2 + M.M4 (both required) |
  | false | false | true | M.M4 only (no DFARS) |
  | false | false | false | Neither (warn-out) |

## Build steps (concrete, numbered)

1. **Define ICF types** in `core/dfars-incident-icf.ts`:
   ```ts
   export interface DfarsIcfV3 {
     schema_version: '3.0';
     submitter: {
       company_name: string;
       duns: string;
       cage_code: string;
       facility_cage: string;
       poc: { name: string; email: string; phone: string };
     };
     contract: {
       contract_numbers: string[];
       contracting_officer: { name: string; email: string; phone: string };
       program_manager: { name: string; email: string; phone: string };
     };
     incident: {
       date_discovered: string;
       date_occurred?: string;
       location: string;
       technique_or_method: string;
       system_type: string;
       outcome: string;
       type_of_compromise: string[];
       description: string;        // ≥200 chars
       impact: string;             // ≥100 chars
       affected_defense_information: string;
       compromised_record_count?: number;
       forensic_information?: string;
     };
     malicious_software_sample?: { filename: string; sha256: string; submitted_via: string };
     media_preservation?: { items: Array<{ description: string; sha256?: string; retention_until: string }> };
   }
   ```
   Plus ajv schema; export `validateIcf(record: DfarsIcfV3)`.

2. **Tracker DB migration**: append tables to `schema.sql` (idempotent
   `CREATE TABLE IF NOT EXISTS` pattern). Run migration test that
   re-runs the script on a populated DB — must not throw + not
   destroy data.

3. **POST route `/api/dfars/incidents`**:
   ```ts
   interface CreateBody {
     source_incident_uuid: string;        // must reference real G.G2 incident
     discovered_at: string;
     occurred_at?: string;
     cui_affected: boolean;
     cdi_affected: boolean;
     pii_affected: boolean;
     affected_cui_categories?: string[];
     contract_numbers: string[];          // ≥1
     contracting_officer_poc: { name: string; email: string; phone: string };
     program_manager_poc: { name: string; email: string; phone: string };
     description: string;                 // ≥200 chars
     impact: string;                      // ≥100 chars
     affected_defense_information: string;
     compromised_record_count?: number;
     forensic_information?: string;
   }
   ```
   Validation:
   - Caller has `iso` or `so` role.
   - At least one of `cui_affected`, `cdi_affected` is true.
   - `contract_numbers.length >= 1`.
   - `description.length >= 200`.
   - `impact.length >= 100`.
   Compute `deadline_at = discovered_at + 72h`. Sign canonical JSON
   with Ed25519. Insert row `status='draft'` (or `'ready-for-submit'`
   if everything required is populated). Audit log
   `event='dfars-incident-created'`.

4. **POST `/api/dfars/incidents/:uuid/submit`**:
   ```ts
   interface SubmitBody { dc3_tracking_number: string; submission_evidence_url?: string; submission_evidence_sha256?: string; }
   ```
   Update `dfars_incidents.status='submitted'`,
   `submitted_at=now()`, `dc3_tracking_number`. Insert
   `dfars_incident_submissions` row with its own signature. Audit log.

5. **Deadline enforcer** `tracker/server/dfars-deadline-enforcer.ts`
   (mirrors B.B3 enforcer pattern). Runs on boot + every 5 minutes.
   For each incident where `status != 'submitted'`:
   - If `now() >= warn_at AND warn_emitted = 0`: emit `notify` (Slack +
     PagerDuty via `core/notify.ts`), set `warn_emitted=1`, audit log
     `event='dfars-incident-deadline-warning'`.
   - If `now() >= deadline_at AND escalation_emitted = 0`: emit
     elevated `notify`, audit log `event='dfars-incident-deadline-exceeded'`.

6. **ICF builder** in `core/dfars-incident-reporting.ts`:
   ```ts
   export function buildIcf(incident: DfarsIncidentRecord, csp: CspProfile): DfarsIcfV3;
   ```
   Pure mapping; validates via `validateIcf()`.

7. **Emitter**:
   ```ts
   export interface DfarsIncidentEmitOptions {
     outDir: string;
     incidentUuid: string;
     trackerUrl: string;
     trackerToken: string;
     cspProfilePath: string;
     runId: string;
   }
   export interface DfarsIncidentEmitResult {
     icf_json_path: string;
     icf_docx_path: string;
     incident_uuid: string;
     deadline_at: string;
     deadline_status: 'on-time' | 'warning-48h' | 'exceeded';
     dc3_tracking_number?: string;
   }
   export async function emitDfarsIncidentReport(opts: DfarsIncidentEmitOptions): Promise<DfarsIncidentEmitResult>;
   ```
   Reads incident from tracker, builds ICF, writes JSON + docx,
   computes deadline_status from current time vs deadline_at. Returns
   non-zero exit code from orchestrator if `deadline_status ===
   'exceeded'` (the operator must still ship the report).

8. **DOCX renderer** `core/dfars-incident-docx.ts`. Follows the OOXML
   pattern used by `core/oscal-ssp-docx.ts`. Cover page lists:
   - Company name, DUNS, CAGE, contract numbers
   - Discovery date, deadline, time-remaining
   - Affected CUI categories (NARA labels)
   - Description, impact, affected_defense_information
   - Forensic information
   - DC3 tracking number (if assigned)
   - Footer citing DFARS 252.204-7012(c)(1)(ii) verbatim + DIBNet URL +
     "Submit via DoD-approved Medium-Assurance ECA or DoD CAC".

9. **Provenance block** on `dfars-incident-report-{uuid}.json`:
   ```ts
   provenance: {
     emitter: 'dfars-incident-reporting',
     emittedAt: string,
     sourceCalls: [
       { kind: 'tracker', path: 'api/dfars/incidents/{uuid}' },
       { kind: 'tracker', path: 'api/incidents/{source_uuid}' },        // G.G2 incident
       { kind: 'config', path: 'org-profile.yaml' },
     ],
     signingKeyId: string,
   }
   ```

10. **Coordination with M.M4**: when `pii_affected === true`, the
    tracker UI banner reads "This incident requires BOTH a DFARS DC3
    report (deadline 72h from discovery) AND a PII breach notification
    per M.M4 (deadline varies — see M.M4)". The two flows are
    independent state machines. The S.S2 emitter logs a coordination
    notice but never coalesces.

11. **Orchestrator wiring**: `--dfars-incident-report <incident-uuid>`
    is an event-driven on-demand flag. When set, the orchestrator runs
    ONLY `emitDfarsIncidentReport(opts)` + signs the output. Other
    flags (collect, oscal-poam, bundle-submission) are ignored unless
    explicitly set in the same command.

12. **UI** (`DfarsIncidents.tsx`):
    - List view filterable by status, deadline-imminence, contract.
    - Color-coded urgency: green (>48h remaining), yellow (24-48h),
      red (<24h or exceeded).
    - Detail view shows ICF preview (read from emitted JSON), deadline
      countdown, "Build Report" button (runs the emitter through the
      orchestrator), "Mark Submitted" button (opens dialog).
    - "Both DFARS and PII" banner when `pii_affected && (cui_affected
      || cdi_affected)`.
    - Routes hidden when `DFARS_ENABLED=false`.

13. **Bundler integration**: bundler includes a
    `dfars-incident-report-bundle` directory role that archives all
    `dfars-incident-report-*.json` + `.docx` produced in the last 12
    months when `--dfars-equivalency` is set (consumed by S.S3).

## REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4, every field that cannot be auto-derived:

| Field | Source | Behavior when missing |
|---|---|---|
| `source_incident_uuid` | Operator selects existing G.G2 incident | Required — server rejects empty value |
| `cui_affected`/`cdi_affected` | Operator UI flag | At least one required — server rejects neither |
| `contract_numbers[]` | Operator UI input | Required (≥1) |
| `contracting_officer_poc` | Operator UI input | Required |
| `program_manager_poc` | Operator UI input | Required |
| `description` (≥200 chars) | Operator UI input | Required |
| `impact` (≥100 chars) | Operator UI input | Required |
| `affected_cui_categories[]` | Operator UI multi-select from NARA categories | Optional but recommended; missing → `coverage:partial` log warning |
| `forensic_information` | Operator UI input | Optional (filled as forensic work progresses) |
| `dc3_tracking_number` | Operator submits via DIBNet, then records back | Stays empty until operator records; deadline status stays "on-time" / "warning-48h" / "exceeded" |
| `malicious_software_sample` | Operator records per § 252.204-7012(d) when applicable | Optional; UI prompts "Required if malware involved" |
| `media_preservation.items[]` | Operator captures per § 252.204-7012(e) (90-day preservation) | Required (≥1 item) when any system was imaged; UI prompts |

## Test specifications (≥17 tests)

### Route handler tests
1. `it('rejects POST without source_incident_uuid')`.
2. `it('rejects POST with neither cui_affected nor cdi_affected')`.
3. `it('rejects POST with empty contract_numbers[]')`.
4. `it('rejects POST with description < 200 chars')`.
5. `it('rejects POST with impact < 100 chars')`.
6. `it('rejects POST when caller lacks iso/so role')`.
7. `it('computes deadline_at = discovered_at + 72h')`.
8. `it('signs canonical JSON with Ed25519')`.
9. `it('inserts row with status=draft when required fields missing')`.
10. `it('inserts row with status=ready-for-submit when complete')`.
11. `it('records signed submission row when operator marks submitted')`.
12. `it('rejects double-submit')`.

### Enforcer tests
13. `it('emits deadline-warning notification at +48h once')`.
14. `it('emits deadline-exceeded notification at +72h once')`.
15. `it('does NOT emit warnings for already-submitted incidents')`.

### Emitter tests
16. `it('builds valid ICF v3.0 record passing the ajv schema')`.
17. `it('writes dfars-incident-report-{uuid}.json with provenance block')`.
18. `it('writes dfars-incident-report-{uuid}.docx with the cover-page fields')`.
19. `it('emits deadline_status=warning-48h between 48h and 72h')`.
20. `it('emits deadline_status=exceeded after 72h, non-zero exit code')`.
21. `it('does NOT auto-submit to DIBNet (REO Rule 4)')` — assert no
    HTTPS call is made to dibnet.dod.mil.

### UI tests
22. `it('hides DFARS routes when DFARS_ENABLED=false')`.
23. `it('surfaces both-flows banner when pii_affected && (cui_affected || cdi_affected)')`.

## REO compliance specific to this slice

- The incident record is operator-supplied via tracker UI (real human
  action) — never synthesized.
- The ICF schema is loaded from a documented published source; not
  invented.
- The 72-hour deadline is computed from real timestamps; no fudging.
- Submission is human-operated through the DIBNet portal; the emitter
  records evidence (tracking number + screenshot URL) but never
  auto-submits. REO Rule 4.
- Signatures are real Ed25519 over canonical JSON.
- Notifications go through existing `core/notify.ts` Slack/PagerDuty
  pipeline; no new credentials.
- No `process.env.NODE_ENV === 'test'` branches.
- `DFARS_ENABLED=false` is the default so non-DoD-prime tenants don't
  see DFARS noise in the UI.
- Provenance block populated.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/dfars-incident-reporting.test.ts tests/core/dfars-incident-icf.test.ts
cd ../tracker
npm run typecheck
npm test -- server/routes/dfars-incidents.test.ts server/dfars-deadline-enforcer.test.ts client/src/pages/DfarsIncidents.test.tsx
cd ../cloud-evidence
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues

- **Risk 1: DIBNet portal authentication procurement lag.** The
  DoD-approved Medium-Assurance ECA / DoD CAC must be in hand BEFORE
  an incident occurs; procurement can take weeks. Mitigation: operator
  runbook documents procurement steps explicitly; the LOOP-S.S2 ship
  checklist includes a "DIBNet credential ready" pre-flight.
- **Risk 2: 72-hour clock starts at discovery, not occurrence.** A
  late-discovered breach has a foreshortened window — discovered_at
  may be days after occurred_at. The deadline math is correct
  (discovered_at + 72h) but the operator must understand the timer.
  Documented in tracker UI.
- **Risk 3: ICF v3.0 schema evolution.** DC3 may publish ICF v3.1 with
  added fields. Mitigation: schema_version field on every record;
  emitter rejects mismatched versions; extraction script is the single
  point of truth.
- **Risk 4: Conflict with M.M4 timing.** PII breach notification
  windows vary (state laws + GDPR-equivalent + FAR 52.224-2). When
  both flows are required, the operator may prioritize one over the
  other. Mitigation: UI surfaces both deadlines side-by-side; no
  coalescing.
- **Risk 5: Subcontractor incidents.** Per DFARS 7012(m), the CSP-side
  reporting flow MUST flow down to subcontractors. If a subprocessor
  has an incident affecting CUI on the CSP, the subprocessor reports
  AND the CSP records the incident in S.S2 for tracking. Documented
  in runbook.
- **Risk 6: 90-day media preservation costs.** Storage costs for
  affected media. Mitigation: LOOP-H long-term storage classifier
  routes preserved media to cheaper tier; per-artifact
  `retention_until` field is honored.
- **Risk 7: Officer signature absent at submit time.** If the
  designated officer is unavailable, the submission deadline still
  applies. Mitigation: tracker supports an "acting" officer role
  delegation chain documented in runbook.

## Open questions (for implementation session to resolve)

- **Q1**: Should the emitter encrypt the ICF docx at rest before
  bundling? Recommend: yes when the docx contains classified
  attribution; CSP-specific decision via `--encrypt-dfars-artifacts`
  flag.
- **Q2**: Should we model `forensic_information` as a free-text field
  or a structured object (IOCs, TTPs, MITRE ATT&CK tags)? Recommend:
  free-text first ship (mirrors DC3 ICF); a future enhancement could
  add structure.
- **Q3**: How do we handle simultaneous incidents (multiple incidents
  in a single attack)? Recommend: one DFARS report per incident
  record; the tracker offers a "link related" relationship between
  records.
- **Q4**: Should the deadline enforcer page on-call directly? Recommend:
  yes via existing notify.ts; CHANGELOG explicitly documents the
  page-out behavior.
- **Q5**: Should submission status `submitted` be terminal, or do we
  model post-submit updates (e.g. damage-assessment results per
  DFARS 7012(g))? Recommend: terminal status, but a separate "damage
  assessment" artifact can be linked to the same incident UUID.

## Implementation log (running journal — implementing session updates)

```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

The implementing session MUST check every box:

- [ ] typecheck clean (`npm run typecheck`) in both cloud-evidence + tracker
- [ ] tests passing 100% (count increased by ≥23 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + LOOP-S conditional gate noted)
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
   (Dependencies) for cross-loop context.
4. Read the LOOP-G.G2 spec for the existing incident schema you extend.
5. Read the LOOP-M.M4 spec for the PII breach-notification flow you
   coordinate with.
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
7. Read `cloud-evidence/core/oscal-ssp-docx.ts` (the OOXML pattern
   S.S2's docx renderer mirrors).
8. Confirm DIBNet authentication credentials are procured BEFORE
   declaring S.S2 production-ready; pre-flight is operator-side.
9. Begin implementation; update Implementation log section as you go.

---
