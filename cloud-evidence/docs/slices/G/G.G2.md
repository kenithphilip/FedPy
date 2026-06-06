---
slice_id: G.G2
title: AFR-ICP (Incident Communications Procedures)
loop: G
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A3, LOOP-A.A4, REO-0]
blocks: [LOOP-F.F4, LOOP-I.I1]
estimated_effort: 6 days
last_updated: 2026-06-06
---

# G.G2 — AFR-ICP (Incident Communications Procedures)

## TL;DR
Ships a dependency-free `.docx` "Incident Communications Procedures" document plus a
tracker incident log with SLA enforcement (1-hour-to-FedRAMP / 1-hour-to-agencies /
1-hour-to-CISA), daily-update cadence enforcement, and a per-incident final-report
generator. Closes the six CSP-actionable ICP MUSTs (IRF, IRA, IRC, ICU, RPT, FIR).

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
ICP-CSX-IRF/IRA/IRC require a 1-hour incident-notification path to FedRAMP, every agency
customer, and (when CISA attack-vector taxonomy applies) CISA. ICU requires daily updates
until resolution; RPT requires reports to be made available in the secure FedRAMP repository
(USDA Connect.gov or vendor trust center); FIR requires a final report enumerating
specific fields. Without this slice the CSP has no published procedures document to
reference in the SSP §IR-8 control narrative, no audit trail proving the 1-hour SLA, and
no daily-update cadence enforcement. NIST 800-53 Rev5 §IR-6 (Incident Reporting), §IR-8
(Incident Response Plan), and §IR-4 (Incident Handling) are the underlying controls;
this slice ships the FedRAMP-flavored deliverable.

## Authoritative sources (with verbatim quotes)

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta, ICP-CSX-IRF / FRR-ICP-01):
  > "Providers MUST responsibly report incidents to FedRAMP within 1 hour of identification
  > by sending an email to fedramp_security@fedramp.gov or fedramp_security@gsa.gov."

- https://github.com/FedRAMP/docs (ICP-CSX-IRA / FRR-ICP-02):
  > "Providers MUST responsibly report incidents to all agency customers within 1 hour of
  > identification using the incident communications points of contact provided by each
  > agency customer."

- https://github.com/FedRAMP/docs (ICP-CSX-IRC / FRR-ICP-03):
  > "Providers MUST responsibly report incidents to CISA within 1 hour of identification
  > if the incident is confirmed or suspected to be the result of an attack vector listed
  > at https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy,
  > following the CISA Federal Incident Notification Guidelines at
  > https://www.cisa.gov/federal-incident-notification-guidelines, by using the CISA Incident
  > Reporting System at https://myservices.cisa.gov/irf."

- https://github.com/FedRAMP/docs (ICP-CSX-ICU / FRR-ICP-04):
  > "Providers MUST update all necessary parties, including at least FedRAMP, CISA (if
  > applicable), and all agency customers, at least once per calendar day until the incident
  > is resolved and recovery is complete."

- https://github.com/FedRAMP/docs (ICP-CSX-RPT / FRR-ICP-05):
  > "Providers MUST make incident report information available in their secure FedRAMP
  > repository (such as USDA Connect) or trust center."

- https://github.com/FedRAMP/docs (ICP-CSX-FIR / FRR-ICP-07):
  > "Providers MUST provide a final report once the incident is resolved and recovery is
  > complete that describes at least: [enumerated fields in FRMR sub-bullets]."

- https://www.cisa.gov/federal-incident-notification-guidelines — CISA "Federal Incident
  Notification Guidelines":
  > "Federal agencies should report incidents to CISA via the Incident Reporting System
  > (IRS) at https://myservices.cisa.gov/irf or by emailing report@cisa.gov when the
  > incident meets a major-incident threshold."
  (Used as the canonical CISA reporting endpoint reference. §"Reporting Procedures",
  retrieved 2026-06-06.)

- https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy —
  CISA "Attack Vectors Taxonomy" (referenced verbatim in ICP-CSX-IRC):
  > "Attack vectors include: External / Removable Media; Attrition; Web; Email; Improper
  > Usage; Loss or Theft of Equipment; Other; Impersonation/Spoofing."

- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — NIST SP 800-53 Rev5 §IR-6
  Incident Reporting; §IR-8 Incident Response Plan; §IR-4 Incident Handling. Pp. 167-172
  (Rev5 update-1 PDF). Specifically IR-6(a):
  > "Require personnel to report suspected incidents to the organizational incident response
  > capability within [Assignment: organization-defined time period]."

- https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/ —
  FedRAMP Rev5 Playbook (ConMon Overview):
  > "Continuous monitoring activities should include reporting of security incidents
  > consistent with the agency's incident response plan and the CSP's IRP."
  (Context for tying incident records to ConMon evidence in LOOP-E.E1.)

- https://datatracker.ietf.org/doc/html/rfc5322 — RFC 5322 "Internet Message Format" —
  used for From/To/Subject header parsing on incoming acknowledgements.

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/afr-icp.ts` — pure builder for the ICP procedures document data shape + dependency-free `.docx` emitter (mirrors `core/roe-emit.ts` OOXML + `core/zip.ts` zipStore pattern). Pure routine to emit a per-incident "report packet" JSON when called from the tracker.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/afr-icp.test.ts` — ≥14 unit tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-icp.ts` — REST endpoints: POST `/api/afr-icp/incidents`, POST `/api/afr-icp/incidents/:id/updates`, POST `/api/afr-icp/incidents/:id/final-report`, GET `/api/afr-icp/incidents` (list+filter).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-icp.test.ts` — route tests + DB constraint tests + SLA enforcement tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/IcpIncidents.tsx` — operator UI: incident create + update + final-report; cadence reminder for daily updates; one-click "generate report packet" → downloads JSON ready for upload to USDA Connect.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/AFR-ICP-RUNBOOK.md` — operator runbook (which CISA URL is canonical, how to populate agency contacts, USDA Connect upload procedure).

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--afr-icp` flag + `CLOUD_EVIDENCE_AFR_ICP` env. Generates the ICP procedures `.docx` + dumps the closed-incident packet JSON into `out/afr-icp/`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — catalogue rows for `afr-icp/incident-comms-procedures.docx` (`role='afr-icp-procedures-docx'`) + `afr-icp/incident-log.json` (`role='afr-icp-incident-log'`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/schema.sql` — additive `icp_incidents`, `icp_incident_updates`, `icp_incident_final_reports`, `icp_agency_contacts` tables with the constraints listed in Schemas section below.

## Schemas / standards

### `IcpProceduresInput` (in `core/afr-icp.ts`)

| Field | Type | Source |
|---|---|---|
| `systemName` | string | SSP `metadata.title` |
| `csoFedRampId` | string | SSP `system-id` |
| `fedRampSecurityEmail` | `'fedramp_security@fedramp.gov' \| 'fedramp_security@gsa.gov'` | CLI flag; default = `fedramp_security@fedramp.gov` (allowed fixed-data per CLAUDE.md Rule 3) |
| `cisaReportingUrl` | fixed = `https://myservices.cisa.gov/irf` | allowed fixed-data per Rule 3 |
| `cisaGuidelineUrl` | fixed = `https://www.cisa.gov/federal-incident-notification-guidelines` | allowed fixed-data |
| `cisaAttackVectorsUrl` | fixed = `https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy` | allowed fixed-data |
| `agencyContacts[]` | `{agency, pocName, pocEmail, pocPhone}` | tracker UI `icp_agency_contacts` |
| `repositoryUrl` | string | CLI `--csp-secure-repo-url` or `CLOUD_EVIDENCE_SECURE_REPO_URL` env |
| `incidentResponseTeam[]` | `{name, role, email, phone, escalation}` | tracker UI |

### DB tables

`icp_incidents`:
```
id TEXT PRIMARY KEY
system_id TEXT NOT NULL
discovered_at TEXT NOT NULL (RFC 3339)
discovered_by_user_id TEXT NOT NULL
summary TEXT NOT NULL
severity TEXT CHECK (severity IN ('low','moderate','high','critical'))
attack_vector TEXT (CISA-taxonomy enum)
confirmed_or_suspected_attack INTEGER CHECK (confirmed_or_suspected_attack IN (0,1))
reported_to_fedramp_at TEXT
reported_to_cisa_at TEXT
reported_to_agencies_at_json TEXT (JSON object: {agency_id: ISO})
status TEXT CHECK (status IN ('open','contained','resolved'))
resolved_at TEXT
```

`icp_incident_updates`:
```
id TEXT PRIMARY KEY
incident_id TEXT REFERENCES icp_incidents(id)
update_at TEXT NOT NULL
update_text TEXT NOT NULL
posted_to_fedramp INTEGER
posted_to_cisa INTEGER
posted_to_agencies INTEGER
update_by_user_id TEXT NOT NULL
```

`icp_incident_final_reports`:
```
incident_id TEXT PRIMARY KEY REFERENCES icp_incidents(id)
narrative TEXT NOT NULL
root_cause TEXT NOT NULL
mitigations_taken TEXT NOT NULL
lessons_learned TEXT NOT NULL
compensating_controls_added_json TEXT
submitted_at TEXT NOT NULL
submitted_by_user_id TEXT NOT NULL
submission_url TEXT
```

### `.docx` structure (mirrors `core/roe-emit.ts`)

- §1 System Identity (auto from SSP).
- §2 Reporting Channels (fixed: FedRAMP email, CISA URL, agency PoCs from tracker).
- §3 1-hour SLA Procedures (verbatim ICP-CSX-IRF/IRA/IRC text + step-by-step).
- §4 Daily Update Cadence (verbatim ICP-CSX-ICU + cron job description).
- §5 Final Report Template (verbatim ICP-CSX-FIR + required-fields list).
- §6 Secure Repository Reference (per ICP-CSX-RPT, with `repositoryUrl`).
- §7 Incident Response Team Roster (operator-supplied).
- §8 Document Provenance (tool name + run id + commit hash + RFC 3339 emittedAt + provenance.requirementTexts).

OOXML zip: store-only (no DEFLATE), parts: `[Content_Types].xml`, `_rels/.rels`, `word/document.xml`, `word/styles.xml`, `word/_rels/document.xml.rels`, `docProps/core.xml`. Same parts as `roe-emit.ts`.

## Build steps (concrete, numbered)

1. Define interfaces in `core/afr-icp.ts`: `IcpProceduresInput`, `IcpIncidentRow`, `IcpUpdateRow`, `IcpFinalReportRow`, `IcpEmitOptions`, `IcpEmitResult`.
2. Pure builder `buildIcpProceduresDocx(input): { docxBytes: Uint8Array; requires_operator_input: string[]; ready_for_signature: boolean }` — assembles document.xml from the 8 sections; uses verbatim FRMR statements for each MUST in §3-§5.
3. Pure builder `buildIncidentReportPacket(incident, updates, final): IncidentReportPacket` — produces a JSON suitable for upload to USDA Connect (per ICP-CSX-RPT format).
4. Disk emitter `emitAfrIcp(outDir, ctx)`:
   - Read SSP metadata for §1.
   - Query `icp_incidents` + child rows for the report period (default last 12 months).
   - Build `.docx` + serialize incident-log packets.
   - Write `out/afr-icp/incident-comms-procedures.docx` + `out/afr-icp/incident-log.json`.
5. Wire orchestrator `--afr-icp` flag. Runs BEFORE signing.
6. Tracker routes:
   - POST create: validates required fields; on save, computes `reported_to_fedramp_at - discovered_at` and writes a tracker audit-log event `late_report=true` when `> 1h`.
   - POST update: cadence enforcer cron runs once per day per open incident; raises a `missed_daily_update` event if last update > 24h (ICP-CSX-ICU).
   - POST final-report: closes the incident; requires `narrative`, `root_cause`, `mitigations_taken`, `lessons_learned`; emits the FedRAMP-required "at least" fields per ICP-CSX-FIR.
7. UI: incident-create form, incident-list table, daily-update modal, final-report editor; "Download report packet" button.
8. Submission bundle catalogue: 2 new rows.
9. Validation pass: re-open emitted `.docx` with the bundled `core/zip.ts` reader; assert parts present and document.xml well-formed.
10. Sign+timestamp via `core/sign.ts`.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | What happens when missing |
|---|---|---|
| `agencyContacts[]` | tracker UI table per agency customer | `.docx` §2 emits a REQUIRES-OPERATOR-INPUT row; `ready_for_signature=false` |
| `repositoryUrl` | CLI `--csp-secure-repo-url` or env | `.docx` §6 emits REQUIRES-OPERATOR-INPUT; report-packet `submission_url` is null |
| `incidentResponseTeam[]` | tracker UI | `.docx` §7 emits REQUIRES-OPERATOR-INPUT |
| `fedRampSecurityEmail` | CLI flag | defaults to `fedramp_security@fedramp.gov` (allowed-fixed); validator rejects values outside the two FedRAMP-published addresses |
| `attack_vector` per incident | operator picks from CISA taxonomy enum in UI | incident row cannot pass `confirmed_or_suspected_attack=1` validation without a vector |

## Test specifications (≥14 tests)

1. `it('renders procedures docx with all 6 ICP MUST texts verbatim')` — parse body XML; assert each FRMR statement is present.
2. `it('emits REQUIRES-OPERATOR-INPUT for agencyContacts when empty')`.
3. `it('emits REQUIRES-OPERATOR-INPUT for incidentResponseTeam when empty')`.
4. `it('hard-codes CISA URLs from spec exactly')` — assert the three CISA URLs appear unaltered in §3.
5. `it('rejects fedRampSecurityEmail values outside the two allowed FedRAMP addresses')`.
6. `it('flags late_report when reported_to_fedramp_at - discovered_at > 1h')` — incident with reported_at 65min after discovered_at → tracker audit event recorded.
7. `it('treats reported_to_cisa_at=null as OK when confirmed_or_suspected_attack=0')`.
8. `it('requires reported_to_cisa_at when confirmed_or_suspected_attack=1')` — DB constraint or pre-write check rejects.
9. `it('emits missed_daily_update when no update in 24h on open incident')` — fake clock advanced; cadence enforcer raises event.
10. `it('final report rejects empty root_cause')` — POST returns 400.
11. `it('incident-log.json serializes deterministically for byte-identical output across runs')` — sort by `id`, RFC 3339 ts.
12. `it('writes docx with correct OOXML zip structure (store-only)')` — open with bundled zip parser; assert 6 parts present + document.xml parses as XML.
13. `it('records discovered_by_user_id + each update_by_user_id from real tracker auth context')` — never null.
14. `it('omits incidents outside the report period')` — only last-12-months closed incidents appear in the bundled packet.
15. `it('records provenance.requirementTexts for all 6 ICP MUSTs')` — verbatim from FRMR.
16. `it('detects attack_vector values not in CISA taxonomy enum')` — rejects unknown vectors.

## REO compliance specific to this slice

- Every emitted incident row traces to a real tracker DB record (human-entered + auth-stamped).
- All CISA / FedRAMP URLs + email addresses come from FedRAMP spec (allowed fixed-data per CLAUDE.md Rule 3).
- No auto-fabricated incidents.
- The 1-hour-to-FedRAMP SLA is computed from real `discovered_at` + `reported_to_fedramp_at` timestamps; the system never back-dates.
- Provenance fields populated: `emitter`, `emittedAt`, `sourceCalls`, `requirementTexts` (6 MUSTs), `runId`.
- Signed by: `core/sign.ts` (Ed25519 + RFC 3161).

## Verification commands

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/afr-icp.test.ts
npm test -- tracker/server/routes/afr-icp.test.ts
npm run check:reo
```

## Known risks / issues

- **Risk 1 — CISA IRS has no API.** `myservices.cisa.gov/irf` is currently a web form. The tracker generates the report packet but operator manually submits. Mitigation: runbook documents the manual submission flow; when CISA publishes an API, a submitter module can be added without breaking the tracker data shape.
- **Risk 2 — Agency PoC list grows unbounded.** Some CSOs have dozens of agency customers. Mitigation: paginate the `.docx` §2 table; cap visible rows at 100, link to tracker UI for full list.
- **Risk 3 — Cron cadence enforcer false positives.** Daily-update cadence (ICU) cron may fire across DST boundaries or for incidents marked `contained` (not yet `resolved`). Mitigation: cadence enforcer uses calendar-day boundaries in UTC and skips `contained` status if container note specifies "no further updates required".
- **Risk 4 — Final-report leaks PII.** Operator-entered narrative may include user data. Mitigation: the `.docx` is internal-only at emit time; LOOP-J subprocessor expansion adds a redaction reviewer; tracker UI warns "verify no PII" before submit.
- **Risk 5 — Late SLA detection after the fact.** If `reported_to_fedramp_at` is entered later than `discovered_at + 1h`, the late_report flag fires retroactively. Mitigation: the flag is informational, not blocking; the `incident-log.json` includes SLA-met counts as a metric for ConMon.
- **Risk 6 — DOCX parsers reject store-only zip.** Some Word versions complain about uncompressed OOXML. Mitigation: same pattern is already used by `core/roe-emit.ts` and `core/ssp-docx.ts` and is accepted by Word 2019+ and LibreOffice 7+.

## Open questions (for implementation session to resolve)

- **Q1**: Should `summary` be required on incident-create or allow `'TBD'` for first 10 minutes during triage? Recommendation: require non-empty; operator can update later (REO: no placeholder).
- **Q2**: For `attack_vector`, do we hardcode the CISA enum in TypeScript or fetch from CISA periodically? Recommendation: hardcode (it's allowed fixed-data per Rule 3) + add an annual review note to the runbook.
- **Q3**: Daily-update cadence cron schedule — when does "day N" start: midnight UTC or 24h after the last update? Recommendation: 24h-after-last-update (matches ICU's "at least once per calendar day" reading).
- **Q4**: Final-report `compensating_controls_added_json` — is this LOOP-B.B4 dependency or operator-typed? Recommendation: operator-typed for G.G2; LOOP-B.B4 may later auto-populate from CCR registry.
- **Q5**: `repositoryUrl` validation — restrict to USDA Connect / specific trust centers, or any HTTPS URL? Recommendation: any HTTPS URL; runbook lists FedRAMP-acceptable trust centers.
- **Q6**: For `severity`, do we tie it to NIST 800-30 risk-rating bands? Recommendation: low/moderate/high/critical strings; map to 800-30 in LOOP-B.B5.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

- [ ] typecheck clean
- [ ] tests passing (count +~20 for slice tests + route tests)
- [ ] check:reo green
- [ ] STATUS.md updated (slice row + Overall section: next-priority = G.G3)
- [ ] LOOP-G-SPEC.md §7 status table updated
- [ ] This file's frontmatter updated
- [ ] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-G.G2: AFR-ICP (Incident Communications Procedures)`
- [ ] Commit with `LOOP-G.G2:` in message
- [ ] Commit amended with hash
- [ ] Pushed to origin/main
- [ ] AFR-ICP-RUNBOOK.md authored
- [ ] End-to-end orchestrator smoke: `npm run collect -- --impact-level moderate --afr-icp` produces `out/afr-icp/incident-comms-procedures.docx` + `out/afr-icp/incident-log.json` + signed manifest entries.

## Resume-from-fresh-session checklist

1. Read `cloud-evidence/CLAUDE.md`.
2. This file is the entry point.
3. Read `cloud-evidence/docs/loops/LOOP-G-SPEC.md` §2 + §4 (G.G2).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Read `cloud-evidence/core/roe-emit.ts` for the dep-free `.docx` + zipStore pattern to mirror.
6. Read `cloud-evidence/core/ssp-docx.ts` for the OOXML body-construction pattern.
7. Read `cloud-evidence/core/zip.ts` for `zipStore`.
8. Read `cloud-evidence/tracker/server/routes/` for an existing route to model `afr-icp.ts` on.
9. Read `cloud-evidence/tracker/server/schema.sql` for migration style.
10. Begin implementation; update Implementation log as you go.
