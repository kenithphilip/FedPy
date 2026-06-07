---
slice_id: G.G2.CIRCIA
parent: G.G2
title: CIRCIA reporting workflow extension to AFR-ICP
loop: G
status: pending
commit: —
completed_date: —
depends_on: [G.G2, LOOP-A.A1, LOOP-A.A4, REO-0]
blocks: [LOOP-S.S3]
estimated_effort: 5-7 working days
last_updated: 2026-06-07
---

# G.G2.CIRCIA — CIRCIA reporting workflow extension to AFR-ICP

## TL;DR
Extends the AFR-ICP (LOOP-G.G2) framework with the Cyber Incident Reporting for
Critical Infrastructure Act (CIRCIA) 72-hour covered-cyber-incident clock and
24-hour ransom-payment clock. Adds `core/circia-report.ts`, the
`circia_covered_entity_assessment` / `circia_incidents` /
`circia_ransom_payments` / `circia_submission_receipts` /
`circia_supplemental_reports` tracker tables, a timer-enforcement daemon, a
deterministic JSON packet emitter, a deterministic PDF preview emitter, and
operator UI flows for the 4-prong covered-cyber-incident classification +
manual CISA submission workflow + acknowledgement-token capture.

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this extension exists

The AFR-ICP slice (LOOP-G.G2) enforces 1-hour notification SLAs to FedRAMP, to
agencies, and to CISA (when the CISA attack-vector taxonomy applies). It does
NOT cover the CIRCIA 72-hour covered-cyber-incident reporting clock or the
CIRCIA 24-hour ransom-payment reporting clock — those are separate statutory
obligations under 6 U.S.C. §681b that go to a distinct CISA intake channel
with a distinct schema and a 2-year records-retention requirement.

The CIRCIA Final Rule was published in May 2026 (per CISA timeline) and the
72-hour clock will become enforceable approximately 18 months after
publication (operator confirms exact effective date). Once effective, any
FedRAMP CSP that qualifies as a "covered entity" under PPD-21 (which is
substantially all federal-customer-facing CSPs) carries this reporting duty
in addition to the existing AFR-ICP duties. Failing to submit within 72h is
informational-but-still-reportable (the late-report flag is itself a CISA
input field), but repeated late-reporting carries §681d subpoena risk and
trust-relationship erosion with both CISA and agency customers.

This extension makes the CIRCIA workflow first-class in the tracker, with
operator-driven covered-entity determination, prong classification,
submission, acknowledgement-token capture, supplemental-report cadence
enforcement, and 2-year records-retention sweep.

Read `docs/CIRCIA-WORKFLOW.md` (the cross-cutting reference) BEFORE reading
this slice doc.

## Connection to FedPy mission

- **Extends LOOP-G.G2 AFR-ICP** — adds CIRCIA classifier + timers + packet
  emitter on top of the existing AFR-ICP framework.
- **Reads tracker DB** — covered-entity assessment, incident metadata, IOCs,
  TTPs all live in the tracker; auth-stamped + signed.
- **Reads AFR-ICP rows** — `circia_incidents.afr_icp_incident_id` joins
  back to `icp_incidents`; single source of truth for discovery metadata.
- **Reads M.M4 privacy rows** — when PII is involved,
  `circia_incidents.privacy_incident_id` joins to `privacy_incidents`;
  this slice + M.M4-CIRCIA-EXTENSION cross-reference symmetrically.
- **Submission bundler** — adds `circia-incidents-log-json` role to the
  submission bundle catalogue (LOOP-A.A4) so the CIRCIA log is part of the
  ATO package.
- **POA&M integration** — when a CIRCIA-eligible incident is unreported past
  the 72h deadline AND the operator has not signed an explicit waiver,
  emits a POA&M finding via `core/oscal-poam.ts` with severity=high and
  deadline=now+24h.
- **OSCAL chain** — the CIRCIA report is referenced in the AR
  `assessment-results.findings` block for the relevant assessment cycle.
- **REO** — every report packet field traces back to tracker DB or AFR-ICP
  data; the system never auto-decides covered-entity status or prong
  selection; the system never auto-submits to CISA; the acknowledgement
  token is operator-pasted from the CISA response.

## Authoritative sources (verbatim quotes)

### 6 U.S.C. §681b(a)(1)(A) — 72-hour covered cyber incident reporting

> "A covered entity that experiences a covered cyber incident shall report
> the covered cyber incident to the Director not later than 72 hours after
> the covered entity reasonably believes that the covered cyber incident
> has occurred."

Source: https://www.govinfo.gov/content/pkg/COMPS-15425/pdf/COMPS-15425.pdf

### 6 U.S.C. §681b(a)(2)(A) — 24-hour ransom payment reporting

> "A covered entity that makes a ransom payment as the result of a
> ransomware attack against the covered entity shall report the payment to
> the Director not later than 24 hours after the ransom payment has been
> made."

### 6 U.S.C. §681b(a)(3) — supplemental reports

> "A covered entity shall promptly submit to the Director an update or
> supplement to a previously submitted covered cyber incident report if
> substantial new or different information becomes available or if the
> covered entity makes a ransom payment after submitting a covered cyber
> incident report."

### 6 U.S.C. §681b(a)(5) — records preservation

> "A covered entity that is required to submit a covered cyber incident
> report or a ransom payment report shall preserve data relevant to the
> covered cyber incident or ransom payment in accordance with procedures
> established in the final rule issued pursuant to section 681c(b) of this
> title."

### CIRCIA NPRM (89 FR 23644, 2024-04-04) — substantial cyber incident definition

Verbatim from the proposed rule preamble (§ III.D.2.b.i):

> "...substantial cyber incident means a cyber incident that leads to: (1)
> substantial loss of confidentiality, integrity, or availability of a
> covered entity's information system or network; (2) serious impact on the
> safety and resiliency of a covered entity's operational systems and
> processes; (3) disruption of a covered entity's ability to engage in
> business or industrial operations, or deliver goods or services; or (4)
> unauthorized access to a covered entity's information system or network,
> or any nonpublic information contained therein, that is facilitated
> through or caused by either a compromise of a cloud service provider,
> managed service provider, other third-party data hosting provider, or a
> supply chain compromise."

Source: https://www.federalregister.gov/documents/2024/04/04/2024-06526/cyber-incident-reporting-for-critical-infrastructure-act-circia-reporting-requirements

### Presidential Policy Directive 21 (Feb 12, 2013) — 16 critical infrastructure sectors

> "There are 16 critical infrastructure sectors whose assets, systems, and
> networks, whether physical or virtual, are considered so vital to the
> United States that their incapacitation or destruction would have a
> debilitating effect on security, national economic security, national
> public health or safety, or any combination thereof."

Sectors list: Chemical; Commercial Facilities; Communications; Critical
Manufacturing; Dams; Defense Industrial Base; Emergency Services; Energy;
Financial Services; Food and Agriculture; Government Facilities; Healthcare
and Public Health; Information Technology; Nuclear Reactors, Materials, and
Waste; Transportation Systems; Water and Wastewater Systems.

Source: https://www.cisa.gov/topics/critical-infrastructure-security-and-resilience/critical-infrastructure-sectors

### CISA CIRCIA topic page

> "CIRCIA requires CISA to develop and implement regulations requiring
> covered entities to report covered cyber incidents and ransom payments to
> CISA. The final rule that will implement these reporting requirements
> [...] sets a regulatory floor for reporting in a transparent, balanced,
> and well-thought-out manner [...]."

Source: https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/cyber-incident-reporting-critical-infrastructure-act-2022-circia

### CIRCIA Town Hall Meetings (2026-02-13 Federal Register Notice)

> "[CISA is convening] town hall meetings to receive input from members of
> the public regarding the Cyber Incident Reporting for Critical
> Infrastructure Act (CIRCIA) rulemaking."

Source: https://www.federalregister.gov/documents/2026/02/13/2026-02948/cyber-incident-reporting-for-critical-infrastructure-act-circia-rulemaking-town-hall-meetings

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/circia-report.ts`
  (~850 lines) — pure JSON-packet builder + signing-ready
  `buildCirciaReport(input): { reportJson, requires_operator_input, ready_for_signature }`,
  plus helpers `assessCoveredEntity(profile)`, `classifySubstantialProngs(incident)`,
  `computeReportingClock(reasonable_belief_at): { initial_due_at, status }`,
  `computeRansomClock(paid_at): { ransom_due_at, status }`,
  `computeSupplementalClock(change_at): { supplemental_due_at, status }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/circia-report-pdf.ts`
  (~400 lines) — deterministic PDF emitter for the human-reviewable preview
  (uses the same dependency-free zip+PDF pattern as `core/roe-emit.ts`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/circia-timers.ts`
  (~300 lines) — pure clock-arithmetic helpers + the timer-enforcement
  daemon entry point. No SDK calls; reads tracker via the same DB pool used
  by other process-artifact KSIs.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/circia-report.test.ts`
  — ≥16 unit tests (enumerated below).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/circia-report-pdf.test.ts`
  — ≥4 deterministic PDF emission tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/circia-timers.test.ts`
  — ≥10 clock-arithmetic tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/circia.ts`
  — REST endpoints: POST `/api/circia/covered-entity` (record assessment),
  POST `/api/circia/incidents`, POST `/api/circia/incidents/:id/prongs`,
  POST `/api/circia/incidents/:id/submission-receipt`,
  POST `/api/circia/incidents/:id/supplemental`,
  POST `/api/circia/ransom-payments`,
  POST `/api/circia/ransom-payments/:id/submission-receipt`,
  GET `/api/circia/incidents`, GET `/api/circia/incidents/:id/packet`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/circia.test.ts`
  — route tests + DB constraint tests + permission tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/CirciaIncidents.tsx`
  — operator UI: covered-entity wizard, 4-prong checklist, packet preview,
  one-click submission helper, acknowledgement-token capture.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/CIRCIA-RUNBOOK.md`
  — operator runbook (which CISA URL is canonical, how to obtain a CISA
  submission token, how to handle late reports, how to handle OFAC
  consultations before ransom payments, how the 2-year retention sweep
  works).

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/afr-icp.ts` — add
  hook `classifyCircia(incident): CirciaClassification | null` (operator-
  driven); add `circia_report_id` cross-reference field to AFR-ICP packet.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  new `--circia` flag + `CLOUD_EVIDENCE_CIRCIA` env. Generates the
  `out/circia/incidents-log.json` packet from tracker rows; emits PDF
  previews for incidents in `status: open` or `reported`; emits POA&M
  findings for incidents with breached timers.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — catalogue row for `circia/incidents-log.json` (`role='circia-incidents-log'`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` —
  when a CIRCIA-eligible incident's 72h or 24h deadline passes WITHOUT a
  recorded submission AND no explicit waiver, emit a POA&M finding.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` —
  register `KSI-INR-CIRCIA` process-artifact KSI.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/schema.sql`
  — additive: `circia_covered_entity_assessment`, `circia_incidents`,
  `circia_ransom_payments`, `circia_submission_receipts`,
  `circia_supplemental_reports` tables with constraints in §Schemas.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/index.ts`
  — mount `/api/circia` route.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/App.tsx`
  — add `/circia/incidents` route + nav entry.

## Schemas / standards

### `CirciaCoveredEntityAssessment`
- `ppd21_sector` ∈ 16-sector enum (from §3.2 of CIRCIA-WORKFLOW.md).
- `primary_naics_code` (string; from SBA NAICS table).
- `sba_size_standard_usd` (integer; from SBA published table for this NAICS).
- `annual_revenue_usd` (integer; operator).
- `sba_size_exceeded` (boolean; computed).
- `sector_specific_criterion_triggered` (boolean; operator).
- `covered_entity_determination` (boolean; operator final).
- `rationale` (string; operator).
- Signed Ed25519 by `core/sign.ts`.

### `CirciaIncident`
- `circia_report_id` (uuid).
- `afr_icp_incident_id` (FK, optional).
- `privacy_incident_id` (FK, optional).
- `discovered_at` / `reasonable_belief_at` (RFC 3339).
- `is_covered_cyber_incident` (boolean).
- `prongs_triggered` (subset of [1, 2, 3, 4]).
- `prong_rationale` (string).
- `status` ∈ {'open', 'reported', 'supplemental_pending', 'concluded'}.
- `initial_report_due_at` = `reasonable_belief_at + 72h`.
- `initial_report_submitted_at` (RFC 3339, nullable).
- `cisa_acknowledgement_token` (string, nullable).
- Operator-entered: narrative, IOCs, TTPs (MITRE ATT&CK), mitigation steps,
  attribution, other federal reports.
- Signed.

### `CirciaRansomPayment`
- `id` (uuid).
- `circia_report_id` (FK, optional — payments can exist without a covered
  cyber incident, per statute).
- `paid_at` (RFC 3339).
- `payment_amount_usd`, `payment_medium`, `payment_crypto_address`,
  `payer_party`, `initial_demand_amount`, `decryption_outcome`,
  `data_returned`.
- `ransom_report_due_at` = `paid_at + 24h`.
- Signed.

### `CirciaSubmissionReceipt`
- `id` (uuid).
- `circia_report_id` (FK).
- `submitted_at`, `submitted_by_user_id`, `submission_channel`,
  `cisa_acknowledgement_token`, `cisa_receipt_at`,
  `cisa_assigned_incident_id`.
- Signed.

### `CirciaSupplementalReport`
- `id` (uuid).
- `circia_report_id` (FK).
- `triggering_change` (which field changed).
- `supplemental_due_at` = `change_at + 24h`.
- `supplemental_submitted_at`, `cisa_acknowledgement_token`.
- Signed.

### JSON packet schema

Per §5.3 of `docs/CIRCIA-WORKFLOW.md`. Full schema enforced by
`core/circia-report.ts::validatePacket()` via the same JSON Schema pattern
used by `core/envelope.ts`.

## Build steps (numbered, concrete)

1. **Define types** in `core/circia-report.ts`:
   `CirciaCoveredEntityAssessment`, `CirciaIncident`, `CirciaRansomPayment`,
   `CirciaSubmissionReceipt`, `CirciaSupplementalReport`,
   `CirciaReportPacket`, `CirciaClassification`, `CirciaEmitOptions`,
   `CirciaEmitResult`.
2. **Implement** `assessCoveredEntity(profile)` — pure function. Input:
   `{ ppd21_sector, primary_naics_code, annual_revenue_usd, sector_specific_criterion_triggered }`.
   Output: `{ sba_size_standard_usd, sba_size_exceeded, covered_entity_determination, rationale }`.
   SBA size standards table is allowed-fixed-data (Rule 3, published SBA table).
3. **Implement** `classifySubstantialProngs(incident, prong_selections)` —
   pure function. Validates that at least one prong is checked when
   `is_covered_cyber_incident=true`, computes prong rationale aggregation.
4. **Implement** clock helpers in `core/circia-timers.ts`:
   `compute72hClock(reasonable_belief_at): { due_at, hours_remaining }`,
   `compute24hRansomClock(paid_at): { due_at, hours_remaining }`,
   `compute24hSupplementalClock(change_at): { due_at, hours_remaining }`,
   `compute2yRetentionClock(final_report_at): { until_at }`.
5. **Implement** `buildCirciaReport(input): { reportJson, requires_operator_input, ready_for_signature }`
   — pure builder. Reads `CirciaIncident` + linked `IcpIncident` (LOOP-G.G2)
   + linked `PrivacyIncident` (LOOP-M.M4) + linked `CirciaRansomPayment`.
   Produces the §5.3 JSON envelope. Emits `requires_operator_input` for any
   missing required field. Sets `ready_for_signature=false` if any
   REQUIRES-OPERATOR-INPUT is present.
6. **Implement** `buildCirciaReportPdf(reportJson): Uint8Array` in
   `core/circia-report-pdf.ts` — deterministic dep-free PDF emission for
   the human-reviewable preview. Same store-only zip approach as
   `core/roe-emit.ts`. Cover page + per-section content.
7. **Implement** disk emitter `emitCircia(outDir, ctx)`:
   - Query `circia_incidents` for the report period (default: last 12
     months + any open).
   - For each incident: build report JSON + PDF preview + write to
     `out/circia/<circia_report_id>.json` + `out/circia/<circia_report_id>.pdf`.
   - Write aggregated `out/circia/incidents-log.json` (sorted by
     `circia_report_id` for deterministic byte output).
8. **Wire orchestrator** `--circia` flag. Runs AFTER `--afr-icp` (consumes
   icp_incidents data) AND AFTER `--privacy-irp` (consumes privacy_incidents
   data) AND BEFORE `--oscal-poam` (so POA&M picks up CIRCIA breaches).
9. **Implement tracker routes** in `tracker/server/routes/circia.ts`:
   - POST `/covered-entity`: validates fields, signs, writes
     `circia_covered_entity_assessment`. Permission: `compliance.admin`.
   - POST `/incidents`: requires covered-entity row exists; validates 4-prong
     checklist; writes signed `circia_incidents`. Permission: `ir.lead`.
   - POST `/incidents/:id/prongs`: updates prong rationale. Audit-logged.
   - POST `/incidents/:id/submission-receipt`: operator pastes
     acknowledgement token. Writes `circia_submission_receipts`. Updates
     `circia_incidents.initial_report_submitted_at`.
   - POST `/incidents/:id/supplemental`: triggers supplemental clock.
   - POST `/ransom-payments`: writes signed `circia_ransom_payments`. May
     reference an existing `circia_report_id` or stand alone.
   - POST `/ransom-payments/:id/submission-receipt`: operator pastes token.
   - GET `/incidents`: list + filter by status / date.
   - GET `/incidents/:id/packet`: returns the JSON packet (for download).
10. **Implement timer daemon** entry point in `core/circia-timers.ts`:
    - On invoke: query open + reported incidents; compute hours_remaining;
      emit audit events `circia_72h_warning` (<24h), `circia_72h_breach` (<0),
      `circia_24h_warning_ransom` (<8h), `circia_24h_breach_ransom` (<0),
      `circia_24h_warning_supplemental` (<6h), `circia_24h_breach_supplemental` (<0).
    - Idempotent: same event not raised twice within 1h window.
    - Notification fan-out: tracker writes to `core/notify.ts` (Slack +
      PagerDuty) per existing patterns.
11. **Implement UI** in `tracker/client/src/pages/CirciaIncidents.tsx`:
    - Covered-entity wizard (sector picker, NAICS code input, SBA size
      auto-lookup, operator confirmation).
    - Incident list with timer countdown column.
    - 4-prong classification modal.
    - Packet preview pane (renders the JSON + PDF preview).
    - Submission helper (opens CISA web form in new tab with packet data
      copied to clipboard).
    - Acknowledgement-token capture form.
    - Supplemental-report editor.
    - Ransom-payment form (with OFAC consultation gate).
12. **Submission bundle catalogue**: new row
    `{ role: 'circia-incidents-log', path: 'circia/incidents-log.json' }`.
13. **POA&M integration** in `core/oscal-poam.ts`:
    - When `circia_incidents.initial_report_due_at < now()` AND
      `initial_report_submitted_at IS NULL` AND `status != 'concluded'`:
      emit POA&M finding `{ severity: 'high', deadline: now + 24h,
      description: 'CIRCIA covered-cyber-incident report past 72h
      deadline; submission required.' }`.
14. **KSI registration**: `KSI-INR-CIRCIA` process-artifact KSI.
    Evidence sources: `circia_covered_entity_assessment` (latest signed
    row) + `circia_incidents` (any non-concluded) + `circia_submission_receipts`.
15. **Validation pass**: re-open emitted JSON via the same schema; verify
    PDF parses as PDF; verify all signatures.
16. **Sign+timestamp** via `core/sign.ts` (Ed25519 + RFC 3161).

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | What happens when missing |
|---|---|---|
| `covered_entity_determination` | `circia_covered_entity_assessment` tracker row (signed) | Tracker UI gates incident creation behind a "complete covered-entity assessment" prompt; orchestrator emits REQUIRES-OPERATOR-INPUT diagnostic if assessment row missing |
| `circia_effective_date` | `org-profile.yaml::incident_response.circia_effective_date` | Tracker runs in dry-run mode (records incidents but does not start 72h clock); orchestrator emits REQUIRES-OPERATOR-INPUT |
| `prongs_triggered[]` | tracker UI 4-prong checklist | `circia_incidents` row cannot pass `is_covered_cyber_incident=true` validation without at least one prong; REQUIRES-OPERATOR-INPUT in packet |
| `prong_rationale` | tracker UI | REQUIRES-OPERATOR-INPUT |
| `cisa_acknowledgement_token` | operator pastes from CISA response | Submission receipt row written without token; timer remains "unconfirmed"; tracker raises `circia_receipt_missing` diagnostic at +24h |
| `cisa_submission_url` | `org-profile.yaml::incident_response.circia.submission_url` | Default = `https://www.cisa.gov/forms/report` (general intake; CISA-published URL is allowed-fixed-data per Rule 3); runbook documents updates |
| `affected_systems[]` | tracker UI | REQUIRES-OPERATOR-INPUT per system |
| `vulnerabilities[].cve_id` | tracker UI | REQUIRES-OPERATOR-INPUT (null allowed for unknown) |
| `ttps[].mitre_tactic` | tracker UI | REQUIRES-OPERATOR-INPUT (validates against MITRE ATT&CK enum) |
| `iocs.file_hashes[]` | tracker UI | REQUIRES-OPERATOR-INPUT (null allowed if no malware) |
| `attribution.attacker_class` | tracker UI | REQUIRES-OPERATOR-INPUT (default `'unknown'`) |
| `other_federal_reports[]` | tracker UI | REQUIRES-OPERATOR-INPUT (operator confirms list) |
| `payer_party` | tracker UI | required when ransom payment row exists |
| `payment_amount_usd` | tracker UI | required; numeric > 0 |
| OFAC consultation confirmation | tracker UI checkbox | gates ransom payment recording |

## Test specifications (≥12 tests)

### `tests/core/circia-report.test.ts`

1. `it('computes covered_entity_determination=true when ppd21_sector=information_technology and annual_revenue > SBA NAICS 518210 threshold')`
2. `it('computes covered_entity_determination=false when ppd21_sector=information_technology and annual_revenue < SBA NAICS 518210 threshold AND no sector-specific criterion triggered')`
3. `it('computes covered_entity_determination=true when sector_specific_criterion_triggered=true regardless of SBA size')`
4. `it('rejects circia_incidents row creation when is_covered_cyber_incident=true and prongs_triggered=[] (empty)')`
5. `it('builds CIRCIA packet with all 10 required field categories present')` — covered entity, incident description, affected systems, vulnerabilities, TTPs, IOCs, impact, mitigation, attribution, other federal reports.
6. `it('packet ready_for_signature=false when any REQUIRES-OPERATOR-INPUT present')`
7. `it('packet JSON deterministic across runs')` — same input → same bytes (canonical-JSON sorted).
8. `it('builds packet for ransom-only report (no covered cyber incident parent)')` — proves §681b(a)(2)(A) standalone path.
9. `it('builds supplemental packet linking to original circia_report_id')`
10. `it('emits POA&M finding when initial_report_due_at < now AND status != concluded AND no submission')` — high severity, deadline=now+24h.
11. `it('records provenance.requirementTexts citing 6 USC 681b(a)(1)(A) and (a)(2)(A) verbatim')`
12. `it('rejects payment_amount_usd <= 0')`

### `tests/core/circia-timers.test.ts`

13. `it('compute72hClock: reasonable_belief_at + 72h = due_at; hours_remaining counts down by hour')`
14. `it('compute24hRansomClock: paid_at + 24h = due_at')`
15. `it('compute24hSupplementalClock: change_at + 24h = due_at')`
16. `it('compute2yRetentionClock: final_report_at + 2 years = until_at')` — leap year aware.
17. `it('timer daemon raises circia_72h_warning when hours_remaining < 24')`
18. `it('timer daemon raises circia_72h_breach when hours_remaining < 0')`
19. `it('timer daemon idempotent: same warning not raised twice within 1h')`
20. `it('timer daemon skips concluded incidents')`

### `tests/core/circia-report-pdf.test.ts`

21. `it('emits PDF with all 10 sections labeled per Final Rule field categories')`
22. `it('PDF byte-identical across runs (deterministic)')`
23. `it('PDF embeds the covered-entity determination rationale verbatim')`
24. `it('PDF includes timer status badge (on-track / warning / breach)')`

### `tracker/server/routes/circia.test.ts`

25. `it('POST /covered-entity rejects when ppd21_sector is not in 16-sector enum')`
26. `it('POST /incidents rejects when no signed covered-entity assessment exists')`
27. `it('POST /incidents/:id/submission-receipt validates acknowledgement_token format (CISA token regex)')`
28. `it('POST /ransom-payments requires OFAC consultation checkbox')`
29. `it('GET /incidents lists incidents filtered by status with timer countdown column')`
30. `it('permission ir.lead can create incident; auditor cannot')`

## REO compliance specific to this slice

- **Operator-supplied data is real data:** Covered-entity determination,
  prong selection, CISA acknowledgement tokens, ransom-payment fields,
  OFAC consultation confirmation. All signed Ed25519.
- **Tracker-DB-sourced data:** Every CIRCIA report field traces to an
  auth-stamped tracker row OR to a linked AFR-ICP / privacy-incident row.
- **No auto-decisions:** The system never auto-determines covered-entity
  status, never auto-checks a prong box, never auto-submits to CISA.
- **No auto-deletion:** Retention sweep raises eligibility events but never
  deletes incident data. Deletion is operator action with sign-off.
- **Allowed fixed data (Rule 3):** PPD-21 16-sector list (published);
  SBA NAICS size standards table (published); CISA web-form URL (CISA-
  published); 6 USC §681b citation strings; MITRE ATT&CK tactic IDs
  (published); 72h / 24h statutory clocks themselves.
- **No silent fallback:** If `org-profile.yaml::circia_effective_date` is
  missing, the tracker runs in dry-run mode and surfaces
  REQUIRES-OPERATOR-INPUT; never silently fires a real 72h timer.
- **Provenance:** Every emitted CIRCIA artifact carries `provenance`:
  `emitter='core/circia-report.ts'`, `emittedAt`, `sourceCalls`,
  `signingKeyId`, `runId`, `requirementTexts` (verbatim §681b quotes).
- **Signing:** Ed25519 + RFC 3161 via `core/sign.ts`.
- **Determinism:** JSON packet + PDF preview byte-identical across runs.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/circia-report.test.ts
npm test -- tests/core/circia-timers.test.ts
npm test -- tests/core/circia-report-pdf.test.ts
cd tracker
npm test -- server/routes/circia.test.ts
cd ..
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

End-to-end smoke:

```bash
npm run collect -- --impact-level moderate --afr-icp --privacy-irp --circia
ls out/circia/
# expect: incidents-log.json + <circia_report_id>.json + <circia_report_id>.pdf per open incident
```

## Known risks / issues

- **Risk 1 — CIRCIA Final Rule effective date drift.** The Final Rule was
  published May 2026 but the 18-month effective window puts the first
  enforceable 72h clock around November 2027. CISA may shorten or extend
  via additional rulemaking. Mitigation: operator confirms the date in
  `org-profile.yaml::circia_effective_date`; tracker runs in dry-run mode
  until that date. Runbook documents the procedure to flip the flag.
- **Risk 2 — CISA submission URL changes.** Today the general incident form
  is at https://www.cisa.gov/forms/report; the CIRCIA-specific URL may
  differ after the effective date. Mitigation: URL lives in
  `org-profile.yaml`; default points to general form; runbook reminds
  operator to update at effective date.
- **Risk 3 — CISA API does not yet exist.** As of June 2026 there is no
  programmatic CIRCIA API; submission is web-form-manual. Mitigation:
  manual submission helper opens the form pre-populated via clipboard;
  acknowledgement-token capture is operator-pasted. When CISA publishes an
  API, the existing `circia_submission_receipts` schema accommodates
  programmatic tokens without breaking change.
- **Risk 4 — OFAC sanctions on ransom payments.** A ransom payment to a
  sanctioned entity is itself a separate federal crime under OFAC
  regulations. Mitigation: tracker UI gates ransom-payment recording
  behind an explicit "I have consulted legal counsel on OFAC implications"
  checkbox; runbook flags Treasury OFAC FAQs.
- **Risk 5 — Late-report cascade.** If the 72h clock breaches, the POA&M
  finding fires AND the CIRCIA report still must be submitted (lateness
  does not absolve the duty). Operator must NOT interpret the breach as
  "skip the report". Mitigation: POA&M description explicitly states
  "submission still required"; UI warning banner persists.
- **Risk 6 — Supplemental-report cascade.** Each substantively-new finding
  starts a new 24h supplemental clock. A complex incident may generate
  10+ supplemental reports. Mitigation: tracker UI groups supplementals
  by triggering-change category; daily-update cadence enforcer
  (LOOP-G.G2) batches related changes when possible.
- **Risk 7 — Records retention bleed-through.** The CIRCIA 2-year
  retention overlaps with FedRAMP 1-year ConMon retention; CSPs may
  inadvertently delete CIRCIA-relevant data during ConMon cleanup.
  Mitigation: retention sweep flags overlap; tracker UI shows minimum-
  retention = `max(CIRCIA, FedRAMP, agency, M-17-12)`.
- **Risk 8 — Multi-tenant scoping.** If the CSP serves multiple federal
  customers and an incident affects only one tenant, the CIRCIA report
  still covers the CSP-level incident; tenant-level details go in
  `affected_systems[].federal_customer_impact[]`. Risk: over-disclosure
  to CISA of unaffected tenants. Mitigation: schema separates per-tenant
  impact; legal review the runbook step before first submission.
- **Risk 9 — Information-sharing safe harbor over-reliance.** §681b(a)(5)(B)
  provides a partial safe harbor when substantially similar information
  was submitted elsewhere; misapplying the safe harbor means under-reporting.
  Mitigation: default `safe_harbor_invoked=false`; operator must sign
  rationale; legal counsel review.

## Open questions (for implementation session)

- **Q1**: Should the timer daemon run hourly via cron, or be triggered by
  incident-state-change events? Recommendation: both — hourly cron for
  baseline + change-event triggers for immediate warning.
- **Q2**: For the 2-year retention clock — does it start from final
  supplemental submission or from incident closure? §681b(a)(5) is
  ambiguous; NPRM says "submission of the final supplemental report".
  Recommendation: use `final_supplemental_submitted_at` (which equals
  `final_report_at` for incidents without supplementals).
- **Q3**: Should the tracker UI auto-suggest prong-1 when AFR-ICP
  `severity='critical'`? Recommendation: suggest in UI text, but require
  explicit operator click on the checkbox (REO: no auto-decision).
- **Q4**: For ransom payment without a covered cyber incident parent —
  does the system still require a covered-entity assessment? Recommendation:
  yes — §681b(a)(2) requires "a covered entity that makes a ransom payment";
  the covered-entity assessment must precede the payment row.
- **Q5**: How do we handle a ransom payment that's later REFUNDED by the
  attacker (rare but happens)? Recommendation: separate `circia_ransom_refunds`
  table with link to original payment + operator-supplied rationale;
  supplemental report cycle triggered.
- **Q6**: For the CISA acknowledgement-token format — do we validate via
  regex or just accept arbitrary string? Recommendation: accept arbitrary
  string until CISA publishes a token format spec; emit warning if format
  looks unlikely (length < 10, all whitespace, etc.).
- **Q7**: Should the orchestrator's `--circia` flag refuse to run before
  the effective date? Recommendation: no — runs in dry-run mode (produces
  JSON packets, no POA&M findings, no timer warnings); CHANGELOG documents
  effective-date behavior switch.
- **Q8**: Late-report POA&M finding — what's the right deadline? FedRAMP
  CMP table doesn't specifically cover CIRCIA. Recommendation: 24h from
  detection (severity high). Operator can adjust via standard POA&M
  workflow.
- **Q9**: For multi-CSO operators — one covered-entity assessment per CSO
  or one per CSP organization? Recommendation: per CSP organization (CIRCIA
  is entity-scoped, not system-scoped); each CSO's incidents link to the
  same assessment row.

## Implementation log (running journal)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist

- [ ] typecheck clean
- [ ] tests passing (count +~30 for slice tests + route tests + timer tests)
- [ ] check:reo green
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-G-SPEC.md status table updated
- [ ] This file's frontmatter updated
- [ ] CHANGELOG.md "Unreleased" entry under `### Added — LOOP-G.G2.CIRCIA: CIRCIA reporting workflow extension to AFR-ICP`
- [ ] Commit with `LOOP-G.G2.CIRCIA:` in message
- [ ] Commit amended with hash
- [ ] Pushed to origin/main
- [ ] CIRCIA-RUNBOOK.md authored
- [ ] CIRCIA-WORKFLOW.md cross-referenced from LOOP-G-SPEC.md + LOOP-M-SPEC.md
- [ ] LOOP-M.M4-CIRCIA-EXTENSION dependency confirmed
- [ ] LOOP-G-RISKS.md updated with §Known risks entries
- [ ] End-to-end orchestrator smoke: `npm run collect -- --circia` produces
      `out/circia/incidents-log.json` + per-incident JSON + PDF + signed
      manifest entries
- [ ] Dry-run mode verified before effective date: no POA&M findings
      emitted, no timer warnings raised
- [ ] Effective-date flip verified: when `circia_effective_date <= now`,
      72h timers fire normally

## Resume-from-fresh-session checklist

1. Read `cloud-evidence/CLAUDE.md`.
2. Read `cloud-evidence/docs/CIRCIA-WORKFLOW.md` (cross-cutting reference).
3. This file is the entry point.
4. Read `cloud-evidence/docs/slices/G/G.G2.md` (base AFR-ICP slice).
5. Read `cloud-evidence/docs/slices/M/M.M4-CIRCIA-EXTENSION.md`
   (sibling slice for privacy intersection).
6. Read `cloud-evidence/docs/loops/LOOP-G-SPEC.md` §2 + §4 (G.G2).
7. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
8. Read `cloud-evidence/core/afr-icp.ts` (the integration point for
   `classifyCircia()`).
9. Read `cloud-evidence/core/oscal-poam.ts` (POA&M emission point for
   breached CIRCIA timers).
10. Read `cloud-evidence/core/sign.ts` (signing reference).
11. Read `cloud-evidence/core/envelope.ts` (provenance pattern).
12. Begin implementation; update Implementation log as you go.
