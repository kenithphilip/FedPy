---
slice_id: M.M4.CIRCIA
parent: M.M4
title: CIRCIA-Privacy Act intersection — harmonized PII-breach + cyber-incident reporting
loop: M
status: pending
commit: —
completed_date: —
depends_on: [M.M4, G.G2, G.G2.CIRCIA, LOOP-A.A1, REO-0]
blocks: []
estimated_effort: 3-4 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# M.M4.CIRCIA — CIRCIA-Privacy Act intersection (harmonized PII-breach + cyber-incident reporting)

## TL;DR

When a CIRCIA-reportable cyber incident also implicates PII (the common case
for SaaS CSPs serving federal customers), the CIRCIA 72-hour clock and the
OMB M-17-12 privacy-breach response procedures both apply. This extension
slice harmonizes the two workflows: the privacy-incident record (M.M4) and
the CIRCIA report (G.G2.CIRCIA) cross-link, the harm-risk assessment
informs the CIRCIA `impact` block, the M.M4 SAOP notification is recorded
in the CIRCIA `other_federal_reports` array, and the privacy-incident
runbook calls out the additional 72h CIRCIA obligation.

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this extension exists

The base M.M4 slice covers the privacy-incident response framework per
OMB M-17-12: SAOP notification within 30 minutes, CISA US-CERT report
within 1 hour, harm-risk assessment per M-17-12 §V five-factor methodology,
individual notification within 60 days, Congressional notification within
7 days for major incidents, and SORN amendment workflow.

The base G.G2.CIRCIA slice covers the cyber-incident reporting workflow
per 6 U.S.C. §681b: 72-hour covered-cyber-incident report, 24-hour
ransom-payment report, supplemental-report cadence, and 2-year records
retention.

When the same incident is BOTH a "covered cyber incident" under CIRCIA AND
a "PII breach" under M-17-12 — which is the common case for a SaaS CSP
serving federal customers — neither workflow substitutes for the other.
Both clocks run in parallel; both reports must be submitted; both data sets
must be retained. The risk is:

- **Over-disclosure:** the CIRCIA report goes to CISA, not to HHS or the
  SAOP. Sending the privacy-incident's PII-affected-individual lists to
  CISA is over-disclosure.
- **Under-disclosure:** treating the CIRCIA submission as "we already told
  CISA" and failing to also notify per M-17-12 (the M-17-12 1-hour CISA
  US-CERT notice is a SEPARATE intake — US-CERT triages privacy breaches
  differently from cyber incidents).
- **Inconsistent timelines:** the SAOP gets the privacy notification at
  T+30 min; the CIRCIA report is due at T+72 h. If the SAOP later
  determines the breach is NOT CIRCIA-reportable (because it's contained
  to a workstation with no substantial loss), the CIRCIA workflow
  legitimately exits — but if the SAOP determines it IS CIRCIA-reportable,
  the 72h clock has already been running and might be near breach.
- **Field consistency:** `affected_individual_count`, `pii_categories`,
  `attack_vector` should be consistent across both reports. Discrepancies
  raise CISA + SAOP questions.

This slice ships the harmonization: cross-references between the two
record systems, consistency validation, and runbook procedures for the
joint workflow.

## Connection to FedPy mission

- **Extends LOOP-M.M4 privacy IRP** — adds CIRCIA cross-reference field +
  harmonization validator + UI flow.
- **Extends LOOP-G.G2.CIRCIA** — privacy incidents auto-create CIRCIA
  records when the operator marks `circia_reportable=true` during the
  M.M4 triage.
- **Reads M.M4 `privacy_incidents`** — single source of truth for
  `pii_categories`, `affected_individual_count`, `harm_risk_json`.
- **Reads G.G2.CIRCIA `circia_incidents`** — single source of truth for
  `prongs_triggered`, `cisa_acknowledgement_token`.
- **Writes consistency-check audit events** — when `affected_systems` or
  `pii_categories` are inconsistent between the M.M4 record and the CIRCIA
  packet, an audit event flags the divergence for SAOP + IR-lead review.
- **OMB M-17-12 §V harm-risk feeds CIRCIA `impact.prong_1_substantial_loss.rationale`** —
  the harm-risk overall rating (low/moderate/high) is one of the factors the
  CIRCIA `impact` block records.
- **REO** — every cross-reference is a real FK; the harmonization validator
  is operator-acknowledged when divergence is found; the system never
  silently merges or overrides one record with the other.

## Authoritative sources (verbatim quotes)

### OMB M-17-12 §III "Breach Response Team"

> "Each agency shall maintain a breach response plan that includes a list
> of the senior officials who will serve on the breach response team."

(Includes SAOP, CIO, CISO, Communications, Legal, OIG, OGC.) The CSP
mirrors this team composition in its breach response plan emitted by M.M4.

### OMB M-17-12 §V "Assessing the Risk of Harm to Individuals" (verbatim five factors)

> "When evaluating the risk of harm to potentially affected individuals
> resulting from a breach, an agency should consider:
> 1. The nature and sensitivity of the PII potentially compromised by
>    the breach.
> 2. The likelihood of access and use of PII.
> 3. The type of breach.
> 4. The wider context of the breach.
> 5. The number of individuals potentially affected.
> Each factor should be evaluated and assigned a risk level of low,
> moderate, or high. The overall risk of harm is the highest level across
> the five factors, except where the agency justifies a lower overall
> rating with explicit rationale."

The M-17-12 §V harm-risk overall rating is reused by this slice as one
input to the CIRCIA `impact.prong_1_substantial_loss.rationale` block.

### OMB M-17-12 §VI "Notification" (60-day individual notification)

> "Notification of individuals affected by a breach involving PII shall
> occur not later than 60 calendar days following the discovery of a
> breach, unless the agency, for good cause shown, requests a delay from
> the SAOP."

### 6 U.S.C. §681b(a)(1)(A) — 72-hour covered cyber incident reporting

> "A covered entity that experiences a covered cyber incident shall report
> the covered cyber incident to the Director not later than 72 hours after
> the covered entity reasonably believes that the covered cyber incident
> has occurred."

The CIRCIA 72h clock is ADDITIVE to the M-17-12 60-day individual
notification clock; they do NOT substitute. A privacy breach that is also
a covered cyber incident triggers BOTH clocks.

### 6 U.S.C. §681e — Harmonization

> "The Director shall coordinate with appropriate Federal agencies to
> reduce or eliminate duplicative reporting and to harmonize cyber
> incident reporting requirements."

§681e is the statutory basis for the future CIRCIA-M-17-12 harmonization
rule. As of June 2026 no harmonization rule has been published — both
workflows remain independent. This slice prepares for harmonization by
keeping the two record systems cross-linked.

### CIRCIA NPRM (89 FR 23644) — substantial cyber incident prong 4

> "Unauthorized access to a covered entity's information system or
> network, or any nonpublic information contained therein, that is
> facilitated through or caused by either a compromise of a cloud service
> provider, managed service provider, other third-party data hosting
> provider, or a supply chain compromise."

For a SaaS CSP, prong 4 fires when a federal-customer's PII-containing
records are exfiltrated. The M.M4 incident's `pii_categories` field then
becomes a CIRCIA-relevant input.

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/privacy-circia-bridge.ts`
  (~250 lines) — pure cross-reference + consistency validator. Functions:
  `linkPrivacyToCircia(privacyIncident, circiaIncident)`,
  `harmonizeImpactBlock(privacyIncident, circiaIncident)`,
  `validateConsistency(privacyIncident, circiaIncident): { divergences[] }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/privacy-circia-bridge.test.ts`
  — ≥10 unit tests (enumerated below).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/privacy-circia.ts`
  — REST endpoint: POST `/api/privacy-incidents/:id/link-circia`,
  POST `/api/privacy-incidents/:id/promote-to-circia` (one-click create
  CIRCIA record from privacy incident), GET
  `/api/privacy-incidents/:id/consistency-check`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/privacy-circia.test.ts`
  — route tests.

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/privacy-irp-emit.ts`
  — add `circia_report_id` field to the per-incident JSON envelope; emit
  reference into the breach runbook's `phases.notification.actions[]`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/circia-report.ts` —
  add `privacy_incident_uuid` field to the CIRCIA packet's
  `affected_systems` block when the incident is PII-implicated;
  `impact.prong_1_substantial_loss.harm_risk_rating` populated from M.M4.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/schema.sql`
  — additive: `privacy_circia_link` table (one row per linked pair), plus
  index on `(privacy_incident_uuid, circia_report_id)`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/PrivacyIncidents.tsx`
  — add "Promote to CIRCIA" button (visible when CSP is a covered entity);
  show CIRCIA timer countdown beside the M-17-12 timer countdown;
  consistency-check warning banner.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/CirciaIncidents.tsx`
  — show linked `privacy_incident_uuid` link with harm-risk badge.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/CIRCIA-RUNBOOK.md`
  — add §"Joint privacy + cyber incident workflow" section.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` —
  when consistency-check divergence is unresolved past 24h, emit POA&M
  finding `{ severity: 'moderate', deadline: now+72h }`.

## Schemas / standards

### `privacy_circia_link` table

```sql
CREATE TABLE IF NOT EXISTS privacy_circia_link (
  id TEXT PRIMARY KEY,
  privacy_incident_uuid TEXT NOT NULL REFERENCES privacy_incidents(uuid),
  circia_report_id TEXT NOT NULL REFERENCES circia_incidents(circia_report_id),
  linked_at TEXT NOT NULL,
  linked_by_user_id TEXT NOT NULL,
  consistency_check_status TEXT NOT NULL CHECK (consistency_check_status IN ('clean','divergent','divergent_acknowledged')),
  divergences_json TEXT,
  acknowledged_at TEXT,
  acknowledged_by_user_id TEXT,
  acknowledgement_rationale TEXT,
  signature TEXT NOT NULL,
  signing_key_id TEXT NOT NULL,
  UNIQUE (privacy_incident_uuid, circia_report_id)
);
```

### Consistency-check rules

`validateConsistency()` checks the following fields for equality (or
intentional divergence):

| Privacy field | CIRCIA field | Rule |
|---|---|---|
| `privacy_incidents.discovered_at` | `circia_incidents.discovered_at` | equal |
| `privacy_incidents.pii_categories` | `circia_incidents.affected_systems[].data_types` superset of `pii_categories` | superset |
| `privacy_incidents.affected_individual_count` | `circia_incidents.impact.prong_1_substantial_loss.affected_individual_count` | equal |
| `privacy_incidents.breach_mechanism` | `circia_incidents.iocs.attack_vector` (mapped) | mapped enum |
| `privacy_incidents.harm_risk.overall_risk` | `circia_incidents.impact.prong_1_substantial_loss.harm_risk_rating` | equal |
| `privacy_incidents.reported_to_us_cert_at` | `circia_incidents.other_federal_reports[]` includes US-CERT M-17-12 | present |
| `privacy_incidents.reported_to_saop_at` | `circia_incidents.other_federal_reports[]` includes SAOP | present |

Divergence does NOT block submission — the operator may acknowledge it
with rationale (e.g. "M-17-12 PII categories are SSN + DoB; CIRCIA
affected_systems includes those PLUS healthcare-app logs that contain
no PII"). The acknowledgement is signed.

### CIRCIA `impact.prong_1_substantial_loss` harmonization

When the incident has `prong_1_substantial_loss.triggered=true` AND a
linked privacy incident exists, the `rationale` block populates:

```json
{
  "triggered": true,
  "rationale": "PII confidentiality loss per M-17-12 harm-risk overall rating: <high/moderate/low>. Five-factor breakdown: factor_1=<>, factor_2=<>, factor_3=<>, factor_4=<>, factor_5=<>. M-17-12 §V justification: <>.",
  "harm_risk_rating": "<high/moderate/low>",
  "affected_individual_count": <int>,
  "pii_categories": [<from privacy incident>]
}
```

## Build steps (numbered, concrete)

1. **Define types** in `core/privacy-circia-bridge.ts`:
   `PrivacyCirciaLink`, `ConsistencyDivergence`, `HarmonizedImpactBlock`.
2. **Implement** `linkPrivacyToCircia(privacyIncident, circiaIncident,
   linked_by_user_id): PrivacyCirciaLink` — pure builder.
3. **Implement** `harmonizeImpactBlock(privacyIncident, circiaIncident):
   { impact_block, missing_data }` — populates the CIRCIA `impact.prong_1_substantial_loss`
   from M.M4 harm-risk; surfaces missing inputs.
4. **Implement** `validateConsistency(privacyIncident, circiaIncident):
   { divergences: ConsistencyDivergence[] }` — applies the 7 rules above.
5. **Implement tracker route** `POST /api/privacy-incidents/:id/link-circia`
   — operator picks an existing CIRCIA report to link OR triggers
   `promote-to-circia` (auto-create CIRCIA record from privacy incident
   metadata, then prompt operator to complete 4-prong checklist).
6. **Implement tracker route** `POST /api/privacy-incidents/:id/promote-to-circia`
   — pre-fills CIRCIA `discovered_at`, `reasonable_belief_at`,
   `affected_systems[].data_types` (from `pii_categories`),
   `impact.prong_1_substantial_loss.harm_risk_rating`,
   `other_federal_reports[]` (with M-17-12 SAOP + US-CERT entries) from
   the privacy incident; operator confirms + signs.
7. **Implement tracker route** `GET /api/privacy-incidents/:id/consistency-check`
   — runs `validateConsistency()`; returns divergences for UI display.
8. **Extend `core/privacy-irp-emit.ts`** — add `circia_report_id` to the
   per-incident envelope; emit reference into `breach_runbook.phases.notification.actions[]`.
9. **Extend `core/circia-report.ts`** — accept `privacy_incident_uuid`
   as optional input; populate `affected_systems[].privacy_incident_uuid` +
   `impact.prong_1_substantial_loss.harm_risk_rating` from the linked
   privacy incident.
10. **Wire orchestrator** — `--privacy-irp` runs BEFORE `--circia` (which
    already runs after `--afr-icp`); the bridge consults M.M4 snapshot
    when emitting CIRCIA packets for linked incidents.
11. **POA&M emission** — when `privacy_circia_link.consistency_check_status='divergent'`
    AND `acknowledged_at IS NULL` AND `linked_at < now-24h`, emit POA&M
    finding via `core/oscal-poam.ts`.
12. **Validation pass + sign + timestamp** as in base M.M4 + base G.G2.CIRCIA.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| `privacy_circia_link.linked_at` | tracker UI link action | Cross-reference not established; tracker raises diagnostic if privacy incident has `pii_implicated=true` AND CSP is covered entity AND no link exists past 1h after incident discovery |
| `acknowledgement_rationale` for divergences | tracker UI | Divergence stays unresolved; POA&M fires at 24h |
| Promote-to-CIRCIA 4-prong completion | tracker UI 4-prong checklist | Promoted CIRCIA incident stays in `status='open'` until prongs confirmed; 72h clock runs |

## Test specifications (≥10 tests)

### `tests/core/privacy-circia-bridge.test.ts`

1. `it('linkPrivacyToCircia produces signed link row with both FKs')`
2. `it('harmonizeImpactBlock populates prong_1_substantial_loss.harm_risk_rating from M.M4 overall_risk')`
3. `it('harmonizeImpactBlock populates affected_individual_count from M.M4')`
4. `it('harmonizeImpactBlock surfaces missing_data when M.M4 harm_risk is undecided')`
5. `it('validateConsistency flags discovered_at divergence > 1 second')`
6. `it('validateConsistency flags affected_individual_count divergence')`
7. `it('validateConsistency flags pii_categories not subset of CIRCIA data_types')`
8. `it('validateConsistency flags harm_risk overall_risk vs prong_1 harm_risk_rating divergence')`
9. `it('validateConsistency passes when reported_to_saop_at present in other_federal_reports')`
10. `it('validateConsistency returns empty divergences for fully-harmonized records')`

### `tracker/server/routes/privacy-circia.test.ts`

11. `it('POST /link-circia requires both records exist and CSP is covered entity')`
12. `it('POST /promote-to-circia pre-fills 5 fields from privacy incident')` —
    `discovered_at`, `reasonable_belief_at`, `affected_systems[].data_types`,
    `impact.prong_1_substantial_loss.harm_risk_rating`, `other_federal_reports[]`.
13. `it('POST /promote-to-circia leaves prongs_triggered=[] for operator confirmation')`
14. `it('POST /promote-to-circia rejects when no covered-entity assessment exists')`
15. `it('GET /consistency-check returns divergence list when fields mismatch')`
16. `it('GET /consistency-check returns clean status when fields harmonized')`
17. `it('GET /consistency-check rejects when privacy incident is not linked to any CIRCIA record')`

### Integration tests

18. `it('orchestrator: privacy-irp + circia produces both packets with cross-references')` —
    same incident generates both `out/privacy-incident-response-plan.docx`
    record reference AND `out/circia/<id>.json` with linked privacy_incident_uuid.
19. `it('POA&M fires when divergence is unacknowledged past 24h')`

## REO compliance

- **Operator-supplied:** Promote-to-CIRCIA decision, 4-prong confirmation,
  divergence acknowledgement rationale.
- **Cross-references via real FKs:** No copy-paste duplication; CIRCIA
  packet reads M.M4 row at emit time.
- **No silent merge:** Divergences are surfaced, not auto-resolved.
  Operator must acknowledge with rationale.
- **No auto-promote:** The system never auto-creates a CIRCIA record from
  a privacy incident — the operator clicks "Promote to CIRCIA" after
  reviewing.
- **Allowed fixed data:** OMB M-17-12 §V verbatim five factors; 6 USC
  §681b verbatim 72h clock; M-17-12 60-day individual notification clock.
- **Provenance:** `privacy_circia_link` row + bridge output carry
  provenance with `emitter='core/privacy-circia-bridge.ts'`, `emittedAt`,
  `sourceCalls`, `signingKeyId`, `runId`,
  `requirementTexts: [OMB M-17-12 §V, 6 USC §681b(a)(1)(A), 6 USC §681e]`.
- **Signing:** Ed25519 + RFC 3161 via `core/sign.ts`.
- **Determinism:** Bridge output canonical-JSON sorted.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/privacy-circia-bridge.test.ts
cd tracker
npm test -- server/routes/privacy-circia.test.ts
cd ..
npm run check:reo
npm run check:provenance
npm run lint:no-stubs

# Integration smoke
npm run collect -- --impact-level moderate --privacy-irp --circia
ls out/privacy-incident-response-plan.docx
ls out/circia/
# Look for cross-references: out/circia/<id>.json contains "privacy_incident_uuid"
```

## Known risks / issues

- **Risk 1 — Workflow drift between SAOP and IR Lead.** SAOP runs the M.M4
  decision tree; IR Lead runs the CIRCIA prong checklist. Divergence in
  judgement (e.g. SAOP says "low harm-risk", IR Lead checks prong-1
  substantial loss anyway) is a process issue, not a system issue.
  Mitigation: consistency-check UI surfaces the divergence; runbook
  documents the SAOP + IR Lead conferring step.
- **Risk 2 — Promote-to-CIRCIA over-eager use.** Not every PII breach is a
  covered cyber incident; only those meeting the 4-prong test. If
  operators reflexively promote every privacy incident, CIRCIA reports
  are over-issued and signal-to-noise at CISA degrades. Mitigation: UI
  text emphasizes the 4-prong test; promote button requires operator to
  pre-check at least one prong as a confirmation step.
- **Risk 3 — Late M.M4 harm-risk delays CIRCIA submission.** The CIRCIA
  72h clock cannot wait for the M-17-12 harm-risk decision (which often
  takes days). Mitigation: CIRCIA packet may submit with
  `harm_risk_rating='pending'` and trigger a supplemental report once
  M.M4 finalizes; consistency-check tolerates `pending` state.
- **Risk 4 — Divergence acknowledgement abuse.** Operator may dismiss real
  divergences with cursory rationale. Mitigation: rationale string
  required ≥ 200 characters; SAOP must co-sign acknowledgements that
  override M.M4 harm-risk; CHANGELOG documents.
- **Risk 5 — 60-day individual notification vs CIRCIA supplemental.** When
  individuals are notified at T+50 days under M-17-12 §VI, the
  notification itself may surface "substantially new information" (e.g.
  some individuals report identity-theft attempts), triggering a CIRCIA
  supplemental report. Mitigation: M.M4 plan §VII notification action
  IDs emit `circia_supplemental_due` events.
- **Risk 6 — Per-tenant scoping vs CIRCIA covered-entity scoping.** M.M4
  records per-tenant privacy incidents (one CSP serving multiple federal
  customers); CIRCIA reports at the CSP-level (one report per covered
  entity per incident). Mitigation: link-CIRCIA supports many-to-one
  (multiple privacy_incident_uuid linked to one circia_report_id when the
  same incident affected multiple tenants); UI shows aggregated affected-
  individual count.
- **Risk 7 — Records retention conflict.** M.M4 may retain PII for the
  M-17-12 notification window; CIRCIA mandates 2-year retention of all
  incident-relevant data. If an operator deletes PII at the M.M4 cleanup
  cadence, the CIRCIA retention may be violated. Mitigation: retention
  sweep enforces `max(privacy_retention, circia_retention)`; tracker UI
  warns before any deletion that affects CIRCIA-linked data.
- **Risk 8 — EU GDPR Article 33 72h overlap.** If the breached PII also
  involves EU data subjects, GDPR Article 33's separate 72h notification
  clock to the EU supervisory authority also runs. Mitigation: out-of-
  scope for M.M4-CIRCIA-EXTENSION at the moderate baseline; documented
  in M.M2 DPIA + cross-referenced in plan section 2 Authorities.

## Open questions

- **Q1**: Should `promote-to-circia` be one-click or require a confirmation
  modal? Recommend: confirmation modal with 4-prong pre-check as gate.
- **Q2**: For consistency-check divergences, do we permit one signer (IR
  Lead alone) or require co-signing (IR Lead + SAOP)? Recommend: IR Lead
  for non-prong-1 divergences; co-sign for prong-1 / harm-risk
  divergences.
- **Q3**: When a privacy incident is later determined NOT to be CIRCIA-
  reportable (after promote-to-CIRCIA was used), what happens to the
  CIRCIA record? Recommend: status flips to `'withdrawn'`; CISA is
  notified via supplemental; the withdrawal does not absolve the original
  72h reporting duty (if it was met) and does retain records.
- **Q4**: For the `harm_risk_rating='pending'` interim state — does CIRCIA
  packet `ready_for_signature=true`? Recommend: yes, with explicit
  `interim_pending_fields[]` provenance entry; supplemental report
  scheduled.
- **Q5**: Should the bridge auto-update CIRCIA `affected_individual_count`
  when M.M4 `affected_individual_count` changes? Recommend: no, never
  auto-update; surface divergence; operator updates with rationale.
- **Q6**: How do we handle the OMB M-22-05 Congressional 7-day major-
  incident notification when the same incident is CIRCIA-reportable?
  Recommend: separate workflow under M.M4 base slice; CIRCIA
  `other_federal_reports[]` lists Congressional notification as a row.

## Implementation log
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist

- [ ] typecheck clean
- [ ] tests passing (count +~15)
- [ ] check:reo green
- [ ] STATUS.md updated
- [ ] LOOP-M-SPEC.md status row updated
- [ ] This file's frontmatter updated
- [ ] CHANGELOG.md "Unreleased" entry under `### Added — LOOP-M.M4.CIRCIA: CIRCIA-Privacy Act intersection`
- [ ] Commit with `LOOP-M.M4.CIRCIA:` in message
- [ ] Commit amended with hash
- [ ] Pushed to origin/main
- [ ] CIRCIA-WORKFLOW.md cross-referenced from this file
- [ ] G.G2.CIRCIA dependency confirmed (base CIRCIA workflow exists)
- [ ] LOOP-M-RISKS.md updated with §Known risks entries
- [ ] CIRCIA-RUNBOOK.md §"Joint privacy + cyber incident workflow" authored
- [ ] End-to-end smoke: `npm run collect -- --privacy-irp --circia` produces
      both packets with cross-references; consistency-check reports clean

## Resume-from-fresh-session checklist

1. Read `cloud-evidence/CLAUDE.md`.
2. Read `cloud-evidence/docs/CIRCIA-WORKFLOW.md` (cross-cutting reference).
3. Read `cloud-evidence/docs/slices/M/M.M4.md` (base privacy IRP slice).
4. Read `cloud-evidence/docs/slices/G/G.G2-CIRCIA-EXTENSION.md` (sibling
   CIRCIA base extension).
5. This file is the entry point for the privacy-CIRCIA intersection.
6. Read `cloud-evidence/docs/loops/LOOP-M-SPEC.md` §M.M4 sub-section.
7. Read `cloud-evidence/docs/loops/LOOP-G-SPEC.md` §G.G2 sub-section.
8. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
9. Read `cloud-evidence/core/privacy-irp-emit.ts` (M.M4 base emitter — the
   extension point for `circia_report_id`).
10. Read `cloud-evidence/core/circia-report.ts` (G.G2.CIRCIA base — the
    extension point for `privacy_incident_uuid`).
11. Read `cloud-evidence/core/oscal-poam.ts` (POA&M emission for
    unresolved divergences).
12. Begin implementation; update Implementation log as you go.
