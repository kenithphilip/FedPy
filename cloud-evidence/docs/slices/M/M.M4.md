---
slice_id: M.M4
title: Privacy incident response procedures (PT-7 + breach notification per OMB M-17-12)
loop: M
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A4, LOOP-C.C4, M.M1, M.M3, R1]
blocks: [E.E1, G.G2]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# M.M4 — Privacy incident response procedures (PT-7 + breach notification per OMB M-17-12)

## TL;DR
Privacy breaches have a distinct response chain from generic security incidents — SAOP notification, US-CERT/CISA report within 1 hour for FCEB agencies, risk-of-harm assessment per OMB M-17-12 §V five-factor criteria, individual notification within 60 days, Congressional notification within 7 days for major incidents (FISMA §3554), post-breach SORN amendment when record categories change. LOOP-G.G2 AFR-ICP covers the general security-incident communication framework. This slice emits the privacy-specific overlay: `out/privacy-incident-response-plan.docx` + `out/privacy-breach-runbook.json`.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
- **Extends LOOP-G.G2 AFR-ICP** — adds a privacy classifier that the AFR-ICP framework calls when an incident has `pii_implicated=true`. Integration point: `core/afr-icp.ts:classifyIncident()` hook.
- **Reads M.M1 SORN snapshot** — when an incident affects record categories, M.M4 detects whether SORN amendment is required; if so, emits POA&M finding for SORN-amendment workflow.
- **Reads M.M3 PT-control evidence** — PT-7 sensitive-category handling determines per-incident notification timeline (e.g. SSN breach → mandatory individual notification regardless of harm risk).
- **Process-artifact KSI** — registers `KSI-PRV-IRP` in `core/ksi-map.ts`; evidence source = tracker `privacy_incidents` + signed plan.
- **Submission bundler** — adds `privacy-irp-docx` + `privacy-breach-runbook-json` roles.
- **POA&M integration** — when M.M4 incident snapshot surfaces `sorn_amendment_required=true` AND no pending sorn_publication exists, emits POA&M finding via existing `core/oscal-poam.ts` pipeline.
- **REO** — harm-risk assessment is operator-rated (classifier suggests but never decides); containment + notification decisions are signed tracker rows; OMB M-17-12 verbatim text in plan docstring + runbook timelines.

## Why this slice exists
The existing AFR-ICP (LOOP-G.G2) covers the general security-incident communication framework — who notifies whom, on what channels, in what order. It does NOT cover the privacy-specific overlay:
- **Harm-risk assessment using OMB M-17-12 §V five-factor criteria** (nature/sensitivity, likelihood, type of breach, wider context, individuals affected).
- **SAOP notification chain** (Senior Agency Official for Privacy is distinct from CISO).
- **CISA US-CERT 1-hour reporting** for FCEB agencies.
- **Individual notification within 60 days** (M-17-12 §VI).
- **Congressional notification within 7 days for major incidents** (OMB M-22-05 codifies FISMA §3554(b)(7)(C)).
- **Post-breach SORN amendment** (Privacy Act §552a (e)(4) revision when record categories change).
- **Substitute notice** (when individual count > threshold + contact info unavailable).
M.M4 closes that gap with a structured plan + runbook + classifier.

## Authoritative sources (with verbatim quotes)
- **OMB M-17-12 "Preparing for and Responding to a Breach of Personally Identifiable Information" (Jan 3, 2017)** — supersedes M-07-16; downloaded PDF at `cloud-evidence/docs/sources/omb-m-17-12.pdf`. Verbatim sections cited in plan docstring:
  - **§III "Breach Response Team"** — required composition: SAOP, CIO, CISO, Communications, Legal Counsel, Legislative Affairs, OIG, OGC.
  - **§IV "Breach Response Plan"** — required 8-section content.
  - **§V "Assessing the Risk of Harm to Individuals"** — verbatim:
    > "When evaluating the risk of harm to potentially affected individuals resulting from a breach, an agency should consider:
    > 1. The nature and sensitivity of the PII potentially compromised by the breach.
    > 2. The likelihood of access and use of PII.
    > 3. The type of breach.
    > 4. The wider context of the breach.
    > 5. The number of individuals potentially affected.
    > Each factor should be evaluated and assigned a risk level of low, moderate, or high. The overall risk of harm is the highest level across the five factors, except where the agency justifies a lower overall rating with explicit rationale."
    (Per LOOP-M-SPEC.md §12; final verbatim text in plan docstring after PDF download.)
  - **§VI "Notification"** — Congressional timeline, individual notification, substitute notice criteria.
- **OMB M-22-05** "Fiscal Year 2021-2022 Guidance on Federal Information Security and Privacy Management Requirements" — codifies 7-day Congressional notification for major incidents per FISMA §3554(b)(7)(C). Cited by M.M4 for major-incident threshold.
- **NIST SP 800-53 Rev 5 PT-7 "Specific Categories of PII"** — drives per-category notification timeline:
  > "Apply [Assignment: organization-defined processing conditions] for specific categories of personally identifiable information."
- **NIST SP 800-53 Rev 5 IR-6 "Incident Reporting"** + **IR-8 "Incident Response Plan"** — base IR-family controls reused.
- **FISMA §3554(b)(7)(C)** "major incident" definition — codified threshold (100,000 individuals per current OMB practice, operator-overridable).
- **CIRCIA (Cyber Incident Reporting for Critical Infrastructure Act of 2022)** — when applicable, CISA 72-hour incident reporting overlay. Out-of-band for this slice; documented in plan as reference.
- **5 U.S.C. §552a (e)(4)** — drives SORN-amendment-required determination.

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/privacy-irp-emit.ts` — ~700 lines. Emits `out/privacy-incident-response-plan.docx` + `out/privacy-breach-runbook.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/privacy-breach-classifier.ts` — implements M-17-12 §V five-factor assessment guidance; emits `harm_risk` ∈ {low, moderate, high} with explicit per-factor rating + rationale. Classifier SUGGESTS; operator DECIDES.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/privacy-incident-reader.ts` — pulls `privacy_incidents` rows from tracker; writes signature-verified snapshot at `out/.privacy-incidents-snapshot.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/privacy-irp-emit.test.ts` — ≥13 tests (enumerated below).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/privacy-breach-classifier.test.ts` — five-factor + overall_risk derivation tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/privacy-incident-reader.test.ts` — snapshot + signature tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/privacy-irp/` — sample fixtures.
- `tracker/server/routes/privacy-incidents.ts` — CRUD; enforces SAOP review for major incidents; emits audit-log entry per state transition.
- `tracker/client/src/pages/PrivacyIncidents.tsx` — UI page with incident timeline view + five-factor assessment form + notification-decision tracker + state machine display.
- `tracker/server/routes/privacy-incidents.test.ts`.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — `--privacy-irp` flag + env `CLOUD_EVIDENCE_PRIVACY_IRP`; `--major-incident-threshold <count>` operator override (default 100000).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add roles `privacy-irp-docx` + `privacy-breach-runbook-json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — when incident snapshot has `sorn_amendment_required=true` AND no pending sorn_publication row, emit POA&M finding (severity=high, deadline=60d per FedRAMP CMP).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` — register `KSI-PRV-IRP` process-artifact.
- `tracker/server/schema.sql` — `privacy_incidents` table (additive).
- `tracker/server/index.ts` — mount route.
- `tracker/client/src/App.tsx` — add `/privacy/incidents` route.
- `cloud-evidence/core/afr-icp.ts` (LOOP-G.G2 — when shipped) — integration point: privacy classifier hook documented.

## Schemas / standards
- **OMB M-17-12 §IV** — 8-section breach response plan content; M.M4 plan emits a 12-section variant (extends M-17-12's 8 with sub-sections for roster + SORN amendment + sign-off).
- **OMB M-17-12 §V five-factor harm assessment** — classifier follows the verbatim five factors.
- **OMB M-22-05 + FISMA §3554(b)(7)(C)** — major incident threshold (100,000 individuals).
- **NIST SP 800-53 Rev 5 IR-6 / IR-8 / PT-7** — control references.
- **CISA Incident Reporting Guidelines** — endpoint + format.
- **OOXML / .docx** — emit via `core/ssp-docx.ts` deterministic zip-store.

## Build steps (concrete, numbered)
1. Define `PrivacyIncident` + `HarmRiskAssessment` + `ContainmentAction` + `NotificationDecision` in `core/privacy-irp-emit.ts` per LOOP-M-SPEC.md §5 (M.M4 build steps).
2. **Privacy IRP `.docx` emitter** — 12 sections per M-17-12 §IV (M.M4 extends with sub-sections):
   1. Purpose + Scope.
   2. Authorities (Privacy Act, OMB M-17-12, OMB M-22-05, NIST 800-53 IR-6/IR-8, FISMA, CIRCIA).
   3. Roles + Responsibilities (SAOP, Breach Response Team, CIO, CISO, Legal, Communications, OIG, OGC).
   4. Incident Identification + Classification.
   5. Harm Risk Assessment Methodology (M-17-12 §V five factors verbatim).
   6. Containment + Mitigation.
   7. Notification Procedures (per audience, per timeline).
   8. Post-Incident Review + Lessons Learned.
   9. Annual Plan Review + Tabletop Cadence.
   10. Roster + Contact List.
   11. SORN Amendment Procedures (when record categories change).
   12. Approval + Sign-Off block.
3. **Privacy Breach Runbook `.json`** — structured playbook consumed by on-call automation:
   ```json
   {
     "phases": [
       {
         "phase": "identification",
         "actions": [
           { "id": "ID-01", "description": "Triage indicator", "owner_role": "duty-officer", "max_minutes_from_discovery": 15 },
           { "id": "ID-02", "description": "Notify SAOP", "owner_role": "ciso", "max_minutes_from_discovery": 30 },
           { "id": "ID-03", "description": "Report to CISA US-CERT", "owner_role": "ciso", "max_minutes_from_discovery": 60 }
         ]
       },
       { "phase": "containment", "actions": [...] },
       { "phase": "harm-assessment", "actions": [...] },
       { "phase": "notification", "actions": [...] },
       { "phase": "post-incident", "actions": [...] }
     ],
     "thresholds": {
       "major_incident_individual_threshold": 100000,
       "congressional_notification_hours": 168,
       "individual_notification_days": 60,
       "cisa_us_cert_minutes": 60,
       "saop_notification_minutes": 30
     },
     "provenance": {
       "emitter": "core/privacy-irp-emit.ts",
       "emittedAt": "...",
       "sourceCalls": ["org-profile.yaml:read", "tracker:privacy_incidents:list"],
       "signingKeyId": "..."
     }
   }
   ```
4. **Classifier** `assessHarmRisk(incident: Partial<PrivacyIncident>): HarmRiskAssessment` — guides operator through M-17-12 §V criteria; suggests rating per factor based on incident metadata (e.g. ssn breach → factor 1 = high); final decision = operator-supplied. `overall_risk = max(factor_1..factor_5)` unless operator supplies explicit downward-justification rationale.
5. **POA&M integration** — when incident snapshot has `sorn_amendment_required: true` AND no corresponding pending row in `sorn_publications` (M.M1 table), emit POA&M finding:
   - `severity: 'high'`
   - `deadline: discovered_at + 60d` (matches FedRAMP CMP table for high)
   - `description: 'Privacy incident <incident_id> affected SORN-covered record categories; SORN amendment required per §552a (e)(4)'`
   - `related_observations[]`: link to incident uuid
6. **Tracker DB**:
   ```sql
   CREATE TABLE IF NOT EXISTS privacy_incidents (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     incident_id TEXT NOT NULL,
     discovered_at TEXT NOT NULL,
     reported_to_saop_at TEXT,
     reported_to_us_cert_at TEXT,
     reported_to_agency_at TEXT,
     affected_individual_count INTEGER,
     pii_categories TEXT NOT NULL,
     subject_categories TEXT NOT NULL,
     breach_mechanism TEXT NOT NULL,
     harm_risk_json TEXT NOT NULL,
     containment_actions_json TEXT NOT NULL,
     notification_decisions_json TEXT NOT NULL,
     sorn_amendment_required INTEGER NOT NULL CHECK (sorn_amendment_required IN (0,1)),
     status TEXT NOT NULL CHECK (status IN ('open','contained','remediated','closed')),
     created_by_user_id INTEGER NOT NULL REFERENCES users(id),
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_pi_status ON privacy_incidents(status);
   CREATE INDEX IF NOT EXISTS idx_pi_discovered ON privacy_incidents(discovered_at);
   CREATE INDEX IF NOT EXISTS idx_pi_incident_id ON privacy_incidents(incident_id);
   ```
7. **Wire orchestrator** — `--privacy-irp` runs AFTER `--sorn` + `--pt-family` (consumes M.M1/M.M3 snapshots) and BEFORE `--oscal-poam` (so POA&M picks up SORN-amendment findings).
8. **Bundler** — add `privacy-irp-docx` + `privacy-breach-runbook-json` to `WELL_KNOWN`.
9. **Sign + timestamp** — both files in manifest glob.
10. **Runbook determinism** — phase action IDs are stable across runs (e.g. `ID-01`, `CT-01`, `HA-01`, `NF-01`, `PI-01`); thresholds canonical-JSON sorted.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

| Field | Source | Behavior when missing |
|---|---|---|
| SAOP name + contact | `org-profile.yaml` `privacy.saop` | Plan emits REQUIRES-OPERATOR-INPUT for SAOP fields |
| Breach Response Team roster | Tracker `team_roster` or `org-profile.yaml` `privacy.breach_team` | REQUIRES-OPERATOR-INPUT per role |
| Agency notification chain | `org-profile.yaml` `customer.privacy_contacts[]` | REQUIRES-OPERATOR-INPUT |
| CISA US-CERT reporting endpoint | Configured per agency relationship | REQUIRES-OPERATOR-INPUT (template URL suggested but operator confirms) |
| Annual tabletop date | Operator schedule | REQUIRES-OPERATOR-INPUT (annual cadence enforced; never default to today) |
| Per-incident harm risk factor ratings | Operator-assessed via tracker | Cannot be inferred from incident metadata — REQUIRES-OPERATOR-INPUT per factor |
| Per-incident `sorn_amendment_required` | Operator decision after legal review | REQUIRES-OPERATOR-INPUT (default unset; operator confirms YES/NO with rationale) |
| Major-incident threshold | `--major-incident-threshold` (default 100000 per FISMA practice) | Default used; CHANGELOG documents |
| Decision-downward-justification rationale | Operator (when overall_risk < max factor) | REQUIRES-OPERATOR-INPUT |
| Containment actions | Operator records in tracker | Plan marks incident OPEN if none |

## Test specifications (≥13 tests)
1. `it('emits privacy-incident-response-plan.docx with 12 sections in M-17-12 order')`.
2. `it('emits privacy-breach-runbook.json with 5 phases (identification, containment, harm-assessment, notification, post-incident)')`.
3. `it('runbook timeline thresholds match OMB M-17-12 + M-22-05: 1h CISA, 60d individuals, 168h Congressional for major')`.
4. `it('major incident threshold = 100000 individuals per FISMA §3554(b)(7)(C) default')`.
5. `it('classifier scores each of M-17-12 §V five factors independently')`.
6. `it('classifier overall_risk = max of five factor ratings absent justification')`.
7. `it('classifier honors operator-supplied downward justification with rationale')`.
8. `it('REQUIRES-OPERATOR-INPUT for SAOP name when org-profile.privacy.saop missing')`.
9. `it('REQUIRES-OPERATOR-INPUT for tabletop date — never default to today')`.
10. `it('emits POA&M finding when sorn_amendment_required AND no pending sorn_publications row')`.
11. `it('privacy_incidents.harm_risk_json is signed canonical-JSON')`.
12. `it('snapshot reader verifies Ed25519 signature per incident row')`.
13. `it('registers KSI-PRV-IRP process-artifact')`.
14. `it('bundler includes privacy-irp-docx + privacy-breach-runbook-json roles')`.
15. `it('CHANGELOG entry for M.M4 quotes verbatim OMB M-17-12 §V')`.
16. `it('runbook phase IDs are stable across runs (deterministic; same SHA-256)')`.
17. `it('docx zip-store is deterministic across runs')`.
18. `it('PT-7 SSN-handling triggers mandatory individual notification regardless of harm-risk rating')` — when `ssn` in `pii_categories`, notification decision includes individuals.
19. `it('CIRCIA 72h reference appears in plan section 2 Authorities')`.
20. `it('strictPrivacy mode hard-errors when REQUIRES-OPERATOR-INPUT present in privacy-breach-runbook.json')`.

## REO compliance
- Harm-risk assessment is operator-rated; classifier suggests but never decides.
- Containment + notification decisions are signed tracker rows.
- POA&M finding flows through existing pipeline; no fabricated risks.
- `.docx` zip-store deterministic.
- Provenance block on `privacy-breach-runbook.json`.
- OMB M-17-12 §V verbatim in classifier docstring (Rule 3: published OMB guidance).
- Threshold defaults (100000 individuals, 60d, 168h, 60min) are published FISMA + OMB constants (Rule 3).
- No `process.env.NODE_ENV === 'test'` branches.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/privacy-irp-emit.test.ts tests/core/privacy-breach-classifier.test.ts tests/core/privacy-incident-reader.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/privacy-incidents.test.ts
```

## Known risks / issues
- **Risk 1: OMB M-17-12 PDF download blocking** — verbatim §V five factors require PDF download. Mitigation: `cloud-evidence/docs/sources/omb-m-17-12.pdf` pattern; LOOP-M-SPEC.md §12 documents; CHANGELOG cites page numbers.
- **Risk 2: Major-incident threshold drift** — FISMA may revise threshold via OMB memorandum. Mitigation: `--major-incident-threshold` CLI flag; CHANGELOG pins; default 100000.
- **Risk 3: CISA US-CERT endpoint may rotate** — agency relationship-specific. Mitigation: operator-supplied via tracker; documented in runbook.
- **Risk 4: AFR-ICP integration order** — M.M4 ships BEFORE or AFTER LOOP-G.G2? Mitigation: M.M4 emits standalone but exposes `classifyPrivacyIncident()` for G.G2 to call when it ships; documented dependency direction; if G.G2 ships first, M.M4 EXTENDS G.G2's classifier registry.
- **Risk 5: Substitute notice criteria ambiguity** — M-17-12 §VI defines substitute notice but threshold (e.g. "more than 50,000 individuals without contact info") is OMB practice not statute. Mitigation: operator-supplied via tracker; documented in plan.
- **Risk 6: SAOP role mapping** — tracker RBAC must add `saop` role. Per LOOP-B B-X5, first-boot prompt.
- **Risk 7: Multi-agency incident scoping** — when CSO serves multiple agencies and breach affects one tenant, notification chain is tenant-scoped. Mitigation: per-tenant tracker rows; aggregate per agency.
- **Risk 8: CIRCIA 72-hour reporting overlay** — when CIRCIA applies (critical infrastructure designation), 72h reporting overlays M-17-12. Mitigation: plan section 2 cites CIRCIA; operator config sets `circia_applicable`; future slice could expand.
- **Risk 9: POA&M deadline drift** — SORN-amendment-required POA&M emit uses 60d deadline; FedRAMP CMP table revision could change. Mitigation: deadline pulled from `core/deadline-table.ts` (LOOP-B.B2 ship); shared constant.
- **Risk 10: Plan tabletop cadence enforcement** — annual tabletop date is operator-supplied; if not updated annually, plan ships stale. Mitigation: CI guardrail checks `tabletop_date` is within 365d; warns at 330d; CHANGELOG documents.

## Open questions
- **Q1**: When does M.M4 emit POA&M for SORN amendment — at incident creation or at incident closure? Recommend: at incident closure when `sorn_amendment_required=true` AND no pending sorn_publication row.
- **Q2**: Should the docx include a tabletop exercise template? Recommend: yes, as appendix; sourced from CISA tabletop exercises.
- **Q3**: For multi-agency CSO, do we emit one plan or per-agency plans? Recommend: one plan covering CSO operations; agency-specific contacts in roster section.
- **Q4**: How do we handle insider-threat privacy breaches differently? Recommend: `breach_mechanism: 'insider'` value triggers additional notification (OIG); existing schema supports.
- **Q5**: Should runbook integrate with PagerDuty / Opsgenie? Recommend: out of scope for M.M4; future enhancement; current emit is on-call-readable JSON.
- **Q6**: Does the plan need to address EU GDPR Article 33 (72h breach notification) when cross-jurisdictional? Recommend: cite in section 2 Authorities; M.M2 DPIA covers cross-jurisdictional scope; M.M4 plan is US-federal-primary.
- **Q7**: When `affected_individual_count` is unknown at incident creation, do we default to threshold check on update? Recommend: status remains OPEN until count determined; POA&M finding emit waits for count.

## Implementation log
(empty — implementing session fills this in as work progresses)

## Completion checklist
- [ ] typecheck clean
- [ ] tests passing 100% (count increased by ≥20)
- [ ] check:reo green
- [ ] STATUS.md updated
- [ ] LOOP-M-SPEC.md status row updated
- [ ] This file's frontmatter updated
- [ ] CHANGELOG.md "Unreleased" entry with verbatim OMB M-17-12 §V citation
- [ ] Commit with slice ID
- [ ] Commit amended with hash
- [ ] Pushed to origin/main
- [ ] LOOP-M-RISKS.md updated with new risks

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard).
2. Read this file.
3. Read `cloud-evidence/docs/loops/LOOP-M-SPEC.md` §1, §3, §4, §5 (M.M4 sub-section), §12 (verbatim M-17-12 §V).
4. Read `cloud-evidence/docs/slices/M/M.M1.md` (SORN snapshot pattern) + `M.M3.md` (PT-7 sensitive categories).
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
6. Read `cloud-evidence/core/ssp-docx.ts` (deterministic OOXML zip-store reference).
7. Read `cloud-evidence/core/oscal-poam.ts` (POA&M finding emit point for SORN-amendment).
8. Download OMB M-17-12 PDF into `cloud-evidence/docs/sources/omb-m-17-12.pdf` if not already present.
9. Begin implementation; update Implementation log at every milestone.

---
