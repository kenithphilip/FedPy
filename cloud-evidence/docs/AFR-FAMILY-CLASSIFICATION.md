# AFR-* family classification at FedRAMP 20x Moderate

> **Status:** R1 deliverable (research blocker for LOOP-G). Generated directly
> from `cloud-evidence/docs/frmr-requirements.generated.json` (which itself is
> extracted from the authoritative `FRMR.documentation.json` published at
> [github.com/FedRAMP/docs](https://github.com/FedRAMP/docs), v0.9.43-beta).
>
> **Bottom line:** All ten AFR-* families are **REQUIRED** at Moderate — every
> family contains at least one MUST entry that applies at the Moderate impact
> level. None are optional or recommended-only.

---

## Why this document exists

The deep-research synthesis flagged AFR family classification (REQUIRED vs
RECOMMENDED) as an open question — the research run examined the RFC-level
documents (RFC-0006, RFC-0014, RFC-0024) but did not walk the FRMR machine-
readable catalog directly. This document does that walk, so we have a
defensible source-of-truth answer before building LOOP-G (AFR family
emitters: FSI inbox integration, ICP template, ADS sharing, MAS scope doc,
SCG guide, CCM emitter).

---

## Method

1. Read `cloud-evidence/docs/frmr-requirements.generated.json` (10,189 lines,
   complete extracted FRMR catalog).
2. Filter to entries whose `family` field is one of the ten AFR sub-family
   codes: PVA, FSI, ICP, ADS, MAS, CCM, SCG, SCN, VDR, UCM.
3. For each family, filter to entries where `levels.moderate.applies === true`
   (a `null` value means "derived from Rev5 / pending" — not yet applicable).
4. Bucket each Moderate-applicable entry by RFC 2119 key_word: MUST, SHOULD,
   MAY, OTHER.
5. A family is **REQUIRED** if it has ≥1 MUST entry at Moderate, **RECOMMENDED**
   if it has 0 MUST but ≥1 SHOULD, **OPTIONAL** if only MAY entries.
6. Per actor (CSO, CSX, FRP, AGM, TPX, TRC, UTC, ADP, TRF, OAR, QTR, CSL,
   EVA, RPT), classify whether the obligation is on the CSP (our build
   target), 3PAO, FedRAMP PMO, or another party.

The script that performed this walk is reproducible inline (see Appendix A).

---

## Summary table

| Family | Full name | Mod-applicable entries | MUST | SHOULD | MAY | **Classification** | Primary actors |
|---|---|---|---|---|---|---|---|
| **PVA** | Persistent Validation and Assessment | 18 | 12 | 2 | 2 | **REQUIRED** | CSX (CSP-with-extensions), TPX (3PAO-with-extensions) |
| **FSI** | FedRAMP Security Inbox | 16 | 13 | 2 | 1 | **REQUIRED** | CSO (CSP), FRP (FedRAMP PMO) |
| **ICP** | Incident Communications Procedures | 9 | 6 | 2 | 0 | **REQUIRED** | CSX (CSP) |
| **ADS** | Authorization Data Sharing | 20 | 14 | 5 | 1 | **REQUIRED** | CSO/CSX/CSL (CSP), TRC/UTC (Trust Center) |
| **MAS** | Minimum Assessment Scope | 5 | 4 | 0 | 1 | **REQUIRED** | CSO (CSP) |
| **CCM** | Continuous Monitoring | 24 | 10 | 6 | 4 | **REQUIRED** | OAR (Ongoing Authorization Reports), QTR (Quarterly), AGM (Agency) |
| **SCG** | Secure Configuration Guide | 9 | 2 | 7 | 0 | **REQUIRED** | CSO (CSP) |
| **SCN** | Significant Change Notification | 17 | 11 | 1 | 4 | **REQUIRED** | CSO (CSP), TRF (Transformation-related), ADP (Authorizing Data Party) |
| **VDR** | Vulnerability Detection and Response | 39 | 12 | 18 | 5 | **REQUIRED** | CSO (CSP), EVA (Evaluator), RPT (Reporter), AGM (Agency) |
| **UCM** | Using Cryptographic Modules | 3 | 1 | 2 | 0 | **REQUIRED** | CSX (CSP) |
| **TOTAL** | | **160** | **85** | **45** | **23** | All REQUIRED | |

---

## Per-family MUST entries (CSP-actionable items in **bold**)

Listings show the FRMR id, the actor responsible, the legacy FRR id (`fka`),
and the requirement name. **Bold** = the CSP must implement this (CSO / CSX
/ CSL actor); plain text = some other party must implement.

### PVA — Persistent Validation and Assessment
- **PVA-CSX-FAV** (CSX, FRR-PVA-02): Issues As Vulnerabilities
- **PVA-CSX-IVV** (CSX, FRR-PVA-05): Independent Verification and Validation
- **PVA-CSX-NMV** (CSX, FRR-PVA-TF-LO-01,FRR-PVA-TF-MO-01): Non-Machine Validation
- **PVA-CSX-PMV** (CSX, FRR-PVA-TF-LO-02,FRR-PVA-TF-MO-02): Persistent Machine Validation
- **PVA-CSX-RPV** (CSX, FRR-PVA-03): Report Persistent Validation
- **PVA-CSX-VAL** (CSX, FRR-PVA-01): Persistent Validation
- PVA-TPX-MME (TPX/3PAO, FRR-PVA-13): Mixed Methods Evaluation
- PVA-TPX-OUC (TPX/3PAO, FRR-PVA-12): Outcome Consistency
- PVA-TPX-PAD (TPX/3PAO, FRR-PVA-16): Procedure Adherence
- PVA-TPX-PDK (TPX/3PAO, FRR-PVA-11): Processes Derived from Key Security Indicators
- PVA-TPX-SUM (TPX/3PAO, FRR-PVA-17): Assessment Summary
- PVA-TPX-UNP (TPX/3PAO, FRR-PVA-10): Underlying Processes

> **Build implication for LOOP-G:** The 6 CSX entries are CSP-side. We already
> ship `core/pva-collector.ts` and `core/csx-sum-aggregator.ts`; verify those
> cover FAV (issues-as-vulns), IVV (independent verification), NMV
> (non-machine validation = process-artifact KSIs), PMV (persistent machine
> validation = all the cloud collectors), RPV (reporting), VAL (the
> overarching persistent-validation obligation). The 6 TPX entries are
> 3PAO-side — surface them in the assessor UI but do not auto-fulfill.

### FSI — FedRAMP Security Inbox
- **FSI-CSO-CRA** (CSO, FRR-FSI-14): Complete Required Actions
- **FSI-CSO-EMR** (CSO, FRR-FSI-15): Emergency Message Routing
- **FSI-CSO-INB** (CSO, FRR-FSI-09): Maintain a FedRAMP Security Inbox
- **FSI-CSO-NOC** (CSO, FRR-FSI-12): Notification of Changes
- **FSI-CSO-RCV** (CSO, FRR-FSI-11): Receive Email Without Disruption
- **FSI-CSO-TFG** (CSO, FRR-FSI-10): Trust @fedramp.gov and @gsa.gov
- FSI-FRP-CDS (FRP/PMO, FRR-FSI-02): Criticality Designators
- FSI-FRP-COR (FRP/PMO, FRR-FSI-07): Explain Corrective Actions
- FSI-FRP-ERT (FRP/PMO, FRR-FSI-06): Elevated Reaction Timeframes
- FSI-FRP-PNT (FRP/PMO, FRR-FSI-04): Public Notice of Emergency Tests
- FSI-FRP-RQA (FRP/PMO, FRR-FSI-05): Required Actions
- FSI-FRP-UFS (FRP/PMO, FRR-FSI-03): Use FedRAMP_Security Email in Emergencies
- FSI-FRP-VRE (FRP/PMO, FRR-FSI-01): Verified Emails

> **Build implication for LOOP-G.G1 (AFR-FSI integration):** 6 CSO entries
> are CSP-side. The system must (a) maintain a verified email inbox endpoint
> the CSP commits to monitoring, (b) auto-route emergency FedRAMP messages,
> (c) trust @fedramp.gov / @gsa.gov inbound, (d) notify FedRAMP when the
> inbox configuration changes, (e) provide receipt confirmation, (f) close
> the loop on FedRAMP-required actions. This is more than a webhook — it's
> a managed inbox with SLA. Likely implementation: tracker DB table for
> inbox-config + email-receipt-log + FedRAMP-action-tracking.

### ICP — Incident Communications Procedures
- **ICP-CSX-FIR** (CSX, FRR-ICP-07): Final Incident Report
- **ICP-CSX-ICU** (CSX, FRR-ICP-04): Incident Updates
- **ICP-CSX-IRA** (CSX, FRR-ICP-02): Incident Reporting to Agencies
- **ICP-CSX-IRC** (CSX, FRR-ICP-03): Incident Reporting to CISA
- **ICP-CSX-IRF** (CSX, FRR-ICP-01): Incident Reporting to FedRAMP
- **ICP-CSX-RPT** (CSX, FRR-ICP-05): Incident Report Availability

> **Build implication for LOOP-G.G2 (AFR-ICP):** All 6 MUST entries are CSP-
> side. Need (1) incident reporting templates that route to FedRAMP, CISA,
> and authorizing agencies; (2) incident update workflow; (3) final incident
> report archival + availability. Tracker DB tables: incidents, incident-
> updates, incident-final-reports.

### ADS — Authorization Data Sharing
- ADS-CSL-TCM (CSL/Cloud-Service-Legacy, FRR-ADS-08): Trust Center Migration
- ADS-CSL-UCP (CSL, FRR-ADS-06): USDA Connect
- **ADS-CSO-CBF** (CSO, FRR-ADS-02): Consistency Between Formats
- **ADS-CSO-HAD** (CSO, FRR-ADS-09): Historical Authorization Data
- **ADS-CSO-PUB** (CSO, FRR-ADS-01): Public Information
- **ADS-CSO-RIS** (CSO, FRR-ADS-05): Responsible Information Sharing
- **ADS-CSO-SVC** (CSO, FRR-ADS-03): Service List
- **ADS-CSX-UTC** (CSX, FRR-ADS-07): Use Trust Centers
- ADS-TRC-AAI (TRC/Trust-Center, FRR-ADS-TC-05): Agency Access Inventory
- ADS-TRC-ACL (TRC, FRR-ADS-TC-06): Access Logging
- ADS-TRC-PAC (TRC, FRR-ADS-TC-03): Programmatic Access
- ADS-TRC-USH (TRC, FRR-ADS-04): Uninterrupted Sharing
- ADS-UTC-AAD (UTC/Using-Trust-Center, ADS-CSO-AAD): Agency Access Denial
- ADS-UTC-PGD (UTC, FRR-ADS-AC-01,ADS-CSO-PGD): Public Guidance

> **Build implication for LOOP-G.G3 (AFR-ADS):** 6 CSO/CSX entries are CSP-
> side. Need (1) format-consistent publication of authorization data; (2)
> historical authorization archive; (3) public-info disclosure mechanism;
> (4) responsible-info-sharing policy enforcement; (5) machine-readable
> service-list publication; (6) Trust Center usage workflow. TRC and UTC
> entries are for Trust Center operators (not us); CSL entries are legacy-
> repo-related (typically not us either, unless we run a self-managed repo).

### MAS — Minimum Assessment Scope
- **MAS-CSO-FLO** (CSO, FRR-MAS-05): Information Flows and Security Objectives
- **MAS-CSO-IIR** (CSO, FRR-MAS-01): Identify Information Resources
- **MAS-CSO-MDI** (CSO, FRR-MAS-04): Metadata Inclusion
- **MAS-CSO-TPR** (CSO, FRR-MAS-03,FRR-MAS-02): Third-Party Information Resources

> **Build implication for LOOP-G.G4 (AFR-MAS):** All 4 MUST entries are CSP-
> side. Need (1) information-flow diagram + security objective tagging; (2)
> information-resource inventory (already partially have via Appendix M); (3)
> metadata inclusion in scope doc; (4) third-party resource enumeration
> (already partial via subprocessors-sheet.ts). The current
> `core/signal-emitter.ts` MAS placeholder needs to mature into a real scope
> doc generator that produces all four artifacts.

### CCM — Continuous Monitoring (the heavyweight)
- CCM-AGM-NFA (AGM/Agency, FRR-CCM-AG-07): Notify FedRAMP After Requests
- CCM-AGM-NFR (AGM/Agency, FRR-CCM-AG-05): Notify FedRAMP of Concerns
- CCM-AGM-ROR (AGM/Agency, FRR-CCM-AG-01): Review Ongoing Reports
- CCM-OAR-AFS (OAR, FRR-CCM-05): Anonymized Feedback Summary
- CCM-OAR-AVL (OAR, FRR-CCM-01): Report Availability
- CCM-OAR-FBM (OAR, FRR-CCM-04): Feedback Mechanism
- CCM-OAR-NRD (OAR, FRR-CCM-03): Next Report Date
- CCM-QTR-MTG (QTR, FRR-CCM-QR-01,FRR-CCM-QR-02): Quarterly Review Meeting
- CCM-QTR-NRD (QTR, FRR-CCM-QR-06): Next Review Date
- CCM-QTR-REG (QTR, FRR-CCM-QR-05): Meeting Registration Info

> **Build implication for LOOP-G.G6 (AFR-CCM):** This is the trickiest of
> the family. The OAR (Ongoing Authorization Report) entries are about the
> CSP publishing monthly/quarterly reports with feedback mechanisms + next-
> report dates. The QTR (Quarterly Review) entries are about scheduling and
> running quarterly review meetings — partly CSP-driven, partly PMO-driven.
> The AGM entries are agency-side. The CSP-actionable items are: report
> publishing (already partial via existing reports), feedback mechanism
> (new — needs tracker UI), next-report-date scheduling (new), quarterly
> meeting registration/scheduling (new). Closely tied to LOOP-E (ConMon
> agent).

### SCG — Secure Configuration Guide
- **SCG-CSO-AUP** (CSO, no-fka): Use Instructions
- **SCG-CSO-RSC** (CSO, FRR-RSC-01..03): Recommended Secure Configuration

> **Build implication for LOOP-G.G5 (AFR-SCG):** Both MUSTs are CSP-side.
> Need (1) use-instructions document explaining how to securely configure +
> use the offering; (2) the recommended secure configuration itself
> (probably the existing reference-arch.ts output extended to a full SCG
> document with FedRAMP-Moderate-baseline-aligned defaults).

### SCN — Significant Change Notification
- ADP entries: 1 MUST (notification requirements for Authorizing Data Parties)
- **CSO entries: 5 MUSTs** — Evaluate Changes, Historical Notifications,
  Human-and-Machine-Readable, Required Information, Maintain Audit Records
- TRF entries: 5 MUSTs (Transformation-Related actors — partial CSP, partial
  FedRAMP)

> **Build implication:** We already have `core/scn-classifier.ts`. The CSO
> MUSTs require: (1) change-evaluation workflow (the classifier does this);
> (2) historical-notification archive (tracker DB); (3) human-and-machine-
> readable notification format (we emit JSON + markdown — verify .docx is
> covered too); (4) all required information per SCN-CSO-INF (we should
> validate the classifier output against this schema); (5) audit records
> (signed evidence + manifest). LOOP-E.E6 will close this.

### VDR — Vulnerability Detection and Response (the biggest)
- VDR-AGM-NFR (AGM/Agency): Notify FedRAMP
- **VDR-CSO-DET** (CSO, FRR-VDR-01): Vulnerability Detection — covered by `vdr-scan.ts`
- **VDR-CSO-DOC** (CSO, FRR-VDR-11): Documentation for Recommendations
- **VDR-CSO-RES** (CSO, FRR-VDR-02): Vulnerability Response
- VDR-EVA-EIR (EVA/Evaluator, FRR-VDR-08): Evaluate Internet-Reachability
- VDR-EVA-ELX (EVA, FRR-VDR-07): Evaluate Exploitability
- VDR-EVA-EPA (EVA, FRR-VDR-09): Estimate Potential Adverse Impact
- VDR-RPT-AVI (RPT/Reporter, FRR-VDR-RP-06): Accepted Vulnerability Info
- VDR-RPT-PER (RPT, FRR-VDR-RP-01): Persistent Reporting

> **Build implication:** Most are already covered or close to it. The 3 EVA
> entries (evaluate internet-reachability, exploitability, potential adverse
> impact) feed into LOOP-B.B1 (CVSS+EPSS+criticality+exposure scoring) and
> LOOP-B.B2 (deadline math). VDR-CSO-DOC (documentation for recommendations)
> is a new artifact need.

### UCM — Using Cryptographic Modules
- **UCM-CSX-FIP** (CSX, FRR-UCM-01): FIPS-validated cryptographic modules

> Already covered by `providers/azure/crypto.ts` and equivalents for AWS/GCP.

---

## Cross-family deliverables we already partially have (post-INV-S6 baseline)

| Family | Existing coverage | LOOP-G gap to close |
|---|---|---|
| PVA | `core/pva-collector.ts`, `core/csx-sum-aggregator.ts` | Verify 6 CSX MUSTs are each addressed; surface 6 TPX MUSTs in 3PAO UI |
| FSI | none | Inbox endpoint + email-routing config + receipt log + action tracking |
| ICP | none | Incident templates + tracker tables + routing to FedRAMP/CISA/agency |
| ADS | `core/signal-emitter.ts` placeholder | Real publishing mechanism: service list, public info, historical archive |
| MAS | `core/signal-emitter.ts` placeholder | Real scope doc: info-flow diagram, IR inventory, metadata, 3rd-party |
| CCM | partial (reports exist) | Report publication SLAs, feedback mechanism, next-date, quarterly meeting hooks |
| SCG | `providers/*/reference-arch.ts` partial | Full SCG doc + secure-configuration recommendations |
| SCN | `core/scn-classifier.ts` | .docx template + audit-records archive (LOOP-E.E6) |
| VDR | `providers/*/vdr-scan.ts` + CISA KEV reconcile | Recommendation-documentation + EVA evaluator hooks |
| UCM | `providers/azure/crypto.ts` (+ AWS/GCP equivalents) | Done |

---

## Decision: LOOP-G scope is confirmed

The deep-research open-question is **resolved**: all 10 AFR families are
REQUIRED at Moderate. LOOP-G slices G1 through G6 stay as planned:

- **G1: AFR-FSI** — REQUIRED. 6 CSP MUSTs. Inbox + routing + receipt + action.
- **G2: AFR-ICP** — REQUIRED. 6 CSP MUSTs. Incident reporting templates +
  workflow.
- **G3: AFR-ADS** — REQUIRED. 6 CSP MUSTs. Authorization data publication.
- **G4: AFR-MAS** — REQUIRED. 4 CSP MUSTs. Minimum assessment scope doc.
- **G5: AFR-SCG** — REQUIRED. 2 CSP MUSTs. Secure configuration guide.
- **G6: AFR-CCM** — REQUIRED. CSP-actionable subset: report publishing,
  feedback, next-date scheduling, quarterly-meeting integration. (Closely
  tied to LOOP-E.)

No AFR family can be deprioritized as OPTIONAL.

---

## Appendix A — reproducing this analysis

```bash
cd cloud-evidence
node -e "
const data = JSON.parse(require('fs').readFileSync('docs/frmr-requirements.generated.json', 'utf8'));
const FAMILIES = ['PVA','FSI','ICP','ADS','MAS','CCM','SCG','SCN','VDR','UCM'];
for (const fam of FAMILIES) {
  const mustsMod = data.filter(r => r.family === fam
    && r.levels?.moderate?.applies === true
    && (r.levels?.moderate?.key_word || r.key_word || '').toUpperCase() === 'MUST');
  console.log(fam + ': ' + mustsMod.length + ' MUST');
}
"
```

The per-run snapshot is committed at `cloud-evidence/docs/afr-classification.json`
for reproducibility.

---

## Open questions remaining

None for AFR classification. The remaining 3 pre-loop research items (R2:
POA&M delta format, R3: Phase-Two pilot output, R4: sample selection
methodology) are unblocked from LOOP-G and addressed independently.
