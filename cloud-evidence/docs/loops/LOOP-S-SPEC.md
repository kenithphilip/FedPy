---
loop_id: S
title: DFARS 252.204-7012 Cloud Equivalency for DoD-prime customers
status: pending
applicable_conditional: true
condition: CSP has at least one DoD-prime customer (i.e. the CSP processes, stores, or transmits Covered Defense Information / Controlled Unclassified Information for a contractor performing a DoD prime contract subject to DFARS Subpart 204.73)
trigger_flag: "--dfars-equivalency"
trigger_env: CLOUD_EVIDENCE_DFARS_EQUIVALENCY
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A3, LOOP-A.A4, G.G2, M.M4]
blocks: []
estimated_effort: 3 weeks (single implementer, conditional)
last_updated: 2026-06-07
---

# LOOP-S — DFARS 252.204-7012 Cloud Equivalency for DoD-prime customers

> Comprehensive implementation specification for the three slices in LOOP-S.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-S end-to-end by reading ONLY this file + the three supporting
> files cited in Section 2 ("Dependencies"). No prior conversation history
> required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence or
> operator-supplied configuration. Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.
>
> **APPLICABILITY GATE — READ FIRST.** LOOP-S is **conditional**: it applies
> ONLY when the operating CSP has at least one DoD-prime customer (i.e. a
> contractor performing a DoD prime contract subject to DFARS Subpart 204.73
> who stores, processes, or transmits Covered Defense Information / CUI on
> the CSP). For CSPs whose customer base is entirely civilian-agency, LOOP-S
> is a no-op: the slices ship, the artifacts simply do not generate (the
> orchestrator's `--dfars-equivalency` flag is not set, the conditional
> emitter exits 0 with an explanatory `coverage:skipped` log line). When the
> flag IS set, every emitted artifact must trace to real FedRAMP Moderate
> evidence that the existing collectors already produce — LOOP-S does NOT
> introduce new evidence collection. It introduces **attestation, crosswalk,
> and reporting** artifacts that re-express the Moderate evidence in the
> DFARS / DoD CIO Memorandum form.

---

## 1. Why this loop exists

### The gap LOOP-A through LOOP-R left open

LOOP-A through LOOP-R deliver a complete FedRAMP Moderate authorization
package — SSP, SAP, AR, POA&M, IIW, RoE, ConMon agent, AFR family
deliverables, CRM (LOOP-L), Privacy package (LOOP-M), Threat Model
(LOOP-N), AI/ML governance (LOOP-O), Insider Threat (LOOP-P), and
Marketplace publication (LOOP-Q). The package is sufficient for any
**civilian-agency** customer authorizing the CSP through the FedRAMP
PMO or under an agency-led ATO.

For **DoD-prime customers** — contractors performing a Department of
Defense prime contract that processes Controlled Unclassified Information
(CUI) / Covered Defense Information (CDI) on a non-DoD cloud — the
contractual obligation is different. DFARS Subpart 204.73 and the
contract clause **DFARS 252.204-7012 (Safeguarding Covered Defense
Information and Cyber Incident Reporting)** require the prime to ensure
that any cloud service it uses meets:

> "security requirements equivalent to those established by the Government
> for the Federal Risk and Authorization Management Program (FedRAMP)
> Moderate baseline (https://www.FedRAMP.gov) and that the cloud service
> provider complies with requirements in paragraphs (c) through (g) of this
> clause for cyber incident reporting, malicious software, media
> preservation and protection, access to additional information and
> equipment necessary for forensic analysis, and cyber incident damage
> assessment."

— **DFARS 252.204-7012(b)(2)(ii)(D)**, see
https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting

The DoD CIO clarified the equivalency criteria in a memorandum dated
**December 21, 2023** ("FedRAMP Moderate Equivalency for Cloud Service
Providers in Support of the DoD"), which requires:

1. A **Body of Evidence (BoE)** demonstrating that every FedRAMP Moderate
   control is implemented — i.e. the full Moderate baseline (323 controls
   for Rev 5).
2. The BoE must be assessed by a **3PAO** (the same 3PAO ecosystem that
   FedRAMP accredits via A2LA).
3. The CSP must demonstrate compliance with **DFARS 252.204-7012(c)
   through (g)** — the operational obligations beyond control
   implementation: 72-hour cyber-incident reporting to DC3 via
   https://dibnet.dod.mil/, malicious-software submission, 90-day media
   preservation, access for forensic analysis, and cyber-incident damage
   assessment.

In addition, the DoD ecosystem layers on **NIST SP 800-171 Rev 3** (May
2024) as the canonical control set for non-federal systems processing CUI.
800-171 is tailored from NIST 800-53 — it removes controls marked FED
(only-federal), NCO (non-CUI-only), or NFO (expected of any prudent
information system) and re-organizes the residual into 17 control
families (Rev 3) of 110 base requirements plus organizationally-defined
parameters.

Three gaps are left open by the existing FedRAMP Moderate package:

1. **No NIST 800-171 ↔ NIST 800-53 / FedRAMP Moderate crosswalk.** A
   DoD-prime customer needs to see, for each 800-171 requirement, which
   FedRAMP Moderate evidence already covers it and which still needs
   prime-specific coverage. The existing `core/control-benchmark.ts`
   benchmarks against NIST 800-53 Rev 5 only; there is no 800-171 view.
2. **No DFARS 252.204-7012(c) cyber-incident reporting tooling.** The
   prime must report a cyber incident affecting CDI within **72 hours**
   of discovery to the **DoD Cyber Crime Center (DC3)** via
   https://dibnet.dod.mil/. The existing LOOP-G.G2 incident-response
   collector and LOOP-M.M4 privacy breach-notification logic do not know
   about the DC3 endpoint, the DFARS-required Incident Collection Format
   (ICF) fields, or the prime-vs-CSP attribution that 7012(c)(2)(ii)
   requires.
3. **No DoD CIO Equivalency Memorandum attestation package.** The Dec 21
   2023 memorandum prescribes a specific package shape: an Equivalency
   Letter signed by an officer of the CSP, the FedRAMP package, the BoE
   crosswalk, the 3PAO's equivalency assessment letter, and a written
   incident-response runbook tied to DFARS 7012(c)-(g). The existing
   LOOP-A.A4 submission bundler emits a generic FedRAMP-shaped archive
   that doesn't include the DoD-specific overlay.

### Artifacts LOOP-S delivers

| # | Artifact | Source | Consumer |
|---|---|---|---|
| 1 | `core/dfars-crosswalk.ts` — extends `core/control-benchmark.ts` to express results in NIST 800-171 Rev 3 terms | LOOP-S.S1 | `out/dfars-crosswalk.json`, `out/dfars-crosswalk.xlsx`, DoD-prime customer review |
| 2 | `out/dfars-crosswalk.json` + `.xlsx` — per-800-171-requirement coverage report | LOOP-S.S1 | DoD-prime contracting officer, 3PAO equivalency assessor |
| 3 | `core/dfars-incident-reporting.ts` — DFARS 7012(c) Incident Collection Format builder + DC3 / DIBNet submission tooling | LOOP-S.S2 | DC3 (https://dibnet.dod.mil/), CSP CISO, prime CSIRT |
| 4 | `out/dfars-incident-report-{uuid}.json` + `.docx` — per-incident DFARS-shaped report | LOOP-S.S2 | DC3, prime, CSP audit log |
| 5 | `core/dfars-equivalency-attestation.ts` — Equivalency Letter + BoE bundler per DoD CIO Memo | LOOP-S.S3 | DoD CIO, prime contracting officer, 3PAO |
| 6 | `out/dfars-equivalency-letter.docx` + manifest | LOOP-S.S3 | DoD-prime customer deliverable archive |

### Authorization-package gaps closed

| Package gap | Slice | Authoritative source |
|---|---|---|
| 800-171 Rev 3 ↔ FedRAMP Moderate crosswalk absent | S.S1 | DoD CIO Memo Dec 21 2023; NIST SP 800-171 Rev 3 (May 2024) |
| 72-hour DC3 incident report path missing | S.S2 | DFARS 252.204-7012(c)(1); DoD Mandatory Cyber Incident Reporting Procedures; https://dibnet.dod.mil/ |
| DoD CIO Equivalency package overlay missing | S.S3 | DoD CIO Memo Dec 21 2023; DoD CC SRG v1r4 |

---

## 2. Dependencies

### Loops / slices that MUST complete first

| Dep | Why |
|---|---|
| LOOP-A.A1 (`core/oscal-poam.ts`) | S.S1 reads POA&M evidence per FedRAMP Moderate control to express 800-171 coverage. |
| LOOP-A.A2 (`core/oscal-sap.ts`) | S.S3 references the assessor's SAP as the basis for the 3PAO equivalency assessment letter. |
| LOOP-A.A3 (`core/oscal-ar.ts` chain) | S.S1 reads AR evidence per control to determine 800-171 coverage status (satisfied / partially / not-satisfied). |
| LOOP-A.A4 (`core/submission-bundle.ts`) | S.S3 extends `WELL_KNOWN` with five new DFARS roles and reuses the bundler's signed-archive pipeline. |
| `core/control-benchmark.ts` (existing) | S.S1 extends this module — adds an `'800-171-r3'` framework + the per-family roll-up. The existing `BenchmarkFramework` enum gains a third member. |
| LOOP-G.G2 (incident-response collector) | S.S2 reads existing incident records the operator captures in the tracker via G.G2 UI and re-expresses them in the DFARS Incident Collection Format (ICF). |
| LOOP-M.M4 (privacy breach-notification logic) | S.S2 cross-references — when an incident affects both PII (M.M4) and CUI (S.S2), BOTH reports trigger; S.S2's emitter must coordinate so the operator submits the right report to the right authority. |
| `core/nist-r5.ts` | S.S1 reads NIST 800-53 Rev 5 control catalog to perform the 800-171 → 800-53 mapping NIST's Appendix B publishes. |
| `inventory.json` | S.S1 references `inventory.assets[].data_classification` to identify which assets process CUI; only those assets are in DFARS scope. |
| Tracker DB | S.S2's incident-report records persist in `tracker/server/schema.sql` with signed audit trail; S.S3's officer signature on the Equivalency Letter persists as a signed action record. |

### Existing files this loop EXTENDS

| File | Modification |
|---|---|
| `cloud-evidence/core/control-benchmark.ts` | (S.S1) Add `'800-171-r3'` to `BenchmarkFramework`; add `loadNist800171Catalog()` (reads `docs/nist-800-171-r3.generated.json`); add `crosswalkTo800171()` that maps benchmark results from 800-53 Rev 5 to 800-171 Rev 3 via NIST's Appendix B mapping. |
| `cloud-evidence/core/envelope.ts` | (S.S2) Add `cui_affected?: boolean` + `cdi_affected?: boolean` flags to the `Incident` interface so collectors / operators can tag CUI scope explicitly. |
| `cloud-evidence/core/orchestrator.ts` | Add `--dfars-equivalency` flag + env `CLOUD_EVIDENCE_DFARS_EQUIVALENCY`. When set, runs the three S slice emitters in order S.S1 → S.S2 → S.S3 after the POA&M emitter. |
| `cloud-evidence/core/submission-bundle.ts` | (S.S3) Add roles `dfars-crosswalk-json`, `dfars-crosswalk-xlsx`, `dfars-equivalency-letter-docx`, `dfars-equivalency-manifest-json`, `dfars-incident-report-bundle` to `WELL_KNOWN`. |
| `cloud-evidence/CHANGELOG.md` | Unreleased entry per slice (see Section 8). |
| `cloud-evidence/docs/STATUS.md` | Per-slice status line updated when slice ships. Add a "LOOP-S (conditional, DoD-prime only)" header so the gate is visible. |
| `tracker/server/schema.sql` | (S.S2) Tables `dfars_incidents`, `dfars_incident_submissions`, `dfars_incident_artifacts`. (S.S3) Table `dfars_equivalency_attestations`. |
| `tracker/server/index.ts` | Mount `routes/dfars-incidents.ts` and `routes/dfars-equivalency.ts`. |
| `tracker/client/src/App.tsx` | Add routes `/dfars/incidents`, `/dfars/equivalency`. Gated behind a configuration check — the routes are hidden when `DFARS_ENABLED=false` so non-DoD-prime tenants don't see the noise. |

### Loops UNBLOCKED when LOOP-S is complete

| Unblocked loop | Reason |
|---|---|
| LOOP-Q.Q1 — Marketplace metadata emitter | When DFARS is enabled, the Marketplace metadata gains a `dod_equivalency: true` field with the URL of the equivalency letter (so DoD-prime buyers can discover the CSP). |
| LOOP-H.H1 — Long-term storage | The DFARS Incident Collection Format records (S.S2) have a 6-year retention policy (DoD record-management) which slots into LOOP-H's long-term-storage classifier. |
| LOOP-E.E5 — Deviation Request emitter | When a 800-171 requirement is `not-satisfied` (S.S1), the deviation-request flow needs an "800-171 mitigation" choice in addition to the FedRAMP CMP choice — easy extension when S.S1 ships first. |

### Loops LOOP-S explicitly does NOT depend on

- **LOOP-O (AI/ML Governance)** — DFARS 7012 is silent on AI; no
  cross-references.
- **LOOP-P (Insider Threat)** — the DFARS 7012(c) trigger for CUI loss
  via insider action flows through the same S.S2 ICF path as any other
  incident; P-slices are not in S's critical dependency tree.
- **LOOP-N (Threat Model)** — N produces a STRIDE-shaped artifact that
  helps with FAR 52.204-21 baseline compliance; S relies on Moderate
  evidence only.

---

## 3. Authoritative sources

Every URL + spec referenced in any LOOP-S slice. All quotes are verbatim
where retrievable. Where the source PDF returns HTTP 403 to anonymous
fetches (DoD CC SRG v1r4, DoD CIO Memorandum), the slice records the URL
+ the implementer must download the PDF from the cited URL into
`cloud-evidence/docs/sources/` and re-quote in the slice docstring.

### DFARS clauses (acquisition.gov authoritative)

- **DFARS 252.204-7012 — Safeguarding Covered Defense Information and
  Cyber Incident Reporting** —
  https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting
  - Definitions (paragraph (a)):
    > "Covered defense information" means unclassified controlled
    > technical information or other information, as described in the
    > Controlled Unclassified Information (CUI) Registry at
    > http://www.archives.gov/cui/registry/category-list.html, that
    > requires safeguarding or dissemination controls pursuant to and
    > consistent with law, regulations, and Governmentwide policies, and
    > is — (1) Marked or otherwise identified in the contract, task
    > order, or delivery order and provided to the contractor by or on
    > behalf of DoD in support of the performance of the contract; or
    > (2) Collected, developed, received, transmitted, used, or stored
    > by or on behalf of the contractor in support of the performance of
    > the contract.
    > "Cyber incident" means actions taken through the use of computer
    > networks that result in a compromise or an actual or potentially
    > adverse effect on an information system and/or the information
    > residing therein.
  - Equivalency (paragraph (b)(2)(ii)(D)) — quoted in §1.
  - Cyber incident reporting (paragraph (c)(1)(ii)):
    > "Rapidly report cyber incidents to DoD at
    > https://dibnet.dod.mil/."
  - 72-hour timing (paragraph (c)(1)(i)):
    > "Conduct a review for evidence of compromise of covered defense
    > information, including, but not limited to, identifying compromised
    > computers, servers, specific data, and user accounts."
    > (DC3 ICF training materials clarify "rapidly" as 72 hours from
    > discovery; see § DC3 ICF below.)
  - Subcontractor flow-down (paragraph (m)):
    > "Include the substance of this clause, including this paragraph
    > (m), in subcontracts ... when subcontract performance will involve
    > covered defense information or operationally critical support."

- **DFARS 252.204-7019 — Notice of NIST SP 800-171 DoD Assessment
  Requirements** —
  https://www.acquisition.gov/dfars/252.204-7019
  - Requires the contractor to have a current (within 3 years) NIST SP
    800-171 DoD Assessment posted in the Supplier Performance Risk System
    (SPRS) BEFORE the contract is awarded.
  - LOOP-S.S1's crosswalk gives the prime the data it needs to perform a
    Basic / Medium / High self-assessment per the DoD Assessment
    Methodology v1.2.1.

- **DFARS 252.204-7020 — NIST SP 800-171 DoD Assessment Requirements** —
  https://www.acquisition.gov/dfars/252.204-7020
  - Authorizes DoD to conduct higher-confidence (Medium / High)
    assessments and obligates the contractor to provide access. LOOP-S.S1's
    crosswalk provides the per-requirement evidence pointer such an
    assessment would inspect.

### NIST publications

- **NIST SP 800-171 Rev 3 — Protecting Controlled Unclassified
  Information in Nonfederal Systems and Organizations** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf
  - 110 base requirements organized into 17 families. Families (Rev 3):
    AC, AT, AU, CM, IA, IR, MA, MP, PE, PS, RA, CA, SC, SI, SR (added in
    Rev 3 to align with SP 800-53 SR family), and PL (added Rev 3),
    PM (added Rev 3).
  - Appendix B (Tailoring Criteria): for each 800-53 Rev 5 control, marks
    whether the control is in 800-171 (and any tailoring action),
    excluded as FED, excluded as NCO, excluded as NFO, or
    expressed-with-modification (CUI).
  - Appendix C maps every Rev 3 requirement to the Rev 5 controls that
    contribute. This mapping is the heart of S.S1's crosswalk.

- **NIST SP 800-171A Rev 3 — Assessment Procedures** —
  https://csrc.nist.gov/pubs/sp/800/171/A/r3/final
  - Per-requirement assessment objectives + methods (Examine /
    Interview / Test). S.S1 expresses each requirement's evidence
    pointer in 800-171A terminology so a 3PAO performing the equivalency
    assessment can directly use the artifact.

- **NIST SP 800-53 Rev 5** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - Control catalog the existing FedRAMP Moderate package implements.
    S.S1 reads `core/nist-r5.ts` for canonical control metadata and joins
    with the 800-171 Rev 3 Appendix C mapping.

- **NIST SP 800-53B** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53B.pdf
  - Moderate baseline definition. S.S1 uses
    `docs/nist-r5-baselines.generated.json` (already produced) for the
    Moderate membership.

### DoD-side authoritative documents

- **DoD CIO Memorandum, "FedRAMP Moderate Equivalency for Cloud Service
  Providers"** — dated December 21, 2023, published via
  https://dodcio.defense.gov/library/.
  - Three requirements quoted in §1: (1) BoE matching every Moderate
    control, (2) 3PAO assessment, (3) DFARS 7012(c)-(g) compliance.
  - The memo is published as a PDF (HTTP 403 to anonymous fetches in
    some configurations). The implementer downloads the PDF to
    `cloud-evidence/docs/sources/dod-cio-memo-fedramp-equivalency-2023-12-21.pdf`
    before writing S.S3.

- **DoD Cloud Computing Security Requirements Guide (CC SRG) v1r4** —
  https://dodcio.defense.gov/Portals/0/Documents/DD/CloudComputingSRG_v1r4.pdf
  - Defines IL2 / IL4 / IL5 / IL6 impact levels. CUI processed under
    DFARS 7012 cloud-equivalency rides on IL4-equivalent (FedRAMP
    Moderate + DFARS 7012(c)-(g)). S.S3's manifest cites IL4-equivalent
    as the operating level.

- **DC3 (DoD Cyber Crime Center) DIBNet portal** —
  https://dibnet.dod.mil/
  - Submission portal for DFARS 7012(c) reports. Authentication via
    DoD-approved Medium-Assurance ECA / DoD CAC certificate. S.S2's
    emitter does NOT auto-submit (REO Rule 4: human action) — it
    produces the report in the DC3 Incident Collection Format and the
    operator uploads it via the portal in the next operator-driven step.

- **DC3 Incident Collection Format (ICF)** — published as part of the
  DIBNet portal user guide; referenced in the DoD Procurement Toolbox at
  https://dodprocurementtoolbox.com/site-pages/dfars-cyber-reporting.
  - Required fields (verbatim ICF v3.0 schema labels): Company Name,
    DUNS, CAGE Code, Facility CAGE, Contract Numbers Affected (multi),
    Contracting Officer (POC), USG Program Manager (POC), Date Incident
    Discovered, Date Incident Occurred, Incident Location, Technique or
    Method Used, System Type, Incident Outcome, Type of Compromise,
    Description, Impact, Affected Defense Information, Number of
    Compromised Records, Forensic Information / Methods.

### CUI Registry + CFR

- **32 CFR Part 236 — Defense Industrial Base (DIB) Cybersecurity (CS)
  Program** —
  https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-M/part-236
  - Codifies DC3 authority + reporting mechanics. S.S2 cites §236.4
    (reporting required actions) in the per-incident docstring.

- **NARA CUI Registry — Controlled Unclassified Information Categories** —
  https://www.archives.gov/cui/registry/category-list
  - List of CUI categories. S.S1 references the list as the valid
    `data_classification` taxonomy when an asset is tagged `cui`. CUI
    sub-categories (CUI-CTI Controlled Technical Information, CUI-PRVCY,
    etc.) are operator-supplied via tag `fedramp_cui_category`.

### CMMC vs. NIST 800-171 distinction (scope guard)

LOOP-S addresses **NIST 800-171 / DFARS 252.204-7012 cloud equivalency**.
It does NOT address **CMMC (Cybersecurity Maturity Model Certification)**
certification:

- CMMC L1 (FAR-only) — out of LOOP-S scope.
- CMMC L2 (NIST 800-171 + 3rd-party C3PAO assessment) — adjacent but
  distinct. A CSP that wants CMMC L2 certification needs a C3PAO
  assessment; LOOP-S produces the BoE the C3PAO would inspect, but
  LOOP-S does not generate the CMMC L2 Plan of Action and Milestones in
  the eMASS / CMMC PIEE format. That work is filed under a future LOOP
  (out of scope here).
- CMMC L3 (110+ controls including 800-172) — out of LOOP-S scope.

The S slices cite this distinction in their docstrings so an operator
doesn't mistake the LOOP-S artifacts for CMMC certification evidence.

---

## 4. Per-slice implementation specs

### Slice S.S1 — NIST 800-171 Rev 3 → FedRAMP Moderate crosswalk emitter

**Why this slice**: A DoD-prime customer evaluating the CSP for
DFARS 7012 cloud equivalency needs a per-800-171 requirement coverage
report: which Moderate controls map to each 800-171 requirement, what is
the assessed status (satisfied / partially / not-satisfied / not-assessed)
per the existing AR + POA&M evidence, and where is the gap. Today,
`core/control-benchmark.ts` benchmarks against 800-53 only. S.S1 extends
it.

**Files to create**:
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-crosswalk.ts` — pure
  module: loads the NIST 800-171 Rev 3 catalog + Appendix C mapping (from a
  committed `docs/nist-800-171-r3.generated.json` produced by a one-shot
  extract script), reuses the `benchmarkControls` engine in
  `core/control-benchmark.ts`, projects results onto 800-171 requirements.
  Emits `out/dfars-crosswalk.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-crosswalk-xlsx.ts` — xlsx
  renderer following the existing pure-JS xlsx pattern
  (`core/inventory-workbook.ts`). Emits `out/dfars-crosswalk.xlsx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-800-171-r3.mjs` — one-shot
  catalog extractor (NIST publishes 800-171 Rev 3 as PDF + .docx +
  Appendix C .xlsx). Reads the published Appendix C .xlsx (downloaded
  from https://csrc.nist.gov/pubs/sp/800/171/r3/final into
  `docs/sources/nist-sp-800-171r3-AppendixC.xlsx`) and emits the typed
  JSON catalog at `docs/nist-800-171-r3.generated.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-crosswalk.test.ts` — ≥10
  tests covering: catalog load, requirement → control mapping, status
  derivation per the four control statuses, family roll-up totals,
  REQUIRES-OPERATOR-INPUT propagation for un-tagged CUI assets.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-crosswalk-xlsx.test.ts` — ≥4
  tests pinning the xlsx column schema + a SheetJS round-trip.

**Files to extend**:
- `cloud-evidence/core/control-benchmark.ts`:
  - Add `'800-171-r3'` to `BenchmarkFramework`.
  - Re-export `BenchmarkFramework` (and the `ControlResult` type) so
    `dfars-crosswalk.ts` doesn't re-declare them.
  - Document in the file's header docstring that 800-171 is a
    *derived* framework: the benchmark engine still scores controls in
    the 800-53 Rev 5 native space; the projection happens in
    `dfars-crosswalk.ts:projectToRequirement()`.
- `cloud-evidence/core/orchestrator.ts`:
  - Add `--dfars-equivalency` flag + env `CLOUD_EVIDENCE_DFARS_EQUIVALENCY`.
  - When set, runs `emitDfarsCrosswalk()` AFTER POA&M emission (so the
    crosswalk reads the freshly-emitted control evidence) and BEFORE
    `--bundle-submission` (so the bundler picks up the artifacts).
- `cloud-evidence/core/submission-bundle.ts`:
  - Add roles `dfars-crosswalk-json` (filename `dfars-crosswalk.json`)
    + `dfars-crosswalk-xlsx` (filename `dfars-crosswalk.xlsx`) to
    `WELL_KNOWN`.

**Schemas / standards**:
- **NIST SP 800-171 Rev 3 catalog shape** (after extraction):
  ```ts
  export interface Nist800171Requirement {
    requirement_id: string;        // "03.01.01"
    family: string;                 // "AC"
    family_name: string;            // "Access Control"
    title: string;
    statement: string;
    discussion: string;
    /** 800-53 Rev 5 controls this requirement derives from. */
    derived_from: string[];         // ["ac-1", "ac-2"]
    odp: Array<{                    // Organizationally-Defined Parameters
      id: string;
      label: string;
      type: 'organization-defined' | 'selection';
    }>;
  }
  ```
- **NIST SP 800-171A Rev 3 assessment objectives** — referenced for the
  operator's runbook; not loaded at runtime in S.S1 (deferred — see
  Section 6 Open Questions).
- **Coverage status mapping**:
  - All derived 800-53 controls `satisfied` → 800-171 requirement
    `satisfied`.
  - All derived 800-53 controls `not-satisfied` → 800-171 requirement
    `not-satisfied`.
  - Mixed → `partially-satisfied`.
  - All derived controls `not-assessed` → 800-171 requirement
    `not-assessed`.
  - If `derived_from` is empty (the 800-171 requirement has no 800-53
    mapping — rare, but possible for SR/PL controls Rev 3 adds), status
    is `REQUIRES-OPERATOR-INPUT` with a prop pointing to the operator's
    tracker entry.

**Build steps**:

1. **Catalog extraction**: write `scripts/extract-800-171-r3.mjs`. It
   reads `docs/sources/nist-sp-800-171r3-AppendixC.xlsx` using the
   existing xlsx reader (`core/xlsx-reader.ts` if present, else SheetJS).
   For each row: requirement id, family, family name, title, statement,
   derived 800-53 controls. The output is a typed JSON catalog written to
   `docs/nist-800-171-r3.generated.json`. The script is idempotent and
   re-runnable.

2. **Define types** in `core/dfars-crosswalk.ts`:
   ```ts
   export interface CrosswalkEntry {
     requirement_id: string;
     family: string;
     family_name: string;
     title: string;
     statement: string;
     /** The 800-53 Rev 5 controls NIST Appendix C maps to this requirement. */
     derived_from: string[];
     /** The benchmark result per derived 800-53 control. */
     derived_results: ControlResult[];
     /** Roll-up status derived per § Build step 4 below. */
     status: ControlStatus | 'requires-operator-input';
     /** Pointer back to FedRAMP evidence for the 3PAO. */
     evidence_pointers: {
       ksi_ids: string[];          // KSI envelopes that contributed
       observation_uuids: string[]; // OSCAL observation UUIDs
       poam_item_uuids: string[];  // OSCAL poam-item UUIDs (failing)
     };
     /** When CUI-scope, the CUI category from NARA registry. */
     cui_categories?: string[];    // operator-supplied via inventory tags
   }
   export interface DfarsCrosswalkResult {
     framework: 'nist-800-171-r3';
     generated_at: string;
     csp_name: string;             // from operator config
     dod_prime_customers: string[]; // operator-supplied
     totals: {
       in_scope: number;
       satisfied: number;
       partially_satisfied: number;
       not_satisfied: number;
       not_assessed: number;
       requires_operator_input: number;
     };
     by_family: Record<string, {
       in_scope: number;
       satisfied: number;
       partially: number;
       not_satisfied: number;
       not_assessed: number;
       requires_operator_input: number;
     }>;
     entries: CrosswalkEntry[];
     provenance: {
       emitter: 'dfars-crosswalk';
       emittedAt: string;
       sourceCalls: Array<{ kind: 'control-benchmark' | 'inventory' | 'poam' | '800-171-catalog'; path: string }>;
       signingKeyId: string;
     };
   }
   ```

3. **Pure builder**:
   ```ts
   export function buildDfarsCrosswalk(
     benchmark: ControlBenchmark,        // 800-53 Rev 5 Moderate result
     catalog: Nist800171Requirement[],
     inventory: InventorySnapshot,
     opts: { cspName: string; dodPrimeCustomers: string[] },
   ): DfarsCrosswalkResult;
   ```
   For each `Nist800171Requirement`:
   - Look up each entry in `derived_from` in `benchmark.controls[]`.
   - If `derived_from.length === 0` → status =
     `requires-operator-input`.
   - Else: collect the per-control `ControlResult` and roll up per
     § Build step 4.
   - Walk `inventory.assets[]` for assets whose `data_classification ===
     'cui'`. If none, the entire crosswalk is informational-only; the
     `dod_prime_customers` field is empty; emit a `coverage:skipped`
     log line. Otherwise: collect the `fedramp_cui_category` tags into
     `cui_categories[]` (deduplicated) and attach to the family-level
     roll-up.

4. **Roll-up algorithm**:
   ```ts
   function rollupStatus(controls: ControlResult[]): ControlStatus {
     if (controls.length === 0) return 'not-assessed';
     const sat = controls.filter(c => c.status === 'satisfied').length;
     const ns  = controls.filter(c => c.status === 'not-satisfied').length;
     const na  = controls.filter(c => c.status === 'not-assessed').length;
     const ps  = controls.filter(c => c.status === 'partially-satisfied').length;
     if (sat === controls.length) return 'satisfied';
     if (ns + ps === controls.length && ns === controls.length) return 'not-satisfied';
     if (na === controls.length) return 'not-assessed';
     return 'partially-satisfied';
   }
   ```

5. **Evidence pointer extraction**: walk the POA&M JSON
   (`out/poam.json`) — for each derived 800-53 control, list the
   `observation.uuid` + `poam-item.uuid` whose `related-observations[]`
   reference the control. The pointer is what a 3PAO uses to jump from
   the crosswalk to the underlying evidence.

6. **JSON emit**:
   ```ts
   export interface DfarsCrosswalkEmitOptions {
     outDir: string;
     benchmarkPath?: string;          // default: outDir/control-benchmark.json
     catalogPath?: string;            // default: docs/nist-800-171-r3.generated.json
     inventoryPath?: string;          // default: outDir/inventory.json
     poamPath?: string;               // default: outDir/poam.json
     cspName: string;
     dodPrimeCustomers: string[];
     runId: string;
   }
   export async function emitDfarsCrosswalk(opts: DfarsCrosswalkEmitOptions): Promise<DfarsCrosswalkResult>;
   ```
   Writes `out/dfars-crosswalk.json` with the `provenance` block per REO
   Rule 2.6. Picked up by `core/sign.ts` glob + included in the RFC 3161
   manifest.

7. **XLSX emit** in `core/dfars-crosswalk-xlsx.ts`. Columns:
   A. Family
   B. Requirement ID (e.g. 03.01.01)
   C. Requirement Title
   D. Status (satisfied / partial / not-satisfied / not-assessed / requires-operator-input)
   E. Derived NIST 800-53 Rev 5 Controls
   F. Per-control statuses (semicolon-joined)
   G. CUI Categories (when applicable)
   H. Evidence — KSI IDs
   I. Evidence — Observation UUIDs
   J. Evidence — POA&M Item UUIDs
   K. Statement (wrapped)
   L. Discussion (wrapped)
   Header row + per-family group totals + grand-total row.

8. **Bundler integration**: in `submission-bundle.ts`, the new roles land
   in the well-known catalogue:
   ```ts
   { role: 'dfars-crosswalk-json', filename: 'dfars-crosswalk.json', description: 'NIST 800-171 Rev 3 ↔ FedRAMP Moderate per-requirement coverage report (LOOP-S.S1)' },
   { role: 'dfars-crosswalk-xlsx', filename: 'dfars-crosswalk.xlsx', description: 'XLSX twin of dfars-crosswalk.json (LOOP-S.S1)' },
   ```

9. **Orchestrator wiring**: when `--dfars-equivalency` is set, AFTER
   `--oscal-poam` and AFTER `--control-benchmark`, the orchestrator calls
   `emitDfarsCrosswalk()`. Documented order in `core/orchestrator.ts`
   block comment: collect → score → POA&M → control-benchmark → dfars-
   crosswalk → dfars-incident-report (S.S2, on-demand only) → dfars-
   equivalency (S.S3) → bundle → sign → timestamp.

10. **Sign + timestamp**: outputs flow through the existing pipeline.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | Source | Behavior when missing |
|---|---|---|
| `dodPrimeCustomers[]` | Operator-supplied via `config.yaml` `dfars.dod_prime_customers` or CLI `--dod-prime-customer <name>` (repeatable) | Empty list: emit `coverage:skipped` with reason `no DoD-prime customers configured`; the crosswalk JSON is still emitted but `dod_prime_customers: []` is honest. |
| `inventory.assets[].data_classification === 'cui'` | Cloud tag `fedramp_data_classification=cui` (AWS) / label (GCP) / equivalent (Azure) | If NO assets are tagged CUI, the crosswalk is informational only; coverage log line includes `no CUI-tagged assets — DFARS 7012 cloud-equivalency may not apply`. |
| `inventory.assets[].fedramp_cui_category` | Cloud tag set per NARA CUI Registry; operator-supplied | If a CUI-tagged asset lacks a category, the entry's `cui_categories[]` carries a `REQUIRES-OPERATOR-INPUT: missing-cui-category` marker (visible in the xlsx). |
| 800-171 requirements with empty `derived_from` | NIST 800-171 Rev 3 catalog (extraction script output) | Per § Build step 4, `status: 'requires-operator-input'`; the operator's tracker action documents how the requirement is met. |

**Test specifications** (≥10 tests):

1. `it('loads NIST 800-171 Rev 3 catalog with 110 requirements')`.
2. `it('rolls up satisfied when all derived controls satisfied')`.
3. `it('rolls up partially-satisfied when derived controls mixed')`.
4. `it('rolls up not-satisfied when all derived controls not-satisfied')`.
5. `it('rolls up requires-operator-input when derived_from empty')`.
6. `it('emits coverage:skipped when no CUI-tagged assets in inventory')`.
7. `it('attaches cui_categories[] from inventory tags')`.
8. `it('emits family-level roll-up with correct counts')`.
9. `it('emits evidence_pointers.ksi_ids from the underlying POA&M')`.
10. `it('emits provenance block per REO Rule 2.6')`.
11. `it('writes dfars-crosswalk.xlsx with the documented 12 columns')`.
12. `it('xlsx is openable by SheetJS round-trip')`.
13. `it('orchestrator emits crosswalk only when --dfars-equivalency set')`.

**REO compliance checks specific to this slice**:

- The NIST 800-171 Rev 3 catalog is loaded from a real extracted JSON,
  produced by a real extraction script reading a real published NIST
  source (Appendix C .xlsx).
- The 800-171 → 800-53 mapping is NIST-published; not synthesized.
- Coverage statuses are derived from the existing real
  `control-benchmark.json` evidence; not invented.
- CUI scope is determined by real `inventory.assets[].data_classification`
  tags; absence is honestly surfaced as `coverage:skipped`.
- No `process.env.NODE_ENV === 'test'` branches; tests inject seams via
  dependency-injected file readers.
- Provenance block on `dfars-crosswalk.json` populated end-to-end.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/dfars-crosswalk.test.ts tests/core/dfars-crosswalk-xlsx.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

**Estimated effort**: 5 - 6 working days for a single implementer
(includes catalog extraction script + crosswalk module + xlsx + tests).

---

### Slice S.S2 — DFARS 252.204-7012(c) cyber-incident reporting workflow

**Why this slice**: DFARS 7012(c) requires a CSP-side rapid (72-hour)
report to DC3 via DIBNet when a cyber incident affects CDI. The existing
LOOP-G.G2 incident-response collector captures incident metadata for the
FedRAMP IR-6 reporting flow, but does NOT produce the DC3 Incident
Collection Format (ICF) record, does NOT enforce 72-hour timing on a
CDI-scoped incident, and does NOT coordinate with LOOP-M.M4's PII
breach-notification logic so the operator submits the correct report to
each authority.

**Files to create**:
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-incident-reporting.ts`
  — pure builder: takes a tracker-resident incident record (LOOP-G.G2
  schema) + operator-supplied CDI-scope metadata, projects to the DC3 ICF
  v3.0 schema, emits `out/dfars-incident-report-{uuid}.json` and `.docx`,
  computes the 72-hour deadline relative to discovery, and records a
  signed audit row in the tracker.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-incident-icf.ts`
  — pure ICF schema + validator (typed interfaces + ajv schema).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-incident-docx.ts`
  — docx renderer per existing OOXML pattern in `core/oscal-ssp-docx.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-incident-reporting.test.ts`
  — ≥12 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-incident-icf.test.ts`
  — ≥5 tests pinning the ICF schema.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/dfars-incidents.ts`
  — Express route handler: `POST /api/dfars/incidents` (operator triggers
  a DFARS report from a tracker incident), `GET /api/dfars/incidents`,
  `POST /api/dfars/incidents/:uuid/submit` (records the operator's DIBNet
  submission with screenshot + tracking number).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/dfars-incidents.test.ts`
  — route tests (≥10).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/DfarsIncidents.tsx`
  — list + detail UI gated by `DFARS_ENABLED=true`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/DfarsIncidents.test.tsx`
  — UI tests.

**Files to extend**:
- `cloud-evidence/core/envelope.ts`:
  - Add `cui_affected?: boolean` + `cdi_affected?: boolean` flags on the
    `Incident` interface (G.G2 already emits one — add the flags).
- `cloud-evidence/core/orchestrator.ts`:
  - Add `--dfars-incident-report <incident-uuid>` flag (operator-driven,
    NOT scheduled — the workflow is event-driven by an actual incident).
  - When the flag is set: read the incident from the tracker, build the
    ICF record, emit json + docx, return a non-zero exit code if the
    72-hour deadline is exceeded (warn) or if the operator hasn't yet
    captured the DC3 tracking number (info).
- `tracker/server/schema.sql`:
  ```sql
  CREATE TABLE IF NOT EXISTS dfars_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    source_incident_uuid TEXT NOT NULL,              -- G.G2 incident uuid
    discovered_at TEXT NOT NULL,                      -- ISO datetime
    occurred_at TEXT,
    deadline_at TEXT NOT NULL,                        -- discovered_at + 72h
    cui_affected INTEGER NOT NULL DEFAULT 0,
    cdi_affected INTEGER NOT NULL DEFAULT 0,
    pii_affected INTEGER NOT NULL DEFAULT 0,         -- coordinates with M.M4
    contract_numbers TEXT NOT NULL,                   -- JSON array
    contracting_officer_poc TEXT NOT NULL,            -- JSON {name, email, phone}
    program_manager_poc TEXT NOT NULL,
    description TEXT NOT NULL,
    impact TEXT NOT NULL,
    affected_defense_information TEXT NOT NULL,
    compromised_record_count INTEGER,
    forensic_information TEXT,
    status TEXT NOT NULL CHECK (status IN ('draft','ready-for-submit','submitted','closed')),
    submitted_at TEXT,
    dc3_tracking_number TEXT,                         -- assigned by DIBNet after submit
    submitted_by_user_id INTEGER REFERENCES users(id),
    created_by_user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_dfars_inc_deadline ON dfars_incidents(deadline_at);
  CREATE INDEX IF NOT EXISTS idx_dfars_inc_status ON dfars_incidents(status);

  CREATE TABLE IF NOT EXISTS dfars_incident_submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES dfars_incidents(id) ON DELETE CASCADE,
    submitted_at TEXT NOT NULL,
    dc3_tracking_number TEXT NOT NULL,
    submission_evidence_url TEXT,                     -- screenshot of DIBNet confirmation
    submission_evidence_sha256 TEXT,
    submitted_by_user_id INTEGER NOT NULL REFERENCES users(id),
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS dfars_incident_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES dfars_incidents(id) ON DELETE CASCADE,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('icf-json','icf-docx','malicious-software-sample','media-image-manifest','damage-assessment')),
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    captured_by_user_id INTEGER NOT NULL REFERENCES users(id),
    captured_at TEXT NOT NULL
  );
  ```
- `cloud-evidence/core/submission-bundle.ts`: role
  `dfars-incident-report-bundle` (a directory role that bundles all
  per-incident json + docx + screenshots into a single archive entry).

**Schemas / standards**:

- **DC3 Incident Collection Format (ICF) v3.0** — fields enumerated in §3
  (DC3 ICF). Implementation maps:
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
      date_discovered: string;       // ISO datetime
      date_occurred?: string;
      location: string;
      technique_or_method: string;
      system_type: string;
      outcome: string;
      type_of_compromise: string[];
      description: string;
      impact: string;
      affected_defense_information: string;
      compromised_record_count?: number;
      forensic_information?: string;
    };
    /** Per § 252.204-7012(d), malicious software samples submitted separately. */
    malicious_software_sample?: { filename: string; sha256: string; submitted_via: string };
    /** Per § 252.204-7012(e), media preservation for 90 days. */
    media_preservation?: { items: Array<{ description: string; sha256?: string; retention_until: string }> };
  }
  ```

- **DFARS 252.204-7012(c)(1)(ii)** — submission endpoint
  https://dibnet.dod.mil/. Per REO Rule 4, S.S2 does NOT auto-submit
  (DIBNet requires DoD CAC / ECA Medium-Assurance certificate
  authentication; the human operator submits via the portal and records
  the tracking number back into the tracker).

- **72-hour timing**: deadline = `discovered_at + 72h`. The orchestrator
  emits a `dfars-deadline-warning` log line at +48h and a
  `dfars-deadline-exceeded` line + non-zero exit code at +72h if the
  incident's `status !== 'submitted'`.

- **Coordination with LOOP-M.M4**: when an incident has both
  `cdi_affected=true` AND `pii_affected=true`, the tracker UI surfaces a
  banner explaining BOTH a DFARS report (DC3) and a PII breach
  notification (per M.M4 — e.g. agency CIO + affected individuals + OMB)
  are required, with different deadlines. The two flows do NOT collapse
  into one — they are separately addressable, separately auditable.

**Build steps**:

1. **Define ICF types** in `core/dfars-incident-icf.ts` per § Schemas
   above. Add ajv schema; export `validateIcf(record: DfarsIcfV3): { valid: boolean; errors?: ErrorObject[] }`.

2. **Tracker route** `routes/dfars-incidents.ts`:
   - `POST /api/dfars/incidents` body validates:
     - `source_incident_uuid` refers to a real G.G2 incident.
     - At least one of `cui_affected`, `cdi_affected` is true.
     - `contract_numbers[]` non-empty (DFARS reporting requires the
       affected contract numbers).
     - `description` ≥ 200 chars.
     - `impact` ≥ 100 chars.
   - Compute `deadline_at = discovered_at + 72h`.
   - Sign canonical-JSON-encoded body with the tracker Ed25519 key (same
     key path as B.B3); insert row with `status='draft'` (or
     `'ready-for-submit'` if all required fields populated).
   - Record `audit_log` row: `event='dfars-incident-created'`.

3. **Submission endpoint**:
   - `POST /api/dfars/incidents/:uuid/submit` body:
     ```ts
     { dc3_tracking_number: string; submission_evidence_url?: string; submission_evidence_sha256?: string }
     ```
   - Validate caller has `iso` or `so` role.
   - Update incident row `status='submitted'`, `submitted_at=now()`,
     `dc3_tracking_number`.
   - Insert `dfars_incident_submissions` row with separate signature.
   - Record `audit_log` row: `event='dfars-incident-submitted'`.

4. **ICF builder** in `core/dfars-incident-reporting.ts`:
   ```ts
   export function buildIcf(incident: DfarsIncidentRecord, csp: CspProfile): DfarsIcfV3;
   ```
   Pure: maps the tracker record to the ICF v3.0 shape. Validates via
   `validateIcf()`. Returns the typed object.

5. **Emitter**:
   ```ts
   export interface DfarsIncidentEmitOptions {
     outDir: string;
     incidentUuid: string;
     trackerUrl: string;
     trackerToken: string;
     cspProfilePath: string;            // org-profile.yaml
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
   Reads incident from tracker, builds ICF, writes JSON + docx, returns
   status. Provenance block on the JSON enumerates: tracker URL, incident
   UUID, source G.G2 incident UUID, signing key.

6. **DOCX renderer** in `core/dfars-incident-docx.ts`. Follows the OOXML
   pattern used by `core/oscal-ssp-docx.ts`. Cover page lists:
   - Company name, DUNS, CAGE, contract numbers.
   - Discovery date, deadline, time-remaining.
   - Description, impact, affected defense information.
   - Forensic information.
   - DC3 tracking number (if assigned).
   - Footer: "Submitted to DC3 per DFARS 252.204-7012(c)(1)(ii); upload
     to https://dibnet.dod.mil/ using DoD-approved Medium-Assurance ECA
     or DoD CAC".

7. **Orchestrator wiring**: `--dfars-incident-report <uuid>` is an
   on-demand flag. When set, the orchestrator skips the full collection
   pipeline (an incident is a separate axis from a regular run) and runs
   only `emitDfarsIncidentReport()` + signs the output.

8. **Coordination with LOOP-M.M4**: when `pii_affected=true`, the
   tracker UI banner notes the M.M4 path is ALSO required; the operator
   submits both separately. The emitter's log line cites both deadlines.

9. **UI** (`DfarsIncidents.tsx`):
   - List view filterable by status, deadline-imminence, contract.
   - Detail view shows ICF preview (read from `out/dfars-incident-report-{uuid}.json`),
     deadline countdown, "Mark Submitted" button (opens dialog asking
     for DC3 tracking number + optional screenshot URL).
   - "Both DFARS and PII" banner when both flags set.

10. **Bundler integration**: when the orchestrator is run with
    `--dfars-equivalency` + a directory contains
    `dfars-incident-report-*.json` files, the bundler includes a
    `dfars-incident-report-bundle` role with all per-incident JSON +
    docx + screenshots archived together.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | Source | Behavior when missing |
|---|---|---|
| `contract_numbers[]` | Operator UI input on create | Required — server rejects empty array |
| `contracting_officer_poc` | Operator UI input | Required |
| `program_manager_poc` | Operator UI input | Required |
| `description` (≥200 chars) | Operator UI input | Required |
| `dc3_tracking_number` | Operator submits via DIBNet, records back into tracker | Stays empty until operator records; deadline logic ignores absent value once `status='submitted'` |
| `malicious_software_sample` | Operator collects + submits separately per § 252.204-7012(d) | Optional in tracker; UI prompts "Required if applicable" |
| `media_preservation` items | Operator captures per § 252.204-7012(e) (90-day preservation) | Tracker carries the metadata + retention-until date |

**Test specifications** (≥12 tests):

1. `it('rejects POST without source_incident_uuid')`.
2. `it('rejects POST with neither cui_affected nor cdi_affected')`.
3. `it('rejects POST with empty contract_numbers[]')`.
4. `it('rejects POST with description < 200 chars')`.
5. `it('rejects POST when caller lacks iso role')`.
6. `it('computes deadline_at = discovered_at + 72h')`.
7. `it('signs canonical JSON with Ed25519')`.
8. `it('emits deadline-warning log at +48h')`.
9. `it('emits deadline-exceeded log at +72h with non-zero exit code')`.
10. `it('builds valid ICF v3.0 record passing the ajv schema')`.
11. `it('writes dfars-incident-report-{uuid}.json with provenance block')`.
12. `it('writes dfars-incident-report-{uuid}.docx with the cover-page fields')`.
13. `it('records signed submission row when operator marks submitted')`.
14. `it('coordinates with M.M4 — emits both-flows banner when pii_affected and cdi_affected')`.
15. `it('UI hides DFARS routes when DFARS_ENABLED=false')`.
16. `it('does NOT auto-submit to DIBNet (REO Rule 4)')` — emitter never
    invokes the DIBNet URL.

**REO compliance checks specific to this slice**:

- The incident record is operator-supplied via tracker UI (real human
  action) — never synthesized.
- The ICF schema is loaded from a published source; not invented.
- The 72-hour deadline is computed from real timestamps; no fudging.
- Submission is human-operated through the DIBNet portal; the emitter
  records evidence (tracking number + screenshot) but never auto-submits.
  REO Rule 4 ("operator-supplied data is real data").
- Signatures are real Ed25519 over canonical JSON.
- No `process.env.NODE_ENV === 'test'` branches.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/dfars-incident-reporting.test.ts tests/core/dfars-incident-icf.test.ts
cd ../tracker
npm run typecheck
npm test -- server/routes/dfars-incidents.test.ts client/src/pages/DfarsIncidents.test.tsx
cd ../cloud-evidence
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 6 - 7 working days (server + client + emitter +
docx renderer + tests).

---

### Slice S.S3 — DoD CIO Equivalency Memorandum attestation package emitter

**Why this slice**: The DoD CIO Memorandum (Dec 21 2023) prescribes a
specific deliverable shape for a CSP claiming FedRAMP Moderate
Equivalency: a signed Equivalency Letter, the FedRAMP submission bundle,
the S.S1 800-171 crosswalk, the 3PAO's equivalency assessment letter,
and a DFARS 7012(c)-(g) operational runbook. S.S3 packages all of these
into a single signed archive the CSP delivers to each DoD-prime customer.

**Files to create**:
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-equivalency-attestation.ts`
  — emitter: reads the FedRAMP submission bundle (from LOOP-A.A4), the
  S.S1 crosswalk, the 3PAO equivalency assessment letter template, the
  operational runbook template, and emits the Equivalency Letter
  (`dfars-equivalency-letter.docx`) + a manifest
  (`dfars-equivalency-manifest.json`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-equivalency-letter-docx.ts`
  — OOXML renderer for the Equivalency Letter per the DoD CIO Memo
  template.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-equivalency-runbook-docx.ts`
  — OOXML renderer for the operational runbook covering DFARS 7012(c)-(g)
  obligations.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-equivalency-attestation.test.ts`
  — ≥8 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/templates/dfars-equivalency-letter.template.json`
  — operator-editable section seeds (paragraph headings, prompts).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/dfars-equivalency.ts`
  — Express route: `POST /api/dfars/equivalency/attestations` (operator
  records signed officer attestation), `GET /api/dfars/equivalency/attestations`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/DfarsEquivalency.tsx`
  — UI for the officer to review the auto-built letter, edit narrative
  sections, and signe-off (the signed action persists as the audit row
  the emitter reads).

**Files to extend**:
- `cloud-evidence/core/submission-bundle.ts`:
  - Add roles `dfars-equivalency-letter-docx` (filename
    `dfars-equivalency-letter.docx`), `dfars-equivalency-manifest-json`
    (`dfars-equivalency-manifest.json`), `dfars-equivalency-runbook-docx`
    (`dfars-equivalency-runbook.docx`) to `WELL_KNOWN`.
  - When `--dfars-equivalency` is set, the bundler emits a TOP-LEVEL
    nested archive `dfars-equivalency-package.zip` containing:
    1. `dfars-equivalency-letter.docx`
    2. `dfars-equivalency-manifest.json`
    3. `dfars-equivalency-runbook.docx`
    4. `dfars-crosswalk.json` + `dfars-crosswalk.xlsx`
    5. The full FedRAMP submission archive (`fedramp-submission.zip`)
       nested inside.
    6. All `dfars-incident-report-*.json` + `.docx` from the prior 12
       months (audit history).
- `tracker/server/schema.sql`:
  ```sql
  CREATE TABLE IF NOT EXISTS dfars_equivalency_attestations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    attesting_officer_user_id INTEGER NOT NULL REFERENCES users(id),
    attesting_officer_title TEXT NOT NULL,
    csp_name TEXT NOT NULL,
    csp_legal_entity TEXT NOT NULL,
    cso_name TEXT NOT NULL,
    fedramp_package_id TEXT NOT NULL,                  -- the FedRAMP SSP id
    crosswalk_sha256 TEXT NOT NULL,                    -- sha256 of dfars-crosswalk.json
    threepao_letter_uri TEXT NOT NULL,                 -- s3:// or file:// pointer
    threepao_letter_sha256 TEXT NOT NULL,
    runbook_uri TEXT NOT NULL,
    runbook_sha256 TEXT NOT NULL,
    operating_impact_level TEXT NOT NULL CHECK (operating_impact_level IN ('IL4-equivalent','IL5-equivalent')),
    dod_prime_customers TEXT NOT NULL,                 -- JSON array
    attested_at TEXT NOT NULL,
    expiration_date TEXT NOT NULL,                     -- attestation auto-expires after 1 year
    status TEXT NOT NULL CHECK (status IN ('draft','attested','expired','revoked')),
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by_user_id INTEGER REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_dfars_attest_status ON dfars_equivalency_attestations(status);
  CREATE INDEX IF NOT EXISTS idx_dfars_attest_expiration ON dfars_equivalency_attestations(expiration_date);
  ```

**Schemas / standards**:

- **DoD CIO Memorandum Dec 21 2023** — required Equivalency Letter
  content (downloaded PDF + quoted in the emitter docstring):
  - Statement that the CSP's CSO meets FedRAMP Moderate (or higher)
    baseline.
  - Statement that the CSO was assessed by a FedRAMP-recognized 3PAO.
  - Statement that the CSP complies with DFARS 252.204-7012(c)-(g).
  - Statement of operating impact level (typically IL4-equivalent for
    CUI; IL5-equivalent only if FedRAMP High + additional DoD overlays).
  - Officer signature block (officer name, title, date).
  - List of DoD-prime customers covered by the attestation.

- **DoD Cloud Computing SRG v1r4** — defines IL2/IL4/IL5/IL6 boundary
  conditions. S.S3's manifest cites the operating level + the SRG
  section reference.

- **DFARS 7012(c)-(g) operational runbook sections**:
  - (c) Cyber incident reporting (DC3 / DIBNet path — references S.S2).
  - (d) Malicious software (sample handling + DC3 submission).
  - (e) Media preservation (90-day retention).
  - (f) Access to additional information and equipment.
  - (g) Cyber incident damage assessment activities.
  - The runbook is a docx-rendered, operator-editable narrative; the
    emitter seeds each section with the canonical DFARS language + the
    CSP-specific procedures the operator types into the tracker.

**Build steps**:

1. **Tracker route** `routes/dfars-equivalency.ts`:
   - `POST /api/dfars/equivalency/attestations`: officer fills out the
     attestation form, server validates required fields, signs canonical
     JSON, inserts row with `status='draft'`.
   - `POST /api/dfars/equivalency/attestations/:uuid/attest`: officer
     re-signs (second signature over `{uuid, attested_at}`) — record
     transitions to `status='attested'`.
   - Auto-expire enforcer (mirrors B.B3 enforcer pattern) runs hourly;
     `expiration_date < now()` → `status='expired'`.

2. **Letter emitter** `core/dfars-equivalency-attestation.ts`:
   ```ts
   export interface DfarsAttestationEmitOptions {
     outDir: string;
     trackerUrl: string;
     trackerToken: string;
     fedrampBundlePath: string;     // path to bundled fedramp-submission.zip
     crosswalkJsonPath: string;     // path to dfars-crosswalk.json (S.S1)
     threepaoLetterPath?: string;   // operator-supplied path
     runbookTemplatePath?: string;  // default: templates/dfars-runbook.template.json
     cspProfilePath: string;        // org-profile.yaml
     runId: string;
   }
   export interface DfarsAttestationEmitResult {
     letter_docx_path: string;
     manifest_json_path: string;
     runbook_docx_path: string;
     attestation_uuid: string;
     attested_officer: string;
     expiration_date: string;
     dod_prime_customers: string[];
   }
   export async function emitDfarsEquivalencyAttestation(opts: DfarsAttestationEmitOptions): Promise<DfarsAttestationEmitResult>;
   ```

3. **Letter content** (per DoD CIO Memo):
   ```
   <Letterhead with CSP legal entity>
   <Date>

   To: <DoD-Prime Customer Contracting Officer / Authorizing Official>

   Subject: FedRAMP Moderate Equivalency Attestation for {csp_name} —
            {cso_name} per DFARS 252.204-7012 and DoD CIO Memo
            (Dec 21, 2023)

   I, <attesting_officer_name>, in my capacity as <attesting_officer_title>
   of <csp_legal_entity>, attest that:

   1. <cso_name> implements security controls equivalent to the FedRAMP
      Moderate baseline (NIST SP 800-53 Rev 5; FedRAMP Rev 5).
   2. <cso_name> was assessed by <3pao_name>, a FedRAMP-recognized
      Third Party Assessment Organization, on <assessment_date>;
      assessment evidence is enclosed.
   3. <csp_legal_entity> complies with DFARS 252.204-7012 paragraphs
      (c) through (g) operational obligations, as documented in the
      enclosed runbook.
   4. The operating impact level for Covered Defense Information /
      Controlled Unclassified Information processed on <cso_name> is
      <operating_impact_level> per the DoD Cloud Computing Security
      Requirements Guide v1r4.
   5. This attestation covers the following DoD-prime customers and
      contract vehicles: <dod_prime_customers list>.

   This attestation expires on <expiration_date>, one year from issue.
   I will notify each listed prime within 30 days of any material change.

   <officer signature block>
   ```

4. **Manifest emit** `dfars-equivalency-manifest.json`:
   ```ts
   export interface DfarsEquivalencyManifest {
     manifest_version: '1.0';
     csp: { name: string; legal_entity: string };
     cso: { name: string; ssp_uuid: string };
     attesting_officer: { name: string; title: string; signed_at: string };
     operating_impact_level: 'IL4-equivalent' | 'IL5-equivalent';
     fedramp_package: { sha256: string; bytes: number; emit_path: string };
     crosswalk: { sha256: string; total_requirements: number; satisfied: number };
     threepao_assessment: { name: string; sha256: string; assessment_date: string };
     runbook: { sha256: string; bytes: number };
     dod_prime_customers: string[];
     dfars_7012_compliance: {
       c_cyber_incident_reporting: 'covered-by-runbook';
       d_malicious_software: 'covered-by-runbook';
       e_media_preservation: 'covered-by-runbook';
       f_access_for_forensic_analysis: 'covered-by-runbook';
       g_damage_assessment: 'covered-by-runbook';
     };
     expires_at: string;
     provenance: { emitter: 'dfars-equivalency-attestation'; emittedAt: string; sourceCalls: Array<{ kind: string; path: string }>; signingKeyId: string };
   }
   ```

5. **Runbook emit** `dfars-equivalency-runbook.docx`. Sections per DFARS
   7012(c)-(g); each section template-seeded with the verbatim DFARS
   clause text + operator-typed CSP-specific procedure (pulled from
   the tracker `dfars_equivalency_runbook_sections` rows the operator
   filled in via UI). The narrative IS operator-supplied — never auto-
   generated.

6. **Bundler integration** — when `--dfars-equivalency` is set, the
   bundler builds a nested archive containing:
   - `dfars-equivalency-letter.docx`
   - `dfars-equivalency-manifest.json`
   - `dfars-equivalency-runbook.docx`
   - `dfars-crosswalk.json` + `dfars-crosswalk.xlsx`
   - `dfars-incident-report-*.json` + `*.docx` from prior 12 months
   - `fedramp-submission.zip` nested
   - Manifest signature over the SHA-256 of every contained artifact.

7. **Orchestrator wiring**: when `--dfars-equivalency` is set, AFTER
   `dfars-crosswalk.json` is written (S.S1) AND any pending DFARS
   incidents (S.S2) are emitted, the orchestrator invokes
   `emitDfarsEquivalencyAttestation()`. Manifest + letter + runbook
   land in `out/`, then the bundler picks them up.

8. **Sign + timestamp**: all three artifacts (letter docx, manifest
   json, runbook docx) flow through the existing `core/sign.ts` glob +
   `core/timestamp.ts` RFC 3161 pipeline. The bundle's manifest
   re-signs the SHA-256 of the whole archive.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | Source | Behavior when missing |
|---|---|---|
| `attesting_officer_user_id` + `title` | Tracker UI; user with `officer` or `ao` role | Required — emitter errors if no signed attestation exists |
| `csp_legal_entity` | `config.yaml` | Required — error if absent |
| `cso_name` | `config.yaml` | Required |
| `threepao_assessment` (path + sha + date) | Operator uploads in tracker | Required — bundler refuses to ship without it |
| `dod_prime_customers[]` | `config.yaml` | Required (≥1 entry) |
| `operating_impact_level` | `config.yaml` (`IL4-equivalent` default) | If `IL5-equivalent` claimed, additional FedRAMP High baseline + DoD overlay evidence required (warning issued; the bundler refuses unless the operator confirms with `--confirm-il5`) |
| Runbook narrative for (c) through (g) | Tracker UI sections | Each section MUST be operator-typed; the emitter refuses to ship a runbook with empty sections |

**Test specifications** (≥8 tests):

1. `it('rejects emit when no attested record in tracker')`.
2. `it('rejects emit when expiration_date < now())`.
3. `it('rejects emit when threepao_assessment evidence absent')`.
4. `it('rejects emit when runbook sections empty')`.
5. `it('writes letter docx with all 5 paragraph blocks')`.
6. `it('writes manifest with sha256 of every embedded artifact')`.
7. `it('writes runbook docx with 5 sections corresponding to 7012(c)-(g))`.
8. `it('bundler builds nested archive when --dfars-equivalency set')`.
9. `it('emitter refuses IL5-equivalent without --confirm-il5')`.
10. `it('signs every artifact via core/sign.ts pipeline')`.
11. `it('provenance block per REO Rule 2.6')`.
12. `it('enforcer expires attestation 1 year after attestation date')`.

**REO compliance checks specific to this slice**:

- Officer attestation is a real signed human action; never auto-
  generated.
- 3PAO assessment letter is operator-uploaded; the bundler verifies
  the SHA-256 matches the manifest claim.
- Runbook content is operator-authored; the emitter refuses to ship
  empty sections.
- DFARS quote text + DoD CIO Memo language are REO Rule 3 allowed
  fixed-data (NIST / DoD published constants) and are quoted with
  citation.
- Signatures are real Ed25519 + RFC 3161 timestamps.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/dfars-equivalency-attestation.test.ts
cd ../tracker
npm test -- server/routes/dfars-equivalency.test.ts client/src/pages/DfarsEquivalency.test.tsx
cd ../cloud-evidence
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 5 - 6 working days (server + client + emitter +
docx renderers + bundler integration + tests).

---

## 5. Loop-wide acceptance criteria

LOOP-S is COMPLETE when ALL of the following are true:

1. **Conditional gate is honored.** When `--dfars-equivalency` is NOT set
   AND `CLOUD_EVIDENCE_DFARS_EQUIVALENCY` env is unset, NONE of the S
   slice emitters run. The orchestrator emits no DFARS artifacts. This
   is the default. Existing FedRAMP-only flows are unaffected.

2. **S.S1**: when the flag is set + at least one inventory asset carries
   `data_classification === 'cui'`, `out/dfars-crosswalk.json` +
   `out/dfars-crosswalk.xlsx` are emitted with provenance blocks; family-
   level totals match per-requirement totals; CUI categories from
   inventory tags populate the entries; bundler includes both roles.

3. **S.S2**: tracker has `dfars_incidents` + `dfars_incident_submissions`
   + `dfars_incident_artifacts` tables; route handlers reject invalid
   bodies; deadline math computes 72h from discovery; ICF v3.0 schema
   validates; `dfars-incident-report-{uuid}.json` + `.docx` emit when
   `--dfars-incident-report <uuid>` is set; coordination with M.M4 PII
   surfaces both-flows banner; UI hides DFARS routes when
   `DFARS_ENABLED=false`.

4. **S.S3**: tracker has `dfars_equivalency_attestations` table;
   attestation requires signed officer action; runbook sections are
   operator-typed (emitter refuses empty); letter + manifest + runbook
   emit with all five DoD CIO Memo paragraphs; bundler builds nested
   `dfars-equivalency-package.zip` when flag is set; expiration enforcer
   runs hourly.

5. All three slices pass `npm run typecheck`, `npm test`, and
   `npm run check:reo` in both `cloud-evidence/` and `tracker/`.

6. CHANGELOG "Unreleased" has three entries (one per slice) with module
   names + verification counts + REO compliance notes + the DFARS
   conditional gate noted at the top of each entry.

7. STATUS.md per-slice rows updated. STATUS.md shows the LOOP-S
   conditional gate explicitly so future sessions know to check
   applicability before resuming.

8. Per-slice docs `docs/slices/S/S.S1.md`, `S.S2.md`, `S.S3.md`
   frontmatter all carry `applicable_conditional: true` with the
   condition statement copied verbatim from this file's frontmatter.

---

## 6. Open questions / caveats

1. **DoD CIO Memo PDF reachability.** The Dec 21 2023 memo PDF may be
   gated by HTTP 403 to anonymous fetches via the DoD CIO library. Until
   the implementer downloads the PDF to
   `cloud-evidence/docs/sources/dod-cio-memo-fedramp-equivalency-2023-12-21.pdf`,
   S.S3's emitter docstring carries a `REQUIRES-OPERATOR-INPUT:
   confirm-against-dod-cio-memo-pdf` marker on the quoted language
   constants (visible to `check:reo` reviewers; not a silent fallback).

2. **NIST 800-171 Rev 3 Appendix C mapping changes vs Rev 2.** Rev 3
   (May 2024) re-organized families and added SR/PL/PM. Some prime
   contracts still reference Rev 2 by clause. S.S1 ships Rev 3 ONLY;
   when a prime contract requires Rev 2 mapping, the operator's runbook
   documents the manual gap.

3. **DIBNet authentication.** The DIBNet portal requires DoD-approved
   Medium-Assurance ECA certificate or DoD CAC; the CSP operator must
   procure this out-of-band. Documented in the operator runbook.
   S.S2's emitter explicitly does NOT auto-submit — it produces the
   ICF record and the operator uploads via the portal.

4. **3PAO availability for DFARS equivalency.** Not every FedRAMP 3PAO
   has DFARS-specific assessment experience. The CSP must engage a
   3PAO; the engagement is out of the system's authority. S.S3 requires
   the 3PAO letter as operator-uploaded evidence.

5. **CUI sub-category taxonomy completeness.** NARA's CUI Registry is
   the authoritative list; tags must match. S.S1's xlsx column G shows
   the operator-supplied category; mismatches surface as
   `REQUIRES-OPERATOR-INPUT: unknown-cui-category-<value>`.

6. **CMMC vs DFARS-equivalency** — LOOP-S is DFARS-equivalency only.
   CMMC L2 certification is a SEPARATE path (C3PAO assessment, eMASS
   submission). Documented in the LOOP-S spec docstring.

7. **Multi-tenant DFARS isolation.** When LOOP-H.H3 multi-CSO ships,
   the four S-slice tables need a `tenant_id` migration (mirrors LOOP-B
   risk-acceptance / compensating-control / risk-register tables). The
   S tables ship single-tenant in this loop; H.H3 sweeps them in one
   atomic migration.

8. **Incident-report retention.** DFARS 7012(e) requires 90-day media
   preservation. S.S2's `dfars_incident_artifacts` table records the
   `retention_until` date per artifact. LOOP-H long-term storage
   classifier (H.H1) picks up the 90-day signal automatically; no LOOP-S
   change required.

9. **Officer signature authority.** S.S3 requires a CSP officer (CISO,
   CTO, or higher). The tracker's `officer` role is added in this loop;
   operator's identity provider (Okta / Azure AD) must map a real human
   to it. Documented in runbook.

10. **PII + CUI overlap (M.M4 + S.S2).** When a single incident affects
    both PII (M.M4 scope) and CUI/CDI (S.S2 scope), TWO reports are
    required to TWO authorities with DIFFERENT deadlines. S.S2's UI
    surfaces a banner; the two flows are NOT collapsed into one.

---

## 7. Status tracking

Update this table when a slice ships (see Section 8).

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| S.S1 | NIST 800-171 Rev 3 → FedRAMP Moderate crosswalk emitter | pending | — | — |
| S.S2 | DFARS 252.204-7012(c) cyber-incident reporting workflow | pending | — | — |
| S.S3 | DoD CIO Equivalency Memorandum attestation package emitter | pending | — | — |

---

## 8. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST perform these steps. Skipping
any one is a REO Rule 2 violation.

1. **Verify green**: from repo root
   ```bash
   cd cloud-evidence
   npm run typecheck            # must be clean
   npm test                     # 100% passing
   npm run check:reo            # G1 + G2 + G3 all green
   npm run check:provenance     # every new emit-field has provenance entry
   ```
   For slices touching the tracker (S.S2, S.S3):
   ```bash
   cd ../tracker
   npm run typecheck
   npm test
   ```

2. **Update Section 7 status table** in this file: set the slice's row
   to `status=done`, `commit=<short-sha>`, `date=<YYYY-MM-DD>`.

3. **Update CHANGELOG.md "Unreleased"**: add a new `### Added — LOOP-S.<id>: <title>` block at the top of "Unreleased". The CHANGELOG entry MUST open with the line: "**Conditional**: ships only when the CSP serves a DoD-prime customer; controlled by `--dfars-equivalency` flag."

4. **Update `cloud-evidence/docs/STATUS.md`**: set the slice row to
   `done`. Add a top-of-LOOP-S note: "LOOP-S is conditional (DoD-prime
   customers only)."

5. **Update the per-slice doc** (`docs/slices/S/S.S<n>.md`) frontmatter:
   `status: done`, `commit: <hash>`, `completed_date: <ISO>`,
   `last_updated: <ISO>`. Append the final Implementation log entry.

6. **Commit**: from repo root
   ```bash
   git add -A
   git commit -m "LOOP-S.<id>: <title>"
   ```
   Commit message body: short paragraph mirroring CHANGELOG entry intent
   PLUS the conditional gate statement.

7. **Push**: `git push origin main`.

---

## 9. Appendix — Worked end-to-end example

To make LOOP-S reviewable, here is a worked end-to-end example.

### 9.1 Setup

- CSP: ExampleCSP Inc., DoD-prime customer: Anduril Industries (contract
  HQ0034-24-C-0123), operating on `cso_name = ExampleCSP CMMS`.
- Inventory: 47 assets, 12 tagged `fedramp_data_classification=cui`,
  CUI category `CUI-CTI` (Controlled Technical Information).
- FedRAMP Moderate package: complete (LOOP-A through LOOP-R). 287
  Moderate controls assessed. Current control-benchmark.json:
  - 234 satisfied
  - 28 partially-satisfied
  - 11 not-satisfied (open POA&M items)
  - 14 not-assessed (operator-attested only)

### 9.2 S.S1 — crosswalk emit

Operator runs:

```
cloud-evidence orchestrate \
    --collect aws,gcp \
    --oscal-poam \
    --control-benchmark \
    --dfars-equivalency \
    --dod-prime-customer "Anduril Industries (HQ0034-24-C-0123)"
```

After `--control-benchmark` writes `out/control-benchmark.json` with the
287-control Moderate result, `--dfars-equivalency` triggers
`emitDfarsCrosswalk()`:

- Loads `docs/nist-800-171-r3.generated.json` (110 requirements,
  17 families).
- For each requirement, looks up its `derived_from` 800-53 controls in
  the benchmark.
- Example: `03.01.01 — Limit system access to authorized users` derives
  from {ac-1, ac-2, ac-3, ac-6, ac-17, ac-18, ac-20, ia-2, ia-4, ia-5,
  ia-8}. Benchmark: 9 satisfied + 2 partially → roll-up: partial.
- Aggregates family AC totals: 22 requirements; 17 satisfied,
  3 partial, 1 not-satisfied, 1 not-assessed.

Emits:
- `out/dfars-crosswalk.json` with 110 entries + family roll-ups +
  provenance.
- `out/dfars-crosswalk.xlsx` with 110+ rows + 17 family group totals.

### 9.3 S.S2 — incident report (hypothetical)

Six months later, ExampleCSP's SOC detects unauthorized lateral
movement against a CUI-tagged S3 bucket containing CTI for Anduril.
At 2027-01-15T14:30Z the operator creates a G.G2 incident in the
tracker, marks `cui_affected=true` + `cdi_affected=true`, fills in
contract HQ0034-24-C-0123 + contracting officer POC.

Tracker computes `deadline_at = 2027-01-18T14:30Z` (72h).

Operator runs:

```
cloud-evidence orchestrate \
    --dfars-incident-report <incident-uuid>
```

Emitter:
- Reads the incident from the tracker.
- Builds DC3 ICF v3.0 record.
- Writes `out/dfars-incident-report-<uuid>.json` + `.docx`.
- Logs `dfars-deadline-warning: 24h remaining`.

Operator uploads the docx to DIBNet, receives tracking number
`DC3-2027-0143`, records back into tracker. Status flips to
`submitted`.

### 9.4 S.S3 — annual attestation

Annually, the CSP CISO reviews the FedRAMP package + S.S1 crosswalk
+ 3PAO equivalency assessment letter (engaged externally) and signs
an attestation in the tracker. Operator runs:

```
cloud-evidence orchestrate \
    --dfars-equivalency \
    --bundle-submission
```

Bundler builds `dfars-equivalency-package.zip` containing:
- `dfars-equivalency-letter.docx` — CISO-signed
- `dfars-equivalency-manifest.json` — SHA-256 of every artifact
- `dfars-equivalency-runbook.docx` — operator-authored (c)-(g)
  procedures
- `dfars-crosswalk.json` + `.xlsx`
- `dfars-incident-report-<uuid>.json` + `.docx` (12-month history)
- `fedramp-submission.zip` (nested)

Manifest is signed Ed25519 + RFC 3161 timestamped. The archive is
delivered to Anduril contracting officer + retained for audit.

### 9.5 What this gives ExampleCSP

- A defensible, evidence-grade record that CSO ExampleCSP CMMS meets
  FedRAMP Moderate equivalency for DoD-prime customers per the
  DoD CIO Dec 21 2023 memorandum.
- A real ICF v3.0 record reportable to DC3 within 72h of a
  CUI-affecting incident.
- A 1-year-renewable Equivalency Letter signed by a real CSP
  officer.
- An audit trail every artifact traces back to (existing FedRAMP
  evidence + signed tracker records + operator-typed runbook).

That is the LOOP-S value proposition end-to-end.

---

## 10. Cross-references

- Per-slice deep-context docs:
  - `cloud-evidence/docs/slices/S/S.S1.md`
  - `cloud-evidence/docs/slices/S/S.S2.md`
  - `cloud-evidence/docs/slices/S/S.S3.md`
- Risks register: `cloud-evidence/docs/loops/LOOP-S-RISKS.md`
- Originating audit: `cloud-evidence/docs/SECOND-PASS-AUDIT.md` §2.7
- Existing benchmark extension point:
  `cloud-evidence/core/control-benchmark.ts`
- Existing IR collector: `cloud-evidence/providers/{aws,gcp,azure}/incident.ts` (LOOP-G.G2)
- Existing privacy collector: LOOP-M.M4 PII breach-notification logic
- Existing FedRAMP submission bundler:
  `cloud-evidence/core/submission-bundle.ts` (LOOP-A.A4)
- OSCAL POA&M: `cloud-evidence/core/oscal-poam.ts` (LOOP-A.A1)
- NIST 800-53 Rev 5: `cloud-evidence/core/nist-r5.ts`
- Baseline data: `cloud-evidence/docs/nist-r5-baselines.generated.json`
