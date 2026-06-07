# LOOP-P — Insider Threat + PS-family Workforce Security

> Comprehensive implementation specification for the five slices in LOOP-P.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-P end-to-end by reading ONLY this file + the five supporting
> per-slice docs cited in Section 5. No prior conversation history required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence,
> operator-supplied configuration, or a tracker-stored process artifact
> with signed audit log entry. Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.
>
> Status (2026-06-07): all five slices pending. LOOP-P closes the FedRAMP
> Moderate gap for the entire NIST 800-53 Rev5 PS-family (PS-1 through PS-9)
> and PM-12 (Insider Threat Program), surfaced as a missing coverage area
> by `docs/ADDITIONAL-LOOPS-AUDIT.md` §2 LOOP-P (2026-06-06).

---

## 1. Why this loop exists

### The workforce-security gap the existing roadmap leaves open

The 49-slice LOOP-A..K roadmap covers **technical** workforce-touching
controls (IAM-AAM, IAM-JIT, IAM-SUS, AC-2, AC-6) and **process-artifact**
slots for CED training records via the tracker. It does **NOT** cover the
NIST 800-53 Rev5 **Personnel Security (PS) family** or the program-level
control **PM-12 (Insider Threat Program)**. Audit doc
`docs/ADDITIONAL-LOOPS-AUDIT.md` (2026-06-06) §2 LOOP-P states this
verbatim:

> "NIST SP 800-53 Rev5 control **PM-12 (Insider Threat Program)** is in
> the FedRAMP Moderate baseline (and is a CSP organization-wide control,
> not system-scoped). The PS family (PS-1 through PS-9) is also
> Moderate-baseline and currently has zero direct coverage in our 49
> slices (the IAM family covers AC-2 etc. but not PS-3 personnel
> screening, PS-4 personnel termination, PS-7 third-party personnel
> security, PS-8 personnel sanctions)."

The audit further notes:

> "32 CFR Part 117 (NISPOM) — Insider-Threat Program guidance applies
> when the CSP handles or processes data covered by the National
> Industrial Security Program."

Five FedRAMP Moderate-baseline controls become unsatisfiable without
LOOP-P (or with hand-authored Word documents and zero signed evidence
chain):

| Control | Title | Why uncovered today |
|---|---|---|
| **PM-12** | Insider Threat Program | Organization-wide control. No SSP narrative, no team roster, no incident log. |
| **PS-2** | Position Risk Designation | Per-position risk-level designations required; no enumeration in tracker or SSP. |
| **PS-3** | Personnel Screening | Screening records (and re-screening cadence) needed; nowhere to store. |
| **PS-4** | Personnel Termination | Off-boarding within org-defined time window; tracker has no signed termination workflow. |
| **PS-5** | Personnel Transfer | Internal transfers require access re-baseline; not modelled. |
| **PS-6** | Access Agreements | NDA + acceptable-use + non-disclosure agreements per-user with signature evidence; missing. |
| **PS-7** | External Personnel Security | Subprocessor / contractor screening attestations; intersects LOOP-J.J2 but workforce side is missing. |
| **PS-8** | Personnel Sanctions | Sanctions / disciplinary records for security violations; nowhere to record. |
| **PS-9** | Position Descriptions | Security-relevant role responsibilities in position descriptions; not surfaced. |

### Artifacts LOOP-P delivers

| # | Artifact | Source | Consumer |
|---|---|---|---|
| 1 | `core/insider-threat-program.ts` — .docx ITP plan emitter | LOOP-P.P1 | SSP appendix, AO, 3PAO |
| 2 | Insider Threat Program tracker (DB tables + UI + signed roster) | LOOP-P.P1 | KSI-PIY-PSE process-artifact evidence |
| 3 | `core/position-risk-emit.ts` — position risk register + PS-2/PS-3 envelope | LOOP-P.P2 | OSCAL AR, POA&M, SSP |
| 4 | Screening records tracker (per-user, with cadence enforcer) | LOOP-P.P2 | PS-3 process-artifact evidence |
| 5 | `core/personnel-lifecycle.ts` — transfer + termination evidence | LOOP-P.P3 | PS-4 + PS-5 envelopes; IAM-SUS deletion correlation |
| 6 | Termination + transfer tracker workflows (signed checklist) | LOOP-P.P3 | PS-4 SLA evidence (org-defined time window) |
| 7 | `core/access-agreements.ts` — NDA / acceptable-use / role-acknowledgment emitter | LOOP-P.P4 | PS-6 envelope; tracker per-user signature |
| 8 | Continuous workforce monitoring + behavioral analytics | LOOP-P.P5 | PM-12 incident handling; monthly ConMon report |

### Authorization-package gaps closed

| Package gap | Slice | Authoritative source |
|---|---|---|
| No SSP narrative for PM-12 / PS-1 program scope | P.P1 | NIST 800-53r5 PM-12, EO 13587 §6, NITTF minimum standards |
| No position risk designation register | P.P2 | NIST 800-53r5 PS-2; 5 CFR 731 (OPM Position Designation System) |
| No per-user screening + re-screening cadence | P.P2 | NIST 800-53r5 PS-3; 5 CFR 731.106 |
| No signed termination workflow w/ SLA on access revocation | P.P3 | NIST 800-53r5 PS-4, PS-5 |
| No NDA / access agreement signature evidence | P.P4 | NIST 800-53r5 PS-6 |
| No continuous workforce indicator pipeline (insider threat) | P.P5 | NIST 800-53r5 PM-12; EO 13587 §6; NITTF |
| 32 CFR 117 NISPOM contractor ITP obligations | P.P1 + P.P5 | 32 CFR 117.7 |

---

## 2. Connection to FedPy mission

LOOP-P sits squarely inside the FedPy mission ("read-only, evidence-grade
automation for FedRAMP 20x & Rev5 — a TypeScript collector that captures
AWS/GCP/Kubernetes config evidence … plus a local multi-user tracker over
the FRMR catalog"). It connects to every layer of the FedPy architecture:

### Cloud collectors (`providers/aws|gcp|azure/`)

LOOP-P does **not** add net-new cloud SDK calls for workforce screening —
that's process-artifact data managed by HR, not cloud config. LOOP-P
**reads** the existing IAM evidence collectors for two correlation tasks:

- **P.P3 termination correlation**: when a user is marked terminated in
  the tracker, the orchestrator cross-references `providers/*/iam.ts`
  output (existing IAM-SUS collector) to verify the IAM principal was
  in fact disabled within the org-defined PS-4 time window. Mismatch
  emits a POA&M finding tied to PS-4.
- **P.P5 dormancy correlation**: existing IAM-SUS dormant-account
  detection is correlated with HR-supplied employment status; a "dormant
  IAM principal" that maps to an "active employee" is one of the NITTF
  insider-threat behavioral indicators.

### KSI evidence envelopes (`out/KSI-*.json`)

LOOP-P emits new KSI envelopes:

- `out/KSI-PIY-PSE.json` — Personnel Security Evidence (new process-
  artifact KSI introduced by this loop; the `PIY-PSE` token is added to
  `core/ksi-map.ts`).
- `out/KSI-PIY-ITP.json` — Insider Threat Program evidence (PM-12).
- `out/KSI-PIY-AGM.json` — Access Agreement Management (PS-6).

Each envelope follows the existing `core/envelope.ts` schema (signed,
timestamped, with `provenance` block) and lands in the submission bundle
via `core/submission-bundle.ts` well-known role catalogue.

### OSCAL chain (SSP → AP → AR → POA&M)

- **SSP**: P.P1 contributes an `implemented-requirements` entry for
  PM-12 with by-component narrative drawn from the ITP plan; P.P2
  populates PS-1 through PS-9 implementation statements.
- **AP**: P.P2 + P.P3 add OSCAL `assessment-activities[]` for PS-3
  screening verification and PS-4 termination sample testing.
- **AR**: existing AR chain (LOOP-A.A3) receives PS-family
  `finding-target` references; deltas flow into LOOP-E.E1 monthly report.
- **POA&M**: failed PS controls (e.g. screening records missing for a
  sample user) emit standard `poam-item` entries via the LOOP-A.A1
  emitter — extended in P.P3 to recognise the PS-specific finding shape.

### FRMR catalog (`docs/frmr-requirements.generated.json`)

LOOP-P does NOT add to the FedRAMP-published FRMR catalog (that catalog
is upstream). It DOES map the new PIY-PSE / PIY-ITP / PIY-AGM KSI tokens
into `core/ksi-map.ts` so the existing FRMR-walk + control-benchmark
pipeline picks them up. The mapping cites NIST 800-53 Rev5 PS-1..PS-9 +
PM-12 as the underlying NIST controls (via `core/control-benchmark.ts`).

### Tracker DB (SQLite)

LOOP-P adds **eight** new tables to `tracker/server/schema.sql`:

```sql
insider_threat_program       -- single-row org-wide ITP attestation
insider_threat_indicators    -- behavioral indicators catalog (operator-tunable)
insider_threat_cases         -- active + historical insider-threat cases
insider_threat_team_roster   -- cross-discipline team membership (PM-12 requirement)
personnel_positions          -- PS-2 position risk designations
personnel_screening_records  -- PS-3 per-user screening + re-screening cadence
personnel_lifecycle_events   -- PS-4/PS-5 termination + transfer events
access_agreements            -- PS-6 NDA + acceptable-use signature ledger
```

All eight tables follow the LOOP-B pattern: signed audit log, RBAC
(roles `hr`, `iso`, `ao`, `assessor`), Ed25519 signatures over canonical
JSON, idempotent `CREATE TABLE IF NOT EXISTS` migration.

### REO standard (CLAUDE.md)

Every LOOP-P emit field traces to one of:

1. Cloud SDK call (e.g. IAM-SUS correlation).
2. Tracker DB row (every screening record, termination event, access
   agreement signature is a real signed row).
3. Operator-supplied config (`config/workforce-policy.yaml` carries the
   org-defined PS-4 time window, the PS-3 re-screening frequency, etc.).
4. `REQUIRES-OPERATOR-INPUT` marker when a per-user screening date is
   missing — surfaced on every affected OSCAL prop, never silently
   defaulted.

No stubs. No fabricated screening dates. No "all good" attestations
that aren't backed by a signed tracker entry.

---

## 3. Dependencies

### Loops / slices that MUST complete first

| Dep | Why |
|---|---|
| LOOP-A.A1 (`core/oscal-poam.ts`) | P.P2 + P.P3 emit POA&M items for screening/termination findings; reuses the existing emitter. |
| LOOP-A.A2 (`core/oscal-ap.ts`) | P.P2 + P.P3 add `assessment-activities[]` to the SAP. |
| LOOP-A.A3 (AR chain) | P.P2/P.P3 findings flow through the AR chain validator. |
| LOOP-A.A4 (`core/submission-bundle.ts`) | LOOP-P adds 8+ new roles to the well-known artifact catalogue. |
| LOOP-J.J1 (User Roles & Privileges matrix, AC-2 + AC-6) | P.P2 reads the roles matrix to enumerate positions for PS-2 risk designation. |
| Tracker user accounts + RBAC + audit log | Already in tracker; LOOP-P extends with `hr` role. |
| `core/ksi-map.ts` (existing) | LOOP-P registers three new KSI tokens (PIY-PSE, PIY-ITP, PIY-AGM). |
| `providers/*/iam.ts` (existing IAM-SUS collector) | P.P3 + P.P5 cross-reference dormant-IAM-principal signals. |
| `core/notify.ts` (existing) | P.P3 + P.P5 fire termination + behavioral-indicator notifications. |
| `core/envelope.ts` + `core/findings.ts` (existing) | All P emitters land Finding entries in standard envelopes. |
| `core/sign.ts` (existing Ed25519 + RFC 3161) | Every P artifact + DB record is signed by the existing pipeline. |

### Existing files this loop EXTENDS

| File | Modification |
|---|---|
| `cloud-evidence/core/ksi-map.ts` | Register `PIY-PSE`, `PIY-ITP`, `PIY-AGM` token entries with their NIST 800-53 r5 control mappings (PS-1..PS-9 for PSE; PM-12 for ITP; PS-6 for AGM). |
| `cloud-evidence/core/orchestrator.ts` | New flags: `--insider-threat-program`, `--personnel-evidence`, `--workforce-monitoring`, `--access-agreements`, `--strict-workforce` plus env equivalents. |
| `cloud-evidence/core/submission-bundle.ts` | Add roles `insider-threat-program-docx`, `position-risk-register-json`, `screening-records-snapshot`, `personnel-lifecycle-snapshot`, `access-agreements-snapshot`, `workforce-indicators-json`. |
| `cloud-evidence/core/control-benchmark.ts` | Wire PS-1..PS-9 and PM-12 to the new KSI emitters (so the benchmark coverage report counts them). |
| `cloud-evidence/core/oscal-ssp.ts` | Add per-component implementation narrative blocks for PS-1..PS-9 and PM-12 (reads from tracker `insider_threat_program` + `personnel_positions` + `access_agreements`). |
| `cloud-evidence/core/oscal-ap.ts` | Add PS-3 + PS-4 assessment-activities[] (sample-test procedures). |
| `cloud-evidence/core/oscal-poam.ts` | Recognise `psFindingKind` discriminator on Finding entries; map to NIST 800-53 PS-* in `related-observations`. |
| `cloud-evidence/CHANGELOG.md` | Unreleased entry per slice (see Section 9). |
| `cloud-evidence/docs/STATUS.md` | Per-slice status line updated when slice ships; new LOOP-P table section. |
| `tracker/server/schema.sql` | Eight new tables (above). |
| `tracker/server/index.ts` | Mount new routes (see per-slice specs). |
| `tracker/server/rbac.ts` | New `hr` role + per-route permissions. |
| `tracker/client/src/App.tsx` | Add routes `/insider-threat-program`, `/personnel-positions`, `/screening-records`, `/personnel-lifecycle`, `/access-agreements`, `/workforce-monitoring`. |
| `cloud-evidence/config/workforce-policy.example.yaml` | NEW committed example operator copies + customises (PS-4 time window, PS-3 re-screening cadence, etc.). |

### Loops UNBLOCKED when LOOP-P is complete

| Unblocked loop | Reason |
|---|---|
| LOOP-C.C7 — Risk Management Strategy doc | Pulls insider-threat case summary as a real organisational risk class. |
| LOOP-E.E1 — Monthly ConMon report | Adds workforce indicators delta (new screenings, terminations within SLA, expired access agreements). |
| LOOP-E.E5 — Deviation Request emitter | Acceptance workflow for "screening overdue but mitigating control X" reuses B.B3 + P.P2 records. |
| LOOP-F.F3 — Sample selection methodology | 3PAO sampling for PS-3 verification uses P.P2 position register as the population frame. |
| LOOP-J.J2 — Subprocessor inventory expansion (SA-9) | PS-7 external-personnel-security side reads P.P2 third-party position-risk designations. |

---

## 4. Authoritative sources

Every URL + spec referenced in any LOOP-P slice. All quotes are verbatim
where retrievable. Where the source PDF/HTML returns 403 to anonymous
fetches, the slice records the URL + the implementer must download the
PDF into `cloud-evidence/docs/sources/` and re-quote in the slice
docstring. Quotes below are pulled from the audit doc
(`docs/ADDITIONAL-LOOPS-AUDIT.md` §2 LOOP-P) and from successful
WebFetches done by the spec author on 2026-06-07.

### NIST SP 800-53 Rev5 — Personnel Security family (PS-1 through PS-9)

- **NIST SP 800-53 Rev5** — full catalog:
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  Also at NIST CPRT (search by family "PS"):
  https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search

- **PS-1 (Policy and Procedures)** — control statement:
  > "Develop, document, and disseminate to [Assignment: organization-
  > defined personnel or roles]: 1. [Selection (one or more):
  > Organization-level; Mission/business process-level; System-level]
  > personnel security policy that: (a) Addresses purpose, scope, roles,
  > responsibilities, management commitment, coordination among
  > organizational entities, and compliance; and (b) Is consistent with
  > applicable laws, executive orders, directives, regulations, policies,
  > standards, and guidelines; and 2. Procedures to facilitate the
  > implementation of the personnel security policy and the associated
  > personnel security controls."

  (FedRAMP Moderate baseline: REQUIRED. Source: NIST 800-53B Rev5.
  Operator-supplied policy text + tracker-stored review cadence.)

- **PS-2 (Position Risk Designation)** — control statement (cited
  verbatim from the audit doc and from the NIST CPRT control view):
  > "a. Assign a risk designation to all organizational positions;
  > b. Establish screening criteria for individuals filling those
  > positions; and
  > c. Review and update position risk designations [Assignment:
  > organization-defined frequency]."

  (FedRAMP Moderate baseline: REQUIRED. The audit doc quotes:
  > "designate the risk level of all organizational positions; review and
  > update designations periodically".)

- **PS-3 (Personnel Screening)** — control statement (verbatim, audit
  doc §2 LOOP-P + NIST 800-53r5):
  > "a. Screen individuals prior to authorizing access to the system;
  > and b. Rescreen individuals in accordance with [Assignment:
  > organization-defined conditions requiring rescreening and, where
  > rescreening is so indicated, the frequency of rescreening]."

- **PS-4 (Personnel Termination)** — control statement (verbatim, audit
  doc):
  > "Upon termination of individual employment: a. Disable system access
  > within [Assignment: organization-defined time period]; b. Terminate
  > or revoke any authenticators and credentials associated with the
  > individual; c. Conduct exit interviews that include [Assignment:
  > organization-defined topics]; d. Retrieve all security-related
  > organizational system-related property; and e. Retain access to
  > organizational information and systems formerly controlled by the
  > terminated individual."

- **PS-5 (Personnel Transfer)** — control statement:
  > "a. Review and confirm ongoing operational need for current logical
  > and physical access authorizations to systems and facilities when
  > individuals are reassigned or transferred to other positions within
  > the organization; b. Initiate [Assignment: organization-defined
  > transfer or reassignment actions] within [Assignment: organization-
  > defined time period following the formal transfer action]; c. Modify
  > access authorization as needed to correspond with any changes in
  > operational need due to reassignment or transfer; and d. Notify
  > [Assignment: organization-defined personnel or roles] within
  > [Assignment: organization-defined time period]."

- **PS-6 (Access Agreements)** — control statement:
  > "a. Develop and document access agreements for organizational
  > systems; b. Review and update the access agreements [Assignment:
  > organization-defined frequency]; and c. Verify that individuals
  > requiring access to organizational information and systems:
  > 1. Sign appropriate access agreements prior to being granted
  > access; and 2. Re-sign access agreements to maintain access to
  > organizational systems when access agreements have been updated or
  > [Assignment: organization-defined frequency]."

- **PS-7 (External Personnel Security)** — control statement:
  > "a. Establish personnel security requirements, including security
  > roles and responsibilities for external providers; b. Require
  > external providers to comply with personnel security policies and
  > procedures established by the organization; c. Document personnel
  > security requirements; d. Require external providers to notify
  > [Assignment: organization-defined personnel or roles] of any
  > personnel transfers or terminations of external personnel who
  > possess organizational credentials or badges, or who have system
  > privileges within [Assignment: organization-defined time period];
  > and e. Monitor provider compliance with personnel security
  > requirements."

- **PS-8 (Personnel Sanctions)** — control statement:
  > "a. Employ a formal sanctions process for individuals failing to
  > comply with established information security and privacy policies
  > and procedures; and b. Notify [Assignment: organization-defined
  > personnel or roles] within [Assignment: organization-defined time
  > period] when a formal employee sanctions process is initiated,
  > identifying the individual sanctioned and the reason for the
  > sanction."

- **PS-9 (Position Descriptions)** — control statement:
  > "Incorporate security and privacy roles and responsibilities into
  > organizational position descriptions."

### NIST SP 800-53 Rev5 — Program Management (PM-12, PM-13)

- **PM-12 (Insider Threat Program)** — control statement (verbatim,
  audit doc §2 LOOP-P):
  > "Implement an insider threat program that includes a cross-
  > discipline insider threat incident handling team."

  (FedRAMP Moderate baseline: REQUIRED. Discussion text (NIST):
  > "Organizations that handle classified information are required, under
  > Executive Order 13587 and the National Insider Threat Policy, to
  > establish insider threat programs. The standards and guidelines that
  > apply to insider threat programs in classified environments can also
  > be employed effectively to improve the security of [Controlled
  > Unclassified Information] in non-national security systems.")

- **PM-13 (Security and Privacy Workforce)** — control statement:
  > "Establish a security and privacy workforce development and
  > improvement program."

### Executive Order 13587 (October 7, 2011)

- **Executive Order 13587 — Structural Reforms to Improve the Security
  of Classified Networks and the Responsible Sharing and Safeguarding
  of Classified Information** —
  https://obamawhitehouse.archives.gov/the-press-office/2011/10/07/executive-order-13587-structural-reforms-improve-security-classified-net

  WebFetch quotes returned (2026-06-07):
  > "The order establishes an interagency task force to 'develop a
  > Government-wide program (insider threat program) for deterring,
  > detecting, and mitigating insider threats.'"

  > "Agency heads must designate a senior official and 'implement an
  > insider threat detection and prevention program consistent with
  > guidance and standards developed by the Insider Threat Task Force.'"

  > "Key duties included developing 'a Government-wide policy for the
  > deterrence, detection, and mitigation of insider threats' and
  > issuing 'minimum standards and guidance for implementation' that
  > would be 'binding on the executive branch.'"

  (LOOP-P references EO 13587 §2.1 for agency-side ITP obligations and
  §6 for the NITTF mandate. Although EO 13587 is technically classified
  network-scoped, NIST 800-53 PM-12 discussion explicitly extends the
  same standards to CUI / non-national security systems, which is the
  FedRAMP-Moderate context.)

### National Insider Threat Task Force (NITTF) — Minimum Standards

- **National Insider Threat Task Force homepage** —
  https://www.dni.gov/index.php/ncsc-who-we-are/organizations/ncsc-nittf
  (returns 403 to anonymous fetch; operator downloads documents
  manually into `cloud-evidence/docs/sources/nittf-minimum-standards.pdf`
  before P.P1 + P.P5 finalize their citations.)

- **National Insider Threat Policy and Minimum Standards** (Nov 21, 2012):
  https://www.dni.gov/index.php/ncsc-newsroom/ncsc-cpd/3251-natinal-insider-threat-policy-and-minimum-standards
  Six elements an insider-threat program must address (drawn from the
  NITTF Minimum Standards summary):
  1. Designated senior official (Insider Threat Senior Official, ITSO).
  2. Cross-discipline incident handling team (HR, security, IT, legal,
     counterintelligence, behavioral science where applicable).
  3. Personnel access controls + monitoring of user activity on
     classified/CUI systems.
  4. Information integration + analysis (correlating personnel +
     network indicators).
  5. Insider threat training + awareness for all cleared personnel.
  6. Self-assessment / annual program review.

  LOOP-P.P1 tracks these six elements as required attestations in the
  ITP plan; LOOP-P.P5 implements element #3 (monitoring) + #4
  (information integration).

### 32 CFR Part 117 — NISPOM (National Industrial Security Program Operating Manual)

- **32 CFR Part 117** —
  https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-D/part-117
  (Note: eCFR redirects to Federal Register unblock service. Implementer
  re-fetches at run time or downloads the rule HTML to
  `cloud-evidence/docs/sources/32-cfr-117.html`.)

- **32 CFR 117.7 — Insider Threat Program** (verbatim, audit doc):
  > "Contractors shall establish and maintain an insider threat program
  > to detect, deter, and mitigate insider threats."

  Per 32 CFR 117.7(b), the ITP must:
  - Designate a senior official (Insider Threat Program Senior Official,
    ITPSO).
  - Establish capabilities to gather, integrate, and report relevant
    information consistent with applicable law.
  - Provide insider threat training within 30 days of initial assignment.
  - Self-certify the ITP implementation.

  (LOOP-P applies this scope to FedRAMP CSPs that hold CUI or
  classified-adjacent agency data; otherwise the NISPOM obligations are
  documented as advisory in the ITP plan and the SSP narrative cites
  PM-12 + EO 13587 as the binding obligation.)

### OPM — 5 CFR Part 731 (Suitability) + Position Designation System

- **5 CFR Part 731** (Suitability):
  https://www.ecfr.gov/current/title-5/chapter-I/subchapter-B/part-731
  5 CFR 731.106 mandates position risk levels:
  > "Each agency head shall designate every covered position within the
  > agency at a high, moderate, or low risk level as determined by the
  > position's potential for adverse impact to the efficiency or
  > integrity of the service."

  Position risk levels (LOOP-P.P2 uses these tokens verbatim as the
  `position_risk_level` enum):
  - **High Risk** — Public Trust positions with broad scope and
    authority, including positions involved in policy-making, major
    program responsibility, public safety + health, law enforcement,
    significant fiduciary responsibilities, or other duties demanding the
    highest degree of public trust.
  - **Moderate Risk** — Public Trust positions with moderate scope and
    authority.
  - **Low Risk** — Positions with low scope and authority.

  Additional sensitivity levels (national security positions, per
  5 CFR 1400 / 32 CFR 147):
  - **Special-Sensitive (SS)** — top-secret access + sensitive
    compartmented information access.
  - **Critical-Sensitive (CS)** — top-secret access.
  - **Noncritical-Sensitive (NCS)** — secret access.
  - **Non-Sensitive (NS)** — no national security access.

  LOOP-P.P2 stores both axes per position (`public_trust_level` and
  `national_security_level`) so a CSP holding CUI for a national-
  security-context customer can declare both.

- **OPM Position Designation System policy page**:
  https://www.opm.gov/suitability/suitability-executive-agent/policy/position-designation/
  (timed out on fetch 2026-06-07; implementer downloads the policy HTML
  manually into sources.)

- **OPM Position Designation Tool (PDT)** — automated position-risk
  assignment tool federal agencies use:
  https://nbib.opm.gov/e-qip-background-investigations/position-designation/
  (LOOP-P.P2 does NOT integrate with PDT directly — too federal-internal
  — but ingests PDT JSON exports as an optional input source for the
  position register.)

### CISA Insider Threat Mitigation Guide

- **CISA Insider Threat Mitigation Guide**:
  https://www.cisa.gov/topics/physical-security/insider-threat-mitigation

- **CISA Insider Threat Mitigation Guide Publication (PDF)**:
  https://www.cisa.gov/sites/default/files/2023-02/Insider%20Threat%20Mitigation%20Guide_Final_508.pdf
  (Operator downloads to
  `cloud-evidence/docs/sources/cisa-insider-threat-mitigation-guide.pdf`
  before P.P5 finalizes its behavioral-indicator catalogue.)

  Key concepts P.P5 imports verbatim:
  - The "Pathway to Insider Threat" model — Personal Predispositions,
    Stressors, Concerning Behaviors, Problematic Organizational
    Responses.
  - 33 behavioral indicators across four categories (Verbal, Behavioral,
    Cyber, Physical-access).
  - Hub-and-spoke insider threat program model (intersects with NITTF
    cross-discipline team requirement).

### FedRAMP CSP Personnel Security guidance

- **FedRAMP Rev5 SSP Template — Section 13 / Appendix A** controls
  implementation guidance for PS-1..PS-9 — operator follows the FedRAMP
  Rev5 template structure. P.P2 + P.P4 emit OSCAL `implemented-
  requirement` blocks that the SSP renderer in LOOP-A.A1 (and the docx
  renderer SSP-2) consume.

- **FedRAMP CSP Authorization Playbook** —
  https://www.fedramp.gov/docs/rev5/playbook/csp/
  (Section on personnel security obligations — references NIST 800-53
  PS family verbatim; LOOP-P SSP narrative blocks tie back here.)

### NIST SP 800-37 Rev 2 — RMF (organizational context)

- **NIST SP 800-37 Rev 2** —
  https://csrc.nist.gov/pubs/sp/800/37/r2/final
  Step 6 (Authorize) requires the SSP to enumerate every Moderate
  baseline control; PS-1..PS-9 + PM-12 are in scope; LOOP-P closes the
  authoring gap.

### NIST SP 800-181 Rev 1 — NICE Workforce Framework (PM-13 context)

- **NIST SP 800-181 Rev 1** (Workforce Framework for Cybersecurity):
  https://csrc.nist.gov/publications/detail/sp/800-181/rev-1/final
  PM-13 (Security and Privacy Workforce) references the NICE Framework;
  LOOP-P.P1 ITP plan cites NICE Work Roles as the language for
  cross-discipline team membership categories.

---

## 5. Per-slice implementation specs

### Slice P.P1 — Insider Threat Program documentation + tracker workflow

**Why this slice**: NIST 800-53 Rev5 PM-12 ("Implement an insider threat
program that includes a cross-discipline insider threat incident handling
team") is in the FedRAMP Moderate baseline. EO 13587 §2.1 makes the
program obligation organization-level. NITTF Minimum Standards (Nov 2012)
enumerate six required program elements. Today the FedPy artifact corpus
has no ITP plan, no team roster, no incident log — meaning the SSP cannot
truthfully cite PM-12 implementation. P.P1 ships the .docx ITP plan + the
tracker tables that produce signed, ongoing evidence the plan is operating.

**Connection to FedPy mission**: Reuses the existing tracker auth + RBAC
+ audit log pipeline; emits a .docx artifact through the same OOXML
pattern as `core/roe-emit.ts` (LOOP-A.A5) and `core/ssp-2.ts`. The ITP
plan + roster signed-attestation + case log become a new KSI process-
artifact envelope `out/KSI-PIY-ITP.json` consumed by the OSCAL SSP
implementation-statement for PM-12.

**Files to create**:
- `cloud-evidence/core/insider-threat-program.ts` — .docx emitter
  (OOXML + zip-store pattern, no external libs) producing the ITP plan
  per NITTF Minimum Standards (six elements). ~700 lines.
- `cloud-evidence/core/itp-evidence.ts` — KSI envelope builder. Reads
  tracker tables (`insider_threat_program`, `insider_threat_indicators`,
  `insider_threat_cases`, `insider_threat_team_roster`) and emits
  `out/KSI-PIY-ITP.json`.
- `tracker/server/routes/insider-threat-program.ts` — Express CRUD
  routes for the four tables.
- `tracker/server/routes/insider-threat-cases.ts` — Express routes
  scoped to case lifecycle (open / investigating / closed / referred).
- `tracker/client/src/pages/InsiderThreatProgram.tsx` — ITP plan editor
  (covers the 6 NITTF elements) + roster + cases UI.
- `tracker/client/src/pages/InsiderThreatCaseDetail.tsx` — per-case
  detail with signed audit record.
- `cloud-evidence/config/workforce-policy.example.yaml` — committed
  example (operator copies to `workforce-policy.yaml`, gitignored).
- Tests: `tests/core/insider-threat-program.test.ts`,
  `tests/core/itp-evidence.test.ts`, plus tracker route + UI tests.

**Files to extend**:
- `cloud-evidence/core/ksi-map.ts` — register `PIY-ITP` token with NIST
  PM-12 mapping.
- `cloud-evidence/core/orchestrator.ts` — new `--insider-threat-program`
  flag invokes the .docx emitter + KSI envelope builder.
- `cloud-evidence/core/oscal-ssp.ts` — implementation statement for
  PM-12 reads the ITP attestation.
- `cloud-evidence/core/submission-bundle.ts` — add roles
  `insider-threat-program-docx` (filename `insider-threat-program.docx`)
  and `insider-threat-program-snapshot`.
- `tracker/server/schema.sql` — four new tables.
- `tracker/server/index.ts` — mount routes with `requireRole(['iso','ao','hr'])`.
- `tracker/server/rbac.ts` — add `hr` role + per-route permissions.
- `tracker/client/src/App.tsx` — `/insider-threat-program` route.

**Schemas / standards**:
- **NIST 800-53 Rev5 PM-12** — see §4 above for verbatim quote.
- **EO 13587 §2.1 + §6** — see §4 above.
- **NITTF Minimum Standards** — six required elements (designated
  ITSO; cross-discipline team; access controls + monitoring;
  information integration; training; self-assessment).
- **32 CFR 117.7** — see §4 above; applies conditionally when CSP
  holds NISPOM-scoped data.
- **OSCAL SSP `implemented-requirements`** — schema field set:
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/
  See `implementation-statement.description` for the prose block P.P1
  populates from tracker text.

**Build steps**:

1. Define types in `core/insider-threat-program.ts`:
   ```ts
   export interface ItpAttestation {
     itso_user_id: number;          // Insider Threat Senior Official
     itso_name: string;
     itso_title: string;
     itpso_user_id?: number;        // ITPSO (NISPOM 32 CFR 117.7 senior official)
     itpso_name?: string;
     reviewed_at: string;           // ISO datetime, signed
     review_cadence_days: number;   // operator-defined, default 365
     six_elements: {
       senior_official: { attested: boolean; user_id?: number; note?: string };
       cross_discipline_team: { attested: boolean; roster_count: number; note?: string };
       access_controls_monitoring: { attested: boolean; tool_refs: string[] };
       information_integration: { attested: boolean; analyst_user_ids: number[] };
       training: { attested: boolean; training_cadence_days: number; last_completion_pct: number };
       self_assessment: { attested: boolean; last_assessment_date: string; next_due: string };
     };
     applies_nispom: boolean;       // operator declares whether 32 CFR 117 in scope
     signature: string;             // Ed25519 over canonical JSON
     signing_key_id: string;
   }
   ```

2. Tracker schema (DDL):
   ```sql
   CREATE TABLE IF NOT EXISTS insider_threat_program (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     itso_user_id INTEGER NOT NULL REFERENCES users(id),
     itpso_user_id INTEGER REFERENCES users(id),
     reviewed_at TEXT NOT NULL,
     review_cadence_days INTEGER NOT NULL DEFAULT 365,
     six_elements_json TEXT NOT NULL,        -- canonical JSON of the attestation
     applies_nispom INTEGER NOT NULL DEFAULT 0,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     created_at TEXT NOT NULL,
     CHECK (json_valid(six_elements_json))
   );

   CREATE TABLE IF NOT EXISTS insider_threat_team_roster (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     user_id INTEGER NOT NULL REFERENCES users(id),
     discipline TEXT NOT NULL CHECK (discipline IN ('hr','security','it','legal','counterintelligence','behavioral-science','other')),
     role TEXT NOT NULL,
     joined_at TEXT NOT NULL,
     left_at TEXT,
     status TEXT NOT NULL CHECK (status IN ('active','departed'))
   );

   CREATE TABLE IF NOT EXISTS insider_threat_indicators (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     code TEXT NOT NULL UNIQUE,              -- e.g. 'CISA-IND-04'
     category TEXT NOT NULL CHECK (category IN ('verbal','behavioral','cyber','physical-access')),
     description TEXT NOT NULL,
     severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
     source TEXT NOT NULL                    -- e.g. 'CISA-Insider-Threat-Mitigation-Guide-2023'
   );

   CREATE TABLE IF NOT EXISTS insider_threat_cases (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     opened_at TEXT NOT NULL,
     opened_by_user_id INTEGER NOT NULL REFERENCES users(id),
     subject_user_ref TEXT NOT NULL,         -- opaque ref; NOT a user_id, to keep HR data outside ordinary RBAC
     indicators_json TEXT NOT NULL,          -- array of indicator codes
     status TEXT NOT NULL CHECK (status IN ('open','investigating','closed-substantiated','closed-unsubstantiated','referred')),
     closed_at TEXT,
     resolution_summary TEXT,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL
   );
   ```

3. .docx emitter — sections (mirror the NITTF Minimum Standards table of
   contents):
   1. Cover page (system id, CSP, run id, review date, ITSO name + title)
   2. Authority + Scope (cites PM-12, EO 13587, NITTF Minimum Standards,
      conditionally 32 CFR 117.7)
   3. Senior Official Designation (ITSO + optional ITPSO)
   4. Cross-Discipline Team Roster (table from `insider_threat_team_roster`)
   5. Access Controls + Monitoring (refs to LOOP-P.P5 + existing IAM-SUS)
   6. Information Integration + Analysis (process narrative)
   7. Insider Threat Training (cadence + last completion %)
   8. Self-Assessment / Annual Program Review (last + next dates)
   9. Behavioral Indicator Catalogue (table from `insider_threat_indicators`)
   10. Case Handling Procedure (steps; signatures)
   11. Provenance (tool name, run id, ksi-map entry, NIST cite)
   - Every operator-supplied field renders `REQUIRES-OPERATOR-INPUT` when
     missing (mirroring `core/roe-emit.ts` patterns).

4. KSI envelope builder (`core/itp-evidence.ts`):
   - Reads tracker tables via `core/tracker-pull.ts` (existing).
   - Builds `Finding[]` entries per six-element compliance state.
   - Provenance block lists tracker URL, snapshot ISO timestamp, signing
     key id.
   - Emits to `out/KSI-PIY-ITP.json` with the standard envelope shape.

5. Orchestrator wiring: `--insider-threat-program` runs BEFORE
   `--oscal-ssp` so the SSP picks up the ITP attestation in its PM-12
   implementation statement.

6. SSP integration (`core/oscal-ssp.ts`): when PM-12 implementation
   block is rendered, read the latest ITP attestation; populate
   `implementation-statement.description` with a templated narrative
   citing the six elements + the signed attestation UUID; add prop
   `itp-attestation-uuid` to the implementation block.

7. Bundler integration: add `insider-threat-program-docx` role +
   `insider-threat-program-snapshot` role (the JSON snapshot
   `out/.itp-snapshot.json` pulled from tracker).

**REQUIRES-OPERATOR-INPUT fields** (REO Rule 4):
- ITSO designation (must be a tracker user; SSP renders REQUIRES-OPERATOR-
  INPUT when missing).
- ITPSO designation when `applies_nispom = true`.
- Six-element narrative text for items 3/4/6 (the prose explaining HOW
  monitoring + integration + training are operationalised).
- Behavioral-indicator catalogue (seeded from CISA Insider Threat
  Mitigation Guide; operator tunes severity bands).
- Training cadence + last completion %.
- Self-assessment last + next dates.
- `applies_nispom` (operator declares).

**Test specifications** (≥12):
1. `it('emits a .docx with all 10 sections rendered')`.
2. `it('renders REQUIRES-OPERATOR-INPUT when ITSO unset')`.
3. `it('renders ITSO name + title verbatim when set')`.
4. `it('renders cross-discipline team table from roster rows')`.
5. `it('renders behavioral indicator catalogue table')`.
6. `it('marks NISPOM-scope sections REQUIRES-OPERATOR-INPUT when applies_nispom=false')`.
7. `it('signs the ITP attestation with Ed25519')`.
8. `it('KSI-PIY-ITP envelope has provenance.emitter set')`.
9. `it('KSI-PIY-ITP envelope contains a Finding per six-element state')`.
10. `it('KSI-PIY-ITP envelope status reflects all-six-elements-attested')`.
11. `it('tracker route POST /api/itp accepts ISO + AO roles only')`.
12. `it('tracker route GET /api/itp returns latest attestation')`.
13. `it('case CRUD enforces uuid stability across updates')`.
14. `it('SSP PM-12 implementation statement includes attestation UUID prop')`.

**REO compliance** specific to this slice:
- Every emitted field traces to a signed tracker row.
- No synthesised attestation; missing fields emit REQUIRES-OPERATOR-INPUT
  visibly in the .docx + the envelope.
- Signatures are real Ed25519 over canonical JSON.
- Provenance block populated on `out/KSI-PIY-ITP.json`.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/insider-threat-program.test.ts tests/core/itp-evidence.test.ts
npm run check:reo
cd ../tracker
npm run typecheck
npm test -- server/routes/insider-threat-program.test.ts client/src/pages/InsiderThreatProgram.test.tsx
```

**Estimated effort**: 5 - 6 working days (emitter + tracker server + UI +
SSP wire-through).

---

### Slice P.P2 — Position risk designation per role (PS-2 + PS-3 screening)

**Why this slice**: NIST 800-53 Rev5 PS-2 ("Assign a risk designation to
all organizational positions; establish screening criteria; review and
update") and PS-3 ("Screen individuals prior to authorizing access;
rescreen…") are FedRAMP Moderate baseline. 5 CFR 731.106 supplies the
public-trust risk levels (High / Moderate / Low); 32 CFR 147 / 5 CFR 1400
supply the national-security sensitivity levels (Special-Sensitive /
Critical-Sensitive / Noncritical-Sensitive / Non-Sensitive). LOOP-J.J1
ships a Roles & Privileges matrix (AC-2 + AC-6) — P.P2 takes the same
positions table and overlays PS-2 risk designation + PS-3 per-user
screening + re-screening cadence.

**Connection to FedPy mission**: Reads `out/.roles-matrix.json` (LOOP-J.J1
pulled snapshot) for the position list. Adds a new collector-side emitter
that joins position metadata × per-user screening records into per-user
status rows. Outputs `out/position-risk-register.json` (PS-2
deliverable) + `out/KSI-PIY-PSE.json` envelope; failing PS-3 status
flows into POA&M items via the existing emitter.

**Files to create**:
- `cloud-evidence/core/position-risk-emit.ts` — pure builder + emitter.
- `cloud-evidence/core/personnel-evidence.ts` — KSI envelope builder for
  PIY-PSE.
- `tracker/server/routes/personnel-positions.ts` — CRUD for positions.
- `tracker/server/routes/screening-records.ts` — CRUD for screening
  records with cadence enforcer.
- `tracker/server/screening-record-enforcer.ts` — hourly task that flips
  records to `overdue` when re-screening cadence elapses.
- `tracker/client/src/pages/PersonnelPositions.tsx` — list + form UI.
- `tracker/client/src/pages/ScreeningRecords.tsx` — list + form UI.
- Tests for all of the above (≥12 per emitter; ≥15 across tracker).

**Files to extend**:
- `cloud-evidence/core/ksi-map.ts` — register `PIY-PSE` with mapping to
  NIST PS-1..PS-9.
- `cloud-evidence/core/orchestrator.ts` — `--personnel-evidence` flag.
- `cloud-evidence/core/oscal-ssp.ts` — implementation statements for
  PS-1..PS-9.
- `cloud-evidence/core/oscal-poam.ts` — accept `pssFindingKind` shape on
  Finding; map to PS-3 related-observations.
- `cloud-evidence/core/submission-bundle.ts` — new roles
  `position-risk-register-json`, `screening-records-snapshot`.
- `tracker/server/schema.sql` — two new tables (`personnel_positions`,
  `personnel_screening_records`).

**Schemas / standards**:
- **NIST 800-53 Rev5 PS-2 + PS-3** — verbatim quotes in §4.
- **5 CFR Part 731** — public-trust risk levels.
- **32 CFR Part 147 + 5 CFR 1400** — national-security sensitivity
  levels.
- **OPM Position Designation System** — workflow language; LOOP-P.P2
  uses the OPM tokens verbatim.

**Build steps**:

1. Tracker schema:
   ```sql
   CREATE TABLE IF NOT EXISTS personnel_positions (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     position_id TEXT NOT NULL UNIQUE,                -- operator-defined stable identifier
     title TEXT NOT NULL,
     description TEXT NOT NULL,
     public_trust_level TEXT NOT NULL CHECK (public_trust_level IN ('high','moderate','low','non-sensitive')),
     national_security_level TEXT NOT NULL CHECK (national_security_level IN ('special-sensitive','critical-sensitive','noncritical-sensitive','non-sensitive','not-applicable')),
     designated_at TEXT NOT NULL,
     designated_by_user_id INTEGER NOT NULL REFERENCES users(id),
     review_cadence_days INTEGER NOT NULL DEFAULT 365,
     next_review_due TEXT NOT NULL,
     ac_roles_json TEXT NOT NULL,                     -- linked AC-2 roles (from LOOP-J.J1)
     nist_control_ids TEXT NOT NULL,                  -- JSON array (PS-2 + PS-3 + relevant)
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('active','retired')) DEFAULT 'active'
   );
   CREATE INDEX IF NOT EXISTS idx_pos_review ON personnel_positions(next_review_due);

   CREATE TABLE IF NOT EXISTS personnel_screening_records (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     user_id INTEGER NOT NULL REFERENCES users(id),
     position_uuid TEXT NOT NULL REFERENCES personnel_positions(uuid),
     screening_type TEXT NOT NULL CHECK (screening_type IN ('tier-1','tier-2','tier-3','tier-4','tier-5','contractor-baseline','operator-defined')),
     screening_completed_at TEXT NOT NULL,
     next_rescreening_due TEXT NOT NULL,              -- computed from policy
     screening_evidence_url TEXT,                     -- e.g. link to OPM eApp completion
     screening_evidence_sha256 TEXT,
     status TEXT NOT NULL CHECK (status IN ('current','overdue','expired','revoked')),
     attested_by_user_id INTEGER NOT NULL REFERENCES users(id),
     attested_at TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_screen_due ON personnel_screening_records(next_rescreening_due);
   CREATE INDEX IF NOT EXISTS idx_screen_user ON personnel_screening_records(user_id);
   ```

2. Cadence enforcer task (`tracker/server/screening-record-enforcer.ts`):
   - Runs at boot + every hour.
   - Flips `status` to `overdue` when `next_rescreening_due < now()`.
   - Writes audit-log entry.
   - Surfaces via UI badge + emits via KSI envelope.

3. Reader (`core/personnel-evidence.ts`):
   - Pulls snapshots of both tables.
   - For each user with `iam_principal_active = true` (correlation with
     existing IAM-SUS data), match against `personnel_screening_records`
     and assert `status = 'current'`.
   - Failure case → Finding with `psFindingKind: 'screening-missing'` |
     `'screening-overdue'` | `'screening-expired'`.

4. Position risk register emitter (`core/position-risk-emit.ts`):
   - Joins positions × screening records × IAM principals.
   - Emits `out/position-risk-register.json` (PS-2 deliverable).
   - Columns: position_id, title, public_trust_level, national_security_
     level, AC-2 roles, current incumbents, screening status counts.

5. KSI envelope `out/KSI-PIY-PSE.json` carries:
   - One Finding per failing PS-3 (overdue / missing).
   - Aggregate gap for PS-2 (any position without designation).
   - References to OSCAL POA&M items for each failure.

6. SSP integration: PS-1..PS-9 implementation statements pull narrative
   from `config/workforce-policy.yaml` + the position register summary
   (no fabricated text).

7. POA&M integration: existing emitter handles `psFindingKind`; map to
   PS-3 in `related-observations`.

8. Orchestrator wiring: `--personnel-evidence` runs AFTER LOOP-J.J1
   roles matrix pull, BEFORE `--oscal-poam`.

**REQUIRES-OPERATOR-INPUT fields**:
- Position list (operator authors via tracker UI; can bulk-import via
  CSV → tracker route).
- Per-position `public_trust_level` (operator categorisation under 5
  CFR 731).
- Per-position `national_security_level` (operator declares; default
  `not-applicable` for non-NS CSPs).
- Per-user screening completion date + evidence URL.
- Re-screening cadence policy (`config/workforce-policy.yaml`:
  `rescreening_cadence_days`, defaults: high=5y/1825d, moderate=5y,
  low=5y per OPM but operator-tunable).
- Screening tier (per OPM Tier 1-5 plus contractor-baseline).

**Test specifications** (≥12):
1. `it('rejects public_trust_level not in OPM enum')`.
2. `it('rejects national_security_level not in 32 CFR 147 enum')`.
3. `it('enforcer flips status=overdue when next_rescreening_due<now')`.
4. `it('reader emits psFindingKind=screening-missing for IAM principal w/o screening row')`.
5. `it('reader emits psFindingKind=screening-overdue when status=overdue')`.
6. `it('position-risk-register.json columns match PS-2 schema')`.
7. `it('signs every screening record + position row with Ed25519')`.
8. `it('respects review_cadence_days from workforce-policy.yaml')`.
9. `it('KSI-PIY-PSE envelope status fails when any psFindingKind present')`.
10. `it('SSP PS-3 implementation statement cites operator workforce policy')`.
11. `it('rejects screening_evidence_sha256 mismatch when sha provided')`.
12. `it('CSV bulk-import upserts positions atomically with audit-log entries')`.
13. `it('RBAC: hr role can write positions; assessor can read; iso can approve')`.
14. `it('reader correlates with IAM-SUS to detect dormant-IAM-principal-with-active-screening anomaly')`.
15. `it('orchestrator --strict-workforce fails build when any PS-3 status=overdue')`.

**REO compliance**:
- Every screening row signed (Ed25519). Operator UI input → audit log →
  signed canonical JSON.
- No synthesised screening dates. Missing → REQUIRES-OPERATOR-INPUT.
- Position designations come from operator UI, not from defaults.
- IAM-SUS correlation is a real `providers/*/iam.ts` read.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/position-risk-emit.test.ts tests/core/personnel-evidence.test.ts
npm run check:reo
cd ../tracker
npm run typecheck
npm test -- server/routes/personnel-positions.test.ts server/routes/screening-records.test.ts server/screening-record-enforcer.test.ts
```

**Estimated effort**: 6 - 7 working days.

---

### Slice P.P3 — Personnel transfer + termination procedures (PS-4 + PS-5)

**Why this slice**: NIST 800-53 Rev5 PS-4 ("Upon termination of
individual employment … disable system access within [Assignment:
organization-defined time period]; terminate or revoke any authenticators
/ credentials associated with the individual") and PS-5 ("Review and
confirm ongoing operational need for current logical and physical access
authorizations to systems and facilities when individuals are reassigned
or transferred…"). Both demand structured, signed lifecycle events with
SLA evidence — today there is none. P.P3 ships the tracker workflow +
cross-checks the SLA against IAM-SUS observed disable times.

**Connection to FedPy mission**: P.P3 is the bridge between HR signals
(tracker) and cloud reality (`providers/*/iam.ts`). The orchestrator-
side reader reads the lifecycle events, then reads the existing IAM-SUS
output, then asserts the IAM principal was in fact disabled within the
org-defined PS-4 time window. Mismatches emit Findings tied to PS-4 in
POA&M.

**Files to create**:
- `cloud-evidence/core/personnel-lifecycle.ts` — pure builder. Reads
  tracker `personnel_lifecycle_events` + IAM-SUS snapshot; emits
  `out/KSI-PIY-PSE.json` Findings for PS-4 + PS-5; pure no-IO.
- `cloud-evidence/core/personnel-lifecycle-emit.ts` — disk-side emitter
  + orchestrator entry point.
- `tracker/server/routes/personnel-lifecycle.ts` — Express routes.
- `tracker/server/lifecycle-sla-enforcer.ts` — task: checks each
  termination/transfer for SLA breach vs IAM-SUS observed-disable time.
- `tracker/client/src/pages/PersonnelLifecycle.tsx` — Lifecycle event
  log UI with signed-checklist for terminations.
- `tracker/client/src/pages/PersonnelLifecycleDetail.tsx` — per-event
  signed audit record view.
- Tests: ≥12.

**Files to extend**:
- `cloud-evidence/core/orchestrator.ts` — `--personnel-lifecycle` flag.
- `cloud-evidence/core/notify.ts` — fire termination event on tracker
  POST.
- `cloud-evidence/core/oscal-ssp.ts` — implementation statements for
  PS-4 + PS-5 reference signed termination checklist procedure.
- `tracker/server/schema.sql` — new table `personnel_lifecycle_events`.

**Schemas / standards**:
- **NIST 800-53 Rev5 PS-4** — see §4 verbatim.
- **NIST 800-53 Rev5 PS-5** — see §4 verbatim.
- **OSCAL POA&M `risk` schema** — Finding maps to PS-4 via
  `related-observations[].subjects[]` referencing the user's IAM principal.

**Build steps**:

1. Tracker schema:
   ```sql
   CREATE TABLE IF NOT EXISTS personnel_lifecycle_events (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     event_type TEXT NOT NULL CHECK (event_type IN ('termination-voluntary','termination-involuntary','transfer-internal','transfer-promotion','transfer-demotion','contractor-end')),
     user_id INTEGER NOT NULL REFERENCES users(id),
     prior_position_uuid TEXT NOT NULL,        -- references personnel_positions
     new_position_uuid TEXT,                   -- null for terminations
     effective_at TEXT NOT NULL,               -- when the termination/transfer took effect (HR-recorded)
     access_revoked_at TEXT,                   -- when IT confirmed access revocation
     authenticators_revoked_at TEXT,
     credentials_recovered_at TEXT,
     exit_interview_completed_at TEXT,         -- PS-4 (c)
     property_returned_at TEXT,                -- PS-4 (d)
     information_retention_attested_at TEXT,   -- PS-4 (e)
     org_defined_time_period_hours INTEGER NOT NULL,  -- from workforce-policy.yaml
     sla_status TEXT NOT NULL CHECK (sla_status IN ('within-sla','breached','pending')),
     iam_observed_disabled_at TEXT,            -- from IAM-SUS correlation
     processed_by_user_id INTEGER NOT NULL REFERENCES users(id),
     processed_at TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     CHECK (event_type LIKE 'termination%' OR (new_position_uuid IS NOT NULL))
   );
   CREATE INDEX IF NOT EXISTS idx_lifecycle_user ON personnel_lifecycle_events(user_id);
   CREATE INDEX IF NOT EXISTS idx_lifecycle_effective ON personnel_lifecycle_events(effective_at);
   CREATE INDEX IF NOT EXISTS idx_lifecycle_sla ON personnel_lifecycle_events(sla_status);
   ```

2. SLA enforcer (`tracker/server/lifecycle-sla-enforcer.ts`):
   ```ts
   const pending = db.prepare(`
     SELECT * FROM personnel_lifecycle_events
     WHERE event_type LIKE 'termination%' AND sla_status = 'pending'
   `).all();
   for (const row of pending) {
     const slaDeadline = new Date(new Date(row.effective_at).getTime() +
       row.org_defined_time_period_hours * 3600 * 1000);
     const observed = row.iam_observed_disabled_at
       ? new Date(row.iam_observed_disabled_at)
       : null;
     if (observed && observed <= slaDeadline) {
       db.prepare(`UPDATE personnel_lifecycle_events SET sla_status='within-sla' WHERE id=?`).run(row.id);
     } else if (new Date() > slaDeadline) {
       db.prepare(`UPDATE personnel_lifecycle_events SET sla_status='breached' WHERE id=?`).run(row.id);
       auditLog.write({ event: 'ps-4-sla-breach', uuid: row.uuid, at: new Date().toISOString() });
     }
   }
   ```

3. Reader (`core/personnel-lifecycle.ts`):
   - Pulls events snapshot + IAM-SUS snapshot.
   - For each termination: assert IAM principal in `providers/*/iam.ts`
     output is `disabled` AND `disabled_at <= effective_at + org_defined_
     time_period_hours`. Mismatch → Finding `psFindingKind: 'ps-4-breached'`.
   - For each transfer: assert previous AC-2 role membership removed +
     new role membership added; mismatch → Finding `psFindingKind: 'ps-5-
     access-not-rebaselined'`.
   - Checklist 5-step (PS-4 a-e) — per termination, every checklist box
     attested? Mismatch → Finding.

4. SSP integration: PS-4 + PS-5 implementation statements describe the
   tracker-driven workflow + cite operator policy time window.

5. Orchestrator wiring: `--personnel-lifecycle` runs AFTER providers
   collect (so IAM-SUS data is fresh), BEFORE POA&M emission.

**REQUIRES-OPERATOR-INPUT fields**:
- `org_defined_time_period_hours` — `config/workforce-policy.yaml`
  `ps4_time_period_hours` (default 24; FedRAMP Moderate typical is 24h).
- Per-event effective time, access-revocation timestamps (HR/IT UI input).
- Exit-interview / property-return / information-retention attestations
  (per-row checkboxes signed by `hr` role).

**Test specifications** (≥12):
1. `it('rejects event_type not in enum')`.
2. `it('terminations require all five PS-4 a-e checkboxes attested')`.
3. `it('SLA enforcer transitions pending→within-sla when IAM observed_disabled<=deadline')`.
4. `it('SLA enforcer transitions pending→breached when deadline passed without observation')`.
5. `it('reader emits psFindingKind=ps-4-breached on SLA breach')`.
6. `it('reader emits psFindingKind=ps-5-access-not-rebaselined for transfers with no role delta')`.
7. `it('reader does NOT emit Finding when within SLA + all checkboxes set')`.
8. `it('signs lifecycle events with Ed25519')`.
9. `it('respects workforce-policy.yaml ps4_time_period_hours override')`.
10. `it('correlates with providers/aws/iam.ts IAM-SUS output for disable observation')`.
11. `it('emits POA&M item with related-observation citing the IAM principal')`.
12. `it('notify.ts fires on tracker termination POST')`.
13. `it('UI: signed-checklist requires hr role')`.
14. `it('--strict-workforce fails build on any sla_status=breached')`.

**REO compliance**:
- Termination signed; checklist signed; IAM correlation real
  (existing `providers/*/iam.ts` output, no mocks).
- SLA breach is observable in OSCAL POA&M with cited evidence path
  (the IAM principal id + observation timestamp).
- No silent "passed" status; missing IAM observation flags the SLA as
  `pending` until either observed or deadline.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/personnel-lifecycle.test.ts tests/core/personnel-lifecycle-emit.test.ts
npm run check:reo
cd ../tracker
npm test -- server/routes/personnel-lifecycle.test.ts server/lifecycle-sla-enforcer.test.ts client/src/pages/PersonnelLifecycle.test.tsx
```

**Estimated effort**: 5 - 6 working days.

---

### Slice P.P4 — Access agreements + acknowledgments + NDA (PS-6)

**Why this slice**: NIST 800-53 Rev5 PS-6 mandates documented access
agreements, periodic re-signing when agreements change, and verified
per-individual signature evidence. Today the FedPy corpus has no
agreement template, no signature ledger, no re-sign cadence enforcement.
P.P4 ships the .docx template emitter (covers NDA, acceptable-use,
non-disclosure, rules-of-behavior) + the tracker signature ledger with
canonical-JSON signature evidence per user × agreement version.

**Connection to FedPy mission**: Reuses the OOXML emitter pattern from
`core/roe-emit.ts` for the .docx template; reuses the tracker signed-
audit-log pattern; emits a new KSI envelope `out/KSI-PIY-AGM.json`
consumed by SSP PS-6 implementation statement; failure (user has IAM
access but no current signed agreement) emits POA&M items.

**Files to create**:
- `cloud-evidence/core/access-agreements.ts` — .docx template emitter
  (configurable: which agreement types — NDA / AUP / NDA-with-clearance
  / rules-of-behavior).
- `cloud-evidence/core/access-agreements-evidence.ts` — KSI envelope
  builder.
- `tracker/server/routes/access-agreements.ts` — Express routes.
- `tracker/server/routes/access-agreement-signatures.ts` — per-signature
  ledger CRUD.
- `tracker/server/access-agreement-resign-enforcer.ts` — flips
  signature status to `requires-resign` when agreement version bumps.
- `tracker/client/src/pages/AccessAgreements.tsx` — list + version
  history UI.
- `tracker/client/src/pages/AccessAgreementSign.tsx` — per-user sign
  flow (user reads agreement → confirms → server records signature).
- Tests: ≥12.

**Files to extend**:
- `cloud-evidence/core/ksi-map.ts` — register `PIY-AGM` token with
  PS-6 mapping.
- `cloud-evidence/core/orchestrator.ts` — `--access-agreements` flag.
- `cloud-evidence/core/oscal-ssp.ts` — PS-6 implementation statement
  reads agreement metadata.
- `cloud-evidence/core/submission-bundle.ts` — roles
  `access-agreements-docx`, `access-agreements-snapshot`.
- `tracker/server/schema.sql` — two new tables (`access_agreements`,
  `access_agreement_signatures`).

**Schemas / standards**:
- **NIST 800-53 Rev5 PS-6** — see §4 verbatim.
- **FedRAMP Rules of Behavior template** — typical access agreement
  content (operator may seed); we don't ship FedRAMP-licensed verbiage,
  only the structural template.

**Build steps**:

1. Tracker schema:
   ```sql
   CREATE TABLE IF NOT EXISTS access_agreements (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     agreement_type TEXT NOT NULL CHECK (agreement_type IN ('nda','acceptable-use','rules-of-behavior','non-disclosure','contractor-conduct','operator-defined')),
     version TEXT NOT NULL,                  -- e.g. '2026.1'
     title TEXT NOT NULL,
     body_markdown TEXT NOT NULL,            -- operator-authored body
     body_sha256 TEXT NOT NULL,              -- pinned content hash
     effective_at TEXT NOT NULL,
     review_cadence_days INTEGER NOT NULL DEFAULT 365,
     next_review_due TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('draft','active','retired')),
     superseded_by_uuid TEXT,
     created_by_user_id INTEGER NOT NULL REFERENCES users(id),
     approved_by_user_id INTEGER REFERENCES users(id),
     approved_at TEXT,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     UNIQUE (agreement_type, version)
   );

   CREATE TABLE IF NOT EXISTS access_agreement_signatures (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     agreement_uuid TEXT NOT NULL REFERENCES access_agreements(uuid),
     user_id INTEGER NOT NULL REFERENCES users(id),
     signed_at TEXT NOT NULL,
     ip_address TEXT NOT NULL,
     user_agent TEXT NOT NULL,
     attestation_text TEXT NOT NULL,        -- short verbatim acknowledgement
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('current','requires-resign','revoked')) DEFAULT 'current',
     UNIQUE (agreement_uuid, user_id)
   );
   CREATE INDEX IF NOT EXISTS idx_sig_user ON access_agreement_signatures(user_id);
   CREATE INDEX IF NOT EXISTS idx_sig_status ON access_agreement_signatures(status);
   ```

2. Resign enforcer:
   - When an `access_agreements` row's status flips to `retired` + a
     `superseded_by_uuid` is set, flip all current signatures for that
     agreement to `requires-resign`.
   - When the new agreement version is signed, a fresh row appears in
     `access_agreement_signatures` for the new uuid.

3. .docx emitter (`core/access-agreements.ts`):
   - Inputs: agreement type, version, body markdown, signature block.
   - Output sections: Cover, Acknowledgements, Rules / Provisions
     (verbatim operator body), Signature block (REQUIRES-OPERATOR-INPUT
     for ink signatures), Provenance.
   - Bundler adds `access-agreements-docx` role.

4. KSI envelope (`core/access-agreements-evidence.ts`):
   - For each tracker user with IAM access (cross-ref IAM-SUS):
     - For each active agreement type the org requires (per
       `workforce-policy.yaml`):
       - Lookup current signature → if missing or `requires-resign`,
         emit Finding `psFindingKind: 'ps-6-missing'`.
   - Aggregate: % users with current signature for each agreement type.

5. SSP integration: PS-6 implementation statement reads agreement metadata
   + signature counts.

6. Orchestrator wiring: `--access-agreements` flag runs AFTER providers
   (IAM cross-ref), BEFORE POA&M emission.

**REQUIRES-OPERATOR-INPUT fields**:
- Agreement body markdown (operator authors via tracker UI).
- `workforce-policy.yaml` `required_agreement_types: []` (e.g. `['nda',
  'acceptable-use']`).
- Re-sign cadence per type (default 365 days).
- AO approval signature per version.

**Test specifications** (≥12):
1. `it('rejects agreement_type not in enum')`.
2. `it('rejects active status without AO approval')`.
3. `it('body_sha256 must match canonical sha of body_markdown')`.
4. `it('signature row enforces UNIQUE(agreement_uuid, user_id)')`.
5. `it('signing a new version creates a new signature row')`.
6. `it('retiring an agreement flips all signatures to requires-resign')`.
7. `it('reader emits psFindingKind=ps-6-missing for IAM user lacking signature')`.
8. `it('reader respects workforce-policy.yaml required_agreement_types')`.
9. `it('.docx body matches body_markdown rendered to OOXML')`.
10. `it('signs agreement row + signature row with Ed25519')`.
11. `it('captures ip + user_agent verbatim from request')`.
12. `it('KSI-PIY-AGM envelope provenance.emitter set')`.
13. `it('--strict-workforce fails build on any ps-6-missing finding')`.

**REO compliance**:
- Every agreement body operator-authored; sha-pinned; immutable.
- Every signature row signed; ip + user_agent captured to make
  spoofing visible.
- No system-generated signatures; never auto-sign.
- KSI envelope provenance block lists tracker URL + snapshot time.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/access-agreements.test.ts tests/core/access-agreements-evidence.test.ts
npm run check:reo
cd ../tracker
npm test -- server/routes/access-agreements.test.ts server/routes/access-agreement-signatures.test.ts server/access-agreement-resign-enforcer.test.ts
```

**Estimated effort**: 4 - 5 working days.

---

### Slice P.P5 — Continuous workforce monitoring + behavioral analytics

**Why this slice**: NIST 800-53 PM-12 requires a cross-discipline team
that *detects + responds*. EO 13587 §6 + NITTF Minimum Standards specify
six required program elements including (3) personnel access controls +
monitoring and (4) information integration + analysis. CISA's Insider
Threat Mitigation Guide provides a structured behavioral-indicator
catalogue. Today the FedPy corpus has IAM-SUS dormant-account detection
but no correlation against HR status, no behavioral-indicator pipeline,
no signed case open/close cadence. P.P5 ties it all together — and is
the slice that makes P.P1 (ITP plan) operational.

**Connection to FedPy mission**: Closes the loop between existing
collectors (IAM-SUS) + tracker workforce data (P.P2 screening, P.P3
lifecycle, P.P4 agreements) + the ITP plan (P.P1). Produces a structured
`out/workforce-indicators.json` artifact that drives:
- LOOP-E.E1 monthly ConMon report (insider-threat indicators delta).
- LOOP-P.P1 ITP case table (auto-open candidate cases for review).
- Tracker dashboard surface (existing tracker UI extended).

**Files to create**:
- `cloud-evidence/core/workforce-monitor.ts` — pure correlator + emitter.
  Reads IAM-SUS + screening records + lifecycle events + access
  agreement signatures + tracker audit log; runs the CISA behavioral-
  indicator catalogue against the joined data; emits
  `out/workforce-indicators.json`.
- `cloud-evidence/core/workforce-indicator-rules.ts` — typed rule library
  (each rule maps to a CISA indicator code with verbatim citation).
- `tracker/server/routes/workforce-monitoring.ts` — read-only routes for
  dashboard.
- `tracker/client/src/pages/WorkforceMonitoring.tsx` — dashboard.
- Tests: ≥12.

**Files to extend**:
- `cloud-evidence/core/orchestrator.ts` — `--workforce-monitoring` flag.
- `cloud-evidence/core/submission-bundle.ts` — role
  `workforce-indicators-json`.
- `cloud-evidence/core/notify.ts` — fire `workforce-indicator-detected`
  on each new finding.
- `tracker/server/index.ts` — mount route.
- `tracker/client/src/App.tsx` — `/workforce-monitoring` route.

**Schemas / standards**:
- **NIST 800-53 Rev5 PM-12** + **EO 13587 §6** + **NITTF Minimum
  Standards** — see §4 verbatim.
- **CISA Insider Threat Mitigation Guide (2023, 508 PDF)** — Indicator
  catalogue (33 indicators across 4 categories). Operator downloads to
  `cloud-evidence/docs/sources/cisa-insider-threat-mitigation-guide.pdf`;
  `workforce-indicator-rules.ts` cites page + indicator code verbatim
  in each rule's docstring.

**Build steps**:

1. Indicator rule shape:
   ```ts
   export interface WorkforceIndicatorRule {
     code: string;                 // e.g. 'CISA-CYBER-04'
     category: 'verbal' | 'behavioral' | 'cyber' | 'physical-access';
     description: string;          // verbatim from CISA guide
     severity: 'low' | 'medium' | 'high' | 'critical';
     source_citation: string;      // 'CISA-Insider-Threat-Mitigation-Guide-2023 p.NN'
     detect: (ctx: WorkforceContext) => DetectionResult[];
   }
   export interface WorkforceContext {
     iam_principals: IamPrincipal[];       // from providers/*/iam.ts
     screening_records: ScreeningRecord[]; // from tracker
     lifecycle_events: LifecycleEvent[];   // from tracker
     agreements: SignatureRow[];           // from tracker
     audit_log: AuditEntry[];              // from tracker
   }
   export interface DetectionResult {
     indicator_code: string;
     subject_user_ref: string;             // opaque
     severity: string;
     observation: string;
     evidence_refs: string[];
     detected_at: string;
   }
   ```

2. Concrete rules (sample subset; ≥10 ship in first cut):
   - `CISA-CYBER-04`: dormant IAM principal (>90 days) for active employee
     — correlates IAM-SUS `last_used_at` with screening `status='current'`
     + lifecycle absence of termination.
   - `CISA-CYBER-12`: access-after-termination — IAM principal observed
     `last_used_at > effective_at` of a termination event.
   - `CISA-CYBER-07`: privilege-escalation outside role baseline —
     correlation with LOOP-J.J1 roles matrix delta.
   - `CISA-BEHAV-09`: missed re-screening on high-risk position —
     `position.public_trust_level='high'` + `screening.status='overdue'`.
   - `CISA-CYBER-15`: bulk download / mass operation in audit log
     (≥N events in 24h window).
   - `CISA-BEHAV-03`: unrevoked credentials after exit interview
     completed (PS-4 (b) breach).
   - `CISA-CYBER-09`: unattested agreement on user with elevated AC role.
   - `CISA-CYBER-21`: multiple failed MFA attempts (cross-ref
     IAM-MFA collector output).
   - `CISA-BEHAV-17`: rapid lifecycle event churn for same user (>3 events
     in 90 days).
   - `CISA-PHYS-08`: physical-access badge log mismatch (operator-supplied
     CSV).

3. Correlator `correlate(ctx: WorkforceContext, rules: WorkforceIndicatorRule[]): DetectionResult[]`:
   - Loops rules × ctx; aggregates findings.
   - Emits `out/workforce-indicators.json` with provenance block.
   - Optionally auto-opens `insider_threat_cases` (P.P1 table) when
     `severity='critical'` AND operator opt-in via
     `workforce-policy.yaml: auto_open_critical_cases: true`.

4. Tracker dashboard: aggregate counts by category × severity × 30-day
   window; case-creation queue from auto-detected high/critical
   findings.

5. SSP integration: PM-12 implementation statement augmented with
   indicator catalogue summary.

6. Notify integration: fire `workforce-indicator-detected` via Slack /
   PagerDuty for severity≥high.

7. Orchestrator wiring: `--workforce-monitoring` runs LAST in workforce
   chain (after P.P2, P.P3, P.P4 emits land).

**REQUIRES-OPERATOR-INPUT fields**:
- Indicator severity thresholds (org policy via `workforce-policy.yaml`).
- `auto_open_critical_cases` (default false).
- Physical-access badge log feed (operator-supplied CSV; not in scope
  for cloud SDK reads).
- Cadence window for "bulk download" detection
  (`workforce-policy.yaml: bulk_event_window_hours`).

**Test specifications** (≥12):
1. `it('CISA-CYBER-04 fires on dormant IAM principal with active screening')`.
2. `it('CISA-CYBER-12 fires on access-after-termination')`.
3. `it('CISA-BEHAV-09 fires on missed re-screening + high position')`.
4. `it('CISA-CYBER-15 fires on bulk download window threshold')`.
5. `it('CISA-CYBER-09 fires on unattested agreement + elevated role')`.
6. `it('correlator dedupes overlapping rule firings per subject')`.
7. `it('emits workforce-indicators.json with provenance block')`.
8. `it('auto-opens insider_threat_cases when auto_open_critical_cases=true and severity=critical')`.
9. `it('respects workforce-policy.yaml thresholds')`.
10. `it('does NOT fire when no IAM principals + no audit log present')`.
11. `it('fires notify on severity>=high')`.
12. `it('SSP PM-12 implementation statement reflects indicator catalogue summary')`.
13. `it('subject_user_ref is opaque (not a tracker user_id) per data-protection guidance')`.
14. `it('detection_results signed under existing signing pipeline')`.

**REO compliance**:
- Every rule cites verbatim from CISA Insider Threat Mitigation Guide
  (operator downloads the PDF; spec page + indicator code recorded).
- Subject identifiers are opaque references (not raw user_ids) — per the
  data-protection guidance the ITP plan documents.
- No synthesised indicators; every detection ties to a real evidence
  path (IAM-SUS snapshot + tracker row).
- Provenance block on `out/workforce-indicators.json` lists every input
  snapshot URL/path.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/workforce-monitor.test.ts tests/core/workforce-indicator-rules.test.ts
npm run check:reo
cd ../tracker
npm test -- server/routes/workforce-monitoring.test.ts client/src/pages/WorkforceMonitoring.test.tsx
```

**Estimated effort**: 6 - 7 working days.

---

## 6. Loop-wide acceptance criteria

LOOP-P is COMPLETE when ALL of the following are true:

1. **P.P1**: ITP plan emitter ships; `out/insider-threat-program.docx`
   renders all 10 sections; tracker has four ITP tables; UI ships;
   `out/KSI-PIY-ITP.json` envelope emitted with provenance; SSP PM-12
   implementation statement reads attestation; CHANGELOG entry quotes
   NIST 800-53 PM-12 verbatim + cites EO 13587 + NITTF Minimum Standards.
2. **P.P2**: position register + screening record tables ship; cadence
   enforcer runs; reader correlates with IAM-SUS; `out/position-risk-
   register.json` + `out/KSI-PIY-PSE.json` emitted; SSP PS-1..PS-9
   implementation statements pull narrative from policy + register;
   POA&M emits `psFindingKind` entries for failures; CHANGELOG cites
   NIST PS-2 + PS-3 + 5 CFR 731 verbatim.
3. **P.P3**: personnel lifecycle event table ships; SLA enforcer
   correlates with IAM-SUS observed disable; UI ships; reader emits
   PS-4 + PS-5 Findings; CHANGELOG cites NIST PS-4 + PS-5 verbatim.
4. **P.P4**: access agreement + signature tables ship; .docx emitter
   ships; resign enforcer runs; UI ships; KSI-PIY-AGM envelope emitted;
   CHANGELOG cites NIST PS-6 verbatim.
5. **P.P5**: workforce monitor + indicator rule library ship; ≥10
   CISA rules implemented with verbatim citations; `out/workforce-
   indicators.json` emitted with provenance; auto-case-open works when
   opted in; CHANGELOG cites CISA Insider Threat Mitigation Guide
   (page + indicator code).
6. All five slices pass `npm run typecheck`, `npm test`, and
   `npm run check:reo` in BOTH `cloud-evidence/` and `tracker/`.
7. `core/control-benchmark.ts` shows PS-1..PS-9 + PM-12 covered at
   FedRAMP Moderate.
8. STATUS.md per-slice rows updated; LOOP-P table section added.
9. CHANGELOG "Unreleased" has five entries (one per slice).

---

## 7. Open questions / caveats

1. **NISPOM scope** — 32 CFR 117 obligations are conditional. The
   `applies_nispom` flag in P.P1 lets the operator declare in/out of
   scope; when out of scope, NISPOM-only sections render REQUIRES-
   OPERATOR-INPUT but the .docx + SSP PM-12 statement still ship under
   NIST PM-12 alone. Documented in slice P.P1.
2. **National-security position levels** — most FedRAMP Moderate CSPs
   will set `national_security_level='not-applicable'`. The schema
   still requires the field to force operator declaration (REO Rule 4).
3. **Subject-identifier data protection** — insider-threat investigations
   handle pre-adverse-action data. P.P5 uses opaque `subject_user_ref`
   tokens (not raw user_ids); the resolver from token→identity lives
   only in the `insider_threat_cases` audit table accessible to `iso`+`ao`.
   This mirrors NITTF data-protection guidance.
4. **Workforce-policy.yaml location** — operator copies
   `config/workforce-policy.example.yaml` to `config/workforce-policy.yaml`
   (gitignored). Schema validated by `core/workforce-policy.ts` (a new
   typed loader created in P.P1).
5. **Re-screening cadence vs OPM tiers** — OPM Tier 1-5 have specific
   cadences (Tier 1 = 5 years initial; tiers vary). Default cadence is
   per-tier; operator overrides via `workforce-policy.yaml`.
6. **PS-7 external-personnel-security overlap with LOOP-J.J2** — LOOP-P
   stores INTERNAL personnel; LOOP-J.J2 stores subprocessors. PS-7 lands
   PARTIALLY in P.P2 (positions for contractor positions) + the rest in
   LOOP-J.J2 (per-subprocessor attestation that they screen their own).
   Documented in P.P2 §"Files to extend".
7. **PS-8 sanctions** — modelled by an audit_log event type
   `personnel-sanction-imposed` + a tracker row in
   `personnel_lifecycle_events` of `event_type='sanction'` (added in P.P3
   schema extension). Treated as a lifecycle event, not a separate slice.
8. **PS-9 position descriptions** — covered via P.P2 `description` field
   on `personnel_positions`; required to include `security_responsibilities`
   per row. No separate emitter.
9. **PM-13 workforce-development plan** — out of scope for LOOP-P; folded
   into LOOP-C document template pack (CED-family extension).
10. **Auto-case-open for P.P5 critical findings** — operator opt-in to
    avoid noise; default false. Documented in P.P5.
11. **IAM-SUS dormant threshold** — existing collector uses 90-day
    default; P.P5 correlation must align thresholds via
    `workforce-policy.yaml: dormant_threshold_days`.
12. **EO 13587 vs commercial CSP scope** — EO 13587 §6 is gov-side; our
    citation is via NIST PM-12 discussion (which extends standards to
    CUI / non-NSS). Documented in spec to forestall 3PAO confusion.

---

## 8. Status tracking

Update this table when a slice ships (see Section 9).

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| P.P1 | Insider Threat Program documentation + tracker workflow | pending | — | — |
| P.P2 | Position risk designation per role (PS-2 + PS-3 screening) | pending | — | — |
| P.P3 | Personnel transfer + termination procedures (PS-4 + PS-5) | pending | — | — |
| P.P4 | Access agreements + acknowledgments + NDA (PS-6) | pending | — | — |
| P.P5 | Continuous workforce monitoring + behavioral analytics | pending | — | — |

---

## 9. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST perform the 7-step procedure
documented in `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
Summarised:

1. **Verify green**: typecheck + tests + check:reo + check:provenance.
2. **Update STATUS.md** — set slice row to `done`, fill commit + date.
3. **Update Section 8 status table** (this file).
4. **Update CHANGELOG.md "Unreleased"** — `### Added — LOOP-P.P<id>: <title>`
   block at TOP of Unreleased, mirror LOOP-A.A* style.
5. **Commit** with slice id in message:
   ```bash
   git commit -m "LOOP-P.P<id>: <title>

   <detailed message describing slice + REO compliance notes>

   Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
   ```
6. **Amend commit hash** into STATUS.md + this file's Section 8 row.
7. **Push** to origin/main.

Failure handling: see CLAUDE.md (REO Rule 2) — slice is not done until
all 7 steps execute.

---

## 10. Appendix — per-loop coverage impact on NIST 800-53 Rev5

LOOP-P delivers FedRAMP Moderate baseline coverage for:

| Control | Title | Slice |
|---|---|---|
| PS-1 | Policy and Procedures | P.P1 + P.P2 (joint SSP narrative) |
| PS-2 | Position Risk Designation | P.P2 |
| PS-3 | Personnel Screening | P.P2 |
| PS-4 | Personnel Termination | P.P3 |
| PS-5 | Personnel Transfer | P.P3 |
| PS-6 | Access Agreements | P.P4 |
| PS-7 | External Personnel Security | P.P2 (positions side) + LOOP-J.J2 (subprocessor side) |
| PS-8 | Personnel Sanctions | P.P3 (lifecycle event type) |
| PS-9 | Position Descriptions | P.P2 (position description field) |
| PM-12 | Insider Threat Program | P.P1 + P.P5 |

Each implementation reads from REAL evidence (cloud SDK or signed
tracker row); each emission carries provenance + is signed by the
existing pipeline; each gap surfaces REQUIRES-OPERATOR-INPUT in
OSCAL props + SSP narrative until operator fills it in.

---

## 11. Appendix — worked example: a terminated employee, end-to-end

Reviewable scenario the loop's test suites encode collectively:

**Employee:** Alex Doe, position "Cloud Platform Engineer (Tier-2 Public
Trust, Moderate Risk)".

**Setup (pre-termination):**
- P.P2 has a `personnel_positions` row for "Cloud Platform Engineer"
  with `public_trust_level='moderate'`, `national_security_level='not-
  applicable'`.
- P.P2 has a `personnel_screening_records` row for Alex Doe with
  `status='current'` and `next_rescreening_due=2027-08-15`.
- P.P4 has signature rows for Alex against active NDA + AUP.
- providers/aws/iam.ts shows IAM principal `alex.doe@example` with
  `last_used_at=2026-06-01`.

**T+0 (termination event):**
- HR opens tracker; clicks "Personnel Lifecycle" → "Terminate" →
  uploads `event_type='termination-voluntary'`,
  `effective_at='2026-06-06T17:00Z'`, `org_defined_time_period_hours=24`.
- P.P3 signed checklist: HR attests `exit_interview_completed_at`,
  `property_returned_at`, `information_retention_attested_at`. Signs
  with `hr` role.
- `personnel_lifecycle_events` row signed Ed25519; sla_status=`pending`;
  notify.ts fires "termination-recorded" to PagerDuty.

**T+12h (IT actions):**
- IT disables IAM principal in AWS; `providers/aws/iam.ts` next run
  shows `alex.doe@example` `status='disabled'`, `disabled_at='2026-06-
  06T22:00Z'`.

**T+24h (orchestrator run):**
- `--personnel-lifecycle` reads tracker snapshot + IAM-SUS snapshot;
  correlator finds `iam_observed_disabled_at=2026-06-06T22:00Z`
  ≤ `effective_at + 24h = 2026-06-07T17:00Z` → `sla_status='within-sla'`.
- No Finding emitted; KSI-PIY-PSE envelope reflects success.

**T+90 days (P.P5 correlation):**
- `--workforce-monitoring` runs; CISA-CYBER-04 rule checks IAM-SUS for
  Alex Doe — principal `disabled`, employment ended; no dormant-active-
  employee fire. Clean.
- If IT had FAILED to disable in time, CISA-CYBER-12 fires
  (`access-after-termination`); auto-case-open candidate; PM-12 incident
  handling team notified.

**T+365 days (P.P2 re-review):**
- Cadence enforcer flags Alex's screening as `status='expired'` (no
  re-attestation for terminated user expected; UI surfaces `terminated`
  badge and suppresses the alert).
- Annual ITP self-assessment (P.P1) lists 1 termination, 0 SLA breaches,
  1 access-revocation correlation; updates `insider_threat_program`
  `six_elements.self_assessment.last_assessment_date`.

This is the LOOP-P value proposition end-to-end: every workforce-security
event is signed, time-stamped, correlated against real cloud state, and
surfaces in the OSCAL SSP + AR + POA&M chain without a single line of
unverified narrative.
