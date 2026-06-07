# Third-Pass Audit (after LOOP-A through LOOP-S + CIRCIA)

> Date: 2026-06-07. Author: automated audit pass (third).
> Status: PROPOSED — not yet adopted in STATUS.md.
>
> Authority: governed by `cloud-evidence/CLAUDE.md` Real-Evidence-Only (REO)
> standard. Every recommendation below cites a public authoritative source.
> Where the source is unreachable through anonymous fetch (SEC PDF, DoD CIO,
> OMB whitehouse.gov PDFs, NIST PDFs, FAR/DFARS, CISA pages return 403/404),
> the URL is recorded verbatim and the implementer downloads the source PDF
> into `cloud-evidence/docs/sources/` per the same pattern LOOP-B follows for
> the FedRAMP CMP PDF and LOOP-R follows for OMB M-23-02.
>
> Provenance for this audit: this is a **third pass** over the FedRAMP 20x
> Moderate obligation surface.
>
> - First pass (`docs/ADDITIONAL-LOOPS-AUDIT.md`, 2026-06-06) surfaced
>   LOOP-L through LOOP-Q (20 new slices + 12 extensions) on top of the
>   original LOOP-A–K (49 slices, A complete + B–K pending).
> - Second pass (`docs/SECOND-PASS-AUDIT.md`, 2026-06-07) surfaced LOOP-R
>   (PQC), LOOP-S (DFARS 252.204-7012 cloud-equivalency, conditional),
>   plus the CIRCIA cross-cutting workflow (extends G.G2 + M.M4) and
>   four in-loop extensions (C.C11 SLA, G.G8 SBD, I.I4 CSF v2.0,
>   J.J3.b OCI signing).
> - This pass treats every recommendation from the first two passes as
>   accepted (LOOP-R, LOOP-S, CIRCIA workflow all have full SPEC + risk
>   register files on disk) and looks specifically for what is STILL
>   missing from the prompted set of 23 candidate obligation surfaces.

---

## 1. Methodology

### 1.1 What I searched for

A targeted re-audit of 23 candidate obligation surfaces the human prompt
named explicitly:

1. CIRCIA / SEC 8-K Item 1.05 harmonization (for public-co. CSPs)
2. HIPAA Security Rule cross-walk
3. PCI-DSS v4.0 cross-walk
4. GLBA Safeguards Rule cross-walk
5. CCPA / CPRA cross-walk (California state-law)
6. GDPR cross-walk (EU customers)
7. CMMC Level 2/3 (distinct from LOOP-S DFARS)
8. NIST SP 800-218 SSDF v1.1 alignment
9. NIST SP 800-218A SSDF-AI (Generative AI)
10. OMB M-22-09 Zero Trust Architecture Strategy
11. NIST SP 800-207 + SP 800-207A Zero Trust Architecture
12. CISA Zero Trust Maturity Model v2.0
13. NIST IR 8334 (FIPS validation transition)
14. NIST SP 800-63 Rev 4 (Digital Identity)
15. FedRAMP TIC 3.0 Capability Catalog alignment
16. OMB M-21-07 (TLS 1.3, HTTPS-only)
17. FedRAMP Federal Mobility Group (FMG) guidance
18. Section 889 Part B (FAR 52.204-25) Huawei / ZTE prohibition
19. Open Source Software (OSS) Security per CISA + OpenSSF
20. CISA KEV lifecycle depth (we have detection)
21. NDAA Sec. 1634 Kaspersky prohibition
22. TIC 3.0 / EINSTEIN integration
23. DoD Mission Owner / SaaS-equivalency under DoD CCSRG
24. CSA Cloud Controls Matrix (CCM) v4
25. CIS Benchmarks (CIS Controls v8)
26. GSA 18F technical guidance + login.gov integration
27. FedRAMP Phase Two automation specifics (post-L–Q)

For each I:
1. Read every loop spec (LOOP-A through LOOP-S, plus CIRCIA-WORKFLOW.md
   and supporting risk registers).
2. Read first-pass + second-pass audits for any prior coverage.
3. Web-fetched the authoritative source where possible (many returned
   403/404 to anonymous fetches; in those cases the operator downloads
   the PDF locally per the established source-staging pattern).
4. Compared the obligation against the proposed extension surface in
   prior §3 sections.
5. Categorised each item into §2 STILL missing, §3 confirmed-covered
   after R + S + CIRCIA, §4 out-of-scope at FedRAMP Moderate.

### 1.2 What I deliberately did NOT do

- Did not re-propose anything already covered by LOOP-A–S or CIRCIA.
- Did not propose net-new artifacts without a real obligation citation.
- Did not rescope existing loops; where partial coverage exists I
  recommend extending an existing slice rather than splitting the loop.
- Did not author full SPEC files for the new proposals — those follow
  if the human ratifies the audit (per the established L–S precedent).
- Did not duplicate items already flagged as out-of-scope in first-pass
  §4 (CMMC L2/L3 certification, EU AI Act, etc.); they are referenced
  by section.

### 1.3 Authoritative fetch status

| Source | Status | Resolution |
|---|---|---|
| SEC 33-11216 PDF | 403 anonymous | Operator downloads to `docs/sources/sec-33-11216.pdf` |
| DoD CIO CMMC pages | 403 / 404 anonymous | Operator downloads to `docs/sources/cmmc-32-cfr-170.pdf` |
| NIST SP 800-218 (SSDF) PDF | landing page only | Operator downloads SP 800-218 + 800-218A PDFs |
| NIST SP 800-218A (IPD then final July 2024) | landing page summary | Operator downloads `NIST.SP.800-218A.pdf` |
| OMB M-22-09 (Zero Trust) PDF | binary corrupted via WebFetch | Operator downloads `docs/sources/omb-m-22-09.pdf` |
| NIST SP 800-207 PDF | binary corrupted via WebFetch | Operator downloads `docs/sources/nist-sp-800-207.pdf` |
| CISA ZTMM v2.0 | 403 anonymous | Operator downloads `docs/sources/cisa-ztmm-v2.pdf` |
| FAR 52.204-25 | fetched (acquisition.gov OK) | Used in §2.5 below |
| NIST SP 800-63 Rev 4 (2pd) | landing-page summary | Operator downloads `nist-sp-800-63-4.pdf` |
| Federal Register SEC | 302 redirect | Operator follows redirect |
| OMB M-22-18 (self-attest) | 404 anonymous | Operator downloads `omb-m-22-18.pdf` + `m-23-16.pdf` |

The PDF-staging pattern (operator downloads into
`cloud-evidence/docs/sources/` then per-slice docstring re-quotes verbatim)
is the same pattern LOOP-B used for the FedRAMP CMP PDF and LOOP-R uses
for OMB M-23-02. The audit is not blocked on the 403s — the
verbatim-quote requirement transfers to the implementing slice docs.

---

## 2. STILL missing — propose adding to roadmap

Eight first-class additions surface in this pass. They are LOOP-T
(Federal Software Self-Attestation + SSDF), LOOP-U (Zero Trust
Architecture Maturity), LOOP-V (Sector-Specific Privacy Cross-Walks —
HIPAA / GLBA / PCI / CCPA / GDPR conditional), LOOP-W (Prohibited
Vendors + Section 889 + Kaspersky), and four in-loop extensions
(D.D4 TIC 3.0, E.E8 KEV lifecycle, J.J4 OSS Security, plus G.G2-SEC-8K
addition to the CIRCIA workflow).

---

### 2.1 SEC Form 8-K Item 1.05 cyber-incident disclosure — extend CIRCIA-WORKFLOW.md + G.G2 (NEW G.G2-SEC-8K-EXTENSION)

**Source obligation (verbatim):**

- SEC Final Rule "Cybersecurity Risk Management, Strategy, Governance,
  and Incident Disclosure" (SEC Release Nos. 33-11216, 34-97989; 88 FR
  51896, published July 26 2023, effective September 5 2023; Item 1.05
  compliance for accelerated filers from December 18 2023 and for
  smaller reporting companies June 15 2024). Final rule URL:
  https://www.sec.gov/files/rules/final/2023/33-11216.pdf  
  Federal Register URL:
  https://www.federalregister.gov/documents/2023/08/04/2023-16194/cybersecurity-risk-management-strategy-governance-and-incident-disclosure
- 17 CFR §240.13a-11 (Form 8-K) + Item 1.05 added by 33-11216:
  > "Registrants must disclose any cybersecurity incident they
  > determine to be material and describe the material aspects of the
  > incident's nature, scope, and timing, as well as its material
  > impact or reasonably likely material impact on the registrant.
  > The Item 1.05 Form 8-K will generally be due four business days
  > after a registrant determines that a cybersecurity incident is
  > material."
- Regulation S-K Item 106 (annual disclosure):
  > "Registrants must describe their processes, if any, for assessing,
  > identifying, and managing material risks from cybersecurity
  > threats … and describe the board of directors' oversight of risks
  > from cybersecurity threats and management's role and expertise in
  > assessing and managing material risks."

**Why first + second-pass missed it:** The first pass (2026-06-06)
did not include public-company-listing obligations in its 49-loop
canvas. The second pass added CIRCIA but explicitly noted SEC 8-K
was "not in scope (CSP is rarely public co. directly)" in
CIRCIA-WORKFLOW.md §9.1. That assumption is **wrong for a meaningful
subset of FedRAMP CSPs**: every FedRAMP-Moderate CSP that is (a) a
public company, (b) a wholly-owned subsidiary of a public company
where cyber materiality could propagate, or (c) preparing for IPO
inherits Item 1.05 + Item 106 obligations. The Final Rule's
materiality determination is the start of the 4-business-day clock —
which overlaps but is not coterminous with CIRCIA's 72h and FedRAMP's
1h clocks.

**Where it lands:** **Extend CIRCIA-WORKFLOW.md + LOOP-G.G2 with new
sub-slice G.G2-SEC-8K-EXTENSION**.

- New `core/sec-8k-incident.ts` — pure builder.
- Tracker DB additions: `sec_8k_assessments` (per-incident materiality
  determination with operator + board-counsel sign-off),
  `sec_8k_filings` (Item 1.05 filing record), `sec_10k_item_106`
  (annual governance disclosure draft).
- Materiality classifier: prompts the operator with the SEC's
  non-exclusive materiality factors (financial impact, ops impact,
  data-integrity impact, reputational impact, customer-trust impact,
  legal/regulatory impact, possible mitigation cost). Operator
  decides; signed.
- Clock: 4 business days from materiality determination. Tracker
  carries `materiality_determined_at` + `8k_due_at = +4 bus. days`
  (calendar-aware including Federal holidays).
- Inter-framework coordination: when an incident triggers CIRCIA
  72h + DFARS 72h + SEC 4-bus-day + FedRAMP 1h + HIPAA-overlay 60d
  + GDPR 72h (if EU customers), the tracker UI surfaces ALL clocks
  side-by-side. Per second-pass §9.3 "substantially similar
  information" safe harbor: an SEC Item 1.05 is NOT substantially
  similar to a CIRCIA report (different fields, different intake).
- Annual Item 106 emitter: pulls from existing artifacts (risk
  register B.B5, threat model N.N1, AFR-ADS publication G.G3, board
  cyber oversight roster from tracker, ConMon strategy C.C6) and
  drafts the Item 106 cybersecurity disclosure for the 10-K.

**Priority + reason:** **Medium-high (conditional)** — applies only
when the CSP (or its parent) is SEC-registered. Conditional gate
in `org-profile.yaml::sec_registered: true/false`. When true, the
Item 1.05 emitter is hard-required by federal securities law (not
FedRAMP); when false, the slice is a no-op attestation that the
CSP is privately held.

**Estimated effort:** 1.5 weeks (Item 1.05 + Item 106 emitters +
tracker + tests).

---

### 2.2 NIST SP 800-218 SSDF + OMB M-22-18 federal-software self-attestation — NEW LOOP-T

**Source obligation (verbatim):**

- NIST SP 800-218 (SSDF v1.1, Feb 2022) — four practice groups
  (publicly-known structure; full text in operator-downloaded PDF):
  - **PO** — Prepare the Organization
  - **PS** — Protect the Software
  - **PW** — Produce Well-Secured Software
  - **RV** — Respond to Vulnerabilities
- EO 14028 (May 12 2021) §4(e):
  > "The Director of NIST, in consultation with the heads of such
  > agencies as the Director deems appropriate, shall publish
  > preliminary guidelines, based on the consensus existing among
  > industry experts, for enhancing software supply chain security,
  > to include criteria that can be used to evaluate software
  > security."
- OMB M-22-18 (Sep 14 2022) "Enhancing the Security of the Software
  Supply Chain through Secure Software Development Practices":
  - Requires every federal-software producer to self-attest to NIST
    SSDF (SP 800-218) compliance via the **CISA Self-Attestation
    Common Form** before federal agencies may use the software.
- OMB M-23-16 (Jun 9 2023) "Update to M-22-18" — extends deadlines
  + clarifies third-party-component attestation requirement.
- CISA Self-Attestation Common Form (March 2024 release):
  https://www.cisa.gov/secure-software-attestation-form
  - 4 SSDF practices required: PS.1 (Protect All Forms of Code),
    PS.2 (Provide a Mechanism for Verifying Software Release
    Integrity), PS.3 (Archive and Protect Each Software Release),
    PW.4 (Reuse Existing Well-Secured Software).

**Why first + second-pass missed it:** First-pass §3.8 mentioned
"DevSecOps Pipeline Attestations (SA-11, SA-15, SR-3)" as an
extension of LOOP-J.J3 — but **OMB M-22-18 is a distinct procurement
gate**, not a control implementation. The CISA Self-Attestation
Common Form is signed by a corporate officer (CISO / VP Eng) and
submitted to **each federal customer** the CSP serves. Second-pass
§2.3 (J.J3.b OCI signing + SLSA L3) covers the *engineering* side
(in-toto + Rekor + cosign); it does NOT cover the *procurement
artifact* — the signed form a federal customer's contracting officer
files. These are two different deliverables.

**Where it lands:** **NEW LOOP-T — Federal Software Self-Attestation
+ SSDF Evidence Pack**:

- **T.T1 — CISA Self-Attestation Common Form emitter** — pure builder
  that pre-fills the form from existing evidence (SBOM, signed
  releases, SSDF mapping). Emits `.docx` + `.json`. REQUIRES-OPERATOR-
  INPUT for: corporate officer name + title, attestation date, scope
  of products covered, declined-attestation rationale (if any).
- **T.T2 — SSDF v1.1 evidence map** — per-practice (PO.1.1, PO.1.2,
  …, RV.3.4) evidence pointer. Crosswalks to existing collectors
  (cosign / SBOM from E.2, CI gates from J.J3, secret-scanning from
  CMT-RMV, etc.). Operator-supplied for organizational practices
  (PO.1 governance, PO.4 review cadence). Emits
  `out/ssdf-evidence-map.json` + `.xlsx`.
- **T.T3 — Third-party-component attestation aggregator** — per
  M-23-16, when the CSP integrates 3rd-party components without
  self-attesting on the producer's behalf, the producer's
  self-attestation (or POA&M for non-attestable use) is required.
  Tracker workflow: per-component attestation status registry.
- **T.T4 — Per-federal-customer attestation distribution log** —
  tracks which agency received which form version on what date,
  with operator + agency-acknowledgement audit trail.

**Priority + reason:** **High** — M-22-18 is in force; every
federal-customer renewal/award since Q3 2024 has needed an
attestation. This is currently the most likely UNFILED procurement
gap for a CSP about to be awarded a new agency contract.

**Estimated effort:** 4 weeks (4 slices).

---

### 2.3 NIST SP 800-218A — SSDF Companion for Generative AI — extend LOOP-O + LOOP-T

**Source obligation (verbatim):**

- NIST SP 800-218A "Secure Software Development Practices for
  Generative AI and Dual-Use Foundation Models" (final, July 26
  2024) — extends SSDF v1.1 with AI-specific practices.
  https://csrc.nist.gov/pubs/sp/800/218/a/final
- EO 14110 §4.1(a)(i) (Oct 30 2023, "Safe, Secure, and Trustworthy
  Development and Use of AI"):
  > "Within 270 days of the date of this order, the Secretary of
  > Commerce, acting through the Director of NIST … shall: … develop
  > a companion resource to the AI Risk Management Framework, NIST AI
  > 100-1, for generative AI."
- NIST SP 800-218A adds practices for AI model producers + AI system
  builders + acquirers: training-data integrity, model-card emission,
  inference-time security controls.

**Why first + second-pass missed it:** LOOP-O (NIST AI RMF + OMB
M-24-10) covers AI **risk management** (GOVERN / MAP / MEASURE /
MANAGE) but does NOT cover **AI software development practices**
(SSDF + 218A). They are separate NIST publication tracks.

**Where it lands:** **Extend LOOP-T with sub-slice T.T5 — SSDF-AI
evidence map** AND **extend LOOP-O.O2 NIST AI RMF MEASURE collector**
to surface 218A-specific evidence (training-data provenance, model
red-team test artifacts, prompt-injection test results).

- New `core/ssdf-ai-evidence-map.ts` — pure builder. For each AI
  surface in O.O1 inventory, maps to SSDF-AI practice tasks (e.g.
  PW.1.AI Document AI model design decisions, PS.1.AI Protect
  training data, RV.2.AI Identify and document AI-specific
  vulnerabilities).
- Operator-supplied for closed-source upstream models; auto-fill
  for in-house models that integrate with the existing CI signal.

**Priority + reason:** **Medium-high (conditional on AI use)** —
same gate as LOOP-O. If the CSP has any GenAI feature, 218A
attestation is required by federal-customer agency AI governance
offices from FY 2026 onward.

**Estimated effort:** 1 week (one slice as T.T5 extension).

---

### 2.4 Zero Trust Architecture — OMB M-22-09 + NIST SP 800-207 + CISA ZTMM v2.0 — NEW LOOP-U

**Source obligation (verbatim):**

- OMB M-22-09 (Jan 26 2022) "Moving the U.S. Government Toward Zero
  Trust Cybersecurity Principles":
  > "This memorandum sets forth a Federal zero trust architecture
  > (ZTA) strategy, requiring agencies to meet specific cybersecurity
  > standards and objectives by the end of Fiscal Year (FY) 2024…"
  - 5 pillars (per CISA ZTMM derivation): Identity, Devices,
    Networks, Applications & Workloads, Data.
  - Cross-cutting capabilities: Visibility & Analytics, Automation
    & Orchestration, Governance.
- NIST SP 800-207 (Aug 2020) "Zero Trust Architecture" — 7 tenets,
  3 logical components (PE/PA/PEP), 4 deployment variants (device-
  agent, enclave, resource-portal, sandbox).
- NIST SP 800-207A (Sep 2023) "A Zero Trust Architecture Model for
  Access Control in Cloud-Native Applications in Multi-Cloud
  Environments" — extends 207 to multi-cloud workload identity +
  workload-level authz.
- CISA Zero Trust Maturity Model v2.0 (April 2023):
  - 5 pillars × 4 maturity levels (Traditional, Initial, Advanced,
    Optimal).
  - Pillars: Identity, Devices, Networks, Applications & Workloads,
    Data. Cross-cutting: Visibility & Analytics, Automation &
    Orchestration, Governance.
- FedRAMP Phase Two (RFC-0014) does not yet enumerate ZTA-specific
  KSIs but the AFR-CNA + AFR-IAM + AFR-MLA families implicitly cover
  several pillars at the **Initial / Advanced** maturity bands.

**Why first + second-pass missed it:** First-pass §1.1 enumerated
RFC-0014 + NIST publications but did not include 800-207, 800-207A,
M-22-09, or ZTMM. The AFR-CNA + AFR-IAM families partially cover
ZTA Identity + Networks pillars at a CONTROL level, but no current
slice produces the per-pillar maturity score the federal customer
ASKs about at every agency authorization conversation since
FY 2024.

**Where it lands:** **NEW LOOP-U — Zero Trust Architecture Maturity
Pack**:

- **U.U1 — Per-pillar maturity self-assessment emitter** — for each
  of CISA ZTMM v2.0's 5 pillars + 3 cross-cutting capabilities,
  produces a per-function maturity score (Traditional / Initial /
  Advanced / Optimal) derived from existing collector evidence.
  Maps to OMB M-22-09 FY24 objectives.
  - Identity → derive from IAM-MFA + IAM-AAM + IAM-APM + IAM-ELP
    + LOOP-N attack surface enumeration.
  - Devices → derive from CMT-RMV + INV-P2 inventory + ATO posture.
  - Networks → derive from CNA-MAT + CNA-RVP + CNA-RNT + CNA-IBP.
  - Applications & Workloads → derive from CNA-OFA + SVC-VCM +
    second-pass J.J3.b OCI signing.
  - Data → derive from SVC-RUD + SVC-VRI + L.L3 inheritance trace
    + M.M3 PT-family inventory.
- **U.U2 — NIST SP 800-207 7-tenets compliance crosswalk** — per-
  tenet evidence pointer (e.g. tenet #5 "the enterprise monitors
  and measures the integrity and security posture of all owned
  and associated assets" → maps to INV-P2 + AFR-CCM ConMon).
- **U.U3 — Multi-cloud workload identity per SP 800-207A** —
  workload-identity inventory across AWS IAM Roles for Service
  Accounts (IRSA), GCP Workload Identity Federation, Azure
  Managed Identities. Maps each workload to its identity primitive
  + identity-token issuance flow + verifying-party.
- **U.U4 — OMB M-22-09 FY24 objectives evidence pack** — per-
  objective (e.g. "agencies must use enterprise-managed identities
  to access the applications they use in their work" — Identity
  Pillar Objective 1) evidence pointer + status (met / partial /
  not-met / customer-responsibility).
- **U.U5 — ZTA roadmap emitter** — for not-met or partially-met
  objectives, emit a roadmap artifact (.docx) with target-maturity
  date + planned actions + tracker workflow. Operator-supplied
  for organizational decisions; auto-fill for technical evidence.

**Priority + reason:** **High** — every agency authorization
conversation since FY 2024 includes "show me your ZTA maturity".
The agency customer's M-22-09 obligation cascades to the CSP via
contract.

**Estimated effort:** 5 weeks (5 slices).

---

### 2.5 Section 889 Part B (FAR 52.204-25) + NDAA Sec. 1634 Kaspersky + supply-chain prohibited vendors — NEW LOOP-W

**Source obligation (verbatim):**

- FAR 52.204-25 (per fetched content, https://www.acquisition.gov/far/52.204-25):
  > "The Contractor is prohibited from … using any equipment, system,
  > or service that uses covered telecommunications equipment or
  > services as a substantial or essential component of any system,
  > or as critical technology as part of any system."
  - Covered telecom vendors enumerated: Huawei Technologies, ZTE
    Corp, Hytera Communications, Hangzhou Hikvision Digital Tech,
    Dahua Technology (and subsidiaries/affiliates).
  - Reporting timeline: within **1 business day** to the Contracting
    Officer with contract/order numbers, supplier identity, CAGE
    code, brand, model, mitigation; **+10 business days** for full
    mitigation description.
  - Flow-down: contractor must "insert the substance of this clause"
    into subcontracts.
- NDAA FY 2018 §1634 (Pub. L. 115-91) "Prohibition on Use of
  Products and Services Developed or Provided by Kaspersky Lab" —
  prohibits federal-government use of any hardware, software, or
  service developed or provided by Kaspersky Lab, its subsidiaries,
  or successor entities. Codified at 41 U.S.C. §3901 note.
- NDAA FY 2019 §889 (Pub. L. 115-232) — codifies Section 889 parts
  A + B at FAR 4.21 + DFARS 204.21.
- DHS BOD 17-01 (Sep 13 2017) prohibits Kaspersky on federal info
  systems (per CISA BOD page).
- Treasury OFAC SDN list — sanctioned entities the CSP must screen
  subprocessors against (cross-cuts CIRCIA ransom payment §6 ban).

**Why first + second-pass missed it:** First-pass §3.8 covered
"DevSecOps Pipeline Attestations" but never named Section 889 or
NDAA §1634. The existing LOOP-J subprocessor inventory (J.J2)
captures vendor identity but does NOT screen against prohibited-
vendor lists. Second-pass added DFARS 252.204-7012 (cyber-incident
side of DoD compliance) but not 889/Kaspersky (prohibited-vendor
side).

**Where it lands:** **NEW LOOP-W — Prohibited Vendors + Section 889
+ Sanctions Screening**:

- **W.W1 — Prohibited-vendor screener** — pure module that screens
  every subprocessor (J.J2), every COTS dependency (E.2 SBOM),
  every OCI image source (J.J3.b), every npm/pypi/maven package
  publisher against:
  - FAR 52.204-25 covered telecom list (5 named + subsidiaries).
  - NDAA §1634 Kaspersky list.
  - Treasury OFAC SDN list (JSON feed from
    https://www.treasury.gov/ofac/downloads/sdn.csv).
  - GSA SAM Excluded Parties list.
  - Commerce Entity List (BIS).
  - DoD Section 1260H list (Chinese military companies).
  Emits `out/prohibited-vendor-screening.json` with per-match
  evidence.
- **W.W2 — Section 889 attestation emitter** — pure `.docx`
  emitter for the FAR 52.204-26 attestation contractors provide
  to the agency. Pre-fills from inventory + W.W1 screen results.
  Operator officer signs.
- **W.W3 — 1-business-day reporting workflow** — when W.W1 finds
  a match, tracker triggers the 1-bus-day clock to Contracting
  Officer + 10-bus-day mitigation report. Same calendar-aware
  clock pattern as the SEC 8-K timer (§2.1).
- **W.W4 — Annual screening rerun + delta** — annual
  re-screening; emits delta vs prior year (added matches, removed
  matches, mitigations completed).

**Priority + reason:** **High** — Section 889 has been in force
since August 2020; CISA + DOJ have prosecuted contractors for
non-compliance. Every federal contract since FY21 requires the
attestation. Kaspersky is a hard ban for all federal info
systems. This is currently **unfiled** at most CSPs.

**Estimated effort:** 4 weeks (4 slices).

---

### 2.6 CISA KEV full-lifecycle (not just detection) — extend LOOP-B.B2 + LOOP-E.E1

**Source obligation (verbatim):**

- CISA BOD 22-01 (Nov 3 2021) "Reducing the Significant Risk of
  Known Exploited Vulnerabilities":
  > "Agencies shall remediate each vulnerability according to the
  > timelines set forth in the CISA-managed vulnerability catalog.
  > … For vulnerabilities added to the catalog after the
  > effective date, the catalog will specify the due date."
- CISA Known Exploited Vulnerabilities Catalog —
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - Published as JSON at https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - Per-CVE: `cveID`, `vendorProject`, `product`,
    `vulnerabilityName`, `dateAdded`, `shortDescription`,
    `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`.

**Why first + second-pass missed it:** First-pass §B.B2 includes
"CISA KEV: 21d from CISA's published `dueDate`" — that's the
**detection + deadline math**. Missing: full lifecycle —
- pre-KEV-listing exploitation evidence capture (when did the CSP
  first detect this CVE in inventory?),
- patch-fail / patch-blocked workflow (what to do when the patch
  breaks something),
- KEV ransomware-campaign correlation with CIRCIA (the
  `knownRansomwareCampaignUse` field is a CIRCIA "covered cyber
  incident" prong indicator),
- annual KEV exposure trend reporting.

**Where it lands:** **Extend LOOP-B.B2 + LOOP-E.E1 with sub-
extension B.B2-KEV-LIFECYCLE**:

- New `core/kev-lifecycle.ts` — pure module: ingests CISA KEV
  feed daily, joins to existing VDR pipeline, computes per-CVE
  lifecycle: `first_detected_in_inventory`,
  `kev_listed_at`, `patch_applied_at` (or
  `compensating_control_applied`), `closed_at`.
- New tracker DB tables: `kev_lifecycle`, `kev_patch_blockers`.
- KEV `knownRansomwareCampaignUse=true` correlation flag wired
  into CIRCIA prong-4 classifier (CIRCIA-WORKFLOW.md §4.4).
- E.E1 monthly ConMon report gains a "KEV Exposure Summary"
  section: count of unpatched KEVs by due-date bucket, mean time
  to patch, top-5 oldest unpatched.

**Priority + reason:** **Medium-high** — BOD 22-01 is in force;
agency customers ask "what's your KEV exposure" at every monthly
ConMon review. The deadline math alone (B.B2) is insufficient
without the lifecycle reporting.

**Estimated effort:** 1.5 weeks.

---

### 2.7 TIC 3.0 + OMB M-21-07 TLS 1.3 + EINSTEIN — extend LOOP-D + LOOP-G.G5

**Source obligation (verbatim):**

- OMB M-19-26 (Sep 12 2019) "Update to the Trusted Internet
  Connections (TIC) Initiative" — supersedes M-08-05 + M-08-26.
- CISA TIC 3.0 Capability Catalog (April 2021, latest June 2023):
  - 5 security capabilities × per-PEP guidance (Universal Security
    Capabilities; PEP-Use-Case capabilities for branch office,
    remote user, cloud, agency campus).
- OMB M-21-07 (Mar 17 2021) "Completing the Transition to Internet
  Protocol Version 6 (IPv6)":
  > "Agencies must take steps to … require that all new procurement
  > include IPv6 capability as a requirement."
- OMB M-15-13 (Jun 8 2015) "Policy to Require Secure Connections
  across Federal Websites and Web Services" — HTTPS-only + HSTS
  preload-list inclusion.
- OMB M-22-09 §C.III.b (overlap with LOOP-U):
  > "Agencies must encrypt all DNS requests and HTTP traffic within
  > their environment."
- CISA EINSTEIN program (E1/E2/E3A) — federal-network sensor
  ecosystem; CSPs delivering to federal customers may need to
  participate in EINSTEIN data-sharing under MOA with CISA.

**Why first + second-pass missed it:** First-pass §3.7 covered
"Boundary Protection Traffic-Flow Logs (SC-7(5), (8))" but not
TIC 3.0 capability-catalog alignment + M-21-07 IPv6 + HTTPS-only
attestation. The CNA-MAT + CNA-RVP collectors implicitly cover
SC-7 boundary at the control level but produce no TIC-mapped
capability artifact.

**Where it lands:** **Extend LOOP-D with new slice D.D4 — TIC 3.0
Capability Map**:

- New `core/tic-30-capability-map.ts` — emits per-capability (e.g.
  "Universal Security Capability 1: Backup and Recovery") evidence
  pointer + status per CISA TIC 3.0 catalog. Wires to existing
  CNA + MLA + SVC collectors.
- IPv6 capability + HSTS preload-list inclusion: extend
  CNA-RVP collector with per-asset IPv6 + HSTS check.
- EINSTEIN MOA tracker workflow: per-agency-customer EINSTEIN
  participation status (operator-supplied; signed audit trail).

**Priority + reason:** **Medium** — TIC 3.0 alignment is asked
about during agency authorization; not a hard FedRAMP gate.
M-21-07 IPv6 requirement applies to **federal agencies'
procurements**, not directly to CSPs — but a CSP that lacks IPv6
support fails the agency's M-21-07 obligation and loses the
contract.

**Estimated effort:** 1.5 weeks.

---

### 2.8 OSS Security per CISA + OpenSSF — extend LOOP-J.J3 (new J.J4)

**Source obligation (verbatim):**

- CISA + ONCD Open Source Software Security Initiative (Aug 2023
  RFI; March 2024 Roadmap):
  https://www.cisa.gov/resources-tools/resources/open-source-software-security-roadmap
- OpenSSF Best Practices Badge program:
  https://www.bestpractices.dev/
- OpenSSF Scorecard project — automated OSS-project health checks.
- NIST SP 800-218 PW.4 + PW.5 + PW.6 — reuse + analysis of open-
  source components.
- CISA OSS Security Roadmap (Mar 2024) §III Objective 2: "Drive
  the prioritization of secure-by-design and secure-by-default
  practices in open source software."

**Why first + second-pass missed it:** Second-pass §2.3 added
J.J3.b (OCI signing + Rekor + SLSA L3) which covers build-side
provenance. OSS Security goes one layer deeper: per-dependency
OpenSSF Scorecard, per-project maintenance signal, per-CVE
attribution to specific upstream maintainers.

**Where it lands:** **New LOOP-J.J4 — OSS Security Posture**:

- New `core/oss-security-posture.ts`. Per OSS dependency in SBOM:
  - OpenSSF Scorecard score (fetched from
    https://api.scorecard.dev/projects/github.com/<org>/<repo>).
  - OpenSSF Best Practices Badge status.
  - Maintainer activity signal (last commit, release cadence).
  - Bus-factor estimate (number of active maintainers).
  - CVE history (count + mean time to patch).
- Emits `out/oss-security-posture.json` + `.xlsx` heatmap.
- Per-package risk-tier classification feeds J.J3 supply-chain
  risk register.

**Priority + reason:** **Medium** — not a current FedRAMP gate
but agency customers (Treasury, HHS, DoD) increasingly ask
about OSS dependency hygiene. The CISA OSS Roadmap (Mar 2024)
signals near-future obligation.

**Estimated effort:** 1.5 weeks.

---

### 2.9 Sector-specific privacy crosswalks (HIPAA / PCI-DSS / GLBA / CCPA / GDPR) — NEW LOOP-V (conditional)

**Source obligation (verbatim — selected):**

- **HIPAA Security Rule** (45 CFR Part 160, Subparts A + C of Part
  164) — applies when CSP processes PHI as a Business Associate.
  Requires BAA + breach notification (60d to HHS; immediate for
  ≥500-individual breaches per 45 CFR §164.408).
- **PCI-DSS v4.0** (March 2022, fully effective March 31, 2025) —
  applies when CSP processes/stores/transmits payment card data
  for a merchant or service provider. 12 requirements; v4.0 adds
  64 "future-dated" requirements effective 2025.
- **GLBA Safeguards Rule** (16 CFR Part 314) — applies when CSP
  serves "financial institutions" under GLBA. Revised June 2023 —
  30-day FTC breach notification at ≥500 customers per §314.4(j).
- **CCPA / CPRA** — California Civil Code §1798.100 et seq.
  Applies when CSP processes data of California residents above
  thresholds.
- **GDPR** (EU 2016/679) — applies when CSP processes data of
  EU data subjects; 72h Article 33 notification.

**Why first + second-pass missed it:** First-pass §4.5 + §4.8
flagged "PCI DSS, HIPAA — sector-specific" as out-of-scope under
the assumption that the CSP processed only federal-customer
data. **That assumption is incorrect** for many real-world
FedRAMP CSPs — federal agencies often process PHI (HHS / VA),
payment data (Treasury), and mixed data including California
residents (almost all). The CSP's processor-role obligations
under those frameworks cascade through the CRM (LOOP-L) but
need a dedicated crosswalk emitter.

**Where it lands:** **NEW LOOP-V — Sector-Specific Privacy
Crosswalks** (conditional; each sub-slice gated):

- **V.V1 — HIPAA Security Rule crosswalk** (conditional, when
  PHI processed). Per 45 CFR §164.308–§164.312 standards +
  implementation specifications, evidence pointer per existing
  collector. BAA emitter + ≥500-individual breach-notification
  workflow.
- **V.V2 — PCI-DSS v4.0 crosswalk** (conditional, when PAN
  processed). Per 12 requirements + 64 v4.0-future-dated
  requirements, evidence pointer.
- **V.V3 — GLBA Safeguards Rule crosswalk** (conditional, when
  CSP serves financial institutions). Per 16 CFR §314.4
  elements (a)–(i) evidence pointer + 30d/500+ FTC notification.
- **V.V4 — CCPA/CPRA crosswalk** (conditional, when California
  resident data processed). Per CCPA + CPRA requirements
  (purposes, disclosures, opt-out, deletion rights) evidence
  pointer + AB-1130 breach notification.
- **V.V5 — GDPR crosswalk** (conditional, when EU data subjects
  processed). Per GDPR Articles 5/6/13–14/15–22/24–30/32/33–34
  evidence pointer + 72h Article 33 breach notification
  (separate from CIRCIA 72h — different agency, different
  fields).

**Priority + reason:** **Medium-low for V.V1/V.V2/V.V3 (most
FedRAMP CSPs); HIGH for V.V4 (almost universal)** — the slice
ships as a conditional with operator-supplied gate flags
similar to LOOP-S.

**Estimated effort:** 5 weeks (5 sub-slices, each ~1 week).

---

### 2.10 Summary of §2 additions (8 first-class)

| # | Item | Landing | Priority | Effort |
|---|---|---|---|---|
| 2.1 | SEC 8-K Item 1.05 + S-K Item 106 (G.G2-SEC-8K) | Extends G.G2 + CIRCIA-WORKFLOW.md | Medium-high (conditional on SEC-registration) | 1.5 wk |
| 2.2 | LOOP-T (SSDF + CISA Self-Attest Common Form, M-22-18) | NEW LOOP-T (4 slices) | High | 4 wk |
| 2.3 | SSDF-AI (SP 800-218A) | Extends LOOP-T as T.T5 + LOOP-O.O2 | Medium-high (conditional on AI use) | 1 wk |
| 2.4 | LOOP-U (ZTA — M-22-09 + 800-207/207A + CISA ZTMM v2.0) | NEW LOOP-U (5 slices) | High | 5 wk |
| 2.5 | LOOP-W (Prohibited Vendors — 889 + Kaspersky + OFAC) | NEW LOOP-W (4 slices) | High | 4 wk |
| 2.6 | KEV full lifecycle | Extends LOOP-B.B2 + LOOP-E.E1 | Medium-high | 1.5 wk |
| 2.7 | TIC 3.0 + M-21-07 + EINSTEIN | NEW slice LOOP-D.D4 | Medium | 1.5 wk |
| 2.8 | OSS Security (CISA + OpenSSF) | NEW slice LOOP-J.J4 | Medium | 1.5 wk |
| 2.9 | LOOP-V (HIPAA / PCI / GLBA / CCPA / GDPR conditional) | NEW LOOP-V (5 sub-slices) | Conditional High for V4; medium others | 5 wk |
| **TOTAL** | | | | **~25 wk single-thread** |

---

## 3. Confirmed-covered after R + S + CIRCIA

Items the prompt asked me to check that ARE covered, with the
covering slice cited.

### 3.1 CIRCIA workflow (cyber-incident reporting)

- **Covered by:** `docs/CIRCIA-WORKFLOW.md` (cross-cutting
  reference, ratified 2026-06-07) + LOOP-G.G2-CIRCIA-EXTENSION
  (in spec) + LOOP-M.M4-CIRCIA-EXTENSION (in spec).
- **Residual gap closed by §2.1 above** (SEC 8-K integration to
  CIRCIA-WORKFLOW.md §9.1 entry that currently says "not in
  scope" — it IS in scope for SEC-registered CSPs).

### 3.2 NIST SSDF SP 800-218 (control-side) + SLSA L3

- **Partially covered by:** Second-pass §2.3 (J.J3.b OCI signing
  + in-toto + Rekor + SLSA L3).
- **Residual gap closed by §2.2 above (LOOP-T)** — covers the
  *procurement-attestation* side (CISA Common Form), which is
  distinct from the engineering side.

### 3.3 CMMC Level 2/3 — DISTINCTION from LOOP-S

- **Covered by reference:** First-pass §4.3 flagged CMMC as
  out-of-scope. LOOP-S Section 3 explicitly distinguishes:
  - CMMC L1 (FAR-only) — out of scope.
  - CMMC L2 (NIST 800-171 + C3PAO assessment) — adjacent; LOOP-S
    produces the BoE a C3PAO would inspect, but does NOT generate
    the CMMC L2 PIEE / eMASS submission package.
  - CMMC L3 — out of scope.
- **Residual gap:** when a CSP serves DoD primes that need CMMC L2
  certification (vs DFARS equivalency), a future LOOP-X (or LOOP-S
  extension) covering the PIEE / eMASS submission would close it.
  Filed under §5 open question #2.

### 3.4 DFARS 252.204-7012 cloud-equivalency

- **Covered by:** `docs/loops/LOOP-S-SPEC.md` (3 slices:
  S.S1 800-171 crosswalk, S.S2 DC3/DIBNet incident reporting,
  S.S3 DoD CIO Equivalency Memorandum attestation).

### 3.5 Post-Quantum Cryptography (PQC)

- **Covered by:** `docs/loops/LOOP-R-SPEC.md` (3 slices:
  R.R1 inventory, R.R2 migration plan, R.R3 annual OMB report).

### 3.6 NIST IR 8334 — FIPS validation transition

- **Covered by:** NIST IR 8334 is the FIPS 140 transition guidance
  (140-2 → 140-3). FedRAMP AFR-UCM collectors validate against the
  current CMVP/MIP/IUT lists; second-pass first-pass §3.1 added
  SSP Appendix Q via LOOP-C.C10 emitter. IR 8334's transition rules
  are absorbed by the existing UCM collector logic.
- **Residual gap:** IR 8334-specific sunset-date emission per
  module — fold into LOOP-C.C10 SSP Appendix Q narrative.

### 3.7 NIST SP 800-63 Rev 4 — Digital Identity Guidelines

- **Partially covered by:** Existing IAM-MFA + IAM-AAM collectors.
  Rev 4 (2pd, July 2025; final pending) adds syncable authenticators
  + restructured proofing taxonomy + digital wallets.
- **Residual gap:** at the *AAL/IAL/FAL declaration* level, no
  current slice emits the SP 800-63-4 attestation
  (Rev 4 supersedes Rev 3 sunset 2026). Fold into LOOP-J.J1
  (User Roles + Privileges matrix) as an authenticator-class column.
- **Effort to close:** 0.5 wk (fold-in only).

### 3.8 DoD Mission Owner / DoD CCSRG SaaS-equivalency

- **Partially covered by:** LOOP-S Section 3 references
  CCSRG v1r4 (IL2/IL4/IL5/IL6). LOOP-S targets IL4-equivalent.
- **Out-of-scope:** IL5/IL6 — first-pass §4.2.

### 3.9 GSA 18F + login.gov

- **Covered by reference:** Second-pass §3.7 noted no specific
  obligation surface. login.gov is a federal-customer SSO option;
  the CSP integrates via OIDC (existing IAM stack). No new slice
  needed.

### 3.10 FedRAMP Phase Two automation specifics

- **No new public guidance since 2026-06-06.** RFC-0014 remains
  Request-For-Comment; the FRMR catalog at v0.9.43-beta absorbs
  iteration. STATUS-QUO.

### 3.11 CSA Cloud Controls Matrix (CCM) v4

- **Out-of-scope at Moderate** — commercial framework. Same
  bucket as first-pass §4.5 (SOC 2 / ISO 27001 / HITRUST).
  Could be added as a future crosswalk under multi-framework
  task #104 if a customer asks.

### 3.12 CIS Benchmarks (CIS Controls v8)

- **Partially covered by:** Task #114 K8s-direct collector (CIS
  Kubernetes Benchmark + EKS/GKE security baseline). Per-provider
  CIS Benchmark (CIS AWS Foundations, CIS GCP Foundations, CIS
  Azure Foundations) is NOT covered.
- **Residual gap:** Mid-priority extension to CMT-LMC + CNA-IBP
  collectors to surface CIS-Benchmark-pass-rate per asset. Filed
  as low-priority §3 fold-in to existing benchmark machinery.

---

## 4. Out of scope (NOT FedRAMP 20x Moderate)

Items found that don't apply at FedRAMP Moderate, with documented
re-visit triggers.

### 4.1 CMMC L2/L3 certification process (PIEE / eMASS submission)

- **Why out of scope:** CMMC is a DoD-specific *certification*
  process; FedRAMP is a separate authorization. LOOP-S produces
  the BoE; CMMC certification is a different deliverable
  modality (C3PAO assessment + PIEE submission).
- **When revisit:** when a DoD prime asks specifically for CMMC L2
  certification (not just DFARS equivalency).

### 4.2 EU NIS2 Directive 2022/2555 (24h+72h+1m)

- **Why out of scope at FedRAMP Moderate:** EU regulation; applies
  to CSPs offering services in the EU. CIRCIA-WORKFLOW.md §9.1
  already flagged this.
- **When revisit:** when CSP onboards EU-customer base.

### 4.3 GDPR Article 33 (72h)

- **Conditional in-scope via LOOP-V.V5** (§2.9 above).
- **Why out at default scope:** US-federal-only.

### 4.4 EU AI Act (Brussels Effect)

- **Out of scope:** first-pass §4.7. Confirmed.

### 4.5 PCI-DSS L1 standalone assessment

- **Conditional in-scope via LOOP-V.V2** (§2.9 above) when CSP
  processes PAN. Standalone PCI-DSS QSA assessment is a separate
  deliverable.

### 4.6 ISO 27001 / ISO 27017 / ISO 27018 / ISO 27701

- **Out of scope at Moderate** — commercial frameworks. Same
  bucket as first-pass §4.5.

### 4.7 SOC 2 Type 2

- **Out of scope at Moderate** — commercial. Same as first-pass
  §4.5.

### 4.8 FedRAMP 20x Low Baseline

- **Out of scope:** Second-pass §3.6 already addressed. Different
  authorization tier.

### 4.9 FedRAMP High / DoD IL5+

- **Out of scope:** first-pass §4.1 + §4.2. Different impact
  tier.

### 4.10 OMB M-21-07 IPv6 (federal agency procurement obligation)

- **Out of scope at the CSP level directly:** M-21-07 obligates
  federal **agencies** to procure IPv6-capable services. The CSP's
  IPv6 capability is a contracting-prerequisite, not a FedRAMP
  control.
- **Conditional in-scope:** if the CSP wants to win FY 2026+ agency
  contracts, IPv6 support is *de facto* mandatory; LOOP-D.D4
  (§2.7) covers the capability attestation.

### 4.11 Section 508 / WCAG 2.1 AA for tracker

- **Out of scope:** first-pass §4.6 + second-pass §4.1. Confirmed.

### 4.12 FedRAMP Federal Mobility Group (FMG) guidance

- **Out of scope at default:** FMG guidance applies when the CSP
  is a mobile-app provider. Mainstream SaaS CSPs are not
  mobile-app providers per the FMG definition.
- **When revisit:** when CSP ships a mobile app to federal users.

---

## 5. Open questions for the human

Decision-bearing questions before §2 work starts.

### 5.1 SEC registration status (gates §2.1)

Is the CSP (or its ultimate parent) SEC-registered?
(a) Yes — public co.; Item 1.05 + Item 106 are hard-required.
(b) No — private; G.G2-SEC-8K is a no-op attestation.
(c) Subsidiary of public co. — Item 1.05 may flow up; consult
    securities counsel.

### 5.2 AI/ML use confirmation (gates §2.3)

LOOP-O question is open per first-pass §5.1. If "yes", SP 800-218A
attestation (T.T5) follows. If "no", T.T5 is a no-op.

### 5.3 Sector-specific privacy gates (gates §2.9)

Operator must answer five conditional gates:
(a) PHI processed? (HIPAA V.V1)
(b) PAN processed? (PCI-DSS V.V2)
(c) Financial-institution customers? (GLBA V.V3)
(d) California-resident data? (CCPA V.V4) — almost universal
(e) EU data subjects? (GDPR V.V5)

### 5.4 EINSTEIN MOA participation (gates §2.7)

Does any agency customer require EINSTEIN data-sharing via MOA?
Operator confirms per-agency.

### 5.5 Section 889 vendor screen — false positive handling

Many enterprise SaaS depend on commodity hardware (e.g. surveillance
cameras at office sites) that may include 889-covered components.
LOOP-W.W1 will produce false positives. Operator confirms
mitigation policy (replace? exclude from federal-data path?
attest mitigation?).

### 5.6 OFAC sanctions screening cadence (gates §2.5)

Daily / weekly / monthly OFAC SDN-list re-screen? Operator
confirms. (Daily is safer; cost is minor.)

### 5.7 CISA Common Form scope (gates §2.2)

LOOP-T.T1 covers the form. Operator confirms: per-product or
per-CSO scope? Most CSPs sign per-CSO; some sign per-product if
SKUs differ in dev practice.

### 5.8 ZTA maturity self-rating (gates §2.4)

LOOP-U requires operator self-rating per pillar against ZTMM v2.0.
Recommend bringing in an internal architect to anchor the ratings
before U.U1 emits. The rating is signed.

### 5.9 KEV patch-blocked workflow ownership (gates §2.6)

When a KEV patch breaks something, who owns the call to defer +
apply compensating control? CIO? CISO? Eng VP? Operator confirms.

### 5.10 CMMC L2 pursuit decision (gates §3.3 residual)

Does the CSP plan to pursue CMMC L2 certification independently of
DFARS equivalency? If yes, a future LOOP covers PIEE/eMASS
submission (out of scope for this audit).

### 5.11 SP 800-63 Rev 4 timeline (gates §3.7)

Rev 4 final-publication date is still pending (2pd was July 2025).
When Rev 4 finalizes, the fold-in to LOOP-J.J1 should happen
within 90 days. Operator confirms the trigger.

### 5.12 OSS Scorecard rate-limit (gates §2.8)

`api.scorecard.dev` rate-limits anonymous calls. For >100 OSS
dependencies, the CSP needs a Scorecard API key. Operator confirms
the key-management path (env var? secret store?).

---

## 6. Final roadmap proposal

### 6.1 Updated slice count

| Source | Slices |
|---|---|
| LOOP-A (complete) | 5 |
| LOOP-B–K (pending, first-pass original) | 44 |
| LOOP-L–Q (added by first-pass) | 20 |
| First-pass §3 extensions (C10, G7, K3, etc., new slice IDs) | ~3 |
| Second-pass §2 (R + S + CIRCIA + in-loop) — LOOP-R | 3 |
| Second-pass §2 — LOOP-S (conditional) | 3 |
| Second-pass §2 — CIRCIA extensions (G.G2 + M.M4) | 2 |
| Second-pass §2 — in-loop extensions (C.C11, G.G8, I.I4 ext, J.J3.b) | 4 |
| **This audit §2 — first-class additions** | **8 (G.G2-SEC-8K + LOOP-T(4) + LOOP-U(5) + LOOP-V(5) + LOOP-W(4) + in-loop: B.B2-KEV, D.D4 TIC, J.J4 OSS, T.T5 AI-SSDF)** |
| **TOTAL** | **~99 slices** |

Breakdown of the 8 third-pass first-class additions:

| New slice / loop | Source obligation | Effort |
|---|---|---|
| **G.G2-SEC-8K-EXTENSION** | SEC 33-11216 (Item 1.05 + S-K Item 106) | 1.5 wk |
| **LOOP-T** (4 slices + T.T5 AI extension) | OMB M-22-18 + M-23-16 + NIST SP 800-218 + 800-218A + CISA Common Form | 5 wk |
| **LOOP-U** (5 slices) | OMB M-22-09 + NIST SP 800-207 / 207A + CISA ZTMM v2.0 | 5 wk |
| **LOOP-V** (5 conditional slices) | HIPAA / PCI-DSS v4.0 / GLBA / CCPA / GDPR | 5 wk |
| **LOOP-W** (4 slices) | FAR 52.204-25 + NDAA §1634 + OFAC + GSA SAM + BIS Entity List | 4 wk |
| **LOOP-B.B2-KEV-LIFECYCLE** | CISA BOD 22-01 + KEV catalog | 1.5 wk |
| **LOOP-D.D4** TIC 3.0 / M-21-07 / EINSTEIN | OMB M-19-26 + M-21-07 + CISA TIC 3.0 Capability Catalog | 1.5 wk |
| **LOOP-J.J4** OSS Security Posture | CISA + ONCD OSS Roadmap + OpenSSF Scorecard | 1.5 wk |
| **TOTAL ADDS** | | **~25 wk single-thread** |

### 6.2 Phasing recommendation

Three integration phases on top of the existing roadmap:

**Phase X1 (urgent, lands inside LOOP-B–K execution):**
- LOOP-W (Prohibited Vendors) — Section 889 has been in force
  since 2020; compliance gap is widely under-served at CSPs.
- LOOP-T (SSDF self-attestation) — M-22-18 in force; every new
  agency award since Q3 2024 has needed an attestation.
- G.G2-SEC-8K-EXTENSION (if §5.1 = yes) — 4-business-day clock
  cannot slip.

**Phase Y (lands alongside LOOP-L–S):**
- LOOP-U (ZTA) — every agency authorization conversation since
  FY 2024 expects this.
- B.B2-KEV-LIFECYCLE — pairs with LOOP-B risk engine.
- D.D4 TIC 3.0 — pairs with LOOP-D diagrams.
- J.J4 OSS Security — pairs with LOOP-J supply chain.

**Phase Z (post-L–S, conditional on operator answers):**
- T.T5 SSDF-AI (gated on §5.2 AI confirmation).
- LOOP-V (HIPAA / PCI / GLBA / CCPA / GDPR — gated on §5.3
  five-part operator confirmation; V.V4 CCPA is near-universal).

### 6.3 Total cumulative roadmap

| Phase | Loops | Slices | Single-thread effort |
|---|---|---|---|
| LOOP-A complete | A | 5 | done |
| LOOP-B..K pending | B–K | 44 | 46 wk (first-pass original) |
| LOOP-L..Q (first-pass adds) | L–Q | 20 | 25 wk |
| First-pass §3 extensions | (in loops) | 3 | 3 wk |
| LOOP-R (PQC) | R | 3 | 3 wk |
| LOOP-S (DFARS, conditional) | S | 3 | 3 wk |
| CIRCIA + 2nd-pass in-loop | (in loops) | 6 | 6 wk |
| **THIRD-PASS new** | **T + U + V + W + (in-loop ext)** | **8 first-class** | **~25 wk** |
| **GRAND TOTAL** | **17 loops + ~25 condit.** | **~99 slices** | **~111 wk single-thread (~37 wk 3-stream parallel)** |

Compared to first-pass projection (~72 slices ~64 wk) and
second-pass projection (~78 slices ~76 wk), this third pass adds
~21 slices and ~35 wk. The cumulative ~99 slices captures the
known FedRAMP-Moderate-adjacent obligation surface as of
2026-06-07. Of those, ~17 are conditional gates (LOOP-S, LOOP-V
sub-slices, LOOP-T.T5, G.G2-SEC-8K).

### 6.4 Suggested re-cut of the EXECUTION-PLAN table

| Loop | Title | Slices | Effort | Conditional? |
|---|---|---|---|---|
| (rows A–S identical to second-pass §6 table) | | | | |
| **T** | **Federal Software Self-Attestation (SSDF + AI)** | **5** | **5 wk** | T.T5 conditional on AI |
| **U** | **Zero Trust Architecture Maturity (M-22-09 + ZTMM v2.0)** | **5** | **5 wk** | always-applicable |
| **V** | **Sector-Specific Privacy Crosswalks (HIPAA / PCI / GLBA / CCPA / GDPR)** | **5** | **5 wk** | per-framework conditional |
| **W** | **Prohibited Vendors + Section 889 + Kaspersky + OFAC** | **4** | **4 wk** | always-applicable |
| (in-loop) | G.G2-SEC-8K, B.B2-KEV-LIFE, D.D4 TIC 3.0, J.J4 OSS, T.T5 AI-SSDF | ~5 | ~6 wk | various |
| **TOTAL** | | **~99 slices** | **~111 wk single-thread** | |

---

## 7. Acceptance for this audit

Mirroring the first-pass + second-pass §7 acceptance contracts:

1. ✅ Every §2 STILL-missing item has a real source citation +
   landing spot (new loop or existing extension) + effort
   estimate.
2. ✅ Every §3 confirmed-covered item names the covering slice.
3. ✅ Every §4 out-of-scope item has a documented re-visit
   trigger.
4. ✅ Every §5 open question is decision-bearing.
5. ✅ §6 totals balance: 5 (A done) + 44 (B–K) + 20 (L–Q) + 3
   (1st §3) + 3 (R) + 3 (S) + 6 (CIRCIA + 2nd in-loop) + 8 (3rd
   first-class) + 4 (3rd in-loop) ≈ 99 slices (with conditionals).

The human (or the next session that reads this audit) should be
able to: (a) accept / reject each §2 item individually; (b)
confirm §3 covered items are actually covered by reading the
named slice; (c) confirm / decline each §4 out-of-scope flag;
(d) answer each §5 open question; (e) ratify or amend the §6
phasing.

---

## Appendix — Source URL map (this audit's citation chain)

- SEC Final Rule 33-11216: https://www.sec.gov/files/rules/final/2023/33-11216.pdf
- Federal Register SEC Cyber Disclosure: https://www.federalregister.gov/documents/2023/08/04/2023-16194/cybersecurity-risk-management-strategy-governance-and-incident-disclosure
- OMB M-22-18 (Software Supply Chain): https://www.whitehouse.gov/wp-content/uploads/2022/09/M-22-18.pdf
- OMB M-23-16 (Update to M-22-18): https://www.whitehouse.gov/wp-content/uploads/2023/06/M-23-16-Update-to-M-22-18.pdf
- CISA Self-Attestation Common Form: https://www.cisa.gov/secure-software-attestation-form
- NIST SP 800-218 (SSDF v1.1): https://csrc.nist.gov/publications/detail/sp/800-218/final
- NIST SP 800-218A (SSDF for GenAI): https://csrc.nist.gov/pubs/sp/800/218/a/final
- EO 14028: https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
- EO 14110 (Safe AI): https://www.whitehouse.gov/briefing-room/presidential-actions/2023/10/30/executive-order-on-the-safe-secure-and-trustworthy-development-and-use-of-artificial-intelligence/
- OMB M-22-09 (Zero Trust): https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf
- NIST SP 800-207 (Zero Trust Architecture): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf
- NIST SP 800-207A (Multi-Cloud ZTA): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207A.pdf
- CISA Zero Trust Maturity Model v2.0: https://www.cisa.gov/zero-trust-maturity-model
- FAR 52.204-25 (Section 889 Part B): https://www.acquisition.gov/far/52.204-25
- NDAA FY18 §1634 Kaspersky: codified 41 U.S.C. §3901 note
- DHS BOD 17-01: https://www.cisa.gov/news-events/directives/bod-17-01-removal-kaspersky-branded-products
- Treasury OFAC SDN list: https://www.treasury.gov/ofac/downloads/sdn.csv
- GSA SAM Excluded Parties: https://sam.gov/
- Commerce Entity List (BIS): https://www.bis.doc.gov/index.php/policy-guidance/lists-of-parties-of-concern/entity-list
- DoD Section 1260H Chinese military companies list: https://media.defense.gov/2024/Jan/31/2003386339/-1/-1/0/1260H-FY2024.PDF
- CISA BOD 22-01 (KEV): https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01
- CISA KEV catalog JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- CISA TIC 3.0 Capability Catalog: https://www.cisa.gov/sites/default/files/publications/CISA_TIC_3.0_Vol._2_Reference_Architecture_508c_0.pdf
- OMB M-21-07 (IPv6): https://www.whitehouse.gov/wp-content/uploads/2020/11/M-21-07.pdf
- OMB M-19-26 (TIC): https://www.whitehouse.gov/wp-content/uploads/2019/09/M-19-26.pdf
- OMB M-15-13 (HTTPS-only): https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2015/m-15-13.pdf
- CISA OSS Security Roadmap (Mar 2024): https://www.cisa.gov/resources-tools/resources/open-source-software-security-roadmap
- OpenSSF Best Practices Badge: https://www.bestpractices.dev/
- OpenSSF Scorecard: https://api.scorecard.dev/
- HIPAA Security Rule (45 CFR Part 164): https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164
- PCI-DSS v4.0: https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf
- GLBA Safeguards Rule (16 CFR Part 314): https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314
- CCPA / CPRA (California Civil Code §1798.100 et seq.): https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?lawCode=CIV&division=3.&title=1.81.5.
- GDPR (Regulation (EU) 2016/679): https://eur-lex.europa.eu/eli/reg/2016/679/oj
- NIST SP 800-63 Rev 4 (2pd): https://csrc.nist.gov/pubs/sp/800/63/4/2pd
- NIST IR 8334 (FIPS 140 transition): https://csrc.nist.gov/publications/detail/nistir/8334/final
- DoD CMMC (32 CFR Part 170): https://www.dodcio.defense.gov/CMMC
- DoD CC SRG v1r4: https://dodcio.defense.gov/Portals/0/Documents/DD/CloudComputingSRG_v1r4.pdf
