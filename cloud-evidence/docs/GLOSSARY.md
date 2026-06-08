# Glossary — FedRAMP 20x, NIST, OSCAL, and internal terms

> A–Z glossary of every domain term used across the `cloud-evidence/`
> spec corpus (CLAUDE.md, EXECUTION-PLAN, SECTION-A..F, per-loop specs,
> per-slice docs, RISKS registers, audits). For each term:
>
> - **Source** — where the term is defined.
> - **Definition** — 1–3 sentence working definition as used in this
>   project. (Authoritative wording is in the cited source; this entry
>   captures the operational meaning that the spec docs presume.)
> - **Authoritative source URL** when applicable.
>
> 150+ terms. Indexed alphabetically. If you add a term during slice
> implementation, add it here too — the per-slice docs presume the
> glossary is current. 2026-06-07: 30+ new entries added covering
> LOOP-L (CRM/Inheritance), LOOP-M (Privacy/SORN/DPIA), LOOP-N (Threat
> Modeling), LOOP-O (AI/ML Governance), LOOP-P (Insider Threat + PS),
> and LOOP-Q (Marketplace + Post-ATO). 2026-06-07 (third pass): 25+
> new entries added covering LOOP-R (Post-Quantum Cryptography: PQC,
> FIPS 203/204/205, NIST IR 8547, OMB M-23-02, NSM-10, CNSA 2.0, Crypto
> Agility, Hybrid TLS), LOOP-S (DFARS 252.204-7012/-7019/-7020, NIST
> 800-171 Rev 3, CDI, DC3, DoD Cloud Computing SRG, Cloud Equivalency),
> and CIRCIA extensions (CIRCIA, Covered Entity, Covered Cyber
> Incident, Ransom Payment Report, 6 USC §681b, PPD-21 sectors).
> 2026-06-07 (fourth pass): 25+ new entries added covering LOOP-W
> (SSDF self-attestation per OMB M-22-18 / M-23-16: CISA Common Form,
> SP 800-218 + 800-218A SSDF, RSAA, Practice Group, SSDF Practice,
> SSDF Task, Self-Attestation vs Engineering Attestation), LOOP-T
> (NDAA §889 Part A / Part B + §1634 Kaspersky, FAR 52.204-25,
> FAR 52.204-26, FAR 4.2102, Covered Telecommunications Equipment or
> Services, 8 Federal-Government Business Hours, DHS Section 889
> Reporting Memo, BIS Entity List, OFAC SDN List, SAM.gov Exclusions),
> and the SEC Form 8-K Item 1.05 extension (SEC Final Rule 33-11216,
> Form 8-K Item 1.05, Material Cybersecurity Incident, Materiality /
> TSC v. Northway, 4-Business-Day Cyber Disclosure, Smaller Reporting
> Company, Wholly-Owned Subsidiary, iXBRL Inline Tagging, EDGAR
> CIK / CCC / Password / PMAC, EO 14028 §4). 2026-06-08 (fifth pass):
> 30+ new entries added covering LOOP-U (Privacy Frameworks Crosswalk:
> CCPA/CPRA, COPPA, FERPA, GLBA Safeguards Rule, GDPR Article 33, DSAR),
> LOOP-V (Healthcare Overlay: 45 CFR §164 Subparts C/D, BAA, Breach
> (HIPAA), PHI, NIST SP 800-66 Rev 2, HITRUST CSF v11.2.0, 21st Century
> Cures Act Information Blocking Rule), LOOP-X (Zero Trust: OMB M-22-09,
> NIST SP 800-207, NIST SP 800-207A, ZTMM v2.0, Zero Trust Pillar,
> PDP / PEP / PA, NIST OLIR), LOOP-Y (Sector Overlays: CJIS Security
> Policy v5.9.5, CJI, Advanced Authentication, CSO (CJIS Systems
> Officer), IRS Publication 1075, FTI, SCSEM, SSR), and LOOP-Z
> (International Equivalence: ISO/IEC 27001:2022, ISO/IEC 27017:2015,
> ISO/IEC 27018:2019, ISO/IEC 27701:2019, Annex A, SoA, PIMS, PII
> Processor, ENISA EUCS Candidate Scheme, EU Standard Contractual
> Clauses 2021/914, Schrems II, Transfer Impact Assessment).

---

## A

**3PAO (Third-Party Assessment Organization)** — *FedRAMP.* An independent
organization accredited by A2LA to perform FedRAMP assessments of CSOs.
The 3PAO produces the SAR + signs the recommendation letter that
accompanies the authorization package.
https://www.fedramp.gov/3pao-requirements/

**21st Century Cures Act Information Blocking Rule** — *45 CFR Part 171
(ONC Final Rule, effective April 2021).* Federal rule under §4004 of the
21st Century Cures Act prohibiting healthcare actors (providers, health
IT developers, HINs/HIEs) from practices likely to interfere with the
access, exchange, or use of electronic health information. Triggers
LOOP-X applicability when a CSP processes EHI on behalf of healthcare
covered entities and surfaces alongside the HIPAA stack.
https://www.healthit.gov/topic/information-blocking

**45 CFR §164 Subpart C (HIPAA Security Rule)** — *HHS.* The HIPAA
Security Rule covering administrative, physical, and technical
safeguards for electronic Protected Health Information (ePHI).
Implemented by LOOP-X.X1 control crosswalk to NIST 800-53 Rev 5 via
NIST SP 800-66 Rev 2.
https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C

**45 CFR §164 Subpart D (HIPAA Breach Notification Rule)** — *HHS.* The
HIPAA breach notification regime: notify affected individuals within 60
days of discovery, notify HHS (immediately for breaches ≥500
individuals, annually otherwise), notify prominent media for large
breaches in a state/jurisdiction. Implemented by LOOP-X.X2 breach
notification workflow + harmonized with CIRCIA + state breach laws.
https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D

**4-Business-Day Cyber Disclosure (SEC)** — *SEC Final Rule 33-11216
(July 2023).* The four-business-day deadline by which an SEC-registered
public company must file Form 8-K Item 1.05 disclosing a Material
Cybersecurity Incident, measured from the date the company determines
the incident is material (NOT from the discovery date). If a CSP is a
public registrant or a wholly-owned subsidiary whose parent is, LOOP-W
must track this clock alongside the CIRCIA 72-hour clock. Implemented
by LOOP-W.
https://www.sec.gov/files/rules/final/2023/33-11216.pdf

**8 Federal-Government Business Hours (FAR 52.204-25(d))** — *FAR
52.204-25 paragraph (d) reporting clause.* The deadline by which a
federal contractor that identifies covered telecommunications equipment
or services (NDAA §889 Part A or Part B) during contract performance
MUST report the discovery to the contracting officer (one business
day for the initial report, with additional information within 10
business days). Tracked by LOOP-T.T2 reporting workflow.
https://www.acquisition.gov/far/52.204-25

**800-218 SSDF v1.1** — *NIST SP 800-218 (February 2022).* Secure
Software Development Framework v1.1. Defines 4 Practice Groups (PO
Prepare the Organization, PS Protect the Software, PW Produce
Well-Secured Software, RV Respond to Vulnerabilities) and 19 Practices,
each decomposed into Tasks with implementation examples and references.
The reference taxonomy invoked by OMB M-22-18 / M-23-16 self-attestation
common form. Drives LOOP-W self-attestation crosswalk and LOOP-J.J3 SBOM
integration.
https://csrc.nist.gov/publications/detail/sp/800-218/final

**800-218A SSDF-AI IPD** — *NIST SP 800-218A Initial Public Draft
(April 2024).* "Secure Software Development Practices for Generative
AI and Dual-Use Foundation Models." Profile of 800-218 that adds
AI-specific Tasks (e.g. model-card emission, training-data lineage,
prompt-injection testing, adversarial evaluation) under the existing
PO/PS/PW/RV Practice Groups. Cross-references LOOP-O AI/ML governance
artifacts and is consumed by LOOP-W self-attestation when the registrant
ships generative-AI features.
https://csrc.nist.gov/pubs/sp/800/218/a/ipd

**AAR (After-Action Report)** — *Internal / NIST 800-184.* A
post-tabletop / post-incident written report covering what happened,
what worked, what failed, lessons learned. Required annually by CP-4 +
IR-3 for ISCP and IRP tests. Templated in LOOP-C.C2/C.C3.
https://csrc.nist.gov/publications/detail/sp/800-184/final

**AC-2 (Account Management)** — *NIST SP 800-53 Rev 5 control.*
Establishes the lifecycle for system accounts (create, modify,
disable, remove). Foundation control for IAM-AAM/IAM-ELP collectors +
LOOP-J.J1 roles matrix.

**AC-6 (Least Privilege)** — *NIST SP 800-53 Rev 5 control.* Requires
"minimum necessary" privileges per account; underpins LOOP-J.J1 +
periodic recertification cadence (AC-6(7)).

**ADC (Application Default Credentials)** — *GCP.* The default
credential-resolution chain for Google Cloud SDKs. The
`cloud-evidence/` GCP read-only guardrail wraps ADC.

**Advanced Authentication (CJIS §5.6.2.2.1)** — *FBI CJIS Security Policy
v5.9.5 §5.6.2.2.1.* The CJIS-mandated multi-factor authentication
requirement for access to Criminal Justice Information (CJI) from
non-trusted networks. Defines acceptable factor types (biometric,
hardware token, PKI cert, soft token, OTP) and explicitly excludes
knowledge-based answers. Implemented by LOOP-Y CJIS overlay; cross-
mapped to NIST IA-2(1)/(2).
https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center

**Annex A (ISO 27001:2022)** — *ISO/IEC 27001:2022.* The normative
annex of ISO 27001:2022 enumerating the 93 controls (reorganized from
the 114 of the 2013 edition) grouped into 4 themes: Organizational,
People, Physical, Technological. Statement of Applicability (SoA)
declares which Annex A controls apply + the implementation status.
Cross-walked to NIST 800-53 by LOOP-V.V1.

**AFR (Authorized FedRAMP Requirement)** — *FRMR.* A FedRAMP-specific
requirement (not 800-53). Ten AFR families exist; all are REQUIRED at
Moderate per R1. See `docs/AFR-FAMILY-CLASSIFICATION.md`.

**AFR-ADS (Authorization Data Sharing)** — *FRMR.* The AFR family
covering the Trust Center publication + service list publication +
historical authorization-data archive. Implemented by LOOP-G.G3.

**AFR-CCM (Continuous Monitoring)** — *FRMR.* The AFR family that
defines FedRAMP-20x-specific ConMon obligations distinct from CA-7.
Implemented by LOOP-G.G6.

**AFR-FSI (FedRAMP Security Inbox)** — *FRMR.* The AFR family requiring
a verified, monitored email inbox for FedRAMP communications.
Implemented by LOOP-G.G1.

**AFR-ICP (Incident Communications Procedures)** — *FRMR.* AFR family
defining incident reporting + update + final-report procedures.
Implemented by LOOP-G.G2.

**AFR-MAS (Minimum Assessment Scope)** — *FRMR.* AFR family covering
information-flow diagram + resource inventory + third-party-resource
enumeration. Implemented by LOOP-G.G4.

**AFR-PVA (Penetration / Vulnerability Assessment)** — *FRMR.* AFR
family. Meta-collector exists; final emitter TBD.

**AFR-SCG (Secure Configuration Guide)** — *FRMR.* AFR family. CSP
publishes the use-instructions + recommended secure configuration.
Implemented by LOOP-G.G5.

**AFR-UCM (Use of Cryptographic Modules)** — *FRMR.* AFR family. CSP
attests to FIPS 140-3 module usage. Existing collector exists; SSP
Appendix Q crypto-modules table proposed under
ADDITIONAL-LOOPS-AUDIT.md §3.1.

**AFR-VDR (Vulnerability Disclosure + Response)** — *FRMR.* AFR family
covering CVE detection + response. The VDP policy document is
proposed under ADDITIONAL-LOOPS-AUDIT.md §3.2.

**ajv** — *JSON Schema validator library.* Used in
`core/oscal-validate.ts` to validate emitted OSCAL against the v1.1.2
schemas.

**AO (Authorizing Official)** — *FedRAMP / NIST RMF.* The federal
official who signs the ATO. In 20x, the JAB has been retired; AO is
single-agency under sponsored authorization.

**AP (Assessment Plan)** — *OSCAL model.* The SAP encoded in OSCAL
v1.1.2. Emitted by LOOP-A.A2.
https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-plan/

**AR (Assessment Results)** — *OSCAL model.* SAR encoded in OSCAL
v1.1.2. Emitted by LOOP-A.A3; chained to AP via `import-ap`.
https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/

**Assessment Objective** — *NIST SP 800-53A Rev 5.* The
determination-statement-level breakdown of a control's testing
requirements. Maps to OSCAL AR `finding.target` in LOOP-K.K2.

**ATO (Authority to Operate)** — *NIST RMF.* The AO's formal decision
authorizing a system to operate in a federal environment. Tracked end-
to-end by LOOP-F.F6.

**AU-10 (Non-Repudiation)** — *NIST SP 800-53 Rev 5 control.* The
basis for evidence signing (Ed25519) + RFC 3161 timestamping in
LOOP-A.A4 + REO Rule 1.6.

**AU-11 (Audit Record Retention)** — *NIST SP 800-53 Rev 5 control.*
Three-year FedRAMP retention requirement. Implemented by LOOP-H.H2.

**AI 600-1 (GenAI Profile)** — *NIST.* Generative-AI profile of the AI
RMF, addressing risks specific to generative models (confabulation,
data poisoning, prompt injection, IP). Drives LOOP-O.O3 + O.O4.
https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.600-1.pdf

**AI RMF (Artificial Intelligence Risk Management Framework)** —
*NIST AI 100-1, v1.0 (2023).* The federal AI-risk framework. Four
functions: GOVERN, MAP, MEASURE, MANAGE. Drives LOOP-O.O2.
https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf

**Agency Authorization** — *FedRAMP.* Authorization track where a
sponsoring federal agency's AO issues the ATO directly (vs the now-
retired JAB path). Tracked per-agency in LOOP-Q.Q3.

**Appendix J** — See **SSP Appendix J** under S.

**Attack Surface** — *NIST SP 800-160.* Enumeration of every boundary
entry point + exposed service through which an adversary can interact
with a system. Enumerated by LOOP-N.N2.

**ATT&CK (MITRE ATT&CK)** — *MITRE.* Knowledge base of adversary
tactics, techniques, and procedures observed in the wild. Includes the
Cloud Matrix variant. Mapped to the boundary in LOOP-N.N4.
https://attack.mitre.org/

## B

**BAA (Business Associate Agreement)** — *HIPAA / 45 CFR §164.504(e).*
The contract a HIPAA Covered Entity must execute with any Business
Associate (e.g. a CSP processing ePHI) that pins the BA's compliance
with the HIPAA Security Rule (Subpart C), Breach Notification Rule
(Subpart D), and Privacy Rule (Subpart E) obligations. LOOP-X.X1
attestation pack includes the BAA template + signed-BAA register.
https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html

**Baseline (control baseline)** — *NIST SP 800-53B.* The published low /
moderate / high control-set per impact level. FedRAMP Moderate baseline
has ~325 controls + enhancements. Catalog at
`docs/nist-r5-baselines.generated.json`.

**Breach (HIPAA)** — *45 CFR §164.402.* The HIPAA-specific definition
of "breach": an acquisition, access, use, or disclosure of PHI in a
manner not permitted under the Privacy Rule that compromises the
security or privacy of the PHI. Subject to a 4-factor risk assessment
(nature/extent of PHI, recipient identity, whether PHI was actually
acquired/viewed, mitigation extent). Distinct from generic "incident";
LOOP-X.X2 implements the 4-factor assessment + Subpart D notification.
https://www.ecfr.gov/current/title-45/section-164.402

**BIS Entity List (15 CFR Part 744 Supp. 4)** — *U.S. Department of
Commerce Bureau of Industry and Security (BIS).* The list of foreign
parties subject to specific Export Administration Regulations license
requirements. Adding a vendor or its parent to the Entity List is a
trigger condition for LOOP-T re-evaluation of NDAA §889 supply-chain
risk and for OFAC/sanctions screening. The list is republished in the
Federal Register on a rolling basis; LOOP-T.T3 pulls the BIS-published
JSON snapshot.
https://www.bis.doc.gov/index.php/policy-guidance/lists-of-parties-of-concern/entity-list

**BOD (Binding Operational Directive)** — *CISA.* Mandatory federal
agency directive. **BOD 20-01** (VDP), **BOD 22-01** (KEV), **BOD 23-01**
(Asset Visibility) inform 20x scope.
https://www.cisa.gov/news-events/directives

**Boundary (authorization boundary)** — *FedRAMP RFC-0004 + SSP §13.*
The defined set of components in scope for the authorization.
Diagrammed in LOOP-D.D1.

## C

**CA-7 (Continuous Monitoring)** — *NIST SP 800-53 Rev 5 control.*
Foundation of LOOP-C.C6 ConMon Strategy + LOOP-E.

**CCPA/CPRA** — *California Consumer Privacy Act of 2018 (Cal. Civ.
Code §1798.100 et seq.), as amended by the California Privacy Rights
Act of 2020.* California's consumer-privacy regime granting California
residents rights of access, deletion, correction, opt-out of sale/
sharing, and limit-use of sensitive personal information. Enforced by
the California Privacy Protection Agency. LOOP-U.U2 implements
DSAR-handling crosswalk against CCPA/CPRA + GDPR.
https://cppa.ca.gov/regulations/

**CJI (Criminal Justice Information)** — *FBI CJIS Security Policy.*
Data provided by or for FBI CJIS systems used for criminal justice
purposes (CHRI, biometric, identity history, biographic data,
property data, case/incident history, etc.). Triggers CJIS Security
Policy applicability + Advanced Authentication requirement.
Inventoried by LOOP-Y.Y1.

**CJIS Security Policy v5.9.5** — *FBI Criminal Justice Information
Services Division (December 2024).* The federal policy enumerating
the security controls a CSP must satisfy to host Criminal Justice
Information (CJI) on behalf of a Criminal Justice Agency. Defines 13
policy areas (access control, awareness training, audit/accountability,
incident response, physical protection, advanced authentication,
encryption, etc.) and a CJIS Systems Officer (CSO) governance role.
Implemented by LOOP-Y.
https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center

**COPPA (Children's Online Privacy Protection Act)** — *15 USC §6501 et
seq.; 16 CFR Part 312 (FTC Rule).* The U.S. federal statute + FTC rule
restricting collection of personal information from children under 13
without verifiable parental consent. Triggers LOOP-U applicability when
CSP processes child-directed content or has actual knowledge of
under-13 users. Carries strict FTC enforcement (per-violation civil
penalties).
https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa

**Canonical JSON** — *Internal.* Sorted-keys + LF-only line ending +
no extra whitespace JSON format used for signed manifests so signatures
are stable across re-emits.

**CHANGELOG.md "Unreleased"** — *Internal.* The section every slice
appends to as part of the 7-step completion procedure. Source of
truth for what's shipped per slice.

**CIS/CRM Workbook** — *FedRAMP / SSP Appendix J.* Control
Implementation Summary / Customer Responsibility Matrix workbook.
Proposed LOOP-L.L1 in ADDITIONAL-LOOPS-AUDIT.md §2.

**CISA AIS (Automated Indicator Sharing)** — *CISA.* The federal STIX
feed for threat indicators. Proposed extension under
ADDITIONAL-LOOPS-AUDIT.md §3.9.

**CISA Common Form (OMB 1670-0052)** — *CISA / OMB.* The Secure
Software Development Attestation Common Form (OMB Control Number
1670-0052) that a software producer signs and submits to CISA's
Repository for Software Attestations and Artifacts (RSAA) per OMB
M-22-18 / M-23-16. Lists the SSDF-mapped practices the producer
attests to performing. LOOP-W emits the populated Common Form + the
RSAA submission envelope.
https://www.cisa.gov/resources-tools/services/secure-software-development-attestation-form

**Common Form Self-Attestation** — See **Self-Attestation (vs Engineering
Attestation)** under S.

**CIRCIA (Cyber Incident Reporting for Critical Infrastructure Act)** —
*Federal statute, 6 USC §681b.* Enacted March 2022; CISA published the
Final Rule in early 2026 with an effective date of May 2026. Requires
Covered Entities in PPD-21 critical-infrastructure sectors to report
Covered Cyber Incidents to CISA within 72 hours and ransom payments
within 24 hours. Implemented as overlay extensions to G.G2 (AFR-ICP)
and M.M4 (Privacy incident response) — see
`docs/CIRCIA-WORKFLOW.md` and `docs/slices/G/G.G2-CIRCIA-EXTENSION.md` +
`docs/slices/M/M.M4-CIRCIA-EXTENSION.md`. HIGH PRIORITY due to May 2026
effective date.
https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/cyber-incident-reporting-critical-infrastructure-act-2022-circia

**Cloud Equivalency** — *DoD CIO Memo (DFARS supplement).* The DoD
policy that lets a FedRAMP-Moderate CSO satisfy NIST 800-171 protection
for CDI on DoD-prime contracts, provided the CSO also implements the
DFARS 252.204-7012(c) incident reporting flow + a delta crosswalk
showing every 800-171 Rev 3 control is mapped to the corresponding
800-53 Rev 5 baseline control. Implemented by LOOP-S.

**Cloud Computing SRG (Security Requirements Guide)** — *DoD CIO /
DISA.* The DoD Cloud Computing SRG defines IL2/IL4/IL5/IL6 cloud
impact levels. LOOP-S references the IL4/IL5 alignment with FedRAMP
Moderate/High for DoD-prime customer scenarios.
https://public.cyber.mil/dccs/dccs-documents/

**CNSA 2.0 (Commercial National Security Algorithm Suite 2.0)** — *NSA.*
The NSA-published successor to CNSA 1.0; mandates PQC-safe primitives
(ML-KEM, ML-DSA, SHA-2-384/512, AES-256) for National Security Systems.
Federal civilian systems align via NSM-10. Consumed by LOOP-R.
https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF

**Covered Cyber Incident** — *CIRCIA / 6 USC §681b(c)(2)(C).* A
substantial cyber incident at a Covered Entity that meets one of the
CIRCIA Final Rule thresholds (loss of confidentiality/integrity/
availability of information systems, disruption of operations,
unauthorized access via supply chain compromise). Triggers the
72-hour reporting deadline.

**Covered Defense Information (CDI)** — *DFARS 252.204-7012(a).*
Unclassified controlled technical information or other information
identified in the contract that requires safeguarding. Triggers DFARS
7012 compliance + 800-171 control set. Routed through LOOP-S
data-classification tagging.

**Covered Entity** — *CIRCIA / 6 USC §681b(c)(2)(B).* An entity in one
of the 16 PPD-21 critical-infrastructure sectors that meets CISA's
size + role thresholds. CSPs processing critical-infrastructure
workloads are Covered Entities. Determines CIRCIA reporting obligation.

**Covered Telecommunications Equipment or Services (FAR 52.204-25(a))** —
*FAR 52.204-25 paragraph (a).* Telecommunications and video-surveillance
equipment or services produced or provided by Huawei, ZTE, Hytera,
Hangzhou Hikvision, Dahua, or any subsidiary or affiliate, AND any
covered telecommunications service that uses such equipment as a
substantial or essential component of any system or as critical
technology. Triggers NDAA §889 Part A prohibition (use / sale to USG)
and Part B prohibition (USG contracts with entities that use it).
LOOP-T.T1 collectors enumerate boundary inventory against this
definition.
https://www.acquisition.gov/far/52.204-25

**Crypto Agility** — *NIST IR 8547 / OMB M-23-02.* The system property
of being able to swap cryptographic algorithms (or algorithm
parameters) without re-architecting the application. Crypto-agile
designs are a precondition for the PQC migration path. Tracked by
LOOP-R.R1 + LOOP-R.R2.

**check:provenance** — *Internal CI guardrail G3.* Fails the build when
a new emit-field lacks a `provenance` entry or `coverage_source` registry
entry.

**check:reo** — *Internal CI command.* Aggregates G1+G2+G3 guardrails.
Every slice MUST pass before commit.

**CMP (Configuration Management Plan)** — *FedRAMP template / NIST
CM-9.* Required SSP appendix doc. Emitted by LOOP-C.C1.

**CMVP (Cryptographic Module Validation Program)** — *NIST / NSA.* The
program that certifies FIPS 140-3 modules. Cert numbers feed SSP
Appendix Q crypto table.

**ComponentDefinition** — *OSCAL model.* Used to declare leveraged-
authorization inherited controls. Proposed LOOP-L.L2.

**ConMon (Continuous Monitoring)** — *FedRAMP / NIST CA-7.* Post-ATO
recurring evidence delivery. LOOP-E + AFR-CCM (LOOP-G.G6).

**Coverage:miss** — *Internal log line.* Emitted by collectors when an
inventory cell can't be filled. Required by REO Rule 1.5.

**Coverage report** — *Internal.* `out/inventory-coverage.json` tracks
fill-rate per asset family + per emit-field; coverage cannot regress
(G2 guardrail).

**CRM (Customer Responsibility Matrix)** — *FedRAMP.* The mandatory
SSP Appendix J workbook assigning each NIST 800-53 Rev 5 control to one
responsibility bucket: CSP-Implemented, Customer-Implemented, Shared,
Hybrid, Inherited, or Not-Applicable. Synonym for CIS/CRM workbook.
Implemented by LOOP-L.L1.

**Cloud Matrix (ATT&CK Cloud)** — *MITRE.* The cloud-specific variant of
the MITRE ATT&CK matrix covering IaaS, SaaS, identity providers, and
office suites. Filtered subset consumed by LOOP-N.N4.
https://attack.mitre.org/matrices/enterprise/cloud/

**CSP-Implemented** — *FedRAMP / SSP Appendix J.* CRM responsibility
bucket where the CSP performs the control implementation end-to-end
(no customer action required). One of six buckets enumerated by
LOOP-L.L1.

**Customer-Implemented** — *FedRAMP / SSP Appendix J.* CRM
responsibility bucket where the customer must perform the control
implementation (the CSP cannot complete it). One of six buckets
enumerated by LOOP-L.L1.

**CSP (Cloud Service Provider)** — *FedRAMP.* The vendor seeking
authorization. In this repo: the operator running `cloud-evidence/`.

**CSO (Cloud Service Offering)** — *FedRAMP.* A single offering inside
a CSP. Multi-CSO supported via LOOP-H.H3.

**CSF v2.0 (Cybersecurity Framework)** — *NIST.* Cited in
ADDITIONAL-LOOPS-AUDIT.md as a cross-framework reference for LOOP-I.I4.
https://www.nist.gov/cyberframework

**CVE (Common Vulnerabilities and Exposures)** — *MITRE.* CVE IDs feed
the VDR pipeline + LOOP-B.B1 risk scoring.

**CVSS (Common Vulnerability Scoring System)** — *FIRST.org.*
v3.1 + v4.0 vector parsing in LOOP-B.B1.
https://www.first.org/cvss/v3.1/specification-document

## D

**Data classification** — *Internal tag.* `inventory.assets[].data_classification`
∈ {public, internal, confidential, cui, pii}. Set via cloud tag
`fedramp_data_classification`. Drives LOOP-B.B1 criticality.

**Data Subject Access Request (DSAR)** — *GDPR Articles 15-22; CCPA/CPRA
§1798.100-130.* A formal request by a data subject (or California
consumer) to exercise rights of access, rectification, erasure,
portability, restriction, objection, or opt-out. LOOP-U.U2 emits the
DSAR-handling workflow + per-jurisdiction response deadlines (GDPR: 1
month; CCPA: 45 days, extendable +45) + the audit trail evidence pack.

**DC3 (DoD Cyber Crime Center)** — *DoD.* The DoD organization that
receives DFARS 252.204-7012(c) cyber incident reports via the DIB Net
portal (https://dibnet.dod.mil/). LOOP-S.S2 emits the DC3 submission
record and tracks the 72-hour deadline.

**DFARS 252.204-7012 (Safeguarding Covered Defense Information +
Cyber Incident Reporting)** — *DFARS / 48 CFR §252.204-7012.* The DoD
clause that requires contractors handling CDI to implement NIST
800-171 safeguards + report cyber incidents to DC3 within 72 hours of
discovery. Cloud-equivalency path lets a FedRAMP-Moderate CSO satisfy
the safeguarding clause. Implemented by LOOP-S.
https://www.acq.osd.mil/dpap/dars/dfars/html/current/252204.htm#252.204-7012

**DFARS 252.204-7019 (Notice of NIST SP 800-171 DoD Assessment
Requirements)** — *DFARS / 48 CFR §252.204-7019.* The clause requiring
contractors to post a current SPRS score before contract award. Cited
in LOOP-S.S3 for the attestation package's SPRS coverage.

**DFARS 252.204-7020 (NIST SP 800-171 DoD Assessment Requirements)** —
*DFARS / 48 CFR §252.204-7020.* The DoD-self / 3PAO assessment regime
underpinning -7019. Cited in LOOP-S.S3 as the trail that the
equivalency attestation aligns to.

**DHS Section 889 Reporting Memo** — *DHS Procurement Innovation Lab /
DHS HQ (revised 2024).* The DHS implementation guidance for federal
contractors reporting identifications of Covered Telecommunications
Equipment or Services during contract performance per FAR 52.204-25(d).
Pins the report content (CAGE code, contract number, identifying
party, removal plan) and the contracting officer routing. LOOP-T.T2
emits in this format when DHS is the contracting agency; otherwise the
agency-specific equivalent.
https://www.dhs.gov/sites/default/files/publications/section-889-implementation-guidance.pdf

**Datasheet for Datasets** — *Gebru et al. 2018; NIST AI RMF MAP.*
Structured document for training-data provenance: collection process,
demographics, intended use, known biases, maintenance. Emitted per
training-dataset by LOOP-O.O5.

**Determination statement** — *NIST 800-53A Rev 5.* Sub-objective of
an assessment objective; maps to OSCAL AR `finding.target` in LOOP-K.K2.

**DPIA (Data Protection Impact Assessment)** — *GDPR Art. 35 / OMB
M-03-22.* Privacy-impact assessment scoped to cross-border data
transfers and agency-partner data sharing. Beyond the baseline PIA.
Implemented by LOOP-M.M2.

**Diagram Label** — *Internal synthesized field.* `asset.diagram_label`
computed in INV-S6 when operator opts in; provenance recorded in
`asset.synthesized_fields[]`.

**DKIM (DomainKeys Identified Mail)** — *IETF RFC 6376.* Used in
LOOP-G.G1 FSI webhook to verify @fedramp.gov senders.

**DR (Deviation Request)** — *FedRAMP CMP.* Operator-triggered
deviation form when a control or scan window can't be met. Emitted by
LOOP-E.E5.

## E

**Ed25519** — *Cryptographic signature algorithm.* Used by `core/sign.ts`
for all evidence envelopes. REO Rule 1.6.

**ENISA EUCS Candidate Scheme** — *European Union Agency for
Cybersecurity (ENISA).* The European Cybersecurity Certification Scheme
for Cloud Services — a candidate certification scheme under the EU
Cybersecurity Act (Regulation (EU) 2019/881) defining three assurance
levels (Basic / Substantial / High) for cloud service providers. Once
finalized, becomes the EU-wide equivalent of FedRAMP. LOOP-Z.Z2 emits
a FedRAMP-Moderate → EUCS-Substantial mapping.
https://www.enisa.europa.eu/publications/eucs-cloud-service-scheme

**EDGAR CIK / CCC / Password / PMAC** — *SEC EDGAR filer-credential set.*
The four credentials the SEC EDGAR filing system uses to authenticate a
filer: CIK (Central Index Key, the 10-digit registrant identifier; not
secret), CCC (CIK Confirmation Code, an 8-char secret bound to the
CIK), Password (filer login password), and PMAC (Password Modification
Authorization Code, used to rotate the password). LOOP-W.W3 + the
SEC 8-K extension pack populate the EDGAR submission envelope using the
CIK + CCC from operator config; Password + PMAC stay out of the repo.
https://www.sec.gov/edgar/filer-information

**EO 14028 §4 (Software Supply Chain)** — *Executive Order 14028
(May 2021), Section 4.* "Enhancing Software Supply Chain Security."
Directs NIST to publish guidance for federal-procured software
(realized as SP 800-218 SSDF) and directs OMB to require federal
agencies to obtain producer self-attestations to that guidance
(realized as OMB M-22-18 + M-23-16). Root authority for the LOOP-W
self-attestation flow.
https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity

**EPSS (Exploit Prediction Scoring System)** — *FIRST.org.* Per-CVE
probability of exploitation. Consumed by LOOP-B.B1.
https://www.first.org/epss/

**Envelope** — *Internal.* `core/envelope.ts` defines the canonical
KSI envelope JSON: `{ ksi_id, collected_at, findings[], provenance, ... }`.

**EO 13587** — *Executive Order (2011).* Establishes the federal
Insider Threat Program (cross-agency). Foundational authority for
PM-12 + LOOP-P.P1.
https://www.federalregister.gov/documents/2011/10/13/2011-26729/structural-reforms-to-improve-the-security-of-classified-networks-and-the-responsible-sharing-and

**EO 14110** — *Executive Order (Oct 2023).* "Safe, Secure, and
Trustworthy Development and Use of Artificial Intelligence." Drives
OMB M-24-10 implementation deadlines and the AI risk-management
obligations enumerated in LOOP-O.
https://www.federalregister.gov/documents/2023/11/01/2023-24283/

**EO 14179** — *Executive Order (Jan 2025).* "Removing Barriers to
American Leadership in Artificial Intelligence." Reframes (does not
fully rescind) EO 14110; OMB M-25-21 updates LOOP-O implementation
guidance accordingly.

**Evidence walk-through artifacts** — *FedRAMP B-side.* Screenshots +
transcripts captured during 3PAO testing. LOOP-F.F4.

## F

**FAR 4.2102** — *Federal Acquisition Regulation Subpart 4.21,
section 4.2102 (Prohibition).* Codifies NDAA §889 Part A + Part B
prohibitions into the FAR procurement framework. Pins the contractor
representation + reporting requirements that flow through FAR
52.204-25, FAR 52.204-26, and SAM.gov representations. Cited by
LOOP-T.T1 + T.T2 as the procurement-side anchor for the §889
inventory + reporting workflow.
https://www.acquisition.gov/far/subpart-4.21

**FAR 52.204-25 (Part A vs Part B)** — *FAR clause 52.204-25
(Prohibition on Contracting for Certain Telecommunications and
Video Surveillance Services or Equipment).* Implements NDAA §889
in contracts. **Part A** = contractor may not provide covered
telecommunications equipment or services to USG. **Part B** = USG
may not enter into a contract with an entity that uses such equipment
or services. The two parts have different scopes (sale-to-USG vs
use-anywhere-in-the-entity), different applicability tests, and
different reporting deadlines. LOOP-T.T1 emits per-asset Part A +
Part B determinations.
https://www.acquisition.gov/far/52.204-25

**FAR 52.204-26** — *FAR clause 52.204-26 (Covered Telecommunications
Equipment or Services—Representation).* The pre-award representation
in which a contractor declares whether it does or does not provide /
use Covered Telecommunications Equipment or Services. Posted by the
contractor in SAM.gov. LOOP-T.T2 emits the supporting evidence pack +
representation language.
https://www.acquisition.gov/far/52.204-26

**FedRAMP** — *Federal Risk and Authorization Management Program.* The
US-government CSP authorization program.
https://www.fedramp.gov/

**FERPA (Family Educational Rights and Privacy Act)** — *20 USC §1232g;
34 CFR Part 99.* Federal statute + DoE rule protecting the privacy of
student education records. Applies to educational agencies / institutions
receiving DoE funds and (by contract) to school-service-provider CSPs
that process student records as a "school official" with a legitimate
educational interest. LOOP-U.U3 implements the FERPA evidence pack.
https://www2.ed.gov/policy/gen/guid/fpco/ferpa/index.html

**FTI (Federal Tax Information)** — *26 USC §6103 / IRS Publication 1075.*
Federal tax return / return-information data covered by the
confidentiality protections of 26 USC §6103. Triggers IRS Publication
1075 applicability when a CSP receives, processes, stores, or transmits
FTI on behalf of a federal/state/local agency. Inventoried by LOOP-Y.Y2.

**FedRAMP 20x** — *Program revision.* Authorization framework
modernization, Phase Two specifies automated/opinionated KSI validation.
https://www.fedramp.gov/20x/

**FedRAMP Marketplace** — *FedRAMP.* The public-facing CSO registry.
Proposed integration LOOP-Q.
https://marketplace.fedramp.gov/

**FedRAMP Phase Two** — *RFC-0014.* Mandates truly automated +
opinionated validation of KSIs for Moderate.

**FIPS 140-3** — *NIST CMVP.* Cryptographic module certification
standard. SSP Appendix Q crypto table cites FIPS validation numbers.

**FIPS 203 (ML-KEM)** — *NIST FIPS 203 (August 2024).* Module-Lattice-
Based Key-Encapsulation Mechanism Standard. The NIST-standardised PQC-
safe key-encapsulation primitive (derived from CRYSTALS-Kyber). Tracked
by LOOP-R.R1 cryptographic inventory + R.R2 migration plan.
https://csrc.nist.gov/pubs/fips/203/final

**FIPS 204 (ML-DSA)** — *NIST FIPS 204 (August 2024).* Module-Lattice-
Based Digital Signature Standard. NIST-standardised PQC-safe digital
signature primitive (derived from CRYSTALS-Dilithium). Tracked by
LOOP-R.R1 inventory + R.R2 migration plan.
https://csrc.nist.gov/pubs/fips/204/final

**FIPS 205 (SLH-DSA)** — *NIST FIPS 205 (August 2024).* Stateless Hash-
Based Digital Signature Standard. NIST-standardised PQC-safe signature
primitive (derived from SPHINCS+) intended for long-lived signing keys.
Tracked by LOOP-R.R1 inventory + R.R2 migration plan.
https://csrc.nist.gov/pubs/fips/205/final

**FIPS 199** — *NIST.* Federal Information Processing Standard for
categorization. Worksheet emitted by LOOP-C.C5.

**Finding** — *Internal envelope field.* A single
PASS/FAIL/INFO/REQUIRES-OPERATOR-INPUT determination from a collector.
Defined in `core/findings.ts`.

**Form 8-K Item 1.05** — *SEC Final Rule 33-11216 (July 2023).* The
SEC Form 8-K item the registrant must file within 4 business days of
determining a cybersecurity incident is material. Item 1.05 requires
disclosure of the nature, scope, and timing of the incident plus the
material impact (financial, operational, reputational). LOOP-W /
G.G2-SEC-8K-EXTENSION emit the populated Item 1.05 narrative + the
iXBRL-tagged 8-K envelope.
https://www.sec.gov/files/rules/final/2023/33-11216.pdf

**FRMR** — *FedRAMP Machine-Readable Requirements.* JSON catalog at
`github.com/FedRAMP/docs`. Source of truth for all FedRAMP-specific
requirements. Cached locally as `docs/frmr-requirements.generated.json`.

**FRR (FedRAMP Requirement Reference)** — *FRMR.* The catalog ID for
a single requirement statement (e.g. FRR-FSI-09).

## G

**GDPR Article 33** — *Regulation (EU) 2016/679, Article 33.* The
GDPR "Notification of a personal data breach to the supervisory
authority" requirement: a controller must notify the competent
supervisory authority without undue delay and, where feasible, within
72 hours of becoming aware of a personal data breach. Processors must
notify controllers without undue delay. Harmonized with CIRCIA 72-hour
clock + HIPAA Subpart D + state laws by LOOP-U.U1.
https://gdpr-info.eu/art-33-gdpr/

**GLBA Safeguards Rule** — *Gramm-Leach-Bliley Act §501(b); 16 CFR Part
314 (FTC).* The FTC rule (revised 2021, full compliance 2023) requiring
financial institutions to develop, implement, and maintain a written
information-security program with administrative, technical, and
physical safeguards. Includes specific elements: qualified individual,
risk assessment, access controls, encryption, MFA, incident response
plan. Triggers LOOP-U applicability for CSPs serving GLBA-covered
financial institutions.
https://www.ftc.gov/legal-library/browse/rules/safeguards-rule

**Guardrail (G1, G2, G3)** — *Internal CI.* G1 = lint:no-stubs;
G2 = check:coverage-regression; G3 = check:provenance. Required checks
in `.github/workflows/ci.yml`.

## H

**HITRUST CSF v11.2.0** — *HITRUST Alliance.* A prescriptive, certifiable
security + privacy framework that crosswalks 60+ source authorities
(HIPAA, NIST 800-53, ISO 27001, PCI-DSS, GDPR, AI RMF, etc.) into a
unified control set with three assessment tiers: e1, i1, r2. HITRUST
CSF v11.2.0 (April 2024) added AI risk-management requirements. LOOP-V.V3
emits the HITRUST → FedRAMP Moderate crosswalk for healthcare CSPs.
https://hitrustalliance.net/product-tool/hitrust-csf/

**HMAC-SHA256** — *Cryptographic primitive.* Used in LOOP-G.G1 webhook
auth + generic-webhook adapter (Phase F.4).

**Hybrid TLS** — *NIST SP 800-227 (draft) / IETF TLS WG.* A TLS
configuration that runs a classical key-exchange primitive (e.g.
ECDH-P256) in parallel with a PQC-safe key-encapsulation mechanism
(e.g. ML-KEM-768) and combines the shared secrets via a KDF, so the
session is forward-secure even if one primitive is later broken.
LOOP-R.R2 migration plan recommends Hybrid TLS as the staged migration
target before PQC-only deployments.

**Hybrid Control** — *FedRAMP / SSP Appendix J.* CRM responsibility
bucket where the CSP implements one portion of the control and the
customer implements another portion (distinct from Shared, where both
parties implement the same portion). One of six buckets enumerated by
LOOP-L.L1.

## I

**IAM-AAM (Account Access Management)** — *KSI.* Existing IAM collector
covering AC-2.

**iXBRL Inline Tagging (SEC)** — *SEC EDGAR / XBRL US.* Inline eXtensible
Business Reporting Language. SEC Form 8-K Item 1.05 disclosures must be
filed with iXBRL inline tags that machine-tag the disclosure elements
(incident date, materiality determination date, nature of incident,
material impact). LOOP-W / G.G2-SEC-8K-EXTENSION emits the iXBRL-tagged
HTML envelope, not just plain narrative.
https://www.sec.gov/structureddata/osd-inline-xbrl.html

**IAM-ELP (Enforce Least Privilege)** — *KSI.* Existing IAM collector
covering AC-6.

**IIW (Integrated Inventory Workbook)** — *FedRAMP template.* The
inventory submission spreadsheet. Generator already shipped (INV-1..4).

**Impact level** — *FedRAMP / FIPS 199.* Low / Moderate / High. This
codebase targets Moderate; High emits a `HIGH-CLARIFY` warning until
20x High exists.

**Implementation log** — *Internal per-slice doc section.* Running
journal kept during slice implementation. See
`IMPLEMENTATION-LOG-TEMPLATE.md`.

**INV-P1..P5 + INV-S1..S6** — *Internal inventory chain.* The
already-shipped inventory enrichment passes. Source of all asset
metadata consumed downstream.

**Inventory** — *Internal.* `out/inventory.json` is the structured
asset catalog. Every diagram + risk-score input traces here.

**Inherited Control** — *FedRAMP / SSP Appendix J.* CRM responsibility
bucket where the control is implemented by an underlying FedRAMP-
Authorized IaaS/PaaS and the CSO inherits the implementation
end-to-end. Tracked back to the underlying provider's CRM by
LOOP-L.L2.

**Insider Threat (PM-12)** — See **PM-12** under P.

**IR-8 (Incident Response Plan)** — *NIST SP 800-53 Rev 5 control.*
Drives LOOP-C.C3.

**IRP (Incident Response Plan)** — *FedRAMP template.* The Word doc
emitted by LOOP-C.C3.

**IRS Publication 1075** — *IRS Publication 1075 (Tax Information
Security Guidelines for Federal, State and Local Agencies),
Rev. November 2021.* The IRS-published security guideline (and SCSEM
testing checklists) that agencies receiving FTI must implement. Builds
on NIST 800-53 Moderate with FTI-specific overlays (mandatory state
disclosure, contractor employee fingerprinting, dedicated facility
inspection). LOOP-Y.Y2 emits the IRS Pub 1075 attestation pack.
https://www.irs.gov/pub/irs-pdf/p1075.pdf

**ISO/IEC 27001:2022** — *ISO/IEC.* The international standard for
Information Security Management Systems (ISMS). Defines the
risk-based ISMS lifecycle (clauses 4-10) + Annex A control catalog (93
controls in 4 themes, reorganised from the 114-control / 14-domain
structure in the 2013 edition). LOOP-Z.Z1 emits the ISO 27001:2022 →
FedRAMP Moderate crosswalk + Statement of Applicability template.
https://www.iso.org/standard/27001

**ISO/IEC 27017:2015** — *ISO/IEC.* The international standard giving
cloud-specific guidance on top of ISO 27001/27002. Adds CLD.* controls
covering customer/provider role separation, virtual environment
segmentation, virtual machine hardening, administrator operational
security. LOOP-Z.Z1 includes 27017 in the ISO crosswalk pack.
https://www.iso.org/standard/43757.html

**ISO/IEC 27018:2019** — *ISO/IEC.* The international code of practice
for protection of PII in public clouds acting as PII Processors.
Extends 27002 + 27017 with PII-processor-specific controls (purpose
limitation, consent, transparency, data-subject rights, secure deletion,
sub-processor disclosure). LOOP-Z.Z1 includes 27018 alongside 27701
when the CSP processes PII.
https://www.iso.org/standard/76559.html

**ISO/IEC 27701:2019** — *ISO/IEC.* The international standard extending
ISO 27001 + 27002 to a Privacy Information Management System (PIMS) for
PII Controllers and PII Processors. Adds privacy-specific clauses + two
new Annexes (A for controllers, B for processors) crosswalked to GDPR.
LOOP-Z.Z2 emits the 27701 PIMS evidence pack alongside the ISO 27001
ISMS pack.
https://www.iso.org/standard/71670.html

**ISCP (Information System Contingency Plan)** — *FedRAMP template.*
Emitted by LOOP-C.C2.

## J

**JAB (Joint Authorization Board)** — *FedRAMP legacy.* Retired in
20x; replaced by single-agency sponsored P-ATO.

## K

**KEV (Known Exploited Vulnerabilities Catalog)** — *CISA.* Per-CVE
"actively exploited" list with `dueDate` (21d). Consumed by LOOP-B.B2
remediation deadline math.
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**KSI (Key Security Indicator)** — *FedRAMP 20x.* Per RFC-0014, a
single automatically-verifiable security property of the CSO. ~63 KSIs
classified in this repo (see `docs/AFR-FAMILY-CLASSIFICATION.md` +
`afr-classification.json`).

**ksi-map** — *Internal `core/ksi-map.ts`.* Maps each KSI to its
collector(s), envelope shape, and downstream artifacts.

## L

**LEV (Likely Exploited Vulnerabilities)** — *FedRAMP / FedPy.* A
remediation-deadline tier in VDR pipeline. Distinct from KEV. LOOP-B.B2
applies the FedRAMP CMP table.

**Leveraged Authorization** — *FedRAMP.* When a CSO inherits controls
from an underlying FedRAMP-Authorized IaaS/PaaS (AWS GovCloud, GCP
Assured Workloads, Azure Government). Drives LOOP-L.L2 + L.L3.

**lint:no-stubs** — *Internal G1 guardrail.* `scripts/lint-no-stubs.mjs`
scans production paths for forbidden tokens (TODO, FIXME, sample,
placeholder, lorem, "coming soon", "not yet implemented", etc.).

**LOOP (LOOP-A through LOOP-Q)** — *Internal roadmap unit.* A
themed collection of slices. LOOP-A complete; LOOP-B..K + LOOP-L..Q
all specified with per-slice docs + risks registers (LOOP-L..Q
ratified 2026-06-07).

## M

**Manifest** — *Internal.* Signed `out/manifest.json` enumerates every
artifact + sha256. Subject of the RFC 3161 timestamp.

**Material Cybersecurity Incident (SEC)** — *SEC Final Rule 33-11216.* A
cybersecurity incident that a registrant determines is "material" under
the TSC v. Northway standard (i.e. a reasonable investor would consider
the incident important in making an investment decision). Triggers the
Form 8-K Item 1.05 4-business-day disclosure clock. Materiality is a
separate determination from incident-discovery; the 4-business-day clock
starts on the materiality-determination date, not the discovery date.

**Materiality (TSC v. Northway standard)** — *U.S. Supreme Court (TSC
Industries, Inc. v. Northway, Inc., 426 U.S. 438 (1976)).* The federal
securities-law standard for whether information is "material": there
must be a substantial likelihood that a reasonable investor would
consider it important in deciding how to vote or invest. Pinned by the
SEC in the 2023 cybersecurity disclosure rule as the threshold for
Form 8-K Item 1.05 reporting.

**MFA (Multi-Factor Authentication)** — *NIST IA-2.* Existing IAM-MFA
collectors validate MFA presence on privileged accounts.

**Moderate (FedRAMP)** — *Impact level.* The scope target for this
repo. Maps to NIST SP 800-53B Moderate baseline.

**Marketplace (FedRAMP)** — See **FedRAMP Marketplace** under F.

**Model Card** — *Mitchell et al. 2019; NIST AI RMF MAP.* Structured
document for trained-model transparency: intended use, training data,
performance metrics across slices, ethical considerations, limitations.
Emitted per inference endpoint by LOOP-O.O5.

**MITRE ATT&CK** — See **ATT&CK** under A.

## N

**NDAA §889 (Pub. L. 115-232)** — *National Defense Authorization Act
for Fiscal Year 2019, Section 889.* The federal statute that prohibits
USG use of (Part A, effective August 2019) and USG contracts with
entities that use (Part B, effective August 2020) Covered
Telecommunications Equipment or Services from named PRC vendors
(Huawei, ZTE, Hytera, Hangzhou Hikvision, Dahua). Implemented in the
FAR via 52.204-25, 52.204-26, and 4.2102. Root statutory authority for
LOOP-T.
https://www.congress.gov/115/plaws/publ232/PLAW-115publ232.pdf

**NDAA §1634 (Kaspersky prohibition)** — *National Defense Authorization
Act for Fiscal Year 2018, Section 1634.* Statutory prohibition on USG
use of any hardware, software, or services developed or provided in
whole or in part by Kaspersky Lab. Separate from §889 but enumerated in
the same LOOP-T inventory pass (T.T1) because the operational
remove-and-attest workflow is identical.
https://www.congress.gov/115/plaws/publ91/PLAW-115publ91.pdf

**NIST AI RMF 1.0** — *NIST AI 100-1.* Drives LOOP-O.
https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf

**NIST OLIR (Online Informative References Program)** — *NIST.* The NIST
program that publishes machine-readable mappings ("Informative
References") between cybersecurity / privacy reference documents (e.g.
NIST 800-53, ISO 27001, HIPAA Security Rule, CSF). OLIRs are the
canonical mechanism used by LOOP-V.V1, LOOP-X.X1, LOOP-Z.Z1, and other
crosswalk emitters to ground claimed control mappings in NIST-published
references.
https://csrc.nist.gov/projects/olir

**NIST SP 800-66 Rev 2** — *NIST SP 800-66 Revision 2 (February 2024).*
"Implementing the HIPAA Security Rule: A Cybersecurity Resource Guide."
The current NIST guidance crosswalking the HIPAA Security Rule
(45 CFR §164 Subpart C) standards + implementation specifications to
NIST 800-53 Rev 5 controls + the NIST Cybersecurity Framework v2.0.
Drives LOOP-V.V1 + LOOP-X.X1 healthcare control crosswalk.
https://csrc.nist.gov/pubs/sp/800/66/r2/final

**NIST SP 800-207** — *NIST SP 800-207 (August 2020).* "Zero Trust
Architecture." Defines the core Zero Trust tenets, the logical
components (Policy Engine / Policy Administrator / Policy Enforcement
Point), and the trust algorithms underlying Zero Trust deployments.
Foundational publication invoked by OMB M-22-09 + ZTMM v2.0.
Implemented by LOOP-X.
https://csrc.nist.gov/pubs/sp/800/207/final

**NIST SP 800-207A** — *NIST SP 800-207A (September 2023).* "A Zero
Trust Architecture Model for Access Control in Cloud-Native
Applications in Multi-Location Environments." Extends 800-207 to the
cloud-native + multi-cluster service-mesh case: per-service identity,
service-to-service authorization, network/identity layered enforcement.
Drives LOOP-X.X2 service-mesh evidence collection.
https://csrc.nist.gov/pubs/sp/800/207/a/final

**NIST SP 800-171 Rev 3** — *NIST SP 800-171 Revision 3 (May 2024).*
Protecting CUI in Nonfederal Systems and Organizations. The 110-control
set DoD-prime contractors must satisfy under DFARS 252.204-7012.
LOOP-S.S1 emits the Rev 3 → FedRAMP Moderate (800-53B) crosswalk that
underpins the cloud-equivalency claim.
https://csrc.nist.gov/pubs/sp/800/171/r3/final

**NIST IR 8547 (Transition to Post-Quantum Cryptography Standards)** —
*NIST internal report (initial public draft November 2024).*
Establishes the federal PQC migration timeline + algorithm-deprecation
schedule + per-algorithm guidance for inventorying + replacing
classical primitives with ML-KEM / ML-DSA / SLH-DSA. Primary technical
authority for LOOP-R.
https://csrc.nist.gov/pubs/ir/8547/ipd

**NSM-10 (National Security Memorandum 10)** — *White House NSM-10
(May 2022).* "Promoting US Leadership in Quantum Computing While
Mitigating Risks to Vulnerable Cryptographic Systems." Mandates that
federal agencies inventory cryptographic systems by 2026 and submit
annual PQC migration progress reports. Drives LOOP-R.R1 + R.R3.
https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/

**NIST SP 800-122** — *Guide to Protecting the Confidentiality of PII.*
Drives the PT-family inventory (LOOP-M.M3) + privacy incident response
(LOOP-M.M4).
https://csrc.nist.gov/publications/detail/sp/800-122/final

**NISPOM (32 CFR Part 117)** — *National Industrial Security Program
Operating Manual.* Insider-threat program minimum standards for
cleared contractors. Authority for LOOP-P.P1.
https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-D/part-117

**NIST SP 800-30 Rev 1** — Risk Assessment. Drives B.B1 likelihood +
impact derivation.

**NIST SP 800-37 Rev 2** — Risk Management Framework (RMF). Steps 4 +
7 map onto LOOP-F (assessment) + LOOP-E (ConMon).

**NIST SP 800-53 Rev 5** — Security and Privacy Controls. The control
catalog this codebase implements against.

**NIST SP 800-53A Rev 5** — Assessment Procedures. Drives LOOP-K.K2
test-result-objects + LOOP-F.F3 sample selection.

**NIST SP 800-53B Rev 5** — Baselines. Cached at
`docs/nist-r5-baselines.generated.json`.

**NIST SP 800-60** — Information type categorization. Drives LOOP-C.C5.

**NIST SP 800-137** — ISCM. Drives LOOP-C.C6 + LOOP-E.

**NIST SP 800-160 Vol 1/Vol 2** — Systems Security Engineering. Cited
in ADDITIONAL-LOOPS-AUDIT.md.

**NIST SP 800-161 Rev 1 Update 1** — C-SCRM. Drives LOOP-J.J3.

**NIST SP 800-184** — Cyber Event Recovery. Drives LOOP-N.N2
tabletop facilitation (proposed).

**NIST SP 800-218** — SSDF. Cited in LOOP-N + LOOP-J.J3.

## O

**OOXML (Office Open XML)** — *ECMA-376.* The format used to emit
.docx + .xlsx artifacts. Hand-rolled in `core/roe-emit.ts` +
`core/ssp-docx.ts`; reusable primitive for LOOP-C docs.

**OMB M-03-22** — Privacy provisions of E-Government Act §208. Drives
LOOP-C.C4 PIA + LOOP-M (SORN, DPIA).

**OMB M-17-12** — *OMB.* Preparing for and responding to a breach of
PII. Drives privacy-incident response procedures in LOOP-M.M4.
https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2017/m-17-12_0.pdf

**OFAC SDN List** — *U.S. Department of the Treasury Office of Foreign
Assets Control.* The Specially Designated Nationals and Blocked Persons
List. Adding a vendor or its parent entity to the SDN List is a trigger
for LOOP-T re-evaluation (a sanctioned entity cannot legally be paid).
The SDN list is published as XML / CSV and pulled by LOOP-T.T3 in
addition to the BIS Entity List + SAM.gov Exclusions.
https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists

**OMB M-22-09** — *OMB (January 2022).* "Moving the U.S. Government
Toward Zero Trust Cybersecurity Principles." Operationalizes EO 14028
§3 by directing federal agencies (and their CSPs) to adopt a Zero
Trust architecture aligned to NIST SP 800-207 + CISA ZTMM. Pins
specific identity / device / network / app / data targets and a FY24
implementation deadline. Drives LOOP-X.
https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf

**OMB M-22-18** — *OMB (September 2022).* "Enhancing the Security of the
Software Supply Chain through Secure Software Development Practices."
Operationalises EO 14028 §4 by requiring federal agencies to obtain a
self-attestation, conformant to NIST SP 800-218 SSDF, from any producer
of software the agency uses. LOOP-W emits the self-attestation pack.
https://www.whitehouse.gov/wp-content/uploads/2022/09/M-22-18.pdf

**OMB M-23-16** — *OMB (June 2023).* "Update to Memorandum M-22-18,
Enhancing the Security of the Software Supply Chain through Secure
Software Development Practices." Updates M-22-18 by deferring some
deadlines, specifying the CISA Common Form as the canonical attestation
artifact, and tying submission to CISA's RSAA. LOOP-W defaults to
M-23-16 deadlines.
https://www.whitehouse.gov/wp-content/uploads/2023/06/M-23-16-Update-to-M-22-18-Enhancing-Software-Security.pdf

**OMB M-23-02** — *OMB (November 2022).* "Migrating to Post-Quantum
Cryptography." Operationalises NSM-10 for federal agencies: requires
each agency to compile a cryptographic inventory, assess migration
costs, prioritise High-Value Asset systems, and submit annual progress
reports to OMB through 2035. Drives the LOOP-R.R3 annual PQC report
format.
https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf

**OMB M-24-10** — Advancing AI use cases at federal agencies. Drives
LOOP-O (AI/ML Governance).

**OMB M-25-21** — *OMB (2025).* Successor guidance to M-24-10
implementing EO 14179 ("Removing Barriers to American Leadership in
AI"). Updates pre-deployment + ongoing AI evaluation requirements for
federal use. Drives LOOP-O.O4.

**OPM Position Designation Tool / 5 CFR 731** — *OPM.* The federal
process for assigning a position risk designation (Low / Moderate /
High / Critical-Sensitive) and corresponding background-investigation
tier. Drives LOOP-P.P2 designation matrix.
https://www.opm.gov/suitability/suitability-executive-agent/policy/

**OSCAL (Open Security Controls Assessment Language)** — *NIST.*
JSON/XML/YAML representation of security artifacts. v1.1.2 used here.
https://pages.nist.gov/OSCAL/

**OSCAL AR / AP / POA&M / SSP / Component Definition / Catalog /
Profile** — The seven OSCAL models. AR + AP + POA&M + SSP are emitted by
LOOP-A; Component Definition proposed in LOOP-L.L2.

**out/** — *Internal output directory.* Every artifact lands here per
run. LOOP-H.H1 archives the directory tree per run.

## P

**PA-id (Provisional Authorization ID)** — *FedRAMP PMO assigned.*
Per-CSO unique identifier. Inherited-authorization PA-ids needed for
LOOP-L.L2.

**PDP / PEP / PA (Policy Decision Point / Policy Enforcement Point /
Policy Administrator)** — *NIST SP 800-207 §3.* The three logical
components of a Zero Trust Architecture per 800-207: the **Policy
Decision Point (PDP)** is the brain that evaluates trust and renders an
allow/deny decision (decomposed in 800-207 into the Policy Engine + the
Policy Administrator); the **Policy Enforcement Point (PEP)** is the
component (e.g. service-mesh proxy, application gateway, identity-aware
proxy) that actually enforces the decision in the data path; the
**Policy Administrator (PA)** sub-component conveys decisions to PEPs +
manages session lifecycle. LOOP-X.X3 inventories PDP/PEP/PA placement
across the CSO boundary.

**Policy Decision Point / Policy Enforcement Point** — See **PDP / PEP /
PA** entry above.

**PAIN / IRV / LEV (deadline tiers)** — *FedRAMP VDR.* Vulnerability
deadline classes consumed by LOOP-B.B2.

**PASTA (Process for Attack Simulation and Threat Analysis)** —
*Industry.* 7-stage risk-centric threat-modeling methodology. Drives
the LOOP-N.N3 red-team adversarial test framework.

**Post-ATO ConMon** — *FedRAMP.* Monthly evidence + POA&M delta
delivery to the FedRAMP secure repository after ATO is issued.
Implemented by LOOP-Q.Q2; ConMon strategy in LOOP-C.C6 + LOOP-E.

**Post-Quantum Cryptography (PQC)** — *NIST / industry.* Cryptographic
primitives believed to remain secure against attacks executed on a
cryptographically-relevant quantum computer. NIST standardised the
first PQC primitives in FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and
FIPS 205 (SLH-DSA), all published August 2024. The federal PQC
migration is mandated by NSM-10 + OMB M-23-02 + NIST IR 8547 + NSA
CNSA 2.0. Implemented by LOOP-R.

**PPD-21 (Presidential Policy Directive 21)** — *White House (February
2013).* "Critical Infrastructure Security and Resilience." Establishes
the 16 critical-infrastructure sectors that determine CIRCIA Covered
Entity scope: Chemical, Commercial Facilities, Communications,
Critical Manufacturing, Dams, Defense Industrial Base, Emergency
Services, Energy, Financial Services, Food and Agriculture, Government
Facilities, Healthcare and Public Health, Information Technology,
Nuclear, Transportation Systems, Water and Wastewater. LOOP-G.G2.CIRCIA
+ LOOP-M.M4.CIRCIA scope CSP applicability against this list.
https://obamawhitehouse.archives.gov/the-press-office/2013/02/12/presidential-policy-directive-critical-infrastructure-security-and-resil

**Practice Group (PO / PS / PW / RV per SP 800-218)** — *NIST SP
800-218.* The four top-level groups SSDF uses to organize Practices:
**PO** Prepare the Organization (policies, training, infra), **PS**
Protect the Software (source / artifact integrity, provenance), **PW**
Produce Well-Secured Software (design, secure coding, review, test),
**RV** Respond to Vulnerabilities (intake, analysis, remediation). The
CISA Common Form lines up its declarations against PO / PS / PW / RV;
LOOP-W groups its emitted attestations the same way.

**Privacy Act §552a** — *5 U.S.C. §552a (Privacy Act of 1974).* Sets
SORN publication + Records-Management obligations for any federal
"system of records." Authority for LOOP-M.M1.

**Phase Two pilot** — *FedRAMP 20x.* The currently-active 20x Moderate
pilot. Output bundle format pinned in LOOP-A.A4 as
`20x.phase-two.preview.2026`.

**PIA (Privacy Impact Assessment)** — *OMB M-03-22.* Emitted by
LOOP-C.C4 when PII tags detected.

**PHI (Protected Health Information)** — *HIPAA / 45 CFR §160.103.*
Individually identifiable health information transmitted or maintained
in any form by a Covered Entity or Business Associate, excluding
employment records and education records covered by FERPA. ePHI =
electronic PHI subject to the Security Rule (Subpart C). Inventoried by
LOOP-V.V1 via `data_classification=phi` tag (extension to the existing
classification enum).

**PII (Personally Identifiable Information)** — *Standard.* Tagged on
assets via `data_classification=pii`. Drives PIA emit + criticality.

**PII Processor (ISO 27018)** — *ISO/IEC 27018:2019 + 27701:2019.* The
ISO term for an entity that processes PII on behalf of (and under the
instructions of) a PII Controller — directly equivalent to the GDPR
"processor" role. ISO 27018 Annex A enumerates 25+ processor-specific
controls. A CSP processing customer PII data is a PII Processor +
inherits Annex A obligations. LOOP-Z.Z2 emits the PII Processor
assertion.

**PIMS (Privacy Information Management System)** — *ISO/IEC 27701:2019.*
The ISO term for a Privacy Information Management System built as an
extension of an ISO 27001 ISMS. Has separate clauses for PII
Controllers + PII Processors, each cross-mapped to GDPR articles.
LOOP-Z.Z2 emits the PIMS evidence pack alongside the ISO 27001 ISMS
pack.

**PM-9 (Risk Management Strategy)** — *NIST SP 800-53 Rev 5 control.*
Drives LOOP-C.C7.

**PM-10 (Authorization Process)** — *NIST SP 800-53 Rev 5 control.*
Drives LOOP-F.F6.

**PM-12 (Insider Threat Program)** — *NIST SP 800-53 Rev 5 control.*
Drives LOOP-P.P1. Authority extends from EO 13587 + 32 CFR Part 117
(NISPOM).

**PM-15 / PM-16 (Threat Intelligence)** — *NIST SP 800-53 Rev 5
controls.* Drive proposed §3.9 threat-intel ingest.

**PM-31 (Continuous Monitoring)** — *NIST SP 800-53 Rev 5 control.*
Drives proposed LOOP-M.M2 PCM strategy.

**POA&M (Plan of Action and Milestones)** — *NIST CA-5 / FedRAMP.* The
findings + remediation deadlines doc. Emitted by LOOP-A.A1; updated
monthly by LOOP-E.E2.

**Provenance** — *Internal.* Per-emit `provenance: { emitter, emittedAt,
sourceCalls[], signingKeyId, runId, requirementTexts? }` block. REO
Rule 1.7 + G3 guardrail.

**PS-family (PS-1 through PS-9)** — *NIST SP 800-53 Rev 5 controls.*
The full Personnel Security family: PS-1 Policy/Procedures, PS-2
Position Risk Designation, PS-3 Screening, PS-4 Termination, PS-5
Transfer, PS-6 Access Agreements, PS-7 External Personnel, PS-8
Sanctions, PS-9 Position Descriptions. Drives LOOP-P.P1..P.P5.

**PT-family (PT-1 through PT-8)** — *NIST SP 800-53 Rev 5 controls.*
The Personally Identifiable Information Processing and Transparency
family: PT-1 Policy/Procedures, PT-2 Authority for Processing, PT-3
PII Purpose Specification, PT-4 Consent, PT-5 Privacy Notice, PT-6
SORN, PT-7 Specific Categories of PII, PT-8 Computer Matching
Requirements. Inventoried by LOOP-M.M3; PT-7 + breach-notification
implemented by LOOP-M.M4.

**PTA (Privacy Threshold Analysis)** — *FedRAMP / OMB M-03-22.*
Emitted by LOOP-C.C4.

## Q

(no terms)

## R

**R1, R2, R3, R4** — *Internal pre-loop research.* Already shipped.
- R1: AFR family classification.
- R2: Monthly POA&M delta research.
- R3: Phase Two pilot output format.
- R4: Sample selection methodology.

**RA-3 (Risk Assessment)** — *NIST SP 800-53 Rev 5 control.* The
risk register Central Risk Register deliverable. LOOP-B.B5.

**RA-5 (Vulnerability Monitoring)** — *NIST SP 800-53 Rev 5 control.*
Underlies the VDR pipeline + BOD 23-01 cadence.

**RBAC (Role-Based Access Control)** — *Standard.* Tracker UI roles +
domain assignments shipped in Phase D.4.

**Ransom Payment Report** — *CIRCIA / 6 USC §681b(a)(2).* A separate
mandatory report (in addition to the Covered Cyber Incident report)
that a Covered Entity must submit to CISA within 24 hours of making a
ransom payment. Distinct schema + faster deadline than the 72-hour
Covered Cyber Incident report. Emitted by LOOP-G.G2.CIRCIA when the
operator records a ransom payment in the tracker.

**Repository for Software Attestations and Artifacts (RSAA)** —
*CISA.* The CISA-hosted federal repository where software producers
submit signed CISA Common Form Self-Attestations + supporting
artifacts per OMB M-22-18 / M-23-16. LOOP-W.W4 emits the signed
submission envelope (attestation form + provenance + Ed25519 signature)
in the RSAA-required schema.
https://www.cisa.gov/resources-tools/services/repository-software-attestations-and-artifacts-rsaa

**Read-only guardrail** — *Internal.* `core/readonly-guardrail-*.ts`
wraps cloud SDKs; throws on any non-read API call.

**REO (Real-Evidence-Only)** — *Internal standard.* Defined in
`cloud-evidence/CLAUDE.md`. Forbids placeholder data + mocked SDKs in
production. Enforced by G1+G2+G3.

**REO-0** — *Internal.* The pre-flight slice that shipped the REO
rule + CI guardrails.

**REQUIRES-OPERATOR-INPUT** — *Internal marker.* Per REO Rule 4, the
literal string emitted whenever a field needs human input. Never
silently defaulted.

**RFC 3161** — *IETF Trusted Timestamping.* Used by `core/sign.ts` to
seal the manifest with a real TSA timestamp. REO Rule 1.6.

**RFC 9116** — *IETF security.txt.* Proposed deliverable in §3.2 VDP
policy doc.

**RFC-0004** — *FedRAMP RFC.* Boundary Policy.

**RFC-0006** — *FedRAMP RFC.* AFR catalog. Drives the AFR-FSI scope.

**RFC-0014** — *FedRAMP RFC.* Phase-Two automated/opinionated KSI
validation. The basis of REO + REO-0.

**RFC-0021** — *FedRAMP RFC.* Marketplace expansion. Drives proposed
LOOP-Q.

**RFC-0024** — *FedRAMP RFC.* OSCAL submission mandate.

**Risk score** — *Internal LOOP-B.B1 output.* Composite score combining
CVSS + EPSS + criticality + exposure. Formula version
`risk-score.v1`.

**RMS (Risk Management Strategy)** — *FedRAMP template / NIST PM-9.*
Emitted by LOOP-C.C7.

**RoE (Rules of Engagement)** — *FedRAMP template.* The assessment
RoE doc. Emitted by LOOP-A.A5. Distinct from PenTest RoE (§3.10
proposal).

**RPL collectors** — *Internal.* RPL-ABO / RPL-TRC / RPL-RRO /
RPL-ARP. Existing backup-recovery-plan KSI collectors.

## S

**SA-9 (External System Services)** — *NIST SP 800-53 Rev 5 control.*
Subprocessor inventory + risk-tier classification. LOOP-J.J2.

**Schrems II (CJEU C-311/18)** — *Court of Justice of the European Union
judgment in Data Protection Commissioner v. Facebook Ireland and
Maximillian Schrems (July 16, 2020).* The CJEU decision that
invalidated the EU-US Privacy Shield and tightened the conditions
under which EU→US personal-data transfers may proceed under Standard
Contractual Clauses, requiring a Transfer Impact Assessment + likely
supplementary measures. Drives LOOP-Z.Z3 TIA workflow for EU customer
data transfers.
https://curia.europa.eu/juris/document/document.jsf?docid=228677

**SAM.gov Exclusions** — *GSA / IAE (Integrated Award Environment).*
The federal exclusions list published in SAM.gov enumerating entities
debarred, suspended, proposed for debarment, or otherwise excluded from
receiving federal contracts or assistance. LOOP-T.T3 pulls the SAM.gov
Exclusions feed in parallel with the BIS Entity List + OFAC SDN list
to compute a single supply-chain-eligibility verdict per subprocessor.
https://sam.gov/content/exclusions

**SA-11 (Developer Testing)** — *NIST SP 800-53 Rev 5 control.* SSDF
attestation cross-link.

**SAR (Security Assessment Report)** — *FedRAMP / NIST.* The 3PAO-
authored summary of the assessment. Draft generated by LOOP-F.F7.

**SAP (Security Assessment Plan)** — *FedRAMP / NIST.* The 3PAO's plan
for testing. Emitted by LOOP-A.A2 (as OSCAL AP).

**SBOM (Software Bill of Materials)** — *NIST 800-218.* Generated by
Syft; verified by cosign. Drives LOOP-J.J3.

**SC-7 (Boundary Protection)** — *NIST SP 800-53 Rev 5 control.*
Drives proposed §3.7 boundary flow-log ingestion.

**SCN (Significant Change Notification)** — *FedRAMP CMP.* Classifier
+ doc emitter. SCN classifier exists; SCN doc emitter is LOOP-E.E6.

**SCSEM (Safeguard Computer Security Evaluation Matrix)** — *IRS Office
of Safeguards.* The IRS-published technical-test checklists used to
verify FTI-handling agencies' compliance with IRS Publication 1075.
Per-platform SCSEMs exist (Windows, Linux, Oracle DB, AWS, Azure, etc.).
LOOP-Y.Y2 emits the populated SCSEM workbook + delta against IRS-
published reference.
https://www.irs.gov/privacy-disclosure/safeguards-program

**SCC (Standard Contractual Clauses, EU SCCs 2021/914)** — *European
Commission Decision (EU) 2021/914 (June 4, 2021).* The European
Commission–approved standard contractual clauses governing transfers
of personal data from the EU/EEA to third countries that lack an
adequacy decision. Four modules (controller-controller,
controller-processor, processor-processor, processor-controller).
LOOP-Z.Z3 includes the SCC module-selector + Transfer Impact
Assessment workflow.
https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en

**Standard Contractual Clauses (EU SCCs 2021/914)** — See **SCC** entry
above.

**SEC Final Rule 33-11216** — *U.S. Securities and Exchange Commission
(July 26, 2023).* "Cybersecurity Risk Management, Strategy, Governance,
and Incident Disclosure." Adds Form 8-K Item 1.05 (incident disclosure
within 4 business days of materiality determination) and Regulation
S-K Item 106 (annual cyber-risk-management governance disclosure in
Form 10-K). Root authority for the LOOP-W / G.G2-SEC-8K-EXTENSION
disclosure flow.
https://www.sec.gov/files/rules/final/2023/33-11216.pdf

**Section 889 Part A vs Part B** — See **FAR 52.204-25 (Part A vs
Part B)** under F.

**Self-Attestation (vs Engineering Attestation)** — *OMB M-22-18 /
M-23-16.* A self-attestation is a statement signed by the producer's
CEO (or designated equivalent) declaring conformance to the SSDF
practices. An engineering attestation, by contrast, is a 3PAO-signed
audit-style attestation that conformance has been independently
verified. M-23-16 deferred mandatory engineering attestation; the
default for LOOP-W is a self-attestation signed via the tracker.

**Smaller Reporting Company (SEC)** — *17 CFR §240.12b-2.* An SEC-
registered company with public float under $250M or annual revenues
under $100M. Under SEC Final Rule 33-11216, Smaller Reporting
Companies got a 180-day deferral on Form 8-K Item 1.05 compliance.
LOOP-W tracks this status because it changes the cutover date.
https://www.ecfr.gov/current/title-17/chapter-II/part-240/subpart-A/subject-group-ECFRefffd57b6ca5b6/section-240.12b-2

**security.txt** — *IETF RFC 9116.* The public-facing VDP file
proposed in §3.2.

**Severity** — *Internal enum.* Critical / High / Medium / Low / Info.
LOOP-A.A1 maps to deadlines per FedRAMP baseline (30/60/90/180 days);
LOOP-B.B2 supersedes with KEV/PAIN/IRV/LEV math.

**Signed manifest** — See "Manifest".

**SLICE-COMPLETION-PROCEDURE.md** — *Internal.* The mandatory 7-step
procedure executed atomically with every slice's final commit.

**SoA (Statement of Applicability)** — *ISO/IEC 27001:2022 §6.1.3 d).*
The mandatory ISMS document declaring which Annex A controls apply to
the in-scope ISMS, the implementation status of each applicable
control, and the justification for excluding any non-applicable
controls. Audited at every ISO 27001 surveillance + recertification
audit. Emitted by LOOP-Z.Z1.

**Safety-Impacting AI** — *OMB M-24-10.* AI categorized as
having the potential to directly affect the physical safety of
individuals. Triggers enhanced pre-deployment + ongoing evaluation
under LOOP-O.O4 and risk-register escalation in LOOP-O.O3.

**Shared Control** — *FedRAMP / SSP Appendix J.* CRM responsibility
bucket where both the CSP and the customer must perform overlapping
parts of the same control. Distinct from Hybrid. One of six buckets
enumerated by LOOP-L.L1.

**SORN (System of Records Notice)** — *Privacy Act of 1974 §552a.*
Required Federal Register notice for any federal system of records.
Emitted by LOOP-M.M1. Aligns with PT-6.

**Rights-Impacting AI** — *OMB M-24-10.* AI categorized as
having a meaningful effect on access to government benefits,
employment, healthcare, housing, or other legal rights. Triggers
enhanced pre-deployment + ongoing evaluation under LOOP-O.O4.

**SR-3 (Supply Chain Controls)** — *NIST SP 800-53 Rev 5 control.*
Drives LOOP-J.J3.

**SSP (System Security Plan)** — *FedRAMP / NIST.* The authoritative
plan describing how the CSO implements controls. OSCAL emitter
already shipped (SSP-1); .docx renderer shipped (SSP-2).

**SSP Appendix J** — *FedRAMP.* The CIS/CRM workbook documenting
per-control responsibility allocation (CSP-Implemented, Customer-
Implemented, Shared, Hybrid, Inherited, N/A). Implemented by LOOP-L.L1.

**SSP Appendix M** — *FedRAMP.* Diagrams (Authorization Boundary +
Network + Data Flow). LOOP-D.

**SSP Appendix Q** — *FedRAMP.* Cryptographic Modules Table. Proposed
LOOP-C.C10.

**SSR (IRS Safeguard Security Report)** — *IRS Publication 1075.* The
annual report each FTI-receiving agency must file with the IRS Office
of Safeguards documenting the state of FTI safeguards: organizational
changes, system inventory, SCSEM results, POA&M, training records, and
incident summary. LOOP-Y.Y2 emits the populated SSR template alongside
the SCSEM evidence pack.

**CSO (CJIS Systems Officer)** — *FBI CJIS Security Policy §3.2.2.* The
designated official within a CJIS Systems Agency (or service provider)
responsible for the administration of the CJIS network and the
agency's compliance with the CJIS Security Policy. Distinct from
"CSO" = Cloud Service Offering. LOOP-Y disambiguates with the term
"CJIS Systems Officer" in artifact narratives.

**SSDF (Secure Software Development Framework)** — *NIST SP 800-218.*

**SSDF Practice** — *NIST SP 800-218.* A Practice is the second-level
unit under a Practice Group: a named, scoped behavior the producer
performs (e.g. PO.1.1 "Identify and document all security requirements
for the organization's software development infrastructure and
processes"). 800-218 lists 19 Practices across PO / PS / PW / RV.
LOOP-W maps each Common Form declaration to a specific Practice.

**SSDF Task** — *NIST SP 800-218.* A Task is the third-level unit
under an SSDF Practice: a concrete action the producer performs to
satisfy the Practice. 800-218 enumerates approximately 50 Tasks. The
CISA Common Form lets the producer attest at the Practice level; the
LOOP-W evidence pack drills down to Task-level evidence for higher-
confidence (engineering-attestation-ready) submissions.

**STIX** — *OASIS.* Structured Threat Information eXpression. CISA AIS
emits STIX.

**STRIDE** — *Microsoft.* Per-component threat-modeling taxonomy:
**S**poofing, **T**ampering, **R**epudiation, **I**nformation
disclosure, **D**enial of service, **E**levation of privilege.
Implemented by LOOP-N.N1 (generated from inventory + DFD).

## T

**Tag (cloud-resource)** — *Operator input mechanism.* Tags like
`fedramp_boundary`, `fedramp_data_classification`,
`fedramp_asset_tier` flow operator decisions to evidence. REO Rule 4.

**TSC Industries v. Northway, 426 U.S. 438 (1976)** — *U.S. Supreme
Court.* The case that pinned the federal securities-law materiality
standard: information is material when there is a substantial
likelihood that a reasonable investor would consider it important.
Adopted by the SEC in Final Rule 33-11216 as the cybersecurity-incident
materiality threshold. See Materiality entry under M.
https://supreme.justia.com/cases/federal/us/426/438/

**Tracker** — *Internal.* The local React + SQLite app under
`cloud-evidence/tracker/`. Captures operator + 3PAO + AO actions with
signed audit log.

**Transfer Impact Assessment (TIA)** — *EDPB Recommendations 01/2020 +
Schrems II.* The case-by-case assessment a data exporter must perform
before transferring personal data to a third country under SCCs:
evaluate the third-country law + practices for adequacy, identify gaps
relative to EU standards, and define supplementary measures (technical:
e.g. encryption with EU-held keys; contractual; organizational). LOOP-Z.Z3
emits the TIA workbook + supplementary-measures register.
https://www.edpb.europa.eu/our-work-tools/our-documents/recommendations/recommendations-012020-measures-supplement-transfer_en

**Trust Center** — *AFR-ADS.* Public-facing CSP publication of
authorization status + service list. LOOP-G.G3.

**TSA (Time Stamp Authority)** — *RFC 3161.* DigiCert / GlobalSign /
Sectigo / FreeTSA. Single-TSA today; multi-TSA failover proposed in
§3.12.

## U

**Unreleased** — See "CHANGELOG.md Unreleased".

**Use-case identifier (OMB M-24-10)** — *OMB.* Agency-assigned ID for
each AI use case. Proposed LOOP-O.O1.

## V

**VDR (Vulnerability Disclosure + Response)** — See "AFR-VDR".

**VDP (Vulnerability Disclosure Policy)** — *CISA BOD 20-01.* Proposed
§3.2 deliverable (G.G7).

**VDR-scan collector** — *Internal.* Existing scan-reconcile collector.

## W

**WELL_KNOWN (catalogue)** — *Internal `core/submission-bundle.ts`
constant.* Enumerates every well-known artifact role + filename for
the LOOP-A.A4 bundler. Every emitter that produces a submission-
package file MUST add a WELL_KNOWN row.

**Wholly-Owned Subsidiary (SEC disclosure)** — *SEC.* For SEC Form 8-K
Item 1.05, a wholly-owned subsidiary of an SEC-registered parent does
NOT file its own 8-K — the parent registrant files on behalf of the
subsidiary if the incident is material at the consolidated level. A
CSP that is a wholly-owned subsidiary of a public-company parent must
therefore route incident notifications upstream so the parent can make
the materiality determination + meet the 4-business-day clock. LOOP-W
encodes this routing as an operator-config field.

## X

(no terms)

## Y

(no terms)

## Z

**Zero Trust Pillar** — *CISA ZTMM v2.0.* The five top-level Zero
Trust capability areas defined by the CISA Zero Trust Maturity Model
v2.0: **Identity**, **Devices**, **Networks**, **Applications &
Workloads**, **Data**, supported by 3 cross-cutting capabilities
(Visibility & Analytics, Automation & Orchestration, Governance).
LOOP-X.X4 emits per-pillar maturity assessments + per-capability target
states.

**ZTMM v2.0 (Zero Trust Maturity Model v2.0)** — *CISA (April 2023).*
The CISA-published maturity model defining four maturity stages
(Traditional, Initial, Advanced, Optimal) for each of the five Zero
Trust Pillars + three cross-cutting capabilities. The federal companion
to NIST SP 800-207 and OMB M-22-09. Drives LOOP-X.X4 maturity
assessment + roadmap.
https://www.cisa.gov/zero-trust-maturity-model

**Zip (OOXML container)** — *ECMA-376.* `core/zip.ts` is the cross-
emitter primitive for .docx and .xlsx OOXML containers.

---

## Sources cited above (canonical URLs)

- FedRAMP Marketplace — https://marketplace.fedramp.gov/
- FedRAMP RFCs — https://www.fedramp.gov/rfcs/
- FedRAMP Rev5 Playbook — https://www.fedramp.gov/docs/rev5/playbook/
- FedRAMP PenTest Guidance v3.0 — https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf
- CISA BOD 20-01 — https://www.cisa.gov/news-events/directives/bod-20-01-develop-and-publish-vulnerability-disclosure-policy
- CISA BOD 22-01 (KEV) — https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01
- CISA BOD 23-01 — https://www.cisa.gov/news-events/directives/bod-23-01-improving-asset-visibility-vulnerability-detection
- CISA KEV Catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NIST SP 800-53 Rev5 — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- NIST SP 800-53B Rev5 — https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final
- NIST SP 800-30 Rev 1 — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf
- NIST SP 800-37 Rev 2 — https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final
- NIST SP 800-60 Vol 1+2 — https://csrc.nist.gov/publications/detail/sp/800-60/vol-1-rev-1/final
- NIST SP 800-137 — https://csrc.nist.gov/publications/detail/sp/800-137/final
- NIST SP 800-160 Vol 1/Vol 2 — https://csrc.nist.gov/publications/detail/sp/800-160/vol-1/final
- NIST SP 800-161 Rev1 Update 1 — https://csrc.nist.gov/publications/detail/sp/800-161/r1-upd1/final
- NIST SP 800-184 — https://csrc.nist.gov/publications/detail/sp/800-184/final
- NIST SP 800-218 SSDF — https://csrc.nist.gov/publications/detail/sp/800-218/final
- NIST CSF v2.0 — https://www.nist.gov/cyberframework
- NIST AI RMF 1.0 — https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf
- NIST AI 600-1 GenAI Profile — https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.600-1.pdf
- NIST SP 800-122 (PII protection) — https://csrc.nist.gov/publications/detail/sp/800-122/final
- MITRE ATT&CK — https://attack.mitre.org/
- MITRE ATT&CK Cloud Matrix — https://attack.mitre.org/matrices/enterprise/cloud/
- EO 13587 (Insider Threat) — https://www.federalregister.gov/documents/2011/10/13/2011-26729/
- EO 14110 (AI) — https://www.federalregister.gov/documents/2023/11/01/2023-24283/
- OMB M-17-12 (PII breach) — https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2017/m-17-12_0.pdf
- OPM Position Designation (5 CFR 731) — https://www.opm.gov/suitability/suitability-executive-agent/policy/
- NIST CMVP / FIPS 140-3 — https://csrc.nist.gov/projects/cryptographic-module-validation-program
- OSCAL v1.1.2 — https://pages.nist.gov/OSCAL/learn/
- OSCAL Releases — https://github.com/usnistgov/OSCAL/releases/tag/v1.1.2
- OMB M-03-22 (PIA) — https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2003/m03_22.pdf
- OMB M-24-10 (AI) — https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf
- FIRST CVSS v3.1 — https://www.first.org/cvss/v3.1/specification-document
- FIRST CVSS v4.0 — https://www.first.org/cvss/v4.0/specification-document
- FIRST EPSS — https://www.first.org/epss/
- FRMR catalog (machine-readable) — https://github.com/FedRAMP/docs
- 32 CFR Part 117 (NISPOM) — https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-D/part-117
- Privacy Act of 1974 — 5 U.S.C. §552a
- IETF RFC 3161 (TSA) — https://www.rfc-editor.org/rfc/rfc3161
- IETF RFC 5321 (SMTP) — https://datatracker.ietf.org/doc/html/rfc5321
- IETF RFC 6376 (DKIM) — https://datatracker.ietf.org/doc/html/rfc6376
- IETF RFC 9116 (security.txt) — https://www.rfc-editor.org/rfc/rfc9116
- NIST FIPS 203 (ML-KEM) — https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 (ML-DSA) — https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205 (SLH-DSA) — https://csrc.nist.gov/pubs/fips/205/final
- NIST SP 800-171 Rev 3 — https://csrc.nist.gov/pubs/sp/800/171/r3/final
- NIST IR 8547 — https://csrc.nist.gov/pubs/ir/8547/ipd
- NSM-10 — https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/
- OMB M-23-02 — https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf
- NSA CNSA 2.0 — https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
- DFARS 252.204-7012 — https://www.acq.osd.mil/dpap/dars/dfars/html/current/252204.htm#252.204-7012
- DoD Cloud Computing SRG — https://public.cyber.mil/dccs/dccs-documents/
- CIRCIA (6 USC §681b) — https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/cyber-incident-reporting-critical-infrastructure-act-2022-circia
- PPD-21 — https://obamawhitehouse.archives.gov/the-press-office/2013/02/12/presidential-policy-directive-critical-infrastructure-security-and-resil
- SEC Final Rule 33-11216 (Cyber Disclosure) — https://www.sec.gov/files/rules/final/2023/33-11216.pdf
- SEC EDGAR Filer Information — https://www.sec.gov/edgar/filer-information
- SEC Inline XBRL — https://www.sec.gov/structureddata/osd-inline-xbrl.html
- TSC Industries v. Northway, 426 U.S. 438 (1976) — https://supreme.justia.com/cases/federal/us/426/438/
- 17 CFR §240.12b-2 (Smaller Reporting Company definition) — https://www.ecfr.gov/current/title-17/chapter-II/part-240/subpart-A/subject-group-ECFRefffd57b6ca5b6/section-240.12b-2
- EO 14028 (Software Supply Chain) — https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity
- OMB M-22-18 — https://www.whitehouse.gov/wp-content/uploads/2022/09/M-22-18.pdf
- OMB M-23-16 — https://www.whitehouse.gov/wp-content/uploads/2023/06/M-23-16-Update-to-M-22-18-Enhancing-Software-Security.pdf
- NIST SP 800-218 SSDF v1.1 — https://csrc.nist.gov/publications/detail/sp/800-218/final
- NIST SP 800-218A SSDF-AI IPD — https://csrc.nist.gov/pubs/sp/800/218/a/ipd
- CISA SSDF Common Form (OMB 1670-0052) — https://www.cisa.gov/resources-tools/services/secure-software-development-attestation-form
- CISA RSAA — https://www.cisa.gov/resources-tools/services/repository-software-attestations-and-artifacts-rsaa
- NDAA §889 (Pub. L. 115-232) — https://www.congress.gov/115/plaws/publ232/PLAW-115publ232.pdf
- NDAA §1634 (Pub. L. 115-91) — https://www.congress.gov/115/plaws/publ91/PLAW-115publ91.pdf
- FAR 4.2102 — https://www.acquisition.gov/far/subpart-4.21
- FAR 52.204-25 — https://www.acquisition.gov/far/52.204-25
- FAR 52.204-26 — https://www.acquisition.gov/far/52.204-26
- DHS Section 889 Implementation Guidance — https://www.dhs.gov/sites/default/files/publications/section-889-implementation-guidance.pdf
- BIS Entity List — https://www.bis.doc.gov/index.php/policy-guidance/lists-of-parties-of-concern/entity-list
- OFAC SDN List — https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists
- SAM.gov Exclusions — https://sam.gov/content/exclusions
- 45 CFR §164 Subpart C (HIPAA Security Rule) — https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C
- 45 CFR §164 Subpart D (HIPAA Breach Notification Rule) — https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D
- HIPAA BAA Sample — https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html
- 21st Century Cures Act Information Blocking — https://www.healthit.gov/topic/information-blocking
- NIST SP 800-66 Rev 2 — https://csrc.nist.gov/pubs/sp/800/66/r2/final
- HITRUST CSF — https://hitrustalliance.net/product-tool/hitrust-csf/
- NIST SP 800-207 (Zero Trust) — https://csrc.nist.gov/pubs/sp/800/207/final
- NIST SP 800-207A — https://csrc.nist.gov/pubs/sp/800/207/a/final
- OMB M-22-09 (Zero Trust) — https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf
- CISA ZTMM v2.0 — https://www.cisa.gov/zero-trust-maturity-model
- NIST OLIR — https://csrc.nist.gov/projects/olir
- CCPA/CPRA (CPPA Regulations) — https://cppa.ca.gov/regulations/
- COPPA (FTC Rule) — https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa
- FERPA (DoE) — https://www2.ed.gov/policy/gen/guid/fpco/ferpa/index.html
- GLBA Safeguards Rule (FTC) — https://www.ftc.gov/legal-library/browse/rules/safeguards-rule
- GDPR Article 33 — https://gdpr-info.eu/art-33-gdpr/
- FBI CJIS Security Policy — https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center
- IRS Publication 1075 — https://www.irs.gov/pub/irs-pdf/p1075.pdf
- IRS Safeguards Program (SCSEM) — https://www.irs.gov/privacy-disclosure/safeguards-program
- ISO/IEC 27001:2022 — https://www.iso.org/standard/27001
- ISO/IEC 27017:2015 — https://www.iso.org/standard/43757.html
- ISO/IEC 27018:2019 — https://www.iso.org/standard/76559.html
- ISO/IEC 27701:2019 — https://www.iso.org/standard/71670.html
- ENISA EUCS — https://www.enisa.europa.eu/publications/eucs-cloud-service-scheme
- EU Standard Contractual Clauses (2021/914) — https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en
- Schrems II (CJEU C-311/18) — https://curia.europa.eu/juris/document/document.jsf?docid=228677
- EDPB Recommendations 01/2020 (TIA) — https://www.edpb.europa.eu/our-work-tools/our-documents/recommendations/recommendations-012020-measures-supplement-transfer_en
