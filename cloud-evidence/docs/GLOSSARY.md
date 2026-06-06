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
> 90+ terms. Indexed alphabetically. If you add a term during slice
> implementation, add it here too — the per-slice docs presume the
> glossary is current.

---

## A

**3PAO (Third-Party Assessment Organization)** — *FedRAMP.* An independent
organization accredited by A2LA to perform FedRAMP assessments of CSOs.
The 3PAO produces the SAR + signs the recommendation letter that
accompanies the authorization package.
https://www.fedramp.gov/3pao-requirements/

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

## B

**Baseline (control baseline)** — *NIST SP 800-53B.* The published low /
moderate / high control-set per impact level. FedRAMP Moderate baseline
has ~325 controls + enhancements. Catalog at
`docs/nist-r5-baselines.generated.json`.

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

**CRM (Customer Responsibility Matrix)** — *FedRAMP.* Synonym for
CIS/CRM workbook. Proposed LOOP-L.L1.

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

**Determination statement** — *NIST 800-53A Rev 5.* Sub-objective of
an assessment objective; maps to OSCAL AR `finding.target` in LOOP-K.K2.

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

**EPSS (Exploit Prediction Scoring System)** — *FIRST.org.* Per-CVE
probability of exploitation. Consumed by LOOP-B.B1.
https://www.first.org/epss/

**Envelope** — *Internal.* `core/envelope.ts` defines the canonical
KSI envelope JSON: `{ ksi_id, collected_at, findings[], provenance, ... }`.

**Evidence walk-through artifacts** — *FedRAMP B-side.* Screenshots +
transcripts captured during 3PAO testing. LOOP-F.F4.

## F

**FedRAMP** — *Federal Risk and Authorization Management Program.* The
US-government CSP authorization program.
https://www.fedramp.gov/

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

**FIPS 199** — *NIST.* Federal Information Processing Standard for
categorization. Worksheet emitted by LOOP-C.C5.

**Finding** — *Internal envelope field.* A single
PASS/FAIL/INFO/REQUIRES-OPERATOR-INPUT determination from a collector.
Defined in `core/findings.ts`.

**FRMR** — *FedRAMP Machine-Readable Requirements.* JSON catalog at
`github.com/FedRAMP/docs`. Source of truth for all FedRAMP-specific
requirements. Cached locally as `docs/frmr-requirements.generated.json`.

**FRR (FedRAMP Requirement Reference)** — *FRMR.* The catalog ID for
a single requirement statement (e.g. FRR-FSI-09).

## G

**Guardrail (G1, G2, G3)** — *Internal CI.* G1 = lint:no-stubs;
G2 = check:coverage-regression; G3 = check:provenance. Required checks
in `.github/workflows/ci.yml`.

## H

**HMAC-SHA256** — *Cryptographic primitive.* Used in LOOP-G.G1 webhook
auth + generic-webhook adapter (Phase F.4).

## I

**IAM-AAM (Account Access Management)** — *KSI.* Existing IAM collector
covering AC-2.

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

**IR-8 (Incident Response Plan)** — *NIST SP 800-53 Rev 5 control.*
Drives LOOP-C.C3.

**IRP (Incident Response Plan)** — *FedRAMP template.* The Word doc
emitted by LOOP-C.C3.

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
Assured Workloads, Azure Government). Drives LOOP-L.L2/L.L3 (proposed).

**lint:no-stubs** — *Internal G1 guardrail.* `scripts/lint-no-stubs.mjs`
scans production paths for forbidden tokens (TODO, FIXME, sample,
placeholder, lorem, "coming soon", "not yet implemented", etc.).

**LOOP (LOOP-A through LOOP-Q)** — *Internal roadmap unit.* A
themed collection of slices. LOOP-A..K enumerated; LOOP-L..Q proposed.

## M

**Manifest** — *Internal.* Signed `out/manifest.json` enumerates every
artifact + sha256. Subject of the RFC 3161 timestamp.

**MFA (Multi-Factor Authentication)** — *NIST IA-2.* Existing IAM-MFA
collectors validate MFA presence on privileged accounts.

**Moderate (FedRAMP)** — *Impact level.* The scope target for this
repo. Maps to NIST SP 800-53B Moderate baseline.

## N

**NIST AI RMF 1.0** — *NIST AI 100-1.* Drives LOOP-O (proposed).
https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf

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
LOOP-C.C4 PIA + LOOP-M (proposed).

**OMB M-24-10** — Advancing AI use cases at federal agencies. Drives
LOOP-O (proposed).

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
LOOP-L.L2 (proposed).

**PAIN / IRV / LEV (deadline tiers)** — *FedRAMP VDR.* Vulnerability
deadline classes consumed by LOOP-B.B2.

**Phase Two pilot** — *FedRAMP 20x.* The currently-active 20x Moderate
pilot. Output bundle format pinned in LOOP-A.A4 as
`20x.phase-two.preview.2026`.

**PIA (Privacy Impact Assessment)** — *OMB M-03-22.* Emitted by
LOOP-C.C4 when PII tags detected.

**PII (Personally Identifiable Information)** — *Standard.* Tagged on
assets via `data_classification=pii`. Drives PIA emit + criticality.

**PM-9 (Risk Management Strategy)** — *NIST SP 800-53 Rev 5 control.*
Drives LOOP-C.C7.

**PM-10 (Authorization Process)** — *NIST SP 800-53 Rev 5 control.*
Drives LOOP-F.F6.

**PM-12 (Insider Threat Program)** — *NIST SP 800-53 Rev 5 control.*
Drives proposed LOOP-P.P1.

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

**PS-3 / PS-4 / PS-7 / PS-8 (Personnel Security)** — *NIST SP 800-53
Rev 5 controls.* Drive proposed LOOP-P.P2.

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

**security.txt** — *IETF RFC 9116.* The public-facing VDP file
proposed in §3.2.

**Severity** — *Internal enum.* Critical / High / Medium / Low / Info.
LOOP-A.A1 maps to deadlines per FedRAMP baseline (30/60/90/180 days);
LOOP-B.B2 supersedes with KEV/PAIN/IRV/LEV math.

**Signed manifest** — See "Manifest".

**SLICE-COMPLETION-PROCEDURE.md** — *Internal.* The mandatory 7-step
procedure executed atomically with every slice's final commit.

**SORN (System of Records Notice)** — *Privacy Act of 1974.* Proposed
LOOP-M.M1.

**SR-3 (Supply Chain Controls)** — *NIST SP 800-53 Rev 5 control.*
Drives LOOP-J.J3.

**SSP (System Security Plan)** — *FedRAMP / NIST.* The authoritative
plan describing how the CSO implements controls. OSCAL emitter
already shipped (SSP-1); .docx renderer shipped (SSP-2).

**SSP Appendix J** — *FedRAMP.* The CIS/CRM workbook. Proposed
LOOP-L.L1.

**SSP Appendix M** — *FedRAMP.* Diagrams (Authorization Boundary +
Network + Data Flow). LOOP-D.

**SSP Appendix Q** — *FedRAMP.* Cryptographic Modules Table. Proposed
LOOP-C.C10.

**SSDF (Secure Software Development Framework)** — *NIST SP 800-218.*

**STIX** — *OASIS.* Structured Threat Information eXpression. CISA AIS
emits STIX.

**STRIDE** — *Microsoft.* Threat-modeling taxonomy. Proposed LOOP-N.N1.

## T

**Tag (cloud-resource)** — *Operator input mechanism.* Tags like
`fedramp_boundary`, `fedramp_data_classification`,
`fedramp_asset_tier` flow operator decisions to evidence. REO Rule 4.

**Tracker** — *Internal.* The local React + SQLite app under
`cloud-evidence/tracker/`. Captures operator + 3PAO + AO actions with
signed audit log.

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

## X

(no terms)

## Y

(no terms)

## Z

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
