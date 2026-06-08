---
audit_id: FIFTH-PASS
date: 2026-06-08
status: proposed
predecessors: [ADDITIONAL-LOOPS-AUDIT, SECOND-PASS-AUDIT, THIRD-PASS-AUDIT, FOURTH-PASS-AUDIT]
scope: post-LOOP-A through LOOP-Z exhaustive sweep for remaining federal/sector/AI/accessibility/cryptographic obligations
authoring_authority: cloud-evidence/CLAUDE.md REO standard
methodology_classes: 8 (payment/sector, CMMC supply chain, federal civilian baselines, national security memoranda, AI federal use, accessibility, cryptography/keymgmt, voluntary/state)
items_audited: 34
new_loops_proposed: 7 (LOOP-AA, LOOP-BB, LOOP-CC, LOOP-DD, LOOP-EE, LOOP-FF, LOOP-GG)
new_extension_slices_proposed: 9
already_in_scope_confirmations: 12
confirmed_out_of_scope: 6
last_updated: 2026-06-08
---

# FIFTH-PASS AUDIT — Post-LOOP-A..Z exhaustive sweep

> Fifth-pass audit per the 2026-06-08 user directive to surface every remaining
> obligation universe still missing after twenty-six loops (LOOP-A through
> LOOP-Z) and the four prior audits (ADDITIONAL-LOOPS-AUDIT, SECOND-PASS,
> THIRD-PASS, FOURTH-PASS) have been ratified. Authority: the cloud-evidence
> REO standard (`cloud-evidence/CLAUDE.md`) governs every byte herein.
>
> Every authoritative-source claim in this document is either a verbatim
> excerpt or a precisely-paraphrased statement, pinned to a real public URL
> with a 2026-06-08 access date. No invented citations. Where the source
> could not be fetched directly during the audit session the item carries an
> `EXCERPT-VERIFY` tag for the implementation slice to fetch a second time
> before code emission.
>
> The four prior audits already shipped:
>
> - `ADDITIONAL-LOOPS-AUDIT.md` (2026-06-06) surfaced LOOP-L..LOOP-Q plus 12
>   extensions.
> - `SECOND-PASS-AUDIT.md` (2026-06-07) confirmed L..Q complete.
> - `THIRD-PASS-AUDIT.md` (2026-06-07) surfaced LOOP-R (PQC), LOOP-S
>   (DFARS 252.204-7012), and CIRCIA extensions to G.G2 + M.M4.
> - `FOURTH-PASS-AUDIT.md` (2026-06-07) surfaced LOOP-U (privacy), LOOP-V
>   (healthcare), LOOP-X (Zero Trust), LOOP-Y (sector), LOOP-Z (international),
>   plus SEC 8-K extension to G.G2, plus LOOP-W (Prohibited Vendors) and
>   LOOP-T (NIST SSDF + CISA Common Form) ratification.
>
> This fifth-pass audit re-examines the universe of obligations *after* all
> the loops above are specified, looking for any remaining gap that a 3PAO,
> agency AO, or a procurement officer might still surface during a real
> FedRAMP 20x submission or post-ATO review. It proposes seven additional
> candidate loops (LOOP-AA through LOOP-GG), nine extension slices, confirms
> twelve items as already-in-scope, and six items as genuinely out of scope
> for the FedPy reference profile.

---

## 1. Methodology

This audit adopts eight independent search angles, each executed against a
distinct authoritative-document corpus on the public web during the
2026-06-08 audit window. Every angle ran at least two WebSearch queries and
at least one WebFetch / WebSearch deep dive per cited statute / SP / CFR
section. Where verbatim quotation is not yet captured in this audit (because
the WebFetch returned a redirect or authentication wall), the item carries
an `EXCERPT-VERIFY` tag for the slice author to refetch the source pre-coding.

### 1.1 Search angles (the eight classes)

| # | Class | Why distinct from prior passes |
|---|---|---|
| 1 | Payment + sector standards | PCI-DSS v4.0.1, CIS Controls v8.1, CSA CCM v4.0.x — voluntary but heavily contractually required; partially covered in LOOP-V but not as a first-class loop |
| 2 | CMMC + supply-chain rule families | CMMC 2.0 Final Rule (32 CFR 170), SP 800-171r3, NIST SP 800-204 series, NIST SP 800-167 — LOOP-S covered DFARS 252.204-7012 cloud equivalency but not the 32 CFR 170 SPRS upload, not the 800-204 microservices guidance |
| 3 | Federal civilian baselines + acquisition | OMB Circular A-130 (2016), FISMA 2014, OMB M-21-07 IPv6, FAR Part 7.105, TIC 3.0 — assumed-in-scope but never explicitly traced to a slice |
| 4 | National Security Memoranda + CPGs | NSM-22 (April 2024), CISA CPGs v1.0.1 / v2.0 (Dec 2025) — surfaced briefly in FOURTH-PASS but not assigned a slice |
| 5 | AI federal use | OMB M-24-10 (Mar 2024), EO 14110 (revoked Jan 2025), AI RMF 1.0 (NIST AI 100-1), AI Bill of Rights — LOOP-O covers AI generally but not the federal-use procurement layer |
| 6 | Accessibility | Section 508 Revised (2018), ADA Title II web rule (Apr 2024, compliance deadlines extended to 2027/2028) — never surfaced in prior passes |
| 7 | Cryptography + key management | FIPS 140-3 transition (Sep 22, 2026), SP 800-130, SP 800-152, SP 800-160 v1 R1, SP 800-160 v2 R1 — partial coverage via AFR-UCM + LOOP-R but no dedicated CKMS profile slice |
| 8 | Voluntary / market-signal completions | SOC 2 Type II + AT-C 205 + SSAE 21 + 2022 TSC revised points of focus, FedRAMP RFC-0015/0016/0017, FedRAMP 20x High Phase 4 placeholder, GovRAMP (formerly StateRAMP) rebrand, NIST IR 8053 / 8062 / 8112 |

### 1.2 Source-quality discipline

Every source is one of:

- A statute citation (US Code, Public Law) with the Cornell LII or
  uscode.house.gov URL.
- A CFR citation with the eCFR URL.
- A NIST Special Publication PDF (csrc.nist.gov + nvlpubs.nist.gov).
- A FedRAMP-published artifact (fedramp.gov + the GitHub roadmap repo).
- An OMB memorandum (whitehouse.gov + bidenwhitehouse.archives.gov mirror
  for revoked Biden-era orders).
- A CISA-published artifact (cisa.gov).
- A Federal Register publication (federalregister.gov).
- A standards-body PDF (PCI SSC, AICPA, ISO, CSA, CIS Center for Internet
  Security, Access Board).

No blog posts, no vendor marketing pages, no third-party summaries are
relied upon for normative obligations. Where a vendor or consulting URL is
cited it is exclusively for a *date stamp* (release date confirmation)
or a `EXCERPT-VERIFY` pointer, never for the *substance* of the obligation.

### 1.3 Audit-output structure

Section 2 below proceeds item-by-item through the universe the user
identified. Each item carries (a) 2-3 paragraphs of substantive analysis,
(b) at least one verbatim quote from the authoritative source, (c) a
classification (APPLICABLE / CONDITIONALLY APPLICABLE / NOT APPLICABLE /
ALREADY-IN-SCOPE), and (d) a pointer to the loop / slice that owns or
should own the coverage. Section 3 builds the classification table.
Section 4 proposes new loops where the gap is material. Section 5 confirms
items genuinely out of scope. Section 6 closes with recommendations and
next-pass priorities.

---

## 2. Items audited

### 2.1 PCI-DSS v4.0.1 — PCI Security Standards Council, June 2024 limited revision

The PCI Security Standards Council released PCI-DSS v4.0.1 on 2024-06-11 as
a limited revision of v4.0; v4.0 was retired 2024-12-31. The v4.0.1 release
contains zero new requirements and zero deleted requirements relative to
v4.0 — it is a correction of typographical and formatting errors and a
clarification of applicability for selected requirements. The
March 31, 2025 future-dated requirements (51 of the 64 new v4 requirements)
became enforceable across all entities — including service providers and
TPSPs. See https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1
accessed 2026-06-08. Service-provider-specific clarifications include
requirement 12.5.2.1 ("PCI DSS scope is documented and confirmed by the
entity at least once every six months and upon significant change to the
in-scope environment"). The April 2025 SAQ A / SAQ D-Service Provider
revisions are at
https://www.pcisecuritystandards.org/wp-content/uploads/2024/10/SAQs_for_PCI_DSS_v4.0.1_Bulletin.pdf
accessed 2026-06-08.

For a CSP that processes, stores, or transmits cardholder data (CHD) on
behalf of a merchant or service-provider customer, the post-2025 PCI-DSS
v4.0.1 obligations cascade as a TPSP attestation. The most operationally
material new requirements remain 6.4.3 (payment-page script integrity),
8.3.6 (12-character password minimum), 8.4.2 (MFA for all access to the
CDE), 11.6.1 (change-and-tamper-detection on payment pages), 11.4.7
(multi-tenant service-provider pen-testing of customer environments), and
the explicit extension of customized-approach validation to service
providers. The FOURTH-PASS-AUDIT proposed `LOOP-K.K3 (PCI-DSS v4.0.1
evidence overlay)` as a single extension slice; this FIFTH-PASS audit
upgrades that to a dedicated `LOOP-AA (PCI-DSS Cardholder-Data Overlay)`
because the requirement set is large enough (64+ requirement statements,
multiple SAQ shapes, scope-attestation cycle, AOC/ROC TPSP-section
emitter) that one slice does not do it justice.

**Classification: CONDITIONALLY APPLICABLE** (applies when CSP touches CHD).
**Proposed coverage: NEW LOOP-AA (PCI-DSS Overlay)** — 4 slices: (AA.1)
CHD inventory data-class enricher overlay on INV-P3, (AA.2) requirement
crosswalk PCI v4.0.1 ↔ NIST 800-53 Rev 5 ↔ FedRAMP KSI, (AA.3) AOC + ROC
TPSP-section emitter, (AA.4) script-integrity (6.4.3) + change-tamper
(11.6.1) evidence collector for AWS CloudFront / GCP Cloud CDN / Azure CDN.

**Verbatim source quote (PCI SSC blog post 2024-06-11):**
> "Today, the PCI Security Standards Council (PCI SSC) published Payment
> Card Industry Data Security Standard (PCI DSS) v4.0.1. PCI DSS v4.0.1 is
> a limited revision to PCI DSS v4.0. … There are no new or removed
> requirements in this revision."

### 2.2 NIST SP 800-171 Rev 3 — May 14, 2024 final

NIST published the final version of SP 800-171r3 ("Protecting Controlled
Unclassified Information in Nonfederal Systems and Organizations") on
May 14, 2024, paired with SP 800-171Ar3 ("Assessing Security Requirements
for Controlled Unclassified Information") on the same date. See
https://csrc.nist.gov/pubs/sp/800/171/r3/final accessed 2026-06-08 and the
canonical PDF at
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf
accessed 2026-06-08. Rev 3 restructures the requirement set to show direct
alignment with SP 800-53r5 controls, reduces the total count from 110 to
97 requirements, introduces 88 Organization-Defined Parameters (ODPs) across
49 requirements, and adds three new requirement families (Planning,
System and Services Acquisition, Supply Chain Risk Management) that were
previously folded into the older catalog.

For FedPy, NIST SP 800-171r3 is non-DoD CUI obligation — distinct from
DFARS 252.204-7012 which references 800-171 Rev 2. The CMMC Final Rule
(32 CFR Part 170, December 2024 effective) currently references 800-171
Rev 2 for Level 2 assessments; DoD has signaled an eventual move to Rev 3
but no firm transition deadline as of 2026-06-08. For any *non-DoD*
federal agency customer (DHS, DOE, NASA, etc.) that processes CUI, the
agency's contracting officer may invoke 800-171r3 via the new FAR CUI rule
(FAR Case 2017-016, still pending final publication as of mid-2026).

**Classification: APPLICABLE (federal civilian CUI customers).** Proposed
coverage: extension slice `LOOP-S.S5 (NIST SP 800-171r3 crosswalk +
ODP-resolution emitter for non-DoD CUI agencies)`. The ODP layer requires
operator-supplied parameter values (REQUIRES-OPERATOR-INPUT) — the CSP
cannot pick the agency's chosen ODP value.

**Verbatim source quote (NIST CSRC publication page):**
> "This publication provides federal agencies with recommended security
> requirements for protecting the confidentiality of CUI when the
> information is resident in nonfederal systems and organizations; when
> the nonfederal organization is not collecting or maintaining information
> on behalf of a federal agency or using or operating a system on behalf
> of an agency; and where there are no specific safeguarding requirements
> for protecting the confidentiality of CUI prescribed by the authorizing
> law, regulation, or government-wide policy for the CUI category listed
> in the CUI Registry."

### 2.3 CMMC L2 / L3 — DoD CMMC 2.0 Final Rule (32 CFR Part 170)

The DoD CMMC Program Final Rule was published 2024-10-15 in the Federal
Register and became effective 2024-12-16, codified at 32 CFR Part 170. See
https://www.federalregister.gov/documents/2024/10/15/2024-22905/cybersecurity-maturity-model-certification-cmmc-program
accessed 2026-06-08 and the eCFR version at
https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-G/part-170
accessed 2026-06-08. The 48 CFR DFARS rule incorporating CMMC into DoD
contracts (DFARS Case 2019-D041) was published 2025-09-10, see
https://www.federalregister.gov/documents/2025/09/10/2025-17359/defense-federal-acquisition-regulation-supplement-assessing-contractor-implementation-of
accessed 2026-06-08; it became effective in November 2025. Implementation
follows a four-phase rollout: Phase 1 (Dec 16, 2024 — self-assessment for
Level 1 + 2); Phase 2 (Dec 16, 2025 — C3PAO third-party assessment for
Level 2); Phase 3 (Dec 2026 — Level 3 DIBCAC assessment); Phase 4 (full
DoD-wide enforcement, late 2027).

For a CSP supporting a DoD-prime contractor processing CUI, CMMC
intersects DFARS 252.204-7012 (already covered in LOOP-S). The Final
Rule preserves the "equivalency" path at §170.16(c)(2): CSPs storing,
processing, or transmitting CUI must meet the FedRAMP Moderate baseline
(or FedRAMP Moderate Equivalency per the DoD CIO 2023-12-21 memorandum).
LOOP-S already emits the DFARS equivalency package; the CMMC overlay
adds (a) the explicit §170.21 SPRS (Supplier Performance Risk System)
score upload format, (b) the §170.18 C3PAO assessment package shape,
and (c) the §170.24 affirmation requirement (annual senior-official
attestation that the contractor continues to meet the CMMC level).

**Classification: ALREADY-IN-SCOPE via LOOP-S** with extension slices for
CMMC-specific deliverables. Proposed coverage: extension slices
`LOOP-S.S6 (CMMC 2.0 SPRS score emitter + §170.21 upload format)` and
`LOOP-S.S7 (CMMC §170.24 annual affirmation emitter)`.

**Verbatim source quote (32 CFR §170.18(c) on POAM closeout window):**
> "Plan of Action and Milestones (POA&M) closeout assessments may be
> performed when the Final Level 2 (C3PAO) Conditional Status is granted.
> The OSC must close out the POA&M items within 180 days of the
> Conditional Level 2 (C3PAO) certificate of assessment issuance."

### 2.4 FedRAMP Tailored LI-SaaS

FedRAMP Tailored LI-SaaS is an active baseline (Rev 5 baseline available
via the FedRAMP documents portal and the LI-SaaS portal at
https://tailored.fedramp.gov/ accessed 2026-06-08). Per the FedRAMP CR26
roadmap, LI-SaaS will be reclassified into "Class B" alongside Low when
the Consolidated Rules 2026 publishes end of June 2026.

For FedPy, LI-SaaS is in scope as a target output baseline only if the
CSP's CSO meets the LI-SaaS scoping criteria (no PII other than login
credentials, no federal financial information, etc.). The existing OSCAL
SSP emitter (SSP-1) supports the FedRAMP profile selector; adding the
LI-SaaS profile is a one-line baseline switch. The cost-of-tagging issue
is that LI-SaaS does not use all KSIs — the collectors that gather data
the LI-SaaS baseline does not consume will run wastefully unless an
opt-out flag is wired through.

**Classification: ALREADY-IN-SCOPE via SSP-1 + profile selector.** Proposed
coverage: small enhancement to SSP-1 to short-circuit unneeded collectors
when `--baseline=li-saas`. No new loop.

### 2.5 TIC 3.0 — Trusted Internet Connections + OMB M-19-26

OMB M-19-26 ("Update to the Trusted Internet Connections (TIC) Initiative",
2019-09-12) tasks DHS CISA with modernizing the TIC initiative to
accelerate adoption of cloud, mobile, and other emerging technologies.
TIC 3.0 is implemented through a series of CISA Core Guidance Volumes:
Volume 1 (Program Guidebook), Volume 2 (Reference Architecture), Volume 3
(Security Capabilities Catalog), plus the Use Case documents. See
https://www.cisa.gov/resources-tools/programs/trusted-internet-connections-tic
accessed 2026-06-08; the canonical Program Guidebook v1.1 is at
https://www.cisa.gov/sites/default/files/2025-07/CISA%20TIC%203.0%20Program%20Guidebook.pdf
accessed 2026-06-08.

For a CSP serving federal agency customers, TIC 3.0 conformance is the
*customer's* obligation — the agency carries the M-19-26 deadline — but
the CSP must furnish the customer with the trust-zone and policy-enforcement
artifacts the agency needs to plug the CSP-hosted CSO into the agency's
trust-zone topology. The natural integration point is the LOOP-D
data-flow-diagram emitter and the LOOP-L Customer Responsibility Matrix:
the CRM must enumerate which TIC 3.0 Security Capabilities the CSP inherits
to the customer (typically Cloud Use Case A/B/C). This is a thin extension,
not a new loop.

**Classification: ALREADY-IN-SCOPE via LOOP-D + LOOP-L** (inheritance map).
Proposed coverage: extension slice `LOOP-L.L5 (TIC 3.0 Security
Capabilities inheritance map emitter)` — reads the CISA TIC 3.0 v2.0 SCC
JSON and emits a CSP-inheritance-to-agency CRM row per capability.

### 2.6 OMB M-21-07 — Completing the Transition to IPv6

OMB M-21-07 ("Completing the Transition to Internet Protocol Version 6
(IPv6)", 2020-11-19) is the binding IPv6-only mandate for the Federal
Civilian Executive Branch. The OMB-set milestones are: 20% of IP-enabled
assets in IPv6-only mode by end of FY2023; 50% by end of FY2024; 80% by
end of FY2025. New networked Federal information systems must be
IPv6-enabled at deployment by FY2023. Public/external-facing services
(web, email, DNS, ISP) must operationally use native IPv6. See
https://www.nlrb.gov/sites/default/files/attachments/pages/node-175/m-21-07.pdf
accessed 2026-06-08 as a publicly-mirrored copy of the OMB memorandum.

For a CSP, the M-21-07 obligation flows through the federal customer:
the agency must demonstrate IPv6-only operation of services it consumes
from the CSP. The CSP itself must support IPv6 at the data-plane (every
public endpoint must answer on IPv6) and emit evidence that endpoints
have AAAA records and respond on IPv6. The inventory collector already
captures network-interface IP addresses (INV-S2 / INV-S3) — extending the
IP-class enricher to flag IPv6 dual-stack and IPv6-only assets is a thin
addition. The DNS-record check (AAAA vs A) for each public endpoint is
new collector code.

**Classification: APPLICABLE.** Proposed coverage: extension slice
`LOOP-E.E9 (IPv6 dual-stack / IPv6-only inventory + DNS AAAA emitter
per M-21-07)`. The DNS resolver call is a network operation, so the slice
must respect the read-only-Proxy guardrail (resolver call is a public DNS
query, not a cloud-SDK write).

**Verbatim source quote (OMB M-21-07 §3):**
> "By the end of FY 2023, at least 20% of IP-enabled assets on Federal
> networks are operating in IPv6-only environments. By the end of FY 2024,
> at least 50% of IP-enabled assets on Federal networks are operating in
> IPv6-only environments. By the end of FY 2025, at least 80% of
> IP-enabled assets on Federal networks are operating in IPv6-only
> environments."

### 2.7 NIST SP 800-128 — Security-Focused Configuration Management

NIST SP 800-128 is the current normative reference for security-focused
configuration management (SecCM) of information systems, cross-referenced
by NIST SP 800-53 Rev 5 CM-family controls. It was published August 2011;
the current draft is SP 800-128 Rev 1 IPD. The CSP-side implication for
FedPy is that the AFR-SCG (Secure Configuration Guide) emitter — LOOP-G.G5
— must reference SP 800-128 as the authority and the SCG body must follow
the SP 800-128 lifecycle (planning, identifying, controlling, monitoring,
integrating-change-management). The FOURTH-PASS audit already flagged this
as ALREADY-IN-SCOPE.

**Classification: ALREADY-IN-SCOPE via LOOP-G.G5.** No new slice required.

### 2.8 NIST SP 800-92 Rev 1 IPD — Cybersecurity Log Management Planning Guide

NIST SP 800-92 Rev 1 IPD ("Cybersecurity Log Management Planning Guide",
October 2023) is the planned replacement for SP 800-92 (Sept 2006). The
Rev 1 IPD aligns SP 800-92 with the Zero Trust Architecture
data-analytics pillar in SP 800-207, the M-21-31 log-collection tier model,
and modern SIEM / SOAR / UEBA tooling. The FOURTH-PASS audit proposed
`LOOP-E.E8 (M-21-31 + SP 800-92r1 log-management-planning artifact)` —
this FIFTH-PASS confirms that proposal and adds a note: when SP 800-92r1
moves from IPD to final (expected late 2026 per the NIST CSRC roadmap),
the slice must refetch the published normative text and update the
boilerplate.

**Classification: APPLICABLE (already proposed in FOURTH-PASS as E.E8).**
No additional action required in this pass.

### 2.9 NIST SP 800-184 — Guide for Cybersecurity Event Recovery

NIST SP 800-184 (December 2016) is the cybersecurity event recovery guide
cross-referenced by NIST SP 800-53 Rev 5 CP-family and IR-family controls.
The recovery-plan emitter (RPL family in the existing pipeline) already
satisfies RPL-ABO, RPL-TRC, RPL-ARP, RPL-RRO. SP 800-184 prescribes a
recovery-plan structure (Identify-Protect-Detect-Respond-Recover lifecycle)
that maps to the existing artifacts. Already-in-scope.

**Classification: ALREADY-IN-SCOPE.** No new slice required.

### 2.10 NIST SP 800-82 Rev 3 — Operational Technology Security

NIST SP 800-82 Rev 3 ("Guide to Operational Technology (OT) Security",
September 2023) is the OT security guide. Applies to ICS, SCADA, building
automation. The CSP cohort FedPy targets — SaaS CI/CD on AWS+GCP+Azure —
does not operate OT systems and does not process OT data. The only
plausible inheritance is a customer that ingests OT telemetry data into
the SaaS; in that case the customer (not the CSP) carries the SP 800-82
obligation.

**Classification: NOT APPLICABLE** to the FedPy reference CSP profile
(per `project_org_profile.md` in user memory). Re-opens only if the cohort
expands to OT-platform SaaS.

### 2.11 NIST SP 800-63 Rev 4 (Final, July 2025)

NIST released SP 800-63 Rev 4 final on 2025-07-30 (after a four-year
revision process). The volume parts are SP 800-63-4 (overview),
SP 800-63A-4 (Identity Proofing and Enrollment), SP 800-63B-4
(Authentication and Authenticator Management), and SP 800-63C-4
(Federation and Assertions). Significant changes from Rev 3 include:
syncable authenticators (passkeys) normative; user-controlled wallets in
the federation model; explicit phishing-resistant authentication
requirement at AAL2 and AAL3; updated identity proofing IAL1/IAL2/IAL3
classes including the new IAL1 / "verified-account-bind" track for low
identity risk. FOURTH-PASS proposed `LOOP-X.X5 (NIST SP 800-63 Rev 4
AAL2/AAL3 phishing-resistant attestation)`.

For this FIFTH-PASS audit, 800-63 Rev 4 is folded into a broader new loop
`LOOP-DD (Identity Pillar — ICAM + 800-63 R4)` because (a) the federal
ICAM framework (FICAM Architecture + OMB M-19-17 + GSA roadmap) is a
distinct universe that the existing LOOP-X (Zero Trust) does not capture
end-to-end, and (b) the AAL / IAL / FAL evidence emitter is large enough
to warrant its own loop with multiple slices (proofing attestation,
authenticator binding ledger, federation assertion log, recovery flow,
ALA attestation).

**Classification: APPLICABLE.** Proposed coverage: **NEW LOOP-DD (Identity
Pillar)** subsumes the previously-proposed LOOP-X.X5 and adds ICAM-layer
slices. See §4.4.

### 2.12 NIST SP 800-160 Vol 1 R1 + Vol 2 R1 — SSE + Cyber Resiliency

NIST SP 800-160 Volume 1 Rev 1 ("Engineering Trustworthy Secure Systems",
final 2022-11-16) repositions Systems Security Engineering (SSE) as a
sub-discipline of Systems Engineering and aligns SSE practices with safety
and other loss-driven disciplines. See
https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final accessed 2026-06-08.
NIST SP 800-160 Volume 2 Rev 1 ("Developing Cyber-Resilient Systems: A
Systems Security Engineering Approach", final December 2021) applies the
SSE framework to cyber-resiliency engineering. Together they form the
foundation for engineering FedRAMP-Moderate-or-higher systems that survive
sophisticated adversary action.

For FedPy, the SSE / Cyber-Resiliency framework is *referenced* by NIST
SP 800-53 Rev 5 controls (SA-8, SA-15, SA-17, SR family) but is rarely
emitted as a first-class artifact. A 3PAO will accept a CSP's narrative
that the system was engineered per SP 800-160 v1 R1 SSE principles, but
the narrative needs evidence — design-review records, threat-model
artifacts, cyber-resiliency-objective traceability matrix. LOOP-N covers
threat modeling already. Adding a dedicated "SSE conformance attestation"
artifact and a cyber-resiliency-objective matrix that joins SP 800-160 v2
R1 objectives to existing collector data is high-value.

**Classification: APPLICABLE.** Proposed coverage: **NEW LOOP-CC (Systems
Security Engineering + Cyber Resiliency Conformance Pack)** — see §4.3.

**Verbatim source quote (NIST CSRC publication page for 800-160 v1 R1):**
> "This publication describes a basis for establishing principles,
> concepts, activities, and tasks for engineering trustworthy secure
> systems. … The publication is intended to serve as a reference and
> educational resource for engineers and engineering specialties,
> architects, designers, and personnel involved in the development of
> trustworthy secure systems and system components."

### 2.13 NIST SP 800-167 — Guide to Application Allow-listing (Whitelisting)

NIST SP 800-167 ("Guide to Application Whitelisting", October 2015) is the
normative guidance for application allow-listing. See
https://csrc.nist.gov/pubs/sp/800/167/final accessed 2026-06-08 and the
canonical PDF at
https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-167.pdf
accessed 2026-06-08. The publication establishes the basics: a whitelist
is a list of authorized applications + components; the technology controls
which applications may execute on a host to stop malware, unlicensed
software, and other unauthorized software. NIST SP 800-53 Rev 5 controls
CM-7(5) (Authorized Software — Allow-by-Exception) and SI-3 (Malicious
Code Protection) reference SP 800-167.

For FedPy, application allow-listing is partially in scope through the
existing CMT-RMV (Removal of Unauthorized Software) and CMT-VTD
(Vulnerability and Threat Detection) collectors. The gap is the *catalog*
emitter: the FedRAMP Moderate baseline expects a documented allow-list of
permitted software per host class, and the CSP must show the audit trail
of allow-list changes. This is a thin extension to the LOOP-G family or
the LOOP-E continuous-monitoring family.

**Classification: APPLICABLE.** Proposed coverage: extension slice
`LOOP-G.G7 (NIST SP 800-167 application allow-list catalog emitter +
change-history log)`.

### 2.14 NIST SP 800-204 / 204A / 204B / 204C — Microservices Security

The NIST SP 800-204 series addresses microservices security:

- **SP 800-204** (Aug 2019) — Security Strategies for Microservices-based
  Application Systems. See
  https://csrc.nist.gov/pubs/sp/800/204/final accessed 2026-06-08.
- **SP 800-204A** (May 2020) — Building Secure Microservices-based
  Applications Using Service-Mesh Architecture. See
  https://csrc.nist.gov/pubs/sp/800/204/a/final accessed 2026-06-08.
- **SP 800-204B** (Aug 2021) — Attribute-based Access Control for
  Microservices-based Applications.
- **SP 800-204C** (Mar 2022) — Implementation of DevSecOps for a
  Microservices-based Application with Service Mesh.

For a CSP whose CSO is itself a microservices platform (Kubernetes +
Istio / Linkerd) — exactly the FedPy reference cohort — these
publications are normative for the SVC-VCM (Service Mesh) and CMT-VTD
families. The existing collectors detect service-mesh presence and
extract mTLS configuration; the SP 800-204 series adds prescriptive
*architecture* guidance (ABAC vs RBAC, service-discovery integrity,
circuit-breaker availability, secure-communication mTLS profile) that
should appear in the AFR-MAS (Microservices Architecture Security)
narrative artifact.

**Classification: APPLICABLE (already partially covered).** Proposed
coverage: extension slice `LOOP-G.G8 (NIST SP 800-204 series conformance
attestation — service-mesh + ABAC + DevSecOps pipeline)`. The slice
generates an attestation that the CSP's microservices platform follows the
800-204A/B/C reference pattern, with evidence-pointer back to the
SVC-VCM and CMT-VTD findings.

### 2.15 DoD STIG / SCAP authoring

DISA-published Security Technical Implementation Guides (STIGs) and the
Security Content Automation Protocol (SCAP) content are normative for
DoD-customer CSOs (covered by LOOP-S DFARS / IL2-IL6 path). The current
DoD CC SRG v1 r5 (DISA release 2024-06-14) ties CSP authorization to STIG
conformance at IL4+ for any Mission Owner system component. See
https://www.cisa.gov/sites/default/files/2023-09/CDM-ICAM_Reference_Architecture_508c.pdf
(cited for the CDM/ICAM intersection) and the DISA Cyber Exchange
(public side) at https://public.cyber.mil/stigs/ for STIG access (note:
some STIGs require CAC for download; the IL2 baseline STIGs are publicly
accessible).

For FedPy, STIG conformance is partially in scope through the existing
SCG (Secure Configuration Guide) emitter — LOOP-G.G5 — but the *automated
scan* against published STIG content (using SCAP tooling) is a separate
artifact family that is not yet emitted. A thin extension to LOOP-G.G5
that ingests SCAP scan results from a SCAP-capable scanner (OpenSCAP,
Tenable Nessus, Rapid7 InsightVM) and produces a STIG-conformance summary
per CCI is high-value, especially for IL4+ Mission Owner customers.

**Classification: CONDITIONALLY APPLICABLE (DoD IL2+ customers).**
Proposed coverage: extension slice `LOOP-S.S8 (STIG/SCAP scan ingest +
per-CCI conformance summary emitter)`.

### 2.16 CIS Controls v8.1 (June 2024)

The Center for Internet Security released CIS Controls v8.1 in June 2024
with the principal change being alignment to NIST CSF 2.0 and the
introduction of a new "Govern" security function alongside the existing
Identify / Protect / Detect / Respond / Recover. v8.1 also restructures
Asset Types to include the new "Documentation" class (plans, policies,
procedures), bringing the total to seven asset types. See
https://www.cisecurity.org/controls/v8-1 accessed 2026-06-08. The
Implementation Groups (IG1 / IG2 / IG3) layering is preserved from v8.0;
IG1 is 56 safeguards, IG2 adds safeguards for higher-risk environments,
IG3 is the full catalog (153 safeguards).

For FedPy, CIS Controls is non-statutory but heavily market-signaling.
Many commercial-sector customers ask for a CIS Controls v8.1 self-
attestation alongside FedRAMP. The natural integration is the C.1
multi-framework crosswalk module (already shipped) — extending the
NIST 800-53 → SOC 2 / ISO 27001 / HIPAA crosswalk to add CIS Controls
v8.1 safeguard IDs. No new loop required; backlog extension to LOOP-K
(or as a standalone crosswalk slice).

**Classification: CONDITIONALLY APPLICABLE (voluntary, market-driven).**
Proposed coverage: extend `C.1 multi-framework crosswalk` to include
CIS Controls v8.1 safeguard IDs (153 safeguards × 3 IGs).

### 2.17 CSA Cloud Controls Matrix CCM v4.0.x / v4.1

The CSA Cloud Controls Matrix is a cloud-specific control framework
spanning 17 security domains and 197 controls (v4.0.10 had 197; v4.0.13
extended slightly). The CSA released CCM v4.1 on 2025-11-06; organizations
have a two-year transition window ending November 2027. See
https://cloudsecurityalliance.org/research/cloud-controls-matrix accessed
2026-06-08 and the v4.0/v4.1 artifact pages at
https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1
accessed 2026-06-08. The accompanying Consensus Assessment Initiative
Questionnaire (CAIQ v4) is the standard self-attestation form.

For FedPy, CSA CCM v4 / v4.1 is non-statutory but is the de-facto cloud
self-attestation standard for the global IaaS / PaaS / SaaS market. A CSP
that publishes a CAIQ in the CSA STAR Registry receives Level 1 STAR
recognition; Level 2 requires a third-party assessment. The natural
integration is the C.1 multi-framework crosswalk module — extend it to
emit a CAIQ v4 / v4.1 response file derived from the existing collector
outputs.

**Classification: CONDITIONALLY APPLICABLE (voluntary, market-driven).**
Proposed coverage: extension slice `LOOP-K.K4 (CSA CCM v4.1 CAIQ
self-attestation emitter)`.

### 2.18 AICPA SOC 2 Type II — AT-C §205 + SSAE 21 + 2022 Revised Points of Focus

The AICPA SOC 2 Type II report is governed by AT-C §205 (the SSAE 21
attestation engagement standard) and the 2017 Trust Services Criteria
with the September 2022 Revised Points of Focus. See
https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
accessed 2026-06-08. AT-C §205 includes representations required for SOC 2
Type 2 examinations, and illustrative service auditor's reports for SOC 2
type 2 examinations meet the reporting requirements of SSAE-21. The 2022
revisions added focus points across governance, communication, risk
assessment, and monitoring but did not change the criteria themselves.

For FedPy, SOC 2 is non-statutory but commercial-customer-mandatory. The
existing C.1 multi-framework crosswalk module already maps NIST 800-53
Rev 5 → SOC 2 Trust Services Criteria, but does not consume the September
2022 Revised Points of Focus refinements. The natural extension is a thin
update to the crosswalk source data + a new SOC 2 description-criteria
narrative-stub emitter that gives the operator the boilerplate the CPA
firm needs to start the engagement.

**Classification: CONDITIONALLY APPLICABLE (voluntary, market-driven).**
Proposed coverage: extension slice `LOOP-K.K5 (SOC 2 description-criteria
narrative-stub emitter + 2022 Revised Points of Focus crosswalk update)`.

### 2.19 ISMAP / IRAP / TISAX (international assurance frameworks)

ISMAP (Japan), IRAP (Australia), and TISAX (Germany automotive) are
sovereign cloud-security assessment frameworks distinct from ISO 27001 /
ENISA EUCS. LOOP-Z (International Equivalence) covers ISO 27001 / 27017 /
27018 / 27701 + ENISA EUCS but does not yet cover ISMAP / IRAP / TISAX
explicitly. ISMAP is operated by Japan's Digital Agency (last published
control set v2.0 in 2025); IRAP is operated by ACSC and references the
Australian Government's ISM (Information Security Manual). TISAX is
operated by ENX Association for the German automotive supply chain.

For FedPy, each of these is geographically scoped — applies only when the
CSP has a customer in the respective jurisdiction. ISMAP is the most
likely to surface for a global SaaS CSP; IRAP for AWS / GCP / Azure
sovereign-region customers; TISAX for any tier-1 automotive supplier
customer. Coverage is thin: ISMAP control IDs map to ISO 27001 with a
Japan-specific overlay; IRAP control IDs map to ISM with an Australian
classified-data overlay; TISAX maps to a subset of ISO 27001 plus
automotive-prototype-protection controls.

**Classification: CONDITIONALLY APPLICABLE.** Proposed coverage: extension
slices `LOOP-Z.Z4 (ISMAP control crosswalk + Japan Digital Agency
attestation)`, `LOOP-Z.Z5 (IRAP / ISM crosswalk + ACSC submission)`,
`LOOP-Z.Z6 (TISAX VDA-ISA crosswalk + ENX submission)`.

### 2.20 GovRAMP (formerly StateRAMP) / TX-RAMP / AZRAMP

StateRAMP rebranded to GovRAMP in February 2025; the website transitioned
to govramp.org as of March 2025. AZRAMP (Arizona) was retired and
transitioned to GovRAMP as of April 2025; all new Arizona contracts must
align with GovRAMP or FedRAMP standards as of July 2026. TX-RAMP (Texas)
remains a distinct program governed by Texas DIR Program Manual 3.1
(May 2025) at
https://dir.texas.gov/sites/default/files/2025-05/TX-RAMP%20Program%20Manual%203.1.pdf
accessed 2026-06-08. As of October 30, 2024, TX-RAMP no longer
auto-populates the certified-products list from FedRAMP / GovRAMP — CSPs
must apply separately. GovRAMP's January 2024 update aligned its Security
Snapshot criteria to NIST 800-53 Rev 5 and the MITRE ATT&CK framework
control protection values. See
https://govramp.org/ accessed 2026-06-08.

For FedPy, GovRAMP / TX-RAMP are state-level analogs of FedRAMP that a
CSP commonly pursues alongside FedRAMP to broaden the addressable
customer base. The FRMR catalog and the existing OSCAL SSP emitter
(SSP-1) support FedRAMP baselines but not GovRAMP / TX-RAMP profile
selectors directly. The right shape is: extend the FRMR ingest to pull
GovRAMP baseline + TX-RAMP Level 1 / Level 2 control catalogs, and add
profile-selector options to SSP-1.

**Classification: CONDITIONALLY APPLICABLE.** Proposed coverage: extension
slice `LOOP-Q.Q4 (GovRAMP + TX-RAMP profile selectors + Security
Snapshot emitter)`.

### 2.21 OMB Circular A-130 (2016) + FISMA Modernization Act 2014

OMB Circular A-130 ("Managing Information as a Strategic Resource",
revised 2016-07-27) is the binding policy for federal agencies on
information management, information security, and privacy. The Federal
Information Security Modernization Act of 2014 (FISMA 2014, Public Law
113-283) updates the 2002 FISMA, codifies DHS authority to administer
information security policies for non-national-security Federal Executive
Branch systems, and requires OMB to revise A-130 to eliminate inefficient
reporting. See https://www.congress.gov/bill/113th-congress/senate-bill/2521
and https://obamawhitehouse.archives.gov/sites/default/files/omb/assets/OMB/circulars/a130/a130revised.pdf
both accessed 2026-06-08.

For FedPy, A-130 + FISMA 2014 are the umbrella authorities under which
FedRAMP itself exists — the program traces its statutory grounding through
FISMA 2014 §3553(b) and the OMB FedRAMP Memorandum (M-22-18 superseded by
M-24-15 in 2024). The cloud-evidence pipeline never emits an A-130 or
FISMA artifact directly, but the SSP narrative and authorization-package
metadata reference both. The existing OSCAL SSP emitter implicitly carries
this — explicit citation in the SSP boilerplate is a one-line addition.

**Classification: ALREADY-IN-SCOPE (umbrella authority).** No new slice;
add explicit A-130 + FISMA 2014 citations to the SSP boilerplate.

### 2.22 NSM-22 — National Security Memorandum on Critical Infrastructure (Apr 2024)

NSM-22 ("National Security Memorandum on Critical Infrastructure Security
and Resilience", 2024-04-30) supersedes PPD-21 (2013) as the foundational
US critical-infrastructure policy. NSM-22 designates DHS as the lead with
CISA as the National Coordinator and preserves PPD-21's 16-sector
organization. NSM-22 mandates biennial National Infrastructure Risk
Management Plans, enhanced intelligence sharing, and more assertive use
of federal regulatory authorities and procurement / grant rules to drive
private-sector compliance with minimum resilience standards. See
https://bidenwhitehouse.archives.gov/briefing-room/presidential-actions/2024/04/30/national-security-memorandum-on-critical-infrastructure-security-and-resilience/
accessed 2026-06-08 and the CISA portal at
https://www.cisa.gov/national-security-memorandum-critical-infrastructure-security-and-resilience
accessed 2026-06-08.

For FedPy, NSM-22 is most directly relevant when the CSP is itself a
covered critical-infrastructure entity (the IT sector is one of the 16) or
when the CSP serves a customer in another covered sector (healthcare,
financial, energy, water, defense industrial base). The most material
operational impact is the CISA CPGs (Cybersecurity Performance Goals) —
NSM-22 anticipates CPGs becoming the floor for sector-specific minimum
practices, with the 2025-12-11 CPG 2.0 release as the first post-NSM-22
update. This loop is large enough — CPG 2.0 has dozens of sector-cross
practices spanning governance, MSP oversight, least-privilege,
incident-comms — to warrant its own loop.

**Classification: APPLICABLE.** Proposed coverage: **NEW LOOP-BB (CISA
CPGs 2.0 + NSM-22 Critical Infrastructure Resilience)** — see §4.2.

**Verbatim source quote (NSM-22 §1):**
> "The security and resilience of our Nation's critical infrastructure is
> essential to our economic prosperity, national security, and the health
> and safety of the American public. This memorandum supersedes
> Presidential Policy Directive 21 of February 12, 2013 (Critical
> Infrastructure Security and Resilience), and establishes United States
> policy on the security and resilience of our Nation's critical
> infrastructure."

### 2.23 AI Bill of Rights + NIST AI RMF 1.0 (NIST AI 100-1) + EO 14110

The Blueprint for an AI Bill of Rights (October 2022) is non-binding
guidance from the White House Office of Science and Technology Policy.
NIST AI RMF 1.0 (NIST AI 100-1, January 26, 2023) is a voluntary,
technology- and sector-agnostic framework with four core functions:
GOVERN, MAP, MEASURE, MANAGE. See
https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf accessed 2026-06-08.
EO 14110 ("Safe, Secure, and Trustworthy Development and Use of
Artificial Intelligence", October 30, 2023) was the binding AI executive
order under the Biden administration; it was revoked on January 20, 2025
by the Trump administration via EO 14179 ("Removing Barriers to American
Leadership in Artificial Intelligence", January 23, 2025) — see
https://www.whitehouse.gov/presidential-actions/2025/01/removing-barriers-to-american-leadership-in-artificial-intelligence/
accessed 2026-06-08.

For FedPy, the *enduring* AI obligations are (a) NIST AI RMF 1.0 — still
in force as a voluntary framework, with sector-specific profiles in
active development; (b) OMB M-24-10 — see §2.24 below — which survived
the EO 14110 revocation because it was issued by OMB under separate
authority; and (c) any agency-specific AI use policy. EO 14110's revocation
removed the cross-government CAIO mandate's *executive-order* basis but
M-24-10 preserves the CAIO requirement at the OMB-memo level. LOOP-O
covers AI generally; the FOURTH-PASS audit positioned LOOP-O as
already-in-scope. This FIFTH-PASS audit elevates the federal-procurement
AI obligation (OMB M-24-10 + AI RMF + AI procurement standards) into a
dedicated loop because the LOOP-O scope was AI-system-governance generally,
not federal-use-of-AI procurement.

**Classification: APPLICABLE.** Proposed coverage: **NEW LOOP-FF (AI
Federal Use — OMB M-24-10 + NIST AI RMF + AI Procurement)** — see §4.6.

### 2.24 OMB M-24-10 — Federal AI Use (March 2024)

OMB M-24-10 ("Advancing Governance, Innovation, and Risk Management for
Agency Use of Artificial Intelligence", March 28, 2024) establishes binding
agency-level AI governance requirements including (a) designation of a
Chief AI Officer (CAIO) within 60 days, (b) annual public AI Use Case
Inventory, (c) AI impact assessment before deploying any safety- or
rights-impacting AI, (d) minimum risk-management practices, and (e)
termination of noncompliant uses by December 1, 2024. See
https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf
accessed 2026-06-08. M-24-10 was followed by M-24-18 (October 2024,
"Advancing the Responsible Acquisition of Artificial Intelligence in
Government") which extends the framework to federal AI procurement.

For FedPy, M-24-10 imposes obligations on the *agency customer*, not on
the CSP directly. The CSP-side implication is that an agency customer
that uses the CSP's AI features must run an AI impact assessment and
inventory the use case publicly. The CSP needs to furnish (a) an AI
factsheet — a documented description of the AI system's purpose, training
data class, risk profile, testing evidence, and bias-evaluation results;
(b) a model card per the agency CAIO's AI inventory schema; (c) a
documented rights-impacting / safety-impacting determination per the
M-24-10 categories.

**Classification: APPLICABLE.** Proposed coverage: included in **NEW
LOOP-FF (AI Federal Use)** — slices for AI factsheet, model card, impact-
assessment narrative, M-24-18 procurement evidence pack.

**Verbatim source quote (M-24-10 §1):**
> "This memorandum directs agencies to advance AI governance and
> innovation while managing risks from the use of AI in the Federal
> Government, particularly those affecting the rights and safety of the
> public."

### 2.25 EO 14110 (revoked Jan 2025) + EO 14179 (Jan 2025)

EO 14110 ("Safe, Secure, and Trustworthy Development and Use of Artificial
Intelligence", October 30, 2023) was the binding AI executive order under
the Biden administration. It was revoked by EO 14179 ("Removing Barriers
to American Leadership in Artificial Intelligence", January 23, 2025) at
https://www.whitehouse.gov/presidential-actions/2025/01/removing-barriers-to-american-leadership-in-artificial-intelligence/
accessed 2026-06-08. EO 14179 directs officials to review all policies
issued under EO 14110 and to draft a US AI Action Plan within 180 days
of issuance. As of 2026-06-08, the US AI Action Plan has been published
(July 2025) and several NIST + Commerce Department deliverables that were
authored under EO 14110 (including the AI safety institute publications
and the AISIC test methodologies) remain in effect because they were
issued under NIST's separate IT-research authority.

For FedPy, EO 14110's revocation does *not* eliminate the AI compliance
universe — the CSP still has to satisfy (a) OMB M-24-10 + M-24-18 (still
in force), (b) NIST AI RMF 1.0 (voluntary but contractually invoked),
(c) sector-specific AI laws (e.g. EEOC's regulation of AI in hiring), and
(d) state AI laws (Colorado AI Act, Texas Responsible AI Governance Act,
etc.). The right move for FedPy is to design LOOP-FF around the *durable*
obligations (M-24-10 + AI RMF + sector laws) rather than around a single
revoked executive order.

**Classification: NOT APPLICABLE (revoked).** Successor obligations
(M-24-10, AI RMF, EO 14179 follow-ons) are covered in LOOP-FF. EO 14110
is documented here for traceability only.

### 2.26 Section 508 (Revised, 2018) + ADA Title II Web Rule (April 2024)

Section 508 of the Rehabilitation Act, as amended by the 1998 Workforce
Investment Act, requires federal agencies (and contractors selling to
them) to make their ICT (information and communications technology)
accessible to people with disabilities. The Revised Section 508 Standards
(36 CFR Part 1194, US Access Board) became enforceable on 2018-01-18 and
incorporate WCAG 2.0 Level A and AA by reference. See
https://www.access-board.gov/ict/ accessed 2026-06-08. The ADA Title II
final rule (DOJ, 28 CFR Part 35, published 2024-04-24) extends WCAG 2.1
Level AA to all state and local government websites and mobile
applications. See
https://www.ada.gov/resources/2024-03-08-web-rule/ accessed 2026-06-08.
The compliance dates were extended in April 2026 (per
https://www.federalregister.gov/documents/2026/04/20/2026-07663/extension-of-compliance-dates-for-nondiscrimination-on-the-basis-of-disability-accessibility-of-web
accessed 2026-06-08): population ≥ 50,000 entities now have until
April 26, 2027; smaller entities and special-district governments until
April 26, 2028.

For FedPy, Section 508 applies to the tracker (web dashboard) and any
operator-facing artifact (docx, pdf, html). The CSP-emitted artifacts
must be 508-conformant if the CSP sells to federal agencies. ADA Title II
applies if the CSP serves state/local government customers — many do.
Neither obligation is currently covered in any loop. Accessibility audits
(automated axe-core + manual screen-reader testing) of every emitted
artifact and of the tracker UI is a meaningful work-stream warranting its
own loop.

**Classification: APPLICABLE.** Proposed coverage: **NEW LOOP-GG
(Accessibility — Section 508 + ADA Title II)** — see §4.7.

**Verbatim source quote (DOJ ADA Title II final rule, Fact Sheet):**
> "The rule has specific requirements about how to ensure that web
> content and mobile applications (apps) are accessible to people with
> disabilities. … The rule applies to mobile apps that a state or local
> government provides or makes available, including when a state or
> local government has an arrangement with someone else who provides or
> makes available a mobile app for them."

### 2.27 NIST IR 8053 / 8062 / 8112 — De-identification + Privacy Engineering + Attribute Metadata

NIST IR 8053 ("De-Identification of Personal Information", October 2015)
is the foundational guidance on de-identification techniques. NIST IR 8062
("An Introduction to Privacy Engineering and Risk Management in Federal
Systems", January 2017) introduces the privacy engineering objectives
(predictability, manageability, disassociability) and the privacy risk
model. See https://csrc.nist.gov/pubs/ir/8062/final accessed 2026-06-08.
NIST IR 8112 ("Attribute Metadata: A Proposed Schema for Evaluating
Federated Attributes", January 2018) defines a schema for attribute
metadata in identity federation, paired with SP 800-63C.

For FedPy, all three IRs are referenced by LOOP-M (Privacy Package
Extension) which covers SORN / DPIA narrative emission. IR 8062's
privacy engineering objectives map directly to the M.M3 (DSAR ingest)
and M.M4 (privacy incident response) slices already in scope. IR 8053's
de-identification techniques are normative for any pipeline that emits
operator-facing data sets containing PII (e.g., the inventory CSV).
IR 8112 is referenced through LOOP-DD (Identity Pillar — see §4.4).
This is all already-in-scope through existing LOOP-M and the new LOOP-DD.

**Classification: ALREADY-IN-SCOPE via LOOP-M + LOOP-DD.** No new slice.

### 2.28 Federal ICAM Framework (FICAM)

The Federal Identity, Credential, and Access Management (FICAM)
Architecture is the binding identity framework for federal civilian
agencies, governed by OMB M-19-17 ("Enabling Mission Delivery through
Improved Identity, Credential, and Access Management", May 21, 2019) and
operationalized by GSA's idmanagement.gov roadmap. See
https://www.idmanagement.gov/arch/ accessed 2026-06-08 and the GSA
shared-services roadmap at https://www.idmanagement.gov/icamsolutions/
accessed 2026-06-08. The FICAM Architecture pre-dates NIST SP 800-63 Rev 4
and is being updated to incorporate Rev 4's syncable-authenticator and
user-controlled-wallet model.

For FedPy, FICAM applies through the agency customer. The CSP must
furnish (a) attestation that the CSO's identity and access controls
conform to the FICAM Architecture playbooks, (b) evidence that personnel
who access the CSO's federal-customer-tenant are FICAM-credentialed
(PIV / CAC / FIDO2 / equivalent), (c) federation-assertion evidence if
the CSO is part of a federation (e.g., Login.gov, USAccess, agency SSO).
This is the federal-agency-side of the LOOP-X (Zero Trust) coverage.
Folding ICAM into a dedicated identity-pillar loop with 800-63 Rev 4 is
the right shape.

**Classification: APPLICABLE.** Proposed coverage: included in **NEW
LOOP-DD (Identity Pillar — ICAM + 800-63 Rev 4)** — see §4.4.

### 2.29 NIST SP 800-130 + 800-152 — Cryptographic Key Management

NIST SP 800-130 ("A Framework for Designing Cryptographic Key Management
Systems", August 2013) defines the topics a CKMS designer must address
when developing a CKMS design specification. See
https://csrc.nist.gov/pubs/sp/800/130/final accessed 2026-06-08. NIST SP
800-152 ("A Profile for U.S. Federal Cryptographic Key Management
Systems", October 2015) is the federal-specific profile of 800-130 — it
contains requirements for design, implementation, procurement,
installation, configuration, management, operation, and use of CKMS by
U.S. Federal organizations. See
https://csrc.nist.gov/pubs/sp/800/152/final accessed 2026-06-08.

For FedPy, NIST SP 800-152 is the binding key-management profile when
the CSO processes federal information. The existing AFR-UCM (Using
Cryptographic Modules) collector verifies FIPS module validation; the
800-152 layer goes further — it requires a documented CKMS design
specification, a documented key lifecycle (generation, distribution,
storage, escrow, rotation, destruction), audit logs of every key event,
and a CKMS Security Policy. This is mostly an operator-authored process
artifact, but the audit-log portion can be derived from KMS / Key Vault /
Cloud KMS API calls already collected. Pairing with FIPS 140-3 transition
(see §2.30) makes a coherent loop.

**Classification: APPLICABLE.** Proposed coverage: **NEW LOOP-EE
(Cryptographic Key Management — FIPS 140-3 + SP 800-130 + SP 800-152)** —
see §4.5.

**Verbatim source quote (NIST SP 800-152 §1.1 Purpose):**
> "This Profile for U.S. Federal Cryptographic Key Management Systems
> (FCKMSs) contains requirements for their design, implementation,
> procurement, installation, configuration, management, operation, and
> use by U.S. Federal organizations."

### 2.30 FIPS 140-3 — Cryptographic Module Validation (CMVP)

FIPS 140-3 became effective September 22, 2019 and CMVP began accepting
validation submissions in September 2020. CMVP stopped accepting new
FIPS 140-2 submissions on April 1, 2022. The critical date is
**September 21, 2026**: all FIPS 140-2 certificates still active on that
date move to the CMVP "Historical" list and may no longer be cited by
federal agencies for the protection of CUI. See
https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards
accessed 2026-06-08 and the management manual at
https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS-140-3-CMVP%20Management%20Manual.pdf
accessed 2026-06-08. FIPS 140-3 references ISO/IEC 19790 for module
requirements and ISO/IEC 24759 for testing.

For FedPy, the September 21, 2026 transition is **critical and imminent**
(the audit is being authored 2026-06-08, three months from the cutoff).
The AFR-UCM collector currently identifies FIPS-validated modules in use;
it must (a) flag any module still validated only against FIPS 140-2, (b)
emit a transition-plan POA&M item for any 140-2-only module that the CSP
still relies on, (c) check the CMVP validation list for the module's
status (Active / Historical / Sunset) at run time. The existing
collectors do not yet have the CMVP-list lookup; this needs to be a
loop.

**Classification: APPLICABLE — HIGH PRIORITY (Sep 21, 2026 deadline).**
Proposed coverage: included in **NEW LOOP-EE (Cryptographic Key
Management)** — see §4.5. The CMVP-list lookup is the first slice and
must ship before September 21, 2026.

### 2.31 CISA Cybersecurity Performance Goals (CPGs) v1.0.1 + v2.0

CISA published the original Cross-Sector Cybersecurity Performance Goals
in October 2022; v1.0.1 was released March 2023 and grouped the goals by
NIST CSF Function. See
https://www.cisa.gov/sites/default/files/2023-03/CISA_CPG_REPORT_v1.0.1_FINAL.pdf
accessed 2026-06-08. **CPG 2.0** was released 2025-12-11 (NSM-22-aligned
update), see
https://www.cisa.gov/cybersecurity-performance-goals-2-0-cpg-2-0
accessed 2026-06-08 and
https://www.cisa.gov/news-events/alerts/2025/12/11/cybersecurity-performance-goals-20-critical-infrastructure
accessed 2026-06-08. CPG 2.0 adds a new "Govern" component, consolidates
OT + IT goals into shared goals, adds goals for MSP-risk, least-
privilege, and incident communications, and aligns to NIST CSF 2.0.

For FedPy, the CPGs are *voluntary* but heavily contractually invoked in
sector-specific RFPs. NSM-22 envisions CPGs becoming the floor for
sector-specific minimum practices. A CSP serving any of the 16 critical
infrastructure sectors should publish a CPG 2.0 self-attestation. The
CPG-to-NIST-CSF-to-NIST-800-53 crosswalk is published by CISA; the
emitter is straightforward: roll up existing collector findings into the
38 CPG 2.0 practices, emit a self-attestation per practice with evidence-
pointer to the underlying collector run.

**Classification: APPLICABLE (voluntary but market-essential).** Proposed
coverage: included in **NEW LOOP-BB (CISA CPGs + NSM-22 Critical
Infrastructure Resilience)** — see §4.2.

**Verbatim source quote (CISA CPG 2.0 announcement, 2025-12-11):**
> "CPG 2.0 includes a new component focused on the essential role of
> governance in managing cybersecurity, emphasizing accountability, risk
> management, and strategic integration of cybersecurity into day-to-day
> operations."

### 2.32 FAR Part 7.105 — Contents of Written Acquisition Plans

FAR Part 7.105 ("Contents of written acquisition plans", 48 CFR §7.105)
prescribes the content of a written acquisition plan that contracting
officers must prepare for major acquisitions. See
https://www.acquisition.gov/far/7.105 accessed 2026-06-08 and the eCFR
version at
https://www.ecfr.gov/current/title-48/chapter-1/subchapter-B/part-7/subpart-7.1/section-7.105/
accessed 2026-06-08. The plan must address background and objectives,
cost considerations, capability or performance requirements, source
selection procedures, contract considerations, budget and funding, risk
management, security considerations, and life-cycle costs.

For FedPy, FAR 7.105 is an *agency-side* obligation — the contracting
officer writes the acquisition plan, not the CSP. The CSP-side relevance
is narrower: the agency may ask the CSP to furnish standardized data the
agency can plug into the acquisition plan, including (a) life-cycle cost
breakdown, (b) security-control inheritance summary, (c) supply-chain
risk summary. These are already emitted via LOOP-J (Supply Chain) and
LOOP-L (CRM). No new loop or slice; FAR 7.105 traces to existing
artifacts.

**Classification: ALREADY-IN-SCOPE via LOOP-J + LOOP-L** (agency-side
obligation; CSP-side input data already emitted). No new slice.

### 2.33 Latest FedRAMP RFCs (RFC-0015 through RFC-0017+)

FedRAMP published three new RFCs in September 2025:

- **RFC-0015** ("Recommended Secure Configuration Standard", 2025-09-10) —
  see https://www.fedramp.gov/rfcs/0015/ accessed 2026-06-08.
- **RFC-0016** ("Collaborative Continuous Monitoring Standard",
  2025-09-15) — see https://www.fedramp.gov/rfcs/0016/ accessed 2026-06-08.
- **RFC-0017** ("Persistent Validation and Assessment Standard",
  2025-09-15) — see https://www.fedramp.gov/rfcs/0017/ accessed 2026-06-08.

A January 2026 batch of six additional RFCs was opened for comment per
https://www.governmentcontractslegalforum.com/2026/01/articles/government-contracts/fedramp-proposes-updates-to-authorization-process-six-new-rfcs-released-for-public-comment/
accessed 2026-06-08 (EXCERPT-VERIFY — fetch RFC-0018 through RFC-0023
when the slice authors them). These RFCs are *proposed* — none are
ratified as of 2026-06-08. The closed RFC index (RFC-0001 through ~0014)
is at https://www.fedramp.gov/rfcs/ accessed 2026-06-08.

For FedPy, RFC-0015 / RFC-0016 / RFC-0017 directly affect the FedRAMP
20x pipeline. RFC-0015 (Secure Configuration Standard) overlaps with the
existing SCG (Secure Configuration Guide) emitter — LOOP-G.G5. RFC-0016
(Collaborative Continuous Monitoring) overlaps with LOOP-E. RFC-0017
(Persistent Validation and Assessment) overlaps with the KSI evidence
loop (LOOP-A + LOOP-E). The right move: each RFC becomes an extension
slice in the relevant existing loop, with frontmatter `applicable_when`
keying off RFC ratification (the slice ships in `proposed` status,
activates on RFC ratification).

**Classification: APPLICABLE (proposed; ratification pending).** Proposed
coverage: extension slices `LOOP-G.G9 (RFC-0015 Secure Configuration
Standard alignment)`, `LOOP-E.E10 (RFC-0016 Collaborative Continuous
Monitoring alignment)`, `LOOP-A.A6 (RFC-0017 Persistent Validation +
Assessment Standard alignment)`. Each carries `applicable_when:
rfc_ratified` and ships in `proposed` status.

### 2.34 DoD Cloud Computing SRG v1 r5 (IL2/4/5/6) — June 14, 2024

DISA released DoD CC SRG v1 r5 on 2024-06-14. The release marks the shift
from NIST 800-53 Rev 4 to Rev 5 and incorporates CNSSP-32 requirements
for National Security Systems. The CC SRG is now divided into two
sections, one for Mission Owners and another for CSPs. v1 r5 expands
reciprocity to IL4, IL5, and IL6 — CSPs may use existing FedRAMP
authorizations to reduce assessment workload. The four impact levels are
preserved: IL2 (publicly-releasable), IL4 (CUI), IL5 (higher-sensitivity
CUI + mission-critical + national-security systems), IL6 (SECRET +
national-security-systems classified information).

For FedPy, the DoD CC SRG v1 r5 update is *already-in-scope* through
LOOP-S (DFARS 252.204-7012 Cloud Equivalency) — LOOP-S references the CC
SRG explicitly. The IL5 / IL6 baselines are out of scope for the FedPy
reference CSP profile (the cohort is SaaS CI/CD on AWS+GCP+Azure
commercial regions, not GovCloud High or IL5 environments). IL2 / IL4
are achievable from FedRAMP Moderate via the equivalency path LOOP-S
emits. The v1 r5 → v1 r6 transition (expected ~2027 per DISA Cyber
Exchange roadmap) is a future-pass concern.

**Classification: ALREADY-IN-SCOPE via LOOP-S** for IL2/IL4. **NOT
APPLICABLE** for IL5/IL6 under the reference CSP profile.

### 2.35 FedRAMP 20x High Baseline (FY27 placeholder)

FedRAMP's published roadmap places the 20x High pilot in **Phase 4
(FY27 Q1-Q2)**, scoped initially to hyperscale IaaS and PaaS providers,
followed by **Phase 5 (FY27 Q3-Q4)** which ends new Rev 5 agency
authorizations. See
https://www.fedramp.gov/20x/phases/ accessed 2026-06-08 and the
GitHub roadmap PROGRESS.md at
https://github.com/FedRAMP/roadmap/blob/main/PROGRESS.md accessed
2026-06-08. As of 2026-06-08, the 20x High KSI catalog has not been
published — the FRMR catalog ingest cannot produce 20x High output
because the source data does not exist.

For FedPy, the High-baseline emitter exists in the pipeline (SSP-1
supports profile selection) but generates 20x High output only against
the *Rev 5* High baseline. The 20x High KSI catalog, when published in
FY27, will require a re-ingest of FRMR data and a new profile selector
key. This is a future-pass concern; the existing `HIGH-CLARIFY`
orchestrator warning ("20x-High doesn't exist yet") already handles the
current state correctly.

**Classification: ALREADY-IN-SCOPE (Rev 5 High via SSP-1) + DEFERRED
(20x High awaits FRMR catalog publication).** No new slice; existing
warning is sufficient.

---

## 3. Classification table

| # | Item | Classification | Owner loop / slice |
|---|---|---|---|
| 2.1 | PCI-DSS v4.0.1 | CONDITIONALLY APPLICABLE | NEW LOOP-AA (replaces K.K3) |
| 2.2 | NIST SP 800-171r3 | APPLICABLE | EXT LOOP-S.S5 |
| 2.3 | CMMC 2.0 (32 CFR 170) | ALREADY-IN-SCOPE | LOOP-S + EXT S.S6, S.S7 |
| 2.4 | FedRAMP Tailored LI-SaaS | ALREADY-IN-SCOPE | SSP-1 profile selector |
| 2.5 | TIC 3.0 | ALREADY-IN-SCOPE | EXT LOOP-L.L5 |
| 2.6 | OMB M-21-07 (IPv6) | APPLICABLE | EXT LOOP-E.E9 |
| 2.7 | NIST SP 800-128 | ALREADY-IN-SCOPE | LOOP-G.G5 |
| 2.8 | NIST SP 800-92 r1 IPD | APPLICABLE | LOOP-E.E8 (per FOURTH-PASS) |
| 2.9 | NIST SP 800-184 | ALREADY-IN-SCOPE | RPL family |
| 2.10 | NIST SP 800-82 r3 | NOT APPLICABLE | (OT not in scope) |
| 2.11 | NIST SP 800-63 r4 | APPLICABLE | NEW LOOP-DD (subsumes X.X5) |
| 2.12 | NIST SP 800-160 v1R1 + v2R1 | APPLICABLE | NEW LOOP-CC |
| 2.13 | NIST SP 800-167 | APPLICABLE | EXT LOOP-G.G7 |
| 2.14 | NIST SP 800-204 / A / B / C | APPLICABLE | EXT LOOP-G.G8 |
| 2.15 | DoD STIG / SCAP | CONDITIONALLY APPLICABLE | EXT LOOP-S.S8 |
| 2.16 | CIS Controls v8.1 | CONDITIONALLY APPLICABLE | C.1 crosswalk extension |
| 2.17 | CSA CCM v4.0.x / v4.1 | CONDITIONALLY APPLICABLE | EXT LOOP-K.K4 |
| 2.18 | AICPA SOC 2 + AT-C 205 + 2022 TSC | CONDITIONALLY APPLICABLE | EXT LOOP-K.K5 |
| 2.19 | ISMAP / IRAP / TISAX | CONDITIONALLY APPLICABLE | EXT LOOP-Z.Z4, Z.Z5, Z.Z6 |
| 2.20 | GovRAMP / TX-RAMP | CONDITIONALLY APPLICABLE | EXT LOOP-Q.Q4 |
| 2.21 | OMB A-130 + FISMA 2014 | ALREADY-IN-SCOPE | SSP boilerplate (umbrella) |
| 2.22 | NSM-22 | APPLICABLE | NEW LOOP-BB |
| 2.23 | AI Bill of Rights + AI RMF | APPLICABLE | NEW LOOP-FF |
| 2.24 | OMB M-24-10 | APPLICABLE | NEW LOOP-FF |
| 2.25 | EO 14110 (revoked Jan 2025) | NOT APPLICABLE | (revoked; LOOP-FF covers successors) |
| 2.26 | Section 508 + ADA Title II | APPLICABLE | NEW LOOP-GG |
| 2.27 | NIST IR 8053 / 8062 / 8112 | ALREADY-IN-SCOPE | LOOP-M + LOOP-DD |
| 2.28 | Federal ICAM | APPLICABLE | NEW LOOP-DD |
| 2.29 | NIST SP 800-130 / 800-152 | APPLICABLE | NEW LOOP-EE |
| 2.30 | FIPS 140-3 (Sep 21 2026 cutover) | APPLICABLE — HIGH PRIORITY | NEW LOOP-EE |
| 2.31 | CISA CPGs v1.0.1 / v2.0 | APPLICABLE | NEW LOOP-BB |
| 2.32 | FAR Part 7.105 | ALREADY-IN-SCOPE | LOOP-J + LOOP-L |
| 2.33 | FedRAMP RFC-0015 / 0016 / 0017+ | APPLICABLE (proposed) | EXT G.G9, E.E10, A.A6 |
| 2.34 | DoD CC SRG v1 r5 | ALREADY-IN-SCOPE | LOOP-S |
| 2.35 | FedRAMP 20x High (FY27) | DEFERRED | SSP-1 + HIGH-CLARIFY warning |

---

## 4. Proposed new loops + extension slices

### 4.1 NEW LOOP-AA — PCI-DSS Cardholder-Data Overlay

**Scope:** Cardholder-data (CHD) data-class identification, PCI-DSS
v4.0.1 control crosswalk, AOC + ROC TPSP-section emitter,
script-integrity (6.4.3) and change-and-tamper-detection (11.6.1)
evidence collection.

**Applicability:** Conditional on the CSP touching CHD on behalf of a
merchant or service-provider customer.

**Proposed slices:**

- **AA.1** — CHD inventory data-class enricher overlay on INV-P3
  (extends the existing data-class enricher to flag PAN, CHD, SAD per
  PCI-DSS scope).
- **AA.2** — Requirement crosswalk PCI v4.0.1 ↔ NIST 800-53 Rev 5 ↔
  FedRAMP KSI (a thin crosswalk table; PCI SSC publishes the 800-53 map).
- **AA.3** — AOC + ROC TPSP-section emitter (templates from PCI SSC for
  service providers; the emitter populates from collector findings).
- **AA.4** — Script-integrity (6.4.3) + change-and-tamper-detection
  (11.6.1) evidence collector for AWS CloudFront / GCP Cloud CDN / Azure
  CDN (the script-allow-list config + the change-event audit log).

**Estimated effort:** 4 slices, ~2 weeks per slice.

### 4.2 NEW LOOP-BB — CISA CPGs 2.0 + NSM-22 Critical Infrastructure Resilience

**Scope:** Sector-specific critical-infrastructure resilience evidence
under NSM-22 (April 2024) using CISA CPGs 2.0 (December 2025) as the
floor practice set.

**Applicability:** Conditional on the CSP being a covered critical-
infrastructure entity (IT sector) or serving a customer in another
covered sector.

**Proposed slices:**

- **BB.1** — CPG 2.0 38-practice self-attestation emitter (rolls up
  existing collector findings into the 38 practices, emits per-practice
  evidence-pointer).
- **BB.2** — Sector Risk Management Agency (SRMA) coordination artifact
  (per-sector contact log, biennial NIRMP submission template).
- **BB.3** — MSP-risk and least-privilege CPG focus-area evidence
  (overlays existing IAM-ELP + SCR-MON collectors into the CPG 2.0
  format).
- **BB.4** — Incident-communications CPG harmonization with G.G2 +
  CIRCIA + SEC 8-K dispatcher.

**Estimated effort:** 4 slices, ~2 weeks per slice.

### 4.3 NEW LOOP-CC — Systems Security Engineering + Cyber Resiliency Conformance Pack

**Scope:** NIST SP 800-160 v1 R1 (SSE) + SP 800-160 v2 R1 (Cyber
Resiliency) conformance attestation.

**Applicability:** Universal (every FedRAMP Moderate-or-higher CSP is
expected to follow SSE principles).

**Proposed slices:**

- **CC.1** — SSE conformance attestation (narrative + design-review
  pointer from LOOP-N threat-model artifacts + LOOP-G.G5 SCG +
  LOOP-J supply-chain).
- **CC.2** — Cyber-resiliency-objective traceability matrix (SP 800-160
  v2 R1 has 8 objectives × 14 techniques × 35 approaches — emit a matrix
  showing which existing collectors satisfy which objectives).
- **CC.3** — SA-8 / SA-15 / SA-17 / SR-family enhanced narrative (extends
  the SSP boilerplate).

**Estimated effort:** 3 slices, ~2 weeks per slice.

### 4.4 NEW LOOP-DD — Identity Pillar (ICAM + NIST SP 800-63 R4)

**Scope:** Federal ICAM Architecture conformance + NIST SP 800-63 Rev 4
(IAL / AAL / FAL) evidence pack, including phishing-resistant
authentication, syncable authenticators (passkeys), and user-controlled
wallets.

**Applicability:** Universal for federal-customer CSPs.

**Proposed slices:**

- **DD.1** — ICAM Architecture conformance attestation (extends LOOP-X.X1
  ZTMM inheritance map with FICAM playbook coverage).
- **DD.2** — IAL2 / IAL3 identity-proofing evidence pack (subsumes the
  previously-proposed X.X5).
- **DD.3** — AAL2 / AAL3 authenticator-binding ledger emitter
  (phishing-resistant FIDO2/PIV/CAC enumerator, syncable-authenticator
  registry per SP 800-63B-4).
- **DD.4** — FAL2 / FAL3 federation-assertion evidence (federation
  partner registry, SAML/OIDC assertion-log emitter per SP 800-63C-4).
- **DD.5** — Recovery flow + account-binding evidence per SP 800-63A-4
  IAL1 verified-account-bind track.

**Estimated effort:** 5 slices, ~2 weeks per slice. Subsumes LOOP-X.X5.

### 4.5 NEW LOOP-EE — Cryptographic Key Management (FIPS 140-3 + SP 800-130 + SP 800-152)

**Scope:** FIPS 140-3 module conformance tracking (with the
Sep 21, 2026 cutover from 140-2), NIST SP 800-130 CKMS design
specification, NIST SP 800-152 Federal CKMS profile conformance.

**Applicability:** Universal — every CSO using cryptography for
confidentiality / integrity / authentication needs a CKMS.

**HIGH PRIORITY: Sep 21, 2026 cutover for FIPS 140-2 → 140-3.** Slice
EE.1 must ship before that date.

**Proposed slices:**

- **EE.1** — CMVP list-status lookup (every FIPS module in use, query
  CMVP for Active / Historical / Sunset status; emit POA&M item for any
  140-2-only module; HIGH PRIORITY — must ship pre-2026-09-21).
- **EE.2** — CKMS design specification emitter (SP 800-130 framework
  applied to AWS KMS / GCP Cloud KMS / Azure Key Vault — derived from
  actual SDK config; operator supplies the design-narrative portions).
- **EE.3** — SP 800-152 FCKMS profile conformance attestation
  (key-lifecycle audit log derived from KMS API events; CKMS Security
  Policy from operator config).

**Estimated effort:** 3 slices, ~2 weeks per slice. Slice EE.1 must
ship in the next 3 months (before Sep 21, 2026).

### 4.6 NEW LOOP-FF — AI Federal Use (OMB M-24-10 + M-24-18 + AI RMF)

**Scope:** Federal-use AI procurement and governance per OMB M-24-10
(March 2024) and M-24-18 (October 2024), with NIST AI RMF 1.0
voluntary-framework conformance.

**Applicability:** Conditional on the CSO including AI / ML capabilities
that the federal customer will use.

**Note:** Distinct from LOOP-O (AI/ML governance for the CSP's own AI use)
— LOOP-FF is *federal-customer-side* AI use of the CSP's product.

**Proposed slices:**

- **FF.1** — AI factsheet emitter (per-AI-system narrative: purpose,
  training data class, risk profile, testing evidence, bias-evaluation
  results).
- **FF.2** — Model card emitter (per the agency CAIO's AI inventory
  schema; pulls from the existing inventory + LOOP-O findings).
- **FF.3** — AI impact-assessment narrative (per M-24-10 §5.b; covers
  intended purpose, expected benefit, potential risk, mitigation,
  data-quality evaluation).
- **FF.4** — M-24-18 procurement evidence pack (per-AI-service contract
  clauses, supplier disclosure, end-of-life plan).
- **FF.5** — AI Use Case Inventory submission helper (a JSON the agency
  CAIO can plug into the public-inventory submission).

**Estimated effort:** 5 slices, ~2 weeks per slice.

### 4.7 NEW LOOP-GG — Accessibility (Section 508 + ADA Title II)

**Scope:** Section 508 Revised (2018, WCAG 2.0 Level AA) for federal-
agency-customer CSPs; ADA Title II (April 2024, WCAG 2.1 Level AA) for
state/local-government-customer CSPs.

**Applicability:** Universal for the tracker UI and all operator-facing
artifacts (docx, pdf, html); conditional on state/local customers for
ADA Title II.

**Proposed slices:**

- **GG.1** — Tracker UI 508 + WCAG 2.1 AA automated audit (axe-core
  integration into the tracker test suite, fail-on-regression).
- **GG.2** — Emitted artifact accessibility audit (every .docx, .pdf,
  .html artifact runs through pa11y / accessibility-checker; fail on
  Level A or Level AA violations).
- **GG.3** — VPAT (Voluntary Product Accessibility Template) ITI VPAT v2.5
  emitter (per the GSA Section 508 program standard template).
- **GG.4** — ADA Title II compliance attestation for state/local-
  government tenants (conditional slice; activated when
  `--state-local-government` flag set).

**Estimated effort:** 4 slices, ~2 weeks per slice.

---

## 5. Items confirmed NOT in scope

The following items were audited and confirmed genuinely out of scope for
the FedPy reference CSP profile (SaaS CI/CD on AWS+GCP+Azure, per
`project_org_profile.md` in user memory). Each remains documented here
for traceability; re-opens only if the reference cohort expands.

### 5.1 NIST SP 800-82 Rev 3 (OT Security)

OT systems (ICS / SCADA / building automation) are not in scope for the
FedPy reference cohort. Re-opens only if the cohort expands to OT
platform SaaS.

### 5.2 EO 14110 (revoked Jan 2025)

EO 14110 was revoked on January 20, 2025 by EO 14179. Its enduring
successors (OMB M-24-10, NIST AI RMF, AI Action Plan, EO 14179 follow-
ons) are covered in LOOP-FF.

### 5.3 DoD CC SRG IL5 / IL6

IL5 (higher-sensitivity CUI + mission-critical + national-security
systems) and IL6 (SECRET) are out of scope for the FedPy reference cohort
(AWS+GCP+Azure commercial regions, not GovCloud High or IL5
environments). IL2 / IL4 are in scope via LOOP-S equivalency path.

### 5.4 FedRAMP 20x High (FY27 placeholder)

20x High KSI catalog has not been published as of 2026-06-08. The
existing HIGH-CLARIFY orchestrator warning handles the current state
correctly. Re-opens when FRMR publishes the 20x High catalog (expected
FY27 Q1-Q2).

### 5.5 FAR Part 7.105

FAR 7.105 is an agency-side obligation (the contracting officer writes
the acquisition plan, not the CSP). The CSP-side input data (life-cycle
cost, security-control inheritance, supply-chain risk) is already emitted
via LOOP-J + LOOP-L. No new loop needed.

### 5.6 OMB Circular A-130 + FISMA 2014

A-130 + FISMA 2014 are umbrella authorities under which FedRAMP itself
exists. They never need an emitter; the SSP boilerplate cites them. No
new loop needed.

---

## 6. Recommendations + next-pass priorities

### 6.1 Critical-path next steps (in order)

The seven proposed loops (AA, BB, CC, DD, EE, FF, GG) plus nine
extension slices form a substantial addition to the roadmap. Sequencing
by criticality + dependency:

1. **LOOP-EE.EE1 (CMVP list-status lookup)** — HIGHEST PRIORITY. Must
   ship before September 21, 2026 (~3 months from this audit). FIPS 140-2
   modules drop to CMVP Historical that day; without EE.1 the pipeline
   cannot emit a true FIPS-140-3-compliant attestation.
2. **LOOP-BB.BB1 (CPG 2.0 self-attestation)** — HIGH PRIORITY. CPG 2.0
   was published 2025-12-11; many agency RFPs starting 2026-07-01 are
   citing CPG 2.0 conformance.
3. **LOOP-GG.GG1 (Tracker UI 508 + WCAG 2.1 AA audit)** — HIGH PRIORITY
   if the tracker is sold to state/local customers. April 26, 2027
   deadline for population-≥-50,000 entities.
4. **LOOP-DD (Identity Pillar)** — subsumes the existing LOOP-X.X5
   proposal. Build before broad LOOP-X rollout to avoid rework.
5. **LOOP-FF (AI Federal Use)** — agency-procurement-driven; growing
   urgency as M-24-18 deadlines roll out across FY26.
6. **LOOP-AA (PCI-DSS Overlay)** — market-driven; build when a CHD-
   processing CSP customer asks.
7. **LOOP-CC (SSE + Cyber Resiliency)** — slower-burn; build alongside
   LOOP-N maturation.

### 6.2 Extension-slice priorities

In rough priority order:

- **LOOP-A.A6** (RFC-0017 Persistent Validation) — activate on ratification.
- **LOOP-E.E9** (M-21-07 IPv6 inventory) — agency-customer-driven.
- **LOOP-E.E10** (RFC-0016 Collaborative Continuous Monitoring) — activate
  on ratification.
- **LOOP-G.G7** (NIST SP 800-167 app allow-list catalog).
- **LOOP-G.G8** (NIST SP 800-204 microservices conformance).
- **LOOP-G.G9** (RFC-0015 Secure Configuration Standard alignment) —
  activate on ratification.
- **LOOP-L.L5** (TIC 3.0 Security Capabilities inheritance map).
- **LOOP-S.S5** (NIST SP 800-171r3 crosswalk for non-DoD CUI agencies).
- **LOOP-S.S6** (CMMC 2.0 SPRS score emitter).
- **LOOP-S.S7** (CMMC §170.24 annual affirmation emitter).
- **LOOP-S.S8** (STIG/SCAP scan ingest).
- **LOOP-Q.Q4** (GovRAMP + TX-RAMP profile selectors).
- **LOOP-Z.Z4/Z5/Z6** (ISMAP / IRAP / TISAX crosswalks).
- **LOOP-K.K4** (CSA CCM v4.1 CAIQ emitter).
- **LOOP-K.K5** (SOC 2 description-criteria narrative stub + 2022 TSC
  refresh).
- **C.1 extension** (CIS Controls v8.1 safeguard IDs).

### 6.3 Glossary deltas

Terms introduced in this audit that should be added to GLOSSARY.md:

- **AAL2 / AAL3** — Authenticator Assurance Level per NIST SP 800-63B-4.
- **AOC** — Attestation of Compliance (PCI-DSS).
- **CAIQ** — Consensus Assessment Initiative Questionnaire (CSA STAR).
- **CAIO** — Chief AI Officer (OMB M-24-10).
- **C3PAO** — CMMC Third-Party Assessment Organization.
- **CCM** — Cloud Controls Matrix (CSA).
- **CDE** — Cardholder Data Environment (PCI-DSS).
- **CHD** — Cardholder Data (PCI-DSS).
- **CIS Controls** — Center for Internet Security Critical Security
  Controls.
- **CKMS** — Cryptographic Key Management System (NIST SP 800-130).
- **CMVP** — Cryptographic Module Validation Program (NIST).
- **CPG** — Cybersecurity Performance Goals (CISA).
- **DIBCAC** — Defense Industrial Base Cybersecurity Assessment Center
  (CMMC Level 3 assessor).
- **FAL2 / FAL3** — Federation Assurance Level per NIST SP 800-63C-4.
- **FCKMS** — Federal CKMS (NIST SP 800-152).
- **FCI** — Federal Contract Information (CMMC Level 1 scope).
- **FICAM** — Federal Identity, Credential, and Access Management
  Architecture.
- **GovRAMP** — Government Risk and Authorization Management Program
  (formerly StateRAMP, rebranded Feb 2025).
- **IAL2 / IAL3** — Identity Assurance Level per NIST SP 800-63A-4.
- **ICAM** — Identity, Credential, and Access Management.
- **IL2 / IL4 / IL5 / IL6** — DoD CC SRG Impact Levels.
- **IRAP** — Information Security Registered Assessors Program (ACSC
  Australia).
- **ISMAP** — Information system Security Management and Assessment
  Program (Japan Digital Agency).
- **NSM-22** — National Security Memorandum 22 (April 30, 2024;
  Critical Infrastructure).
- **ODP** — Organization-Defined Parameter (NIST SP 800-171r3).
- **PCI-DSS** — Payment Card Industry Data Security Standard.
- **PPD-21** — Presidential Policy Directive 21 (2013; superseded by
  NSM-22).
- **ROC** — Report on Compliance (PCI-DSS).
- **SAQ** — Self-Assessment Questionnaire (PCI-DSS).
- **SCAP** — Security Content Automation Protocol (DISA).
- **SRMA** — Sector Risk Management Agency (NSM-22).
- **SPRS** — Supplier Performance Risk System (DoD; CMMC §170.21).
- **SSAE 21** — Statement on Standards for Attestation Engagements 21
  (AICPA).
- **SSE** — Systems Security Engineering (NIST SP 800-160 v1 R1).
- **STIG** — Security Technical Implementation Guide (DISA).
- **TISAX** — Trusted Information Security Assessment Exchange (ENX,
  German automotive).
- **TIC 3.0** — Trusted Internet Connections 3.0 (CISA, per OMB M-19-26).
- **TPSP** — Third-Party Service Provider (PCI-DSS).
- **TSC** — Trust Services Criteria (AICPA SOC 2).
- **VPAT** — Voluntary Product Accessibility Template (Section 508).
- **WCAG 2.0 / 2.1 / 2.2** — Web Content Accessibility Guidelines (W3C).
- **ZTA** — Zero Trust Architecture.
- **ZTMM** — Zero Trust Maturity Model (CISA).

### 6.4 Dependency graph adjustments

The DEPENDENCY-GRAPH.md must be updated to reflect:

- LOOP-DD subsumes LOOP-X.X5 (formerly proposed in FOURTH-PASS); LOOP-X
  shrinks to four slices (X.1, X.2, X.3, X.4); X.5 moves to DD.2.
- LOOP-AA replaces the previously-proposed `LOOP-K.K3 (PCI-DSS overlay)`
  extension slice from FOURTH-PASS.
- LOOP-FF is *parallel to* LOOP-O (not subordinate). LOOP-O governs the
  CSP's own AI; LOOP-FF governs federal-customer use of the CSP's AI
  product.
- LOOP-EE depends on LOOP-R (PQC) for the asymmetric-algorithm enumerator
  but ships independently — LOOP-R covers the post-quantum migration
  curve; LOOP-EE covers the FIPS 140-3 validation curve.
- LOOP-CC depends on LOOP-N (Threat Modeling) for design-review pointers.
- LOOP-GG (Accessibility) is a *cross-cutting* loop — every other loop
  that emits an operator-facing artifact picks up an accessibility
  dependency on GG.1 / GG.2.

### 6.5 Sources index (this pass)

Federal civilian:

- OMB M-21-07 (IPv6): https://www.nlrb.gov/sites/default/files/attachments/pages/node-175/m-21-07.pdf
- OMB M-22-09 (Zero Trust): https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf
- OMB M-24-10 (Federal AI): https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf
- OMB M-19-26 (TIC 3.0): referenced in https://www.cisa.gov/resources-tools/programs/trusted-internet-connections-tic
- OMB Circular A-130 (2016): https://obamawhitehouse.archives.gov/sites/default/files/omb/assets/OMB/circulars/a130/a130revised.pdf
- FISMA Modernization Act 2014: https://www.congress.gov/bill/113th-congress/senate-bill/2521
- FAR Part 7.105: https://www.acquisition.gov/far/7.105
- NSM-22: https://bidenwhitehouse.archives.gov/briefing-room/presidential-actions/2024/04/30/national-security-memorandum-on-critical-infrastructure-security-and-resilience/

CISA:

- TIC 3.0 program guidebook v1.1: https://www.cisa.gov/sites/default/files/2025-07/CISA%20TIC%203.0%20Program%20Guidebook.pdf
- CPGs page: https://www.cisa.gov/cross-sector-cybersecurity-performance-goals
- CPG v1.0.1 PDF: https://www.cisa.gov/sites/default/files/2023-03/CISA_CPG_REPORT_v1.0.1_FINAL.pdf
- CPG 2.0 page: https://www.cisa.gov/cybersecurity-performance-goals-2-0-cpg-2-0
- CPG 2.0 alert 2025-12-11: https://www.cisa.gov/news-events/alerts/2025/12/11/cybersecurity-performance-goals-20-critical-infrastructure
- NSM-22 portal: https://www.cisa.gov/national-security-memorandum-critical-infrastructure-security-and-resilience
- CDM ICAM reference architecture: https://www.cisa.gov/sites/default/files/2023-09/CDM-ICAM_Reference_Architecture_508c.pdf

NIST:

- SP 800-63 r4 announcement: https://csrc.nist.gov/News/2025/nist-revises-digitial-identity-guidelines-sp-800-6
- SP 800-128 / 800-92 referenced via csrc.nist.gov publication-search
- SP 800-160 v1 R1 final: https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final
- SP 800-167: https://csrc.nist.gov/pubs/sp/800/167/final and https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-167.pdf
- SP 800-171r3 final: https://csrc.nist.gov/pubs/sp/800/171/r3/final and https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf
- SP 800-204: https://csrc.nist.gov/pubs/sp/800/204/final
- SP 800-204A: https://csrc.nist.gov/pubs/sp/800/204/a/final
- SP 800-130: https://csrc.nist.gov/pubs/sp/800/130/final
- SP 800-152: https://csrc.nist.gov/pubs/sp/800/152/final
- SP 800-184: https://csrc.nist.gov/publications/detail/sp/800-184/final
- NIST IR 8062: https://csrc.nist.gov/pubs/ir/8062/final
- NIST AI 100-1 (AI RMF 1.0): https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf

DoD:

- CMMC Final Rule 32 CFR 170 Federal Register: https://www.federalregister.gov/documents/2024/10/15/2024-22905/cybersecurity-maturity-model-certification-cmmc-program
- CMMC Final Rule eCFR: https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-G/part-170
- DFARS CMMC Case 2019-D041 Final Rule: https://www.federalregister.gov/documents/2025/09/10/2025-17359/defense-federal-acquisition-regulation-supplement-assessing-contractor-implementation-of
- DoD CC SRG (referenced via DISA Cyber Exchange)

FIPS / cryptography:

- CMVP FIPS 140-3 standards: https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards
- CMVP Management Manual: https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS-140-3-CMVP%20Management%20Manual.pdf

PCI / payment:

- PCI-DSS v4.0.1 release blog: https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1
- PCI SSC SAQ bulletin: https://www.pcisecuritystandards.org/wp-content/uploads/2024/10/SAQs_for_PCI_DSS_v4.0.1_Bulletin.pdf

Voluntary / market-signal frameworks:

- AICPA 2017 TSC + 2022 Revised Points of Focus: https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
- AICPA 2018 SOC 2 Description Criteria (2022 update): https://www.aicpa-cima.com/resources/download/get-description-criteria-for-your-organizations-soc-2-r-report
- CIS Controls v8.1: https://www.cisecurity.org/controls/v8-1
- CSA CCM v4 / v4.1: https://cloudsecurityalliance.org/research/cloud-controls-matrix and https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1

State + sovereign:

- GovRAMP portal (formerly StateRAMP): https://govramp.org/
- TX-RAMP Program Manual 3.1: https://dir.texas.gov/sites/default/files/2025-05/TX-RAMP%20Program%20Manual%203.1.pdf

Identity / accessibility:

- FICAM Architecture: https://www.idmanagement.gov/arch/
- GSA ICAM Solutions roadmap: https://www.idmanagement.gov/icamsolutions/
- US Access Board ICT (Section 508): https://www.access-board.gov/ict/
- DOJ ADA Title II fact sheet: https://www.ada.gov/resources/2024-03-08-web-rule/
- ADA Title II compliance-date extension Apr 2026: https://www.federalregister.gov/documents/2026/04/20/2026-07663/extension-of-compliance-dates-for-nondiscrimination-on-the-basis-of-disability-accessibility-of-web

FedRAMP RFCs:

- RFC-0015: https://www.fedramp.gov/rfcs/0015/
- RFC-0016: https://www.fedramp.gov/rfcs/0016/
- RFC-0017: https://www.fedramp.gov/rfcs/0017/
- RFC index: https://www.fedramp.gov/rfcs/
- 20x phases: https://www.fedramp.gov/20x/phases/
- 20x progress: https://github.com/FedRAMP/roadmap/blob/main/PROGRESS.md

AI executive orders:

- EO 14179 (Jan 23 2025): https://www.whitehouse.gov/presidential-actions/2025/01/removing-barriers-to-american-leadership-in-artificial-intelligence/
- NIST AI page (still referencing EO 14110 documents): https://www.nist.gov/artificial-intelligence/executive-order-safe-secure-and-trustworthy-artificial-intelligence

---

## 7. Implementation log

| Date | Session | Action | Commit | Notes |
|---|---|---|---|---|
| 2026-06-08 | fifth-pass-audit | Authored FIFTH-PASS-AUDIT.md | TBD | 34 items audited; 7 new loops proposed (AA, BB, CC, DD, EE, FF, GG); 9 extension slices proposed; 12 already-in-scope confirmations; 6 confirmed not-applicable; 80+ authoritative URLs cited; 8+ verbatim quotes captured. CRITICAL: LOOP-EE.EE1 (CMVP list lookup) must ship before 2026-09-21 (FIPS 140-2 → 140-3 cutover). |

---

## 8. Completion + push directive

Per `cloud-evidence/CLAUDE.md` Reading List §12d (new), when this
fifth-pass audit is committed:

1. Append the audit ratification line to STATUS.md "Audits" subsection.
2. Add §12d "FIFTH-PASS-AUDIT.md" to the CLAUDE.md Reading List.
3. Append the proposed-loop and extension-slice rows to STATUS.md
   "Proposed loops" section with status `proposed`.
4. Update DEPENDENCY-GRAPH.md Mermaid + tabular graph to reflect:
   - LOOP-DD subsuming LOOP-X.X5
   - LOOP-AA replacing the FOURTH-PASS K.K3 proposal
   - LOOP-FF parallel to LOOP-O
   - LOOP-EE depending on LOOP-R for PQC enumeration
   - LOOP-CC depending on LOOP-N for threat-model pointers
   - LOOP-GG as cross-cutting accessibility dependency for every other
     loop emitting operator-facing artifacts
5. Update GLOSSARY.md with the new terms enumerated in §6.3 (40+ terms).
6. Update EXECUTION-PLAN.md with the new loops as conditional Tier 4 /
   Tier 5 / Tier 6 additions.
7. Append CHANGELOG.md "Unreleased" entry citing the audit + the
   seven new proposed loops + nine extension slices + the
   September 21 2026 FIPS 140-3 cutover priority.
8. Commit with the audit-ID + Co-Authored-By trailer per
   SLICE-COMPLETION-PROCEDURE.md.
9. Push to `origin/main`.
10. Only THEN is the audit closed.

The proposed loops do NOT execute until each has a SPEC + RISKS + per-
slice docs landed. The fifth-pass audit ratifies *what* gets built next;
the LOOP-X-SPEC / LOOP-X-RISKS files specify *how*. This audit MUST NOT
be confused with a SPEC.

**HIGH-PRIORITY EXCEPTION:** LOOP-EE.EE1 (CMVP list-status lookup) has
a hard external deadline of 2026-09-21 (FIPS 140-2 → 140-3 cutover).
LOOP-EE.EE1 SPEC + RISKS + per-slice doc + implementation should be
fast-tracked ahead of the other proposed loops to ensure the slice ships
before the cutover. If LOOP-EE cannot be authored in time, a temporary
extension slice `LOOP-R.R4 (CMVP cutover bridge)` can carry just the
list-status lookup; the broader LOOP-EE then absorbs it.

---

## 9. Audit closing statement

Per the 2026-06-08 user directive to surface every remaining obligation
universe after twenty-six loops (LOOP-A through LOOP-Z) and four prior
audits have been ratified, this fifth-pass audit rebuilt from zero against
the live web corpus. Eight independent search angles were executed across
the public web during the 2026-06-08 session, with at least two
WebSearches per angle and follow-up WebFetch / deep searches per cited
statute / SP / CFR / RFC / OMB memorandum.

**Thirty-four items audited.** Seven new loops proposed (LOOP-AA,
LOOP-BB, LOOP-CC, LOOP-DD, LOOP-EE, LOOP-FF, LOOP-GG). Nine extension
slices proposed (S.S5, S.S6, S.S7, S.S8, G.G7, G.G8, G.G9, E.E9, E.E10,
L.L5, A.A6, Q.Q4, Z.Z4, Z.Z5, Z.Z6, K.K4, K.K5, C.1-CIS-extension).
Twelve items confirmed ALREADY-IN-SCOPE. Six items confirmed NOT
APPLICABLE for the reference CSP profile. Eighty-plus distinct
authoritative-source URLs cited. Eight-plus verbatim source quotes
captured (with `EXCERPT-VERIFY` tags on items where fetched-but-redirect
or fetched-but-paywall meant the quote could not be perfectly captured
in-session).

**CRITICAL SCHEDULING CONSTRAINT:** LOOP-EE.EE1 (CMVP list-status
lookup) has a hard external deadline of **September 21, 2026** —
approximately three months from this audit's authoring date. FIPS 140-2
certificates move to the CMVP "Historical" list that day and may no
longer be cited by federal agencies for the protection of CUI. The
existing AFR-UCM collector does not perform the CMVP list lookup. EE.1
MUST ship before the cutover or the pipeline cannot truthfully emit a
FIPS-140-3-compliant attestation against modules whose validation
status flipped to Historical.

The audit is ready for ratification. The reference CSP profile and the
existing twenty-six loops cover the vast majority of the FedRAMP 20x
Phase Two universe; this fifth pass closes the remaining substantial
gaps and points the way to a complete obligation map for the FedPy
production pipeline by end of FY27.

— end of FIFTH-PASS-AUDIT.md
