---
slice_id: X.X1
title: Zero Trust Pillar Inventory — OMB M-22-09 / NIST SP 800-207 / CISA ZTMM v2.0 catalog + extractor
loop: X
status: proposed
commit: TBD
completed_date: —
depends_on:
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing pipeline (every X output flows through this)
blocks:
  - X.X2                                # NIST SP 800-207 architecture mapper consumes this catalog
  - X.X3                                # NIST SP 800-207A cloud-native augmentation reads sub-functions from this catalog
  - X.X4                                # CISA ZTMM v2.0 maturity scoring engine reads the rubric from this catalog
  - X.X5                                # PDP/PEP integration evidence collector cross-references sub-functions
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-07
applicable_conditional: false
condition: Any CSP serving federal customers subject to OMB M-22-09 (effective FY 2024 deadline). Universal for federal-customer CSPs because the M-22-09 strategic goals were targeted at every Federal Civilian Executive Branch (FCEB) agency by 2024-09-30, and every FedRAMP authorization that renews or initially authorizes in FY 2026 onward is being evaluated against that post-deadline posture. The slice is therefore *not* gated by a CLI flag — once LOOP-X is active (default-ON for production package builds; see LOOP-X-SPEC.md §1.6) the X.X1 catalog ships unconditionally.
trigger_flag: "--zero-trust"
trigger_env: CLOUD_EVIDENCE_ZERO_TRUST
---

# X.X1 — Zero Trust Pillar Inventory (OMB M-22-09 + NIST SP 800-207 + CISA ZTMM v2.0 catalog + extractor)

> This per-slice doc is **self-contained**. Any future Claude or human
> session can execute X.X1 end-to-end by reading ONLY this file plus
> the per-loop SPEC (`docs/loops/LOOP-X-SPEC.md`) and the REO standard
> (`cloud-evidence/CLAUDE.md`). No prior conversation history required.
>
> The X.X1 catalog is the **single source of truth** for the entire
> LOOP-X loop. X.X2/X.X3/X.X4/X.X5 all consume from it; nothing in
> LOOP-X invents pillars, sub-functions, or stage definitions outside
> what X.X1 publishes. Get this slice right and the rest of the loop is
> straight wiring.

## 1. Mission

X.X1 builds the canonical, federally-sourced Zero Trust pillar catalog
that drives every subsequent slice in LOOP-X. The catalog encodes:

- **5 pillars** from OMB Memorandum M-22-09 (Jan 26, 2022) — Identity,
  Devices, Networks, Applications and Workloads, Data.
- **3 cross-cutting capabilities** from CISA Zero Trust Maturity Model
  v2.0 (Apr 2023) — Visibility and Analytics, Automation and
  Orchestration, Governance.
- **~ 21 sub-functions** distributed across the 5 pillars (the exact
  count is fixed at PDF-mirror time when the implementer cross-checks
  the ZTMM v2.0 PDF; the FOURTH-PASS-AUDIT.md cited "≈ 19" within
  rounding tolerance).
- **4 maturity stages per pillar/capability** — Traditional, Initial,
  Advanced, Optimal — with a verbatim definition of each stage taken
  from the ZTMM v2.0 PDF.
- **Cross-walk** from every sub-function to (a) the NIST SP 800-53
  Rev 5 controls that enforce it, (b) the FedRAMP 20x KSIs that
  evidence it, and (c) the NIST CSF 2.0 subcategories that govern it.
- **Alternate-projection** as the DoD Zero Trust Strategy 7-pillar
  model for DoD-customer CSPs (`zt-pillars-dod-7.json`).

The slice ships three artifacts:

1. `core/zt-pillars-catalog.ts` — typed loader (TypeScript interfaces +
   runtime validator using ajv) that any LOOP-X consumer imports.
2. `data/zt-pillars-omb-m-22-09.json` — the canonical JSON catalog
   snapshot (UTF-8, JCS-canonical, Ed25519-signed via LOOP-A.A5).
3. `scripts/extract-zt-pillars.mjs` — the extractor that walks the four
   mirrored authoritative source PDFs (M-22-09, SP 800-207, SP 800-207A,
   ZTMM v2.0) plus the DoD ZT Strategy PDF and produces the JSON; the
   extractor is re-runnable when CISA publishes ZTMM v2.1 or NIST
   publishes a 207B/207C variant.

X.X1 also persists the catalog into the tracker DB (`zt_pillars_catalog`
table) so the tracker UI's pillar-inventory page (delivered in X.X4)
can render the catalog without re-reading the JSON file on every page
load.

X.X1 does **not**:

- Score any pillar maturity — that is X.X4's job.
- Walk CSP infrastructure to collect evidence — that is X.X2/X.X3/X.X5.
- Emit a POA&M finding — that is X.X4's job (the finding template
  references X.X1's pillar IDs).
- Modify cloud resources — REO Rule 1 forbids the system from acting on
  the operator's behalf on regulated infrastructure.

## 2. Authoritative sources

Every URL accessed 2026-06-07. Verbatim quotes appear in Markdown
blockquotes. Where the live federal source returned a non-200 to
anonymous fetches, the implementer downloads the page or PDF to
`cloud-evidence/docs/sources/zt/` and re-quotes verbatim from the local
copy. The extractor (§7.3) hashes each mirrored source file with
SHA-256 and embeds the hash in the emitted catalog's
`source_provenance[].sha256` field.

### 2.1 OMB Memorandum M-22-09 — Moving the U.S. Government Toward Zero Trust Cybersecurity Principles (Jan 26, 2022)

URL (pinned): https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf
(accessed 2026-06-07; PDF returns HTTP 200 to authenticated browsers;
the implementer mirrors to `docs/sources/zt/M-22-09.pdf` before X.X1
ships and confirms each verbatim quote below from the mirrored PDF.)

Acting OMB Director Shalanda D. Young's cover memorandum, M-22-09, is
the executive-branch implementing document for Section 3 of Executive
Order 14028 "Improving the Nation's Cybersecurity" (May 12, 2021).

§1 — Vision (publicly-reported language; pending PDF mirror
confirmation):

> "This memorandum sets forth a Federal zero trust architecture (ZTA)
> strategy, requiring agencies to meet specific cybersecurity standards
> and objectives by the end of Fiscal Year (FY) 2024 in order to
> reinforce the Government's defenses against increasingly sophisticated
> and persistent threat campaigns. Those campaigns target Federal
> technology infrastructure, threatening public safety and privacy,
> damaging the American economy, and weakening trust in Government."

The five strategic-goal bullets (the five pillars):

> "This strategy envisions a Federal Government where:
>
> - Federal staff have enterprise-managed accounts, allowing them to
>   access everything they need to do their job while remaining
>   reliably protected from even targeted, sophisticated phishing
>   attacks.
> - The devices that Federal staff use to do their jobs are
>   consistently tracked and monitored, and the security posture of
>   those devices is taken into account when granting access to
>   internal resources.
> - Agency systems are isolated from each other, and the network
>   traffic flowing between and within them is reliably encrypted.
> - Enterprise applications are tested internally and externally, and
>   can be made available to staff securely over the internet.
> - Federal security teams and data teams work together to develop
>   data categories and security rules to automatically detect and
>   ultimately block unauthorized access to sensitive information."

These five bullets correspond, in order, to the Identity, Devices,
Networks, Applications and Workloads, and Data pillars. X.X1 records
the verbatim bullet text as the `pillar.mission_statement` field for
each of the five pillars.

§2 — FY 2024 deadline (publicly summarised):

> "Agencies must achieve specific zero trust security goals by the end
> of Fiscal Year (FY) 2024."

X.X1 emits `m22_09_deadline: "2024-09-30"` as a top-level catalog
field; X.X4's scoring engine flags any pillar still at Traditional or
Initial stage past that date as a "post-deadline gap" in the emitted
POA&M finding.

REQUIRES-RESEARCH: the implementer MUST mirror the M-22-09 PDF and
confirm the verbatim text of §II.B (Identity specific actions), §II.C
(Devices), §II.D (Networks), §II.E (Applications and Workloads), and
§II.F (Data) — those five sub-sections feed the catalog's per-pillar
`m22_09_specific_actions[]` arrays. Until the mirror is confirmed,
the extractor sets the field to a `REQUIRES-RESEARCH` placeholder and
the lint guardrail (`scripts/lint-no-stubs.mjs`) rejects the catalog.

### 2.2 NIST SP 800-207 — Zero Trust Architecture (August 2020)

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf
(accessed 2026-06-07; HTTP 200; mirrored to
`docs/sources/zt/NIST.SP.800-207.pdf`.)

Authors: Scott Rose, Oliver Borchert, Stu Mitchell, Sean Connelly.
50 pages. Final, not draft.

§2.1 — Tenets of Zero Trust (the seven tenets that drive X.X2's
architecture mapper and feed X.X1's `tenets[]` array verbatim):

> "1. All data sources and computing services are considered resources.
>     A network may be composed of multiple classes of devices. A network
>     may also have small footprint devices that send data to aggregators
>     (e.g., a coffee maker, smart lighting, networked medical devices)
>     and software as a service (SaaS) sending data to internal users."

> "2. All communication is secured regardless of network location.
>     Network location alone does not imply trust. Access requests from
>     assets located on enterprise-owned network infrastructure (e.g.,
>     inside a legacy network perimeter) must meet the same security
>     requirements as access requests and communication from any other
>     non-enterprise-owned network."

> "3. Access to individual enterprise resources is granted on a per-
>     session basis. Trust in the requester is evaluated before the
>     access is granted. Access should also be granted with the least
>     privileges needed to complete the task."

> "4. Access to resources is determined by dynamic policy — including
>     the observable state of client identity, application/service, and
>     the requesting asset — and may include other behavioral and
>     environmental attributes."

> "5. The enterprise monitors and measures the integrity and security
>     posture of all owned and associated assets."

> "6. All resource authentication and authorization are dynamic and
>     strictly enforced before access is allowed."

> "7. The enterprise collects as much information as possible about the
>     current state of assets, network infrastructure and communications
>     and uses it to improve its security posture."

X.X1 encodes the seven tenets one-to-one in the catalog's `tenets[]`
array. Each catalog pillar carries a `tenet_alignment[]` field — an
integer array naming which tenets the pillar enforces. For example,
the Identity pillar's `tenet_alignment[] = [3, 4, 6]` (per-session
access, dynamic policy on identity, dynamic auth/authz enforcement).

§3.1 — Three ZTA approach variations (publicly summarised, pending
PDF-mirror confirmation):

> "Three variations are presented: (1) ZTA using enhanced identity
> governance; (2) ZTA using micro-segmentation; (3) ZTA using network
> infrastructure and software defined perimeters."

These three variations are encoded as `approach_variants[]` in the
catalog. Each pillar lists which of the three approaches its evidence
supports.

§3.3 — Logical components: PE, PA, PEP:

> "A zero trust architecture is composed of three logical components:
> a Policy Engine (PE) that is responsible for the ultimate decision to
> grant access to a resource for a given subject; a Policy Administrator
> (PA) that establishes and/or shuts down the communication path
> between a subject and a resource; and a Policy Enforcement Point
> (PEP) that is responsible for enabling, monitoring, and eventually
> terminating connections between a subject and an enterprise
> resource."

These three logical components — PE / PA / PEP — drive X.X2 and X.X5,
but X.X1 records them in the catalog's top-level
`architectural_components[]` array so every LOOP-X consumer shares the
same vocabulary. The implementer notes the post-2020 industry shift
from "PE" to "PDP" (Policy Decision Point); X.X1 records both terms
with `synonyms: ["Policy Engine", "Policy Decision Point"]`.

### 2.3 NIST SP 800-207A — A Zero Trust Architecture Model for Access Control in Cloud-Native Applications in Multi-Cloud Environments (September 2023)

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207A.pdf
(accessed 2026-06-07; mirrored to `docs/sources/zt/NIST.SP.800-207A.pdf`.)

X.X1 reads 800-207A primarily to record the cloud-native vocabulary
(service mesh, sidecar proxy, API gateway, SPIFFE workload identity)
in the catalog's `cloud_native_primitives[]` array — X.X3 consumes
that vocabulary to walk k8s clusters.

Scope (publicly summarised):

> "This document provides guidance for realizing an architecture that
> can enforce granular application-level policies while meeting the
> runtime requirements of zero trust architecture (ZTA) for multi-
> cloud and hybrid environments. The platform consists of API gateways,
> sidecar proxies, and application identity infrastructures (e.g.,
> SPIFFE) that can enforce policies irrespective of the location of
> services or applications, whether on-premises or on multiple clouds."

Two-tier policy framework:

> "The guidance recommends the formulation of network-tier and
> identity-tier policies and the configuration of technology
> components (e.g., gateways, infrastructure for service identities,
> authentication, and authorization tokens)."

X.X1 emits `policy_tiers: ["network-tier", "identity-tier"]` so X.X3
can map evidence into the correct tier.

### 2.4 CISA Zero Trust Maturity Model v2.0 (April 2023)

URL (pinned, index page): https://www.cisa.gov/zero-trust-maturity-model
(accessed 2026-06-07; HTTP 200.)
URL (PDF): https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf
(accessed 2026-06-07; mirrored to `docs/sources/zt/ZTMM_v2.0.pdf`.)

40 pages. Supersedes ZTMM v1.0 (Aug 2021). Published April 2023.

Maturity stages (verbatim):

> "The Zero Trust Maturity Model represents a gradient of
> implementation across five distinct pillars, where minor advancements
> can be made over time toward optimization. The pillars include
> Identity, Devices, Networks, Applications & Workloads, and Data.
> These pillars are supported by Visibility and Analytics, Automation
> and Orchestration, and Governance."

> "Each pillar includes general details regarding the following four
> stages of maturity: Traditional, Initial, Advanced, and Optimal."

Each stage's definitional language (publicly summarised; verbatim
quotes recorded at PDF-mirror time):

> "Traditional: Manually configured lifecycles (i.e., from
> establishment to decommissioning) and assignments of attributes
> (security and logging), static security policies, and solutions to
> address pillars with little integration, manual response and
> mitigation deployment, and limited correlation of dependencies,
> logs, and telemetry."

> "Initial: Starting automation of attribute assignment and
> configuration of lifecycles, policy decisions and enforcement, and
> initial cross-pillar solutions with integration of external systems,
> some responsive changes to least privilege after provisioning, and
> aggregated visibility for internal systems."

> "Advanced: Wherever applicable, automated controls for lifecycle and
> assignment of configurations and policies with cross-pillar
> coordination; centralized visibility and identity control;
> policy enforcement integrated across pillars; response to
> pre-defined mitigations; changes to least privilege based on risk
> and posture assessments; and building toward enterprise-wide
> awareness (including externally hosted resources)."

> "Optimal: Fully automated, just-in-time lifecycles and assignments
> of attributes to assets and resources that self-report with dynamic
> policies based on automated/observed triggers; dynamic least
> privilege access (just enough and within thresholds) for assets and
> their respective dependencies enterprise wide; cross-pillar
> interoperability with continuous monitoring; centralized visibility
> with comprehensive situational awareness."

REQUIRES-RESEARCH: the implementer MUST confirm the verbatim text of
each stage definition from pages 5-7 of the mirrored
`ZTMM_v2.0.pdf` before X.X1 ships. The extractor reads the literal
text from the mirrored PDF; mismatched text means the X.X4 scorer
operates on the wrong rubric.

Sub-functions per pillar (catalog target; exact count fixed at
PDF-mirror time):

> "Each pillar includes a list of functions that are common categories
> of activities to which the four-stage maturity progression applies."

The five pillars' sub-functions, as published in ZTMM v2.0:

| Pillar | Sub-functions (per ZTMM v2.0) |
|---|---|
| Identity | Authentication; Identity Stores; Risk Assessments; Access Management; Visibility & Analytics Capability |
| Devices | Policy Enforcement & Compliance Monitoring; Asset & Supply Chain Risk Management; Resource Access; Device Threat Protection |
| Networks | Network Segmentation; Network Traffic Management; Traffic Encryption; Network Resilience |
| Applications & Workloads | Application Access; Application Threat Protection; Accessible Applications; Secure Application Development & Deployment Workflow |
| Data | Data Inventory Management; Data Categorization; Data Availability; Data Access; Data Encryption |

Three cross-cutting capabilities (verbatim):

> "These pillars are supported by Visibility and Analytics, Automation
> and Orchestration, and Governance — three foundations that
> interconnect across each pillar."

Each cross-cutting capability has sub-functions of its own at the same
four maturity stages. X.X1 encodes 5 pillars + 3 cross-cutting
capabilities = 8 top-level entries, each with sub-functions, each
sub-function with a four-stage rubric.

### 2.5 DoD Zero Trust Strategy (November 22, 2022)

URL (pinned): https://dodcio.defense.gov/Portals/0/Documents/Library/DoD-ZTStrategy.pdf
(accessed 2026-06-07; mirrored to `docs/sources/zt/DoD-ZT-Strategy.pdf`.)

The DoD ZT Strategy enumerates **seven** pillars instead of OMB's
five:

> "The DoD Zero Trust Strategy and Roadmap is comprised of seven (7)
> pillars: User; Device; Application & Workload; Data; Network &
> Environment; Automation & Orchestration; Visibility & Analytics."

X.X1 produces an **alternate-projection** JSON file
(`data/zt-pillars-dod-7.json`) that maps the same sub-function UUIDs
into the DoD seven-pillar topology. Each sub-function carries one
UUID across both projections so evidence collected once is scored
under both rubrics.

DoD target attainment levels:

> "DoD Components shall achieve Target Level Zero Trust by FY27 and
> shall plan to achieve Advanced Level Zero Trust capabilities by
> FY32."

REQUIRES-RESEARCH: confirm the mapping between DoD's "Target Level"
and "Advanced Level" and the CISA ZTMM v2.0 four stages. Preliminary
mapping (subject to GC review): DoD Target ≈ CISA Advanced; DoD
Advanced ≈ CISA Optimal. The implementer records the mapping in
the catalog's `dod_tier_mapping{}` object and the X.X4 emitter renders
both labels on the scorecard.

### 2.6 NIST SP 800-53 Rev 5 — control cross-walk anchors

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-07; mirrored as part of pre-existing FedPy catalog
work; SHA-256 confirmed against `docs/sources/NIST.SP.800-53r5.pdf`.)

For X.X1, the cross-walk per pillar (each sub-function lists 1..n
controls):

| Pillar | Principal control families |
|---|---|
| Identity | IA-2 (Identification & Authentication, Organizational Users), IA-5 (Authenticator Management), IA-8 (Identification for Non-Organizational Users), AC-2 (Account Management), AC-3 (Access Enforcement), AC-14 (Permitted Actions Without Identification or Authentication) |
| Devices | CM-7 (Least Functionality), CM-8 (System Component Inventory), CM-10 (Software Usage Restrictions), MA family (Maintenance), SI-2 (Flaw Remediation), SI-4 (System Monitoring), SI-7 (Software, Firmware, and Information Integrity) |
| Networks | SC-7 (Boundary Protection), SC-8 (Transmission Confidentiality and Integrity), SC-23 (Session Authenticity), SC-39 (Process Isolation), AC-4 (Information Flow Enforcement) |
| Applications & Workloads | SA-11 (Developer Testing and Evaluation), SA-15 (Development Process, Standards, and Tools), SA-17 (Developer Security Architecture and Design), SI-3 (Malicious Code Protection) |
| Data | MP family (Media Protection), SC-28 (Protection of Information at Rest), AC-4 (Information Flow Enforcement), AU family (Audit and Accountability) |
| Visibility & Analytics | AU-2 (Auditable Events), AU-6 (Audit Review, Analysis, Reporting), AU-12 (Audit Generation), CA-7 (Continuous Monitoring), SI-4 (System Monitoring) |
| Automation & Orchestration | CM-3 (Configuration Change Control), CM-4 (Security Impact Analysis), IR-4 (Incident Handling), IR-6 (Incident Reporting) |
| Governance | PM-1 (Information Security Program Plan), PM-2 (Senior Information Security Officer), CA-2 (Control Assessments), PL-1 (Security and Privacy Planning Policy) |

X.X1 records each pillar sub-function's NIST control mapping in
`pillar.sub_functions[*].nist_53r5_controls[]`. The mapping uses the
canonical NIST control identifiers (e.g. `"AC-2"`, `"AC-2(7)"`). No
invented controls. No vendor-mapped pseudo-controls.

### 2.7 FedRAMP 20x KSI baseline cross-reference

URL: `cloud-evidence/data/frmr-catalog.json` (in-tree; canonical FRMR
loaded by `core/ksi-map.ts`). KSI identifiers are published by the
FedRAMP PMO; the in-tree catalog carries the canonical IDs.

Per-pillar representative KSIs (drawn from LOOP-X-SPEC.md §2.14):

| Pillar | Representative KSIs |
|---|---|
| Identity | IAM-MFA, IAM-AAM, IAM-APM, IAM-ELP, IAM-JIT, IAM-SNU, IAM-SUS |
| Devices | CMT-LMC, CMT-RMV, CMT-VTD, PIY-GIV (inventory family) |
| Networks | CNA-MAT, CNA-RNT, CNA-ULN, CNA-RVP, CNA-EIS, CNA-IBP, CNA-OFA, CNA-DFP |
| Applications & Workloads | SVC-ASM, SVC-ACM, SVC-EIS, SVC-RUD, SVC-VCM, SVC-VRI, SVC-SNT, SCR-MON |
| Data | SVC-RUD, SVC-VCM, SVC-VRI, MLA-LET |
| Visibility & Analytics | MLA-LET, MLA-OSM, MLA-ALA, MLA-RVL, MLA-EVC, INR-RIR |
| Automation & Orchestration | RPL-ABO, RPL-TRC, RPL-ARP, RPL-RRO, INR-RIR |
| Governance | AFR-PVA, PIY-GIV |

X.X1's catalog emits each sub-function's `ksi_ids[]` array. X.X4's
scorer reads the KSI run output (from
`out/ksi-evaluation-{system-id}.json`) and uses pass/fail state plus
evidence depth to assign a stage.

### 2.8 NIST Cybersecurity Framework 2.0 (February 26, 2024)

URL (pinned): https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
(accessed 2026-06-07; mirrored to `docs/sources/zt/NIST.CSWP.29.pdf`.)

CSF 2.0 introduced a new top-level **Govern (GV)** function:

> "The Govern (GV) Function provides outcomes to inform what the
> organization may do to achieve and prioritize the outcomes of the
> other five Functions in the context of its mission and stakeholder
> expectations. Governance activities are critical for incorporating
> cybersecurity into an organization's broader enterprise risk
> management strategy."

X.X1 cross-walks the Governance cross-cutting capability to CSF 2.0
GV.* subcategories (GV.OC, GV.RM, GV.RR, GV.PO, GV.OV, GV.SC). X.X4
uses CSF 2.0 GV.* identifiers as cross-walk anchors for the
Governance score.

### 2.9 EO 14028 — Improving the Nation's Cybersecurity (May 12, 2021)

URL (pinned): https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
(accessed 2026-06-07.)

§3 — Zero Trust mandate:

> "The Federal Government must adopt security best practices; advance
> toward Zero Trust Architecture; accelerate movement to secure cloud
> services, including Software as a Service (SaaS), Infrastructure as
> a Service (IaaS), and Platform as a Service (PaaS); centralize and
> streamline access to cybersecurity data to drive analytics for
> identifying and managing cybersecurity risks; and invest in both
> technology and personnel to match these modernization goals."

EO 14028 is the executive-action root authority that M-22-09
implements. X.X1 records both citations in the catalog header
(`statutory_basis[]`).

### 2.10 NIST SP 800-63B Rev 4 IPD (and Rev 4 Final once published)

URL (pinned): https://csrc.nist.gov/pubs/sp/800/63/b/4/ipd
(accessed 2026-06-07; HTTP 200; mirrored to
`docs/sources/zt/NIST.SP.800-63B-r4-IPD.pdf`.)

800-63B Rev 4 IPD feeds the Identity pillar's Authentication
sub-function with the AAL1/AAL2/AAL3 vocabulary and the
phishing-resistant MFA definition. X.X1 records the AAL definitions
verbatim in the catalog's `aal_definitions{}` object.

> "Authenticator Assurance Level 1 (AAL1): AAL1 provides some
> assurance that the claimant controls an authenticator bound to the
> subscriber's account."

> "Authenticator Assurance Level 2 (AAL2): AAL2 provides high
> confidence that the claimant controls authenticator(s) bound to the
> subscriber's account."

> "Authenticator Assurance Level 3 (AAL3): AAL3 provides very high
> confidence that the claimant controls authenticator(s) bound to the
> subscriber's account."

REQUIRES-RESEARCH: confirm verbatim AAL definitions from the mirrored
PDF once 800-63B Rev 4 Final ships (still IPD as of 2026-06-07; track
the change at https://csrc.nist.gov/pubs/sp/800/63/b/4/final).

### 2.11 OMB Memorandum M-22-19 — Companion FISMA-reporting memo

URL (pinned): https://www.whitehouse.gov/wp-content/uploads/2022/11/M-22-19.pdf
(accessed 2026-06-07; mirrored to `docs/sources/zt/M-22-19.pdf`.)

Companion to M-22-09. Issued Nov 22, 2022. Establishes the
agency-reporting cadence for FISMA + Zero Trust goals. CSPs are not
directly bound by M-22-19 but agency reporting may require CSP-side
data flows; X.X1 records the reporting cadence so X.X4's emitter can
align scorecard publication timing with the agency's FISMA roll-up
windows.

### 2.12 NSA Cybersecurity Information Sheet — ZTMM v2 supplement

URL (pinned): https://media.defense.gov/2023/Apr/19/2003206448/-1/-1/0/CSI_ZERO_TRUST_MATURITY_MODEL_V2_FINAL.PDF
(accessed 2026-06-07; mirrored to
`docs/sources/zt/NSA-CSI-ZTMM-v2.pdf`.)

NSA's CSI supplementing the CISA ZTMM v2.0. Provides procurement-side
guidance on selecting ZT-capable products. X.X1 cites the CSI as a
supplementary reference in the catalog's
`supplementary_references[]` array (not as a normative source).

## 3. Scope

### 3.1 In scope

- Parsing the four primary federal sources (M-22-09, SP 800-207,
  SP 800-207A, ZTMM v2.0) from mirrored PDFs.
- Parsing the DoD ZT Strategy PDF for the alternate seven-pillar
  projection.
- Building the canonical `core/zt-pillars-catalog.ts` TypeScript
  loader with strict typing + ajv runtime validation.
- Emitting `data/zt-pillars-omb-m-22-09.json` (canonical-JSON,
  Ed25519-signed via LOOP-A.A5).
- Emitting `data/zt-pillars-dod-7.json` (DoD seven-pillar projection,
  shared UUIDs).
- Persisting the catalog into the tracker DB `zt_pillars_catalog`
  table for UI consumption.
- Cross-walking each sub-function to NIST 800-53 Rev 5 controls + 20x
  KSIs + CSF 2.0 GV.* subcategories.
- An extractor script (`scripts/extract-zt-pillars.mjs`) that is
  idempotent and re-runnable when CISA publishes ZTMM v2.1 or NIST
  publishes a 207B/207C variant.
- SHA-256 fingerprint of every mirrored source file embedded in
  `catalog.source_provenance[].sha256`.

### 3.2 Out of scope

- Maturity scoring (X.X4).
- Architecture mapping to PDP/PEP/PA (X.X2).
- Cloud-native augmentation with service mesh + sidecar + SPIFFE
  (X.X3).
- PDP/PEP evidence collection (X.X5).
- Vendor ZT framework mappings (Forrester ZTX, Gartner CARTA/SASE/SSE,
  CSA CCM v4) — X.X1's catalog does NOT include vendor-published
  rubrics.
- TIC 3.0 capability mapping (CISA Capabilities Catalog 3.0) —
  potentially a future LOOP-TIC.
- CDM data feed integration (out of LOOP-X scope per LOOP-X-SPEC.md
  §1.3).
- Operator-defined custom pillars (`policy_overlay.yaml` accepts
  operator-tagged sub-functions only; pillars themselves are
  federally fixed).

## 4. Inputs

### 4.1 Mirrored source PDFs (filesystem)

```typescript
interface MirroredSource {
  /** Stable id used as the key in `catalog.source_provenance{}`. */
  id:
    | "M-22-09"
    | "NIST.SP.800-207"
    | "NIST.SP.800-207A"
    | "ZTMM_v2.0"
    | "DoD-ZT-Strategy"
    | "NIST.SP.800-53r5"
    | "NIST.CSWP.29"
    | "NIST.SP.800-63B-r4-IPD"
    | "M-22-19"
    | "NSA-CSI-ZTMM-v2"
    | "EO-14028";
  /** Absolute path under `cloud-evidence/docs/sources/zt/`. */
  pathAbs: string;
  /** SHA-256 of the file (lowercase hex, 64 chars), computed at extract time. */
  sha256: string;
  /** ISO-8601 date the file was downloaded; from the operator's mirror log. */
  downloadedAt: string;
  /** Canonical URL — used for re-download + audit. */
  canonicalUrl: string;
}
```

### 4.2 Operator overlay (`policy_overlay.yaml`)

```yaml
# Optional; absent means defaults from the federal sources only.
operator_additions:
  - pillar: Identity
    sub_function:
      name: "Continuous Conditional Access Re-evaluation"
      provenance: operator-supplied
      operator_note: |
        Required by our customer agency XYZ tailoring letter dated
        2026-04-02. Maps to AC-3(8) Mandatory Access Control.
      nist_53r5_controls: ["AC-3(8)"]
      ksi_ids: ["IAM-SUS"]
```

Operator additions are tagged `provenance: operator-supplied` in the
catalog so a 3PAO can immediately distinguish federally-sourced from
operator-added entries.

### 4.3 FRMR catalog (in-tree)

`cloud-evidence/data/frmr-catalog.json` — loaded by
`core/ksi-map.ts`. Used to validate that every KSI ID referenced in
`sub_functions[*].ksi_ids[]` actually exists.

### 4.4 Tracker DB connection

Tracker DB pool (existing). X.X1 writes to:

- `zt_pillars_catalog(catalog_version, pillar_id, projection, json_blob, sha256, signed_envelope_path, last_updated)`

## 5. Outputs

### 5.1 Canonical JSON catalog — `data/zt-pillars-omb-m-22-09.json`

JCS-canonical (RFC 8785). UTF-8. Newline-terminated.

```json
{
  "$schema": "https://fedpy.io/schemas/zt-pillars-catalog-v1.json",
  "catalog_version": "1.0.0",
  "catalog_id": "zt-pillars-omb-m-22-09",
  "projection": "omb-m-22-09",
  "generated_at": "2026-06-07T18:00:00Z",
  "statutory_basis": ["eo-14028-sec-3", "omb-m-22-09", "omb-m-22-19"],
  "m22_09_deadline": "2024-09-30",
  "tenets": [
    {
      "n": 1,
      "text": "All data sources and computing services are considered resources..."
    }
  ],
  "approach_variants": [
    "enhanced-identity-governance",
    "micro-segmentation",
    "network-infrastructure-sdp"
  ],
  "policy_tiers": ["network-tier", "identity-tier"],
  "architectural_components": [
    {
      "id": "PE",
      "label": "Policy Engine",
      "synonyms": ["Policy Decision Point", "PDP"],
      "spec_source": "NIST.SP.800-207§3.3"
    },
    { "id": "PA", "label": "Policy Administrator", "synonyms": [], "spec_source": "NIST.SP.800-207§3.3" },
    { "id": "PEP", "label": "Policy Enforcement Point", "synonyms": [], "spec_source": "NIST.SP.800-207§3.3" }
  ],
  "cloud_native_primitives": [
    "service-mesh", "sidecar-proxy", "api-gateway", "spiffe-workload-identity"
  ],
  "maturity_stages": [
    {
      "id": "traditional",
      "label": "Traditional",
      "definition_verbatim": "Manually configured lifecycles..."
    },
    { "id": "initial", "label": "Initial", "definition_verbatim": "..." },
    { "id": "advanced", "label": "Advanced", "definition_verbatim": "..." },
    { "id": "optimal", "label": "Optimal", "definition_verbatim": "..." }
  ],
  "pillars": [
    {
      "id": "identity",
      "label": "Identity",
      "uuid": "00000000-0000-0000-0000-000000000001",
      "mission_statement": "Federal staff have enterprise-managed accounts...",
      "tenet_alignment": [3, 4, 6],
      "m22_09_specific_actions": ["...", "..."],
      "sub_functions": [
        {
          "id": "identity-authentication",
          "uuid": "00000000-0000-0000-0001-000000000001",
          "label": "Authentication",
          "definition_verbatim": "...",
          "nist_53r5_controls": ["IA-2", "IA-2(1)", "IA-2(2)", "IA-5"],
          "ksi_ids": ["IAM-MFA", "IAM-AAM"],
          "csf_v2_subcategories": [],
          "maturity_rubric": {
            "traditional": "Password-based authentication...",
            "initial": "MFA with SMS / TOTP...",
            "advanced": "Phishing-resistant MFA (FIDO2/PIV)...",
            "optimal": "Continuous risk-adaptive AAL3..."
          },
          "aal_anchor": "AAL3"
        }
      ]
    }
  ],
  "cross_cutting_capabilities": [
    { "id": "visibility-analytics", "label": "Visibility and Analytics", "uuid": "...", "sub_functions": [] },
    { "id": "automation-orchestration", "label": "Automation and Orchestration", "uuid": "...", "sub_functions": [] },
    { "id": "governance", "label": "Governance", "uuid": "...", "sub_functions": [] }
  ],
  "dod_tier_mapping": {
    "target_level": "advanced",
    "advanced_level": "optimal"
  },
  "source_provenance": [
    {
      "id": "M-22-09",
      "canonicalUrl": "https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf",
      "pathAbs": "/Users/.../docs/sources/zt/M-22-09.pdf",
      "sha256": "...",
      "downloadedAt": "2026-06-07"
    }
  ],
  "supplementary_references": [
    { "id": "NSA-CSI-ZTMM-v2", "canonicalUrl": "..." }
  ]
}
```

The signed envelope wraps the JSON above per LOOP-A.A5's
`SignedEnvelope` schema; the signed envelope is written to
`out/zt-pillars-omb-m-22-09.signed.json`.

### 5.2 DoD seven-pillar projection — `data/zt-pillars-dod-7.json`

Same schema; `projection: "dod-7"`; pillars renamed and re-grouped per
the DoD ZT Strategy; sub-function UUIDs shared with the OMB
projection. The two files therefore form a join-table over
`sub_function.uuid`.

### 5.3 TypeScript loader — `core/zt-pillars-catalog.ts`

```typescript
import type { SignedEnvelope } from "./envelope.js";
import Ajv from "ajv";

export type Projection = "omb-m-22-09" | "dod-7";

export interface ZtPillarsCatalog {
  catalog_version: string;
  catalog_id: string;
  projection: Projection;
  generated_at: string;
  statutory_basis: string[];
  m22_09_deadline: string;
  tenets: Array<{ n: number; text: string }>;
  approach_variants: string[];
  policy_tiers: ("network-tier" | "identity-tier")[];
  architectural_components: ZtArchComponent[];
  cloud_native_primitives: string[];
  maturity_stages: MaturityStage[];
  pillars: ZtPillar[];
  cross_cutting_capabilities: ZtCrossCuttingCapability[];
  dod_tier_mapping?: { target_level: string; advanced_level: string };
  source_provenance: SourceProvenance[];
  supplementary_references: SupplementaryReference[];
}

export interface ZtPillar {
  id: string;
  label: string;
  uuid: string;
  mission_statement: string;
  tenet_alignment: number[];
  m22_09_specific_actions: string[];
  sub_functions: ZtSubFunction[];
}

export interface ZtSubFunction {
  id: string;
  uuid: string;
  label: string;
  definition_verbatim: string;
  nist_53r5_controls: string[];
  ksi_ids: string[];
  csf_v2_subcategories: string[];
  maturity_rubric: Record<"traditional" | "initial" | "advanced" | "optimal", string>;
  aal_anchor?: "AAL1" | "AAL2" | "AAL3";
  provenance: "federal-published" | "operator-supplied";
  operator_note?: string;
}

export function loadCatalog(path: string, projection: Projection): ZtPillarsCatalog;
export function verifyCatalogSignature(envelopePath: string): boolean;
export function lookupPillar(catalog: ZtPillarsCatalog, id: string): ZtPillar | null;
export function lookupSubFunction(catalog: ZtPillarsCatalog, uuid: string): ZtSubFunction | null;
```

### 5.4 Tracker DB row

```sql
CREATE TABLE zt_pillars_catalog (
  catalog_version TEXT NOT NULL,
  pillar_id       TEXT NOT NULL,
  projection      TEXT NOT NULL CHECK (projection IN ('omb-m-22-09','dod-7')),
  json_blob       JSON NOT NULL,
  sha256          CHAR(64) NOT NULL,
  signed_envelope_path TEXT NOT NULL,
  last_updated    TEXT NOT NULL,
  PRIMARY KEY (catalog_version, pillar_id, projection)
);
```

## 6. Algorithm / Steps

The extractor is deterministic. Given the same input mirrored PDFs
(by SHA-256), it produces byte-identical JSON output every time.

```text
1.  Resolve mirror directory:
        SOURCES_DIR := /Users/.../cloud-evidence/docs/sources/zt
2.  Verify each required mirrored file exists:
        for src in MirroredSource[]:
            assert isFile(SOURCES_DIR + src.id + .pdf|.html)
            src.sha256 := sha256(file)
3.  Parse OMB M-22-09 (PDF -> text via pdf-parse or pdftotext):
        text := readPdfText(M-22-09.pdf)
        pillars[5] := extractFivePillarStatements(text, anchors=§1)
        for p in pillars[5]:
            p.m22_09_specific_actions := extractSpecificActions(text, p.id, anchors=§II.B..F)
4.  Parse NIST SP 800-207 §2.1 tenets verbatim:
        tenets[7] := extractTenets(readPdfText(NIST.SP.800-207.pdf))
5.  Parse NIST SP 800-207 §3.1 approach variants:
        approachVariants[3] := extractApproachVariants(text)
6.  Parse NIST SP 800-207 §3.3 architectural components:
        components[3] := extractArchComponents(text)   // PE, PA, PEP
7.  Parse NIST SP 800-207A cloud-native primitives:
        primitives[*] := extractCloudNativePrimitives(readPdfText(NIST.SP.800-207A.pdf))
8.  Parse CISA ZTMM v2.0:
        ztmm_text := readPdfText(ZTMM_v2.0.pdf)
        maturity_stages[4] := extractMaturityStages(ztmm_text)
        for p in pillars[5]:
            p.sub_functions := extractSubFunctions(ztmm_text, p.id)
            for sf in p.sub_functions:
                sf.maturity_rubric := extractRubric(ztmm_text, p.id, sf.id)
        ccs[3] := extractCrossCutting(ztmm_text)
9.  Parse DoD ZT Strategy:
        dod_text := readPdfText(DoD-ZT-Strategy.pdf)
        dod_pillars[7] := extractDoDSevenPillars(dod_text)
        dod_tier_mapping := extractTierLanguage(dod_text)
10. Cross-walk every sub-function to NIST 800-53 Rev 5 controls:
        for sf in allSubFunctions:
            sf.nist_53r5_controls := lookupCrosswalk(sf.id, NIST_53R5_TABLE)
11. Cross-walk every sub-function to 20x KSIs (read frmr-catalog.json):
        ksi_set := loadFrmrKsiIds()
        for sf in allSubFunctions:
            sf.ksi_ids := lookupCrosswalk(sf.id, KSI_TABLE)
            for ksi in sf.ksi_ids:
                assert ksi in ksi_set    // refuse to ship if KSI does not exist
12. Apply operator overlay (if `policy_overlay.yaml` present):
        overlay := loadYaml('policy_overlay.yaml')
        for add in overlay.operator_additions:
            allocateUuid(add); add.provenance := 'operator-supplied'
            attach(add) under named pillar/sub-function
13. Generate uuids for any new pillars / sub-functions; for existing
    entries reuse the deterministic uuid table seeded by ZTMM v2.0
    sub-function order to keep diffs stable across re-runs.
14. Build CSF 2.0 GV.* cross-walk for the Governance capability:
        gv_set := loadCsfV2('NIST.CSWP.29.pdf')
        attach gv_set.subcategories to cross_cutting_capabilities.governance
15. Build the canonical JSON (JCS, RFC 8785):
        catalog_omb := composeCatalog(projection='omb-m-22-09')
        catalog_dod := composeCatalog(projection='dod-7')   // shares uuids
16. Validate against the JSON Schema (`schemas/zt-pillars-catalog-v1.json`)
    using Ajv strict mode. Refuse to emit on any schema violation.
17. Lint with `scripts/lint-no-stubs.mjs` (in JSON-mode); refuse any
    `REQUIRES-RESEARCH` or `TODO` literal in production-path fields.
    The only allowed-placeholder field is `csf_v2_subcategories` if
    CSF 2.0 mapping is pending — and only when emitted into a
    schema-permitted optional location with provenance tag.
18. Compute SHA-256 of the canonical JSON bytes (for tamper-evidence).
19. Wrap in LOOP-A.A5 SignedEnvelope:
        env := signEnvelope(catalog_json, key=corp_ed25519, kid=corp_key_id)
        attachRfc3161Timestamp(env, tsa=FreeTSA-or-DigiCert)
20. Write atomically:
        atomicWrite('data/zt-pillars-omb-m-22-09.json', catalog_json_omb)
        atomicWrite('data/zt-pillars-dod-7.json',        catalog_json_dod)
        atomicWrite('out/zt-pillars-omb-m-22-09.signed.json', env_omb)
        atomicWrite('out/zt-pillars-dod-7.signed.json',        env_dod)
21. Upsert into tracker DB `zt_pillars_catalog` (one row per pillar
    per projection).
22. Append audit log entry: actor=extractor, action=catalog-emit,
    catalog_version, sha256, signed_envelope_path.
23. Exit 0 on success; non-zero on any failure (Ajv mismatch, missing
    mirror file, KSI not in FRMR, signing failure, tracker write).
```

REO Rule 1: every byte in the emitted catalog traces to a mirrored
federal source file (M-22-09, 800-207, 800-207A, ZTMM v2.0, DoD ZT
Strategy, 800-53r5, CSWP.29, EO 14028) or to operator-supplied data
tagged `provenance: operator-supplied`. No invented pillar. No
invented sub-function. No invented control. No invented KSI. Lint
guardrail enforces.

## 7. Files to create / modify

Absolute paths under `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/`:

### 7.1 New files

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/zt-pillars-catalog.ts` — typed loader + ajv validator + envelope verifier; ~ 350 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-zt-pillars.mjs` — extractor (PDF parse + cross-walk + signing); ~ 600 LOC. Executable; shebang `#!/usr/bin/env node`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/schemas/zt-pillars-catalog-v1.json` — JSON Schema 2020-12 for the catalog; ~ 250 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/zt-pillars-omb-m-22-09.json` — generated catalog (committed; deterministic from mirrors).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/zt-pillars-dod-7.json` — DoD projection (committed; deterministic).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/zt/M-22-09.pdf` — mirrored OMB memo.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/zt/NIST.SP.800-207.pdf` — mirrored.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/zt/NIST.SP.800-207A.pdf` — mirrored.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/zt/ZTMM_v2.0.pdf` — mirrored.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/zt/DoD-ZT-Strategy.pdf` — mirrored.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/zt/M-22-19.pdf` — mirrored.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/zt/NIST.CSWP.29.pdf` — mirrored (CSF 2.0).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/zt/NIST.SP.800-63B-r4-IPD.pdf` — mirrored.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/zt/NSA-CSI-ZTMM-v2.pdf` — mirrored.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/zt-pillars-catalog.test.ts` — unit + integration tests; ≥ 15 specs.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/zt/policy_overlay.minimal.yaml` — minimal overlay fixture.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/zt/zt-pillars-omb-m-22-09.expected.json` — golden file for output snapshot.

### 7.2 Modified files

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/db/migrations/20260607_create_zt_pillars_catalog.sql` — new migration creating the table from §5.4.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/package.json` — add `"extract:zt-pillars": "node scripts/extract-zt-pillars.mjs"` to scripts.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/lint-no-stubs.mjs` — allowlist `csf_v2_subcategories: []` placeholder in `data/zt-pillars-*.json` only.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` — flip X.X1 row to `done` at completion.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-X-SPEC.md` — flip §3 X.X1 row + §12 status table to `done` at completion.
- `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md` — append "Unreleased" entry.

### 7.3 Extractor (`scripts/extract-zt-pillars.mjs`) implementation notes

- Uses `pdf-parse` (npm) for PDF -> text. Falls back to invoking
  `pdftotext` (poppler-utils) if `pdf-parse` cannot parse a given
  mirrored PDF (some federally-published PDFs use non-standard fonts).
- Uses `js-yaml` for the operator overlay.
- Uses `ajv` v8 strict mode for schema validation.
- Uses `@noble/ed25519` (already in the tree via LOOP-A.A5) for
  Ed25519 signing.
- Uses the existing `core/canonical-json.ts` (RFC 8785 JCS) for
  canonical serialization.

## 8. Test specifications

Fixtures live under `test/fixtures/zt/`. Snapshot files live under
`test/fixtures/zt/snapshots/`.

| id    | scenario                                                                          | fixture path                                                                  | expected                                                                              | acceptance |
|-------|-----------------------------------------------------------------------------------|-------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|------------|
| T01   | Happy path — all six mirrored PDFs present + valid                                | `test/fixtures/zt/mirrors-valid/`                                              | catalog_omb.json + catalog_dod.json emitted; both pass ajv validate                  | exit 0; both files present; byte-equal to golden snapshot |
| T02   | Missing M-22-09 PDF                                                               | `test/fixtures/zt/mirrors-missing-m2209/`                                      | extractor exits non-zero with diagnostic naming the missing file                     | exit ≠ 0; stderr contains "M-22-09.pdf"; no catalog emitted |
| T03   | M-22-09 PDF SHA-256 changed (tampered)                                            | `test/fixtures/zt/mirrors-tampered-m2209/`                                     | extractor refuses to emit; SHA-256 mismatch diagnostic                                | exit ≠ 0; stderr contains "sha256 mismatch" |
| T04   | All seven NIST 800-207 tenets extracted verbatim                                  | `test/fixtures/zt/mirrors-valid/`                                              | catalog.tenets[].length === 7; each text matches golden                              | snapshot match against `tenets.golden.json` |
| T05   | All five OMB pillars present                                                      | `test/fixtures/zt/mirrors-valid/`                                              | catalog.pillars[].length === 5; ids = identity, devices, networks, apps, data        | array equality with golden |
| T06   | All three cross-cutting capabilities present                                      | `test/fixtures/zt/mirrors-valid/`                                              | catalog.cross_cutting_capabilities[].length === 3                                     | exact array match |
| T07   | All four maturity stages present + verbatim                                       | `test/fixtures/zt/mirrors-valid/`                                              | catalog.maturity_stages[].length === 4; labels = Traditional/Initial/Advanced/Optimal | snapshot match |
| T08   | Sub-function count matches ZTMM v2.0 (21 ± 1)                                     | `test/fixtures/zt/mirrors-valid/`                                              | sum(pillar.sub_functions.length) in [19,21]                                          | assertion within tolerance |
| T09   | KSI cross-walk references existing KSIs only                                      | `test/fixtures/zt/mirrors-valid/` + `data/frmr-catalog.json`                   | every ksi_id in catalog ∈ frmr-catalog.json                                          | set-difference == ∅ |
| T10   | NIST 800-53 r5 controls valid identifiers                                         | `test/fixtures/zt/mirrors-valid/`                                              | every control id matches /^[A-Z]{2}-\d+(\(\d+\))?$/                                    | regex match for all |
| T11   | DoD projection shares sub-function UUIDs with OMB projection                      | `test/fixtures/zt/mirrors-valid/`                                              | for every sub_function uuid in omb, present in dod                                   | set-equality |
| T12   | Operator overlay augments the catalog correctly                                   | `test/fixtures/zt/policy_overlay.minimal.yaml`                                  | added sub-function appears under named pillar with provenance=operator-supplied      | object lookup + tag check |
| T13   | Operator override naming an unknown pillar fails                                  | `test/fixtures/zt/policy_overlay.bad-pillar.yaml`                              | extractor exits non-zero; diagnostic names invalid pillar id                         | exit ≠ 0; stderr substring "unknown pillar" |
| T14   | Schema validation rejects missing required field                                  | hand-edited catalog with `pillars[0].label` removed                            | ajv error pointing at `.pillars[0].label`                                            | ajv error path string match |
| T15   | Signed envelope verifies under known public key                                   | golden envelope under fixtures                                                 | `verifyCatalogSignature()` returns true                                              | bool true |
| T16   | Signed envelope fails under wrong public key                                      | golden envelope + wrong pubkey                                                  | `verifyCatalogSignature()` returns false                                             | bool false |
| T17   | RFC 3161 timestamp token attached + parseable                                     | golden envelope                                                                | env.tstoken parses; `tsa.signingTime` within last 365 days                           | parse success; date assertion |
| T18   | Lint guardrail blocks `REQUIRES-RESEARCH` literal in production-path catalog field | catalog with synthetic `m22_09_specific_actions: ["REQUIRES-RESEARCH"]`         | `lint-no-stubs.mjs` exits non-zero                                                    | exit ≠ 0 |
| T19   | Lint guardrail allows empty `csf_v2_subcategories: []`                             | catalog with empty cross-walk array                                            | `lint-no-stubs.mjs` exits 0                                                           | exit 0 |
| T20   | Tracker DB upsert is idempotent on repeated extractor runs                        | in-memory SQLite                                                               | second run produces same row count as first                                          | rowcount equality |
| T21   | Re-run with same mirrors produces byte-identical JSON                              | `test/fixtures/zt/mirrors-valid/`                                              | sha256(run1) === sha256(run2)                                                         | digest equality |
| T22   | Coverage report registers the catalog as a covered emit-source                    | `out/inventory-coverage.json`                                                  | new entry `zt_pillars_catalog: { fill_rate: 1.0 }`                                    | JSON field present |

≥ 15 test specs satisfied (22 above; T-numbers contiguous).

## 9. Risks

| id   | risk                                                                                                                                                       | impact   | likelihood | mitigation                                                                                                                                                                       |
|------|------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| R01  | **PDF parsing fragility.** ZTMM v2.0 + M-22-09 use multi-column layouts; pdf-parse may concatenate columns wrongly and corrupt verbatim extraction.         | High     | Medium     | Mirror PDFs locally; checksum each; use pdf-parse + pdftotext fallback; ship golden-snapshot tests (T04, T05, T07) that fail on any text drift; run extractor manually before merge. |
| R02  | **CISA publishes ZTMM v2.1 mid-implementation.** Sub-function set changes; existing UUIDs may no longer line up.                                            | Medium   | Low        | Catalog carries `catalog_version` semver; extractor allocates UUIDs deterministically from sub-function ID strings so v2.1 additions get new UUIDs without disturbing existing ones; X.X4 carries forward old maturity_rubric for v2.0 entries during transition. |
| R03  | **Operator overlay introduces a pillar that conflicts with future federal sources.** Operator may name a sub-function that CISA later names differently in v2.1, causing diff churn. | Medium   | Medium     | Operator additions ALWAYS tagged `provenance: operator-supplied`; never overwrite a federal-published entry; on conflict, federal wins and overlay entry is preserved with `superseded_by` link. |
| R04  | **NIST 800-53 r5 control mapping drift.** Future NIST control revisions (rev 6) may renumber controls; existing mappings become stale.                       | Low      | Medium     | Pin to Rev 5; track rev 6 final publication; provide an override map `data/zt-pillars-control-overrides.yaml` consumed at extract time; loud diagnostic on unknown control ID.   |
| R05  | **Signing key compromise.** If the corporate Ed25519 signing key (kid=corp) is compromised, every emitted catalog signature is suspect.                      | High     | Low        | Key lives in 1Password; signing requires session unlock; CHANGELOG entry on every key rotation; tracker audit log records kid + creation time + holder per LOOP-A.A5.            |
| R06  | **DoD seven-pillar projection mismatches OMB five-pillar projection.** Sub-function UUIDs that should be shared may diverge if extraction logic isn't careful. | Medium   | Medium     | T11 enforces UUID set-equality between projections; CI runs T11 on every PR; extractor uses one shared UUID-allocation step (Step 13 in §6) before splitting into projection-specific JSON. |
| R07  | **PDF mirror disappears from federal site.** WhiteHouse.gov / CISA.gov / NIST.gov may relocate or remove a PDF; future re-runs of the extractor fail.        | Medium   | Low        | Mirror committed to `docs/sources/zt/` in the repo; SHA-256 in catalog; if upstream URL 404s the extractor still works against the local mirror.                                  |

≥ 4 risks satisfied (7 above).

## 10. Open questions

1. **Q1 — Sub-function count tolerance.** The FOURTH-PASS-AUDIT.md
   said "≈ 19 sub-functions". The table in §2.4 of this doc lists 22
   sub-functions (5+4+4+4+5). Confirm the exact count from the
   mirrored ZTMM v2.0 PDF at extract time; update T08 tolerance and
   §2.4 table to match.
2. **Q2 — CSF 2.0 Govern (GV) cross-walk fidelity.** Should the
   Governance cross-cutting capability cross-walk to ALL six CSF 2.0
   GV.* subcategories (OC/RM/RR/PO/OV/SC) or only a relevant subset?
   Engage the operator's GRC team for ratification before extractor
   ships.
3. **Q3 — DoD tier mapping confirmation.** Section 2.5 above proposed
   DoD Target ≈ CISA Advanced and DoD Advanced ≈ CISA Optimal. Confirm
   from the DoD ZT Strategy mirrored PDF and from the DoD CIO ZT
   Capability Execution Roadmap.
4. **Q4 — Should the catalog include a "Visibility & Analytics
   Capability" sub-function under the Identity pillar AS WELL AS the
   cross-cutting capability of the same name?** ZTMM v2.0 lists
   "Visibility & Analytics Capability" inside the Identity pillar's
   sub-functions. Decide whether to dedup or carry both with a
   `dedup_partner_uuid` link.
5. **Q5 — Operator overlay versioning.** Should the overlay carry its
   own version vector so a 3PAO can see which overlay was active for
   a given scorecard run? Likely yes; add
   `overlay.version_id: string`.
6. **Q6 — When CSF 2.0 cross-walk is unknown.** Some sub-functions
   may not have a clean CSF 2.0 GV.* anchor. Currently the schema
   permits an empty array. Should the lint guardrail mark empty arrays
   as "missing cross-walk" and require explicit `null`-with-reason?
7. **Q7 — Public catalog publication.** Should this catalog be
   published publicly (e.g. as a fedpy.io asset under
   Apache-2.0) so other vendors can reuse the cross-walk, or remain
   internal to the operator? Discuss with GC.

## 11. REQUIRES-OPERATOR-INPUT

| Field name                       | Type     | Validator                                            | UI location                                                       | Failure mode if missing                                                            |
|----------------------------------|----------|------------------------------------------------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------|
| `signing.key_id`                 | string   | `/^[a-z0-9-]{3,64}$/`                                 | Tracker UI → Settings → Signing Keys                              | Extractor exits non-zero; envelope cannot be signed                                |
| `signing.holder_email`           | string   | RFC 5321 email validator                              | Tracker UI → Settings → Signing Keys                              | Extractor exits non-zero; provenance incomplete                                    |
| `tsa.url`                        | URL      | starts with `https://`                                | Tracker UI → Settings → Time-Stamping Authority                   | Falls back to FreeTSA; logs a `coverage:miss` warning                              |
| `policy_overlay.yaml` (optional) | YAML doc | schema in `schemas/zt-policy-overlay-v1.json`         | Repo path `cloud-evidence/policy_overlay.yaml`                    | Extractor proceeds with federal sources only; no operator additions                |
| `dod_customer_flag`              | bool     | true/false                                            | Tracker UI → Settings → Customer Type                             | If false, DoD projection is still emitted but tracker UI hides DoD pillar columns  |
| `agency_tailoring_note` (opt.)   | string   | free-form, ≤ 2000 chars                              | Tracker UI → Settings → Agency Tailoring                          | Catalog ships without the note; X.X4 scorecard renders without agency-specific footer |
| `mirror_download_log.json`       | JSON     | schema in `schemas/mirror-download-log-v1.json`        | Repo path `cloud-evidence/docs/sources/zt/mirror_download_log.json` | Extractor refuses to proceed; mirrors not traceable to a download event           |
| `csf_v2_cross_walk_ratification` | bool     | true/false                                            | Tracker UI → Settings → CSF Cross-walk                            | Catalog ships with empty `csf_v2_subcategories[]`; X.X4 Governance score lower    |

## 12. Implementation log

| date       | session    | action                                                                   | commit | notes |
|------------|------------|--------------------------------------------------------------------------|--------|-------|
| 2026-06-07 | wf-uvxyz   | spec proposed — Specification authored via FedPy workflow                | TBD    | —     |

## 13. Completion checklist

Quote of `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` (7 steps,
verbatim):

> ### Step 1 — Verify the slice is REO-compliant
> Run all three guardrails. They MUST all be green:
> ```bash
> cd cloud-evidence
> npm run typecheck      # no errors
> npm test               # 100% passing (counts must increase by the slice's new tests)
> npm run check:reo      # G1+G2+G3 all green
> ```

> ### Step 2 — Update STATUS.md
> Open `cloud-evidence/docs/STATUS.md` and for the slice that just shipped:
> - Change `Status` column from `pending` to `done`
> - Fill `Commit` with the PENDING commit's short hash (you'll know it after step 5)
> - Fill `Date` with today's date (ISO format YYYY-MM-DD)
> - If this was the last slice in a loop, change the loop's title section to indicate "(COMPLETE)"
> - Update the "Overall" section: increment loops-complete, change last-shipped, update next-priority

> ### Step 3 — Update the loop's spec doc
> Open `cloud-evidence/docs/loops/LOOP-X-SPEC.md` (where X is your loop letter).
> Find the "Status tracking" section table.
> For your slice row: status=done, commit=<hash>, date=<ISO>.

> ### Step 4 — Add CHANGELOG entry
> Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
> Add a new entry at the TOP of "Unreleased":
>
> ### Added — LOOP-X.XN: <Slice title>
> <2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>

> ### Step 5 — Commit
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
> git commit -m "LOOP-X.XN: <slice title>
> <detailed commit message describing the slice>
> Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
> ```

> ### Step 6 — Update commit hash in STATUS.md + loop spec
> Now that the commit exists, get its hash:
> ```bash
> git log -1 --format=%h
> ```
> Open STATUS.md + the loop's spec doc — paste the actual commit hash in the rows you updated in step 2+3.
> Amend the commit:
> ```bash
> git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md
> git commit --amend --no-edit
> ```

> ### Step 7 — Push
> ```bash
> git push origin main
> ```

> **Step 8: After commit lands, append/update the slice row in STATUS.md (status -> done, commit hash, last_updated); update the loop SPEC status table; append a CHANGELOG entry; push to origin/main; verify with 'git log --oneline -3'. Only THEN is the slice closed.**

---

End of X.X1 per-slice specification.
