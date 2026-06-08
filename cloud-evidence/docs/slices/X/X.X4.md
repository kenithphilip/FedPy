---
slice_id: X.X4
title: CISA ZTMM v2.0 Maturity Scoring + signed .docx / .pdf / .json scorecard emitter + tracker UI maturity-progress pane
loop: X
status: proposed
commit: TBD
completed_date: —
depends_on:
  - X.X1                                # signed pillar catalog (data/zt-pillars-omb-m-22-09.json + data/zt-pillars-dod-7.json)
  - X.X2                                # signed 800-207 architecture map (data/zt-800-207-architecture.json)
  - X.X3                                # signed 800-207A cloud-native augmentation (data/zt-800-207a-cloud-native.json)
  - LOOP-A.A4                           # Submission bundler — scorecard + .docx + .pdf added as bundle roles
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing pipeline (signEnvelope())
  - LOOP-A.A1                           # OSCAL POA&M emitter — "ZT pillar below target stage" finding template
  - LOOP-A.A2                           # OSCAL Assessment Plan — scoring methodology recorded in AP
  - LOOP-A.A3                           # OSCAL Assessment Results — scorecard registered in AR
  - LOOP-B.B1                           # composite risk scoring — picks up X.X4 POA&M items
  - LOOP-INV-P1                         # inventory backbone — sub-function evidence pointers reference assets[]
  - LOOP-E.E1                           # k8s collector — provides NetworkPolicy + admission-webhook evidence
  - LOOP-E.E2                           # SBOM + cosign — provides Applications/Workloads workload-identity evidence
  - LOOP-J.J3                           # OCI cosign + Rekor — image-provenance evidence for Applications/Workloads pillar
  - LOOP-INR-RIR                        # Incident Response evidence feeds Governance cross-cutting score
blocks: []
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: true
condition: Universal for any CSP using LOOP-X. Whenever LOOP-X is active (default-ON for any FedRAMP-targeting build per LOOP-X-SPEC §1.6), X.X4 MUST execute. The slice is the operational fulcrum of LOOP-X — X.X1/X.X2/X.X3 supply inputs; X.X5 supplies cross-validation evidence; but only X.X4 produces the signed scorecard artefact set that 3PAOs and Authorizing Officials consume during the authorization review and that LOOP-Q.Q1 surfaces on the FedRAMP Marketplace badge.
trigger_flag: "--zero-trust"
trigger_env: CLOUD_EVIDENCE_ZERO_TRUST
---

# X.X4 — CISA ZTMM v2.0 Maturity Scoring + signed scorecard emitter

> This per-slice doc is the SINGLE entry point for any future Claude
> session or human implementer who is told "continue with X.X4". It
> carries every authoritative quote, every algorithm step, every
> schema field, every test specification, every risk, and every
> operator-input requirement needed to execute the slice without
> referring to prior conversation history. The doc is intentionally
> exhaustive — under the REO standard nothing may be assumed or
> inferred. If a future change to ZTMM v2.x or M-22-09 or 800-207
> invalidates a quote here, the implementer MUST update this file in
> the same commit that ships the corrected code.
>
> Read order for a fresh session:
> 1. `cloud-evidence/CLAUDE.md` (REO rules + 7-step completion procedure)
> 2. `cloud-evidence/docs/STATUS.md` (confirm X.X1+X.X2+X.X3 are done)
> 3. `cloud-evidence/docs/loops/LOOP-X-SPEC.md` (loop context)
> 4. THIS FILE (X.X4) — body + implementation log
> 5. `cloud-evidence/docs/loops/LOOP-X-RISKS.md`
> 6. `cloud-evidence/docs/IMPLEMENTATION-LOG-TEMPLATE.md`
> 7. `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`

## 1. Mission

X.X4 is the **maturity-scoring engine** of LOOP-X. It joins (a) the
signed pillar catalog produced by X.X1, (b) the signed 800-207
architecture map produced by X.X2, (c) the signed 800-207A cloud-
native augmentation produced by X.X3, and (d) the latest run outputs
of every Key Security Indicator (KSI) collector in the
`cloud-evidence/providers/{aws,gcp,azure,k8s}/` tree, and produces a
per-pillar + per-cross-cutting-capability **maturity score** matching
the four-stage rubric (Traditional / Initial / Advanced / Optimal)
defined in CISA Zero Trust Maturity Model v2.0 (April 2023). The score
is rendered into three artefacts that share identical evidentiary
content: a canonical-JSON signed envelope, an OOXML/zip-store `.docx`
suitable for AO sign-off / 3PAO redlining, and a one-page `.pdf`
summary suitable for inclusion in the FedRAMP submission bundle's
cover-letter pack. Each artefact carries a SHA-256 content hash, an
Ed25519 detached signature, an RFC 3161 trusted timestamp token, and
a fully traceable evidence-pointer index so that any individual stage
assignment can be drilled back to the underlying SDK call, k8s API
response, cosign attestation, KSI run output, or operator-supplied
configuration row that justified it.

X.X4 also emits **OSCAL POA&M items** for any pillar or cross-cutting
capability whose computed stage is **below** the operator-configured
`stage_target` (default = Advanced; configurable per pillar in
`zt-config.yaml` per LOOP-X-SPEC §17.1). Each POA&M item is composed
through the existing `core/oscal-poam.ts` emitter (LOOP-A.A1) and
picked up by `core/risk-score.ts` (LOOP-B.B1) for composite-risk
scoring. The POA&M item title is templated as `"ZT <pillar> pillar
below target stage = <target> (current = <current>)"`; the body
enumerates the failing sub-functions with verbatim ZTMM v2.0 stage
criteria, the gap evidence (e.g. "8 of 80 namespaces lacking default-
deny NetworkPolicy" or "TOTP MFA detected on 12 IAM users instead of
required FIDO2/WebAuthn for Advanced stage"), and the remediation
references back to the relevant NIST 800-53 Rev 5 control IDs that
LOOP-X.X1's catalog cross-walks.

X.X4 **does not** auto-remediate, auto-sign on behalf of the AO, or
emit a marketing-grade "we are Zero Trust" claim. Per REO Rule 10,
sign-off is a human action captured in the tracker UI (operator
officer ID + TOTP + timestamp + signed audit log entry). The
scorecard's officer-attestation page lists the four-stage outcome and
requires the operator to (a) acknowledge each per-pillar score and
(b) attest that no contrary evidence has been suppressed. Only after
operator sign-off does the scorecard graduate from "draft" to "signed
+ published" in the tracker DB, the LOOP-A.A4 submission bundler picks
it up, the LOOP-Q.Q1 Marketplace badge is updated, and the LOOP-I
executive dashboard tile refreshes.

X.X4 is the **operational fulcrum** of LOOP-X. Without X.X4 the loop
produces only raw evidence (X.X1 catalog + X.X2 architecture +
X.X3 cloud-native augmentation + X.X5 PDP/PEP envelope) that a 3PAO
would otherwise have to manually score. X.X4 mechanises the scoring,
locks the rubric to the federally-published authoritative sources,
and produces an artefact that the FedRAMP PMO and AOs can verify
cryptographically.

## 2. Authoritative sources

Every URL accessed 2026-06-08 (date check at slice-implementation
time per LOOP-X-SPEC §21). Verbatim quotes appear in Markdown
blockquotes. PDFs are mirrored to `cloud-evidence/docs/sources/zt/`
before X.X4 ships; the implementer re-runs each `WebFetch` to confirm
the quote is unchanged from the mirrored PDF.

### 2.1 CISA Zero Trust Maturity Model v2.0 (April 2023) — the authoritative scoring rubric

URL (HTML landing): https://www.cisa.gov/zero-trust-maturity-model
(accessed 2026-06-08).
URL (PDF): https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf
(accessed 2026-06-08; mirrored to `docs/sources/zt/ZTMM_v2.0.pdf`).

**Executive summary — five pillars + three cross-cutting capabilities (verbatim, page 1):**

> "The Zero Trust Maturity Model is one of many roadmaps that
> agencies can reference as they transition towards a zero trust
> architecture. CISA's Zero Trust Maturity Model has been refined to
> include a fourth stage of maturity in addition to those listed in
> the previous version. CISA's Zero Trust Maturity Model represents
> the five pillars of zero trust: Identity, Devices, Networks,
> Applications & Workloads, and Data. These pillars are supported by
> Visibility and Analytics, Automation and Orchestration, and
> Governance — three foundations that interconnect across each
> pillar."

**Four maturity stages (verbatim, pages 5-7):**

> "Each pillar includes general details regarding the following four
> stages of maturity: Traditional, Initial, Advanced, and Optimal."

> "Traditional: Manually configured lifecycles (i.e., from
> establishment to decommissioning) and assignments of attributes
> (security and logging) to assets and resources; static security
> policies and solutions that address one pillar at a time with
> discrete dependencies on external systems; least privilege
> established only at provisioning; siloed pillars of policy
> enforcement; manual response and mitigation deployment; and limited
> correlation of dependencies, logs, and telemetry."

> "Initial: Starting automation of attribute assignment and
> configuration of lifecycles, policy decisions and enforcement, and
> initial cross-pillar solutions with integration of external systems;
> some responsive changes to least privilege after provisioning; and
> aggregated visibility for internal systems."

> "Advanced: Wherever applicable, automated controls for lifecycle
> and assignment of configurations and policies with cross-pillar
> coordination; centralized visibility and identity control; policy
> enforcement integrated across pillars; response to pre-defined
> mitigations; changes to least privilege based on risk and posture
> assessments; and building toward enterprise-wide awareness
> (including externally hosted resources)."

> "Optimal: Fully automated, just-in-time lifecycles and assignments
> of attributes to assets and resources that self-report with dynamic
> policies based on automated/observed triggers; dynamic least
> privilege access (just-enough and within thresholds) for assets
> and their respective dependencies enterprise-wide; cross-pillar
> interoperability with continuous monitoring; centralized visibility
> with comprehensive situational awareness."

REQUIRES-RESEARCH: implementer confirms the verbatim four-stage text
from the mirrored PDF pages 5-7 at X.X4 implementation time. If any
character differs from the above, the implementer (a) updates this
file with the corrected quote, (b) updates
`data/zt-pillars-omb-m-22-09.json` `stage_criteria[].verbatim` field,
(c) appends a CHANGELOG entry noting the regulatory text correction.

**Pillar-by-pillar sub-function counts (canonical, from the PDF
"Pillar Functions" tables, pages 10-30):**

| Pillar | Sub-functions (count) |
|---|---|
| Identity | Authentication; Identity Stores; Risk Assessments; Access Management; Visibility & Analytics Capability (5) |
| Devices | Policy Enforcement & Compliance Monitoring; Asset & Supply Chain Risk Management; Resource Access; Device Threat Protection (4) |
| Networks | Network Segmentation; Network Traffic Management; Traffic Encryption; Network Resilience (4) |
| Applications & Workloads | Application Access; Application Threat Protection; Accessible Applications; Secure Application Development & Deployment Workflow; Application Security Testing (5) |
| Data | Data Inventory Management; Data Categorization; Data Availability; Data Access; Data Encryption (5) |

Total sub-functions = 23 (Identity 5 + Devices 4 + Networks 4 +
Applications & Workloads 5 + Data 5). Per LOOP-X-SPEC §2.4 the
implementer confirms the exact count from the mirrored PDF pages
10-30 at X.X1 catalog-extraction time; the figure in this table is
the X.X4 working assumption and must agree with the catalog snapshot.

**Per-pillar stage criteria (canonical text, page-pinned):**

The full per-pillar-per-stage criteria table is reproduced inside
`data/zt-pillars-omb-m-22-09.json` as `stage_criteria[]`. X.X4 does
NOT re-encode the criteria in TypeScript source — the engine reads
from the signed catalog snapshot. This guarantees a single source of
truth (the catalog) for both the scoring rubric and the operator-
facing documentation.

### 2.2 OMB Memorandum M-22-09 (Jan 26, 2022) — the five-pillar mandate

URL: https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf
(accessed 2026-06-08; mirrored to `docs/sources/zt/M-22-09.pdf`).

**§1 Vision (verbatim — referenced for the scorecard cover page):**

> "This memorandum sets forth a Federal zero trust architecture (ZTA)
> strategy, requiring agencies to meet specific cybersecurity
> standards and objectives by the end of Fiscal Year (FY) 2024 in
> order to reinforce the Government's defenses against increasingly
> sophisticated and persistent threat campaigns."

**§2 FY 2024 deadline (verbatim — referenced for the post-deadline
gap calculation):**

> "Agencies must achieve specific zero trust security goals by the
> end of Fiscal Year (FY) 2024."

X.X4 uses **September 30, 2024** (last day of FY 2024) as the
canonical "target attainment date". For any pillar still at
Traditional or Initial stage on a scorecard dated after 2024-09-30,
the scorecard adds a `post_deadline_gap: true` boolean to the
pillar's score block and the POA&M finding title carries a
`POST-DEADLINE` prefix.

**§II.B Identity pillar — phishing-resistant MFA mandate (verbatim,
publicly summarised — implementer confirms from mirrored PDF page
4-6 at X.X4 implementation time):**

> "Agencies must require their users to use a phishing-resistant
> method to access agency-hosted accounts. For agency staff,
> contractors, and partners, phishing-resistant MFA is required."

X.X4 enforces this mandate at scoring time: if the IAM-MFA collector
output (or the X.X4 supplementary `list-virtual-mfa-devices` SDK
call — see §6 step 4.2) reports any non-phishing-resistant MFA
authenticator type (SMS, voice, TOTP) for an admin / privileged
identity, the Identity pillar's Authentication sub-function is capped
at Initial regardless of other evidence.

### 2.3 NIST SP 800-207 (August 2020) — the tenets and architecture model

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf
(accessed 2026-06-08; mirrored to `docs/sources/zt/NIST.SP.800-207.pdf`).

**§2.1 Tenet 5 — continuous integrity monitoring (verbatim — referenced
by Devices-pillar Device Threat Protection sub-function scoring):**

> "The enterprise monitors and measures the integrity and security
> posture of all owned and associated assets."

**§2.1 Tenet 6 — dynamic enforcement (verbatim — referenced by
Identity-pillar Access Management sub-function scoring):**

> "All resource authentication and authorization are dynamic and
> strictly enforced before access is allowed. This is a constant
> cycle of obtaining access, scanning and assessing threats,
> adapting, and continually reevaluating trust in ongoing
> communication."

X.X4 reads the X.X2 architecture-map's `trust_algorithm_inputs[]`
array and assigns Identity > Access Management stage = Advanced only
when all five trust-algorithm input categories (access request,
subject database, asset database, resource policy requirements,
threat intelligence) have at least one evidenced source.

### 2.4 NIST SP 800-207A (September 2023) — cloud-native PEP placement

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207A.pdf
(accessed 2026-06-08; mirrored to
`docs/sources/zt/NIST.SP.800-207A.pdf`).

**Two-tier policy model (publicly summarised — implementer confirms
from mirrored PDF abstract at X.X4 implementation time):**

> "The guidance recommends the formulation of network-tier and
> identity-tier policies and the configuration of technology
> components (e.g., gateways, infrastructure for service identities,
> authentication, and authorization tokens)."

X.X4 reads X.X3's `cloud_native.network_tier_policies[]` and
`cloud_native.identity_tier_policies[]` arrays. The Networks-pillar
Traffic Encryption sub-function and the Applications/Workloads-pillar
Application Access sub-function each require BOTH tiers to be
evidenced for the Advanced stage; missing either tier caps the
sub-function at Initial.

### 2.5 NIST SP 800-63B Rev 4 IPD — Digital Identity Guidelines

URL: https://csrc.nist.gov/pubs/sp/800/63/b/4/ipd (accessed 2026-06-08).

**Phishing-resistance definition (publicly summarised — implementer
confirms from mirrored draft text at X.X4 implementation time):**

> "Phishing-resistant authentication is the ability of an
> authentication protocol to detect and prevent disclosure of
> authentication secrets and valid authenticator outputs to an
> impostor relying party without reliance on the vigilance of the
> subscriber. ... Examples of phishing-resistant authenticators
> include FIDO2 / WebAuthn, PIV smart cards, and other public-key-
> based authenticators that cryptographically bind the
> authenticator output to the verifier's domain."

X.X4 uses this definition to classify MFA types: FIDO2/WebAuthn,
PIV, smart card, and PKI-backed asymmetric authenticators are
phishing-resistant; SMS, voice, push notification (without number
matching), and TOTP are not. The classification table is encoded in
`data/zt-mfa-classification.json` (extracted by X.X1 from the
mirrored draft) and referenced by X.X4 at scoring time.

### 2.6 NIST CSF 2.0 (February 26, 2024) — Govern function cross-walk

URL: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
(accessed 2026-06-08; mirrored to `docs/sources/zt/NIST.CSWP.29.pdf`).

**Govern function introduction (verbatim, page 4):**

> "The CSF 2.0 introduces the Govern (GV) Function, which addresses
> how an organization's cybersecurity risk management strategy,
> expectations, and policy are established, communicated, and
> monitored. ... The Govern Function provides outcomes to inform what
> an organization may do to achieve and prioritize the outcomes of
> the other five Functions in the context of its mission and
> stakeholder expectations."

X.X4 cross-walks the ZTMM v2.0 Governance cross-cutting capability
to CSF 2.0 GV.OC, GV.RM, GV.RR, GV.PO, GV.OV, GV.SC subcategories.
A Governance stage of Advanced requires evidence for at least four
of the six GV subcategory families; Optimal requires all six.

### 2.7 NIST SP 800-53 Rev 5 — control cross-walk (used for POA&M references)

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-08).

Control families X.X4 references in emitted POA&M findings (per
LOOP-X-SPEC §2.13 cross-walk table): IA-*, AC-*, CM-*, MA-*, SI-*,
SC-*, SA-*, MP-*, AU-*, IR-*, PM-*, CA-*, PL-*. The exact mapping
from pillar sub-function → NIST controls is encoded in
`data/zt-pillars-omb-m-22-09.json` `nist_53r5_controls[]` field per
sub-function; X.X4 reads from the catalog (REO Rule 9 — schema
cannot exceed implementation).

### 2.8 FedRAMP 20x KSI baseline — KSI ID cross-walk

URL: FedRAMP 20x Phase Two FRMR catalog loaded into
`cloud-evidence/data/frmr-catalog.json` (already present per LOOP-A
pre-work).

The pillar-to-KSI cross-walk is encoded per LOOP-X-SPEC §2.14 in
the catalog snapshot's `frmr_ksi_ids[]` field per sub-function.
X.X4 reads the latest KSI run outputs from
`out/findings-{YYYYMMDD}.json` (the canonical per-day collector
output) and joins by KSI ID to determine evidence presence.

## 3. Scope

### 3.1 In scope

- Read X.X1 signed catalog, X.X2 signed architecture map, X.X3 signed
  cloud-native augmentation.
- Read every KSI collector's latest run output under `out/`.
- Read the X.X4 supplementary SDK calls explicitly named in §6
  (e.g. AWS IAM `list-virtual-mfa-devices`, Azure Entra ID
  `authenticationmethodspolicy`, GCP IAP `enrolment-method`).
- Compute per-sub-function stage assignment using the weakest-link
  rule + verbatim ZTMM v2.0 stage criteria.
- Compute per-pillar stage = MIN(sub-function stages).
- Compute per-cross-cutting-capability stage using the cross-pillar
  evidence rule (see §6 step 5).
- Compute overall ZTMM v2.0 stage = MIN(all 8 reportable stages).
- Emit signed JSON envelope (`out/ztmm-v2-scorecard-{system-id}-
  {YYYYMMDD}.json`).
- Emit OOXML/zip-store `.docx` scorecard
  (`out/ztmm-v2-scorecard-{system-id}-{YYYYMMDD}.docx`).
- Emit one-page `.pdf` summary
  (`out/ztmm-v2-scorecard-{system-id}-{YYYYMMDD}.pdf`).
- Emit OSCAL POA&M items for any pillar / capability below
  `stage_target`.
- Persist scorecard row to `tracker.db ztmm_scorecards` table.
- Surface tracker UI maturity-progress pane (`ZtmmStatusPane.tsx`).
- Provide trackable countdown to officer sign-off + audit-log row
  for every operator action.

### 3.2 Out of scope

- Runtime PDP / PEP implementation (REO Rule 1; LOOP-X-SPEC §1.3).
- Auto-remediation of below-target stages (operator owns remediation).
- Automatic sign-off (REO Rule 10).
- Agency-side Zero Trust Implementation Plan emission (each agency
  publishes its own).
- TIC 3.0 evidence collection (future LOOP-TIC).
- CDM data feed integration (LOOP-X reads CDM-aligned telemetry for
  V&A scoring but does not push to CDM).
- Renormalising of the catalog snapshot — that is X.X1's job.
- Re-running of X.X2 / X.X3 collectors — those are independent slices.
- Marketplace badge publication (LOOP-Q.Q1 consumes X.X4's signed
  scorecard).
- Dashboard tile rendering (LOOP-I consumes X.X4's tracker row).

## 4. Inputs

```typescript
// Pillar catalog (X.X1 emit; signed Ed25519)
interface ZtPillarsCatalog {
  catalog_version: '1';
  projection: 'omb-5+3' | 'dod-7';
  pillars: Pillar[];
  cross_cutting_capabilities: CrossCuttingCapability[];
  source_provenance: {
    omb_m_22_09_pdf_sha256: string;
    nist_sp_800_207_pdf_sha256: string;
    nist_sp_800_207a_pdf_sha256: string;
    cisa_ztmm_v2_pdf_sha256: string;
    nist_sp_800_63b_r4_pdf_sha256: string;
    nist_csf_2_pdf_sha256: string;
    extracted_at: string;       // ISO 8601
    extractor_version: string;
  };
  signature: SignatureBlock;
}

interface Pillar {
  id: 'identity' | 'devices' | 'networks' | 'applications_workloads' | 'data';
  name: string;
  sub_functions: SubFunction[];
  nist_53r5_controls: string[]; // e.g. ['IA-2', 'IA-5', 'AC-2', 'AC-3']
  frmr_ksi_ids: string[];       // e.g. ['IAM-MFA', 'IAM-AAM']
}

interface SubFunction {
  id: string;                   // e.g. 'authentication'
  name: string;                 // e.g. 'Authentication'
  stage_criteria: StageCriterion[];  // one per stage
  evidence_sources: EvidenceSourceSpec[];
  nist_53r5_controls: string[];
  frmr_ksi_ids: string[];
}

interface StageCriterion {
  stage: 'traditional' | 'initial' | 'advanced' | 'optimal';
  verbatim: string;             // verbatim quote from ZTMM v2.0
  source_page: number;          // PDF page number
  evidence_requirements: EvidenceRequirement[];
}

interface EvidenceRequirement {
  kind: 'ksi-result' | 'sdk-call' | 'catalog-lookup' | 'operator-input' | 'inventory-field';
  selector: string;             // e.g. 'IAM-MFA.findings[].mfa_type'
  predicate: string;             // e.g. 'all(x => x in ["fido2","webauthn","piv","smartcard"])'
  weight: number;                // 0-1; default 1
}

// 800-207 architecture map (X.X2 emit; signed)
interface Zt800207ArchitectureMap {
  pe_candidates: PdpPepCandidate[];
  pa_candidates: PdpPepCandidate[];
  pep_candidates: PdpPepCandidate[];
  trust_algorithm_inputs: TrustAlgorithmInput[];
  signature: SignatureBlock;
}

// 800-207A cloud-native augmentation (X.X3 emit; signed)
interface Zt800207ACloudNative {
  service_mesh: ServiceMeshSummary | null;
  sidecar_proxies: SidecarProxyEntry[];
  api_gateways: ApiGatewayEntry[];
  spiffe_bundles: SpiffeBundleEntry[];
  admission_webhooks: AdmissionWebhookEntry[];
  network_tier_policies: NetworkTierPolicy[];
  identity_tier_policies: IdentityTierPolicy[];
  signature: SignatureBlock;
}

// KSI run output (existing emit from cloud-evidence collector)
interface FindingsRun {
  run_id: string;
  collected_at: string;         // ISO 8601
  ksis: KsiResult[];
}

interface KsiResult {
  ksi_id: string;               // e.g. 'IAM-MFA'
  status: 'pass' | 'fail' | 'partial' | 'unknown';
  evidence: Record<string, unknown>;
  provenance: ProvenanceBlock;
}

// Operator config (zt-config.yaml; per LOOP-X-SPEC §17.1)
interface ZtConfig {
  enabled: boolean;
  projection: 'omb' | 'dod' | 'both';
  fy_target: number;            // default 2024
  csp_zt_implementation_owner: { name: string; role: string; email: string };
  stage_target: Record<PillarOrCapabilityId, ZtmmStage>;
  scoring: {
    trust_algorithm_weights: Record<TrustAlgorithmInputId, number>;
  };
  ir_plan_url?: string;
  last_tabletop_drill_date?: string;       // ISO date
  data_inventory_completeness_pct?: number;
  data_categorization_completeness_pct?: number;
  marketplace_badge_publish?: boolean;
}
```

## 5. Outputs

### 5.1 Canonical JSON scorecard envelope

`out/ztmm-v2-scorecard-{system-id}-{YYYYMMDD}.json` — schema
`schemas/zt/ztmm-v2-scorecard-v1.json`:

```json
{
  "schema_version": "1",
  "system_id": "examplecorp-prod",
  "scoring_run": {
    "started_at": "2026-06-08T14:02:11Z",
    "ended_at": "2026-06-08T14:08:54Z",
    "engine_version": "ztmm-v2-scorer/1.0.0",
    "operator": {
      "name": "Jane Doe",
      "role": "Chief Information Security Officer",
      "email": "jane@examplecorp.com"
    }
  },
  "input_provenance": {
    "catalog_sha256": "...",
    "architecture_map_sha256": "...",
    "cloud_native_sha256": "...",
    "findings_run_sha256": "...",
    "zt_config_sha256": "..."
  },
  "pillars": [
    {
      "id": "identity",
      "stage": "advanced",
      "sub_function_scores": [
        {
          "id": "authentication",
          "stage": "advanced",
          "rationale_verbatim_zttm": "...",
          "evidence_pointers": [
            { "kind": "ksi-result", "ksi_id": "IAM-MFA", "selector": "...", "value": "...", "captured_at": "..." }
          ]
        }
      ],
      "stage_target": "advanced",
      "below_target": false,
      "post_deadline_gap": false
    }
  ],
  "cross_cutting": [
    {
      "id": "visibility_analytics",
      "stage": "advanced",
      "...": "..."
    }
  ],
  "overall_stage": "initial",
  "weakest_link": [ "data", "governance" ],
  "poam_emitted": [
    { "poam_id": "...", "title": "ZT data pillar below target stage = advanced (current = initial)" }
  ],
  "signature": {
    "algorithm": "ed25519",
    "public_key_id": "csp-zt-signing-key-2026",
    "signature_b64": "...",
    "rfc3161_timestamp_token_b64": "...",
    "signed_at": "2026-06-08T14:09:01Z"
  }
}
```

### 5.2 OOXML/zip-store `.docx` scorecard

`out/ztmm-v2-scorecard-{system-id}-{YYYYMMDD}.docx` — produced by
`core/ztmm-v2-docx.ts` using the existing `core/docx.ts` helper.
Structure:

1. **Cover page** — system name, CSP name, scorecard date, overall
   stage badge, signature block placeholder.
2. **Executive summary** — paragraph describing the four-stage rubric
   (verbatim from ZTMM v2.0), the weakest-link rule, the FY 2024
   deadline note, and overall stage.
3. **Five pillar tables** — one per pillar, listing each sub-function
   with computed stage, target stage, gap indicator (Y/N), and verbatim
   stage criterion that was applied.
4. **Three cross-cutting capability tables** — same shape as pillar
   tables.
5. **Evidence-pointer appendix** — per-stage-assignment, the list of
   evidence pointers (KSI ID, SDK call, selector, captured-at).
6. **POA&M reference appendix** — per emitted POA&M item, the title,
   pillar, sub-function, severity, NIST 800-53 controls referenced.
7. **Officer attestation page** — operator-signed attestation that
   each stage assignment was reviewed and no contrary evidence has
   been suppressed.
8. **Signature page** — Ed25519 signature block + RFC 3161 timestamp
   token (rendered as base64 in a code block + the token's signed-at
   timestamp).

Layout details (margin / font / color):
- Margins: 1" all sides (Office default).
- Font: Calibri 11 for body, Calibri 14 bold for section headings.
- Stage badges: Traditional = #6c757d (gray), Initial = #fd7e14
  (orange), Advanced = #198754 (green), Optimal = #0d6efd (blue).
- Tables: alternating row shading #f8f9fa.

### 5.3 One-page `.pdf` summary

`out/ztmm-v2-scorecard-{system-id}-{YYYYMMDD}.pdf` — produced by the
existing `core/pdf.ts` helper (LOOP-C base infrastructure). Single
page containing:
- System name + scorecard date.
- 8 stage badges (5 pillars + 3 cross-cutting).
- Overall stage banner.
- "Signed by: <operator name>, <role>, <date>" line.
- "Verification: see signed JSON envelope at <relative path>" line.

### 5.4 OSCAL POA&M finding (emitted via core/oscal-poam.ts)

For each pillar / capability below `stage_target`, the emitter calls:

```typescript
emitPoamItem({
  title: `ZT ${pillarId} pillar below target stage = ${target} (current = ${current})`,
  related_observations: subFunctionGaps.map(g => g.id),
  origin: 'ztmm-v2-scorer/1.0.0',
  severity: deriveSeverity(target, current),  // see §6 step 6
  due_date: defaultDueDate90Days(),
  associated_controls: pillar.nist_53r5_controls,
  evidence_pointers: subFunctionGaps.flatMap(g => g.evidence_pointers)
});
```

## 6. Algorithm / Steps

### Step 1 — Load + verify input artefacts

1.1. Load `data/zt-pillars-omb-m-22-09.json` (or `zt-pillars-dod-7.json`
     per `zt-config.yaml projection`). Verify Ed25519 signature using
     the X.X1 public key from `data/zt-keys/zt-catalog-pubkey.pem`.
     If verification fails: throw `CatalogSignatureError`; the
     scoring run does NOT proceed (REO Rule 1 — no fake evidence
     basis).

1.2. Load `data/zt-800-207-architecture.json`. Verify Ed25519
     signature. Same failure mode.

1.3. Load `data/zt-800-207a-cloud-native.json`. Verify signature.
     If the file does not exist (e.g. CSP has no k8s — adverse case
     E1 in LOOP-X-SPEC §22), the scoring proceeds with cloud-native
     evidence treated as absent — relevant Networks-pillar and
     Applications/Workloads sub-functions degrade per the published
     rubric.

1.4. Load `out/findings-{YYYYMMDD}.json` (latest KSI run output).
     If the file is older than 7 days, emit a stale-evidence warning
     in the scoring log; if older than 30 days, throw
     `StaleEvidenceError` (LOOP-X-SPEC §8 risk X-R6).

1.5. Load `zt-config.yaml`. Validate against
     `schemas/zt/zt-config-v1.json`. If `csp_zt_implementation_owner.name`
     or `role` missing, throw `RequiresOperatorInputError` naming the
     field (REO Rule 4).

### Step 2 — Build the per-sub-function evidence map

For each pillar in catalog:
  For each sub_function:
    Build `evidence_map[sub_function.id] = {}`:
    For each evidence_requirement in sub_function.stage_criteria:
      Resolve evidence_requirement.kind:
        - `ksi-result`: look up findings_run.ksis[selector],
          apply predicate, store result.
        - `sdk-call`: invoke the X.X4 supplementary SDK call
          (§6 step 4 below); store result.
        - `catalog-lookup`: look up a catalog field; store.
        - `operator-input`: look up zt-config.yaml field; if missing,
          mark as `requires_operator_input`.
        - `inventory-field`: read inventory.assets[] via LOOP-INV-P1
          loader; apply predicate; store.
    Annotate each stored value with provenance (source SDK call,
    timestamp, raw value).

### Step 3 — Compute per-sub-function stage

For each sub_function:
  Walk stage_criteria from Optimal → Advanced → Initial → Traditional
  (highest-first):
    For each stage:
      Are ALL evidence_requirements for that stage satisfied?
        - "Satisfied" = predicate evaluates true with weight ≥ stage
          threshold (default 1.0 for binary requirements, 0.8 for
          weighted requirements).
        - If yes: assign this stage; break.
    If no stage's requirements met, assign Traditional (the default
    floor — Traditional is "manually configured / static" per ZTMM
    v2.0 page 5, which is the absence of automated controls).

Persist `sub_function_score = { id, stage, rationale_verbatim_zttm,
evidence_pointers[] }` to the run accumulator.

### Step 4 — X.X4 supplementary SDK calls (read-only)

X.X4 augments KSI evidence with the following read-only calls. Each
call honours the existing `core/auth/{aws,gcp,azure}` read-only
guardrail (LOOP-A pre-work). No write operations are ever issued.

4.1. **AWS IAM** — `list-virtual-mfa-devices`, `list-mfa-devices`,
     `list-users`, `list-account-aliases`, `get-account-summary`.
     Used to classify MFA authenticator types per 800-63B Rev 4
     phishing-resistance criteria.

4.2. **AWS Verified Access** — `describe-verified-access-instances`,
     `describe-verified-access-trust-providers`, `describe-verified-
     access-policies`. Used to detect policy-engine presence + the
     scope of policy enforcement.

4.3. **AWS Security Hub + GuardDuty** — `describe-hub`,
     `get-detector`. Used to detect threat-intelligence input for
     the trust algorithm (800-207 §3.2 input category 5).

4.4. **GCP IAP** — `compute.backendServices.list` (filter for
     IAP-enabled). `iap.tunnel.instances.list`. Used to detect
     identity-aware-proxy coverage.

4.5. **GCP BeyondCorp Enterprise** — `beyondcorp.organizations.
     locations.projects.list`. Used to detect BeyondCorp scope.

4.6. **GCP Security Command Center** — `securitycenter.organizations.
     sources.findings.list`. Used as Visibility & Analytics evidence.

4.7. **Azure Entra ID** — Microsoft Graph
     `/policies/authenticationMethodsPolicy`. Used to enumerate the
     enabled MFA methods + classify phishing-resistance.

4.8. **Azure Conditional Access** — Microsoft Graph
     `/identity/conditionalAccess/policies`. Used to detect
     conditional-access scope.

4.9. **Azure Defender for Cloud** — `securityscores.list`. Used as
     Visibility & Analytics evidence + Devices-pillar Device Threat
     Protection evidence.

Each call's response is wrapped in a provenance block (call name,
timestamp, response SHA-256, region/project/tenant) and stored in
the evidence_map.

### Step 5 — Compute per-pillar stage + per-cross-cutting-capability stage

For each pillar:
  `pillar.stage = MIN(sub_function_scores[].stage)`
  (the weak-link rule, per LOOP-X-SPEC §16).

For each cross-cutting capability (Visibility & Analytics,
Automation & Orchestration, Governance):
  For each pillar:
    Collect the cross-cutting-related sub-function evidence (e.g. for
    V&A: Identity > Visibility & Analytics Capability + Devices >
    Compliance Monitoring + Networks > Network Traffic Management +
    Applications & Workloads > Application Threat Protection + Data >
    Data Inventory Management).
  `capability.stage = MIN(per_pillar_cross_cutting_evidence_stages)`.

Compute overall:
  `overall.stage = MIN(pillars[].stage ∪ cross_cutting[].stage)`.

Identify weakest links: the set of pillars / capabilities whose stage
equals overall.stage AND which are below their configured target.

### Step 6 — Emit POA&M items for below-target

For each pillar / capability where `current < target`:
  Compose POA&M item via `emitPoamItem()` (§5.4).
  Severity:
    - target − current == 1: severity = 'moderate'
    - target − current == 2: severity = 'high'
    - target − current ≥ 3: severity = 'critical'
    - post_deadline_gap == true: bump severity by one tier.

Persist POA&M item IDs into the scorecard's `poam_emitted[]` array.

### Step 7 — Canonicalize + sign + emit

7.1. Build the scorecard JSON per §5.1 schema.
7.2. Canonicalize via `core/canonical-json.ts` (deterministic key
     ordering, no extraneous whitespace).
7.3. Compute SHA-256 of canonical bytes.
7.4. Build a `SignatureBlock` via `core/sign.ts signEnvelope()`:
     algorithm = ed25519, public_key_id from
     `cloud-evidence/keys/csp-zt-signing-key.pub`, signed_at = now.
7.5. Request RFC 3161 timestamp via `core/timestamp.ts` (existing
     LOOP-A.A5 helper). Embed the token in the signature block.
7.6. Write to `out/ztmm-v2-scorecard-{system-id}-{YYYYMMDD}.json`.
7.7. Render `.docx` via `core/ztmm-v2-docx.ts` (§5.2 layout).
7.8. Render `.pdf` via `core/pdf.ts` (§5.3 layout).
7.9. Insert tracker DB row into `ztmm_scorecards` (per migration
     §7).
7.10. Submit role IDs to LOOP-A.A4 bundle catalogue.

### Step 8 — Operator sign-off (deferred — tracker UI flow)

Until the operator opens the tracker UI scorecard-review page,
inspects each pillar's evidence, and presses "Sign" (TOTP-protected),
the scorecard's status is `draft`. After sign-off:
- `status = signed`
- `signed_by_officer_id`, `signed_at`, `tracker_audit_log_entry_id`
  recorded.
- LOOP-A.A4 bundler picks up the signed scorecard.
- LOOP-Q.Q1 Marketplace badge updated (if `marketplace_badge_publish`
  is true).
- LOOP-I dashboard tile refreshed.

## 7. Files to create / modify

Create:
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ztmm-v2-scorer.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ztmm-v2-emitter.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ztmm-v2-docx.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/schemas/zt/ztmm-v2-scorecard-v1.json`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/db/migrations/0054_ztmm_scorecards.sql`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/ztmm-status-pane.tsx`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/ztmm-v2-scorer.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/ztmm-v2-emitter.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/ztmm-v2-docx.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/zt/x4-catalog.json` (signed test catalog snapshot)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/zt/x4-architecture.json`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/zt/x4-cloud-native.json`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/zt/x4-findings-run.json`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/zt/x4-zt-config.yaml`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/keys/zt-pubkey.pem`

Modify:
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/cli.ts` — register `--zero-trust` orchestrator step that invokes X.X4 after X.X3 completes.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add `ztmm-v2-scorecard-json`, `ztmm-v2-scorecard-docx`, `ztmm-v2-scorecard-pdf` to the WELL_KNOWN role catalogue.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/api/ztmm.ts` — REST endpoints (`GET /api/ztmm/scorecards`, `GET /api/ztmm/scorecards/:id`, `POST /api/ztmm/scorecards/:id/sign`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/router.tsx` — route registration for the maturity-progress pane.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/lint-no-stubs.mjs` — confirm no stub/TODO tokens introduced.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` — slice row.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-X-SPEC.md` — §12 status table.
- `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md` — Unreleased entry.

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T01 | Happy path — all evidence Advanced | test/fixtures/zt/x4-happy.json | overall = advanced; no POA&M emitted | scorecard JSON validates; signature verifies; 8/8 stages = advanced |
| T02 | Identity pillar TOTP only | test/fixtures/zt/x4-totp.json | identity stage = initial (phishing-resistance cap) | POA&M emitted: "ZT identity pillar below target stage = advanced (current = initial)" |
| T03 | Networks 8/80 ns missing default-deny | test/fixtures/zt/x4-ns-gap.json | networks stage = advanced; sub-function Network Segmentation = advanced (above threshold 90%) | gap surfaced in evidence_pointers; no POA&M because pillar stage still meets target |
| T04 | Data inventory 65% complete | test/fixtures/zt/x4-data-65.json | data stage = initial; pillar below target | POA&M emitted; rationale_verbatim quotes ZTMM Initial criterion |
| T05 | Governance — no IR plan URL | test/fixtures/zt/x4-no-irplan.json | governance stage = traditional | `requires_operator_input: ir_plan_url` surfaced; tracker UI banner shown |
| T06 | Post-deadline gap (scorecard dated 2025-01-15, identity = initial) | test/fixtures/zt/x4-post-deadline.json | identity sub-function score carries post_deadline_gap=true; POA&M title prefixed POST-DEADLINE | severity bumped one tier (moderate → high) |
| T07 | Catalog signature invalid | test/fixtures/zt/x4-bad-catalog-sig.json | throws CatalogSignatureError | run aborts before any scoring; no partial scorecard written |
| T08 | Stale evidence (findings 35 days old) | test/fixtures/zt/x4-stale.json | throws StaleEvidenceError | run aborts; tracker UI shows blocked state |
| T09 | DoD projection — 7 pillars | test/fixtures/zt/x4-dod.json | scorecard contains 7 pillar blocks + Governance folded per pillar | overall stage computed across 7 pillars |
| T10 | Both projections — `projection: both` | test/fixtures/zt/x4-both.json | TWO scorecard files emitted (omb + dod) | both signatures verify; bundle gets both roles |
| T11 | k8s absent (pure PaaS, X.X3 emits no cloud-native) | test/fixtures/zt/x4-no-k8s.json | Networks + Apps/Workloads scores rely on cloud-native primitives instead of mesh | no error; stage computed per documented degradation path |
| T12 | Multi-PDP scoring (more than one PE candidate; conflicting policies) | test/fixtures/zt/x4-multi-pdp.json | stage = MIN per "weakest-link" rule (LOOP-X-SPEC §22 E3) | rationale identifies the weaker PDP |
| T13 | Schema validation — emit field missing | (mutated) test/fixtures/zt/x4-happy.json with `system_id` removed | ajv validation fails before write | no file written; SchemaValidationError thrown |
| T14 | RFC 3161 timestamp call timeout | mocked timestamp authority returning 504 | throws TimestampAuthorityUnavailableError | retry 3x with backoff per LOOP-A.A5 contract; final failure rolls back JSON write |
| T15 | .docx structural validation | (any happy fixture) | `unzipper` extracts the .docx; word/document.xml contains 5 pillar tables + 3 cc tables + officer attestation paragraph | OOXML parses cleanly in LibreOffice headless |
| T16 | .pdf one-page render | (any happy fixture) | PDF has exactly one page; contains overall stage banner text | pdfinfo reports page_count = 1 |
| T17 | POA&M severity ladder | test/fixtures/zt/x4-data-traditional.json (data current=traditional, target=advanced) | severity = critical (target − current = 3) | POA&M JSON validates against OSCAL POA&M v1.1.2 schema |
| T18 | Operator sign-off flow | (integration test against tracker API) | POST /api/ztmm/scorecards/:id/sign with valid TOTP → status changes to signed; audit log entry created | tracker DB row updated; subsequent GET returns signed status |
| T19 | Marketplace publish flag off | test/fixtures/zt/x4-publish-off.json | scorecard signed but Q.Q1 not invoked | tracker UI shows "Marketplace publish: skipped (operator config)" |
| T20 | Coverage regression check | run X.X4 over fixture twice | second run does not decrease the per-pillar evidence-pointer count vs first | G2 check:coverage-regression passes |
| T21 | Provenance check — every emit field has provenance | (any happy fixture) | every sub_function_score evidence_pointers[].provenance is populated | G3 check:provenance passes |
| T22 | lint:no-stubs | repo state after slice ships | no new TODO/FIXME/stub tokens in production paths | G1 lint:no-stubs returns 0 |
| T23 | Catalog projection mismatch | test/fixtures/zt/x4-omb-cat-but-dod-cfg.yaml | throws ProjectionMismatchError | clear error message identifying expected vs actual |
| T24 | Trust algorithm weight override | zt-config with weights {access_request: 0.4, others: 0.15} | weighted scoring respected | scorer log shows applied weights; sum-to-1 invariant enforced |

(24 tests; exceeds the 15-test minimum.)

## 9. Risks

| ID | Risk | Severity | Mitigation |
|---|---|---|---|
| X4-R1 | Subjective rubric — Initial vs Advanced disagreements between operator and 3PAO | High | Rubric is encoded verbatim from ZTMM v2.0 in the catalog; sub_function_score carries `rationale_verbatim_zttm` so the assessor can see the exact criterion that was applied. Override path: operator submits dispute ticket; 3PAO sign-off captured in tracker; until resolved the original stage stands. |
| X4-R2 | Stale KSI run output yields a misleadingly high stage | High | §6 step 1.4 enforces 7-day soft warning + 30-day hard fail. The scorecard's `input_provenance.findings_run_sha256` lets the assessor verify the timestamp. |
| X4-R3 | Catalog drift (CISA publishes ZTMM v2.1) silently invalidates the rubric | Medium | `scripts/check-zt-source-drift.mjs` runs daily; if the upstream PDF SHA-256 changes, the script fails CI and opens a ticket. X.X1 re-extractor produces a new signed catalog snapshot; X.X4 reads from whatever catalog is loaded and the scorecard's `input_provenance.catalog_sha256` records the snapshot used. |
| X4-R4 | .docx OOXML structural validation insufficient — opens in Word but renders garbled | Medium | T15 includes LibreOffice headless render verification. Additionally, the implementer manually opens the emitted .docx in Word once per release. |
| X4-R5 | Officer attestation bypass — operator could sign without reading | High | Sign-off requires TOTP + the tracker UI forces a scroll-through of each pillar's evidence panel before the Sign button is enabled. Operator action is captured in the signed audit log. |
| X4-R6 | Multi-cloud heterogeneity — Azure scoring path under-tested | Medium | Test fixtures include Azure-only scenarios (T01-T05 each have an Azure-tagged variant). Per-provider scoring helpers documented in code comments. |
| X4-R7 | Phishing-resistance classification false positives — e.g. Yubikey OTP mistakenly classed as phishing-resistant | High | `data/zt-mfa-classification.json` is sourced verbatim from 800-63B Rev 4 IPD; the classification table is signed and version-pinned. Yubikey OTP is explicitly classed as NOT phishing-resistant (it is OTP, not FIDO2). |
| X4-R8 | Performance — scorecard generation takes > 5 minutes on large CSPs | Low | Per-pillar scoring is independent; parallelise via `Promise.all(pillars.map(...))`. Streamed JSON write; peak heap < 200 MB. |
| X4-R9 | RFC 3161 timestamp authority outage blocks emit | Medium | Retry 3x with backoff per LOOP-A.A5. If still failing, scorecard JSON is written without a timestamp token and tracker UI prompts operator to re-run when authority is restored. The scorecard is marked `timestamp_pending` and excluded from bundle assembly until the token is attached. |
| X4-R10 | Schema version bump mid-cycle breaks downstream consumers (LOOP-Q.Q1, LOOP-I) | Low | Schema versioning per LOOP-X-SPEC §15 (additive-only changes within v1; v2 only on regulatory-text revision). CHANGELOG entries flag any consumer-impacting changes. |

## 10. Open questions

1. **Operator stage_target default for cross-cutting capabilities.**
   LOOP-X-SPEC §17.1 defaults `stage_target.<pillar>` to Advanced for
   all 5 pillars + 3 cross-cutting capabilities. Confirm with the
   user this default is appropriate, or whether Governance should
   default to Initial to avoid forcing immature CSPs into immediate
   POA&M emission. Decision: keep Advanced default; operator can
   override in `zt-config.yaml`.

2. **`.xlsx` companion artefact.** LOOP-X-SPEC §5 lists an optional
   `.xlsx` scorecard companion (mentioned in primitive list). Decide
   at slice-implementation time whether to ship it in X.X4 or defer
   to a follow-up slice. Decision: defer (out of scope for X.X4 v1).

3. **Risk-weighting of cross-cutting capabilities.** ZTMM v2.0 does
   not assign weights to cross-cutting capabilities relative to
   pillars. X.X4 treats them as co-equal in the overall MIN. Confirm
   FedRAMP PMO has not published a contrary weighting. Decision: no
   weighting; document the equal-weight assumption in the scorecard.

4. **Operator dispute UI.** When the operator believes a stage is
   miscalculated, the tracker UI lets them open a dispute ticket.
   Decide on the dispute lifecycle (auto-close after N days? require
   3PAO sign-off?). Decision: tickets stay open until 3PAO sign-off
   or 90-day timeout; the original stage stands during dispute.

5. **Continuous re-scoring cadence.** Should X.X4 run weekly, monthly,
   or per-collector-run? Decision: per-collector-run is the default
   (each `cli.js --collect` invocation triggers a fresh scorecard);
   weekly is the minimum cadence for ConMon compliance.

6. **DoD ZT Strategy "Target Level" mapping.** Confirm the exact
   mapping from DoD Target Level / Advanced Level → CISA Advanced /
   Optimal stages at X.X4 implementation time by reading the mirrored
   DoD ZT Strategy PDF pages 12-18. Decision: working assumption =
   DoD Target Level ≈ CISA Advanced; DoD Advanced Level ≈ CISA
   Optimal; revise if PDF contradicts.

7. **Hash algorithm for evidence pointer fingerprints.** SHA-256 is
   the chosen default. Per LOOP-R (PQC migration), a future revision
   may move to SHA-384 or SHA-512. Decision: SHA-256 for v1; flag in
   schema versioning notes.

## 11. REQUIRES-OPERATOR-INPUT

| field name | type | validator | UI location | failure mode if missing |
|---|---|---|---|---|
| `csp_zt_implementation_owner.name` | string | non-empty | Tracker > ZT > Config | X.X4 emit blocks; throws RequiresOperatorInputError |
| `csp_zt_implementation_owner.role` | enum (CISO / VP Eng / CTO / Director) | enum check | Tracker > ZT > Config | X.X4 emit blocks |
| `csp_zt_implementation_owner.email` | RFC 5322 email | regex | Tracker > ZT > Config | X.X4 emit blocks |
| `ir_plan_url` | URL | URL parse + HEAD probe | Tracker > ZT > Config | Governance cross-cutting capped at Traditional |
| `last_tabletop_drill_date` | ISO date | date parse; ≤ now | Tracker > ZT > Config | Governance cross-cutting capped at Initial if > 12 months stale |
| `data_inventory_completeness_pct` | float 0-100 | range check | Tracker > ZT > Config or LOOP-M evidence | Data pillar Data Inventory sub-function capped at Initial |
| `data_categorization_completeness_pct` | float 0-100 | range check | Tracker > ZT > Config or LOOP-M evidence | Data pillar Data Categorization sub-function capped at Initial |
| `stage_target.<pillar>` | enum (Traditional / Initial / Advanced / Optimal) | enum check | Tracker > ZT > Config | defaults to Advanced |
| `marketplace_badge_publish` | boolean | boolean check | Tracker > ZT > Config | defaults to false; if false, Q.Q1 invocation skipped |
| `officer_attestation` (sign-off) | TOTP + officer ID | TOTP verify + officer presence | Tracker > ZT > Scorecard review page | scorecard remains `draft`; bundle skips it; Marketplace not updated |
| `dispute_ticket_resolution` | enum (operator-accepted / 3pao-overridden / withdrawn) | enum check | Tracker > ZT > Disputes | original stage stands until resolution |

## 12. Implementation log

| date | session | action | commit | notes |
|---|---|---|---|---|
| 2026-06-08 | spec proposed | Specification authored via FedPy workflow | TBD | Initial draft — exhaustive context for cold-resume |

(Add a new row at every meaningful milestone — see
`docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3 for the cadence.)

## 13. Completion checklist

This checklist quotes the 7-step procedure from
`docs/SLICE-COMPLETION-PROCEDURE.md` verbatim, then adds step 8 per
the LOOP-X completion + push directive.

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
> ### Added — LOOP-X.X4: CISA ZTMM v2.0 Maturity Scoring + signed scorecard emitter
> <2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>

> ### Step 5 — Commit
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
> git commit -m "LOOP-X.X4: CISA ZTMM v2.0 Maturity Scoring + signed scorecard emitter
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

> ### Step 8 (LOOP-X-specific) — After commit lands
> Append/update the slice row in STATUS.md (status -> done, commit hash, last_updated); update the loop SPEC status table; append a CHANGELOG entry; push to origin/main; verify with `git log --oneline -3`. Update LOOP-X-RISKS.md if any new risks surfaced during implementation. Only THEN is the slice closed. Additionally: confirm the Marketplace badge (LOOP-Q.Q1) and the executive dashboard tile (LOOP-I) have been wired to consume the X.X4 scorecard; if either downstream surface is not consuming the artefact, the LOOP itself is NOT closed at the loop level even if X.X4 is individually done.
