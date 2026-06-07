# LOOP-N — Threat Modeling + Adversarial Validation

> Comprehensive implementation specification for the four slices in LOOP-N.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-N end-to-end by reading ONLY this file + the four supporting
> files cited in Section 3 ("Dependencies"). No prior conversation history
> required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence or
> operator-supplied configuration. Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.
>
> LOOP-N is one of six new loops proposed in `docs/ADDITIONAL-LOOPS-AUDIT.md`
> §2 (LOOP-L through LOOP-Q). The audit cites the gap: "the CSP-authored
> threat model (STRIDE / PASTA / kill-chain narrative + attack surface
> enumeration) has no home … Threat models are also a prerequisite of NIST
> SSDF (SP 800-218) PW.1.1". This spec realises that recommendation as
> four concrete slices (N.N1–N.N4).

---

## 1. Why this loop exists

### The gap LOOP-A through LOOP-K leave open

The existing 49-slice roadmap (LOOP-A done; LOOP-B–K specified) covers the
authorization package end-to-end at the artifact layer: SSP, AP, AR, POA&M,
RoE, bundler (LOOP-A); risk scoring + remediation deadlines + acceptance
records (LOOP-B); template-pack documents including PTA/PIA, CMP, ISCP, IRP
(LOOP-C); diagrams (LOOP-D); ConMon + monthly delta + annual reports
(LOOP-E); 3PAO experience (LOOP-F); the 20x AFR family (LOOP-G); long-term
storage + multi-CSO (LOOP-H); stakeholder dashboards (LOOP-I); supply
chain + privileges (LOOP-J); pen-test + scan-report ingestion (LOOP-K).

What none of those loops produces is the **CSP-authored, system-specific
threat model**. The audit (`docs/ADDITIONAL-LOOPS-AUDIT.md` §2 LOOP-N)
quotes the gap verbatim:

> "FedRAMP SSP requires (per Rev5 SSP template §13 + ARP § attack surface
> analysis) a documented threat model identifying threat actors, attack
> surface, controls mapping. The existing roadmap covers PenTest report
> ingest (LOOP-K.K1) but the **CSP-authored threat model** (STRIDE /
> PASTA / kill-chain narrative + attack surface enumeration) has no
> home. Threat models are also a prerequisite of NIST SSDF (SP 800-218)
> PW.1.1 ("Use forms of risk modeling — such as threat modeling,
> attack modeling, or attack surface analysis — to help assess the risk
> of attack")."

Concretely four artifacts are missing:

1. **STRIDE per-component threat catalog** — for every system component
   in `inventory.json` (compute, storage, network, identity, data plane),
   what threats (Spoofing / Tampering / Repudiation / Information
   Disclosure / Denial of Service / Elevation of Privilege) apply and
   which NIST 800-53 controls (and which KSIs) mitigate them.
2. **Attack-surface inventory** — the structured enumeration of boundary
   entry points (Internet-reachable endpoints, authentication
   boundaries, administrative interfaces, partner / subprocessor data
   flows) the threat actors target. Today exposure is implicit in
   per-asset `public_facing` / `internet_reachable` booleans; nothing
   aggregates this into a system-level attack-surface document.
3. **Adversarial / red-team test execution evidence** — automated
   adversarial tests against the *validation pipeline itself*: what
   happens when KSI envelopes are tampered, signatures replayed, fixture
   data injected, KEV reconcile bypassed, OSCAL chain broken. RFC-0014
   demands "truly automated and opinionated validation"; the trust
   basis of that claim depends on adversarial evidence that the
   pipeline detects tampering and fails closed.
4. **MITRE ATT&CK technique-to-boundary mapping** — which Enterprise +
   Cloud ATT&CK tactics + techniques apply to our specific cloud
   boundary, traced to mitigating KSIs and NIST controls. Today the VDR
   pipeline maps CVEs to KEV; nothing maps techniques to controls at the
   technique level.

### Artifacts LOOP-N delivers

| # | Artifact | Source | Consumer |
|---|---|---|---|
| 1 | `core/threat-model-emit.ts` — STRIDE catalog + DFD overlay | LOOP-N.N1 | SSP §13, SAR §3 attack surface, LOOP-C.C7 RMS |
| 2 | `out/threat-model.json` — structured per-component threat catalog | LOOP-N.N1 | tracker, dashboards, AR (`observation`) |
| 3 | `out/threat-model.docx` — FedRAMP-style threat model document | LOOP-N.N1 | submission bundle, 3PAO walk-through (LOOP-F.F4) |
| 4 | `core/attack-surface-emit.ts` — boundary entry-point enumerator | LOOP-N.N2 | SSP §9, RA-3 risk register (B.B5) |
| 5 | `out/attack-surface.json` — structured attack surface inventory | LOOP-N.N2 | LOOP-D.D1 boundary diagram cross-check, LOOP-K.K1 PenTest RoE pre-fill |
| 6 | `core/adversarial-test-runner.ts` — orchestrated mutation/fault tests | LOOP-N.N3 | CI gate; `out/adversarial-results.json` |
| 7 | `tests/adversarial/**` suite + signed result manifest | LOOP-N.N3 | CHANGELOG, AR `observation.props["adversarial-result"]` |
| 8 | `core/attack-mapping-emit.ts` — MITRE ATT&CK ↔ KSI ↔ NIST control map | LOOP-N.N4 | dashboard heat-map, monthly ConMon report (E.E1) |
| 9 | `out/attack-mapping.json` — ATT&CK technique coverage matrix | LOOP-N.N4 | tracker, AR observation, IIW (PIY-GIV) |

### Authorization-package gaps closed

| Package gap | Slice | Authoritative source |
|---|---|---|
| SSP §13 Risk Assessment lacks a system-specific threat model | N.N1 | FedRAMP Rev5 SSP Template §13; NIST SP 800-30 Rev 1 §3.2; NIST SP 800-154 (DCSTM) |
| Attack surface analysis absent from SSP §9 + SAR | N.N2 | FedRAMP SAR template §3.4 attack surface; NIST SP 800-115 §3; NIST SP 800-154 |
| Pipeline trust-claim (RFC-0014) lacks adversarial evidence | N.N3 | RFC-0014 §3 "Automated and Opinionated Validation"; NIST SP 800-115 §6 (vulnerability validation testing) |
| No technique-level control coverage view | N.N4 | MITRE ATT&CK Enterprise + Cloud Matrix; NIST SP 800-53 Rev 5 (CA-8, RA-5, RA-10) |

---

## 2. Connection to FedPy mission

FedPy is "read-only, evidence-grade automation for FedRAMP 20x & Rev5"
(README). It captures AWS/GCP/Kubernetes config evidence for all 60 KSIs
(223 requirements), benchmarks against NIST 800-53 at Low/Moderate/High,
signs everything (Ed25519 + OSCAL), and ships a local multi-user tracker
over the FRMR catalog. LOOP-N maps onto this mission at every level:

- **Read-only**: every slice in LOOP-N is read-only against the cloud.
  N.N1 reads `inventory.json` (already emitted by INV-P1..S6). N.N2
  reads `inventory.json` + existing network collectors
  (`providers/{aws,gcp,azure}/network.ts`) to identify Internet-facing
  surfaces. N.N3 runs entirely in-process against fixture envelopes
  under `tests/adversarial/`. N.N4 reads `core/kev-feed.ts`, the
  existing VDR ledger, and the NIST 800-53 control benchmark
  (`core/control-benchmark.ts`) — no new cloud queries.
- **Evidence-grade**: every emitted document carries a `provenance`
  block; every signature is real Ed25519; every timestamp is RFC 3161;
  every cited NIST/MITRE source is quoted verbatim with URL + section
  citation in the module docstring.
- **KSI evidence envelopes**: N.N1 and N.N4 cite which KSIs mitigate
  each threat / technique; the threat-model emits cross-references that
  the AR consumes as `observation.related-tasks` per OSCAL Assessment
  Results v1.1.2.
- **OSCAL chain (SSP → AP → AR → POA&M)**: N.N1 attaches threat-model
  references to SSP `back-matter.resources[type=threat-model]` (LOOP-A
  SSP-1 already emits SSP). N.N2 wires into AR
  `observation.props["attack-surface"]`. N.N3 wires into AR
  `observation.props["adversarial-result"]`. N.N4 wires into AR
  `observation.props["attack-technique"]`.
- **FRMR catalog**: N.N4 reads
  `docs/frmr-requirements.generated.json` (the authoritative source of
  truth for 60 KSIs) so the technique→KSI mapping is grounded in the
  published catalog, not hand-rolled IDs.
- **Tracker DB**: N.N1 + N.N3 add three new tables
  (`threat_models`, `attack_surface_inventory`, `adversarial_test_runs`)
  for operator sign-off + run history.

### Existing collectors this loop EXTENDS or READS FROM

| Module | How LOOP-N uses it |
|---|---|
| `core/inventory-emit.ts` + `inventory.json` | N.N1 enumerates components; N.N2 enumerates boundary entry points. |
| `providers/aws/network.ts`, `providers/gcp/network.ts`, `providers/azure/network.ts` | N.N2 reads ingress rules, public IPs, security groups, NACLs, LB schemes to compute the attack surface. |
| `core/kev-feed.ts` + existing VDR scan output | N.N4 maps KEV CVEs to ATT&CK techniques (via the MITRE-published CVE→technique mapping when available, else operator-supplied). |
| `core/control-benchmark.ts` + `core/nist-r5.ts` | N.N1 + N.N4 map threats/techniques to NIST controls + KSIs. |
| `core/ksi-map.ts` | N.N1 + N.N4 reference KSI IDs by canonical name. |
| `core/oscal-poam.ts`, `core/oscal-ap.ts`, `core/oscal.ts` (AR) | N.N1–N.N4 each attach props to existing OSCAL artifacts (no new OSCAL document type). |
| `core/submission-bundle.ts` | LOOP-N adds 5 new well-known roles to `WELL_KNOWN`. |
| `core/sign.ts` + `core/timestamp.ts` | Every LOOP-N output flows through the existing Ed25519 + RFC 3161 pipeline. |
| `tracker/server/schema.sql` | LOOP-N adds 3 new tables (additive only). |
| `core/envelope.ts` Finding type | N.N3 introduces a mutation-test harness that exercises envelope signing/verification end-to-end. |

### NEW collectors / providers this loop adds

LOOP-N does **not** add any new cloud-side collector. It is an
inference-and-emission loop: every input is sourced from existing
collectors. The new code is `core/threat-model-emit.ts`,
`core/attack-surface-emit.ts`, `core/adversarial-test-runner.ts`, and
`core/attack-mapping-emit.ts` plus tracker routes/pages and an
adversarial-test suite under `tests/adversarial/`. This is intentional:
LOOP-N consumes the existing evidence rather than asking the cloud for
more.

---

## 3. Dependencies

### Loops / slices that MUST complete first

| Dep | Why |
|---|---|
| LOOP-A.A1 (`core/oscal-poam.ts`) | N.N4 attaches `attack-technique` props to OSCAL risks. |
| LOOP-A.A2 (`core/oscal-ap.ts` SAP) | N.N1 attaches threat-model reference to AP `back-matter.resources`. |
| LOOP-A.A3 (`core/oscal.ts` AR / SSP→AP→AR chain) | N.N2 + N.N3 attach observation props that only validate inside an AR. |
| LOOP-A.A4 (`core/submission-bundle.ts`) | LOOP-N adds 5 new well-known roles to the catalogue. |
| INV-P1..S6 (`inventory.json`) | N.N1 + N.N2 read the rich inventory (data_classification, asset_tier, public_facing, internet_reachable, NIC IPs, OS profile). |
| `core/control-benchmark.ts` | N.N1 + N.N4 map threats/techniques back to NIST 800-53 control IDs at the configured impact level. |
| `core/kev-feed.ts` | N.N4 reads the KEV catalog to enumerate which Catalog entries map onto which ATT&CK techniques. |
| `core/sign.ts` + `core/timestamp.ts` | LOOP-N outputs are signed + timestamped under the existing chain. |
| LOOP-D.D3 (Data Flow Diagram) | OPTIONAL but recommended — N.N1's DFD overlay extends D.D3's emitted DFD with STRIDE per-flow annotations. If D.D3 is unshipped at N.N1 time, the slice ships its own minimal DFD baseline (documented in N.N1 §Open Questions). |

### Existing files this loop EXTENDS

| File | Modification |
|---|---|
| `cloud-evidence/core/oscal.ts` (AR builder) | (N.N1–N.N4) Add `observation.props` of names `threat-model-uuid`, `attack-surface-uuid`, `adversarial-result-uuid`, `attack-technique`. |
| `cloud-evidence/core/oscal-ssp.ts` | (N.N1) Append `back-matter.resources[type=threat-model]` referencing `threat-model.json` + `threat-model.docx`. |
| `cloud-evidence/core/oscal-ap.ts` | (N.N1) Append `back-matter.resources[type=attack-surface]` referencing `attack-surface.json`. |
| `cloud-evidence/core/oscal-poam.ts` | (N.N4) `findingProps()` appends `attack-technique` props when a finding maps to an ATT&CK technique. |
| `cloud-evidence/core/orchestrator.ts` | New flags: `--threat-model`, `--attack-surface`, `--adversarial`, `--attack-mapping`, `--strict-threat`, plus env equivalents `CLOUD_EVIDENCE_THREAT_MODEL`, etc. |
| `cloud-evidence/core/submission-bundle.ts` | Add roles `threat-model-json`, `threat-model-docx`, `attack-surface-json`, `adversarial-results-json`, `attack-mapping-json` to `WELL_KNOWN`. |
| `cloud-evidence/core/envelope.ts` | (N.N3 only) No production-path change; the adversarial suite exercises the existing Finding/Envelope contract. |
| `tracker/server/schema.sql` | Tables `threat_models`, `attack_surface_inventory`, `adversarial_test_runs`. |
| `tracker/server/index.ts` | Mount `routes/threat-model.ts`, `routes/attack-surface.ts`, `routes/adversarial-runs.ts`. |
| `tracker/client/src/App.tsx` | Add routes `/threat-model`, `/attack-surface`, `/adversarial-runs`. |
| `cloud-evidence/docs/STATUS.md` | Per-slice status line updated when slice ships. |
| `cloud-evidence/CHANGELOG.md` | Unreleased entry per slice (see Section 9). |

### Loops UNBLOCKED when LOOP-N is complete

| Unblocked loop | Reason |
|---|---|
| LOOP-C.C7 — Risk Management Strategy doc | RMS narrative pulls threat catalog (N.N1) + attack-surface enumeration (N.N2) directly. |
| LOOP-E.E1 — Monthly ConMon analysis report | E.E1 surfaces ATT&CK technique coverage trends from N.N4. |
| LOOP-F.F4 — Evidence walk-through artifacts | F.F4 references the threat model + attack surface as walk-through anchors. |
| LOOP-F.F7 — SAR draft generator | SAR §3.4 attack surface section auto-fills from N.N2's `out/attack-surface.json`. |
| LOOP-I.I3 — Anomaly detection dashboard | Dashboard heat-map of ATT&CK technique coverage is N.N4 output × controls coverage. |
| LOOP-K.K1 — PenTest report ingest (and K.K3 PenTest-RoE extension) | PenTest scope auto-derives from N.N2's attack surface; N.N4 technique map informs sample selection. |

---

## 4. Authoritative sources

Every URL + spec referenced in any LOOP-N slice. All quotes verbatim where
retrievable. Where the source PDF returns HTTP 403 to anonymous fetches
(NIST SP 800-30 r1 PDF, NIST SP 800-154 draft PDF), the slice records the
URL + the implementer downloads the PDF into
`cloud-evidence/docs/sources/` and re-quotes in the slice docstring with
section + page citation. Pattern mirrors LOOP-B-SPEC.md §3.

### STRIDE — Microsoft Security Development Lifecycle threat categorisation

- **Microsoft Threat Modeling Tool — STRIDE model** —
  https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
  - "To better help you formulate these kinds of pointed questions,
    Microsoft uses the STRIDE model, which categorizes different types
    of threats and simplifies the overall security conversations."
  - **Spoofing** — "Involves illegally accessing and then using another
    user's authentication information, such as username and password."
    Violates **Authentication**.
  - **Tampering** — "Involves the malicious modification of data.
    Examples include unauthorized changes made to persistent data, such
    as that held in a database, and the alteration of data as it flows
    between two computers over an open network, such as the Internet."
    Violates **Integrity**.
  - **Repudiation** — "Associated with users who deny performing an
    action without other parties having any way to prove otherwise —
    for example, a user performs an illegal operation in a system that
    lacks the ability to trace the prohibited operations.
    Non-Repudiation refers to the ability of a system to counter
    repudiation threats." Violates **Non-Repudiation**.
  - **Information Disclosure** — "Involves the exposure of information
    to individuals who are not supposed to have access to it — for
    example, the ability of users to read a file that they were not
    granted access to, or the ability of an intruder to read data in
    transit between two computers." Violates **Confidentiality**.
  - **Denial of Service** — "Denial of service (DoS) attacks deny
    service to valid users — for example, by making a Web server
    temporarily unavailable or unusable." Violates **Availability**.
  - **Elevation of Privilege** — "An unprivileged user gains privileged
    access and thereby has sufficient access to compromise or destroy
    the entire system. Elevation of privilege threats include those
    situations in which an attacker has effectively penetrated all
    system defenses and become part of the trusted system itself."
    Violates **Authorization**.

### MITRE ATT&CK — Enterprise + Cloud Matrices

- **MITRE ATT&CK Enterprise Tactics** —
  https://attack.mitre.org/tactics/enterprise/

  All 15 enterprise tactics (verbatim per the matrix index):
  | ID | Name | Definition |
  |---|---|---|
  | TA0043 | Reconnaissance | "The adversary is trying to gather information they can use to plan future operations." |
  | TA0042 | Resource Development | "The adversary is trying to establish resources they can use to support operations." |
  | TA0001 | Initial Access | "The adversary is trying to get into your network." |
  | TA0002 | Execution | "The adversary is trying to run malicious code." |
  | TA0003 | Persistence | "The adversary is trying to maintain their foothold." |
  | TA0004 | Privilege Escalation | "The adversary is trying to gain higher-level permissions." |
  | TA0005 | Stealth / Defense Evasion | "The adversary is trying to hide and conceal their actions, appearing as normal behavior." |
  | TA0006 | Credential Access | "The adversary is trying to steal account names and passwords." |
  | TA0007 | Discovery | "The adversary is trying to figure out your environment." |
  | TA0008 | Lateral Movement | "The adversary is trying to move through your environment." |
  | TA0009 | Collection | "The adversary is trying to gather data of interest to their goal." |
  | TA0011 | Command and Control | "The adversary is trying to communicate with compromised systems to control them." |
  | TA0010 | Exfiltration | "The adversary is trying to steal data." |
  | TA0040 | Impact | "The adversary is trying to manipulate, interrupt, or destroy your systems and data." |
  | TA0112 | Defense Impairment | "The adversary is trying to break security mechanisms, pipelines, and tooling so defenders can't see or trust what's happening." |

- **MITRE ATT&CK Cloud Matrix** — https://attack.mitre.org/matrices/enterprise/cloud/
  - Sub-matrices cited on the page: **Office Suite**, **Identity
    Provider**, **SaaS**, **IaaS**.
  - Representative cloud techniques cited verbatim:
    - T1566 Phishing — Initial Access
    - T1059.009 Cloud API — Execution
    - T1098 Account Manipulation — Persistence
    - T1548.005 Temporary Elevated Cloud Access — Privilege Escalation
    - T1564 Hide Artifacts — Defense Evasion
    - T1556 Modify Authentication Process — Defense Impairment
    - T1110 Brute Force — Credential Access
    - T1526 Cloud Service Discovery — Discovery
    - T1021 Remote Services — Lateral Movement
    - T1114 Email Collection — Collection
    - T1537 Transfer Data to Cloud Account — Exfiltration
    - T1486 Data Encrypted for Impact — Impact

- **MITRE ATT&CK STIX 2.1 data feed** —
  https://github.com/mitre/cti
  - Repository ships the official JSON STIX 2.1 representation of every
    tactic + technique + sub-technique + group + mitigation + data
    source. LOOP-N.N4 pins a release tag (e.g. ATT&CK v15 or current at
    build time) and commits the subset it consumes to
    `cloud-evidence/docs/sources/mitre-attack-cloud.subset.json` so the
    artifact is reproducible across runs.

- **MITRE ATT&CK Mitigations** — https://attack.mitre.org/mitigations/enterprise/
  - Each mitigation (M1013 Application Developer Guidance through
    M1056 Pre-compromise) has a canonical mapping to NIST 800-53
    controls published by the Center for Threat-Informed Defense at
    https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/blob/main/frameworks/nist800-53-r5/mappings/nist800-53-r5-attack-mappings.json
    LOOP-N.N4 pins a release of this mapping file into
    `cloud-evidence/docs/sources/attack-nist-mappings.json`.

### NIST publications

- **NIST SP 800-30 Rev 1 — Guide for Conducting Risk Assessments
  (Sep 2012)** — https://csrc.nist.gov/pubs/sp/800/30/r1/final
  PDF: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf
  - PDF returns binary content to anonymous WebFetch; implementer
    downloads to `cloud-evidence/docs/sources/nist-sp-800-30r1.pdf` and
    quotes verbatim in the module docstring.
  - §3.2 **Conduct the Risk Assessment** — TASK 2-1 Identify Threat
    Sources; TASK 2-2 Identify Threat Events; TASK 2-3 Identify
    Vulnerabilities and Predisposing Conditions; TASK 2-4 Determine
    Likelihood of Occurrence; TASK 2-5 Determine Magnitude of Impact;
    TASK 2-6 Determine Risk. LOOP-N.N1 walks TASK 2-1 through TASK 2-3
    over each inventory component; LOOP-B.B5 walks TASK 2-4 through
    TASK 2-6 over the aggregate.
  - Appendix D **Threat Sources** — taxonomy of adversarial,
    accidental, structural, and environmental threat-source classes.
    N.N1 uses this taxonomy verbatim.
  - Appendix E **Threat Events** — taxonomy of representative events.
    N.N1 cross-references this when authoring per-component STRIDE
    rows.

- **NIST SP 800-154 (Draft) — Guide to Data-Centric System Threat
  Modeling** —
  https://csrc.nist.gov/CSRC/media/Publications/sp/800-154/draft/documents/sp800_154_draft.pdf
  - PDF returns binary content to anonymous WebFetch; implementer
    downloads to
    `cloud-evidence/docs/sources/nist-sp-800-154-draft.pdf` and quotes
    verbatim in the N.N1 + N.N2 module docstrings.
  - The four DCSTM steps (per the draft TOC):
    1. **Identify and characterize the system and data of interest.**
    2. **Identify and select the attack vectors to be included in the
       model.**
    3. **Characterize the security controls for mitigating the attack
       vectors.**
    4. **Analyze the threat model.**
  - LOOP-N.N1 implements steps 1 + 3; LOOP-N.N2 implements step 2;
    LOOP-N.N4 informs step 3 via the ATT&CK mapping.

- **NIST SP 800-53 Rev 5 — Security and Privacy Controls** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - **CA-8 Penetration Testing** — N.N3 + N.N2 inform pen-test scope.
  - **RA-3 Risk Assessment** — N.N1 + N.N4 + B.B5 collectively produce
    the RA-3 artifact set.
  - **RA-10 Threat Hunting** — N.N4 ATT&CK technique map is the
    organisational baseline RA-10 references.
  - **SA-11 Developer Testing and Evaluation** — N.N3 adversarial test
    runner satisfies SA-11(3) Independent Verification + SA-11(5)
    Penetration Testing in part.
  - **SI-3, SI-4** — informed by N.N4's technique coverage.

- **NIST SP 800-115 — Technical Guide to Information Security Testing
  and Assessment** —
  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf
  - §3 **Review Techniques** — informs the N.N1 component-level analysis.
  - §4 **Target Identification and Analysis Techniques** — informs N.N2
    attack-surface enumeration (port discovery, service identification,
    vulnerability scanning).
  - §6 **Penetration Testing** — informs N.N3 adversarial-test design
    (planning, discovery, attack, reporting phases).

- **NIST SP 800-37 Rev 2 — Risk Management Framework for Information
  Systems and Organizations** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
  - **Step 2 Categorize Information System** Task C-3 (Threat
    Identification) — directly satisfied by N.N1 output.

- **NIST SP 800-218 — Secure Software Development Framework (SSDF)
  v1.1** — https://csrc.nist.gov/pubs/sp/800/218/final
  - **PW.1 Design Software to Meet Security Requirements and Mitigate
    Security Risks** — PW.1.1 example task:
    > "Use forms of risk modeling — such as threat modeling, attack
    > modeling, or attack surface analysis — to help assess the risk
    > of attack."
  - N.N1 (threat modeling) + N.N2 (attack surface analysis) + N.N4
    (attack modeling) collectively satisfy PW.1.1.

### FedRAMP guidance

- **FedRAMP Rev5 SSP Template §13 (Control Implementation
  Description)** —
  https://www.fedramp.gov/assets/resources/templates/SSP-A1-FedRAMP-System-Security-Plan-Template.docx
  - The template's narrative for RA-3 + PL-2 requires the CSP to
    "describe the threat sources, threat events, and vulnerabilities
    considered. Include attack surface analysis as appropriate."
    Quoted by `docs/ADDITIONAL-LOOPS-AUDIT.md` §2 LOOP-N. N.N1 +
    N.N2 produce the underlying evidence the SSP narrative cites.

- **FedRAMP SAR Template §3.4 Attack Surface Analysis** —
  https://www.fedramp.gov/assets/resources/templates/SAR-FedRAMP-Security-Assessment-Report-Template.docx
  - SAR §3.4 requires the 3PAO to "summarize the attack surface
    examined during testing". F.F7 (SAR draft generator) auto-fills
    this from N.N2's `out/attack-surface.json`.

- **FedRAMP Penetration Test Guidance v3.0** —
  https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf
  - §3 Rules of Engagement field set; §5 Test Methodology. N.N2's
    attack surface informs PenTest scope (LOOP-K.K1 extension /
    K.K3 candidate); N.N4's technique map informs sample selection.

- **RFC-0014 (FedRAMP 20x Phase Two — Automated/Opinionated
  Validation)** — https://www.fedramp.gov/rfcs/0014/
  - "Phase Two Moderate explicitly mandates truly automated and
    opinionated validation of Key Security Indicators". N.N3
    adversarial tests are the evidence the validation pipeline holds
    up under attack — the trust basis of the RFC-0014 claim.

### Industry frameworks

- **OWASP Threat Modeling** —
  https://owasp.org/www-community/Application_Threat_Modeling
  - Authoritative open-source overview of the threat-modeling
    methodology family. N.N1 cites this in its README for context.
- **OWASP Top 10 Web Application Security Risks (2021)** —
  https://owasp.org/Top10/
  - N.N4 cross-references OWASP categories for web-application
    findings that don't have a clean ATT&CK technique match.
- **PASTA — Process for Attack Simulation and Threat Analysis** —
  https://www.versprite.com/blog/what-is-pasta-threat-modeling/
  - Seven-stage methodology. N.N3 borrows PASTA stages V (Threat
    Analysis), VI (Vulnerability and Weakness Analysis), VII (Attack
    Modeling), VIII (Risk and Impact Analysis) to structure the
    adversarial-test plan.

### CISA Known Exploited Vulnerabilities

- **CISA KEV Catalog** —
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - Already loaded by `core/kev-feed.ts`. N.N4 reads each entry's
    `cveID` and reconciles it against the MITRE
    `attack-cve-mappings.json` (where published) to assign a primary
    technique; entries without a published mapping carry
    `REQUIRES-OPERATOR-INPUT: technique-classification`.

- **BOD 22-01** —
  https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01
  - Documentation only; N.N4 uses KEV entries verbatim.

### CWE — Common Weakness Enumeration

- **CWE Top 25 (2024 release)** — https://cwe.mitre.org/top25/
  - N.N1's STRIDE rows cite the relevant CWE for each threat (e.g.
    Spoofing on auth boundaries → CWE-287 Improper Authentication;
    Information Disclosure on data flows → CWE-200 Exposure of
    Sensitive Information).
- **CWE-to-ATT&CK Mapping** —
  https://github.com/center-for-threat-informed-defense/attack_to_cve
  - LOOP-N.N4 reuses this mapping when reconciling KEV → technique.

### OSCAL

- **OSCAL Assessment Results v1.1.2** — schema committed at
  `cloud-evidence/docs/oscal/oscal_assessment-results_schema.v1.1.2.json`.
  Field references in this spec cite NIST OSCAL doc:
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/
  - `observation.props[]` is the extension point for N.N1–N.N4 props.
  - `observation.relevant-evidence[].href` points at the signed
    threat-model / attack-surface / adversarial-results / attack-mapping
    artifact.
  - `observation.subjects[].type = "component"` is reused to name
    inventory components in N.N1.

- **OSCAL SSP v1.1.2 back-matter.resources** — per
  `core/oscal-ssp.ts`. N.N1 attaches a new resource of `type:
  threat-model` with `rlinks[]` pointing at the signed
  `threat-model.json` + `.docx`.

---

## 5. Per-slice implementation specs

### Slice N.N1 — STRIDE threat model generator (per-component, from inventory + DFD)

**Why this slice**: FedRAMP SSP §13 + NIST 800-30 Rev 1 §3.2 + NIST
SP 800-154 + NIST SP 800-218 PW.1.1 all require a system-specific threat
model. Today the CSP would author this manually. N.N1 produces it
auto-generated from `inventory.json` + the existing component taxonomy,
emits both a structured JSON artifact (consumed by AR, dashboard,
risk-register) and a FedRAMP-style `.docx` document (consumed by the
submission bundle + 3PAO walk-through).

**Connection to FedPy mission**: Reads `inventory.json` (real-evidence
collector output), `core/control-benchmark.ts` (NIST 800-53 control
benchmark), and `core/ksi-map.ts` (KSI canonical map). Emits
`out/threat-model.json` with provenance block + Ed25519 signature + RFC
3161 timestamp through the existing pipeline. Operator input enters via
tracker UI (`/threat-model`) for narratives that cannot be auto-derived
(kill-chain story, organisational threat actors of concern). No new
cloud SDK calls.

**Files to create** (exact paths under `cloud-evidence/`):
- `cloud-evidence/core/threat-model.ts` — pure builder: takes
  `InventoryComponent[]` + `ControlBenchmark` + `KsiMap` + operator
  config and produces `ThreatModel` typed value.
- `cloud-evidence/core/threat-model-emit.ts` — disk emitter: walks
  inventory, calls the pure builder, writes
  `out/threat-model.json` + invokes `core/threat-model-docx.ts`.
- `cloud-evidence/core/threat-model-docx.ts` — `.docx` renderer
  reusing the existing FedRAMP-template `.docx` pattern from
  `core/ssp-docx.ts` (LOOP-A's SSP-2).
- `cloud-evidence/core/stride-catalog.ts` — typed constant catalog of
  per-component-type STRIDE rules (e.g. "compute → Spoofing → IAM-MFA
  + IAM-APM mitigate", "storage → Information Disclosure → SVC-RUD +
  SVC-VRI mitigate"). Each row cites the NIST control + KSI mapping +
  CWE.
- `cloud-evidence/tests/core/threat-model.test.ts` — pure-builder
  tests.
- `cloud-evidence/tests/core/threat-model-emit.test.ts` — emitter
  integration tests.
- `cloud-evidence/tests/core/threat-model-docx.test.ts` — docx
  round-trip tests.
- `cloud-evidence/tests/core/stride-catalog.test.ts` — catalog
  completeness tests.
- `cloud-evidence/threat-model-config.example.yaml` — committed
  example operator config.
- `tracker/server/routes/threat-model.ts` — CRUD route for operator
  kill-chain narratives + sign-off.
- `tracker/server/routes/threat-model.test.ts`.
- `tracker/client/src/pages/ThreatModel.tsx` — UI for narrative
  authoring + per-row sign-off.
- `tracker/client/src/pages/ThreatModel.test.tsx`.

**Files to extend**:
- `cloud-evidence/core/oscal-ssp.ts` — append
  `back-matter.resources[type=threat-model]` block.
- `cloud-evidence/core/oscal.ts` (AR builder) — for each
  per-component threat-model row, emit an `observation` with
  `subjects[type=component]`, `props[name=threat-stride-category]`,
  `relevant-evidence[].href` pointing at `threat-model.json#/<row>`.
- `cloud-evidence/core/orchestrator.ts` — `--threat-model` flag (env
  `CLOUD_EVIDENCE_THREAT_MODEL`) + `--threat-model-config <path>` +
  `--strict-threat`.
- `cloud-evidence/core/submission-bundle.ts` — add roles
  `threat-model-json`, `threat-model-docx`.
- `tracker/server/schema.sql` — add table `threat_models` (one row per
  component-threat-row, signed by the IS owner; AO sign-off optional).
- `tracker/server/index.ts` — mount route.
- `tracker/client/src/App.tsx` — add `/threat-model` route.

**Schemas / standards** (cite + quote verbatim):
- **STRIDE** — six categories per Microsoft Threat Modeling Tool docs
  (quoted verbatim in §4 above). N.N1 emits one row per
  (component, STRIDE-category) cross product.
- **NIST SP 800-30 Rev 1 §3.2 TASK 2-1 Identify Threat Sources**:
  N.N1 emits a per-component `threat_sources[]` taxonomy block citing
  Appendix D taxonomy.
- **NIST SP 800-154 Step 1 (Identify and characterize the system and
  data of interest)** + Step 3 (Characterize the security controls).
- **OSCAL SSP `back-matter.resources[type]`** — accepts arbitrary
  `type` strings; we register `threat-model` as the canonical token
  (cited in module docstring + OSCAL extension registry committed at
  `docs/oscal/extensions.md`).
- **FedRAMP SSP §13** — narrative must describe threat sources,
  threat events, vulnerabilities, and attack surface; the docx
  renderer emits the §13-shaped section the CSP pastes into the SSP
  (or auto-injects via SSP-2 docx merge).

**Build steps**:

1. Define typed interfaces in `core/threat-model.ts`:
   ```ts
   export type StrideCategory = 'spoofing' | 'tampering' | 'repudiation'
     | 'information-disclosure' | 'denial-of-service' | 'elevation-of-privilege';

   export type ComponentClass = 'compute' | 'storage' | 'network'
     | 'identity' | 'data-plane' | 'control-plane' | 'monitoring'
     | 'crypto' | 'human-interface' | 'admin-interface' | 'external-service';

   export interface ThreatSource {
     class: 'adversarial' | 'accidental' | 'structural' | 'environmental';  // NIST 800-30 r1 App. D
     actor: string;                       // e.g. "external attacker", "compromised insider"
     capability: 'low' | 'moderate' | 'high';
     intent: 'unintentional' | 'opportunistic' | 'targeted';
   }

   export interface ThreatRow {
     uuid: string;                        // deterministic v5 over (component_id, stride)
     component_id: string;                // inventory.assets[].identifier
     component_class: ComponentClass;
     stride: StrideCategory;
     threat_sources: ThreatSource[];
     threat_event: string;                // verbatim text or operator-supplied
     cwe_ids: string[];                   // e.g. ["CWE-287"]
     mitigating_ksis: string[];           // canonical KSI IDs (e.g. "IAM-MFA")
     mitigating_controls: string[];       // NIST 800-53 control ids (e.g. "AC-2")
     residual_risk_note?: string;         // operator-supplied
     operator_signed_off: boolean;
     operator_signed_off_at?: string;
     sources: {
       component_source: 'inventory.json' | 'operator-supplied';
       stride_catalog_source: 'stride-catalog.ts' | 'operator-supplied' | 'REQUIRES-OPERATOR-INPUT';
       mitigation_source: 'ksi-map.ts' | 'operator-supplied' | 'REQUIRES-OPERATOR-INPUT';
       threat_source_source: 'NIST-800-30-r1-App-D' | 'operator-supplied' | 'REQUIRES-OPERATOR-INPUT';
     };
   }

   export interface ThreatModel {
     uuid: string;
     emittedAt: string;
     formula_version: 'threat-model.v1';
     system_id: string;
     csp_name: string;
     rows: ThreatRow[];
     dfd_overlay?: DfdStrideOverlay;       // optional; from LOOP-D.D3
     kill_chain_narrative?: string;        // operator-supplied
     organisational_threat_actors?: ThreatSource[];  // operator-supplied
     provenance: ProvenanceBlock;
   }
   ```

2. Pure builder:
   ```ts
   export function buildThreatModel(
     inventory: InventoryComponent[],
     controlBenchmark: ControlBenchmark,
     ksiMap: KsiMap,
     opts: ThreatModelOpts,
   ): ThreatModel;
   ```
   The function classifies every inventory asset to a `ComponentClass`
   via tag-driven heuristics (asset_type/resource_type), then iterates
   the STRIDE catalog to emit one row per (component, stride) cross
   product. Each row's `mitigating_ksis` + `mitigating_controls` is
   derived from `stride-catalog.ts` cross-referenced against
   `controlBenchmark` so only controls applicable to the configured
   impact-level are listed.

3. **STRIDE catalog** (`core/stride-catalog.ts`) — typed constant of
   shape:
   ```ts
   export interface StrideCatalogRow {
     component_class: ComponentClass;
     stride: StrideCategory;
     default_threat_event: string;            // verbatim text
     cwe_ids: string[];
     mitigating_ksi_ids: string[];
     mitigating_nist_control_ids: string[];
     citation: { spec: string; section: string; url: string };
   }
   export const STRIDE_CATALOG: ReadonlyArray<StrideCatalogRow>;
   ```
   Catalog rows cite the FRMR catalog (`docs/frmr-requirements.generated.json`) + NIST 800-53 Rev 5 catalog. The committed catalog
   carries ≥ 30 rows covering the 11 `ComponentClass` × 6 STRIDE
   categories matrix's high-signal cells (not all 66 — some have no
   meaningful threat, documented in catalog comment).

4. **Disk emitter** (`core/threat-model-emit.ts`):
   ```ts
   export interface ThreatModelEmitOptions {
     outDir: string;
     inventoryPath?: string;
     configPath?: string;          // threat-model-config.yaml
     trackerSnapshotPath?: string; // out/.threat-model-snapshot.json
     systemId: string;
     cspName: string;
     impactLevel: 'low' | 'moderate' | 'high';
     runId: string;
   }
   export interface ThreatModelEmitResult {
     jsonPath: string;             // out/threat-model.json
     docxPath: string;             // out/threat-model.docx
     rowCount: number;
     unsigned_rows: number;        // not yet operator-signed
     requires_operator_input: number;
   }
   export async function emitThreatModel(
     opts: ThreatModelEmitOptions,
   ): Promise<ThreatModelEmitResult>;
   ```

5. **DOCX renderer** (`core/threat-model-docx.ts`): mirrors the
   `core/ssp-docx.ts` pattern. The document contains:
   - Title page (system_id, csp_name, emittedAt, version)
   - Executive summary (auto)
   - Threat Sources table (NIST 800-30 r1 App. D taxonomy)
   - Per-component STRIDE matrix (one section per component class)
   - DFD overlay (when supplied by LOOP-D.D3)
   - Mitigations table (cross-reference to NIST controls + KSIs)
   - Residual risks (operator-supplied via tracker)
   - Kill-chain narrative (operator-supplied)
   - Signatures + revision history

6. **AR observation emission** (extend `core/oscal.ts`): for each
   `ThreatRow`, emit:
   ```ts
   {
     uuid: row.uuid,
     description: `STRIDE/${row.stride} on ${row.component_id}`,
     methods: ['EXAMINE'],
     subjects: [{ subject-uuid: row.component_id, type: 'component' }],
     props: [
       { name: 'threat-stride-category', ns: CE_NS, value: row.stride },
       { name: 'threat-component-class', ns: CE_NS, value: row.component_class },
       ...row.cwe_ids.map(cwe => ({ name: 'cwe-id', ns: CE_NS, value: cwe })),
       ...row.mitigating_ksis.map(k => ({ name: 'mitigating-ksi', ns: CE_NS, value: k })),
       ...row.mitigating_controls.map(c => ({ name: 'mitigating-nist-control', ns: CE_NS, value: c })),
     ],
     'relevant-evidence': [{ href: `./threat-model.json#/rows/${idx}` }],
   }
   ```

7. **SSP back-matter** (extend `core/oscal-ssp.ts`): emit one resource
   per signed artifact:
   ```ts
   {
     uuid: deterministicUuid('ssp:back-matter:threat-model'),
     title: 'System threat model (LOOP-N.N1)',
     description: 'STRIDE per-component threat model emitted by core/threat-model-emit.ts',
     props: [{ name: 'type', ns: CE_NS, value: 'threat-model' }],
     rlinks: [
       { href: './threat-model.json', media-type: 'application/json' },
       { href: './threat-model.docx', media-type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' },
     ],
   }
   ```

8. **Tracker UI** — `threat_models` table stores per-row sign-off + the
   operator-supplied kill_chain_narrative + organisational threat
   actors. Schema:
   ```sql
   CREATE TABLE IF NOT EXISTS threat_models (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     system_id TEXT NOT NULL,
     row_uuid TEXT NOT NULL,                   -- ThreatRow.uuid
     component_id TEXT NOT NULL,
     stride TEXT NOT NULL,
     threat_event TEXT NOT NULL,
     residual_risk_note TEXT,
     operator_signed_off INTEGER NOT NULL DEFAULT 0,
     operator_signed_off_by_user_id INTEGER REFERENCES users(id),
     operator_signed_off_at TEXT,
     signature TEXT,
     signing_key_id TEXT,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE TABLE IF NOT EXISTS threat_model_narratives (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     system_id TEXT NOT NULL UNIQUE,
     kill_chain_narrative TEXT,
     organisational_threat_actors_json TEXT,
     signed_off_by_user_id INTEGER REFERENCES users(id),
     signed_off_at TEXT,
     signature TEXT,
     signing_key_id TEXT,
     updated_at TEXT NOT NULL
   );
   ```

9. **Bundler integration**: add roles
   `threat-model-json` (filename `threat-model.json`) and
   `threat-model-docx` (filename `threat-model.docx`) to
   `submission-bundle.ts:WELL_KNOWN`.

10. **Validation pass**: run emitted `out/threat-model.json` through
    `scripts/check-provenance.mjs`; run modified `out/poam.json` +
    `out/ar.json` through `core/oscal-validate.ts`.

11. **Signing + timestamping**: `threat-model.json` and
    `threat-model.docx` are both picked up by the existing
    `core/sign.ts` glob + included in the RFC 3161 manifest.

**REQUIRES-OPERATOR-INPUT fields**:
- `kill_chain_narrative` — operator UI input (tracker).
- `organisational_threat_actors` — operator UI input.
- `threat_event` (per row) — defaults to `default_threat_event` from
  the catalog; operator can override per row. Override is operator-
  supplied; default carries `stride_catalog_source: 'stride-catalog.ts'`.
- `residual_risk_note` — operator UI input.
- `operator_signed_off` — operator sign-off via tracker UI; never
  auto-set.
- `mitigating_ksis` / `mitigating_controls` — derived from
  `stride-catalog.ts` + `ksi-map.ts`; if a row in the catalog has no
  mapped KSI for the configured impact level, emit
  `REQUIRES-OPERATOR-INPUT: mitigation-mapping` and the operator must
  supply via config.

**Test specifications** (≥ 12 tests):

1. `it('classifies inventory assets to ComponentClass via asset_type', ...)` —
   AWS `ec2.instance` → compute; AWS `s3.bucket` → storage; GCP
   `compute.instance` → compute; AWS `iam.user` → identity.
2. `it('emits one row per (component, stride) cross product where catalog has a rule', ...)`.
3. `it('cites NIST 800-30 r1 App. D threat-source class on every row', ...)`.
4. `it('maps mitigating KSIs from STRIDE catalog cross-checked against ksi-map.ts', ...)`.
5. `it('maps mitigating NIST controls to the configured impact level', ...)` —
   Low-baseline doesn't reference Moderate-only controls.
6. `it('emits REQUIRES-OPERATOR-INPUT mitigation-mapping when catalog row has no KSI match', ...)`.
7. `it('produces deterministic uuid v5 per (component, stride)', ...)`.
8. `it('writes threat-model.json with provenance.emitter + sourceCalls', ...)` —
   `check:provenance` passes.
9. `it('writes threat-model.docx with the §13-shaped sections', ...)` —
   docx round-trip via test renderer; assert headings present.
10. `it('appends SSP back-matter resource type=threat-model', ...)`.
11. `it('AR observation emits threat-stride-category + cwe-id + mitigating-ksi props', ...)`.
12. `it('respects operator override of threat_event from tracker snapshot', ...)`.
13. `it('honours kill-chain narrative from threat_model_narratives table', ...)`.
14. `it('bundler includes threat-model-json + threat-model-docx roles', ...)`.
15. `it('strict-threat mode fails when any row carries REQUIRES-OPERATOR-INPUT', ...)`.
16. `it('docx contains the threat-sources taxonomy table (NIST 800-30 r1 App. D)', ...)`.
17. `it('signs threat-model.json with Ed25519 + includes in RFC 3161 manifest', ...)`.

**REO compliance** specific to this slice:
- Every component classified from real `inventory.json` (no synthetic
  components).
- STRIDE catalog is a typed constant whose every row cites
  FRMR/NIST/MITRE source — no placeholder text.
- `mitigating_ksis` / `mitigating_controls` resolve through
  `ksi-map.ts` + `control-benchmark.ts`; unresolved cells surface as
  `REQUIRES-OPERATOR-INPUT`, never silent fallback.
- Operator sign-off is real human action recorded in `threat_models`
  table with Ed25519 signature; never auto-signed.
- `kill_chain_narrative` is verbatim operator text or empty; system
  never substitutes a "lorem ipsum" placeholder.
- Provenance block populated: emitter name, emittedAt (ISO),
  sourceCalls (inventory path, control benchmark version, KSI map
  version, MITRE/NIST citation refs), signingKeyId.
- No `process.env.NODE_ENV === 'test'` branches anywhere.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/threat-model.test.ts tests/core/threat-model-emit.test.ts tests/core/threat-model-docx.test.ts tests/core/stride-catalog.test.ts
npm run check:reo
npm run check:provenance
cd ../tracker
npm run typecheck
npm test -- server/routes/threat-model.test.ts client/src/pages/ThreatModel.test.tsx
```

**Estimated effort**: 6 - 8 working days (catalog seed is the largest
single bullet).

---

### Slice N.N2 — Attack surface enumeration (boundary entry points + exposed services)

**Why this slice**: FedRAMP SAR §3.4 requires an attack-surface
analysis; NIST SP 800-115 §4 + NIST SP 800-154 Step 2 require structured
identification of entry points and attack vectors; LOOP-K.K1 PenTest
ingest needs the scope to test. Today exposure is implicit in per-asset
booleans. N.N2 aggregates those signals + the network collectors'
ingress data into a system-level attack-surface inventory consumed by
SSP §9, SAR §3.4, PenTest RoE, and the OSCAL AR.

**Connection to FedPy mission**: Reads `inventory.json` +
`providers/{aws,gcp,azure}/network.ts` outputs (already collected). No
new cloud SDK calls. Emits `out/attack-surface.json` with provenance +
Ed25519 + RFC 3161. Cross-references LOOP-D.D1 boundary diagram (if
shipped) for visual consistency.

**Files to create**:
- `cloud-evidence/core/attack-surface.ts` — pure builder.
- `cloud-evidence/core/attack-surface-emit.ts` — disk emitter.
- `cloud-evidence/tests/core/attack-surface.test.ts`.
- `cloud-evidence/tests/core/attack-surface-emit.test.ts`.
- `tracker/server/routes/attack-surface.ts` — CRUD for operator-
  supplied annotations (subprocessor flows, partner integrations not in
  the cloud inventory).
- `tracker/server/routes/attack-surface.test.ts`.
- `tracker/client/src/pages/AttackSurface.tsx`.
- `tracker/client/src/pages/AttackSurface.test.tsx`.

**Files to extend**:
- `cloud-evidence/core/oscal.ts` (AR builder) — append
  `observation.props["attack-surface-uuid"]` referencing the
  attack-surface row.
- `cloud-evidence/core/oscal-ap.ts` — append
  `back-matter.resources[type=attack-surface]`.
- `cloud-evidence/core/orchestrator.ts` — `--attack-surface` flag
  (env `CLOUD_EVIDENCE_ATTACK_SURFACE`).
- `cloud-evidence/core/submission-bundle.ts` — add role
  `attack-surface-json`.
- `tracker/server/schema.sql` — `attack_surface_inventory` table.

**Schemas / standards**:
- **NIST SP 800-154 Step 2 (Identify and select the attack vectors)**
  — vector taxonomy referenced verbatim in module docstring.
- **NIST SP 800-115 §4 Target Identification and Analysis Techniques**
  — port discovery (§4.2), service identification (§4.3),
  vulnerability scanning (§4.4) inform the entry-point schema.
- **FedRAMP SAR §3.4** — output shape consumed by F.F7 SAR draft
  generator.
- **OWASP attack-surface analysis** —
  https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html
  — six surface categories used as the top-level grouping.

**Build steps**:

1. Define typed interfaces:
   ```ts
   export type SurfaceCategory =
     | 'internet-reachable-endpoint'
     | 'authentication-boundary'
     | 'administrative-interface'
     | 'data-plane-egress'
     | 'subprocessor-data-flow'
     | 'partner-integration'
     | 'physical-interface';

   export interface EntryPoint {
     uuid: string;
     category: SurfaceCategory;
     component_id: string;                  // inventory.assets[].identifier
     protocol: string;                      // tcp/443, udp/53, ...
     port?: number;
     fqdn?: string;
     ip_cidrs: string[];                    // allowed source CIDRs (0.0.0.0/0 if open)
     authentication: 'none' | 'basic' | 'mtls' | 'oidc' | 'iam' | 'pre-shared-key' | 'unknown';
     authorization: 'none' | 'rbac' | 'abac' | 'allow-list' | 'unknown';
     data_classes_in_transit: ('public' | 'internal' | 'confidential' | 'cui' | 'pii')[];
     mitigating_controls: string[];         // NIST 800-53 control ids
     mitigating_ksis: string[];             // canonical KSI IDs
     sources: {
       discovery: 'inventory.json' | 'providers/aws/network.ts' | 'providers/gcp/network.ts' | 'providers/azure/network.ts' | 'operator-supplied' | 'REQUIRES-OPERATOR-INPUT';
       data_class_source: 'inventory-tag' | 'operator-supplied' | 'REQUIRES-OPERATOR-INPUT';
     };
   }

   export interface AttackSurfaceInventory {
     uuid: string;
     emittedAt: string;
     formula_version: 'attack-surface.v1';
     system_id: string;
     entry_points: EntryPoint[];
     counts_by_category: Record<SurfaceCategory, number>;
     totals: {
       internet_reachable: number;
       authenticated: number;
       unauthenticated: number;
       cui_in_transit: number;
       pii_in_transit: number;
     };
     provenance: ProvenanceBlock;
   }
   ```

2. Pure builder:
   ```ts
   export function buildAttackSurface(
     inventory: InventoryComponent[],
     networkEvidence: NetworkEvidence[],
     ksiMap: KsiMap,
     controlBenchmark: ControlBenchmark,
     operatorAnnotations: OperatorAttackSurfaceAnnotation[],
   ): AttackSurfaceInventory;
   ```
   Algorithm:
   - For each `inventory.assets[]` with `public_facing === true` OR
     `internet_reachable === true`, emit an `internet-reachable-endpoint`
     row.
   - For each AWS Security Group / GCP firewall rule / Azure NSG rule
     with `source = 0.0.0.0/0` (or ::/0) and `action = allow`, emit
     entry points per protocol/port.
   - For each authentication-bearing surface (per inventory tag
     `auth_boundary=true`, or per detected service like API Gateway
     authorizer, GCP IAP), emit an `authentication-boundary` row.
   - For each admin-interface (SSH/RDP/WinRM/kubectl/management port),
     emit an `administrative-interface` row.
   - Egress: for each NAT gateway / VPC endpoint / Private Service
     Connect / Service Endpoint route to non-Internet destinations, do
     NOT emit; for Internet egress with sensitive data classes, emit
     `data-plane-egress`.
   - Operator annotations append `subprocessor-data-flow` and
     `partner-integration` rows (these can't be auto-derived from the
     cloud; operator supplies via tracker).

3. **Disk emitter**:
   ```ts
   export interface AttackSurfaceEmitOptions {
     outDir: string;
     inventoryPath?: string;
     networkEvidencePaths?: string[];     // per provider
     trackerSnapshotPath?: string;
     systemId: string;
     impactLevel: 'low' | 'moderate' | 'high';
     runId: string;
   }
   ```

4. **AR observation emission**: for each `EntryPoint`, emit:
   ```ts
   {
     uuid: ep.uuid,
     description: `Attack surface: ${ep.category} on ${ep.component_id}`,
     methods: ['EXAMINE'],
     subjects: [{ subject-uuid: ep.component_id, type: 'component' }],
     props: [
       { name: 'attack-surface-category', ns: CE_NS, value: ep.category },
       { name: 'attack-surface-protocol', ns: CE_NS, value: ep.protocol },
       ...(ep.port !== undefined ? [{ name: 'attack-surface-port', ns: CE_NS, value: String(ep.port) }] : []),
       { name: 'attack-surface-authentication', ns: CE_NS, value: ep.authentication },
       { name: 'attack-surface-authorization', ns: CE_NS, value: ep.authorization },
       ...ep.data_classes_in_transit.map(d => ({ name: 'data-class', ns: CE_NS, value: d })),
       ...ep.mitigating_ksis.map(k => ({ name: 'mitigating-ksi', ns: CE_NS, value: k })),
     ],
     'relevant-evidence': [{ href: `./attack-surface.json#/entry_points/${idx}` }],
   }
   ```

5. **AP back-matter**: append resource `type: attack-surface`.

6. **Bundler integration**: add role `attack-surface-json`.

7. **Tracker UI** — `attack_surface_inventory` schema:
   ```sql
   CREATE TABLE IF NOT EXISTS attack_surface_inventory (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     system_id TEXT NOT NULL,
     category TEXT NOT NULL,
     component_id TEXT NOT NULL,
     protocol TEXT NOT NULL,
     port INTEGER,
     fqdn TEXT,
     ip_cidrs_json TEXT NOT NULL,
     authentication TEXT NOT NULL,
     authorization TEXT NOT NULL,
     data_classes_in_transit_json TEXT NOT NULL,
     source TEXT NOT NULL CHECK (source IN ('auto-derived','operator-supplied')),
     operator_notes TEXT,
     signed_off_by_user_id INTEGER REFERENCES users(id),
     signed_off_at TEXT,
     signature TEXT,
     signing_key_id TEXT,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   ```

8. **Validation pass**: every entry point with
   `ip_cidrs` containing `0.0.0.0/0` AND `authentication = 'none'` is
   flagged in `out/attack-surface.json#/diagnostics` as an
   `internet-reachable-unauthenticated` finding (informational; not
   POA&M unless the orchestrator's downstream KSI check fails).

9. **`--strict-threat` mode**: orchestrator counts entry points with
   `discovery: 'REQUIRES-OPERATOR-INPUT'` and exits non-zero if any
   exist after operator-config pull.

**REQUIRES-OPERATOR-INPUT fields**:
- `data_classes_in_transit` — inventory tag `data_classification` is
  the primary signal; absent → REQUIRES-OPERATOR-INPUT.
- `subprocessor-data-flow` rows — entirely operator-supplied (no cloud
  signal exists for "we send data to Subprocessor X via SFTP").
- `partner-integration` rows — operator-supplied.
- `authentication` / `authorization` — auto-derived for known service
  types (API GW, IAP, ALB w/ Cognito); falls back to `'unknown'` +
  REQUIRES-OPERATOR-INPUT for the entry-point source.

**Test specifications** (≥ 12 tests):

1. `it('emits entry point per public_facing/internet_reachable inventory asset', ...)`.
2. `it('emits entry point per 0.0.0.0/0 security-group rule', ...)`.
3. `it('aggregates IPv4 + IPv6 CIDRs', ...)`.
4. `it('classifies API Gateway as authentication-boundary when authorizer present', ...)`.
5. `it('classifies SSH/RDP port as administrative-interface', ...)`.
6. `it('records data-class-in-transit from inventory tag', ...)`.
7. `it('emits REQUIRES-OPERATOR-INPUT data_class_source when tag absent', ...)`.
8. `it('appends operator-supplied subprocessor-data-flow rows', ...)`.
9. `it('produces counts_by_category aggregates that sum to entry_points.length', ...)`.
10. `it('AR observation emits attack-surface-category + protocol + port + authentication props', ...)`.
11. `it('AP back-matter resource type=attack-surface present', ...)`.
12. `it('strict-threat fails when REQUIRES-OPERATOR-INPUT discovery rows exist', ...)`.
13. `it('diagnostics flag internet-reachable-unauthenticated rows', ...)`.
14. `it('signs attack-surface.json with Ed25519 + RFC 3161', ...)`.
15. `it('bundler includes attack-surface-json role', ...)`.

**REO compliance**:
- Every entry point traces to a real cloud SDK call (already done by
  upstream collectors) or to operator-supplied annotation.
- No mocked SDK in production paths; the network evidence is read
  from real on-disk JSON emitted by existing collectors.
- `mitigating_ksis` / `mitigating_controls` resolved through real
  catalogs.
- Diagnostics block carries `internet-reachable-unauthenticated` rows
  observably; nothing buried.
- Provenance block populated.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/attack-surface.test.ts tests/core/attack-surface-emit.test.ts
npm run check:reo
npm run check:provenance
cd ../tracker
npm run typecheck
npm test -- server/routes/attack-surface.test.ts client/src/pages/AttackSurface.test.tsx
```

**Estimated effort**: 4 - 5 working days.

---

### Slice N.N3 — PASTA / red-team adversarial test framework (automated adversarial runs)

**Why this slice**: RFC-0014 demands "truly automated and opinionated
validation" of KSIs. The trust basis of that claim depends on
adversarial evidence: when an envelope is tampered, a signature is
replayed, a fixture is injected, the KEV reconcile is bypassed, does
the pipeline detect the attack and fail closed? Today no such evidence
exists. N.N3 ships an adversarial-test framework whose runs are
themselves signed evidence the pipeline meets its trust claim.

**Connection to FedPy mission**: Lives entirely under `tests/adversarial/`
(per CLAUDE.md Rule 1 boundary — production paths never know they're
being tested). Each adversarial run produces `out/adversarial-results.json`
with a signed manifest. The orchestrator `--adversarial` flag invokes
the runner; CI gates on the result. AR observations cite each test
verdict so a 3PAO can audit the pipeline's adversarial resilience.

**Files to create**:
- `cloud-evidence/core/adversarial-test-runner.ts` — orchestrates
  adversarial scenarios; emits result manifest.
- `cloud-evidence/core/adversarial-scenarios.ts` — typed catalog of
  scenarios (signature tampering, fixture injection, replay, KEV
  bypass, OSCAL chain corruption, EPSS-feed poisoning, KSI-map
  shadowing). Each scenario has expected outcome (`fail-closed` or
  `produce-diagnostic`).
- `cloud-evidence/tests/adversarial/signature-tamper.test.ts`.
- `cloud-evidence/tests/adversarial/fixture-injection.test.ts`.
- `cloud-evidence/tests/adversarial/replay-attack.test.ts`.
- `cloud-evidence/tests/adversarial/kev-bypass.test.ts`.
- `cloud-evidence/tests/adversarial/oscal-chain-corruption.test.ts`.
- `cloud-evidence/tests/adversarial/epss-poisoning.test.ts`.
- `cloud-evidence/tests/adversarial/ksi-map-shadowing.test.ts`.
- `cloud-evidence/tests/adversarial/threat-model-tampering.test.ts`.
- `cloud-evidence/tests/adversarial/attack-surface-injection.test.ts`.
- `cloud-evidence/tests/core/adversarial-test-runner.test.ts` — meta
  tests for the runner itself.
- `tracker/server/routes/adversarial-runs.ts` — read-only run viewer.
- `tracker/server/routes/adversarial-runs.test.ts`.
- `tracker/client/src/pages/AdversarialRuns.tsx`.
- `tracker/client/src/pages/AdversarialRuns.test.tsx`.

**Files to extend**:
- `cloud-evidence/core/oscal.ts` (AR builder) — for each adversarial
  scenario, emit `observation` with
  `methods: ['TEST']`, `props["adversarial-result"]`.
- `cloud-evidence/core/orchestrator.ts` — `--adversarial` flag (env
  `CLOUD_EVIDENCE_ADVERSARIAL`) + `--strict-adversarial`.
- `cloud-evidence/core/submission-bundle.ts` — add role
  `adversarial-results-json`.
- `tracker/server/schema.sql` — `adversarial_test_runs` table
  (append-only run history).
- `.github/workflows/ci.yml` — `npm run adversarial` job that fails
  the build on any unexpected outcome.

**Schemas / standards**:
- **PASTA — Process for Attack Simulation and Threat Analysis** —
  https://www.versprite.com/blog/what-is-pasta-threat-modeling/
  - Stage V Threat Analysis, Stage VI Vulnerability and Weakness
    Analysis, Stage VII Attack Modeling, Stage VIII Risk and Impact
    Analysis. Each scenario in `adversarial-scenarios.ts` cites the
    PASTA stage it exercises.
- **NIST SP 800-115 §6 Penetration Testing** — four-phase planning →
  discovery → attack → reporting model; the runner emits a phase
  marker per scenario.
- **NIST SP 800-53 Rev 5 SA-11(5) Penetration Testing** + **CA-8
  Penetration Testing** — the framework provides ongoing internal
  red-team evidence between formal pen tests.
- **RFC-0014 §3 "Automated and Opinionated Validation"** — adversarial
  evidence is the operational proof of the validation claim.
- **OSCAL AR `observation.methods`** — values
  `["EXAMINE","INTERVIEW","TEST"]`; N.N3 uses `"TEST"`.

**Build steps**:

1. Define typed interfaces:
   ```ts
   export type AdversarialOutcome =
     | 'fail-closed'             // expected: pipeline detected attack + rejected
     | 'detected-diagnostic'     // expected: produced REQUIRES-OPERATOR-INPUT
     | 'fail-open-DEFECT'        // pipeline silently accepted; bug
     | 'unexpected-pass-DEFECT'  // pipeline did not detect; bug
     | 'inconclusive';

   export interface AdversarialScenario {
     id: string;                                  // e.g. "ADV-001-sig-tamper"
     title: string;
     pasta_stage: 'V'|'VI'|'VII'|'VIII';
     nist_800_115_phase: 'planning'|'discovery'|'attack'|'reporting';
     target: 'envelope-signing' | 'envelope-parsing' | 'oscal-chain'
       | 'kev-reconcile' | 'epss-feed' | 'ksi-map' | 'threat-model'
       | 'attack-surface' | 'submission-bundle' | 'rfc3161-timestamp';
     mutator: (input: any) => any;                 // pure mutation
     expected_outcome: AdversarialOutcome;
     citation: { url: string; section: string };
   }

   export interface AdversarialRunResult {
     uuid: string;
     ranAt: string;
     run_id: string;
     scenario_id: string;
     observed_outcome: AdversarialOutcome;
     observed_diagnostic?: string;
     verdict: 'pass' | 'fail';
     pipeline_artifacts_hash: string;              // sha256 of relevant artifact post-test
     provenance: ProvenanceBlock;
   }

   export interface AdversarialResultsManifest {
     uuid: string;
     emittedAt: string;
     formula_version: 'adversarial.v1';
     runs: AdversarialRunResult[];
     totals: { pass: number; fail: number; inconclusive: number };
     provenance: ProvenanceBlock;
   }
   ```

2. **Runner** (`core/adversarial-test-runner.ts`):
   ```ts
   export interface AdversarialRunnerOptions {
     outDir: string;
     fixtureDir: string;        // tests/fixtures/adversarial/
     scenarioFilter?: string[]; // run subset by id
     runId: string;
   }
   export async function runAdversarialScenarios(
     opts: AdversarialRunnerOptions,
   ): Promise<AdversarialResultsManifest>;
   ```
   - Iterates `ADVERSARIAL_SCENARIOS` from `adversarial-scenarios.ts`.
   - For each, applies the mutator to a fixture envelope/file/feed,
     invokes the real production code path on the mutated input,
     observes outcome.
   - Outcome compared to `expected_outcome`; mismatch → `verdict:
     'fail'` AND CI exits non-zero in strict mode.

3. **Scenarios** (`core/adversarial-scenarios.ts`) — at minimum:
   - **ADV-001 Signature tamper** — flip a single byte of envelope
     payload after signing; re-verify; expect `fail-closed` (signature
     check returns false; envelope rejected).
   - **ADV-002 Fixture injection** — supply a fixture KSI envelope as
     production input via the file ingest path; expect
     `detected-diagnostic` (provenance block missing → REO Rule 1.3 → 
     check:reo catches; or hash mismatch caught by manifest).
   - **ADV-003 Replay** — re-submit a yesterday-timestamped envelope as
     today's evidence; expect `detected-diagnostic` (RFC 3161 timestamp
     skew check or run-ledger duplicate detection).
   - **ADV-004 KEV bypass** — strip CVE id from a finding referencing a
     KEV-listed CVE; expect `fail-closed` or `detected-diagnostic`
     (deadline computation falls back to CMP table; B.B2's
     `severity-fallback` source surfaces).
   - **ADV-005 OSCAL chain corruption** — flip the AP UUID in the AR
     `import-ap` block; expect `fail-closed` (chain validation rejects).
   - **ADV-006 EPSS poisoning** — supply a forged EPSS cache entry with
     score 0.0 for a KEV-listed CVE; expect `detected-diagnostic`
     (provenance source mismatch; B.B1 `epss.source: 'config'` requires
     operator-confirmed flag).
   - **ADV-007 KSI-map shadowing** — register a duplicate KSI id with
     a different mitigation; expect `fail-closed` (duplicate-id check
     in `core/ksi-map.ts:validate()`).
   - **ADV-008 Threat-model tampering** — modify a row's
     `mitigating_ksis` after operator sign-off; expect `fail-closed`
     (signature verification on the tracker row).
   - **ADV-009 Attack-surface injection** — operator submits a
     fake entry-point row claiming `authentication: 'mtls'` for an
     internet-exposed port that actually has no auth; expect
     `detected-diagnostic` (cross-check against inventory shows no
     mtls config detected).
   - **ADV-010 Submission-bundle role collision** — register two
     different files under the same role; expect `fail-closed`
     (bundler dedup check).

4. **Manifest emission**: `out/adversarial-results.json` carries the
   `AdversarialResultsManifest`. Signed by `core/sign.ts`.

5. **AR observation emission**: for each run, emit:
   ```ts
   {
     uuid: run.uuid,
     description: `Adversarial scenario ${run.scenario_id}`,
     methods: ['TEST'],
     props: [
       { name: 'adversarial-scenario-id', ns: CE_NS, value: run.scenario_id },
       { name: 'adversarial-expected-outcome', ns: CE_NS, value: scenario.expected_outcome },
       { name: 'adversarial-observed-outcome', ns: CE_NS, value: run.observed_outcome },
       { name: 'adversarial-verdict', ns: CE_NS, value: run.verdict },
       { name: 'pasta-stage', ns: CE_NS, value: scenario.pasta_stage },
     ],
     'relevant-evidence': [{ href: `./adversarial-results.json#/runs/${idx}` }],
   }
   ```

6. **Tracker `adversarial_test_runs` table** (append-only):
   ```sql
   CREATE TABLE IF NOT EXISTS adversarial_test_runs (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     run_id TEXT NOT NULL,
     scenario_id TEXT NOT NULL,
     expected_outcome TEXT NOT NULL,
     observed_outcome TEXT NOT NULL,
     verdict TEXT NOT NULL CHECK (verdict IN ('pass','fail')),
     pipeline_artifacts_hash TEXT NOT NULL,
     ran_at TEXT NOT NULL,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_adv_run ON adversarial_test_runs(run_id);
   CREATE INDEX IF NOT EXISTS idx_adv_scenario ON adversarial_test_runs(scenario_id);
   CREATE INDEX IF NOT EXISTS idx_adv_verdict ON adversarial_test_runs(verdict);
   ```

7. **CI integration**: `.github/workflows/ci.yml` runs `npm run
   adversarial` after `npm test`; sets `CLOUD_EVIDENCE_STRICT_ADVERSARIAL=1`;
   any `verdict: 'fail'` exits non-zero; CI rejects the change.

8. **Bundler integration**: add role `adversarial-results-json`.

**REQUIRES-OPERATOR-INPUT fields**:
- Scenario catalog (`ADVERSARIAL_SCENARIOS`) is a typed constant — no
  operator input required to RUN the suite.
- Operator can supply `--scenario-filter` to skip flaky scenarios in
  a particular environment; flag is observable in the manifest
  `provenance.sourceCalls` so a 3PAO sees which were skipped.

**Test specifications** (≥ 12 tests):

1. `it('runs every ADVERSARIAL_SCENARIO and emits one run per scenario', ...)`.
2. `it('ADV-001 signature tamper produces fail-closed verdict pass', ...)`.
3. `it('ADV-002 fixture injection produces detected-diagnostic verdict pass', ...)`.
4. `it('ADV-003 replay attack produces detected-diagnostic verdict pass', ...)`.
5. `it('ADV-004 KEV bypass produces fail-closed or detected-diagnostic verdict pass', ...)`.
6. `it('ADV-005 OSCAL chain corruption produces fail-closed verdict pass', ...)`.
7. `it('ADV-006 EPSS poisoning produces detected-diagnostic verdict pass', ...)`.
8. `it('ADV-007 KSI-map shadowing produces fail-closed verdict pass', ...)`.
9. `it('ADV-008 threat-model tampering produces fail-closed verdict pass', ...)`.
10. `it('ADV-009 attack-surface injection produces detected-diagnostic verdict pass', ...)`.
11. `it('ADV-010 submission-bundle role collision produces fail-closed verdict pass', ...)`.
12. `it('manifest carries provenance block with sourceCalls per scenario', ...)`.
13. `it('signs adversarial-results.json with Ed25519 + RFC 3161', ...)`.
14. `it('writes one row per run to adversarial_test_runs table', ...)`.
15. `it('AR observation emits adversarial-scenario-id + adversarial-verdict props', ...)`.
16. `it('strict-adversarial exits non-zero when any verdict=fail', ...)`.
17. `it('scenario-filter skips listed scenarios and records in provenance', ...)`.

**REO compliance**:
- All adversarial fixtures live under `tests/fixtures/adversarial/`
  (REO Rule 1 boundary).
- Production code paths exercised under attack are the REAL paths —
  no `if (NODE_ENV === 'test')` branches; the runner injects mutators
  through public APIs only.
- Signatures real Ed25519; manifest hash real sha256.
- Failed verdicts are visible (not buried); CI rejects.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/adversarial tests/core/adversarial-test-runner.test.ts
CLOUD_EVIDENCE_STRICT_ADVERSARIAL=1 npm run adversarial
npm run check:reo
npm run check:provenance
cd ../tracker
npm run typecheck
npm test -- server/routes/adversarial-runs.test.ts client/src/pages/AdversarialRuns.test.tsx
```

**Estimated effort**: 7 - 9 working days (scenario authoring +
production-path hardening is the largest single bullet).

---

### Slice N.N4 — MITRE ATT&CK technique mapping (which techniques apply to our boundary)

**Why this slice**: NIST SP 800-53 Rev 5 RA-10 (Threat Hunting), CA-8
(Penetration Testing), and SI-3/SI-4 all reference an organisational
baseline of known adversary techniques. MITRE ATT&CK Enterprise + Cloud
is the de-facto open standard. Today FedPy maps KEV → CVE → KSI via the
existing VDR pipeline; nothing yet maps technique → KSI → control. N.N4
closes that loop and produces a coverage matrix the dashboard, monthly
ConMon report, and SAR all consume.

**Connection to FedPy mission**: Reads `core/kev-feed.ts` output (KEV
entries with CVE ids), the committed MITRE ATT&CK STIX 2.1 subset
(`docs/sources/mitre-attack-cloud.subset.json`), the committed ATT&CK→NIST
mapping (`docs/sources/attack-nist-mappings.json` from Center for
Threat-Informed Defense), and the FRMR catalog
(`docs/frmr-requirements.generated.json`). No cloud SDK calls. Emits
`out/attack-mapping.json` with provenance, Ed25519, RFC 3161.

**Files to create**:
- `cloud-evidence/core/attack-mapping.ts` — pure builder: reads ATT&CK
  subset + ATT&CK→NIST mapping + KSI map; produces
  `AttackMapping` typed value.
- `cloud-evidence/core/attack-mapping-emit.ts` — disk emitter.
- `cloud-evidence/core/attack-stix-loader.ts` — STIX 2.1 reader for
  the committed subset.
- `cloud-evidence/docs/sources/mitre-attack-cloud.subset.json` —
  pinned STIX subset (Cloud platform sub-matrix entries).
- `cloud-evidence/docs/sources/attack-nist-mappings.json` — pinned
  Center for Threat-Informed Defense mapping JSON.
- `cloud-evidence/scripts/refresh-attack-mappings.mjs` — operator-run
  script that re-pulls the upstream sources + versions the subset.
- `cloud-evidence/tests/core/attack-mapping.test.ts`.
- `cloud-evidence/tests/core/attack-mapping-emit.test.ts`.
- `cloud-evidence/tests/core/attack-stix-loader.test.ts`.

**Files to extend**:
- `cloud-evidence/core/oscal-poam.ts` — `findingProps()` appends
  `attack-technique` props when a finding maps to a technique (via
  CVE → KEV → technique).
- `cloud-evidence/core/oscal.ts` (AR builder) — for each technique in
  the system's mapping, emit an `observation` with
  `methods: ['EXAMINE']`, `props["attack-technique"]`,
  `props["attack-tactic"]`, `relevant-evidence` → coverage row.
- `cloud-evidence/core/orchestrator.ts` — `--attack-mapping` flag
  (env `CLOUD_EVIDENCE_ATTACK_MAPPING`).
- `cloud-evidence/core/submission-bundle.ts` — add role
  `attack-mapping-json`.
- `tracker/client/src/pages/AttackMatrix.tsx` — heat-map view of
  techniques × coverage status (reuses existing dashboard pattern,
  no new server route).

**Schemas / standards**:
- **MITRE ATT&CK STIX 2.1** — pinned subset committed at
  `docs/sources/mitre-attack-cloud.subset.json`. Each technique JSON
  carries `external_references[]` (the canonical T-id), `kill_chain_phases[]`
  (tactic mapping), `x_mitre_platforms[]`, `x_mitre_data_sources[]`,
  `x_mitre_detection`.
- **ATT&CK→NIST 800-53 Rev 5 Mapping** — Center for Threat-Informed
  Defense canonical mapping:
  https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/blob/main/frameworks/nist800-53-r5/mappings/nist800-53-r5-attack-mappings.json
  - Each row: `{ technique_id, control_id, mapping_type }`.
- **OSCAL POA&M `risk.props[name=attack-technique]`** + AR
  observation prop — namespace `CE_NS`.

**Build steps**:

1. Define typed interfaces:
   ```ts
   export type TechniqueCoverageStatus =
     | 'covered-full' | 'covered-partial' | 'covered-via-compensating'
     | 'gap' | 'not-applicable' | 'REQUIRES-OPERATOR-INPUT';

   export interface AttackTechniqueRow {
     technique_id: string;                  // e.g. "T1110"
     technique_name: string;
     tactic_ids: string[];                  // e.g. ["TA0006"]
     tactic_names: string[];
     platforms: string[];                   // x_mitre_platforms
     applicable_to_system: boolean;          // derived from inventory.platforms
     mitigating_nist_controls: string[];    // from ATT&CK→NIST mapping
     mitigating_ksis: string[];             // resolved via ksi-map.ts
     coverage_status: TechniqueCoverageStatus;
     active_kev_cve_ids: string[];          // CVEs from KEV mapped to this technique
     observed_findings: string[];           // POA&M finding uuids referencing CVEs in active_kev_cve_ids
     sources: {
       stix_pinned_version: string;
       mapping_pinned_version: string;
       kev_fetched_at: string;
     };
   }

   export interface AttackMapping {
     uuid: string;
     emittedAt: string;
     formula_version: 'attack-mapping.v1';
     system_id: string;
     impact_level: 'low' | 'moderate' | 'high';
     rows: AttackTechniqueRow[];
     totals: Record<TechniqueCoverageStatus, number>;
     tactic_summary: Record<string, {
       tactic_id: string;
       tactic_name: string;
       technique_count: number;
       covered: number;
       gap: number;
     }>;
     provenance: ProvenanceBlock;
   }
   ```

2. **STIX loader** (`core/attack-stix-loader.ts`): reads the pinned
   subset JSON; exposes `loadAttackCatalog(): { techniques, tactics,
   mitigations }`. Validates JSON-schema-by-shape (presence of
   `type: "attack-pattern"` etc.).

3. **Pure builder** (`core/attack-mapping.ts`):
   ```ts
   export function buildAttackMapping(
     inventory: InventoryComponent[],
     attackCatalog: AttackCatalog,
     attackToNistMapping: AttackNistMapping[],
     kevCatalog: KevEntry[],
     attackCveMappings: AttackCveMapping[],       // optional; from CTID attack_to_cve repo
     ksiMap: KsiMap,
     controlBenchmark: ControlBenchmark,
     poamFindings: PoamFinding[],
     impactLevel: 'low' | 'moderate' | 'high',
   ): AttackMapping;
   ```
   Algorithm:
   - Filter techniques to those with `x_mitre_platforms` overlapping
     the inventory's detected platforms (AWS / GCP / Azure / Containers
     / IaaS / SaaS / Identity Provider / Office Suite). For SaaS-only
     CSP, ignore "Linux/Windows/macOS" host-only techniques unless an
     inventory component matches.
   - For each applicable technique, resolve `mitigating_nist_controls`
     via the ATT&CK→NIST mapping filtered to controls in the
     `controlBenchmark` baseline at `impactLevel`.
   - Resolve `mitigating_ksis` via `ksi-map.ts` (NIST control → KSI).
   - Determine `coverage_status`:
     - `covered-full` if every mitigating control is "implemented"
       per benchmark.
     - `covered-partial` if some are implemented.
     - `covered-via-compensating` if all are open but a B.B4
       compensating control is linked.
     - `gap` if mitigations exist in mapping but none implemented.
     - `not-applicable` if `applicable_to_system === false`.
     - `REQUIRES-OPERATOR-INPUT` if mapping has zero rows for the
       technique at this impact level.
   - Reconcile `active_kev_cve_ids`: for each KEV entry, find which
     technique it maps to (via `attackCveMappings` if available, else
     `REQUIRES-OPERATOR-INPUT: technique-classification`). Append CVE
     to the technique row.
   - Reconcile `observed_findings`: for each POA&M finding whose
     `references[].cve_ids` overlaps `active_kev_cve_ids`, append the
     finding uuid.

4. **Disk emitter** (`core/attack-mapping-emit.ts`):
   ```ts
   export interface AttackMappingEmitOptions {
     outDir: string;
     inventoryPath?: string;
     poamPath?: string;
     stixSubsetPath?: string;
     attackNistMappingPath?: string;
     attackCveMappingPath?: string;
     systemId: string;
     impactLevel: 'low' | 'moderate' | 'high';
     runId: string;
   }
   export async function emitAttackMapping(
     opts: AttackMappingEmitOptions,
   ): Promise<{ path: string; coverage_status_counts: Record<TechniqueCoverageStatus, number>; }>;
   ```

5. **POA&M prop emission** (extend `core/oscal-poam.ts:findingProps()`):
   ```ts
   if (f.references) {
     const cves = f.references.flatMap(r => r.cve_ids ?? []);
     for (const cve of cves) {
       const techniques = lookupTechniquesForCve(cve, attackCveMappings);
       for (const t of techniques) {
         props.push({ name: 'attack-technique', ns: CE_NS, value: t.technique_id });
         for (const tactic of t.tactic_ids) {
           props.push({ name: 'attack-tactic', ns: CE_NS, value: tactic });
         }
       }
     }
   }
   ```

6. **AR observation emission**: one observation per technique row.

7. **Bundler integration**: add role `attack-mapping-json`.

8. **Refresh script**: `scripts/refresh-attack-mappings.mjs` fetches
   the latest STIX from the MITRE CTI repo + the latest CTID mapping,
   writes the pinned subset (Cloud platform only) +
   `attack-nist-mappings.json`. Operator runs this manually; CHANGELOG
   entry pins the version.

**REQUIRES-OPERATOR-INPUT fields**:
- `applicable_to_system` heuristics fall back to operator config when
  inventory platform tags are ambiguous (e.g. CSP runs SaaS but has
  Office Suite integrations — operator confirms).
- `coverage_status: REQUIRES-OPERATOR-INPUT` when the ATT&CK→NIST
  mapping has zero rows for a technique at the configured impact
  level — operator supplies a compensating-control reference (B.B4) or
  marks N/A with justification.
- CVE → technique mapping when not in the published CTID
  attack_to_cve repo — operator supplies via tracker / config.

**Test specifications** (≥ 12 tests):

1. `it('loads pinned STIX subset and exposes techniques + tactics + mitigations', ...)`.
2. `it('filters techniques by x_mitre_platforms vs inventory platforms', ...)` —
   AWS-only inventory drops Azure-only techniques.
3. `it('resolves mitigating NIST controls via ATT&CK→NIST mapping at Moderate baseline', ...)`.
4. `it('resolves mitigating KSIs via ksi-map.ts', ...)`.
5. `it('classifies coverage-full when all mitigating controls implemented', ...)`.
6. `it('classifies covered-via-compensating when B.B4 CC linked', ...)`.
7. `it('classifies gap when mappings exist but none implemented', ...)`.
8. `it('classifies REQUIRES-OPERATOR-INPUT when mapping has zero rows', ...)`.
9. `it('reconciles active_kev_cve_ids via attack_to_cve mapping', ...)`.
10. `it('emits REQUIRES-OPERATOR-INPUT for KEV CVE without a CTID mapping', ...)`.
11. `it('reconciles observed_findings by CVE overlap with POA&M', ...)`.
12. `it('totals counts_by_status sum to rows.length', ...)`.
13. `it('produces tactic_summary with correct technique_count per tactic', ...)`.
14. `it('attack-mapping.json provenance block lists STIX + mapping pinned versions', ...)`.
15. `it('POA&M findingProps appends attack-technique + attack-tactic props', ...)`.
16. `it('AR observation per technique row emits attack-technique prop', ...)`.
17. `it('bundler includes attack-mapping-json role', ...)`.
18. `it('refresh script writes a new subset with updated pinned version', ...)`.

**REO compliance**:
- ATT&CK subset + NIST mapping JSON are committed pinned-version
  artifacts under `docs/sources/`; not silently re-pulled at run time.
- KEV catalog read via existing `core/kev-feed.ts` (already real).
- Unmapped techniques emit REQUIRES-OPERATOR-INPUT; never silent
  "covered" default.
- POA&M prop additions go through `CE_NS` namespace + ajv validation.
- Provenance block lists pinned versions of every source.

**Verification commands**:
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/attack-mapping.test.ts tests/core/attack-mapping-emit.test.ts tests/core/attack-stix-loader.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 5 - 6 working days (the largest single bullet
is curating the pinned STIX subset to the platforms actually present
in the CSP's inventory).

---

## 6. Loop-wide acceptance criteria

LOOP-N is COMPLETE when ALL of the following are true:

1. **N.N1**: `out/threat-model.json` + `out/threat-model.docx` emit
   end-to-end; STRIDE catalog covers ≥ 30 high-signal rows with
   FRMR/NIST/MITRE citations; per-component threat rows attach to AR
   observations; SSP back-matter cites the threat-model resource;
   tracker UI for kill-chain narrative + per-row sign-off ships;
   strict-threat mode catches `REQUIRES-OPERATOR-INPUT` rows.
2. **N.N2**: `out/attack-surface.json` emits end-to-end; entry points
   classify into 7 SurfaceCategory buckets; counts_by_category +
   totals match `entry_points.length`; AP back-matter cites the
   attack-surface resource; AR observations attach attack-surface
   props; tracker UI for operator-supplied subprocessor / partner
   flows ships.
3. **N.N3**: `tests/adversarial/**` covers ≥ 10 scenarios (ADV-001 …
   ADV-010); runner emits `out/adversarial-results.json` with verdicts;
   AR observations include adversarial-result props; CI gate fails on
   any `verdict: 'fail'`; `adversarial_test_runs` table persists run
   history.
4. **N.N4**: `out/attack-mapping.json` emits end-to-end; pinned STIX
   subset + ATT&CK→NIST mapping committed; coverage status per
   technique computed; POA&M `findingProps` appends `attack-technique`
   + `attack-tactic` props; AR observation per row emits attack
   coverage; tracker UI heat-map ships.
5. All four slices pass `npm run typecheck`, `npm test`, and
   `npm run check:reo` in both `cloud-evidence/` and `tracker/`.
6. CHANGELOG "Unreleased" has four entries (one per slice) with
   module names + verification counts + REO compliance notes.
7. STATUS.md per-slice rows updated.

---

## 7. Open questions / caveats

1. **LOOP-D.D3 DFD overlay sequencing** — N.N1's DFD overlay
   feature consumes the LOOP-D.D3-emitted Data Flow Diagram. If
   LOOP-D.D3 is unshipped at N.N1 time, the slice ships without
   the overlay (the docstring documents the omission with a
   forward-link to D.D3). The CHANGELOG entry for D.D3 then adds a
   "back-fills LOOP-N.N1 DFD overlay" addendum at D.D3 ship.

2. **MITRE ATT&CK release cadence** — ATT&CK ships a release ~every
   six months; the pinned subset must be refreshed periodically. The
   refresh script (`scripts/refresh-attack-mappings.mjs`) is operator-
   run; cadence documented in operator runbook. CHANGELOG entries log
   the pinned version at each refresh.

3. **CVE → technique mapping completeness** — the Center for
   Threat-Informed Defense `attack_to_cve` repo does not cover every
   CVE. Unmapped CVEs emit `REQUIRES-OPERATOR-INPUT: technique-
   classification`; the operator can supply via tracker (a future
   slice may automate via NLP over CVE descriptions).

4. **STRIDE catalog completeness vs scope** — N.N1's
   `stride-catalog.ts` covers 11 × 6 = 66 cells of the
   ComponentClass × STRIDE matrix, but ~36 cells have meaningful
   threats; the rest are documented as "n/a — no plausible threat at
   this category × class" with a comment in the catalog. CHANGELOG
   entry for N.N1 lists which cells are populated.

5. **Adversarial scenario expansion** — the 10 scenarios ADV-001…010
   are the seed. Future contributions add scenarios as the pipeline
   evolves (e.g. when LOOP-B.B3 ships, ADV-011 should exercise
   risk-acceptance signature replay). The catalog is extensible.

6. **Strict-adversarial in CI** — CI defaults `--strict-adversarial`
   ON. Local development can run `npm test` without the flag for
   iteration speed; the `adversarial` job is separate.

7. **Tracker tenancy** — N.N1 + N.N2 + N.N3 tables omit `tenant_id`.
   When H.H3 (multi-CSO) ships, it migrates all three tables in one
   cross-loop sweep. LOOP-N ships single-tenant only.

8. **OSCAL `back-matter.resources[type]` registration** — the
   `threat-model` and `attack-surface` `type` tokens are
   FedPy-specific extensions. Document them in
   `docs/oscal/extensions.md` (committed alongside N.N1) so the OSCAL
   namespace policy is unambiguous.

9. **NIST SP 800-30 r1 PDF gating** — like the FedRAMP CMP PDF in
   LOOP-B, the NIST 800-30 r1 PDF returns binary content to anonymous
   WebFetch. Implementer manually downloads to
   `docs/sources/nist-sp-800-30r1.pdf`; the N.N1 docstring carries
   `REQUIRES-OPERATOR-INPUT: confirm-against-nist-800-30r1-pdf` until
   downloaded.

10. **Audit-doc audit citation of "3 slices"** —
    `docs/ADDITIONAL-LOOPS-AUDIT.md` §2 LOOP-N enumerates three
    slices (STRIDE emitter, tabletop facilitator, adversarial tests).
    This spec ships **four** slices, replacing the audit's "tabletop
    facilitator" (which belongs more naturally in LOOP-E.E7 / IRP
    cadence) with two more impactful artifacts: attack-surface
    enumeration (N.N2) and MITRE ATT&CK technique map (N.N4). The
    audit's tabletop facilitator slice is re-routed to LOOP-E.E7 as
    an extension; this divergence is documented atomically with
    LOOP-N adoption in STATUS.md.

11. **Sign-off model for the threat model** — IS owner (`iso`)
    signs each row; AO sign-off is OPTIONAL (the threat model is an
    SSP appendix, not a separate authorization artifact). RBAC defined
    in N.N1.

---

## 8. Status tracking

Update this table when a slice ships (see Section 9).

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| N.N1 | STRIDE threat model generator (per-component, from inventory + DFD) | pending | — | — |
| N.N2 | Attack surface enumeration (boundary entry points + exposed services) | pending | — | — |
| N.N3 | PASTA/red-team adversarial test framework (automated runs) | pending | — | — |
| N.N4 | MITRE ATT&CK technique mapping (techniques applicable to our boundary) | pending | — | — |

---

## 9. Slice completion procedure (REO-enforced)

See `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
mandatory 7-step procedure. Summary:

1. **Verify green**: from repo root
   ```bash
   cd cloud-evidence
   npm run typecheck            # must be clean
   npm test                     # 100% passing (existing total + new slice tests)
   npm run check:reo            # G1+G2+G3 all green
   npm run check:provenance     # every new emit-field has provenance entry
   ```
   For slices touching the tracker (N.N1, N.N2, N.N3):
   ```bash
   cd ../tracker
   npm run typecheck
   npm test
   ```

2. **Update Section 8 status table**: edit
   `cloud-evidence/docs/loops/LOOP-N-SPEC.md` (this file). Set the
   slice's row to `status=done`, `commit=<short-sha>`,
   `date=<YYYY-MM-DD>`.

3. **Update CHANGELOG.md "Unreleased"**: add a new
   `### Added — LOOP-N.<id>: <title>` block at the top of "Unreleased".
   Mirror the LOOP-A.A* entries for tone + depth. Cite module names,
   spec links, verification counts:
   - New tests + total tests after slice
   - Whether typecheck + check:reo are green
   - Net new files
   - Brief REO-compliance note (sources cited verbatim; provenance
     populated)

4. **Update `cloud-evidence/docs/STATUS.md`**: set the slice row to
   `done`. Update the Overall section's last-shipped + next-priority
   lines if this was the loop's last slice.

5. **Commit**: from repo root
   ```bash
   git add -A
   git commit -m "LOOP-N.<id>: <title>"
   ```
   Commit message body: short paragraph mirroring CHANGELOG entry intent.

6. **Push**: `git push origin main`.

7. **Sanity check**: re-clone into a scratch directory, run the
   orchestrator on a fixture inventory, verify the new artifact lands
   in `out/`.

---

## 10. Appendix — worked example: STRIDE row for a public-facing ALB

To make N.N1 reviewable, here is the worked example the test suite
encodes verbatim. Given an inventory asset:

```json
{
  "identifier": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/web/abc",
  "asset_type": "elb.application-load-balancer",
  "data_classification": "pii",
  "asset_tier": "tier-0",
  "public_facing": true,
  "internet_reachable": true,
  "tags": { "fedramp_component_class": "network" }
}
```

The threat model emits one row per STRIDE category. The
**Information Disclosure** row:

```json
{
  "uuid": "<v5(component_id, 'information-disclosure')>",
  "component_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/web/abc",
  "component_class": "network",
  "stride": "information-disclosure",
  "threat_sources": [
    { "class": "adversarial", "actor": "external attacker", "capability": "moderate", "intent": "targeted" }
  ],
  "threat_event": "Eavesdropping on PII in transit to the application load balancer",
  "cwe_ids": ["CWE-319", "CWE-200"],
  "mitigating_ksis": ["SVC-VRI", "CNA-RVP"],
  "mitigating_controls": ["SC-8", "SC-8(1)", "SC-12", "SC-13"],
  "operator_signed_off": false,
  "sources": {
    "component_source": "inventory.json",
    "stride_catalog_source": "stride-catalog.ts",
    "mitigation_source": "ksi-map.ts",
    "threat_source_source": "NIST-800-30-r1-App-D"
  }
}
```

Quality of this signal:
- SSP §13 narrative for SC-8 now has a concrete component reference
  + threat-event sentence.
- SAR §3.4 attack-surface analysis cross-references the same component.
- 3PAO walking the threat model sees the KSI ↔ control ↔ component
  chain end-to-end.
- N.N4's attack mapping cross-references the SAME component for
  technique T1040 (Network Sniffing) under tactic TA0009 (Collection).
- B.B5 risk register lists the same finding under
  `inherent_risk = high`, `residual_risk = moderate` after SC-8(1)
  is implemented.

That is the LOOP-N value proposition end-to-end.

---

## 11. Appendix — worked example: ATT&CK technique coverage row

For technique T1110 (Brute Force) under tactic TA0006 (Credential
Access):

```json
{
  "technique_id": "T1110",
  "technique_name": "Brute Force",
  "tactic_ids": ["TA0006"],
  "tactic_names": ["Credential Access"],
  "platforms": ["AWS","Azure","GCP","Office Suite","SaaS","Identity Provider"],
  "applicable_to_system": true,
  "mitigating_nist_controls": ["AC-7","IA-5(1)","IA-2(1)","IA-2(2)","IA-2(11)"],
  "mitigating_ksis": ["IAM-MFA","IAM-APM","IAM-AAM"],
  "coverage_status": "covered-full",
  "active_kev_cve_ids": [],
  "observed_findings": [],
  "sources": {
    "stix_pinned_version": "attack-pattern--v15.1",
    "mapping_pinned_version": "ctid-nist800-53r5-v1.2",
    "kev_fetched_at": "2026-06-07T00:00:00Z"
  }
}
```

The dashboard heat-map (LOOP-I.I3) renders this row as green; the
monthly ConMon report (LOOP-E.E1) reports
`tactic_summary[TA0006].covered = N of total`; the SAR §3.4 lists the
technique under "covered surfaces"; the AR observation cites the
technique mapping.

End of LOOP-N-SPEC.md.
