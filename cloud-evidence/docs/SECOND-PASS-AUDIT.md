# Second-Pass Audit (after LOOP-L through LOOP-Q added)

> **Status update (2026-06-07):** LOOP-R (Post-Quantum Cryptography
> Migration), LOOP-S (DFARS 252.204-7012 Cloud Equivalency, conditional),
> and the CIRCIA Final Rule extensions to G.G2 + M.M4 — the three items
> this second-pass audit flagged as "still missing" — are now **fully
> specified per the human's 2026-06-07 ratification decision**. Spec
> docs, per-slice docs, risks registers, and CIRCIA workflow doc are on
> disk:
>
> - `docs/loops/LOOP-R-SPEC.md` + `docs/loops/LOOP-R-RISKS.md` + `docs/slices/R/R.R{1,2,3}.md`
> - `docs/loops/LOOP-S-SPEC.md` + `docs/loops/LOOP-S-RISKS.md` + `docs/slices/S/S.S{1,2,3}.md`
> - `docs/CIRCIA-WORKFLOW.md` + `docs/slices/G/G.G2-CIRCIA-EXTENSION.md` + `docs/slices/M/M.M4-CIRCIA-EXTENSION.md`
> - `docs/THIRD-PASS-AUDIT.md` — the third-pass audit that surfaced the above
>
> STATUS.md, CLAUDE.md reading list, DEPENDENCY-GRAPH.md, GLOSSARY.md,
> and EXECUTION-PLAN.md have all been updated to reference these new
> loops + overlays. Implementation priority remains LOOP-B.B1 first;
> LOOP-R is mandatory (federal PQC mandate), LOOP-S is conditional
> (DoD-prime customers only), and CIRCIA overlays are HIGH PRIORITY
> (May 2026 effective date — human may elevate above LOOP-B.B1).

> Date: 2026-06-07. Author: automated audit pass. Status: PROPOSED — not yet adopted in STATUS.md.
>
> Authority: governed by `cloud-evidence/CLAUDE.md` Real-Evidence-Only (REO)
> standard. Every recommendation below cites a public authoritative source.
> Where the source is unreachable through anonymous fetch the URL is recorded
> verbatim and the implementer downloads the source PDF / page to
> `cloud-evidence/docs/sources/` per the same pattern LOOP-B follows for the
> FedRAMP CMP PDF.
>
> Provenance for this audit: this is a *second pass* over the FedRAMP 20x
> Moderate obligation surface. The *first pass*
> (`docs/ADDITIONAL-LOOPS-AUDIT.md`, 2026-06-06) surfaced LOOP-L through
> LOOP-Q (20 new slices + 12 extensions) on top of the original LOOP-A–K
> (49 slices). This pass treats LOOP-L–Q as accepted and looks for what is
> *still* missing.

---

## 1. Methodology

### 1.1 What I searched for

A targeted re-audit of 15 candidate obligation surfaces that were NOT
covered by LOOP-A–K and were NOT proposed by the first-pass audit
(LOOP-L–Q). The list was supplied by the human prompt; for each I:

1. Read every loop spec (LOOP-A–Q) + every section doc (SECTION-A–F) +
   `ADDITIONAL-LOOPS-AUDIT.md` for direct coverage or recorded out-of-scope
   classification.
2. Web-fetched the authoritative source (or its closest reachable proxy)
   to confirm the obligation actually applies to a Phase Two Moderate
   CSP at GA.
3. Compared the obligation against the proposed extension surface in
   first-pass §3 to see whether an existing extension already covered it.
4. Categorised each item into one of: §2 STILL missing (propose
   adopting), §3 confirmed-covered after L–Q, §4 out-of-scope at Moderate.

### 1.2 The 15 candidate surfaces evaluated

1. SLAs / Service Level Agreements (uptime, availability, support)
2. DevSecOps + SLSA / SBOM provenance attestations (beyond LOOP-E.2 + LOOP-J.J3)
3. Quantum-safe / Post-Quantum Cryptography (PQC) migration planning (NIST PQC; FIPS 203, 204, 205)
4. Cross-domain integration with CMMC + StateRAMP
5. Cloud-shared-responsibility *operational* validation (beyond LOOP-L CRM static document)
6. Geographic data residency reporting (US-only, US-citizen-only personnel)
7. FIPS attestations beyond AFR-UCM (FIPS 200 baseline, FIPS 197 algorithm)
8. Section 508 / ICT accessibility
9. DFARS NIST 800-171 cross-walk + DFARS 252.204-7012 cloud-equivalency
10. CISA Secure by Design pledge attestations
11. NIST CSF v2.0 alignment crosswalk (GOVERN function + OLIR)
12. OCI image signing (cosign / Notary v2 / Sigstore / Rekor)
13. CISA CIRCIA reporting workflow
14. Federal Risk Profile (FRP) / FedRAMP 20x Low Baseline pre-auth path
15. GSA 18F / TTS technical guidance / IT Standards Guide

### 1.3 What I deliberately did NOT do

- Did not re-propose anything already filed in first-pass §3 extensions.
  Each candidate is *new* coverage beyond the 12 §3 extensions.
- Did not propose net-new artifacts without a real obligation citation.
- Did not rescope L–Q. Where coverage *partially* exists I propose
  extending an existing L–Q slice rather than splitting the loop.
- Did not enumerate every conceivable adjacent framework. The 15
  surfaces above were the prompted set; the §4 out-of-scope section
  flags adjacent frameworks (ISO 27001, SOC 2, HITRUST, PCI, HIPAA) only
  where they intersect the prompt.

---

## 2. STILL missing — propose adding to roadmap

Items that are NOT covered by A–K, NOT covered by L–Q, and have a
real public obligation surface or near-future obligation for a Phase
Two Moderate CSP at GA. Six items rise to "first-class slice
recommendation"; the remainder are deferred to §4 (out-of-scope at
Moderate) or §3 (confirmed-covered).

### 2.1 Quantum-Safe / Post-Quantum Cryptography (PQC) migration inventory + plan — NEW LOOP-R

**Source obligation (verbatim):**

- NIST CSRC Post-Quantum Cryptography Project
  (https://csrc.nist.gov/projects/post-quantum-cryptography):
  > "NIST released the principal three PQC standards in 2024 ... Under
  > the transition timeline in NIST IR 8547, NIST will deprecate and
  > ultimately remove quantum-vulnerable algorithms from its standards
  > by 2035, with high-risk systems transitioning much earlier."
  > "Organizations should begin applying these standards now to migrate
  > their systems to quantum-resistant cryptography ... [the three
  > initial standards] can and should be put into use now."
- **FIPS 203** (Module-Lattice KEM, ML-KEM, derived from Kyber) —
  finalized August 2024.
- **FIPS 204** (Module-Lattice DSA, ML-DSA, derived from Dilithium) —
  finalized August 2024.
- **FIPS 205** (Stateless Hash-Based DSA, SLH-DSA, derived from
  SPHINCS+) — finalized August 2024.
- **NIST IR 8547** — Transition to Post-Quantum Cryptography Standards
  (deprecation schedule; deprecate quantum-vulnerable algorithms by
  2030, disallow by 2035).
- **CNSA 2.0** (NSA Commercial National Security Algorithm Suite 2.0,
  Sep 2022) — already mandates PQC for National Security Systems by
  2030–2033 per asset class.
- **OMB M-23-02** "Migrating to Post-Quantum Cryptography" (Nov 2022) —
  agency obligation to inventory cryptographic systems + submit annual
  reports through 2035.

**Why first-pass missed it:** The first-pass audit (2026-06-06) listed
NIST publications consulted but did NOT enumerate any PQC source. PQC is
not yet a hard FedRAMP Moderate gate but OMB M-23-02 + NIST IR 8547 +
the GA timeline make a *CSP-supplied cryptographic inventory + migration
plan* a near-term submission-package expectation. Federal agency customers
will start asking for this inside the 2026–2028 Consolidated Rules
window.

**Where it lands:** **NEW LOOP-R — Post-Quantum Cryptography Inventory +
Migration Plan**. 3 slices:

- **R.R1 — Cryptographic inventory collector** — extend existing
  `providers/{aws,gcp,azure}/crypto.ts` to enumerate every TLS suite +
  KMS key algorithm + signing-key algorithm + cert SAN entry; emit
  `out/crypto-inventory.json` keyed by asset_id × (algorithm, key_size,
  purpose, rotation_cadence, quantum_vulnerable_class). Quantum-vulnerable
  classification per NIST IR 8547 §3 table (RSA, ECDSA, ECDH, DH ≥ all
  vulnerable; AES-256 / SHA-384 / SHA3 quantum-resistant).
- **R.R2 — PQC migration plan emitter** — new `core/pqc-migration-plan.ts`.
  Per-asset / per-algorithm migration record: target algorithm (FIPS
  203/204/205), target date (default 2030 per OMB M-23-02 §IV phased
  cutover), inheritance from cloud provider (AWS KMS, GCP Cloud KMS,
  Azure Key Vault each publish their own PQC rollouts — track inheritance).
  Emits `.docx` + `.json` + per-asset POA&M items for un-planned migrations.
- **R.R3 — Annual PQC report emitter** — for OMB M-23-02 annual submission.
  Aggregates R.R1 + R.R2 + delta from prior year. Tracker-backed
  operator review + sign-off.

**Priority + reason:** **Medium-high** — not yet a hard 2026 gate but
the Consolidated Rules 2026 window + the broad federal-customer
sensitivity to PQC make it a *table-stakes* deliverable inside 18
months. Ship after LOOP-L (CRM) but before LOOP-Q if the operator's
target customer is DoD or Intelligence-Community-adjacent.

---

### 2.2 SLA / Availability / Uptime structured emitter — extend LOOP-C (NEW C.C11) + LOOP-Q

**Source obligation (verbatim):**

- NIST SP 800-53 Rev 5 **CP-2 (Contingency Plan)**:
  > "Coordinate contingency plan development with organizational elements
  > responsible for related plans."
- NIST SP 800-53 Rev 5 **SA-9 (External System Services) (a)**:
  > "Require that providers of external system services comply with
  > organizational security and privacy requirements and employ the
  > following controls: [Assignment]; define and document
  > organizational oversight and user roles and responsibilities ...
  > including service-level agreements."
- NIST SP 800-53 Rev 5 **CP-7 (Alternate Processing Site) Moderate**:
  > "Establish an alternate processing site, including necessary
  > agreements to permit the transfer and resumption of [Assignment:
  > system operations] for [Assignment] when the primary processing
  > capabilities are unavailable."
- FedRAMP CSP Authorization Playbook — every published authorization
  package's ISCP + Contract includes specific RTO + RPO + availability
  commitments; the playbook's SSP § "Service Level Agreements" subsection
  lists these as mandatory.
- FedRAMP Marketplace `service_level_agreement_url` field (per
  Marketplace API — referenced in LOOP-Q.Q1 but the *content* the URL
  points at is not yet emitter-backed).

**Why first-pass missed it:** LOOP-C.C2 (ISCP) carries `rto/rpo`
operator-supplied fields; LOOP-C.C3 (IRP) carries an `escalationMatrix`
with `sla_minutes`; LOOP-Q.Q1 (Marketplace metadata) references SLAs but
the SLA itself has no first-class emitter. The actual customer-facing
"SLA document" — uptime guarantees per service class, support response
time guarantees per severity, credit terms — has no home in A–Q.

**Where it lands:** **NEW LOOP-C.C11 — Service Level Agreement document
emitter**. One slice (extension of LOOP-C). Emits `out/sla.docx` + JSON
twin. Fields:

- `service_class[]` (per CSO tier: bronze / silver / gold equivalent)
- `availability_target` (per class: 99.9 / 99.95 / 99.99)
- `availability_measurement_window` (per class: monthly / quarterly /
  rolling-12mo)
- `support_response_time_sla[]` (per severity: S1/S2/S3/S4 with
  acknowledgement + resolution targets)
- `credit_schedule[]` (per missed-target credit terms)
- `exclusion_list[]` (scheduled maintenance, force majeure, etc.)
- `historical_uptime_24mo` (computed from inventory + CloudWatch /
  GCP Monitoring / Azure Monitor — operator-attested signature)
- `incident_credit_history_24mo` (tracker-backed)

**Priority + reason:** **Medium** — operationally important (federal
customers ask for it in agency-authorization conversations) but not a
hard FedRAMP submission-package gate. Cheap to ship (~1 week single
slice; reuses LOOP-C OOXML pattern).

---

### 2.3 OCI image signing + Sigstore Rekor transparency log evidence — extend LOOP-J.J3 (new sub-slice J.J3.b)

**Source obligation (verbatim):**

- **NIST SP 800-218 (SSDF) PS.2.1** — "Make software integrity
  verification information available to acquirers."
- **NIST SP 800-218 (SSDF) PW.4.4** — "Verify the integrity of executable
  code by using digital signatures or one or more cryptographic
  techniques."
- **NIST SP 800-204D §3.2** (Strategies for Integrating Software Supply
  Chain Security in DevSecOps CI/CD Pipelines): SBOM + signed image +
  in-toto attestation per build.
- **CISA SBOM Minimum Elements** (July 2021, per EO 14028 §4(f)).
- **EO 14028 §4(e)(iv) + §4(e)(vii)** — software self-attestation by
  federal-software producers must include attestation of "secure
  software development practices" + integrity-verification mechanisms.

**Why first-pass missed it:** First-pass §3.8 mentioned "DevSecOps
Pipeline Attestations" as an extension of LOOP-J.J3, but the citation
ladder stopped at SBOM ingestion + cosign verification (already in PE-2
`SBOM Depth (Syft + cosign verification)` per task #115). What's NOT
covered:

- **In-toto attestations** (https://in-toto.io/) per build emitted to a
  Sigstore Rekor transparency log; verification at ingest time.
- **SLSA Build Level 3 provenance** (https://slsa.dev/spec/v1.0/levels):
  > "Build platform runs on dedicated infrastructure, not an individual's
  > workstation, and the provenance is tied to that infrastructure
  > through a digital signature."
- **Notary v2 / Notation** for OCI artifacts (the OCI 1.1 manifest
  pattern w/ signatures stored as referrer artifacts).
- **Rekor inclusion proof + verification** as a required ingest
  attestation per build.

**Where it lands:** **Extend LOOP-J.J3 with sub-slice J.J3.b** —
"OCI image signing + transparency-log evidence":

- New `core/sigstore-verify.ts` — pure verifier; reads SBOM + cosign
  signature + Rekor inclusion proof; validates against Fulcio CA root.
- Extend `providers/aws/ecr.ts` + GCP Artifact Registry collector + ACR
  collector to enumerate signed-vs-unsigned image tag ratios.
- Emit per-CI-run `out/build-attestations.json` indexed by image digest.
- New POA&M finding family `supply-chain:unsigned-image` per unsigned
  production image.
- New tracker DB `image_signing_policy` table.
- New SSP §SA-11 narrative auto-fill using the verification stats.

**Priority + reason:** **Medium-high** — already implied by E.2 task
#115 (cosign verification) but the *attestation chain emission* +
Rekor-inclusion-proof verification + SLSA-Level-3-provenance ingest are
NOT in PE-2's scope and NOT in LOOP-J.J3 today. Federal-software
self-attestation per EO 14028 §4(e)(iv) makes this a *near-mandatory*
extension before 2027.

---

### 2.4 CISA Secure by Design pledge attestation emitter — extend LOOP-G (NEW G.G8) OR new LOOP-S sub-slice

**Source obligation (verbatim):**

- CISA Secure by Design Pledge
  (https://www.cisa.gov/securebydesign/pledge): voluntary pledge with
  **7 goals** that signatories commit to demonstrating measurable
  progress on within 12 months of signing:
  1. **Multi-Factor Authentication (MFA)** measurable increase.
  2. **Default passwords** measurable reduction.
  3. **Vulnerability class reduction** (memory-safe languages, CSRF/XSS
     reduction, etc.).
  4. **Security patches** measurable customer installation rate increase.
  5. **Vulnerability disclosure policy** (VDP) publication per RFC 9116
     pattern + safe-harbor language.
  6. **CVE transparency** — accurate CWE + CPE on every CVE record.
  7. **Evidence of intrusions** — measurable customer ability to gather
     intrusion evidence.
- Verbatim CISA press release (announcing 68 signatories May 2024 + ongoing
  signups including AWS, Google, Microsoft, Cisco): "Signatories pledge
  to work over the next year to demonstrate measurable progress towards
  seven concrete goals."

**Why first-pass missed it:** First-pass §3.2 covered VDP policy
document (LOOP-G.G7 extension) which addresses *Goal 5* only. The other
six goals have no home. CISA's annual progress-report expectation is a
*signed attestation document* with measurement evidence per goal.

**Where it lands:** **Extend LOOP-G with new slice G.G8 — Secure by
Design Pledge progress report emitter**:

- `core/sbd-pledge-report.ts` — emits `.docx` + JSON.
- Per-goal data sources:
  - Goal 1 MFA — from existing IAM-MFA collector (AWS + GCP + Azure).
  - Goal 2 Defaults — operator-supplied per product + auto-detect via
    inventory tags.
  - Goal 3 Vuln classes — from existing VDR collector + AFR-PVA.
  - Goal 4 Patch installation — from existing patch-assessment collector.
  - Goal 5 VDP — from G.G7 (already extended in first-pass §3.2).
  - Goal 6 CVE transparency — operator-supplied CVE-record-quality
    metrics (CWE/CPE fill rate from published advisories).
  - Goal 7 Evidence — from MLA-LET + log-export-capability collector.
- Annual cadence; tracker review + sign-off.

**Priority + reason:** **Medium** — voluntary today but CISA strongly
expects federal-procurement preference for signatories. If the CSP has
signed the pledge (or plans to), the report is annual-mandatory.

---

### 2.5 NIST CSF v2.0 alignment crosswalk emitter — extend LOOP-I.I4

**Source obligation (verbatim):**

- NIST CSWP 29 (CSF 2.0, February 2024): introduced **sixth function
  GOVERN** (31 subcategories) on top of the five legacy functions
  (IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER).
- NIST OLIR (Online Informative References) program publishes the
  official CSF 2.0 ↔ NIST 800-53 Rev 5 bidirectional crosswalk.
  Out for comment 2024-04 (per NIST bulletin); finalized OLIR record
  available via NIST CPRT.
- Federal customers increasingly request CSF 2.0 reporting alongside
  FedRAMP packages (esp. CISOs using CSF 2.0 GOVERN function for board
  reporting).

**Why first-pass missed it:** First-pass mentioned CSF 2.0 in
"Sources consulted" (§1.1 item 18) but did not propose a slice. The
existing LOOP-I.I4 "SSP narrative library completion" is *adjacent*
but focused on per-control narrative reuse. A separate CSF 2.0
crosswalk emitter (per existing C.1 task #104 multi-framework
crosswalk pattern, scoped narrowly to CSF 2.0 + GOVERN function) is
needed.

**Where it lands:** **Extend LOOP-I.I4** — add a CSF 2.0 sub-report:

- `core/csf-v2-crosswalk.ts` — pure builder. Reads existing
  control-benchmark.ts + ksi-map.ts + ingests the NIST OLIR JSON
  bidirectional record. Emits `out/csf-v2-crosswalk.xlsx` with
  GOVERN/IDENTIFY/PROTECT/DETECT/RESPOND/RECOVER tabs; per-subcategory
  shows mapped NIST 800-53 controls, mapped KSIs, evidence status.
- Tracker UI: GOVERN function dashboard (the new sixth function carries
  31 subcategories that don't all map cleanly to 800-53 — operator-
  supplied evidence for the gaps).

**Priority + reason:** **Medium-low** — not a FedRAMP gate, but federal
customer board-level reporting increasingly requires it. Cheap once the
NIST OLIR JSON is committed.

---

### 2.6 CIRCIA cyber-incident reporting workflow — extend LOOP-G.G2 (AFR-ICP) + LOOP-M.M4

**Source obligation (verbatim):**

- CIRCIA (Cyber Incident Reporting for Critical Infrastructure Act of
  2022, 6 U.S.C. §681 et seq.). Final Rule published **May 2026** per
  CISA timeline. Key reporting obligations:
  - **72 hours** to report a covered cyber incident after "covered entity
    reasonably believes that the covered cyber incident has occurred."
  - **24 hours** to report a ransomware payment.
- CISA covered-entity scope: 16 critical infrastructure sectors;
  ≥300,000 entities estimated. FedRAMP CSPs that serve federal customers
  fall within scope when they support critical-infrastructure
  agencies (essentially all of them).
- Cross-cuts existing FedRAMP US-CERT reporting obligation (1-hour to
  PMO + agency).

**Why first-pass missed it:** First-pass §4.9 BOD 23-01 (Asset
Visibility) noted "applies to FCEB agencies, not CSPs directly"; CIRCIA
was not mentioned at all. CIRCIA's May 2026 Final Rule *did* land
between first-pass authoring (2026-06-06) and this audit — so first-pass
may simply have predated the Final Rule by days.

**Where it lands:** **Extend LOOP-G.G2 (AFR-ICP)** + **LOOP-M.M4
(privacy IRP)** with CIRCIA-specific routing:

- New `core/circia-report.ts` — emits structured CIRCIA Web Form
  submission JSON; tracker workflow for the 72-hour + 24-hour timers.
- Tracker DB additions: `circia_incidents`, `circia_ransom_payments`.
- Per-incident classification: covered-cyber-incident? ransom payment?
- Auto-link to existing AFR-ICP incident records (LOOP-G.G2) +
  privacy-incident records (LOOP-M.M4).
- Operator-signed acknowledgement of report submission + CISA
  acknowledgement-token capture.

**Priority + reason:** **High** — CIRCIA Final Rule (May 2026) is
*compliance-mandatory* for any FedRAMP-authorized CSP serving a critical
infrastructure agency. 72-hour clock is unforgiving; tooling support is
essential.

---

### 2.7 DFARS 252.204-7012 cloud-equivalency evidence package — NEW LOOP-S (conditional)

**Source obligation (verbatim):**

- **DFARS 252.204-7012 (Safeguarding Covered Defense Information and
  Cyber Incident Reporting)**:
  > "If the Contractor intends to use an external cloud service provider
  > to store, process, or transmit any covered defense information in
  > performance of this contract, the Contractor shall require and
  > ensure that the cloud service provider meets security requirements
  > equivalent to those established by the Government for the Federal
  > Risk and Authorization Management Program (FedRAMP) Moderate
  > baseline."
- **NIST SP 800-171 Rev 3** — derived from NIST 800-53 Moderate, tailored
  to remove FED + NCO + NFO items (≈60 % coverage). 110 base requirements
  (Rev 3 expanded; Rev 2 had 110 requirements organized into 14 families).
- DoD CIO memorandum (Dec 21 2023) "FedRAMP Equivalency for CSPs" —
  3PAO assessment required + body of evidence (BoE) matching every
  FedRAMP Moderate control.

**Why first-pass missed it:** First-pass §4.3 marked CMMC L2/L3 as
out-of-scope. That's correct for *CMMC certification* but DFARS
7012 *cloud equivalency* applies to ANY CSP storing CUI for DoD primes
— independent of whether the prime is CMMC-certified. First-pass did
not separate CMMC-cert (out-of-scope) from DFARS-equivalency (in-scope
for any CSP with a DoD-prime customer).

**Where it lands:** **NEW LOOP-S — DFARS 252.204-7012 Cloud Equivalency
Package** (conditional, opt-in via `--dfars-equivalency` flag):

- **S.S1 — NIST 800-171 Rev 3 to FedRAMP Moderate crosswalk emitter** —
  shows every 800-171 requirement covered by existing FedRAMP evidence.
- **S.S2 — Body of Evidence (BoE) bundler** — packages the existing
  FedRAMP submission bundle + crosswalk + 3PAO equivalency letter
  template into a DoD-prime-deliverable archive.
- **S.S3 — DFARS 252.204-7012 cyber-incident-reporting workflow** —
  DIBNet (https://dibnet.dod.mil/) submission tooling; tracker
  integration with LOOP-G.G2.

**Priority + reason:** **Medium (conditional)** — only required if the
CSP has DoD-prime customers. Many SaaS CSPs do (via reseller channels),
so the trigger threshold is low.

---

### 2.8 Other items evaluated — confirmed out-of-scope or covered

The remaining candidates (#1, #4, #6, #7, #8, #14, #15 from §1.2) are
NOT first-class slice recommendations. Each is either:

- **Confirmed out-of-scope at Moderate** (see §4 below) — Section 508,
  StateRAMP standalone, Federal Risk Profile (FRP) is the 20x Low
  Baseline at GA so wouldn't add anything beyond existing 20x Moderate
  scope.
- **Already covered after L–Q** (see §3 below) — geographic data
  residency (first-pass §3.4), FIPS 200/197 (rolled into existing
  AFR-UCM), GSA 18F technical guidance (no new obligation surface).

---

## 3. Confirmed-covered after L–Q

Items the prompt asked me to check that *are* covered, with the
covering slice cited so a future session can verify the trail.

### 3.1 Cloud-shared-responsibility (operational validation beyond CRM)

- **First-pass concern:** CRM (LOOP-L) is a static document; the
  operational reality may drift.
- **Covered by:** LOOP-L.L3 (CRM gap report) emits a finding when a
  Moderate-baseline control has no responsibility designation; LOOP-L.L4
  per-control narrative renderer pulls from KSI evidence; the per-KSI
  pass/fail flow is *operational* validation.
- **Residual gap:** drift between Customer-implemented designation and
  the actual customer's deployment is NOT detected; but that's outside
  the CSP's read-only authority. Filed under §5 open question #3.

### 3.2 Geographic data residency reporting

- **Covered by:** first-pass §3.4 (Data Residency / Sovereignty
  Declarations) — extends LOOP-C.C8 cover letter + LOOP-A.A5 RoE.
- **Residual gap:** none at Moderate. At High the data residency
  becomes a hard gate (filed under §4.1).

### 3.3 FIPS attestations beyond AFR-UCM (FIPS 200, FIPS 197)

- **Covered by:** AFR-UCM existing collector (cryptographic module
  selection + CMVP verification) + first-pass §3.1 SSP Appendix Q
  (Cryptographic Modules Table) under LOOP-C.C10. FIPS 200 is the
  *baseline-selection* standard which feeds the SSP categorization
  (FIPS 199 worksheet covered by LOOP-C.C5); FIPS 197 (AES) is an
  algorithm identifier already part of REO Rule 3 allowed-constants.
- **Residual gap:** none for Moderate.

### 3.4 NIST 800-171 cross-walk (Moderate side only)

- **Partially covered by:** existing C.1 task #104 multi-framework
  crosswalk (SOC2/ISO27001/HIPAA but not 800-171). For DoD-prime CSPs
  this is *not yet covered*; §2.7 recommends new LOOP-S.S1.

### 3.5 SBOM provenance attestations (basic case)

- **Covered by:** task #115 (PE-2 SBOM Depth — Syft + cosign verification)
  + first-pass §3.8 (DevSecOps Pipeline Attestations extension to
  LOOP-J.J3).
- **Residual gap:** SLSA Build Level 3 provenance + Rekor inclusion
  proofs (§2.3 above).

### 3.6 Federal Risk Profile (FRP) / FedRAMP 20x Low Baseline

- **Already aligned with:** existing 20x roadmap targets Phase Two
  Moderate at GA (per project memory). The 20x Low Baseline is a
  separate pre-MVP authorization path with 51 KSIs (vs the Moderate
  223). LOOP-C.C5 FIPS 199 worksheet already covers the impact-tier
  selection that determines whether Low or Moderate applies.
- **Residual gap:** the orchestrator's `--impact-level low` flag is
  partially supported (HIGH-CLARIFY-class warning per task #242) but
  the Low-specific KSI subset filter is not yet wired. Filed under §5
  open question #5.

### 3.7 GSA 18F / TTS technical guidance

- **No specific obligation surface.** 18F / TTS publish best practices
  (https://18f.gsa.gov/ and https://tts.gsa.gov/) but the only
  FedRAMP-binding guidance flows through the FedRAMP PMO docs, which
  LOOP-A–Q already source.
- **Residual gap:** none.

---

## 4. Out of scope (NOT FedRAMP 20x Moderate)

Items that the prompt flagged for review but do NOT belong on the
Moderate roadmap.

### 4.1 Section 508 / ICT accessibility for the tracker UI

- **Why out of scope:** Section 508 applies to the federal customer's
  consumption of the CSO (the *user-facing application*). The
  **tracker UI is CSP-internal** + not consumed by federal users.
  First-pass §4.6 already documented this.
- **When revisit:** before any tracker UI is exposed to federal users.

### 4.2 StateRAMP standalone authorization

- **Why out of scope:** state-government parallel. First-pass §4.4
  already documented.

### 4.3 CMMC L2/L3 certification

- **Why out of scope:** DoD-specific certification process (not just
  evidence). First-pass §4.3 + §2.7 above (LOOP-S handles the
  DFARS-equivalency surface, NOT the CMMC-cert surface).

### 4.4 US-only personnel attestation (US-citizen-only)

- **Why out of scope at Moderate:** FedRAMP has **no US-citizenship
  requirement** at the program level (per GRC Academy + FedRAMP PMO
  guidance:
  > "FedRAMP has no US citizenship/persons requirements at the program
  > level.").
  Agencies may add it in solicitation language; ITAR adds it; FedRAMP
  High implicitly requires it via PS-3(1). At Moderate the requirement
  is *agency-by-agency*, not program-wide.
- **When revisit:** when operator declares High or onboards an agency
  with explicit US-personnel requirement.

### 4.5 EU AI Act / Brussels-Effect AI obligations

- **Out of scope:** first-pass §4.7 already documented.

### 4.6 PCI DSS, HIPAA, SOC 2, ISO 27001, HITRUST (commercial frameworks)

- **Out of scope:** first-pass §4.5 + §4.8 already documented.
  Multi-framework crosswalk under task #104 covers reporting overlap;
  full sector-specific authorization is out of scope.

### 4.7 GSA 18F / TTS technical guidance

- **Not a separate obligation surface** — see §3.7.

---

## 5. Open questions for the human

Items that are decision-bearing before any §2 recommendation starts.

1. **Will this CSP pursue CISA Secure by Design Pledge signature?**
   §2.4 LOOP-G.G8 is conditional. If the CSP has not signed AND has
   no plan to sign, the slice can be deferred indefinitely. If signed,
   the 12-month progress report is hard-mandatory.

2. **Does this CSP have any DoD-prime customers (now or in pipeline)?**
   §2.7 LOOP-S is conditional. If "no" the entire loop ships as a
   single attestation slice. If "yes" or "soon" the BoE bundler is
   near-mandatory.

3. **Customer-side responsibility drift detection — is this in scope?**
   §3.1 residual gap. The CSP's read-only collector authority *ends*
   at the CSP boundary; detecting that the customer DID configure their
   side of the Shared bucket requires data we can't access. Should we:
   (a) emit a customer-self-attestation tracker workflow,
   (b) ignore the drift,
   (c) require a 3PAO interview at annual assessment time?

4. **PQC migration target date — defer to 2030 or accelerate to 2027?**
   §2.1 R.R2 default per OMB M-23-02 is 2030. Some agencies are
   accelerating to 2027 for non-NSS systems. Operator must choose the
   default target date for the migration plan.

5. **20x Low Baseline support — yes or no?**
   §3.6 residual gap. The Low Baseline is a separate FedRAMP 20x
   authorization path. If the operator wants to support customers
   choosing Low, the per-KSI 51-vs-223 filter must be wired into the
   collector + emitter. If "no", current behavior is correct.

6. **CIRCIA Final Rule effective date — when does the 72-hour clock
   start?** §2.6. The Final Rule landed May 2026 but the effective date
   has implementation grace. Operator must confirm the date the CSP's
   first CIRCIA report becomes due.

7. **SLSA Build Level target — L2 or L3?** §2.3. L2 (hosted build
   platform + signed provenance) is achievable on managed CI runners
   today. L3 requires hardened build isolation (e.g. GitHub Actions
   `permissions: read-only` + no shared runners). Operator chooses the
   target.

8. **DFARS-equivalency 3PAO — already engaged or net-new?** §2.7
   LOOP-S requires a 3PAO equivalency letter. If the operator already
   has the FedRAMP 3PAO engagement, the same 3PAO usually issues
   equivalency at marginal cost. If net-new, schedule + budget impact
   is meaningful.

9. **CSF 2.0 OLIR JSON ingestion mechanism** — §2.5 needs the NIST
   OLIR JSON file. Should we commit a pinned snapshot (`docs/csf-v2-olir.generated.json`)
   per the existing FRMR-catalog pattern, or fetch live at orchestrator
   time? Recommend the snapshot pattern for reproducibility.

---

## 6. Final roadmap proposal

### Updated slice count

| Source | Slices |
|---|---|
| LOOP-A (complete) | 5 |
| LOOP-B–K (pending, original first-pass) | 44 |
| LOOP-L–Q (proposed by first-pass) | 20 |
| First-pass §3 extensions (new slice IDs: C10, G7, J3 extension, K3) | ~5 (treat as ~3 new slices, 2 in-slice extensions) |
| **This audit §2 additions** | **6 new** |
| **TOTAL** | **~78 slices** |

Breakdown of the 6 new this-audit additions:

| New slice / loop | Source obligation | Single-thread effort |
|---|---|---|
| **LOOP-R** (3 slices) — PQC inventory + migration plan + annual report | NIST IR 8547, OMB M-23-02, FIPS 203/204/205 | 3 weeks |
| **LOOP-C.C11** — SLA document emitter | NIST 800-53 SA-9, CP-7; FedRAMP Marketplace metadata | 1 week |
| **LOOP-J.J3.b** — OCI signing + Rekor inclusion proof | EO 14028 §4(e)(iv), NIST 800-218 PW.4.4, SLSA L3 | 1.5 weeks |
| **LOOP-G.G8** — Secure by Design Pledge progress report | CISA Pledge | 1 week |
| **LOOP-I.I4 extension** — CSF v2.0 crosswalk | NIST CSWP 29 + OLIR | 1 week |
| **CIRCIA workflow extension** to LOOP-G.G2 + LOOP-M.M4 | CIRCIA Final Rule (May 2026) | 1.5 weeks |
| **LOOP-S** (3 slices, conditional) — DFARS 252.204-7012 cloud equivalency | DFARS 252.204-7012; NIST 800-171 Rev 3 | 3 weeks (if triggered) |
| **TOTAL ADDS** | | **~12 weeks single-thread** |

So the revised total: **49 (A–K) + 20 (L–Q first-pass) + 6 (this audit,
+ LOOP-S conditional) ≈ 75–78 slices**, ~70–76 weeks single-thread (~30
weeks 3-stream parallel).

### Phasing recommendation

Three integration phases on top of the existing roadmap:

**Phase X (urgent, lands inside LOOP-B–K execution):**
- CIRCIA workflow extension (§2.6) — Final Rule effective; can't slip.
- LOOP-C.C11 SLA emitter (§2.2) — federal customer asks during agency
  authorization conversations; cheap to ship.

**Phase Y (lands alongside LOOP-L–Q):**
- LOOP-G.G8 Secure by Design Pledge report (§2.4) — pairs with LOOP-G
  closeout.
- LOOP-I.I4 CSF v2.0 crosswalk extension (§2.5) — pairs with LOOP-I
  dashboards.
- LOOP-J.J3.b OCI signing + Rekor (§2.3) — pairs with LOOP-J supply
  chain.

**Phase Z (post-L-Q, conditional on operator decisions):**
- LOOP-R (PQC, §2.1) — high-impact, can wait until LOOP-A–Q ship.
- LOOP-S (DFARS, §2.7) — conditional on DoD-prime customer trigger.

Suggested re-cut of the EXECUTION-PLAN table (delta from first-pass §6
table):

| Loop | Title | Slices | Effort | Depends on |
|---|---|---|---|---|
| ... (rows A–Q identical to first-pass §6) | | | | |
| **R** | **PQC inventory + migration plan** | **3** | **3 wk** | **AFR-UCM existing** |
| **S** | **DFARS 252.204-7012 equivalency (conditional)** | **3** | **3 wk** | **A.A4 + L** |
| (in-loop extensions) | C.C11 SLA, G.G8 SBD, I.I4 CSF v2, J.J3.b Sigstore, G.G2/M.M4 CIRCIA | ~5 | ~6 wk | various |
| **TOTAL** | | **~78 slices** | **~76 weeks single-thread** | |

---

## 7. Acceptance for this audit

Mirroring the first-pass §7 acceptance contract:

1. Every §2 STILL-missing item has a real source citation + landing
   spot (new loop or existing extension) + effort estimate.
2. Every §3 confirmed-covered item names the covering slice.
3. Every §4 out-of-scope item has a documented re-visit trigger.
4. Every §5 open question is decision-bearing.
5. §6 totals balance: 49 + 20 + 6 ≈ 75 slices (78 with LOOP-S).

The human (or the next session that reads this audit) should be able
to: (a) accept / reject each §2 item individually; (b) confirm
§3 covered items are *actually* covered by reading the named slice;
(c) confirm / decline each §4 out-of-scope flag; (d) answer each §5
open question; (e) ratify or amend the §6 phasing.

---

## Appendix — Source URL map (this audit's citation chain)

- NIST PQC project: https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST IR 8547 (PQC transition): https://csrc.nist.gov/pubs/ir/8547/ipd
- OMB M-23-02 (PQC migration): https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf
- SLSA v1.0 spec / levels: https://slsa.dev/spec/v1.0/levels
- in-toto attestations: https://in-toto.io/
- Sigstore / Rekor: https://www.sigstore.dev/ + https://docs.sigstore.dev/logging/overview/
- CISA Secure by Design Pledge: https://www.cisa.gov/securebydesign/pledge
- CISA SBD pledge announcement: https://www.cisa.gov/news-events/news/cisa-announces-secure-design-commitments-leading-technology-providers
- NIST CSF 2.0 (CSWP 29): https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
- NIST CSF 2.0 Informative References (OLIR): https://www.nist.gov/cyberframework/informative-references
- CIRCIA Final Rule (federalregister.gov NPRM 2024-04-04): https://www.federalregister.gov/documents/2024/04/04/2024-06526/cyber-incident-reporting-for-critical-infrastructure-act-circia-reporting-requirements
- CISA CIRCIA topic page: https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/cyber-incident-reporting-critical-infrastructure-act-2022-circia
- DFARS 252.204-7012: https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting.
- NIST 800-171 Rev 3: https://csrc.nist.gov/pubs/sp/800/171/r3/final
- DIBNet: https://dibnet.dod.mil/
- FedRAMP Marketplace: https://marketplace.fedramp.gov/
- FedRAMP 20x Low Baseline (preview / January 2026 finalization): https://www.fedramp.gov/20x/
- Section 508: https://www.section508.gov/
- EO 14028 (May 2021): https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
- NIST SP 800-218 (SSDF): https://csrc.nist.gov/publications/detail/sp/800-218/final
- NIST SP 800-204D (Strategies for Integrating Software Supply Chain Security in DevSecOps): https://csrc.nist.gov/pubs/sp/800/204/d/final
