---
loop_id: V
title: HIPAA Security Rule Compliance + BAA Tracker + Breach Notification + NIST SP 800-66 Rev 2 Crosswalk + HITRUST CSF v11.2.0 Mapping
status: pending
applicable_conditional: true
condition: Any CSP acting as a HIPAA Business Associate or Covered Entity — processes PHI on behalf of a Covered Entity per 45 CFR §164.502(e). Activated via org-profile.yaml processes_phi true.
trigger_flag: "--hipaa"
trigger_env: CLOUD_EVIDENCE_HIPAA
depends_on: [LOOP-A.A1, LOOP-A.A4, LOOP-A.A5, LOOP-INV-S, LOOP-G.G2, LOOP-M.M4, LOOP-B]
blocks: [LOOP-Z.Z4]
estimated_effort: 6 weeks
last_updated: 2026-06-08
---

# LOOP-V — HIPAA Security Rule compliance + BAA Tracker + Breach Notification + NIST SP 800-66 Rev 2 + HITRUST CSF v11.2.0

> Comprehensive implementation specification for the five slices in LOOP-V.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-V end-to-end by reading ONLY this file + the five supporting
> per-slice docs cited in §3. No prior conversation history required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence
> (a federally-published HIPAA / NIST / HHS-OCR / HITRUST source, a live
> cloud SDK call, a tracker DB query for an executed BAA, or operator-
> supplied configuration). Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.
>
> LOOP-V is **applicability-conditional** in the strict legal sense (only
> CSPs that handle Protected Health Information on behalf of a Covered
> Entity are HIPAA Business Associates) but **default-ON for any package
> build where `org-profile.yaml processes_phi: true` is set**. The
> FIFTH-PASS-AUDIT.md surfaced HIPAA + HITRUST evidence as a gap in the
> FedPy / cloud-evidence toolkit specifically for CSPs whose federal
> agency customers include HHS, CMS, VA, IHS, or DoD-Health-Affairs.
> LOOP-V closes it.

---

## 1. Mission & scope

### 1.1 Why LOOP-V exists (the audit story)

The first-pass execution plan for the FedPy / cloud-evidence toolkit
covered FedRAMP Moderate baseline, ConMon, inventory, and SSDF — but
never enumerated the HIPAA Security Rule's Administrative / Physical /
Technical safeguards, never tracked the Business Associate Agreements
(BAAs) flowing in (from upstream Covered Entities and subprocessors)
or out (to the CSP's own subprocessors), and never specified a
breach-notification pipeline that satisfies the 60-day individual-
notice + 60-day-or-immediate HHS-notice + media-notice clocks at
45 CFR §164.404 / .406 / .408. The second-pass (DFARS / PQC / SSDF),
third-pass (PQC + DFARS + CIRCIA), and fourth-pass (Prohibited
Vendors, SSDF, SEC 8-K) audits did not touch healthcare. The
FIFTH-PASS-AUDIT.md, dated 2026-06-08, surfaced HIPAA as a high-
priority remaining gap because:

1. **A material fraction of FedRAMP-authorized CSPs handle PHI.**
   Federal agencies that buy SaaS — VA, CMS, IHS, HHS, DHA, SSA,
   parts of DoD — flow PHI through SaaS workflows. Any CSP whose
   customer list includes one of those agencies must execute a BAA
   under 45 CFR §164.502(e) and operate under HIPAA Security Rule
   obligations. There is no FedRAMP analog of a BAA, so the CSP has
   to operate both regimes in parallel.

2. **HIPAA breach-notification clocks are statutory and short.** The
   HHS-individual-notice clock under §164.404(b) is "no later than 60
   calendar days after the discovery of a breach." The HHS-Secretary
   notice clock at §164.408 is either contemporaneous (for breaches
   affecting 500+ individuals) or annual (for smaller breaches). The
   media-notice clock at §164.406 is also 60 days for 500+-individual
   breaches in a given state. A CSP-as-Business-Associate that
   discovers a breach must notify the Covered Entity "without
   unreasonable delay and in no case later than 60 calendar days after
   discovery" per §164.410. Missing any of these clocks creates
   regulatory exposure measured in millions per the OCR penalty tiers.

3. **The HHS OCR enforcement risk is real and rising.** OCR resolution
   agreements have hit eight figures (e.g. the 2023 Banner Health
   $1.25M settlement, the 2023 Lifespan $1.04M settlement, the 2024
   Montefiore Medical Center $4.75M settlement, the 2024 Optum 360
   $4.75M settlement). The OCR Audit Protocol (HIPAA Audit Program,
   v2 active since 2016) is a checklist a CSP-as-BA can be asked to
   demonstrate compliance against at any time.

4. **NIST SP 800-66 Rev 2 (Feb 2024) is the canonical implementation
   guide.** "Implementing the Health Insurance Portability and
   Accountability Act (HIPAA) Security Rule: A Cybersecurity Resource
   Guide" was finalised February 2024 (final, after the IPD). It
   provides the verbatim cross-walk from each HIPAA Security Rule
   safeguard to NIST SP 800-53 Rev 5 controls and to the NIST CSF
   subcategories. A CSP that wants to demonstrate HIPAA compliance
   without re-implementing the safeguard catalog reads 800-66 Rev 2
   first. LOOP-V.V3 emits the cross-walk as a signed JSON envelope.

5. **HITRUST CSF v11.2.0 is the de-facto private-sector audit
   framework.** HITRUST CSF is the framework most healthcare-customer
   procurement teams ask for. CSPs that already hold a HITRUST CSF
   Validated Assessment frequently are asked to demonstrate that the
   FedRAMP control evidence already collected satisfies the parallel
   HITRUST CSF v11.2.0 control requirements. LOOP-V.V5 emits the
   FedRAMP → HITRUST mapping so that one set of evidence supports
   both regimes.

6. **BAAs are contracts, not security controls — but they are
   audit-relevant.** Without an executed BAA, the CSP cannot lawfully
   process PHI for the Covered Entity. The BAA itself is the
   permission slip. Tracking which BAAs are signed, when they were
   signed, who signed them, the data scope, the breach-notification
   path inside the BAA, the subprocessor flow-down requirements, and
   the termination provisions is a contracts-management discipline
   that LOOP-V brings into the evidence pipeline. LOOP-V.V2 owns the
   BAA tracker.

7. **The 21st Century Cures Act information-blocking rule (45 CFR
   Part 171) overlaps HIPAA.** A CSP that handles Electronic Health
   Information (EHI) must avoid practices that constitute information
   blocking. LOOP-V notes the cross-reference but does not implement
   information-blocking attestation directly (out of scope).

8. **CMS Interoperability and Patient Access Final Rule (CMS-9115-F)
   overlaps HIPAA for CMS-regulated entities.** For CSPs whose
   customers are Medicare Advantage / Medicaid / CHIP / QHP plans, the
   interoperability rule's API requirements layer atop HIPAA Security
   Rule + Privacy Rule. LOOP-V notes the cross-reference for catalog
   completeness.

### 1.2 What LOOP-V delivers

| # | Artifact | Slice | Consumer |
|---|---|---|---|
| 1 | `core/hipaa-safeguards-catalog.ts` — typed loader for the canonical HIPAA Security Rule safeguard catalog (Administrative §164.308 / Physical §164.310 / Technical §164.312 / Organizational §164.314 / Policies & Procedures §164.316; each safeguard carries required-vs-addressable flag + NIST SP 800-66 Rev 2 cross-walk to 800-53 r5 + HITRUST CSF v11.2.0 control IDs) | V.V1 | V.V2 + V.V3 + V.V4 + V.V5 |
| 2 | `data/hipaa-safeguards-catalog.json` — canonical JSON snapshot of the catalog, Ed25519-signed | V.V1 | V.V2 onward; OCR audit |
| 3 | `scripts/extract-hipaa-catalog.mjs` — extractor that walks the four authoritative source PDFs (45 CFR Subpart C; 45 CFR Subpart D; NIST SP 800-66 Rev 2; HITRUST CSF v11.2.0) and produces the catalog | V.V1 | Operator + CI cron (re-runnable when HHS publishes amendments) |
| 4 | `tracker.baa_registry` table + `core/baa-tracker.ts` — Business Associate Agreement tracker: inbound BAAs (Covered-Entity → CSP), outbound BAAs (CSP → subprocessor), executed date, expiry, signatories, data scope, breach-clock terms, indemnification, termination | V.V2 | V.V4 (breach pipeline); operator + counsel |
| 5 | `out/baa-status-{system-id}-{YYYYMMDD}.{json,docx}` — signed BAA inventory rendered for OCR audit + operator review | V.V2 | Submission bundle; tracker UI |
| 6 | `core/hipaa-800-66-mapper.ts` — NIST SP 800-66 Rev 2 cross-walk: each HIPAA safeguard mapped to 800-53 r5 controls + CSF 2.0 subcategories; consumes V.V1 catalog + existing FedRAMP control evidence | V.V3 | V.V5 + 3PAO + OCR audit |
| 7 | `data/hipaa-800-66-crosswalk.json` — canonical signed cross-walk of HIPAA safeguard → 800-53 r5 control → existing FedRAMP evidence pointer | V.V3 | Submission bundle; OCR audit |
| 8 | `core/breach-notification.ts` — breach-notification pipeline implementing the 4-factor probability-of-compromise assessment per §164.402; the §164.404 (60-day individual notice) clock; the §164.408 (HHS-Secretary notice) clock; the §164.406 (media notice) clock; the §164.410 (BA → CE notification) clock | V.V4 | Operator + counsel; HHS OCR portal |
| 9 | `out/breach-incident-{incident-id}.{json,docx}` — per-incident breach record: 4-factor analysis, notification deadlines, evidence pointers, sign-off | V.V4 | Operator (signs); HHS OCR; AO; counsel |
| 10 | `core/hitrust-csf-mapper.ts` — HITRUST CSF v11.2.0 control cross-walk: FedRAMP KSI / NIST 800-53 r5 → HITRUST CSF v11.2.0 control reference + maturity level | V.V5 | HITRUST Validator (external); operator + HITRUST assessor |
| 11 | `data/hitrust-csf-v11.2.0-crosswalk.json` — canonical signed cross-walk | V.V5 | HITRUST Validated Assessment; bundle |
| 12 | `out/hitrust-readiness-{system-id}-{YYYYMMDD}.{json,xlsx,docx}` — HITRUST readiness scorecard + gap list | V.V5 | HITRUST assessor; operator |
| 13 | Tracker DB tables `hipaa_safeguards`, `baa_registry`, `hipaa_800_66_crosswalk`, `breach_incidents`, `hitrust_csf_scores` | V.V1+V.V2+V.V3+V.V4+V.V5 | Tracker UI; audit |
| 14 | Tracker UI: HIPAA safeguard inventory page; BAA registry page with expiry alerts; breach-incident workspace with countdown timers; HITRUST readiness pane | V.V1+V.V2+V.V4+V.V5 | Operator + counsel |
| 15 | POA&M finding template "HIPAA safeguard gap" emitted via existing `core/oscal-poam.ts` | V.V3 | OSCAL chain (LOOP-A.A1) |
| 16 | OCR Audit Protocol response packet (`out/ocr-audit-response-{audit-id}.zip`) | V.V3 + V.V4 | HHS OCR auditor |

### 1.3 What LOOP-V does NOT do (scope guard)

- **LOOP-V does not implement HIPAA Privacy Rule compliance.** The
  Privacy Rule (45 CFR Subpart E) governs uses-and-disclosures of
  PHI; the Security Rule (Subpart C) governs ePHI safeguards. LOOP-V
  scope is Security Rule + BAA + Breach. Privacy Rule attestation is
  cross-referenced (V.V2 BAA includes Privacy Rule flow-down) but not
  implemented as a separate evidence stream.
- **LOOP-V does not auto-sign BAAs.** BAAs are contracts signed by
  legal counsel + officers; the system never auto-signs (REO Rule 10).
  The tracker records signed PDFs uploaded by counsel + captures
  signatory identity + date.
- **LOOP-V does not submit breach notices to HHS OCR on the operator's
  behalf.** The OCR Breach Portal (https://ocrportal.hhs.gov/ocr/
  breach/wizard_breach.jsf) requires a human submitter authenticated
  via OCR's own login. LOOP-V emits the notice content + a submission
  packet; the operator + counsel perform the actual submission and
  log the OCR submission receipt back into the tracker.
- **LOOP-V does not implement the 21st Century Cures Act information-
  blocking attestation.** That is a separate ONC framework (Attestation
  Condition + Maintenance of Certification) governed by 45 CFR Part
  170 / Part 171. Cross-reference only.
- **LOOP-V does not implement CMS Interoperability Final Rule API
  evidence.** That is a CMS framework (CMS-9115-F) governed by
  Patient Access API + Provider Directory API requirements.
- **LOOP-V does not perform a HITRUST Validated Assessment.** HITRUST
  assessments are performed by HITRUST-approved CSF Assessors (CSFAs)
  per HITRUST's external authorization process. LOOP-V.V5 emits the
  control cross-walk + readiness scorecard; the assessor performs the
  actual validation.
- **LOOP-V does not implement state-law breach-notification clocks
  beyond what overlaps HIPAA.** State PII breach laws (e.g. CCPA,
  Texas SB 1471, Florida 501.171) are handled by LOOP-U Privacy. The
  overlap rule: where the same incident involves both PHI and state
  PII, V.V4 hands off the state-PII portion to LOOP-U.

### 1.4 How LOOP-V is distinct from neighbour loops

| Neighbour | Distinction |
|---|---|
| **LOOP-U (Privacy)** | LOOP-U handles state-PII / OMB Privacy Act / NIST Privacy Framework. PHI is a subset of "sensitive personal information" — when PHI overlaps state PII, V.V4 and U coordinate (see §11 cross-references). HIPAA-only PHI stays in V; PII-only data stays in U. |
| **LOOP-M (Privacy Package Extension — SORN/DPIA)** | LOOP-M handles federal Privacy Act SORN + agency-side DPIA artifacts. LOOP-V handles HIPAA-specific safeguards. The two are complementary: a CSP that processes PHI under a federal Privacy Act SOR will ship both LOOP-M's SORN and LOOP-V's safeguards. |
| **LOOP-G.G2 (Incident Communications) + LOOP-M.M4 + CIRCIA** | G.G2 handles the FedRAMP IR-6 + customer-facing incident-comms machinery; M.M4 handles privacy-incident response; CIRCIA adds the 72-hour CISA report. LOOP-V.V4 adds the HIPAA-specific breach clocks (60-day individual / HHS / media + BA-to-CE) on top — V.V4 cross-references G.G2 + M.M4 + CIRCIA but is the canonical clock for HIPAA. |
| **LOOP-A.A4 (bundler)** | All five V slices' artifacts join the submission bundle catalogue. |
| **LOOP-A.A5 (signing)** | All V outputs flow through `signEnvelope()`. |
| **LOOP-A.A1 (POA&M)** | V.V3 + V.V5 emit POA&M items for safeguard gaps + HITRUST gaps. |
| **LOOP-INV-S (PHI-tagged inventory)** | LOOP-INV-S maintains the asset inventory; V relies on the `data_classification: PHI` tag in inventory entries to scope its evidence collection. |
| **LOOP-B (risk + remediation)** | LOOP-B.B1 scores POA&M items. When V.V3 emits a safeguard-gap POA&M item, B.B1 picks it up. |
| **LOOP-Z.Z4 (ISO/IEC 27018 PII Processor)** | LOOP-Z.Z4 emits the international privacy-processor evidence; for PHI that is also "PII" under ISO 27018, the V.V3 cross-walk feeds Z.Z4. V blocks Z.Z4. |

### 1.5 Authoritative scope guard (REO-locked)

LOOP-V's safeguard catalog and breach-clock rubric come **only** from
federally-published HIPAA + NIST + HHS-OCR sources plus the HITRUST
Alliance for the CSF cross-walk (HITRUST CSF is private but its
control identifiers are stable + published):

1. **45 CFR §164 Subpart C — Security Standards for the Protection
   of Electronic Protected Health Information** (§§164.302 – 164.318)
   — the verbatim safeguard list comes from the eCFR-rendered text
   captured at extractor time.
2. **45 CFR §164 Subpart D — Notification in the Case of Breach of
   Unprotected Protected Health Information** (§§164.400 – 164.414)
   — the verbatim breach-notification text comes from eCFR.
3. **45 CFR §164 Subpart A — General Provisions + definitions**
   (§§164.103 – 164.106) — for definitions of "Protected Health
   Information", "Electronic Protected Health Information", "Covered
   Entity", "Business Associate", "Subcontractor".
4. **45 CFR §164 Subpart E — Privacy Rule** (cross-reference: §164.502
   "Uses and disclosures of protected health information: General
   rules", §164.504 "Uses and disclosures: Organizational
   requirements").
5. **HITECH Act — Health Information Technology for Economic and
   Clinical Health Act**, codified at 42 USC §17931 – §17954. Section
   13402 (the breach-notification statute that empowered the §164.400
   – §164.414 rule).
6. **NIST SP 800-66 Rev 2** (Feb 2024) — "Implementing the Health
   Insurance Portability and Accountability Act (HIPAA) Security
   Rule: A Cybersecurity Resource Guide". The verbatim 800-53 r5
   cross-walk + CSF 2.0 mapping comes from this publication.
7. **HHS OCR HIPAA Audit Protocol** — the comprehensive control
   checklist OCR uses during compliance audits. Published at
   https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/
   audit/protocol/index.html.
8. **OCR Resolution Agreements + Corrective Action Plans** — the
   public record of OCR enforcement actions. LOOP-V references but
   does not encode these; they are case-law not statutory law.
9. **HITRUST CSF v11.2.0 control catalog** — HITRUST Alliance
   publication. LOOP-V.V5 reads the catalog reference (control IDs +
   maturity tiers); the HITRUST Validated Assessment is performed
   external to LOOP-V.
10. **NIST CSF 2.0** (Feb 26, 2024) — the cross-walk anchor for
    NIST SP 800-66 Rev 2's CSF subcategory mapping.
11. **21st Century Cures Act, §4004 (information blocking)** + 45 CFR
    Part 171 — cross-reference only.
12. **CMS Interoperability and Patient Access Final Rule, CMS-9115-F
    (May 2020)** — cross-reference only.

Operator-supplied configuration (e.g. naming the CSP's Privacy Officer
+ Security Officer per §164.308(a)(2), supplying executed BAA PDFs
into the tracker) is accepted via `org-profile.yaml` + tracker UI.
Operator adds carry a `provenance: operator-supplied` tag
distinguishable from federal-published catalog entries.

The catalog never includes invented safeguards, hearsay-sourced
implementation specs, or vendor-marketing rubrics. If a vendor (e.g.
AWS HIPAA Eligible Services list, GCP HIPAA Implementation Guide,
Azure HIPAA/HITECH Implementation Guide) publishes its own narrative,
that material is cited as supporting context only and does NOT define
the catalog content.

### 1.6 Operational defaulting

LOOP-V is `applicable_conditional: true` and **default-OFF**. The
trigger is `org-profile.yaml processes_phi: true` OR
`--hipaa` CLI flag OR `CLOUD_EVIDENCE_HIPAA=1` env var. A CSP whose
customers do not include any healthcare entity does not run LOOP-V.

When the trigger fires:
- All five slices execute in dependency order (V.V1 → V.V2 → V.V3 →
  V.V4 → V.V5).
- BAA registry is pre-populated from `org-profile.yaml customers[]`
  entries where `data_classification` includes `PHI`.
- The breach-notification pipeline V.V4 connects to LOOP-G.G2 + LOOP-
  M.M4 incident-comms so a single incident routes through the
  CIRCIA / SEC 8-K / HIPAA / state-PII pipelines simultaneously.

---

## 2. Statutory & regulatory drivers (verbatim quotes; pinned URLs)

Every URL accessed 2026-06-08. Where the federal source returns HTTP
403 / 404 to anonymous fetches, the implementer downloads the
PDF / HTML into `cloud-evidence/docs/sources/hipaa/` and re-quotes
verbatim inside the per-slice doc. Each source is mirrored in
`cloud-evidence/docs/sources/hipaa/` before V.V1 ships.

### 2.1 45 CFR §164 Subpart C — Security Standards for the Protection of Electronic Protected Health Information

URL (pinned): https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C
(accessed 2026-06-08; HTTP 200; eCFR rendering.)

**§164.302 — Applicability (verbatim):**

> "A covered entity or business associate must comply with the
> applicable standards, implementation specifications, and
> requirements of this subpart with respect to electronic protected
> health information of a covered entity."

**§164.304 — Definitions (verbatim, principal terms):**

> "Access means the ability or the means necessary to read, write,
> modify, or communicate data/information or otherwise use any system
> resource."

> "Administrative safeguards are administrative actions, and
> policies and procedures, to manage the selection, development,
> implementation, and maintenance of security measures to protect
> electronic protected health information and to manage the conduct
> of the covered entity's or business associate's workforce in
> relation to the protection of that information."

> "Physical safeguards are physical measures, policies, and
> procedures to protect a covered entity's or business associate's
> electronic information systems and related buildings and equipment,
> from natural and environmental hazards, and unauthorized intrusion."

> "Technical safeguards means the technology and the policy and
> procedures for its use that protect electronic protected health
> information and control access to it."

**§164.306 — Security standards: General rules (verbatim):**

> "(a) General requirements. Covered entities and business associates
> must do the following:
> (1) Ensure the confidentiality, integrity, and availability of all
>     electronic protected health information the covered entity or
>     business associate creates, receives, maintains, or transmits.
> (2) Protect against any reasonably anticipated threats or hazards
>     to the security or integrity of such information.
> (3) Protect against any reasonably anticipated uses or disclosures
>     of such information that are not permitted or required under
>     subpart E of this part.
> (4) Ensure compliance with this subpart by its workforce."

> "(d) Implementation specifications. ... (2) When a standard adopted
> in §164.308, §164.310, §164.312, §164.314, or §164.316 includes
> required implementation specifications, a covered entity or
> business associate must implement the implementation
> specifications. (3) When a standard adopted in §164.308, §164.310,
> §164.312, §164.314, or §164.316 includes addressable
> implementation specifications, a covered entity or business
> associate must — (i) Assess whether each implementation
> specification is a reasonable and appropriate safeguard in its
> environment, when analyzed with reference to the likely
> contribution to protecting electronic protected health
> information; and (ii) As applicable to the covered entity or
> business associate — (A) Implement the implementation
> specification if reasonable and appropriate; or (B) If
> implementing the implementation specification is not reasonable
> and appropriate — (1) Document why it would not be reasonable
> and appropriate to implement the implementation specification;
> and (2) Implement an equivalent alternative measure if
> reasonable and appropriate."

The "required vs addressable" distinction is encoded in V.V1's
catalog as a per-implementation-spec `requirement_type:
required|addressable` field. Addressable implementation specs that
the CSP chooses not to implement carry a tracker entry capturing
the §164.306(d)(3)(ii)(B)(1) documentation rationale.

**§164.308 — Administrative safeguards (verbatim, headline list):**

> "(a) A covered entity or business associate must, in accordance
> with §164.306:
> (1)(i) Standard: Security management process. Implement policies
>        and procedures to prevent, detect, contain, and correct
>        security violations.
> (1)(ii) Implementation specifications:
>         (A) Risk analysis (Required). ...
>         (B) Risk management (Required). ...
>         (C) Sanction policy (Required). ...
>         (D) Information system activity review (Required). ...
> (2) Standard: Assigned security responsibility. ...
> (3)(i) Standard: Workforce security. ...
> (4)(i) Standard: Information access management. ...
> (5)(i) Standard: Security awareness and training. ...
> (6)(i) Standard: Security incident procedures. ...
> (7)(i) Standard: Contingency plan. ...
> (8) Standard: Evaluation. ...
> (b)(1) Standard: Business associate contracts and other
>        arrangements. ..."

Total: 9 standards under §164.308 with ~20 implementation specs.

**§164.310 — Physical safeguards (verbatim, headline list):**

> "(a)(1) Standard: Facility access controls. ...
> (b) Standard: Workstation use. ...
> (c) Standard: Workstation security. ...
> (d)(1) Standard: Device and media controls. ..."

Total: 4 standards under §164.310 with ~10 implementation specs.

**§164.312 — Technical safeguards (verbatim, headline list):**

> "A covered entity or business associate must, in accordance with
> §164.306:
> (a)(1) Standard: Access control. ...
> (b) Standard: Audit controls. ...
> (c)(1) Standard: Integrity. ...
> (d) Standard: Person or entity authentication. ...
> (e)(1) Standard: Transmission security. ..."

Total: 5 standards under §164.312 with ~10 implementation specs.

**§164.314 — Organizational requirements (verbatim, headline list):**

> "(a)(1) Standard: Business associate contracts or other
>        arrangements. ...
> (b)(1) Standard: Requirements for group health plans. ..."

Critically, §164.314(a)(2) enumerates the required BAA terms:

> "(2)(i) Business associate contracts. The contract between a
>        covered entity and a business associate must provide that
>        the business associate will:
>        (A) Comply, where applicable, with the Security Rule with
>            regard to electronic protected health information;
>        (B) In accordance with §164.308(b)(2), ensure that any
>            subcontractors that create, receive, maintain, or
>            transmit electronic protected health information on
>            behalf of the business associate agree to comply with
>            the applicable requirements of this subpart by
>            entering into a contract or other arrangement that
>            complies with this section; and
>        (C) Report to the covered entity any security incident of
>            which it becomes aware, including breaches of
>            unsecured protected health information as required by
>            §164.410."

This text drives V.V2's BAA-content checklist.

**§164.316 — Policies and procedures and documentation requirements
(verbatim):**

> "(a) Standard: Policies and procedures. Implement reasonable and
> appropriate policies and procedures to comply with the standards,
> implementation specifications, or other requirements of this
> subpart, taking into account those factors specified in §164.306(b)(2)."

> "(b)(1) Standard: Documentation.
> (i) Maintain the policies and procedures implemented to comply with
>     this subpart in written (which may be electronic) form; and
> (ii) If an action, activity or assessment is required by this
>      subpart to be documented, maintain a written (which may be
>      electronic) record of the action, activity, or assessment."

> "(2) Implementation specifications:
> (i) Time limit (Required). Retain the documentation required by
>     paragraph (b)(1) of this section for 6 years from the date of
>     its creation or the date when it last was in effect, whichever
>     is later.
> (ii) Availability (Required). Make documentation available to
>      those persons responsible for implementing the procedures to
>      which the documentation pertains.
> (iii) Updates (Required). Review documentation periodically, and
>       update as needed, in response to environmental or
>       operational changes affecting the security of the electronic
>       protected health information."

The 6-year retention period is encoded in V.V1's catalog and surfaces
in the tracker UI as a per-document retention countdown.

### 2.2 45 CFR §164 Subpart D — Notification in the Case of Breach of Unprotected Protected Health Information

URL (pinned): https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D
(accessed 2026-06-08.)

**§164.400 — Applicability (verbatim):**

> "The requirements of this subpart shall apply with respect to
> breaches of protected health information occurring on or after
> September 23, 2009."

**§164.402 — Definitions (verbatim, principal terms):**

> "Breach means the acquisition, access, use, or disclosure of
> protected health information in a manner not permitted under
> subpart E of this part which compromises the security or privacy
> of the protected health information."

> "(2) Except as provided in paragraph (1) of this definition, an
> acquisition, access, use, or disclosure of protected health
> information in a manner not permitted under subpart E is
> presumed to be a breach unless the covered entity or business
> associate, as applicable, demonstrates that there is a low
> probability that the protected health information has been
> compromised based on a risk assessment of at least the following
> factors:
> (i) The nature and extent of the protected health information
>     involved, including the types of identifiers and the
>     likelihood of re-identification;
> (ii) The unauthorized person who used the protected health
>      information or to whom the disclosure was made;
> (iii) Whether the protected health information was actually
>       acquired or viewed; and
> (iv) The extent to which the risk to the protected health
>      information has been mitigated."

The 4-factor probability-of-compromise assessment is the structural
heart of V.V4. Each incident gets a 4-factor risk assessment with
verbatim factor labels + operator narrative + score.

**§164.402 — Definition of "Unsecured protected health information"
(verbatim):**

> "Unsecured protected health information means protected health
> information that is not rendered unusable, unreadable, or
> indecipherable to unauthorized persons through the use of a
> technology or methodology specified by the Secretary in the
> guidance issued under section 13402(h)(2) of Public Law 111-5."

The HHS guidance (74 FR 42740, Aug 24, 2009) specifies AES + FIPS
140-validated encryption + NIST SP 800-88 media-destruction methods.
LOOP-V cross-references LOOP-A's FIPS 140 evidence + LOOP-R's PQC
roadmap.

**§164.404 — Notification to individuals (verbatim):**

> "(a)(1) General rule. A covered entity shall, following the
> discovery of a breach of unsecured protected health information,
> notify each individual whose unsecured protected health information
> has been, or is reasonably believed by the covered entity to have
> been, accessed, acquired, used, or disclosed as a result of such
> breach.
> (2) Breaches treated as discovered. ... a breach shall be treated
> as discovered by a covered entity as of the first day on which
> such breach is known to the covered entity, or, by exercising
> reasonable diligence, would have been known to the covered
> entity. A covered entity shall be deemed to have knowledge of a
> breach if such breach is known, or by exercising reasonable
> diligence would have been known, to any person, other than the
> person committing the breach, who is a workforce member or agent
> of the covered entity."

> "(b) Implementation specifications: Timeliness of notification.
> ... a covered entity shall provide the notification required by
> paragraph (a) of this section without unreasonable delay and in
> no case later than 60 calendar days after discovery of a breach."

**60 calendar days** is the V.V4 individual-notice clock.

> "(c) Implementation specifications: Content of notification.
> (1) Elements. The notification ... shall include, to the extent
> possible:
> (A) A brief description of what happened, including the date of
>     the breach and the date of the discovery of the breach, if
>     known;
> (B) A description of the types of unsecured protected health
>     information that were involved in the breach (such as whether
>     full name, social security number, date of birth, home
>     address, account number, diagnosis, disability code, or other
>     types of information were involved);
> (C) Any steps individuals should take to protect themselves from
>     potential harm resulting from the breach;
> (D) A brief description of what the covered entity involved is
>     doing to investigate the breach, to mitigate harm to
>     individuals, and to protect against any further breaches;
>     and
> (E) Contact procedures for individuals to ask questions or learn
>     additional information, which shall include a toll-free
>     telephone number, an e-mail address, Web site, or postal
>     address."

The 5-element notice content (A-E) is encoded in V.V4's notice
template; the template renders into a `.docx` ready for counsel
sign-off.

### 2.3 45 CFR §164.406 — Notification to the media

URL: same eCFR Subpart D as above.

**§164.406 (verbatim):**

> "(a) Standard. For a breach of unsecured protected health
> information involving more than 500 residents of a State or
> jurisdiction, a covered entity shall, following the discovery of
> the breach as provided in §164.404(a)(2), notify prominent media
> outlets serving the State or jurisdiction.
> (b) Implementation specifications: Timeliness of notification.
> ... a covered entity shall provide the notification required by
> paragraph (a) of this section without unreasonable delay and in
> no case later than 60 calendar days after discovery of a breach."

The **500-individual threshold** + 60-day clock is encoded in V.V4.

### 2.4 45 CFR §164.408 — Notification to the Secretary

**§164.408 (verbatim):**

> "(a) Standard. A covered entity shall, following the discovery of a
> breach of unsecured protected health information as provided in
> §164.404(a)(2), notify the Secretary."

> "(b) Implementation specifications: Breaches involving 500 or more
> individuals. For breaches of unsecured protected health information
> involving 500 or more individuals, a covered entity shall, except
> as provided in §164.412, provide the notification required by
> paragraph (a) of this section contemporaneously with the
> notification required by §164.404(a) and in the manner specified
> on the HHS Web site."

> "(c) Implementation specifications: Breaches involving less than
> 500 individuals. For breaches of unsecured protected health
> information involving less than 500 individuals, a covered entity
> shall maintain a log or other documentation of such breaches and,
> not later than 60 days after the end of each calendar year,
> provide the notification required by paragraph (a) of this section
> for breaches discovered during the preceding calendar year, in the
> manner specified on the HHS Web site."

V.V4 tracks both notification paths: contemporaneous (500+) +
annual roll-up (<500) due by 60 days after year-end (so March 1 of
the following year).

### 2.5 45 CFR §164.410 — Notification by a business associate

This is the section directly governing a CSP-as-Business-Associate.

**§164.410 (verbatim):**

> "(a)(1) General rule. A business associate shall, following the
> discovery of a breach of unsecured protected health information,
> notify the covered entity of such breach.
> (2) Breaches treated as discovered. ... a breach shall be treated
> as discovered by a business associate as of the first day on
> which such breach is known to the business associate or, by
> exercising reasonable diligence, would have been known to the
> business associate."

> "(b) Implementation specifications: Timeliness of notification. ...
> a business associate shall provide the notification required by
> paragraph (a) of this section without unreasonable delay and in
> no case later than 60 calendar days after discovery of a breach."

> "(c) Implementation specifications: Content of notification.
> (1) The notification required by paragraph (a) of this section
> shall include, to the extent possible, the identification of each
> individual whose unsecured protected health information has been,
> or is reasonably believed by the business associate to have been,
> accessed, acquired, used, or disclosed during the breach.
> (2) A business associate shall provide the covered entity with
> any other available information that the covered entity is
> required to include in notification to the individual under
> §164.404(c) at the time of the notification ... or promptly
> thereafter as information becomes available."

V.V4 routes any incident scoped to a Covered Entity's data through a
BA-to-CE notification template that includes the §164.410(c)
individual-identification list + the §164.404(c) content elements.
The BA-to-CE clock is the inner clock; the CE-to-individual clock is
60 days from the CE's discovery (which is, per the regulation, when
the BA notified the CE).

### 2.6 45 CFR §164 Subpart E — Privacy Rule (cross-reference)

**§164.502 — Uses and disclosures of protected health information:
General rules (verbatim, principal):**

> "(a) Standard. A covered entity or business associate may not use
> or disclose protected health information, except as permitted or
> required by this subpart or by subpart C of this part."

> "(e)(1) Standard: Disclosures to business associates. (i) A
> covered entity may disclose protected health information to a
> business associate and may allow a business associate to create,
> receive, maintain, or transmit protected health information on
> its behalf, if the covered entity obtains satisfactory assurances
> ... that the business associate will appropriately safeguard the
> information."

**§164.504 — Uses and disclosures: Organizational requirements
(verbatim, principal):**

> "(e)(1) Standard: Business associate contracts. (i) The contract
> or other arrangement required by §164.502(e)(2) must meet the
> requirements of paragraph (e)(2), (e)(3), or (e)(5) of this
> section, as applicable."

> "(2) Implementation specifications: Business associate contracts.
> A contract between the covered entity and a business associate
> must:
> (i) Establish the permitted and required uses and disclosures of
>     protected health information by the business associate;
> (ii) Provide that the business associate will:
>      (A) Not use or further disclose the information other than
>          as permitted or required by the contract or as required
>          by law;
>      (B) Use appropriate safeguards and comply, where applicable,
>          with subpart C of this part with respect to electronic
>          protected health information, to prevent use or
>          disclosure of the information other than as provided for
>          by its contract;
>      (C) Report to the covered entity any use or disclosure of
>          the information not provided for by its contract of
>          which it becomes aware, including breaches of unsecured
>          protected health information as required by §164.410,
>          and any security incident of which it becomes aware;
>      (D) In accordance with §164.502(e)(1)(ii), ensure that any
>          subcontractors that create, receive, maintain, or
>          transmit protected health information on behalf of the
>          business associate agree to the same restrictions,
>          conditions, and requirements that apply to the business
>          associate ... ;
>      (E) Make available protected health information in
>          accordance with §164.524 ... ;
>      (F) Make available protected health information for
>          amendment ... ;
>      (G) Make available the information required to provide an
>          accounting of disclosures ... ;
>      (H) To the extent the business associate is to carry out a
>          covered entity's obligation under this subpart, comply
>          with the requirements of this subpart that apply to the
>          covered entity in the performance of such obligation;
>      (I) Make its internal practices, books, and records relating
>          to the use and disclosure of protected health
>          information received from, or created or received by the
>          business associate on behalf of, the covered entity
>          available to the Secretary for purposes of determining
>          the covered entity's compliance with this subpart; and
>      (J) At termination of the contract, if feasible, return or
>          destroy all protected health information received from,
>          or created or received by the business associate on
>          behalf of, the covered entity ... "

V.V2's BAA-content checklist encodes all 10 sub-bullets ((A)-(J))
of §164.504(e)(2)(ii). Each executed BAA in the registry is checked
against the 10-bullet list; missing terms surface as compliance
exceptions in the BAA registry UI.

### 2.7 HITECH Act — 42 USC §§17931 – 17954

URL (pinned): https://www.govinfo.gov/content/pkg/USCODE-2023-title42/pdf/USCODE-2023-title42-chap156-subchapIII.pdf
(accessed 2026-06-08; mirrored to `docs/sources/hipaa/HITECH-42USC-17931-17954.pdf`.)

The HITECH Act is the statute that empowered §164 Subpart D.
Principal sections:

- **§17931** — Application of security provisions and penalties to
  business associates of covered entities; annual guidance on
  security provisions. Establishes that business associates are
  directly subject to certain Security Rule provisions + that HHS
  must issue annual guidance.
- **§17932** — Notification in the case of breach. The statutory
  text that 45 CFR §164.404 implements.
- **§17934** — Application of privacy provisions and penalties to
  business associates. Establishes that business associates are
  directly subject to certain Privacy Rule provisions.
- **§17937** — Conditions on certain disclosures of records to
  health plans. Cross-reference only.
- **§17939** — Improved enforcement.
- **§17953** — Information for individuals.
- **§17954** — Studies on cloud computing + similar matters.

**§17932(d) — Timing of notification (verbatim):**

> "Except as provided in section 17937(g) of this title or
> subsection (g) of this section, all notifications required under
> this section shall be made without unreasonable delay and in no
> case later than 60 calendar days after the discovery of a breach
> by the covered entity involved (or business associate involved
> in the case of a notification required under subsection (b))."

This is the statutory anchor for the 60-day clocks at §164.404,
§164.406, §164.410.

### 2.8 NIST SP 800-66 Rev 2 — Implementing the HIPAA Security Rule: A Cybersecurity Resource Guide

URL (pinned): https://csrc.nist.gov/pubs/sp/800/66/r2/final
PDF: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf
(accessed 2026-06-08; PDF mirrored to `docs/sources/hipaa/NIST.SP.800-66r2.pdf`.)

Published February 2024. Authors: Jeffrey A. Marron, R. Gary McGraw,
Ronald S. Ross, et al. Final, supersedes Rev 1 (Oct 2008).

**Purpose (verbatim, from abstract):**

> "The HIPAA Security Rule focuses on safeguarding electronic
> protected health information (ePHI) maintained or transmitted by
> covered entities and their business associates. ... This document
> provides practical guidance and resources that can be used by
> regulated entities of all sizes to safeguard ePHI and better
> understand the security concepts discussed in the HIPAA Security
> Rule. The guide is not intended to serve as legal advice or as
> recommendations based on a covered entity's or business associate's
> specific circumstances."

**§3 — Key Activities + Sample Questions (verbatim structural
description):**

> "This section presents Key Activities derived from the HIPAA
> Security Rule and Sample Questions that regulated entities may
> consider as they perform a risk analysis and implement security
> controls."

Each Key Activity is mapped to NIST SP 800-53 Rev 5 controls in
Appendix F of 800-66 Rev 2 (the cross-walk table). V.V3 reads
Appendix F as the authoritative cross-walk and emits the mapping
as a signed JSON envelope. The cross-walk has approximately 100
HIPAA Security Rule implementation specifications mapped to 400+
800-53 control statements.

**Appendix F structure (verbatim, section heading):**

> "Appendix F — Mapping of HIPAA Security Rule Standards and
> Implementation Specifications to NIST SP 800-53, Revision 5
> Controls"

The appendix is a multi-page table organized by:
- HIPAA Security Rule citation (e.g. §164.308(a)(1)(ii)(A))
- HIPAA Standard / Implementation Specification name (e.g. "Risk
  Analysis")
- Requirement type (Required / Addressable)
- Mapped NIST SP 800-53 Rev 5 control identifiers (e.g. RA-3, RA-5,
  CA-2, CA-7)

V.V3's extractor parses this table at extractor-run time and emits
the cross-walk JSON. The implementer confirms the row-by-row mapping
at slice-implementation time from the mirrored PDF.

### 2.9 HITRUST CSF v11.2.0

URL (pinned): https://hitrustalliance.net/product-tool/hitrust-csf/
(accessed 2026-06-08; HTTP 200; HITRUST Alliance landing.)

HITRUST CSF (Common Security Framework) is a private-sector
framework that integrates and harmonises requirements from
HIPAA / HITECH, NIST SP 800-53, ISO/IEC 27001, COBIT, PCI-DSS, GDPR,
NIST CSF, FedRAMP, and others. Version 11.2.0 released October 2024
(per HITRUST Alliance public release notes). The CSF catalog is
delivered to HITRUST CSF Assessor (CSFA) firms + HITRUST-licensed
entities via the MyCSF portal; the control identifiers (e.g.
01.a, 06.d, 09.aa) are stable + publicly cited across the industry.

**HITRUST CSF v11.2.0 structure (publicly summarised):**

> 14 Control Categories (named 01 through 14) plus an Information
> Security Management Program category:
> - 00 — Information Security Management Program
> - 01 — Access Control
> - 02 — Human Resources Security
> - 03 — Risk Management
> - 04 — Security Policy
> - 05 — Organization of Information Security
> - 06 — Compliance
> - 07 — Asset Management
> - 08 — Physical and Environmental Security
> - 09 — Communications and Operations Management
> - 10 — Information Systems Acquisition, Development, and
>        Maintenance
> - 11 — Information Security Incident Management
> - 12 — Business Continuity Management
> - 13 — Privacy Practices
> - 14 — Third-Party Assurance

Total: ~ 156 controls (varies slightly per CSF version) at the
"baseline implementation" level. Each control has 5 maturity
implementation levels (Policy, Process, Implemented, Measured,
Managed).

V.V5 reads the publicly-cited HITRUST CSF v11.2.0 control identifiers
(only — not the full control text, which is under HITRUST licensing)
and emits the cross-walk from FedRAMP-collected evidence to HITRUST
control IDs. Operators who hold a HITRUST CSF license can join the
cross-walk to their MyCSF tenant manually.

**REQUIRES-RESEARCH:** confirm HITRUST CSF v11.2.0 release date +
control category list from a mirrored HITRUST Alliance public
release-notes page before V.V5 ships.

### 2.10 HHS OCR Enforcement + Resolution Agreements

URL (pinned): https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html
(accessed 2026-06-08.)

OCR publishes resolution agreements + corrective action plans for
HIPAA enforcement actions. Recent representative settlements:

- **Banner Health (2023)** — $1.25M settlement; 2016 breach affecting
  ~ 2.8M individuals.
- **Lifespan Health System (2023)** — $1.04M settlement; lost
  unencrypted laptop.
- **iHealth Solutions (2023)** — $75,000 settlement; small BA
  enforcement action — relevant to LOOP-V because it shows OCR will
  enforce against business associates directly.
- **Montefiore Medical Center (2024)** — $4.75M settlement; insider-
  threat data theft.
- **Optum 360 (2024)** — $4.75M settlement; OptumInsight breach.
- **Doctors' Management Services (Dec 2023)** — $100,000 settlement;
  ransomware attack.

LOOP-V does not encode this case law into the catalog; it references
the OCR enforcement page in operator-facing tracker UI documentation
so the operator + counsel see the precedent base when triaging
incidents.

### 2.11 HHS OCR HIPAA Audit Protocol

URL (pinned): https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/audit/protocol/index.html
(accessed 2026-06-08.)

The Audit Protocol is the operational checklist OCR auditors use
during HIPAA compliance audits. Structured by:

- Section: Privacy Rule / Breach Notification Rule / Security Rule
- Established Performance Criteria (the regulatory citation, e.g.
  §164.308(a)(1)(ii)(A))
- Inquiry of Management questions
- Procedural steps OCR auditors take to verify evidence
- Sample-size guidance for control testing

V.V3's emitter produces an OCR Audit Protocol response packet
(`out/ocr-audit-response-{audit-id}.zip`) that pre-populates the
evidence-pointer fields for each control statement, citing the
LOOP-A / LOOP-E / LOOP-G / LOOP-V evidence already collected. The
operator + counsel review the packet before submission to OCR.

### 2.12 21st Century Cures Act §4004 — Information Blocking (cross-reference)

URL (pinned): https://www.congress.gov/bill/114th-congress/house-bill/34/text
+ implementing regulation 45 CFR Part 171.

The Cures Act §4004 establishes information-blocking prohibitions
against actors (health IT developers, health information networks,
and health information exchanges) that "engage in a practice that ...
is likely to interfere with, prevent, or materially discourage
access, exchange, or use of electronic health information." 45 CFR
Part 171 implements the rule with eight exceptions + enforcement
mechanisms.

LOOP-V does not implement information-blocking attestation directly
(out of scope per §1.3) but tags BAA registry entries where the
counterparty is a Cures-Act "actor" so the operator + counsel see
the cross-regulatory exposure.

### 2.13 CMS Interoperability and Patient Access Final Rule (CMS-9115-F) (cross-reference)

URL (pinned): https://www.cms.gov/Regulations-and-Guidance/Guidance/Interoperability/index
(accessed 2026-06-08.)

CMS-9115-F (effective May 1, 2020 with phased deadlines through
July 2021) requires CMS-regulated payors (Medicare Advantage,
Medicaid managed care, CHIP managed care, QHP issuers) to:

- Implement a Patient Access API.
- Implement a Provider Directory API.
- Implement a Payer-to-Payer Data Exchange.

For CSPs whose customers are CMS-regulated payors, the
interoperability rule's API requirements layer atop HIPAA Security
Rule + Privacy Rule. LOOP-V cross-references for catalog
completeness but does not implement Patient Access API attestation.

### 2.14 NIST CSF 2.0 cross-walk anchor

URL (pinned): https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
(accessed 2026-06-08; mirrored as part of pre-existing FedPy work.)

NIST CSF 2.0 added the "Govern" function as a new top-level function
(in addition to Identify, Protect, Detect, Respond, Recover). NIST
SP 800-66 Rev 2 Appendix C provides the cross-walk from HIPAA
Security Rule citations to CSF 2.0 subcategories. V.V3 reads that
appendix in addition to Appendix F (800-53 cross-walk) and emits
the dual cross-walk.

### 2.15 NIST SP 800-53 Rev 5 — controls cross-walked into LOOP-V

URL (pinned): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-08; mirrored as part of pre-existing FedPy work.)

LOOP-V's V.V3 cross-walk uses NIST SP 800-66 Rev 2 Appendix F as the
authoritative mapping. The principal 800-53 r5 control families
involved (high-level):

| HIPAA Section | Principal 800-53 r5 control families |
|---|---|
| §164.308 (Administrative) | AT (Awareness & Training), CA (Assessment, Authorization, Monitoring), CP (Contingency Planning), IR (Incident Response), PS (Personnel Security), PM (Program Management), PL (Planning), RA (Risk Assessment), SI (System & Information Integrity) |
| §164.310 (Physical) | PE (Physical & Environmental Protection), MP (Media Protection) |
| §164.312 (Technical) | AC (Access Control), AU (Audit & Accountability), IA (Identification & Authentication), SC (System & Communications Protection), SI (System & Information Integrity) |
| §164.314 (Organizational) | SA (System & Services Acquisition), PS (Personnel Security), PM (Program Management) |
| §164.316 (Documentation) | DM (Data Management — privacy), PL (Planning), CM (Configuration Management) |
| §164 Subpart D (Breach) | IR-6 (Incident Reporting), IR-8 (Incident Response Plan), PT-5 (Privacy Notice) |

The exact per-implementation-spec mapping is read from 800-66 Rev 2
Appendix F at V.V3 extractor time.

### 2.16 FedRAMP 20x KSI baseline cross-reference

URL: FedRAMP 20x Phase Two FRMR catalog (already loaded into the
`cloud-evidence/data/frmr-catalog.json` artifact from prior work).

LOOP-V.V3 augments the 800-66 Rev 2 cross-walk with a join to FedRAMP
KSIs. Each HIPAA implementation spec → 800-53 control mapping is
extended to → KSI ID where a KSI maps to the same 800-53 control.
This lets the operator demonstrate "FedRAMP evidence X (already
collected for KSI Y) satisfies HIPAA Security Rule implementation
spec Z" — a single evidence path covers both regimes.

### 2.17 Additional supporting references

- **NIST SP 800-30 Rev 1 — Guide for Conducting Risk Assessments**
  — the risk-assessment methodology HIPAA §164.308(a)(1)(ii)(A)
  Risk Analysis spec is most commonly implemented against.
- **NIST SP 800-37 Rev 2 — Risk Management Framework** — the RMF
  process feeds §164.308(a)(8) Evaluation.
- **NIST SP 800-88 Rev 1 — Guidelines for Media Sanitization** —
  the methodology for §164.310(d)(2)(i) Disposal + (ii) Media
  re-use.
- **NIST SP 800-111 — Guide to Storage Encryption Technologies for
  End User Devices** — feeds §164.312(a)(2)(iv) Encryption and
  Decryption.
- **NIST SP 800-52 Rev 2 — Guidelines for the Selection,
  Configuration, and Use of Transport Layer Security (TLS)
  Implementations** — feeds §164.312(e) Transmission Security.
- **NIST SP 800-178 — A Comparison of Attribute Based Access Control
  (ABAC) Standards for Data Service Applications** — feeds
  §164.312(a)(1) Access Control.
- **FIPS 140-3 — Security Requirements for Cryptographic Modules**
  — the validated-encryption standard for "unsecured PHI" definition.

LOOP-V cites these but does not encode them as catalog content;
they are supporting context for the operator + counsel.

---

## 3. Slice list

| id   | title                                                                  | status  | commit | depends_on (within LOOP-V) | also depends_on (external)                                                       | estimated_effort |
|------|------------------------------------------------------------------------|---------|--------|----------------------------|----------------------------------------------------------------------------------|------------------|
| V.V1 | HIPAA Safeguard Catalog (catalog + extractor)                          | pending | TBD    | —                          | LOOP-A.A5 (signing); eCFR fetcher                                                | small (~5d)      |
| V.V2 | BAA Tracker (registry + tracker UI + .docx renderer)                   | pending | TBD    | V.V1                       | tracker DB + auth + signed audit log; LOOP-A.A4 (bundle)                         | medium (~6d)     |
| V.V3 | NIST SP 800-66 Rev 2 Cross-walk + OCR Audit Protocol response packet   | pending | TBD    | V.V1                       | LOOP-A.A1 (POA&M); LOOP-A.A5 (signing); existing FedRAMP control evidence        | medium (~6d)     |
| V.V4 | Breach Notification Pipeline (4-factor + clocks + BA-to-CE + HHS)      | pending | TBD    | V.V1, V.V2                 | LOOP-G.G2 + LOOP-M.M4 (incident comms); CIRCIA workflow; LOOP-A.A5; LOOP-INV-S   | large (~7d)      |
| V.V5 | HITRUST CSF v11.2.0 Mapping + readiness scorecard                      | pending | TBD    | V.V1, V.V3                 | LOOP-A.A5 (signing); FedRAMP control evidence; HITRUST CSF public catalog refs   | medium (~6d)     |

Per-slice docs (each ≥ 800 lines):

- `cloud-evidence/docs/slices/V/V.V1.md`
- `cloud-evidence/docs/slices/V/V.V2.md`
- `cloud-evidence/docs/slices/V/V.V3.md`
- `cloud-evidence/docs/slices/V/V.V4.md`
- `cloud-evidence/docs/slices/V/V.V5.md`

Each per-slice doc carries:

- YAML frontmatter (status, commit, completed_date, depends_on, blocks,
  estimated_effort, last_updated, applicable_conditional flag).
- Mission, authoritative-sources (≥ 6 sources with verbatim quotes),
  scope (in/out), inputs (TypeScript interfaces), outputs (canonical
  JSON schemas + .docx / .xlsx / .pdf layouts), algorithm / steps,
  files-to-create / modify, test specifications (≥ 15 tests), risks
  (≥ 4), open questions, REQUIRES-OPERATOR-INPUT table, implementation
  log slot, completion checklist.

---

## 4. Authoritative sources (full list)

| # | Source | URL | Accessed | Form |
|---|---|---|---|---|
| 1 | 45 CFR §164 Subpart A (definitions) | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-A | 2026-06-08 | HTML (eCFR) |
| 2 | 45 CFR §164 Subpart C (Security Rule) | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C | 2026-06-08 | HTML (eCFR) |
| 3 | 45 CFR §164 Subpart D (Breach Notification) | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D | 2026-06-08 | HTML (eCFR) |
| 4 | 45 CFR §164 Subpart E (Privacy Rule, cross-ref) | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E | 2026-06-08 | HTML (eCFR) |
| 5 | HITECH Act 42 USC §17931–§17954 | https://www.govinfo.gov/content/pkg/USCODE-2023-title42/pdf/USCODE-2023-title42-chap156-subchapIII.pdf | 2026-06-08 | PDF |
| 6 | NIST SP 800-66 Rev 2 (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf | 2026-06-08 | PDF |
| 7 | NIST SP 800-66 Rev 2 landing | https://csrc.nist.gov/pubs/sp/800/66/r2/final | 2026-06-08 | HTML |
| 8 | HITRUST CSF v11.2.0 page | https://hitrustalliance.net/product-tool/hitrust-csf/ | 2026-06-08 | HTML |
| 9 | HITRUST CSF release notes (search) | https://hitrustalliance.net/blog/ | 2026-06-08 | HTML |
| 10 | HHS OCR HIPAA enforcement page | https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/index.html | 2026-06-08 | HTML |
| 11 | HHS OCR Resolution Agreements | https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html | 2026-06-08 | HTML |
| 12 | HHS OCR HIPAA Audit Protocol | https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/audit/protocol/index.html | 2026-06-08 | HTML |
| 13 | HHS Breach Notification Portal | https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf | 2026-06-08 | HTML (auth-walled) |
| 14 | HHS Breach Report Tool (Wall of Shame) | https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf | 2026-06-08 | HTML |
| 15 | HHS Guidance Specifying Technologies and Methodologies That Render PHI Unusable (74 FR 42740) | https://www.federalregister.gov/documents/2009/08/24/E9-20169 | 2026-06-08 | HTML |
| 16 | 21st Century Cures Act §4004 | https://www.congress.gov/bill/114th-congress/house-bill/34/text | 2026-06-08 | HTML |
| 17 | 45 CFR Part 171 (Information Blocking) | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-D/part-171 | 2026-06-08 | HTML (eCFR) |
| 18 | CMS-9115-F Interoperability Final Rule | https://www.cms.gov/Regulations-and-Guidance/Guidance/Interoperability/index | 2026-06-08 | HTML |
| 19 | NIST CSF 2.0 | https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf | 2026-06-08 | PDF |
| 20 | NIST SP 800-53 Rev 5 | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf | 2026-06-08 | PDF |
| 21 | NIST SP 800-30 Rev 1 (Risk Assessment) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-30r1.pdf | 2026-06-08 | PDF |
| 22 | NIST SP 800-37 Rev 2 (RMF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf | 2026-06-08 | PDF |
| 23 | NIST SP 800-88 Rev 1 (Media Sanitization) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf | 2026-06-08 | PDF |
| 24 | NIST SP 800-52 Rev 2 (TLS) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf | 2026-06-08 | PDF |
| 25 | FIPS 140-3 | https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf | 2026-06-08 | PDF |
| 26 | OSCAL 1.1.2 model | https://pages.nist.gov/OSCAL/concepts/layer/ | 2026-06-08 | HTML |

All sources are public; no PII; no controlled material. Every PDF
mirrored to `cloud-evidence/docs/sources/hipaa/` before the dependent
slice ships.

---

## 5. Reusable primitives (modules from other loops this loop depends on)

| Primitive | Owner loop | Use in LOOP-V |
|---|---|---|
| `core/sign.ts` (Ed25519 + manifest builder) | LOOP-A.A5 / B.1 | All five V slices flow outputs through `signEnvelope()` before write |
| `core/oscal-poam.ts` (OSCAL POA&M v1.1.2 emitter) | LOOP-A.A1 | V.V3 emits a "HIPAA safeguard gap" POA&M finding per addressable spec not implemented |
| `core/submission-bundle.ts` (`WELL_KNOWN` catalogue) | LOOP-A.A4 | V.V1 catalog + V.V2 BAA inventory + V.V3 cross-walk + V.V4 breach record + V.V5 HITRUST readiness added as roles |
| `core/envelope.ts` (provider blocks, signed envelope schema) | LOOP-A | V.V1+V.V3+V.V4+V.V5 reuse envelope shape |
| `core/control-benchmark.ts` (NIST 800-53 r5) | existing | V.V3 cross-references each HIPAA safeguard to the 800-53 r5 controls already collected |
| `core/risk-score.ts` | LOOP-B.B1 | V.V3 POA&M items pick up composite scores; V.V4 4-factor analysis emits a composite breach-risk score |
| Tracker DB pool + signed audit log | existing | V.V1 + V.V2 + V.V4 + V.V5 persist data + sign-offs in tracker DB |
| `core/docx.ts` OOXML helper (zip-store layout) | LOOP-C.* (template pack) | V.V2 BAA registry .docx + V.V4 breach notice .docx + V.V5 HITRUST scorecard .docx reuse this helper |
| `core/xlsx-reader.ts` + `inventory-workbook.ts` patterns | existing | V.V5 emits an `.xlsx` HITRUST gap-list companion to the `.docx` scorecard |
| FRMR catalog reader (`core/ksi-map.ts` + frmr-catalog.json) | existing | V.V3 + V.V5 join HIPAA safeguard / HITRUST control IDs to KSIs |
| `core/incident-comms.ts` (G.G2) + CIRCIA extension + privacy-incident-response (M.M4) | LOOP-G.G2 + LOOP-M.M4 | V.V4 plugs into the unified incident-comms pipeline so a single incident routes to HIPAA + CIRCIA + state-PII + SEC simultaneously |
| `inventory.assets[].data_classification` tag = "PHI" | LOOP-INV-S | V.V3 + V.V4 scope evidence collection to PHI-tagged assets only |

LOOP-V **introduces** these new primitives (not present in prior loops):

- `core/hipaa-safeguards-catalog.ts` — typed safeguard catalog loader (V.V1).
- `core/baa-tracker.ts` — BAA registry + executed-BAA upload handler (V.V2).
- `core/hipaa-800-66-mapper.ts` — 800-66 Rev 2 cross-walk emitter (V.V3).
- `core/breach-notification.ts` — 4-factor analysis + clock engine (V.V4).
- `core/hitrust-csf-mapper.ts` — HITRUST CSF v11.2.0 cross-walk (V.V5).

These new primitives are positioned for reuse by future LOOPs (notably
LOOP-Z.Z4 for ISO/IEC 27018 PII processor evidence, which re-uses
V.V3's cross-walk shape).

---

## 6. Data flow diagram

```mermaid
flowchart TD
    subgraph Sources[Federally-published HIPAA / NIST / HHS-OCR / HITRUST sources]
        ECFR_C[(eCFR 45 CFR §164 Subpart C)]
        ECFR_D[(eCFR 45 CFR §164 Subpart D)]
        ECFR_E[(eCFR 45 CFR §164 Subpart E)]
        HITECH[(HITECH Act 42 USC §§17931-17954)]
        SP66[(NIST SP 800-66 Rev 2 PDF)]
        SP53[(NIST 800-53 Rev 5 PDF)]
        CSF[(NIST CSF 2.0 PDF)]
        OCR_PROTOCOL[(HHS OCR HIPAA Audit Protocol)]
        HHS_GUIDANCE[(74 FR 42740 — Unsecured PHI guidance)]
        HITRUST[(HITRUST CSF v11.2.0 catalog refs)]
        FRMR[(FedRAMP 20x FRMR catalog)]
    end

    subgraph V1[Slice V.V1 — Safeguard Catalog]
        EXT[scripts/extract-hipaa-catalog.mjs]
        NORM[normalize standards + impl specs + required/addressable]
        XWALK1[cross-walk to NIST 800-53 r5 via 800-66 Rev 2 Appendix F]
        XWALK2[cross-walk to NIST CSF 2.0 via 800-66 Rev 2 Appendix C]
        SIGN1[Ed25519 + RFC 3161 sign]
        CATJSON[(data/hipaa-safeguards-catalog.json)]
        CATLOADER[core/hipaa-safeguards-catalog.ts loader]
    end

    ECFR_C --> EXT
    ECFR_D --> EXT
    ECFR_E --> EXT
    HITECH --> EXT
    SP66 --> EXT
    SP53 --> EXT
    CSF --> EXT
    HHS_GUIDANCE --> EXT
    EXT --> NORM --> XWALK1 --> XWALK2 --> SIGN1 --> CATJSON --> CATLOADER

    subgraph CSP[CSP environment / tracker DB]
        ORGPROF[(org-profile.yaml processes_phi)]
        INV[(LOOP-INV-S PHI-tagged inventory.json)]
        TRACKER_DB[(tracker DB — baa_registry + breach_incidents + hipaa_safeguards)]
        KSIS[(KSI run outputs from prior FedPy runs)]
        UPLOAD_BAA[(Operator-uploaded executed BAA PDFs)]
    end

    subgraph V2[Slice V.V2 — BAA Tracker]
        BAAREG[core/baa-tracker.ts]
        INBOUND[Inbound BAAs — Covered Entity → CSP]
        OUTBOUND[Outbound BAAs — CSP → subprocessor]
        CHECKLIST[§164.504(e)(2)(ii) 10-bullet checklist]
        EXPIRY[expiry alerts + signatory tracking]
        BAA_DOCX[(out/baa-status-{system-id}-{date}.docx)]
        BAA_JSON[(out/baa-status-{system-id}-{date}.json signed)]
    end

    CATLOADER --> BAAREG
    ORGPROF --> BAAREG
    UPLOAD_BAA --> BAAREG
    BAAREG --> INBOUND --> CHECKLIST --> TRACKER_DB
    BAAREG --> OUTBOUND --> CHECKLIST --> TRACKER_DB
    BAAREG --> EXPIRY --> TRACKER_DB
    BAAREG --> BAA_DOCX
    BAAREG --> BAA_JSON

    subgraph V3[Slice V.V3 — 800-66 Rev 2 Cross-walk + OCR Audit Packet]
        MAP66[core/hipaa-800-66-mapper.ts]
        APP_F[Read Appendix F (HIPAA → 800-53 mapping)]
        APP_C[Read Appendix C (HIPAA → CSF 2.0 mapping)]
        JOIN_EVIDENCE[Join to existing FedRAMP control evidence]
        XWALK_JSON[(data/hipaa-800-66-crosswalk.json signed)]
        OCR_PACKET[(out/ocr-audit-response-{audit-id}.zip)]
        POAM_GAP[POA&M finding per addressable spec gap]
    end

    CATLOADER --> MAP66
    SP66 --> MAP66
    OCR_PROTOCOL --> MAP66
    KSIS --> JOIN_EVIDENCE
    MAP66 --> APP_F --> JOIN_EVIDENCE --> XWALK_JSON
    MAP66 --> APP_C --> XWALK_JSON
    XWALK_JSON --> OCR_PACKET
    XWALK_JSON --> POAM_GAP

    subgraph V4[Slice V.V4 — Breach Notification Pipeline]
        BREACH[core/breach-notification.ts]
        DETECT[Incident detected — feeds from G.G2 + M.M4]
        FOUR_FACTOR[§164.402 4-factor probability-of-compromise assessment]
        SCOPE[Scope: which Covered Entities? how many individuals?]
        CLOCKS[Clocks: BA-to-CE 60d / CE-to-individuals 60d / HHS 60d or contemporaneous / media 60d if 500+]
        BA_TO_CE[Generate BA-to-CE notice §164.410]
        CE_TO_IND[Generate CE-to-individual notice §164.404]
        HHS_NOTICE[Generate HHS-Secretary notice §164.408]
        MEDIA_NOTICE[Generate media notice §164.406 if 500+]
        BREACH_JSON[(out/breach-incident-{id}.json signed)]
        BREACH_DOCX[(out/breach-incident-{id}.docx)]
    end

    INV --> BREACH
    TRACKER_DB --> BREACH
    DETECT --> FOUR_FACTOR --> SCOPE --> CLOCKS
    CLOCKS --> BA_TO_CE
    CLOCKS --> CE_TO_IND
    CLOCKS --> HHS_NOTICE
    CLOCKS --> MEDIA_NOTICE
    BA_TO_CE --> BREACH_DOCX
    CE_TO_IND --> BREACH_DOCX
    HHS_NOTICE --> BREACH_DOCX
    MEDIA_NOTICE --> BREACH_DOCX
    FOUR_FACTOR --> BREACH_JSON
    SCOPE --> BREACH_JSON
    CLOCKS --> BREACH_JSON

    subgraph V5[Slice V.V5 — HITRUST CSF v11.2.0 Mapping]
        HITRUST_MAP[core/hitrust-csf-mapper.ts]
        FEDRAMP_TO_HITRUST[FedRAMP KSI / 800-53 → HITRUST CSF control IDs]
        HITRUST_GAPS[Identify gaps where HITRUST requires more than FedRAMP]
        HITRUST_JSON[(data/hitrust-csf-v11.2.0-crosswalk.json signed)]
        HITRUST_DOCX[(out/hitrust-readiness-{system-id}-{date}.docx)]
        HITRUST_XLSX[(out/hitrust-readiness-{system-id}-{date}.xlsx)]
    end

    CATLOADER --> HITRUST_MAP
    HITRUST --> HITRUST_MAP
    KSIS --> FEDRAMP_TO_HITRUST
    FRMR --> FEDRAMP_TO_HITRUST
    XWALK_JSON --> HITRUST_MAP
    HITRUST_MAP --> FEDRAMP_TO_HITRUST --> HITRUST_GAPS
    FEDRAMP_TO_HITRUST --> HITRUST_JSON
    HITRUST_GAPS --> HITRUST_DOCX
    HITRUST_GAPS --> HITRUST_XLSX

    subgraph Tracker[Tracker DB + UI]
        DB_SAFE[(hipaa_safeguards)]
        DB_BAA[(baa_registry)]
        DB_XWALK[(hipaa_800_66_crosswalk)]
        DB_BREACH[(breach_incidents)]
        DB_HITRUST[(hitrust_csf_scores)]
        UI_SAFE[Safeguard inventory page]
        UI_BAA[BAA registry page + expiry alerts]
        UI_BREACH[Breach incident workspace with countdown timers]
        UI_HITRUST[HITRUST readiness pane]
    end

    CATJSON --> DB_SAFE
    BAA_JSON --> DB_BAA
    XWALK_JSON --> DB_XWALK
    BREACH_JSON --> DB_BREACH
    HITRUST_JSON --> DB_HITRUST
    DB_SAFE --> UI_SAFE
    DB_BAA --> UI_BAA
    DB_BREACH --> UI_BREACH
    DB_HITRUST --> UI_HITRUST

    subgraph Submission[Submission bundle / downstream]
        BUNDLE[(submission bundle — A.A4)]
        OCR_SUBMIT[(HHS OCR Breach Portal — operator-submitted)]
        OCR_AUDIT[(HHS OCR HIPAA Audit response — operator-submitted)]
        Z4[(LOOP-Z.Z4 ISO/IEC 27018 PII Processor evidence)]
    end

    CATJSON --> BUNDLE
    BAA_JSON --> BUNDLE
    XWALK_JSON --> BUNDLE
    BREACH_JSON --> BUNDLE
    HITRUST_JSON --> BUNDLE
    BREACH_DOCX --> OCR_SUBMIT
    OCR_PACKET --> OCR_AUDIT
    XWALK_JSON --> Z4
```

---

## 7. Test strategy

LOOP-V tests live under `cloud-evidence/tests/hipaa/`. Two strata:

**Stratum A — unit + integration (per-slice).** Each slice ships its
own test file (`hipaa-safeguards-catalog.test.ts`, `baa-tracker.test.ts`,
`hipaa-800-66-mapper.test.ts`, `breach-notification.test.ts`,
`hitrust-csf-mapper.test.ts`). Coverage targets: 90%+ on production
code paths, 100% on signing + canonical-JSON serialisation paths +
100% on breach-clock arithmetic.

**Stratum B — end-to-end (loop-level).** A single
`hipaa-end-to-end.test.ts` exercises V.V1 → V.V2 → V.V3 → V.V4 → V.V5
on a fixture environment (synthetic Covered Entity + 3 BAAs + 1
breach incident under `tests/fixtures/hipaa/`) and asserts:

1. Catalog snapshot validates against schema v1.
2. BAA registry validates; the 10-bullet §164.504(e)(2)(ii) checklist
   is computed correctly for each BAA.
3. 800-66 Rev 2 cross-walk JSON validates; the join to FedRAMP
   evidence produces the expected count of "covered" vs "uncovered"
   safeguards.
4. OCR Audit Protocol response packet ZIP contains the expected
   per-control evidence-pointer entries.
5. Breach-notification incident:
   - 4-factor analysis emits a probability-of-compromise rating.
   - 60-day BA-to-CE clock computes correctly.
   - 60-day CE-to-individual clock computes correctly.
   - HHS-Secretary clock computes correctly (contemporaneous vs
     annual based on individual count).
   - Media-notice clock fires for 500+-individual breaches in a
     single state.
   - All four notices render in `.docx` with the §164.404(c) 5-element
     content for individual notice.
6. HITRUST CSF v11.2.0 cross-walk validates; gap list is computed.
7. POA&M emission count matches the number of safeguard gaps.
8. Bundle catalogue contains all five new role IDs.
9. Signed envelopes verify cleanly with public key in
   `tests/fixtures/keys/hipaa-pubkey.pem`.

**Stratum C — clock arithmetic + edge cases (V.V4-focused).** A
dedicated `breach-clocks.test.ts` exercises:

- Discovery date on Dec 31 → CE-to-individual notice due Mar 1
  (60 calendar days, not business days).
- Discovery date on Feb 28 in a leap year → notice due Apr 28 + 1.
- Discovery date on Feb 28 in a non-leap year → notice due Apr 29.
- Breach affecting exactly 500 individuals in a single state → media
  notice required.
- Breach affecting 499 individuals in a single state but 600 across
  three states → no media notice (per-state threshold).
- Breach affecting 100 individuals → HHS annual roll-up due Mar 1 of
  next calendar year.
- Late discovery (BA discovered the breach 90 days after it occurred)
  → the BA-to-CE clock starts from BA discovery date.

**Fixture data sources.** All fixtures derive from real federally-
published sources (mirrored PDFs + their text extractions) plus
synthetic-but-realistic CSP environment snapshots (BAA PDFs are
synthetic; signatures are test-key signatures). No production-code
mocks; SDK transport may be mocked at the wire layer per REO Rule 2.

**Schema-validation tests.** Every emitted JSON validates via
`ajv` against the schemas under `cloud-evidence/schemas/hipaa/`. A
regression suite re-validates older snapshots against newer schema
versions to ensure forward-compatibility.

**Adversarial cases (per-slice doc §8).** Each per-slice doc enumerates
≥ 4 adversarial cases (e.g. "BAA missing one of the 10 bullets",
"breach where 4-factor analysis concludes low probability —
notification not required", "HITRUST gap where FedRAMP collected
sufficient evidence but at a different maturity tier", "OCR audit
request for evidence pre-dating the FedRAMP authorization") and the
expected emitter behaviour.

---

## 8. Risks summary (reference RISKS file)

Full risks register lives in `docs/loops/LOOP-V-RISKS.md` (1309 lines).
Highest-priority risks summarised here:

| ID | Risk | Severity | Mitigation |
|---|---|---|---|
| V-R1 | Breach-clock miscalculation (60-day clock starts from wrong date — discovery vs incident vs notification) | Critical | V.V4 unit tests for every clock-start scenario; clock computed as MAX(incident-date, discovery-date) per §164.404(a)(2); tracker UI shows the chosen start date with regulatory citation |
| V-R2 | 4-factor probability-of-compromise analysis underestimates risk → BA fails to notify CE → CE fails to notify individuals → OCR enforcement | Critical | V.V4 four-factor analysis requires operator + counsel sign-off; system never auto-determines "low probability"; defaults to "presumed breach" per §164.402(2); 3PAO + counsel review path mandatory before "no notification" decision |
| V-R3 | BAA registry incomplete or out-of-date — a Covered Entity not in the registry submits PHI; CSP processes PHI without a BAA in place | High | V.V2 pulls customer list from `org-profile.yaml`; periodic reconciliation against actual customer DB; missing BAA blocks PHI-tagged data ingestion via INV-S policy enforcement |
| V-R4 | Source drift — HHS amends 45 CFR Subpart C/D or NIST publishes 800-66 Rev 3 mid-cycle | Medium | V.V1 + V.V3 extractors are re-runnable; source-drift detection in `scripts/check-hipaa-source-drift.mjs` runs daily; CHANGELOG entry mandatory |
| V-R5 | HITRUST CSF v11.2.0 license restriction — full control text is under HITRUST license; LOOP-V can only cite IDs, not text | Medium | V.V5 emits ID + maturity-tier cross-walk only; operator who holds HITRUST license joins to MyCSF tenant for full text |
| V-R6 | OCR Audit Protocol response packet incomplete — auditor asks for evidence LOOP-V did not anticipate | High | V.V3 packet covers every Established Performance Criterion in the protocol; gaps surface as `coverage:miss` diagnostics; operator + counsel add manual evidence pointers via tracker |
| V-R7 | Breach involves PHI that is also state PII — both V.V4 and LOOP-U fire; risk of double-notice or conflicting notice text | Medium | V.V4 + LOOP-U coordinate via shared `incident-id`; single notice consolidates both regimes; counsel reviews the merged notice text |
| V-R8 | Subprocessor flow-down failure — CSP's own subprocessor processes PHI without a downstream BAA | High | V.V2 tracks outbound BAAs (CSP → subprocessor); the `org-profile.yaml subprocessors[]` list cross-checks; missing outbound BAA surfaces as a §164.308(b)(2) compliance exception |
| V-R9 | Encryption-coverage gap — PHI stored or transmitted without FIPS 140-validated encryption → "unsecured PHI" definition triggers → any incident becomes a breach | High | V.V3 cross-walks §164.312(a)(2)(iv) + (e)(2)(ii) Encryption to LOOP-A FIPS 140 evidence; gaps surface as POA&M items + INV-S `coverage:miss` |
| V-R10 | OCR enforcement action while LOOP-V is mid-cycle — operator needs to demonstrate compliance with retroactive evidence | High | 6-year retention per §164.316(b)(2)(i) is encoded in tracker; all signed envelopes persist; OCR audit packet pulls historical snapshots from the tracker DB |
| V-R11 | BA processes PHI for which no Covered Entity has assigned data-classification — risk of unidentified PHI | Medium | INV-S tagging is mandatory before LOOP-V runs; missing classification blocks LOOP-V execution; operator surfaces gaps via the inventory-coverage report |
| V-R12 | Scope-creep into HIPAA Privacy Rule attestation | Low | Explicit REO Rule 1 + scope guard in §1.3 |

---

## 9. Open questions

1. **§164.402 4-factor analysis — operator vs counsel ownership.**
   The 4-factor analysis is the gateway between "incident" and
   "presumed breach". Should the operator perform the analysis with
   counsel review, or counsel perform the analysis with operator
   evidence input? Decision: counsel performs the analysis; operator
   supplies evidence; the tracker UI captures both signatures (counsel
   + operator) before the analysis is finalised. The system never
   auto-determines.
2. **HITRUST CSF v11.2.0 release date.** The exact release date of
   v11.2.0 must be confirmed from a mirrored HITRUST Alliance public
   release-notes page before V.V5 ships. Working assumption: October
   2024 per industry reports.
3. **OCR Audit Protocol versioning.** OCR's Audit Protocol page does
   not carry a version number. The protocol structure has been stable
   since 2016 but HHS may amend silently. V.V3 captures the protocol
   page hash at packet-generation time; CHANGELOG entry on hash change.
4. **State-AG coordination on breaches.** Some state AGs require
   direct breach notification (e.g. NY OAG, CA OAG). V.V4 emits a
   "state-AG notification candidates" list per the
   `org-profile.yaml customer_states[]` setting; coordination with
   LOOP-U state-PII handler is via shared incident-id.
5. **BAA template choice — HHS sample vs counsel-custom.** HHS
   provides a sample BAA on its website. Should V.V2 ship the HHS
   sample as a template? Decision: yes — V.V2 includes the HHS
   sample as a starter template; counsel customises before execution;
   the executed BAA PDF is uploaded into the tracker.
6. **Subprocessor BAA chain depth.** §164.308(b)(2) requires a BA
   to flow down to its subcontractors. V.V2 tracks one level of
   outbound BAAs. What about subprocessors-of-subprocessors? Decision:
   V.V2 tracks first-level only; deeper levels are the subprocessor's
   responsibility; operator + counsel review the depth boundary.
7. **Breach affecting multiple Covered Entities simultaneously.** A
   single incident may compromise PHI from multiple Covered Entities.
   V.V4 must emit one BA-to-CE notice per CE. Decision: V.V4 enumerates
   the affected CE list from the inventory-asset map; emits N notices;
   each notice scoped to that CE's PHI only.
8. **Cross-border PHI under HIPAA.** What if the BA processes PHI in
   a non-US cloud region for a US Covered Entity? HIPAA does not
   prohibit cross-border processing per se, but the BAA must address
   it. V.V2's BAA checklist includes a "data-location" attestation
   field; operator captures the geographic scope.
9. **OCR portal API automation.** Could V.V4 auto-submit to the
   HHS OCR portal? Decision: no — REO Rule 10 prohibits auto-sign;
   the portal requires human authentication anyway.
10. **Sample BAA storage encryption.** Executed BAAs uploaded into
    the tracker are themselves sensitive (contain signatures + terms).
    They MUST be stored at rest in the tracker DB with KMS-managed
    encryption + access controls limited to operator + counsel
    roles. V.V2 enforces.

---

## 10. Glossary deltas

The following terms are added to `docs/GLOSSARY.md` when V.V1 ships:

- **Protected Health Information (PHI)** — 45 CFR §160.103: individually
  identifiable health information transmitted or maintained by a
  covered entity (or BA) in any form. Excludes employment records
  held by a covered entity in its role as employer and education
  records covered by FERPA.
- **Electronic Protected Health Information (ePHI)** — PHI that is
  created, received, maintained, or transmitted in electronic form.
  The Security Rule (Subpart C) governs ePHI; the Privacy Rule
  (Subpart E) governs all PHI regardless of form.
- **Covered Entity (CE)** — 45 CFR §160.103: a health plan, a health
  care clearinghouse, or a health care provider who transmits any
  health information in electronic form in connection with a
  transaction covered by subchapter C.
- **Business Associate (BA)** — 45 CFR §160.103: a person who, on
  behalf of a covered entity, performs or assists in the performance
  of a function or activity involving the use or disclosure of PHI.
  CSPs that process PHI for a CE are BAs.
- **Business Associate Agreement (BAA)** — the contract required by
  §164.502(e) + §164.504(e) + §164.314(a) between a CE and a BA (or
  between a BA and a subcontractor BA).
- **Breach (HIPAA)** — 45 CFR §164.402: the acquisition, access, use,
  or disclosure of PHI in a manner not permitted under Subpart E
  which compromises the security or privacy of the PHI.
- **Unsecured PHI** — PHI not rendered unusable, unreadable, or
  indecipherable to unauthorized persons via the technology /
  methodology specified in the HHS guidance (74 FR 42740): FIPS 140-
  validated encryption + NIST SP 800-88 media-destruction methods.
- **Required implementation specification** — 45 CFR §164.306(d)(2):
  an implementation specification that a CE or BA must implement.
- **Addressable implementation specification** — 45 CFR §164.306(d)(3):
  an implementation specification that the CE or BA must assess, then
  either implement or document why implementation is not reasonable
  and appropriate (and implement an equivalent alternative).
- **4-factor analysis** — the four risk-assessment factors at §164.402(2)
  used to determine whether an impermissible use/disclosure is presumed
  to be a breach: (i) nature + extent of PHI; (ii) unauthorized person;
  (iii) actually acquired or viewed; (iv) extent of mitigation.
- **HHS OCR** — Department of Health and Human Services Office for
  Civil Rights; the HIPAA enforcement agency.
- **OCR Audit Protocol** — the published checklist OCR auditors use
  during HIPAA compliance audits.
- **HITECH Act** — Health Information Technology for Economic and
  Clinical Health Act (2009); the statute that empowered the HIPAA
  Breach Notification Rule + extended direct BA liability.
- **HITRUST CSF** — Health Information Trust Alliance Common Security
  Framework; a private-sector framework integrating HIPAA / HITECH /
  NIST / ISO / PCI requirements. v11.2.0 is the current version.
- **HITRUST CSF Assessor (CSFA)** — a firm certified by HITRUST to
  perform Validated Assessments.
- **MyCSF** — the HITRUST online portal for assessment management +
  control catalog access.
- **NIST SP 800-66 Rev 2** — NIST's HIPAA Security Rule implementation
  guide (Feb 2024). Appendix F = HIPAA → 800-53 r5 cross-walk;
  Appendix C = HIPAA → CSF 2.0 cross-walk.
- **Sample BAA** — the model BAA HHS publishes at
  https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html.
- **Subcontractor BA** — a BA that processes PHI on behalf of another
  BA (rather than directly for a CE); requires a flow-down BAA per
  §164.308(b)(2).

---

## 11. Cross-references (other loops / overlays / extensions)

| Reference | Direction | Detail |
|---|---|---|
| LOOP-U (Privacy — state PII + OMB Privacy Act) | bidirectional | Where PHI overlaps state PII, V.V4 + LOOP-U coordinate via shared incident-id; single consolidated notice text; counsel reviews; LOOP-U handles state-AG notification timing for the PII portion |
| LOOP-G.G2 (Incident Communications Procedures) | inbound | V.V4 consumes the incident-detection event from G.G2; V.V4 emits its HIPAA-specific notification artifacts; G.G2 also handles the customer-facing comms loop |
| LOOP-G.G2 + CIRCIA extension | bidirectional | If the breach is also a CIRCIA Covered Cyber Incident, the 72-hour CISA report fires in parallel; CIRCIA-WORKFLOW.md governs the coordination |
| LOOP-M.M4 (Privacy incident response) | bidirectional | M.M4 handles federal-Privacy-Act §552a(e)(10) incident notification; V.V4 handles HIPAA-specific notification; the two pipelines share incident-id |
| LOOP-A.A1 (POA&M) | outbound | V.V3 + V.V5 emit POA&M items for safeguard gaps + HITRUST gaps |
| LOOP-A.A2 (Assessment Plan) | outbound | V.V3 cross-walk methodology recorded in AP |
| LOOP-A.A3 (Assessment Results) | outbound | V.V3 + V.V5 evidence recorded in AR |
| LOOP-A.A4 (bundler) | outbound | V.V1 + V.V2 + V.V3 + V.V4 + V.V5 outputs added to bundle |
| LOOP-A.A5 (signing) | outbound | all V outputs flow through `signEnvelope()` |
| LOOP-A FIPS 140 evidence | inbound | V.V3 cross-walks §164.312(a)(2)(iv) + (e)(2)(ii) Encryption to FIPS 140 evidence; gap → POA&M |
| LOOP-B.B1 (risk score) | outbound | V.V3 POA&M items + V.V4 4-factor analysis receive composite scores |
| LOOP-INV-S (PHI-tagged inventory) | inbound | V.V3 + V.V4 scope evidence collection to PHI-tagged assets only; INV-S tagging mandatory before LOOP-V runs |
| LOOP-INR-RIR (incident response) | inbound | V.V4 reads IR plan + drill evidence as supporting context for breach-incident workspace |
| LOOP-Z.Z4 (ISO/IEC 27018 PII Processor) | outbound | V.V3 cross-walk feeds Z.Z4; V blocks Z.Z4 |
| LOOP-Q.Q1 (Marketplace) | optional | Operators that complete HITRUST Validated Assessment may surface a "HITRUST CSF v11.2.0 Validated" badge via Q.Q1 (the validation itself is external to LOOP-V) |
| LOOP-W (prohibited vendors) | none | unrelated |
| LOOP-S (DFARS) | none directly | but a DoD-Health-Affairs customer would invoke both LOOP-S + LOOP-V |
| LOOP-R (PQC) | partial | PQC migration affects §164.312(a)(2)(iv) + (e)(2)(ii) Encryption sub-functions (long-term) |
| LOOP-Y (sector overlays) | reuse | LOOP-Y healthcare overlay can reuse V.V1 catalog + V.V3 cross-walk |
| SEC 8-K Item 1.05 extension to G.G2 | bidirectional | If the CSP is also a registrant subject to SEC reporting + the breach meets the 8-K materiality threshold, the SEC 4-business-day clock fires; V.V4 + G.G2 SEC extension coordinate via shared incident-id |
| CIRCIA Final Rule extensions to G.G2 + M.M4 | bidirectional | If the incident is also a CIRCIA Covered Cyber Incident, the CIRCIA 72-hour clock + 24-hour ransom-payment clock fire in parallel; CIRCIA-WORKFLOW.md governs |

---

## 12. Status table

| slice | status | commit | last_updated | notes |
|---|---|---|---|---|
| V.V1 | pending | TBD | 2026-06-08 | foundation — extractor + catalog loader + signed snapshot |
| V.V2 | pending | TBD | 2026-06-08 | BAA tracker + §164.504(e)(2)(ii) checklist; depends on V.V1 |
| V.V3 | pending | TBD | 2026-06-08 | 800-66 Rev 2 cross-walk + OCR Audit Protocol response packet; depends on V.V1 |
| V.V4 | pending | TBD | 2026-06-08 | Breach notification pipeline + 4-factor + clocks; depends on V.V1+V.V2 |
| V.V5 | pending | TBD | 2026-06-08 | HITRUST CSF v11.2.0 mapping + readiness scorecard; depends on V.V1+V.V3 |

When each slice completes, the implementer:

1. Updates this status row (status → done, commit hash, last_updated).
2. Updates the corresponding per-slice doc's frontmatter.
3. Updates `docs/STATUS.md` slice row (master tracker).
4. Appends a CHANGELOG entry.
5. Pushes to origin/main.
6. Runs `git log --oneline -3` to verify the commit landed.

Step 1 is what `## 12. Status table` provides. Steps 2-6 are governed
by `docs/SLICE-COMPLETION-PROCEDURE.md`.

---

## 13. Completion + push directive

> ### Slice-completion directive (apply to EVERY LOOP-V slice / section completion)
>
> When a LOOP-V slice / section completes implementation, the
> implementer MUST execute the following 7-step procedure atomically
> with the final commit. This procedure is identical to the
> repository-wide `docs/SLICE-COMPLETION-PROCEDURE.md` directive, with
> LOOP-V-specific augmentations:
>
> **Step 1** — Update `docs/STATUS.md` status row for the slice
> (`status` → `done`, `commit` hash, `last_updated` ISO date).
>
> **Step 2** — Update the loop SPEC status table in §12 of this file
> (commit hash, `status` → `done`).
>
> **Step 3** — Update the per-slice doc's frontmatter
> (`status: done`, `commit: <hash>`, `completed_date: <ISO>`,
> `last_updated: <ISO>`) and append the final Implementation log entry
> per `docs/IMPLEMENTATION-LOG-TEMPLATE.md`.
>
> **Step 4** — Update `docs/loops/LOOP-V-RISKS.md` if any new risks
> surfaced during implementation (severity, mitigation, owner). Adding
> the risk in the same commit is mandatory per REO standard.
>
> **Step 5** — Append a `CHANGELOG.md` entry in the "Unreleased"
> section: date, slice ID, summary of evidence path (which eCFR
> extraction, which DB query, which tracker action), commit hash
> placeholder.
>
> **Step 6** — Commit with the slice ID in the subject line plus
> `Co-Authored-By: Claude` trailer. Reference signed artefact
> filenames in the body if any were emitted.
>
> **Step 7** — Push to `origin/main`. Verify with
> `git log --oneline -3` that the commit landed. Until step 7 reports
> a clean push, the slice is NOT closed.
>
> **Step 8 (LOOP-V-specific)** — Counsel sign-off required for V.V2
> BAA tracker production deploy and V.V4 breach-notification pipeline
> production deploy. The implementer captures counsel sign-off in the
> per-slice doc's Implementation log + the tracker's signed audit log
> before declaring the slice closed.
>
> Failure to follow steps 1-8 is a REO violation. Future sessions WILL
> see the inconsistency. The on-disk archaeological record (STATUS.md,
> per-slice docs, RISKS file, CHANGELOG, git history) MUST stay in
> sync with the code at every commit boundary.

---

## 14. Worked end-to-end example (a representative happy path)

A SaaS CSP "ExampleCorp" runs the FedPy orchestrator in production on
2026-06-08. ExampleCorp:

- Serves 5 federal civilian customers (subject to OMB M-22-09 and
  FedRAMP Moderate). Two of the five are HHS components (CMS + VA)
  that flow PHI through the SaaS workflow.
- Has executed BAAs with CMS (signed 2024-03-15, expires 2027-03-14)
  and VA (signed 2024-07-22, expires 2027-07-21).
- Uses 3 subprocessors that touch PHI: an EHR data normalization
  vendor, a transcription vendor, and a cloud-native ML inference
  vendor. Outbound BAAs in place with all three.
- Has a Security Officer (Jane Doe) + Privacy Officer (John Smith)
  per §164.308(a)(2).
- Encrypts ePHI at rest with AWS KMS CMKs (FIPS 140-3 Level 1
  validated) + in transit with TLS 1.3 (FIPS-mode OpenSSL).
- Has a documented IR plan + completed two tabletop drills in
  CY 2025.
- Holds an active HITRUST CSF Validated Assessment (v11.0.0) from
  2024-09-01, expiring 2026-08-31. Plans to renew to v11.2.0.

1. **Orchestrator step 1** — `node cli.js --collect --bundle-submission
   --hipaa --zero-trust --prohibited-vendor-screen --pqc-inventory`.
2. **V.V1** runs `scripts/extract-hipaa-catalog.mjs`:
   - Fetches eCFR 45 CFR §164 Subparts A/C/D/E (HTML).
   - Fetches mirrored PDF of NIST SP 800-66 Rev 2 from
     `docs/sources/hipaa/`.
   - Builds safeguard catalog: 9 standards under §164.308 + 4 under
     §164.310 + 5 under §164.312 + 2 under §164.314 + 1 under §164.316
     = 21 standards with ~ 55 implementation specs.
   - Each impl spec tagged Required or Addressable.
   - Cross-walks each impl spec to NIST 800-53 r5 via 800-66 Rev 2
     Appendix F.
   - Cross-walks each impl spec to NIST CSF 2.0 via 800-66 Rev 2
     Appendix C.
   - Ed25519-signs the catalog. Writes
     `data/hipaa-safeguards-catalog.json`.
3. **V.V2** runs `core/baa-tracker.ts`:
   - Reads `org-profile.yaml` for customer + subprocessor lists.
   - Reads tracker DB `baa_registry` table.
   - For each inbound BAA (CMS, VA): runs the §164.504(e)(2)(ii)
     10-bullet checklist; all 10 bullets present → marked compliant.
   - For each outbound BAA (3 subprocessors): runs the 10-bullet
     checklist; one subprocessor BAA missing bullet (J) (return /
     destroy at termination) → marked incomplete; counsel notified.
   - Expiry alerts: CMS BAA expires in 280 days; VA BAA in 410 days.
     Both within the 12-month renewal-prep window; alert raised.
   - Emits `out/baa-status-examplecorp-20260608.json` (signed) +
     `.docx`.
4. **V.V3** runs `core/hipaa-800-66-mapper.ts`:
   - Reads V.V1 catalog.
   - For each impl spec → 800-53 control mapping, reads the existing
     FedRAMP control evidence (from prior KSI runs).
   - Result: ~ 48 of 55 impl specs fully covered by existing FedRAMP
     evidence; 7 impl specs partially covered or uncovered:
     - §164.308(a)(7)(ii)(A) Data backup plan — covered.
     - §164.308(a)(7)(ii)(B) Disaster recovery plan — covered.
     - §164.308(a)(7)(ii)(C) Emergency mode operation plan — covered.
     - §164.308(a)(7)(ii)(D) Testing and revision procedures —
       partially covered (annual DR test evidence present; no monthly
       small-scale tests).
     - §164.308(a)(7)(ii)(E) Applications and data criticality
       analysis — uncovered (no formal application-criticality
       artifact in FedRAMP evidence).
     - §164.310(d)(2)(iii) Accountability — partially covered (asset
       inventory present; per-asset accountability log missing).
     - §164.314(b) Requirements for group health plans — N/A
       (ExampleCorp does not serve a group health plan customer).
   - Writes `data/hipaa-800-66-crosswalk.json` (signed).
   - Emits 4 POA&M items for the 4 gaps (excluding N/A).
   - Builds `out/ocr-audit-response-{audit-id}.zip` (the OCR Audit
     Protocol response packet) pre-populated with evidence pointers
     for each of the OCR protocol's Established Performance Criteria.
5. **V.V4** does not run in the happy-path orchestrator execution
   (no active incident). The slice's runtime path is exercised only
   when LOOP-G.G2 / LOOP-M.M4 / CIRCIA fires an incident event.
   However, V.V4 ships a daily clock-sweep cron that:
   - Checks `breach_incidents` table for open incidents.
   - For each open incident, computes the remaining time on each
     active clock (BA-to-CE, CE-to-individual, HHS, media).
   - Surfaces countdown timers in tracker UI; emits low-water-mark
     alerts at 50% / 25% / 10% of the clock; emits final escalation
     at the deadline.
   - No new incident on 2026-06-08; clock sweep emits "no active
     incidents" status to operator.
6. **V.V5** runs `core/hitrust-csf-mapper.ts`:
   - Reads V.V1 catalog + V.V3 cross-walk.
   - For each FedRAMP control evidence pointer, joins to the HITRUST
     CSF v11.2.0 control IDs the evidence supports.
   - Result: HITRUST 09.aa Audit Logging — covered by AU-2 / AU-12;
     HITRUST 01.b User Authentication — covered by IA-2 / IA-5;
     HITRUST 06.d Compliance with Policies and Standards — covered
     by CA-2 / CA-7; etc.
   - Identifies HITRUST controls that require more than FedRAMP
     evidence (e.g. HITRUST 03.b Risk Treatment requires a risk-
     treatment-decision artifact that FedRAMP does not require
     explicitly).
   - Emits `data/hitrust-csf-v11.2.0-crosswalk.json` (signed).
   - Emits `out/hitrust-readiness-examplecorp-20260608.docx` +
     `.xlsx` gap list.
7. **Bundler (A.A4)**: picks up all five new role IDs in the bundle
   catalogue:
   - `hipaa-safeguards-catalog`
   - `baa-registry`
   - `hipaa-800-66-crosswalk`
   - `hitrust-csf-v11.2.0-crosswalk`
   - `ocr-audit-response-packet` (on demand)
8. **Tracker UI**: operator opens the HIPAA safeguard inventory page.
   Sees 21 standards with per-standard implementation-spec status
   (Required / Addressable / Implemented / Documented-non-implement).
   Drills into §164.308(a)(7)(ii)(E) — sees the POA&M item URL.
   Opens BAA registry — sees CMS + VA inbound + 3 subprocessor
   outbound; notes the missing-bullet-(J) flag on one subprocessor;
   counsel adds a follow-up task.
9. **Operator sign-off**: ExampleCorp's CISO (Jane Doe) opens the
   tracker safeguards-review page, reviews the V.V1 catalog snapshot
   + V.V3 cross-walk + V.V5 HITRUST readiness, signs (TOTP-protected
   operator key). Sign-off captured in tracker DB with timestamp +
   officer ID. Privacy Officer (John Smith) co-signs the V.V2 BAA
   inventory + V.V4 clock-sweep config.
10. **HITRUST Assessor handoff**: ExampleCorp's HITRUST CSFA opens
    the V.V5 readiness `.xlsx`, sees the gap list, plans the
    Validated Assessment scope for the v11.2.0 renewal.
11. **OCR audit response packet**: ExampleCorp's counsel reviews the
    `ocr-audit-response-{audit-id}.zip` for completeness against the
    OCR Audit Protocol. Approves for retention; if OCR issues an
    audit notice, counsel submits the packet within the OCR response
    window.

End-to-end orchestrator wall-clock for V.V1..V.V3 + V.V5:
~ 12-18 min. V.V4 runs as a daily cron + on incident events.
All artifacts signed + timestamped + REO-compliant.

---

## 15. Schema versioning

LOOP-V introduces five canonical JSON schemas, all under
`cloud-evidence/schemas/hipaa/`:

- `hipaa-safeguards-catalog-v1.json` — safeguard catalog (V.V1 emit).
- `baa-registry-v1.json` — BAA registry export (V.V2 emit).
- `hipaa-800-66-crosswalk-v1.json` — 800-66 Rev 2 cross-walk
  (V.V3 emit).
- `breach-incident-v1.json` — per-incident breach record (V.V4 emit).
- `hitrust-csf-v11.2.0-crosswalk-v1.json` — HITRUST cross-walk
  (V.V5 emit).

Schema v2 will be introduced if (a) HHS amends 45 CFR Subpart C / D
with new safeguards, (b) NIST publishes SP 800-66 Rev 3, (c) HITRUST
publishes CSF v12.x with structural changes, (d) HHS guidance on
"unsecured PHI" changes, or (e) the Real-Evidence-Only standard adds
new mandatory provenance fields. v1 is forward-compatible with
additive-only changes.

Every emit goes through:

```typescript
const validated = ajv.compile(schema)(payload);
if (!validated) throw new SchemaValidationError(...);
const envelope = signEnvelope(payload, { algorithm: 'ed25519', ... });
await fs.writeFile(outPath, JSON.stringify(envelope, null, 2));
```

REO Rule 9: schema cannot exceed implementation. Every declared field
is computed end-to-end from real evidence.

---

## 16. HIPAA safeguard implementation-spec rubric (canonical)

Each safeguard implementation spec has a stage-determination rubric
based on §164.306(d) Required vs Addressable. The rubric is encoded
in `data/hipaa-safeguards-catalog.json` per impl spec as a
`compliance_states[]` array. Below is the canonical projection for
§164.308(a)(1)(ii)(A) Risk Analysis — the other ~ 54 impl specs
follow the same pattern.

### §164.308(a)(1)(ii)(A) — Risk Analysis (Required)

| Compliance State | Criteria | Evidence sources |
|---|---|---|
| Not Implemented | No risk analysis on file; or analysis predates 6-year retention window with no successor. | Absence of risk-analysis artifact in tracker; absence in FedRAMP RA-3 control evidence. |
| Partially Implemented | Risk analysis present but outdated (> 12 months since last review) OR scope incomplete (does not cover all ePHI systems). | FedRAMP RA-3 evidence shows annual SAR but does not address PHI-specific risks; gap noted. |
| Implemented (Required satisfied) | Current risk analysis (< 12 months old) covering all ePHI systems; documented findings; risk-treatment plan present. | FedRAMP RA-3 + RA-5 + CA-2 evidence joined to PHI inventory (INV-S); risk register entry per PHI asset. |
| Documented + Reviewed (Audit-ready) | Risk analysis + treatment plan + ongoing-monitoring procedures + 6-year retention demonstrated. | FedRAMP RA-3 + CA-7 + PM-9 + signed risk register + tracker retention metadata. |

For Addressable impl specs (e.g. §164.308(a)(7)(ii)(D) Testing and
revision procedures), an additional state "Documented Non-
Implementation" exists per §164.306(d)(3)(ii)(B)(1):

| Compliance State | Criteria | Evidence sources |
|---|---|---|
| Documented Non-Implementation | Operator + counsel have documented why implementation is not reasonable and appropriate AND have implemented an equivalent alternative measure. | Tracker entry capturing the §164.306(d)(3)(ii)(B)(1) rationale + the equivalent-alternative measure description. |

Similar rubrics exist for each of the ~ 54 other impl specs; full
text lives in the catalog JSON.

### Overall safeguard standard compliance (weak-link rule)

A standard's overall compliance = MIN(impl spec compliance states),
with Required specs failing the standard if not Implemented or
better, and Addressable specs failing only if neither Implemented
nor Documented Non-Implementation.

### Overall HIPAA Security Rule compliance

Overall compliance = MIN across all 21 standards. A single Required
impl spec at "Not Implemented" caps the overall compliance and
emits a POA&M item.

REO Rule 4: where the rubric requires operator-supplied evidence
(e.g. "Risk analysis on file" — the operator uploads the analysis
artifact into the tracker), the operator types the citation in the
tracker UI; the system never substitutes.

---

## 17. Operator configuration

### 17.1 `cloud-evidence/org-profile.yaml` (HIPAA-relevant fields)

```yaml
processes_phi: true
hipaa:
  enabled: true
  security_officer:
    name: "Jane Doe"
    role: "Chief Information Security Officer"
    email: "jane@examplecorp.com"
    appointment_date: "2023-01-15"
  privacy_officer:
    name: "John Smith"
    role: "Chief Privacy Officer"
    email: "john@examplecorp.com"
    appointment_date: "2023-01-15"
  covered_entities:
    - id: "CMS"
      name: "Centers for Medicare & Medicaid Services"
      baa_executed_date: "2024-03-15"
      baa_expiry_date: "2027-03-14"
      baa_pdf_path: "secure-uploads/baa-cms-20240315.pdf"
      data_scope: "Medicare beneficiary records — claims data + enrollment"
      breach_notification_contact: "ocio-incidents@cms.hhs.gov"
    - id: "VA"
      name: "Department of Veterans Affairs"
      baa_executed_date: "2024-07-22"
      baa_expiry_date: "2027-07-21"
      baa_pdf_path: "secure-uploads/baa-va-20240722.pdf"
      data_scope: "Veterans health records — VistA + Cerner Millennium"
      breach_notification_contact: "incident-response@va.gov"
  subprocessors:
    - id: "ehr-normalizer-vendor"
      name: "ExampleEHR Normalizer Inc."
      baa_executed_date: "2024-04-01"
      baa_expiry_date: "2027-03-31"
      baa_pdf_path: "secure-uploads/baa-out-ehr-norm-20240401.pdf"
      data_scope: "PHI normalization service"
    - id: "transcription-vendor"
      name: "ExampleTranscription LLC"
      baa_executed_date: "2024-04-01"
      baa_expiry_date: "2027-03-31"
      baa_pdf_path: "secure-uploads/baa-out-transcription-20240401.pdf"
      data_scope: "Voice-to-text transcription for clinical notes"
    - id: "ml-inference-vendor"
      name: "ExampleML Inc."
      baa_executed_date: "2024-05-15"
      baa_expiry_date: "2027-05-14"
      baa_pdf_path: "secure-uploads/baa-out-ml-20240515.pdf"
      data_scope: "Cloud-native ML inference on de-identified PHI"
  data_locations:
    - region: "us-east-1"
      cloud: "aws"
      services: ["S3 (phi-bucket)", "RDS (phi-db)", "EKS (phi-cluster)"]
  encryption_attestation:
    at_rest: "AWS KMS CMK — FIPS 140-3 Level 1 validated"
    in_transit: "TLS 1.3 — FIPS-mode OpenSSL 3.0.x"
  hitrust:
    current_assessment_version: "v11.0.0"
    current_assessment_expiry: "2026-08-31"
    target_renewal_version: "v11.2.0"
    csfa_firm: "ExampleHITRUSTAssessor Inc."
```

### 17.2 `cloud-evidence/breach-notification-config.yaml`

```yaml
breach_notification:
  bata_default_clock_days: 60
  ce_to_individual_default_clock_days: 60
  hhs_500plus_clock: contemporaneous
  hhs_under500_annual_due_by: "March 1 of next calendar year"
  media_notice_threshold_individuals_per_state: 500
  media_notice_default_clock_days: 60
  notice_content_template:
    individual: "templates/164-404-c-individual-notice.docx"
    ba_to_ce: "templates/164-410-c-ba-to-ce-notice.docx"
    hhs: "templates/164-408-hhs-notice.docx"
    media: "templates/164-406-media-notice.docx"
  counsel_review_required: true
  operator_sign_off_required: true
  alert_thresholds_pct: [50, 25, 10, 0]
```

### 17.3 Required operator inputs (REQUIRES-OPERATOR-INPUT table)

| field name | type | validator | UI location | failure mode if missing |
|---|---|---|---|---|
| `hipaa.security_officer.name` | string | non-empty | Tracker > HIPAA > Officers | V.V3 emit blocks; diagnostic `requires_operator_input: security_officer.name` |
| `hipaa.privacy_officer.name` | string | non-empty | Tracker > HIPAA > Officers | V.V3 emit blocks |
| `hipaa.covered_entities[].baa_executed_date` | ISO date | date validator | Tracker > HIPAA > BAA Registry | V.V2 marks BAA invalid |
| `hipaa.covered_entities[].baa_pdf_path` | path | file-exists validator | Tracker > HIPAA > BAA Registry > Upload | V.V2 marks BAA missing-document |
| `hipaa.covered_entities[].data_scope` | string | non-empty | Tracker > HIPAA > BAA Registry | V.V2 marks BAA missing-data-scope |
| `hipaa.subprocessors[].baa_executed_date` | ISO date | date validator | Tracker > HIPAA > Subprocessors | V.V2 flags §164.308(b)(2) flow-down gap |
| `hipaa.encryption_attestation.at_rest` | string | non-empty | Tracker > HIPAA > Encryption | V.V3 caps §164.312(a)(2)(iv) at Not Implemented |
| `hipaa.encryption_attestation.in_transit` | string | non-empty | Tracker > HIPAA > Encryption | V.V3 caps §164.312(e)(2)(ii) at Not Implemented |
| `breach_notification.counsel_review_required` | bool | boolean | Tracker > HIPAA > Breach Config | defaults to true; cannot be false in production |
| `addressable_spec_documentation[]` | array of objects | per-impl-spec | Tracker > HIPAA > Addressable Specs | V.V3 flags addressable spec as undocumented |
| `risk_analysis_artifact_url` | URL or path | URL/file validator | Tracker > HIPAA > §164.308(a)(1)(ii)(A) | V.V3 caps Risk Analysis at Not Implemented |
| `incident_response_plan_url` | URL or path | URL/file validator | Tracker > HIPAA > §164.308(a)(6) | V.V3 caps Security Incident Procedures at Not Implemented |
| `contingency_plan_url` | URL or path | URL/file validator | Tracker > HIPAA > §164.308(a)(7) | V.V3 caps Contingency Plan at Not Implemented |

---

## 18. Audit & OCR / 3PAO surface

LOOP-V emits artifacts an OCR auditor or 3PAO can inspect in this
order:

1. **Catalog snapshot** (`data/hipaa-safeguards-catalog.json`) —
   proves the CSP's safeguard catalog is sourced from federally-
   published material with verbatim quote-anchored provenance.
2. **BAA inventory** (`out/baa-status-{system-id}-{date}.json` +
   `.docx`) — proves all inbound + outbound BAAs are tracked with
   §164.504(e)(2)(ii) checklist results.
3. **800-66 Rev 2 cross-walk**
   (`data/hipaa-800-66-crosswalk.json`) — proves the CSP's evidence
   maps to HIPAA safeguards via the NIST-published cross-walk; gaps
   are documented as POA&M items.
4. **OCR Audit Protocol response packet**
   (`out/ocr-audit-response-{audit-id}.zip`) — pre-populated response
   to every Established Performance Criterion in the OCR protocol.
5. **Breach incident records**
   (`out/breach-incident-{id}.json` + `.docx`) — per-incident 4-factor
   analysis, notification deadlines, evidence pointers, sign-off.
6. **HITRUST readiness scorecard**
   (`out/hitrust-readiness-{system-id}-{date}.docx` + `.xlsx`) — gap
   list for HITRUST CSF v11.2.0 Validated Assessment preparation.
7. **POA&M items** (in `out/poam.json` via LOOP-A.A1) — per safeguard
   gap; risk-scored via LOOP-B.B1.
8. **Tracker audit log** — every operator action on the HIPAA pages
   (catalog reviews, BAA uploads, addressable-spec documentation,
   incident triage, counsel sign-offs) captured with timestamp +
   officer ID.

The OCR auditor + 3PAO can verify each artifact's signature using
the public key in the system's authorization-package metadata. The
6-year retention per §164.316(b)(2)(i) is enforced by the tracker DB
backup + signed audit log.

---

## 19. Multi-cloud + cross-region heterogeneity handling

Different clouds expose different HIPAA-relevant primitives. LOOP-V's
emitter normalises them into a common shape:

| Normalised class | AWS native | GCP native | Azure native | k8s native |
|---|---|---|---|---|
| Encryption-at-rest (FIPS 140) | KMS CMK | Cloud KMS | Key Vault | k8s Secret + Sealed Secrets |
| Encryption-in-transit (FIPS TLS) | ACM + ALB | Cloud Load Balancing + Certificate Manager | Application Gateway + Key Vault Cert | Istio + TLS 1.3 |
| Audit logging | CloudTrail + S3 | Cloud Audit Logs + BigQuery | Activity Logs + Log Analytics | Audit subsystem |
| Access control | IAM + IAM Identity Center | IAM + BeyondCorp | Entra ID + RBAC | k8s RBAC + ABAC |
| Backup + DR | AWS Backup + S3 cross-region replication | Cloud Storage replication | Azure Backup + GRS | Velero |
| Asset inventory | Config + Resource Explorer | Asset Inventory | Resource Graph | LOOP-INV-S |
| Vulnerability scanning | Inspector + ECR scanning | Security Command Center | Defender for Cloud | Trivy / Grype |
| Physical safeguards | AWS data center attestations (SOC 2 / ISO 27001) | GCP data center attestations | Azure data center attestations | N/A (inherited) |

The normalised cross-walk envelope (V.V3) requires:

- `hipaa_citation` — e.g. `"§164.312(a)(2)(iv)"`.
- `nist_53_controls[]` — from 800-66 Rev 2 Appendix F.
- `csf_2_0_subcategories[]` — from 800-66 Rev 2 Appendix C.
- `fedramp_ksi_ids[]` — joined from FRMR catalog.
- `evidence_pointers[]` — array of references to underlying KSI
  outputs / inventory entries / tracker artifacts.
- `compliance_state` — per the rubric in §16.

REO Rule 5: no silent fallbacks. If a CSP's cloud has no native
primitive for a given normalised class, the field is `null` and a
`coverage:miss` diagnostic is emitted naming the missing primitive +
the affected impl spec.

---

## 20. Performance + scale

Expected scale on a representative CSP environment:

- Safeguard catalog: 21 standards × ~ 55 impl specs × ~ 4 evidence
  pointers per impl spec = ~ 220 evidence pointer rows. JSON size
  ~ 250 KB.
- BAA registry: typically 5-30 BAAs per CSP (mix of inbound +
  outbound). JSON size ~ 50-200 KB.
- 800-66 Rev 2 cross-walk: ~ 55 impl specs × ~ 8 800-53 controls
  per spec = ~ 440 mapping rows. JSON size ~ 500 KB.
- OCR Audit Protocol response packet: 78 Established Performance
  Criteria across Privacy / Security / Breach Notification + evidence
  attachments. Zip size ~ 5-20 MB depending on attachment count.
- Breach incident record: per-incident; typical 50-200 KB JSON +
  500 KB .docx.
- HITRUST CSF cross-walk: ~ 156 controls × 5 maturity tiers = ~ 780
  evaluation cells. JSON size ~ 400 KB. XLSX gap list ~ 200 KB.

V.V1 + V.V2 + V.V3 + V.V5 collectors run sequentially (with V.V3
depending on V.V1 and V.V5 depending on V.V1+V.V3). Total V.V1..V.V5
wall-clock time on a representative deployment (excluding V.V4 which
runs on incident events): ~ 12-18 min.

V.V4 incident execution: per-incident, ~ 30-60 sec for 4-factor
analysis + notice generation + clock setup; the actual notification
delivery is operator + counsel.

Memory: streamed JSON write; peak heap < 200 MB. The OCR audit
packet ZIP build streams attachments to avoid loading the full
attachment set in memory.

---

## 21. Source-quote re-affirmation (for OCR + 3PAO trust)

Every verbatim quote in this file came from a federally-published
source URL accessed 2026-06-08. The implementer of any slice MUST
re-fetch the cited URL at slice-implementation time and confirm the
quote is unchanged. If a quote has changed (e.g. HHS amends 45 CFR
Subpart C or D, NIST publishes 800-66 Rev 3), the implementer:

1. Captures the new verbatim text in
   `cloud-evidence/docs/sources/hipaa/<source>-YYYYMMDD.txt`.
2. Updates the relevant per-slice doc with the new quote.
3. Updates `docs/loops/LOOP-V-RISKS.md` with the change.
4. Updates §2 of this SPEC in the same commit.
5. Updates `CHANGELOG.md` noting the regulatory change.

This is the "authoritative-source drift" risk category (V-R4). The
RISKS register tracks it explicitly. The
`scripts/check-hipaa-source-drift.mjs` script runs daily in CI and
flags any source URL change.

---

## 22. Edge cases (additional, beyond §7 adversarial cases)

**E1.** CSP discovers a breach on Day N; the 4-factor analysis is
completed on Day N+15; counsel determines low probability of
compromise and "no notification required". V.V4 captures the
analysis + decision + counsel + operator sign-offs; the incident is
closed without notification BUT the analysis record is retained in
the tracker for 6 years per §164.316(b)(2)(i) and is part of any
OCR audit response.

**E2.** CSP discovers a breach on Day N. The 60-day BA-to-CE clock
starts Day N. The BA notifies the CE on Day N+45. The CE-to-individual
60-day clock starts Day N+45 (when the CE was deemed to discover the
breach per §164.404(a)(2)) — NOT Day N. V.V4 captures both clocks
with the correct start dates and surfaces both timers.

**E3.** Breach involves 501 individuals in California + 50 in Texas
+ 50 in Florida. Media notice fires for California (>500 in one
state). HHS contemporaneous notice fires (501+50+50 = 601 total >
500). V.V4 emits both notices; the media notice is California-only;
the HHS notice covers all 601.

**E4.** Subprocessor breach — the EHR normalizer vendor (subprocessor)
suffers a ransomware incident affecting PHI it processes on behalf
of ExampleCorp. The subprocessor notifies ExampleCorp (per the
outbound BAA flow-down). ExampleCorp then notifies CMS + VA (per the
inbound BAAs). V.V4 captures the full chain: subprocessor →
ExampleCorp → CE → individuals. Each step has its own clock.

**E5.** Cross-border PHI — a CMS dataset is processed in a CSP cloud
region outside the US. The BAA permits cross-border processing
(captured in V.V2 BAA data-location attestation). The breach
notification + 4-factor analysis follow the US-based clocks; no
additional non-US notification because HIPAA applies regardless of
processing location.

**E6.** Mixed PHI + state PII breach — single incident exposes both
PHI (HIPAA) and state PII (e.g. driver's license numbers under
California Civil Code §1798.82). V.V4 + LOOP-U coordinate via shared
incident-id; one consolidated incident-workspace; counsel reviews
the merged notice text; HIPAA + state-AG notifications fire on their
respective clocks.

**E7.** CSP changes BAA terms mid-cycle — CE requests revised BAA
language. V.V2 captures the BAA history (original + amendment +
re-execution date + new signatories). The §164.504(e)(2)(ii)
10-bullet checklist re-runs on the new BAA. Both BAA versions are
retained.

**E8.** OCR audit notice arrives. ExampleCorp's counsel + operator
open the OCR Audit Protocol response packet from V.V3, review each
Established Performance Criterion, supplement with any missing
narrative, and submit within the OCR response window. The
submission is logged in the tracker.

**E9.** HITRUST CSF v12.0 releases mid-cycle. V.V5's cross-walk is
invalidated; the operator updates the catalog reference; V.V5 re-runs;
the readiness scorecard re-emits against v12.0.

**E10.** Two slices are running concurrently in CI (e.g. V.V3 and
V.V5 both reading FedRAMP control evidence). The FRMR + KSI reader
has a shared cache layer; no race conditions in writes (each slice
writes to its own canonical-JSON output file).

**E11.** A breach affecting fewer than 500 individuals is discovered
in November of the calendar year. V.V4 logs the incident; the HHS
annual roll-up does not fire until March 1 of the following year;
the tracker UI shows the pending annual-rollup timer.

**E12.** Operator deletes a BAA record by accident. The tracker
audit log captures the deletion + operator ID + timestamp. The
record is soft-deleted (tombstoned) per the 6-year retention; OCR
audit can still retrieve it.

---

## 23. Cross-loop coordination — when does V cross-reference G.G2 / M.M4 / CIRCIA / SEC / U?

| Discovery scenario | V fires? | Related loops? | Cross-reference required? |
|---|---|---|---|
| Routine FedRAMP package build for a CSP that processes PHI | yes | A.A4 bundling | yes — V outputs in bundle |
| Routine FedRAMP package build for a CSP with no PHI | no | none | none |
| Incident detected (LOOP-G.G2 fires) — PHI is in scope | yes | G.G2 + M.M4 + CIRCIA (if criteria met) + SEC 8-K (if criteria met) + LOOP-U (if state PII also) | yes — shared incident-id; V.V4 fires HIPAA-specific clocks; G.G2 handles customer-facing comms; M.M4 handles federal-Privacy-Act notice; CIRCIA fires 72-hour CISA report; SEC fires 4-business-day 8-K if material |
| Incident detected — PHI NOT in scope | no | depends on data type | V does not fire; G.G2 + M.M4 + CIRCIA + SEC + U may fire per their own triggers |
| BAA renewal alert (V.V2 expiry timer fires) | yes | none | counsel + operator workflow |
| OCR audit notice arrives | yes | A.A4 (bundle assembly) | V.V3 OCR Audit Protocol response packet is the principal artifact |
| HITRUST CSF Validated Assessment in progress | yes | A.A4 | V.V5 readiness scorecard feeds the CSFA |
| FedRAMP control evidence regression (a KSI fails that V.V3 had relied on) | yes | LOOP-A coverage report | V.V3 re-runs; HIPAA cross-walk re-emits; gap appears as POA&M |
| CIRCIA Covered Cyber Incident criteria met | yes (if PHI in scope) | G.G2 CIRCIA extension | shared incident-id; CIRCIA 72-hour CISA fires in parallel with HIPAA 60-day clocks |
| SEC 8-K Item 1.05 materiality threshold met | yes (if PHI in scope) | G.G2 SEC extension | shared incident-id; SEC 4-business-day clock fires in parallel |
| State-AG notification required (CCPA, NY OAG, etc.) | yes | LOOP-U | shared incident-id; state-AG notification timing handled by LOOP-U |
| 21st Century Cures Act information-blocking complaint filed | partial | not implemented in LOOP-V | cross-reference only; operator + counsel handle externally |
| CMS Interoperability API audit | partial | not implemented in LOOP-V | cross-reference only; operator + counsel handle externally |

LOOP-V is the canonical HIPAA pipeline; other loops cross-reference
V for HIPAA-specific clocks + safeguard cross-walks. V does not
replace G.G2 + M.M4 + CIRCIA + SEC + U — it augments them with
HIPAA-specific requirements that those loops do not encode.

---

## 24. Final completion gate (loop-level)

LOOP-V is "done" when ALL of:

1. ✅ All five slices' tests pass (V.V1..V.V5).
2. ✅ All five slices' artifacts are in the submission bundle
   catalogue.
3. ✅ The first catalog snapshot has been emitted and verified.
4. ✅ The first BAA inventory has been emitted, all BAAs uploaded +
   §164.504(e)(2)(ii) checklist runs cleanly.
5. ✅ The first 800-66 Rev 2 cross-walk has been emitted; OCR Audit
   Protocol response packet has been built; counsel reviewed.
6. ✅ The breach-notification pipeline has been exercised end-to-end
   in a tabletop drill; clock arithmetic verified; counsel + operator
   sign-offs flow through the tracker.
7. ✅ The first HITRUST CSF v11.2.0 readiness scorecard has been
   emitted; CSFA reviewed.
8. ✅ STATUS.md, CHANGELOG.md, LOOP-V-SPEC.md (this file),
   LOOP-V-RISKS.md, and the five per-slice docs are all consistent.
9. ✅ The dependency-graph edge additions are in DEPENDENCY-GRAPH.md.
10. ✅ The glossary deltas are in GLOSSARY.md.
11. ✅ LOOP-Z.Z4 ISO/IEC 27018 PII Processor evidence references the
    V.V3 cross-walk (V blocks Z.Z4).
12. ✅ The FIFTH-PASS-AUDIT.md confirms no remaining LOOP-V gaps.

---

## 25. Resume-from-fresh-session checklist

A new Claude / human session opening LOOP-V must, in order:

1. Read this file (LOOP-V-SPEC.md) in full.
2. Read `cloud-evidence/CLAUDE.md` for the REO standard.
3. Read `cloud-evidence/docs/STATUS.md` to find the next slice (line
   "Overall → Next priority").
4. Read `cloud-evidence/docs/loops/LOOP-V-RISKS.md`.
5. Read the relevant `cloud-evidence/docs/slices/V/V.VN.md` for the
   slice in question — full per-slice context lives there.
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
7. Read `cloud-evidence/docs/IMPLEMENTATION-LOG-TEMPLATE.md`.
8. Execute the slice under the REO standard.
9. Follow the 7-step completion procedure (plus LOOP-V step 8 for
   counsel sign-off on V.V2 + V.V4) atomically with the final commit,
   then push to origin/main.

No prior conversation history is required. This file plus the cited
per-slice doc is sufficient.

---

## 26. Concluding notes

LOOP-V closes the HIPAA + BAA + Breach Notification + HITRUST
evidence gap surfaced by the FIFTH-PASS-AUDIT.md (2026-06-08). The
five slices together give FedPy / cloud-evidence:

- **V.V1** — a federally-sourced, signed HIPAA Security Rule
  safeguard catalog with verbatim 45 CFR §164 Subpart C standards +
  Required/Addressable flags + NIST 800-66 Rev 2 cross-walks to
  800-53 r5 + CSF 2.0.
- **V.V2** — a Business Associate Agreement tracker with inbound +
  outbound BAA registry, §164.504(e)(2)(ii) 10-bullet checklist,
  expiry alerts, signatory + data-scope capture, counsel workflow.
- **V.V3** — a NIST SP 800-66 Rev 2 cross-walk emitted as a signed
  JSON envelope plus an OCR Audit Protocol response packet pre-
  populated with FedRAMP-collected evidence pointers, ready for OCR
  audit response.
- **V.V4** — a Breach Notification pipeline implementing the §164.402
  4-factor probability-of-compromise analysis, the §164.404
  60-day individual-notice clock, the §164.406 media-notice clock
  for 500+-individual breaches, the §164.408 HHS-Secretary notice
  (contemporaneous or annual roll-up), the §164.410 BA-to-CE
  60-day clock, with counsel + operator sign-offs flowing through
  the tracker.
- **V.V5** — a HITRUST CSF v11.2.0 mapping that joins existing
  FedRAMP control evidence to HITRUST control IDs and emits a
  readiness scorecard for the CSP's HITRUST CSFA.

Every byte traces to a federally-published HIPAA / NIST / HHS-OCR
source or to operator-supplied configuration (BAA PDFs uploaded +
officer appointments + risk-analysis artifacts). Every emission is
operator-reviewed (and counsel-reviewed for V.V2 + V.V4) before
submission. Every artifact is part of the submission bundle the
3PAO or OCR auditor sees. The breach-notification pipeline integrates
with the unified incident-comms machinery (G.G2 + M.M4 + CIRCIA + SEC
+ LOOP-U) via shared incident-id so a single incident routes through
every applicable regime in parallel.

LOOP-V is positioned as a reusable scaffold: its safeguard catalog
(V.V1) and cross-walk emitter (V.V3) primitives are designed for
re-projection onto sector overlays (LOOP-Y healthcare overlay) and
international equivalence frameworks (LOOP-Z.Z4 ISO/IEC 27018 PII
processor evidence). The BAA tracker (V.V2) is a foundation any
contracts-management discipline can re-use. The breach-notification
pipeline (V.V4) is the canonical breach-clock engine for any future
regulatory regime that adds notification clocks (state PII, GDPR
Art. 33, ENISA NIS2, etc.).

Open the V.V1 per-slice doc to begin.
