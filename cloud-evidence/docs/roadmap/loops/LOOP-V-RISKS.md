# LOOP-V — Risks Register (Healthcare Overlay: HIPAA + 800-66 R2 + HITRUST)

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status=resolved` + resolution note.
> Severity: high = ship-blocking; med = should fix in-loop; low = file
> as follow-up.

> Authoritative companion to `docs/loops/LOOP-V-SPEC.md` and the
> per-slice docs at `docs/slices/V/V.V[1-5].md`. Read those for context
> before acting on any risk here.

> **CONDITIONAL GATE — HIPAA scope**: LOOP-V applies when the CSP is a
> **Business Associate** (BA) of a **Covered Entity** (CE) under HIPAA
> (45 CFR §160.103), OR a Subcontractor of a Business Associate (45 CFR
> §160.103 defining "business associate" to include any subcontractor
> that creates, receives, maintains, or transmits PHI on behalf of a
> business associate). When the operator-supplied `--hipaa-overlay`
> flag (or `CLOUD_EVIDENCE_HIPAA_OVERLAY` env var) is unset, NONE of the
> LOOP-V risks below activate. Every risk below carries an implicit
> "WHEN LOOP-V IS ACTIVE" precondition. The Jan 2025 HHS Security Rule
> NPRM does **not** absolve a BA whose existing BAA contracts already
> reference the 2013 Omnibus Rule text — see V-X11 (NPRM-vs-existing-
> BAA drift) and V-X19 (NPRM-finalization horizon).

> Last updated: 2026-06-07.

> Companion reading (cross-reference these registers when triaging a
> LOOP-V risk that interacts with another loop):
> - `LOOP-M-RISKS.md` — Privacy package (SORN, DPIA); LOOP-V.V4
>   ePHI tagging extends LOOP-M's data-classification model.
> - `LOOP-L-RISKS.md` — Customer Responsibility Matrix; LOOP-V.V1
>   BAA registry overlays the LOOP-L CRM.
> - `LOOP-G-RISKS.md` — Incident communications; LOOP-V.V3
>   breach-notification emitter extends G.G2 incident workflow.
> - `LOOP-U-RISKS.md` — Other privacy frameworks (GLBA / CCPA / GDPR);
>   the V-X28 cross-framework-confusion risk pairs with U.U*.
> - `LOOP-B-RISKS.md` — POA&M emitter; LOOP-V uses POA&M cascade for
>   the 800-66 Rev 2 "risk-management process" remediation tracking.
> - `LOOP-N-RISKS.md` — Threat modeling; HITRUST CSF v11.x scoping
>   leverages N.N2 threat-model artefacts.
> - `docs/CIRCIA-WORKFLOW.md` — CIRCIA harmonization (a HIPAA breach
>   that is also a CIRCIA-covered cyber-incident triggers BOTH clocks).

---

## Table of Contents

- [Cross-cutting risks (apply to ALL slices in LOOP-V)](#cross-cutting-risks-apply-to-all-slices-in-loop-v)
  - BAA registry + scope (V-X1..V-X6)
  - 4-factor breach risk assessment (V-X7..V-X10)
  - 60-day clock arithmetic + ≥500-individual escalations (V-X11..V-X15)
  - 800-66 Rev 2 vs Rev 1 crosswalk drift (V-X16..V-X19)
  - HITRUST assessor scope + i1/r2 assessment type (V-X20..V-X23)
  - OCR audit / enforcement readiness (V-X24..V-X27)
  - PHI inventory false-negative / false-positive (V-X28..V-X31)
  - BA-to-CE notification + breach-letter content (V-X32..V-X35)
  - 21st Century Cures Information Blocking exposure (V-X36..V-X38)
  - REO + cross-loop infrastructure risks (V-X39..V-X44)
- [Per-slice risks](#per-slice-risks)
  - V.V1 — BAA Registry + CE→CSP responsibility overlay
  - V.V2 — §164.308 administrative-safeguard evidence pack
  - V.V3 — §164.400-§164.414 breach-notification emitter
  - V.V4 — ePHI data-class auto-tagger overlay
  - V.V5 — NPRM-finalization-readiness pack
- [External dependencies that may change](#external-dependencies-that-may-change)
- [Resume-from-fresh-session checklist](#resume-from-fresh-session-checklist)

---

## Cross-cutting risks (apply to ALL slices in LOOP-V)

### V-X1 — BAA registry drift: contracts present in legal but absent from the tracker

- **Description**: A Business Associate Agreement (BAA) is the contract
  required by 45 CFR §164.504(e) between a Covered Entity and a Business
  Associate. Real-world CSPs accumulate BAAs across dozens of CE
  customers; the legal team holds the executed PDFs in a contract
  management system (CMS — DocuSign CLM / Ironclad / Conga / SharePoint),
  but the FedPy tracker only knows what was loaded into
  `baa-registry.yaml`. When legal executes a new BAA and forgets to
  notify ops, LOOP-V.V1 silently under-counts the BA relationships, the
  CRM overlay is incomplete, and a breach notification might miss a
  contractually-required CE notification path.
- **Severity**: high (legal + contractual + breach-notification gap).
- **Mitigation**: V.V1's `core/baa-registry.ts` requires a **dual-source
  reconciliation**: (a) operator-curated `baa-registry.yaml` AND (b) a
  CMS-export CSV/JSON dropped quarterly under
  `inputs/cms-baa-export-YYYYQN.json`. The reconciler emits a
  `REQUIRES-OPERATOR-INPUT: baa-drift-<ce_id>` diagnostic for every CE
  present in CMS but absent from `baa-registry.yaml` (and vice versa).
  Tracker UI surfaces "BAAs in registry vs CMS" delta count on the
  LOOP-V dashboard banner. A quarterly cron emits a reconciliation
  report (`out/baa-reconciliation-YYYYQN.json`). CHANGELOG entry per
  reconciliation run records the delta.
- **Owner**: LOOP-V.V1 implementer + operator legal-ops liaison.
- **Status**: open.
- **References**: 45 CFR §164.504(e); LOOP-L-RISKS.md L-X3 (CRM
  drift); LOOP-V-SPEC.md §3.

### V-X2 — BAA contract-language drift: pre-Omnibus vs post-Omnibus templates coexisting

- **Description**: The HHS HITECH Omnibus Final Rule (Jan 25 2013;
  effective Sept 23 2013) materially revised the required BAA content
  (45 CFR §164.504(e)(2)). BAAs executed before Sept 23 2013 may NOT
  contain Omnibus-required clauses (downstream-subcontractor flow-down,
  individual access rights, breach notification to CE within statutory
  deadlines). A CSP with a 12-year-old BAA still in effect may be
  partially out of compliance even though the contract exists. LOOP-V.V1
  must distinguish pre/post-Omnibus templates so the operator can
  triage which CEs need a BAA amendment.
- **Severity**: high (regulatory compliance gap).
- **Mitigation**: V.V1's BAA-registry schema includes `template_era:
  enum('pre-omnibus-2013', 'post-omnibus-2013', 'post-2025-nprm',
  'unknown')` and `last_amended_at: date`; the reconciler flags
  `pre-omnibus-2013` records with `requires_amendment: true`; the
  tracker UI emits an "Amendment required" badge. Operator runbook
  documents the HHS Sample BAA Provisions (see V-X16 sources). Future
  V.V1 enhancement could auto-classify by scanning BAA text for known
  Omnibus phrases ("downstream subcontractor", "individual access").
- **Owner**: LOOP-V.V1 + operator legal counsel.
- **Status**: open.
- **References**: HHS Omnibus Final Rule (78 FR 5566, 2013-01-25); HHS
  Sample BAA Provisions (https://www.hhs.gov/hipaa/for-professionals/
  covered-entities/sample-business-associate-agreement-provisions/
  index.html, accessed 2026-06-07).

### V-X3 — Subcontractor BA flow-down (downstream BAAs for cloud sub-processors)

- **Description**: Under 45 CFR §164.308(b)(2) and §164.502(e)(1)(ii),
  a Business Associate must obtain "satisfactory assurances" (i.e.
  a downstream BAA) from any subcontractor that creates, receives,
  maintains, or transmits PHI on behalf of the BA. CSPs using
  sub-processors (analytics vendors, AI/ML providers, log-aggregation
  SaaS) for ePHI-touching workflows must have downstream BAAs with
  every such subcontractor. A missing downstream BAA exposes the CSP
  to direct HHS-OCR enforcement under HITECH §13408.
- **Severity**: high (direct enforcement exposure).
- **Mitigation**: V.V1's BAA registry includes a `downstream_baas[]`
  array per CE relationship, populated by joining against
  `core/subprocessors-sheet.ts` (LOOP-W cross-reference). For every
  subprocessor flagged as ePHI-touching (operator-tagged via
  `subprocessors-sheet ephi_touching: bool` column), V.V1 asserts a
  matching downstream-BAA record; missing records emit
  `REQUIRES-OPERATOR-INPUT: missing-downstream-baa-<subprocessor>`.
  Cross-loop test integrates with LOOP-W subprocessor list.
- **Owner**: LOOP-V.V1 + LOOP-W subprocessor-list owner.
- **Status**: open.
- **References**: 45 CFR §164.308(b)(2); HITECH Act §13408 (Pub. L.
  111-5, 42 U.S.C. §17938).

### V-X4 — Hybrid entity / Organized Health Care Arrangement (OHCA) scoping ambiguity

- **Description**: A "hybrid entity" (45 CFR §164.103) is a single legal
  entity whose business activities include both covered and
  non-covered functions; only the "health care component" is subject
  to HIPAA. An OHCA (45 CFR §160.103) is a group of legally separate
  CEs that share PHI for joint operations. CSPs serving hybrid-entity
  or OHCA customers must scope the BAA + breach notification flows
  per-component, not per-legal-entity. A naive registry that treats
  one CE = one legal entity will misroute breach notifications
  (notifying the wrong component CIO or compliance officer).
- **Severity**: med.
- **Mitigation**: V.V1's BAA registry models `ce_organizational_form:
  enum('single-ce', 'hybrid-entity', 'ohca-member', 'affiliated-ce')`
  + per-component notification routing (`notification_routing[]`
  with component-level contacts). Runbook documents the hybrid-entity
  notification routing pattern; operator triage required at BAA
  intake. Tracker UI surfaces the organizational form on the BAA
  detail page.
- **Owner**: LOOP-V.V1.
- **Status**: open.
- **References**: 45 CFR §164.103 (hybrid entity); 45 CFR §160.103
  (OHCA definition).

### V-X5 — Conduit Exception misapplied (BA vs conduit distinction)

- **Description**: A "conduit" (e.g. US Postal Service, ISPs providing
  pure connectivity) that only transmits PHI without storage or
  meaningful access is NOT a BA under HHS guidance (78 FR 5571, 2013;
  HHS FAQ Aug 2013). Some CSPs incorrectly self-classify as conduits
  to avoid the BAA burden; HHS has clarified that cloud-storage and
  cloud-processing providers — even if encryption keys are
  customer-held — are BAs, not conduits (HHS Cloud Computing
  Guidance 2016). A wrong conduit classification → no BAA → direct
  enforcement exposure.
- **Severity**: high.
- **Mitigation**: V.V1's BAA-intake wizard explicitly asks the
  operator-side question "Does this CSP service store PHI for more
  than transient transmission?"; "yes" forces BAA path. Runbook
  cites the HHS 2016 Cloud Computing Guidance verbatim. LOOP-V is
  designed for CSPs that ARE BAs; if the operator believes they are
  a conduit, LOOP-V emits a `coverage:skipped-conduit-claim`
  diagnostic + requires operator narrative + flags for legal review.
- **Owner**: LOOP-V.V1 + operator legal counsel.
- **Status**: open.
- **References**: HHS Cloud Computing Guidance (Oct 2016, updated;
  https://www.hhs.gov/hipaa/for-professionals/special-topics/
  health-information-technology/cloud-computing/index.html,
  accessed 2026-06-07).

### V-X6 — BAA termination handling (PHI return-or-destruction obligations)

- **Description**: 45 CFR §164.504(e)(2)(ii)(I) requires the BA to
  return or destroy all PHI "at termination of the contract", or — if
  return/destruction is infeasible — to extend HIPAA protections to
  the retained PHI indefinitely. A terminated BAA without a documented
  PHI disposition record is a downstream-enforcement risk if a breach
  later occurs in the retained data.
- **Severity**: med.
- **Mitigation**: V.V1's BAA registry tracks `termination_status:
  enum('active', 'expired-phi-returned', 'expired-phi-destroyed',
  'expired-phi-retained-with-protections')` and `disposition_evidence:
  text` (URL to certificate of destruction or operator narrative).
  CHANGELOG entry per termination. Annual reconciliation report
  surfaces terminated BAAs lacking disposition evidence.
- **Owner**: LOOP-V.V1.
- **Status**: open.
- **References**: 45 CFR §164.504(e)(2)(ii)(I).

### V-X7 — 4-factor breach risk assessment misclassification: "low probability" overuse

- **Description**: 45 CFR §164.402 ("Breach" definition) requires
  notification UNLESS the BA/CE demonstrates "low probability that the
  protected health information has been compromised" through a
  4-factor risk assessment: (1) nature + extent of PHI; (2) unauthorized
  recipient; (3) actual acquisition/viewing; (4) extent of risk
  mitigation. Empirical pattern: BAs over-classify incidents as
  "low probability" to avoid notification overhead, which HHS-OCR has
  publicly criticized (multiple enforcement actions cite mis-classified
  assessments — e.g. CHSPSC 2020 settlement $2.3M). A LOOP-V emitter
  that lets the operator click "low probability" without documenting
  the 4-factor analysis perpetuates the pattern.
- **Severity**: high (regulatory + enforcement risk).
- **Mitigation**: V.V3's `core/breach-risk-assessment.ts` REQUIRES the
  operator to enter a structured 4-factor JSON object: each factor
  has a `score: enum('low','med','high')` + `narrative: text` (min
  150 chars) + optional `evidence_url: text`. The renderer refuses to
  emit "low probability" UNLESS all four factors score `low` AND
  every narrative is non-empty AND the operator has digitally signed
  the assessment via WebAuthn/PIV. Tracker UI surfaces a 4-factor
  matrix view + historical statistics ("Your last 10 assessments:
  N classified as low, M as breach"); excessive low-probability
  rate triggers an `over-classification-warning` flag for legal
  review. Cross-references HHS OCR Resolution Agreements as
  comparable benchmarks (`data/ocr-resolution-agreements.json`).
- **Owner**: LOOP-V.V3 + operator privacy officer.
- **Status**: open.
- **References**: 45 CFR §164.402; HHS OCR Resolution Agreements
  (https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/
  agreements/index.html, accessed 2026-06-07); CHSPSC LLC Resolution
  Agreement (HHS, Feb 2020, $2.3M, 6.1M individuals).

### V-X8 — 4-factor assessment evidence tampering after the fact

- **Description**: The 4-factor risk assessment is the operator's
  defense in an HHS-OCR audit. If the operator can edit a past
  assessment to retroactively justify a non-notification decision,
  the audit defense collapses (HHS expects tamper-evident records).
  A simple "edit" button on the tracker would create the risk.
- **Severity**: high.
- **Mitigation**: V.V3's `breach_risk_assessments` table is
  **append-only**: each save creates a new immutable row with
  `version_seq: int` + `prior_version_hash: text` (forms a hash chain
  per incident). UI shows the full version history; PDF emit
  embeds all versions. Edits are not destructive; the "Edit" action
  creates a new version with operator's reason for change in
  `change_reason: text`. Ed25519 signature on each version. Cross-
  references LOOP-B.B1 audit-log pattern. CHANGELOG entry for V.V3
  cites the append-only contract.
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: 45 CFR §164.312(c)(1) (integrity controls);
  45 CFR §164.530(j) (documentation retention 6 years).

### V-X9 — Encryption safe-harbor misapplication (claiming safe-harbor without meeting NIST SP 800-111 / 800-52 requirements)

- **Description**: HHS guidance (74 FR 19006, 2009; updated 2013) creates
  a "safe harbor" — if PHI is encrypted per HHS-specified standards
  (NIST SP 800-111 for at-rest; NIST SP 800-52 for in-transit; FIPS
  140-2 validated modules), then unauthorized disclosure is NOT a
  breach. Operators sometimes claim safe-harbor for data that is only
  TLS-encrypted in transit but unencrypted at rest, or data encrypted
  with non-FIPS-validated algorithms. A wrong safe-harbor claim
  becomes a willful-neglect finding.
- **Severity**: high.
- **Mitigation**: V.V3's 4-factor renderer specifically asks "Was the
  PHI encrypted per HHS standards (NIST SP 800-111 / 800-52, FIPS
  140-2)?"; "yes" requires the operator to attach evidence (link to
  cloud-provider FIPS 140-2 certificate, encryption-mode
  documentation). Cross-references LOOP-R PQC / FIPS records.
  V.V3 emits a safe-harbor-claim warning if the operator selects
  safe-harbor without the supporting evidence chain. Runbook
  documents the HHS guidance verbatim.
- **Owner**: LOOP-V.V3 + LOOP-R cryptography evidence owner.
- **Status**: open.
- **References**: HHS Guidance Specifying Technologies and
  Methodologies (74 FR 19006, 2009-04-27; 78 FR 5566 §IV.A);
  https://www.hhs.gov/hipaa/for-professionals/breach-notification/
  guidance/index.html, accessed 2026-06-07.

### V-X10 — Incident-classification drift between LOOP-G.G2 + LOOP-V.V3 + CIRCIA

- **Description**: A single cyber-incident may trigger BOTH the HIPAA
  breach-notification clock (LOOP-V.V3, 60 days to individuals + 60 days
  to HHS) AND the CIRCIA 72-hour cyber-incident reporting clock
  (CIRCIA-WORKFLOW.md) AND the FedRAMP IR-6 incident-comms clock
  (LOOP-G.G2). Incident classifications can drift between the three
  emitters; an incident classified as "breach" in V.V3 but
  "non-reportable" in G.G2 is a contradiction that an HHS audit will
  surface.
- **Severity**: high (multi-clock consistency).
- **Mitigation**: V.V3's `incidents` table FK-joins to G.G2's
  `incident_records.incident_id`; the breach-classification
  decision is a property OF the incident, not a separate entity.
  V.V3's renderer asserts G.G2 incident metadata is consistent
  (e.g. G.G2 says "ransomware" → V.V3 risk assessment factor 4
  must mention encryption + exfiltration). Cross-loop integration
  test pins this. Runbook documents the dual-classification flow.
- **Owner**: LOOP-V.V3 + LOOP-G.G2 + CIRCIA-extension owner.
- **Status**: open.
- **References**: 45 CFR §164.402; CIRCIA Final Rule (6 CFR Part 226);
  CIRCIA-WORKFLOW.md; LOOP-G-RISKS.md.

### V-X11 — 60-day clock miss for ≥500 individuals: missed media notice + missed HHS contemporaneous notice

- **Description**: Under 45 CFR §164.406 (media notice) and §164.408
  (notification to HHS), when a breach affects ≥500 residents of a
  state/jurisdiction, the CE must notify "prominent media outlets" of
  that area without unreasonable delay (and in no case later than
  60 calendar days). HHS notification at ≥500 individuals is
  **contemporaneous** (not annual). A missed clock = additional civil
  monetary penalties + featured listing on the HHS-OCR "Wall of Shame"
  breach portal. Pattern: an operator misreads "60 days for
  individuals" as also applying to media + HHS in the ≥500 case;
  in fact, the ≥500 contemporaneous-HHS rule overlays.
- **Severity**: high (statutory; HHS Wall of Shame visibility).
- **Mitigation**: V.V3's `core/breach-clock.ts` evaluates THREE
  clocks per incident: (a) individual notification (60 days from
  discovery, always); (b) media notice (60 days, ONLY if ≥500
  residents in a single state/jurisdiction); (c) HHS notification
  (60 days for ≥500 individuals; otherwise annual aggregate by 60
  days after end of calendar year). The renderer surfaces all three
  clocks side-by-side on the UI countdown + bundles three .docx
  templates per qualifying incident. Adversarial test pins the
  503-individual case (just over threshold) + a multi-jurisdiction
  case (single incident, two states each ≥500). HHS Wall of Shame
  download (`data/hhs-breach-portal-snapshot-YYYYMMDD.json`) read
  by V.V3 for historical baseline.
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: 45 CFR §164.406; 45 CFR §164.408(b); HHS OCR
  Breach Portal (https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf,
  accessed 2026-06-07).

### V-X12 — 60-day clock anchoring: "discovery" date misidentification

- **Description**: 45 CFR §164.404(b) anchors the 60-day individual
  clock at "the date a breach is discovered". §164.404(a)(2)
  defines "discovered" as the day a breach is "known, or by
  exercising reasonable diligence would have been known". For BAs,
  the BA must notify the CE without unreasonable delay (max 60 days
  per §164.410(b)). The discovery anchor is contested in audit:
  was it when the SOC analyst opened the ticket? When the CISO
  was briefed? When the forensics team confirmed PHI exposure? A
  late anchor = late notification = HHS findings.
- **Severity**: high.
- **Mitigation**: V.V3's `incidents` table records FOUR anchor
  timestamps: (a) `system_detection_at` (SOC/SIEM alert),
  (b) `analyst_triage_at` (first human review), (c) `officer_briefed_at`
  (CISO/Privacy Officer notification), (d) `discovery_acknowledged_at`
  (formal breach-discovery declaration). The clock starts at the
  EARLIEST of (a), (b), or "would have known by reasonable
  diligence" (operator must justify if not (a)). UI shows all four;
  .docx renders the timeline. Cross-references LOOP-G.G2 incident
  timeline. Runbook cites HHS Wall of Shame enforcement examples
  where late anchors were penalized.
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: 45 CFR §164.404(a)(2), (b); 45 CFR §164.410(b).

### V-X13 — Weekend/holiday discovery boundary cases (60 calendar days, not business days)

- **Description**: Unlike FAR §889 1-business-day clock (LOOP-W) or
  CIRCIA 72-hour, the HIPAA 60-day clock is **calendar days** (per
  §164.404(b)). A breach discovered Dec 31 must be notified by
  March 1 (or Feb 29 in leap years) — weekends and holidays count.
  However, the rule requires notification "without unreasonable
  delay" — a CE waiting until day 60 may be cited for unreasonable
  delay if remediation was complete on day 5.
- **Severity**: med (clock math is simpler but "unreasonable delay"
  test still exposes risk).
- **Mitigation**: V.V3's clock is calendar-day arithmetic (no
  business-day exclusions). The renderer adds an
  `unreasonable_delay_rationale: text` field that the operator must
  populate IF `notified_at - discovered_at > 30 days` (a heuristic
  threshold; HHS has cited delays of 30+ days in enforcement
  actions). Adversarial test pins Feb 29 leap-year boundary +
  end-of-year December discovery. Cross-loop with LOOP-W (FAR §889
  clock uses business days; do not conflate).
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: 45 CFR §164.404(b); HHS guidance on "unreasonable
  delay" (Resolution Agreement narratives).

### V-X14 — State breach-notification law overlay (50+ state laws + DC + territories)

- **Description**: HIPAA preempts state laws that are LESS stringent
  but NOT state laws that are MORE stringent. All 50 states + DC +
  PR + USVI + Guam have data-breach notification laws; many require
  notification to state Attorneys General + state-specific clocks
  (CA, NY, TX, IL have shorter clocks for some categories). A CSP
  operating nationally faces 50+ overlapping state clocks in
  addition to the HIPAA 60-day clock. Missing a state AG notification
  is a state-law enforcement risk (state AGs have HIPAA enforcement
  authority under HITECH §13410(e)).
- **Severity**: high (state AG enforcement; cumulative penalty
  exposure).
- **Mitigation**: V.V3's `data/state-breach-laws.json` registry
  enumerates per-state requirements: clock duration, AG-notification
  threshold (some states notify AG only when ≥500 residents
  affected; others at any breach), AG email/portal URL, additional
  content requirements. The renderer iterates affected-residents-
  per-state and emits per-state notification packets. Runbook
  documents the per-state intake. Cross-references LOOP-U state
  privacy law overlap (CCPA, NY SHIELD). CHANGELOG entry per
  state-law registry update. Quarterly refresh of registry against
  NAAG / state-AG sources.
- **Owner**: LOOP-V.V3 + LOOP-U operator.
- **Status**: open.
- **References**: HITECH Act §13410(e) (Pub. L. 111-5); NAAG
  state-breach-notification compendium
  (https://www.naag.org/issues/cybercrime/, accessed 2026-06-07);
  CA Civil Code §1798.82; NY GBL §899-aa.

### V-X15 — HHS Annual Breach Submission (<500 individuals) cadence miss

- **Description**: For breaches affecting <500 individuals, §164.408(c)
  requires submission to HHS no later than 60 days after the end of
  the calendar year in which the breach was discovered. So breaches
  discovered in CY2026 must be submitted by March 1, 2027. CSPs
  forgetting the annual cadence accumulate unreported breaches
  visible in subsequent OCR audits.
- **Severity**: med.
- **Mitigation**: V.V3's tracker runs an annual cron that emits
  `out/hhs-annual-breach-submission-CYYYYY.json` + `.docx` on or
  before March 1; the renderer aggregates all `<500` breaches with
  `discovered_at` in the prior CY and `hhs_individual_notice_sent
  IS NULL`; the operator submits via HHS OCR breach portal manually
  (REO Rule 4 — no auto-submit). Tracker UI banner reminds at
  T-90/T-30/T-7 days. CHANGELOG entry per annual submission.
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: 45 CFR §164.408(c); HHS OCR Breach Portal
  submission form (https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf,
  accessed 2026-06-07).

### V-X16 — 800-66 Rev 2 vs Rev 1 control crosswalk drift

- **Description**: NIST SP 800-66 Rev 2 (Feb 2024) — "Implementing the
  HIPAA Security Rule: A Cybersecurity Resource Guide" — replaces
  Rev 1 (Oct 2008). Rev 2 restructures the §164.308/.310/.312
  guidance into a risk-management framework aligned with NIST RMF +
  CSF v2.0 + 800-53 Rev 5. Rev 2's structure differs MATERIALLY from
  Rev 1; a CSP migrating from a Rev-1-based control inventory to
  Rev 2 must rebuild the crosswalk. LOOP-V.V2 must ship the Rev 2
  crosswalk authoritatively; mis-mapped Rev 1 evidence to Rev 2
  controls creates false attestations.
- **Severity**: high (control-evidence correctness).
- **Mitigation**: V.V2's `data/hipaa-800-66-rev2.json` carries the
  authoritative Rev 2 → 800-53 Rev 5 mapping per the NIST SP 800-66
  Rev 2 Appendix F crosswalk; mapping rows record
  `crosswalk_source: 'nist-800-66r2-appendix-f'` + `confidence: high`.
  Rev 1 legacy mappings (if any) are retained in
  `data/hipaa-800-66-rev1-legacy.json` for historical evidence but
  flagged `deprecated: true`. V.V2 refuses to emit a Rev-1-only
  attestation past 2026-12-31 (operator-configurable sunset).
  CHANGELOG entry per crosswalk revision. Cross-references LOOP-E
  control-evidence collectors.
- **Owner**: LOOP-V.V2.
- **Status**: open.
- **References**: NIST SP 800-66 Rev 2 (Feb 2024;
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf,
  accessed 2026-06-07); NIST SP 800-66 Rev 1 (Oct 2008, withdrawn);
  NIST SP 800-53 Rev 5 (Dec 2020 + errata 2023-12).

### V-X17 — 800-66 Rev 2 vs FedRAMP 20x KSI overlap (double-counted evidence)

- **Description**: Many 800-66 Rev 2 control implementations overlap
  with FedRAMP 20x KSIs (e.g. 800-66 R2's §164.312(a)(1) Access
  Control overlaps with IAM-MFA, IAM-AAM, IAM-APM KSIs). If V.V2
  separately emits HIPAA-specific evidence without referencing the
  FedRAMP 20x KSI evidence already collected, the operator faces
  duplicated effort + potentially inconsistent narratives ("strong"
  in one place, "needs improvement" in another).
- **Severity**: med.
- **Mitigation**: V.V2's emit references FedRAMP 20x KSI evidence
  via the `ksi_evidence_link[]` field per HIPAA safeguard;
  consistency check asserts the HIPAA narrative status (`implemented`
  / `partial` / `gap`) matches the KSI evidence status. Tracker UI
  surfaces "Inherited from FedRAMP KSI" badges. CHANGELOG entry per
  V.V2 cites the inheritance map. Future enhancement could automate
  the consistency check.
- **Owner**: LOOP-V.V2 + LOOP-E KSI evidence owner.
- **Status**: open.
- **References**: NIST SP 800-66 Rev 2 Appendix F crosswalk;
  FedRAMP 20x KSI manifest.

### V-X18 — 800-66 Rev 2 IPD vs Final divergence

- **Description**: NIST SP 800-66 Rev 2 went through Initial Public
  Draft (IPD, Jul 2022) → Final (Feb 2024). Pre-Final implementations
  may have used IPD field names + structure that don't match Final.
  Implementing sessions should pin to the Final (Feb 2024) document;
  an IPD-vintage `data/hipaa-800-66-rev2.json` would carry stale
  rows.
- **Severity**: low (catchable in code review).
- **Mitigation**: V.V2's `data/hipaa-800-66-rev2.json` records
  `source_doc_sha256` of the Final PDF; extractor script asserts
  hash matches the known-Final hash (Feb 2024 release); IPD-vintage
  data file refuses to load. CHANGELOG entry pins the source URL +
  hash. Runbook documents the IPD-vs-Final distinction.
- **Owner**: LOOP-V.V2.
- **Status**: open.
- **References**: NIST SP 800-66 Rev 2 IPD (Jul 2022; deprecated);
  NIST SP 800-66 Rev 2 Final (Feb 2024).

### V-X19 — Future 800-66 Rev 3 / NPRM-aligned revision horizon

- **Description**: The Jan 6 2025 HHS HIPAA Security Rule NPRM (90 FR
  898) significantly revises §164.308/.310/.312 — making encryption,
  MFA, vulnerability scanning, and penetration testing mandatory.
  NIST will likely revise 800-66 Rev 2 to align with the NPRM upon
  finalization (Final Rule expected 2026-late or 2027). A LOOP-V.V2
  pinned to 800-66 Rev 2 (Feb 2024) will drift the moment the NPRM
  finalizes.
- **Severity**: med (planned drift; not silent).
- **Mitigation**: V.V2's catalog version constant
  `nist_800_66_version = "rev2-2024-02"` is operator-overridable in
  `hipaa-overlay-config.yaml`. LOOP-V.V5 (NPRM-readiness pack)
  carries a forward-looking gap-analysis emitter that compares
  current LOOP-V.V2 evidence against NPRM-proposed requirements;
  upon NPRM finalization, the implementer bumps the constant +
  re-runs the crosswalk extractor. Runbook documents the NPRM
  finalization watch (check
  https://www.hhs.gov/hipaa/for-professionals/security/index.html
  quarterly).
- **Owner**: LOOP-V.V2 + LOOP-V.V5.
- **Status**: open.
- **References**: HHS NPRM (90 FR 898, 2025-01-06,
  https://www.federalregister.gov/documents/2025/01/06/2024-30983/
  hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-
  protected-health-information, accessed 2026-06-07).

### V-X20 — HITRUST assessor scope mismatch (i1 vs r2 vs e1 assessment types)

- **Description**: HITRUST CSF offers four assessment types: e1
  (entry-level, single-page), i1 (implemented 1-year), r2 (risk-based
  2-year, the gold standard), and bC (baseline cyber). The r2 is what
  most enterprise customers expect. An operator selecting i1 because
  it's cheaper may surprise CE customers who expect r2. LOOP-V (which
  optionally integrates HITRUST evidence) must surface the
  assessment type so the operator + CE customer alignment is
  explicit.
- **Severity**: med (commercial + audit-expectation).
- **Mitigation**: V.V2's HITRUST-evidence overlay records
  `hitrust_assessment_type: enum('e1', 'i1', 'r2', 'bC')` +
  `hitrust_assessment_date: date` + `hitrust_external_assessor:
  text` + `hitrust_certification_id: text` + `hitrust_certification_
  expires_at: date`; tracker UI surfaces all four fields. V.V2
  refuses to mark a control "HITRUST-attested" UNLESS the assessment
  type ≥ i1 (e1 is too narrow; bC is too cyber-focused for HIPAA
  scope). Runbook documents the assessment-type matrix.
- **Owner**: LOOP-V.V2.
- **Status**: open.
- **References**: HITRUST CSF v11.x (https://hitrustalliance.net/
  product-tool/hitrust-csf/, accessed 2026-06-07); HITRUST
  assessment-types overview (https://hitrustalliance.net/
  assessments/, accessed 2026-06-07).

### V-X21 — HITRUST CSF v11.x version drift

- **Description**: HITRUST CSF releases minor versions roughly annually
  (v11.0, v11.1, v11.2, ...). A LOOP-V emitter pinned to v11.0 may
  drift over time. Unlike 800-66 (which moves slowly), HITRUST CSF
  moves quickly; a multi-year-old CSF version is increasingly stale.
- **Severity**: med.
- **Mitigation**: V.V2's `data/hitrust-csf-version.json` carries
  `csf_version: "11.x.y"` + `csf_published_at: date`; warns operator
  when version > 18 months old. CHANGELOG entry per version bump.
  Cross-reference to HITRUST published changelogs.
- **Owner**: LOOP-V.V2.
- **Status**: open.
- **References**: HITRUST CSF release notes (member-only portal;
  operator-supplied evidence).

### V-X22 — HITRUST → 800-66 / FedRAMP crosswalk inaccuracy

- **Description**: HITRUST CSF maps controls to 30+ authoritative
  sources (HIPAA, ISO 27001, NIST 800-53, PCI-DSS, COBIT, CMMC,
  etc.). The mapping is HITRUST-curated and considered authoritative
  for member organizations but is not always 1:1 with the underlying
  standards. A LOOP-V.V2 emitter that reuses HITRUST mappings without
  validation may carry inaccuracies into the HIPAA-specific
  attestation.
- **Severity**: med.
- **Mitigation**: V.V2's HITRUST crosswalk records
  `mapping_source: 'hitrust-csf-vNN.x'` + `mapping_confidence:
  enum('high','medium','low')` per row; rows with `low` confidence
  are flagged in the UI for operator review. Future enhancement: a
  reconciliation report comparing HITRUST mappings against the
  NIST-authoritative crosswalk in `data/hipaa-800-66-rev2.json`.
- **Owner**: LOOP-V.V2.
- **Status**: open.
- **References**: HITRUST CSF cross-references portal (member-only).

### V-X23 — HITRUST credential revocation / suspension affecting LOOP-V evidence chain

- **Description**: HITRUST certifications can be suspended or revoked
  (e.g. for material misstatements, post-certification breaches). A
  CSP that holds a HITRUST i1/r2 certification, suffers a breach,
  and loses the certification mid-cycle has stale LOOP-V.V2 evidence
  citing the revoked certification ID.
- **Severity**: low (low likelihood but high impact if it occurs).
- **Mitigation**: V.V2's HITRUST evidence record carries
  `certification_status: enum('active','suspended','revoked',
  'expired')`; an operator-driven status change triggers a
  cascade (V.V2 emits an updated attestation pack; LOOP-S DFARS
  cross-link may also need refresh). Tracker UI surfaces status
  changes prominently. Runbook documents the revocation flow.
- **Owner**: LOOP-V.V2.
- **Status**: open.
- **References**: HITRUST Assurance Program Requirements (member-only).

### V-X24 — OCR audit unpreparedness: no audit-evidence package ready

- **Description**: HHS-OCR conducts both proactive audits (e.g. the
  2016 Phase 2 audit; the audit program is ongoing) and reactive
  investigations (post-breach). The OCR Audit Protocol enumerates
  specific evidence categories (policies, procedures, training
  records, risk-assessment documentation, BAA inventories). A CSP
  that has scattered, ad-hoc evidence (not bundled) faces a 30-day
  document-production deadline and frequently misses pieces.
- **Severity**: high (audit defense).
- **Mitigation**: V.V2's `out/hipaa-ocr-audit-package-YYYYMMDD.zip`
  bundle includes ALL OCR-Audit-Protocol-categorized evidence: BAA
  inventory (LOOP-V.V1), Security Rule administrative-safeguard
  evidence (V.V2), Breach Notification Rule incident history (V.V3),
  ePHI inventory (V.V4), workforce training records (operator-
  supplied), risk-assessment documents (V.V2 + V.V5), sanctions
  evidence (HR system, operator-supplied). The bundler maps each
  audit-protocol category to a folder. Tracker UI has a "Generate
  OCR audit package" button. Cross-references LOOP-A.A4 submission-
  bundle pattern. Runbook documents the 30-day production timeline.
- **Owner**: LOOP-V.V2.
- **Status**: open.
- **References**: HHS OCR Audit Protocol (https://www.hhs.gov/hipaa/
  for-professionals/compliance-enforcement/audit/protocol-current/
  index.html, accessed 2026-06-07).

### V-X25 — OCR Resolution Agreement reference drift

- **Description**: HHS-OCR Resolution Agreements (settlement records)
  are a critical learning resource — they show what HHS considered
  enforcement-worthy. LOOP-V's risk-assessment and breach-
  notification guidance is partially calibrated against these
  agreements. If the agreements registry isn't refreshed, the
  guidance becomes stale (e.g. a new agreement clarifying
  ransomware-as-breach treatment).
- **Severity**: low.
- **Mitigation**: V.V3's `data/ocr-resolution-agreements.json` is a
  cached snapshot of the HHS OCR Resolution Agreements page;
  refreshed quarterly by `scripts/extract-ocr-resolution-agreements.mjs`.
  CHANGELOG entry per refresh. Tracker UI surfaces "Recent OCR
  enforcement examples" panel on V.V3 dashboard.
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: HHS OCR Resolution Agreements (https://www.hhs.gov/
  hipaa/for-professionals/compliance-enforcement/agreements/index.html,
  accessed 2026-06-07).

### V-X26 — Workforce training evidence collection gap (§164.308(a)(5))

- **Description**: §164.308(a)(5)(i) requires a security awareness +
  training program. OCR audit findings frequently cite missing
  training-completion records, role-specific training, or
  acknowledgments of policy receipt. LOOP-V cannot collect training
  records directly (the records live in the operator's HRIS or LMS),
  but LOOP-V.V2's evidence pack must REFERENCE training-record
  storage location + completion-rate metrics.
- **Severity**: med.
- **Mitigation**: V.V2 records `workforce_training_evidence: {
  lms_system_name, completion_rate_lookback_90d, last_attestation_
  date, evidence_storage_location_url }`; renders a placeholder
  in the audit package linking to the operator's HRIS/LMS;
  REQUIRES-OPERATOR-INPUT diagnostic if not populated. Cross-
  references LOOP-P.P1 (PS-family workforce security) which carries
  workforce security artefacts. Runbook documents the LMS export
  workflow.
- **Owner**: LOOP-V.V2 + LOOP-P workforce security owner.
- **Status**: open.
- **References**: 45 CFR §164.308(a)(5).

### V-X27 — HHS-OCR enforcement penalty tier ambiguity (HITECH §13410(d))

- **Description**: HITECH §13410(d) establishes 4 penalty tiers
  (unknowing → reasonable cause → willful neglect corrected →
  willful neglect uncorrected) with materially different penalty
  amounts ($141-$71,162 minimum to $2.13M cap per year per
  violation type, 2024 dollars). LOOP-V's audit-readiness emitter
  must not pre-judge an operator's tier (this is an HHS finding),
  but the operator's risk posture documentation influences the tier
  classification.
- **Severity**: med.
- **Mitigation**: V.V2's evidence package includes a "reasonable
  cause vs willful neglect" defense narrative slot — operator
  writes a structured narrative referencing documented diligence
  (training, risk assessments, BAA inventory, prior remediations).
  V.V2 NEVER assigns a penalty tier (REO Rule 1.1, 10).  The
  runbook cites HHS Civil Money Penalties annual adjustments
  (45 CFR §102.3 updated annually for inflation). Cross-reference
  to current adjusted dollar amounts via `data/hhs-ocr-penalty-
  tiers-YYYY.json` (refreshed annually).
- **Owner**: LOOP-V.V2.
- **Status**: open.
- **References**: HITECH Act §13410(d) (42 U.S.C. §1320d-5);
  45 CFR §102.3 (annual penalty adjustments); HHS Annual CMP
  Adjustment Rule (most recent: 89 FR 80,019, 2024-10-03 for CY2025
  penalties).

### V-X28 — PHI inventory false-negative: ePHI present but undetected

- **Description**: PHI/ePHI is identifiable health information of any
  of the 18 HIPAA identifiers (45 CFR §164.514(b)(2)). Detecting
  PHI in unstructured stores (S3 buckets, Cloud Storage, mailboxes,
  ticketing systems) is hard. A LOOP-V.V4 PHI tagger that misses
  PHI in a bucket → no BAA flow-down on the wrong subprocessor →
  unreported breach. The 18-identifier list includes subtle items
  (geographic subdivision smaller than state, dates more specific
  than year for individuals over 89, certain unique numbers).
- **Severity**: high (regulatory compliance gap).
- **Mitigation**: V.V4's `core/ephi-tagger.ts` uses a multi-method
  classifier: (a) regex/dictionary matching on the 18 identifiers,
  (b) NER-based ML classifier (operator-supplied model or AWS
  Comprehend Medical / GCP Healthcare Data Loss Prevention API),
  (c) operator-supplied bucket/path overrides (`ephi-overrides.yaml`).
  Classifier output records confidence score; low-confidence hits
  are flagged for operator review. Test corpus
  (`tests/fixtures/ephi-test-corpus.json`) covers the 18 identifiers
  + adversarial patterns (e.g. dates for >89-year-olds, near-IP-address
  patterns). Cross-references LOOP-M.M3 data-class tagger.
- **Owner**: LOOP-V.V4.
- **Status**: open.
- **References**: 45 CFR §164.514(b)(2) (18 identifiers); AWS
  Comprehend Medical / GCP Healthcare DLP API documentation.

### V-X29 — PHI false-positive: over-tagging triggers unnecessary BAA flow-down

- **Description**: Inverse of V-X28: a tagger that over-tags ordinary
  data as PHI causes BAA-flow-down work on subprocessors handling
  non-PHI data. This wastes legal-ops effort + may dilute the BAA
  signal. Common patterns: addresses (zip codes ≥3 digits are
  PHI-relevant only if combined with other identifiers — context-
  dependent), email addresses (PHI only if in a health context).
- **Severity**: med.
- **Mitigation**: V.V4's classifier outputs `ephi_confidence:
  enum('very-low','low','medium','high','certain')` + multi-factor
  score; UI surfaces score breakdown; operator can confirm or
  override per finding. Tracker UI shows a per-bucket "PHI
  confidence distribution" histogram. Adversarial test pins the
  context-dependent patterns.
- **Owner**: LOOP-V.V4.
- **Status**: open.
- **References**: 45 CFR §164.514(b)(2).

### V-X30 — De-identification standard misapplication (Safe Harbor vs Expert Determination)

- **Description**: 45 CFR §164.514(b) defines two de-identification
  methods: Safe Harbor (remove all 18 identifiers + no actual
  knowledge of re-identifiability) and Expert Determination (a
  statistician certifies very small re-identification risk).
  Operators sometimes claim de-identification without meeting
  either standard — and de-identified data is NOT PHI, so the
  BAA + breach-notification flows skip. Wrong de-identification
  claim → undetected PHI → undetected breaches.
- **Severity**: high.
- **Mitigation**: V.V4 records per-dataset `deidentification_method:
  enum('not-deidentified','safe-harbor','expert-determination',
  'limited-dataset')` + `deidentification_evidence_url: text` +
  `deidentification_validated_at: date` + `validator_credential:
  text`. Datasets claimed as de-identified must have evidence; V.V4
  refuses to exempt a dataset from PHI flow without evidence. Cross-
  references HHS guidance on de-identification methods.
- **Owner**: LOOP-V.V4.
- **Status**: open.
- **References**: 45 CFR §164.514(b); HHS de-identification
  guidance (https://www.hhs.gov/hipaa/for-professionals/privacy/
  special-topics/de-identification/index.html, accessed 2026-06-07).

### V-X31 — Limited Data Set (LDS) handling — partial PHI scope

- **Description**: 45 CFR §164.514(e) defines a Limited Data Set (LDS)
  — data with most direct identifiers stripped but with dates and
  some geographic detail. LDS requires a Data Use Agreement (DUA)
  rather than a full BAA. CSPs may co-mingle full PHI with LDS in
  the same data lake; tagging logic must distinguish the two.
- **Severity**: med.
- **Mitigation**: V.V4's tagger output includes
  `phi_category: enum('full-phi', 'limited-data-set', 'de-identified',
  'not-phi')`. LDS datasets route to LDS-tagged DUA workflow (not
  BAA). Cross-references LOOP-V.V1 contract-registry which models
  DUA records alongside BAA records. Runbook documents the LDS/DUA
  distinction.
- **Owner**: LOOP-V.V4 + LOOP-V.V1.
- **Status**: open.
- **References**: 45 CFR §164.514(e); HHS LDS guidance.

### V-X32 — BA-to-CE notification delay: BA's 60-day clock vs CE's 60-day clock

- **Description**: When a BA discovers a breach, §164.410(b) requires
  notification to the CE "without unreasonable delay and in no case
  later than 60 calendar days after discovery". The CE then has 60
  days from BA's notification to notify individuals. If the BA
  exhausts most of its 60 days before notifying the CE, the CE has
  less time to assemble individual notifications. HHS has cited
  BAs for "unreasonable delay" even within the 60-day cap.
- **Severity**: high (BA-side enforcement risk).
- **Mitigation**: V.V3's BA-to-CE notification clock is treated as
  a tighter clock than the individual 60-day clock; configurable
  target of 30 days (default; operator can shorten to 5/10/15 days
  per BAA agreement). Tracker UI shows BOTH clocks; the BA-to-CE
  clock counts down separately. Adversarial test pins the case
  where BA exhausts day 58 before notifying CE. Runbook references
  HHS enforcement examples (e.g. CHSPSC 2020).
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: 45 CFR §164.410(b); HHS Resolution Agreements.

### V-X33 — Breach-letter content non-compliance: missing required §164.404(c) elements

- **Description**: 45 CFR §164.404(c)(1) requires individual breach
  notifications to contain SPECIFIC elements: (a) brief description
  of the breach, (b) types of PHI involved, (c) steps individuals
  should take, (d) what the CE/BA is doing, (e) contact procedures.
  Letters missing any of these elements are non-compliant and
  trigger OCR findings.
- **Severity**: high.
- **Mitigation**: V.V3's `.docx` breach-letter template embeds ALL
  FIVE required elements as separate operator-fillable sections;
  the renderer refuses to emit unless all five are populated (min
  100 chars each) AND the operator-supplied content has passed a
  legal-review checkbox. The template ships with the regulation
  text inline as a guide. Adversarial test pins missing-element
  case. Cross-references LOOP-C.C* document-template-pack.
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: 45 CFR §164.404(c)(1).

### V-X34 — Breach-letter delivery method non-compliance (§164.404(d))

- **Description**: §164.404(d) requires individual notification by
  first-class mail (default) OR by email if the individual has
  affirmatively consented to email notification. Substitute notice
  (web posting / media notice) requires specific conditions met
  (10+ undeliverable letters, etc.). A CSP/CE that emails without
  affirmative consent or skips substitute notice is non-compliant.
- **Severity**: med.
- **Mitigation**: V.V3's individual-notification workflow records
  `delivery_method: enum('first-class-mail','email-with-consent',
  'substitute-notice-web','substitute-notice-media')` + the
  consent evidence for email + the substitute-notice trigger
  conditions for web/media. The renderer asserts conditions are
  met before emitting. Operator runbook documents the substitute-
  notice criteria.
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: 45 CFR §164.404(d).

### V-X35 — Foreign-language + accessibility requirements for breach letters

- **Description**: HHS guidance + Title VI / Section 1557 of ACA may
  require breach letters in languages other than English if the CE
  has populations with limited English proficiency. ADA Title II
  / Section 508 (LOOP-I cross-reference) may require accessible
  format. Letters in English-only may be non-compliant.
- **Severity**: med.
- **Mitigation**: V.V3's renderer allows multi-language emit;
  operator supplies translations via
  `breach-letter-translations.yaml`. Runbook documents Title VI /
  Section 1557 + ADA requirements (cross-reference LOOP-I.I5
  Section 508 extension). Tracker UI prompts for language list
  per affected-individual cohort.
- **Owner**: LOOP-V.V3 + LOOP-I.
- **Status**: open.
- **References**: Section 1557 of the ACA (42 U.S.C. §18116);
  Title VI (42 U.S.C. §2000d); ADA Title II / Section 508.

### V-X36 — 21st Century Cures Information Blocking exposure

- **Description**: The 21st Century Cures Act §4004 (42 U.S.C.
  §300jj-52) + HHS Information Blocking Rule (45 CFR Part 171,
  effective Apr 2021) prohibit "actors" (including health IT
  developers + health information networks + healthcare providers)
  from interfering with the access, exchange, or use of electronic
  health information (EHI). CSPs serving healthcare are increasingly
  becoming "actors" under expanded interpretation. Information
  blocking penalties (45 CFR §171.301) — $1M/violation for
  developers + networks; provider disincentives — are non-trivial.
  A LOOP-V emitter must not inadvertently encourage information
  blocking (e.g. "block PHI access until breach response complete").
- **Severity**: high (regulatory exposure; civil monetary penalty).
- **Mitigation**: V.V3's incident-response flow includes explicit
  guidance that PHI access restrictions during breach response
  must be SCOPED narrowly (only affected systems / records) +
  documented + time-bounded. The runbook references the 8 statutory
  exceptions (45 CFR §§171.201-208) including the "preventing harm"
  exception. V.V2's evidence pack includes an "Information Blocking
  Compliance" attestation slot. Cross-references HHS-ONC enforcement
  guidance. Future enhancement: a dedicated Information Blocking
  compliance emitter (could become LOOP-V.V6).
- **Owner**: LOOP-V.V3 + operator legal counsel.
- **Status**: open.
- **References**: 21st Century Cures Act §4004 (Pub. L. 114-255);
  45 CFR Part 171 (Information Blocking);
  https://www.healthit.gov/topic/information-blocking, accessed
  2026-06-07; ONC Cures Act Final Rule (85 FR 25642, 2020-05-01).

### V-X37 — Information Blocking penalty schedule (HHS-OIG 45 CFR Part 1003 amendments)

- **Description**: HHS-OIG promulgated penalty schedules under 45 CFR
  Part 1003 for information blocking by health IT developers +
  HIEs/HINs (max $1M per violation, effective Sept 2023). Provider
  disincentives are separate (CMS issued in 2024). LOOP-V must
  surface the penalty exposure so operators understand the risk.
- **Severity**: high.
- **Mitigation**: V.V3's tracker dashboard surfaces a "Cures Act
  Information Blocking" risk panel. Operator narrative slot for
  "blocking review process". Runbook cites the OIG Final Rule
  + CMS provider disincentive rule. Cross-references
  data/ocr-resolution-agreements.json with OIG enforcement
  examples (currently empty; OIG enforcement began 2023).
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: HHS-OIG Final Rule (88 FR 42820, 2023-06-27);
  CMS Final Rule on provider disincentives (89 FR 54662, 2024-07-03).

### V-X38 — EHI definition scope expansion (USCDI v3+ / v4+)

- **Description**: The Information Blocking Rule defines EHI as
  electronic protected health information per HIPAA + a US Core Data
  for Interoperability (USCDI) subset. USCDI versions evolve (v1
  → v2 → v3 → v4); the EHI definition expands accordingly. A
  LOOP-V emitter pinned to USCDI v3 may drift as ONC publishes
  v4/v5.
- **Severity**: med.
- **Mitigation**: V.V4's PHI tagger records
  `uscdi_version_pinned: "v3"` (constant); operator can override.
  CHANGELOG entry per USCDI version bump. Runbook documents the
  ONC USCDI publication schedule.
- **Owner**: LOOP-V.V4.
- **Status**: open.
- **References**: USCDI v3 (https://www.healthit.gov/isa/
  united-states-core-data-interoperability-uscdi, accessed
  2026-06-07); 45 CFR §171.102 (EHI definition).

### V-X39 — REO Rule 1.8 `process.env.NODE_ENV === 'test'` branch creep

- **Description**: REO Rule 1.8 prohibits the literal in production
  code. The new LOOP-V emit infrastructure (BAA registry loader,
  breach-clock evaluator, ePHI tagger, OCR audit bundler,
  4-factor risk-assessment renderer) is exactly where developers
  reach for the test-short-circuit. Same class as LOOP-W-X26,
  LOOP-T-X20, LOOP-B-X6, LOOP-R-X6, LOOP-S-X15.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal;
  tests inject seams via dependency-injected HTTP fetcher +
  filesystem helper + clock helper + (for V.V4) classifier seam;
  CI gate is non-bypassable.
- **Owner**: LOOP-V implementer.
- **Status**: open.
- **References**: CLAUDE.md REO Rule 1.8.

### V-X40 — Provenance schema drift across new emit artifacts

- **Description**: Every new emit artifact (`baa-registry-YYYYMMDD.json`,
  `hipaa-admin-safeguards-pack-YYYYMMDD.json`, `breach-incidents-
  YYYYMMDD.json`, individual `breach-letter-<incident_id>-<recipient_
  id>.docx`, `hhs-annual-breach-submission-CYYYYY.json`, `hhs-ocr-
  audit-package-YYYYMMDD.zip`, `ephi-inventory-YYYYMMDD.json`,
  `nprm-readiness-gap-YYYYMMDD.json`) must carry a `provenance` block
  per REO Rule 2.6. `scripts/check-provenance.mjs` enforces. A missed
  block silently fails the slice.
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via
  `check:provenance`; pattern reused from `core/inventory-coverage.ts`.
  Cross-references LOOP-W-X25, LOOP-T-X21, LOOP-B-X9, LOOP-R-X9,
  LOOP-S-X16. CHANGELOG entry per slice cites provenance contents.
- **Owner**: LOOP-V implementer.
- **Status**: open.
- **References**: CLAUDE.md REO Rule 2.6.

### V-X41 — Submission-bundle role growth + per-incident / per-CY pattern

- **Description**: LOOP-V adds ~14 new roles to
  `submission-bundle.ts:WELL_KNOWN`: `baa-registry-json`,
  `hipaa-admin-safeguards-pack-json`, `hipaa-admin-safeguards-pack-
  pdf`, `breach-incidents-json`, `breach-letter-docx-{incident_id}-
  {recipient_id}`, `breach-media-notice-docx-{incident_id}`,
  `hhs-annual-breach-submission-json`, `hhs-annual-breach-
  submission-docx`, `hhs-ocr-audit-package-zip`, `ephi-inventory-json`,
  `ephi-tagger-coverage-json`, `nprm-readiness-gap-json`, `nprm-
  readiness-gap-docx`, `hitrust-evidence-pack-json` (conditional on
  HITRUST overlay). Per-incident + per-recipient suffixed filenames
  require `filenamePattern` (regex) support added in LOOP-R-X8.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins
  literal-filename + `filenamePattern` role matches; per-slice tests
  assert presence; CHANGELOG entry for LOOP-V close lists final role
  inventory. Cross-references LOOP-R-X8, LOOP-T-X22, LOOP-W-X27.
- **Owner**: LOOP-V implementer.
- **Status**: open.
- **References**: LOOP-A.A4 submission-bundle spec.

### V-X42 — Tracker schema migration on existing installs

- **Description**: LOOP-V adds ~10 new tracker tables (`baa_registry`,
  `baa_amendments`, `downstream_baas`, `hipaa_admin_safeguards`,
  `breach_incidents`, `breach_risk_assessments`, `breach_
  notifications_individual`, `breach_notifications_media`,
  `breach_notifications_hhs`, `ephi_inventory`, `ephi_tagger_runs`,
  `hitrust_evidence`, `information_blocking_assessments`). All must
  be additive `CREATE TABLE IF NOT EXISTS`; no DROP / ALTER COLUMN.
- **Severity**: high.
- **Mitigation**: All tables additive; CHANGELOG documents upgrade
  path; smoke test on a copy of a production DB; multi-tenant work
  batched under LOOP-H.H3. Cross-references LOOP-T-X23, LOOP-S-X18,
  LOOP-R-X10, LOOP-B-X10.
- **Owner**: LOOP-V implementer.
- **Status**: open.
- **References**: LOOP-H.H3 multi-CSO design.

### V-X43 — Tracker Ed25519 signing-key rotation across multi-year breach records

- **Description**: Breach records persist for at least 6 years
  (§164.530(j) documentation retention). Tracker resident-key
  rotation across years could invalidate prior signatures when
  V.V3 reads historical incidents for trend reporting or for OCR
  audit response.
- **Severity**: med.
- **Mitigation**: Tracker exposes `GET /api/sign/public-keys`
  returning all historical keys keyed by `key_id`; reader cross-
  references each record's `signing_key_id` against the registry.
  Pattern reused from LOOP-B-X3, LOOP-R-X4, LOOP-S-X6, LOOP-T-X24,
  LOOP-W-X23. Rotation events written to `audit_log`; runbook
  documents.
- **Owner**: LOOP-V.V3.
- **Status**: open.
- **References**: 45 CFR §164.530(j); CLAUDE.md REO Rule 2.2.

### V-X44 — Multi-tenant LOOP-V isolation deferred to LOOP-H.H3

- **Description**: All LOOP-V tracker tables omit a `tenant_id`
  column. When multi-CSO ships (H.H3), all need migration in a
  single cross-loop sweep. PHI cross-tenant leakage is a
  hyper-critical risk that LOOP-H.H3 must address explicitly for
  LOOP-V tables.
- **Severity**: med (long-tail; single-tenant deploy mitigates short-
  term).
- **Mitigation**: Documented in `LOOP-V-SPEC.md §11 Open Questions`;
  H.H3 spec must enumerate every LOOP-V table; LOOP-V ships in
  single-tenant deployments only (documented in runbook). LOOP-V's
  PHI sensitivity makes this a TOP-priority migration when H.H3
  ships. Cross-references LOOP-T-X28, LOOP-S-X21, LOOP-R-X15,
  LOOP-W-X38, LOOP-B-X15.
- **Owner**: LOOP-H.H3 implementer; LOOP-V advises.
- **Status**: open.
- **References**: LOOP-H.H3 multi-tenant design.

---

## Per-slice risks

### V.V1 — BAA Registry + CE→CSP responsibility overlay

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| V.V1-1 | high | BAA registry drift from CMS (cross-ref V-X1) | Dual-source reconciler + quarterly cron + drift diagnostics | open |
| V.V1-2 | high | Pre-Omnibus BAA template still in effect (cross-ref V-X2) | `template_era` enum + amendment flag + tracker badge | open |
| V.V1-3 | high | Missing downstream-BAA for ePHI-touching subprocessor (cross-ref V-X3) | Cross-loop join with LOOP-W subprocessors-sheet + REQUIRES-OPERATOR-INPUT | open |
| V.V1-4 | med | Hybrid-entity / OHCA notification routing (cross-ref V-X4) | `ce_organizational_form` enum + per-component routing | open |
| V.V1-5 | high | Conduit-exception misapplication (cross-ref V-X5) | Intake wizard PHI-storage question + legal-review forcing | open |
| V.V1-6 | med | BAA termination PHI-disposition gap (cross-ref V-X6) | `termination_status` enum + disposition evidence URL + annual reconciliation | open |
| V.V1-7 | med | CRM overlay drift vs LOOP-L | Join `baa_registry` → LOOP-L `crm_responsibility_matrix`; consistency check | open |
| V.V1-8 | low | BAA contract-text storage location (CSP doesn't hold legal-binding original) | Registry stores URL to CMS + SHA-256 + operator runbook on legal-original retention | open |
| V.V1-9 | med | BAA expiration / renewal cadence drift (annual auto-renewals) | `auto_renewal: bool` + `next_renewal_review_at: date` + T-60/T-30/T-7 warnings | open |
| V.V1-10 | low | CE business name vs trade name vs NPI inconsistency | Registry stores all three; multi-match search; operator triage on intake | open |
| V.V1-11 | high | CE legal acquirer / merger changes notification routing | `ce_parent_org_change_history[]` + cron reminder for review on M&A activity | open |
| V.V1-12 | med | BAA carve-outs (e.g. "for analytics workload only") not modeled | `scope_carveouts: text` narrative field; future enhancement: structured carveout schema | open |
| V.V1-13 | low | BAA insurance + indemnification clause tracking | Out-of-scope of V.V1 (commercial-contracts area); reference field only | open |
| V.V1-14 | med | DUA (Data Use Agreement for LDS) modeling separate from BAA | `contract_type: enum('baa','dua','combined')` + separate workflow | open |
| V.V1-15 | low | Multi-BAA per CE (different products under different BAAs) | `(ce_id, product_id, fiscal_year)` composite key; tracker UI groups by CE | open |
| V.V1-16 | med | BAA-signature evidence (executed PDF SHA-256 vs CMS-stored binary) | Registry stores executed-PDF SHA-256; reconciler verifies | open |
| V.V1-17 | low | International CE customers (rare but possible: non-US healthcare providers operating in US) | Out of HIPAA scope; LOOP-Z international-equivalence may extend | open |

### V.V2 — §164.308 administrative-safeguard evidence pack

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| V.V2-1 | high | 800-66 Rev 2 crosswalk drift (cross-ref V-X16) | Pinned source SHA-256 + Appendix F mapping + `crosswalk_source` field | open |
| V.V2-2 | med | KSI overlap double-counting (cross-ref V-X17) | `ksi_evidence_link[]` per safeguard + consistency check | open |
| V.V2-3 | low | IPD vs Final 800-66 R2 source drift (cross-ref V-X18) | Hash assert on source PDF | open |
| V.V2-4 | med | 800-66 R3 / NPRM-aligned revision horizon (cross-ref V-X19) | Version constant overridable + LOOP-V.V5 forward gap analysis | open |
| V.V2-5 | med | HITRUST assessment-type mismatch (cross-ref V-X20) | `hitrust_assessment_type` enum + refuse-attest below i1 | open |
| V.V2-6 | med | HITRUST CSF version drift (cross-ref V-X21) | `csf_version` field + 18-month staleness warning | open |
| V.V2-7 | med | HITRUST crosswalk inaccuracy (cross-ref V-X22) | `mapping_source` + `mapping_confidence` per row + low-confidence UI review | open |
| V.V2-8 | low | HITRUST certification revocation (cross-ref V-X23) | `certification_status` enum + cascade refresh | open |
| V.V2-9 | high | OCR audit-package incomplete (cross-ref V-X24) | Audit-Protocol-categorized bundle + 30-day production timeline | open |
| V.V2-10 | low | OCR Resolution Agreements registry stale (cross-ref V-X25) | Quarterly refresh + tracker UI panel | open |
| V.V2-11 | med | Workforce training evidence gap (cross-ref V-X26) | HRIS/LMS reference + REQUIRES-OPERATOR-INPUT | open |
| V.V2-12 | med | HHS-OCR penalty tier ambiguity (cross-ref V-X27) | Defense narrative slot + no auto-tier assignment | open |
| V.V2-13 | med | Risk Analysis (§164.308(a)(1)(ii)(A)) cadence missing | Annual + post-material-change recurrence; runbook + tracker reminders | open |
| V.V2-14 | med | Sanctions Policy (§164.308(a)(1)(ii)(C)) HR system gap | Operator narrative + HR-system reference URL + REQUIRES-OPERATOR-INPUT | open |
| V.V2-15 | med | Contingency Plan (§164.308(a)(7)) overlap with FedRAMP CP family | Cross-loop with LOOP-G CP-family + KSI evidence link | open |
| V.V2-16 | med | Periodic Evaluation (§164.308(a)(8)) cadence drift | `last_periodic_eval_at` + T-30 warning before due | open |
| V.V2-17 | low | Workstation Use / Security (§164.310(b)/(c)) endpoint-management coverage | Operator narrative + EDR-system reference | open |
| V.V2-18 | med | Device + Media Controls (§164.310(d)) disposal-evidence | Per-disposal-event log + chain-of-custody | open |

### V.V3 — §164.400-§164.414 breach-notification emitter

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| V.V3-1 | high | 4-factor over-classification (cross-ref V-X7) | Structured 4-factor JSON + min narratives + WebAuthn signature + over-classification warning | open |
| V.V3-2 | high | 4-factor assessment tampering (cross-ref V-X8) | Append-only versioned table + Ed25519 per version | open |
| V.V3-3 | high | Encryption safe-harbor misclaim (cross-ref V-X9) | Evidence-required + FIPS 140-2 link + LOOP-R cross-loop | open |
| V.V3-4 | high | Multi-clock classification drift G.G2 / CIRCIA (cross-ref V-X10) | FK to G.G2 incident + consistency check + cross-loop test | open |
| V.V3-5 | high | ≥500-individual triple-clock miss (cross-ref V-X11) | Three clocks (individual / media / HHS) + side-by-side UI + adversarial test | open |
| V.V3-6 | high | Discovery anchor misidentification (cross-ref V-X12) | Four anchor timestamps + earliest-of clock + UI display | open |
| V.V3-7 | med | Weekend/holiday boundary (calendar days; cross-ref V-X13) | Calendar-day arithmetic + unreasonable-delay narrative if >30 days | open |
| V.V3-8 | high | State breach-notification overlay miss (cross-ref V-X14) | Per-state registry + per-state notification packets + AG routing | open |
| V.V3-9 | med | HHS annual <500 submission miss (cross-ref V-X15) | Annual cron + T-90/T-30/T-7 warnings + manual submission per REO Rule 4 | open |
| V.V3-10 | high | BA-to-CE notification delay (cross-ref V-X32) | Tighter clock (default 30 days) + per-BAA override + separate countdown | open |
| V.V3-11 | high | Breach-letter missing required elements (cross-ref V-X33) | Five-element template + min char + legal-review checkbox + adversarial test | open |
| V.V3-12 | med | Delivery method non-compliance (cross-ref V-X34) | `delivery_method` enum + consent evidence + substitute-notice conditions | open |
| V.V3-13 | med | Foreign-language / Section 1557 / ADA accessibility (cross-ref V-X35) | Multi-language emit + translations registry + accessibility cross-ref LOOP-I.I5 | open |
| V.V3-14 | high | 21st Century Cures Information Blocking exposure (cross-ref V-X36) | Scoped + documented + time-bounded restrictions + 8-exception runbook | open |
| V.V3-15 | high | Information Blocking penalty schedule (cross-ref V-X37) | Risk panel + operator narrative + cross-ref OIG enforcement | open |
| V.V3-16 | med | USCDI version / EHI scope drift (cross-ref V-X38) | USCDI version constant + override + CHANGELOG | open |
| V.V3-17 | high | Tracker signing-key rotation across 6-year retention (cross-ref V-X43) | Inherit B-X3 fix; signing_key_id per record | open |
| V.V3-18 | high | Repository tampering / incident record integrity post-emit | Signed envelope + tracker audit log + submission_channel hash | open |
| V.V3-19 | med | Multi-incident roll-up (single root cause, multiple incidents) | `parent_incident_id` FK + group-by-root in reporting | open |
| V.V3-20 | low | Incident metadata redaction for media notice | Renderer strips operator-flagged-sensitive fields; runbook documents | open |

### V.V4 — ePHI data-class auto-tagger overlay

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| V.V4-1 | high | PHI false-negative undetected (cross-ref V-X28) | Multi-method classifier + 18-identifier test corpus + adversarial patterns | open |
| V.V4-2 | med | PHI false-positive over-tagging (cross-ref V-X29) | Confidence enum + per-finding override + histogram | open |
| V.V4-3 | high | De-identification standard misapplied (cross-ref V-X30) | `deidentification_method` enum + evidence URL + validator credential | open |
| V.V4-4 | med | Limited Data Set distinction (cross-ref V-X31) | `phi_category` enum + LDS workflow + DUA cross-ref | open |
| V.V4-5 | med | USCDI version drift (cross-ref V-X38) | Version constant + CHANGELOG per bump | open |
| V.V4-6 | high | AWS Comprehend Medical / GCP DLP API outage / quota | Graceful fallback to regex-only + coverage-miss diagnostic + retry queue | open |
| V.V4-7 | med | ML classifier model drift / re-training cadence | Operator-supplied model version + per-finding `classifier_version`; quarterly accuracy review | open |
| V.V4-8 | med | Cross-region data residency (PHI in non-US region) | Per-bucket region check + flag non-US storage | open |
| V.V4-9 | low | Encrypted blob without classification access | If blob can't be decrypted by tagger, flag as `unclassifiable`; operator review | open |
| V.V4-10 | med | Tag persistence across object versions / lifecycle | Tagger run records `object_version_id`; re-tag on new version | open |
| V.V4-11 | low | Operator override registry drift | `ephi-overrides.yaml` with version pin + reconciliation check | open |
| V.V4-12 | med | High-volume scan cost ($$$) on AWS Comprehend Medical | Cost estimation pre-run + sampling option + operator confirmation | open |
| V.V4-13 | low | Bucket-level vs object-level granularity | Default object-level; bucket-level summary roll-up; operator picks | open |
| V.V4-14 | med | LOOP-M data-class tagger overlap | V.V4 overlay extends LOOP-M.M3; consistency check; cross-loop test | open |
| V.V4-15 | low | DICOM / HL7 / FHIR-format ePHI extra parsing | Format-aware parsers (operator can supply); default treats as binary; runbook | open |

### V.V5 — NPRM-finalization-readiness pack

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| V.V5-1 | high | NPRM finalization horizon uncertain (cross-ref V-X19) | Forward gap-analysis emitter + operator override + quarterly NPRM-watch runbook | open |
| V.V5-2 | high | Encryption-mandatory readiness gap | Cross-loop join LOOP-R PQC + LOOP-E crypto KSIs; per-asset gap | open |
| V.V5-3 | high | MFA-mandatory readiness gap | Cross-loop join LOOP-X IAM KSIs (IAM-MFA, IAM-AAM); per-account gap | open |
| V.V5-4 | med | Vuln-scan cadence readiness | Cross-loop join LOOP-E VDR; cadence-gap report | open |
| V.V5-5 | med | Pen-test cadence readiness | Operator-supplied evidence + cadence-gap report | open |
| V.V5-6 | med | Asset inventory readiness (NPRM expects complete inventory) | Cross-loop join LOOP-INV; gap-analysis report | open |
| V.V5-7 | med | Network map readiness | Cross-loop join LOOP-D diagrams; gap-analysis report | open |
| V.V5-8 | low | NPRM final rule may differ materially from proposed (e.g. additional categories) | Forward-looking only; re-author V.V5 post-finalization | open |
| V.V5-9 | low | Cost-impact estimation for NPRM compliance | Out of V.V5 scope; future enhancement | open |
| V.V5-10 | med | Effective-date arithmetic (NPRM proposes 180-day compliance) | Compliance-deadline tracker + T-90/T-30/T-7 warnings | open |

---

## External dependencies that may change

### Federal regulatory / statutory sources
- **45 CFR Part 160 / 164 (HIPAA Rules)** —
  https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C — stable
  since Omnibus 2013; pending revision via Jan 2025 NPRM
  (publication expected late-2026 to mid-2027).
- **42 U.S.C. §1320d et seq. (HIPAA statute)** — stable.
- **HITECH Act (Pub. L. 111-5 Title XIII)** — stable; §13408 (BA direct
  enforcement), §13410 (penalty tiers), §13402 (breach notification).
- **21st Century Cures Act §4004 (Pub. L. 114-255)** — stable.
- **45 CFR Part 171 (Information Blocking)** — effective Apr 2021;
  HHS-OIG enforcement schedule effective Sept 2023; CMS provider
  disincentive rule effective Jul 2024.
- **HHS HIPAA Security Rule NPRM (90 FR 898, Jan 6 2025)** — proposed;
  final rule expected late-2026 to mid-2027.
- **45 CFR §102.3 / HHS Annual CMP Adjustment** — annual update each
  October for following CY.

### NIST / NIST IR sources
- **NIST SP 800-66 Rev 2 (Feb 2024)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf
  — current authoritative HIPAA Security Rule implementation guide.
- **NIST SP 800-66 Rev 2 IPD (Jul 2022)** — withdrawn; do not use.
- **NIST SP 800-111 (Nov 2007)** — guide to storage encryption.
- **NIST SP 800-52 Rev 2 (Aug 2019)** — TLS implementation guidance.
- **NIST SP 800-53 Rev 5 (Dec 2020 + errata 2023-12)** — controls.

### HHS / OCR / OIG / CMS / ONC operational sources
- **HHS OCR Breach Portal (Wall of Shame)** —
  https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf — public list of
  breaches affecting ≥500 individuals.
- **HHS OCR Resolution Agreements** —
  https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html
  — settlement record; refreshed as OCR settles.
- **HHS OCR Audit Protocol** —
  https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/audit/protocol-current/index.html
  — current audit-protocol matrix.
- **HHS Sample BAA Provisions** —
  https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html
  — last updated 2013 Omnibus.
- **HHS Cloud Computing Guidance** —
  https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html
  — Oct 2016, updated 2020.
- **HHS De-Identification Guidance** —
  https://www.hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification/index.html
  — Nov 2012 (current).
- **ONC USCDI v3 / v4** —
  https://www.healthit.gov/isa/united-states-core-data-interoperability-uscdi
  — versioned roughly annually.
- **HHS-OIG Final Rule on Info Blocking CMPs (88 FR 42820)** —
  Sept 2023.
- **CMS Provider Disincentives Final Rule (89 FR 54662)** — Jul 2024.

### State / cross-jurisdictional
- **NAAG state-breach-notification compendium** —
  https://www.naag.org/issues/cybercrime/ — state AG reference.
- **California Civil Code §1798.82** — CA breach law.
- **NY GBL §899-aa** — NY SHIELD breach law.
- **TX Business & Commerce Code §521.053** — TX breach law.
- **All 50 state breach laws** — operator-maintained registry.

### HITRUST (conditional)
- **HITRUST CSF v11.x** — https://hitrustalliance.net/product-tool/hitrust-csf/
  — member portal; release cadence ~annual.
- **HITRUST Assurance Program Requirements** — member portal; defines
  e1 / i1 / r2 / bC assessment types.

### Cross-loop deps
- **LOOP-L CRM** — V.V1 overlays.
- **LOOP-M Privacy Package** — V.V4 extends data-class tagger.
- **LOOP-G.G2 Incident Comms** — V.V3 incident FK.
- **CIRCIA Workflow** — V.V3 dual-classification.
- **LOOP-R PQC / FIPS** — V.V3 safe-harbor evidence; V.V5 encryption gap.
- **LOOP-X Zero Trust / IAM** — V.V5 MFA-mandatory gap.
- **LOOP-E Continuous Monitoring** — V.V2 KSI evidence inheritance.
- **LOOP-W Subprocessors** — V.V1 downstream-BAA join.
- **LOOP-A.A4 Submission Bundler** — V.V2/V.V3 bundle integration.
- **LOOP-B POA&M** — V.V2/V.V5 gap-remediation tracking.
- **LOOP-H.H3 Multi-tenant** — V-X44 long-tail.
- **LOOP-I.I5 Section 508 / ADA** — V.V3 breach-letter accessibility.
- **LOOP-Z International** — V.V1-17 international CE customers.
- **LOOP-N Threat Model** — HITRUST scoping references.
- **LOOP-P Workforce Security** — V.V2 training evidence cross-ref.

---

## Resume-from-fresh-session checklist

A future session opening this register cold should be able to act
on any open risk without rediscovery. The checklist:

1. Read `CLAUDE.md` (REO standard).
2. Read `docs/STATUS.md` to find LOOP-V slice status.
3. Read `docs/loops/LOOP-V-SPEC.md` for loop mission + slice list.
4. Read this file (`docs/loops/LOOP-V-RISKS.md`) end-to-end.
5. Read the per-slice doc relevant to the in-progress slice
   (`docs/slices/V/V.V[1-5].md`).
6. Read companion risks registers (LOOP-M-RISKS, LOOP-L-RISKS,
   LOOP-G-RISKS, LOOP-U-RISKS, LOOP-B-RISKS, CIRCIA-WORKFLOW)
   to triage cross-loop risk interactions.
7. For each open risk: read the `References` block, fetch the cited
   URL with the 2026-06-07 access date verified, confirm verbatim
   text matches before authoring code or docs.
8. Update this register with new findings; commit per the 7-step
   procedure in `docs/SLICE-COMPLETION-PROCEDURE.md`.
9. If a new risk is surfaced during implementation, append a new
   `V-X<NN>` entry here in the same commit that introduces the
   code/spec change.
10. Slice completion directive: when a LOOP-V slice closes, update
    STATUS.md, the LOOP-V SPEC status table, CHANGELOG.md, push to
    origin/main, and verify with `git log --oneline -3`. Only THEN is
    the slice closed.

---

## Implementation log (cross-cutting)

| date | session | action | commit | notes |
|---|---|---|---|---|
| 2026-06-07 | wf-loopv-risks | Risks register authored (44 cross-cutting + 80 per-slice risks). Sources cited verbatim from HHS / NIST / HITRUST / state-AG / ONC / OIG / CMS. | TBD | — |
