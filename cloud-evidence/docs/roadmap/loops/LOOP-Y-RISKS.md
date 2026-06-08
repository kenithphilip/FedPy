# LOOP-Y — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status=resolved` + resolution note.
> Severity: high = ship-blocking; med = should fix in-loop; low = file
> as follow-up.

> Authoritative companion to `docs/loops/LOOP-Y-SPEC.md` and the
> per-slice docs at `docs/slices/Y/Y.Y[1-4].md`. Read those for context
> before acting on any risk here.

> **CONDITIONAL GATE**: LOOP-Y is **conditional**. The CJIS path (Y.Y1 +
> Y.Y2) activates when `org-profile.yaml` declares
> `serves_criminal_justice_information: true`; the IRS 1075 path
> (Y.Y3 + Y.Y4) activates when `serves_federal_tax_information: true`.
> Both flags may be true simultaneously (e.g. a fusion-center tenant
> whose stack also handles state Department of Revenue tax workloads).
> When BOTH are false the loop is skipped end-to-end; the orchestrator
> emits a one-line `loop:Y skipped — sector_overlay_not_applicable`
> diagnostic and proceeds. Every risk below carries an implicit "WHEN
> the relevant Y-path is ACTIVE" precondition. False-declaration of
> "not applicable" when CJI or FTI is in fact processed is itself an
> audit finding the FOURTH-PASS-AUDIT.md flagged — see Y-X44 below.

> Last updated: 2026-06-07.

> Companion reading (cross-reference these registers when triaging a
> LOOP-Y risk that interacts with another loop):
> - `LOOP-V-RISKS.md` — healthcare overlay; LOOP-Y reuses V's BAA
>   primitive for the IRS 1075 §6.3 contractor agreement (Y-X22 +
>   cross-loop with V's BAA-key-rotation register).
> - `LOOP-U-RISKS.md` — privacy frameworks crosswalk; touches CJIS
>   notice-and-consent + IRS 1075 §10 disclosure-awareness boundary.
> - `LOOP-X-RISKS.md` — zero trust; Y.Y2 borrows X's phishing-
>   resistant MFA pattern and inherits its registers.
> - `LOOP-A-RISKS.md` (where present) / per-slice A.A1, A.A4, A.A5
>   risks files — Y.Y2 + Y.Y4 emit POA&M items via A.A1; SSR + AA
>   evidence flow through A.A4 bundler + A.A5 signing.
> - `LOOP-INV-S` inventory-coverage risk surface — Y.Y2 + Y.Y4 read
>   `inventory.assets[].data_classes[]` to scope CJI / FTI assets;
>   silent tagger drift surfaces as a LOOP-Y false-negative (see
>   Y-X19 + Y-X20).

---

## Table of Contents

- [Cross-cutting risks (apply to ALL slices in LOOP-Y)](#cross-cutting-risks-apply-to-all-slices-in-loop-y)
  - Authoritative-source drift (Y-X1..Y-X7)
  - Catalog correctness & cross-walk (Y-X8..Y-X14)
  - CJIS Advanced-Authentication detector correctness (Y-X15..Y-X18)
  - FTI / CJI inventory boundary (Y-X19..Y-X21)
  - SSR submission lifecycle (Y-X22..Y-X27)
  - State-CSO ecosystem (Y-X28..Y-X32)
  - Signing, provenance, tamper-evidence (Y-X33..Y-X37)
  - Cross-loop interaction (Y-X38..Y-X43)
  - Operator-workflow & legal boundary (Y-X44..Y-X48)
- [Per-slice risks](#per-slice-risks)
  - Y.Y1 — CJIS Security Policy v5.9.5 Control Catalog
  - Y.Y2 — CJIS Advanced Authentication (AA) Detector
  - Y.Y3 — IRS Publication 1075 Control Catalog
  - Y.Y4 — IRS Safeguard Security Report (SSR) Emitter
- [External dependencies that may change](#external-dependencies-that-may-change)
- [Resolved risks (historical)](#resolved-risks-historical)
- [Procedure for adding / updating a risk in this register](#procedure-for-adding--updating-a-risk-in-this-register)
- [Resume-from-fresh-session checklist](#resume-from-fresh-session-checklist)
- [Appendix — when does LOOP-Y apply?](#appendix--when-does-loop-y-apply)
- [Appendix — risk-severity calibration](#appendix--risk-severity-calibration)

---

## Cross-cutting risks (apply to ALL slices in LOOP-Y)

### Y-X1 — CJIS Security Policy v5.9.6+ supersession during a live audit cycle

- **Description**: The FBI CJIS Division publishes new Security
  Policy versions on a cadence determined by the CJIS Advisory
  Process — typically 1-2 minor releases per year (5.9.4 → 5.9.5 in
  Jul 2024; a v6.0 draft was published 2024-12-27 per Louisiana
  State Police's mirror but remains in CSA-adoption-vote phase as
  of 2026-06-07). State CJIS Systems Officers (CSOs) decide
  individually when their state adopts a new version — Texas may
  adopt v6.0 on 2026-04-01 while Massachusetts may delay until
  2026-10-01. Y.Y1's catalog is pinned to v5.9.5; if a state CSO
  switches mid-audit, the operator's evidence envelope references
  the wrong policy version and the audit finds non-compliance on
  a control that didn't exist (or did exist with different
  language) under the operator's pinned snapshot.
- **Category**: authoritative-source drift.
- **Severity**: high (ship-blocking once a state CSO transitions
  while the operator's snapshot is stale).
- **Likelihood**: med — staggered adoption is well-precedented;
  per-state CJIS Audit Unit communications usually give 90+ days
  notice.
- **Impact**: false-negative on controls newly added in v6.0;
  false-positive on controls removed; full re-cross-walk to
  NIST 800-53 r5 may shift.
- **Mitigation**: Y.Y1 catalog snapshot carries
  `policy_version`, `policy_publication_date`, `state_adoption_map{}`
  per-state with `effective_date_in_state`; Y.Y2's evaluator picks
  the catalog version each customer agency's CSO is auditing
  against. CI cron `0 6 * * 1` (weekly Monday) re-fetches
  `https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center`
  and `https://lsp.org/media/dgxluyj3/cjis_security_policy_v6-0_20241227-1.pdf`
  + diffs the SHA-256 vs the pinned snapshot. Strict mode refuses to
  run if the snapshot is more than 180 days old (CJIS major-version
  cadence). Operator runbook `cjis-state-adoption-runbook.md`
  documents the per-state monitor workflow. CHANGELOG entry per
  version bump quoting the FBI-published change-control table.
  Cross-references slice **Y.Y1** (catalog ingester) and the
  future `Y.Y5-v6-migration` follow-up slice queued at v6.0
  national-adoption time.
- **Owner**: catalog ingester maintainer (Y.Y1 owner).
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.5 + §2.1 + §22; CJIS Advisory
  Process page (https://le.fbi.gov/cjis-division/the-cjis-advisory-process,
  accessed 2026-06-07); Louisiana State Police mirror.

### Y-X2 — CSO-approved Advanced-Authentication factor list drift between v5.9.x revisions

- **Description**: CJIS Security Policy §5.6.2.2.1 enumerates the
  CSO-approved AA factor categories (biometric, user-based digital
  certificates, smart cards, software tokens, hardware tokens,
  paper tokens, out-of-band authenticators). The list has shifted
  between v5.8 and v5.9.5 — paper (inert) tokens were re-added
  after community feedback; software tokens were clarified for
  on-device biometric attestation; "out-of-band" was tightened to
  exclude SMS for new deployments after 2024. A drift in the
  authoritative list between Y.Y1's catalog snapshot and Y.Y2's
  evaluator can either over-approve (false-positive AA pass) or
  under-approve (false-negative POA&M emission). The text-extraction
  step (`scripts/extract-cjis-policy.mjs`) reads the PDF; a typo or
  layout-OCR error in the factor list propagates silently.
- **Category**: authoritative-source drift.
- **Severity**: high (correctness signal on the highest-stakes
  CJIS control).
- **Likelihood**: med — per-revision drift is small (1-2 factor
  rewordings per release) but the operational consequence is
  immediate.
- **Impact**: a misclassified factor produces either an
  unjustified POA&M (operator wastes triage cycles) or an
  unjustified clean-pass (CSP ships an attestation that fails the
  next CJIS audit cycle).
- **Mitigation**: Y.Y1 extractor pins the factor-list block by
  XPath/text-anchor pair (`anchor_start = "5.6.2.2.1"`,
  `anchor_end = "5.6.2.2.2"`); extracts the seven categories
  verbatim into `data/cjis-policy-v5.9.5-catalog.json
  aa_factor_categories[]`; emits a SHA-256 of the extracted block
  pinned in CHANGELOG. Y.Y2's `core/cjis-aa-detector.ts` loads
  the categories from the signed snapshot and refuses to run if
  `aa_factor_categories.length !== 7` (the floor for v5.9.5).
  Test fixture `tests/fixtures/cjis-aa-factor-list-v5.9.5.json`
  pins the exact list. Adversarial test asserts that adding a
  spurious "(8) SMS one-time password" entry to the catalog
  triggers a typed `INVALID_AA_FACTOR_CATEGORY` error rather than
  a silent pass. Cross-references slice **Y.Y1** + **Y.Y2** + the
  catalog snapshot at `data/cjis-policy-v5.9.5-catalog.json`.
- **Owner**: AA-detector maintainer (Y.Y2 owner).
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.3 (verbatim quote of the
  factor list) + §16 (AA factor decision table); CJIS Security
  Policy v5.9.5 §5.6.2.2.1.

### Y-X3 — IRS Publication 1075 revision drift (Rev. 11-2021 → Rev. 11-2024/2025)

- **Description**: IRS Pub 1075 is typically re-published every
  3-5 years; the current version is Rev. 11-2021. The IRS Office
  of Safeguards has signalled (per the IRS Safeguards Program
  page accessed 2026-06-07) that a NIST 800-53 Rev 5 re-mapping
  refresh is in progress. A new revision (anticipated as
  "Rev. 11-2024" or "Rev. 11-2025") would re-number sections,
  modify the control crosswalk, and potentially change SSR
  reporting cadence or template. Y.Y3's catalog and Y.Y4's SSR
  emitter would emit stale references if not updated.
- **Category**: authoritative-source drift.
- **Severity**: high (a stale Pub 1075 reference can cause the
  IRS Office of Safeguards to reject the SSR on receipt).
- **Likelihood**: high — the IRS typically pre-announces revisions
  60-90 days in advance via the safeguards mailing list, but a
  CSP not subscribed will miss it.
- **Impact**: rejected SSR → IRS Office of Safeguards may
  withhold approval of FTI receipt → CSP customer (state agency)
  loses authorisation to receive FTI from the IRS → cascading
  contractual / customer-impact event.
- **Mitigation**: Y.Y3 catalog snapshot embeds
  `publication_revision = "Rev. 11-2021"`,
  `irs_safeguards_publication_date = "2021-11"`,
  `next_anticipated_revision = "2024 or 2025 — pending NIST 800-53 r5 re-mapping"`,
  `irs_safeguards_mailing_list_subscription_recommended = true`.
  CI cron weekly re-fetches the IRS Pub 1075 PDF URL
  (`https://www.irs.gov/pub/irs-pdf/p1075.pdf` and the utility
  mirror at `https://www.irs.gov/pub/irs-utl/p1075.pdf`) + diffs
  SHA-256 against the pinned snapshot; mismatch pages the team
  via PagerDuty per `core/notify.ts`. Strict mode refuses to run
  if the snapshot is more than 365 days old (annual SSR cycle).
  Operator runbook documents subscription to the IRS Safeguards
  mailing list (`safeguardreports@irs.gov` reply-list) +
  quarterly check of the IRS Safeguards page. CHANGELOG entry
  per Pub 1075 revision bump. Cross-references slice **Y.Y3** +
  **Y.Y4**.
- **Owner**: IRS-1075 catalog maintainer (Y.Y3 owner).
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.5 + §2.9; IRS Publication 1075
  Rev. 11-2021 cover page; IRS Safeguards Program page
  (https://www.irs.gov/privacy-disclosure/safeguards-program,
  accessed 2026-06-07).

### Y-X4 — IRS Safeguards Computer Security Evaluation Matrix (SCSEM) platform-coverage additions

- **Description**: The IRS Office of Safeguards publishes
  platform-specific SCSEMs as Excel workbooks (one per platform:
  Windows 2019, Windows 2022, RHEL 8, RHEL 9, AWS, Azure, GCP,
  Oracle Database, Microsoft SQL Server, Cisco IOS, Palo Alto
  PAN-OS, etc.). New SCSEMs are added when the IRS audits a new
  platform class; existing SCSEMs are revised on a 12-24 month
  cadence. The SCSEM catalog Y.Y3 cross-walks IS pinned by file
  identifier (e.g. `AWS-SCSEM-1.2.xlsx`, `Azure-SCSEM-1.1.xlsx`).
  A new SCSEM (e.g. `GCP-SCSEM-1.0.xlsx`) or a revised SCSEM
  (e.g. `AWS-SCSEM-1.3.xlsx`) would not appear in the cross-walk
  unless Y.Y3 is re-run.
- **Category**: authoritative-source drift.
- **Severity**: med (catalog completeness; not immediate ship-blocker).
- **Likelihood**: high — the SCSEM library has visibly expanded
  every 6-12 months since 2018.
- **Impact**: a platform the operator runs on (e.g. AWS GovCloud
  on a newly-released GovCloud region) does not have its
  configuration cross-walked to a SCSEM; the operator must
  manually map; CHANGELOG entry per SCSEM is required.
- **Mitigation**: Y.Y3 catalog records
  `scsem_inventory[]` per `scsem_id`, `file_path`,
  `last_observed_at`, `irs_publication_date`,
  `expected_control_count`. CI cron monthly re-fetches the IRS
  Safeguards SCSEM listing page
  (`https://www.irs.gov/privacy-disclosure/safeguards-program`)
  and lists current SCSEMs; mismatch surfaces a tracker UI
  banner. Operator runbook documents how to import a new SCSEM
  (operator downloads the .xlsx, places at
  `cloud-evidence/data/scsem/`, re-runs
  `scripts/extract-irs-1075.mjs`). The catalog snapshot's
  signature covers the SCSEM inventory; a missing platform is
  surfaced as `REQUIRES-OPERATOR-INPUT: scsem-platform-<name>-missing`.
  CHANGELOG entry per SCSEM addition / revision. Cross-references
  slice **Y.Y3** + **Y.Y4** (SSR Section 3 control status).
- **Owner**: IRS-1075 catalog maintainer (Y.Y3 owner).
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.19 (SCSEM table); IRS
  Safeguards Program page; IRS IRM 11.3.36 §3.

### Y-X5 — NCIC Operating Manual revision lag affects audit-retention floor inheritance

- **Description**: CJIS §5.4.7 cross-references the NCIC Operating
  Manual for audit-retention semantics ("audit records [...] no
  longer needed for administrative, legal, audit, or other
  operational purposes"). The NCIC Operating Manual is a non-
  public, restricted-distribution document maintained by the FBI;
  revisions are issued via CJIS Advisory Process bulletins. A
  retention-floor change in the NCIC Operating Manual (e.g.
  raising the minimum from 1 year to 18 months for III queries)
  would not be visible to LOOP-Y's PDF-based extractor; the
  operator would discover the gap only at audit. Y.Y1 must
  default conservatively.
- **Category**: authoritative-source drift.
- **Severity**: med (retention is a measurable engineering
  control; under-retention is correctable post-discovery but with
  reputational damage).
- **Likelihood**: low — NCIC Operating Manual changes are
  infrequent (every 3-5 years).
- **Impact**: an under-retention finding at audit can require
  the CSP to re-architect log storage; ConMon drift; LOOP-E.E1
  re-baseline.
- **Mitigation**: Y.Y1 catalog defaults `audit_retention_floor_days = 365`
  (the v5.9.5 §5.4.7 minimum) and emits a
  `REQUIRES-OPERATOR-INPUT: ncic-retention-floor-override` field
  per CSO. The operator runbook documents that the CSO is the
  authoritative source for the floor and that the operator must
  confirm with each customer agency's CSO whether the NCIC
  Operating Manual specifies a higher floor for the customer's
  specific use case (III, NICS, NSOR). Tracker UI captures the
  per-CSO confirmation as
  `cjis_cso_retention_confirmations(state, cso_email, floor_days,
  confirmation_date, confirmation_evidence_url)`. CHANGELOG
  entry per CSO confirmation. Cross-references slice **Y.Y1**
  + **Y.Y2**; cross-loop with **LOOP-E.E1** (ConMon retention
  baseline) and **LOOP-INV-S** (inventory log-asset tagging).
- **Owner**: CJIS catalog maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.6 + §2.8; CJIS Security
  Policy v5.9.5 §5.4.7; NCIC Operating Manual (restricted).

### Y-X6 — State CJIS supplement revision drift (Texas DPS, Massachusetts 803 CMR 7.00, Illinois LEADS, etc.)

- **Description**: Several states publish CJIS supplements that
  layer additional controls on top of the FBI baseline (the
  catalog never *removes* controls; state supplements are
  additive). Texas DPS publishes `RequirementCompanionDoc_v5-9-5.pdf`
  on a state cadence; Massachusetts 803 CMR 7.00 is a regulation
  amended through state administrative procedure; Illinois LEADS
  is published by the Illinois State Police. Each state's
  revision cadence is independent. Y.Y1's catalog snapshot is a
  union (FBI baseline ∪ per-state supplements); state-supplement
  drift produces stale per-state controls.
- **Category**: authoritative-source drift.
- **Severity**: med.
- **Likelihood**: high — at least one of the 50+ state
  supplements changes every quarter.
- **Impact**: a stale per-state catalog produces a stale POA&M
  recommendation against a customer agency in that state.
- **Mitigation**: Y.Y1 catalog records `state_supplements[]` with
  per-state `supplement_url`, `supplement_publication_date`,
  `supplement_sha256`. CI cron weekly re-fetches the major state
  supplement URLs (Texas DPS, Massachusetts, Illinois, Ohio,
  California, Florida, Pennsylvania); SHA-256 mismatch pages the
  team. Operator can declare additional state supplements via
  `cjis-state-supplements.yaml supplements[{state, url, type}]`.
  Tracker UI per-state banner when a supplement is more than 365
  days stale. CHANGELOG entry per state-supplement bump. The
  state-supplement registry at
  `cloud-evidence/data/cjis-state-supplements-registry.json`
  records all known supplements; the operator extends the
  registry as new states publish. Cross-references slice
  **Y.Y1** + future `Y.Y2-state-overlay` enhancement queued at
  the FIFTH-PASS audit.
- **Owner**: CJIS catalog maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.3 + §2.22; Texas DPS
  RequirementCompanionDoc_v5-9-5.pdf; Massachusetts 803 CMR 7.00
  (https://www.mass.gov/doc/803-cmr-700-criminal-justice-information-system-cjis-0/download,
  accessed 2026-06-07); Illinois LEADS Security Policy.

### Y-X7 — FedRAMP Marketplace badge format drift for "CJIS Compliant" / "IRS 1075 Compliant"

- **Description**: LOOP-Q.Q1 surfaces sector-overlay badges in the
  FedRAMP Marketplace metadata. The badge schema is owned by
  FedRAMP PMO + GSA; format changes are infrequent but
  meaningful (e.g. an added `attestation_id` field, a renamed
  `compliance_regime` enumeration value, a tightened expiration
  format). Y.Y2 emits the AA evidence envelope; Y.Y4 emits the
  SSR envelope; both feed Q.Q1. A schema drift in Q.Q1's reader
  would render the LOOP-Y badges invisible in the Marketplace.
- **Category**: authoritative-source drift.
- **Severity**: low (operator-visible but not audit-blocking).
- **Likelihood**: low.
- **Impact**: badge missing from Marketplace listing reduces
  customer-discovery; no compliance impact.
- **Mitigation**: Y.Y2 + Y.Y4 envelopes are JSON; adding fields
  is backward-compatible; Q.Q1 reads named fields by selector.
  Tracker UI surfaces `marketplace_badge_status` per slice with
  a `last_badge_render_at` timestamp; if Q.Q1 stops rendering
  the badge for more than 30 days, the operator is notified.
  CHANGELOG entry per Q.Q1-required field addition. Cross-
  references slice **Y.Y2** + **Y.Y4** + **LOOP-Q.Q1**.
- **Owner**: Marketplace integration maintainer (Q.Q1).
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.2 line item 16 + §11.2;
  FedRAMP Marketplace public listing schema.

### Y-X8 — CJIS shall-statement extraction OCR errors

- **Description**: The CJIS Security Policy PDF is the canonical
  source. The PDF is well-formed (text-layer present, not a
  scanned image) but contains complex formatting — bullet
  hierarchies, tables, footnotes, page-break artifacts. A naive
  PDF-text extractor can produce errors: "shall" rendered as
  "shall," with a stray comma; bullet markers (●, ►, *) merged
  with the next word; page footers ("CJIS Security Policy
  v5.9.5") concatenated mid-paragraph. Each such error in a
  shall-statement produces either an unparseable control or a
  false control with paraphrased text.
- **Category**: catalog correctness.
- **Severity**: high (catalog quality directly drives evaluator
  correctness).
- **Likelihood**: med — PDF text-extraction errors are common
  with complex policy documents.
- **Impact**: false-positive controls (shall-statement
  misattributed to wrong section); false-negative controls (a
  shall-statement parsed as plain text and dropped).
- **Mitigation**: `scripts/extract-cjis-policy.mjs` uses a
  multi-pass extractor: (a) `pdf-parse` for raw text, (b)
  per-section anchor matching on Section IDs (`§5.5.1`,
  `§5.6.2.2`, etc.), (c) per-shall-statement verbatim quoting
  with a length-floor (a shall-statement < 30 characters likely
  truncated; flag for operator review). Test fixture pins 30+
  shall-statements with byte-exact expected text. Adversarial
  test injects a known truncation case (a partial sentence) and
  asserts the extractor flags it as `REQUIRES-OPERATOR-INPUT:
  potential-truncation-<section-id>`. Operator runbook documents
  the cross-check workflow: operator opens the PDF at the
  cited page and re-affirms the verbatim text matches the
  catalog snapshot. CHANGELOG entry per re-extraction bump.
  Cross-references slice **Y.Y1**.
- **Owner**: CJIS extractor maintainer (Y.Y1).
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2 (every verbatim quote MUST be
  re-affirmed at slice-implementation time per §33); CJIS PDF
  source.

### Y-X9 — NIST 800-53 r5 cross-walk ambiguity in CJIS catalog

- **Description**: CJIS v5.9.5 includes an Appendix G cross-walk to
  NIST 800-53 Rev 5, but some shall-statements span multiple
  controls (e.g. §5.6.2.2 AA maps to IA-2(1), IA-2(2), IA-2(11),
  IA-2(12) collectively; not a single 1-to-1 mapping). Other
  shall-statements (e.g. §5.13.7 BYOD) have no direct NIST r5
  control. A naive cross-walk emits a 1-to-1 map and silently
  drops the multi-control or unmapped cases.
- **Category**: catalog correctness.
- **Severity**: med (cross-walk completeness affects 3PAO trust;
  not a Y-level ship-blocker if cross-walk is partial and
  acknowledged).
- **Likelihood**: high — verified during the LOOP-Y-SPEC.md §2
  authoring pass.
- **Impact**: under-mapped controls hide CJIS requirements from
  the LOOP-A.A1 POA&M / LOOP-G.G1 SSP cross-walk; over-mapped
  controls cause double-counting in the LOOP-B.B1 risk score.
- **Mitigation**: Y.Y1 catalog records
  `nist_800_53_r5_mapping[]` per shall-statement (array of
  control IDs, not a single field). Each mapping entry carries
  `confidence ∈ {"high", "medium", "low"}` with `high` reserved
  for cases where the CJIS appendix names the NIST control
  explicitly. `low` confidence triggers a tracker UI banner.
  Operator can override via `cjis-nist-mapping-overrides.yaml`.
  Unmapped shall-statements emit
  `coverage:nist-mapping-absent-<cjis-id>` for visibility.
  CHANGELOG entry per mapping bump. Cross-references slice
  **Y.Y1** + **LOOP-B.B1** (risk score) +
  `core/control-benchmark.ts`.
- **Owner**: CJIS catalog maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.21; CJIS v5.9.5 Appendix G.

### Y-X10 — IRS Pub 1075 NIST 800-53 cross-walk uses Rev 4 selectively

- **Description**: IRS Pub 1075 Rev. 11-2021 was authored against
  NIST 800-53 Rev 4 (and selectively Rev 5; the IRS Office of
  Safeguards has not yet published a full Rev 5 re-mapping —
  acknowledged in Pub 1075 §9.3 transitional language). LOOP-Y
  must emit *both* mappings because conflating them produces a
  false-positive coverage claim. The cross-walk table is
  Appendix B of Pub 1075; transitional cases are footnoted.
- **Category**: catalog correctness.
- **Severity**: high (cross-walk correctness drives 3PAO
  evidence chain validity).
- **Likelihood**: high — every implementer hits this on first
  Y.Y3 build.
- **Impact**: a Rev 5-only cross-walk drops controls IRS still
  references against Rev 4 IDs; a Rev 4-only cross-walk misses
  Rev 5 control enhancements LOOP-A.A1 emits POA&Ms against.
- **Mitigation**: Y.Y3 catalog emits TWO independent cross-walk
  arrays per Pub 1075 control: `nist_800_53_r4_mapping[]` and
  `nist_800_53_r5_mapping[]`. Each entry includes
  `source_appendix_pin = "Pub 1075 App B"`,
  `source_rev = "4" | "5"`,
  `transitional_note: string | null`. The SSR emitter (Y.Y4)
  reads both; the .docx renders both side-by-side for the
  IRS Office of Safeguards reviewer. Open question OQ-Y-04
  tracks the IRS Office of Safeguards confirmation that Rev 5
  fully replaces Rev 4 (when that confirmation lands, Y.Y3
  catalog version-bumps to drop Rev 4). CHANGELOG entry per
  bump. Cross-references slice **Y.Y3** + **Y.Y4** + the open
  question OQ-Y-04 in LOOP-Y-SPEC.md §9.
- **Owner**: IRS-1075 catalog maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.21 + §9 OQ-Y-04; IRS Pub
  1075 Rev. 11-2021 Appendix B + §9.3.

### Y-X11 — CJIS catalog shall-statement count regression

- **Description**: CJIS v5.9.5 contains approximately 250-300
  enumerable shall-statements (rough count from §5.1 through
  §5.13). A regression in the extractor (e.g. a missed bullet
  level, a mis-anchored section boundary) can silently drop
  10-50 statements; the result looks plausibly complete but
  fails to flag the missing controls when the 3PAO compares
  against the FBI-published table.
- **Category**: catalog correctness.
- **Severity**: high.
- **Likelihood**: med.
- **Impact**: silent under-coverage. The CSP ships an
  attestation that omits controls; the audit catches them.
- **Mitigation**: Y.Y1 extractor asserts
  `shall_statement_count >= 220` (50-control floor below the
  expected 270 average). The exact expected count for v5.9.5
  is pinned in `data/cjis-policy-v5.9.5-expected-counts.json`
  per Policy Area: `§5.1: 6, §5.2: 25, ..., §5.13: 18`.
  Adversarial test corrupts one Policy-Area expected-count
  value and asserts the extractor fails with a typed error.
  CI cron re-runs the extractor weekly + diffs the counts;
  any decrease pages the team. Cross-references slice
  **Y.Y1** + the per-Policy-Area count fixture.
- **Owner**: CJIS extractor maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §17 (catalog snapshot schema);
  CJIS v5.9.5 Table of Contents.

### Y-X12 — IRS 1075 §9 (Computer Security) control enumeration drift

- **Description**: Pub 1075 §9 is the Mandatory Computer
  Security section — encryption, access control, audit, system
  integrity. The section is structured as numbered sub-sections
  (§9.1 through §9.4 in Rev. 11-2021). The IRS occasionally
  re-numbers or adds sub-sections when Federal cryptographic
  standards shift (e.g. when FIPS 140-3 superseded 140-2 in
  Sep 2026, §9.1 re-cited the standard). Y.Y3 must track these
  changes; a stale §9 enumeration produces a misaligned SSR.
- **Category**: catalog correctness.
- **Severity**: high (Y.Y4's SSR Section 3 directly enumerates
  §9 controls).
- **Likelihood**: med.
- **Impact**: a stale §9 enumeration drops the FIPS 140-3
  reference and emits an SSR claiming compliance against the
  superseded 140-2 standard; IRS Office of Safeguards flags.
- **Mitigation**: Y.Y3 catalog records §9 sub-section anchors
  with verbatim text; the extractor asserts the full §9 anchor
  chain is present + the FIPS reference text matches one of
  `"FIPS 140-2"` or `"FIPS 140-3"`. CI cron monthly diffs the
  Pub 1075 PDF; mismatch pages the team. Cross-references
  slice **Y.Y3** + **Y.Y4** SSR Section 3.
- **Owner**: IRS-1075 catalog maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.16; IRS Pub 1075 §9; FIPS
  140-3 standard.

### Y-X13 — SCSEM matrix drift (per-platform control IDs change between SCSEM revisions)

- **Description**: Each SCSEM is an Excel workbook with a
  unique per-platform control numbering scheme (e.g.
  AWS-SCSEM-1.2.xlsx uses `AC-2-CIS-1.1`, `AC-2-CIS-1.2`, ...;
  the next revision AWS-SCSEM-1.3 may renumber to
  `AC-2-CIS-2.1`, etc.). Y.Y3's cross-walk pins specific SCSEM
  IDs; a revision causes downstream cross-walks (Y.Y4 SSR
  Section 3, LOOP-A.A1 POA&M findings) to reference dead IDs.
- **Category**: catalog correctness.
- **Severity**: med.
- **Likelihood**: high — per-SCSEM revision cycles are 12-24
  months and almost always include renumbering.
- **Impact**: dead-ID references in the SSR confuse the IRS
  Office of Safeguards reviewer; rejection or follow-up
  request.
- **Mitigation**: Y.Y3 catalog stores
  `scsem_inventory[{scsem_id, version, checksum_path,
  control_id_mapping_to_prior_version}]`; on SCSEM bump,
  operator runs `scripts/extract-irs-1075.mjs --refresh-scsem`
  which re-reads the new SCSEM + emits a delta report
  showing per-control-ID changes. Tracker UI surfaces the
  delta before Y.Y3 ships the next snapshot. CHANGELOG entry
  per SCSEM revision. Cross-references slice **Y.Y3** + **Y.Y4**.
- **Owner**: IRS-1075 catalog maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.19; IRS SCSEM library page.

### Y-X14 — Catalog snapshot signature/provenance loss across major version migrations

- **Description**: When CJIS v5.9.5 → v6.0 (or Pub 1075
  Rev. 11-2021 → Rev. 11-2024) lands, the new catalog snapshot
  is signed with the current Ed25519 key. The PRIOR snapshot's
  signature continues to verify only if the historical key is
  preserved in the signing-key registry. Same risk class as
  W-X9, T-X11, R-X4, S-X6.
- **Category**: signing / provenance.
- **Severity**: med (impacts 3PAO audit trail for historical
  evidence; not run-time blocker).
- **Likelihood**: med — comes due each major version bump.
- **Impact**: 3PAO cannot re-verify a historical CJIS or IRS
  1075 evidence envelope; audit trail breaks.
- **Mitigation**: Catalog signing keys go through the tracker's
  `GET /api/sign/public-keys` historical registry (inherits
  pattern from B-X3); every snapshot records `signing_key_id`;
  loader verifies against the registry. Operator runbook
  documents quarterly key rotation procedure. CHANGELOG entry
  per key rotation. Cross-references slice **Y.Y1** + **Y.Y3**;
  cross-loop with `LOOP-B-RISKS.md` B-X3.
- **Owner**: Tracker / signing infra maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §17 + §19 + §37; LOOP-W-RISKS.md
  W-X9 pattern.

### Y-X15 — IdP factor-type addition (AWS / GCP / Entra ID add new factors mid-cycle)

- **Description**: AWS (Cognito + IAM Identity Center), GCP
  (Workforce Identity Federation + Identity-Aware Proxy), and
  Microsoft Entra ID periodically add new authentication factor
  types: passkeys, device-bound passkeys, Windows Hello for
  Business, FIDO2 security keys, certificate-based
  authentication, Authenticator Lite, Temporary Access Pass,
  etc. Each factor type may or may not satisfy CJIS §5.6.2.2.1.
  Y.Y2's evaluator MUST map each detected factor type to the
  CSO-approved AA category. An unmapped factor causes the
  evaluator to silently treat it as non-conformant — a false-
  positive POA&M — or to error out.
- **Category**: AA detector correctness.
- **Severity**: high (operator trust + churn from spurious
  POA&Ms).
- **Likelihood**: high — IdPs release new factor types every
  3-6 months.
- **Impact**: false-positive POA&Ms (operator wastes triage
  cycles); false-negative pass (operator ships an AA
  attestation that includes a non-CSO-approved factor).
- **Mitigation**: Y.Y2 `core/cjis-aa-detector.ts` reads a
  per-provider factor-to-AA-category map from
  `data/cjis-aa-factor-map.json` (operator-extendable); each
  entry includes `factor_type_id`, `provider`,
  `aa_category_v5_9_5` ∈ {biometric, digital-cert, smart-card,
  software-token, hardware-token, paper-token, out-of-band},
  `phishing_resistant: boolean`, `provenance_url`,
  `last_verified_at`. When the detector encounters an
  unmapped factor type, it emits
  `REQUIRES-OPERATOR-INPUT: aa-factor-map-missing-<provider>-<factor_type>`
  and treats the factor as unknown (NOT silently pass).
  Tracker UI surfaces the mapping; operator confirms +
  signs. CI cron weekly re-fetches each provider's factor
  documentation URL + flags additions. CHANGELOG entry per
  factor-map bump. Cross-references slice **Y.Y2** + the
  factor decision table at LOOP-Y-SPEC.md §16.
- **Owner**: AA-detector maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §16; CJIS §5.6.2.2.1 (verbatim
  list); AWS Cognito MFA documentation; Entra ID Authentication
  Methods Policy documentation.

### Y-X16 — Phishing-resistance attestation absent from IdP

- **Description**: CJIS v5.9.5 §5.6.2.2 does NOT explicitly
  require phishing resistance (the policy predates the OMB
  M-22-09 zero-trust phishing-resistant MFA push). The CJIS
  Advisory Process has signalled (per minutes accessed
  2026-06-07) that v6.0 will tighten this. Meanwhile, Y.Y2's
  evaluator must NOT over-claim phishing resistance for IdP
  factors that don't advertise it. An IdP factor that is
  phishing-resistant in practice (e.g. FIDO2 hardware token)
  but has no metadata claim cannot be auto-classified as
  phishing-resistant.
- **Category**: AA detector correctness.
- **Severity**: med.
- **Likelihood**: high — most IdPs ship factor metadata
  without explicit phishing-resistance flags.
- **Impact**: under-classification produces a misleading SSR
  Section 3 control narrative; over-classification produces
  audit risk under v6.0 when that requirement is hardened.
- **Mitigation**: Y.Y2 `core/cjis-aa-detector.ts` reads
  `phishing_resistant` only from the factor-map (Y-X15
  mitigation); never infers from name or vendor label. The
  detector records `phishing_resistance_evidence` per match:
  `{source: "factor-map" | "operator-attestation" | "absent",
  evidence_url, last_observed_at}`. When absent, the detector
  emits `coverage:phishing-resistance-not-attested-<factor>`
  and the SSR / POA&M render accordingly. Cross-references
  slice **Y.Y2** + cross-loop with **LOOP-X** (zero-trust
  phishing-resistant MFA pattern; Y.Y2 borrows X's evaluator
  primitives).
- **Owner**: AA-detector maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.4 (LOOP-X distinction) +
  §16; OMB M-22-09; CISA Phishing-Resistant MFA guidance.

### Y-X17 — Biometric-on-device attestation parsing fragility

- **Description**: Mobile biometric factors (Apple Face ID,
  Android Fingerprint, Windows Hello for Business) are
  evaluated through device-side attestation (Apple App
  Attest, Android Key Attestation, TPM-2.0 attestation). The
  attestation payload formats vary by platform + version and
  occasionally change (Apple App Attest v2 → v3, etc.). A
  parsing failure produces an "unverified" classification
  even when the factor is fully CSO-approved.
- **Category**: AA detector correctness.
- **Severity**: med.
- **Likelihood**: med — attestation format changes are
  announced 90+ days in advance via platform release notes.
- **Impact**: false-negative pass classification → spurious
  POA&Ms → operator triage cost.
- **Mitigation**: Y.Y2 uses per-platform attestation parsers
  in `core/biometric-attestation.ts` with version
  discriminators; CI cron weekly re-fetches platform
  release notes (Apple developer release notes, Android
  Key Attestation documentation, Microsoft TPM Attestation
  docs); attestation-format additions flag a per-platform
  parser bump. Operator runbook documents the per-platform
  update workflow. CHANGELOG entry per parser bump. Cross-
  references slice **Y.Y2**.
- **Owner**: AA-detector maintainer.
- **Status**: open.
- **References**: Apple App Attest documentation; Android Key
  Attestation; Microsoft Platform Crypto Provider docs.

### Y-X18 — Conditional Access per-app rule evaluation (Entra ID specific)

- **Description**: Microsoft Entra ID Conditional Access is
  evaluated per-application via policy rules that combine
  signals (factor, location, device compliance, sign-in risk).
  CJIS §5.6.2.2 anchors on "non-secure location or non-
  organizational device". A naive evaluator that only checks
  "MFA enabled" misses Conditional Access rules that exclude
  specific user populations or trusted locations from MFA.
- **Category**: AA detector correctness.
- **Severity**: high (false-positive AA pass when Conditional
  Access rules permit unauthenticated access from "trusted
  IP" — common operator misconfiguration).
- **Likelihood**: med — observed in CSP-customer Entra ID
  tenants during AZ-IAM-MFA implementation.
- **Impact**: an AA evidence envelope passes evaluation while
  the actual policy permits non-MFA access from some
  populations; audit finds the gap.
- **Mitigation**: Y.Y2 `providers/azure/cjis-aa.ts` reads
  Conditional Access policies via Graph
  `/policies/conditionalAccessPolicies` and evaluates EACH
  policy against CJIS §5.6.2.2 requirements; surfaces
  per-policy `cjis_aa_evaluation: 'conformant' |
  'non-conformant' | 'compensating-control'`. Adversarial test
  pins a Conditional Access policy with a trusted-IP exclusion
  + asserts the evaluator surfaces a non-conformant verdict
  (NOT silently pass on the org-wide MFA-enabled signal).
  Cross-references slice **Y.Y2** +
  `providers/azure/cjis-aa.ts` + adversarial test fixture.
- **Owner**: AA-detector Azure maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.2 line 7 + §16; Entra ID
  Conditional Access documentation.

### Y-X19 — FTI inventory false-negative (asset not tagged data_classes ⊇ {"FTI"})

- **Description**: Y.Y4 reads `inventory.assets[].data_classes[]`
  to scope which assets receive FTI evaluation. If an
  inventory asset is missing the `"FTI"` tag — operator
  oversight, missing tag-propagation in a downstream pipeline,
  or a newly-created asset prior to first tag-sweep — Y.Y4
  silently omits it from the SSR. The omitted asset still
  processes FTI; the SSR is materially inaccurate.
- **Category**: FTI / CJI inventory boundary.
- **Severity**: high (statutory: SSR Section 1 inventory must
  reflect ALL systems that store, process, or transmit FTI).
- **Likelihood**: high — operator-tagging is brittle; LOOP-INV-S
  coverage report has historically surfaced 1-3% untagged
  asset rate per refresh.
- **Impact**: SSR understates FTI footprint; IRS Office of
  Safeguards rejects or flags; CSP customer loses FTI receipt
  authorisation.
- **Mitigation**: Y.Y4 `core/irs-ssr-emitter.ts` reads
  `inventory.coverage.data_class_tagging_rate` (LOOP-INV-S
  emitted field); if rate < 95%, refuses to emit the SSR in
  strict mode + emits `REQUIRES-OPERATOR-INPUT:
  fti-inventory-tagging-coverage-low`. Tracker UI surfaces a
  per-asset "FTI-eligible-but-untagged" candidate list using
  heuristic signals (asset name contains `tax`, `fti`, `1099`,
  `w2`, `irs`, `1040`; asset connects to a data store known to
  hold tax data; asset is in a Federal-customer subscription).
  The operator confirms / rejects each candidate via tracker
  UI; rejections persist with `provenance: operator-confirmed-not-fti`.
  CHANGELOG entry per tagging-sweep. Cross-references slice
  **Y.Y4** + **LOOP-INV-S** coverage + LOOP-V (HIPAA PHI
  tagging pattern reused).
- **Owner**: SSR emitter maintainer (Y.Y4) + INV-S maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.4 (LOOP-INV-S row) + §20
  (SSR envelope schema); IRS Pub 1075 §4 + §7.

### Y-X20 — CJI inventory false-negative (asset not tagged data_classes ⊇ {"CJI"})

- **Description**: Symmetric to Y-X19 but for CJI. Y.Y2 reads
  `inventory.assets[].data_classes ⊇ {"CJI"}` to scope AA
  evaluation. An untagged CJI-handling asset receives no AA
  evaluation; the CSP ships an AA attestation that excludes
  the asset; the FBI CJIS audit finds the gap.
- **Category**: FTI / CJI inventory boundary.
- **Severity**: high.
- **Likelihood**: high (same tagging brittleness as Y-X19).
- **Impact**: AA attestation understates CJI footprint; FBI
  CJIS audit flags; state CSO escalates to CSA leadership.
- **Mitigation**: Y.Y2 `core/cjis-aa-detector.ts` reads
  `inventory.coverage.data_class_tagging_rate`; if rate <
  95% for the CSP's CJI-bearing subscriptions, refuses to
  emit AA evidence in strict mode + emits
  `REQUIRES-OPERATOR-INPUT: cji-inventory-tagging-coverage-low`.
  Heuristic signals: asset name contains `cjis`, `ncic`, `iii`,
  `nibrs`, `cor`, `dna`, `afis`, `nsor`, `nics`; asset in a
  customer-agency subscription known to be CJIS-mission;
  asset accesses a data store classified as CJI. Operator
  confirms / rejects via tracker UI;
  `provenance: operator-confirmed-not-cji` persists. CHANGELOG
  entry per sweep. Cross-references slice **Y.Y2** +
  **LOOP-INV-S**.
- **Owner**: AA-detector maintainer (Y.Y2) + INV-S maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.4 (LOOP-INV-S row) + §18
  (AA evaluation record schema); CJIS §5.6.2.2.

### Y-X21 — Inventory data-class taxonomy collisions ("CJI" vs "CJI-Adjacent" vs "Restricted")

- **Description**: LOOP-INV-S owns the `data_classes[]` taxonomy.
  When LOOP-V (HIPAA) introduces "PHI" and LOOP-U (privacy)
  introduces "PII", the namespace gets crowded. An asset
  tagged `["PII", "Restricted"]` may or may not be CJI; an
  asset tagged `["FTI", "PII"]` triggers both Y.Y4 and LOOP-U
  paths. The risk is two-fold: (a) overlap creates
  redundant POA&Ms; (b) the taxonomy may drift and a value
  like `"CJI"` may be renamed to `"CriminalJusticeInformation"`
  silently.
- **Category**: FTI / CJI inventory boundary.
- **Severity**: med.
- **Likelihood**: med.
- **Impact**: redundant or missed scoping.
- **Mitigation**: Y.Y2 + Y.Y4 read from a pinned taxonomy
  enum (`docs/inventory-data-class-enum.md` owned by
  LOOP-INV-S); refuse to run if the inventory uses a value
  outside the enum. POA&M emission deduplicates by
  `(asset_id, control_id)` pair so a dual-tag asset emits
  one POA&M per control. CHANGELOG entry per enum change.
  Cross-references slice **Y.Y2** + **Y.Y4** + LOOP-INV-S
  coverage contract.
- **Owner**: AA-detector + SSR emitter maintainers.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.4; LOOP-INV-S
  `core/inventory-coverage.ts` data-class section.

### Y-X22 — SSR submission deadline miss (Jan 31 federal; staggered state through Nov 30)

- **Description**: The IRS Office of Safeguards requires SSR
  submission by January 31 for federal agencies, with
  staggered due dates for state agencies extending through
  November 30 (per the IRS Safeguards Program page accessed
  2026-06-07). A CSP whose customer is a state agency with
  (say) a June 30 due date must deliver the SSR-ready
  artifact in time for the agency to submit. If Y.Y4 fails
  to emit on time, the agency misses the deadline; FTI
  receipt authorisation is at risk.
- **Category**: SSR submission lifecycle.
- **Severity**: high (statutory deadline; IRS Office of
  Safeguards monitors).
- **Likelihood**: med — operators routinely under-schedule
  the SSR cycle.
- **Impact**: late SSR → IRS Office of Safeguards inquiry →
  CSP customer loses FTI receipt authorisation → contractual
  cascade.
- **Mitigation**: Y.Y4 tracker DB
  `irs_ssr_submissions(customer_agency_id, due_date,
  submitted_date, status)` schedules per-customer reminders
  at T-90, T-60, T-30, T-14, T-7, T-3, T-1 days; UI
  countdown; email + Slack/PagerDuty notification via
  `core/notify.ts`. Per-state due-date defaults are pinned
  in `data/irs-ssr-state-due-dates.json` (operator can
  override). Strict mode refuses to skip a customer whose
  due date is < 30 days out. CHANGELOG entry per due-date
  bump. Cross-references slice **Y.Y4** +
  `core/notify.ts` + the open question OQ-Y-05 (IRS
  Office of Safeguards response SLA) in LOOP-Y-SPEC.md
  §9.
- **Owner**: SSR emitter maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.14 + §20; IRS Safeguard
  Security Report page
  (https://www.irs.gov/privacy-disclosure/safeguard-security-report,
  accessed 2026-06-07).

### Y-X23 — First-year SSR (no prior-year acceptance .docx)

- **Description**: The IRS Safeguards page guidance is "Do not
  start a new SSR using a blank template; use the accepted
  prior year SSR as a starting point." For a CSP customer's
  first SSR (e.g. a new state agency that has just begun
  receiving FTI), there IS no prior-year acceptance .docx.
  Y.Y4's emitter must handle this gracefully — generating a
  first-year SSR from the IRS-published blank template +
  surfacing this as an operator-acknowledged first-year mode.
- **Category**: SSR submission lifecycle.
- **Severity**: med.
- **Likelihood**: med (first-year filings happen at every new
  customer onboarding).
- **Impact**: emitter crashes or emits an invalid SSR if
  first-year mode is unhandled.
- **Mitigation**: Y.Y4 supports `--first-year-ssr` flag with
  explicit operator confirmation; emitter reads
  `data/irs-ssr-template-blank.docx` (the IRS-published
  blank template at
  `https://www.irs.gov/pub/irs-utl/SSRTemplate.docx`) as the
  starting point; CHANGELOG documents the first-year
  workflow; tracker UI captures `first_year_attestation_signed_by`,
  `first_year_attestation_date`. Adversarial test asserts
  that omitting the flag while
  `prior_year_acceptance_docx_path` is also missing emits
  a typed `MISSING_PRIOR_YEAR_OR_FIRST_YEAR_FLAG` error.
  Cross-references slice **Y.Y4** + LOOP-Y-SPEC.md §20
  SSR envelope schema.
- **Owner**: SSR emitter maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.14; IRS Safeguard Security
  Report page.

### Y-X24 — Section 3 control-status enumeration drift (SSR template format change)

- **Description**: The SSR template (Y.Y4 reads
  `data/irs-ssr-template-blank.docx`) is owned by the IRS
  Office of Safeguards. Template format changes (added
  sections, renamed columns, changed enumeration values for
  control status: "Compliant" vs "Non-Compliant" vs "POA&M"
  vs "Compensating Control" vs "Not Applicable") happen
  every 2-3 years. A stale template renders an SSR the IRS
  rejects on receipt.
- **Category**: SSR submission lifecycle.
- **Severity**: high.
- **Likelihood**: med.
- **Impact**: rejected SSR; re-submission required; deadline
  risk (Y-X22).
- **Mitigation**: Y.Y4 records `ssr_template_version` per
  emit; CI cron monthly re-fetches
  `https://www.irs.gov/pub/irs-utl/SSRTemplate.docx` + diffs
  SHA-256 against the pinned version. Mismatch pages the
  team. Operator runbook documents the template-watch
  process. CHANGELOG entry per template bump. Cross-
  references slice **Y.Y4**.
- **Owner**: SSR emitter maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.20; IRS SSR template URL.

### Y-X25 — CAP / POA&M consolidation between SSR Section 3 and OSCAL POA&M (LOOP-A.A1)

- **Description**: SSR Section 3 enumerates Corrective Action
  Plans (CAPs) — IRS-format remediation tracking — that
  overlap with the OSCAL POA&M (LOOP-A.A1) flow. A single
  Pub 1075 control gap should be tracked in ONE place;
  duplicating produces inconsistent due dates + remediation
  status. Y.Y4 must consolidate.
- **Category**: SSR submission lifecycle.
- **Severity**: med.
- **Likelihood**: high — every operator hits this.
- **Impact**: divergent due dates between SSR and OSCAL POA&M;
  3PAO confusion.
- **Mitigation**: Y.Y4 reads OSCAL POA&M items via
  `core/oscal-poam.ts` filtered to
  `framework: "irs-pub-1075"`; emits SSR Section 3 CAPs by
  projecting POA&M items 1-to-1; tracker DB
  `irs_ssr_caps(ssr_id, poam_uuid, irs_status_enum)`
  enforces UNIQUE(ssr_id, poam_uuid). Adversarial test
  pins a duplicate-attempt scenario + asserts SQL UNIQUE
  rejects. Cross-references slice **Y.Y4** + **LOOP-A.A1**
  POA&M emitter.
- **Owner**: SSR emitter maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §20; IRS Pub 1075 §2.E.4.3.

### Y-X26 — Officer signature missing on SSR

- **Description**: The SSR is signed by the head of the
  receiving agency (or the head's designee). A CSP that
  emits the SSR on behalf of a customer agency cannot
  pre-sign the SSR — the agency head must apply the
  signature out-of-band. If Y.Y4 emits without a captured
  signature pathway, the operator may inadvertently submit
  an unsigned SSR.
- **Category**: SSR submission lifecycle.
- **Severity**: high (REO Rule 1.6: no auto-signing on
  behalf of another party).
- **Likelihood**: med — first-year operators most likely to
  miss.
- **Impact**: IRS rejects on receipt; deadline risk (Y-X22).
- **Mitigation**: Y.Y4 emits the SSR .docx with an unsigned
  signature block + a tracker checklist for the operator
  to coordinate signature collection; the JSON envelope
  records `signature_block_status: "unsigned" | "signed"`
  + `signing_official: {name, title, agency, signed_at}`.
  Adversarial test asserts the JSON envelope refuses to
  flip `status: "submitted"` until `signature_block_status
  === "signed"`. Tracker UI surfaces a "ready to sign"
  prompt with email-the-official-with-document workflow.
  CHANGELOG entry per workflow refinement. Cross-references
  slice **Y.Y4** + REO Rule 1.6 (no auto-signing).
- **Owner**: SSR emitter maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.3 (REO Rule 4 scope
  guard); IRS Pub 1075 §2.E.4.3.

### Y-X27 — IRS Secure Data Transfer URL or auth change

- **Description**: The IRS Office of Safeguards accepts SSR
  submissions via Secure Data Transfer (a portal at
  `safeguardreports@irs.gov` mailbox + IRS Secure Data
  Transfer portal). The portal URL + authentication flow
  occasionally changes (login.gov migration, certificate-
  based auth additions, PIV/CAC). LOOP-Y does NOT
  auto-submit (REO Rule 4) but the operator runbook must
  stay current.
- **Category**: SSR submission lifecycle.
- **Severity**: low (out of LOOP-Y's code path).
- **Likelihood**: med — IRS infrastructure modernization
  is ongoing.
- **Impact**: operator confusion + temporary submission
  delay.
- **Mitigation**: Operator runbook
  `cloud-evidence/docs/runbooks/irs-ssr-submission.md`
  references the IRS Secure Data Transfer help page +
  `safeguardreports@irs.gov` mailbox. Y.Y4 records
  `submission_channel: "irs-secure-data-transfer" | "email-safeguardreports" | "other"`
  + `submission_receipt_id` per submission. CHANGELOG
  entry per runbook refresh. Cross-references slice
  **Y.Y4**.
- **Owner**: Runbook maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.3; IRS Safeguards
  Technical Assistance pages.

### Y-X28 — State-CSO escalation chain ambiguity

- **Description**: The CJIS Systems Officer (CSO) is the
  state-government authority for CJIS compliance issues.
  Each state appoints its own CSO (per CJIS Advisory
  Process); the CSO's escalation chain (deputy CSO, CSA
  leadership, Attorney General office) varies state by
  state. When Y.Y2 emits a POA&M against a state agency's
  CJI footprint, the escalation path is not standardised.
  Operator can address the wrong contact + delay
  remediation.
- **Category**: State-CSO ecosystem.
- **Severity**: med.
- **Likelihood**: high — 50+ states; no central directory.
- **Impact**: delayed remediation; CSO complaint to FBI
  CJIS Audit Unit.
- **Mitigation**: Y.Y2 tracker DB
  `cjis_state_cso_directory(state, cso_name, cso_email,
  deputy_cso_email, csa_leadership_email,
  escalation_protocol_text, confirmation_date,
  confirmation_signed_by)`; operator populates per state
  customer; CHANGELOG entry per state addition. Tracker
  UI surfaces missing-CSO-contact banner per state with
  active CJI footprint. Adversarial test asserts a POA&M
  cannot ship to a state customer without a CSO contact
  on file. Cross-references slice **Y.Y2**.
- **Owner**: AA-detector + tracker UI maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.7 (CSO role); CJIS
  Advisory Process page.

### Y-X29 — CSO email or appointment change mid-cycle

- **Description**: A state CSO is appointed by the head of
  the CSA. Appointments rotate every 2-4 years; the
  appointee's email changes between appointments. Y.Y2's
  CSO directory can go stale silently — POA&M and AA
  evidence emails route to a former CSO's inactive
  address.
- **Category**: State-CSO ecosystem.
- **Severity**: med.
- **Likelihood**: high — observed in multiple states
  per audit cycle.
- **Impact**: missed remediation deadlines; FBI CJIS Audit
  Unit interest.
- **Mitigation**: Y.Y2 tracker requires per-CSO
  `last_confirmed_at` timestamp; warns at T-180 days;
  refuses to ship in strict mode at T-365 days. Operator
  re-confirms CSO contact annually via tracker workflow
  (operator initiates an out-of-band confirmation email;
  CSO replies; operator marks confirmed). Cross-references
  slice **Y.Y2** + Y-X28.
- **Owner**: AA-detector + tracker UI maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.7.

### Y-X30 — State CJIS Audit Unit notification path absence

- **Description**: Each state CSA operates a CJIS Audit
  Unit (or contracts the FBI Audit Unit to perform the
  triennial audit). When LOOP-Y emits an AA evidence
  envelope, the audit-trail consumer is the state CJIS
  Audit Unit (read by the auditor at audit-time).
  Y.Y2 must record the per-state Audit Unit contact +
  acceptance protocol.
- **Category**: State-CSO ecosystem.
- **Severity**: low.
- **Likelihood**: med.
- **Impact**: at audit, operator scrambles to share
  evidence; not a ship-blocker.
- **Mitigation**: Tracker DB
  `cjis_state_audit_unit_directory(state, audit_unit_email,
  evidence_share_protocol_url, last_confirmed_at)`;
  operator populates per state customer. Operator
  runbook documents the share process. Cross-references
  slice **Y.Y2**.
- **Owner**: AA-detector + tracker UI maintainer.
- **Status**: open.
- **References**: CJIS Audit Program page
  (https://le.fbi.gov/cjis-division/audit-unit,
  accessed 2026-06-07).

### Y-X31 — Per-state CJIS supplement adoption-vote schedule unpredictability

- **Description**: When the FBI CJIS Division publishes a
  new Security Policy version (e.g. v6.0), each state's
  CSA votes on adoption. Vote schedules are not standardised;
  Texas DPS may vote Q1, Massachusetts may vote Q4. Y.Y1's
  catalog snapshot may track a version a state has not yet
  adopted — producing audit envelope references to controls
  the state CSO has not yet authorised.
- **Category**: State-CSO ecosystem.
- **Severity**: med.
- **Likelihood**: high.
- **Impact**: confused state CSO; potential POA&M against
  a not-yet-adopted control.
- **Mitigation**: Y.Y1 catalog records
  `state_adoption_map[]` per state with `effective_date_in_state`,
  `adoption_evidence_url` (link to CSA bulletin or board
  minutes), `adoption_evidence_signed_by`. Y.Y2 reads the
  per-customer-agency CSO state + picks the catalog version
  effective in that state at evaluation time. CHANGELOG
  entry per per-state adoption-date update. Cross-references
  slice **Y.Y1** + **Y.Y2** + Y-X1.
- **Owner**: CJIS catalog maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.5 + CJIS Advisory
  Process page.

### Y-X32 — MOU / access-agreement expiry between CSP and customer agency

- **Description**: CJIS Security Policy §5.1 requires
  "Information Exchange Agreements" (often an MOU or
  Inter-Agency Agreement, IAA) between the CSP and each
  customer agency. IRS Pub 1075 §6.3 requires the same
  for FTI. These agreements have expiration dates (1-3
  year terms). An expired agreement nullifies LOOP-Y's
  evidence envelope's authorisation chain — the CSP is
  effectively unauthorised to process CJI/FTI for that
  customer.
- **Category**: State-CSO + IRS submission lifecycle.
- **Severity**: high (regulatory boundary; processing
  without an active agreement is a Pub 1075 §6.3
  violation).
- **Likelihood**: med — observed in multi-year CSP
  customer relationships.
- **Impact**: unauthorised processing; potential IRS
  inquiry; CSO escalation.
- **Mitigation**: Tracker DB
  `cjis_information_exchange_agreements` and
  `irs_contractor_agreements` carry
  `effective_date`, `expiration_date`,
  `extension_signed`, `renewal_workflow_status`.
  Strict mode refuses to emit AA evidence or SSR for a
  customer whose agreement is expired or expires within
  30 days. Tracker UI warns at T-180 / T-90 / T-30.
  CHANGELOG entry per agreement signed/renewed.
  Cross-references slice **Y.Y2** + **Y.Y4** + cross-loop
  with **LOOP-V** BAA primitive (Y.Y3 + Y.Y4 reuse for
  IRS-1075 contractor agreement; pattern mirrored).
- **Owner**: AA-detector + SSR emitter + tracker UI
  maintainers.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §5 (Reusable primitives —
  LOOP-V BAA); CJIS §5.1; IRS Pub 1075 §6.3.

### Y-X33 — Tracker Ed25519 signing-key rotation on AA + SSR records

- **Description**: Y.Y2 (AA evaluation records) and Y.Y4
  (SSR submission records) sign tracker records with the
  tracker-resident Ed25519 key. If the tracker rotates
  without preserving a historical key registry, prior
  snapshots fail verification when a 3PAO audits. Same
  risk class as B-X3, R-X4, S-X6, W-X23.
- **Category**: signing / provenance / tamper-evidence.
- **Severity**: med.
- **Likelihood**: med — quarterly key rotations are
  recommended.
- **Impact**: 3PAO cannot re-verify historical CJIS /
  IRS 1075 evidence; audit trail breaks.
- **Mitigation**: Tracker exposes
  `GET /api/sign/public-keys` returning ALL historical
  public keys keyed by `key_id`; reader cross-references
  each record's `signing_key_id` against the registry.
  Inherits B-X3 fix — if B-X3 ships first, Y inherits.
  Rotation events written to `audit_log`; runbook
  documents procedure. Cross-references slice **Y.Y2** +
  **Y.Y4** + LOOP-B-RISKS B-X3 + LOOP-W-RISKS W-X23.
- **Owner**: Tracker / signing infra maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §17 + §19 + §37.

### Y-X34 — Repository tampering: CJIS / IRS catalog snapshot files

- **Description**: Y.Y1's CJIS snapshot
  (`data/cjis-policy-v5.9.5-catalog.json`) and Y.Y3's
  Pub 1075 snapshot (`data/irs-1075-catalog.json`) are
  committed to the cloud-evidence repo. An attacker with
  repo-write access could swap the file with a tampered
  version omitting controls the attacker wants to suppress.
  The Ed25519 signature catches the swap IF the verifier
  checks; silent verifier bypass is the risk class. Same
  pattern as W-X24.
- **Category**: signing / provenance / tamper-evidence.
- **Severity**: high (security boundary).
- **Likelihood**: low — limited write surface in a
  well-gated repo.
- **Impact**: tampered catalog produces tampered audit
  envelope; 3PAO trust collapses.
- **Mitigation**: (1) Loader unconditionally verifies the
  snapshot signature on every load with no `skip-verify`
  flag — REO Rule 1 forbids; CI guardrail rejects code
  bypassing. (2) Each snapshot file includes
  `provenance.git_commit` of the cloud-evidence repo at
  signing time + the prior snapshot's hash → hash chain.
  (3) CI cron re-verifies the latest snapshots' signatures
  on every push to main; failure pages the team.
  (4) Signing key is held in a hardware-security-module-
  backed location (runbook). Adversarial test pins the
  corrupted-signature case. Cross-references slice **Y.Y1**
  + **Y.Y3** + LOOP-W-RISKS W-X24.
- **Owner**: Catalog ingester maintainers + CI guardrail
  maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §17 + §19 + §37; CLAUDE.md
  Rule 1.

### Y-X35 — REO Rule 1.8 `process.env.NODE_ENV === 'test'` branch creep

- **Description**: REO Rule 1.8 prohibits the literal in
  production code. New emitter signing paths, IdP-fetch
  fallback code, scheduling code, and SCSEM-parsing code
  are exactly where developers reach for the test-short-
  circuit. Same class as B-X6, R-X6, S-X15, W-X26, T-X12.
- **Category**: signing / provenance / tamper-evidence.
- **Severity**: high (REO violation; CI rejects).
- **Likelihood**: med — historically the most common REO
  violation across loops.
- **Impact**: CI rejects PR + the violation hides until
  re-noticed.
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the
  literal; tests inject seams via dependency-injected
  HTTP fetcher + filesystem helper + clock; CI gate is
  non-bypassable. Cross-references slice **Y.Y1**, **Y.Y2**,
  **Y.Y3**, **Y.Y4** + REO CI guardrail G1.
- **Owner**: All slice maintainers.
- **Status**: open.
- **References**: CLAUDE.md Rule 1.8.

### Y-X36 — Provenance schema drift across LOOP-Y emit artifacts

- **Description**: Y.Y1 + Y.Y2 + Y.Y3 + Y.Y4 emit
  artifacts with `provenance` blocks per REO Rule 2.6.
  A missed block fails `check:provenance` (REO CI
  guardrail G3). Same class as B-X9, R-X9, S-X16, W-X25.
- **Category**: signing / provenance / tamper-evidence.
- **Severity**: high.
- **Likelihood**: med.
- **Impact**: CI rejects PR.
- **Mitigation**: Per-slice test verifies provenance via
  `check:provenance`; pattern reused from
  `core/inventory-coverage.ts`; CHANGELOG entry per slice
  cites provenance contents. Cross-references all four
  Y slices + REO guardrail G3.
- **Owner**: All slice maintainers.
- **Status**: open.
- **References**: CLAUDE.md Rule 2.6; `scripts/check-provenance.mjs`.

### Y-X37 — Submission bundle role count growth

- **Description**: LOOP-Y adds 6+ new roles to
  `core/submission-bundle.ts:WELL_KNOWN`:
  `cjis-policy-catalog-json`,
  `cjis-aa-evidence-json`,
  `cjis-aa-poam-bundle`,
  `irs-1075-catalog-json`,
  `irs-ssr-docx`,
  `irs-ssr-json`.
  Role collisions or filename collisions corrupt the
  bundle. Same class as S-X17, W-X27.
- **Category**: signing / provenance / tamper-evidence.
- **Severity**: med.
- **Likelihood**: low — single-namespace; per-loop
  reviewers catch.
- **Impact**: bundler emits a corrupt manifest; downstream
  consumer (3PAO) cannot find an artifact.
- **Mitigation**: `tests/core/submission-bundle.test.ts`
  pins the full role table; per-slice tests assert
  presence; CHANGELOG entry for Y.Y4 (last slice) lists
  the final inventory. Cross-references all four Y
  slices + LOOP-A.A4.
- **Owner**: Bundler + slice maintainers.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §22; LOOP-W-RISKS W-X27.

### Y-X38 — Cross-loop dependency: LOOP-INV-S inventory data_classes pipeline changes

- **Description**: Y.Y2 reads `inventory.assets[].data_classes
  ⊇ {"CJI"}`; Y.Y4 reads `⊇ {"FTI"}`. If LOOP-INV-S
  changes the data_classes pipeline (renames a tag,
  splits a tag into two, deprecates the enum), Y.Y2 +
  Y.Y4 silently miss assets. Same risk class as Y-X19 +
  Y-X20 but from the upstream-pipeline side.
- **Category**: cross-loop interaction.
- **Severity**: high.
- **Likelihood**: med.
- **Impact**: silent false-negative; LOOP-Y produces
  incomplete evidence.
- **Mitigation**: Y.Y2 + Y.Y4 read the data-class enum
  via `core/inventory-data-class-enum.ts`; refuse to
  run if the enum doesn't include `"CJI"` and `"FTI"`
  respectively. Cross-loop test pins the enum contract
  + LOOP-INV-S coverage signal. Operator runbook
  documents the change-management workflow when
  LOOP-INV-S evolves the enum. CHANGELOG entry per
  enum-evolution event. Cross-references slice **Y.Y2**
  + **Y.Y4** + LOOP-INV-S.
- **Owner**: AA-detector + SSR emitter maintainers.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.4 (LOOP-INV-S row).

### Y-X39 — Cross-loop dependency: LOOP-V BAA primitive evolution

- **Description**: Y.Y3 + Y.Y4 reuse LOOP-V's BAA signing
  primitive (`core/baa-signing.ts`) for the Pub 1075 §6.3
  contractor agreement. LOOP-V owns the primitive; if V
  generalises (e.g. adds a `regime` discriminator) or
  breaks (e.g. renames a function), Y.Y3 + Y.Y4 break.
- **Category**: cross-loop interaction.
- **Severity**: med.
- **Likelihood**: med — V is in active development.
- **Impact**: Y.Y3 + Y.Y4 fail to ship; cascading delay.
- **Mitigation**: Cross-loop integration test in
  `tests/core/baa-signing-irs-1075.test.ts` pins the
  expected interface; LOOP-V maintainer notified of
  Y consumer when changing the API. Y.Y3 specifies
  `regime: "irs-1075"` argument so V can branch on it
  if needed. Cross-references slice **Y.Y3** + **Y.Y4** +
  **LOOP-V** + `LOOP-V-RISKS.md`.
- **Owner**: SSR emitter + LOOP-V maintainers.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §5 + §11.2.

### Y-X40 — Cross-loop dependency: existing IAM-MFA detector schema changes

- **Description**: Y.Y2's AA evaluator augments the existing
  `core/iam-mfa.ts` detectors (AWS, GCP, Azure). If those
  detectors evolve their output schema (rename a field,
  drop a field, add a required field), Y.Y2 silently
  reads stale or missing data → false positive/negative.
- **Category**: cross-loop interaction.
- **Severity**: med.
- **Likelihood**: med.
- **Impact**: false readings on the AA evaluation.
- **Mitigation**: Y.Y2 asserts expected schema fields from
  `core/iam-mfa.ts` output; typed error on schema drift.
  Cross-loop integration test pins the contract. Operator
  runbook documents the shared schema in
  `cloud-evidence/docs/iam-mfa-schema.md`. CHANGELOG
  entry per schema bump. Cross-references slice **Y.Y2**
  + existing IAM family.
- **Owner**: AA-detector maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.4 (LOOP-IAM row); existing
  `core/iam-mfa.ts`.

### Y-X41 — Cross-loop dependency: LOOP-A.A1 POA&M emitter schema

- **Description**: Y.Y2 + Y.Y4 emit POA&M findings via
  `core/oscal-poam.ts` (LOOP-A.A1). If A.A1 evolves the
  finding template (e.g. adds a required `regime` field,
  renames `control_id` to `control_identifier`), Y.Y2 +
  Y.Y4 break.
- **Category**: cross-loop interaction.
- **Severity**: med.
- **Likelihood**: low — A.A1 is shipped and stable; OSCAL
  schema is pinned at v1.1.2.
- **Impact**: Y POA&M emission fails.
- **Mitigation**: Y.Y2 + Y.Y4 use A.A1's typed emitter API;
  TypeScript compile-time check catches schema drift.
  Cross-loop integration test in
  `tests/core/poam-emit-y.test.ts` pins the Y-specific
  finding templates. CHANGELOG entry per schema bump.
  Cross-references slice **Y.Y2** + **Y.Y4** + **LOOP-A.A1**.
- **Owner**: Slice maintainers + LOOP-A.A1 owner.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.2 line 15; `core/oscal-poam.ts`.

### Y-X42 — Cross-loop overlap with LOOP-G.G2 + CIRCIA for CJI/FTI incident reporting

- **Description**: A cyber incident touching CJI or FTI
  assets triggers LOOP-G.G2 + CIRCIA 72-hour reporting
  duties (and CJIS §5.3 incident handling, IRS Pub 1075
  §10 incident reporting). LOOP-Y does NOT own incident
  reporting (LOOP-G + CIRCIA do) but operators may
  confuse the duties and skip one.
- **Category**: cross-loop interaction.
- **Severity**: med.
- **Likelihood**: med.
- **Impact**: missed regulatory deadlines (FBI / IRS /
  CISA / state CSO).
- **Mitigation**: Tracker UI surfaces all incident-reporting
  duties side-by-side ("FBI CJIS incident report",
  "IRS Pub 1075 §10 report", "CIRCIA 72h CISA report",
  "CSP customer agency notification"). Tracker
  cross-links via `linked_incident_id` foreign-key.
  Runbook documents distinct triggers + endpoints.
  Adversarial test pins a dual/triple-trigger scenario.
  Cross-references slice **Y.Y2** + **Y.Y4** +
  **LOOP-G.G2** + `docs/CIRCIA-WORKFLOW.md`.
- **Owner**: Tracker UI + slice maintainers.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §11.2 (LOOP-G.G2 row);
  CJIS §5.3; IRS Pub 1075 §10; CIRCIA Final Rule.

### Y-X43 — Multi-tenant LOOP-Y isolation deferred to LOOP-H.H3

- **Description**: All LOOP-Y tracker tables omit a
  `tenant_id` column. When multi-CSO ships (H.H3), all
  need migration in a single cross-loop sweep. Same
  class as B-X15, R-X15, S-X21, W-X38, T-X14.
- **Category**: cross-loop interaction.
- **Severity**: med (long-tail).
- **Likelihood**: low (deferred by design).
- **Impact**: when multi-tenant ships, a tenant could see
  another tenant's CJIS/IRS evidence; high impact at
  that moment.
- **Mitigation**: Documented in LOOP-Y-SPEC.md §9 open
  questions + per-slice doc DEFER notes; H.H3 spec must
  enumerate every LOOP-Y table; LOOP-Y ships in single-
  tenant deployments only (documented in runbook).
  Cross-references slice **Y.Y2** + **Y.Y4** + **LOOP-H.H3**.
- **Owner**: H.H3 maintainer; Y slice maintainers.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §21 (Tracker DB schema);
  LOOP-W-RISKS W-X38.

### Y-X44 — Operator-falsified "not applicable" sector flag

- **Description**: The FOURTH-PASS-AUDIT.md flagged this
  vector explicitly. A CSP that backs a fusion-center
  tenant (CJI) or a state Department of Revenue tenant
  (FTI) but declares
  `serves_criminal_justice_information: false` or
  `serves_federal_tax_information: false` in
  `org-profile.yaml` skips LOOP-Y entirely. The omission
  is itself a 3PAO finding; worse, it understates the
  CSP's regulatory footprint.
- **Category**: operator-workflow / legal boundary.
- **Severity**: high (audit-finding-grade).
- **Likelihood**: med.
- **Impact**: 3PAO audit finding; potential CSO + IRS
  inquiry; possible 18 U.S.C. §1001 exposure if the
  operator signed an attestation claiming non-applicability.
- **Mitigation**: Tracker first-boot wizard forces the
  operator to attest under "reasonable inquiry" standard
  per FAR 4.2101; the attestation is recorded with
  signing-officer + bylaws-citation. Operator runbook
  documents the per-tenant scoping process. Y orchestrator
  cross-checks customer-list signals (operator-supplied
  `customer-agencies.yaml` lists customer agencies; if
  any are tagged as law-enforcement or revenue-collection,
  the wizard challenges the negative declaration).
  Adversarial test pins a "false-declaration-with-positive-
  signal" case + asserts the orchestrator emits a tracker
  warning banner. CHANGELOG entry per scoping confirmation.
  Cross-references LOOP-Y-SPEC.md §1.5 + §11; FAR 4.2101
  reasonable-inquiry standard; FOURTH-PASS-AUDIT.md
  scoping section.
- **Owner**: First-boot wizard + orchestrator maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §1.5; FOURTH-PASS-AUDIT.md
  Section 4.

### Y-X45 — IRC §6103 amendment risk (statutory change)

- **Description**: 26 U.S.C. §6103 — the statutory anchor
  for FTI safeguarding — is amendable only by Congress.
  Congressional amendments to §6103 happen rarely but
  have material impact (e.g. expanded disclosure
  authority to a new federal program). A statutory
  amendment can change Pub 1075 enforcement scope, the
  SSR cadence, or the contractor-agreement requirements.
- **Category**: legal / regulatory boundary.
- **Severity**: low (Congressional cadence; long advance
  notice).
- **Likelihood**: low.
- **Impact**: catalog re-extraction + SSR template re-pin.
- **Mitigation**: Operator runbook references the
  uscode.house.gov §6103 page for change tracking. The
  IRS Office of Safeguards typically issues guidance
  via the Safeguards Program page within 90 days of an
  amendment. Y.Y3 catalog version-bump procedure handles
  the re-extraction. CHANGELOG entry per amendment.
  Cross-references slice **Y.Y3** + **Y.Y4**.
- **Owner**: IRS-1075 catalog maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.18; 26 U.S.C. §6103
  (https://www.law.cornell.edu/uscode/text/26/6103,
  accessed 2026-06-07).

### Y-X46 — State-level CJIS interpretation variance (Massachusetts vs Texas vs California)

- **Description**: States interpret CJIS Security Policy
  differently. Massachusetts 803 CMR 7.00 layers state-
  specific obligations; Texas DPS publishes a companion
  document but also issues per-tenant "Security Reviewer"
  guidance; California DOJ has its own access-control
  memorandum process. A CSP that serves multiple states
  faces interpretation conflict (e.g. Massachusetts
  requires a state-issued PIV; Texas accepts a
  CSO-approved hardware token; California requires
  per-incident notice within 24h instead of CIRCIA's 72h
  for CJI-touching incidents).
- **Category**: legal / regulatory boundary.
- **Severity**: med.
- **Likelihood**: high — every multi-state CSP customer
  hits this.
- **Impact**: operator confusion; tracker UI proliferation;
  per-state policy maintenance burden.
- **Mitigation**: Y.Y1 catalog records per-state overlays;
  Y.Y2 evaluator picks the strictest applicable per-state
  rule per-customer-agency. Operator-supplied
  `cjis-state-interpretation-overrides.yaml` per state +
  per customer. Tracker UI surfaces a per-customer policy
  pin. CHANGELOG entry per interpretation update.
  Cross-references slice **Y.Y1** + **Y.Y2** + Y-X6 +
  Y-X31.
- **Owner**: CJIS catalog maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.22; Massachusetts 803
  CMR 7.00; Texas DPS companion document; California DOJ
  memoranda.

### Y-X47 — Disclosure Awareness Training non-completion (Pub 1075 §10)

- **Description**: IRS Pub 1075 §10 requires annual
  Disclosure Awareness Training for all personnel with
  FTI access. The SSR Section 2 attests to training
  completion. Tracking training completion is operator-
  process work, but the SSR cannot truthfully attest if
  not all personnel completed it. Y.Y4 must surface the
  completion-rate signal.
- **Category**: operator-workflow / legal boundary.
- **Severity**: med.
- **Likelihood**: med — multi-employee CSP customer
  agencies routinely have a few percent un-completion
  rate.
- **Impact**: SSR Section 2 misrepresents training
  posture; IRS Office of Safeguards inquiry.
- **Mitigation**: Tracker DB
  `irs_disclosure_awareness_training_completion(user_id,
  customer_agency_id, training_date, training_evidence_path,
  expires_at)`; UI surfaces per-customer completion rate
  with a 95% strict floor; Y.Y4 refuses to emit the SSR
  Section 2 affirmative claim in strict mode if any
  population is < 95%. Operator runbook documents the
  training import workflow (LMS export → tracker bulk
  import). CHANGELOG entry per import. Cross-references
  slice **Y.Y4**.
- **Owner**: SSR emitter + tracker UI maintainers.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §2.17; IRS Pub 1075 §10.

### Y-X48 — Per-customer per-FY SSR uniqueness vs annual reset

- **Description**: The SSR is emitted annually per
  customer agency. The tracker DB must enforce one SSR
  per (customer_agency_id, fiscal_year) — but the IRS
  fiscal year is October 1 to September 30, while
  some state customer agencies use a calendar fiscal year
  or a July-June fiscal year. An off-by-one fiscal-year
  classification could produce duplicate or skipped
  SSRs.
- **Category**: operator-workflow / legal boundary.
- **Severity**: med.
- **Likelihood**: med.
- **Impact**: duplicate or skipped SSR; IRS Office of
  Safeguards inquiry.
- **Mitigation**: Tracker DB
  `irs_ssr_submissions UNIQUE(customer_agency_id,
  irs_fiscal_year)` with `irs_fiscal_year` always
  derived from the federal Oct 1 – Sep 30 calendar
  (not from the customer's local fiscal calendar).
  Operator runbook documents the federal-FY anchor.
  Tracker UI surfaces "next SSR due" countdown.
  Adversarial test asserts that a duplicate
  `(customer_agency_id, irs_fiscal_year)` insert
  rejects. Cross-references slice **Y.Y4**.
- **Owner**: SSR emitter maintainer.
- **Status**: open.
- **References**: LOOP-Y-SPEC.md §20 + §21; IRS Pub 1075
  §2.E.4.3.

---

## Per-slice risks

### Y.Y1 — CJIS Security Policy v5.9.5 Control Catalog

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Y.Y1-1 | high | CJIS v6.0 supersession during audit cycle (cross-ref Y-X1) | state_adoption_map per-state + 180-day staleness floor + CI cron weekly | open |
| Y.Y1-2 | high | AA factor list drift between v5.9.x revisions (cross-ref Y-X2) | XPath anchor + 7-factor floor + SHA-256 pin + adversarial test | open |
| Y.Y1-3 | high | shall-statement extraction OCR errors (cross-ref Y-X8) | Multi-pass extractor + per-section anchor matching + 30-char floor + verbatim re-affirmation | open |
| Y.Y1-4 | med | NIST 800-53 r5 cross-walk ambiguity (cross-ref Y-X9) | multi-control mapping array + confidence tier + operator override + coverage flag | open |
| Y.Y1-5 | high | Shall-statement count regression (cross-ref Y-X11) | Per-Policy-Area expected-count fixture + 220 floor + weekly CI re-run | open |
| Y.Y1-6 | med | NCIC Operating Manual revision lag (cross-ref Y-X5) | Default 365-day floor + per-CSO confirmation + tracker DB capture | open |
| Y.Y1-7 | med | State-supplement revision drift (cross-ref Y-X6) | Per-state SHA-256 pin + weekly CI re-fetch + operator-extendable registry | open |
| Y.Y1-8 | high | Catalog snapshot tampering (cross-ref Y-X34) | Unconditional Ed25519 verify + hash-chain + HSM-held key + CI re-verify | open |
| Y.Y1-9 | med | Catalog signing-key rotation (cross-ref Y-X14) | Tracker key registry + per-snapshot signing_key_id + B-X3 inherit | open |
| Y.Y1-10 | med | State CJIS adoption-vote schedule unpredictability (cross-ref Y-X31) | state_adoption_map + per-state effective_date + adoption_evidence_url | open |
| Y.Y1-11 | high | REO Rule 1.8 branch creep (cross-ref Y-X35) | scripts/lint-no-stubs.mjs + DI seams + CI gate | open |
| Y.Y1-12 | med | State-level CJIS interpretation variance (cross-ref Y-X46) | Per-state overlay catalog + strictest-rule selection + operator override | open |
| Y.Y1-13 | low | Snapshot retention policy (how long do we keep historical snapshots) | LOOP-H.H1 long-term storage classifier reads `data/cjis-policy-*.json retention_until`; default 7 years per FedRAMP record-retention | open |
| Y.Y1-14 | low | First-snapshot bootstrap when no prior snapshot exists | `--first-snapshot` flag opts into emit; CHANGELOG documents; no hash-chain prior reference | open |
| Y.Y1-15 | med | Operator config `cjis-state-supplements.yaml` schema validation | ajv schema in `core/cjis-state-supplements-schema.json`; validate on every load | open |
| Y.Y1-16 | low | Submission bundle role naming collisions (cross-ref Y-X37) | submission-bundle test pins role table | open |
| Y.Y1-17 | low | FBI Federal-Register URL stability for CJIS-related notices | FR doc-number permanence; CHANGELOG documents citation form | open |

### Y.Y2 — CJIS Advanced Authentication (AA) Detector

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Y.Y2-1 | high | IdP factor-type addition (cross-ref Y-X15) | factor-map JSON + REQUIRES-OPERATOR-INPUT on unmapped + weekly CI re-fetch | open |
| Y.Y2-2 | med | Phishing-resistance attestation absent (cross-ref Y-X16) | Read from factor-map only; never infer from name | open |
| Y.Y2-3 | med | Biometric-on-device attestation parsing fragility (cross-ref Y-X17) | Per-platform parsers with version discriminators + weekly CI release-note check | open |
| Y.Y2-4 | high | Conditional Access per-app rule evaluation (cross-ref Y-X18) | Per-policy CA evaluator + adversarial test on trusted-IP exclusion | open |
| Y.Y2-5 | high | CJI inventory false-negative (cross-ref Y-X20) | inventory.coverage gate + heuristic candidate-asset list + operator confirm | open |
| Y.Y2-6 | med | Inventory data-class taxonomy collisions (cross-ref Y-X21) | Pinned taxonomy enum + dedup by (asset_id, control_id) | open |
| Y.Y2-7 | med | State-CSO escalation chain ambiguity (cross-ref Y-X28) | cjis_state_cso_directory tracker DB + missing-CSO banner + ship-blocker assert | open |
| Y.Y2-8 | med | CSO email or appointment change mid-cycle (cross-ref Y-X29) | last_confirmed_at + T-180 warn / T-365 strict-block | open |
| Y.Y2-9 | low | State CJIS Audit Unit notification path (cross-ref Y-X30) | cjis_state_audit_unit_directory tracker DB + operator-supplied | open |
| Y.Y2-10 | high | MOU / access-agreement expiry (cross-ref Y-X32) | Tracker DB with expiration tracking + T-30 strict-block | open |
| Y.Y2-11 | med | Tracker signing-key rotation (cross-ref Y-X33) | Tracker key registry + per-record signing_key_id | open |
| Y.Y2-12 | high | REO Rule 1.8 branch creep (cross-ref Y-X35) | lint-no-stubs + DI seams | open |
| Y.Y2-13 | high | Provenance schema drift (cross-ref Y-X36) | check:provenance + per-slice provenance test | open |
| Y.Y2-14 | med | Cross-loop dependency: IAM-MFA schema (cross-ref Y-X40) | Schema-field assertions + typed error + cross-loop integration test | open |
| Y.Y2-15 | med | Cross-loop dependency: LOOP-A.A1 POA&M emitter (cross-ref Y-X41) | Typed emitter API + cross-loop integration test | open |
| Y.Y2-16 | med | Cross-loop overlap with LOOP-G.G2 + CIRCIA (cross-ref Y-X42) | Tracker UI side-by-side + linked_incident_id FK | open |
| Y.Y2-17 | med | Multi-tenant deferred (cross-ref Y-X43) | LOOP-H.H3 sweep + single-tenant deploy | open |
| Y.Y2-18 | high | Operator-falsified sector flag (cross-ref Y-X44) | First-boot wizard + reasonable-inquiry attestation + customer-list cross-check | open |
| Y.Y2-19 | low | Marketplace badge format drift (cross-ref Y-X7) | Backward-compatible JSON additive | open |
| Y.Y2-20 | med | POA&M emit explosion (e.g. 500 users with non-conformant factor) | Group by control_id + factor_type; one POA&M per (control, factor); UI surfaces "CJIS AA" filter facet | open |
| Y.Y2-21 | med | AA Compensating Control workflow misuse (operator over-uses compensating control) | Tracker UI requires per-use CSO countersign evidence path; CHANGELOG per compensating control approved | open |
| Y.Y2-22 | low | IdP factor with no CSO-approved category mapping (truly novel) | REQUIRES-OPERATOR-INPUT + tracker UI + operator confirms post-CSO consultation | open |

### Y.Y3 — IRS Publication 1075 Control Catalog

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Y.Y3-1 | high | IRS Pub 1075 revision drift (cross-ref Y-X3) | publication_revision pin + CI cron weekly + 365-day floor + mailing-list subscription runbook | open |
| Y.Y3-2 | med | SCSEM platform-coverage additions (cross-ref Y-X4) | scsem_inventory table + monthly CI re-fetch + operator import workflow | open |
| Y.Y3-3 | high | NIST 800-53 r4 vs r5 cross-walk dual emit (cross-ref Y-X10) | Both arrays emitted per control + OQ-Y-04 tracker | open |
| Y.Y3-4 | high | Pub 1075 §9 sub-section enumeration drift (cross-ref Y-X12) | Anchor chain assertion + FIPS reference text match + monthly CI diff | open |
| Y.Y3-5 | med | SCSEM matrix drift (cross-ref Y-X13) | Per-version control-ID mapping + delta report on bump | open |
| Y.Y3-6 | high | Catalog snapshot tampering (cross-ref Y-X34) | Unconditional Ed25519 verify + hash-chain + HSM key + CI re-verify | open |
| Y.Y3-7 | med | Catalog signing-key rotation (cross-ref Y-X14) | Tracker key registry + per-snapshot signing_key_id | open |
| Y.Y3-8 | high | REO Rule 1.8 branch creep (cross-ref Y-X35) | lint-no-stubs + DI seams | open |
| Y.Y3-9 | high | Provenance schema drift (cross-ref Y-X36) | check:provenance + per-slice test | open |
| Y.Y3-10 | med | LOOP-V BAA primitive evolution (cross-ref Y-X39) | Cross-loop integration test + regime discriminator | open |
| Y.Y3-11 | low | IRC §6103 amendment (cross-ref Y-X45) | Runbook references uscode.house.gov + IRS guidance window | open |
| Y.Y3-12 | med | Catalog shall-statement count regression (Pub 1075 ~150 controls) | Per-section expected-count fixture + 130 floor + weekly CI re-run | open |
| Y.Y3-13 | low | First-snapshot bootstrap (Y.Y1-14 mirror) | --first-snapshot flag + CHANGELOG | open |
| Y.Y3-14 | med | Operator config `irs-1075-overrides.yaml` schema validation | ajv schema validation on every load | open |
| Y.Y3-15 | low | Snapshot retention policy (Y.Y1-13 mirror) | retention_until field; 7-year default | open |
| Y.Y3-16 | low | Submission bundle role naming collisions (cross-ref Y-X37) | submission-bundle test pins role table | open |

### Y.Y4 — IRS Safeguard Security Report (SSR) Emitter

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Y.Y4-1 | high | SSR submission deadline miss (cross-ref Y-X22) | Per-customer due-date tracker + T-90/60/30/14/7/3/1 reminders + state due-date defaults | open |
| Y.Y4-2 | med | First-year SSR (no prior-year acceptance .docx) (cross-ref Y-X23) | --first-year-ssr flag + IRS blank template + operator attestation | open |
| Y.Y4-3 | high | Section 3 control-status enumeration drift (cross-ref Y-X24) | ssr_template_version pin + monthly CI re-fetch + page-the-team on diff | open |
| Y.Y4-4 | med | CAP / POA&M consolidation (cross-ref Y-X25) | POA&M-projection + UNIQUE(ssr_id, poam_uuid) + adversarial dup test | open |
| Y.Y4-5 | high | Officer signature missing (cross-ref Y-X26) | Unsigned signature block + tracker checklist + status flip-blocker | open |
| Y.Y4-6 | low | IRS Secure Data Transfer URL/auth change (cross-ref Y-X27) | Runbook references IRS help + submission_channel + receipt_id capture | open |
| Y.Y4-7 | high | FTI inventory false-negative (cross-ref Y-X19) | inventory.coverage gate + heuristic candidate list + operator confirm | open |
| Y.Y4-8 | med | Inventory data-class taxonomy collisions (cross-ref Y-X21) | Pinned taxonomy enum + dedup | open |
| Y.Y4-9 | high | MOU / contractor-agreement expiry (Pub 1075 §6.3) (cross-ref Y-X32) | Tracker DB with expiration tracking + T-30 strict-block + LOOP-V BAA primitive | open |
| Y.Y4-10 | med | Tracker signing-key rotation (cross-ref Y-X33) | Tracker key registry + per-record signing_key_id | open |
| Y.Y4-11 | high | REO Rule 1.8 branch creep (cross-ref Y-X35) | lint-no-stubs + DI seams | open |
| Y.Y4-12 | high | Provenance schema drift (cross-ref Y-X36) | check:provenance | open |
| Y.Y4-13 | med | Submission bundle role growth (cross-ref Y-X37) | submission-bundle test pins role table | open |
| Y.Y4-14 | med | LOOP-V BAA primitive evolution (cross-ref Y-X39) | Cross-loop integration test + regime: "irs-1075" | open |
| Y.Y4-15 | med | LOOP-A.A1 POA&M emitter schema (cross-ref Y-X41) | Typed emitter API + cross-loop integration test | open |
| Y.Y4-16 | med | Cross-loop overlap with LOOP-G.G2 + CIRCIA (cross-ref Y-X42) | Tracker UI side-by-side + linked_incident_id FK | open |
| Y.Y4-17 | med | Multi-tenant deferred (cross-ref Y-X43) | LOOP-H.H3 sweep | open |
| Y.Y4-18 | high | Operator-falsified sector flag (cross-ref Y-X44) | First-boot wizard + reasonable-inquiry attestation | open |
| Y.Y4-19 | low | Marketplace badge format drift (cross-ref Y-X7) | Backward-compatible JSON additive | open |
| Y.Y4-20 | med | Disclosure Awareness Training non-completion (cross-ref Y-X47) | Tracker DB completion tracking + 95% strict floor + operator runbook | open |
| Y.Y4-21 | med | Per-customer per-FY SSR uniqueness (cross-ref Y-X48) | UNIQUE(customer_agency_id, irs_fiscal_year) + federal-FY anchor | open |
| Y.Y4-22 | low | Report file size cap | Warn at 5 MB, fail at 25 MB; per-customer files small (~50-200 KB) | open |
| Y.Y4-23 | med | Tracker schema migration on existing installs (cross-ref to S-X18 / W.W4-13) | All tables additive CREATE TABLE IF NOT EXISTS; CHANGELOG documents | open |
| Y.Y4-24 | low | Multiple customer-agency overlap (a single CSP system serves several agencies; one SSR per agency) | UNIQUE(customer_agency_id, fiscal_year); per-agency .docx + JSON | open |
| Y.Y4-25 | med | Auto-suggest checkbox could mislead operator (similar to W.W4-15) | UI shows control-status summary + recommended status + operator must explicitly accept; the system never auto-files | open |
| Y.Y4-26 | low | Officer leaves customer-agency between sign-off + IRS filing | Signed SSR retains historical signature; IRS filing requires currently-authorized officer | open |

---

## External dependencies that may change

### Federal-Government bulk feeds (catalog source data)

- **FBI CJIS Security Policy** — index:
  https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center
  — v5.9.5 pinned 2024-07-09; v6.0 draft 2024-12-27 (CSA-adoption
  phase as of 2026-06-07). Operator downloads PDF (FBI HTTP 403
  blocks anonymous WebFetch); Y.Y1 reads from local disk.
- **FBI Advisory Process minutes** —
  https://le.fbi.gov/cjis-division/the-cjis-advisory-process —
  quarterly publication; meeting minutes signal upcoming policy
  revisions.
- **FBI CJIS Audit Unit** —
  https://le.fbi.gov/cjis-division/audit-unit — defines audit
  program + escalation chain.
- **IRS Publication 1075 PDF** — https://www.irs.gov/pub/irs-pdf/p1075.pdf
  (utility mirror at https://www.irs.gov/pub/irs-utl/p1075.pdf) —
  Rev. 11-2021 pinned. Operator downloads PDF (IRS HTTP 403
  blocks anonymous WebFetch); Y.Y3 reads from local disk.
- **IRS Safeguards Program page** —
  https://www.irs.gov/privacy-disclosure/safeguards-program —
  HTML; SCSEM listing, SSR guidance, mailing-list link.
- **IRS Safeguard Security Report page** —
  https://www.irs.gov/privacy-disclosure/safeguard-security-report —
  HTML; annual filing cadence, state-staggered due dates.
- **IRS SSR Template** — https://www.irs.gov/pub/irs-utl/SSRTemplate.docx
  — blank template; first-year filings reference. Format
  refreshed every 2-3 years.
- **IRS IRM 11.3.36** —
  https://www.irs.gov/irm/part11/irm_11-003-036 — Internal Revenue
  Manual section on the Safeguard Review Program.
- **IRS IRM 11.3.1** —
  https://www.irs.gov/irm/part11/irm_11-003-001 — Internal Revenue
  Manual section on Introduction to Disclosure.
- **IRS Encryption Requirements of Pub 1075** —
  https://www.irs.gov/privacy-disclosure/encryption-requirements-of-publication-1075
  — HTML annotations on §9.1 encryption controls.

### State CJIS supplements

- **Texas DPS CJIS Companion Document v5.9.5** —
  https://www.dps.texas.gov/sites/default/files/documents/securityreview/documents/RequirementCompanionDoc_v5-9-5.pdf
  — public-domain PDF.
- **Massachusetts 803 CMR 7.00** —
  https://www.mass.gov/doc/803-cmr-700-criminal-justice-information-system-cjis-0/download
  — regulation in PDF.
- **Illinois LEADS Security Policy** —
  https://isp.illinois.gov/LawEnforcement/GetFile/dd6b6bd1-5f5f-4a54-80e9-a606a51ab75a
  — public-domain PDF.
- **Ohio Administrative Code 4501:2-10-01** (CSO appointment) —
  https://codes.ohio.gov/ohio-administrative-code/rule-4501:2-10-01
  — HTML.
- **Louisiana State Police v6.0 mirror** —
  https://lsp.org/media/dgxluyj3/cjis_security_policy_v6-0_20241227-1.pdf
  — accessed for v6.0 draft text.

### Statute / regulation / directive

- **26 U.S.C. §6103** —
  https://www.law.cornell.edu/uscode/text/26/6103
  (Cornell LII mirror) + https://uscode.house.gov/view.xhtml?req=granuleid%3AUSC-prelim-title26-section6103
  — statutory. Amendable only by Congress.
- **NIST SP 800-53 Rev 5** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  — cross-walk target. Rev 6 long-tail.
- **NIST SP 800-53B** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53B.pdf
  — baselines; Moderate cross-walk anchor.
- **NIST SP 800-88 Rev 1** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf
  — media sanitization; CJIS §5.8 + IRS Pub 1075 §8 cross-reference.
- **FIPS 140-3** —
  https://csrc.nist.gov/publications/detail/fips/140/3/final
  — supersedes FIPS 140-2 in §9.1 encryption requirements.

### FedRAMP guidance updates that could affect LOOP-Y

- **FedRAMP 20x Phase Two RFCs (RFC-0014 + future)** — could
  redefine KSI semantics + cross-walk to sector-overlay controls.
  Y.Y1 + Y.Y3 cross-walks read the current KSI catalogue.
- **FedRAMP Marketplace `compliance_overlay_badges[]` field
  (hypothetical)** — LOOP-Q.Q1 would surface from Y.Y2 + Y.Y4
  records once Marketplace metadata extends.

### Upstream library updates

- **OSCAL JSON Schema v1.1.2** — committed at
  `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json`.
  LOOP-Y emits POA&M findings via existing `core/oscal-poam.ts`;
  pinned to v1.1.2.
- **ajv (^8.x)** — used by `core/oscal-validate.ts` + future
  `core/cjis-state-supplements-schema.json` + future
  `core/irs-1075-overrides-schema.json`. Schema-behaviour
  changes rare; lock major version.
- **better-sqlite3 (~9.x or ~11.x)** — tracker. SQL dialect
  stable.
- **noble-ed25519 (^2.x) or @noble/ed25519** — Ed25519 signing.
  Stable API.
- **OOXML compose helpers** — used by `core/oscal-ssp-docx.ts`;
  reused for `core/irs-ssr-docx.ts`. No external dep; pure JS.
- **xlsx parser (e.g. `exceljs` ^4.x)** — Y.Y3 SCSEM ingester
  reads .xlsx workbooks. Pin major version; CHANGELOG entry
  per bump.
- **pdf-parse (^1.x)** — Y.Y1 + Y.Y3 catalog extractors.
  Stable API.
- **React (^18.x)** — tracker UI; pin major within LOOP-Y.

### Cloud-provider IdP services

- **AWS Cognito + IAM Identity Center** — factor-type additions
  every 3-6 months.
- **GCP Workforce Identity Federation + Identity-Aware Proxy** —
  factor-type additions every 3-6 months.
- **Microsoft Entra ID** — factor-type additions every 3-6
  months; Conditional Access policy schema updates periodic.

### IRS submission infrastructure

- **IRS Secure Data Transfer portal** — third-party operator-side
  dependency. Outages affect operator workflow; not
  code-correctness.
- **`safeguardreports@irs.gov` mailbox** — alternative submission
  channel; rate-limited; large attachments may bounce.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the
   appropriate per-slice section with a fresh ID (e.g. `Y.Y2-23`);
   commit alongside the slice's implementation-log update.
2. Risks resolved during implementation: move the row to the
   "Resolved risks" table at the bottom with date + resolution
   note + responsible session/commit. Do NOT delete the original
   entry — historical record matters.
3. Severity bump (low → med → high): add a `note` line under the
   original entry describing why; do not edit history.
4. Cross-cutting risks affecting multiple slices: keep in the
   cross-cutting section; reference from per-slice tables via
   "(cross-ref Y-X<n>)".
5. CHANGELOG entry on every register update — even register-only
   changes; this is the audit trail.

---

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-Y-SPEC.md` — full LOOP-Y
   specification including §1.5 (authoritative scope guard),
   §2 (verbatim statutory quotes), §9 (open questions
   OQ-Y-01 through OQ-Y-11), §11 (cross-references), §16 (CJIS
   AA factor decision table), §17 + §19 (catalog schemas),
   §20 (SSR envelope schema), §21 (tracker DB tables), §33
   (resume-from-fresh-session checklist).
3. Read the specific per-slice doc at `docs/slices/Y/Y.Y<n>.md`
   for the slice you're implementing — risks here are the LIVE
   working set; risks in the per-slice docs are the spec
   snapshot.
4. Cross-reference `docs/DEPENDENCY-GRAPH.md` for cross-loop
   dependencies (LOOP-V BAA primitive; LOOP-A.A1/A.A4/A.A5
   POA&M/bundler/signing; LOOP-INV-S data_classes; LOOP-IAM
   AA augmentation; LOOP-X zero-trust phishing-resistance
   pattern; LOOP-Q.Q1 Marketplace badge).
5. Cross-reference companion registers when triaging a risk
   that crosses loops: `LOOP-V-RISKS.md` (BAA primitive),
   `LOOP-U-RISKS.md` (privacy overlap), `LOOP-X-RISKS.md`
   (zero-trust MFA), `LOOP-W-RISKS.md` (shared patterns:
   W-X9 catalog provenance, W-X23 signing-key rotation,
   W-X24 repo tampering, W-X25 provenance schema, W-X26 REO
   1.8, W-X27 bundle roles), `LOOP-T-RISKS.md` (T-X11/T-X12
   shared signing patterns), `LOOP-S-RISKS.md` (DFARS
   parallel; S-X18 schema migration), `LOOP-B-RISKS.md`
   (B-X3 signing-key registry, B-X15 multi-tenant deferral),
   `LOOP-R-RISKS.md` (PQC).
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` —
   the 7-step procedure to follow at slice close.
7. Before shipping a slice, update this file's per-slice section
   + move any resolved risks to the resolved table atomically
   with the slice's commit (per SLICE-COMPLETION-PROCEDURE.md).
8. **Push to origin/main is part of the completion procedure.**
   Per the GROUND-UP DIRECTIVE: "There should be a directive to
   update status each time in claude.md when the respective
   loop, slice, section is completed at the end along with
   pushing to github." Confirm STATUS.md row + CHANGELOG line
   + per-slice doc frontmatter + LOOP-Y-SPEC.md status table
   + this register's per-slice section are all current BEFORE
   the push.

---

## Appendix — when does LOOP-Y apply?

LOOP-Y applies when ANY of the following are true:

1. The CSP's `org-profile.yaml` declares
   `serves_criminal_justice_information: true` (CJIS path:
   Y.Y1 + Y.Y2 activate). This is true when the CSP processes,
   stores, or transmits Criminal Justice Information for a
   state, local, tribal, or territorial law enforcement /
   criminal-justice agency.
2. The CSP's `org-profile.yaml` declares
   `serves_federal_tax_information: true` (IRS 1075 path:
   Y.Y3 + Y.Y4 activate). This is true when the CSP receives
   Federal Tax Information under the disclosure authorities of
   26 U.S.C. §6103 — directly from the IRS or from any
   authorised secondary source (SSA, OCSE, BFS, CMS).
3. Both of the above are true simultaneously (e.g. a
   fusion-center tenant whose stack also handles state
   Department of Revenue tax workloads).

LOOP-Y does NOT apply when BOTH flags are false. The
orchestrator emits a single-line `loop:Y skipped —
sector_overlay_not_applicable` diagnostic and proceeds.

Negative-declaration risk: a CSP that backs a CJI- or
FTI-handling tenant but declares both flags false is in
audit-finding territory. See Y-X44 + LOOP-Y-SPEC.md §1.5.
The first-boot wizard enforces a reasonable-inquiry
attestation; the operator MUST attest under FAR 4.2101 (or
the equivalent professional standard for non-Federal-
contract customers) that the negative declaration is
accurate.

The `--sector-overlay` flag (or
`CLOUD_EVIDENCE_SECTOR_OVERLAY` env var) is the operator's
binary signal to activate LOOP-Y in CI mode. The first-boot
wizard prompts the operator to confirm scope decisions
before LOOP-Y's tracker pages activate.

---

## Appendix — risk-severity calibration

- **high** = ship-blocker. Resolve before merging the slice's
  commit. CI guardrail or test failure required.
- **med** = should fix in-loop. Resolve before LOOP-Y closes
  (i.e. before Y.Y4 ships). Operator runbook + CHANGELOG must
  document any unresolved med-severity item.
- **low** = file as follow-up. May remain open after LOOP-Y
  closes; must have an owner + a target loop (LOOP-Y-StateOverlay,
  LOOP-H.H3 multi-tenant, FIFTH-PASS-AUDIT follow-up, etc.)
  where the resolution will land.

This calibration mirrors LOOP-W-RISKS.md, LOOP-T-RISKS.md,
LOOP-R-RISKS.md, and LOOP-S-RISKS.md.

---
