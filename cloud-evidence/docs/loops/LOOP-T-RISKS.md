# LOOP-T — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status=resolved` + resolution note.
> Severity: high = ship-blocking; med = should fix in-loop; low = file
> as follow-up.

> Authoritative companion to `docs/loops/LOOP-T-SPEC.md` and the
> per-slice docs at `docs/slices/T/T.T[1-5].md`. Read those for context
> before acting on any risk here.

> **CONDITIONAL GATE**: LOOP-T applies when the CSP sells software to
> any federal agency (civilian or defense) under a contract that
> references OMB M-22-18 / M-23-16, or under a post-M-26-05 agency
> tailoring that elects to continue using the Common Form / SSDF / RSAA.
> When the operator-supplied `--ssdf-attestation` flag (or
> `CLOUD_EVIDENCE_SSDF_ATTESTATION` env var) is unset, NONE of the LOOP-T
> risks below activate. Every risk below carries an implicit "WHEN
> LOOP-T IS ACTIVE" precondition. The post-M-26-05 "voluntary regime"
> does **not** absolve a CSP whose existing contracts incorporate
> M-22-18 / M-23-16 flow-downs — see R-X19.

> Last updated: 2026-06-07.

> Companion reading (cross-reference these registers when triaging a
> LOOP-T risk that interacts with another loop):
> - `LOOP-J-RISKS.md` — supply chain + privileges; J.J3.b is the
>   engineering-attestation sibling of LOOP-T (see R-X11 distinction
>   collapse).
> - `LOOP-O-RISKS.md` — AI/ML governance; O.O5 model cards feed T.T5.
> - `LOOP-B-RISKS.md` — POA&M emitter; LOOP-T uses POA&M cascade for
>   the M-22-18 §III.E "POA&M in lieu of attestation" safety valve.
> - `LOOP-S-RISKS.md` — DFARS equivalency; DoD primes often demand
>   the SSDF Common Form as an equivalency artefact (R-X16).

---

## Cross-cutting risks (apply to ALL slices in LOOP-T)

### T-X1 — Corporate-officer attestation forgery / unauthorized signing

- **Description**: The CISA Self-Attestation Common Form (OMB 1670-0052)
  is a binding corporate document. The Common Form is signed by a
  natural person — a corporate officer (CEO, CISO, COO, VP Engineering,
  General Counsel) — who must be empowered under corporate bylaws to
  attest on behalf of the producer. Three forgery vectors exist:
  (a) a non-officer obtains write access to the tracker's attestation
  table and inserts a signature record, (b) an officer-role user signs
  on behalf of a different officer (impersonation within the org),
  (c) the unsigned canonical PDF emitted by T.T3 is intercepted and
  signed by a third party before it reaches the legitimate officer.
  Vector (a) breaks RBAC; (b) breaks audit trail; (c) breaks the
  hand-off chain between emitter and signer.
- **Severity**: high (legal exposure for the CSP under 18 U.S.C. §1001
  False Statements; M-22-18 §III explicitly invokes federal false-
  statement law).
- **Mitigation**: (i) Tracker enforces a dedicated `corporate-officer`
  role distinct from `admin` and `officer` (cf. LOOP-S S-X8); a user
  must be assigned to a specific named officer identity (full name +
  title + bylaws-citation field) on the `ssdf_corporate_officers` table
  before they can sign. (ii) Officer identity is locked at sign time;
  the audit log records `signing_officer_id`, `signing_user_id` (the
  authenticated user account), `bylaws_citation`, and signature
  timestamp; mismatch between `signing_officer_id` and
  `signing_user_id`'s assigned officer identity rejects the sign-off
  with a `403 OFFICER_IDENTITY_MISMATCH` response. (iii) Out-of-band
  signing — T.T3 emits the canonical *unsigned* PDF; the officer applies
  the digital signature externally (Adobe Sign / DocuSign / x.509-based
  PDF signature); the tracker records the signed PDF's SHA-256 +
  signature certificate fingerprint as evidence that the binding
  document matches the emitted canonical bytes. (iv) Canonical-PDF
  determinism — `core/ssdf-common-form-pdf.ts` produces byte-identical
  output for identical inputs (no timestamps, no random UUIDs, no
  embedded fonts that vary by Node version); the SHA-256 is computed +
  recorded at emit time + re-verified at evidence-upload time.
  (v) REO Rule 1.6 / Rule 4 — the system MUST NOT auto-sign on the
  officer's behalf; CI test `T.T3-REO` asserts no Ed25519 / x.509
  signing path in `core/ssdf-common-form.ts` or in any tracker route
  that touches the attestation record.
- **Status**: open.

### T-X2 — Inconsistency between LOOP-J.J3.b engineering artifacts and LOOP-T corporate attestation

- **Description**: LOOP-J.J3.b emits SLSA Build L3 / SBOM / Sigstore
  provenance for every CI build (engineering attestation, per-binary).
  LOOP-T emits the CISA Common Form (corporate attestation,
  per-product, annual). The two surfaces describe overlapping practice
  groups — PS (Protect the Software) and PW (Produce Well-Secured
  Software) — and a divergence is materially dangerous. Concrete
  example: T.T3 emits a Common Form that attests "PW.4 — uses
  cryptographically signed releases" while LOOP-J.J3.b's most recent
  build for the same product emitted `cosign verify` failures because
  the build pipeline regressed last week. A 3PAO or contracting officer
  who cross-checks the two artefacts will reject the package and may
  cite false statement under 18 U.S.C. §1001.
- **Severity**: high (false-attestation / legal exposure).
- **Mitigation**: T.T2's satisfaction matrix joins SSDF practice rows
  against LOOP-J.J3.b's per-build attestation envelope, the SBOM index,
  and Sigstore Rekor entries (see LOOP-J-RISKS.md J-X*). For practices
  where the engineering signal is "RED" (e.g. last 7 days of builds
  contain ≥1 cosign verification failure for the in-scope product),
  T.T2 emits `practice_status: 'not-satisfied'` and T.T3's renderer
  REFUSES to render the Common Form attestation block as "Attested" —
  the operator MUST either remediate J.J3.b OR file a POA&M (M-22-18
  §III.E). The cross-check is encoded as `core/ssdf-cross-check.ts`
  unit-tested with a fixture matrix of (Common Form claim, J.J3.b
  status) pairs; CHANGELOG entry per slice cites the cross-check
  coverage. The unsigned PDF cover page renders a "Engineering
  evidence summary" table that surfaces J.J3.b status side-by-side
  with each attested practice so the corporate officer sees the
  alignment before signing.
- **Status**: open.

### T-X3 — NIST SP 800-218A still in Initial Public Draft as of Apr 2024; final-rule drift

- **Description**: NIST SP 800-218A "Secure Software Development
  Practices for Generative AI and Dual-Use Foundation Models" was
  posted as Initial Public Draft (IPD) in Apr 2024 and finalised
  Jul 26 2024. As of 2026-06-07, NIST has begun signalling minor
  revision work; a future minor-update (800-218A Rev 1 or 800-218A
  errata) could re-number augmentations, change the practice
  mappings, or introduce new practice tasks for content
  provenance / watermarking. T.T5's catalogue + tracker page would
  drift silently if the version pin is not enforced.
- **Severity**: med (correctness signal; not a ship-blocker because
  the Jul 2024 final is the currently-authoritative reference).
- **Mitigation**: `core/ssdf-ai-extension.ts` carries an
  `extension_version = "800-218A-final-2024-07-26"` constant; when
  NIST publishes an update, bump the constant + add deltas to the
  augmentation table; operator override via `ssdf-config.yaml
  ai_extension_overrides{}` for early adopters; CHANGELOG entry per
  update. The extractor script (`scripts/extract-ssdf-218A.mjs`)
  asserts the source PDF's SHA-256 against a known-good hash; mismatch
  flags `REQUIRES-OPERATOR-INPUT: confirm-against-new-revision`.
- **Status**: open.

### T-X4 — CISA Common Form schema changes (OMB 1670-0052 renewal cycle)

- **Description**: OMB Information Collection authorisations (OMB
  Control Numbers, prefixed 1670-XXXX for CISA) carry a 3-year renewal
  cycle under the Paperwork Reduction Act (44 U.S.C. §3501 et seq.).
  Form 1670-0052 was approved in 2024; the next renewal window opens
  in 2027. At renewal, CISA may revise field labels, re-number sections,
  add fields (e.g., AI-specific augmentation block), or change the
  attestation language. T.T3's canonical-PDF renderer is template-
  driven; a silent template-version drift would emit a form that does
  not match the form actively accepted by RSAA.
- **Severity**: high (a stale Common Form is rejected at RSAA upload).
- **Mitigation**: `core/ssdf-common-form.ts` version-pins the template
  as `template_version = "OMB-1670-0052-r1-2024-04"`; CHANGELOG +
  CI guard `check:common-form-version` verifies the constant against
  `templates/cisa-common-form.template.json`'s `schema_version` field
  at emit time; the renderer refuses to emit if a CLI-configured
  `--common-form-version` does not match. The template JSON is updated
  in a single dedicated commit when CISA publishes a revision; the
  operator runbook documents the renewal-watch process (check
  https://www.reginfo.gov/public/do/PRAMain quarterly under OMB
  Control Number 1670-0052 for renewal status). RSAA submission
  metadata records the template version used for forensic correlation
  with rejection events.
- **Status**: open.

### T-X5 — Agency-specific addenda layered on top of the Common Form

- **Description**: Even when an agency accepts the Common Form, some
  agencies (notably DoD components, the Department of State, IRS,
  the Veterans Administration) layer a customised addendum on top —
  asking the producer to additionally attest to agency-specific
  controls (e.g. DoD CIO supplemental questions, State Department
  FOCI questions, IRS Publication 1075 alignment). T.T4's tracker
  models per-agency submissions but T.T3's single canonical form
  cannot answer agency-specific addenda; a partial submission may be
  rejected.
- **Severity**: med (operational / coverage gap, not ship-blocker).
- **Mitigation**: T.T4 tracker `ssdf_agency_submissions` table carries
  an `addendum_required: boolean` + `addendum_template_path: text`
  + `addendum_status: ('not-required' | 'pending' | 'submitted')`
  per (agency, product) row; the UI surfaces a banner when
  `addendum_required && addendum_status === 'pending'`; the runbook
  documents the manual addendum-collection workflow; future
  enhancement (T.T6+) could ship per-agency addendum renderers as
  separate emit modules. The `data/known-agency-addenda.json`
  registry maintains a curated list of agencies known to require
  addenda; CHANGELOG entry per registry update.
- **Status**: open.

### T-X6 — Material-change re-attestation trigger ambiguity

- **Description**: OMB M-23-16 and the CISA Common Form expect
  re-attestation upon "material changes" to the producer's SSDF
  practices, but neither source defines "material" with precision.
  Examples of ambiguous changes: a sub-team adopting a new SAST tool,
  a CI pipeline migration (Jenkins → GitHub Actions), a personnel
  change at the VP Engineering level, an org-wide policy update to
  the SDLC. If T.T4's detector treats every minor change as material,
  the operator faces a re-attestation flood; if it under-detects, the
  operator ships a stale attestation that becomes false on a future
  audit.
- **Severity**: med.
- **Mitigation**: `core/ssdf-material-change-detector.ts` implements
  three tiers — **definitely material** (officer change, M&A,
  divestiture, withdrawal under T-X14, new contract under a new
  agency, change in EO-critical-software status), **likely material**
  (SDLC overhaul, CI pipeline migration, primary-language change,
  threat-model overhaul), **likely not material** (minor SAST tool
  update, branch-protection policy tweak, individual developer
  hire/depart). Tier 1 triggers automatic
  `requires_reattestation_within_30_days = true`; Tier 2 prompts the
  operator with a "Material change detected — confirm
  re-attestation?" modal in the UI; Tier 3 is recorded in the
  changelog but does not trigger re-attestation. The tier definitions
  are documented in `docs/runbooks/ssdf-material-change-runbook.md`
  + reviewed by general counsel before T.T4 ships; CHANGELOG entry
  for T.T4 cites the runbook version.
- **Status**: open.

### T-X7 — Practice cross-walk inaccuracy (SSDF → NIST 800-53 → KSI)

- **Description**: T.T1's catalogue cross-walks the 19 SSDF practices
  to NIST SP 800-53 Rev 5 controls and to FedRAMP 20x KSIs. The
  cross-walk is opinionated — NIST's own 800-218 §3 provides a
  representative (not definitive) mapping; gaps + multiple-mappings
  are common. A wrong cross-walk causes T.T2 to aggregate evidence
  from the wrong KSIs, which propagates into the Common Form
  attestation block as a false claim.
- **Severity**: high (false-attestation if the wrong evidence backs
  a "yes" practice claim).
- **Mitigation**: `data/ssdf-800-218-v1.1.json` records the cross-walk
  with three fields per practice: `mapping_source` (one of
  `nist-800-218-appendix-a`, `nist-irc-rsa-2024`,
  `operator-defined-via-ssdf-config-yaml`), `mapping_confidence`
  (`high` / `medium` / `low`), `mapping_rationale` (free-text
  justification). T.T2 propagates `mapping_confidence: 'low'` rows to
  the Common Form as `requires-operator-review` flags; T.T3's
  renderer refuses to mark the practice as Attested when ANY
  contributing mapping is `low` and unreviewed. The cross-walk is
  reviewed against NIST SP 800-218 Appendix A + NIST IR cybersecurity
  framework v2 informative references + FedRAMP 20x KSI manifest at
  catalogue-extraction time (T.T1); a CHANGELOG cross-walk delta is
  emitted on every catalogue update.
- **Status**: open.

### T-X8 — Operator misclassifying a software product as out-of-scope

- **Description**: M-22-18 / M-23-16 scope is defined as "software
  developed after the effective date of this memorandum, as well as
  existing software that is modified by major version changes ...
  after the effective date." The operator decides per product whether
  the product is in scope. A mis-classification — declaring a SaaS
  product "out of scope" because the operator misreads the EO-critical
  definition or because the operator forgets a major-version release
  — produces zero Common Forms for a product that should have one, a
  procurement-blocking gap discovered at contract award.
- **Severity**: high (contract-award blocker; no T.T3 artefact emitted
  for an in-scope product).
- **Mitigation**: T.T1's `ssdf_products` registry is populated by the
  operator via the tracker UI; first-boot wizard walks the operator
  through M-22-18 scope criteria with explicit yes/no checkboxes
  (developed-post-effective-date, major-version-modification-post-
  effective-date, EO-critical-software, federal-customer); the
  registry records `in_scope: boolean` with `in_scope_rationale:
  text` and `in_scope_decided_by: user_id` for audit. The runbook
  documents the EO-critical definition (NIST EO-critical-software
  definition, last revised Oct 13 2021 — URL:
  https://www.nist.gov/itl/executive-order-improving-nations-
  cybersecurity/critical-software-definition); a quarterly
  re-classification job (`scripts/ssdf-rescan-scope.mjs`) prompts
  the operator if no review has occurred in 90 days. CHANGELOG entry
  on every product addition documents the in-scope rationale.
- **Status**: open.

### T-X9 — POA&M required when one or more practices cannot be fully attested (M-22-18 §III.E)

- **Description**: M-22-18 §III.E permits a producer to identify
  practices "to which they cannot attest, document practices they
  have in place to mitigate associated risks, and provide an agency
  with a Plan of Action and Milestones (POA&M)." If T.T2 surfaces
  any practice as `not-satisfied` or `partially-satisfied`, the
  Common Form (T.T3) is incomplete UNLESS a corresponding POA&M is
  emitted via LOOP-B.B5 + attached to the Common Form package. A
  silent omission produces a Common Form that overclaims (every
  attested practice marked "yes" when the underlying evidence shows
  `not-satisfied`).
- **Severity**: high (false-attestation risk; M-22-18 §III.E is
  explicit).
- **Mitigation**: T.T3's renderer iterates the T.T2 matrix; for every
  practice row that is not `satisfied`, the renderer REQUIRES a
  matching POA&M item with `risk_category = 'ssdf-attestation-gap'`
  + `practice_id = <practice>` + `task_id = <task>` to exist in
  `out/poam.json`; missing POA&M items cause the renderer to fail
  with a typed `MissingPOAMItemError(practice_id, task_id)` and emit
  a `REQUIRES-OPERATOR-INPUT: file-poam-for-ssdf-gap` diagnostic.
  Operator workflow: file POA&M items via LOOP-B.B1's tracker UI
  before re-running T.T3. The Common Form's Section V (Plan of
  Action and Milestones) is auto-populated from `out/poam.json`
  filtered by `risk_category = 'ssdf-attestation-gap'`. CHANGELOG
  entry per T.T3 documents the POA&M wiring; CI integration test
  asserts the POA&M-required path is exercised.
- **Status**: open.

### T-X10 — Repository for Software Attestations and Artifacts (RSAA) upload failure modes

- **Description**: CISA RSAA (https://rsaa.cisa.gov/) is the federal
  civilian central repository for signed Common Forms. RSAA accepts
  PDF + JSON metadata; rejection modes include (a) wrong OMB control
  number, (b) PDF signature certificate revoked, (c) malformed
  metadata, (d) duplicate submission for same product/fiscal year
  (RSAA dedupes; an unintentional resubmission is treated as a
  modification request), (e) RSAA infrastructure outage. LOOP-T does
  NOT auto-upload (REO Rule 4 — submission is a human action with
  CAC / PIV / agency-issued credentials the system must not hold),
  but the tracker DOES record the upload outcome the operator
  reports. A missed rejection signal leaves the operator believing
  the Common Form is on file when it is not.
- **Severity**: med (procurement-blocking; not code-correctness).
- **Mitigation**: T.T4 tracker `ssdf_agency_submissions` table carries
  `submission_status: enum('drafted', 'signed', 'submitted',
  'accepted', 'rejected', 'withdrawn')` + `submission_receipt_id:
  text` + `rejection_reason: text` per (agency, product, fiscal_year)
  row; the operator records the RSAA receipt ID after upload; rejection
  triggers an automatic re-render request. The runbook documents the
  RSAA upload steps + rejection-recovery procedure. A future LOOP-Q.Q2
  Marketplace integration could surface RSAA receipt IDs via a
  Marketplace lookup if CISA publishes the API.
- **Status**: open.

### T-X11 — Distinction collapse between LOOP-T (procurement) and LOOP-J.J3.b (engineering) — risk of duplicate attestation

- **Description**: A developer who does not read the LOOP-T spec
  carefully may collapse the two attestation tracks — treating LOOP-T
  as "another way to ship the J.J3.b output" — leading to (a) duplicate
  emit of the same evidence under different labels, (b) confusion in
  the submission bundle (which artefact goes where?), (c) regression
  of the corporate-officer signature requirement when the
  J.J3.b automated signature is treated as equivalent.
- **Severity**: med (architectural drift).
- **Mitigation**: `LOOP-T-SPEC.md §1` (already authored) contains an
  explicit comparison table distinguishing the two surfaces; every
  T.T* docstring opens with a 1-paragraph "LOOP-T is NOT J.J3.b"
  disclaimer; the submission bundler (LOOP-A.A4) has separate roles
  for `ssdf-common-form-pdf` (LOOP-T) and
  `slsa-build-attestation-blob` (J.J3.b) — neither role can be
  substituted for the other. A regression test
  `tests/integration/loop-t-vs-loop-j.test.ts` asserts the two
  emitters produce distinct artefacts under disjoint role names + no
  cross-substitution under any orchestrator flag combination.
- **Status**: open.

### T-X12 — Annual cadence drift (each agency has its own renewal date)

- **Description**: M-22-18 / M-23-16 set the annual cadence as
  "annually, or upon material change". Each agency interprets
  "annually" relative to its own contract anniversary, not relative
  to a fiscal-year boundary; a producer with 12 agency customers may
  face 12 different renewal dates. T.T4's tracker must track per-
  agency renewal dates; treating "annual" as a single org-wide
  refresh would miss renewals on out-of-cycle agencies.
- **Severity**: med.
- **Mitigation**: T.T4's `ssdf_agency_submissions` table carries
  `original_attestation_date: date`, `next_renewal_due:
  date = original_attestation_date + 365 days`, + per-agency override
  via `renewal_cadence_days: int` (some agencies require 6-month
  refreshes for higher-impact systems); the renewal-watcher CRON
  emits a 60-day, 30-day, 14-day, 7-day, 1-day pre-due notification
  via `core/notify.ts`. The runbook documents the per-agency
  recording workflow. CHANGELOG entry for T.T4 cites the per-agency
  cadence model.
- **Status**: open.

### T-X13 — Open-source dependency attestation gap (CSP cannot attest for upstream OSS)

- **Description**: M-22-18 §III.D permits producers to rely on
  third-party suppliers' attestations, but the producer remains the
  attesting party. For deeply-transitive open-source dependencies,
  upstream OSS maintainers (e.g. solo maintainers of small npm /
  PyPI packages) often do NOT publish SSDF attestations. T.T2's
  evidence aggregator that sources practice PS.3.1 ("Archive and
  protect each software release") from an SBOM may surface
  thousands of OSS dependencies for which no upstream attestation
  exists.
- **Severity**: med (operational gap; affects PS.3, PW.4, PW.7).
- **Mitigation**: T.T2 distinguishes three evidence states per
  practice: `first-party-attested` (the producer's own code),
  `third-party-attested-via-vendor` (commercial dependencies with
  vendor SSDF attestation on file), `upstream-oss-unattested`
  (OSS dependencies without SSDF attestation). The Common Form
  attestation language for PS.3 / PW.4 explicitly carves out
  `upstream-oss-unattested` as a known gap; T.T2 emits an OSS
  attestation gap report (`out/ssdf-oss-attestation-gap.json`)
  enumerating the unattested dependencies. The runbook documents
  the operator's mitigation options: switch to attested commercial
  alternatives, vendor + maintain a private fork (taking on the
  attestation responsibility), or file a POA&M (cf. T-X9). LOOP-J's
  SBOM minimum-elements work surfaces the dependency list; T.T2
  joins against that.
- **Status**: open.

### T-X14 — Withdrawn-attestation handling (security incident triggers withdrawal)

- **Description**: A material security incident (e.g. CVE in the
  CSP's own product disclosed via LOOP-G.G2 incident reporting, or
  a CIRCIA-reportable incident) may force the producer to *withdraw*
  a previously-submitted Common Form attestation. Withdrawal has
  cascading federal-acquisition consequences: existing federal
  contracts may be paused; new contract awards may be denied; the
  procurement officer must be notified within an agency-specific
  window (typically 5 business days). The current LOOP-T design has
  no withdrawal workflow; absent it, the operator ships a Common
  Form that is materially inaccurate after the incident.
- **Severity**: high (legal exposure post-incident; cascading contract
  consequences).
- **Mitigation**: T.T4 tracker `ssdf_agency_submissions.submission_
  status` adds a `withdrawn` state with `withdrawal_reason: text` +
  `withdrawal_notified_date: timestamp` + `withdrawing_officer_id:
  reference` fields; a withdrawal triggers an automatic notification
  to each agency `contracting_officer_email` (operator-provided via
  `ssdf-config.yaml agencies[*].contracting_officer_email`); the
  withdrawal is countersigned by the corporate officer + recorded
  with Ed25519 audit-log signature. The runbook documents the
  cross-loop withdrawal flow: incident detection (LOOP-G.G2 /
  CIRCIA) → operator decision to withdraw → T.T4 withdrawal action
  → re-attestation under T.T3 once remediation lands → re-
  submission. CHANGELOG entry for T.T4 cites the withdrawal model.
  Cross-references LOOP-G-RISKS.md + CIRCIA-WORKFLOW.md.
- **Status**: open.

### T-X15 — Cross-agency uplift drift (one agency accepts the Common Form; another insists on a custom addendum)

- **Description**: Even within the post-M-26-05 voluntary regime,
  agencies will diverge in how they consume the Common Form:
  agency A accepts the canonical form as-is, agency B requires a
  custom addendum (cf. T-X5), agency C reverts to a legacy
  agency-specific attestation form (e.g. SaaS Vendor Risk
  Assessment), agency D requires a 3PAO-validated attestation
  instead of a self-attestation. The producer cannot ship a single
  Common Form across all agencies without per-agency tailoring,
  but tailoring multiplies the operator's workload + introduces
  drift risk between tailored versions.
- **Severity**: med.
- **Mitigation**: T.T4's `ssdf_agency_submissions` table carries
  `submission_modality: enum('common-form', 'common-form-with-
  addendum', 'agency-specific-form', '3pao-validated-attestation',
  'rejected')` + a `tailoring_diff: jsonb` recording the delta from
  the canonical Common Form for each agency's submission. The
  runbook documents the per-agency intake process; a quarterly
  cross-agency reconciliation report (`out/ssdf-per-agency-
  reconciliation-FYNNNN.json`) surfaces inconsistencies (e.g.
  agency A told "yes" for PS.3, agency B told "with caveat" for
  PS.3) for operator review. Future enhancement could ship a
  per-agency template registry under `templates/agency-
  tailoring/<agency-code>.template.json`.
- **Status**: open.

### T-X16 — DoD-prime equivalency: SSDF attestation as DFARS Body-of-Evidence

- **Description**: DoD-prime customers (LOOP-S DFARS scope)
  increasingly demand the SSDF Common Form as part of the DFARS
  equivalency Body-of-Evidence even though M-22-18 / M-23-16 are
  civilian-agency memos. The CSP shipping LOOP-S equivalency
  artefacts must coordinate with LOOP-T to ensure the SSDF
  attestation referenced in the DFARS Equivalency Letter (LOOP-S.S3)
  matches the current LOOP-T attestation on file. A version drift
  (LOOP-S.S3 cites Common Form FY2026; LOOP-T's tracker shows a
  withdrawn FY2026 + a re-issued FY2026-r2) breaks the equivalency
  package.
- **Severity**: med.
- **Mitigation**: LOOP-S.S3 manifest reads
  `out/ssdf-agency-submissions.json` and references the active SSDF
  attestation record by `attestation_id` + `signed_form_sha256` +
  `template_version`; a withdrawal under T-X14 cascades to the LOOP-S
  manifest as a "DFARS Body-of-Evidence stale" alert; the runbook
  documents the dual-track coordination. Cross-references LOOP-S-
  RISKS.md S-X11 / S-X20.
- **Status**: open.

### T-X17 — Legal-counsel review bottleneck (every Form requires general-counsel sign-off)

- **Description**: A corporate-officer-signed Common Form is a
  binding legal document. In practice, every emit ships through
  general counsel for review before the corporate officer signs;
  general counsel review can take 5-15 business days per form. For
  a producer with 12 agency renewals and multiple material-change
  re-attestations per year, the legal-review queue becomes the
  rate-limiting step; an operator pressed for time may pressure
  counsel to skim, increasing the risk of an erroneous attestation.
- **Severity**: med (operational; not code-correctness, but
  cascading into false-attestation risk).
- **Mitigation**: T.T4 tracker workflow adds an explicit
  `legal_review_status: enum('not-started', 'in-review',
  'approved', 'rejected', 'changes-requested')` +
  `legal_reviewer_id` + `legal_review_completed_at` per
  attestation record; the renderer (T.T3) refuses to mark the
  attestation as "ready-to-sign" unless `legal_review_status ===
  'approved'`. The renderer ships a 1-page "legal-review summary"
  (auto-attached to the unsigned PDF) that surfaces the practice
  matrix + POA&M list + cross-walk confidence flags + J.J3.b
  cross-check status so counsel can review in 30-60 minutes
  instead of 5-15 days. The runbook documents the legal-review
  expectations.
- **Status**: open.

### T-X18 — AI/ML model card propagation lag (T.T5 depends on O.O5 model cards)

- **Description**: T.T5's AI augmentation worksheet reads
  LOOP-O.O5's model-card evidence to populate the 800-218A
  augmentations. If O.O5's model card has not been updated for the
  latest model version, T.T5's worksheet reflects stale model
  metadata; the corporate officer signs a Common Form whose AI
  augmentation block attests to a model that is no longer in
  production. The propagation lag between model deployment + model-
  card refresh is a known gap (cf. LOOP-O-RISKS.md O-X*).
- **Severity**: med.
- **Mitigation**: T.T5 reads
  `out/oscal-ssp.json` augmented with O.O5 model-card data + the
  per-model `model_card.last_refreshed_at` timestamp; T.T5 refuses
  to mark the AI augmentation block as ready unless every in-scope
  model's card was refreshed within the past 90 days. Stale model
  cards emit `REQUIRES-OPERATOR-INPUT: refresh-model-card-<model_
  id>`; the runbook documents the refresh cadence. Cross-references
  LOOP-O-RISKS.md.
- **Status**: open.

### T-X19 — Post-M-26-05 voluntary regime: legacy contract flow-down still binds

- **Description**: OMB M-26-05 (Jan 23 2026) rescinded the
  *mandatory* M-22-18 / M-23-16 Common Form collection requirement,
  shifting to a tailored risk-based approach. A naive operator may
  conclude that LOOP-T is no longer needed. This is wrong on three
  counts: (a) legacy federal contracts entered before Jan 23 2026
  frequently incorporate M-22-18 / M-23-16 obligations whose
  flow-down to the CSP persists through the contract term (often
  5-10 years); (b) M-26-05 explicitly permits agencies to continue
  using the Common Form / SSDF / RSAA on a tailored basis, and many
  will; (c) DoD-prime customers (LOOP-S) demand the Common Form as
  DFARS equivalency evidence regardless of OMB's civilian-side
  rescission. An operator who decommissions LOOP-T post-M-26-05
  faces contract-award denial + breach-of-contract exposure under
  the legacy flow-down clauses.
- **Severity**: high (legal exposure for the CSP).
- **Mitigation**: `LOOP-T-SPEC.md §1` (already authored) contains the
  M-26-05 applicability note; the CLAUDE.md reading list cites the
  M-26-05 carve-out; T.T4's tracker UI shows a "M-26-05 applicability
  matrix" page per agency listing each agency's post-rescission
  posture (continues-mandatory / continues-voluntary / accepts-
  voluntary / no-longer-requires) so the operator does not over-
  rotate on M-26-05; the runbook documents the
  contract-flow-down review procedure. CHANGELOG entry for the
  LOOP-T loop ship cites the M-26-05 applicability rationale.
- **Status**: open.

### T-X20 — REO Rule 1.8: `process.env.NODE_ENV === 'test'` branch creep

- **Description**: REO Rule 1.8 prohibits this branch in production
  code. The new SSDF emit infrastructure (PDF renderer, satisfaction
  matrix joiner, cross-check engine, tracker review-snapshot reader,
  per-agency submission registry) is exactly where developers reach
  for `if (NODE_ENV === 'test')` shortcuts when injection seams are
  tricky.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal;
  tests inject seams via dependency-injected HTTP fetcher +
  filesystem helper + clock helper + PDF-renderer seam; CI gate is
  non-bypassable. Cross-references LOOP-B-X6, LOOP-R-X6, LOOP-S-X15.
- **Status**: open.

### T-X21 — Provenance schema drift across new emit artifacts

- **Description**: Every new emit artifact (`ssdf-practices-catalog.
  json`, `ssdf-satisfaction-matrix.json`, `ssdf-satisfaction-matrix.
  xlsx`, `ssdf-common-form-<product>-FYNNNN.pdf`, `ssdf-common-form-
  manifest-<product>-FYNNNN.json`, `ssdf-ai-augmentation-worksheet-
  <product>-FYNNNN.json`, `ssdf-agency-submissions.json`, `ssdf-oss-
  attestation-gap.json`) must carry a `provenance` block per REO Rule
  2.6. `scripts/check-provenance.mjs` enforces the schema (emitter,
  emittedAt, sourceCalls, signingKeyId). A missed block silently
  fails the slice.
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via
  `check:provenance`; pattern reused from `core/inventory-coverage.
  ts`. Cross-references LOOP-B-X9, LOOP-R-X9, LOOP-S-X16. CHANGELOG
  entry per slice cites the provenance block contents.
- **Status**: open.

### T-X22 — Submission-bundle role count growth + per-product/per-FY pattern

- **Description**: LOOP-T adds 8-10 new roles to
  `submission-bundle.ts:WELL_KNOWN`
  (`ssdf-practices-catalog-json`, `ssdf-satisfaction-matrix-json`,
   `ssdf-satisfaction-matrix-xlsx`,
   `ssdf-common-form-pdf-{product}-FYNNNN`,
   `ssdf-common-form-manifest-json-{product}-FYNNNN`,
   `ssdf-ai-augmentation-worksheet-json-{product}-FYNNNN`,
   `ssdf-agency-submissions-json`,
   `ssdf-oss-attestation-gap-json`). Per-product + per-FY suffixed
  filenames require `filenamePattern` (regex) support added in
  LOOP-R-X8.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins both
  literal-filename and `filenamePattern` role matches; per-slice
  tests assert presence; CHANGELOG entry for the LOOP-T close lists
  the final role inventory. Cross-references LOOP-R-X8.
- **Status**: open.

### T-X23 — Tracker schema migration on existing installs

- **Description**: LOOP-T adds 8 new tables (`ssdf_corporate_
  officers`, `ssdf_products`, `ssdf_agency_submissions`,
  `ssdf_attestations`, `ssdf_attestation_signatures`,
  `ssdf_material_changes`, `ssdf_ai_models`, `ssdf_oss_attestation_
  gaps`). Existing tracker installs have user data — migrations must
  be additive only.
- **Severity**: high.
- **Mitigation**: All eight tables are additive `CREATE TABLE IF NOT
  EXISTS`; CHANGELOG documents the upgrade path; smoke test on a
  copy of a production DB; no DROP / ALTER COLUMN under any
  circumstance in LOOP-T; multi-tenant work batches all cross-loop
  migrations under LOOP-H.H3. Cross-references LOOP-B-X10, LOOP-R-X10,
  LOOP-S-X18.
- **Status**: open.

### T-X24 — Tracker Ed25519 signing-key rotation across fiscal-year boundaries

- **Description**: T.T3 + T.T4 sign tracker-side audit records with
  the tracker-resident Ed25519 key. Multi-fiscal-year attestation
  records persist indefinitely. Tracker resident-key rotation, AO
  role-holder rotation, or system-wide signing-key rotation across
  fiscal-year boundaries could invalidate prior-FY attestation
  audit-log signatures during T.T4 cross-FY reporting.
- **Severity**: med.
- **Mitigation**: Tracker exposes `GET /api/sign/public-keys`
  returning all historical keys keyed by `key_id`; reader cross-
  references each audit record's `signing_key_id` against the
  registry. Pattern reused from LOOP-B-X3, LOOP-R-X4, LOOP-S-X6.
  Key rotation events written to `audit_log`; runbook documents.
- **Status**: open.

### T-X25 — CISA Common Form PDF determinism + font/Acrobat compatibility

- **Description**: A canonical-PDF emitter is only deterministic if
  every input that influences the PDF byte stream is pinned: PDF
  library version, font set, page-size, embedded image bytes,
  metadata timestamps. T-X1's forgery mitigation depends on
  byte-level determinism. The Common Form PDF must also render
  correctly in Adobe Acrobat Reader + Foxit + browser-native viewers
  (Chromium PDF viewer is the most common at federal agencies)
  without layout drift; certain SVG-rendering paths break in
  agency-restricted viewers.
- **Severity**: med (determinism: high if violated; cross-viewer
  rendering: med).
- **Mitigation**: `core/ssdf-common-form-pdf.ts` pins the PDF library
  version (`pdf-lib` or `pdfkit`, decision pending T.T3 implementation
  + spike); pins the font set (NIST recommends Open Sans for
  accessibility; the renderer embeds the font subset); pins the
  page-size (US Letter, 612x792 pt); strips creation/modification
  timestamps from PDF metadata (overrides with the
  `effective_attestation_date` constant from the input). Cross-
  viewer testing: a CI job renders the canonical PDF + runs it
  through `pdftotext` to assert text-layer extractability;
  manual-QA checklist on Acrobat + Chromium + Foxit before each
  template-version bump.
- **Status**: open.

### T-X26 — Practice catalogue version pinning vs operator override drift

- **Description**: T.T1 ships the 800-218 v1.1 catalogue + an
  override mechanism (`ssdf-config.yaml practice_overrides{}`) for
  operator adjustments (e.g. mapping a custom-internal-practice ID
  to an 800-218 task). Overrides without a version pin drift when
  the operator forgets they overrode a mapping; on a future
  catalogue refresh, the override silently overrides the new
  mapping (which may not be what the operator wanted).
- **Severity**: low.
- **Mitigation**: Every operator override records
  `override_for_catalog_version: text` + `override_created_at:
  timestamp`; on catalogue version bump, the loader flags overrides
  whose `override_for_catalog_version` does not match the current
  version as `REQUIRES-OPERATOR-INPUT: review-override-against-new-
  catalogue-version`. The runbook documents the override-review
  procedure on every catalogue refresh.
- **Status**: open.

### T-X27 — Test count expectations / CI thresholds

- **Description**: LOOP-T adds ≥110 new tests across cloud-evidence
  + tracker (per-slice estimates: T.T1 ~15, T.T2 ~30, T.T3 ~25,
  T.T4 ~20, T.T5 ~20). Existing CI may have hard-coded "expected
  test count" assertions or coverage thresholds that need bumping.
- **Severity**: low.
- **Mitigation**: Per slice, the implementing session updates any
  test-count assertion; CHANGELOG entries cite the new totals;
  STATUS.md "Overall → tests" line bumped atomically with each
  slice ship. Cross-references LOOP-B-X13, LOOP-R-X13, LOOP-S-X24.
- **Status**: open.

### T-X28 — Multi-CSO / multi-product tenant isolation deferred to LOOP-H.H3

- **Description**: All eight LOOP-T tracker tables omit a
  `tenant_id` column. When multi-CSO ships (H.H3), all eight need
  migration in a single cross-loop sweep. For a CSP with multiple
  product lines (a common pattern), `ssdf_products.product_id`
  serves as the per-product key but lacks tenant scoping.
- **Severity**: med (long-tail).
- **Mitigation**: Documented in `LOOP-T-SPEC.md §11 Open Questions`;
  H.H3 spec must enumerate every LOOP-T table; LOOP-T ships in
  single-tenant deployments only (documented in runbook). Cross-
  references LOOP-B-X15, LOOP-R-X15, LOOP-S-X21.
- **Status**: open.

### T-X29 — RSAA submission API non-existence (manual upload only)

- **Description**: As of 2026-06-07, CISA RSAA does not publish a
  programmatic submission API; submissions are manual web-form
  uploads with operator CAC/PIV. If a future CISA RSAA API is
  published, the tracker MUST NOT auto-submit (REO Rule 4 — submission
  is a human action requiring federal credentials). The risk is that
  a developer reads the published API + adds auto-submission as a
  "convenience".
- **Severity**: high (REO violation if implemented).
- **Mitigation**: A T.T4 unit test asserts no HTTPS call to
  `rsaa.cisa.gov` from any production code path (mirrors the LOOP-S
  S-X14 pattern asserting no auto-submit to `dibnet.dod.mil`); CI
  gate is non-bypassable; CLAUDE.md REO Rule 4 example list updated
  to include RSAA as a "never auto-submit" target. Cross-references
  LOOP-S-X14.
- **Status**: open.

### T-X30 — CISA Software Acquisition Guide alignment drift

- **Description**: CISA published the "Software Acquisition Guide
  for Government Enterprise Consumers: Software Assurance in the
  Cyber-Supply Chain Risk Management (C-SCRM) Lifecycle" (Aug 2024).
  The Guide layers procurement-side expectations on top of the
  Common Form; a producer ignoring the Guide may receive procurement
  pushback at agencies that have adopted the Guide as internal
  policy. The Guide is not law but is increasingly cited by agency
  CIOs.
- **Severity**: low (procurement risk; not code-correctness).
- **Mitigation**: T.T3's docstring + runbook reference the Software
  Acquisition Guide as a procurement-side companion to the Common
  Form; T.T4's per-agency policy tracker records which agencies
  have adopted the Guide internally; future enhancement could ship
  a Guide-alignment supplementary report. CHANGELOG entry for T.T3
  cites the Guide URL.
- **Status**: open.

---

## Per-slice risks

### T.T1 — SSDF Practices Inventory (catalogue + extractor)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| T.T1-1 | high | NIST SP 800-218 PDF / Excel companion under HTTP 403 to anonymous fetch; cross-walk extraction blocked | Implementer downloads PDF + xlsx to `cloud-evidence/docs/sources/`; extractor asserts SHA-256 against pinned hash; `REQUIRES-OPERATOR-INPUT: confirm-against-pdf` marker on every quote until verified | resolved (2026-06-10): PDF fetched + committed to `docs/sources/NIST.SP.800-218.pdf` (sha256 `617746e5…`, pinned in catalog `source_pdf_sha256`); all practice/task text + 800-53 controls parsed verbatim from it; the xlsx companion was not needed (PDF Table 1 sufficed). |
| T.T1-2 | high | Cross-walk inaccuracy SSDF → 800-53 → KSI (cross-ref T-X7) | `mapping_confidence` field + per-practice `mapping_source` + `mapping_rationale`; CHANGELOG cross-walk delta on every catalogue update | open |
| T.T1-3 | med | NIST SP 800-218 v1.2 / Rev 2 publication horizon (currently v1.1 from Feb 2022; updates expected pre-2030) | `catalog_version` constant pins source version; bump constant + add deltas + version-aware operator overrides on revision | open |
| T.T1-4 | med | Operator override drift (cross-ref T-X26) | `override_for_catalog_version` field on every override row; flagged for review on version bump | open |
| T.T1-5 | low | Custom internal practices that do not map to any 800-218 task (e.g. organisation-specific FOCI controls) | Operator declares `custom_practice` rows via `ssdf-config.yaml`; cross-walk surfaces unmapped customs as informational rows in T.T2 matrix | open |
| T.T1-6 | low | NIST publishes only a representative cross-walk to 800-53 in 800-218 Appendix A; FedRAMP 20x KSI cross-walk is the operator's invention | Cross-walk documented as `mapping_source: 'operator-defined-via-cloud-evidence'`; reviewable + adjustable; CHANGELOG documents the canonical KSI cross-walk that ships out-of-the-box | open |
| T.T1-7 | med | PDF / xlsx extraction script silently emits empty catalogue if source format changes | Extractor asserts expected practice count (19) + expected task count (43) + practice-group enumeration (PO, PS, PW, RV); throws typed `CatalogueShapeMismatchError` on drift; CI runs the extraction on every PR | resolved (2026-06-10): extractor + loader throw typed `SsdfExtractError` (ERR_SSDF_PRACTICE_COUNT_MISMATCH / ERR_SSDF_TASK_COUNT_MISMATCH / ERR_SSDF_NAME_MISMATCH / ERR_SSDF_STATEMENT_MISSING) on any shape drift. NB: the asserted task count is **42** (the real Table 1 active-task count), not 43 — see T.T1-16. |
| T.T1-8 | low | Catalogue extractor non-deterministic ordering (PDF text extraction may shuffle rows) | Extractor sorts output by `(practice_group, practice_id, task_id)` before emit; CHANGELOG documents the sort order | resolved (2026-06-10): practices emitted in canonical PO→PS→PW→RV / ascending order; tasks sorted ascending; controls + Common Form refs + withdrawn tasks sorted; canonical-JSON (RFC 8785) re-serialization is byte-deterministic (test T18). |
| T.T1-9 | low | NIST IR 8397 minimum-developer-verification practices not in 800-218 catalogue | IR 8397 cross-walk is a `data/ssdf-irc-8397-supplement.json` overlay loaded conditionally; not on the Common Form attestation path; documented as a `coverage_source` field | open |
| T.T1-10 | low | Bilingual / accessibility text variants for practice descriptions | English-only at launch; future enhancement could add localisation; documented in operator runbook | open |
| T.T1-11 | med | NIST SP 800-53 Rev 6 horizon (currently Rev 5 errata Dec 2023); a future Rev 6 would require catalogue regeneration | `nist_53_revision: '5'` constant pinned in cross-walk; bump + regenerate cross-walk on Rev 6 publication | open |
| T.T1-12 | low | NIST CSF v2.0 informative references to SSDF tasks may drift; T.T1 does not currently consume CSF cross-walks | Out of T.T1 scope; future enhancement could add CSF cross-walk overlay | open |
| T.T1-13 | low | Practice ordering for UI display (alphabetical vs canonical 800-218 order) | Renderer sorts by canonical 800-218 §3 order (PO → PS → PW → RV) by default; operator override via `ssdf-config.yaml ui_practice_sort_order` | open |
| T.T1-14 | low | NIST publishes the SSDF practices xlsx with merged cells / metadata rows; extractor must skip them | Extractor normalises merged-cell rows + asserts a "Date generated" cell exists in the source; CHANGELOG documents the parsing assumptions | open |
| T.T1-15 | low | Cross-walk references to FedRAMP-deprecated KSIs (KSI catalogue versioning under LOOP-A) | Cross-walk records FedRAMP KSI catalogue version (`fedramp_ksi_catalog_version`); on KSI catalogue refresh, T.T1 flags now-deprecated cross-walks for operator review | open |
| T.T1-16 | med | **Authoritative count reconciliation (discovered 2026-06-10).** The spec stated SSDF v1.1 has "43 tasks" and that every practice maps to ≥1 SP 800-53 control; the committed NIST PDF actually has **42 active tasks** (+5 withdrawn) and **PW.2 / PW.5 carry NO `SP80053:` reference** in Table 1. A spec-trusting implementation would have asserted the wrong shape and either failed or fabricated controls. | RESOLVED: extractor + loader assert `EXPECTED_TASK_COUNT = 42`; tests pin PW.2/PW.5 as the only two un-mapped practices (17/19 mapped) and the per-group split (13/4/16/9); reconciliations documented in `docs/slices/T/T.T1.md` §10. Authoritative source wins (REO). | resolved |
| T.T1-17 | med | **Ephemeral signing key.** When `EVIDENCE_SIGNING_KEY_PATH` is unset, the catalog is signed with an ephemeral Ed25519 keypair generated at build time. The committed `data/ssdf-800-218-v1.1.json` self-verifies via its embedded `provenance.publicKeyPem`, but its signature is not anchored to the org's stable published key, and a re-extract produces a different `signingKeyId`. | Set `EVIDENCE_SIGNING_KEY_PATH` to a stable Ed25519 key before authoritative regeneration; the catalog records `provenance.signingKeyId` so a verifier can locate the right pubkey (cf. T.T1-R6 / `core/key-registry.ts` future). The extractor writes the ephemeral private key to a transient temp dir (never `data/`). | open |
| T.T1-18 | med | **pdf-parse runtime dependency.** The spec assumed `pdf-parse` was "existing from LOOP-C.C2"; it was absent (LOOP-C is unimplemented). It was added as a devDependency (`pdf-parse@^2.4.5`, new `PDFParse` class API). A future pdf-parse major could change the extracted text layout and break the Table 1 parse. | Mitigated by deterministic structural assertions (19 practices / 42 tasks / 4 groups / exact id set / each practice name verified present in the PDF text) that fail loudly on any drift, plus the sha-pinned committed PDF + committed catalog (regeneration is rare, not per-CI). The runtime loader (`core/ssdf-practices-catalog.ts`) does NOT depend on pdf-parse — only the build-time extractor does. | open |
| T.T1-19 | low | **Common Form mapping is the abbreviated published set.** `COMMON_FORM_TASK_MAP` ships the documented §2.6 CISA Section IV → SSDF task mapping (11 practices / a subset of tasks). CISA's fuller instruction maps the four attestations to 17 of 19 practices / 31 of 43 tasks; the gap to that fuller mapping is a T.T2 (satisfaction-matrix) concern. | `COMMON_FORM_TASK_MAP` is a named, PR-reviewable constant in `core/ssdf-practices-catalog.ts`; T.T2 extends it to the full CISA per-task mapping when it builds the satisfaction matrix. Test pins `tasksByCommonFormSection('§IV(3)')` ⊇ {PS.3.2}. | open |

### T.T2 — SSDF Evidence Aggregator + Satisfaction Matrix

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| T.T2-1 | high | Practice satisfaction false-positive (matrix says "satisfied" when evidence is weak) | Evidence aggregation requires ≥1 high-confidence `coverage_source` + zero `coverage:miss` lines per task; matrix rows record `confidence: enum('high','medium','low')` + per-evidence justification; T.T3 refuses to mark "Attested" when ANY contributing evidence is `low` | open |
| T.T2-2 | high | Engineering-vs-corporate drift (cross-ref T-X2) | `core/ssdf-cross-check.ts` joins T.T2 matrix against LOOP-J.J3.b status; J.J3.b "RED" forces T.T2 row to `not-satisfied`; CHANGELOG cites cross-check coverage | open |
| T.T2-3 | high | POA&M required for not-satisfied practices (cross-ref T-X9) | `out/poam.json` filtered by `risk_category = 'ssdf-attestation-gap'` is required for every not-satisfied row; missing items raise `MissingPOAMItemError`; tracker UI surfaces filing workflow | open |
| T.T2-4 | med | Upstream OSS attestation gap (cross-ref T-X13) | Matrix distinguishes `first-party-attested` / `third-party-attested-via-vendor` / `upstream-oss-unattested`; OSS-gap report emitted to `out/ssdf-oss-attestation-gap.json` | open |
| T.T2-5 | med | KSI evidence envelope schema drift; aggregator reads multiple LOOPs' envelopes | Aggregator pins each consumed envelope schema version; CI integration test asserts cross-loop schema compatibility; CHANGELOG records pinned versions | open |
| T.T2-6 | med | Cross-walk confidence `low` rows propagate as `requires-operator-review` flags but operator may rubber-stamp | UI requires per-flag operator justification text + reviewer-id + timestamp; audit log records every rubber-stamp event; quarterly compliance review surfaces stamp rate | open |
| T.T2-7 | med | Matrix .xlsx + .json emit divergence (one updated; other not) | Single source of truth (`out/ssdf-satisfaction-matrix.json`); .xlsx renderer reads .json; checksum cross-validation at emit time | open |
| T.T2-8 | med | Evidence aggregator runtime cost on large estates (many KSIs × many practices) | Aggregation parallelised per practice; benchmark target ≤ +20% wall-clock for a 500-asset CSP; CI perf budget asserts ≤ 5 minutes total | open |
| T.T2-9 | med | Task-level evidence may differ from practice-level rollup (one task satisfied, another not) | Matrix preserves both task-level + practice-level rollup; Common Form attests at practice level; renderer requires ALL tasks in a practice to be satisfied for the practice rollup to be "Attested" | open |
| T.T2-10 | low | Process-artifact KSIs (operator-typed narratives) lack programmatic coverage signal | Process-artifact evidence reads `tracker_db.process_artifacts` table; operator-supplied with audit-log + last-reviewed-at timestamps; freshness threshold (e.g. ≤ 90 days) | open |
| T.T2-11 | low | Evidence-aggregator output schema versioning | `aggregator_schema_version: '1.0'` field; CHANGELOG documents schema bumps | open |
| T.T2-12 | low | Tracker review snapshot drift vs cloud-evidence disk reads (cross-ref LOOP-B-X4, LOOP-R-X7) | `fetched_at` records on every snapshot; strict-ssdf mode enforces 1-hour window | open |
| T.T2-13 | low | Property-based test coverage for satisfaction-matrix join | `fast-check` property tests assert join idempotence + commutativity over reordered envelopes; CHANGELOG cites property coverage | open |
| T.T2-14 | med | Matrix overflow on >100-product estates | Per-product matrix emit; bundle index references per-product files; CHANGELOG documents the file-per-product pattern | open |
| T.T2-15 | low | NIST IR 8397 supplement (developer verification minimum standards) cross-walked into matrix when operator opts in | Optional overlay; default off; runbook documents activation | open |
| T.T2-16 | med | Spec-vs-catalogue schema divergence (surfaced 2026-06-20): T.T2.md §4/§5 assumed per-TASK `crosswalk_ksi[]`/`crosswalk_800_53_r5[]` + 43 tasks; the committed T.T1 catalogue (`core/ssdf-practices-catalog.ts`) carries those crosswalks per-PRACTICE (`fedramp_ksi_forward_map`, `nist_800_53_r5_controls`), Common Form refs per-task, and 42 active tasks (PW.3 withdrawn in v1.1). Risk: a downstream consumer (T.T3) that assumes per-task crosswalk granularity misreads the matrix | Implemented the join at the practice level + attributed the pointer set to each of the practice's tasks; matrix task rows expose the inherited `crosswalk_ksi`/`nist_800_53_r5_controls` so the granularity is explicit, while `common_form_section_ref` stays per-task. Documented in T.T2.md §12 | mitigated |
| T.T2-17 | med | Tracker process-artefact pointer kind (T.T2.md §4 #11 / §5.1 `tracker-artefact`) + per-product tracker DB scoping (§11) cannot ship — no tracker subsystem exists in this repo (no `pg`/`express`/`react`), same posture as W.W3/W.W4 | Deferred; a task whose only evidence would be a tracker artefact resolves to `requires-operator-input` with a diagnostic naming where the operator supplies it; surfaced in `provenance.coverageDiagnostics`. Revisit when the tracker subsystem lands | open |
| T.T2-18 | med | Cosign / build-pipeline attestation state (`core/cosign-verify.ts`, T.T2.md §4 #8) is not collected as a standalone artefact in this repo, so PS.2/PW.6 release-integrity evidence keys off SBOM presence only | The `cosign-verify` evidence-pointer kind is omitted; the gap is recorded once per matrix in `provenance.coverageDiagnostics` ("cosign build-attestation state not collected") so a 3PAO sees the coverage boundary. Revisit when a cosign/Rekor verification collector lands (cross-ref W.W2 `core/oci-publisher-screen.ts`) | open |

### T.T3 — CISA Common Form Renderer

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| T.T3-1 | high | Corporate-officer attestation forgery (cross-ref T-X1) | Out-of-band signing + `signing_officer_id` lock + canonical PDF SHA-256 + audit log + Ed25519 audit signatures | open |
| T.T3-2 | high | Engineering-vs-corporate drift (cross-ref T-X2) | T.T2 cross-check ascertains practice alignment before T.T3 emits; engineering-summary cover page rendered for officer's review | open |
| T.T3-3 | high | Common Form template version drift vs RSAA (cross-ref T-X4) | `template_version` pinned in renderer constant + template JSON; CI guard `check:common-form-version` blocks emit if mismatch; runbook documents PRA renewal-watch | open |
| T.T3-4 | high | False-attestation on under-evidenced practices (cross-ref T-X9, T.T2-1) | Renderer fails if T.T2 matrix has any `not-satisfied` or `low-confidence` rows without a matching POA&M; `MissingPOAMItemError` propagates | open |
| T.T3-5 | med | PDF determinism + cross-viewer rendering (cross-ref T-X25) | Pinned PDF library + font set + page size; metadata timestamps stripped; CI renders + pdftotext-asserts; manual QA on Acrobat + Chromium + Foxit | open |
| T.T3-6 | med | OMB control number stale on form face | Renderer reads OMB control number from `templates/cisa-common-form.template.json` `omb_control_number` field; CHANGELOG bump on PRA renewal | open |
| T.T3-7 | med | Per-product naming conflicts (`product_id` characters break filename pattern) | Renderer slugifies `product_id` (lowercase, alphanumeric + dash); slug recorded in `out/ssdf-products.json` for forensic correlation; CI assert slug uniqueness | open |
| T.T3-8 | med | Legal-review status gating (cross-ref T-X17) | Renderer requires `legal_review_status === 'approved'` before marking attestation ready-to-sign; legal-review summary cover page auto-attached | open |
| T.T3-9 | med | Section IV "Practices Attested" enumeration order | Renderer sorts practices in canonical 800-218 order (PO → PS → PW → RV; numerically within group); CHANGELOG documents | open |
| T.T3-10 | low | PDF size cap (>10 MB rejected by some agency portals) | Warn at 5 MB, fail at 10 MB; renderer offloads attachments to separate files referenced by hash | open |
| T.T3-11 | low | PDF accessibility (Section 508 compliance) | PDF/UA tagging applied via `pdf-lib` accessibility helpers; manual axe-pdf or PAC2024 QA pass on every template-version bump | open |
| T.T3-12 | low | Form face renders correctly only when LOOP-T.T1 catalogue is fully populated | Renderer fails if catalogue is incomplete (`expectedPracticeCount === 19, actual count < 19`) | open |
| T.T3-13 | med | Signature placeholder block on unsigned PDF must be machine-detectable for downstream tooling | Signature placeholder is a named PDF AcroForm field (`signature_officer`) with empty `/V` value; downstream tooling detects unsigned state via `pdf-lib`'s form-field reader | open |
| T.T3-14 | low | Renderer output filename collisions across fiscal years for same product | Filename pattern `ssdf-common-form-<product-slug>-FY<YYYY>.pdf`; CI assert uniqueness via `out/ssdf-products.json` join | open |
| T.T3-15 | med | DoD-prime equivalency drift (cross-ref T-X16) | Common Form manifest JSON records `dod_equivalency_referenced: boolean`; LOOP-S.S3 reads this field | open |
| T.T3-16 | med | RSAA upload failure recovery (cross-ref T-X10) | T.T3 emits a "post-submission checklist" in the manifest; T.T4 tracker records the upload outcome | open |
| T.T3-17 | low | Template visual drift on minor template bumps (small CISA design tweaks) | CHANGELOG entry per template bump documents visual deltas; manual-QA gate before merging template-version bump | open |
| T.T3-18 | low | Form rejection due to missing optional fields (some agencies want producer DUNS / SAM.gov UEI) | Common Form manifest carries `producer_uei: text` operator-supplied field; renderer surfaces missing UEI as `REQUIRES-OPERATOR-INPUT: ssdf_producer_uei` | open |
| T.T3-19 | med | Spec-vs-reality schema divergence (surfaced 2026-06-21): T.T3.md §4.2 reads `out/ssdf-practice-map.json` (T.T1) + `out/ssdf-evidence-binding.json` (T.T2) with status enum implemented/…/not-applicable and an illustrative per-task `CISA_PRACTICE_TO_SSDF` table (§6.5, 1.a–4.c). Those artefacts/enums/table do not exist. Risk: a future session wires T.T3 to non-existent inputs | Implemented against the REAL `out/ssdf-satisfaction-matrix.json` (T.T2) — statuses satisfied/partially-satisfied/not-satisfied/not-assessed/requires-operator-input — and the authoritative T.T1-catalogue `COMMON_FORM_TASK_MAP` (§IV(1)→Practice 1 … §IV(4)→Practice 4), surfaced per-task as `common_form_section_ref`. Selection is computed per §IV clause; the 1.a–1.f / 4.a–4.c sub-items are verbatim form text rendered under each practice (not separately evidence-bound). Documented in T.T3.md §12 + the STATUS T.T3 scope note | mitigated |
| T.T3-20 | med | The binary CISA template PDF (`docs/sources/cisa-common-form-1670-0052.pdf`) + CISA/OMB logo assets (`docs/assets/*.pdf`) the spec §7 lists for verbatim-text fidelity + page imagery are not fetched in this clean-room tree (no network for arbitrary external PDFs), same posture as the deferred tracker layer | The verbatim Section IV attestation text is reproduced from the public record cited in T.T3.md §2.4 (a constant in `core/ssdf-common-form.ts`) and the PDF renders a text-only header; `provenance.formTextSource` records the authority + OMB control + accessed date + the embedding boundary. Revisit if a committed template/asset fetch step is added (then pin its SHA-256 per the spec §6 step 1) | open |
| T.T3-21 | low | PDF/A-3b conformance (spec §5.1 / Q2) requires an embedded TrueType font the dependency-free zip-store pattern cannot ship; some archival-ingest agencies prefer PDF/A | The emitter produces deterministic dependency-free PDF 1.4 (the proven `core/conmon-pdf.ts` lineage); the spec §5.1 explicitly permits this fallback. A font-embedding upgrade (`npm run pdf:fonts:embed`) is out of LOOP-T scope. T.T3 itself stays dependency-free | open |
| T.T3-22 | med | Tracker-DB / legal-review-gating / RSAA-submission features in the planned risks (T.T3-3 `check:common-form-version` CI guard, T.T3-8 `legal_review_status`, T.T3-13 AcroForm signature field, T.T3-16 RSAA checklist) assume infrastructure absent from this repo (no tracker subsystem; no AcroForm dependency) | T.T3 ships the realizable core (matrix-driven canonical form + deterministic PDF + sign + bundle + coverage). Signature/date lines are blank flattened text (machine-detectable as unsigned by the absence of officer fields); electronic-signature binding, the version-pinned template JSON, legal-review gating, and RSAA upload are deferred to T.T4. Recorded so a future session does not assume those guards already exist | open |

### T.T4 — Per-Agency Annual Re-Attestation Tracker

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| T.T4-1 | high | Withdrawal workflow (cross-ref T-X14) | `submission_status: 'withdrawn'` state + `withdrawal_reason` + agency-specific notification cascade + countersigned by officer | open |
| T.T4-2 | high | Material-change re-attestation tier definitions (cross-ref T-X6) | Three-tier detector with general-counsel-reviewed runbook; CHANGELOG cites runbook version | open |
| T.T4-3 | high | Post-M-26-05 legacy contract flow-down (cross-ref T-X19) | M-26-05 applicability matrix per agency; runbook + UI banner | open |
| T.T4-4 | high | RSAA auto-submit prohibition (cross-ref T-X29) | CI test asserts no HTTPS call to `rsaa.cisa.gov` from production code; CLAUDE.md REO example | open |
| T.T4-5 | med | Annual cadence drift across agencies (cross-ref T-X12) | Per-agency `original_attestation_date` + `next_renewal_due` + override; multi-stage renewal-watcher notifications | open |
| T.T4-6 | med | Cross-agency uplift drift (cross-ref T-X15) | `submission_modality` + `tailoring_diff`; quarterly reconciliation report | open |
| T.T4-7 | med | Agency-specific addenda (cross-ref T-X5) | `addendum_required` / `addendum_template_path` / `addendum_status` per (agency, product) row; known-agencies registry | open |
| T.T4-8 | med | Legal-review bottleneck (cross-ref T-X17) | `legal_review_status` + summary cover page; UI workflow gates ready-to-sign | open |
| T.T4-9 | med | DoD-prime SSDF as DFARS equivalency (cross-ref T-X16) | LOOP-S.S3 manifest cross-reference; withdrawal cascades | open |
| T.T4-10 | med | Tracker signing-key rotation across FY boundaries (cross-ref T-X24) | Historical public-keys registry; reader cross-references by `signing_key_id` | open |
| T.T4-11 | med | Multi-tenant isolation deferred to LOOP-H.H3 (cross-ref T-X28) | Single-tenant for LOOP-T; LOOP-H.H3 batch migration | open |
| T.T4-12 | low | Agency contracting-officer email maintenance | Operator-supplied via `ssdf-config.yaml agencies[*].contracting_officer_email`; per-agency record + last-verified timestamp; quarterly re-verification prompt | open |
| T.T4-13 | low | Per-agency policy posture (continues-mandatory / continues-voluntary / etc) requires manual upkeep | Operator records per-agency posture; runbook documents the M-26-05 follow-up source list (agency CIO memos, OMB FAQ updates) | open |
| T.T4-14 | low | Multi-product UI scalability (>50 products) | UI paginates products; aggregation views collapse by agency-status; future enhancement could add saved-views | open |
| T.T4-15 | low | Renewal-watcher CRON timezone drift | CRON job runs in UTC; tracker stores all timestamps as ISO-8601 UTC; UI converts to operator's locale | open |
| T.T4-16 | med | Withdrawal cascade to LOOP-S (DFARS equivalency stale alert) | T.T4 withdrawal triggers LOOP-S.S3 manifest revalidation; CHANGELOG documents the cross-loop trigger | open |
| T.T4-17 | low | Operator may forget to record RSAA receipt ID; submission status stuck at `submitted` | UI nag reminder at 14 days post-`submitted`; runbook documents | open |
| T.T4-18 | low | UI surfacing of "expires in N days" countdown for multi-fiscal-year tracking | Countdown widget reads `next_renewal_due`; sortable by date | open |
| T.T4-19 | low | Material-change detection false-positives produce alert fatigue | Tier 2 prompts the operator with a "confirm re-attestation?" modal that includes a "dismiss as non-material" option with text justification | open |
| T.T4-20 | low | Annual report cross-FY analytics (e.g. attestation count delta YoY) | T.T4 emits `out/ssdf-cadence-FYNNNN-summary.json` per FY; cross-FY analytics consumes the per-FY snapshots | open |
| T.T4-21 | med | **Tracker DB / REST / React status pane deferred (discovered 2026-07-01).** The per-slice §5.1 four SQLite tables (`ssdf_products` / `ssdf_attestation_submissions` / `ssdf_practice_overrides` / `ssdf_material_change_events`), the §6 Step 4 REST routes + `ssdf-service`, the §6 Step 5 three React panes (status / products / material-changes) + `ssdf-admin` / `ssdf-viewer` RBAC roles, and the operator signed-PDF-SHA-256 / RSAA-submission-id capture cannot ship — no tracker subsystem exists in this repo (no `pg`/`express`/`react`/`better-sqlite3`), same posture as T.T2-17 / W.W3-17 / W.W4-EXT-1..4. | Shipped the two pure engines (`core/ssdf-annual-attestation.ts` cadence + `core/ssdf-material-change-detector.ts` detector) + a signed on-disk ledger (`out/ssdf-material-change-events.json` + `.sig`) + content-addressed snapshots (`out/ssdf-attestation-snapshots/<product>/<sha256>.json`) + the append-only `out/ssdf-attestation-ledger.jsonl` standing in for tracker storage; per-(product × agency) cadence rows are computed + emitted, just not served by a UI. Revisit when the tracker subsystem lands (single cross-loop sweep with T.T2-17 / W.W3-17 / W.W4-EXT + LOOP-H.H3 multi-tenant). | open |
| T.T4-22 | med | **Operator submission / force-reattestation / withdrawal / legal-review actions deferred.** The per-slice §5.4 status-pane "force re-attestation" action (the `operator_forced` event kind), the T-X14 withdrawal workflow, the T-X17 legal-review gating, and the operator recording of the signed-PDF SHA-256 + RSAA receipt id are human actions that require the tracker UI + audit log absent from this repo. | The `operator_forced` / withdrawal / legal-review states remain in the type union / risk register for when the tracker lands; the detector itself never auto-signs a producer attestation and never files with an agency / CISA RSAA (REO Rule 4). The realizable core surfaces the material-change events + cadence rows the operator acts on out of band. | open |
| T.T4-23 | low | **`major_version_bump` + `ai_augmentation_gap` inputs not orchestrator-fed.** The detector emits both kinds via unit-tested `DetectOptions` seams (`priorSbomVersion` / `currentSbomVersion` / `aiAugmentationGapPracticeIds`), but the orchestrator does not yet carry a per-product SBOM version across runs (LOOP-J.J3.b integration) nor a T.T5 AI-augmented matrix (T.T5 unshipped), so in a live run only the matrix-diff / regime / agency kinds fire. | Documented seam; wire the SBOM-version carry when a per-product SBOM-version ledger exists, and the AI-gap feed when T.T5 ships (T.T5's material-change subscription is already spec'd in the per-slice §2 800-218A cross-reference). No fabricated version data (REO Rule 1). | open |
| T.T4-24 | low | **Snapshot integrity not in the run manifest.** `out/ssdf-attestation-snapshots/**` and `ssdf-attestation-ledger.jsonl` are not enumerated by `core/sign.ts` `listSignedFiles` (top-level + `archive/` only), so the diff-baseline snapshots are not covered by the Ed25519 run manifest. | Integrity is anchored two ways instead: the snapshot filename IS its SHA-256 (content-addressed, self-detecting on tamper) and every snapshot sha256 is recorded in the SIGNED `out/ssdf-material-change-events.json` (`events[].prior_matrix_sha256` / `products[].matrix_sha256`) which IS manifest-covered. Revisit if `listSignedFiles` is extended to walk the snapshots dir. | open |

### T.T5 — 800-218A AI Augmentation Worksheet

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| T.T5-1 | high | 800-218A version pinning + post-final revision drift (cross-ref T-X3) | `extension_version = "800-218A-final-2024-07-26"`; revisions trigger CHANGELOG + delta review + operator-override review | open |
| T.T5-2 | high | AI/ML model card propagation lag (cross-ref T-X18) | T.T5 requires `model_card.last_refreshed_at ≤ 90 days`; stale cards block AI augmentation block ready-state | open |
| T.T5-3 | high | LOOP-O.O5 dependency — O.O5 must ship before T.T5 (dependency chain) | T.T5 gracefully degrades if O.O5 has not shipped: emits worksheet with `requires-O.O5-model-cards` placeholder; CI integration test asserts dependency check | open |
| T.T5-4 | med | Dataset provenance ambiguity (training data lineage may be partial for foundation models) | T.T5 worksheet records `training_data_provenance_completeness: enum('complete', 'partial', 'undisclosed')` per model; partial / undisclosed surface POA&M cascade | open |
| T.T5-5 | med | Generative-AI vs traditional-ML scope distinction in 800-218A | T.T5 catalogue records the 800-218A "in-scope model types" (foundation models, generative AI, dual-use models); operator declares per model whether it's in-scope; runbook documents 800-218A §2 scope | open |
| T.T5-6 | med | Content provenance / watermarking practice tasks (NIST AI RMF + EO 14110 cross-cuts) | 800-218A includes a content-provenance practice (PW.A.1) augmentation; T.T5 cross-walks against LOOP-O.O5 watermarking evidence; gap surfaces POA&M | open |
| T.T5-7 | med | Red-teaming evidence aggregation (AI-specific practice augmentation) | T.T5 reads LOOP-N (Threat Modeling) adversarial-test evidence + LOOP-O.O5 red-team artefacts; CHANGELOG documents the cross-loop joins | open |
| T.T5-8 | low | Open-source LLM / foundation-model upstream attestation gap (cross-ref T-X13 specialised for AI) | T.T5's OSS augmentation gap reads from the same `out/ssdf-oss-attestation-gap.json` filtered by `is_ai_model: true` | open |
| T.T5-9 | low | Worksheet emit per AI-product per FY | Naming pattern `ssdf-ai-augmentation-worksheet-<product-slug>-FY<YYYY>.json`; bundled into LOOP-T submission package | open |
| T.T5-10 | low | NIST AI RMF v1.1 horizon (currently AI RMF v1.0 Jan 2023 + Generative AI Profile Jul 2024) | T.T5 cross-walks against AI RMF + Profile; revision-pinned constants; CHANGELOG documents bumps | open |
| T.T5-11 | low | EO 14110 / EO 14110-rescission churn — federal AI policy unstable | T.T5's docstring + runbook record the EO 14110 status as-of-2026-06-07; T.T5 emits regardless of EO status because 800-218A is NIST guidance independent of EO authority | open |
| T.T5-12 | med | OMB M-24-10 vs M-25-21 federal AI use governance churn affecting T.T5 evidence inputs | T.T5 reads LOOP-O.O5 model cards which themselves cross-walk to M-24-10 + M-25-21; T.T5 surfaces the cross-walk via O.O5; ZERO direct M-24-10 / M-25-21 reads in T.T5 | open |
| T.T5-13 | low | Foundation-model fine-tuning lineage (operator fine-tunes a base model; both base + fine-tuned require model cards) | T.T5 distinguishes `base_model_id` + `fine_tuned_from_model_id`; both must have current model cards | open |
| T.T5-14 | low | AI augmentation block on Common Form (T.T3) is optional vs required | T.T5 worksheet emit is gated by `--ssdf-ai-extension` flag (or `is_ai_product: true` in `ssdf-config.yaml`); when applicable, the Common Form's AI Section is rendered | open |
| T.T5-15 | low | Per-model augmentation overhead on >20-model estates | T.T5 batches per-model evaluation; CI perf budget asserts ≤ 5 minutes for 20 models; bulk-worksheet emit pattern | open |

---

## External dependencies that may change

### NIST publication versions
- **NIST SP 800-218 v1.1 (Feb 2022)** — current SSDF source. URL:
  https://csrc.nist.gov/pubs/sp/800/218/final. PDF URL:
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf.
  v1.2 / Rev 2 horizon: pre-2030.
- **NIST SP 800-218A (Jul 26 2024, final)** — generative-AI / dual-use
  foundation model community profile. URL:
  https://csrc.nist.gov/pubs/sp/800/218/A/final. Revision horizon:
  unknown; NIST has signalled erratum work.
- **NIST IR 8397 (Oct 2021)** — Guidelines on Minimum Standards for
  Developer Verification of Software. URL:
  https://csrc.nist.gov/pubs/ir/8397/final. Optional T.T1 supplement.
- **NIST SP 800-161 Rev 1 (May 2022)** — C-SCRM Practices. URL:
  https://csrc.nist.gov/pubs/sp/800/161/r1/final. Cross-referenced by
  LOOP-T runbook.
- **NIST SP 800-53 Rev 5 (Sep 2020, errata Dec 2023)** — control
  catalogue underlying T.T1's cross-walk. Rev 6 is long-tail; would
  require catalogue regeneration. URL:
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf.
- **NIST AI RMF v1.0 (Jan 2023) + Generative AI Profile (Jul 2024)** —
  cross-walked from T.T5. URL: https://www.nist.gov/itl/ai-risk-
  management-framework. Revision horizon: AI RMF v1.1 expected
  2026-2027.
- **NIST EO-critical-software definition (Oct 13 2021)** — drives T-X8
  in-scope decision. URL: https://www.nist.gov/itl/executive-order-
  improving-nations-cybersecurity/critical-software-definition.
  Definition stable since 2021 with minor clarifying FAQs.

### Executive / OMB / Federal Register publications
- **EO 14028 (May 12 2021)** — statutory taproot for M-22-18. URL:
  https://www.whitehouse.gov/briefing-room/presidential-actions/
  2021/05/12/executive-order-on-improving-the-nations-cybersecurity/.
- **OMB M-22-18 (Sep 14 2022)** — Common Form mandate. URL:
  https://www.whitehouse.gov/wp-content/uploads/2022/09/M-22-18.pdf.
- **OMB M-23-16 (Jun 9 2023)** — M-22-18 update. URL:
  https://www.whitehouse.gov/wp-content/uploads/2023/06/M-23-16-
  Update-to-M-22-18-Enhancing-Software-Supply-Chain-Security.pdf.
- **OMB M-26-05 (Jan 23 2026)** — rescission of mandatory Common Form
  collection; tailored-risk-based approach. URL (pending official
  posting): https://www.whitehouse.gov/wp-content/uploads/2026/01/
  M-26-05.pdf. Critical for T-X19.
- **EO 14110 (Oct 30 2023) / EO 14110-rescission (Jan 20 2025)** —
  federal AI policy churn affecting T.T5's context but NOT its
  technical basis (which is NIST 800-218A). URL:
  https://www.whitehouse.gov/briefing-room/presidential-actions/
  2023/10/30/executive-order-on-the-safe-secure-and-trustworthy-
  development-and-use-of-artificial-intelligence/.
- **OMB M-24-10 (Mar 28 2024)** — AI governance for federal agencies;
  upstream of LOOP-O.O5; T.T5 transitively dependent. URL:
  https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-
  Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-
  of-Artificial-Intelligence.pdf.
- **OMB M-25-21 (Apr 3 2025)** — successor / update to M-24-10. URL
  pending verification at access date.

### CISA publications + repositories
- **CISA Common Form (OMB 1670-0052, current revision Apr 2024)** —
  the form T.T3 renders. URL:
  https://www.cisa.gov/sites/default/files/2024-03/Common-Form-
  Final.pdf. PRA renewal window opens 2027.
- **CISA Repository for Software Attestations and Artifacts (RSAA)** —
  https://rsaa.cisa.gov/. Manual web-form upload only as of
  2026-06-07; future API horizon unknown.
- **CISA Software Acquisition Guide (Aug 2024)** — procurement-side
  companion. URL: https://www.cisa.gov/resources-tools/resources/
  software-acquisition-guide-government-enterprise-consumers.
- **CISA Secure-by-Design pledge + guidance** — informational
  supplement; not on the T.T3 attestation path.

### FedRAMP guidance updates that could affect LOOP-T
- **FedRAMP 20x Phase Two RFCs (RFC-0014 + future)** — could redefine
  KSI semantics + cross-walk to SSDF practices. T.T1 cross-walk reads
  the current KSI catalogue.
- **FedRAMP Marketplace `ssdf_attestation_url` field (hypothetical)** —
  LOOP-Q.Q1 would surface from T.T4 records once Marketplace
  metadata extends.

### Upstream library updates
- **OSCAL JSON Schema v1.1.2** — committed at
  `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json`. LOOP-T
  reads POA&M items; pinned to v1.1.2.
- **ajv (^8.x)** — used by `core/oscal-validate.ts` + any JSON-schema
  validation in LOOP-T.
- **better-sqlite3 (~9.x or ~11.x)** — tracker. SQL dialect stable.
- **noble-ed25519 (^2.x) or @noble/ed25519** — Ed25519 signing. Stable.
- **`pdf-lib` (^1.x) or `pdfkit` (^0.x)** — Common Form renderer.
  Decision pending T.T3 implementation. CHANGELOG pins the choice.
- **OOXML compose helpers** — used by `core/oscal-ssp-docx.ts` +
  T.T2 .xlsx renderer. Pure JS; stable.
- **React (^18.x)** — tracker UI. v19 ships routinely; pin major
  version within LOOP-T.

### Cloud-provider / federal infrastructure
- **CISA RSAA infrastructure** — third-party operator-side dependency.
  Outages affect operator workflow; not code-correctness.
- **Agency procurement portals** — heterogeneous; LOOP-T does not
  integrate directly.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the
   appropriate per-slice section with a fresh ID (e.g. `T.T2-16`);
   commit alongside the slice's implementation log update.
2. Risks resolved during implementation: move the row to the
   "Resolved risks" table at the bottom with date + resolution note +
   responsible session/commit. Do NOT delete the original entry —
   historical record matters.
3. Severity bump (low → med → high): add a `note` line under the
   original entry describing why; do not edit history.
4. Cross-cutting risks affecting multiple slices: keep in the
   cross-cutting section; reference from per-slice tables via
   "(cross-ref T-X<n>)".

---

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-T-SPEC.md` §1 (mission +
   distinction from LOOP-J.J3.b) + §11 (open questions) — overlaps
   with this register.
3. Read the specific per-slice doc at `docs/slices/T/T.T<n>.md` for
   the slice you're implementing — risks here are the LIVE working
   set; risks in the per-slice docs are the spec snapshot.
4. Cross-reference companion registers when triaging a risk that
   crosses loops: `LOOP-J-RISKS.md` (engineering attestation),
   `LOOP-O-RISKS.md` (AI/ML governance), `LOOP-B-RISKS.md` (POA&M),
   `LOOP-S-RISKS.md` (DFARS equivalency).
5. Before shipping a slice, update this file's per-slice section +
   move any resolved risks to the resolved table atomically with the
   slice's commit (per SLICE-COMPLETION-PROCEDURE.md).

---

## Appendix — when does LOOP-T apply?

LOOP-T applies when ANY of the following are true:

1. The CSP sells software (including SaaS) to any federal agency under
   a contract executed BEFORE January 23 2026 that incorporates
   OMB M-22-18 / M-23-16 flow-down obligations. (Legacy
   flow-downs persist through contract term, often 5-10 years; see
   T-X19.)
2. The CSP sells software to any federal agency under a contract
   executed AFTER January 23 2026 where the agency elects, on a
   tailored / risk-based basis under OMB M-26-05, to continue using
   the Common Form / SSDF / RSAA.
3. The CSP serves a DoD-prime customer (LOOP-S DFARS scope) who
   demands the SSDF Common Form as DFARS equivalency Body-of-Evidence
   (see T-X16).
4. The CSP's authorisation package consumer (3PAO, FedRAMP PMO, AO)
   reads the SSDF Common Form as a *de facto* readiness artefact
   independent of OMB's mandate (common practice in 2026).

LOOP-T does NOT apply when ALL of the following are simultaneously
true:

- No federal customer (commercial-only).
- No legacy federal contract with M-22-18 / M-23-16 flow-down.
- No DoD-prime DFARS equivalency demand.
- No 3PAO / PMO / AO expectation of the Common Form as readiness
  evidence.

The `--ssdf-attestation` flag (or `CLOUD_EVIDENCE_SSDF_ATTESTATION`
env var) is the operator's binary signal that the gate is open. When
the flag is unset, NONE of the LOOP-T risks above activate. The
operator runbook documents the four applicability triggers; first-
boot wizard prompts the operator to confirm scope decisions before
LOOP-T's tracker pages activate.

---
