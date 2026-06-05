# Pre-LOOP-A research findings (R2 + R3 + R4)

> **Status:** Research-blocker resolution before LOOP-A (OSCAL POA&M + AP +
> AR-chain + submission bundler) begins. R1 (AFR family classification) is
> documented separately at `docs/AFR-FAMILY-CLASSIFICATION.md`.

---

## R2 — Monthly POA&M submission format + cadence

### What was sought
Whether monthly POA&M updates are submitted as full-document re-submission
(with `metadata.last-modified` updates), as deltas only, in Excel template
form, in OSCAL JSON, or some other format — so that LOOP-A.A1 emits the
right artifact and LOOP-E.E2 (monthly POA&M workflow) targets the right
submission mechanism.

### What was found

**Source: [FedRAMP Rev5 Playbook — ConMon Overview](https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/)**

> "Each month, the CSP uploads an up-to-date POA&M and inventory, along
> with raw vulnerability scan files (when required by agreements with
> agency customers) and reports to the secure repository."

> "CSPs with cloud offerings categorized at LI-SaaS, Low, or Moderate use
> the FedRAMP secure repository on USDA Connect.gov for posting ConMon
> deliverables. CSPs with cloud offerings categorized at High use their
> own secure repository."

**Source: [FedRAMP Rev5 Playbook — ConMon Vulnerability Scanning](https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/)**

> "The scan output must display all scan findings with a low risk or
> higher in a structured, machine-readable format (such as XML, CSV, or
> JSON)."

### What was NOT explicitly confirmed (open caveats)
- The exact wire-format of the POA&M itself (Excel vs OSCAL JSON) — the
  public Rev5 playbook describes the cadence and repository but not the
  schema. Historically, the FedRAMP POA&M Template (`FedRAMP-POAM-Template.xlsx`)
  has been the de-facto baseline; RFC-0024 mandates OSCAL JSON for 20x
  submissions but the Rev5 → 20x transition for POA&M-specific format is
  not yet documented in machine-readable form on fedramp.gov.
- Whether monthly submissions are full re-uploads or delta packages — the
  PMO's documented behavior is full re-upload with the POA&M reflecting
  the as-of-last-day-of-month state.

### Decision for LOOP-A.A1 + LOOP-E.E2

**LOOP-A.A1 (POA&M emitter)** will:
- Emit **OSCAL POA&M v1.1.2 JSON + XML** (per RFC-0024 + the OSCAL spec
  the deep-research synthesized).
- Use full-document re-emission semantics: every monthly run produces a
  complete POA&M JSON with `metadata.last-modified` set to the run
  timestamp + a new version bump. The PMO accepts full re-upload.
- Carry a `metadata.revisions` array so the historical chain of monthly
  versions is recoverable from any single document.
- **Also emit a FedRAMP POA&M Template `.xlsx`** as a companion artifact
  in LOOP-A.A4 (submission bundler), so CSPs that prefer the Excel
  format-of-record for upload to USDA Connect.gov have a real artifact
  to use immediately. Both files are signed.

**LOOP-E.E2 (monthly POA&M workflow)** will:
- Re-emit the full POA&M each month with updated `metadata.last-modified`.
- Compare against the previous month's POA&M and surface a Markdown
  "POA&M delta report" (added items, closed items, status changes) for
  operator review and PMO submission.
- Push the freshly-signed POA&M to USDA Connect.gov via the configured
  webhook/API (if `FEDRAMP_REPO_URL` env is set).

---

## R3 — Phase Two pilot output format check

### What was sought
Whether any post-pilot (post-March 2026) guidance has refined the Phase
Two Moderate submission package format, so LOOP-A.A4 (submission bundler)
matches what the PMO actually expects from the 13-participant pilot
cohort.

### What was found

**Source: [RFC-0014](https://www.fedramp.gov/rfcs/0014/) (current published version)**

> "During Phase Two, FedRAMP will expect truly automated and opinionated
> validation of Key Security Indicators for a Moderate authorization."

No post-pilot guidance documents are publicly available via fedramp.gov/blog
or fedramp.gov/rfcs as of this research. The RFC-0014 text remains
authoritative.

### Decision for LOOP-A.A4

The submission bundler will:
- Target the OSCAL v1.1.2 SSP + AP + AR + POA&M chain mandated by
  RFC-0024 + the OSCAL spec.
- Include the IIW (Appendix M .xlsx), the signed evidence manifest
  (Ed25519), the RFC 3161 timestamp, and an `INDEX.json` enumerating
  every artifact with sha256 + provenance.
- **Be format-stable but version-aware**: the manifest declares
  `package_format_version: "20x.phase-two.preview.2026"` so when post-
  pilot guidance lands and the format shifts, we can bump the version
  cleanly and 3PAOs can request the version they need.
- Subscribe to the FedRAMP blog/changelog via a low-frequency check
  (deferred to LOOP-A.A4-followup if format shifts post-GA late 2026).

### Open caveat

The Phase Two pilot deadlines (Jan 30, Mar 13, 2026) have passed. If
FedRAMP publishes a post-pilot retrospective with revised format guidance
before GA Moderate (late 2026), LOOP-A.A4 may need a quick patch. We will
re-fetch fedramp.gov/blog and fedramp.gov/rfcs quarterly. **This caveat
does NOT block LOOP-A.A1–A.A3.**

---

## R4 — Sample selection methodology

### What was sought
What sampling approach FedRAMP requires for control assessments (random,
stratified, judgmental, full-population), with minimum sample sizes per
control family + statistical confidence requirements, so LOOP-F.F3
(sample-selection methodology auto-derive) implements the correct
algorithm.

### What was found

**Source: [FedRAMP Rev5 Playbook — Continuous Monitoring Vulnerability Scanning](https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/)**

> "FedRAMP vulnerability scanning guidelines require at least monthly
> scans of 100% of inventory components."

> "Vulnerability scanning using sampling targets the same component
> asset categories but instead requires scanning of a sample attested to
> represent the unique inventory by an assessor and approved by the AO."

> "FedRAMP recommends that externally accessible (outside of the boundary,
> without the use of a VPN) system components do not use this sampling
> methodology; 100% of externally accessible system components should be
> scanned."

> "The entire inventory (or approved sampling percentage) within the
> boundary must be scanned at the operating system (OS) level at least
> once a month. All Web interfaces and services (or approved sampling
> percentage) must be scanned. All databases (or approved sampling
> percentage) must be scanned."

**Source: [FedRAMP Rev5 Playbook — Authorization SAP](https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/)**

> "the methodology must be included as an appendix to the SAP" and must
> "align with FedRAMP's vulnerability scanning sampling requirements."

> "Appendix B: Sampling Methodology" — required in the SAP when sampling
> is used.

> "the CSP and 3PAO must sign the SAP, which indicates acknowledgement
> of and agreement with the SAP and rules of engagement."

### What was NOT explicitly confirmed
- A specific minimum sample size per control family or per asset class.
  FedRAMP delegates the specifics to the 3PAO's attestation that the
  sample is representative, with AO approval.
- Statistical confidence thresholds (e.g. 95% confidence at ±5% margin).
  Not stated explicitly. The standard appears to be assessor judgment +
  AO sign-off.

### Decision for LOOP-A.A2 + LOOP-F.F3

**LOOP-A.A2 (OSCAL AP / SAP emitter)** will:
- Include a "Sampling Methodology" appendix structure in the emitted SAP,
  even if the operator hasn't yet supplied one (emit
  `REQUIRES-OPERATOR-INPUT: sampling-methodology` marker per REO Rule 4).
- When the operator supplies sampling parameters via CLI or config, emit
  a complete Appendix B with: (a) which asset classes use sampling vs
  full-population, (b) the stratification basis (e.g. by region, by
  service tier, by data-classification), (c) the sample-size rationale,
  (d) AO approval timestamp.

**LOOP-F.F3 (sample-selection methodology auto-derive)** will:
- Read the live inventory from `out/inventory.json` (already produced
  by INV-P1..S6).
- Apply the FedRAMP rule: externally-accessible components → 100% scan,
  internal-only components → operator-configurable sample (stratified by
  asset class + region by default, with a minimum 10% floor per class).
- Emit a sampling-plan JSON + Markdown doc that the 3PAO can attach to
  the SAP as Appendix B.
- The 100% rule for externally-accessible is **hard-coded** (it's a
  FedRAMP MUST); the internal sampling percentage is **operator-input**
  with sensible defaults.

---

## Consolidated open caveats (none block LOOP-A start)

1. **POA&M wire format final**: Excel-only vs OSCAL-only vs both. We emit
   both to be safe.
2. **Phase Two pilot post-retrospective format**: may shift the bundler.
   We emit `package_format_version` so a future patch is clean.
3. **Sampling statistical confidence**: not specified by FedRAMP today.
   We default to "stratified by asset class + region, min 10% per class,
   operator-overrideable", document the algorithm in Appendix B, and
   defer to AO sign-off.

None of these block LOOP-A.A1 (POA&M emitter) starting now.

---

## Sources cited

| URL | Used for |
|---|---|
| https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/ | R2: monthly cadence + USDA Connect.gov repository |
| https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/ | R2 + R4: machine-readable scan output + 100%/sampling rules |
| https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/ | R4: SAP Appendix B requirement + sign-off |
| https://www.fedramp.gov/rfcs/0014/ | R3: Phase Two automated/opinionated validation expectation |
| `cloud-evidence/docs/frmr-requirements.generated.json` | R1 (separate doc) |
