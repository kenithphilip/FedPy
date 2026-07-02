# LOOP-B — Risk + Remediation Engine

> Comprehensive implementation specification for the five slices in LOOP-B.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-B end-to-end by reading ONLY this file + the four supporting
> files cited in Section 2 ("Dependencies"). No prior conversation history
> required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence or
> operator-supplied configuration. Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.

---

## 1. Why this loop exists

### The gap LOOP-A.A1 (POA&M) left open

LOOP-A.A1 shipped a fully-OSCAL-compliant Plan of Action and Milestones
emitter. For every FAILING finding in `out/KSI-*.json`, it emits exactly one
`poam-item` plus an `OscalRisk` carrying `deadline = collected_at + N days`,
where N comes from a fixed table keyed off the cloud-evidence
`Severity` enum:

```
critical → 30 days
high     → 60 days
medium   → 90 days
low      → 180 days
info     → 365 days
```

(See `core/oscal-poam.ts:84-90`, constant `REMEDIATION_DEADLINE_DAYS`.)

Three real-world signals are absent from this baseline:

1. **CVSS** — the industry-standard score of intrinsic vulnerability severity
   (FIRST.org CVSS 3.1 + 4.0). A CSP cannot defend "high" without it; a 3PAO
   cannot sort POA&M items by exploitability without it; an AO cannot do
   risk-based prioritisation across thousands of items without it.
2. **EPSS** — FIRST's Exploit Prediction Scoring System: probability that
   the CVE will be exploited in the next 30 days. Two CVEs both rated CVSS
   9.0 but EPSS 0.001 vs 0.97 demand different operational treatment.
3. **Criticality + Exposure** — the *organizational* dimensions: is the
   affected asset Internet-reachable, does it process CUI/PII, is it the
   sole supplier of a high-value process. These come from `inventory.json`
   asset metadata (the INV-P1..S6 work LOOP-A inherited).

In addition, FedRAMP and CISA have published harder remediation deadlines
for specific classes of finding that the LOOP-A.A1 baseline silently
ignores:

- **CISA KEV (BOD 22-01)** — when a vulnerability is on the Known
  Exploited Vulnerabilities Catalog, the federal due date is the catalog's
  per-entry `dueDate` (typically 14 or 21 days from add date), not a
  severity-keyed default.
- **FedRAMP ConMon Strategy & Guide** — the canonical severity → days
  table (Critical 30 / High 30 / Moderate 90 / Low 180) is similar to ours
  but *not identical*, and PAIN / IRV / LEV (Possible Adverse Impact /
  Internet-Reachable / Likely Exploitable Verdict) math can pull a deadline
  forward.

Finally, the system today has **no first-class concept of risk acceptance**:
when an operator decides a failing finding is mitigated by a compensating
control + business justification, there is nowhere to record that decision,
no expiration enforcement, no audit trail, no path to `risk.status =
"deviation-approved"` in the OSCAL POA&M.

### Artifacts LOOP-B delivers

| # | Artifact | Source | Consumer |
|---|---|---|---|
| 1 | `core/risk-score.ts` — pure scoring library | LOOP-B.B1 | POA&M, AR, tracker dashboard |
| 2 | `risk_score{}` block on every Finding | LOOP-B.B1 | POA&M `poam-item.props` |
| 3 | `risk.deadline` computed via KEV / PAIN-IRV-LEV / FedRAMP-baseline | LOOP-B.B2 | OSCAL POA&M, monthly delta report |
| 4 | Risk-acceptance UI + DB + signed audit log | LOOP-B.B3 | OSCAL POA&M `risk.status="deviation-approved"`, AO review |
| 5 | Compensating-controls registry + sign-off UI | LOOP-B.B4 | OSCAL POA&M `risk.mitigating-factors`, RMS doc (LOOP-C.C7) |
| 6 | Central Risk Register `risk-register.json` + `risk-register.xlsx` | LOOP-B.B5 | NIST RA-3 deliverable, exec dashboard (LOOP-I.I1) |

### Authorization-package gaps closed

| Package gap | Slice | Authoritative source |
|---|---|---|
| POA&M items lack defensible per-finding risk ranking | B.B1 | NIST SP 800-30 Rev 1 §3.2 Risk = Likelihood × Impact |
| KEV vulnerabilities not assigned the 21-day BOD 22-01 deadline | B.B2 | CISA BOD 22-01 |
| Recurring "false-positive / risk-adjustment" requests have no system path | B.B3 | FedRAMP Continuous Monitoring Strategy & Guide, Deviation Request template |
| Compensating controls referenced ad-hoc in narrative — not as structured records | B.B4 | NIST SP 800-53 Rev 5 CA-5(1), RA-3 |
| RA-3 Risk Assessment has no aggregated artifact | B.B5 | NIST SP 800-53 Rev 5 RA-3 |

---

## 2. Dependencies

### Loops / slices that MUST complete first

| Dep | Why |
|---|---|
| LOOP-A.A1 (`core/oscal-poam.ts`) | B.B1 extends `findingProps()` to include `risk_score` props; B.B2 overrides the `OscalRisk.deadline` formula. |
| LOOP-A.A3 (`core/oscal.ts` SSP→AP→AR chain) | B.B3 emits `risk.status="deviation-approved"` which only validates against AR `import-ap` chains. |
| LOOP-A.A4 (`core/submission-bundle.ts`) | B.B5 adds a new role `risk-register-json` / `risk-register-xlsx` to the well-known catalogue. |
| INV-P1..S6 (`inventory.json`) | B.B1 reads `inventory.json` asset metadata to compute `criticality` (data_classification, asset_tier) and `exposure` (public_facing, internet_reachable). |
| `core/kev-feed.ts` | B.B2 reads the committed CISA KEV catalog to pull per-CVE `dueDate`. |
| `core/findings.ts`, `core/envelope.ts` | B.B1 extends the `Finding` schema with an optional `risk_score` block — every collector continues working unchanged. |
| `core/vdr-ledger.ts` (existing VDR pipeline) | B.B2 reads existing PAIN / IRV / LEV signals to drive the FedRAMP CMP table override. |

### Existing files this loop EXTENDS

| File | Modification |
|---|---|
| `cloud-evidence/core/envelope.ts` | Add `risk_score?: RiskScore` field on the `Finding` interface (REO-safe: optional, backward compatible). |
| `cloud-evidence/core/findings.ts` | Add `risk_score` parameter to `FindingInput` interface so collectors can attach scores at build time. |
| `cloud-evidence/core/oscal-poam.ts` | (B.B1) `findingProps()` adds `composite-score`, `cvss-base`, `epss-score`, `criticality`, `exposure` props. (B.B2) `deadlineFromCollected()` replaced by `computeDeadline()` which honours KEV/PAIN-IRV-LEV. (B.B3) `severityToRiskStatus()` honours active risk-acceptance records → `deviation-approved`. (B.B4) `risk.remediations[]` gets `mitigating-factors` link to compensating-control resources. |
| `cloud-evidence/core/orchestrator.ts` | New flags: `--risk-score`, `--risk-config <path>`, `--risk-register`, `--strict-risk` plus env equivalents. |
| `cloud-evidence/core/submission-bundle.ts` | Add roles `risk-register-json`, `risk-register-xlsx` to `WELL_KNOWN` catalogue. |
| `cloud-evidence/CHANGELOG.md` | Unreleased entry per slice (see Section 8). |
| `cloud-evidence/docs/STATUS.md` | Per-slice status line updated when slice ships. |
| `tracker/server/schema.sql` | Tables `risk_acceptances`, `compensating_controls`, `compensating_control_links`, `risk_register_entries`. |
| `tracker/server/index.ts` | Mount `routes/risk-acceptance.ts`, `routes/compensating-controls.ts`, `routes/risk-register.ts`. |
| `tracker/client/src/App.tsx` | Add routes `/risk-acceptance`, `/compensating-controls`, `/risk-register`. |

### Loops UNBLOCKED when LOOP-B is complete

| Unblocked loop | Reason |
|---|---|
| LOOP-I.I1 — Executive posture dashboard | Needs `risk_score.composite_score` for the "Top 10 risks" view. |
| LOOP-I.I2 — Burndown + deadline pipeline | Needs B.B2's authoritative `risk.deadline` distribution. |
| LOOP-F.F1 — 3PAO sign-off UI | Builds on B.B3's `risk_acceptances` table pattern (signed action records). |
| LOOP-C.C7 — Risk Management Strategy doc | Auto-fills from B.B5 risk register + B.B4 compensating-controls registry + B.B3 acceptance policy. |
| LOOP-E.E1 — Monthly ConMon analysis report | Aggregates risk score deltas month over month. |
| LOOP-E.E5 — Deviation Request emitter | Reads B.B3 risk-acceptance records to pre-fill the FedRAMP DR template. |

---

## 3. Authoritative sources

Every URL + spec referenced in any LOOP-B slice. All quotes are verbatim
where retrievable. Where the source PDF returns HTTP 403 to anonymous
fetches (FedRAMP CMP, NIST SP 800-30 r1 PDF), the slice records the URL
+ the implementer must download the PDF from the cited URL into
`cloud-evidence/docs/sources/` and re-quote in the slice docstring.

### CVSS — Common Vulnerability Scoring System

- **CVSS v3.1 Specification Document** —
  https://www.first.org/cvss/v3.1/specification-document
  - Equation 5 (Base Score, Scope Unchanged):
    `Roundup(Minimum[(Impact + Exploitability), 10])`
  - Impact (Scope Unchanged): `6.42 × ISS`
  - Impact Sub-Score (ISS):
    `1 - [(1 - Confidentiality) × (1 - Integrity) × (1 - Availability)]`
  - Exploitability:
    `8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction`
  - Qualitative Severity Rating Scale (Table 14):
    None=0.0, Low=0.1-3.9, Medium=4.0-6.9, High=7.0-8.9, Critical=9.0-10.0
  - Vector string prefix: `CVSS:3.1/`
  - Metric value constants (used by `core/risk-score.ts` to back-compute when
    only a vector string is available):
    - AttackVector: Network=0.85, Adjacent=0.62, Local=0.55, Physical=0.2
    - AttackComplexity: Low=0.77, High=0.44
    - PrivilegesRequired: None=0.85, Low=0.62 (0.68 if Scope Changed),
      High=0.27 (0.5 if Scope Changed)
    - UserInteraction: None=0.85, Required=0.62
    - C/I/A: High=0.56, Low=0.22, None=0

- **CVSS v4.0 Specification Document** —
  https://www.first.org/cvss/v4.0/specification-document
  - "A MacroVector is one of the sets of CVSS vectors that the expert
    evaluation process...determined to be of comparable qualitative
    severity." (4.0 replaces 3.1's closed-form formula with a MacroVector
    equivalence-class scoring scheme.)
  - New metric **AT (Attack Requirements)**: "prerequisite deployment and
    execution conditions or variables of the vulnerable system."
  - Impact split into **Vulnerable System** (VC, VI, VA) and **Subsequent
    System** (SC, SI, SA) — replaces v3.1's Scope.
  - Same qualitative rating bands: None=0.0, Low=0.1-3.9, Medium=4.0-6.9,
    High=7.0-8.9, Critical=9.0-10.0.
  - Vector string prefix: `CVSS:4.0/`.

### EPSS — Exploit Prediction Scoring System

- **EPSS overview** — https://www.first.org/epss/
  > "The Exploit Prediction Scoring System (EPSS) is a data-driven
  > machine-learning model that estimates the probability that a published
  > CVE will be exploited in the wild in the next 30 days."
  > "EPSS publishes a 0–1 probability (with ranking percentiles) every day
  > for every CVE."

- **EPSS API documentation** — https://www.first.org/epss/api
  - Base URL: `https://api.first.org/data/v1/epss`
  - Single-CVE: `https://api.first.org/data/v1/epss?cve=CVE-2022-27225`
  - Batch: `?cve=CVE-A,CVE-B,CVE-C` (comma-separated, no spaces)
  - Response (observed shape — to be re-verified by implementer at build
    time): `{ status, status-code, version, access, total, offset, limit,
    data: [ { cve, epss, percentile, date } ] }`.
  - Daily refresh; the `date` field is the publication date for that score.

### CISA KEV — Known Exploited Vulnerabilities

- **BOD 22-01** —
  https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01
  - Per-entry `dueDate` is the authoritative deadline (typically 14 or 21
    days from `dateAdded`). The 21-day default applies to vulnerabilities
    added without an explicit accelerated due date.

- **CISA KEV Catalog (JSON feed)** —
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - Already loaded by `core/kev-feed.ts`. Per-entry shape:
    `{ cveID, vendorProject, product, vulnerabilityName, dateAdded,
       shortDescription, requiredAction, dueDate,
       knownRansomwareCampaignUse, notes }`.
  - `dueDate` is ISO date `YYYY-MM-DD`; LOOP-B.B2 uses this VERBATIM, never
    a re-computed +21d.

### FedRAMP Continuous Monitoring

- **FedRAMP Continuous Monitoring Strategy & Guide (Rev 5)** —
  https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf
  - Published as PDF (anonymous HTTP fetches return 403). The
    implementer MUST download the PDF, store it at
    `cloud-evidence/docs/sources/fedramp-conmon-strategy-guide.pdf`, and
    quote the severity → days table verbatim in `core/risk-score.ts`
    docstring.
  - Canonical baseline (from prior published guidance, to be re-verified
    against the downloaded PDF): Critical 30 days, High 30 days, Moderate
    90 days, Low 180 days. **Note the divergence from LOOP-A.A1's
    `REMEDIATION_DEADLINE_DAYS`** (which used High=60). LOOP-B.B2 must
    reconcile: when the FedRAMP CMP table differs, B.B2's `computeDeadline`
    takes precedence and a `risk.props["deadline-source"]` prop on the
    OSCAL risk records which table was used.

- **FedRAMP Rev5 Playbook — ConMon Vulnerability Scanning** —
  https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/
  - Quoted in `docs/PRE-LOOP-A-RESEARCH-FINDINGS.md` (R2/R4).

- **FedRAMP Deviation Request (DR) form** — referenced from the FedRAMP
  ConMon Strategy & Guide. The DR template fields drive B.B3's
  acceptance-record schema: justification, expiration, compensating
  control reference, AO approval signature.

- **FedRAMP Risk Adjustment Request (RAR)** — referenced from the same
  ConMon Strategy & Guide. A RAR re-categorises a finding's severity
  (e.g. demonstrating false-positive); modelled in B.B3 as a separate
  `acceptance_type = "risk-adjustment"` discriminator on `risk_acceptances`.

### NIST publications

- **NIST SP 800-30 Rev 1 — Guide for Conducting Risk Assessments** —
  https://csrc.nist.gov/pubs/sp/800/30/r1/final  
  PDF: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf
  - Risk = function of (Threat × Vulnerability × Likelihood × Impact).
  - §3.2 defines the likelihood and impact qualitative scales
    (Very Low, Low, Moderate, High, Very High). B.B5 reuses these tokens
    verbatim in the Risk Register schema's `likelihood` / `impact` fields
    so the artifact maps 1:1 to 800-30 r1 Appendix G assessment scales.

- **NIST SP 800-53 Rev 5 — Security and Privacy Controls** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - **CA-5 (Plan of Action and Milestones)** — the control B.B3's
    deviation-approved status maps to. CA-5(1) is the automation
    enhancement, which is the *positive* outcome of shipping LOOP-B end-
    to-end.
  - **RA-3 (Risk Assessment)** — B.B5's Risk Register IS the RA-3
    deliverable. Per RA-3(a), the organisation must "conduct a risk
    assessment, including: identifying threats to and vulnerabilities in
    the system; the likelihood and magnitude of harm...". B.B5 produces
    `risk-register.json` keyed on (threat_id, vulnerability_id, asset_id)
    so the artifact directly satisfies RA-3(a).
  - **RA-5 (Vulnerability Monitoring and Scanning)** — already covered by
    existing `vdr-scan.ts` collectors per provider; B.B1+B.B2 turn the
    raw scan output into a triaged, deadline-bearing risk ledger.

### OSCAL

- **OSCAL POA&M v1.1.2 schema** — committed at
  `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json`. Field
  references in this spec cite NIST OSCAL doc:
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
  - `risk.status` enum: `open`, `investigating`, `remediating`,
    `deviation-requested`, `deviation-approved`, `closed`. B.B3 transitions
    items between these via signed tracker actions.
  - `risk.props[]` is the extension point for `composite-score`,
    `deadline-source`, `acceptance-uuid`, `compensating-control-uuids`.
  - `risk.remediations[].lifecycle` enum: `recommendation`, `planned`,
    `completed`. B.B4 mitigating-factors land here when they're
    actively-deployed compensating controls.

---

## 4. Per-slice implementation specs

### Slice B.B1 — Per-finding CVSS + EPSS + criticality + exposure scoring

**Why this slice**: LOOP-A.A1 sorts the POA&M by severity (a 5-bucket
enum). Real risk-based prioritisation needs CVSS + EPSS + organisational
criticality + exposure. This slice produces a defensible composite score
per finding, attached as OSCAL props the 3PAO can sort + filter on.

**Files to create**:
- `cloud-evidence/core/risk-score.ts` — pure scoring library:
  CVSS parsing (3.1 + 4.0 vector strings), EPSS lookup (with optional
  HTTP fetch + on-disk cache), criticality/exposure extraction from
  inventory metadata, composite formula.
- `cloud-evidence/core/risk-config.ts` — typed loader for the operator's
  risk-scoring config (weights, criticality tag map, exposure tag map,
  EPSS feed config). Reads `cloud-evidence/risk-config.yaml` or path from
  `--risk-config`.
- `cloud-evidence/core/risk-score-emit.ts` — disk emitter that walks
  `out/KSI-*.json`, computes risk scores, rewrites each envelope's
  Findings with `risk_score` blocks, and emits `out/risk-scores.json`
  (the catalog the POA&M, AR, and dashboard read from).
- `cloud-evidence/tests/core/risk-score.test.ts` — unit tests for pure
  scoring math (CVSS 3.1 + 4.0 parsing, composite formula, fallback).
- `cloud-evidence/tests/core/risk-config.test.ts` — config loader tests.
- `cloud-evidence/tests/core/risk-score-emit.test.ts` — integration tests
  (read sample KSI-*.json, write risk-scores.json, verify props on
  re-emitted POA&M).
- `cloud-evidence/risk-config.example.yaml` — committed example
  configuration the operator copies + customises.

**Files to extend**:
- `cloud-evidence/core/envelope.ts`: add to `Finding` the optional
  `risk_score?: RiskScore` field — new type defined in `risk-score.ts`.
- `cloud-evidence/core/findings.ts`: extend `FindingInput` with optional
  `risk_score` so collectors can attach scores at construction time (for
  collectors that natively know CVSS — e.g. `vdr-scan.ts`).
- `cloud-evidence/core/oscal-poam.ts`: in `findingProps()`, append
  `composite-score`, `cvss-base`, `cvss-version`, `cvss-vector`,
  `epss-score`, `epss-percentile`, `criticality`, `exposure`,
  `risk-score-source`. Keep all existing props.
- `cloud-evidence/core/orchestrator.ts`: new `--risk-score` flag (env
  `CLOUD_EVIDENCE_RISK_SCORE`) + `--risk-config <path>` flag (env
  `CLOUD_EVIDENCE_RISK_CONFIG`). Runs BEFORE `--oscal-poam` so the POA&M
  picks up the scores.

**Schemas / standards**:
- **CVSS 3.1 Base** —
  https://www.first.org/cvss/v3.1/specification-document Equations 1–7.
  When a Finding cites a CVE that has a CVSS vector string, parse the
  vector and back-compute the Base score (or accept the score verbatim if
  also present). Always store the original vector string for traceability.
- **CVSS 4.0 MacroVector** —
  https://www.first.org/cvss/v4.0/specification-document. Detect vector
  strings beginning with `CVSS:4.0/` and parse to the 4.0 MacroVector +
  score. We treat a 4.0 score as authoritative over a 3.1 score on the
  same CVE.
- **EPSS API** — https://api.first.org/data/v1/epss?cve=<id>
  - Response shape (verify against live API at build time):
    `{ data: [ { cve: "CVE-XXXX-YYYY", epss: "0.97214", percentile: "0.99876", date: "YYYY-MM-DD" } ] }`
  - On-disk cache at `out/.epss-cache.json` keyed by `(cve, date)` with
    24-hour TTL.
- **Inventory metadata** —
  - `inventory.assets[].data_classification` ∈ {public, internal, confidential, cui, pii}
  - `inventory.assets[].asset_tier` ∈ {tier-0, tier-1, tier-2, tier-3}
  - `inventory.assets[].public_facing` (boolean)
  - `inventory.assets[].internet_reachable` (boolean)

**Build steps**:

1. Define types in `core/risk-score.ts`:
   ```ts
   export interface CvssVector {
     version: '3.1' | '4.0';
     vector: string;        // raw vector string
     base_score: number;    // 0.0 - 10.0, rounded per spec
     severity_label: 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
     parsed_metrics: Record<string, string>;
   }

   export interface EpssScore {
     cve: string;
     score: number;         // 0.0 - 1.0
     percentile: number;    // 0.0 - 1.0
     date: string;          // YYYY-MM-DD
     source: 'api' | 'cache' | 'config';
   }

   export interface RiskScore {
     composite_score: number;          // 0.0 - 10.0
     cvss?: CvssVector;
     epss?: EpssScore;
     criticality: number;              // 0.0 - 1.0
     exposure: number;                 // 0.0 - 1.0
     /** Whence the inputs came (per-field traceability). */
     sources: {
       cvss_source: 'finding-cited' | 'inventory-derived' | 'operator-supplied' | 'REQUIRES-OPERATOR-INPUT';
       epss_source: 'api' | 'cache' | 'operator-supplied' | 'REQUIRES-OPERATOR-INPUT';
       criticality_source: 'inventory-tag' | 'data-classification' | 'asset-tier' | 'REQUIRES-OPERATOR-INPUT';
       exposure_source: 'inventory-public-facing' | 'inventory-internet-reachable' | 'REQUIRES-OPERATOR-INPUT';
     };
     computed_at: string;              // ISO timestamp
     formula_version: string;          // e.g. "risk-score.v1"
   }
   ```

2. Pure builder signature:
   ```ts
   export function computeRiskScore(
     finding: Finding,
     ctx: RiskContext,
     opts: RiskScoringOpts,
   ): RiskScore;
   ```
   where `RiskContext` carries the resolved inventory assets matching
   `finding.gap.affected_resources` and any CVEs cited in
   `finding.references`, and `RiskScoringOpts` carries the operator's
   weights + criticality/exposure maps.

3. **Composite formula** (documented at length in the module docstring;
   weights are operator-tunable via `risk-config.yaml`):
   ```
   composite = w_cvss × cvss_base
             + w_epss × (epss_score × 10)
             + w_criticality × (criticality × 10)
             + w_exposure × (exposure × 10)
   ```
   Defaults: `w_cvss=0.4, w_epss=0.3, w_criticality=0.2, w_exposure=0.1`.
   The defaults match the LOOP-B design memo and are tunable; the
   module's docstring CITES the FIRST CVSS Section 7 (Scoring Rubric)
   discussion of weighting prioritisation, but does NOT claim the
   weights themselves are FIRST-published — they are an operator-tunable
   organisational choice, documented as such.

4. **CVSS source priority**:
   1. `finding.references[].cvss_vector` if a collector populated it
      (e.g. `vdr-scan.ts` for KEV/CVE-cited findings).
   2. NIST NVD lookup via API (DEFERRED — operator-supplied for now).
   3. Severity-derived fallback (MUST be marked
      `cvss_source: 'REQUIRES-OPERATOR-INPUT'`):
      critical → 9.5, high → 7.5, medium → 5.5, low → 2.5, info → 0.5.
      This is a *placeholder for risk math only*; the OSCAL prop
      `cvss-source` carries the literal string `REQUIRES-OPERATOR-INPUT`
      so a 3PAO sees the gap.

5. **EPSS lookup**:
   - When `ctx.cve_ids` is non-empty AND `opts.epss.enabled === true`,
     batch-query `https://api.first.org/data/v1/epss?cve=<csv>`.
   - Cache responses to `out/.epss-cache.json` with 24-hour TTL.
   - On HTTP failure: log `epss:fetch-failed` warning, set
     `epss_source: 'REQUIRES-OPERATOR-INPUT'`, do NOT silently fall back
     to zero (REO Rule 5).
   - When no CVE is cited, `epss` is `undefined` (no score) and the
     composite formula re-normalises the remaining weights.

6. **Criticality derivation**:
   - For each affected resource, resolve to `inventory.assets[]` by
     `identifier`. From the matched asset:
     - data_classification: cui=1.0, pii=0.9, confidential=0.7,
       internal=0.4, public=0.1.
     - asset_tier: tier-0=1.0, tier-1=0.75, tier-2=0.5, tier-3=0.25.
   - Criticality = max(data_class_score, asset_tier_score) across all
     affected resources.
   - When no affected resources OR no inventory match,
     `criticality_source: 'REQUIRES-OPERATOR-INPUT'`, criticality = 0.5
     (mid-range placeholder visible in the prop).

7. **Exposure derivation**:
   - For each affected resource: `exposure = 1.0` if
     `public_facing === true` OR `internet_reachable === true`, else 0.2.
   - Aggregate across resources via max.
   - When no asset matched OR fields absent on asset,
     `exposure_source: 'REQUIRES-OPERATOR-INPUT'`, exposure = 0.5.

8. **Disk emitter** in `core/risk-score-emit.ts`:
   ```ts
   export interface RiskScoreEmitOptions {
     outDir: string;
     inventoryPath?: string;        // default: outDir/inventory.json
     riskConfigPath?: string;       // default: ./risk-config.yaml
     epssEnabled?: boolean;         // default: true
     epssCachePath?: string;        // default: outDir/.epss-cache.json
     runId: string;
   }
   export interface RiskScoreEmitResult {
     path: string;                  // out/risk-scores.json
     scored_findings: number;
     unscored_findings: number;     // findings that returned REQUIRES-OPERATOR-INPUT for every source
     cve_lookups: number;
     epss_cache_hits: number;
     epss_api_calls: number;
   }
   export function emitRiskScores(opts: RiskScoreEmitOptions): RiskScoreEmitResult;
   ```
   The emitter ALSO rewrites each `KSI-*.json` envelope in-place to attach
   `finding.risk_score` for downstream consumers (POA&M, AR, dashboard).

9. **Wire into orchestrator**: `--risk-score` flag invokes
   `emitRiskScores()` BEFORE the OSCAL POA&M emitter. The POA&M emitter
   then sees `risk_score` blocks on each Finding and surfaces them as
   OSCAL props (see step 10).

10. **Extend `core/oscal-poam.ts:findingProps()`** to append:
    ```ts
    if (f.risk_score) {
      const rs = f.risk_score;
      props.push({ name: 'composite-score', ns: CE_NS, value: rs.composite_score.toFixed(2) });
      if (rs.cvss) {
        props.push({ name: 'cvss-version', ns: CE_NS, value: rs.cvss.version });
        props.push({ name: 'cvss-base', ns: CE_NS, value: rs.cvss.base_score.toFixed(1) });
        props.push({ name: 'cvss-vector', ns: CE_NS, value: rs.cvss.vector });
      }
      if (rs.epss) {
        props.push({ name: 'epss-score', ns: CE_NS, value: rs.epss.score.toFixed(5) });
        props.push({ name: 'epss-percentile', ns: CE_NS, value: rs.epss.percentile.toFixed(5) });
      }
      props.push({ name: 'criticality', ns: CE_NS, value: rs.criticality.toFixed(2) });
      props.push({ name: 'exposure', ns: CE_NS, value: rs.exposure.toFixed(2) });
      props.push({ name: 'risk-score-source-cvss', ns: CE_NS, value: rs.sources.cvss_source });
      props.push({ name: 'risk-score-source-epss', ns: CE_NS, value: rs.sources.epss_source });
      props.push({ name: 'risk-score-source-criticality', ns: CE_NS, value: rs.sources.criticality_source });
      props.push({ name: 'risk-score-source-exposure', ns: CE_NS, value: rs.sources.exposure_source });
      props.push({ name: 'risk-score-formula', ns: CE_NS, value: rs.formula_version });
    }
    ```

11. **Add to `submission-bundle.ts` well-known catalogue**:
    ```ts
    { role: 'risk-scores-json', filename: 'risk-scores.json', description: 'Per-finding CVSS+EPSS+criticality+exposure scores (LOOP-B.B1)' },
    { role: 'epss-cache', filename: '.epss-cache.json', description: 'On-disk EPSS API response cache' },
    ```

**REQUIRES-OPERATOR-INPUT fields**:
- `risk_score.sources.cvss_source = 'REQUIRES-OPERATOR-INPUT'` — when the
  finding's references[] cite no CVSS vector and no upstream NVD lookup
  is configured. Surfaced via prop `risk-score-source-cvss` on every
  affected OSCAL risk + poam-item.
- `risk_score.sources.epss_source = 'REQUIRES-OPERATOR-INPUT'` — when
  EPSS feed is disabled or the API call failed.
- `risk_score.sources.criticality_source = 'REQUIRES-OPERATOR-INPUT'` —
  when no inventory asset matched the affected resource OR
  `data_classification` + `asset_tier` are both absent on the matched
  asset. Operator fixes by tagging the asset
  (e.g. AWS tag `fedramp_data_classification=cui`).
- `risk_score.sources.exposure_source = 'REQUIRES-OPERATOR-INPUT'` — same
  pattern as criticality, for `public_facing` / `internet_reachable`.
- Composite weights — set via `risk-config.yaml` (flag
  `--risk-config <path>`).

**Test specifications** (≥12 tests):

1. `it('parses CVSS 3.1 vector with Scope Unchanged', ...)` — verify the
   spec's Equation 5 produces the published example score (CVSS:3.1/
   AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8).
2. `it('parses CVSS 3.1 vector with Scope Changed', ...)` — verifies
   Equation 5's 1.08 multiplier path.
3. `it('parses CVSS 4.0 MacroVector vector', ...)` — verifies CVSS:4.0/
   prefix detection + score interpolation table lookup.
4. `it('classifies severity label per Table 14', ...)` — None=0, Low<4,
   Medium<7, High<9, Critical≥9.
5. `it('emits REQUIRES-OPERATOR-INPUT cvss_source when no CVSS data', ...)`.
6. `it('honours operator-supplied CVSS via finding.references[].cvss_vector', ...)`.
7. `it('looks up EPSS via batch API and respects cache TTL', ...)` —
   mocks HTTP at the wire layer per CLAUDE.md Rule 2.4; production code
   never knows it's being tested.
8. `it('marks epss_source = REQUIRES-OPERATOR-INPUT on API failure', ...)`.
9. `it('derives criticality from inventory.assets data_classification', ...)`.
10. `it('derives criticality from asset_tier when data_class absent', ...)`.
11. `it('derives exposure from public_facing + internet_reachable', ...)`.
12. `it('emits REQUIRES-OPERATOR-INPUT exposure_source when fields absent', ...)`.
13. `it('computes composite per documented formula with default weights', ...)`.
14. `it('respects operator-tuned weights from risk-config.yaml', ...)`.
15. `it('re-normalises composite when epss missing', ...)`.
16. `it('attaches risk_score to every Finding in re-emitted KSI-*.json envelopes', ...)`.
17. `it('writes risk-scores.json with provenance.emitter + provenance.sourceCalls', ...)`.
18. `it('OSCAL POA&M findingProps emits composite-score + cvss-* + epss-* props', ...)`.

**REO compliance checks specific to this slice**:
- Every CVSS score traces to either a Finding-cited vector, an operator-
  supplied vector, or carries `cvss_source: REQUIRES-OPERATOR-INPUT`.
  No silent severity-fallback marketed as "real CVSS".
- EPSS lookups go through real HTTPS GET; the cache is real on-disk JSON.
- On API failure → REQUIRES-OPERATOR-INPUT marker, never `epss=0`.
- Composite formula is constant + operator-tunable; the version string
  `formula_version: "risk-score.v1"` lets future re-scoring trace lineage.
- Inventory matches go through real `inventory.json` reads.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/risk-score.test.ts tests/core/risk-config.test.ts tests/core/risk-score-emit.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 4 - 5 working days for a single implementer.

---

### Slice B.B2 — Remediation deadline math (KEV / PAIN / IRV / LEV)

**Why this slice**: LOOP-A.A1's deadlines are severity-keyed only. KEV-
listed findings are subject to the BOD 22-01 `dueDate` (not 60 days);
PAIN / IRV / LEV signals from the VDR pipeline accelerate deadlines per
the FedRAMP CMP table. This slice produces the authoritative deadline
formula.

**Files to create**:
- `cloud-evidence/core/deadline-engine.ts` — pure builder
  `computeDeadline()` with the priority cascade documented below.
- `cloud-evidence/core/deadline-table.ts` — typed constant table for
  FedRAMP CMP severity → days, KEV special case, PAIN/IRV/LEV overrides.
- `cloud-evidence/tests/core/deadline-engine.test.ts` — ~12 tests.
- `cloud-evidence/tests/core/deadline-table.test.ts` — 3 tests pinning
  the FedRAMP CMP values.

**Files to extend**:
- `cloud-evidence/core/oscal-poam.ts`:
  - Replace `deadlineFromCollected()` with a thin wrapper that calls
    `computeDeadline()` from `deadline-engine.ts`. The wrapper also adds
    a new OSCAL prop `deadline-source` to every risk:
    `{ name: 'deadline-source', value: 'kev'|'fedramp-cmp'|'pain-irv-lev'|'operator-override' }`.
  - Remove the local `REMEDIATION_DEADLINE_DAYS` constant; the new
    `deadline-table.ts` is the single source.
- `cloud-evidence/core/vdr-ledger.ts`: emit `pain`, `irv`, `lev` fields
  on each VDR entry (probably already partly present — verify and extend).
- `cloud-evidence/core/orchestrator.ts`: when `--strict-risk` is set,
  refuse to emit the POA&M if any KEV-listed finding still has
  `deadline-source = "fedramp-cmp"` (a sign the KEV catalog wasn't
  loaded; better to fail loud than ship a stale deadline).

**Schemas / standards**:
- **CISA KEV catalog** — already loaded by `core/kev-feed.ts`. The
  per-entry `dueDate` field is used VERBATIM:
  ```ts
  if (kevEntry) return { deadline: kevEntry.dueDate + 'T00:00:00Z', source: 'kev' };
  ```
- **BOD 22-01** —
  https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01
  — for documentation only; the catalog's own `dueDate` is authoritative.
- **FedRAMP Continuous Monitoring Strategy & Guide** —
  https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf
  - The implementer downloads this PDF to
    `cloud-evidence/docs/sources/fedramp-conmon-strategy-guide.pdf`,
    extracts the severity → days table verbatim, and pastes the table
    into `deadline-table.ts` as a string constant + a typed
    `FEDRAMP_CMP_DEADLINES` Record. The docstring cites the PDF page +
    section number.
- **PAIN / IRV / LEV** — the existing VDR pipeline definitions, documented
  in `docs/analysis/vdr.md`. Recap:
  - **PAIN** (Possible Adverse Impact Number) — operator-supplied
    classification of how bad an exploit would be; 1-5.
  - **IRV** (Internet-Reachable Verdict) — boolean derived from network
    topology (security groups, NACLs, ingress rules).
  - **LEV** (Likely Exploitable Verdict) — boolean derived from KEV
    membership + EPSS percentile threshold.

**Build steps**:

1. Define `DeadlineSource` enum: `'kev' | 'fedramp-cmp' | 'pain-irv-lev' | 'operator-override' | 'severity-fallback'`.

2. Define `DeadlineResult`:
   ```ts
   export interface DeadlineResult {
     deadline: string;              // ISO datetime
     source: DeadlineSource;
     days_from_collected: number;
     rationale: string;             // human-readable WHY this was chosen
     /** When source = 'kev', the CISA KEV entry that drove it. */
     kev_entry?: { cveID: string; dueDate: string; dateAdded: string };
     /** When source = 'pain-irv-lev', the signals that drove it. */
     pain_irv_lev?: { pain?: number; irv?: boolean; lev?: boolean };
   }
   ```

3. Pure builder:
   ```ts
   export function computeDeadline(
     finding: Finding,
     ctx: DeadlineContext,
     collectedAt: string,
   ): DeadlineResult;
   ```

4. **Priority cascade** (documented at length in module docstring):
   1. **Operator override** — when `finding.note` carries an explicit
      `OPERATOR_OVERRIDE_DEADLINE: 2026-08-15` token (or, more cleanly,
      `risk_acceptances` table has an active acceptance for this finding
      and B.B3 supplied the override). Source: `operator-override`.
   2. **KEV match** — when any CVE cited in `finding.references[]` OR
      `finding.gap.affected_resources[].attributes.cve_ids` is present
      in the loaded KEV catalog, use the catalog's `dueDate`. Source:
      `kev`.
   3. **PAIN / IRV / LEV override** — when the finding's
      `risk_score.composite_score >= 9.0` AND IRV=true AND LEV=true,
      override to "Critical equivalent" (30d per FedRAMP CMP) regardless
      of severity. Source: `pain-irv-lev`.
   4. **FedRAMP CMP table** — severity → days from
      `FEDRAMP_CMP_DEADLINES`. Source: `fedramp-cmp`.
   5. **Severity fallback** — if even the CMP table is missing for the
      severity (should never happen given the typed Record), fall through
      to LOOP-A.A1's hardcoded `REMEDIATION_DEADLINE_DAYS`. Source:
      `severity-fallback`. This branch is observable via the OSCAL prop
      so a 3PAO can verify it never fires in production.

5. **Strict mode**: when `--strict-risk` is set, the orchestrator counts
   findings with `source: 'severity-fallback'` and exits non-zero if any
   exist — a signal that the FedRAMP CMP table wasn't loaded properly.

6. Update `core/oscal-poam.ts:buildOscalPoam()` to invoke
   `computeDeadline()` and attach `deadline-source` + (when applicable)
   `kev-cve-id`, `kev-due-date`, `pain`, `irv`, `lev` props.

7. **Bundler integration**: add new role `deadline-audit-json` for the
   per-run report `out/deadline-audit.json` (one row per item with
   source + rationale). This is a NEW artifact this slice ships.

8. **CHANGELOG**: when slice ships, the entry MUST quote the FedRAMP CMP
   table values verbatim, with the PDF page + section number.

**REQUIRES-OPERATOR-INPUT fields**:
- `deadline-source = 'severity-fallback'` — surfaces when the FedRAMP CMP
  table didn't load (i.e. the PDF source was missing or `deadline-table.ts`
  wasn't updated). NOT silently buried — visible in every affected risk
  prop.
- Operator-override deadlines come from B.B3's risk-acceptance records
  (DB-backed, signed).

**Test specifications** (≥10):

1. `it('uses CISA KEV dueDate verbatim when CVE matches KEV', ...)`.
2. `it('does NOT compute +21d when KEV catalog supplied a dueDate', ...)`.
3. `it('falls through to FedRAMP CMP table when no KEV match', ...)`.
4. `it('applies PAIN/IRV/LEV override when composite >= 9 and IRV+LEV true', ...)`.
5. `it('honours operator override from risk_acceptances table', ...)`.
6. `it('logs severity-fallback source when CMP table missing', ...)`.
7. `it('throws under --strict-risk when severity-fallback fires', ...)`.
8. `it('attaches deadline-source prop on every OSCAL risk', ...)`.
9. `it('attaches kev-cve-id + kev-due-date props on KEV findings', ...)`.
10. `it('handles malformed collected_at by falling back to now', ...)`.
11. `it('handles multiple KEV CVEs by taking the earliest dueDate', ...)`.
12. `it('emits deadline-audit.json with one row per finding', ...)`.

**REO compliance checks specific to this slice**:
- KEV `dueDate` is read VERBATIM from the catalog — no synthetic +21d.
- FedRAMP CMP values are sourced from the downloaded PDF, with
  quote-and-citation in the constant's docstring.
- `severity-fallback` is observable in props; not hidden.
- Operator overrides flow through B.B3 signed records; never inline.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/deadline-engine.test.ts tests/core/deadline-table.test.ts tests/core/oscal-poam.test.ts
npm run check:reo
```

**Estimated effort**: 2 working days.

---

### Slice B.B3 — Risk acceptance workflow (tracker DB + signed audit record)

**Why this slice**: Today there is no system path for "we accept this
finding's residual risk because X, expires Y". This slice creates the
audited workflow + flips OSCAL `risk.status` to `deviation-approved`
when an active acceptance exists.

**Files to create**:
- `tracker/server/routes/risk-acceptance.ts` — Express route handler
  module: `POST /api/risk-acceptances`, `GET /api/risk-acceptances`,
  `GET /api/risk-acceptances/:id`, `POST /api/risk-acceptances/:id/expire`.
- `tracker/server/risk-acceptance-enforcer.ts` — recurring task (run on
  server boot + every hour) that checks `expiration_date < now()` and
  flips status to `expired`. The next POA&M emission then re-opens the
  finding.
- `tracker/client/src/pages/RiskAcceptance.tsx` — list + create page.
- `tracker/client/src/pages/RiskAcceptanceDetail.tsx` — per-acceptance
  detail view with signed-audit-record display.
- `cloud-evidence/core/risk-acceptance-reader.ts` — read-only client the
  POA&M emitter uses to pull active acceptances from the tracker.
- `tracker/server/routes/risk-acceptance.test.ts` — route tests.
- `tracker/server/risk-acceptance-enforcer.test.ts` — enforcer tests.
- `tracker/client/src/pages/RiskAcceptance.test.tsx` — UI tests.
- `cloud-evidence/tests/core/risk-acceptance-reader.test.ts` — reader.

**Files to extend**:
- `tracker/server/schema.sql` — append the new tables (single
  `schema.sql` model; no migrations dir today). Tables:
  ```sql
  CREATE TABLE IF NOT EXISTS risk_acceptances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,                       -- v4 uuid for OSCAL linking
    finding_uuid TEXT NOT NULL,                      -- maps to oscal finding.uuid
    poam_item_uuid TEXT NOT NULL,                    -- maps to oscal poam-item.uuid
    ksi_id TEXT NOT NULL,
    rule TEXT NOT NULL,
    provider TEXT NOT NULL,
    accepted_by_user_id INTEGER NOT NULL REFERENCES users(id),
    accepted_at TEXT NOT NULL,                       -- ISO datetime
    expiration_date TEXT NOT NULL,                   -- ISO datetime
    business_justification TEXT NOT NULL,
    acceptance_type TEXT NOT NULL CHECK (acceptance_type IN ('deviation-request','risk-adjustment','false-positive','operational-requirement')),
    status TEXT NOT NULL CHECK (status IN ('pending','approved','expired','revoked')),
    approved_by_user_id INTEGER REFERENCES users(id),
    approved_at TEXT,
    signature TEXT NOT NULL,                         -- Ed25519 signature of canonical JSON
    signing_key_id TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by_user_id INTEGER REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_ra_finding ON risk_acceptances(finding_uuid);
  CREATE INDEX IF NOT EXISTS idx_ra_status ON risk_acceptances(status);
  CREATE INDEX IF NOT EXISTS idx_ra_expiration ON risk_acceptances(expiration_date);

  CREATE TABLE IF NOT EXISTS risk_acceptance_compensating_links (
    acceptance_id INTEGER NOT NULL REFERENCES risk_acceptances(id) ON DELETE CASCADE,
    compensating_control_id INTEGER NOT NULL REFERENCES compensating_controls(id),
    PRIMARY KEY (acceptance_id, compensating_control_id)
  );
  ```
- `tracker/server/index.ts`: `app.use('/api/risk-acceptances', requireAuth, requireRole(['so','iso','ao']), routes.riskAcceptance)`.
- `tracker/server/rbac.ts`: new role permissions:
  - `iso` (Information System Owner) can create + revoke acceptances.
  - `ao` (Authorizing Official) can approve.
  - `assessor` (3PAO) can view, cannot create.
- `tracker/client/src/App.tsx`: add route `/risk-acceptance` + nav link.
- `cloud-evidence/core/oscal-poam.ts`:
  - Read `out/.risk-acceptances.json` (a snapshot the orchestrator pulls
    from the tracker via `risk-acceptance-reader.ts`) at build time.
  - For each finding, look up acceptances by `(ksi_id, rule, provider)`.
  - When an active acceptance exists: set `risk.status = 'deviation-approved'`,
    add prop `acceptance-uuid`, override `risk.deadline` to the
    acceptance's `expiration_date`, and add `risk.props["deadline-source"] = 'operator-override'`.
- `cloud-evidence/core/orchestrator.ts`: new
  `--pull-risk-acceptances <tracker-url>` flag + env
  `CLOUD_EVIDENCE_TRACKER_URL`. Runs BEFORE `--oscal-poam`.

**Schemas / standards**:
- **NIST SP 800-53 Rev 5 CA-5** — Plan of Action and Milestones,
  including the deviation/risk-acceptance lifecycle.
- **FedRAMP Deviation Request (DR)** — fields drive the form schema:
  finding identifier, justification (required), proposed remediation,
  proposed expiration, compensating controls, AO signature.
- **OSCAL POA&M `risk.status` enum** — `deviation-approved` is the spec-
  defined token; B.B3 produces this status legitimately (real signed
  human action, not synthesized).

**Build steps**:

1. Define typed interfaces in `tracker/server/routes/risk-acceptance.ts`:
   ```ts
   interface CreateAcceptanceBody {
     finding_uuid: string;
     poam_item_uuid: string;
     ksi_id: string;
     rule: string;
     provider: string;
     expiration_date: string;   // ISO datetime; must be > now + 7d
     business_justification: string;  // min 100 chars
     acceptance_type: 'deviation-request' | 'risk-adjustment' | 'false-positive' | 'operational-requirement';
     compensating_control_uuids: string[];   // from B.B4 registry
   }
   ```

2. **Validation**:
   - `expiration_date` must be ≥ 7 days from now (operator can't accept
     for "today only").
   - `expiration_date` must be ≤ 365 days from now (mirrors FedRAMP DR
     annual-review default).
   - `business_justification` minimum 100 characters.
   - At least one `compensating_control_uuid` required for
     `acceptance_type = 'deviation-request'`.
   - User must have `iso` or higher role.

3. **Signature**:
   - Canonical-JSON-encode `{finding_uuid, accepted_by_user_id, accepted_at, expiration_date, business_justification, acceptance_type, compensating_control_uuids}`.
   - Sign with the tracker's resident Ed25519 key (existing key from
     LOOP-B.1 signing pipeline; surfaced as `signing_key_id`).
   - Store signature + key id on the row. Persistence is the audit
     record.

4. **AO approval flow**: acceptance is created with `status='pending'`;
   transitioning to `approved` requires `ao` role + a second signature
   over `{acceptance_uuid, approved_by_user_id, approved_at}`.

5. **Enforcer task** runs every hour:
   ```ts
   const expired = db.prepare(`
     SELECT id, uuid, finding_uuid FROM risk_acceptances
     WHERE status = 'approved' AND expiration_date < ?
   `).all(new Date().toISOString());
   for (const row of expired) {
     db.prepare(`UPDATE risk_acceptances SET status='expired' WHERE id=?`).run(row.id);
     auditLog.write({
       event: 'risk-acceptance-expired',
       acceptance_uuid: row.uuid,
       finding_uuid: row.finding_uuid,
       at: new Date().toISOString(),
     });
   }
   ```

6. **`risk-acceptance-reader.ts`** (cloud-evidence side):
   ```ts
   export interface PulledAcceptance {
     uuid: string;
     finding_uuid: string;
     poam_item_uuid: string;
     ksi_id: string;
     rule: string;
     provider: string;
     expiration_date: string;
     business_justification: string;
     acceptance_type: string;
     compensating_control_uuids: string[];
     signature: string;
     signing_key_id: string;
   }
   export async function pullActiveAcceptances(
     trackerUrl: string,
     apiToken: string,
     outDir: string,
   ): Promise<PulledAcceptance[]>;
   ```
   Writes `out/.risk-acceptances.json` (the snapshot the POA&M emitter
   reads) + verifies every record's signature against the tracker's
   advertised public key.

7. **POA&M integration** (`core/oscal-poam.ts`):
   ```ts
   // Inside buildOscalPoam(), per failing finding:
   const acc = activeAcceptanceFor(ksiId, f.rule, prov.provider, acceptances);
   if (acc) {
     riskStatus = 'deviation-approved';
     overrideDeadline = acc.expiration_date;
     extraProps.push({ name: 'acceptance-uuid', ns: CE_NS, value: acc.uuid });
     extraProps.push({ name: 'acceptance-type', ns: CE_NS, value: acc.acceptance_type });
     extraProps.push({ name: 'acceptance-justification', ns: CE_NS, value: acc.business_justification.slice(0, 240) });
     for (const ccUuid of acc.compensating_control_uuids) {
       extraProps.push({ name: 'compensating-control-uuid', ns: CE_NS, value: ccUuid });
     }
   }
   ```

8. **Bundler integration**: `risk-acceptances.json` snapshot included in
   the submission bundle as role `risk-acceptances-snapshot`.

9. **UI** (`RiskAcceptance.tsx`):
   - List view: filterable by KSI, severity, status, expiration date.
   - Per-finding "Accept Risk" button (visible only on findings that
     don't already have an active acceptance).
   - Create form: free-text justification, expiration date picker,
   compensating-control multi-select (sourced from B.B4 registry).
   - Per-acceptance detail view shows signed audit record + diff against
   the original finding state.

**REQUIRES-OPERATOR-INPUT fields**:
- `business_justification` — operator UI input.
- `expiration_date` — operator UI input.
- `compensating_control_uuids` — operator UI select from B.B4 registry.
- `approved_by_user_id` — must be a user with `ao` role; otherwise the
  acceptance stays `pending`.

**Test specifications** (≥15):

1. `it('creates a pending acceptance when iso submits valid body', ...)`.
2. `it('rejects expiration_date < 7d from now', ...)`.
3. `it('rejects expiration_date > 365d from now', ...)`.
4. `it('rejects justification < 100 chars', ...)`.
5. `it('rejects when user lacks iso role', ...)`.
6. `it('rejects deviation-request with empty compensating_control_uuids', ...)`.
7. `it('signs the canonical JSON with the tracker Ed25519 key', ...)`.
8. `it('allows ao to transition pending → approved', ...)`.
9. `it('rejects ao approval signature replay (uuid + approved_at must change)', ...)`.
10. `it('enforcer flips status to expired when expiration_date past', ...)`.
11. `it('enforcer writes audit-log row on expiration', ...)`.
12. `it('pullActiveAcceptances writes .risk-acceptances.json with verified sigs', ...)`.
13. `it('refuses to write snapshot for any record whose signature is invalid', ...)`.
14. `it('POA&M emitter flips risk.status to deviation-approved when active acceptance exists', ...)`.
15. `it('POA&M emitter overrides risk.deadline with acceptance.expiration_date', ...)`.
16. `it('POA&M emitter attaches acceptance-uuid + acceptance-type + compensating-control-uuid props', ...)`.
17. `it('does NOT flip status when acceptance is pending (not yet approved)', ...)`.
18. `it('does NOT flip status when acceptance is expired', ...)`.
19. `it('RBAC: assessor can view but not create', ...)`.

**REO compliance checks specific to this slice**:
- Signatures are real Ed25519 over canonical-JSON. No mocked crypto. The
  tracker's resident key is the same key core/sign.ts uses, with
  provenance recorded.
- `business_justification` is verbatim operator input — never auto-
  populated.
- AO approval requires the `ao` role; system never auto-approves.
- `deviation-approved` only ever propagates to OSCAL when a signed,
  approved, unexpired record exists.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/risk-acceptance-reader.test.ts
cd ../tracker
npm run typecheck
npm test -- server/routes/risk-acceptance.test.ts server/risk-acceptance-enforcer.test.ts client/src/pages/RiskAcceptance.test.tsx
cd ../cloud-evidence
npm run check:reo
```

**Estimated effort**: 6 - 7 working days (server + client + integration).

---

### Slice B.B4 — Compensating-controls registry

**Why this slice**: B.B3 acceptances must reference real compensating
controls. Today these are ad-hoc free text. This slice creates a typed,
auditable registry; B.B3 selects from it; the POA&M emits structured
`mitigating-factors` references.

**Files to create**:
- `tracker/server/routes/compensating-controls.ts` — CRUD route.
- `tracker/client/src/pages/CompensatingControls.tsx` — list + CRUD UI.
- `tracker/client/src/pages/CompensatingControlDetail.tsx` — per-control
  detail view with linked acceptances + evidence.
- `cloud-evidence/core/compensating-control-reader.ts` — read-only client
  the POA&M emitter uses to pull control records.
- `tracker/server/routes/compensating-controls.test.ts`.
- `tracker/client/src/pages/CompensatingControls.test.tsx`.
- `cloud-evidence/tests/core/compensating-control-reader.test.ts`.

**Files to extend**:
- `tracker/server/schema.sql`:
  ```sql
  CREATE TABLE IF NOT EXISTS compensating_controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    nist_control_ids TEXT NOT NULL,        -- JSON array of NIST control ids
    implemented_by_user_id INTEGER NOT NULL REFERENCES users(id),
    implemented_at TEXT NOT NULL,
    signed_off_by_user_id INTEGER REFERENCES users(id),
    signed_off_at TEXT,
    expiration_date TEXT,                  -- null = no expiration
    evidence_url TEXT,                     -- e.g. link to runbook
    evidence_sha256 TEXT,                  -- sha256 of evidence attachment if uploaded
    status TEXT NOT NULL CHECK (status IN ('draft','active','retired')),
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_cc_status ON compensating_controls(status);
  CREATE INDEX IF NOT EXISTS idx_cc_expiration ON compensating_controls(expiration_date);
  ```
- `tracker/server/index.ts`: mount route.
- `tracker/client/src/App.tsx`: add `/compensating-controls` route.
- `cloud-evidence/core/oscal-poam.ts`:
  - Read `out/.compensating-controls.json` snapshot.
  - For risks with active acceptance carrying compensating-control
    UUIDs, emit a `risk.remediations[]` entry per compensating control
    with `lifecycle: 'completed'` (the control is already in place) and
    `title` / `description` from the registry.
  - Add `risk.props["mitigating-factor"]` props naming the
    compensating-control UUID + NIST control IDs.

**Schemas / standards**:
- **NIST SP 800-53 Rev 5 CA-5(1)** — automation enhancement to POA&M.
  Compensating controls referenced here directly satisfy CA-5(1)'s
  requirement that mitigations be tracked alongside the items.
- **NIST SP 800-53 Rev 5 PL-2** — System Security Plan, which
  enumerates compensating controls. B.B4's UUIDs become the canonical
  identifier the SSP narrative cites.
- **OSCAL `risk.remediations[]`** with `lifecycle: 'completed'`.

**Build steps**:

1. CRUD routes with RBAC: only users with `iso` role can create/update;
   `ao` signs off; `assessor` views.
2. Validation:
   - `title`: 5–200 chars.
   - `description`: ≥ 200 chars.
   - `nist_control_ids[]`: each must validate against the loaded NIST
     control catalog (`core/nist-r5.ts`).
   - `status` transitions: `draft → active → retired`; `active` requires
     `signed_off_by_user_id` set + valid AO signature.
3. Sign the canonical-JSON payload, same Ed25519 key as B.B3.
4. **Reader** `pullCompensatingControls(trackerUrl, apiToken, outDir)`
   writes `out/.compensating-controls.json`.
5. **POA&M emission**: when a risk has active acceptance with
   compensating-control UUIDs, emit:
   ```ts
   const remediations: OscalRiskRemediation[] = acc.compensating_control_uuids.map((ccUuid) => {
     const cc = compensatingControls.find(c => c.uuid === ccUuid);
     return {
       uuid: deterministicUuid(`poam:risk:${ksiId}:${rule}:cc:${ccUuid}`),
       lifecycle: 'completed' as const,
       title: cc?.title ?? `Compensating control ${ccUuid}`,
       description: cc?.description ?? 'compensating control referenced by acceptance',
       props: [
         { name: 'compensating-control-uuid', ns: CE_NS, value: ccUuid },
         ...(cc?.nist_control_ids ?? []).map(cid => ({ name: 'nist-control', ns: CE_NS, value: cid })),
       ],
       links: cc?.evidence_url ? [{ href: cc.evidence_url, rel: 'reference' }] : undefined,
     };
   });
   ```
6. **Bundler integration**: `compensating-controls.json` snapshot
   bundled as role `compensating-controls-snapshot`.
7. UI: list / create / sign-off / retire pages with reusable card
   components.

**REQUIRES-OPERATOR-INPUT fields**:
- All compensating-control content is operator-supplied; nothing is
  synthesised. If a B.B3 acceptance references a UUID not in the registry,
  the POA&M emitter records prop
  `compensating-control-status = "REQUIRES-OPERATOR-INPUT: unknown uuid"`
  rather than dropping the reference.

**Test specifications** (≥12):

1. `it('creates a draft compensating control', ...)`.
2. `it('rejects active status without ao sign-off', ...)`.
3. `it('rejects invalid NIST control id', ...)`.
4. `it('rejects title < 5 chars or > 200 chars', ...)`.
5. `it('signs canonical JSON with Ed25519', ...)`.
6. `it('allows transition draft → active when AO signs', ...)`.
7. `it('rejects active → draft transition', ...)`.
8. `it('lists only active controls in the B.B3 acceptance UI selector', ...)`.
9. `it('reader writes snapshot with verified signatures', ...)`.
10. `it('POA&M emits risk.remediations[] with lifecycle=completed', ...)`.
11. `it('POA&M emits compensating-control-uuid + nist-control props', ...)`.
12. `it('POA&M emits REQUIRES-OPERATOR-INPUT marker when acceptance cites unknown UUID', ...)`.
13. `it('expired compensating control does NOT propagate to active acceptances', ...)`.

**REO compliance checks specific to this slice**:
- All registry content is operator-supplied through tracker UI; nothing
  is auto-generated.
- NIST control IDs validate against the published catalog.
- Signatures real Ed25519.
- Unknown UUIDs surface as REQUIRES-OPERATOR-INPUT, never silently
  dropped.

**Verification commands**:
```bash
cd tracker
npm run typecheck
npm test -- server/routes/compensating-controls.test.ts client/src/pages/CompensatingControls.test.tsx
cd ../cloud-evidence
npm run typecheck
npm test -- tests/core/compensating-control-reader.test.ts
npm run check:reo
```

**Estimated effort**: 4 working days.

---

### Slice B.B5 — Central Risk Register (RA-3)

**Why this slice**: NIST SP 800-53 Rev 5 RA-3 mandates a system-wide risk
assessment artifact. B.B1 produces per-finding scores; B.B3 captures
accepted risks; B.B4 captures mitigations — but there is no single,
exec-readable Risk Register today. This slice aggregates everything plus
operator-entered organisational risks (third-party, supply-chain,
environmental).

**Files to create**:
- `cloud-evidence/core/risk-register.ts` — pure aggregator + emitter:
  reads `out/risk-scores.json`, `out/.risk-acceptances.json`,
  `out/.compensating-controls.json`, plus
  `out/.organisational-risks.json` (pulled from tracker), produces
  `out/risk-register.json` + `out/risk-register.xlsx`.
- `cloud-evidence/core/risk-register-xlsx.ts` — xlsx renderer reusing
  the existing pure-JS xlsx pattern (same approach as
  `core/inventory-workbook.ts`).
- `tracker/server/routes/risk-register.ts` — CRUD for organisational
  risks (third-party, supply-chain, environmental, contractual).
- `tracker/client/src/pages/RiskRegister.tsx` — list + create UI for
  organisational risks; shows the consolidated register (read from a
  GET endpoint that joins the per-finding and organisational sources).
- `tracker/server/routes/risk-register.test.ts`.
- `tracker/client/src/pages/RiskRegister.test.tsx`.
- `cloud-evidence/tests/core/risk-register.test.ts`.
- `cloud-evidence/tests/core/risk-register-xlsx.test.ts`.

**Files to extend**:
- `tracker/server/schema.sql`:
  ```sql
  CREATE TABLE IF NOT EXISTS organisational_risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('third-party','supply-chain','environmental','contractual','operational','other')),
    likelihood TEXT NOT NULL CHECK (likelihood IN ('very-low','low','moderate','high','very-high')),
    impact TEXT NOT NULL CHECK (impact IN ('very-low','low','moderate','high','very-high')),
    inherent_risk TEXT NOT NULL CHECK (inherent_risk IN ('very-low','low','moderate','high','very-high')),
    residual_risk TEXT NOT NULL CHECK (residual_risk IN ('very-low','low','moderate','high','very-high')),
    treatment TEXT NOT NULL CHECK (treatment IN ('accept','mitigate','transfer','avoid')),
    owner_user_id INTEGER NOT NULL REFERENCES users(id),
    review_date TEXT NOT NULL,
    nist_control_ids TEXT,                -- JSON array, optional
    compensating_control_uuids TEXT,      -- JSON array of B.B4 UUIDs, optional
    status TEXT NOT NULL CHECK (status IN ('open','closed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_org_risk_category ON organisational_risks(category);
  CREATE INDEX IF NOT EXISTS idx_org_risk_status ON organisational_risks(status);
  CREATE INDEX IF NOT EXISTS idx_org_risk_review ON organisational_risks(review_date);
  ```
- `cloud-evidence/core/orchestrator.ts`: new `--risk-register` flag
  (env `CLOUD_EVIDENCE_RISK_REGISTER`). Runs AFTER B.B1/B.B2/B.B3
  pulls; emits the combined register.
- `cloud-evidence/core/submission-bundle.ts`: new roles
  `risk-register-json`, `risk-register-xlsx`.

**Schemas / standards**:
- **NIST SP 800-30 Rev 1 §3.2** — likelihood/impact qualitative scales
  ("Very Low", "Low", "Moderate", "High", "Very High"). Used VERBATIM as
  the schema enum.
- **NIST SP 800-53 Rev 5 RA-3** — Risk Assessment control statement;
  this artifact directly satisfies RA-3(a) the per-system risk
  assessment.
- **NIST SP 800-39 §2.3 (Risk Management Hierarchy)** — informs the
  three-tier organisational risk decomposition (organisational,
  business-process, information-system) reflected in the `category`
  enum.
- **FedRAMP RMS template** (LOOP-C.C7) — risk register is its primary
  input.

**Build steps**:

1. Define `RiskRegisterEntry`:
   ```ts
   export type RiskSource = 'finding' | 'acceptance' | 'organisational';
   export interface RiskRegisterEntry {
     uuid: string;
     source: RiskSource;
     title: string;
     description: string;
     category: string;                 // matches OrganisationalRiskCategory or "ksi-finding"
     likelihood: 'very-low'|'low'|'moderate'|'high'|'very-high';
     impact:     'very-low'|'low'|'moderate'|'high'|'very-high';
     inherent_risk: 'very-low'|'low'|'moderate'|'high'|'very-high';
     residual_risk: 'very-low'|'low'|'moderate'|'high'|'very-high';
     treatment: 'accept'|'mitigate'|'transfer'|'avoid';
     owner: string;                    // user name or role
     review_date: string;
     status: 'open'|'closed';
     /** Source-specific back-references. */
     references: {
       finding_uuid?: string;
       poam_item_uuid?: string;
       acceptance_uuid?: string;
       organisational_risk_uuid?: string;
       compensating_control_uuids?: string[];
       nist_control_ids?: string[];
     };
   }
   ```

2. **Aggregator** `buildRiskRegister(inputs: RiskRegisterInputs): RiskRegisterEntry[]`:
   - For each OSCAL POA&M risk: synthesise a RiskRegisterEntry with
     `source='finding'`, likelihood derived from EPSS percentile bands
     (≥0.95=very-high, ≥0.5=high, ≥0.05=moderate, ≥0.005=low,
     else very-low; bands are operator-tunable via risk-config.yaml),
     impact derived from criticality bands (≥0.9=very-high, ...),
     inherent = max(likelihood,impact), residual = same unless
     compensating-control present (then drop one band).
   - For each active risk-acceptance: synthesise an entry with
     `source='acceptance'`, treatment='accept'.
   - For each organisational risk: copy verbatim.

3. **JSON emit**: `out/risk-register.json` with top-level
   `provenance: { emitter, emittedAt, sourceCalls, signingKeyId }` block
   per REO Rule 2.6 + `scripts/check-provenance.mjs`.

4. **XLSX emit**: same pure-JS xlsx pattern as
   `core/inventory-workbook.ts`. Columns:
   A. Risk ID (uuid)
   B. Source (finding | acceptance | organisational)
   C. Title
   D. Category
   E. Likelihood
   F. Impact
   G. Inherent Risk
   H. Residual Risk
   I. Treatment
   J. Owner
   K. Review Date
   L. Status
   M. Linked POA&M Item
   N. Linked Acceptance
   O. Compensating Controls
   P. NIST Controls
   Q. Description (wrapped)

5. **Orchestrator wiring**: `--risk-register` flag runs AFTER POA&M
   emission. Reads OSCAL POA&M, joins with acceptance/CC/organisational
   snapshots, writes both artifacts.

6. **Bundler**: add `risk-register-json` + `risk-register-xlsx` roles
   to well-known catalogue.

7. **UI** (`RiskRegister.tsx`): table view sortable by inherent_risk +
   residual_risk. "Add organisational risk" form. "Export" button hits
   the orchestrator (or a server-side render of the same xlsx).

**REQUIRES-OPERATOR-INPUT fields**:
- Organisational risks are entirely operator-supplied.
- `likelihood`, `impact`, `treatment`, `owner_user_id` — operator form
  inputs.
- When a finding-source entry's EPSS / criticality is REQUIRES-OPERATOR-
  INPUT (from B.B1), the derived `likelihood` / `impact` carry the same
  marker into the register.

**Test specifications** (≥8):

1. `it('aggregates per-finding risks from POA&M', ...)`.
2. `it('aggregates active acceptances as source=acceptance entries', ...)`.
3. `it('aggregates organisational risks verbatim', ...)`.
4. `it('derives likelihood from EPSS percentile bands', ...)`.
5. `it('derives impact from criticality bands', ...)`.
6. `it('drops residual_risk one band when compensating control linked', ...)`.
7. `it('emits risk-register.json with provenance block', ...)`.
8. `it('emits risk-register.xlsx with 17 columns and one row per entry', ...)`.
9. `it('xlsx is openable by SheetJS round-trip', ...)`.
10. `it('REQUIRES-OPERATOR-INPUT propagates from B.B1 risk_score to register entry', ...)`.
11. `it('organisational_risks table enforces 800-30 likelihood/impact enums', ...)`.

**REO compliance checks specific to this slice**:
- Every per-finding entry traces to a real OSCAL risk in poam.json.
- Every acceptance entry traces to a signed `risk_acceptances` row.
- Every organisational entry traces to a tracker row with audit trail.
- No synthetic risks; the aggregator is a join, not a generator.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/risk-register.test.ts tests/core/risk-register-xlsx.test.ts
cd ../tracker
npm test -- server/routes/risk-register.test.ts client/src/pages/RiskRegister.test.tsx
cd ../cloud-evidence
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 3 - 4 working days.

---

## 5. Loop-wide acceptance criteria

LOOP-B is COMPLETE when ALL of the following are true:

1. **B.B1**: every Finding in every `KSI-*.json` envelope carries a
   `risk_score` block (or its sources carry REQUIRES-OPERATOR-INPUT
   markers). `out/risk-scores.json` exists with provenance block. POA&M
   `findingProps` emits the new score props. The composite formula is
   tunable via `risk-config.yaml`. EPSS lookups use the real
   `api.first.org/data/v1/epss` endpoint, with on-disk cache.
2. **B.B2**: every OSCAL risk carries `deadline-source` prop in
   {kev, fedramp-cmp, pain-irv-lev, operator-override}. KEV-listed
   findings use the catalog's `dueDate` verbatim. `--strict-risk` mode
   fails the build if `severity-fallback` ever fires.
3. **B.B3**: tracker has `risk_acceptances` + link table; signed audit
   records persist; AO approval flow works; UI ships; enforcer runs;
   POA&M flips affected risks to `deviation-approved` when an active
   acceptance exists.
4. **B.B4**: tracker has `compensating_controls` table; sign-off flow
   works; UI ships; POA&M emits `risk.remediations[]` with `lifecycle:
   completed` for active controls.
5. **B.B5**: `out/risk-register.json` + `out/risk-register.xlsx` emit
   end-to-end; bundler includes both; UI ships for organisational risks.
6. All five slices pass `npm run typecheck`, `npm test`, and
   `npm run check:reo` in both `cloud-evidence/` and `tracker/`.
7. CHANGELOG "Unreleased" has five entries (one per slice) with module
   names + verification counts + REO compliance notes.
8. STATUS.md per-slice rows updated.

---

## 6. Open questions / caveats

1. **FedRAMP CMP table values** — until the implementer downloads the
   PDF and quotes the verbatim table, B.B2's `deadline-table.ts`
   ships with the LOOP-A.A1 baseline values + a TODO-free
   `REQUIRES-OPERATOR-INPUT: confirm-against-fedramp-cmp-pdf` marker on
   the constant's docstring (visible to `check:reo` reviewers; not a
   silent fallback).
2. **NVD CVE data** — B.B1's CVSS source priority lists "NIST NVD lookup
   via API" as deferred. The interim path is operator-supplied vectors
   (collectors that natively know CVE — e.g. `vdr-scan.ts` — populate
   `finding.references[].cvss_vector` directly). A future slice (call
   it B.B6 or extend B.B1) could add an NVD client; not required for
   LOOP-B completion.
3. **CVSS 4.0 MacroVector implementation** — full MacroVector lookup
   tables are large. The implementer's first cut may approximate via
   the 4.0 spec's qualitative bands and refine if/when the lookup
   tables are committed to disk. Either way, the OSCAL prop
   `cvss-version` is honest: `3.1` or `4.0`.
4. **EPSS rate limits** — FIRST does not publish rate limits. If the
   batch endpoint returns 429, the cache + retry logic
   (`core/retry.ts`) is reused; on persistent failure, B.B1 falls back
   to REQUIRES-OPERATOR-INPUT per spec.
5. **AO sign-off identity** — B.B3 requires a user with `ao` role to
   approve. The tracker's RBAC already supports custom roles; B.B3
   ships the `ao` role definition + the OPS doc that explains who in
   the org should hold it.
6. **POA&M XML emission** — `oscal-xml.ts` already projects JSON→XML.
   New props from B.B1/B.B2/B.B3/B.B4 flow through unchanged. Verify
   no new prose fields need wrapping.
7. **Multi-CSO** — H.H3 will add tenant isolation. B.B3/B.B4/B.B5
   tables include no `tenant_id` column in this loop. When H.H3 ships,
   it migrates all four tables in one cross-loop sweep.

---

## 7. Status tracking

Update this table when a slice ships (see Section 8).

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| B.B1 | Per-finding CVSS+EPSS+criticality+exposure scoring | done | `22b6590` | 2026-06-10 |
| B.B2 | Remediation deadline math (KEV / PAIN-IRV-LEV) | done | `f25255d` | 2026-06-11 |
| B.B3 | Risk acceptance workflow (tracker DB + signed audit) | done | `99f5afe` | 2026-07-02 |
| B.B4 | Compensating-controls registry | pending | — | — |
| B.B5 | Central Risk Register (RA-3) | pending | — | — |

---

## 8. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST perform these steps. Skipping
any one is a REO Rule 2 violation.

1. **Verify green**: from repo root
   ```bash
   cd cloud-evidence
   npm run typecheck            # must be clean
   npm test                     # 100% passing (existing 874 + new slice tests)
   npm run check:reo            # G1 + G2 + G3 all green
   npm run check:provenance     # every new emit-field has provenance entry
   ```
   For slices touching the tracker (B.B3, B.B4, B.B5):
   ```bash
   cd ../tracker
   npm run typecheck
   npm test
   ```

2. **Update Section 7 status table**: edit
   `cloud-evidence/docs/loops/LOOP-B-SPEC.md` (this file). Set the
   slice's row to `status=done`, `commit=<short-sha>`,
   `date=<YYYY-MM-DD>`.

3. **Update CHANGELOG.md "Unreleased"**: add a new `### Added — LOOP-B.<id>: <title>` block at the top of "Unreleased". Mirror the
   LOOP-A.A* entries in `CHANGELOG.md` for tone and depth. Cite the
   module names, the spec links, and the verification counts:
   - Number of new tests + total tests after slice
   - Whether typecheck + check:reo are green
   - Net new files
   - Brief REO-compliance note

4. **Update `cloud-evidence/docs/STATUS.md`**: set the slice row to
   `done`. (If STATUS.md doesn't exist yet, this slice's commit creates
   it with one row per LOOP slice.)

5. **Commit**: from repo root
   ```bash
   git add -A
   git commit -m "LOOP-B.<id>: <title>"
   ```
   Commit message body: short paragraph mirroring CHANGELOG entry intent.

6. **Push**: `git push origin main` (single-branch repo; no PR flow
   required for solo workflow; future multi-contributor mode adopts
   PR review).

7. **Sanity check**: re-clone into a scratch directory, run the
   orchestrator on a fixture inventory, verify the new artifact lands
   in `out/`. Removes "works on my machine" failure modes.

---

## 9. Appendix — composite formula derivation worked example

To make B.B1 reviewable, here is the worked example the test suite
encodes verbatim. Given a Finding with:

- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → base_score = 9.8
- EPSS score = 0.972, percentile = 0.998 (from FIRST API)
- Asset: data_classification=cui, asset_tier=tier-0 → criticality = 1.0
- Asset: public_facing=true → exposure = 1.0

Default weights: 0.4 / 0.3 / 0.2 / 0.1

```
composite = 0.4 * 9.8 + 0.3 * (0.972 * 10) + 0.2 * (1.0 * 10) + 0.1 * (1.0 * 10)
          = 3.92 + 2.916 + 2.0 + 1.0
          = 9.836
```

Composite score: **9.84** (rounded to 2 decimal places, per the OSCAL
prop emission code in step 10 of B.B1).

Quality of this prioritisation signal:
- Severity alone would say "critical, 30-day deadline".
- B.B2 layered on top: KEV match? If yes → catalog dueDate (typically
  21d). PAIN/IRV/LEV check (composite ≥9 ∧ IRV ∧ LEV) — both true →
  override to 30d treated-as-critical regardless of the original
  severity (already critical here, so no change).
- B.B3: operator accepts the risk citing CC-007 (a compensating WAF
  rule). Risk status flips to `deviation-approved`, deadline = the
  acceptance's `expiration_date` (say 2026-12-31).
- B.B4: registry record for CC-007 carries title "Block CVE-yyyy-xxxx
  payloads at WAF" + NIST control SC-7(5).
- B.B5: register entry source=finding, likelihood=very-high (EPSS≥0.95),
  impact=very-high (criticality≥0.9), inherent=very-high; CC-007 linked
  → residual=high.

The same Finding goes from a 60-day generic "high" deadline (LOOP-A.A1
behaviour) to a fully-prioritised, AO-signed, compensating-control-
backed `deviation-approved` item with a 6-month expiration and a Risk
Register entry traceable to NIST SP 800-30 likelihood/impact tokens.
That is the LOOP-B value proposition end-to-end.
