# FedPy operator guide

This is the **single consolidated reference** for operating FedPy
(`cloud-evidence/` + `tracker/`) against a real FedRAMP 20x / Rev5 program.
It does NOT duplicate `README.md` (root) or `RUNBOOK.md` (root) — those
cover the high-level architecture, IAM setup, daily run, scaling, and
disaster recovery. This guide covers:

1. **System architecture at a glance** (1-page summary; pointers to deeper docs)
2. **Configuration files** — `config.yaml`, `thresholds.yaml`, the
   forward-spec `org-profile.yaml`
3. **CLI flags reference** — complete list, one place
4. **Environment variables reference** — complete list, grouped by purpose
5. **Loop landscape** — what's implemented today, what's specified for
   future implementation, what's roadmap-only
6. **Conditional loops + org-profile.yaml** — when each conditional loop
   fires + how to opt in via the forward-spec org-profile.yaml
7. **Output artifacts** — what each file is, when it's emitted
8. **Common run patterns** — recipes for the typical operator scenarios

> Read alongside:
> - [`cloud-evidence/CLAUDE.md`](../CLAUDE.md) — the Scope Guard block,
>   REO standard, and the Conditional Applicability Matrix
> - [`README.md`](../../README.md) (root) — marketing + quick start +
>   architecture diagram
> - [`RUNBOOK.md`](../../RUNBOOK.md) (root) — daily-run + IAM + DR
> - [`cloud-evidence/docs/STATUS.md`](STATUS.md) — current loop / slice
>   implementation status

---

## 1. System architecture at a glance

```
                  ┌─────────────────────────────────────┐
                  │           CONFIGURATION             │
                  │  config.yaml  (technical / SDK)     │
                  │  thresholds.yaml  (rollup gates)    │
                  │  org-profile.yaml  (forward-spec —  │
                  │      conditional-loop triggers)     │
                  └─────────────────┬───────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────┐
│                       ORCHESTRATOR                          │
│            core/orchestrator.ts (CLI entrypoint)            │
│                                                             │
│   args + env vars → impact level, framework, KSI filter,    │
│                     submission-bundle flags, integrations   │
└──────┬──────────────┬──────────────┬──────────────┬─────────┘
       │              │              │              │
       ▼              ▼              ▼              ▼
   AWS Provider   GCP Provider   Azure Provider  Kubernetes
   (44 KSIs +     (44 KSIs +     (44 KSIs +      (CIS K8s +
   inventory)     inventory)     inventory)      EKS/GKE)
       │              │              │              │
       └──────────────┴──────────────┴──────────────┘
                            │
                            ▼ (read-only Proxy guardrails)
              ┌─────────────────────────────┐
              │   Per-KSI evidence files    │
              │      KSI-IAM-MFA.json       │
              │      KSI-CNA-MAT.json       │
              │           ... (60 KSIs)     │
              └─────────────────────────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │   Aggregation + signing     │
              │  family-rollup, NIST 800-53 │
              │  benchmark, control-bench,  │
              │  OSCAL SSP/AP/AR/POA&M,     │
              │  IIW, RoE, submission       │
              │  bundle, manifest, Ed25519, │
              │  RFC 3161 timestamp         │
              └──────────────┬──────────────┘
                             │
                             ▼
              ┌─────────────────────────────┐
              │   out/  (gitignored)        │
              │   + downstream pushes       │
              │   (Paramify / tracker /     │
              │   Slack / PagerDuty / Jira  │
              │   / SIEM / webhook / cosign)│
              └─────────────────────────────┘
```

For the high-level mission statement, see the root `README.md`. For the
read-only safety model, see the "Read-only commitments" section of
`cloud-evidence/README.md` and `core/readonly-guardrail.ts`.

---

## 2. Configuration files

FedPy uses three configuration files. Two exist today; one is forward-spec.

### 2.1 `cloud-evidence/config.yaml` (technical / SDK-side)

**Status:** Exists today; read by `core/orchestrator.ts`.

Authoritative source for: the FRMR catalog version, the impact level,
the AWS / GCP / Azure account scope, the prod-tag filter, and the output
directory.

| Section | Field | Default | Purpose |
|---|---|---|---|
| (top) | `frmr_version` | `"0.9.43-beta"` | Pinned FRMR catalog version. Bump only when refreshing `scripts/extract-frmr-requirements.mjs` output. |
| (top) | `impact_level` | `moderate` | Default FedRAMP impact tier (`low`, `moderate`, `high`). Override per-run with `--impact-level` or `CLOUD_EVIDENCE_IMPACT_LEVEL`. High is **derived from NIST 800-53 Rev 5** — no 20x High is published as of 2026-06. |
| `aws` | `enabled` | `true` | Toggle the AWS provider on / off. |
| `aws` | `regions` | `[us-east-1]` | List of AWS regions to inspect. Expand as your footprint grows. |
| `aws` | `prod_tag.key` / `prod_tag.values` | `env` / `[prod, production]` | Tag filter that limits findings to production resources. |
| `gcp` | `enabled` | `true` | Toggle GCP. |
| `gcp` | `organization_id` | `null` | Set to `organizations/123…` if you have org-level read; otherwise leave null and use the projects list. |
| `gcp` | `projects` | `[…]` | List of GCP project IDs to inspect. |
| `gcp` | `prod_label.key` / `prod_label.values` | `env` / `[prod, production]` | GCP label filter (mirror of `aws.prod_tag`). |
| `azure` | `enabled` | `false` | Toggle Azure (default off because most CSPs are AWS+GCP). |
| `azure` | `subscriptions` | `[]` | Subscription IDs to inspect. Empty = none. |
| `azure` | `tenant_id` | `null` | Pin if `DefaultAzureCredential` can't auto-discover. |
| `azure` | `prod_tag` | same shape as `aws.prod_tag` | Production filter. |
| (top) | `output_dir` | `./out` | Where evidence files land. Relative to `config.yaml`. |

The file ships with verbose inline comments. Read it directly:
[`cloud-evidence/config.yaml`](../config.yaml).

### 2.2 `cloud-evidence/thresholds.yaml` (finding rollup gates)

**Status:** Exists today; read by `core/findings.ts`.

Per-severity rollup behavior for KSI evidence. Critical and high
findings have **exact bounds** (count must be ≤ `max_count`); medium
findings have a **bounded ceiling + trend gate**; low findings are
**trending-only**.

| Severity | Key fields | Default |
|---|---|---|
| `critical` | `max_count` | `0` (any critical fails the KSI) |
| `high` | `max_count` | `0` (any high fails the KSI) |
| `medium` | `max_count`, `trend` | `25`, `flat_or_down` |
| `low` | `trend` | `flat_or_down` |

Per-KSI overrides live under `overrides:`. Example:

```yaml
overrides:
  KSI-IAM-AAM:
    medium:
      max_count: 50   # legacy unused-access findings tolerated
```

### 2.3 `cloud-evidence/org-profile.yaml` (forward-spec — conditional loops)

**Status:** **FORWARD-SPEC.** The template lives at
[`cloud-evidence/org-profile.yaml.example`](../org-profile.yaml.example).
The orchestrator does NOT read this file yet — the conditional loops
(LOOP-M, LOOP-O, LOOP-S, LOOP-X, G.G2-CIRCIA, M.M4-CIRCIA, G.G2-SEC-8K)
that depend on it are SPECIFIED but not yet implemented. When those
loops ship, they read this file at startup to decide whether to fire
their collection passes.

Why pre-fill it now? So that the day a conditional loop ships, your
configuration is already correct. The fields below have been
documented as the contract the loop SPECs commit to.

Sections of `org-profile.yaml`:

| Section | Drives | Trigger fields |
|---|---|---|
| `organization` | OSCAL SSP / AP / AR identification embedded into every signed artifact | `legal_name`, `csp_name`, `d_uns_number`, `cage_code`, `primary_poc` |
| `customer_posture.federal_civilian_agencies` | LOOP-X Zero Trust agency-tailoring posture | list of agency short codes |
| `customer_posture.serves_dod_cdi` | LOOP-S DFARS 252.204-7012 Cloud Equivalency | bool + `dod_prime_relationships` list |
| `service_architecture.uses_ai_ml` | LOOP-O AI/ML Governance (NIST AI RMF + OMB M-24-10) | bool + `ai_ml_components` list with model cards |
| `corporate_status.publicly_traded` / `wholly_owned_subsidiary_of_public_co` / `pre_ipo_with_cyber_disclosure_obligations` | G.G2-SEC-8K (SEC Form 8-K Item 1.05 4-business-day clock) | bool + `edgar` filer credentials + `designated_signing_officer` |
| `critical_infrastructure.is_circia_covered_entity` | G.G2-CIRCIA + M.M4-CIRCIA (CIRCIA Final Rule 72-hour clock) | bool + `cisa_sectors` |
| `data_posture.handles_federal_pii` | LOOP-M Privacy Package (SORN + PIA always-on) | bool |
| `software_supply_chain.delivers_software_to_federal_agencies` | LOOP-T NIST SSDF + CISA Common Form (OMB M-22-18) | bool + `attestation_signing_officer` |
| `cryptography.pqc_migration_plan_required` | LOOP-R PQC Migration (NSM-10 + OMB M-23-02) | bool + `pqc_target_completion_year` |
| `federal_contracting.section_889_screening_required` | LOOP-W Section 889 Prohibited Vendors (FAR 52.204-25) | bool + `far_52_204_26_signing_officer` + `section_889_reporting_endpoint` |

See [`cloud-evidence/org-profile.yaml.example`](../org-profile.yaml.example)
for the full template with field-by-field comments.

### 2.4 `cloud-evidence/risk-config.yaml` (LOOP-B.B1 risk-score tuning)

**Status:** **OPTIONAL, IMPLEMENTED.** Template at
[`cloud-evidence/risk-config.example.yaml`](../risk-config.example.yaml).
Read by `--risk-score` (LOOP-B.B1). Copy the example to `risk-config.yaml`
(kept out-of-tree) and customise, or pass `--risk-config <path>` /
`CLOUD_EVIDENCE_RISK_CONFIG`. Omit it entirely to accept built-in defaults.

| Section | Purpose | Default |
|---|---|---|
| `weights` | Composite formula weights (`cvss`, `epss`, `criticality`, `exposure`) — must sum to 1.0 (±0.01) | `0.4 / 0.3 / 0.2 / 0.1` |
| `epss.enabled` / `epss.ttl_hours` | Toggle the live FIRST EPSS feed; on-disk cache TTL | `true` / `24` |
| `cvss_vectors` | Operator CVE→CVSS vector overrides (rank below collector-cited, above severity fallback) | `{}` |
| `bands` | Composite-score → qualitative band thresholds (strictly descending) | `9.0 / 7.0 / 4.0 / 0.1` |

---

## 3. CLI flags reference (complete)

All flags are read by `core/orchestrator.ts::parseArgs`. Every flag has
an equivalent environment variable (see §4); the CLI flag wins when both
are set.

### 3.1 Run-shape flags

| Flag | Argument | Purpose |
|---|---|---|
| `--providers` | csv: `aws`, `gcp`, `azure`, `k8s` | Limit which providers run. Default: all enabled in `config.yaml`. |
| `--ksis` | csv: `KSI-IAM-MFA,KSI-IAM-AAM,…` | Limit to a subset of KSIs (skip the rest). |
| `--impact-level` | `low` / `moderate` / `high` | Override `config.yaml` `impact_level`. |
| `--framework` | `20x` / `rev5` | NIST 800-53 control-benchmark framing. `20x` scores only controls the in-scope KSIs reference; `rev5` scores the full SP 800-53B baseline for the level. |
| `--out` | path | Override `config.yaml` `output_dir`. |
| `--config` | path | Override the default `./config.yaml` location. |
| `--concurrency` | integer | Parallel collector threads. Default `4`. |
| `--dry-run` | (flag) | Plan only — no SDK calls. Useful for checking the in-scope KSI set. |

### 3.2 Report-generation flags

| Flag | Output | Purpose |
|---|---|---|
| `--html-report` | `out/report.html` | Human-readable HTML rendering. |
| `--csv-export` | `out/findings.csv` | Spreadsheet-friendly findings export. |
| `--diff-report` | `out/diff-report.json` | Diff vs the previous baseline run. |
| `--all-reports` | (above three) | Convenience flag — all three. |
| `--conmon-monthly` | `out/conmon-monthly-<YYYY-MM>.{json,md,pdf}` | LOOP-E.E1. Emit the monthly ConMon analysis report — KSI posture, vulnerability-scan coverage (with internet-reachable 100%-scanned compliance), POA&M activity (opened/closed/status-changes from `diff-report.json`), past-deadline items, KEV exposure, deviation-request + SCN-event rollups, and annual-cycle progress — aggregated from the run's own artifacts (`poam.json`, `KSI-*.json`, `inventory.json`, `diff-report.json`, `scn-classification.json`) + CISA KEV + the pinned ConMon Playbook. JSON is detached-Ed25519-signed; MD + PDF are renders. Runs AFTER POA&M/VDR/inventory but BEFORE signing (the report is covered by the run manifest). **LOOP-E.E2:** when combined with `--oscal-poam`, the POA&M pass routes through the monthly workflow — it threads the prior month's `metadata.revisions[]` forward, re-emits the POA&M, writes a month-over-month delta (`out/poam-delta-<YYYY-MM>.md`), archives the document to `out/archive/poam-<YYYY-MM>.json`, and appends `out/poam-ledger.jsonl`. |
| `--month <YYYY-MM>` | (input) | Report month for `--conmon-monthly` (default: current UTC month). Rejected when not strict `YYYY-MM`. |
| `--fedramp-package-id <id>` | (input) | FedRAMP-assigned package id for the report header (emits `REQUIRES-OPERATOR-INPUT` when absent). |
| `--csp-name <name>` | (input) | CSP legal corporate name for the report header. |
| `--conmon-strategy-href <href>` | (input) | Href of the ConMon Strategy doc (C.C6) cited in the report header. |
| `--sampling-pct <0-100>` | (input) | Internal-only scan sampling percentage (default `100` — the FedRAMP MUST; LOOP-F.F3 will auto-derive per-class). |
| `--ssp-last-reviewed <ISO>` | (input) | Date the SSP was last reviewed (annual-cycle section; from E.E4 when it ships). |
| `--authorization-date <YYYY-MM-DD>` | (input) | Authorization date anchoring the report's annual-cycle math (months-elapsed + next-assessment-due). |

### 3.3 OSCAL + submission-package flags

| Flag | Output | Purpose |
|---|---|---|
| `--oscal` | `out/assessment-results.json` | OSCAL 1.1.2 Assessment Results. |
| `--oscal-ssp` | `out/ssp.json` | Draft OSCAL 1.1.2 System Security Plan. |
| `--oscal-poam` | `out/poam.json` | OSCAL 1.1.2 Plan of Action and Milestones. |
| `--pull-risk-acceptances <tracker-url>` | `out/.risk-acceptances.json` (+ detached sig) | LOOP-B.B3. Pull the tracker's approved risk acceptances, verify each record's Ed25519 signature against the tracker's published public key, and write the signed snapshot. Approved, unexpired acceptances matching a finding `(ksi_id, rule, provider)` flip its POA&M risk to `deviation-approved`, override the deadline to the acceptance `expiration_date`, and attach `acceptance-*` + `compensating-control-uuid` props. Runs BEFORE `--oscal-poam`. Requires `--tracker-api-token`. Omit for air-gapped runs (the POA&M emitter falls back to any cached `out/.risk-acceptances.json`; absent that, every risk stays `open`). |
| `--tracker-api-token <token>` | (auth input) | LOOP-B.B3. Bearer token for the tracker risk-acceptance API (pairs with `--pull-risk-acceptances`; env `CLOUD_EVIDENCE_TRACKER_TOKEN`). Also used by `--pull-compensating-controls`. |
| `--pull-compensating-controls <tracker-url>` | `out/.compensating-controls.json` (+ detached sig) | LOOP-B.B4. Pull the tracker's active compensating controls, verify each record's Ed25519 signature against the tracker's published public key, and write the signed snapshot. For every finding with an approved, unexpired risk acceptance (B.B3), each cited compensating-control UUID that resolves to an active, unexpired registry record fills the POA&M `risk.remediations[]` with a `lifecycle=completed` entry (title/description + `compensating-control-uuid` + one `nist-control` prop per id + evidence link); an unresolvable UUID surfaces a `REQUIRES-OPERATOR-INPUT: unknown uuid` marker, never silently dropped. Runs BEFORE `--oscal-poam`. Requires `--tracker-api-token`. Defaults to the same tracker URL as `--pull-risk-acceptances`. Omit for air-gapped runs (the POA&M emitter falls back to any cached `out/.compensating-controls.json`). |
| `--risk-register` | `out/risk-register.json` + `out/risk-register.xlsx` | LOOP-B.B5. Aggregate the Central Risk Register (NIST SP 800-53 Rev 5 RA-3): JOIN the just-emitted OSCAL POA&M risks (B.B1+B.B2), the signed risk-acceptance snapshot (B.B3), the compensating-control snapshot (B.B4), and the operator-entered organisational-risk snapshot into a signed `risk-register.json` + a single-sheet `risk-register.xlsx` (20 cols, frozen header, conditional formatting on high/very-high inherent + very-high residual). Likelihood/impact use the NIST SP 800-30 Rev 1 qualitative scale; inherent = Table I-2 matrix; residual drops a band per active compensating control. Runs AFTER `--oscal-poam` (which it reads) and BEFORE signing. |
| `--pull-organisational-risks <tracker-url>` | `out/.organisational-risks.json` (+ detached sig) | LOOP-B.B5. Pull the tracker's operator-entered organisational risks and write the signed snapshot the `--risk-register` aggregator reads for its organisational entries. Requires `--tracker-api-token`. Defaults to the same tracker URL as `--pull-risk-acceptances`. Omit for air-gapped runs (the register omits organisational entries; logged, never fabricated). |
| `--risk-score` | `out/risk-scores.json` (+ `.epss-cache.json`) | LOOP-B.B1. Compute a per-finding composite risk score (CVSS 3.1/4.0 + FIRST EPSS + inventory-derived criticality + exposure), rewrite each `KSI-*.json` envelope in place with a `risk_score` block, and surface the score as OSCAL props on every POA&M risk/poam-item. Runs BEFORE `--oscal-poam` and before signing. |
| `--risk-config <path>` | (config input) | Path to `risk-config.yaml` (weights, EPSS settings, CVE→CVSS overrides, band thresholds). Defaults: auto-discover `./risk-config.yaml`, else built-in defaults. See `risk-config.example.yaml`. |
| `--subprocessors-config <path>` | `out/subprocessor-inventory.json` + `out/subprocessor-inventory.xlsx` | LOOP-J.J2. Emit the signed SA-9 Subprocessor Inventory from an operator YAML/JSON config (and/or the `config.yaml` `subprocessors` Google-Sheet block; both merge, config wins on a name conflict). Adds SA-9 fields (risk_tier, monitoring_methods, contracted_controls, incident_notification_sla_hours, data_residency, subprocessor_subprocessors, oversight_party_uuid). Runs BEFORE `--oscal-ssp` (which reads it for `leveraged-authorizations[]`) and before signing. See `examples/subprocessors.yaml`. |
| `--supply-chain-risk` | `out/supply-chain-risk-register.json` + `out/supply-chain-risk-register.xlsx` | LOOP-J.J3. Emit the signed SR-3 / NIST SP 800-161r1 supply-chain risk register (per-system C-SCRM Plan) joining SBOM-derived CVEs (`--sbom-dir`), CISA KEV exposure, J.J2 subprocessor risk tiers, and operator-asserted risks (`--risks-config`). Open critical/high entries flow to the POA&M (`props.risk-source=supply-chain`, deadline anchored at first_seen) and an SSP back-matter resource. Runs AFTER the SBOM + subprocessor passes and BEFORE `--oscal-ssp`/`--oscal-poam` + signing. Requires ≥1 source (`--sbom-dir`, `--subprocessors-config`, `--risks-config`, or a KEV catalog). |
| `--risks-config <path>` | (config input) | LOOP-J.J3. Operator-asserted supply-chain risks (vendor advisories) + mitigation overrides (`status` + `mitigation_summary` by entry id). Severity is not operator-overridable. See `examples/risks-config.yaml`. |
| `--strict-risk` | (gate) + `out/deadline-audit.json` | LOOP-B.B2. Fail the run (exit 5) if any POA&M finding's remediation deadline fell through to `severity-fallback` (a sign the FedRAMP CMP table was not loaded). The deadline engine cascades operator-override → CISA KEV `dueDate` → PAIN/IRV/LEV → FedRAMP CMP table → fallback; each risk/poam-item carries a `deadline-source` prop and `out/deadline-audit.json` logs the source per finding. |
| `--risk-no-epss` | (flag) | Disable the live FIRST EPSS feed for this run (offline / air-gapped). The EPSS term is dropped and every finding's `epss_source` prop reads `REQUIRES-OPERATOR-INPUT`. |
| `--oscal-ap` | `out/ap.json` | OSCAL 1.1.2 Assessment Plan. |
| `--ssp-docx` | `out/ssp.docx` | FedRAMP-style Word render of the SSP (implies `--oscal-ssp`). Dependency-free OOXML. |
| `--strict-chain` | (flag) | Enforce OSCAL chain validity: AR must import-AP; AP must import-SSP. Fails the run on chain breakage. |
| `--submission-bundle` | `out/submission-bundle.tar.gz` | Bundle all FedRAMP submission artifacts into a single signed tarball. |
| `--strict-bundle` | (flag) | Refuse to bundle if any expected artifact is missing. |
| `--roe` | `out/roe.docx` + `out/roe.json` | Rules of Engagement template. |
| `--cmp` | `out/cmp.docx` | LOOP-C.C1. Configuration Management Plan (CM-9) — an 11-section Word doc. §4 Configuration Items auto-derived from `out/inventory.json` (CM-8, grouped by provider+asset-type); §7 Configuration Monitoring auto-derived from `core/ksi-map.ts`. Process narratives (§3 CCB roster, §6 change control, §8 change windows, §9 rollback, §10 tooling) fall back to `REQUIRES-OPERATOR-INPUT` (inferred cloud-native tooling → `REQUIRES-OPERATOR-INPUT-VERIFY`). Deterministic output; integrity anchored by the signed submission-bundle INDEX.json. Runs before signing. |
| `--cmp-approval-narrative` | string | §6 change-control workflow narrative (CM-3/CM-4). Or `config.yaml: cmp.approval_narrative`. |
| `--cmp-rollback-authority` | string | §9 role authorized to order a rollback + trigger criteria. Or `config.yaml: cmp.rollback_authority`. |
| `--cmp-change-windows` | string | §8 approved maintenance / change windows. Or `config.yaml: cmp.change_windows`. |
| `--cmp-baseline-config-href` | path / URL | §5 link to the CM-2 Baseline Configuration doc (C.C9). Defaults to `./baseline-config.docx` when C.C9 emits in the same run. Or `config.yaml: cmp.baseline_config_href`. |
| `--iscp` | `out/iscp.docx` | LOOP-C.C2. Information System Contingency Plan (CP-2/CP-9/CP-10) — 6 sections + 6 appendices per the FedRAMP SSP Appendix G ISCP Template + NIST SP 800-34 Rev. 1. §4.2 Recovery-evidence table auto-filled from the real signed RPL-family KSI files (`KSI-RPL-ABO/TRC/RRO/ARP.json`); §2.1 components from `out/inventory.json`; Appendix B vendor contacts from `out/subprocessor-inventory.json`. Recovery narratives (RTO/RPO, alternate site, activation, rosters) fall back to `REQUIRES-OPERATOR-INPUT`. Deterministic; integrity anchored by the signed submission-bundle INDEX.json. Structured input via `config.yaml: iscp.*`. Runs after `--cmp`, before signing. |
| `--iscp-test-aar` | `out/iscp-test-aar.docx` | LOOP-C.C2. Contingency Plan Test After-Action Report (CP-4) — 6 sections per Appendix G Appendix F. Test scenarios + lessons learned are operator-supplied (`config.yaml: iscp.test.*`) — never fabricated (empty → a `REQUIRES-OPERATOR-INPUT` row). High/critical lessons route to a POA&M footer note; the §6 sign-off cells stay `REQUIRES-OPERATOR-INPUT` (never auto-signed). Anchors to `out/iscp.docx` (SHA-256) when `--iscp` ran the same run. |
| `--iscp-rto-hours` | number | §4.1 Recovery Time Objective in hours (overrides `config.yaml: iscp.rto.hours`). |
| `--iscp-rpo-hours` | number | §4.1 Recovery Point Objective in hours (overrides `config.yaml: iscp.rpo.hours`). |
| `--iscp-test-date` | ISO date | AAR test date (overrides `config.yaml: iscp.test.test_date`). |
| `--iscp-test-type` | `tabletop`\|`functional`\|`full-interruption` | AAR test type (overrides `config.yaml: iscp.test.test_type`). |
| `--irp` | `out/irp.docx` | LOOP-C.C3. Incident Response Plan (IR-8/IR-3/IR-4/IR-6) — 11 sections structured per NIST SP 800-61 Rev. 3 (CSF 2.0 phases). §4 Detect auto-filled from the real signed KSI-INR-RIR evidence (one row per collector finding + a coverage % from the pass ratio; <95% warns); §9 Reporting SLAs bake the FedRAMP Incident Communications Procedures baselines (1h PMO / 1h agency / 4h CISA); §3 classification levels + §7 external contacts (`info@fedramp.gov`, `report@cisa.gov` — no personal PII) + §8 escalation matrix default to verify-marked FedRAMP baselines. Team roster + communications plan fall back to `REQUIRES-OPERATOR-INPUT`. Deterministic; integrity anchored by the signed submission-bundle INDEX.json. Structured input via `config.yaml: irp.*`. Runs after `--iscp`, before signing. |
| `--irp-test-aar` | `out/irp-test-aar.docx` | LOOP-C.C3. Incident Response Test After-Action Report (IR-3) — 7 sections with the 5-phase timing matrix (detection → response → containment → eradication → recovery, minutes since onset). Test scenarios + lessons learned are operator-supplied (`config.yaml: irp.test.*`) — never fabricated (empty → a `REQUIRES-OPERATOR-INPUT` row). High/critical lessons route to a §6 POA&M footer note; the §7 sign-off cells stay `REQUIRES-OPERATOR-INPUT` (never auto-signed). Anchors to `out/irp.docx` (SHA-256) when `--irp` ran the same run. |
| `--irp-spec-version` | `800-61r2`\|`800-61r3` | IR spec version (default `800-61r3`, the current NIST standard; `800-61r2` renders the withdrawn four-phase §5 model). Overrides `config.yaml: irp.spec_version`. |
| `--pta-pia` | `out/pta.docx` (+ conditional `out/pia.docx`) | LOOP-C.C4. Privacy Threshold Analysis (PT-2/PT-3/PT-6, AR-2 screening) — 4 sections. §3 PII-inventory evidence auto-derived from the real `out/inventory.json` `data_classification` tags (`pii`/`phi`); Q1 `collectsPII` auto-derives from their presence; resource names are REDACTED (masked to `***` + a `ref:<sha8>` hash) so the doc never leaks PII. Emits the conditional 9-section Privacy Impact Assessment (`pia.docx`, AR-2) iff the PTA determination is positive OR `pia_force_mode: always-emit`; `never-emit` suppresses the PIA even on a positive PTA (with a §4 verify warning). Every PIA narrative (categories/sources/authority/consent/retention/disposal/safeguards) falls back to `REQUIRES-OPERATOR-INPUT` — the toolkit never invents PII categories; signature cells never auto-signed. Deterministic; integrity anchored by the signed submission-bundle INDEX.json. Structured input via `config.yaml: privacy.*` (`pia_force_mode` / `pta` / `pia`). Runs after `--irp`, before signing. (env: `CLOUD_EVIDENCE_PTA_PIA`) |
| `--fips199` | `out/fips199.docx` | LOOP-C.C5. FIPS 199 security-categorization worksheet (RA-2 / SC-7) — 6 sections. §1.2 quotes the FIPS 199 §3 LOW/MODERATE/HIGH impact definitions + the SC formula verbatim; §3 lists the operator-supplied information types (codes from the NIST SP 800-60 Vol. 2 Rev. 1 SaaS-relevant subset in `core/fips199-types.ts`; a code outside the subset is accepted with an `UNKNOWN-TYPE-CODE` annotation); §4 computes the system-level Security Category as the FIPS 199 §3 high-water-mark and §4.1 cross-checks it against `out/ssp.json` `security-impact-level` (CONSISTENT / MISMATCH + a per-objective table). Zero info types → a `REQUIRES-OPERATOR-INPUT` §3 row with the SP 800-60 V2 selection guidance; rationales + the §6 RA-2.c approver fall back to `REQUIRES-OPERATOR-INPUT` (never auto-signed). Deterministic; integrity anchored by the signed submission-bundle INDEX.json. Structured input via `config.yaml: fips199.*`. Runs after `--pta-pia`, before signing. (env: `CLOUD_EVIDENCE_FIPS199`) |
| `--fips199-info-type` | `"code:name:c:i:a:rationale"` | Repeatable. Add one FIPS 199 information type (the rationale may contain colons — everything after the 5th colon is the rationale). `c` is `low`/`moderate`/`high`/`n/a` (`n/a` only for confidentiality); `i` + `a` are `low`/`moderate`/`high`. Merged ahead of `config.yaml: fips199.information_types[]`. |
| `--ap-roe-href` | path / URL | URL or path embedded in the AP's RoE link (LOOP-A.A2). |
| `--ap-sampling-href` | path / URL | URL or path embedded in the AP's sampling-methodology link. |
| `--3pao-name` | string | The 3PAO organization name embedded in the AP. |
| `--oscal-org` | string | Operator org name embedded in OSCAL artifacts (overrides `CLOUD_EVIDENCE_ORG_NAME`). |
| `--system-name` | string | System name in OSCAL SSP (default `Cloud System`). |
| `--system-id` | string | System identifier in OSCAL SSP (default `cloud-evidence-system`). |
| `--crosswalk` | `out/crosswalk-report.json` | NIST → SOC 2 / ISO 27001 / HIPAA crosswalk. |

### 3.4 Inventory + scope flags

| Flag | Output | Purpose |
|---|---|---|
| `--inventory-workbook` | `out/inventory.json` + `inventory-workbook.{csv,xlsx}` + `inventory-oscal.json` + `inventory-cmdb.json` + `inventory-diff.json` + `inventory-cost.json` | Enumerate cloud assets (generic discovery backbone + per-service depth, all regions); emits FedRAMP Appendix M Integrated Inventory Workbook. |
| `--inventory-only` | (above) only | Fast inventory-focused run that skips KSI/process evidence. |
| `--reference-arch` | `out/AUDIT-REFARCH-AWS.json` + `AUDIT-REFARCH-GCP.json` | FedRAMP reference-architecture hardening audit (Coalfire-RAMPpak-derived; clean-room). |
| `--prohibited-vendors-catalog` | `out/prohibited-vendors-catalog.json` (+ `.sig`) + `data/prohibited-vendors-snapshot-YYYYMMDD/MANIFEST.json` | LOOP-W.W1. Emit the signed prohibited-vendor catalog merged from OFAC SDN + BIS Entity List + SAM Exclusions + FAR 52.204-25 + NDAA §889 + NDAA §1634 + FASCSA. Offline-first: ingests a snapshot staged by `scripts/extract-prohibited-vendors.mjs` plus the committed statutory constants under `data/`. Runs before signing (catalog is covered by the run manifest) and is the substrate W.W2/W.W3/W.W4 read. Optional `prohibited-vendors-config.yaml` (see `prohibited-vendors-config.example.yaml`). |
| `--prohibited-vendor-screen` | `out/prohibited-vendors-screen-result.json` (+ `.sig`) + `out/prohibited-vendors-screen-result.xlsx` + `out/prohibited-vendor-screens.jsonl` | LOOP-W.W2. Screen four surfaces — the subprocessor sheet, the SBOM (transitively, to `--sbom-max-depth`), OCI image publishers (cosign/Rekor attestations under `out/oci-attestations/`), and inventory `provider_tag`/`sku` — against the W.W1 catalog. Emits a signed match envelope (confidence band + provenance chain + FAR 52.204-25(d) data elements per match), an operator `.xlsx`, and an append-only ledger. Requires `--prohibited-vendors-catalog` to have produced the catalog first. Runs before signing. Honours `prohibited-vendors-overrides.yaml` (see `prohibited-vendors-overrides.example.yaml`) for false-positive suppression + manual additions. NEVER auto-submits to a federal endpoint. |
| `--sbom-max-depth <int>` | (modifies `--prohibited-vendor-screen`) | LOOP-W.W2. Max transitive SBOM dependency depth walked by the screen. Default `8`. Truncation is recorded in the run log + coverage. |
| `--max-subsidiary-depth <int>` | (modifies `--prohibited-vendor-screen`) | LOOP-W.W2. Max operator-supplied subsidiary-chain depth walked by the screen. Default `3`. |
| `--prohibited-vendor-1bd-report` | `out/section889-1bd-reports/s889-*.json` (+ `.json.sig`) + `out/section889-1bd-reports/s889-*.docx` + `out/section889-1bd-reports.jsonl` | LOOP-W.W3. Ingest the W.W2 screen result, and for each reportable match (non-suppressed, high-confidence, Section 889 / NDAA §1634 / operator-addition source) emit a signed FAR 52.204-25(d) 1-business-day discovery report (canonical JSON + `.docx`) per affected contract. Computes the federal-business-day deadline per 5 U.S.C. §6103 (Mon–Fri 09:00–17:00 ET, 8 business hours/day, observed holidays + operator agency closures). Requires `--prohibited-vendor-screen` to have produced the screen first; reads `section889-contacts.yaml` (Contracting-Officer routing; see `section889-contacts.example.yaml`) and optional `section889-agency-closures.yaml` (see `section889-agency-closures.example.yaml`). Idempotent via the append-only ledger. Runs before signing. NEVER auto-submits to a federal endpoint — the operator transmits the artifact pair. |
| `--section889-annual-rep` | `out/section889-annual-rep.json` (+ `.json.sig`) + `out/section889-annual-rep.docx` + `out/section889-annual-reps.jsonl` + `out/marketplace-section889-badge.json` | LOOP-W.W4. Ingest the W.W2 screen result and emit the signed FAR 52.204-26 Section 889 Part B annual representation (canonical-JSON envelope + printable `.docx`). The two FAR 52.204-26(c) "does / does not" answers are computed from the non-suppressed matches: (c)(1) "provides" keys off the subprocessor-sheet + inventory provider-tag surfaces; (c)(2) "uses" off every non-suppressed match. Links W.W3 1-business-day incidents (from `section889-1bd-reports.jsonl`), records a 365-day `valid_until` (FAR 52.204-8(d)), detects representation flips vs the prior ledger row, and writes the LOOP-Q.Q1 Marketplace badge feed (enabled iff both answers "does not" AND within validity). Reads `config.yaml#section_889` (offeror + authorized_officer + annual_representation; see `section889-annual-rep.example.yaml`) + the operator methodology doc (`docs/section889/reasonable-inquiry-methodology.md`). Mandatory operator fields (UEI, officer block, methodology doc) are validated before any write — a missing field throws `requires_operator_input:<field>` and emits nothing. Requires `--prohibited-vendor-screen` first; runs after `--prohibited-vendor-1bd-report` and before signing. NEVER files the representation in SAM.gov — the operator submits the `.docx`. See `docs/section889/annual-rep-runbook.md`. |
| `--ssdf-attestation` | `out/ssdf-satisfaction-matrix.json` (+ `.json.sig`) + `out/ssdf-satisfaction-matrix.xlsx` + `out/ssdf-satisfaction-matrix.jsonl` (per-product files are slug-suffixed, e.g. `ssdf-satisfaction-matrix.<product>.json`) | LOOP-T.T2 (OMB M-22-18 / M-23-16 procurement gate). Join the T.T1 SSDF practices catalogue (`data/ssdf-800-218-v1.1.json`) to the run's REAL evidence corpus — the signed KSI evidence envelopes (`out/KSI-*.json`, joined per-practice via the catalogue's `fedramp_ksi_forward_map`), `risk-scores.json` (B.B1 composite → per-practice open-risk), `subprocessor-inventory.json` (J.J2), `supply-chain-risk-register.json` (J.J3), `sbom-report.json` (E.E2), and `poam.json` (A.A1, control-based secondary join) — and emit a signed per-practice × per-task satisfaction matrix (19 practices / 42 tasks) with typed evidence pointers + per-task status ∈ {satisfied, partially-satisfied, not-satisfied, not-assessed, requires-operator-input}. A task with no joined evidence is `requires-operator-input` (never a silent pass — enforced by `npm run check:ssdf-no-silent-pass`, wired into `check:reo`). Reads `config.yaml#ssdf` (optional: `regime`, `products[]`, `ksi_to_product_map`); with no products configured a single default product is derived from `--csp-name`. Runs after every per-loop emitter and before signing (matrix is covered by the run manifest + RFC 3161 TSR). The matrix is the data backbone of the CISA Common Form (T.T3); it carries the machine signature only — the producer-officer attestation is signed on the T.T3 Common Form, never here (REO Rule 1.10). **Also runs the LOOP-T.T4 re-attestation detector** (after the matrix emit, before signing): it diffs the matrix against its most recent prior snapshot and emits the signed `out/ssdf-material-change-events.json` (per-product × per-agency cadence rows + typed `MaterialChangeEvent[]`), archiving the matrix to `out/ssdf-attestation-snapshots/<product>/<sha256>.json` and appending `out/ssdf-attestation-ledger.jsonl`. The T.T4 cadence + per-agency tracking read the optional `config.yaml#ssdf.products[]` fields `regime` (one of `m-22-18-mandatory` / `m-23-16-extended` / `m-26-05-tailored` / `post-m-26-05-future`), `continuous_delivery`, `major_version_pattern`, `cadence_override_days`, `poam_extension_allowed`, `federal_agencies[]`; an absent `regime` yields a `requires-operator-input` diagnostic (no fabricated default, REO Rule 4). `next_due_at` is the producer's INTERNAL review date, not an expiry (the M-23-16 binding clause keeps an attestation in force until the producer notifies the agency). **Also runs the LOOP-T.T5 SP 800-218A SSDF-AI extension** (after the T.T2 matrix, before T.T3) when `config.yaml#ssdf.ai_augmentation_enabled: true` AND at least one `out/model-cards/*.json` (LOOP-O.O5) declares an AI use case or dual-use foundation model: it augments the matrix with the 800-218A R/C/N items for those products and emits the signed `out/ssdf-ai-augmentation.json` + `.xlsx` + `out/ssdf-satisfaction-matrix.augmented.json`. Reads optional `config.yaml#ssdf` keys `ai_augmentation_enabled` (default false), `primary_catalogue` (`IPD` default | `final`), `ai_products_in_scope[]` (empty ⇒ auto-detect). With LOOP-O.O5 unshipped there are no model cards, so the step no-ops (`coverage:skipped`); it NEVER fabricates AI evidence — an augmentation with no AI-specific evidence inherits its parent task, and a new 800-218A AI task with no base parent is `requires-operator-input` (REO Rule 4). |
| `--ssdf-common-form` | `out/cisa-common-form-1670-0052.pdf` + `out/cisa-common-form-1670-0052.json` (+ `.json.sig`) | LOOP-T.T3 (OMB M-22-18 / M-23-16; optional under M-26-05's risk-based regime). Project the T.T2 satisfaction matrix + `config.yaml#ssdf.producer` into the CISA Secure Software Development Attestation Common Form (OMB Control Number `1670-0052`, expiration `03/31/2027`) and emit the **unsigned** canonical PDF + a signed canonical-JSON shadow. Each of the four Section IV attestation selections (∈ {comply, comply-with-conditions, cannot-comply, not-yet-determined}) is computed deterministically from the matrix tasks mapped to that §IV clause via `common_form_section_ref` — a `requires-operator-input`/`not-assessed` task forces `not-yet-determined` (no silent `comply`); a `cannot-comply` clause must cite ≥1 POA&M item (`out/poam.json` or `config.yaml#ssdf.producer.poam_reference_overrides`) or the emit throws `MissingPoamReferenceError`. Mandatory producer fields (`legal_name`, `address`, `point_of_contact`, `signatory`, `scope_of_attestation.products[]`) are validated up front — every missing field is collected and thrown as `MissingOperatorInputError` naming the exact YAML path. Implies `--ssdf-attestation`. Runs after the T.T2 matrix + A.A1 POA&M emit and before signing (PDF + JSON covered by the run manifest + RFC 3161 TSR). The signature + date lines are left blank — the corporate officer signs the PDF out of band (T.T4); the system NEVER auto-signs the human attestation (REO Rule 1.10) and NEVER files it with CISA / an agency (REO Rule 4). |

### 3.5 Multi-account / fan-out flags (AWS Organizations)

| Flag | Argument | Purpose |
|---|---|---|
| `--aws-org-fanout` | (flag) | Enable AWS Organizations fan-out (LOOP-C.2). Requires `--aws-cross-account-role`. |
| `--aws-include` | csv: account IDs | Whitelist specific accounts in the org. |
| `--aws-exclude` | csv: account IDs | Blacklist specific accounts in the org. |
| `--aws-cross-account-role` | role name | The cross-account role to assume in each account (e.g. `OrganizationAccountAccessRole`). |

### 3.6 Significant-change-notification (SCN) flags

| Flag | Output | Purpose |
|---|---|---|
| `--scn` | `out/scn-classification.json` + `out/scn-notice-draft.md` | Classify the run's diff as a FedRAMP Significant Change Notification report. Implies `--diff-report`. |
| `--scn-proposed` | path | JSON file of operator-proposed (forward-looking) changes to include in the SCN classification. |

### 3.7 Signing + integrity flags

| Flag | Purpose |
|---|---|
| `--no-sign` | Skip Ed25519 signing. Diagnostic only. |
| `--expected-public-key` | Path to the expected public key. Verifies the signing key matches the trusted manifest. |
| `--strict-schema` | Fail the run if any emitted evidence file fails schema validation. Recommended for CI. |

### 3.8 Integration flags

| Flag | Argument | Purpose |
|---|---|---|
| `--push-paramify` | (flag) | Push findings to Paramify GRC. Requires `PARAMIFY_API_KEY` + `PARAMIFY_BASE_URL` env vars. |
| `--push-tracker` | (flag) | Push run summary to the local tracker. Requires `TRACKER_API_TOKEN` + `TRACKER_BASE_URL` env vars. |
| `--notify-on-drift` | (flag) | Send Slack / PagerDuty alerts on threshold-crossing drift. Requires `SLACK_WEBHOOK_URL` and/or `PAGERDUTY_INTEGRATION_KEY`. |
| `--ticket-push` | `jira` / `servicenow` / `github` / `linear` | Open a ticket per failing finding in the selected system. Requires the system-specific env vars (see §4.5). |
| `--siem-url` | URL | OCSF-formatted SIEM ingest endpoint (HTTPS POST). |
| `--webhook-url` | URL | Generic HMAC-signed webhook. Requires `WEBHOOK_HMAC_SECRET`. |
| `--llm-generate-prs` | (flag) | Use Anthropic Claude to draft remediation PRs for failing findings. Requires `ANTHROPIC_API_KEY`. |

### 3.9 Extension flags

| Flag | Purpose |
|---|---|
| `--powerpipe` | Render evidence via the Powerpipe mod. |
| `--sbom-dir` | Path to a directory of Syft-generated SBOM files; ingested for SR-family findings. |
| `--anomaly` | Enable anomaly-detection pass against the rolling baseline. |
| `--plugins-dir` | Path to a directory of custom KSI collector plugins (loaded at startup). |

### 3.10 Help

| Flag | Output |
|---|---|
| `--help`, `-h` | Print the flag reference. |

---

## 4. Environment variables reference (complete)

Environment variables let you set defaults that the CLI flag can
override. The orchestrator reads all of these at `parseArgs` time;
several other modules read additional env vars at their own initialization
(noted below).

### 4.1 Core run shape

| Env var | Default | Purpose |
|---|---|---|
| `CLOUD_EVIDENCE_IMPACT_LEVEL` | (from config.yaml) | `low`/`moderate`/`high`. Same effect as `--impact-level`. |
| `CLOUD_EVIDENCE_FRAMEWORK` | `20x` | `20x`/`rev5`. Same effect as `--framework`. |
| `CLOUD_EVIDENCE_CONCURRENCY` | `4` | Parallel collector threads. Same effect as `--concurrency`. |
| `CLOUD_EVIDENCE_NO_SIGN` | `0` | Set `1` to disable Ed25519 signing. Diagnostic only. |
| `EVIDENCE_EXPECTED_PUBLIC_KEY_PATH` | (none) | Path to the expected signing public key. |

### 4.2 OSCAL + submission package

| Env var | Default | Purpose |
|---|---|---|
| `CLOUD_EVIDENCE_OSCAL` | `0` | Emit OSCAL Assessment Results. |
| `CLOUD_EVIDENCE_OSCAL_SSP` | `0` | Emit draft OSCAL SSP. |
| `CLOUD_EVIDENCE_OSCAL_POAM` | `0` | Emit OSCAL POA&M. |
| `CLOUD_EVIDENCE_TRACKER_URL` | (none) | LOOP-B.B3. Tracker base URL to pull signed risk acceptances from before the POA&M emit (equivalent to `--pull-risk-acceptances`). |
| `CLOUD_EVIDENCE_TRACKER_TOKEN` | (none) | LOOP-B.B3. Bearer token for the tracker risk-acceptance API (equivalent to `--tracker-api-token`; also used by `--pull-compensating-controls`). |
| `CLOUD_EVIDENCE_COMPENSATING_CONTROLS_URL` | (none) | LOOP-B.B4. Tracker base URL to pull signed compensating controls from before the POA&M emit (equivalent to `--pull-compensating-controls`). When unset but `CLOUD_EVIDENCE_TRACKER_URL` is set, the compensating-control pull reuses that same tracker URL. |
| `CLOUD_EVIDENCE_RISK_REGISTER` | `0` | LOOP-B.B5. When `1`, aggregate the Central Risk Register (equivalent to `--risk-register`) after the POA&M emit. |
| `CLOUD_EVIDENCE_ORGANISATIONAL_RISKS_URL` | (none) | LOOP-B.B5. Tracker base URL to pull operator-entered organisational risks from before the register emit (equivalent to `--pull-organisational-risks`). When unset but `CLOUD_EVIDENCE_TRACKER_URL` is set, the organisational-risk pull reuses that same tracker URL. |
| `CLOUD_EVIDENCE_RISK_SCORE` | `0` | Compute per-finding composite risk scores (equivalent to `--risk-score`, LOOP-B.B1). |
| `CLOUD_EVIDENCE_STRICT_RISK` | `0` | Fail the run if any POA&M deadline falls through to severity-fallback (equivalent to `--strict-risk`, LOOP-B.B2). |
| `CLOUD_EVIDENCE_RISK_CONFIG` | (none) | Path to `risk-config.yaml` (equivalent to `--risk-config`). |
| `CLOUD_EVIDENCE_RISK_NO_EPSS` | `0` | Disable the live FIRST EPSS feed (equivalent to `--risk-no-epss`). |
| `CLOUD_EVIDENCE_OSCAL_AP` | `0` | Emit OSCAL Assessment Plan. |
| `CLOUD_EVIDENCE_STRICT_CHAIN` | `0` | Enforce OSCAL chain validity. |
| `CLOUD_EVIDENCE_SUBMISSION_BUNDLE` | `0` | Bundle the submission package. |
| `CLOUD_EVIDENCE_STRICT_BUNDLE` | `0` | Refuse to bundle on missing artifacts. |
| `CLOUD_EVIDENCE_ROE` | `0` | Emit Rules of Engagement template. |
| `CLOUD_EVIDENCE_CMP` | `0` | LOOP-C.C1. Emit the Configuration Management Plan (CM-9) as `out/cmp.docx`. |
| `CLOUD_EVIDENCE_CMP_APPROVAL_NARRATIVE` | (none) | §6 change-control workflow narrative (overrides `config.yaml: cmp.approval_narrative`). |
| `CLOUD_EVIDENCE_CMP_ROLLBACK_AUTHORITY` | (none) | §9 rollback authority + criteria (overrides `config.yaml: cmp.rollback_authority`). |
| `CLOUD_EVIDENCE_CMP_CHANGE_WINDOWS` | (none) | §8 approved change/maintenance windows (overrides `config.yaml: cmp.change_windows`). |
| `CLOUD_EVIDENCE_CMP_BASELINE_CONFIG_HREF` | (none) | §5 CM-2 Baseline Configuration doc link (overrides `config.yaml: cmp.baseline_config_href`). |
| `CLOUD_EVIDENCE_ISCP` | `0` | LOOP-C.C2. Emit the Information System Contingency Plan (CP-2/CP-9/CP-10) as `out/iscp.docx`. |
| `CLOUD_EVIDENCE_ISCP_TEST_AAR` | `0` | LOOP-C.C2. Emit the Contingency Plan Test After-Action Report (CP-4) as `out/iscp-test-aar.docx`. |
| `CLOUD_EVIDENCE_ISCP_RTO_HOURS` | (none) | §4.1 Recovery Time Objective hours (overrides `config.yaml: iscp.rto.hours`). |
| `CLOUD_EVIDENCE_ISCP_RPO_HOURS` | (none) | §4.1 Recovery Point Objective hours (overrides `config.yaml: iscp.rpo.hours`). |
| `CLOUD_EVIDENCE_ISCP_TEST_DATE` | (none) | AAR test date, ISO (overrides `config.yaml: iscp.test.test_date`). |
| `CLOUD_EVIDENCE_ISCP_TEST_TYPE` | (none) | AAR test type: tabletop\|functional\|full-interruption (overrides `config.yaml: iscp.test.test_type`). |
| `CLOUD_EVIDENCE_IRP` | `0` | LOOP-C.C3. Emit the Incident Response Plan (IR-8/IR-3/IR-4/IR-6) as `out/irp.docx`. |
| `CLOUD_EVIDENCE_IRP_TEST_AAR` | `0` | LOOP-C.C3. Emit the Incident Response Test After-Action Report (IR-3) as `out/irp-test-aar.docx`. |
| `CLOUD_EVIDENCE_IRP_SPEC_VERSION` | (none) | IR spec version: 800-61r2\|800-61r3 (default 800-61r3; overrides `config.yaml: irp.spec_version`). |
| `CLOUD_EVIDENCE_PTA_PIA` | `0` | LOOP-C.C4. Emit the Privacy Threshold Analysis (`out/pta.docx`, always) + the conditional Privacy Impact Assessment (`out/pia.docx`) — PT-2/PT-3/PT-6/AR-2. Same as `--pta-pia`. |
| `CLOUD_EVIDENCE_FIPS199` | `0` | LOOP-C.C5. Emit the FIPS 199 security-categorization worksheet (`out/fips199.docx`) — RA-2. Same as `--fips199`. (Information types are supplied via `config.yaml: fips199.information_types[]` or the repeatable `--fips199-info-type` flag.) |
| `CLOUD_EVIDENCE_AP_ROE_HREF` | (none) | URL embedded in AP RoE link. |
| `CLOUD_EVIDENCE_AP_SAMPLING_HREF` | (none) | URL embedded in AP sampling-methodology link. |
| `CLOUD_EVIDENCE_3PAO_NAME` | (none) | 3PAO org name embedded in AP. |
| `CLOUD_EVIDENCE_SSP_DOCX` | `0` | Render SSP as `.docx`. |
| `CLOUD_EVIDENCE_ORG_NAME` | (none) | Operator org embedded in OSCAL. |
| `CLOUD_EVIDENCE_SYSTEM_NAME` | `Cloud System` | System name embedded in OSCAL SSP. |
| `CLOUD_EVIDENCE_SYSTEM_ID` | `cloud-evidence-system` | System identifier embedded in OSCAL SSP. |
| `CLOUD_EVIDENCE_SYSTEM_DESCRIPTION` | (auto) | System description in OSCAL SSP. |
| `CLOUD_EVIDENCE_CROSSWALK` | `0` | Emit NIST→SOC2/ISO27001/HIPAA crosswalk. |
| `CLOUD_EVIDENCE_CONMON_MONTHLY` | `0` | Emit the LOOP-E.E1 monthly ConMon analysis report (equivalent to `--conmon-monthly`). |
| `CLOUD_EVIDENCE_CONMON_MONTH` | (current UTC month) | Report month `YYYY-MM` (equivalent to `--month`). |
| `CLOUD_EVIDENCE_FEDRAMP_PACKAGE_ID` | (none) | FedRAMP package id for the monthly report (equivalent to `--fedramp-package-id`). |
| `CLOUD_EVIDENCE_CSP_NAME` | (none) | CSP legal name for the monthly report (equivalent to `--csp-name`). |
| `CLOUD_EVIDENCE_CONMON_STRATEGY_HREF` | (none) | ConMon Strategy doc href cited in the report (equivalent to `--conmon-strategy-href`). |
| `CLOUD_EVIDENCE_SAMPLING_PCT` | `100` | Internal-only scan sampling percentage (equivalent to `--sampling-pct`). |
| `CLOUD_EVIDENCE_SSP_LAST_REVIEWED` | (none) | Date the SSP was last reviewed (equivalent to `--ssp-last-reviewed`). |
| `CLOUD_EVIDENCE_AUTHORIZATION_DATE` | (none) | Authorization date anchoring annual-cycle math (equivalent to `--authorization-date`). |

### 4.3 Inventory + scope

| Env var | Default | Purpose |
|---|---|---|
| `CLOUD_EVIDENCE_INVENTORY_WORKBOOK` | `0` | Emit Appendix M inventory workbook. |
| `CLOUD_EVIDENCE_REFERENCE_ARCH` | `0` | Run reference-architecture audit. |
| `CLOUD_EVIDENCE_APPROVED_AMI_PATTERN` | (none) | Regex of approved AMI IDs (`reference-arch` flags non-matches). |
| `CLOUD_EVIDENCE_GCP_API_ALLOWLIST` | (none) | Comma-separated allow-listed GCP service APIs. |
| `CLOUD_EVIDENCE_ATTESTATIONS` | (none) | Path to attestation register JSON for process requirements. |
| `CLOUD_EVIDENCE_KEV_PATH` | (none) | Path to cached CISA KEV JSON for offline checks. |
| `CLOUD_EVIDENCE_ADS_URLS` | (none) | Trust Center / CSO / OSCAL URLs the ADS probe checks. |
| `CLOUD_EVIDENCE_MAS_DOCUMENTED_PATH` | (none) | JSON array of documented in-scope resource identifiers. |
| `CLOUD_EVIDENCE_MAS_DISCOVERED_PATH` | (auto) | Discovered identifiers for MAS reconciliation. |
| `CLOUD_EVIDENCE_SCG_GUIDE_PATH` | (none) | Path to Secure Configuration Guide JSON. |
| `CLOUD_EVIDENCE_SCG_OBSERVED_PATH` | (none) | Observed config map for SCG comparator. |
| `CLOUD_EVIDENCE_PROHIBITED_VENDORS_CATALOG` | `0` | Emit the LOOP-W.W1 prohibited-vendor catalog (equivalent to `--prohibited-vendors-catalog`). |
| `CLOUD_EVIDENCE_PROHIBITED_VENDOR_SCREEN` | `0` | Run the LOOP-W.W2 prohibited-vendor screen (equivalent to `--prohibited-vendor-screen`). |
| `CLOUD_EVIDENCE_PROHIBITED_VENDOR_1BD_REPORT` | `0` | Emit the LOOP-W.W3 FAR 52.204-25(d) 1-business-day reports (equivalent to `--prohibited-vendor-1bd-report`). |
| `CLOUD_EVIDENCE_SECTION889_ANNUAL_REP` | `0` | Emit the LOOP-W.W4 FAR 52.204-26 Section 889 annual representation (equivalent to `--section889-annual-rep`). |
| `CLOUD_EVIDENCE_SSDF_ATTESTATION` | `0` | Emit the LOOP-T.T2 SSDF per-practice satisfaction matrix (equivalent to `--ssdf-attestation`). Accepts `1` or `true`. The OMB M-22-18 / M-23-16 procurement-gate signal; reads optional `config.yaml#ssdf` (`regime`, `products[]`, `ksi_to_product_map`). |
| `CLOUD_EVIDENCE_SSDF_COMMON_FORM` | `0` | Emit the LOOP-T.T3 CISA Common Form (OMB 1670-0052) PDF + signed JSON (equivalent to `--ssdf-common-form`). Accepts `1` or `true`. Implies `CLOUD_EVIDENCE_SSDF_ATTESTATION`; reads required `config.yaml#ssdf.producer`. |
| `CLOUD_EVIDENCE_SBOM_MAX_DEPTH` | `8` | Max transitive SBOM dependency depth walked by the LOOP-W.W2 screen (equivalent to `--sbom-max-depth`). |
| `CLOUD_EVIDENCE_MAX_SUBSIDIARY_DEPTH` | `3` | Max operator-supplied subsidiary-chain depth walked by the LOOP-W.W2 screen (equivalent to `--max-subsidiary-depth`). |
| `CLOUD_EVIDENCE_SUBPROCESSORS_CONFIG` | (none) | Path to an operator subprocessor config (YAML/JSON) for the LOOP-J.J2 SA-9 Subprocessor Inventory (equivalent to `--subprocessors-config`). Can also be set via the `config.yaml` `subprocessors.config_path` / `subprocessors.spreadsheet_id` block. |
| `CLOUD_EVIDENCE_SUPPLY_CHAIN_RISK` | `0` | Emit the LOOP-J.J3 supply-chain risk register (equivalent to `--supply-chain-risk`). |
| `CLOUD_EVIDENCE_RISKS_CONFIG` | (none) | Path to an operator `--risks-config` (YAML/JSON) for LOOP-J.J3 operator-asserted supply-chain risks + mitigation overrides. |
| `SAM_GOV_API_KEY` | (none) | SAM.gov Entity Management API key; required only on the network fetch path (`scripts/extract-prohibited-vendors.mjs`). Obtain at https://sam.gov/data-services. |
| `PROHIBITED_VENDORS_SIGNING_KEY_ID` | (none) | Optional expected Ed25519 key fingerprint for the prohibited-vendor catalog; validated against the actual signing key when set. |

### 4.4 Multi-account fan-out

| Env var | Default | Purpose |
|---|---|---|
| `CLOUD_EVIDENCE_AWS_ORG_FANOUT` | `0` | Enable AWS Organizations fan-out. |
| `CLOUD_EVIDENCE_AWS_INCLUDE` | (none) | csv whitelist of account IDs. |
| `CLOUD_EVIDENCE_AWS_EXCLUDE` | (none) | csv blacklist of account IDs. |
| `AWS_CROSS_ACCOUNT_ROLE` | (none) | The cross-account role to assume. |

### 4.5 Integrations

| Env var | Default | Purpose |
|---|---|---|
| `PARAMIFY_API_KEY` / `PARAMIFY_BASE_URL` | (none) | Paramify GRC push credentials. |
| `TRACKER_API_TOKEN` / `TRACKER_BASE_URL` | (none) | Tracker push credentials. |
| `SLACK_WEBHOOK_URL` | (none) | Slack drift alerts. |
| `PAGERDUTY_INTEGRATION_KEY` | (none) | PagerDuty drift alerts. |
| `CLOUD_EVIDENCE_TICKET_PROVIDER` | (none) | `jira` / `servicenow` / `github` / `linear`. |
| `JIRA_BASE_URL` / `JIRA_API_TOKEN` / `JIRA_PROJECT_KEY` | (none) | Jira ticket-push. |
| `SERVICENOW_BASE_URL` / `SERVICENOW_API_TOKEN` | (none) | ServiceNow ticket-push. |
| `GITHUB_TOKEN` / `GITHUB_REPO` | (none) | GitHub Issues ticket-push. |
| `LINEAR_API_KEY` / `LINEAR_TEAM_ID` | (none) | Linear ticket-push. |
| `CLOUD_EVIDENCE_SIEM_URL` | (none) | OCSF SIEM ingest endpoint. |
| `CLOUD_EVIDENCE_WEBHOOK_URL` | (none) | Generic HMAC-signed webhook endpoint. |
| `WEBHOOK_HMAC_SECRET` | (none) | HMAC signing secret for the webhook. |
| `CLOUD_EVIDENCE_LLM_PRS` | `0` | Set `1` to enable Anthropic Claude PR-draft generator. |
| `ANTHROPIC_API_KEY` | (none) | Claude API key for `--llm-generate-prs`. |
| `ANTHROPIC_API_URL` | `https://api.anthropic.com/v1/messages` | Proxy / VPC endpoint override. |
| `LLM_MODEL` | `claude-opus-4-5` | Model selection (use `claude-haiku-4-5` for cost-sensitive). |

### 4.6 Reliability / debugging

| Env var | Default | Purpose |
|---|---|---|
| `CLOUD_EVIDENCE_RETRY_ATTEMPTS` | `4` | SDK retry max attempts. |
| `CLOUD_EVIDENCE_RETRY_BASE_MS` | `200` | Initial backoff. |
| `CLOUD_EVIDENCE_RETRY_MAX_MS` | `5000` | Per-attempt backoff cap. |
| `CLOUD_EVIDENCE_DISABLE_RETRY` | `0` | Set `1` to disable retry. Diagnostic only. |
| `EVIDENCE_TSA_URL` | `http://timestamp.digicert.com` | RFC 3161 timestamp authority. |
| `EVIDENCE_TSA_CA_BUNDLE` | (none) | PEM bundle for offline TSA verification. |
| `CLOUD_EVIDENCE_DISABLE_GCP_GUARDRAIL` | `0` | Bypass GCP read-only Proxy. Diagnostic only — NEVER set in production. |
| `CLOUD_EVIDENCE_DISABLE_AZURE_GUARDRAIL` | `0` | Bypass Azure read-only Proxy. Diagnostic only. |
| `CLOUD_EVIDENCE_K8S_TIMEOUT_MS` | `10000` | Kubernetes API per-call timeout. |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | (none) | Service-principal credentials for Azure CI. |

### 4.7 Significant change notification

| Env var | Default | Purpose |
|---|---|---|
| `CLOUD_EVIDENCE_SCN` | `0` | Enable SCN classification. |
| `CLOUD_EVIDENCE_SCN_PROPOSED_PATH` | (none) | Path to proposed-changes JSON. |

### 4.8 Extension

| Env var | Default | Purpose |
|---|---|---|
| `CLOUD_EVIDENCE_POWERPIPE` | `0` | Render via Powerpipe mod. |
| `CLOUD_EVIDENCE_SBOM_DIR` | (none) | SBOM directory for SR ingest. |
| `CLOUD_EVIDENCE_ANOMALY` | `0` | Anomaly-detection pass. |
| `CLOUD_EVIDENCE_PLUGINS_DIR` | (none) | Custom KSI collector plugin directory. |

---

## 5. Loop landscape — what's where

### 5.1 Currently implemented (60 KSI collectors, ConMon pipeline, signing)

Run `npx tsx core/orchestrator.ts --dry-run` to print the exact in-scope
KSI set for your config + tier. The orchestrator currently ships **44 live
cloud collectors across 60 KSIs** (the remaining ~16 are governance /
process requirements satisfied via the attestation register). See
[`cloud-evidence/README.md`](../README.md) for the per-domain layout
(`providers/aws/*.ts` + `providers/gcp/*.ts` + `providers/azure/*.ts` +
`providers/k8s/security.ts`).

### 5.2 Specified for future implementation

These are documented in `docs/loops/LOOP-X-SPEC.md` and `docs/slices/X/`
per the FedPy slice-by-slice methodology. **Status: spec-only, code not
yet shipped.** Implementation queue priority is documented in `STATUS.md`.

| Loop | Slices | Conditional? | Trigger |
|---|---|---|---|
| **LOOP-A** OSCAL submission package | 5 (A.A1–A.A5: **all DONE**) | No | always |
| **LOOP-B** Risk + Remediation Engine | 5 (B.B1–B.B5) | No | always |
| **LOOP-C** Document Template Pack | 9 (C.C1–C.C9) | No | always |
| **LOOP-D** Diagram Auto-Generation | 3 (D.D1–D.D3) | No | always |
| **LOOP-E** Continuous Monitoring Agent | 7 (E.E1–E.E7) | No | always |
| **LOOP-F** 3PAO Assessor Experience | 7 (F.F1–F.F7) | No | always |
| **LOOP-G** AFR Family (FedRAMP 20x Deliverables) | 6 (G.G1–G.G6) | No | always |
| **LOOP-H** Long-Term Storage + Multi-CSO | 3 (H.H1–H.H3) | No | always |
| **LOOP-I** Stakeholder Dashboards | 4 (I.I1–I.I4) | No | always |
| **LOOP-J** Supply Chain + Privileges | 3 (J.J1–J.J3) | No | always |
| **LOOP-K** Test Artifact Ingestion | 2 (K.K1–K.K2) | No | always |
| **LOOP-L** CRM + Leveraged-Authorization | 4 (L.L1–L.L4) | No | always |
| **LOOP-M** Privacy Package (SORN + PIA + DPIA + PT-family) | 4 (M.M1–M.M4) | Partial | SORN+PIA always; DPIA gated on `data_posture.handles_eu_uk_data_subjects` |
| **LOOP-N** Threat Modeling + Adversarial Validation | 4 (N.N1–N.N4) | No | always |
| **LOOP-O** AI/ML Governance | 5 (O.O1–O.O5) | Yes | `service_architecture.uses_ai_ml: true` |
| **LOOP-P** Insider Threat + PS-family | 5 (P.P1–P.P5) | No | always |
| **LOOP-Q** Marketplace + Post-ATO Publication | 3 (Q.Q1–Q.Q3) | No | always |
| **LOOP-R** PQC Migration | 3 (R.R1–R.R3) | No | always for federal-data CSPs |
| **LOOP-S** DFARS 252.204-7012 Cloud Equivalency | 3 (S.S1–S.S3) | Yes | `customer_posture.serves_dod_cdi: true` |
| **LOOP-T** NIST SSDF + CISA Common Form | 5 (T.T1–T.T5) | No | universal for federal-software CSPs |
| **LOOP-W** Section 889 Prohibited Vendors | 4 (W.W1–W.W4) | No | universal for federal contracts |
| **LOOP-X** Zero Trust Architecture | 5 (X.X1–X.X5) | Yes | `customer_posture.federal_civilian_agencies` non-empty |
| **G.G2-CIRCIA** | 1 (G.G2 extension) | Yes | `critical_infrastructure.is_circia_covered_entity: true` |
| **M.M4-CIRCIA** | 1 (M.M4 extension) | Yes | same as G.G2-CIRCIA |
| **G.G2-SEC-8K** | 1 (G.G2 extension) | Yes | `corporate_status.publicly_traded` or related |

**Total: 22 core loops + 2 CIRCIA extensions + 1 SEC-8K overlay = 103 in-core slices.**

The current implementation queue (per `STATUS.md` "Next priority" line):
**W.W1 → W.W2 → W.W3 → W.W4 → T.T1 → … → T.T5 → B.B1 → 50 pending LOOP-B–K base implementations.**

### 5.3 Roadmap (out-of-core / not on implementation queue)

These were specified during planning but scope-fenced out of core (see
`docs/roadmap/README.md`). They are NOT on the implementation queue;
they are preserved as research / boundary documentation.

| Roadmap loop | What it would cover | Why out-of-core |
|---|---|---|
| LOOP-U | Privacy frameworks (FERPA / COPPA / GLBA / CCPA / CPRA / GDPR / state breach) | State + EU privacy regimes parallel to FedRAMP |
| LOOP-V | HIPAA Security Rule + Breach Notification + BAA + 800-66 R2 + HITRUST | Separate federal regime (HHS OCR), not FedRAMP |
| LOOP-Y | CJIS Security Policy v5.9.5 + IRS Publication 1075 | Sector overlays, not FedRAMP |
| LOOP-Z | ISO/IEC 27001/27017/27018/27701 + ENISA EUCS | International certification chains parallel to FedRAMP |
| FIFTH-PASS-AUDIT candidates (LOOP-AA-GG) | PCI-DSS, CMMC, FedRAMP Tailored, TIC 3.0, SOC 2, etc. | Various — see `docs/roadmap/FIFTH-PASS-AUDIT.md` |

Do not propose moving these back to core without an explicit user
directive. See CLAUDE.md Scope Guard for the policy.

---

## 6. Conditional loops + org-profile.yaml

When the conditional loops ship, they read `org-profile.yaml` at
orchestrator startup to decide whether to fire their collection pass
for the run. The decision flow:

```
  orchestrator startup
        │
        ▼
  load org-profile.yaml (skip if absent — conditional loops idle)
        │
        ▼
  for each conditional loop:
        │
        ├── trigger condition met (per org-profile.yaml field) ?
        │        │
        │        ├── YES → loop's collectors enabled for this run
        │        │
        │        └── NO  → loop skipped; emit
        │                  `coverage:<loop>:not-applicable:1` log line
        │
        ▼
  proceed with main collection pass
```

Conditional triggers are documented in §2.3 and in the example file at
[`cloud-evidence/org-profile.yaml.example`](../org-profile.yaml.example).

**Activation guidance:**
- Pre-fill `org-profile.yaml.example` → `org-profile.yaml` now (with
  your real org's situation) so it's ready when conditional loops ship.
- Leave conditional triggers FALSE until the corresponding loop is
  implemented AND your org actually needs it. The default state of
  every conditional loop is OFF (won't run unless trigger is true).
- The `applicable_conditional: true` flag in a loop SPEC's YAML
  frontmatter is what wires the runtime gating. It is NOT a statement
  that the loop is deferred — every conditional loop is on the
  implementation queue along with the always-on loops.

---

## 7. Output artifacts (full catalogue)

Each FedPy run writes to `out/` (the `output_dir` set in `config.yaml`).
Files emitted depend on the flags you pass.

| File | Always emitted? | Flag to enable | Format | Signed? |
|---|---|---|---|---|
| `pva-run-summary.json` | Yes | — | JSON | Yes |
| `family-rollup.json` | Yes | — | JSON | Yes |
| `control-benchmark.json` | Yes | — | JSON | Yes |
| `KSI-<DOMAIN>-<NAME>.json` (per KSI) | Yes (per in-scope KSI) | — | JSON | Yes |
| `manifest.json` + `manifest.sig` | Yes | — | JSON + Ed25519 sig | — |
| `run-ledger.jsonl` | Yes | — | JSONL append-only | — |
| `assessment-results.json` | No | `--oscal` | OSCAL 1.1.2 | Yes |
| `ssp.json` | No | `--oscal-ssp` | OSCAL 1.1.2 | Yes |
| `ssp.docx` | No | `--ssp-docx` | OOXML | rendered from signed SSP |
| `poam.json` | No | `--oscal-poam` | OSCAL 1.1.2 | Yes |
| `risk-scores.json` | No | `--risk-score` | JSON + detached Ed25519 | yes (detached sig + run manifest) |
| `.epss-cache.json` | No | `--risk-score` (live EPSS) | JSON (provenance-stamped) | yes (detached sig + run manifest) |
| `deadline-audit.json` | No | `--oscal-poam` (LOOP-B.B2) | JSON + detached Ed25519 | yes (detached sig + run manifest) |
| `.risk-acceptances.json` | No | `--pull-risk-acceptances <url>` (LOOP-B.B3) | JSON (provenance-stamped) + detached Ed25519 | yes (detached sig + run manifest) |
| `.compensating-controls.json` | No | `--pull-compensating-controls <url>` (LOOP-B.B4) | JSON (provenance-stamped) + detached Ed25519 | yes (detached sig + run manifest) |
| `.organisational-risks.json` | No | `--pull-organisational-risks <url>` (LOOP-B.B5) | JSON (provenance-stamped) + detached Ed25519 | yes (detached sig + run manifest) |
| `risk-register.json` | No | `--risk-register` (LOOP-B.B5) | JSON (provenance-stamped) + detached Ed25519 | yes (detached sig + run manifest) |
| `risk-register.xlsx` | No | `--risk-register` (LOOP-B.B5) | XLSX (single "Risk Register" sheet) | yes (run manifest) |
| `ap.json` | No | `--oscal-ap` | OSCAL 1.1.2 | Yes |
| `roe.docx` + `roe.json` | No | `--roe` | OOXML + JSON | Yes |
| `cmp.docx` | No | `--cmp` (LOOP-C.C1) | OOXML docx (Configuration Management Plan, CM-9; §4 from inventory, §7 from ksi-map) | printable companion — integrity anchored by the signed submission-bundle INDEX.json (SHA-256 + Ed25519), same as roe.docx/ssp.docx |
| `iscp.docx` | No | `--iscp` (LOOP-C.C2) | OOXML docx (Information System Contingency Plan, CP-2/CP-9/CP-10; §4.2 from RPL-family KSI files, Appendix B from subprocessor inventory) | printable companion — integrity anchored by the signed submission-bundle INDEX.json (SHA-256 + Ed25519) |
| `iscp-test-aar.docx` | No | `--iscp-test-aar` (LOOP-C.C2) | OOXML docx (Contingency Plan Test After-Action Report, CP-4; operator-supplied scenarios + lessons; anchors to iscp.docx SHA-256) | printable companion — integrity anchored by the signed submission-bundle INDEX.json (SHA-256 + Ed25519) |
| `irp.docx` | No | `--irp` (LOOP-C.C3) | OOXML docx (Incident Response Plan, IR-8/IR-3/IR-4/IR-6, NIST SP 800-61 Rev. 3 CSF 2.0 phases; §4 Detect from KSI-INR-RIR evidence, §9 Reporting SLAs from the FedRAMP Incident Communications Procedures) | printable companion — integrity anchored by the signed submission-bundle INDEX.json (SHA-256 + Ed25519) |
| `irp-test-aar.docx` | No | `--irp-test-aar` (LOOP-C.C3) | OOXML docx (Incident Response Test After-Action Report, IR-3; operator-supplied scenarios + 5-phase timing matrix + lessons; anchors to irp.docx SHA-256) | printable companion — integrity anchored by the signed submission-bundle INDEX.json (SHA-256 + Ed25519) |
| `pta.docx` | No | `--pta-pia` (LOOP-C.C4) | OOXML docx (Privacy Threshold Analysis, PT-2/PT-3/PT-6, AR-2 screening; §3 PII evidence auto-derived from inventory.json data_classification tags with resource names redacted) | printable companion — integrity anchored by the signed submission-bundle INDEX.json (SHA-256 + Ed25519) |
| `pia.docx` | No (conditional) | `--pta-pia` (LOOP-C.C4) | OOXML docx (Privacy Impact Assessment, PT-2/PT-3/PT-6/AR-2, FedRAMP A04 Rev4 structure) — emitted ONLY when the PTA determination is positive or `pia_force_mode: always-emit` | printable companion — integrity anchored by the signed submission-bundle INDEX.json (SHA-256 + Ed25519) |
| `fips199.docx` | No | `--fips199` (LOOP-C.C5) | OOXML docx (FIPS 199 security-categorization worksheet, RA-2 / SC-7; system-level SC computed as the high-water-mark across operator-supplied SP 800-60 V2 information types; §4.1 cross-checks against the SSP security-impact-level, CONSISTENT / MISMATCH) | printable companion — integrity anchored by the signed submission-bundle INDEX.json (SHA-256 + Ed25519) |
| `submission-bundle.tar.gz` | No | `--submission-bundle` | POSIX ustar + gzip | bundle is signed |
| `inventory.json` + `inventory-workbook.csv` + `…xlsx` + `inventory-oscal.json` + `inventory-cmdb.json` + `inventory-diff.json` + `inventory-cost.json` | No | `--inventory-workbook` | JSON / CSV / XLSX | yes |
| `crosswalk-report.json` | No | `--crosswalk` | JSON | yes |
| `report.html` + `findings.csv` + `diff-report.json` | No | `--all-reports` (or individual flags) | HTML / CSV / JSON | — |
| `anomaly-report.json` | No | `--anomaly` | JSON | — |
| `scn-classification.json` + `scn-notice-draft.md` | No | `--scn` | JSON + markdown | yes |
| `conmon-monthly-<YYYY-MM>.json` + `.md` + `.pdf` | No | `--conmon-monthly` (LOOP-E.E1) | JSON + detached Ed25519 / Markdown / PDF 1.4 | yes (JSON: detached sig + run manifest; MD + PDF: run manifest — `.md`/`.pdf` are now in the signed set) |
| `poam-delta-<YYYY-MM>.md` | No | `--conmon-monthly` + `--oscal-poam` (LOOP-E.E2) | Markdown | yes (run manifest — `.md` is in the signed set) |
| `poam-ledger.jsonl` | No | `--conmon-monthly` + `--oscal-poam` (LOOP-E.E2) | JSONL append-only | — (append-only audit index; like `run-ledger.jsonl`) |
| `archive/poam-<YYYY-MM>.json` | No | `--conmon-monthly` + `--oscal-poam` (LOOP-E.E2) | OSCAL 1.1.2 | yes (run manifest — `archive/` is in the signed set) |
| `AUDIT-REFARCH-AWS.json` + `AUDIT-REFARCH-GCP.json` | No | `--reference-arch` | JSON | yes |
| `prohibited-vendors-catalog.json` + `.sig` | No | `--prohibited-vendors-catalog` | JSON + detached Ed25519 | yes (detached sig + run manifest) |
| `prohibited-vendors-screen-result.json` + `.sig` | No | `--prohibited-vendor-screen` (LOOP-W.W2) | JSON + detached Ed25519 | yes (detached sig + run manifest) |
| `prohibited-vendors-screen-result.xlsx` | No | `--prohibited-vendor-screen` (LOOP-W.W2) | OOXML xlsx (3 sheets: Matches / Surfaces Screened / Summary) | yes (run manifest) |
| `prohibited-vendor-screens.jsonl` | No | `--prohibited-vendor-screen` (LOOP-W.W2) | JSONL append-only | — (append-only audit ledger; like `run-ledger.jsonl`) |
| `section889-1bd-reports/s889-*.json` + `.json.sig` | No | `--prohibited-vendor-1bd-report` (LOOP-W.W3) | JSON + detached Ed25519 | yes (detached sig + run manifest) |
| `section889-1bd-reports/s889-*.docx` | No | `--prohibited-vendor-1bd-report` (LOOP-W.W3) | OOXML docx (FAR 52.204-25(d) report for CO/DIBNet transmission) | yes (run manifest) |
| `section889-1bd-reports.jsonl` | No | `--prohibited-vendor-1bd-report` (LOOP-W.W3) | JSONL append-only | — (append-only idempotency + audit ledger; like `prohibited-vendor-screens.jsonl`) |
| `section889-annual-rep.json` + `.json.sig` | No | `--section889-annual-rep` (LOOP-W.W4) | JSON + detached Ed25519 | yes (detached sig + run manifest) |
| `section889-annual-rep.docx` | No | `--section889-annual-rep` (LOOP-W.W4) | OOXML docx (FAR 52.204-26 representation for officer signature + SAM.gov submission) | yes (run manifest) |
| `section889-annual-reps.jsonl` | No | `--section889-annual-rep` (LOOP-W.W4) | JSONL append-only | — (append-only delta + continuity + flip-detection ledger) |
| `marketplace-section889-badge.json` | No | `--section889-annual-rep` (LOOP-W.W4) | JSON | yes (run manifest) — LOOP-Q.Q1 "Section 889 Compliant" badge feed |
| `subprocessor-inventory.json` + `subprocessor-inventory.xlsx` | No | `--subprocessors-config` (or `config.yaml` `subprocessors`) | JSON + detached Ed25519 / XLSX | yes (detached sig + run manifest) |
| `supply-chain-risk-register.json` + `supply-chain-risk-register.xlsx` | No | `--supply-chain-risk` | JSON + detached Ed25519 / multi-sheet XLSX | yes (detached sig + run manifest) |
| `ssdf-satisfaction-matrix.json` + `.json.sig` | No | `--ssdf-attestation` (LOOP-T.T2) | JSON + detached Ed25519 | yes (detached sig + run manifest) — per-practice × per-task SSDF satisfaction matrix; per-product files are slug-suffixed (`ssdf-satisfaction-matrix.<product>.json`) |
| `ssdf-satisfaction-matrix.xlsx` | No | `--ssdf-attestation` (LOOP-T.T2) | OOXML xlsx (2 sheets: Per-Task Matrix / Per-Practice Summary) | yes (run manifest) |
| `ssdf-satisfaction-matrix.jsonl` | No | `--ssdf-attestation` (LOOP-T.T2) | JSONL append-only | — (append-only emission ledger; like `prohibited-vendor-screens.jsonl`) |
| `cisa-common-form-1670-0052.pdf` | No | `--ssdf-common-form` (LOOP-T.T3) | Deterministic PDF 1.4 (CISA Common Form OMB 1670-0052 — unsigned; corporate officer signs out of band, submits via CISA RSAA / agency portal) | yes (run manifest — `.pdf` signed by extension) |
| `cisa-common-form-1670-0052.json` + `.json.sig` | No | `--ssdf-common-form` (LOOP-T.T3) | JSON + detached Ed25519 | yes (detached sig + run manifest) — canonical-JSON shadow recording the four Section IV selections derived from the T.T2 matrix |
| `ssdf-material-change-events.json` + `.json.sig` | No | `--ssdf-attestation` (LOOP-T.T4) | JSON + detached Ed25519 | yes (detached sig + run manifest) — SSDF annual re-attestation cadence rows (per product × federal agency: last-submitted / next-due / due-state) + typed `MaterialChangeEvent[]` diffing successive T.T2 matrix snapshots (OMB M-23-16 §III binding-clause trigger) |
| `ssdf-attestation-ledger.jsonl` | No | `--ssdf-attestation` (LOOP-T.T4) | JSONL append-only | — (append-only run index: run_id, product, matrix sha256, snapshot path, regime, agencies, events, next-due; the matrix-snapshot version chain) |
| `ssdf-attestation-snapshots/<product>/<sha256>.json` | No | `--ssdf-attestation` (LOOP-T.T4) | JSON (content-addressed copy of a T.T2 matrix) | — (immutable diff baseline; integrity anchored by the sha256 filename + the signed events file that records each sha256) |
| `ssdf-ai-augmentation.json` + `.json.sig` | No | `--ssdf-attestation` + `config.yaml#ssdf.ai_augmentation_enabled: true` + ≥1 in-scope model card (LOOP-T.T5) | JSON + detached Ed25519 | yes (detached sig + run manifest) — NIST SP 800-218A per-in-scope-product AI augmentation matrix (R/C/N items joined to the T.T2 matrix + LOOP-O.O5 model cards); only emitted when at least one `out/model-cards/*.json` is in AI scope, else the step no-ops (`coverage:skipped`) |
| `ssdf-ai-augmentation.xlsx` | No | as above (LOOP-T.T5) | OOXML xlsx (Summary + per-product A..O + IPD-vs-final delta + statutory-lineage sheets) | yes (run manifest) |
| `ssdf-satisfaction-matrix.augmented.json` + `.json.sig` | No | as above (LOOP-T.T5) | JSON + detached Ed25519 | yes (detached sig + run manifest) — the T.T2 matrix re-emitted with 800-218A augmentations interleaved under each parent task (+ new AI tasks appended); read by a future T.T3 revision |

### 7.1 Committed reference catalogs (built offline, not per-run)

Some signed catalogs are checked into version control rather than emitted on
every run. They are rebuilt only when their upstream published source changes,
via a dedicated `npm run build:*` script, and committed to `data/`.

| File | Build command | Source | Format | Signed? |
|---|---|---|---|---|
| `data/ssdf-800-218-v1.1.json` | `npm run build:ssdf-catalog` | `docs/sources/NIST.SP.800-218.pdf` (sha256-pinned) | JSON | yes (embedded detached Ed25519 in `provenance`) |
| `docs/fedramp-conmon-playbook.generated.json` | `node scripts/fetch-conmon-playbook.mjs` | FedRAMP Continuous Monitoring Playbook v1.0 PDF (sha256-pinned) | JSON | — (drift-detected via sha256) |

The ConMon Playbook projection (LOOP-E.E1) pins the FedRAMP remediation-deadline
table, scan-cadence table, monthly-deliverables list, and version/date from the
888 KB PDF (sha256 `d96379ec…`). It drives the monthly report's pinned constants
(`provenance.conmonPlaybookVersion`) rather than hard-coded strings. Re-run the
fetcher quarterly (RUNBOOK) to detect playbook drift.

The SSDF catalog (LOOP-T.T1) holds the 19 NIST SP 800-218 v1.1 practices, 42
tasks, the verbatim SP 800-53 Rev 5 control mapping, the CISA Common Form
Section IV labelling, and a curated FedRAMP KSI forward map. It is loaded via
`core/ssdf-practices-catalog.ts` and consumed by LOOP-T.T2/T3/T5. It joins a
submission bundle (role `ssdf-practice-catalog-json`) only when
`--include-ssdf-catalog` is set (wired in T.T2). To regenerate with the org's
stable signing key, set `EVIDENCE_SIGNING_KEY_PATH` before running the build.

The bundle catalogue (LOOP-A.A4) is the authoritative index of what's
in a submission bundle for a given run.

---

## 8. Common run patterns

### 8.1 First-time smoke test

```sh
cd cloud-evidence
npm install
npx tsx core/orchestrator.ts --dry-run
```

The `--dry-run` flag prints the in-scope KSI set without making any SDK
calls. Useful for verifying your `config.yaml` is loaded correctly.

### 8.2 Daily ConMon run (Moderate, all reports)

```sh
npm run collect -- --impact-level moderate --framework 20x \
  --all-reports --oscal --crosswalk \
  --inventory-workbook \
  --push-tracker --notify-on-drift
```

Outputs: per-KSI evidence + OSCAL AR + crosswalk + inventory workbook +
HTML report + findings.csv + diff vs last run; pushed to tracker;
Slack/PagerDuty on drift.

### 8.3 Full FedRAMP submission package

```sh
npm run collect -- --impact-level moderate --framework 20x \
  --oscal-ssp --oscal-ap --oscal --oscal-poam \
  --ssp-docx --roe --inventory-workbook --reference-arch \
  --submission-bundle --strict-bundle --strict-chain \
  --3pao-name "Coalfire" --system-name "Acme Federal Cloud" \
  --system-id "acme-fed-cloud-csp-12345"
```

Outputs the complete signed submission package as a single tarball with
the OSCAL SSP/AP/AR/POA&M chain validated end-to-end.

### 8.4 High-baseline benchmark against full SP 800-53 Rev 5

```sh
npm run collect -- --impact-level high --framework rev5 \
  --all-reports
```

Note: "high" is derived from NIST 800-53 Rev 5 — no FedRAMP 20x High
KSIs are published yet (see `docs/IMPACT-LEVEL-NOTES.md`).

### 8.5 Single-KSI debug

```sh
npm run collect -- --ksis KSI-IAM-MFA --providers aws --dry-run
npm run collect -- --ksis KSI-IAM-MFA --providers aws
```

Useful when iterating on a specific collector or troubleshooting a
specific finding.

### 8.6 SCN classification (proposed-change preview)

```sh
npm run collect -- --scn --scn-proposed ./proposed-changes.json
```

Outputs `scn-classification.json` + `scn-notice-draft.md` — a starting-
point Significant Change Notification email for the authorizing agency.

---

## 9. Where to look for what

| Question | Doc |
|---|---|
| What is FedPy + what does it do? | [`README.md`](../../README.md) (root) |
| How do I install + run for the first time? | [`RUNBOOK.md`](../../RUNBOOK.md) §§ 0–3 |
| How do I configure AWS / GCP / Azure IAM read-only access? | [`RUNBOOK.md`](../../RUNBOOK.md) §2 + [`docs/IAM-PERMISSIONS-CATALOG.md`](IAM-PERMISSIONS-CATALOG.md) |
| What flags / env vars exist? | **This file** §§ 3–4 |
| What does each output file mean? | **This file** §7 + [`README.md`](../../README.md) "Output artifacts" |
| What is `org-profile.yaml`? | **This file** §§ 2.3, 6 + [`org-profile.yaml.example`](../org-profile.yaml.example) |
| What's the FedRAMP impact-level meaning? | [`docs/IMPACT-LEVEL-NOTES.md`](IMPACT-LEVEL-NOTES.md) |
| What loops are in scope? | **This file** §5 + [`cloud-evidence/CLAUDE.md`](../CLAUDE.md) Scope Guard |
| What's the current implementation status? | [`docs/STATUS.md`](STATUS.md) |
| What's the implementation contract for a loop / slice? | `docs/loops/LOOP-X-SPEC.md` + `docs/slices/X/X.XN.md` |
| What does the read-only safety model do? | [`cloud-evidence/README.md`](../README.md) "Read-only commitments" |
| Why is X in scope but Y is not? | [`docs/roadmap/README.md`](roadmap/README.md) + CLAUDE.md Scope Guard |
| How do I troubleshoot Y? | [`RUNBOOK.md`](../../RUNBOOK.md) §4 |
| How do I scale to a multi-account / multi-CSO org? | [`RUNBOOK.md`](../../RUNBOOK.md) §5 |
| How do I back up + restore the tracker DB? | [`RUNBOOK.md`](../../RUNBOOK.md) §6 |
| What every term means | [`docs/GLOSSARY.md`](GLOSSARY.md) |

---

## 10. Maintenance

This operator guide is a **stable reference** — it changes when new
CLI flags / env vars / loops ship. The slice-completion procedure
(`docs/SLICE-COMPLETION-PROCEDURE.md` step 6) requires updating the
relevant sections of this file when:
- A new CLI flag lands in `core/orchestrator.ts`
- A new env var is read in any production-path module
- A new loop's SPEC is committed (add to §5.2 or §5.3 table)
- A conditional loop's implementation ships (move it from "spec only"
  to "implemented" in §5.2; add the actual config field name to
  `org-profile.yaml` / §2.3 if it changed during implementation)

The maintenance contract for this file is the same as for `STATUS.md`:
do not let it drift from the code.
