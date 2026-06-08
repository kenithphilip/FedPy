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

### 3.3 OSCAL + submission-package flags

| Flag | Output | Purpose |
|---|---|---|
| `--oscal` | `out/assessment-results.json` | OSCAL 1.1.2 Assessment Results. |
| `--oscal-ssp` | `out/ssp.json` | Draft OSCAL 1.1.2 System Security Plan. |
| `--oscal-poam` | `out/poam.json` | OSCAL 1.1.2 Plan of Action and Milestones. |
| `--oscal-ap` | `out/ap.json` | OSCAL 1.1.2 Assessment Plan. |
| `--ssp-docx` | `out/ssp.docx` | FedRAMP-style Word render of the SSP (implies `--oscal-ssp`). Dependency-free OOXML. |
| `--strict-chain` | (flag) | Enforce OSCAL chain validity: AR must import-AP; AP must import-SSP. Fails the run on chain breakage. |
| `--submission-bundle` | `out/submission-bundle.tar.gz` | Bundle all FedRAMP submission artifacts into a single signed tarball. |
| `--strict-bundle` | (flag) | Refuse to bundle if any expected artifact is missing. |
| `--roe` | `out/roe.docx` + `out/roe.json` | Rules of Engagement template. |
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
| `CLOUD_EVIDENCE_OSCAL_AP` | `0` | Emit OSCAL Assessment Plan. |
| `CLOUD_EVIDENCE_STRICT_CHAIN` | `0` | Enforce OSCAL chain validity. |
| `CLOUD_EVIDENCE_SUBMISSION_BUNDLE` | `0` | Bundle the submission package. |
| `CLOUD_EVIDENCE_STRICT_BUNDLE` | `0` | Refuse to bundle on missing artifacts. |
| `CLOUD_EVIDENCE_ROE` | `0` | Emit Rules of Engagement template. |
| `CLOUD_EVIDENCE_AP_ROE_HREF` | (none) | URL embedded in AP RoE link. |
| `CLOUD_EVIDENCE_AP_SAMPLING_HREF` | (none) | URL embedded in AP sampling-methodology link. |
| `CLOUD_EVIDENCE_3PAO_NAME` | (none) | 3PAO org name embedded in AP. |
| `CLOUD_EVIDENCE_SSP_DOCX` | `0` | Render SSP as `.docx`. |
| `CLOUD_EVIDENCE_ORG_NAME` | (none) | Operator org embedded in OSCAL. |
| `CLOUD_EVIDENCE_SYSTEM_NAME` | `Cloud System` | System name embedded in OSCAL SSP. |
| `CLOUD_EVIDENCE_SYSTEM_ID` | `cloud-evidence-system` | System identifier embedded in OSCAL SSP. |
| `CLOUD_EVIDENCE_SYSTEM_DESCRIPTION` | (auto) | System description in OSCAL SSP. |
| `CLOUD_EVIDENCE_CROSSWALK` | `0` | Emit NIST→SOC2/ISO27001/HIPAA crosswalk. |

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
| `ap.json` | No | `--oscal-ap` | OSCAL 1.1.2 | Yes |
| `roe.docx` + `roe.json` | No | `--roe` | OOXML + JSON | Yes |
| `submission-bundle.tar.gz` | No | `--submission-bundle` | POSIX ustar + gzip | bundle is signed |
| `inventory.json` + `inventory-workbook.csv` + `…xlsx` + `inventory-oscal.json` + `inventory-cmdb.json` + `inventory-diff.json` + `inventory-cost.json` | No | `--inventory-workbook` | JSON / CSV / XLSX | yes |
| `crosswalk-report.json` | No | `--crosswalk` | JSON | yes |
| `report.html` + `findings.csv` + `diff-report.json` | No | `--all-reports` (or individual flags) | HTML / CSV / JSON | — |
| `anomaly-report.json` | No | `--anomaly` | JSON | — |
| `scn-classification.json` + `scn-notice-draft.md` | No | `--scn` | JSON + markdown | yes |
| `AUDIT-REFARCH-AWS.json` + `AUDIT-REFARCH-GCP.json` | No | `--reference-arch` | JSON | yes |
| `prohibited-vendors-catalog.json` + `.sig` | No | `--prohibited-vendors-catalog` | JSON + detached Ed25519 | yes (detached sig + run manifest) |

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
