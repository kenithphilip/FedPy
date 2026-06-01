# Changelog

All notable changes to the FedRAMP 20x tooling (cloud-evidence + tracker) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — Azure logging closeout (AZ-MLA-ALA + AZ-MLA-RVL + AZ-CMT-LMC)
Three more Azure logging KSI collectors land on the AZ-MLA-LET/OSM foundation —
all via Resource Graph (no new permissions beyond Reader + RBAC read).
- **`collectMlaAla`** (Authorizing Log Access) — 2 findings:
  1. `azure.mla.ala.log_analytics_reader_assigned` — at least one explicit
     `Log Analytics Reader` role assignment (`73c42c96-…`) exists at a Log
     Analytics workspace scope. Strong signal that operators use the dedicated
     read-only role for log access.
  2. `azure.mla.ala.no_broad_workspace_admins` — no Owner / Contributor role
     assignments scope directly at a workspace (admin scopes should inherit
     from above, not be granted at the workspace itself).
- **`collectMlaRvl`** (Reviewing Logs) — 2 findings:
  1. `azure.mla.rvl.workspace_retention_at_floor` (high) — at least one Log
     Analytics workspace has retention ≥ 90 days.
  2. `azure.mla.rvl.alert_rules_present` (high) — at least one Azure Monitor
     `scheduledQueryRules` OR Sentinel `securityinsights/alertrules` rule is
     actively querying logs on a schedule (active review, not just collection).
- **`collectCmtLmc`** (Logging Changes) — 2 findings:
  1. `azure.cmt.lmc.activity_log_exported` (high) — every configured
     subscription has a **subscription-scope** diagnostic setting exporting the
     Activity Log. Filter is JS-authoritative (the regex anchor on
     `/subscriptions/{id}/providers/microsoft.insights/diagnosticsettings`
     correctly rejects resource-scope child diag settings).
  2. `azure.cmt.lmc.change_tracking_enabled` (medium) — a Change Tracking
     solution (`microsoft.operationsmanagement/solutions` with name starting
     `ChangeTracking`) is deployed.
- IAM-PERMISSIONS-CATALOG: row added noting `authorizationresources` table
  needs an RBAC-read role; `Reader and Data Access` (or any role granting
  `Microsoft.Authorization/roleAssignments/read`) is sufficient.
- 13 new dedicated tests covering all three (passing, failing, mixed,
  no-subs, child-resource diag-setting exclusion). 573 tests pass.

### Added — Azure logging collectors (AZ-MLA-LET + AZ-MLA-OSM)
First non-IAM Azure family. Both KSIs run a couple of Azure Resource Graph
queries — **no new permissions** beyond AZ-1's `Reader` role. KSI-MLA-LET and
KSI-MLA-OSM are now AWS + GCP + Azure.

- **`providers/azure/logging.ts`** — new file.
- **`collectMlaLet`** (Logging Event Types) — 2 findings:
  1. `azure.diagnostic_settings_present` (high) — at least one
     `microsoft.insights/diagnosticsettings` child resource exists somewhere in
     the configured subscriptions. Reports the count + how many subscriptions
     have any diagnostic settings.
  2. `azure.log_analytics_workspace_present` (high) — at least one Log
     Analytics workspace exists as the substrate for diagnostic-setting output.
- **`collectMlaOsm`** (Operating SIEM Capability) — 2 findings:
  1. `azure.siem.workspace_substrate_present` — workspace ready for Sentinel.
  2. `azure.siem.sentinel_deployed` (high) — Microsoft Sentinel is onboarded
     on a workspace, detected via either the legacy
     `microsoft.operationsmanagement/solutions` (name starts with
     `SecurityInsights`) **or** the newer
     `microsoft.securityinsights/onboardingstates` resource. 3rd-party SIEM
     consumers (Splunk, Datadog, etc.) surfaced as an awareness alternative
     satisfier — this collector can't see those flows from ARM data alone.
- **Multi-subscription support**: `CollectorContext.azure.subscription_ids:
  string[]` plumbed through the orchestrator so Resource Graph collectors query
  the entire configured subscription set (orchestrator dispatch sets it).
  Backward-compatible: collectors that only carry `subscription_id` still work.
- 10 new tests (passing, failing, fall-back-to-`subscription_id`, no-subs
  warning, alternative-satisfier surface). tsc clean; 560 tests pass.

### Added — Azure IAM family completion (IAM-APM / IAM-SNU / IAM-JIT / IAM-SUS)
Last four KSIs in the Entra ID / Microsoft Graph track land — **every IAM KSI is
now AWS + GCP + Azure** (7 of 7). No new auth infrastructure; reuses the Graph
helper + per-KSI Azure dispatch shipped earlier.
- **`collectIamApm`** (Adopting Passwordless Methods) — 2 findings on the same
  CA-policies endpoint already used by IAM-MFA:
  1. `aad.ca_uses_authentication_strength` — pass when ≥1 enabled CA policy
     references `grantControls.authenticationStrength` (FIDO2 / Windows Hello /
     cert-based) instead of the legacy `mfa` built-in.
  2. `aad.ca_authentication_strength_for_admins` (severity `high`) — same but
     specifically targeting privileged directory roles.
- **`collectIamSnu`** (Securing Non-User Authentication) — service-principal
  credential hygiene via `/applications`:
  1. `aad.sp_no_expired_credentials` — no SP carries a credential past its
     `endDateTime`. Hygiene + reduces audit-log noise.
  2. `aad.sp_credentials_rotated_within_year` — no SP credential is > 365 days
     old. Workload-identity federation surfaced as the preferred remediation.
- **`collectIamJit`** (Authorizing Just-in-Time) — 1 finding on
  `/roleManagement/directory/roleAssignmentScheduleRequests`:
  - `aad.pim_admin_activation_within_30d` — proves JIT is **operationally live**
    by requiring ≥1 granted PIM self-activation on a privileged role in the last
    30 days, not just configured. Cross-KSI link to IAM-ELP (config) / IAM-MFA.
- **`collectIamSus`** (Responding to Suspicious Activity) — 1 finding on the
  CA-policies endpoint:
  - `aad.risk_based_conditional_access` (severity `high`) — pass when ≥1
    enabled CA policy reacts to Entra ID **Identity Protection** signals
    (`signInRiskLevels` / `userRiskLevels`) to automatically block, step-up, or
    force password reset on suspicious sign-ins.
- **IAM-PERMISSIONS-CATALOG**: added the new `Application.Read.All` row;
  Policy.Read.All / RoleManagement.Read.Directory already in place from earlier
  slices.
- 18 new dedicated tests (each KSI: passing, failing, ignore-disabled,
  ignore-non-matching). **AZ-2 IAM family is complete; 550 tests pass.**

### Added — Azure IAM-ELP + IAM-AAM collectors (next AZ-2 slice)
Two more Azure KSI collectors land on the Microsoft Graph + per-KSI Azure
dispatch foundation shipped with AZ-IAM-MFA. KSI-IAM-ELP and KSI-IAM-AAM are
now AWS + GCP + **Azure**.
- **`collectIamElp`** (Ensuring Least Privilege) — two findings:
  1. `aad.global_admin_count_within_threshold` — passes when total Global
     Administrators is ≤ 5 (FedRAMP / Microsoft guidance: ≥ 2 for emergency
     access, ≤ 5 to limit concentration of risk). Warning emitted when the
     role isn't yet activated (no members) so the human reviewer notices the
     emergency-access gap.
  2. `aad.pim_eligible_for_admin_roles` — passes when at least one PIM-eligible
     assignment covers a privileged directory role (Global / Privileged Role /
     Application / Security / User Administrator). Encourages just-in-time
     activation over standing admin grants. Cross-KSI link to KSI-IAM-JIT.
- **`collectIamAam`** (Automating Account Management) — two findings derived
  from the `signInActivity` field on `/users`:
  1. `aad.no_dormant_enabled_accounts` — passes when no enabled member account
     has been silent for > 90 days. Ignores guests (`userType=Guest`) and
     disabled accounts. **Degrades to a "data-missing" warning** (rather than
     false positives) when `signInActivity` is absent on every user —
     reliable signal that `AuditLog.Read.All` is missing.
  2. `aad.no_severely_dormant_accounts` (severity `critical`) — same data with
     a 365-day threshold.
- IAM-PERMISSIONS-CATALOG: added rows for `RoleManagement.Read.Directory`,
  `Directory.Read.All`, `User.Read.All`, `AuditLog.Read.All`.
- 13 new dedicated tests covering both passing + failing scenarios + degraded
  paths (no role activated, AuditLog missing, guests/disabled-users ignored).
  532 tests pass.

### Added — Azure IAM-MFA collector (AZ-IAM-MFA, first slice of AZ-2)
The first per-KSI Azure collector — establishes the Microsoft Graph + KSI-dispatch
infrastructure follow-up Azure KSIs reuse.
- **`core/auth/azure-graph.ts`** — Microsoft Graph access via plain REST (`fetch`)
  using a Graph-scoped token from `DefaultAzureCredential`. No `@microsoft/microsoft-graph-client`
  dep. Read-only by API design: only `graphFetchAll` (paginated, follows
  `@odata.nextLink`) and `graphFetchOne` are exposed. Graph errors are surfaced as
  readable warnings (401 / 403 / 404 / 429 classified).
- **`providers/azure/iam.ts`** — `collectIamMfa(ctx)` returns a `ProviderBlock` with two findings:
  1. `aad.security_defaults_or_ca_mfa_for_all_users` — passes when Security Defaults
     are on **or** an enabled Conditional Access policy enforces MFA on `includeUsers = All`.
  2. `aad.ca_mfa_for_admin_roles` (severity `critical`) — passes when at least one
     enabled CA policy includes a privileged directory-role template (Global Admin,
     Privileged Role Admin, Application Admin, Security Admin, etc.) and grants MFA.
  Authentication-strength references are treated as MFA-equivalent. Disabled policies
  are ignored. External SAML/OIDC IdPs are surfaced as a `ksi_level_alternatives` entry.
- **KSI dispatch wired through:** `KsiEntry` and `CollectorContext` gain an `azure?`
  slot in `core/ksi-map.ts`; `runOneKsi` gets an Azure branch (single tenant-scoped
  call, mirrors the GCP per-project branch). `KSI-IAM-MFA` is now AWS + GCP + **Azure**.
- 9 new dedicated tests + Azure smoke iterating all `ksi.azure` collectors (no-data
  degraded path, schema-valid output). 519 tests pass.

### Added — Significant Change Notification (SCN) classifier (SCN-1)
A new opt-in classifier (`--scn`, env `CLOUD_EVIDENCE_SCN`) takes the run's existing diff
outputs and labels each change with a FedRAMP **significance level**, a recommended
notification window, and the artifacts the change requires. Emits a starting-point
notice email so the CSP can complete + send to the authorizing agency before applying.
Clean-room from the huntridge-labs/argus AGPL project (research report 08 — idea source
only, no code copied).

- **`core/scn-classifier.ts`** — pure `classifyChange`/`classifyChanges`/`harvestChanges`/
  `draftNotice` + a thin disk reader/emitter (`buildScnReport`/`writeScnReport`).
- **Harvest sources:** `diff-report.json` (regressed / new-failing / fixed findings),
  `inventory-diff.json` (added / removed / mutated assets), and an optional
  operator-supplied proposed-changes JSON (forward-looking — `--scn-proposed <path>` or
  env `CLOUD_EVIDENCE_SCN_PROPOSED_PATH`).
- **Categories:** boundary · authentication · cryptography · network · data-flow ·
  personnel · platform-version · subprocessor · configuration · improvement. Field-aware
  categorization on inventory diffs (e.g. `publicFacing` change → `network`; `kmsKeyId`
  change → `cryptography`; `osNameVersion` change → `platform-version`).
- **Default rule library** (10 rules) covers the FedRAMP "significant change" taxonomy
  (SP 800-37 r2 § 3.6 + the FedRAMP SCR guide), with each rule mapping a category to:
  significance (`significant` / `advisory` / `not-significant`), a recommended
  notice-days window (30 for boundary/auth/crypto/network/data-flow/subprocessor/personnel,
  14 for platform-major upgrades, 7 for config regressions), and the required artifacts
  (updated SSP narratives, updated FIPS-199, POA&M entries, FIPS 140-3 cert, network
  diagrams, etc.). Caller can pass a custom rule set.
- **Outputs:** `out/scn-classification.json` (structured) + `out/scn-notice-draft.md`
  (markdown notice the CSP refines). Wired into the orchestrator after the diff-report
  block (`--scn` implies `--diff-report`).
- 18 new tests (rule matching, harvesting from real diff shapes, categorisation
  heuristics, totals aggregation, draft-notice render, end-to-end disk reader,
  proposed-changes JSON in both array and `{changes:[...]}` shapes). tsc clean;
  509 tests pass.

### Added — Azure FedRAMP reference-architecture audit (AZ-CHK)
Third leg of the multi-cloud reference-arch trio. Joins the existing AWS-CHK / GCP-CHK
audits behind the same `--reference-arch` flag (env `CLOUD_EVIDENCE_REFERENCE_ARCH`)
and emits `AUDIT-REFARCH-AZURE.json` whose findings flow into the NIST 800-53
benchmark, family roll-up (`REFARCH`), crosswalk, OSCAL, and the signed manifest.
Derived **clean-room** from the Coalfire Azure RAMPpak reference architecture
(research report 03 — idea source, MIT, no code copied).

- **`providers/azure/reference-arch.ts`** → `AUDIT-REFARCH-AZURE.json` (11 checks):
  Defender for Cloud enabled, FedRAMP policy initiative assigned, storage no
  public-blob, storage HTTPS-only + TLS 1.2+, storage public-network-access
  restricted, Key Vault soft-delete + purge protection + RBAC, CMK in use, managed
  disk encryption (not platform-key-only), NSGs with no SSH/RDP open to the
  Internet, no public IPs attached directly to VM NICs, Log Analytics workspace
  with retention ≥ 90 days.
- Every check is a **single Azure Resource Graph KQL query** against the
  `Resources` / `PolicyResources` / `SecurityResources` tables — no extra SDK deps
  beyond the AZ-1 scaffolding. Reuses the existing read-only Azure Proxy
  guardrail. Each check try/catch → warning (fail-open contract), so a missing
  RBAC grant for one table doesn't break the run.
- Excluded from the KSI pass/fail rollup (hardening audit, not a KSI obligation)
  — same convention as AWS-CHK / GCP-CHK.
- 5 new tests (passing scenario, degraded/empty fail-open, storage offender
  detection, NSG offender detection, no-subscriptions warning). tsc clean;
  491 tests pass.

### Added — Azure collector scaffolding (AZ-1)
Third-cloud foundation. The collector can now enumerate Azure subscriptions and feed
the inventory workbook (`--inventory-workbook`) alongside AWS + GCP. KSI collectors
land in AZ-2.
- **`core/auth/azure.ts`** — `DefaultAzureCredential` (env / workload identity / managed
  identity / `az login` / azd / PowerShell). `whoAmIAzure` is JWT-based (no API call —
  decodes the ARM token) so it works even without subscription-list permission. Client
  factories `resourceGraph()` and `resources(subscriptionId)`. Every client is wrapped
  in the read-only guardrail.
- **`core/readonly-guardrail-azure.ts`** — Azure-flavoured mirror of the GCP guardrail.
  Adds the Azure long-running-operation `begin*` prefix family (`beginCreate`,
  `beginCreateOrUpdate`, `beginDeleteAndWait`, …) to the write denylist. Disable with
  `CLOUD_EVIDENCE_DISABLE_AZURE_GUARDRAIL=1` only for debugging.
- **`providers/azure/discover.ts`** — Azure Resource Graph as the breadth discovery
  backbone (the Azure analog of AWS Config Advanced Query and GCP CAI
  `searchAllResources`). One KQL query across all configured subscriptions returns every
  resource with the projection the inventory workbook needs.
- **`providers/azure/inventory-assets.ts`** — depth enricher for storage accounts
  (public-blob access, encryption key source, CMK URI, TLS floor) and virtual machines
  (image / SKU / provisioning state).
- Orchestrator: `azure` is now a third provider alongside `aws`/`gcp` (default
  `--providers aws,gcp,azure`; silently skipped unless `config.azure.enabled` is true).
  `Config.azure` block in `config.yaml` (`enabled`, `subscriptions`, `tenant_id?`).
  Schema: `azure` added to `ProviderName` (validator unblocks it as a provider value).
- 19 new tests (12 Azure guardrail classification + wrap/throw, 7 discover + inventory
  pagination + row → CloudAsset mapping). tsc clean; 486 tests pass.

### Added — OSCAL SSP → FedRAMP Word (.docx) renderer (SSP-2)
Renders the draft OSCAL SSP (SSP-1) into a human-readable Word document so a system
owner can review/circulate it without a GRC tool.
- **`core/ssp-docx.ts`** — pure `renderSspDocx(ssp)` + disk emitter `emitSspDocx(opts)`.
  A `.docx` is a ZIP of WordprocessingML (OOXML) parts, so it's built **dependency-free**
  (no `docx`/python-docx, no network) and packed with the same **store-only ZIP** writer
  used for the inventory `.xlsx`. The idea (OSCAL → FedRAMP template prose) is drawn
  clean-room from the CC0 GoComply/fedramp tool; no code copied.
- **`core/zip.ts`** — extracted the shared store-only ZIP writer + `xmlEscape` (previously
  private to `inventory-workbook.ts`); both the xlsx and docx writers now use it.
- The document renders: a title page, document-information table, system characteristics
  (FIPS-199 impact, information types, status, authorization boundary), system
  implementation (components + users tables), and a control-implementation section with a
  status summary + a per-control table (control id/name, status, implementation statement).
- Wired behind `--ssp-docx` (env `CLOUD_EVIDENCE_SSP_DOCX`), which **implies `--oscal-ssp`**;
  emitted in the SSP block after the JSON is written + schema-validated. The `.docx` is not
  in the signed manifest (the signer covers `*.json`), but it's a faithful render of the
  signed `ssp.json` — reproducible from the signed source. 4 new tests (valid store-only
  ZIP + required OOXML parts, rendered content, XML escaping, wrapped/unwrapped input).

### Added — OSCAL System Security Plan emitter (SSP-1)
A new opt-in emitter (`--oscal-ssp`, env `CLOUD_EVIDENCE_OSCAL_SSP`) generates a **draft**
OSCAL 1.1.2 System Security Plan (`out/ssp.json`) directly from the run's evidence.
- **`core/oscal-ssp.ts`** — pure `buildOscalSsp(benchmark, opts)` + disk emitter
  `emitOscalSsp(opts)`. The SSP documents the **whole FedRAMP Rev5 baseline** for the
  run's impact level (so it always benchmarks `framework='rev5'`, independent of
  `--framework`): one `implemented-requirement` per baseline control.
- **Status mapping** (from the NIST 800-53 control benchmark): satisfied→`implemented`,
  partially-satisfied→`partial`, not-satisfied→`planned`, not-assessed→`planned` (with a
  remark to assess manually or document as inherited from the underlying CSP). Each
  requirement carries a FedRAMP `implementation-status` prop + a `by-component` narrative
  citing the KSIs/rules and pass counts that produced the evidence.
- Pre-populates `metadata` (roles/parties), `import-profile` (the published FedRAMP Rev5
  Low/Moderate/High baseline profile href), `system-characteristics` (FIPS-199 impact,
  information types, status, boundary placeholder), and `system-implementation`
  (this-system + leveraged AWS/GCP components, a placeholder user).
- Emitted **before signing** (covered by the manifest) and **validated against the
  committed NIST OSCAL SSP schema** (`validateOscalFile(path,'ssp')`); fails the run under
  `--strict-schema`. New flags `--system-name` / `--system-id` (+ env
  `CLOUD_EVIDENCE_SYSTEM_NAME`/`_ID`/`_DESCRIPTION`).
- Deterministic UUIDs (re-running on the same evidence yields a stable diff). Clearly
  framed as a **starting point** for the system owner, not a final SSP. 4 new tests
  (schema-valid output, status mapping, required structure, determinism).

### Added — FedRAMP reference-architecture audit (AWS-CHK / GCP-CHK)
A new opt-in audit (`--reference-arch`, env `CLOUD_EVIDENCE_REFERENCE_ARCH`) checks the
**running** AWS/GCP environment against the hardening a FedRAMP-compliant build is
expected to have — derived **clean-room** from the Coalfire AWS/GCP RAMPpak reference
architectures (research reports 02 & 04; idea source only, MIT, no code copied).
- **`providers/aws/reference-arch.ts`** → `AUDIT-REFARCH-AWS.json` (10 checks):
  customer-managed KMS keys in use, Security Hub CIS + AWS FSBP standards, AWS Network
  Firewall present, active VPC flow logs, Organizations SCPs + delegated admin,
  org trusted access for core security services, CloudTrail→CloudWatch delivery,
  AWS Backup selection coverage, Terraform-state bucket integrity (SSE + lock table),
  and approved/STIG AMI provenance (`CLOUD_EVIDENCE_APPROVED_AMI_PATTERN`).
- **`providers/gcp/reference-arch.ts`** → `AUDIT-REFARCH-GCP.json` (13 checks):
  Assured Workloads (FedRAMP regime), baseline Org Policy constraints, VPC Service
  Controls perimeter, per-service CMEK, data-access audit logging, Security Command
  Center, private egress (Cloud NAT / no external IPs), no primitive-role service
  accounts, DNS query logging, curated-API allow-list (`CLOUD_EVIDENCE_GCP_API_ALLOWLIST`),
  private-only Cloud SQL, group-based org admin, and Terraform-state bucket integrity.
- **Read-only** (guardrail-wrapped AWS clients / GCP Proxy). Every check **degrades to
  a warning, never a false failure** when its API isn't accessible (e.g. not an
  Organizations management account, service not enabled). GCP org-scoped checks
  skip-with-warning when no `organization_id` is configured; across multiple GCP
  projects the org-scoped checks run once and project-scoped checks run per project.
- Emitted as their own evidence files so the findings flow into the NIST 800-53
  **benchmark** (`control-benchmark.json`), the **family roll-up** (a new `REFARCH`
  family), the **crosswalk**, **OSCAL**, and the **signed manifest** — but, being
  hardening *audits* rather than KSI obligations, they are intentionally **excluded
  from the KSI pass/fail rollup**.
- IAM catalog regenerated (`npm run gen:iam-actions`); all new read actions are
  covered by AWS `ReadOnlyAccess` / GCP viewer roles. 5 new tests (passing,
  fail-open/degraded, AMI-pattern, GCP org-skip, GCP org-present).

### Added — OSCAL schema validation + fixed the OSCAL document wrapper (OSC-1/2)
- **`core/oscal-validate.ts`** validates the OSCAL we emit against NIST's official
  JSON Schema using the already-vendored `ajv` — no new dependency, no runtime
  network. Schemas are committed offline (`docs/oscal/oscal_*_schema.v1.1.2.json`,
  assessment-results + ssp + poam) by **`scripts/extract-oscal-schemas.mjs`**
  (`npm run gen:oscal-schemas`), mirroring our "commit data, validate offline" pattern.
- The orchestrator validates `assessment-results.json` after emitting it (under the
  signed manifest); reports any errors and fails the run under `--strict-schema`.
- **Bug fix (surfaced by OSC-1):** the emitter now wraps the document in the
  required top-level `{ "assessment-results": … }` key — previously it wrote the
  inner object directly, which is **not** a schema-valid OSCAL document and would
  be rejected by NIST tooling / Paramify. Emitted docs now pass NIST schema
  validation. 4 validator tests + updated emitter tests.

### Added — Organization-grade cloud inventory (FedRAMP workbook + full asset inventory)
A complete cloud asset inventory for any org, not just FedRAMP — enabled by
`--inventory-workbook` (env `CLOUD_EVIDENCE_INVENTORY_WORKBOOK`) or the fast
`--inventory-only`. Emits, all under the signed manifest:
`inventory.json` (rich superset, source of truth), `inventory-workbook.{csv,xlsx}`
(FedRAMP **Appendix M** 25-column projection), `inventory-oscal.json` (OSCAL
inventory-items), `inventory-cmdb.json` (ServiceNow/CSDM CI records),
`inventory-diff.json` (run-over-run change tracking), and `inventory-cost.json`
(month-to-date cost by service).

- **Generic discovery backbone** (breadth = *every* resource type): AWS
  `providers/aws/discover.ts` (Config Advanced Query → Resource Explorer → Tagging
  API fallback chain) and GCP `providers/gcp/discover.ts` (Cloud Asset Inventory
  `searchAllResources`); merged with per-service **depth enrichers** via
  `dedupeAssets`.
- **Depth enrichers** (`providers/aws/inventory-assets.ts`): EC2(+ENI IP/MAC), EBS,
  RDS, S3, Lambda, ELBv2, DynamoDB, ECR, EKS, CloudFront — with multi-region sweep
  (global-once), security-group **network exposure** (open-to-internet ports), S3
  **public-access + encryption/KMS**, and **SSM Inventory** OS enrichment.
- **Rich data model + FedPy-native enrichment** (`core/inventory-workbook.ts`):
  lifecycle (created/state/**EOL**), security (KMS/encryption/exposure), ownership
  (tag-driven env/criticality/cost-center + **required-tag governance**), **scan
  reconciliation** vs our own VDR evidence, **KSI-finding cross-linking**, **data
  classification** (tags + AWS **Macie**), a **relationship graph** (`edges`), and
  a dependency-free `.xlsx` writer (`zlib.crc32` + inline-string OOXML).
- **Cost** (`providers/aws/inventory-cost.ts`): month-to-date by service via Cost
  Explorer (honest service-level summary). **Change tracking** + **OSCAL/CMDB**
  emitters in `core/inventory-emit.ts`. Tracker collector-runs view surfaces the
  inventory headline.
- All new SDK clients are read-only + guardrail-wrapped. Field mapping is clean-room
  from the Apache-2.0 reference designs (aws-samples / google) per the Path A
  licensing decision. ~50 inventory unit tests; design in
  `research/reports/12-inventory-completeness.md`.

### Added — turn the four deferred in-collector TODOs into real detectors
- **AWS Security Lake** (MLA-OSM): `collectMlaOsm` now probes `securitylake:ListDataLakes`
  (+ `ListSubscribers`) directly — a configured data lake counts as SIEM plumbing and
  grounds the Security Lake alternative-satisfier. Added `@aws-sdk/client-securitylake`
  + a read-only auth factory.
- **AWS EKS service mesh** (SVC-VCM): `collectSvcVcm` enumerates EKS clusters and their
  managed add-ons (`eks:ListClusters` + `eks:ListAddons`) and detects mesh add-ons
  (istio/linkerd/cilium/appmesh/consul); the Istio/Linkerd alternative-satisfier is now
  evidence-grounded instead of "deferred", pointing Helm-installed-mesh validation at the
  K8s collector.
- **GCP deletion events** (SVC-RUD): `collectSvcRud` queries Cloud Audit Logs
  (`logging.entries.list`) over a 90-day window for delete methods (storage/SQL/KMS/
  BigQuery/Compute) and reports real counts + samples, replacing the "sample query needed"
  placeholder. Degrades to a warning on permission/availability error.
- **IAM-permission auto-inventory**: `scripts/extract-iam-actions.mjs` +
  `docs/iam-actions.generated.json` (137 AWS actions / 39 services, 42 GCP roles) statically
  derive the permissions the code references — turning the catalog's "future enhancement"
  note into real, unit-tested tooling (`npm run gen:iam-actions`, `--check` for CI drift).

## [0.2.0] - 2026-05-28

### Changed — documentation accuracy
- Refreshed stale docs to match the shipped code: `cloud-evidence/README.md`
  (was "35+ KSIs / Phase 1 — IAM only"; now reflects 63 KSIs / 44 cloud collectors
  / 223 requirements + level selector + benchmark), `tracker/README.md` (evidence
  uploads / 2FA / RBAC / audit search / backup are shipped, not "out of v0.1"),
  `ARCHITECTURE.md` (test counts 396/99, correct workflow filenames, benchmark +
  ledger in the pipeline), and a status banner on `GAP-ANALYSIS.md` noting §1–§12
  are largely implemented.

### Added — Deno runtime support for the collector
- The cloud-evidence collector now runs on **Deno 2.8+** in addition to Node and Bun.
  npm dependencies resolve from the existing `node_modules`; Deno's secure-by-default
  model needs explicit permission flags, bundled as `collect:deno` / `verify:deno`
  npm scripts (`--allow-read,-env,-sys,-net,-write` for collection; add `--allow-run`
  only for the optional RFC 3161 `openssl` timestamp — Ed25519 signing uses `node:crypto`).
  Verified on Deno 2.8.1: a full dry-run plans all 44 KSIs and the offline control
  benchmark + `verify` run clean. `.tool-versions` and RUNBOOK updated. Bun remains
  the production recommendation.

### Added — NIST 800-53 control benchmark (Low / Moderate / High, for both 20x and Rev5)
- **`core/control-benchmark.ts` + `control-benchmark.json`:** every run now rolls the cloud
  findings UP to NIST 800-53 controls and scores each control at the chosen impact level, so a
  user can benchmark their cloud infrastructure against the baseline. Per-control status is
  `satisfied` / `partially-satisfied` / `not-satisfied` / `not-assessed`, derived from the
  findings that map to it (via each finding's / file's `nist_controls`); awareness-only
  attestations are listed but never satisfy a control on their own. `totals` report both
  `assessed_pass_rate` (of controls with evidence) and `baseline_coverage_rate` (of the whole
  in-scope set).
- **Two framings (`--framework`, env `CLOUD_EVIDENCE_FRAMEWORK`, default `20x`):**
  `20x` scores only the controls the evaluated 20x KSIs/FRRs reference; `rev5` scores the full
  NIST SP 800-53B Rev5 baseline for the level (Low 149 / Moderate 287 / High 370 controls),
  honestly surfacing which baseline controls have automated cloud evidence vs. which still need
  manual assessment.
- **Committed baseline membership** (`docs/nist-r5-baselines.generated.json`) + reproducible
  extractor (`scripts/extract-nist-baselines.mjs`) sourced from NIST's official OSCAL
  resolved-profile catalogs (usnistgov/oscal-content). No network at runtime; re-run to refresh.
- Orchestrator emits the benchmark after the family roll-up (covered by the signed manifest),
  records a `control_benchmark.complete` ledger event, and adds `framework` to the run summary.
  21 new unit tests in `tests/core/control-benchmark.test.ts`.

### Added — Completeness, NIST grounding, production hardening, Bun runtime
- **Corrected KSI count to 63** (was 60): `KSI-CSX-SUM/MAS/ORD` live under the `FRR.KSI`
  family and were mis-classified — they are KSIs. Registry now reports 63 KSIs; a
  completeness regression test asserts 63 KSIs + **zero generic-stub gaps** (every one of
  the 223 requirements resolves to a collector, the aggregator/meta, a specific playbook,
  or awareness-only). Added specific playbooks for the 6 previously-generic KSIs
  (CSX-MAS/ORD, PIY-RES/RIS/RSD/RVD).
- **NIST 800-53 Rev5 enrichment** (`core/nist-r5.ts` + `docs/nist-r5-controls.generated.json`
  from the GovReady r5 dataset): High-derived findings now carry official Rev5 control
  names (e.g. "ra-5 — Vulnerability Monitoring and Scanning") as grounding evidence.
- **Production-hardening layer:** `core/run-ledger.ts` (append-only JSONL audit trail of
  every action + outcome + timing, crash-durable → `out/run-ledger.jsonl`), `core/run-lock.ts`
  (prevents overlapping runs clobbering the same out dir; TTL + PID-liveness; auto-released on
  exit), `core/rate-control.ts` (token bucket + AIMD adaptive concurrency on throttle + TTL
  in-run memoization). Orchestrator records run.start / per-collector run / run.complete and
  surfaces ledger + throttle telemetry in the run summary.
- **Bun runtime for the collector** (`collect:bun` / `verify:bun`, `.tool-versions`): the
  sqlite-free collector runs on Bun 1.3+ (recommended for production — native TS, faster I/O);
  verified end-to-end at High tier. Node + tsx remains the default; the tracker stays on Node.

### Added — FedRAMP 20x full-level coverage (Low / Moderate / High)
Expands the collector from the 35 implemented KSIs toward the full **223-requirement**
FedRAMP 20x set (60 KSI indicators + 163 FRR requirements) with a setup-time impact-tier selector.

- **Impact-level selector**: `impact_level: low|moderate|high` in `config.yaml` + `--impact-level`
  CLI flag (env `CLOUD_EVIDENCE_IMPACT_LEVEL`). Low/Moderate come from the 20x machine-readable
  data; **High is DERIVED from the NIST 800-53 Rev5 baseline** via each requirement's `controls[]`
  and always labeled `derived-rev5` (or `derived-rev5-pending` when there's no control to anchor).
- **Requirement registry** (`core/requirements-registry.ts`) + reproducible extractor
  (`scripts/extract-frmr-requirements.mjs`) producing `docs/frmr-requirements.generated.json`.
- **Process-artifact tracker** (`core/process-artifact-tracker.ts`): emits signed, schema-valid,
  OSCAL-mapped, LLM-readable `scope: PROCESS` evidence for the ~99 governance requirements —
  artifact + attestation register, SLA/deadline monitoring (`core/bizdays.ts`), and
  alternative-satisfier detection. Requirements that obligate FedRAMP/agency/3PAO are tracked as
  **awareness-only** and excluded from the provider's pass/fail rollup.
- **Requirement playbooks** (`core/requirement-playbooks.ts`): 174 per-requirement playbooks with
  concrete artifacts, practical FedRAMP-aligned remediation steps, real vendor alternative
  satisfiers (Vanta/Drata/Paramify, KnowBe4, HackerOne/Bugcrowd, ServiceNow/Jira, PagerDuty,
  Wiz/Tenable/Snyk, CMVP/CloudHSM), and 38 SLA windows.
- **UCM crypto collectors** (`providers/{aws,gcp}/crypto.ts`, registered as `KSI-AFR-UCM`):
  read-only FIPS/CMVP validation of KMS/ACM/TLS against a CMVP cert reference table, with
  per-level obligation strength (Low MAY / Moderate SHOULD / High MUST).
- **VDR modules** (`core/kev-feed.ts`, `vdr-ledger.ts`, `vdr-report.ts`): CISA KEV feed (offline-cacheable),
  normalized vulnerability ledger with VDR-TFR-* SLA day-tables, and a breach summary.
- Deep per-requirement analysis for all 188 gap requirements in
  `cloud-evidence/docs/RSI-COVERAGE-ANALYSIS.md` + `docs/analysis/*.md`.
- Schema + envelope gained `impact_level`, `applicable_key_word`, `actor_scope`, `level_source`,
  `category`, `family`, `awareness_only` (all ajv-validated). Read-only guardrails unchanged.
- **7 KSI hybrid collectors** (`providers/{aws,gcp}/ksi-hybrids.ts`): read-only cloud signals for
  KSI-CMT-RVP, INR-AAR, INR-RPI, RPL-ARP, RPL-RRO, SCR-MIT, SVC-PRR.
- **VDR live-scan collectors** (`providers/{aws,gcp}/vdr-scan.ts`, `KSI-AFR-VDR`): Inspector v2 /
  Container Analysis → the VDR ledger + CISA KEV join + SLA-breach detection.
- **ADS / MAS / SCG automated signals** wired into the orchestrator (env-gated, read-only):
  Trust-Center reachability probe, assessment-scope-drift reconciliation, Secure-Config-Guide diff.
- **Family roll-up** (`core/family-rollup.ts`, `family-rollup.json`): per-family pass-rate posture,
  awareness items excluded.
- New third-party detector rules (Okta/Entra, Wiz/Prisma/Orca/Tenable/Snyk, Terraform Cloud/ArgoCD,
  Vanta/Drata, KnowBe4, HackerOne, PagerDuty, Sigstore) so alternative satisfiers auto-detect.

### Fixed — Hardening pass #3 (all-severity error-handling sweep, 2026-05)
Resolved every remaining finding (high → info) from the error-handling audit, in four batches:

**Batch 1 — collector granularity (cloud-evidence):**
- Converted every bare `catch {}` / `catch (e) { warnings.push(e.message) }` in the AWS
  `data.ts`/`iam.ts`/`config.ts` and **all 9 GCP collectors** (95 catches) to
  `diagnoseAwsError` / `diagnoseGcpError` / `warnIfActionable` — warnings now name the
  exact IAM action or GCP role (e.g. `compute.instances.list (roles/compute.viewer)`).
- Pagination loops (Lambda `ListFunctions`, IAM SSO/identity-store, 4 IsTruncated loops)
  hardened with repeated-marker detection + a `MAX_PAGINATION_ITERATIONS` cap.
- K8s ClusterRoleBinding parsing null-safety; EKS inventory filters undefined names.

**Batch 2 — core robustness (cloud-evidence):**
- `writeFileSafe` / `mkdirSafe` translate `ENOSPC`/`EACCES`/`EROFS`/`EMFILE` into actionable
  messages instead of opaque stack traces mid-run. `core/orchestrator.ts`.
- `pva-run-summary.json` now carries explicit `failed_ksis` + `schema_invalid_ksis` arrays;
  the PVA collector records `parse_error_ksis` for corrupt evidence files.
- Signing key: loose file permissions (group/world-readable) warn; malformed PEM and
  `EACCES` produce clear errors. `verifyRun` no longer throws on a corrupt/unreadable
  manifest or signature — it returns an error result. `core/sign.ts`.
- Paramify + tracker push gained `withRetry` (5xx/429/network) with URL-in-error reporting;
  ticket-push wraps the 6 previously-silent `JSON.parse` sites; SIEM/webhook errors now
  surface `ECONNREFUSED`/`ETIMEDOUT` codes. Plugin-loader survives an unreadable dir.

**Batch 3 — server robustness (tracker):**
- Input validation: token name length, `collector-runs` datetime + integer coercion,
  invalid-JSON guards (signup/login/tokens/admin/collector-runs), password upper-bound
  (scrypt CPU-DoS guard), domain/user-id `NaN` guards.
- CSRF middleware rejects duplicated (comma-joined) `X-CSRF-Token` headers explicitly.
- Rate-limit falls back to the TCP peer address when proxy headers are absent (no shared
  `unknown` bucket). Attachment downloads use RFC 5987 `filename*` Content-Disposition.
- Backup checkpoints the WAL before snapshotting; restore validates the SQLite magic header
  before clobbering, writes atomically (temp + rename), and clears stale `-wal`/`-shm`
  sidecars. `db()` sets `busy_timeout`, runs a startup health check, and gives an actionable
  open-failure message.

**Batch 4 — regression tests:** +13 cloud-evidence (push retry, sign hardening, PVA summary)
and +8 tracker (collector-run validation, CSRF duplicate, restore magic-header) tests.
Totals: **cloud-evidence 202** tests / **tracker 86** tests; both projects `tsc --noEmit` clean.

### Fixed — Hardening pass #2 (error handling + edge cases, 2026-05)
Following a focused error-handling / edge-case audit:
- **SECURITY: backup-code replay race.** `consumeBackupCode` did a read-modify-write
  that let two concurrent `/api/2fa/verify` requests accept the same backup code.
  Replaced with an atomic `INSERT OR IGNORE` into a new `totp_backup_codes_used`
  table (unique constraint). `tracker/server/totp.ts`, `db.ts`.
- **SECURITY: restore symlink overwrite.** `restore()` could write through a symlink
  at the DB path, overwriting arbitrary files. Now refuses symlink targets +
  gives a clear error on truncated gzip. `tracker/server/backup.ts`.
- **Unguarded `JSON.parse`** in IAM policy decode, diff-report run-id read, and Lambda
  resource-policy parse now wrapped — a malformed policy/file no longer crashes the run.
- **Exit code 4** when a collector throws an exception (vs. merely emitting failing
  findings, which stays exit 0 — findings are data). CI runners now catch broken collectors.
- **Pagination safety** on `ListUsers` (and pattern documented): max-iteration cap +
  repeated-marker detection to prevent infinite loops on broken API responses.
- **`core/error-diagnostics.ts`**: centralized AWS/GCP/K8s error → actionable-message
  translator. Access-denied warnings now name the exact IAM action / GCP role / K8s
  verb to grant. Wired into the orchestrator's per-collector catch + the K8s collector.
- **Startup-time integration validation**: missing env vars for `--llm-generate-prs`,
  `--ticket-push`, `--webhook-url`, `--push-paramify`, `--push-tracker` now abort
  BEFORE collection instead of wasting compute then erroring.
- **`config.yaml` schema validation**: malformed YAML / missing `frmr_version` /
  empty `aws.regions` fail fast with a clear message.
- **AWS/GCP auth-failure messages** now classify the error (access_denied / network /
  expired) and print the specific recovery command.
- **NaN guards** on `TRACKER_MAX_ATTACHMENT_MB` and audit-search `limit`/`offset`/`actor`
  query params (garbage input no longer cascades to `NaN`).
- **K8s API timeout** (`CLOUD_EVIDENCE_K8S_TIMEOUT_MS`, default 10s) so an unreachable
  cluster doesn't hang the run; clear "cluster unreachable" warning on timeout.
- **Client `ApiError`** class carrying HTTP status + server error code + Retry-After,
  so the SPA can distinguish 401/403/429/5xx and network failures. `fetch()` wrapped
  to surface offline errors clearly. `tracker/client/src/lib/api.ts`.
- **`docs/IAM-PERMISSIONS-CATALOG.md`**: authoritative per-collector AWS action / GCP
  role / K8s verb reference for least-privilege policy construction.

### Fixed — Hardening pass #1 (completeness audit, 2026-05)
- OpenAPI spec malformation (duplicate `components:` block) corrected.
- 2FA login bypass closed: enrolled users get a 5-min pre-auth session that only
  `/api/2fa/verify` can elevate. `sessions.preauth_until` column + middleware gating.
- `routes/audit.test.ts` now exercises the real `auditRoutes` module (was a stubbed
  re-implementation). Admin self-demotion + last-admin protection added.
- Provider smoke test (`tests/providers/smoke.test.ts`) added — caught 6 collectors
  emitting schema-invalid findings (missing gap/remediation/data); all fixed.
- 19 TypeScript strict-mode errors across both projects resolved.
- Dead code removed (`neutralizedByAlternative`, 6 legacy findings helpers, `backup.ts.bak`).

### Added — Phase A: Foundation
- Vitest test harness for `cloud-evidence`. 33 reference tests across retry, schema, log, sign, timestamp, oscal, crosswalk, coverage-check.
- `core/schema.ts`: ajv-based EvidenceFile JSON Schema validator. Wired into orchestrator with `--strict-schema` flag.
- `core/retry.ts`: decorrelated-jitter retry middleware applied to every AWS SDK call via `readonly-guardrail.ts`.
- `core/log.ts`: structured pino logger with pretty/JSON modes, redaction, file sink. Configurable via `LOG_LEVEL`, `LOG_PRETTY`, `LOG_FILE`.
- p-limit-based parallel KSI collection in the orchestrator. CLI: `--concurrency <N>`.

### Added — Phase B: Audit defensibility
- `core/sign.ts`: Ed25519 signing of every run's evidence files. Emits `manifest.json` + `manifest.sig`. Self-verifies after writing.
- `core/verify-cli.ts`: standalone verifier CLI (`npm run verify <out-dir>`).
- `core/timestamp.ts`: RFC 3161 trusted timestamps via `openssl ts -query` + configurable TSA (default DigiCert). Graceful degradation when openssl/TSA unavailable.
- `core/oscal.ts`: NIST OSCAL 1.1 Assessment Results emitter. CLI: `--oscal`.
- `core/coverage-check.ts`: hardened with 6 silent-failure detectors (missing accounts/projects/regions/KSIs, zero-finding KSIs, excess collector warnings); persists `coverage-report.json`.

### Added — Phase C: Coverage breadth
- `core/crosswalk.ts`: NIST 800-53 → SOC 2 / ISO 27001 / HIPAA mapping (28+ controls). CLI: `--crosswalk`.
- `core/aws-org-fanout.ts`: AWS Organizations multi-account fan-out with include/exclude filters + cross-account `AssumeRole`. CLI: `--aws-org-fanout`, `--aws-include`, `--aws-exclude`, `--aws-cross-account-role`.
- `core/readonly-guardrail-gcp.ts`: recursive Proxy guardrail for every GCP client method dispatched. Verb-prefix classifier (~50 read verbs / 30 write verbs).
- `core/powerpipe-emitter.ts`: auto-generated Powerpipe HCL mod (`out/powerpipe/`). One control per KSI; benchmarks grouped by domain. CLI: `--powerpipe`.
- Refactored every AWS collector's `setupCtx` to honor `c.aws?.auth` (enables fan-out).

### Added — Phase D: Tracker hardening
- `server/rate-limit.ts`: SQLite-backed sliding-window rate limiter. Per-IP / per-user / per-API-token policies; `X-RateLimit-*` + `Retry-After` headers.
- `server/csrf.ts`: double-submit cookie CSRF middleware. Skip-paths for bootstrap; client API helper auto-attaches `X-CSRF-Token`.
- `server/totp.ts`: RFC 6238 TOTP with 8 single-use SHA-256-hashed backup codes. `/api/2fa/*` routes. Verified against RFC 6238 canonical test vector.
- `server/rbac.ts`: 5 granular roles (viewer, contributor, ksi-owner, auditor, admin) + per-KSI-domain assignments + `requirePermission()` middleware. Audit-logged role changes. Idempotent SQLite migration relaxes legacy `users.role` CHECK.
- `server/backup.ts`: online SQLite `.backup()` + gzip; `npm run backup` / `npm run restore`. Integrity-check on restore.
- `server/routes/audit.ts`: filter/search/CSV-export endpoints over `audit_log`.

### Added — Phase E: K8s + advanced
- `core/auth/k8s.ts`: kubeconfig loader + per-context auth (kubectl-compatible).
- `providers/k8s/security.ts`: `collectK8sIamElp` enumerates cluster-admin bindings + custom wildcard ClusterRoles (KSI-IAM-ELP).
- `core/sbom.ts`: CycloneDX 1.4 + SPDX 2.3 SBOM parser; CVE correlation via `SBOM_NVD_INDEX_PATH`; cosign signature verification when `COSIGN_PUBLIC_KEY` is set. CLI: `--sbom-dir`.
- `core/anomaly.ts`: rolling-baseline anomaly detector (persistent regressions, spikes, new rules, KSI full-regression). Persists `anomaly-history.jsonl`. CLI: `--anomaly`.

### Added — Phase F: Ecosystem integrations
- `core/llm-pr-generator.ts`: Anthropic Claude API integration. Builds a strict-JSON-schema remediation PR per failing finding.
- `core/ticket-push.ts`: generic ticket-driver interface + GitHub Issues, Jira (Atlassian REST v3), ServiceNow (Now REST) drivers. Idempotent via stable `external_key`; create/update/reopen flows.
- `core/siem-push.ts`: OCSF v1.2 `compliance_finding` events. Batched POST; supports `ocsf-jsonl`, `ocsf-array`, `splunk-hec` wire formats.
- `core/webhook-push.ts`: Stripe-style HMAC-SHA256 signing over `<timestamp>.<body>`. Ships `verifySignature` helper.

### Added — Phase G: DX + polish
- `core/plugin-loader.ts`: opt-in custom KSI collector plugin system. CLI: `--plugins-dir`. Example plugin under `plugins.example/`.
- `tracker/server/openapi.yaml`: OpenAPI 3.0.3 spec for the tracker API. Served at `/api/openapi.yaml`.
- Initial `CHANGELOG.md` + `ARCHITECTURE.md`.

### Test counts
| Project          | Files | Tests |
|------------------|-------|-------|
| cloud-evidence   | 20    | 161   |
| tracker          | 6     | 48    |
| **Total**        | **26**| **209** |

## [0.1.0] - 2026-05-15
Initial scaffold: 37-KSI cloud-evidence collector + multi-user tracker over FRMR JSON.
