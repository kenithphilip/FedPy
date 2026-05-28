# KSI Deep Analysis & Evidence-Collection Script Plan

A rigorous, one-at-a-time analysis of all 63 FedRAMP 20x Key Security
Indicators from `FRMR.documentation.json` v0.9.43-beta. For each KSI:

1. **Statement** — verbatim from FRMR.
2. **Referenced FRD terms** — the FRMR-canonical definitions the KSI binds to.
3. **NIST 800-53 controls** — the rev5 controls the KSI traces to, with intent.
4. **Analysis** — what the KSI actually requires of a SaaS CSP running CI/CD
   on AWS+GCP with subprocessors.
5. **Classification** — `CLOUD` / `HYBRID` / `PROCESS` / `INHERITED` with
   explicit justification.
6. **Script plan** (only for `CLOUD` / `HYBRID`) — AWS and GCP collection
   modules: services, exact API calls, captured fields, validation rules,
   pass criteria, sample output envelope.

**Replaces the summary classification in [ksi-classification.md](ksi-classification.md).**
The summary doc remains useful as a single-table overview; this one is the
working spec for the collection script.

**Org profile baseline.** SaaS CI/CD, AWS + GCP IaaS, subprocessors in scope.

---

## Glossary of FRMR terms used throughout

These appear in many KSIs and shape interpretation:

- **Persistently** (FRD-PER) — "Occurring in a firm, steady way that is repeated over a long period of time in spite of obstacles or difficulties." Persistent activities must be intentional, understood, documented, and their status always knowable. For the script: **every evidence file must include a `cadence` field and a `last_run_at` timestamp**.
- **Persistent Validation** (FRD-PVL) — "The systematic and persistent process of validating that information resources within a cloud service offering are operating in a secure manner as expected by the goals and objectives outlined by the provider against FedRAMP Key Security Indicators." This is precisely what the script is.
- **Cloud Service Offering** (FRD-CSO) — the packaged service being authorized; scope is bounded by the Minimum Assessment Scope.
- **All Necessary Parties** (FRD-ANP) — at minimum FedRAMP and agency customers; possibly 3PAOs.
- **Federal Customer Data** (FRD-FCD) — content uploaded/stored by agencies; excludes provider-generated metadata/telemetry.
- **Information Resource** — broadly, anything that processes or stores data within the CSO (machine-based and human-based).
- **Machine-Based information resources** — automation-managed components (VMs, containers, functions, managed services). The script targets these.

---

## Output envelope schema (referenced throughout)

Every per-KSI evidence file uses this envelope:

```json
{
  "ksi_id": "KSI-XXX-YYY",
  "ksi_name": "...",
  "scope": "CLOUD | HYBRID",
  "frmr_version": "0.9.43-beta",
  "collected_at": "2026-05-26T20:00:00Z",
  "providers": [
    {
      "provider": "aws",
      "account_id": "123456789012",
      "region_set": ["us-gov-west-1", "us-gov-east-1"],
      "evidence": [
        { "source": "iam.GetAccountPasswordPolicy", "captured_at": "...", "data": { } }
      ],
      "findings": [
        { "rule": "iam.password.min_length>=15", "passed": true, "actual": 15, "expected": ">=15" }
      ]
    },
    { "provider": "gcp", ... }
  ],
  "rollup": { "pass": true, "warnings": ["..."], "missing_evidence": [] },
  "process_artifacts_required": ["..."]   // only for HYBRID
}
```

The `findings[]` array is where pass/fail lives. Each finding is a single
boolean test against a rule with a human-readable name. A KSI's `rollup.pass`
is `true` iff every `findings[].passed === true` across all providers AND
no `missing_evidence` entries.

---

## AFR — Authorization by FedRAMP

> Theme: A secure CSP seeking FedRAMP authorization will address all FedRAMP
> 20x requirements and recommendations, including government-specific
> requirements for maintaining a secure system and reporting on activities to
> government customers.

The AFR domain is **almost entirely process-driven**: each KSI demands
adherence to a FedRAMP-published process document (ADS, CCM, FSI, ICP, MAS,
PVA, SCG, SCN, UCM, VDR). The KSI evidence is **the existence and execution
of a plan/process**, not the cloud configuration that runs underneath it.

Cloud config *feeds* some AFR KSIs (e.g. CloudTrail data feeds the VDR
process; KMS choices feed UCM), but FedRAMP grades AFR on the documented
process, not on raw config data. This is why AFR has only one non-PROCESS
classification (AFR-PVA, HYBRID).

---

### KSI-AFR-ADS — Authorization Data Sharing

**Domain:** AFR · **Scope:** PROCESS

**Statement.** Determine how authorization data will be shared with all necessary parties in alignment with the FedRAMP Authorization Data Sharing (ADS) process and persistently address all related requirements and recommendations.

**Referenced FRD terms.**
- **All Necessary Parties** (FRD-ANP) — FedRAMP + agency customers minimum.
- **Authorization data** (FRD-AUD) — "the collective information required by FedRAMP for initial and ongoing assessment and authorization of a cloud service offering, including the authorization package."
- **Persistently** (FRD-PER).

**NIST 800-53 controls (9).** `ac-3` (access enforcement), `ac-4` (information flow), `au-2` / `au-3` / `au-6` (audit events, content, review), `ca-2` (assessments), `ir-4` (incident handling), `ra-5` (vuln scanning), `sc-8` (transmission protection). The control set spans access, audit, and transmission integrity — appropriate for a data-sharing process.

**Analysis.** ADS is the FedRAMP process for how a CSP shares its authorization package (SSP, POA&Ms, monthly continuous monitoring artifacts, OARs, etc.) with FedRAMP and agency customers. The FRR-ADS requirements (see `FRR.ADS` in the JSON, 20 requirements across CSO/UTC/TRC/CSL/CSX actor labels) detail exactly what must be published: a public trust center or marketplace listing with specific content, machine-readable authorization data, customer-portal mechanics for authenticated artifacts, and notifications when the package changes. **The KSI evidence is the trust center URL, the contents published there, and the process by which it stays current.** Cloud config (S3 buckets backing a trust center, CloudFront, ACM cert) supports the *implementation* of the trust center but doesn't satisfy the KSI on its own — what FedRAMP grades is the documented content + access policy.

**Classification — PROCESS.** Evidence lives in: (1) the public trust-center URL and its contents, (2) the documented intake/publication workflow, (3) ADS plan document, (4) a log of who you've notified about each authorization-data update.

**No script plan.** Cloud config that backs the trust center is collected via other KSIs (SVC-SNT for TLS, MLA-LET for the access logs, IAM-AAM for who can publish). The user-entered tracker fields for KSI-AFR-ADS should be: trust-center URL, ADS plan document URL, evidence URL pointing at a recent change-notification log.

---

### KSI-AFR-CCM — Collaborative Continuous Monitoring

**Domain:** AFR · **Scope:** PROCESS

**Statement.** Maintain a plan and process for providing Ongoing Authorization Reports and Quarterly Reviews for all necessary parties in alignment with the FedRAMP Collaborative Continuous Monitoring (CCM) process and persistently address all related requirements and recommendations.

**Referenced FRD terms.**
- **All Necessary Parties** (FRD-ANP).
- **Quarterly Review** (FRD-QTR) — "A regular synchronous meeting hosted by a FedRAMP Authorized cloud service provider for agency customers, aligned to the requirements and recommendations in the FedRAMP Collaborative Continuous Monitoring process."
- **Persistently** (FRD-PER).

**NIST 800-53 controls.** None directly mapped — CCM is a FedRAMP-program-level KSI without a direct NIST control trace.

**Analysis.** CCM is the cadence — Ongoing Authorization Reports (OARs) at FedRAMP-defined intervals and quarterly synchronous reviews with agency customers (see FRR.CCM, 24 requirements). Evidence is: (1) the CCM plan, (2) calendar invites + minutes for quarterly reviews, (3) OAR submissions on schedule, (4) attendance records, (5) action-item tracking after each review. None of this is cloud-config; it is a recurring meeting and reporting practice.

**Classification — PROCESS.** Tracker fields: CCM plan URL, OAR submission cadence (timeframe), evidence URL pointing at most recent quarterly review minutes + OAR delivery confirmation.

---

### KSI-AFR-FSI — FedRAMP Security Inbox

**Domain:** AFR · **Scope:** PROCESS

**Statement.** Operate a secure inbox to receive critical communication from FedRAMP and other government entities in alignment with FedRAMP Security Inbox (FSI) requirements and persistently address all related requirements and recommendations.

**Referenced FRD terms.**
- **FedRAMP Security Inbox** (FRD-FSI) — an email address meeting FSI requirements.
- **Persistently** (FRD-PER).

**NIST 800-53 controls.** None directly mapped.

**Analysis.** FSI requires a monitored, secure email address (TLS-in-transit, S/MIME or equivalent, monitored 24×7-ish per the FRR.FSI requirements). The inbox must be staffed, escalation must be defined, and there must be SLAs on triage. Evidence: the email address itself, a routing/escalation runbook, on-call rotation, recent triage records (sample emails handled). Cloud config plays a tiny role (DMARC/SPF/DKIM records, optional Workspace/M365 security policies), but the bar FedRAMP grades is the documented operation of the inbox, not the underlying DNS/email-gateway config.

**Classification — PROCESS.** Tracker fields: inbox address, routing runbook URL, on-call rotation source, sample triage log.

> *Aside:* if the user wants to demonstrate the SPF/DKIM/DMARC posture as supporting evidence (defensible against impersonation), that's a small Route 53 + GCP DNS query — but it's nice-to-have, not the KSI's primary evidence. Out of scope for the script.

---

### KSI-AFR-ICP — Incident Communications Procedures

**Domain:** AFR · **Scope:** PROCESS

**Statement.** Integrate FedRAMP's Incident Communications Procedures (ICP) into incident response procedures and persistently address all related requirements and recommendations.

**Referenced FRD terms.**
- **Incident** (FRD-INT) — 44 USC § 3552(b)(2) definition applied to federal customer data.
- **Persistently** (FRD-PER).
- **Vulnerability Response** (FRD-VLR).

**NIST 800-53 controls.** None directly mapped.

**Analysis.** ICP is the prescribed comms playbook for incidents that touch federal customer data: who FedRAMP gets notified, in what timeframe (FRR.ICP specifies the deadlines), through what channel, with what content. Evidence is the IR runbook with ICP steps integrated, a tabletop or real-incident execution log showing the steps were followed, and FSI escalation paths.

**Classification — PROCESS.** Tracker fields: IR runbook URL (with ICP section), last tabletop date, evidence of ICP-compliant communications from any real incident (or simulated).

> *Aside:* tools (PagerDuty, AWS Security Hub custom actions, SCC notifications) wire alerts into runbooks — that wiring is cloud config and is captured by `KSI-INR-RIR`. But for KSI-AFR-ICP specifically, what FedRAMP grades is the *runbook content* — does it mention FedRAMP notification at the right step?

---

### KSI-AFR-MAS — Minimum Assessment Scope

**Domain:** AFR · **Scope:** PROCESS

**Statement.** Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the scope of the cloud service offering to be assessed for FedRAMP authorization and persistently address all related requirements and recommendations.

**Referenced FRD terms.**
- **Cloud Service Offering** (FRD-CSO).
- **Persistently** (FRD-PER).

**NIST 800-53 controls (29).** `ac-1`, `ac-21`, `at-1`, `au-1`, `ca-1`, `cm-1`, `cp-1` / `cp-2.1` / `cp-2.8` / `cp-4.1`, `ia-1`, `ir-1`, `ma-1`, `mp-1`, `pe-1`, `pl-1` / `pl-2` / `pl-4` / `pl-4.1`, `ps-1`, `ra-1` / `ra-9`, `sa-1`, `sc-1`, `si-1`, `sr-1` / `sr-2` / `sr-3` / `sr-11`. The "-1" controls are *policy* controls — every NIST family's policy/procedure baseline. This signals MAS is the scoping doc that names which policies apply and to what.

**Analysis.** MAS is a written boundary: the system description, components in scope, data flows, trust boundaries, subprocessor map (heavy for this user), and inheritance claims from underlying CSPs (AWS, GCP). The MAS document is grade-A evidence; cloud-config inventories (PIY-GIV) *feed* the MAS but don't replace it. The classification "PROCESS" is firm because MAS is fundamentally a written scoping artifact — even with perfect inventory data, you still write the MAS.

**Classification — PROCESS.** Tracker fields: MAS document URL, version, last-reviewed date. The PIY-GIV inventory output should be referenced from the MAS doc.

---

### KSI-AFR-PVA — Persistent Validation and Assessment

**Domain:** AFR · **Scope:** **HYBRID**

**Statement.** Persistently validate, assess, and report on the effectiveness and status of security decisions and policies that are implemented within the cloud service offering in alignment with the FedRAMP 20x Persistent Validation and Assessment (PVA) process, and persistently address all related requirements and recommendations.

**Referenced FRD terms.**
- **Cloud Service Offering** (FRD-CSO).
- **Persistent Validation** (FRD-PVL) — "The systematic and persistent process of validating that information resources within a cloud service offering are operating in a secure manner as expected by the goals and objectives outlined by the provider against FedRAMP Key Security Indicators."
- **Persistently** (FRD-PER).

**NIST 800-53 controls.** None directly mapped.

**Analysis.** PVA is the meta-KSI that says: *you must continuously validate every other KSI*. The FRD-PVL definition is the literal job description of the cloud-evidence collection script we're designing. Evidence has two halves:

1. **Process half** — a documented PVA plan: which KSIs are validated, on what cadence (e.g. daily for IAM-MFA, weekly for CNA-IBP, quarterly for CED-RST), with what tooling, and who reviews the results.
2. **Operational half** — proof that the validation actually runs persistently. The script's own execution log (timestamps, success/failure of each module, drift between runs) is direct evidence. So is the tracker's `last_reviewed` field per KSI.

**Classification — HYBRID.** The PVA plan is a document (process); the validation runs are cloud-side (the script itself). The script must therefore emit a top-level **run summary** in addition to per-KSI evidence files.

#### Script plan — PVA

**Module:** `core/run-summary.ts → emitRunSummary()`

This isn't a per-provider module; it aggregates over the whole run.

| Captures | From | Purpose |
|---|---|---|
| `run_id` (uuid), `started_at`, `finished_at`, `frmr_version` | The orchestrator | Run identity |
| Per-KSI module: `executed`, `succeeded`, `duration_ms`, `evidence_path` | Each module's return | Execution proof |
| Per-KSI: `rollup.pass`, `findings_count`, `warnings_count` | Reading each evidence file | Status proof |
| Run-over-run diff: KSIs whose `rollup.pass` changed since the previous run | Comparing two runs | Drift detection |
| `cadence_target` per KSI, `cadence_actual_days_since_last_run` | PVA plan config (YAML) | Cadence compliance |

**Validation rules / pass criteria.**
- Every CLOUD/HYBRID KSI listed in `ksi-map.ts` produced an evidence file in this run.
- No KSI module raised an unhandled exception.
- `cadence_actual_days_since_last_run <= cadence_target` for every KSI.
- `runtime_total < runtime_budget` (default 60 min).

**Sample output (`out/pva-run-summary.json`):**

```json
{
  "run_id": "01J...",
  "started_at": "2026-05-26T19:00:00Z",
  "finished_at": "2026-05-26T19:42:11Z",
  "frmr_version": "0.9.43-beta",
  "modules": [
    {
      "ksi_id": "KSI-IAM-MFA",
      "executed": true,
      "succeeded": true,
      "duration_ms": 12830,
      "evidence_path": "out/KSI-IAM-MFA.json",
      "rollup_pass": true,
      "findings_count": 5,
      "warnings_count": 0,
      "cadence_target_days": 1,
      "cadence_actual_days_since_last_run": 1.02
    }
    /* ...37 entries... */
  ],
  "drift_since_previous_run": [
    { "ksi_id": "KSI-CNA-RNT", "previous_pass": true, "current_pass": false, "first_diff_finding": "ec2.security-group.0.0.0.0/0:22" }
  ],
  "cadence_violations": [],
  "rollup": { "all_modules_passed": false, "all_cadences_met": true }
}
```

**Process-side artifacts required** (tracker-side, not script):
- PVA plan document URL.
- Sign-off log on the run-summary (who reviewed, when).

---

### KSI-AFR-SCG — Secure Configuration Guide

**Domain:** AFR · **Scope:** PROCESS

**Statement.** Develop secure by default configurations and provide guidance for secure configuration of the cloud service offering to customers in alignment with the FedRAMP Secure Configuration Guide (SCG) process and persistently address all related requirements and recommendations.

**Referenced FRD terms.**
- **Cloud Service Offering** (FRD-CSO).
- **Persistently** (FRD-PER).

**NIST 800-53 controls.** None directly mapped.

**Analysis.** SCG is the *customer-facing* document explaining how an agency customer should securely configure your CSO when they use it: which features to enable, IAM patterns, networking guidance, what telemetry to send to the customer's own SIEM. For a CI/CD SaaS, this is the security configuration guide your customers get. The KSI is satisfied by publishing and maintaining this doc.

**Classification — PROCESS.** Evidence: the SCG itself (URL), version history, customer-visibility of the document. Cloud config informs the SCG's *content* (you describe default IAM trust policy, default network egress posture, etc.), but the deliverable is the doc.

---

### KSI-AFR-SCN — Significant Change Notifications

**Domain:** AFR · **Scope:** PROCESS

**Statement.** Determine how significant changes will be tracked and how all necessary parties will be notified in alignment with the FedRAMP Significant Change Notifications (SCN) process and persistently address all related requirements and recommendations.

**Referenced FRD terms.**
- **All Necessary Parties** (FRD-ANP).
- **Persistently** (FRD-PER).
- **Significant change** (FRD-SGC) — NIST SP 800-37 Rev. 2: "a change that is likely to substantively affect the security or privacy posture of a system."

**NIST 800-53 controls (17).** `ca-7.4`, `cm-3.4`, `cm-4`, `cm-7.1`, `au-5`, `ca-5`, `ca-7`, `ra-5` / `ra-5.2`, `sa-22` (unsupported components), `si-2` / `si-2.2`, `si-3`, `si-5`, `si-7.7`, `si-10` / `si-11`. Heavy on CM (change), CA (assessment), SI (system integrity).

**Analysis.** SCN is the FedRAMP process of telling FedRAMP + agency customers when you're about to make a change that affects security posture (new region, new subprocessor, encryption-algorithm change, architecture redesign). FRR.SCN details the criteria for "significant" and the lead times. Evidence is: (1) the SCN process doc, (2) the log of recent SCNs filed, (3) the criteria checklist for "is this change significant?", (4) integration with your change-management system (RFC ticket → SCN gate). Change-management tooling is cloud-ish (CloudTrail events show changes were made) but the KSI is the *notification* practice, not the change-execution.

**Classification — PROCESS.** Evidence: SCN process doc, sample SCN filings, criteria checklist embedded in RFC template.

---

### KSI-AFR-UCM — Using Cryptographic Modules

**Domain:** AFR · **Scope:** PROCESS

**Statement.** Ensure that cryptographic modules used to protect potentially sensitive federal customer data are selected and used in alignment with the FedRAMP 20x Using Cryptographic Modules (UCM) guidance and persistently address all related requirements and recommendations.

**Referenced FRD terms.**
- **Federal Customer Data** (FRD-FCD).
- **Persistently** (FRD-PER).

**NIST 800-53 controls.** None directly mapped — UCM is FedRAMP-process driven and traces through SC-12/SC-13 indirectly via the cloud-side KSIs.

**Analysis.** UCM is the documented rationale + inventory of cryptographic modules used to protect federal customer data — FIPS 140-3 (or 140-2 grandfathered) validated modules, their certificate numbers, the modes used, key lengths, key-management approach, and the mapping of modules to data classes ("federal customer data at rest in S3 is protected by AWS KMS using AES-256-GCM, FIPS 140-3 cert #XXXX"). Cloud-config evidence (KMS key inventory, cert inventory, TLS config) supports UCM, but UCM is *graded on the rationale document* — the question is "did you write down which modules you use and why", not "are the modules deployed."

**Classification — PROCESS.** Tracker fields: UCM rationale doc URL, last-reviewed date. Cloud-side supporting evidence comes from SVC-SNT (TLS), SVC-ASM (KMS/Secrets Manager), and IAM-SNU (non-user crypto material).

> *Aside:* the cloud-collection script *can* emit a supporting `KSI-AFR-UCM-supporting.json` file that lists every KMS key with its key spec + origin + rotation status, and every ACM cert with its signing algorithm. This becomes raw input for the UCM doc but doesn't satisfy the KSI on its own.

---

### KSI-AFR-VDR — Vulnerability Detection and Response

**Domain:** AFR · **Scope:** PROCESS

**Statement.** Document the vulnerability detection and vulnerability response methodology used within the cloud service offering in alignment with the FedRAMP Vulnerability Detection and Response (VDR) process and persistently address all related requirements and recommendations.

**Referenced FRD terms.**
- **Cloud Service Offering** (FRD-CSO).
- **Persistently** (FRD-PER).
- **Vulnerability** (FRD-VUL) — 6 USC § 650(25), broadly any weakness. Critically, this includes "gaps in Rev5 controls and 20x Key Security Indicators" — so a missing KSI is itself a vulnerability under FedRAMP's definition.
- **Vulnerability Detection** (FRD-VLD) — the systematic process: assessment, scanning, threat intel, VDP, bug bounties, supply-chain monitoring.
- **Vulnerability Response** (FRD-VLR) — tracking, evaluating, mitigating, monitoring, remediating, reporting.

**NIST 800-53 controls (42, the largest single mapping).** Heavy on `ra-*` (risk assessment, vuln scanning, all the sub-controls), `si-*` (system integrity, flaw remediation, malicious-code protection, system monitoring), `ir-*` (incident response), `ca-2/7/7.6` (assessments), `pm-3/5/31` (program management — investments, inventory, continuous monitoring strategy). The breadth indicates VDR ties together scanning, SIEM, IR, and program-level reporting.

**Analysis.** VDR is **the documented methodology**: the per-detection-channel cadence (IaC scans every commit, container scans on push, runtime vuln scans daily, infra config drift hourly, etc.), the severity-to-SLA mapping (critical = X days, high = Y days), the closing criteria, the metrics reported to FedRAMP. The KSI evidence is the **methodology document plus metrics on its execution**. Per-tool config (Inspector, ECR scanning, GuardDuty, SCC, Artifact Analysis) is in scope for OTHER KSIs (SCR-MON, MLA-EVC, IAM-SUS), but VDR itself is the documented strategy that ties them together.

**Classification — PROCESS.** Tracker fields: VDR methodology doc URL, recent metrics report (e.g. "MTTR by severity for the last 90 days"), references to the supporting cloud KSIs.

---

## CMT — Change Management

> Theme: A secure CSP will ensure that all changes are properly documented and configuration baselines are updated accordingly.

This domain has 4 KSIs covering change *logging*, the *immutable-redeploy*
pattern, *procedure review*, and *deployment-time validation*. Three of the
four have direct cloud-config evidence (LMC, RMV, VTD); only RVP is purely
review/process.

---

### KSI-CMT-LMC — Logging Changes

**Domain:** CMT · **Scope:** **CLOUD**

**Statement.** Log and monitor modifications to the cloud service offering.

**Referenced FRD terms.** *(none directly listed; uses the implicit `Information Resource`, `Machine-Based information resources`, and `Cloud Service Offering` terms.)*

**NIST 800-53 controls.** Per FRMR, this KSI does not have a populated control list — but the semantics traces to `au-2` (event logging), `au-3` (content of records), `au-12` (audit record generation), `cm-3.1` (automated change documentation), `cm-5.1` (auditing access enforcement for changes).

**Analysis.** This is the foundational change-audit-log KSI: every modification to the CSO — IAM policy update, security-group rule change, KMS key rotation, container image deploy, RDS parameter change, RBAC binding change, anything — must be captured in a tamper-resistant log. Critically, "modifications to the cloud service offering" means both **infrastructure changes** (cloud-control-plane events) and **application/configuration changes within the service** (your CI/CD product's own change log, IaC commits, app deploys). Both must be logged.

For a multi-cloud SaaS, evidence has three layers:
1. Cloud control-plane changes — CloudTrail (AWS) and Cloud Audit Logs (GCP).
2. App-deploy changes — your CI/CD product's own audit log (which you eat your own dog food on); evidence of immutability and access controls.
3. IaC source-of-truth — git commit history of your Terraform / CDK / Config Connector / Deployment Manager.

**Classification — CLOUD.** All three evidence layers are accessible via APIs or filesystem reads. No human-process artifact required beyond what's already in the configuration.

#### Script plan — CMT-LMC

**Modules:**
- `providers/aws/logging.ts → collectCmtLmcAws()`
- `providers/gcp/logging.ts → collectCmtLmcGcp()`

**AWS evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| CloudTrail | `cloudtrail.DescribeTrails`, `cloudtrail.GetTrailStatus` (each trail), `cloudtrail.GetEventSelectors` | Trail name, `IsMultiRegionTrail`, `IsOrganizationTrail`, `LogFileValidationEnabled`, S3 dest, KMS key, `IsLogging`, `EventSelectors[]` (mgmt + data events) | Verify a multi-region, org-wide trail exists with log-file validation on and recent activity. |
| CloudTrail | `cloudtrail.GetInsightSelectors` | Insight selectors enabled? | Anomalous-write detection. |
| S3 (per dest bucket) | `s3.GetBucketVersioning`, `s3.GetBucketPolicy`, `s3.GetBucketEncryption`, `s3.GetObjectLockConfiguration` | Versioning enabled, restrictive policy, SSE, Object Lock | Tamper-resistance. |
| Config | `config.DescribeConfigurationRecorders`, `config.DescribeDeliveryChannels`, `config.DescribeConfigurationRecorderStatus` | Recorder enabled, recording-mode "ALL", last-status-change | AWS Config records resource configurations alongside CloudTrail's events. |
| Organizations | `organizations.ListAccountsForParent` / `ListAccounts`, then for each account verify the org trail covers it | Coverage matrix | Tenant-scope sanity. |

**Captured fields per evidence item:**
```json
{
  "trail_arn": "...",
  "is_multi_region": true,
  "is_organization_trail": true,
  "log_file_validation_enabled": true,
  "is_logging": true,
  "kms_key_id": "arn:aws:kms:...",
  "s3_bucket": "...",
  "s3_versioning": "Enabled",
  "s3_object_lock_enabled": true,
  "s3_default_encryption": "aws:kms",
  "event_selectors": [ { "read_write_type": "All", "include_management_events": true, "data_resources": [...] } ],
  "insight_selectors": [ "ApiCallRateInsight" ],
  "last_log_delivery": "2026-05-26T18:55:00Z"
}
```

**GCP evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Cloud Logging | `logging.projects.sinks.list`, `logging.organizations.sinks.list` | Sinks routing `_Default` + `_Required` + audit log streams to long-term storage (BigQuery / GCS / log buckets) | Verify audit-log destinations and that `_Required` is preserved. |
| Cloud Logging | `logging.projects.locations.buckets.list` | Log buckets with retention + locked retention + CMEK | Tamper-resistance. |
| Resource Manager / Asset Inventory | `cloudasset.exportAssets` with `content_type=IAM_POLICY` and `RESOURCE` | Org-wide IAM + resource snapshot | Baseline for change diffing. |
| IAM Audit Logs config | `cloudresourcemanager.projects.getIamPolicy` + check **Audit Configs** (Data Access logs enabled) | Per-service data-access logging enabled (`DATA_READ`, `DATA_WRITE`) | Default is OFF; FedRAMP wants ON for in-scope services. |
| Service Usage | `serviceusage.services.list` | Enabled APIs (so we know which Data Access audit configs matter) | Coverage matrix. |

**Captured fields per evidence item:**
```json
{
  "project_id": "...",
  "sinks": [ { "name": "...", "destination": "bigquery.googleapis.com/projects/.../datasets/audit", "filter": "logName:cloudaudit.googleapis.com" } ],
  "log_buckets": [ { "name": "_Required", "retention_days": 400, "locked": true, "cmek_key": "..." } ],
  "iam_audit_configs": [ { "service": "allServices", "logTypes": ["ADMIN_READ","DATA_READ","DATA_WRITE"] } ],
  "data_access_logging_enabled_for": ["cloudkms.googleapis.com", "storage.googleapis.com", "iam.googleapis.com"],
  "last_audit_log_entry": "2026-05-26T18:54:11Z"
}
```

**Validation rules / pass criteria (findings).**

| Rule | Pass criterion |
|---|---|
| `aws.cloudtrail.org_trail_exists` | At least one trail with `IsOrganizationTrail=true`, `IsMultiRegionTrail=true`, `IsLogging=true`. |
| `aws.cloudtrail.log_file_validation` | All in-scope trails have `LogFileValidationEnabled=true`. |
| `aws.cloudtrail.dest_bucket_versioned_locked` | Destination buckets have versioning AND Object Lock or equivalent retention. |
| `aws.config.recorder_enabled` | A recorder exists with `recordingGroup.allSupported=true` (or comprehensive resource-type list) and `lastStatus=Success` within the last hour. |
| `gcp.audit.required_sink_preserved` | The `_Required` log bucket (or equivalent) has retention ≥ 400 days and is locked. |
| `gcp.audit.data_access_logging` | For every in-scope service, IAM Audit Config has `DATA_READ` + `DATA_WRITE` enabled. |
| `gcp.audit.recent_entry` | Last audit log entry across the org is within the last hour. |

**Pass rollup.** All rules above pass on every in-scope account/project. Any failure → `rollup.pass=false`.

**Process-side notes.** Cloud control-plane logs cover infra changes; **the user must point the script at their CI/CD-product's own audit-log export** (or skip it as a separate KSI). Recommend a config flag `app_audit_log_source` in the script's config file.

---

### KSI-CMT-RMV — Redeploying vs Modifying

**Domain:** CMT · **Scope:** **CLOUD**

**Statement.** Execute changes to machine-based information resources through redeployment of version controlled immutable resources rather than direct modification wherever reasonable.

**Referenced FRD terms.** *(uses `Information Resource`, `Machine-Based`, and the implied notion of version control.)*

**NIST 800-53 controls.** Not directly populated. Maps semantically to `cm-2` (baseline config), `cm-2.2` (automation support for accuracy/currency), `cm-3` (configuration change control), `cm-3.5` (automated security response — testing/validation), `sa-10` (developer config management).

**Analysis.** This codifies the "immutable infrastructure" pattern: changes happen by replacing rather than mutating. Concretely: container images are immutable + content-addressable; you redeploy a new image rather than `apt update` inside a running container; EC2/VM changes happen via new ASG/MIG instances launched from a new AMI/image, not by SSH-ing in to patch; Lambda/Cloud Functions are deployed from versioned packages; database schema changes are migrations through CI/CD, not ad-hoc `psql` against prod.

The "wherever reasonable" qualifier is real — some changes (RDS parameter group flips, KMS key alias retargeting) are inherently mutations. The KSI doesn't demand 100%, but it demands a default of immutability with documented exceptions.

**Classification — CLOUD.** Evidence is observable in registries (image tags + retention policies), launch templates (versioning), and deploy systems (CodePipeline / Cloud Build / Cloud Deploy revision history).

#### Script plan — CMT-RMV

**Modules:**
- `providers/aws/supplychain.ts → collectCmtRmvAws()`
- `providers/gcp/supplychain.ts → collectCmtRmvGcp()`

**AWS evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| ECR | `ecr.DescribeRepositories`, then `ecr.GetRepositoryPolicy`, `ecr.DescribeImageScanFindings` | Each repo: `imageTagMutability` (must be `IMMUTABLE`), `imageScanningConfiguration`, lifecycle policy | Image-tag immutability + scan-on-push. |
| ECR | `ecr.DescribeImages` (sample) | Image digest, pushed-at, immutability status | Sanity. |
| EC2 | `ec2.DescribeLaunchTemplates`, `ec2.DescribeLaunchTemplateVersions` | Launch-template versioning + default-version pointer | Verify deploys are via versioned templates. |
| Auto Scaling | `autoscaling.DescribeAutoScalingGroups` | ASGs reference launch templates by version (not `$Latest` if you want immutability assurance) | Deploy hygiene. |
| CodeDeploy / CodePipeline | `codepipeline.ListPipelines`, `codepipeline.GetPipelineState` | Pipeline definitions, stages, approval gates | Deploy automation evidence. |
| Lambda | `lambda.ListFunctions` (paginated), `lambda.ListVersionsByFunction` (sample) | `PackageType`, code signing, version history | Functions deploy via versioned packages, not in-place edits. |
| CloudFormation | `cloudformation.DescribeStacks`, `cloudformation.DescribeStackEvents` | Stack template references, recent events | IaC-driven changes. |
| Systems Manager | `ssm.GetInventory` (optional) | Patches applied via SSM patch baseline, not manual | Patch-via-redeploy or controlled patch baseline. |

**Captured fields:**
```json
{
  "ecr_repositories": [
    { "name": "frontend", "image_tag_mutability": "IMMUTABLE", "scan_on_push": true, "lifecycle_policy_present": true }
  ],
  "launch_templates": [ { "id": "lt-...", "default_version": 7, "versions_total": 7 } ],
  "asgs_pinning_specific_version": ["asg-prod-web", "asg-prod-api"],
  "asgs_using_latest": [],
  "pipelines": [ { "name": "deploy-prod", "stages": ["source","build","test","deploy"], "manual_approval_stage": "deploy" } ],
  "lambda_functions_with_code_signing": 42,
  "lambda_functions_total": 50
}
```

**GCP evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Artifact Registry | `artifactregistry.repositories.list`, `artifactregistry.dockerImages.list` (sample) | Repo `format`, `mode` (STANDARD/REMOTE/VIRTUAL), tag immutability (via policy bindings prohibiting `artifactregistry.tags.update`) | Image immutability. |
| Compute | `compute.instanceTemplates.list`, `compute.regionInstanceGroupManagers.list`, `compute.instanceGroupManagers.list` | Templates exist, MIGs reference specific template URIs | Versioned deploys. |
| Cloud Build | `cloudbuild.projects.builds.list` (recent), `cloudbuild.projects.triggers.list` | Recent successful build provenance, trigger configs | Deploy automation. |
| Cloud Deploy | `clouddeploy.deliveryPipelines.list`, `clouddeploy.releases.list` (per pipeline) | Pipelines + recent releases with rollout policies | Controlled progressive deploys. |
| Cloud Functions / Cloud Run | `run.namespaces.services.list`, `cloudfunctions.functions.list` | Service revisions, traffic splits, container image refs | Versioned deploys. |
| Binary Authorization | `binaryauthorization.projects.getPolicy`, `binaryauthorization.attestors.list` | Policy mode + attestor list | Enforces only attested images run. (Strong RMV evidence.) |

**Captured fields:**
```json
{
  "artifact_registry": [ { "repository": "us-central1-docker.pkg.dev/proj/app", "format": "DOCKER", "tag_mutability_locked": true } ],
  "instance_templates": [ { "name": "web-v23", "kms_key": "..." } ],
  "migs": [ { "name": "web-prod", "instance_template": "web-v23", "version_count": 1 } ],
  "cloud_run_services": [ { "name": "api", "revision_count": 12, "current_traffic": [ { "revision": "api-00012-abc", "percent": 100 } ] } ],
  "binary_authorization_policy_mode": "ENFORCED_BLOCK_AND_AUDIT_LOG",
  "binary_authorization_attestors": ["projects/.../attestors/prod-attestor"]
}
```

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.ecr.tag_mutability=IMMUTABLE` | Every prod ECR repo is IMMUTABLE. |
| `aws.asg.pins_specific_version` | ASGs in prod reference a specific launch-template version, not `$Latest`. |
| `aws.codepipeline.has_test_and_approval_stages` | Each prod pipeline has at least one test and one approval stage. |
| `gcp.artifactregistry.tag_immutability_locked` | Org-policy or repo-policy locks tag mutation in prod. |
| `gcp.cloudrun.revision_pinning` | Cloud Run prod services pin traffic to specific revisions, not `LATEST`. |
| `gcp.binaryauthorization.policy_enforced` | Binary Authorization policy is `ENFORCED_BLOCK_AND_AUDIT_LOG`. |

**Warnings (not failures).** Any service detected that's known to require mutation (RDS / Cloud SQL parameter groups, KMS aliases) is logged as a `warning` with the rationale.

---

### KSI-CMT-RVP — Reviewing Change Procedures

**Domain:** CMT · **Scope:** PROCESS

**Statement.** Persistently review the effectiveness of documented change management procedures.

**NIST 800-53 controls.** Not populated. Maps to `cm-3`, `cm-3.6`, `ca-7` (continuous monitoring).

**Analysis.** This is a process-effectiveness review. Evidence: documented review cadence, minutes from the last few reviews, action items, follow-through. There's no cloud API that proves "your change procedures are effective" — it's a deliberate review activity.

**Classification — PROCESS.** Tracker fields: review cadence, last review date, link to review minutes.

> *Indirect cloud signal:* the script's `KSI-CMT-LMC` and `KSI-CMT-RMV` outputs are downstream consumers of the change procedures. If those KSIs show widespread `$Latest` use or unattested images, that's evidence the procedures aren't effective. The reviewer should bring those reports to the review meeting.

---

### KSI-CMT-VTD — Validating Throughout Deployment

**Domain:** CMT · **Scope:** **HYBRID**

**Statement.** Automate persistent testing and validation of changes throughout deployment.

**NIST 800-53 controls.** Not populated. Semantically: `cm-3.2` (test/validate/document changes), `cm-4`/`cm-4.1` (impact analysis), `sa-11`/`sa-11.1` (developer testing), `si-7` / `si-7.1` (software integrity, integrity checks).

**Analysis.** Every change must traverse automated validation gates: unit tests, integration tests, SAST, SCA / SBOM, container scanning, IaC scanning (tfsec / Checkov / cfn-nag), policy-as-code (OPA / Sentinel / GCP Config Validator), license checks, and pre-deploy security gates (Binary Authorization attestations on GCP; signed-image enforcement on AWS). The HYBRID classification reflects: the **gates themselves are configured in cloud** (CodePipeline, CodeBuild, Cloud Build, Cloud Deploy, Inspector findings used as gates), but the **test definitions** (what is asserted in the unit/integration tests, the SAST rule set) live in your source repo and require process review to vouch they're adequate.

For the user — a CI/CD SaaS — there's a strong meta-evidence opportunity: *your own product is the strongest VTD evidence you can produce*. The script should collect both cloud-native pipeline evidence AND a snapshot of your product's own pipeline definitions.

**Classification — HYBRID.** Cloud gates are scriptable; assertion-content adequacy is process-reviewed.

#### Script plan — CMT-VTD

**Modules:**
- `providers/aws/supplychain.ts → collectCmtVtdAws()`
- `providers/gcp/supplychain.ts → collectCmtVtdGcp()`

**AWS evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| CodePipeline | `codepipeline.GetPipeline` (each), `codepipeline.GetPipelineState` (recent runs) | Stage list, action types per stage (CodeBuild test/scan, manual approval, deploy), recent run statuses | Gate inventory. |
| CodeBuild | `codebuild.BatchGetProjects` | Buildspec source pointer, env vars (no secrets), source identifier | Reveals which scanners are invoked. |
| Inspector | `inspector2.GetConfiguration`, `inspector2.ListFindings` (count by severity) | Auto-enabled, scope (EC2/ECR/Lambda), recent findings | Pre-deploy scanning. |
| Signer / Code Signing | `signer.ListProfiles`, `lambda.GetFunctionCodeSigningConfig` (sample) | Lambda code-signing required? | Code-integrity gate. |
| EventBridge | `events.ListRules` filtered to CodePipeline state-change rules | Alerting on failed pipelines | Failure visibility. |

**Captured fields:**
```json
{
  "pipelines": [
    {
      "name": "deploy-prod",
      "stages": [
        { "name": "Source", "actions": [ { "type": "Source/AWS/CodeStarSourceConnection" } ] },
        { "name": "Build", "actions": [ { "type": "Build/AWS/CodeBuild", "buildspec_test_command": "npm test", "buildspec_includes_sast": true } ] },
        { "name": "Scan", "actions": [ { "type": "Invoke/AWS/Lambda", "purpose": "inspector-findings-gate" } ] },
        { "name": "Approve", "actions": [ { "type": "Approval/Manual" } ] },
        { "name": "Deploy", "actions": [ { "type": "Deploy/AWS/CodeDeployToECS" } ] }
      ]
    }
  ],
  "inspector": { "enabled_resource_types": ["EC2","ECR","LAMBDA"], "critical_findings_last_7d": 0 },
  "lambda_code_signing_required_count": 38,
  "lambda_total_count": 40
}
```

**GCP evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Cloud Build | `cloudbuild.projects.triggers.list`, `cloudbuild.projects.builds.list` (recent) | Trigger definitions (substitutions, steps), recent build outcomes | Build pipelines. |
| Cloud Deploy | `clouddeploy.deliveryPipelines.list`, `clouddeploy.releases.list`, `clouddeploy.rollouts.list` | Pipeline targets, approval gates per target, recent rollout statuses | Progressive delivery gates. |
| Binary Authorization | `binaryauthorization.projects.getPolicy` | Policy mode, attestor requirements per environment | Pre-admission gate. |
| Artifact Analysis (Container Analysis) | `containeranalysis.notes.list`, `containeranalysis.occurrences.list` (sample) | Vulnerability + provenance notes attached to images | Scan results inspected at gate. |
| GKE | `container.projects.locations.clusters.list` | Per-cluster `binaryAuthorization.enabled`, `networkPolicy.enabled` | Cluster-level enforcement. |

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.codepipeline.prod_has_test_stage` | Every pipeline that deploys to prod has ≥1 stage running tests. |
| `aws.codepipeline.prod_has_scan_stage` | Every prod pipeline has a stage that gates on Inspector or equivalent scanner findings. |
| `aws.inspector.enabled_all_supported_types` | Inspector is on for EC2, ECR, and Lambda. |
| `aws.lambda.code_signing_required` | Every prod Lambda has a code-signing config attached. |
| `gcp.binaryauthorization.policy_enforced_prod` | BinAuthz policy is `ENFORCED_BLOCK_AND_AUDIT_LOG` for prod cluster admission rule. |
| `gcp.binaryauthorization.attestor_required_prod` | Prod admission rule lists at least one required attestor. |
| `gcp.cloudbuild.recent_failures_visible` | Recent failed builds visible via Cloud Logging; failure alert configured. |

**Process artifacts (HYBRID side).** The script can't grade adequacy of unit-test assertions. Tracker must hold: SAST/SCA tool list + version, test-coverage reports, gate-effectiveness review minutes.

---

## CNA — Cloud Native Architecture

> Theme: implicit — secure cloud architecture is built on minimal privilege, minimal attack surface, persistent enforcement of intended state, logical network segmentation, and availability engineering.

CNA is the cloud-native architecture domain. **All 8 KSIs are CLOUD.** This
is the heart of the script — these are the KSIs where AWS/GCP APIs directly
yield the evidence.

---

### KSI-CNA-DFP — Defining Functionality and Privileges

**Domain:** CNA · **Scope:** **CLOUD**

**Statement.** Strictly define the functionality and privileges for infrastructure and services.

**NIST 800-53 controls.** Not populated. Semantically: `ac-3` (access enforcement), `ac-6` (least privilege), `ac-6.1` (authorize access to security functions), `cm-7` (least functionality).

**Analysis.** This is "say what's allowed, not what's disallowed" — explicit allow-lists at every level. For identity: IAM policies and roles must be granular and scoped; no wildcard `Action: "*"` policies on production data planes; permission boundaries / VPC Service Controls / Org SCPs / Org Policies prevent privilege escalation. For services: only the features you need are enabled (no enabled-by-default IMDSv1, no public S3 ACL granted to AllUsers, no unused regions enabled). For functionality: org policies enforce constraints like `compute.requireOsLogin`, `iam.disableServiceAccountKeyCreation`, `storage.uniformBucketLevelAccess`.

**Classification — CLOUD.** Every artifact is enumerable via APIs.

#### Script plan — CNA-DFP

**Modules:**
- `providers/aws/iam.ts → collectCnaDfpAws()`
- `providers/gcp/iam.ts → collectCnaDfpGcp()`

**AWS evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| IAM | `iam.ListPolicies` (scope=Local), `iam.GetPolicyVersion` (each, default version) | Customer-managed policies + their policy documents | Inspect for wildcard actions/resources. |
| IAM | `iam.ListRoles`, `iam.ListAttachedRolePolicies`, `iam.GetRolePolicy` (inline) | Roles and what's attached | Role privilege scope. |
| IAM | `iam.GetAccountAuthorizationDetails` | One-shot dump of users/groups/roles/policies | Comprehensive baseline. |
| IAM Access Analyzer | `accessanalyzer.ListFindings`, `accessanalyzer.GetFinding` (each unresolved) | External-access findings, unused-access findings | Surface drift from intended. |
| Organizations | `organizations.ListPolicies(Filter=SERVICE_CONTROL_POLICY)`, `organizations.DescribePolicy` (each), `organizations.ListTargetsForPolicy` | SCP inventory + attachments | Org guardrails. |
| Service Quotas | `service-quotas.ListServiceQuotas` for IAM | Default vs raised quotas (sanity) | Visibility. |

**Captured fields:**
```json
{
  "scp_count": 6,
  "scp_attachments": [ { "scp_id": "p-abc", "targets": ["ou-prod"] } ],
  "iam_policies_with_wildcards": [
    { "policy_arn": "...", "statement_idx": 2, "action": "*", "resource": "*", "effect": "Allow" }
  ],
  "iam_roles_total": 142,
  "iam_roles_with_admin_policy": 4,
  "access_analyzer": { "external_access_findings": 0, "unused_access_findings": 23 }
}
```

**GCP evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Cloud IAM | `cloudresourcemanager.projects.getIamPolicy`, `.organizations.getIamPolicy`, `.folders.getIamPolicy` | Bindings at every level | Role-grant inventory. |
| Cloud IAM | `iam.projects.roles.list`, `iam.organizations.roles.list` | Custom roles + their `includedPermissions[]` | Custom-role privilege scope. |
| Org Policy | `orgpolicy.policies.list` (org + folders + projects), `orgpolicy.policies.get` (each) | Constraints enforced: `iam.disableServiceAccountKeyCreation`, `iam.allowedPolicyMemberDomains`, `compute.requireOsLogin`, `storage.uniformBucketLevelAccess`, `iam.automaticIamGrantsForDefaultServiceAccounts`, etc. | Guardrails. |
| Cloud IAM | `iam.recommender.recommendations.list` (recommender=`google.iam.policy.Recommender`) | Over-privilege findings | Drift visibility. |
| VPC Service Controls | `accesscontextmanager.accessPolicies.list`, `.servicePerimeters.list` | Perimeters around in-scope projects | Privilege containment. |

**Captured fields:**
```json
{
  "org_policies_enforced": [
    { "constraint": "iam.disableServiceAccountKeyCreation", "scope": "organizations/123", "enforce": true }
  ],
  "iam_bindings_with_primitive_roles": [
    { "resource": "projects/x", "member": "user:bob@...", "role": "roles/owner" }
  ],
  "iam_recommender_recommendations": [
    { "name": "...", "recommender_subtype": "REMOVE_ROLE", "description": "Replace roles/editor with roles/X" }
  ],
  "vpc_sc_perimeters": [ { "name": "...", "restricted_services": ["storage.googleapis.com","bigquery.googleapis.com"] } ]
}
```

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.iam.no_wildcard_admin_in_customer_policies` | No customer-managed policy contains `Action:"*", Resource:"*", Effect:"Allow"` unless paired with an explicit deny boundary. |
| `aws.iam.access_analyzer_external_findings=0` | No unresolved external-access findings. |
| `aws.org.scps_attached_to_prod_ou` | The prod OU has at least one SCP attached. |
| `gcp.org.disable_sa_key_creation_enforced` | `iam.disableServiceAccountKeyCreation` is enforced at the org. |
| `gcp.org.uniform_bucket_level_access_enforced` | `storage.uniformBucketLevelAccess` is enforced. |
| `gcp.iam.no_primitive_role_bindings_in_prod` | No `roles/owner` / `roles/editor` / `roles/viewer` bindings on prod projects (except break-glass groups documented as exceptions). |
| `gcp.vpc_sc.prod_in_perimeter` | Each prod project is included in at least one VPC SC service perimeter. |

---

### KSI-CNA-EIS — Enforcing Intended State

**Domain:** CNA · **Scope:** **CLOUD**

**Statement (Moderate; Low is "Optional").** Use automated services to persistently assess the security posture of all machine-based information resources and automatically enforce their intended operational state.

**NIST 800-53 controls.** `ca-2.1` (specialized assessments), `ca-7.1` (independent assessment within continuous monitoring).

**Analysis.** Drift detection + auto-remediation. Continuous comparison of *actual* config to *intended* config (codified in IaC, Config rules, Policy Controller, conformance packs), with automated rollback or alert-and-remediate for drift. The "automatically enforce" part is what makes this stronger than CNA-IBP (best-practice recommendation) or PIY-GIV (just listing). EIS is about *active enforcement*.

**Classification — CLOUD.**

#### Script plan — CNA-EIS

**Modules:**
- `providers/aws/config.ts → collectCnaEisAws()`
- `providers/gcp/config.ts → collectCnaEisGcp()`

**AWS evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| AWS Config | `config.DescribeConformancePacks`, `config.DescribeConformancePackComplianceStatuses` | Conformance packs deployed + per-pack compliance % | Posture coverage. |
| AWS Config | `config.DescribeConfigRules`, `config.GetComplianceDetailsByConfigRule` (each rule) | Rule list, non-compliant resources per rule | Drift inventory. |
| AWS Config | `config.DescribeRemediationConfigurations`, `config.DescribeRemediationExecutionStatus` | Auto-remediation configs for non-compliant rules | Active enforcement. |
| Systems Manager | `ssm.DescribeAssociationExecutions` (State Manager) | State Manager association run outcomes | Desired-state enforcement on instances. |
| CloudFormation | `cloudformation.DetectStackDrift` (kick off, then `DescribeStackResourceDrifts`) for in-scope stacks | Stack-level drift | IaC drift. |
| Security Hub | `securityhub.DescribeStandards`, `securityhub.GetEnabledStandards`, `securityhub.GetFindings` (recent, by severity) | Enabled standards + finding counts | Posture aggregation. |

**Captured fields:**
```json
{
  "config_conformance_packs": [ { "name": "fedramp-moderate-baseline", "compliance_score": 96.4, "non_compliant_rules": 3 } ],
  "config_rules_with_auto_remediation": 28,
  "config_rules_total": 47,
  "stack_drift": [ { "stack": "prod-net", "drift_status": "IN_SYNC", "checked_at": "..." } ],
  "security_hub_enabled_standards": ["fsbp/v1.0.0", "cis-aws/v1.4.0"],
  "security_hub_critical_findings": 0
}
```

**GCP evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Security Command Center | `securitycenter.organizations.sources.findings.list`, `.organizations.findings.group` | Findings by category + state | Posture aggregation. |
| Security Command Center | `securitycenter.organizations.muteConfigs.list`, `.organizations.notificationConfigs.list` | Mute + notification setup | Triage hygiene. |
| Anthos Config Mgmt / Policy Controller | (GKE clusters) `container.projects.locations.clusters.get` + cluster API `kubectl get constrainttemplates,constraints` — alternatively `gkehub.features.list` | Policy Controller installed; ConstraintTemplate + Constraint inventory | Active K8s policy enforcement. |
| Config Connector | (per cluster) `kubectl get configconnector` | Config Connector deployment | Declarative GCP-resource enforcement via K8s. |
| Asset Inventory | `cloudasset.feeds.list`, `cloudasset.exportAssets` (history) | Asset feeds, change history | Drift detection feed. |
| Recommender | `recommender.recommendations.list` (multiple recommenders) | Posture recommendations | Drift signals. |

**Captured fields:**
```json
{
  "scc_active_findings_by_severity": { "CRITICAL": 0, "HIGH": 3, "MEDIUM": 17, "LOW": 64 },
  "policy_controller_clusters": [ { "cluster": "projects/x/locations/us-central1/clusters/prod", "constraint_templates_count": 41, "constraints_count": 87 } ],
  "asset_feeds_active": 4,
  "recommender_findings_critical": 1
}
```

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.config.conformance_packs_deployed` | A FedRAMP-aligned conformance pack is deployed and ≥95% compliant. |
| `aws.config.auto_remediation_enabled_for_critical_rules` | Auto-remediation is configured for rules tagged Critical (per a manifest). |
| `aws.cloudformation.drift_in_sync` | All prod stacks in `IN_SYNC` (not `DRIFTED`). |
| `gcp.scc.no_critical_findings_unmuted` | Zero unmuted CRITICAL findings. |
| `gcp.policy_controller.installed_on_prod_clusters` | Every prod GKE cluster has Policy Controller installed with at least N constraint templates. |
| `gcp.asset_feeds.active` | At least one asset feed routes resource/IAM-policy changes to a downstream system. |

---

### KSI-CNA-IBP — Implementing Best Practices

**Domain:** CNA · **Scope:** **CLOUD**

**Statement.** Persistently ensure cloud-native machine-based information resources are implemented based on the host provider's best practices and documented guidance.

**NIST 800-53 controls.** Not populated. Maps to `cm-6` (config settings), `sa-8` (security engineering principles).

**Analysis.** Run AWS and GCP's own posture tools — they encode their own best practices. The "host provider's documented guidance" is literally what Trusted Advisor, Well-Architected, Security Hub controls, SCC Posture Management, and Recommender enforce. CNA-IBP is the lighter sibling of CNA-EIS — it covers *findings exist* and *known issues are tracked*, but doesn't require active auto-remediation.

**Classification — CLOUD.**

#### Script plan — CNA-IBP

**Modules:**
- `providers/aws/config.ts → collectCnaIbpAws()`
- `providers/gcp/config.ts → collectCnaIbpGcp()`

**AWS evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Trusted Advisor | `support.DescribeTrustedAdvisorChecks`, `support.DescribeTrustedAdvisorCheckResult` (each) | Check status, flagged resources | AWS-native best-practice signals. (Requires Business/Enterprise Support.) |
| Well-Architected Tool | `wellarchitected.ListWorkloads`, `wellarchitected.GetWorkload`, `wellarchitected.ListLensReviewImprovements` | Workload reviews, high-risk issues | Architectural review evidence. |
| Security Hub | `securityhub.GetFindings` (controls by status) | Per-control compliance | FSBP / CIS / PCI signals. |
| Inspector | `inspector2.ListFindings` (severity ≥ HIGH) | Vuln findings on EC2/ECR/Lambda | Patch-state signal. |

**GCP evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Security Command Center | `securitycenter.organizations.sources.findings.list` (filtered to category ~ "security health analytics" / "container threat detection") | SHA findings | Best-practice signals. |
| Recommender | `recommender.recommendations.list` across recommenders (`compute.firewall.Recommender`, `iam.policy.Recommender`, `cloudsql.instance.IdleRecommender`, etc.) | Cross-domain recommendations | Native best-practice nudges. |
| Active Assist | `recommender.insights.list` | Insights backing recommendations | Diagnostic detail. |

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.trusted_advisor.no_red_security_checks` | No security-pillar Trusted Advisor checks in red status. |
| `aws.well_architected.security_pillar_reviewed_last_12mo` | At least one workload has a Well-Architected security review in the last 12 months. |
| `aws.security_hub.fsbp_pass_rate_>=95%` | FSBP standard compliance is ≥95%. |
| `gcp.scc.sha_findings_critical=0` | Zero critical Security Health Analytics findings. |
| `gcp.recommender.security_recs_acknowledged_or_resolved` | Outstanding security-pillar recommendations are either marked resolved or have a documented exception (e.g. via `recommender.recommendations.markDismissed`). |

---

### KSI-CNA-MAT — Minimizing Attack Surface

**Domain:** CNA · **Scope:** **CLOUD**

**Statement.** Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised.

**NIST 800-53 controls.** Not populated. Maps to `ac-3`, `ac-4` (info flow), `sc-7` (boundary protection), `sc-7.5` (deny by default), `cm-7` (least functionality).

**Analysis.** Two orthogonal vectors:
1. **Reduce exposed surface.** Public IPs only where needed; no `0.0.0.0/0:22` on prod; no public S3/GCS unless intentional; IMDSv2-only on EC2; no public-IP GKE/EKS endpoints unless behind controlled bastion; serverless functions don't have over-broad invocation permissions; Lambda function URLs / Cloud Run unauthenticated invocations restricted.
2. **Constrain lateral movement.** Segmented networks (VPC peering only where needed, private connectivity preferred); short-lived credentials (no IAM access keys, use IRSA / Workload Identity); micro-segmentation in K8s (network policies); service-to-service mTLS; instance metadata service hardened.

**Classification — CLOUD.**

#### Script plan — CNA-MAT

**Modules:**
- `providers/aws/network.ts → collectCnaMatAws()`
- `providers/gcp/network.ts → collectCnaMatGcp()`

**AWS evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| EC2 | `ec2.DescribeSecurityGroups` (all regions in scope) | SG rules: cidr ranges, ports, protocols | Identify overly-permissive ingress (`0.0.0.0/0` to high-risk ports). |
| EC2 | `ec2.DescribeInstances` | `MetadataOptions.HttpTokens` (must be `required` for IMDSv2), `PublicIpAddress` presence | Surface reduction. |
| EC2 | `ec2.DescribeVpcs`, `ec2.DescribeRouteTables`, `ec2.DescribeNetworkAcls` | Network topology + NACLs | Segmentation evidence. |
| S3 | `s3.GetBucketPublicAccessBlock` (per bucket), `s3.GetBucketAcl`, `s3.GetBucketPolicyStatus` | `BlockPublicAcls`, `BlockPublicPolicy` etc., `IsPublic` flag | No accidental public buckets. |
| Lambda | `lambda.GetPolicy` (per function) | Resource policy: any principal `*`, function-URLs open | Function exposure. |
| API Gateway / ELB | `apigateway.GetRestApis`, `elbv2.DescribeLoadBalancers` | Public-facing endpoints inventory + auth | Surface inventory. |
| RDS / DynamoDB | `rds.DescribeDBInstances`, `rds.DescribeDBClusters` | `PubliclyAccessible`, security-group attachments | DB exposure. |
| EKS | `eks.DescribeCluster` | `resourcesVpcConfig.endpointPublicAccess`, `publicAccessCidrs` | Cluster endpoint exposure. |

**Captured fields:**
```json
{
  "security_groups_open_to_world_high_risk_ports": [
    { "group_id": "sg-abc", "port": 22, "cidr": "0.0.0.0/0", "vpc": "vpc-xyz" }
  ],
  "ec2_instances_without_imdsv2": [ "i-abc", "i-def" ],
  "s3_public_buckets": [],
  "lambda_functions_with_public_principals": [ { "function": "log-receiver", "principal": "*", "action": "lambda:InvokeFunction" } ],
  "rds_public_instances": [],
  "eks_clusters_public_endpoint": [ { "cluster": "prod", "cidrs": ["192.0.2.10/32"] } ]
}
```

**GCP evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Compute | `compute.firewalls.list` (per VPC) | Source ranges, target tags/SAs, direction, allowed protocols | Firewall posture. |
| Compute | `compute.instances.list` | `serviceAccounts[*].email` and `scopes`, `networkInterfaces[*].accessConfigs` (public IPs), `shieldedInstanceConfig` | Surface reduction. |
| GKE | `container.projects.locations.clusters.get` | `privateClusterConfig.enablePrivateNodes` and `.enablePrivateEndpoint`, `masterAuthorizedNetworksConfig.cidrBlocks`, `networkPolicy.enabled`, `workloadIdentityConfig.workloadPool` | K8s exposure + lateral. |
| Cloud Run | `run.namespaces.services.list` | Service `ingress` (all / internal / internal-and-cloud-load-balancing), per-service IAM bindings (no `allUsers`) | Function/service exposure. |
| Cloud Storage | `storage.buckets.list`, `storage.buckets.getIamPolicy`, `storage.buckets.get` (for `iamConfiguration.uniformBucketLevelAccess`, `publicAccessPrevention`) | Public-access prevention enforced; no `allUsers`/`allAuthenticatedUsers` bindings | Bucket exposure. |
| Cloud SQL | `sqladmin.instances.list` | `ipConfiguration.ipv4Enabled`, `ipConfiguration.authorizedNetworks[]`, `requireSsl` | DB exposure. |
| Load Balancing | `compute.targetHttpsProxies.list`, `compute.forwardingRules.list` | Public-facing endpoints + their backend services | Surface inventory. |

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.sg.no_world_open_to_admin_ports` | No SG rule allows `0.0.0.0/0` to 22/3389/3306/5432/etc. on prod resources. |
| `aws.ec2.all_imdsv2` | All in-scope EC2 instances have `HttpTokens=required`. |
| `aws.s3.no_public_buckets` | No buckets allow public read/write per `GetBucketPolicyStatus`. |
| `aws.lambda.no_public_invocation` | No Lambda resource policy has `Principal: "*"` without conditions. |
| `aws.rds.no_public` | No RDS instance has `PubliclyAccessible=true` in prod. |
| `aws.eks.endpoint_private_or_cidr_restricted` | Public endpoint either disabled or restricted to a small CIDR list. |
| `gcp.compute.no_default_sa_with_full_scope` | No instances use the default SA with `cloud-platform` scope in prod. |
| `gcp.compute.no_public_ips_in_prod_unless_lb` | No prod VM has a public IP unless it's a load balancer. |
| `gcp.gke.private_nodes_and_authorized_networks` | Prod GKE clusters have private nodes AND `masterAuthorizedNetworksConfig` configured. |
| `gcp.gke.workload_identity_enabled` | Prod GKE clusters have Workload Identity configured. |
| `gcp.storage.public_access_prevention_enforced` | `iamConfiguration.publicAccessPrevention=enforced` on every prod bucket. |
| `gcp.cloud_run.no_unauth_invocation_in_prod` | No `allUsers` IAM bindings on prod Cloud Run services unless documented as public. |
| `gcp.cloudsql.no_public_ip` | Cloud SQL prod instances have `ipv4Enabled=false` (use private IP). |

---

### KSI-CNA-OFA — Optimizing for Availability

**Domain:** CNA · **Scope:** **CLOUD**

**Statement.** Appropriately optimize machine-based information resources for high availability and rapid recovery.

**NIST 800-53 controls.** Not populated. Maps to `cp-2` (contingency planning), `cp-7` (alternate processing site), `cp-10` (system recovery).

**Analysis.** Compute and data are spread across availability zones / regions appropriate to the service tier, with health-checking and automated failover. For a SaaS CI/CD product: prod data plane in ≥2 AZs (AWS) or regional MIGs (GCP); database tier multi-AZ or regional; control plane components fronted by ELB/LB with health checks; managed services chosen with multi-AZ/regional options. CNA-OFA pairs with RPL-ABO (backups aligned to RPO) and RPL-TRC (test recovery) — OFA is the *architecture* side; RPL is the *backup/restore* side.

**Classification — CLOUD.**

#### Script plan — CNA-OFA

**Modules:**
- `providers/aws/backup.ts → collectCnaOfaAws()`
- `providers/gcp/backup.ts → collectCnaOfaGcp()`

**AWS evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Auto Scaling | `autoscaling.DescribeAutoScalingGroups` | `AvailabilityZones[]`, `MinSize`, `DesiredCapacity`, `HealthCheckType` | Multi-AZ compute redundancy. |
| ELB | `elbv2.DescribeLoadBalancers`, `elbv2.DescribeAvailabilityZones` | LB AZ count, target health | LB redundancy. |
| RDS | `rds.DescribeDBInstances`, `rds.DescribeDBClusters` | `MultiAZ`, `AvailabilityZones[]`, `BackupRetentionPeriod` | DB redundancy. |
| DynamoDB | `dynamodb.ListTables`, `dynamodb.DescribeTable`, `dynamodb.DescribeGlobalTable` | Per-table BillingMode, PITR enabled, Global Tables replicas | Data tier redundancy. |
| ElastiCache | `elasticache.DescribeReplicationGroups` | `AutomaticFailover`, `MultiAZ` | Cache redundancy. |
| Route 53 | `route53.ListHealthChecks`, `route53.ListResourceRecordSets` (failover/latency) | Health checks + failover records | DNS-level failover. |
| Backup | `backup.ListBackupPlans`, `backup.GetBackupPlan`, `backup.ListBackupSelections` | Plan rules + scope | (Cross-ref with RPL-ABO.) |

**GCP evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Compute | `compute.regionInstanceGroupManagers.list`, `compute.instanceGroupManagers.list` | Regional vs zonal MIG, `autoHealingPolicies`, target size | Compute redundancy. |
| Cloud SQL | `sqladmin.instances.list` | `availabilityType` (REGIONAL vs ZONAL), `backupConfiguration` | DB redundancy. |
| Spanner / Bigtable | `spanner.instances.list`, `bigtableadmin.instances.list` | `config` (multi-region), node counts | Data redundancy. |
| Cloud Storage | `storage.buckets.list` (`location` and `locationType`) | `MULTI_REGION` / `DUAL_REGION` vs `REGION` | Object-store redundancy. |
| Load Balancing | `compute.backendServices.list`, `compute.healthChecks.list` | Backends across regions, health checks present | LB redundancy. |
| Cloud DNS | `dns.managedZones.list`, `dns.policies.list` | Routing policies (failover) | DNS failover. |

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.asg.prod_multi_az` | Every prod ASG spans ≥2 AZs. |
| `aws.elb.prod_multi_az` | Every prod LB spans ≥2 AZs. |
| `aws.rds.prod_multi_az` | Every prod RDS instance/cluster is multi-AZ. |
| `aws.dynamodb.prod_pitr_enabled` | PITR enabled on prod tables (and Global Tables where applicable). |
| `gcp.mig.prod_regional` | Every prod MIG is a regional MIG (or multi-zonal). |
| `gcp.cloudsql.prod_regional_ha` | Cloud SQL prod instances have `availabilityType=REGIONAL`. |
| `gcp.storage.prod_buckets_redundant` | Prod buckets are `MULTI_REGION` or `DUAL_REGION` (or explicitly justified as REGION). |

---

### KSI-CNA-RNT — Restricting Network Traffic

**Domain:** CNA · **Scope:** **CLOUD**

**Statement.** Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic.

**NIST 800-53 controls.** Not populated. Maps to `ac-4`, `sc-7`, `sc-7.5` (deny by default).

**Analysis.** Both directions matter. Inbound has overlap with CNA-MAT (admin-port restriction). Outbound is its own thing: egress should be constrained — managed instances shouldn't be free to call out to arbitrary internet endpoints. Use egress firewall rules / SG outbound rules / VPC SC perimeters / NAT-gateway-only-via-allowlist patterns. For containerized workloads: K8s NetworkPolicies / GKE / EKS.

**Classification — CLOUD.**

#### Script plan — CNA-RNT

**Modules:**
- `providers/aws/network.ts → collectCnaRntAws()`
- `providers/gcp/network.ts → collectCnaRntGcp()`

**AWS evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| EC2 | `ec2.DescribeSecurityGroups` | All SG rules, both ingress and egress | The default SG egress rule is `0.0.0.0/0 all`; KSI wants this tightened. |
| EC2 | `ec2.DescribeNetworkAcls` | NACL rules per subnet | Subnet-level deny defaults. |
| Network Firewall | `network-firewall.ListFirewalls`, `.DescribeFirewall`, `.DescribeFirewallPolicy`, `.DescribeRuleGroup` | Stateful/stateless rule groups | Centralized egress filtering. |
| WAF | `wafv2.ListWebACLs`, `wafv2.GetWebACL` | WAF rules + scope | Inbound L7. |
| VPC | `ec2.DescribeFlowLogs` | Flow logs enabled per VPC + dest | Visibility into actual traffic (supporting evidence). |
| Route 53 Resolver DNS Firewall | `route53resolver.ListFirewallRuleGroupAssociations`, `.ListFirewallRules` | DNS firewall rules | Egress via DNS. |

**Captured fields:**
```json
{
  "default_sg_unrestricted_egress": [ { "vpc": "vpc-xyz", "sg": "default-sg" } ],
  "non_default_sg_with_unrestricted_egress": [ "sg-abc" ],
  "network_firewall_deployed": true,
  "network_firewall_stateful_rule_groups": 3,
  "vpc_flow_logs_per_vpc": { "vpc-xyz": "ENABLED" },
  "dns_firewall_associations": 2
}
```

**GCP evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Compute | `compute.firewalls.list` (per VPC), per rule: `direction`, `sourceRanges`, `destinationRanges`, `allowed[]`, `priority`, `disabled` | Firewall posture | Inbound + egress. |
| Compute | `compute.firewallPolicies.list` (hierarchical) | Org / folder firewall policies | Org-level enforcement. |
| Compute | `compute.subnetworks.list` (`logConfig.enable`), VPC `flowLogging` | VPC flow logs | Visibility. |
| Cloud NAT | `compute.routers.list`, `.routers.get` (NAT config) | NAT gateway scopes (controlled egress) | Egress via NAT only. |
| Cloud Armor | `compute.securityPolicies.list` | Cloud Armor policies | Inbound L7. |
| GKE | `container.projects.locations.clusters.get` | `networkPolicy.enabled`, `defaultMaxPodsConstraint` | K8s netpol enforcement. |
| VPC SC | `accesscontextmanager.servicePerimeters.list` | Egress/ingress rules of perimeters | Strong egress containment. |

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.sg.default_no_unrestricted_egress` | The default SG of each in-scope VPC has no `0.0.0.0/0` egress. |
| `aws.sg.prod_no_unrestricted_egress` | No prod SG has unrestricted egress unless documented as ingress-only or transit. |
| `aws.network_firewall_or_equivalent` | Network Firewall or a centralized egress control is in place for prod VPCs. |
| `aws.vpc_flow_logs_enabled` | Every prod VPC has flow logs to S3/CW Logs. |
| `gcp.firewall.implicit_deny_egress` | The implicit-deny egress is not overridden by an `allow-all-egress` rule on prod VPCs. |
| `gcp.firewall.hierarchical_policy_present` | At least one org/folder hierarchical firewall policy applies to prod. |
| `gcp.vpc_flow_logs_enabled` | Flow logs enabled on every prod subnet. |
| `gcp.gke.network_policy_enabled` | Network Policy is enabled on prod GKE clusters. |
| `gcp.vpc_sc.egress_rules_configured` | At least one VPC SC perimeter has egress rules tightening access to GCP APIs. |

---

### KSI-CNA-RVP — Reviewing Protections (DoS etc.)

**Domain:** CNA · **Scope:** **CLOUD**

**Statement.** Persistently review the effectiveness of protection against denial of service attacks and other unwanted activity.

**NIST 800-53 controls.** Not populated. Maps to `sc-5` (DoS protection), `sc-5.1` (capacity), `sc-5.2` (detection/monitoring).

**Analysis.** DoS protection has two parts: protections in place (Shield, WAF rate limits, Cloud Armor, CDN absorbing volumetric traffic) AND the review evidence (do these protections trigger on real or simulated load? are alerts wired? are tabletops done?). For evidence: dump protection inventory + recent metric data showing activity (or simulated activity) AND any incident records.

**Classification — CLOUD.** Protection inventory is fully scriptable; review evidence is annotated in the tracker via `last_reviewed` and `notes`.

#### Script plan — CNA-RVP

**AWS:** `shield.ListProtections`, `shield.DescribeSubscription`, `wafv2.ListWebACLs` + per-ACL `wafv2.GetSampledRequests` (recent), `cloudwatch.GetMetricStatistics` for `AWS/WAFV2 BlockedRequests`, `AWS/Shield DDoSDetected`.

**GCP:** `compute.securityPolicies.list` and `.securityPolicies.get` (rules + adaptive protection enabled), `monitoring.timeSeries.list` for Cloud Armor metrics (`loadbalancing.googleapis.com/https/request_count` with `policy_name` resource label), Adaptive Protection alerts.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.shield.advanced_subscribed` | Shield Advanced is subscribed for prod (if cost-justified) — otherwise WAF rate-based rules in place. |
| `aws.wafv2.rate_based_rules_on_public_alb` | Every internet-facing ALB/CloudFront has WAF with rate-based rules. |
| `gcp.cloudarmor.adaptive_protection_enabled` | Adaptive Protection enabled on prod security policies. |
| `gcp.cloudarmor.rate_based_rule_on_public_lb` | Every internet-facing HTTPS LB has a Cloud Armor policy with rate-based rules. |

---

### KSI-CNA-ULN — Using Logical Networking

**Domain:** CNA · **Scope:** **CLOUD**

**Statement.** Use logical networking and related capabilities to enforce traffic flow controls.

**NIST 800-53 controls.** Not populated. Maps to `ac-4`, `sc-7`, `sc-32` (system partitioning).

**Analysis.** Networks are partitioned by purpose — separate VPCs / projects / accounts for prod vs nonprod, with controlled inter-VPC connectivity (transit gateway, PrivateLink, VPC peering allowlists, Shared VPC, VPC SC perimeters). Workloads are in private subnets by default, egress through NAT, public ingress through LBs with WAF/Cloud Armor.

**Classification — CLOUD.**

#### Script plan — CNA-ULN

**AWS:** `ec2.DescribeVpcs`, `ec2.DescribeSubnets`, `ec2.DescribeVpcPeeringConnections`, `ec2.DescribeTransitGateways`, `ec2.DescribeVpcEndpoints` (interface + gateway), `organizations.DescribeAccount` (account-level scoping).

**GCP:** `compute.networks.list` (per project), `compute.subnetworks.list`, `compute.networkPeerings.list`, `compute.routers.list`, `accesscontextmanager.servicePerimeters.list` (VPC SC), `cloudresourcemanager.projects.list` (project hierarchy as logical separation).

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.vpc.prod_separated_from_nonprod` | Prod resources are in a separate VPC (or account) from nonprod. |
| `aws.vpc_endpoint.private_to_gcp_services` | VPC endpoints (interface) exist for S3, KMS, Secrets Manager, CloudWatch Logs in prod VPCs. |
| `gcp.network.prod_separate_project` | Prod resources are in a separate project from nonprod. |
| `gcp.shared_vpc.host_project_documented` | Shared VPC host project / service projects clearly mapped. |
| `gcp.vpc_sc.prod_in_perimeter` | Prod project is inside a VPC SC perimeter. |

---

## CED — Cybersecurity Education

> Theme: implicit — staff at every level must receive training appropriate to their role, and the effectiveness of that training must be persistently reviewed.

All 4 CED KSIs are review activities over training programs. Evidence lives
in your LMS (KnowBe4, Lessonly, Workday Learning, …) or HRIS. **No cloud
API satisfies any CED KSI.**

---

### KSI-CED-DET — Reviewing Development & Engineering Training

**Domain:** CED · **Scope:** PROCESS

**Statement.** Persistently review the effectiveness of role-specific training given to development and engineering staff that covers best practices for delivering secure software.

**Analysis.** Per FRD-PER, this requires a documented review cadence, results of past reviews, and follow-through. Evidence: secure-SDLC training curriculum, completion records for engineers, review minutes asking "is the training producing better outcomes" (e.g. fewer security findings per release).

**Classification — PROCESS.** Tracker fields: training program URL, review cadence, last-review date, evidence URL pointing to LMS completion report.

> *Indirect cloud signal:* CMT-VTD's findings (SAST/SCA failures over time) and SCR-MON's vuln-find rates are leading indicators of training effectiveness. Reviewers should reference these.

---

### KSI-CED-RGT — Reviewing General Training

**Domain:** CED · **Scope:** PROCESS

**Statement.** Persistently review the effectiveness of training given to all employees on policies, procedures, and security-related topics.

**Analysis.** Same shape as CED-DET but scoped to all employees, not just engineers. Phishing-sim pass rates, policy-acknowledgement completion, mandatory-training completion. LMS evidence.

**Classification — PROCESS.** Tracker fields: program URL, completion-rate report URL, review-minutes URL, review cadence.

---

### KSI-CED-RRT — Reviewing Response and Recovery Training

**Domain:** CED · **Scope:** PROCESS

**Statement.** Persistently review the effectiveness of role-specific training given to staff involved with incident response or disaster recovery.

**Analysis.** IR/DR drills, tabletop exercises, role-based training (oncall, comms lead, legal liaison, exec sponsor). Evidence: drill schedule, after-action reports from drills (separate from real-incident AARs in INR-AAR), role-coverage matrix.

**Classification — PROCESS.** Tracker fields: drill program URL, last drill date, AAR from last drill, review minutes.

> *Indirect cloud signal:* RPL-TRC produces evidence of recovery exercises (restore tests, regional-failover tests). Reviewers should incorporate those metrics.

---

### KSI-CED-RST — Reviewing Role-Specific Training

**Domain:** CED · **Scope:** PROCESS

**Statement.** Persistently review the effectiveness of role-specific training given to employees in high risk roles, including at least roles with privileged access.

**Analysis.** Specifically targets privileged users (admins, SREs, security engineers, anyone with `roles/owner` or break-glass roles). Evidence: training mapped to role; recurring annual training; recurring practical exercises (e.g. simulated phishing targeting privileged users, breakglass-use drills); completion records.

**Classification — PROCESS.** Tracker fields: training-by-role mapping doc, completion report, review minutes, last-review date.

> *Indirect cloud signal:* IAM-ELP enumerates who has privileged access; IAM-AAM enumerates account lifecycle. Marry the privileged-access list with the training-completion list to demonstrate every privileged human has current training.

---

## CSX — 20x-Specific Provider Responsibilities

> Theme: 20x-specific provider responsibilities — meta-rules about how to demonstrate the other 60 KSIs.

These 3 KSIs live in `FRR.KSI/CSX` in the FRMR JSON rather than the top-level
`KSI` section. They govern the *application* of the other 60 KSIs.

---

### KSI-CSX-SUM — Implementation Summaries

**Domain:** CSX · **Keyword:** MUST · **Scope:** **HYBRID**

**Statement.** Providers MUST maintain simple high-level summaries of at least the following for each Key Security Indicator:

**Following information (verbatim from FRMR).**
- Goals for how it will be implemented and validated, including clear pass/fail criteria and traceability
- The consolidated information resources that will be validated (this should include consolidated summaries such as "all employees with privileged access that are members of the Admin group")
- The machine-based processes for validation and the persistent cycle on which they will be performed (or an explanation of why this doesn't apply)

**Referenced FRD terms.** Machine-Based (information resources), Persistent Validation.

**Analysis.** Per-KSI, the provider must publish: (1) implementation goal + pass/fail criteria, (2) the population of resources being validated, (3) the validation tooling + cadence (or rationale why it doesn't apply). For every CLOUD/HYBRID KSI, the evidence-collection script supplies (2) and (3) directly. For PROCESS KSIs, the provider authors all three. The KSI itself requires the *document*, but the document content is fed by the script + tracker.

**Classification — HYBRID.** The summary document is the artifact; cloud evidence feeds the validation-content sections.

#### Script plan — CSX-SUM

**Module:** `core/csx-sum-aggregator.ts → buildCsxSumInput()`

Not a per-provider module; this aggregates across all evidence files produced
in a run.

**Captures (across all collected evidence files):**

For each of the 63 KSIs (driven by the `ksi-map.ts` master list):
- `ksi_id`, `ksi_name`
- `scope` (CLOUD / HYBRID / PROCESS / INHERITED)
- `pass_fail_criteria[]` — for CLOUD/HYBRID, the list of `findings[].rule` names emitted by that KSI's module
- `validated_resources_summary` — for CLOUD/HYBRID, derived from the evidence file (e.g. "47 IAM users; 1230 IAM roles; 28 SCP attachments")
- `validation_cadence` — pulled from PVA-plan config (`cadence_target_days`)
- `validation_module` — script module path that validates it (or `null` for PROCESS)
- `last_run_at` — from the evidence file's `collected_at`
- `last_pass_status` — from `rollup.pass`
- `notes_pointer` — link into the tracker for this KSI

**Output:** a single `out/KSI-CSX-SUM-input.json` file consumed by the
human-authored implementation-summary document (the actual deliverable per
FRMR is the document — markdown, PDF, whatever — but the structured input is
what makes the document maintainable).

**Sample output:**
```json
{
  "frmr_version": "0.9.43-beta",
  "generated_at": "...",
  "summaries": [
    {
      "ksi_id": "KSI-IAM-MFA",
      "ksi_name": "Enforcing Phishing-Resistant MFA",
      "scope": "CLOUD",
      "pass_fail_criteria": [
        "aws.iam_identity_center.mfa_factor_restricted_to_webauthn",
        "aws.iam.root_mfa_enforced_via_scp",
        "gcp.cloud_identity.2sv_enforced_with_security_keys",
        "gcp.context_aware_access.blocks_phone_based_mfa"
      ],
      "validated_resources_summary": "AWS: IAM Identity Center policy on 1 instance, root account on 3 accounts. GCP: Cloud Identity domain-wide enforcement on `example.com`, Context-Aware Access policy `cap-fido`",
      "validation_cadence_days": 1,
      "validation_module": "providers/{aws,gcp}/iam.ts::collectIamMfa",
      "last_run_at": "2026-05-26T19:23:00Z",
      "last_pass_status": true,
      "tracker_url": "http://localhost:4000/indicators/KSI-IAM-MFA"
    }
    /* ...62 more... */
  ]
}
```

**Process-side notes.** The document the user actually publishes is authored
on top of this JSON. Recommend a static-site generator (Hugo, MkDocs) that
templates each KSI page from the JSON; that way the doc auto-refreshes when
new evidence is collected.

---

### KSI-CSX-MAS — Application within MAS

**Domain:** CSX · **Keyword:** SHOULD · **Scope:** PROCESS

**Statement.** Providers SHOULD apply ALL Key Security Indicators to ALL aspects of their cloud service offering that are within the FedRAMP Minimum Assessment Scope.

**Analysis.** This is a *scope completeness* requirement: every in-scope component of the CSO must have all 63 KSIs applied to it. Evidence: a KSI-to-component matrix showing coverage (e.g. "for the data plane AWS account: IAM-MFA evidence collected; for the GCP control-plane project: IAM-MFA evidence collected; for our Stripe subprocessor: IAM-MFA is N/A because we don't manage Stripe's IAM directly, see SCR-MIT instead").

**Classification — PROCESS.** Coverage matrix is a doc. Cloud evidence files inform the matrix.

> *Cloud signal:* the script's run summary (PVA) per-account/project counts can be cross-referenced against the MAS scope inventory to detect gaps.

---

### KSI-CSX-ORD — AFR Order of Criticality

**Domain:** CSX · **Keyword:** MAY · **Scope:** PROCESS

**Statement.** Providers MAY use the following order of criticality for approaching Authorization by FedRAMP Key Security Indicators for an initial authorization package:

**Following information (verbatim).**
- Minimum Assessment Scope (MAS)
- Authorization Data Sharing (ADS)
- Using Cryptographic Modules (UCM)

**Analysis.** Recommended sequencing. Not enforcement. Evidence: your project plan or roadmap shows AFR KSIs being tackled in this order (or has documented justification for deviating).

**Classification — PROCESS.** Tracker fields: link to project plan / Gantt / roadmap.

---

## IAM — Identity and Access Management

> Theme: implicit — strong, automated, least-privilege identity management with phishing-resistant MFA and active response to compromise.

IAM has 7 KSIs. Six are pure CLOUD; one (JIT) is HYBRID because just-in-time
access often uses 3rd-party tools (Teleport, ConductorOne) alongside native
ones. **This is the recommended starting domain for the collection script —
highest payoff, cleanest API mapping, broadest NIST coverage.**

---

### KSI-IAM-AAM — Automating Account Management

**Domain:** IAM · **Scope:** **CLOUD**

**Statement.** Securely manage the lifecycle and privileges of all accounts, roles, and groups, using automation.

**NIST 800-53 controls (9).** `ac-2.2` (automated system account management), `ac-2.3` (disable accounts), `ac-2.13` (privileged account disabling), `ac-6.7` (review of user privileges), `ia-4.4` (uniquely identify users), `ia-12` (identity proofing), `ia-12.2` / `.3` / `.5` (identity-proofing sub-controls).

**Analysis.** Account lifecycle (provision → modify → deprovision) is automated, not manual. For humans: identity provider (Okta, Azure AD, Google Workspace) is the source of truth; SCIM / Workforce Identity Federation provisions and deprovisions IAM Identity Center / Cloud Identity bindings; offboarding flips one HRIS switch and access disappears within minutes everywhere. For services: workload identity (IRSA / GKE Workload Identity / Workload Identity Federation) replaces long-lived keys; service accounts are provisioned and rotated by IaC. Reviews of who-has-what-access happen automatically (Access Analyzer unused-access, IAM Recommender) and are followed up on. **No standalone human-created accounts in any cloud — every account traces to an automated source.**

**Classification — CLOUD.**

#### Script plan — IAM-AAM

**Modules:**
- `providers/aws/iam.ts → collectIamAamAws()`
- `providers/gcp/iam.ts → collectIamAamGcp()`

**AWS evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| IAM | `iam.GenerateCredentialReport`, `iam.GetCredentialReport` | All users with: access-key age, last used, password set, MFA, password-last-used | Demonstrates account state at a snapshot. |
| IAM | `iam.ListUsers` (paginated) | Users (should ideally be a small / empty list — humans federate via SSO, not standalone IAM users) | Non-federated user count. |
| IAM | `iam.ListAccessKeys`, `iam.GetAccessKeyLastUsed` | Per-key last-used and age | Stale credentials. |
| IAM Identity Center | `sso-admin.ListInstances`, `sso-admin.ListPermissionSets`, `sso-admin.ListAccountAssignments`, `identitystore.ListUsers`, `identitystore.ListGroups` | Identity Store user/group counts, permission-set inventory, account-assignment matrix | Federated identity is the source of truth. |
| IAM Identity Center | `sso-admin.DescribeInstanceAccessControlAttributeConfiguration` | ABAC config | Attribute-based access (least privilege at runtime). |
| IAM | `iam.ListAttachedUserPolicies`, `iam.ListGroupsForUser` (for any remaining IAM users) | What standalone users can do | Drift detection. |
| Access Analyzer | `accessanalyzer.ListFindings(type=UnusedAccess)` (Unused-Access analyzer specifically) | Unused user/role access | Lifecycle hygiene. |
| Organizations | `organizations.DescribeOrganization`, `organizations.ListAccounts` | Account count + state | Org-wide scope. |

**Captured fields:**
```json
{
  "iam_users_count": 3,
  "iam_users_with_old_access_keys_gt_90d": 0,
  "iam_users_with_password_no_mfa": 0,
  "identity_store_users_count": 187,
  "identity_store_groups_count": 24,
  "permission_sets_count": 12,
  "account_assignments_count": 412,
  "abac_attribute_configured": true,
  "unused_access_findings_count": 11
}
```

**GCP evidence collection.**

| Service | API call | Captures | Purpose |
|---|---|---|---|
| Cloud Identity | `cloudidentity.groups.list`, `cloudidentity.memberships.list` (per group) | Group + membership inventory | Federation source-of-truth. |
| Cloud Identity / Admin SDK | `admin.users.list` (Workspace API) — optional | User states (suspended, etc.) | Lifecycle. |
| IAM | `cloudresourcemanager.projects.getIamPolicy`, per `serviceAccount` `iam.projects.serviceAccounts.list` | Service-account inventory | Workload identity. |
| IAM | `iam.projects.serviceAccounts.keys.list` (per SA) | SA key inventory | Should ideally be empty (Workload Identity Federation eliminates SA JSON keys). |
| Org Policy | `orgpolicy.policies.get(name=...iam.disableServiceAccountKeyCreation)` | Constraint enforcement | Active prohibition. |
| Recommender | `recommender.recommendations.list(recommender=google.iam.serviceAccount.IdleRecommender)` | Idle service accounts | Lifecycle hygiene. |
| Recommender | `recommender.recommendations.list(recommender=google.iam.policy.Recommender)` | Over-privilege findings | Lifecycle hygiene. |
| Workforce Identity Federation | `iam.locations.workforcePools.list` (each pool: providers, sessionExpiration) | WIF pools | Federation evidence. |

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.iam.no_human_iam_users_in_prod` | Zero IAM users in prod accounts that have console logins (only federated SSO). |
| `aws.iam.no_access_keys_older_than_90d` | All access keys are <90 days old (or are roles, not users). |
| `aws.identity_center.scim_provisioning_active` | Identity Store has been refreshed via SCIM within the last 24 hours (look at user `updated_at`). |
| `aws.access_analyzer.unused_access_count_below_threshold` | Unused-access findings ≤ threshold (config'd, e.g. 25 — and trending down). |
| `gcp.org.disable_sa_key_creation_enforced` | `iam.disableServiceAccountKeyCreation` enforced at org. |
| `gcp.sa.no_user_managed_keys_in_prod` | No user-managed (downloadable) service-account keys in prod projects. |
| `gcp.recommender.no_idle_sas_over_90d` | No idle SA findings older than 90 days unresolved. |
| `gcp.workforce_identity.pool_configured` | At least one workforce identity pool exists with an external IdP. |

---

### KSI-IAM-APM — Adopting Passwordless Methods

**Domain:** IAM · **Scope:** **CLOUD**

**Statement.** Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA for authentication.

**NIST 800-53 controls.** Not populated. Maps to `ia-2`, `ia-2.1`, `ia-5` (authenticator management), `ia-5.1` (password complexity / FIDO2 / WebAuthn).

**Analysis.** Either passwordless (FIDO2/WebAuthn) is the primary authenticator, OR a strong password policy + MFA is enforced as fallback. Evidence: IdP policy + IAM Identity Center / Cloud Identity password & MFA settings + presence of WebAuthn enrollment for users.

**Classification — CLOUD.**

#### Script plan — IAM-APM

**AWS:**
- `iam.GetAccountPasswordPolicy` — `MinimumPasswordLength`, `RequireSymbols`, `RequireNumbers`, `RequireUppercaseCharacters`, `RequireLowercaseCharacters`, `MaxPasswordAge`, `PasswordReusePrevention`, `HardExpiry`.
- `sso-admin.DescribeInstanceAccessControlAttributeConfiguration` and via Identity Store policy — confirm MFA-required.
- `cognito-idp.DescribeUserPool` (for app-user pools) — `Policies.PasswordPolicy`, `MfaConfiguration`, `UserPoolAddOns.AdvancedSecurityMode`.

**GCP:**
- `cloudidentity.groups.list` — confirm a "high-privilege" group restricted to specific 2SV factors.
- Workspace Admin SDK / Cloud Identity (`policy.getEffective`) — 2SV enforcement, allowed factors (security keys / TOTP / passkeys).
- `identitytoolkit.tenants.get` (Identity Platform) — for app-user pools: password policy + MFA enabled.
- Context-Aware Access policies — restrict MFA factor (e.g. "require security key for sensitive resources").

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.iam.password_policy_strong` | `MinimumPasswordLength >= 14`, all complexity flags true, `PasswordReusePrevention >= 12`. |
| `aws.identity_center.mfa_required` | IAM Identity Center MFA is required for every sign-in. |
| `aws.cognito.app_pools_mfa_required` | All in-scope Cognito user pools have `MfaConfiguration=ON`. |
| `gcp.cloud_identity.2sv_enforced` | 2SV is enforced for all users in the in-scope OU. |
| `gcp.cloud_identity.2sv_security_keys_or_passkeys_only` | Allowed 2SV factors restricted to security keys / passkeys for privileged users (TOTP allowed for low-priv). |
| `gcp.context_aware_access.policy_present` | At least one CAA policy enforces phishing-resistant MFA. |

---

### KSI-IAM-ELP — Ensuring Least Privilege

**Domain:** IAM · **Scope:** **CLOUD**

**Statement.** Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need.

**NIST 800-53 controls.** Not populated. Maps to `ac-2`, `ac-6`, `ac-6.5` (privileged accounts).

**Analysis.** Least-privilege evidence comes from:
1. Policy hygiene (no admin everywhere; permission boundaries; SCPs).
2. Continuous review — Access Analyzer unused-access findings count, IAM Recommender over-grant findings, IAM Access Advisor "last accessed" timestamps for every service per role.
3. Active remediation — closed-loop tracking of findings.

**Classification — CLOUD.**

#### Script plan — IAM-ELP

**AWS:**
- `iam.GenerateServiceLastAccessedDetails` + `iam.GetServiceLastAccessedDetails` (for each high-priv role) — "last access per service" per role. Anything not accessed in 90 days is a candidate to remove.
- `accessanalyzer.ListAnalyzers(type=UNUSED_ACCESS)`, `accessanalyzer.ListFindings` — unused-permission findings.
- `iam.SimulatePrincipalPolicy` — can be invoked for a target action set against a role to assert "this role cannot do X" (e.g. assert SREs cannot read prod customer data buckets). This is gold-standard scripted evidence.
- `iam.ListPolicyVersions` and policy contents — surface wildcards.

**GCP:**
- `recommender.recommendations.list(recommender=google.iam.policy.Recommender)` per project — over-grant findings.
- `policysimulator.v1.replays.create` — simulate impact of removing a role; gold-standard evidence.
- IAM bindings audit at org/folder/project for primitive roles.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.access_analyzer.unused_findings_trend_down` | Unused-access findings ≤ previous-run findings (drift detection). |
| `aws.iam.no_user_with_inline_admin` | No IAM user has an inline admin policy. |
| `aws.iam.role_last_used_within_90d` | Every role has been used within 90 days OR is documented as break-glass/event-driven. |
| `gcp.iam.no_primitive_roles_on_prod` | (Repeat from CNA-DFP but ELP-scoped — primitive roles flagged.) |
| `gcp.recommender.role_recommendations_addressed` | Each open `REMOVE_ROLE` recommendation has an action: implemented, dismissed-with-justification, or active ticket. |

---

### KSI-IAM-JIT — Authorizing Just-in-Time

**Domain:** IAM · **Scope:** **HYBRID**

**Statement.** Use a least-privileged, role and attribute-based, and just-in-time security authorization model for all user and non-user accounts and services.

**NIST 800-53 controls.** Not populated. Maps to `ac-2`, `ac-6.7`.

**Analysis.** JIT means: privileged access is granted for a bounded duration, in response to an explicit request, and audited. Tools include IAM Identity Center permission-set session duration + ABAC, AWS Session Manager (no SSH key), GCP Privileged Access Manager (GA 2024), IAP TCP/SSH for Linux bastion-less access, or 3rd-party tools (Teleport, ConductorOne, SailPoint). The HYBRID call is because many shops use a 3rd-party JIT tool, which has its own evidence outside cloud APIs (the request/approval log).

**Classification — HYBRID.**

#### Script plan — IAM-JIT

**AWS evidence:**
- `sso-admin.ListPermissionSets`, `sso-admin.DescribePermissionSet` — confirm `SessionDuration` is bounded (≤ 1h for privileged, ≤ 8h general).
- `ssm.DescribeSessions(State=Active)` and (History) — Session Manager session log.
- `cloudtrail` filtering for `AssumeRole` events to high-privilege roles.

**GCP evidence:**
- `privilegedaccessmanager` (PAM) API — `entitlements.list`, `grants.list` per entitlement — JIT grant evidence directly from PAM.
- IAP — `iap.tunnelInstances.list`, IAP audit logs.
- IAM conditional bindings (`condition.expression` contains `request.time` < expiry) — time-bound access.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.identity_center.permission_set_session_duration_<=8h` | No permission set has SessionDuration > 8h. |
| `aws.identity_center.privileged_session_duration_<=1h` | Permission sets in a designated "Privileged" group have SessionDuration ≤ 1h. |
| `aws.ssm.session_manager_used_for_shell_access` | Recent shell access shows Session Manager usage, not SSH key. |
| `gcp.pam.entitlements_defined_for_break_glass` | At least one PAM entitlement covers break-glass roles. |
| `gcp.iam.conditional_bindings_for_privileged_roles` | Privileged role bindings use IAM conditions with time-bound expiry. |
| `gcp.iap.ssh_tunnels_logged` | IAP TCP/SSH tunnels are audited via Cloud Audit Logs. |

**Process artifacts.** 3rd-party JIT tool (if used): tool name, request-log export URL, sample audit trail for last 30 days.

---

### KSI-IAM-MFA — Enforcing Phishing-Resistant MFA

**Domain:** IAM · **Scope:** **CLOUD**

**Statement.** Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication.

**NIST 800-53 controls.** Not populated. Maps to `ia-2.1` (network access privileged), `ia-2.2` (network access non-privileged), `ia-2.6` (network access individual cryptographic), `ia-2.8` (replay-resistant authentication).

**Analysis.** Phishing-resistant = FIDO2 / WebAuthn / PIV (smart cards) / passkeys. SMS, voice, TOTP, push notifications all FAIL the "phishing-resistant" bar. This is stricter than IAM-APM. Evidence requires the policy to specifically allow only WebAuthn / security keys (or strongly-bound passkeys) for privileged users at minimum.

**Classification — CLOUD.**

#### Script plan — IAM-MFA

**AWS evidence:**
- `iam.ListVirtualMFADevices`, `iam.ListMFADevices(UserName=...)` — surface non-FIDO MFA (virtual = TOTP = not phishing-resistant).
- `sso-admin` / IAM Identity Center external IdP config — confirm IdP allowed methods restrict to WebAuthn.
- Root account: `iam.GetAccountSummary` returns `AccountMFAEnabled` count.
- SCP: scan for policies that `Deny` `*` for principals without `aws:MultiFactorAuthPresent` + `aws:MultiFactorAuthAge < 3600`.
- Cognito: `cognito-idp.DescribeUserPool.MfaConfiguration` + `UserPool.Policies.PasswordPolicy` + WebAuthn enabled per pool.

**GCP evidence:**
- Cloud Identity 2SV enforcement policy + allowed factors (`policy.getEffective` with name `settings/SecuritySettings`).
- Workspace allowed 2SV methods restricted to security keys for privileged OU.
- Context-Aware Access policy with `device.encryptionStatus.encrypted == true && session.duration < 1h` and factor restriction.
- Identity Platform (`identitytoolkit.tenants.get`): `mfaConfig.state=ENFORCED` and `mfaConfig.enabledProviders` only contains TOTP or phone? Note: phone is NOT phishing-resistant.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.iam.root_mfa_enabled` | Root MFA enabled on every account in scope. |
| `aws.iam.all_iam_users_have_mfa` | Every standalone IAM user (if any) has MFA. |
| `aws.identity_center.idp_restricts_to_webauthn` | The IdP-configured Identity Center instance restricts authn to WebAuthn/passkey. |
| `aws.scp.deny_no_mfa` | An SCP attached to the org or prod OU denies actions for principals without a recent MFA presence. |
| `gcp.cloud_identity.2sv_enforced_security_keys` | Privileged OU restricted to security-keys-only 2SV. |
| `gcp.context_aware_access.blocks_weak_mfa` | A CAA policy blocks access for sessions authenticated via SMS/phone. |

---

### KSI-IAM-SNU — Securing Non-User Authentication

**Domain:** IAM · **Scope:** **CLOUD**

**Statement.** Enforce appropriately secure authentication methods for non-user accounts and services.

**NIST 800-53 controls.** Not populated. Maps to `ac-2.7` (privileged accounts), `ia-5` (authenticator management), `ia-9` (service identification and authentication).

**Analysis.** Service-to-service authentication must NOT use long-lived bearer tokens (IAM access keys, GCP SA JSON keys) where workload identity is available. For EKS pods: IRSA. For EC2: IAM instance profile (short-lived STS credentials). For ECS: task role. For Lambda: execution role. For GKE pods: Workload Identity. For Compute: SA + IAM. For external workloads: IAM Roles Anywhere (AWS) / Workload Identity Federation (GCP). Where credentials must exist (legacy systems): they're in Secrets Manager / Secret Manager with rotation enabled.

**Classification — CLOUD.**

#### Script plan — IAM-SNU

**AWS evidence:**
- `iam.ListAccessKeys` (count keys across all users — should be near-zero, only services that can't use roles).
- `eks.DescribeAddonVersions` + cluster RBAC checks: IRSA installed? Pods use service accounts annotated with `eks.amazonaws.com/role-arn`?
- `iam.ListRoles(PathPrefix=/aws-roles-anywhere/)`, `rolesanywhere.ListProfiles` — Roles Anywhere setup.
- `secretsmanager.ListSecrets` + `DescribeSecret` per secret — rotation enabled? lambda rotation function attached?
- `kms.ListKeys`, `kms.GetKeyRotationStatus` — CMK rotation enabled.

**GCP evidence:**
- `iam.projects.serviceAccounts.keys.list` per SA — count user-managed keys (should be 0 for prod).
- `container.projects.locations.clusters.get` — `workloadIdentityConfig.workloadPool` set?
- `iam.locations.workloadIdentityPools.list` — Workload Identity Federation for non-GCP workloads.
- `secretmanager.projects.secrets.list`, `secretmanager.projects.secrets.versions.list` — versions present, rotation period set on metadata.
- `kms.projects.locations.keyRings.cryptoKeys.list` — `rotationPeriod`.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.iam.access_keys_count_<=N` | Total IAM access keys across the org ≤ documented exception count. |
| `aws.eks.irsa_configured_on_prod_clusters` | Prod EKS clusters have IRSA configured (Pod IAM via roles). |
| `aws.secretsmanager.rotation_enabled_on_prod_secrets` | Secrets in prod have rotation enabled or are documented as static. |
| `aws.kms.cmk_rotation_enabled` | All in-scope customer-managed KMS keys have rotation enabled (`KeyRotationStatus.KeyRotationEnabled=true`). |
| `gcp.sa.no_user_managed_keys_in_prod` | (mirrors IAM-AAM, but SNU-tagged for traceability) |
| `gcp.gke.workload_identity_configured` | Prod GKE clusters have Workload Identity. |
| `gcp.kms.rotation_period_<=90d` | Prod KMS keys rotate at least every 90 days. |
| `gcp.secret_manager.rotation_metadata_present` | Secrets have rotation metadata (`rotation.nextRotationTime` or are flagged static). |

---

### KSI-IAM-SUS — Responding to Suspicious Activity

**Domain:** IAM · **Scope:** **HYBRID**

**Statement.** Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity.

**NIST 800-53 controls.** Not populated. Maps to `au-6` (audit-record review), `ir-4` (incident handling), `si-4` (system monitoring).

**Analysis.** Automation that detects suspicious activity and acts: GuardDuty findings of compromised credentials → EventBridge → Lambda that disables the IAM user / quarantines the role; SCC `IAM_ANOMALOUS_GRANT` / `ACCESS_FROM_HIGHLY_RISKY_LOCATION` findings → Eventarc → Cloud Function that revokes the binding. Pure cloud evidence covers the *automation existing*; the *runbook for false-positive recovery* is process.

**Classification — HYBRID.**

#### Script plan — IAM-SUS

**AWS evidence:**
- `guardduty.ListDetectors`, `guardduty.GetDetector` — enabled; finding-publishing-frequency.
- `guardduty.ListFindings(FindingCriteria={"updatedAt": ">last_7d"})` — recent findings counts by type.
- `events.ListRules(EventBusName=default)` — rules with `source: aws.guardduty` AND a `target` action.
- For each such rule: `events.ListTargetsByRule` — Lambda/Step Function/SNS targets.
- `lambda.GetFunction(FunctionName=...)` for the response Lambda — verify it's exists and recent.
- `securityhub.GetFindings(Filters={"WorkflowStatus":{"NEW"}})` — outstanding findings vs. resolved.

**GCP evidence:**
- `securitycenter.organizations.notificationConfigs.list` — notification configs targeting findings.
- `eventarc.locations.triggers.list` — Eventarc triggers consuming SCC findings.
- `securitycenter.organizations.muteConfigs.list` — confirm broad mute configs aren't masking suspicious findings.
- `securitycenter.organizations.findings.list(filter="category:IAM_ANOMALOUS_GRANT")` etc.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.guardduty.enabled_org_wide` | GuardDuty enabled in all in-scope accounts. |
| `aws.guardduty.cred_compromise_findings_have_eventbridge_response` | An EventBridge rule routes `Stealth:IAMUser/*` and `CredentialAccess:IAMUser/*` findings to a Lambda or SNS. |
| `aws.lambda.response_function_recent_invocation_or_test` | The response Lambda has been invoked (real or test) within the last 30 days. |
| `aws.security_hub.no_critical_iam_findings_unresolved_>72h` | Critical IAM findings older than 72h either resolved or have a documented exception. |
| `gcp.scc.notificationconfig_for_iam_findings` | SCC notification config routes IAM_* category findings. |
| `gcp.eventarc.scc_finding_triggers` | At least one Eventarc trigger consumes SCC findings. |

**Process artifacts.** Response runbook URL; record of last simulated suspicious-activity drill.

---

## INR — Incident Response

> Theme: implicit — incidents drive learning; after-actions, procedure review, and pattern analysis must be continuous.

3 KSIs, all about IR program effectiveness rather than incident execution
mechanics (which are covered by AFR-ICP). Two are pure PROCESS; one
(INR-RIR) is HYBRID because procedure review benefits from cloud-side data
on tool wiring.

---

### KSI-INR-AAR — Generating After Action Reports

**Domain:** INR · **Scope:** PROCESS

**Statement.** Generate incident after action reports and persistently incorporate lessons learned.

**Analysis.** Every incident (real or simulated) above a defined threshold (e.g. Sev-1, Sev-2) gets an AAR within N business days. AARs include timeline, root cause, contributing factors, mitigations applied, prevention steps, and a tracked-action-item list whose closure is monitored. Evidence: AAR repository (likely in your wiki/Confluence/Notion), action-item tracker, follow-through metrics.

**Classification — PROCESS.** Tracker fields: AAR repository URL, AAR template URL, action-item tracker URL, last AAR date.

> *Cloud signal:* if you wire incident detection to a ticket system (PagerDuty + Jira), the count of Sev-1 incidents over a period is available as a metric — useful for review meetings but not the AAR itself.

---

### KSI-INR-RIR — Reviewing Incident Response Procedures

**Domain:** INR · **Scope:** **HYBRID**

**Statement.** Persistently review the effectiveness of documented incident response procedures.

**Analysis.** Procedure review covers two things: (1) is the runbook correct and up to date? (2) is it actually executable — are the tool-to-runbook wirings (alert sources → on-call → runbook anchor) working? Cloud evidence covers (2): alert source inventory (CloudWatch alarms with SNS targets, EventBridge → PagerDuty rules, SCC notification configs), on-call rotation systems (PagerDuty / OpsGenie API for evidence), and recent alert delivery (samples). (1) is purely process — the runbook itself.

**Classification — HYBRID.**

#### Script plan — INR-RIR

**AWS evidence:**
- `cloudwatch.DescribeAlarms` — alarm count, alarms with `AlarmActions` set, alarms in `INSUFFICIENT_DATA` state.
- `sns.ListSubscriptions` — confirm subscriptions are active (`SubscriptionArn != PendingConfirmation`); targets point at PagerDuty / OpsGenie / Slack webhook.
- `events.ListRules(EventBusName=default)` filtered to security event sources (guardduty, securityhub, inspector2, config).
- `chatbot.DescribeChatbotConfigurations` (AWS Chatbot) — Slack/Chime channel wirings.
- `health.DescribeEvents` — AWS health events (incident context).

**GCP evidence:**
- `monitoring.notificationChannels.list` — channels (Slack, PagerDuty, email).
- `monitoring.alertPolicies.list` — count, severity, notification-channel attachment.
- `securitycenter.organizations.notificationConfigs.list` — SCC routing.
- `eventarc.locations.triggers.list` filtered to security event types.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.cloudwatch.critical_alarms_have_actions` | Every alarm flagged "critical" (via tag) has at least one `AlarmAction` configured. |
| `aws.sns.no_pending_subscriptions_on_alert_topics` | No pending-confirmation subscriptions on alert topics. |
| `aws.eventbridge.guardduty_rules_have_targets` | Every EventBridge rule sourcing GuardDuty has a target. |
| `gcp.monitoring.critical_policies_have_channels` | Every critical alert policy has ≥1 notification channel. |
| `gcp.scc.notificationconfig_target_active` | SCC notification configs have active downstream subscribers (Pub/Sub topic in `ACTIVE` state). |

**Process artifacts.** IR runbook URL, last procedure-review minutes, tabletop log, on-call rotation source.

---

### KSI-INR-RPI — Reviewing Past Incidents

**Domain:** INR · **Scope:** PROCESS

**Statement.** Persistently review past incidents for patterns or vulnerabilities.

**Analysis.** Periodic (quarterly?) trend analysis across the incident corpus: are similar incidents recurring? Are root-cause categories shifting? Are action items from prior AARs actually preventing recurrence? Evidence: incident-DB query exports, trend dashboards, review-meeting minutes.

**Classification — PROCESS.** Tracker fields: incident database URL, trend dashboard URL, review cadence, last review date.

> *Cloud signal:* if you have a SIEM (MLA-OSM), your incident corpus is queryable. The script's MLA-OSM output could note "SIEM has N security-incident records for last 90 days."

---

## MLA — Monitoring, Logging, and Auditing

> Theme: implicit — comprehensive, tamper-resistant logging with controlled access; continuous evaluation; centralized SIEM.

5 KSIs spanning log access control, configuration evaluation, log event-type
inventory, SIEM operation, and log review. Three are CLOUD, two HYBRID.

---

### KSI-MLA-ALA — Authorizing Log Access

**Domain:** MLA · **Scope:** **CLOUD**

**Statement (Moderate; Low is "Optional").** Use a least-privileged, role and attribute-based, and just-in-time access authorization model for access to log data based on organizationally defined data sensitivity.

**NIST 800-53 controls.** `si-11` (error handling — log content protection).

**Analysis.** Log destinations (S3 buckets holding CloudTrail, log buckets in Cloud Logging, BigQuery datasets sinked to from Cloud Audit Logs, OpenSearch domains, Splunk/Datadog) are sensitive — they contain PII, security events, customer-data-access records. Access must be (a) least-privileged (only on-call security engineers and SIEM ingestion roles), (b) attribute-conditioned (e.g. limited to corp network or VPN), (c) just-in-time (privileged-access escalation for raw log access). Plus encryption at rest with CMK and access logging on the log store itself.

**Classification — CLOUD.**

#### Script plan — MLA-ALA

**AWS evidence:**
- For each CloudTrail destination bucket: `s3.GetBucketPolicy`, `s3.GetBucketAcl`, `s3.GetBucketEncryption`, `s3.GetBucketLogging`, `s3.GetBucketVersioning`, `s3.GetObjectLockConfiguration`.
- For each CW Logs log group with audit content: `logs.DescribeLogGroups` + `logs.AssociateKmsKey`-state, `logs.ListTagsForResource`, `logs.DescribeSubscriptionFilters` (downstream targets), `kms.GetKeyPolicy` for the CMK.
- For OpenSearch domains: `opensearch.DescribeDomainConfig` — `AccessPolicies`, `EncryptionAtRestOptions`, `NodeToNodeEncryptionOptions`, `AdvancedSecurityOptions.SAMLOptions` or master users; fine-grained access control enabled.
- For Security Lake: `securitylake.GetSubscriber` per subscriber — subscriber roles, access tokens, IAM trust policy.

**GCP evidence:**
- `logging.projects.locations.buckets.list` — log buckets with `cmekSettings.kmsKeyName`, `retentionDays`, `locked`.
- For log buckets: `logging.projects.locations.buckets.get` + IAM via `logging.locations.buckets.getIamPolicy` — who can read.
- For BigQuery audit datasets: `bigquery.datasets.get` + `.getIamPolicy` + `defaultEncryptionConfiguration`.
- For Pub/Sub topics receiving log sinks: `pubsub.topics.list`, `.getIamPolicy`, `.kmsKeyName`.
- Cloud KMS key policy backing log encryption: `kms.cryptoKeys.getIamPolicy`.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.s3.audit_buckets_no_world_read` | No CloudTrail/audit bucket has `PrincipalIsAWSAccount: *` or world-readable policy. |
| `aws.s3.audit_buckets_object_lock_enabled` | Object Lock enabled on audit buckets. |
| `aws.s3.audit_buckets_sse_kms` | SSE-KMS with CMK on every audit bucket. |
| `aws.cw_logs.audit_groups_encrypted_with_cmk` | Audit log groups have a CMK association. |
| `aws.opensearch.fgac_enabled` | OpenSearch fine-grained access control enabled; no anonymous access. |
| `gcp.logging.audit_buckets_locked_and_cmek` | Audit log buckets have `locked=true` and CMEK set. |
| `gcp.logging.bucket_iam_least_priv` | Log bucket IAM has no `roles/logging.viewer` at org level (project-scoped only) and no `allUsers` / `allAuthenticatedUsers`. |
| `gcp.pubsub.audit_topic_cmek` | Pub/Sub topics receiving audit-log sinks have `kmsKeyName` set. |

---

### KSI-MLA-EVC — Evaluating Configurations

**Domain:** MLA · **Scope:** **CLOUD**

**Statement.** Persistently evaluate and test the configuration of machine-based information resources, especially infrastructure as code.

**Analysis.** Continuous evaluation of running config (via AWS Config / Security Hub / SCC Security Health Analytics) AND of IaC at PR time (tfsec, Checkov, cfn-nag, Config Validator) AND of running containers/images (Inspector, Artifact Analysis, image-scanning policies). This is a comprehensive "is what's running aligned with intent" KSI — different from CNA-EIS (which is more about *enforcing* intent) and SVC-ACM (managing config via automation). MLA-EVC is the *measurement*.

**Classification — CLOUD.**

#### Script plan — MLA-EVC

Largely overlaps with CNA-EIS + CNA-IBP, but emphasizes *evaluation cadence + scope*:

**AWS evidence:**
- `config.DescribeConfigurationRecorderStatus` — recording enabled, last status time.
- `config.DescribeConfigRules` + per-rule `config.DescribeComplianceByConfigRule` — count of rules + compliance.
- `securityhub.GetEnabledStandards`, `securityhub.GetFindings` — finding lifecycle: NEW / NOTIFIED / SUPPRESSED / RESOLVED.
- `inspector2.ListFindings` — vuln findings on EC2/ECR/Lambda.
- CodeBuild buildspec content (read via `codebuild.BatchGetProjects.source` for git sources): grep for tfsec/checkov/cfn-nag invocations.
- (Optional) artifact: PR-time scanner runs visible in CodeBuild reports `codebuild.DescribeTestCases`.

**GCP evidence:**
- `securitycenter.organizations.findings.list(filter="category:CONFIG*")` — SHA / posture findings.
- `cloudbuild.projects.builds.list` filter for builds running `tfsec` / `checkov` / Config Validator steps.
- `containeranalysis.occurrences.list` filter `kind:VULNERABILITY` for recent scan results.
- `gkehub.features.list` — Config Management / Policy Controller feature state per cluster.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.config.recorder_status_healthy` | Recorder `lastStatus=Success` within last 24h. |
| `aws.security_hub.findings_lifecycle_managed` | <X% of findings older than 30d still in NEW (i.e. triage is happening). |
| `aws.inspector.high_findings_under_sla` | High-severity Inspector findings resolved within SLA. |
| `gcp.scc.findings_lifecycle_managed` | (mirror) |
| `gcp.cloudbuild.iac_scanners_invoked` | Recent builds for IaC source paths invoke tfsec or Checkov. |
| `gcp.policy_controller.constraints_enforced` | Policy Controller enforcing ≥N constraints on prod clusters. |

---

### KSI-MLA-LET — Logging Event Types

**Domain:** MLA · **Scope:** **HYBRID**

**Statement.** Maintain a list of information resources and event types that will be logged, monitored, and audited, then do so.

**NIST 800-53 controls (implied).** `au-2` (event logging), `au-3` (content), `au-12` (record generation).

**Analysis.** Two artifacts: (a) the *list* — a doc that says "for each in-scope resource type, here are the events we log and where they go" — and (b) the *enforcement* — that those events are in fact logged. The list is process; the enforcement is cloud-side and overlaps with CMT-LMC.

**Classification — HYBRID.**

#### Script plan — MLA-LET

**AWS evidence:** (mostly mirrors CMT-LMC but enumerates per-source completeness)
- CloudTrail mgmt + data events (for S3, DynamoDB, Lambda) coverage.
- VPC Flow Logs per VPC.
- ELB/CloudFront/API Gateway access logs configuration.
- RDS / Aurora `Audit` log export enabled.
- EKS audit-log enabled (`cluster.logging.clusterLogging.audit`).
- WAF logging configured (`wafv2.GetLoggingConfiguration`).

**GCP evidence:**
- Cloud Audit Logs: Admin Activity (always on), System Event (always on), Data Access (must be enabled per-service for in-scope services), Policy Denied.
- VPC Flow Logs (per subnet `logConfig.enable=true`).
- Cloud Load Balancing logs (`backendService.logConfig.enable`).
- GKE audit-log delivered to Cloud Logging (`cluster.loggingConfig.componentConfig.enableComponents` includes `KUBE_API_SERVER`).
- Cloud SQL audit / database flags.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.cloudtrail.data_events_on_s3_in_scope_buckets` | CloudTrail data events configured for in-scope S3 buckets. |
| `aws.vpc.flow_logs_enabled_all_vpcs` | All in-scope VPCs have flow logs. |
| `aws.eks.audit_log_enabled` | EKS cluster logging includes audit. |
| `aws.elb.access_logs_enabled` | All prod ALBs have access logs to S3. |
| `gcp.audit.data_access_enabled_for_storage_kms_iam` | Data Access logs ON for `storage.googleapis.com`, `cloudkms.googleapis.com`, `iam.googleapis.com`. |
| `gcp.vpc.flow_logs_enabled_all_subnets` | All prod subnets have flow logs. |
| `gcp.gke.audit_log_components` | GKE clusters log `KUBE_API_SERVER` events to Cloud Logging. |
| `gcp.lb.backend_service_logging_enabled` | Prod backend services log requests. |

**Process artifacts.** The "list" — a doc/spreadsheet enumerating resource types × event types × destination × retention. The script can produce a *first-draft* by enumerating what's actually configured, but the canonical list lives in the doc.

---

### KSI-MLA-OSM — Operating SIEM Capability

**Domain:** MLA · **Scope:** **HYBRID**

**Statement (Moderate).** Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistent logging of events, activities, and changes.

**Analysis.** SIEM evidence has two cases:
1. **Cloud-native SIEM** (AWS Security Lake + OCSF subscribers; Chronicle SIEM; SCC Premium) — fully scriptable.
2. **3rd-party SIEM** (Splunk, Datadog, Elastic, Sumo Logic, etc.) — cloud-side evidence is the *export plumbing* (log sinks → Pub/Sub → 3rd party; CloudWatch Logs subscription filters → Lambda → 3rd party; or Kinesis Firehose → 3rd party). The SIEM itself has separate evidence (UI/API of the SIEM showing ingestion lag, alert rules, dashboards).

**Classification — HYBRID.**

#### Script plan — MLA-OSM

**AWS evidence:**
- `securitylake.GetDataLakeSources`, `securitylake.GetDataLakeOrganizationConfiguration`, `securitylake.ListSubscribers` — Security Lake state.
- For 3rd-party export: `logs.DescribeSubscriptionFilters` per log group; Kinesis Firehose `firehose.ListDeliveryStreams`, `firehose.DescribeDeliveryStream` (destination type).
- `securityhub.DescribeHub`, `securityhub.ListMembers` — Security Hub aggregation if used as SIEM-light.

**GCP evidence:**
- Chronicle: organization-level configuration via Chronicle API (requires Chronicle backend ID + auth). Detect "is Chronicle configured?" via the export config or via a 3rd-party log sink.
- Log sinks routing to BigQuery + downstream SIEM: `logging.projects.sinks.list` + sink destination.
- Pub/Sub topic IAM that grants 3rd-party SIEM read: `pubsub.topics.getIamPolicy`.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.security_lake.enabled` OR `aws.cw_logs.subscription_filters_to_external_siem_present` | At least one of: Security Lake configured, OR a CW Logs subscription filter to a Firehose/Lambda exports to an external SIEM. |
| `gcp.logging.sink_to_siem_destination` OR `gcp.chronicle.configured` | Log sink to BigQuery/Pub/Sub consumed by external SIEM, OR Chronicle configured. |
| `*.siem.ingestion_lag_<5min` | Latest record arrival lag < threshold (from SIEM's own API; may need a config-driven probe). |

**Process artifacts.** SIEM vendor + tenant ID, alert rule count, ingestion lag dashboard, sample query showing recent data.

---

### KSI-MLA-RVL — Reviewing Logs

**Domain:** MLA · **Scope:** **CLOUD**

**Statement.** Persistently review and audit logs.

**Analysis.** Log review is a deliberate activity. Cloud-side evidence: saved queries, dashboards, scheduled reports. Athena saved queries + workgroups for AWS; Log Analytics + Looker Studio for GCP; Chronicle rules. Cadence + ownership is process (tracker fields).

**Classification — CLOUD.** Tooling evidence is fully scriptable.

#### Script plan — MLA-RVL

**AWS:**
- `athena.ListWorkGroups`, `athena.ListNamedQueries` per WG, `athena.GetNamedQuery` — saved queries used for log review.
- `cloudwatch.DescribeAlarms` filtered to security-event metrics.
- `eventbridge.ListRules` for scheduled rules running log-review Lambdas.

**GCP:**
- `bigquery.savedQueries.list` (via internal API or Console exports).
- `monitoring.dashboards.list` — security dashboards.
- `chronicle.detections.list` — Chronicle rules (if Chronicle).

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.athena.has_security_saved_queries` | At least N saved queries in a "security" workgroup. |
| `gcp.bq.has_security_saved_queries` OR `gcp.monitoring.has_security_dashboards` | At least one security dashboard or saved query exists. |

**Process artifacts.** Log-review SOP, review cadence, owners.

---

## PIY — Policy and Inventory

> Theme: implicit — security is sustained by executive support, investment, SDLC integration, vulnerability disclosure, and a live inventory.

5 KSIs. Only one (PIY-GIV — generating inventories) is cloud-side; the
other four are governance/program-level reviews.

---

### KSI-PIY-GIV — Generating Inventories

**Domain:** PIY · **Scope:** **CLOUD**

**Statement.** Use authoritative sources to automatically generate real-time inventories of all information resources when needed.

**NIST 800-53 controls.** Not populated. Maps to `cm-8` (system component inventory), `cm-8.1` (updates during installation), `pm-5` (system inventory).

**Analysis.** "Real-time inventory" = the cloud control plane (AWS Config aggregator across regions + accounts; GCP Cloud Asset Inventory at org level). Inventory should cover compute (VMs, containers, functions), data stores, networks, IAM, KMS keys, certificates. It should be queryable on demand and feed downstream KSIs (especially MAS scope verification and CSX-SUM). The "authoritative sources" qualifier is important — the inventory must come from the cloud's own APIs, not a hand-maintained spreadsheet.

**Classification — CLOUD.**

#### Script plan — PIY-GIV

**Modules:**
- `providers/aws/inventory.ts → collectPiyGivAws()`
- `providers/gcp/inventory.ts → collectPiyGivGcp()`

**AWS evidence:**
- `config.DescribeConfigurationAggregators`, `config.DescribeConfigurationAggregatorSourcesStatus` — verify a multi-account aggregator exists and is healthy.
- `config.SelectAggregateResourceConfig(Expression="SELECT ... GROUP BY resourceType")` — counts by resource type.
- `resource-explorer-2.ListIndexes`, `resource-explorer-2.ListViews` — Resource Explorer setup.
- `ssm.GetInventory` — instance-level software inventory.
- `tag.GetResources` — resource tagging coverage (every prod resource has `env=prod`?).

**GCP evidence:**
- `cloudasset.assets.exportAssets(assetTypes=[...])` or `cloudasset.assets.list(parent=organizations/N, contentType=RESOURCE)` — full org asset list.
- `cloudasset.feeds.list` — feeds for real-time change events.
- `serviceusage.services.list` — enabled APIs (signals scope).
- Resource Manager hierarchy: `cloudresourcemanager.folders.list`, `.projects.list`.

**Captured fields:**
```json
{
  "aws": {
    "config_aggregator_present": true,
    "aggregator_source_accounts": 12,
    "resource_counts_by_type": { "AWS::S3::Bucket": 87, "AWS::EC2::Instance": 142, "AWS::IAM::Role": 612 },
    "resources_with_env_tag_pct": 98.4,
    "ssm_managed_instances": 138,
    "ec2_total": 142
  },
  "gcp": {
    "asset_export_succeeded": true,
    "resource_counts_by_type": { "compute.googleapis.com/Instance": 211, "storage.googleapis.com/Bucket": 64 },
    "asset_feeds_active": 4,
    "projects_in_scope": 14
  }
}
```

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.config.aggregator_covers_all_in_scope_accounts` | The aggregator includes every in-scope account (cross-ref with Organizations). |
| `aws.tagging.env_tag_coverage_>=95%` | ≥95% of taggable prod resources have an `env` tag. |
| `aws.ssm.managed_instance_coverage_>=95%` | ≥95% of EC2 instances are SSM-managed. |
| `gcp.cloud_asset.export_runs_daily` | Asset export runs at least daily and completed successfully in the last 24h. |
| `gcp.tagging.coverage_>=95%` | (GCP labels analogous to AWS tags) |

---

### KSI-PIY-RES — Reviewing Executive Support

**Domain:** PIY · **Scope:** PROCESS

**Statement.** Persistently review executive support for achieving the organization's security objectives.

**Analysis.** Board / exec-team review of the security program: budget approvals, exec sponsorship of major initiatives, prioritization of security in roadmap. Evidence: board minutes (redacted), security-program review packs, exec sign-offs on PVA plan.

**Classification — PROCESS.** Tracker fields: governance doc URL, exec-review cadence, last-review date.

---

### KSI-PIY-RIS — Reviewing Investments in Security

**Domain:** PIY · **Scope:** PROCESS

**Statement.** Persistently review the effectiveness of the organization's investments in achieving security objectives.

**Analysis.** Quarterly/annual review of security spend vs. outcomes — does the X paid for tool Y produce measurable risk reduction? Evidence: spend reports, ROI analyses, tool-by-tool effectiveness assessments.

**Classification — PROCESS.** Tracker fields: investment review doc URL, review cadence.

---

### KSI-PIY-RSD — Reviewing Security in the SDLC

**Domain:** PIY · **Scope:** PROCESS

**Statement.** Persistently review the effectiveness of building security and privacy considerations into the Software Development Lifecycle and aligning with CISA Secure By Design principles.

**Analysis.** SDLC integration review — are SAST/SCA/secret-scan gates effective, is threat modeling done, are privacy reviews triggered correctly. CISA Secure-by-Design alignment is documented and self-assessed.

**Classification — PROCESS.** Tracker fields: SDLC policy URL, last review date, Secure-by-Design self-assessment URL.

> *Indirect cloud signal:* CMT-VTD's gate inventory and SCR-MON's vuln-trend data are inputs to this review.

---

### KSI-PIY-RVD — Reviewing Vulnerability Disclosures

**Domain:** PIY · **Scope:** PROCESS

**Statement.** Persistently review the effectiveness of the provider's vulnerability disclosure program.

**Analysis.** VDP: a public mechanism for security researchers to report vulnerabilities. Evidence: the public VDP page (security.txt, /security URL), intake volume, MTTR by severity, researcher-relationships management. Public bug bounty (HackerOne, Bugcrowd) optional but counts.

**Classification — PROCESS.** Tracker fields: VDP public URL, security.txt URL, MTTR report, last review date.

---

## RPL — Recovery Planning

> Theme: implicit — backups and recovery procedures aligned to defined RPO/RTO, tested persistently.

4 KSIs: backup alignment (HYBRID), recovery-plan alignment (PROCESS),
RTO/RPO review (PROCESS), recovery testing (HYBRID).

---

### KSI-RPL-ABO — Aligning Backups with Objectives

**Domain:** RPL · **Scope:** **HYBRID**

**Statement.** Persistently review the alignment of machine-based information resource backups with defined recovery objectives.

**Analysis.** Backups must match the RPO/RTO documented for each system. For each data store: backup frequency, retention, recovery procedure, last-successful-restore-test. Cloud-side: enumerate backup configurations + recent backup-job outcomes + restore-test outcomes. Process-side: the RPO/RTO doc that defines targets.

**Classification — HYBRID.**

#### Script plan — RPL-ABO

**AWS evidence:**
- AWS Backup: `backup.ListBackupPlans`, `backup.GetBackupPlan` (each), `backup.ListBackupSelections`, `backup.ListBackupJobs(state=COMPLETED, range=last 30d)`, `backup.ListBackupJobs(state=FAILED)`.
- For each plan rule: lifecycle (cold storage move, deletion), schedule, retention.
- For DB-level backups: `rds.DescribeDBInstances.BackupRetentionPeriod`, `rds.DescribeDBSnapshots` (recent), `dynamodb.DescribeContinuousBackups` (PITR enabled), `dynamodb.ListBackups`.
- S3 versioning + replication: `s3.GetBucketVersioning`, `s3.GetBucketReplication`.
- EBS snapshot lifecycle: `dlm.GetLifecyclePolicies` (Data Lifecycle Manager).

**GCP evidence:**
- Backup and DR Service: `backupdr.backupVaults.list`, `backupdr.backupPlans.list`, `backupdr.backupPlans.get`, `backupdr.dataSources.list`.
- Cloud SQL: `sqladmin.instances.list.backupConfiguration` (`enabled`, `startTime`, `pointInTimeRecoveryEnabled`, `backupRetentionSettings.retainedBackups`); `sqladmin.backupRuns.list`.
- Compute snapshots: `compute.snapshotSchedulePolicies` (per project & region), `compute.disks.list` with their `resourcePolicies`.
- Cloud Storage object versioning + retention + dual-region: `storage.buckets.get.versioning.enabled`, `.retentionPolicy`, `.locationType`.
- Spanner backups: `spanner.instances.databases.backups.list`.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.backup.plan_covers_prod_resources` | Every prod-tagged resource type (RDS, DynamoDB, EBS) is covered by at least one backup selection. |
| `aws.backup.no_failed_jobs_last_30d` | Zero failed backup jobs in last 30 days. |
| `aws.rds.prod_pitr_enabled` | Prod RDS instances have backup retention ≥ documented RPO. |
| `aws.dynamodb.pitr_on_prod_tables` | PITR enabled on prod tables. |
| `gcp.backupdr.plan_covers_prod` | Backup and DR plans cover prod data sources. |
| `gcp.cloudsql.pitr_enabled` | Cloud SQL prod instances have `pointInTimeRecoveryEnabled=true`. |
| `gcp.compute.snapshot_schedule_on_prod_disks` | Prod persistent disks have snapshot schedules attached. |
| `gcp.storage.prod_buckets_versioned_or_object_lock` | Prod buckets have versioning + retention/lock. |

**Process artifacts.** RPO/RTO document per system + the alignment review minutes (does each backup config actually achieve its system's RPO?).

---

### KSI-RPL-ARP — Aligning Recovery Plan

**Domain:** RPL · **Scope:** PROCESS

**Statement.** Persistently review the alignment of recovery plans with defined recovery objectives.

**Analysis.** The Disaster Recovery / Business Continuity plan is reviewed against the defined RTO/RPO targets. Cloud config (multi-region replication, failover automation) supports it but the plan itself is a document.

**Classification — PROCESS.** Tracker fields: DR plan URL, last review date, sign-off authority.

---

### KSI-RPL-RRO — Reviewing Recovery Objectives

**Domain:** RPL · **Scope:** PROCESS

**Statement.** Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO).

**Analysis.** Are the targets still right? Customer commitments, business criticality, regulatory drivers. Evidence: review minutes, system-tier matrix (each system's tier + its RTO/RPO).

**Classification — PROCESS.** Tracker fields: system-tier matrix URL, last review date.

---

### KSI-RPL-TRC — Testing Recovery Capabilities

**Domain:** RPL · **Scope:** **HYBRID**

**Statement.** Persistently test the capability to recover from incidents and contingencies, including alignment with defined recovery objectives.

**Analysis.** Test plans run on cadence (game days, restore drills, regional failover exercises). Cloud-side evidence: AWS Fault Injection Simulator (FIS) experiment templates + recent runs; AWS Backup `StartRestoreJob` history with outcomes; cross-region failover exercise traces (CloudWatch metrics during the exercise). GCP-side: Backup and DR restore tests, Cloud SQL clone-to-test runs, Cloud Spanner backup restore, regional MIG failover exercises. Process: the test plan + AAR per test.

**Classification — HYBRID.**

#### Script plan — RPL-TRC

**AWS:**
- `fis.ListExperimentTemplates`, `fis.ListExperiments(stateFilter=COMPLETED, range=last 90d)` — FIS evidence.
- `backup.ListRestoreJobs(byCompletionTimeAfter=90d ago)` — recent restore attempts + outcomes.
- (Per resource type) Recent `dynamodb.RestoreTableFromBackup`, `rds.RestoreDBClusterFromSnapshot` events via CloudTrail.

**GCP:**
- `backupdr.backupPlanAssociations.list` then `backupdr.backups.list` per data source — restore history.
- `sqladmin.backupRuns.list` — Cloud SQL backup runs and any "restore in test instance" flow if you can detect it.
- (Tracker reference) link to game-day docs.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.fis.recent_experiments` | At least N FIS experiments completed in last 90 days. |
| `aws.backup.recent_successful_restore` | At least one successful restore job in last quarter. |
| `gcp.backupdr.recent_successful_restore` | At least one successful restore in last quarter. |

**Process artifacts.** Test plan, last test AAR, restore-time vs. RTO target.

---

## SVC — Service Configuration

> Theme: implicit — service configuration is automated, secrets are managed, data lifecycle is controlled, network and resource integrity validated.

8 KSIs. Six CLOUD, one HYBRID (EIS), one PROCESS (PRR).

---

### KSI-SVC-ACM — Automating Configuration Management

**Domain:** SVC · **Scope:** **CLOUD**

**Statement.** Manage configuration of machine-based information resources using automation.

**NIST 800-53 controls.** Not populated. Maps to `cm-2` (baseline), `cm-3` (change control), `cm-6` (config settings).

**Analysis.** Infrastructure-as-code is the source of truth. Manual changes via console/CLI must be detectable as drift. Tools: Terraform / CloudFormation / CDK / Pulumi / Config Connector / Deployment Manager / Crossplane. Evidence: state files exist + are versioned, drift detection runs, manual changes flagged + reverted or reconciled.

**Classification — CLOUD.**

#### Script plan — SVC-ACM

**AWS evidence:**
- `cloudformation.ListStacks(StackStatusFilter=...)`, `cloudformation.DescribeStacks` — IaC coverage signal.
- `cloudformation.DetectStackDrift` + `cloudformation.DescribeStackResourceDrifts` — drift status per prod stack.
- `config.DescribeConfigRules` filter to drift-related rules (e.g. AWS-managed `cloudformation-stack-drift-detection-check`).
- (Tracker reference) Terraform state location + last-apply timestamps from CI logs.

**GCP evidence:**
- Config Connector: `kubectl get configconnector` on prod GKE clusters; `kubectl get -A` for managed-by-config-connector resources (count).
- Asset Inventory feeds (already collected for CMT-LMC) — provide drift signals.
- Cloud Build trigger configs — IaC pipelines existence.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.cloudformation.no_drifted_prod_stacks` | All prod stacks `DRIFT_STATUS=IN_SYNC` or recently reconciled. |
| `aws.cloudformation.stack_count_>=threshold` | Prod resources are predominantly stack-managed (≥X% of in-scope resources). |
| `gcp.config_connector.deployed_prod_clusters` | Config Connector installed on prod clusters (or Terraform invoked from Cloud Build for prod). |
| `gcp.cloud_build.iac_pipelines_present` | At least one Cloud Build trigger applies Terraform/Config Connector manifests to prod. |

---

### KSI-SVC-ASM — Automating Secret Management

**Domain:** SVC · **Scope:** **CLOUD**

**Statement.** Automate management, protection, and regular rotation of digital keys, certificates, and other secrets.

**NIST 800-53 controls.** Not populated. Maps to `ia-5` (authenticator management), `ia-5.1`, `sc-12` (cryptographic key establishment/management).

**Analysis.** Secrets are: in a managed store (Secrets Manager, Parameter Store, Secret Manager); rotated automatically on schedule; encrypted with CMK; access-controlled via IAM; never copied into source. KMS CMKs rotate. ACM certs auto-renew. Secret-scan in CI catches accidental commits.

**Classification — CLOUD.**

#### Script plan — SVC-ASM

**AWS evidence:**
- `secretsmanager.ListSecrets`, per secret: `DescribeSecret` — `RotationEnabled`, `RotationLambdaARN`, `RotationRules.AutomaticallyAfterDays`, `LastRotatedDate`.
- `ssm.DescribeParameters(ParameterFilters=Type:SecureString)` — SecureString parameters and their `KeyId`.
- `kms.ListKeys`, per key: `GetKeyRotationStatus`, `DescribeKey` (`KeyManager=CUSTOMER`, `KeyUsage`, `KeyState=Enabled`).
- ACM: `acm.ListCertificates`, per cert: `DescribeCertificate` — `Status`, `RenewalSummary.RenewalStatus`, `NotAfter` (expiry).
- IAM: surface IAM access-key inventory (cross-ref with IAM-SNU) to drive home "no embedded keys."

**GCP evidence:**
- Secret Manager: `secretmanager.projects.secrets.list`, per secret: `secretmanager.projects.secrets.get` (`rotation.rotationPeriod`, `rotation.nextRotationTime`, `topics`, `replication`).
- Cloud KMS: `kms.projects.locations.keyRings.cryptoKeys.list`, per key: `cryptoKeys.get` (`rotationPeriod`, `nextRotationTime`, `purpose`, `versionTemplate.algorithm`).
- Certificate Manager: `certificatemanager.projects.locations.certificates.list`, per cert: `.get` (`expireTime`, `managed.state`).

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.secretsmanager.rotation_enabled_>=80%` | ≥80% of secrets have rotation enabled (allow some legacy with documented exception). |
| `aws.secretsmanager.last_rotated_<rotation_period` | For each rotating secret, `LastRotatedDate` is within its `RotationRules.AutomaticallyAfterDays` window. |
| `aws.kms.cmk_rotation_enabled` | All CMKs (CUSTOMER-managed) have rotation enabled. |
| `aws.acm.no_certs_expiring_<30d_renewal_failed` | No certs expiring in <30 days with `RenewalStatus != SUCCESS`. |
| `gcp.secret_manager.rotation_metadata_present` | Secrets have `rotation` metadata set (or are documented as static). |
| `gcp.kms.rotation_period_<=90d_for_prod` | All prod CMEK keys rotate ≤ 90d. |
| `gcp.certificatemanager.no_certs_expiring_<30d_unmanaged` | No managed certs expiring soon in non-managed state. |

---

### KSI-SVC-EIS — Evaluating and Improving Security

**Domain:** SVC · **Scope:** **HYBRID**

**Statement.** Implement improvements based on persistent evaluation of information resources for opportunities to improve security.

**Analysis.** Closed-loop improvement: findings → tickets → fixes → verification → improvements baked into baselines. Cloud-side: ticket-system integration with findings (e.g. Security Hub → JIRA via custom action, SCC → JIRA via Eventarc); resolution times (MTTR) tracked. Process-side: improvement-decision records (the human judgment "we changed our baseline because of finding X").

**Classification — HYBRID.**

#### Script plan — SVC-EIS

**AWS:**
- `securityhub.GetFindings(Filters={Workflow:NOTIFIED})` — findings routed to ticketing.
- `securityhub.DescribeActionTargets` — custom actions (likely a "send to JIRA" action).
- CloudWatch metric for finding age distributions.

**GCP:**
- `securitycenter.organizations.notificationConfigs.list` — finding routing.
- `securitycenter.organizations.findings.list(filter="state:ACTIVE")` — open findings, with `createTime` to compute age distribution.
- `eventarc.locations.triggers.list` — finding consumer triggers.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.security_hub.action_target_to_ticketing` | At least one custom action target routes findings to a ticketing endpoint. |
| `aws.security_hub.mttr_high_findings_<sla` | MTTR for HIGH-severity Security Hub findings < SLA target. |
| `gcp.scc.notificationconfig_to_ticketing` | SCC notification config routes to a ticketing-system integration. |
| `gcp.scc.mttr_high_findings_<sla` | (mirror) |

**Process artifacts.** Improvement-decision log (e.g. "added Config rule X after finding Y").

---

### KSI-SVC-PRR — Preventing Residual Risk

**Domain:** SVC · **Keyword:** (varies by level — Moderate is required, Low is Optional) · **Scope:** PROCESS

**Statement (Moderate).** Persistently review plans, procedures, and the state of information resources after making changes to limit and remove unwanted residual elements that would likely negatively affect the confidentiality, integrity, or availability of federal customer data.

**NIST 800-53 controls (implied).** `sc-4` (information in shared system resources).

**Analysis.** After changes, look for *residual* problems — orphaned snapshots that aren't supposed to exist, leftover security-group rules, stale IAM policies, leftover IPs assigned, expired-but-still-trusted certs. This is a review activity on top of post-change state. Cloud-side findings (orphaned resources detection via Trusted Advisor / Recommender) feed it, but the *act of reviewing* is process.

**Classification — PROCESS.** Tracker fields: post-change review checklist, review cadence.

> *Cloud signal:* the script's CNA-EIS + SVC-ACM outputs surface drifted/residual resources that should be on the review agenda.

---

### KSI-SVC-RUD — Removing Unwanted Data

**Domain:** SVC · **Keyword:** (varies by level) · **Scope:** **CLOUD**

**Statement (Moderate).** Remove unwanted federal customer data promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.

**NIST 800-53 controls (implied).** `mp-6` (media sanitization), `si-12` (information management and retention).

**Analysis.** Data-deletion workflow exists and is auditable, INCLUDING backups. Mechanism: bucket lifecycle rules, KMS key destruction, RDS/Cloud SQL snapshot deletion, and a *customer-deletion-request* runbook. Evidence: lifecycle configurations, retention policies, deletion-event audit trails.

**Classification — CLOUD.** Lifecycle config is fully scriptable.

#### Script plan — SVC-RUD

**AWS evidence:**
- `s3.GetBucketLifecycleConfiguration` per in-scope bucket — expiration rules, abort-incomplete-uploads rules.
- `s3.GetObjectLockConfiguration` — verify legal-hold + retention modes (preserves data; CSPs need *delete* capability too).
- `kms.ListKeys` + `kms.GetKeyPolicy` + `kms.DescribeKey.KeyState` — keys in `PendingDeletion` state with a documented schedule are evidence of deletion mechanism use.
- `glue.GetTables` (per database) — orphaned tables.
- Backup vault retention: `backup.GetBackupPlan.Rules.Lifecycle.DeleteAfterDays`.
- CloudTrail filter on `DeleteObject`, `ScheduleKeyDeletion`, `DeleteDBSnapshot` events for sample deletions.

**GCP evidence:**
- Cloud Storage: `storage.buckets.get` → `lifecycle.rule[].action.type='Delete'`, `retentionPolicy`.
- Cloud KMS: per key version `state`, deletion schedule.
- Cloud SQL backup retention + deletion configs.
- BigQuery table expiration: `bigquery.datasets.get.defaultTableExpirationMs`.
- Cloud Audit Logs filter on deletion events for sample.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.s3.prod_buckets_have_lifecycle_or_retention` | Every prod data bucket has either a lifecycle rule or a documented infinite-retention exception. |
| `aws.backup.retention_aligned_with_policy` | Backup retention matches the documented data-retention policy. |
| `gcp.storage.prod_buckets_have_lifecycle_or_retention` | (mirror) |
| `gcp.bigquery.in_scope_datasets_have_table_expiration_or_documented` | (mirror) |

---

### KSI-SVC-SNT — Securing Network Traffic

**Domain:** SVC · **Scope:** **CLOUD**

**Statement.** Encrypt or otherwise secure network traffic.

**NIST 800-53 controls (implied).** `sc-8` (transmission protection), `sc-8.1` (cryptographic mechanisms), `sc-13` (cryptographic protection).

**Analysis.** TLS everywhere with strong ciphers + minimum TLS 1.2 (preferably 1.3); no internal plaintext; data-in-transit between services encrypted (mTLS where reasonable); certificates managed; AWS PrivateLink / GCP Private Service Connect for service-to-service.

**Classification — CLOUD.**

#### Script plan — SVC-SNT

**AWS evidence:**
- ELB: `elbv2.DescribeListeners` — `Protocol`, `SslPolicy` (e.g. `ELBSecurityPolicy-TLS13-1-2-2021-06`).
- CloudFront: `cloudfront.GetDistributionConfig` — `ViewerCertificate.MinimumProtocolVersion`, `ViewerProtocolPolicy=redirect-to-https | https-only`.
- API Gateway: `apigateway.GetDomainNames` / `apigatewayv2.GetDomainNames` — `SecurityPolicy=TLS_1_2`.
- ACM: cert inventory + key spec (RSA-2048 minimum / ECDSA-256).
- VPC endpoints: `ec2.DescribeVpcEndpoints` — interface endpoints for service-to-service.

**GCP evidence:**
- Target HTTPS proxies: `compute.targetHttpsProxies.list` — `sslPolicy` (referencing a `compute.sslPolicies` resource with `minTlsVersion=TLS_1_2`, `profile=RESTRICTED|MODERN`).
- SSL policies: `compute.sslPolicies.list` + `.get`.
- Certificate Manager: cert inventory + algorithm.
- Cloud Run: `run.namespaces.services.list` — `ingress` settings (internal vs external) and TLS termination.
- Private Service Connect: `compute.serviceAttachments.list`, `compute.forwardingRules.list` with `target=serviceAttachment`.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.elb.no_http_listeners_prod` | No prod ALBs have HTTP listeners (only HTTPS, with HTTP→HTTPS redirect rules permitted). |
| `aws.elb.ssl_policy_tls_1_2_or_higher` | Every prod HTTPS listener uses an SSL policy enforcing TLS ≥1.2 (TLS13-1-2 preferred). |
| `aws.cloudfront.viewer_protocol_https_only` | All prod CloudFront distributions are HTTPS-only with `MinimumProtocolVersion >= TLSv1.2_2021`. |
| `aws.apigateway.security_policy_tls_1_2` | API Gateway custom domains have `SecurityPolicy=TLS_1_2`. |
| `gcp.lb.ssl_policy_restricted_or_modern` | All public HTTPS LBs use SSL policies of `profile=RESTRICTED` or `MODERN` with `minTlsVersion=TLS_1_2`. |
| `gcp.cloud_run.ingress_restricted_for_internal` | Internal services have `ingress=internal` or `internal-and-cloud-load-balancing`. |

---

### KSI-SVC-VCM — Validating Communications

**Domain:** SVC · **Keyword:** (varies by level) · **Scope:** **CLOUD**

**Statement (Moderate).** Persistently validate the authenticity and integrity of communications between machine-based information resources using automation.

**NIST 800-53 controls.** `sc-23` (session authenticity), `si-7.1` (integrity checks).

**Analysis.** Authenticity (not just confidentiality): mTLS between services, signed requests, JWT validation at gateways, AWS SigV4, GCS signed URLs for sensitive object access, IAP enforcing identity at L7. The "automation" word is key — manual cert verification doesn't count.

**Classification — CLOUD.**

#### Script plan — SVC-VCM

**AWS evidence:**
- App Mesh / ECS Service Connect: `appmesh.ListMeshes`, `appmesh.DescribeVirtualNode` — TLS config blocks; `ecs.DescribeServices.serviceConnectConfiguration`.
- API Gateway: authorizer configs (`apigateway.GetAuthorizers`) — JWT, Lambda, IAM.
- Lambda function URL auth: `lambda.GetFunctionUrlConfig.AuthType` (must be `AWS_IAM`).
- ELB target groups: `targetGroup.HealthCheckProtocol=HTTPS`, target-group `Protocol=HTTPS`.

**GCP evidence:**
- Anthos / Cloud Service Mesh: `gkehub.features.list` filtered to `servicemesh`, then per-cluster mTLS strict mode via `kubectl get peerauthentication`.
- IAP TCP/SSH: `iap.tunnelInstances.list`, `iap.webBackendServices.list` — IAP enforcement on backend services.
- API Gateway: JWT auth on routes.
- Cloud Storage: signed URLs / signed cookies usage (less directly enumerable; can detect generation via Cloud Audit Logs).

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.appmesh.mtls_strict_in_prod` | mTLS strict mode set on prod virtual nodes (where mesh is in use). |
| `aws.lambda.function_urls_require_iam` | Function URLs (if used) require IAM auth. |
| `gcp.csm.mtls_strict` | Cloud Service Mesh strict mTLS enabled in prod. |
| `gcp.iap.enforced_for_internal_apps` | IAP enforced for internal admin apps. |

---

### KSI-SVC-VRI — Validating Resource Integrity

**Domain:** SVC · **Scope:** **CLOUD**

**Statement.** Use cryptographic methods to validate the integrity of machine-based information resources.

**NIST 800-53 controls (implied).** `si-7` (software, firmware, information integrity), `si-7.1` (integrity checks), `si-7.6` (cryptographic protection).

**Analysis.** Code, images, infra are signed and verified before execution: container images signed (Cosign / Notary v2); Lambda code signing configured + enforced; SSM Patch Manager validates; signed AMIs; Binary Authorization enforces attestor presence; Shielded VM / Shielded GKE Nodes for hardware-rooted boot integrity. Plus SLSA build provenance: every artifact traceable to its build.

**Classification — CLOUD.**

#### Script plan — SVC-VRI

**AWS evidence:**
- `signer.ListProfiles`, `signer.ListSigningJobs` — signer profiles and jobs.
- `lambda.ListFunctions` with `lambda.GetFunctionCodeSigningConfig` — code signing required.
- ECR: `ecr.DescribeRepositories.imageScanningConfiguration` AND image-signing via Notation (if applicable). Image signatures show up in image tags (`*-sig`).
- EC2 launch templates: `LaunchTemplateData.MetadataOptions` (IMDSv2), `EnclaveOptions`.
- SSM: `ssm.GetPatchBaseline` — patch baseline content.

**GCP evidence:**
- `binaryauthorization.projects.getPolicy` — policy enforced + attestors.
- `binaryauthorization.projects.attestors.list` — attestor signing material.
- `containeranalysis.notes.list` filter `kind:ATTESTATION` — provenance attestations.
- `compute.instances.list` — `shieldedInstanceConfig.enableSecureBoot=true`, `enableVtpm=true`, `enableIntegrityMonitoring=true`.
- GKE: `cluster.shieldedNodes.enabled=true`, BinAuthz enabled.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.lambda.code_signing_required_for_prod` | Every prod Lambda has a code-signing config attached. |
| `aws.ec2.imdsv2_required` | EC2 prod instances enforce IMDSv2 (mirror of CNA-MAT). |
| `aws.ssm.patch_baselines_assigned_to_prod_groups` | Patch baselines assigned to prod patch groups. |
| `gcp.binaryauthorization.attestor_required_for_prod` | BinAuthz policy requires attestor signatures for prod cluster admission. |
| `gcp.compute.prod_shielded_vm_enabled` | All prod VMs have Shielded VM secureBoot + integrityMonitoring on. |
| `gcp.gke.prod_shielded_nodes_enabled` | Prod GKE clusters have `shieldedNodes.enabled=true`. |

---

## SCR — Supply Chain Risk

> Theme: implicit — supply-chain risks are identified, mitigated, and continuously monitored.

2 KSIs. SCR-MIT is process-heavy (subprocessor management, contracts).
SCR-MON is hybrid (vuln monitoring tools + policy).

**Important for this user:** SCR is *heavy* because of subprocessors. Each
subprocessor's FedRAMP-equivalency must be tracked; their security postures
relevant to your CSO must be ingested where automatable (e.g. a SOC 2 status
URL, an attestation-renewal date in your vendor-mgmt system).

---

### KSI-SCR-MIT — Mitigating Supply Chain Risk

**Domain:** SCR · **Scope:** PROCESS

**Statement.** Persistently identify, review, and mitigate potential supply chain risks.

**NIST 800-53 controls.** Not populated. Maps to `sr-3` (supply chain controls), `sr-6` (supplier assessments and reviews).

**Analysis.** Subprocessor inventory + per-subprocessor risk assessment + FedRAMP-equivalency review for in-scope subprocessors + contractual flow-down. The user's "applications as subprocessors" profile makes this central. Evidence: subprocessor inventory (your DPA appendix); per-subprocessor security questionnaire / SOC 2 / FedRAMP package review; contracts with required flow-down clauses; review cadence (annual at minimum).

**Classification — PROCESS.** Tracker fields: subprocessor inventory URL, vendor-risk-mgmt system reference (OneTrust, Vanta, Drata), per-subprocessor review status.

> *Indirect cloud signal:* the script's IAM-AAM and IAM-SNU outputs (which 3rd-party identities have what access) cross-reference subprocessor scope. Inspector findings on 3rd-party container base images (SCR-MON) feed the risk register.

---

### KSI-SCR-MON — Monitoring Supply Chain Risk

**Domain:** SCR · **Scope:** **HYBRID**

**Statement.** Automatically monitor third party software information resources for upstream vulnerabilities using mechanisms that may include contractual notification requirements or active monitoring services.

**Analysis.** Automated CVE feeds on dependencies: container images, language packages, OS packages, base AMIs / images. Tools: Inspector (AWS), Artifact Analysis (GCP), Dependabot/Snyk/Renovate/GitHub Advanced Security in your CI; SBOM generation + ingest. The "third party" framing makes container-base-image scanning the biggest single source of evidence.

**Classification — HYBRID.** (Cloud tooling + a documented monitoring policy.)

#### Script plan — SCR-MON

**AWS evidence:**
- Inspector: `inspector2.GetConfiguration`, `inspector2.ListFindings(filter={resourceType: ECR_REPOSITORY OR EC2_INSTANCE OR AWS_LAMBDA_FUNCTION})` — count by severity.
- ECR: `ecr.DescribeImageScanFindings` per repo (sample) — image-level vuln counts.
- CodeArtifact: `codeartifact.ListPackages`, `codeartifact.DescribePackage` (sample) — package origins, upstream sources.
- SBOM: `inspector2.GetSbomExport` or pull from CodeBuild reports.

**GCP evidence:**
- Artifact Analysis: `containeranalysis.notes.list(filter="kind:VULNERABILITY")`, `containeranalysis.occurrences.list` filter `kind:VULNERABILITY` — vuln findings per image.
- Artifact Registry: per-repo vuln scanning enabled (`artifactregistry.repositories.get` — scanning config implicit per the registry tier).
- Container Threat Detection: `gkehub.features.list` filter to `containerthreatdetection`.
- Cloud Build SBOM generation: `cloudbuild.projects.builds.get` — look for `sbom` artifacts in build outputs.

**Validation rules.**

| Rule | Pass |
|---|---|
| `aws.inspector.ecr_scanning_enabled` | Inspector ECR scanning enabled for all in-scope repos. |
| `aws.inspector.no_critical_findings_>30d_unresolved` | Zero CRITICAL findings older than 30 days without a ticket / exception. |
| `aws.codeartifact.dependencies_from_trusted_sources_only` | CodeArtifact upstream repos restricted to trusted sources. |
| `gcp.artifact_analysis.vuln_scanning_enabled` | Artifact Analysis vulnerability scanning enabled on prod registries. |
| `gcp.artifact_analysis.no_critical_findings_>30d_unresolved` | (mirror) |

**Process artifacts.** Supply-chain monitoring policy (what severity SLAs, what sources, who responds); contractual notification clauses sample.

---

## Consolidated catalog (post-deep-analysis)

After deep review, the final counts are:

| Bucket | Count | KSIs |
|---|---|---|
| **CLOUD** | 27 | CMT-LMC, CMT-RMV · CNA-DFP, CNA-EIS, CNA-IBP, CNA-MAT, CNA-OFA, CNA-RNT, CNA-RVP, CNA-ULN · IAM-AAM, IAM-APM, IAM-ELP, IAM-MFA, IAM-SNU · MLA-ALA, MLA-EVC, MLA-RVL · PIY-GIV · SVC-ACM, SVC-ASM, SVC-RUD, SVC-SNT, SVC-VCM, SVC-VRI |
| **HYBRID** | 10 | AFR-PVA · CMT-VTD · IAM-JIT, IAM-SUS · INR-RIR · MLA-LET, MLA-OSM · RPL-ABO, RPL-TRC · SVC-EIS · SCR-MON · **CSX-SUM** |
| **PROCESS** | 26 | AFR-ADS, AFR-CCM, AFR-FSI, AFR-ICP, AFR-MAS, AFR-SCG, AFR-SCN, AFR-UCM, AFR-VDR · CMT-RVP · CED-DET, CED-RGT, CED-RRT, CED-RST · CSX-MAS, CSX-ORD · INR-AAR, INR-RPI · PIY-RES, PIY-RIS, PIY-RSD, PIY-RVD · RPL-ARP, RPL-RRO · SVC-PRR · SCR-MIT |
| **Total** | **63** | — |

> **Counting note.** The CSX-SUM count of 11 HYBRID and 26 PROCESS reflects the deep re-analysis. The CLOUD count is 27 (up from 26 in the summary doc) because RPL-ABO was found to have direct cloud evidence sufficient to qualify CLOUD-only — but it remains HYBRID here because the RPO/RTO target *document* is the second half of the evidence chain. Adjust per how strict you want the boundary.

**Script in-scope.** All 37 CLOUD + HYBRID KSIs are in scope for evidence
collection. The script *additionally* emits the PVA run-summary (which is
KSI-AFR-PVA's primary evidence) and the CSX-SUM aggregator output.

---

## Script architecture

```
cloud-evidence/
  package.json
  tsconfig.json
  config.yaml                       # scope: accounts, projects, regions, cadence, exceptions
  ksi-map.ts                        # master list: KSI -> [provider, module, function, scope]
  core/
    orchestrator.ts                 # entrypoint: --providers aws,gcp --kis IAM,CNA --out ./out
    envelope.ts                     # output envelope helpers
    findings.ts                     # finding/rollup utilities
    run-summary.ts                  # AFR-PVA: aggregate per-KSI results
    csx-sum-aggregator.ts           # CSX-SUM: build implementation-summary input
    tracker-push.ts                 # optional: PATCH evidence URL + status into local tracker DB
    auth/
      aws.ts                        # STS-assume-role flow; supports SSO/profile
      gcp.ts                        # ADC / impersonation flow
  providers/
    aws/
      iam.ts                        # IAM-AAM, IAM-APM, IAM-ELP, IAM-JIT, IAM-MFA, IAM-SNU, IAM-SUS, CNA-DFP
      network.ts                    # CNA-MAT, CNA-RNT, CNA-ULN, CNA-RVP, SVC-SNT
      logging.ts                    # MLA-ALA, MLA-EVC, MLA-LET, MLA-OSM, MLA-RVL, CMT-LMC
      backup.ts                     # CNA-OFA, RPL-ABO, RPL-TRC
      config.ts                     # CNA-EIS, CNA-IBP, SVC-ACM
      secrets.ts                    # SVC-ASM
      data.ts                       # SVC-RUD, SVC-VCM, SVC-VRI
      supplychain.ts                # SCR-MON, CMT-RMV, CMT-VTD
      inventory.ts                  # PIY-GIV
    gcp/
      iam.ts                        # mirrors AWS iam.ts
      network.ts
      logging.ts
      backup.ts
      config.ts
      secrets.ts
      data.ts
      supplychain.ts
      inventory.ts
  out/                              # per-KSI evidence JSON + pva-run-summary.json + KSI-CSX-SUM-input.json
  README.md
```

**`ksi-map.ts` (master list, abridged):**

```ts
export const KSI_MAP = {
  // CLOUD
  'KSI-CMT-LMC': { scope: 'CLOUD', aws: ['logging.collectCmtLmcAws'], gcp: ['logging.collectCmtLmcGcp'] },
  'KSI-CMT-RMV': { scope: 'CLOUD', aws: ['supplychain.collectCmtRmvAws'], gcp: ['supplychain.collectCmtRmvGcp'] },
  'KSI-CNA-DFP': { scope: 'CLOUD', aws: ['iam.collectCnaDfpAws'], gcp: ['iam.collectCnaDfpGcp'] },
  /* ...all 27 CLOUD entries... */

  // HYBRID
  'KSI-AFR-PVA': { scope: 'HYBRID', aws: ['../core/run-summary.emit'], gcp: [], process_artifacts: ['pva_plan_doc'] },
  'KSI-CMT-VTD': { scope: 'HYBRID', aws: ['supplychain.collectCmtVtdAws'], gcp: ['supplychain.collectCmtVtdGcp'], process_artifacts: ['sast_sca_tool_inventory'] },
  /* ...all 10 HYBRID entries... */

  // PROCESS (no module; tracker-only)
  'KSI-AFR-ADS': { scope: 'PROCESS', process_artifacts: ['trust_center_url', 'ads_plan_doc'] },
  /* ...all 26 PROCESS entries... */
} as const;
```

---

## Auth approach

**AWS.** Cross-account assume-role chain. A central "audit" account holds
a role; that role can `sts:AssumeRole` into per-account read-only roles
(IAM read-only + Config / Inspector / Security Hub / Access Analyzer
viewer + organizations:Describe* if running against the management account).
The script needs:

```
PrincipalAuditRole/
  trust: SSO identity or CI worker role
  policy: only `sts:AssumeRole` to ChildRoleAcrossOrg

ChildRoleAcrossOrg (one per in-scope account):
  trust: PrincipalAuditRole
  policy: ReadOnlyAccess + AWSSecurityHubReadOnlyAccess +
          AWSCloudTrailReadOnlyAccess + IAMAccessAnalyzerReadOnlyAccess +
          AWSConfigUserAccess +
          (limited Inspector + Backup read perms)
```

**GCP.** Application Default Credentials with impersonation. The script
authenticates as a service account in an "audit" project; that SA has
`roles/iam.serviceAccountTokenCreator` on per-project audit SAs (one per
in-scope project), each of which holds:

```
roles/viewer (org-level, scoped to in-scope folders)
roles/iam.securityReviewer
roles/cloudasset.viewer
roles/securitycenter.findingsViewer
roles/logging.viewer + roles/logging.privateLogViewer (for audit log buckets)
roles/recommender.viewer
roles/orgpolicy.policyViewer
```

The script auths once as the principal, then impersonates per project.

---

## Build sequence (recommended)

Phase 1 — **IAM domain end-to-end** (highest payoff, validates the
architecture + envelope on real KSIs):
1. `providers/aws/iam.ts` — IAM-AAM, IAM-APM, IAM-ELP, IAM-MFA, IAM-SNU.
2. `providers/gcp/iam.ts` — same.
3. `core/envelope.ts`, `core/findings.ts`, `core/orchestrator.ts` skeleton.
4. Run end-to-end against a sandbox AWS account + GCP project, verify
   evidence JSON shape is right.
5. Wire `tracker-push.ts` and verify the tracker reflects the evidence.

Phase 2 — **CNA domain** (highest KSI count, fully CLOUD):
- All 8 CNA KSIs across `iam.ts` (CNA-DFP), `network.ts` (CNA-MAT/RNT/ULN/RVP), `backup.ts` (CNA-OFA), `config.ts` (CNA-EIS/IBP).

Phase 3 — **MLA + CMT** (logging + change mgmt):
- `logging.ts` carries 5 MLA + 1 CMT KSIs.
- `supplychain.ts` carries CMT-RMV/VTD + SCR-MON.

Phase 4 — **SVC** (8 KSIs, the data + crypto KSIs):
- `secrets.ts` for SVC-ASM.
- `data.ts` for SVC-RUD/VCM/VRI.
- `network.ts` adds SVC-SNT.
- `config.ts` adds SVC-ACM.

Phase 5 — **RPL + PIY-GIV + HYBRID extras**:
- `backup.ts` adds RPL-ABO/TRC.
- `inventory.ts` for PIY-GIV.
- `core/run-summary.ts` emits AFR-PVA evidence.
- `core/csx-sum-aggregator.ts` emits CSX-SUM input.
- `tracker-push.ts` finalized; INR-RIR + SVC-EIS HYBRID rollups wired.

Phase 6 — **Tracker integration & reporting**:
- `--push-to-tracker` flag PATCHes `evidence_url` + `notes` + `status`
  per KSI based on `rollup.pass`.
- Add a tracker view that surfaces last-run summary inline (the dashboard
  could show the run drift since previous run, surfaced from
  `pva-run-summary.json`).

---

## Output envelope (final)

```json
{
  "ksi_id": "KSI-IAM-MFA",
  "ksi_name": "Enforcing Phishing-Resistant MFA",
  "scope": "CLOUD",
  "frmr_version": "0.9.43-beta",
  "run_id": "01J...",
  "collected_at": "2026-05-26T20:00:00Z",
  "providers": [
    {
      "provider": "aws",
      "account_id": "123456789012",
      "region_set": ["us-gov-west-1"],
      "evidence": [
        {
          "source": "iam.GetAccountSummary",
          "captured_at": "2026-05-26T20:00:03Z",
          "data": { "AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0, "Users": 3 }
        },
        {
          "source": "sso-admin.ListInstances + DescribeInstanceAccessControlAttributeConfiguration",
          "captured_at": "2026-05-26T20:00:05Z",
          "data": { "InstanceArn": "...", "AttributeConfig": {/* ... */} }
        }
      ],
      "findings": [
        { "rule": "aws.iam.root_mfa_enabled", "passed": true, "actual": 1, "expected": ">=1" },
        { "rule": "aws.identity_center.idp_restricts_to_webauthn", "passed": true, "actual": "webauthn-only", "expected": "phishing-resistant only" },
        { "rule": "aws.scp.deny_no_mfa", "passed": false, "actual": "no matching SCP found", "expected": "SCP denying actions w/o aws:MultiFactorAuthPresent=true" }
      ]
    },
    {
      "provider": "gcp",
      "project_id": "tracker-prod",
      "evidence": [/* ... */],
      "findings": [/* ... */]
    }
  ],
  "rollup": {
    "pass": false,
    "passing_findings": 5,
    "failing_findings": 1,
    "warnings": [],
    "missing_evidence": []
  },
  "process_artifacts_required": []
}
```

`rollup.pass` is the boolean used by the tracker `status` push: `true` →
status `met`, `false` → status `in_progress` (with notes citing the failing
finding rule names).

---

## How this updates the tracker

`tracker-push.ts` posts to the tracker API:

```http
PATCH /api/items/indicator/KSI-IAM-MFA
{
  "status": "met",          // or "in_progress" if rollup.pass=false
  "evidence_url": "file:///.../out/KSI-IAM-MFA.json",
  "notes": "Run 01J... at 2026-05-26T20:00Z. 5/6 findings passing. Failing: aws.scp.deny_no_mfa. See evidence file.",
  "last_reviewed": "2026-05-26"
}
```

For HYBRID KSIs, the script also surfaces `process_artifacts_required` —
the tracker's notes field includes a checklist of those, so the human
reviewer knows what's still needed.

---

## Key decisions for you to confirm

1. **PVA scope.** AFR-PVA HYBRID — agreed? Or should it stay PROCESS, with the script viewed only as a *supporting tool* rather than direct evidence?
2. **CSX-SUM rendering target.** Static-site generator (Hugo / MkDocs) building the summary doc from the aggregator JSON? Or template into the tracker's UI directly?
3. **Threshold for "trends down" rules** (e.g. `unused_access_findings`): exact numbers (e.g. ≤25) or "current ≤ previous run"?
4. **Subprocessor coverage approach.** For SCR-MIT / IAM-AAM external identities — pull from your vendor-risk-management system, or maintain a separate `subprocessors.yaml` in this repo?
5. **Phasing.** Start Phase 1 (IAM end-to-end)? Recommend yes — finishing IAM gives you the cleanest validation of the architecture before fanning out.
