# KSI Cloud-Configuration Classification

**Purpose.** For each of the 63 Key Security Indicators in FedRAMP 20x
(`FRMR.documentation.json` v0.9.43-beta, 2026-04-08), identify which ones
require evidence that comes from your AWS / GCP configuration as a SaaS CSP
running CI/CD on multi-cloud infrastructure with subprocessors. This file
drives the design of the cloud-evidence collection script that will follow.

**Org profile assumed (see [project_org_profile.md](../../.claude/projects/-Users-kenith-philip-FedRAMP-20x/memory/project_org_profile.md)):**
SaaS CI/CD product · AWS + GCP IaaS · subprocessors in scope · CSP role.

**Source of truth.** All statements and NIST control mappings come directly
from [`FedRAMP/docs FRMR.documentation.json`](https://github.com/FedRAMP/docs).
For any KSI where this doc disagrees with the FRMR JSON or with FedRAMP
guidance, the FRMR JSON wins. Re-run the classification when FRMR is
updated.

---

## Scope legend

| Scope | Meaning | Evidence comes from |
|---|---|---|
| **CLOUD** | Primary evidence is configuration data from AWS/GCP. Automatable. | Cloud APIs (AWS SDK, gcloud) |
| **HYBRID** | Cloud config supplies part of the evidence; a process/doc supplies the rest. | Cloud APIs **plus** docs/SIEM/ticketing |
| **PROCESS** | Evidence is a document, training record, contract, plan, or review log. Cloud APIs do not satisfy this. | Org artifacts (docs, HRIS, ticketing) |
| **INHERITED** | Satisfied by AWS or GCP's own FedRAMP authorization; reference their attestation, do not collect. | AWS / GCP FedRAMP package |

KSIs marked CLOUD or HYBRID are in-scope for the collection script.

---

## Summary by scope

| Domain | KSIs | CLOUD | HYBRID | PROCESS | INHERITED |
|---|---|---|---|---|---|
| AFR — Authorization by FedRAMP | 10 | 0 | 1 (PVA) | 9 | 0 |
| CMT — Change Management | 4 | 2 | 1 | 1 | 0 |
| CNA — Cloud Native Architecture | 8 | 8 | 0 | 0 | 0 |
| CED — Cybersecurity Education | 4 | 0 | 0 | 4 | 0 |
| CSX — 20x-Specific Provider Responsibilities | 3 | 0 | 1 | 2 | 0 |
| IAM — Identity and Access Management | 7 | 6 | 1 | 0 | 0 |
| INR — Incident Response | 3 | 0 | 1 | 2 | 0 |
| MLA — Monitoring, Logging, Auditing | 5 | 3 | 2 | 0 | 0 |
| PIY — Policy and Inventory | 5 | 1 | 0 | 4 | 0 |
| RPL — Recovery Planning | 4 | 0 | 2 | 2 | 0 |
| SVC — Service Configuration | 8 | 6 | 1 | 1 | 0 |
| SCR — Supply Chain Risk | 2 | 0 | 1 | 1 | 0 |
| **Total** | **63** | **26** | **11** | **26** | **0** |

> The **CSX** domain holds the 3 meta-KSIs that live in `FRR.KSI` under the
> `CSX` ("20x-Specific Provider Responsibilities") label in the FRMR JSON,
> rather than under the top-level `KSI` section with the other 60. They
> are KSIs *about* applying KSIs — implementation summaries, scope, and
> sequencing.

> Note on INHERITED = 0: FedRAMP 20x KSIs are written at the CSP-outcome level,
> so none are *fully* inherited from the underlying IaaS. AWS/GCP's
> FedRAMP-Authorized attestations support several KSIs (e.g. physical security
> aspects of CNA-MAT, hardware-level integrity for SVC-VRI) but you still own
> the demonstration of how *your* tenant is configured.

**Bottom line:** 37 of 63 KSIs (59%) have cloud-config evidence. That's the
target scope for the collection script.

---

## Domain-by-domain classification

Each KSI lists: scope, the FRMR statement, mapped NIST controls (if any),
and (for CLOUD/HYBRID) the AWS + GCP services you'd query for evidence.

### AFR — Authorization by FedRAMP

These KSIs are about *participating in the FedRAMP program* — they are
overwhelmingly process artifacts (plans, inboxes, marketplace listings,
quarterly reports). Cloud configuration may *feed* these processes
(e.g. vuln data from Security Hub feeds AFR-VDR), but the KSI itself is
demonstrated by the process artifact, not cloud config.

| KSI | Scope | Why |
|---|---|---|
| KSI-AFR-ADS — Authorization Data Sharing | PROCESS | Provider publishes auth data via the ADS process; evidence is the trust center / marketplace listing. |
| KSI-AFR-CCM — Collaborative Continuous Monitoring | PROCESS | Plan for OARs + quarterly reviews. |
| KSI-AFR-FSI — FedRAMP Security Inbox | PROCESS | Operate a secure inbox; evidence is the inbox itself + routing rules. |
| KSI-AFR-ICP — Incident Communications Procedures | PROCESS | Integrate FedRAMP ICP into IR runbooks. |
| KSI-AFR-MAS — Minimum Assessment Scope | PROCESS | Document the assessed scope. |
| KSI-AFR-PVA — Persistent Validation and Assessment | **HYBRID** | Process *and* tooling: the PVA plan is a doc, but its execution requires continuous-monitoring tooling (config drift, KSI assessment automation). The cloud-collection script *is itself* PVA evidence. |
| KSI-AFR-SCG — Secure Configuration Guide | PROCESS | Customer-facing guide. Cloud-config data may inform the guide, but the KSI evidence is the guide. |
| KSI-AFR-SCN — Significant Change Notifications | PROCESS | SCN plan + notification log. |
| KSI-AFR-UCM — Using Cryptographic Modules | PROCESS | FIPS module selection rationale + inventory. (KMS/HSM choices are evidence of policy, but the *KSI* is the documented rationale.) |
| KSI-AFR-VDR — Vulnerability Detection and Response | PROCESS | Documented vuln detection + response methodology. The actual scanning runs in cloud (see SCR-MON, MLA-EVC) but this KSI is the documented *method*. |

---

### CMT — Change Management

| KSI | Scope | NIST controls | AWS evidence | GCP evidence |
|---|---|---|---|---|
| **KSI-CMT-LMC** — Logging Changes | **CLOUD** | au-2, cm-3.1, cm-5.1 | CloudTrail (management + data events on/off, multi-region, log file validation); Config configuration history; AWS CloudFormation drift detection | Cloud Audit Logs (Admin Activity + Data Access); Asset Inventory change history; Config Connector / Deployment Manager change records |
| **KSI-CMT-RMV** — Redeploying vs Modifying | **CLOUD** | cm-2, cm-2.2, cm-3, cm-3.5 | ECR image immutability tags; CodePipeline + CodeDeploy + CodeBuild rollout records; EC2/ECS task-definition revisions; Terraform/CloudFormation stack history | Artifact Registry immutable tags; Cloud Build + Cloud Deploy rollout records; GKE deployment manifests; Config Connector / Terraform state |
| KSI-CMT-RVP — Reviewing Change Procedures | PROCESS | — | Process artifact: cadence + minutes of change-procedure reviews. |  |
| **KSI-CMT-VTD** — Validating Throughout Deployment | **HYBRID** | cm-3.2, cm-4, cm-4.1 | CodePipeline stage gates with tests/security scans; CodeBuild reports; Inspector findings blocking deploys | Cloud Build steps with required gates; Binary Authorization attestations; Artifact Analysis scan results. **Note: you build CI/CD — your own product likely provides the strongest evidence here.** |

---

### CNA — Cloud Native Architecture

Every CNA indicator is cloud-config. This is the heart of the script.

| KSI | Scope | NIST controls | AWS evidence | GCP evidence |
|---|---|---|---|---|
| **KSI-CNA-DFP** — Defining Functionality and Privileges | CLOUD | ac-6, ac-6.1, cm-7 | IAM policies + permission boundaries; service control policies (Organizations SCPs); resource-based policies (S3, KMS, SQS, etc.); IAM Access Analyzer findings | IAM policy bindings + IAM Deny policies; Organization Policies (constraints); VPC Service Controls; IAM Recommender least-privilege findings |
| **KSI-CNA-EIS** — Enforcing Intended State | CLOUD | ca-2.1, ca-7.1 | AWS Config rules + conformance packs (drift detection); Systems Manager State Manager; CloudFormation drift detection | Security Health Analytics; Config Validator (Anthos / Policy Controller); Asset Inventory + custom rules; Cloud Deploy enforcement |
| **KSI-CNA-IBP** — Implementing Best Practices | CLOUD | cm-6, cm-7, sa-8 | Trusted Advisor; Well-Architected Tool reviews; Security Hub controls (FSBP, CIS AWS); Inspector | Security Command Center premium (Posture Management); Recommender; Cloud Asset Inventory + posture analysis |
| **KSI-CNA-MAT** — Minimizing Attack Surface / Lateral Movement | CLOUD | ac-3, ac-4, sc-7, sc-7.5 | Security groups (ingress/egress rules); NACLs; VPC flow logs; PrivateLink / endpoint policies; SCP boundaries; instance metadata service v2 enforcement | VPC firewall rules; Hierarchical firewall policies; VPC Service Controls; Private Google Access; GKE network policies; Shielded VM |
| **KSI-CNA-OFA** — Optimizing for Availability | CLOUD | cp-2, cp-7, cp-10 | Multi-AZ RDS / DynamoDB global tables; Auto Scaling groups across AZs; ELB target group health; Route 53 health checks; Multi-region replication where required | Multi-region Cloud SQL / Spanner / Storage; Regional managed instance groups; Cloud Load Balancing health checks; multi-region buckets |
| **KSI-CNA-RNT** — Restricting Network Traffic | CLOUD | ac-4, sc-7, sc-7.5 | Security group rules; NACL rules; egress restrictions; WAF rules; Network Firewall policies | VPC firewall rules (ingress + egress); Cloud Armor security policies; Cloud NAT egress rules; GKE network policies |
| **KSI-CNA-RVP** — Reviewing Protections (DoS etc.) | CLOUD | sc-5, sc-5.1, sc-5.2 | AWS Shield Advanced; WAF rate limits + managed rules; Shield Response Team engagement records | Cloud Armor (rate-based rules, Adaptive Protection); Cloud CDN; reCAPTCHA Enterprise |
| **KSI-CNA-ULN** — Using Logical Networking | CLOUD | ac-4, sc-7, sc-32 | VPCs, subnets (public/private), route tables, transit gateway, PrivateLink, VPC peering inventory | VPCs, subnets, shared VPC, VPC Service Controls perimeters, Private Service Connect |

---

### CSX — 20x-Specific Provider Responsibilities

These 3 KSIs are meta-rules about *how* the other 60 KSIs are demonstrated.
They live in `FRR.KSI/CSX` in the FRMR JSON rather than the top-level `KSI`
section, but FedRAMP counts them in the 63-KSI total.

| KSI | KW | Scope | Why |
|---|---|---|---|
| **KSI-CSX-SUM** — Implementation Summaries | MUST | **HYBRID** | Provider MUST maintain a high-level summary per KSI with goals, pass/fail criteria, in-scope resources, validation processes, and cadence. The summary itself is a process artifact, but its content (machine-based validation cycle, scope inventories, pass/fail status) is fed directly by the cloud-evidence collection script + the tracker. **This is the KSI your tooling jointly satisfies.** |
| KSI-CSX-MAS — Application within MAS | SHOULD | PROCESS | Apply all KSIs across the entire Minimum Assessment Scope. Scoping decision — evidence is the documented scope + KSI-to-scope mapping. |
| KSI-CSX-ORD — AFR Order of Criticality | MAY | PROCESS | Recommended sequence for AFR KSIs (MAS → ADS → UCM). Planning artifact. |

For **CSX-SUM**, the cloud-evidence script and tracker together produce most
of the input the summary needs: per-KSI status, evidence URLs, validation
cadence, in-scope resources from `PIY-GIV`. The script should emit a
`csx-sum-input.json` that aggregates this per KSI, ready to be embedded in
the human-authored summary doc.

---

### CED — Cybersecurity Education

| KSI | Scope | Why |
|---|---|---|
| KSI-CED-DET — Reviewing Development & Engineering Training | PROCESS | Training records + review cadence (LMS / HRIS). |
| KSI-CED-RGT — Reviewing General Training | PROCESS | Completion records for all employees. |
| KSI-CED-RRT — Reviewing Response and Recovery Training | PROCESS | IR/DR drill records, training rosters. |
| KSI-CED-RST — Reviewing Role-Specific Training | PROCESS | Privileged-access training records. |

Pipe these from your LMS (e.g. KnowBe4, Lessonly) or HRIS — not from cloud APIs.

---

### IAM — Identity and Access Management

| KSI | Scope | NIST controls | AWS evidence | GCP evidence |
|---|---|---|---|---|
| **KSI-IAM-AAM** — Automating Account Management | CLOUD | ac-2.2, ac-2.3, ac-2.13, ac-6.7, ia-4.4, ia-12, ia-12.2, ia-12.3, ia-12.5 | IAM Identity Center provisioning + SCIM; IAM Access Analyzer unused-access findings; IAM credential report; Identity provider integration (SAML/OIDC) | Cloud Identity provisioning; Workforce Identity Federation; Identity-Aware Proxy; IAM Recommender (unused service accounts/roles) |
| **KSI-IAM-APM** — Adopting Passwordless / MFA fallback | CLOUD | ia-2, ia-2.1, ia-5, ia-5.1 | IAM Identity Center MFA settings (FIDO2/WebAuthn); IAM password policy; account-level MFA enforcement | Cloud Identity 2SV enforcement + security keys; Workforce Identity Federation; Context-Aware Access (CAA) |
| **KSI-IAM-ELP** — Ensuring Least Privilege | CLOUD | ac-2, ac-6, ac-6.5 | IAM Access Analyzer (external + unused access); Service Control Policies; IAM permission boundaries; Access Advisor (last-used services) | IAM Recommender (over-granted roles); IAM Deny policies; Organization Policies; Policy Intelligence |
| **KSI-IAM-JIT** — Authorizing Just-in-Time | HYBRID | ac-2, ac-6.7 | IAM Identity Center session duration + permission set design; Session Manager; eventual JIT via 3rd-party (Teleport, ConductorOne, etc.) | Privileged Access Manager (PAM, GA 2024); IAP TCP/SSH for JIT shell; Workforce Identity Federation session policies |
| **KSI-IAM-MFA** — Phishing-Resistant MFA | CLOUD | ia-2.1, ia-2.2, ia-2.6, ia-2.8 | IAM Identity Center policy restricting MFA factor to WebAuthn/PIV; SCP denying root use without MFA; Cognito user pools enforcing WebAuthn for app users | Cloud Identity policy enforcing security keys; CAA blocking phone-based MFA; Identity Platform for app users |
| **KSI-IAM-SNU** — Securing Non-User Authentication | CLOUD | ac-2.7, ia-5, ia-9 | IAM roles (no long-lived access keys); IAM Roles Anywhere; IRSA for EKS; key-rotation policies; secret rotation in Secrets Manager | Service accounts with Workload Identity Federation (no JSON keys); GKE Workload Identity; short-lived OAuth tokens |
| **KSI-IAM-SUS** — Responding to Suspicious Activity | HYBRID | au-6, ir-4, si-4 | GuardDuty findings → EventBridge → Lambda to disable IAM user / revoke session / SCP block; IAM Access Analyzer findings; CloudTrail Insights | SCC findings → Eventarc → Cloud Functions to disable account; Event Threat Detection; reCAPTCHA Enterprise account-defender. The *response automation* is the cloud evidence; the *runbook* is the process side. |

---

### INR — Incident Response

| KSI | Scope | Why |
|---|---|---|
| KSI-INR-AAR — Generating After Action Reports | PROCESS | AAR documents in your ticketing/wiki. |
| **KSI-INR-RIR** — Reviewing IR Procedures | **HYBRID** | Process *plus* attached evidence that tools wire to runbooks (Security Hub custom actions → PagerDuty, SCC notifications → Slack/PagerDuty). The runbook review is the artifact; tool plumbing is cloud-side. |
| KSI-INR-RPI — Reviewing Past Incidents | PROCESS | Incident archive + trend reviews. |

---

### MLA — Monitoring, Logging, and Auditing

| KSI | Scope | NIST controls | AWS evidence | GCP evidence |
|---|---|---|---|---|
| **KSI-MLA-ALA** — Authorizing Log Access | CLOUD | si-11 | IAM policies on log destinations (S3 buckets, CloudWatch Log groups, Security Lake account); KMS key policies for log encryption; bucket policies | IAM bindings on Log Bucket destinations; KMS key policies; Log Router sinks + IAM; IAP for log UI |
| **KSI-MLA-EVC** — Evaluating Configurations | CLOUD | ca-7, cm-6, cm-7 | AWS Config rules + conformance packs results; Security Hub controls + findings; Inspector (IaC scanning via Inspector + CodeGuru); cfn-nag/Checkov in CodePipeline | Security Health Analytics findings; Policy Analyzer; Cloud Build IaC scans (e.g. tfsec, Checkov); Config Validator |
| **KSI-MLA-LET** — Logging Event Types | HYBRID | au-2, au-3, au-12 | Inventory of CloudTrail trails (mgmt + data events), VPC Flow Logs, ELB/CloudFront access logs, RDS audit logs, EKS audit logs — *plus* a documented list of in-scope event types | Inventory of Cloud Audit Logs (Admin Activity, Data Access, System Event, Policy Denied), VPC Flow Logs, Load Balancer logs, GKE audit logs — *plus* documented event-type list |
| **KSI-MLA-OSM** — Operating SIEM | HYBRID | au-2, au-6, au-6.1, au-7 | Security Lake + OCSF subscribers; or 3rd-party SIEM (Splunk, Datadog, Elastic) with CloudTrail/Config/GuardDuty/Security Hub ingestion. The SIEM may be off-cloud; the *evidence* of its existence + ingestion is cloud-side (log destinations, sinks). | Chronicle SIEM; or 3rd-party SIEM with Pub/Sub log sink subscribers; or Security Command Center + custom export. |
| KSI-MLA-RVL — Reviewing Logs | CLOUD | au-6 | Athena saved queries + workgroups; OpenSearch dashboards; Security Hub workflow status; review cadence in ticketing. *The review activity itself is process, but the tooling and saved-query/dashboard evidence is cloud-side.* | Log Analytics saved queries; Looker Studio dashboards over BQ log sinks; Chronicle rules + investigation records. |

---

### PIY — Policy and Inventory

| KSI | Scope | NIST controls | AWS evidence | GCP evidence |
|---|---|---|---|---|
| **KSI-PIY-GIV** — Generating Inventories | CLOUD | cm-8, cm-8.1, pm-5 | AWS Config Aggregator; Resource Explorer; Resource Groups + Tag Editor; Systems Manager Inventory (for EC2 software) | Cloud Asset Inventory (org-level export); Resource Manager hierarchy; Asset feeds → Pub/Sub for real-time |
| KSI-PIY-RES — Reviewing Executive Support | PROCESS | — | Board minutes, exec sponsorship docs. | |
| KSI-PIY-RIS — Reviewing Investments in Security | PROCESS | — | Budget docs, security program metrics. | |
| KSI-PIY-RSD — Reviewing Security in the SDLC | PROCESS | — | SDLC policy + review records; CISA Secure-by-Design self-assessment. | |
| KSI-PIY-RVD — Reviewing Vulnerability Disclosures | PROCESS | — | Public VDP page, intake records, mean-time-to-triage metrics. | |

---

### RPL — Recovery Planning

| KSI | Scope | NIST controls | AWS evidence | GCP evidence |
|---|---|---|---|---|
| **KSI-RPL-ABO** — Aligning Backups with Objectives | HYBRID | cp-9, cp-9.1, cp-9.8 | AWS Backup plans + jobs + restore tests; S3 versioning + replication; EBS snapshot policies; RDS automated backups + retention; cross-region copies. *Plus* the RPO/RTO doc. | Cloud Storage versioning + retention/lock; Cloud SQL automated backups + cross-region; Persistent Disk snapshot schedules; Backup and DR Service. *Plus* RPO/RTO doc. |
| KSI-RPL-ARP — Aligning Recovery Plan | PROCESS | cp-2, cp-2.1 | DR plan document + alignment review minutes. | |
| KSI-RPL-RRO — Reviewing Recovery Objectives | PROCESS | cp-2, cp-10 | Documented RPO/RTO per system + review cadence. | |
| **KSI-RPL-TRC** — Testing Recovery Capabilities | HYBRID | cp-4, cp-4.1, cp-10.2 | AWS Backup restore test plans + results; gameday/fault-injection records (FIS); cross-region failover test logs. *Plus* the test plan and outcome report. | Backup and DR restore tests; cross-region failover exercises; Cloud SQL clone-to-test. *Plus* test plan and outcome. |

---

### SVC — Service Configuration

| KSI | Scope | NIST controls | AWS evidence | GCP evidence |
|---|---|---|---|---|
| **KSI-SVC-ACM** — Automating Configuration Management | CLOUD | cm-2, cm-3, cm-6 | Terraform/CloudFormation/CDK state + drift; AWS Config rules; Systems Manager State Manager; OpsItems on drift | Terraform / Config Connector / Deployment Manager state; Anthos Config Management; Policy Controller; Asset Inventory drift |
| **KSI-SVC-ASM** — Automating Secret Management | CLOUD | ia-5, ia-5.1, sc-12 | Secrets Manager (rotation lambdas + rotation schedule); Parameter Store (SecureString); KMS key rotation; ACM cert renewals; IAM key-age policy | Secret Manager (with rotation triggers); Cloud KMS key rotation; Certificate Manager; Workload Identity (eliminates long-lived secrets) |
| KSI-SVC-EIS — Evaluating and Improving Security | HYBRID | ca-7, pm-31 | Security Hub findings + remediation tickets; Well-Architected reviews; closed-loop tickets in your tracker. *Plus* improvement-decision records.| SCC findings + remediation tickets; CIS posture findings; closed-loop tickets. *Plus* improvement-decision records. |
| KSI-SVC-PRR — Preventing Residual Risk | PROCESS | sc-4 | Change-review checklist for residual-risk assessment after changes. | |
| **KSI-SVC-RUD** — Removing Unwanted Data | CLOUD | mp-6, si-12 | S3 lifecycle policies + Object Lock; KMS key deletion records; data-deletion workflow audit trail (e.g. customer-data-purge Lambda + CloudTrail); RDS backup retention | Cloud Storage lifecycle + retention/lock; KMS key versions destroyed; data-deletion workflow logs; Cloud SQL backup retention |
| **KSI-SVC-SNT** — Securing Network Traffic | CLOUD | sc-8, sc-8.1, sc-13 | TLS on ELB listeners + minimum TLS version; CloudFront viewer protocol policies; ACM cert inventory + expiry; VPC encryption (EBS, S3, RDS, DynamoDB encryption-at-rest); KMS CMK inventory | Load Balancer SSL policies + min TLS; Certificate Manager inventory; default encryption at rest (per-resource); CMEK usage on critical resources |
| **KSI-SVC-VCM** — Validating Communications | CLOUD | sc-23, si-7.1 | mTLS in App Mesh / ECS Service Connect; PrivateLink endpoint policies; Signature v4 on API calls; signed CloudFront requests where applicable | mTLS via Anthos Service Mesh / Cloud Service Mesh; IAP + JWT validation; signed URLs for GCS; Workload Identity attestations |
| **KSI-SVC-VRI** — Validating Resource Integrity | CLOUD | si-7, si-7.1, si-7.6 | ECR image scanning + signing (Notation / Sigstore); CodeArtifact signed packages; Lambda code signing; SSM Patch Manager compliance; EC2 secure boot | Binary Authorization (attestor policy); Artifact Analysis (vuln + provenance); Container Analysis; Shielded VM / Shielded GKE Nodes; SLSA build provenance |

---

### SCR — Supply Chain Risk

| KSI | Scope | NIST controls | AWS evidence | GCP evidence |
|---|---|---|---|---|
| KSI-SCR-MIT — Mitigating Supply Chain Risk | PROCESS | sr-3, sr-6 | Subprocessor inventory + risk assessments; FedRAMP-equivalency review records for subprocessors; contractual flow-down evidence. **Heavy for you given subprocessors.** | |
| **KSI-SCR-MON** — Monitoring Supply Chain Risk | HYBRID | sr-3, ra-5 | Inspector SBOM + vuln findings; ECR image-scan findings; CodeArtifact + Dependabot/Snyk; subscription to vendor advisories (CISA, GHSA). *Plus* a documented monitoring policy. | Artifact Analysis (CVE scanning + provenance); GKE security posture; Container Threat Detection; subscriptions to vendor advisories. *Plus* monitoring policy. |

---

## In-scope catalog for the collection script

The collection script should produce evidence for these 37 KSIs:

**AWS + GCP both required:**

```
CMT-LMC, CMT-RMV, CMT-VTD
CNA-DFP, CNA-EIS, CNA-IBP, CNA-MAT, CNA-OFA, CNA-RNT, CNA-RVP, CNA-ULN
IAM-AAM, IAM-APM, IAM-ELP, IAM-JIT, IAM-MFA, IAM-SNU, IAM-SUS
MLA-ALA, MLA-EVC, MLA-LET, MLA-OSM, MLA-RVL
PIY-GIV
RPL-ABO, RPL-TRC
SVC-ACM, SVC-ASM, SVC-EIS, SVC-RUD, SVC-SNT, SVC-VCM, SVC-VRI
SCR-MON
AFR-PVA, INR-RIR
CSX-SUM  (script emits aggregated input for the implementation-summary doc)
```

---

## Evidence-collection script — proposed shape

The classification above implies a script with this structure (this is a
**proposal** for the next phase, not yet built):

```
cloud-evidence/
  collect.ts                  # entry point: --provider aws|gcp|both, --account/--project, --out
  providers/
    aws/
      iam.ts                  # IAM-AAM, IAM-ELP, IAM-MFA, IAM-SNU, CNA-DFP
      network.ts              # CNA-MAT, CNA-RNT, CNA-ULN, CNA-RVP, SVC-SNT
      logging.ts              # MLA-ALA, MLA-EVC, MLA-LET, MLA-OSM, MLA-RVL, CMT-LMC
      backup.ts               # RPL-ABO, RPL-TRC, CNA-OFA
      config.ts               # CNA-EIS, CNA-IBP, SVC-ACM, MLA-EVC
      secrets.ts              # SVC-ASM, IAM-SNU
      data.ts                 # SVC-RUD, SVC-VRI, SVC-VCM
      supplychain.ts          # SCR-MON, CMT-RMV, CMT-VTD
      inventory.ts            # PIY-GIV
    gcp/                      # mirror of the same domains
      iam.ts
      network.ts
      logging.ts
      backup.ts
      config.ts
      secrets.ts
      data.ts
      supplychain.ts
      inventory.ts
  ksi-map.ts                  # KSI -> [provider, module, function] map (the source of truth)
  out/                        # JSON evidence files per KSI, plus a summary
```

Each evidence file is JSON conforming to a fixed envelope:

```json
{
  "ksi_id": "KSI-IAM-MFA",
  "collected_at": "2026-05-26T20:15:00Z",
  "provider": "aws",
  "account_id": "123456789012",
  "evidence": [
    { "source": "iam.GetAccountPasswordPolicy", "data": { ... } },
    { "source": "identity-store.ListUsers", "data": [ ... ] }
  ],
  "warnings": []
}
```

This makes it trivial to PATCH the corresponding `KSI-IAM-MFA` row in the
tracker via `/api/items/indicator/KSI-IAM-MFA` with the evidence URL set to
the file location and a `notes` field summarizing what was found.

---

## Next steps

1. **You review and override the classification above.** This is the
   place where I most need your domain knowledge — especially around
   AFR-PVA, MLA-OSM, IAM-JIT, and SVC-EIS where the line between cloud and
   process is fuzziest.
2. Once classification is settled, we pick a starting domain (recommend
   **IAM** — highest payoff, clearest API mapping) and build that module
   first end-to-end (AWS + GCP), so we can validate the envelope/output
   format on a real domain before scaling out.
3. Decide whether the script writes evidence to local JSON only, or also
   PATCHes the tracker directly. (Recommend: local JSON first; PATCH as a
   separate `--push-to-tracker` flag.)
