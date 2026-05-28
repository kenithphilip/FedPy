# KSI Gap Analysis — 25 Uncovered Indicators

**Scope:** the 25 `category=="ksi-indicator"`, `covered==false` indicators in `frmr-requirements.generated.json`.
**Track:** all 20x. **Actor:** all `Providers`. **Key word:** all **MUST**.
**Collector constraint:** STRICTLY READ-ONLY (`List*`/`Get*`/`Describe*` only) per the locked cloud-evidence decisions. Org = SaaS CI/CD on AWS + GCP + EKS/GKE with subprocessors; CSP is the user.

## Level model

- **Low / Moderate:** every one of the 25 has `levels.low.applies == true` and `levels.moderate.applies == true` (verbatim from the dump). All apply at L and M.
- **High:** the dump carries `levels.high.applies == null` for 24 of 25 (FedRAMP has not published 20x High machine-readable text yet) and `== false` for **KSI-SVC-PRR**. For every KSI below, **High applicability is DERIVED from the NIST 800-53 Rev5 High baseline via the `controls[]` array** — it is not asserted by the 20x dump. Where `controls[]` is empty (several AFR/CED/PIY items), the High derivation rests on the parent FRR family's controls, stated per-item.

## The dominant pattern

22 of 25 are **"Persistently review the effectiveness of …"** (a recurring *meta-review* of a capability) or AFR **"address the FedRAMP <X> process"** pointers. `Persistently` (FRD) = *"firm, steady, repeated over a long period … status will always be known."* That makes the **review cadence + its minutes/decisions a process-artifact in every case**, but most carry an **api-testable proxy signal** that the underlying capability still exists and is healthy — which is what makes them `hybrid` rather than pure `process-artifact`. The collector's job for these is: (a) prove the capability is present and not regressing (the cloud signal), and (b) hold a slot for the human-attached review artifact. The existing **PVA meta-collector** (`core/pva-collector.ts`) already models exactly this for KSI-AFR-PVA and is the template for the "review cadence + drift" half.

## Coverage table (count = 25)

| ID | Domain | Name | L/M/H | Testability | Primary signal |
|----|--------|------|-------|-------------|----------------|
| KSI-AFR-ADS | AFR | Authorization Data Sharing | ✓/✓/derived(ac-3,ac-4,au-2,sc-8) | process-artifact | ADS process pointer; repo/share-target attestation |
| KSI-AFR-CCM | AFR | Collaborative Continuous Monitoring | ✓/✓/derived(family) | process-artifact | OA-report + Quarterly-Review cadence; PVA run-summary feed |
| KSI-AFR-FSI | AFR | FedRAMP Security Inbox | ✓/✓/derived(family) | process-artifact | Monitored security inbox existence + routing |
| KSI-AFR-ICP | AFR | Incident Communications Procedures | ✓/✓/derived(family) | process-artifact | IR runbook references FedRAMP ICP timelines |
| KSI-AFR-MAS | AFR | Minimum Assessment Scope | ✓/✓/derived(ac-1,ca-1,cm-1,sr-1…) | hybrid | Documented MAS boundary vs live inventory (PIY-GIV) |
| KSI-AFR-PVA | AFR | Persistent Validation & Assessment | ✓/✓/derived(ca-7) | hybrid | **Already covered** by `pva-collector.ts` (roll-up) |
| KSI-AFR-SCG | AFR | Secure Configuration Guide | ✓/✓/derived(family) | hybrid | Published SCG doc; secure-by-default config baseline signal |
| KSI-AFR-SCN | AFR | Significant Change Notifications | ✓/✓/derived(cm-3.4,cm-4,ca-7,si-2…) | hybrid | Change-event log (CloudTrail/Config) + notification record |
| KSI-AFR-UCM | AFR | Using Cryptographic Modules | ✓/✓/derived(family) | hybrid | FIPS-validated KMS/CMVP module usage |
| KSI-AFR-VDR | AFR | Vulnerability Detection & Response | ✓/✓/derived(ra-5*,si-2*,ir-4*…) | hybrid | Inspector/GuardDuty/Security Hub finding lifecycle |
| KSI-CED-DET | CED | Reviewing Dev/Eng Training | ✓/✓/derived(cp-3,ir-2,ps-6) | process-artifact | Secure-coding LMS completion + effectiveness review |
| KSI-CED-RGT | CED | Reviewing General Training | ✓/✓/derived(at-2*,at-3.5,at-4) | process-artifact | All-staff awareness LMS + phish-test metrics |
| KSI-CED-RRT | CED | Reviewing Response/Recovery Training | ✓/✓/derived(family) | process-artifact | IR/DR role training + drill participation |
| KSI-CED-RST | CED | Reviewing Role-Specific Training | ✓/✓/derived(at-2*,at-3,sr-11.1) | hybrid | Privileged-principal roster (IAM) proxy + training records |
| KSI-CMT-RVP | CMT | Reviewing Change Procedures | ✓/✓/derived(cm-3*,cm-5,cm-7.1,cm-9) | hybrid | Change-mgmt review cadence + CloudTrail/Config drift |
| KSI-INR-AAR | INR | Generating After Action Reports | ✓/✓/derived(ir-3,ir-4,ir-4.1,ir-8) | hybrid | Incident history (GuardDuty/Security Hub) + AAR artifact |
| KSI-INR-RPI | INR | Reviewing Past Incidents | ✓/✓/derived(ir-3,ir-4,ir-5,ir-8) | hybrid | Incident corpus + pattern/trend review |
| KSI-PIY-RES | PIY | Reviewing Executive Support | ✓/✓/derived(family) | process-artifact | Exec sign-off / governance review minutes |
| KSI-PIY-RIS | PIY | Reviewing Investments in Security | ✓/✓/derived(pm-3,sa-2,sa-3,sr-2.1) | process-artifact | Security budget/investment effectiveness review |
| KSI-PIY-RSD | PIY | Reviewing Security in the SDLC | ✓/✓/derived(sa-3,sa-8,pl-8,si-11) | hybrid | SDLC/Secure-by-Design review + pipeline gate signal |
| KSI-PIY-RVD | PIY | Reviewing Vulnerability Disclosures | ✓/✓/derived(ra-5.11) | hybrid | VDP endpoint reachability + intake/triage review |
| KSI-RPL-ARP | RPL | Aligning Recovery Plan | ✓/✓/derived(cp-2*,cp-6,cp-7,cp-10) | hybrid | Recovery plan vs backup/replication config (RPL-ABO) |
| KSI-RPL-RRO | RPL | Reviewing Recovery Objectives | ✓/✓/derived(cp-2.3,cp-10) | hybrid | Documented RTO/RPO vs measured backup cadence |
| KSI-SCR-MIT | SCR | Mitigating Supply Chain Risk | ✓/✓/derived(sa-9,sa-10,sa-11,sr-5,sr-6) | hybrid | Inspector lifecycle + subprocessor sheet + SLSA/sign |
| KSI-SVC-PRR | SVC | Preventing Residual Risk | ✓/✓/**High=false**(sc-4) | hybrid | Storage sanitization / lifecycle / no-residual-data config |

**Testability breakdown:** api-testable 0 · hybrid 15 · process-artifact 10.
**Pure process-artifact domains:** CED (all 4) and PIY-RES/RIS (governance) + the non-technical AFR pointers (ADS/CCM/FSI/ICP). **Hybrid domains** (cloud proxy + artifact): CMT, INR, RPL, SCR, SVC, and the technical AFR items (MAS/SCG/SCN/UCM/VDR/PVA) + PIY-RSD/RVD. **No KSI here is purely api-testable** — every one carries a "review effectiveness / address the process" obligation that requires a human artifact.

---

### KSI-AFR-ADS — Authorization Data Sharing  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: ac-3, ac-4, au-2, au-3, au-6, ca-2, ir-4, ra-5, sc-8)
- **Requirement (plain English):** Decide and document how *authorization data* (FRD: the package + all info FedRAMP needs for initial and ongoing assessment) is shared with *all necessary parties* (FRD: always FedRAMP + any agency customer operating the offering, sometimes 3PAO/consultants) per the FedRAMP ADS process, and persistently keep doing it.
- **Testability:** process-artifact
- **Automated validation:** No cloud primitive sets this. Collector emits a fixed `process_artifacts_required` slot and a presence check: does an ADS sharing plan exist and name a repository/share target? If the org uses FedRAMP's ADS API/repository, a future read-only HTTPS reachability probe of the configured share endpoint can confirm the channel is live (artifact-config check, not a cloud API).
- **Required permissions & error handling:** None cloud-side. If a share-endpoint URL is configured, surface network/4xx via the `network`/`not_found` classes in `error-diagnostics.ts` so the operator knows the share target is unreachable vs misconfigured.
- **Alternative satisfiers:** FedRAMP ADS repository / legacy self-managed repo (note the FRR-ADS legacy-repo MAY-exception for Rev5-High); GRC platform that publishes the package (Paramify, Vanta, Drata) — detected via the GRC rules in `third-party-tools.ts`.
- **OSCAL / NIST:** ac-3, ac-4, au-2/3/6, ca-2, ir-4, ra-5, sc-8. High-derivation: these controls all carry High-baseline enhancements; treat as applies-at-High.
- **Module connections:** Roll this and the other non-technical AFR pointers into the existing **`core/pva-collector.ts`** family as `process` findings (it already enumerates AFR), plus a new `KSI-AFR-ADS` registration in `ksi-map.ts` with `process_artifacts_required: ['ADS sharing plan + named repository/share target','Last share-event log']`.
- **Recommended implementation:** process-artifact-tracker (slot + optional endpoint reachability probe); rationale: no read-only cloud signal exists; effort **S**.

### KSI-AFR-CCM — Collaborative Continuous Monitoring  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: FRR-CCM family — ca-7, ca-7.4 via VDR/SCN siblings)
- **Requirement (plain English):** Maintain a plan/process to deliver Ongoing Authorization Reports and *Quarterly Reviews* (FRD: a regular synchronous meeting hosted for agency customers per the CCM process) to all necessary parties.
- **Testability:** process-artifact
- **Automated validation:** Artifact slot for the CCM plan + the Quarterly-Review schedule. The collector CAN feed CCM: the **PVA run-summary** (per-KSI pass/fail + drift) IS the data an Ongoing Authorization Report draws on. Auto-validation = "a PVA run-summary exists on the documented cadence and was distributed" (cadence check against `pva-run-summary.json` timestamps).
- **Required permissions & error handling:** None cloud-side; reads local `out/pva-run-summary.json`. Surface FS read errors as warnings (pattern from `pva-collector.ts`).
- **Alternative satisfiers:** GRC platform that schedules/sends ConMon reports (Vanta, Drata, Paramify); calendar/Quarterly-Review attendance export.
- **OSCAL / NIST:** family controls (ca-7 lineage). High-derivation via the CCM family + ca-7.4.
- **Module connections:** Extend **`core/pva-collector.ts`** (it already synthesizes the run summary) to add a `ccm.report_cadence_met` finding; register `KSI-AFR-CCM`.
- **Recommended implementation:** hybrid (PVA-cadence signal + artifact slot); rationale: PVA already produces the underlying report data; effort **S**.

### KSI-AFR-FSI — FedRAMP Security Inbox  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: FRR-FSI family; ir-6 lineage)
- **Requirement (plain English):** Operate a secure inbox (FRD: an email address meeting FedRAMP Security Inbox requirements) to receive critical FedRAMP/government communications.
- **Testability:** process-artifact
- **Automated validation:** Artifact slot for the inbox address + monitoring/routing config. Optional read-only DNS/MX lookup of the inbox domain confirms the mail domain resolves (presence, not security). Cannot read mailbox contents read-only.
- **Required permissions & error handling:** None cloud-side. DNS lookup failure → `network` class warning.
- **Alternative satisfiers:** Shared mailbox/distribution list with on-call routing into PagerDuty (detected via `third-party-tools.ts` PagerDuty rule).
- **OSCAL / NIST:** ir-6 lineage. High-derivation via family.
- **Module connections:** `core/pva-collector.ts` AFR roll-up; register `KSI-AFR-FSI` with artifact slot `['Security inbox address','Routing/monitoring config (who is paged)']`.
- **Recommended implementation:** process-artifact-tracker; rationale: mailbox is out-of-band; effort **S**.

### KSI-AFR-ICP — Incident Communications Procedures  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: ir-6, ir-6.1, ir-6.2 via VDR sibling)
- **Requirement (plain English):** Integrate FedRAMP's Incident Communications Procedures (notification timelines/recipients) into the org's *incident* (FRD: 44 USC §3552 occurrence jeopardizing federal customer data) response procedures.
- **Testability:** process-artifact
- **Automated validation:** Artifact slot for the IR runbook section that cites FedRAMP ICP timelines + recipient list. No read-only cloud call asserts procedure content. Cross-link to INR-AAR/RPI incident-history signal as corroboration the IR program is live.
- **Required permissions & error handling:** None cloud-side.
- **Alternative satisfiers:** PagerDuty/Opsgenie escalation policy referencing FedRAMP notification SLAs; SOAR runbook (Tines/Torq) — all in `third-party-tools.ts`.
- **OSCAL / NIST:** ir-6.*. High-derivation via family + ir-6.2 (High enhancement).
- **Module connections:** `core/pva-collector.ts` AFR roll-up; register `KSI-AFR-ICP`. Cross-KSI link to KSI-INR-RIR (already registered) and KSI-INR-AAR.
- **Recommended implementation:** process-artifact-tracker; rationale: procedure-content review; effort **S**.

### KSI-AFR-MAS — Minimum Assessment Scope  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: ac-1, ca-1, cm-1, cp-1/2.1/2.8/4.1, pl-2, ra-1/9, sa-1, sc-1, si-1, sr-1/2/3/11)
- **Requirement (plain English):** Apply the FedRAMP MAS to identify and document the assessed scope of the *cloud service offering* (FRD: the packaged product whose authorization is based on the MAS).
- **Testability:** hybrid
- **Automated validation:** Compare the documented MAS boundary (artifact: in-scope accounts/projects/services) against the **live inventory** the collector already generates for KSI-PIY-GIV. PASS = no in-scope account/project/region observed by `inventory.ts` that is absent from the documented MAS (and vice-versa). Surface "drift between documented scope and observed resources."
- **Required permissions & error handling:** Reuses PIY-GIV reads — AWS `config:DescribeConfigurationAggregators`, `config:DescribeConfigurationRecorders`, `tag:GetResources`; GCP `cloudasset.assets.list` (Cloud Asset Inventory viewer). AccessDenied → name the action via `diagnoseAwsError`/`diagnoseGcpError`; not-enabled (no aggregator) → recommend enabling, don't fail silently.
- **Alternative satisfiers:** CMDB/CSPM asset inventory (Wiz, ServiceNow CMDB) exported as the authoritative scope; Terraform state as boundary source.
- **OSCAL / NIST:** the listed -1 policy controls + ra-9 (supply-chain scope), sr-2/3. High-derivation: -1 controls + cp-2.8/4.1 are High-baseline.
- **Module connections:** Extend **`providers/aws/inventory.ts`** + `providers/gcp/inventory.ts` (which already power PIY-GIV) with a `mas.documented_scope_matches_inventory` finding that reads a configured MAS-boundary list; register `KSI-AFR-MAS`.
- **Recommended implementation:** hybrid (inventory-diff signal + MAS doc artifact); rationale: GIV inventory already collected — cheap diff; effort **M**.

### KSI-AFR-PVA — Persistent Validation and Assessment  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: ca-7, ca-7.6)
- **Requirement (plain English):** Persistently validate, assess, and report on the effectiveness/status of security decisions per the 20x PVA process. *Persistent Validation* (FRD) = the systematic process of validating that information resources operate securely against the KSIs.
- **Testability:** hybrid — **ALREADY COVERED** by the existing meta-collector.
- **Automated validation:** `core/pva-collector.ts` already produces `KSI-AFR-PVA.json`: it asserts the collector ran on cadence over every KSI and that no KSI regressed PASS→FAIL (negative drift) vs the previous run summary.
- **Required permissions & error handling:** None cloud-side (reads local `out/`). Already handles parse errors per file as failed modules.
- **Alternative satisfiers:** 3rd-party continuous-compliance platform (Vanta, Drata, Paramify, SecureFrame) — already enumerated in the collector.
- **OSCAL / NIST:** ca-7, ca-7.6. High-derivation via ca-7.6 (High enhancement).
- **Module connections:** No new work; listed here only because it appears in the 25. The other 9 AFR pointers feed it.
- **Recommended implementation:** none — already implemented; effort **—** (informational).

### KSI-AFR-SCG — Secure Configuration Guide  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: FRR-SCG family; cm-6, cm-7, sa-8 lineage)
- **Requirement (plain English):** Develop secure-by-default configurations and publish secure-configuration guidance for the offering to customers, per the FedRAMP SCG process.
- **Testability:** hybrid
- **Automated validation:** Artifact slot for the published SCG document. Corroborating cloud signal = the **secure-by-default baseline** already measured by KSI-CNA-IBP (`config.ts collectCnaIbp`: Security Hub FSBP/CIS enabled, 0 open critical). PASS-with-artifact = SCG doc attached AND IBP baseline healthy (you can't claim "secure by default" while criticals are open).
- **Required permissions & error handling:** Reuses IBP reads — `securityhub:GetEnabledStandards`, `securityhub:GetFindings`. AccessDenied/not-enabled surfaced via diagnostics.
- **Alternative satisfiers:** CIS-Benchmark-aligned hardening guide; CSPM posture export as "secure defaults" evidence (Wiz/Lacework).
- **OSCAL / NIST:** cm-6, cm-7, sa-8. High-derivation via family.
- **Module connections:** Cross-link to KSI-CNA-IBP (already registered); add a `scg.doc_present_and_baseline_healthy` finding in the AFR roll-up of `pva-collector.ts` or a thin extension to `config.ts`; register `KSI-AFR-SCG`.
- **Recommended implementation:** hybrid; rationale: IBP signal exists, doc is the gap; effort **S**.

### KSI-AFR-SCN — Significant Change Notifications  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: ca-7, ca-7.4, cm-3.4, cm-4, cm-7.1, au-5, ca-5, ra-5/5.2, sa-22, si-2/2.2/3/5/7.7/10/11)
- **Requirement (plain English):** Determine how *significant changes* (FRD/NIST 800-37: a change likely to substantively affect security/privacy posture) are tracked and how all necessary parties are notified, per the FedRAMP SCN process.
- **Testability:** hybrid
- **Automated validation:** Two signals: (1) change events ARE captured — reuse KSI-CMT-LMC's CloudTrail/Config change history (`logging.ts collectCmtLmc`) to prove a tracking substrate exists; (2) artifact slot for the SCN notification process + a sample notification record. PASS-with-artifact = change-logging healthy AND SCN procedure attached.
- **Required permissions & error handling:** Reuses CMT-LMC reads — `cloudtrail:DescribeTrails`/`GetTrailStatus`, `config:DescribeConfigurationRecorders`. GCP `logging.logEntries.list` + Asset Inventory. Diagnostics name each action on AccessDenied; no-trail → `not_found`/`not_enabled` guidance.
- **Alternative satisfiers:** GRC platform change-tracking (Vanta/Drata); ITSM change tickets (ServiceNow/Jira) as the notification ledger.
- **OSCAL / NIST:** the listed change/assessment controls. High-derivation: cm-3.4, ca-7.4, si-7.7 are High-baseline.
- **Module connections:** Extend **`providers/aws/logging.ts`** (CMT-LMC already here) with `scn.change_tracking_substrate_present`; register `KSI-AFR-SCN` with the notification artifact slot. Cross-KSI: KSI-CMT-LMC, KSI-CMT-RVP.
- **Recommended implementation:** hybrid; rationale: change-log signal reused, notification is artifact; effort **M**.

### KSI-AFR-UCM — Using Cryptographic Modules  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: FRR-UCM family; sc-12, sc-13, sc-8.1 lineage)
- **Requirement (plain English):** Ensure cryptographic modules protecting potentially sensitive *federal customer data* (FRD: agency-uploaded content, excluding provider telemetry/metadata) are selected/used per 20x UCM guidance (FIPS-validated / CMVP).
- **Testability:** hybrid
- **Automated validation:** Confirm key material lives in FIPS-validated KMS: AWS `kms:ListKeys`/`DescribeKey` (note AWS KMS HSM backing + FIPS 140 endpoints), ACM cert key specs; GCP Cloud KMS `cryptoKeys.list` with `protectionLevel` HSM and FIPS-validated levels. PASS = customer-data-protecting keys are CMK in KMS/Cloud KMS with FIPS-validated protection level; FAIL = software/keyless or external unvalidated modules without an attestation artifact. Validation *level* itself (CMVP cert #) is an artifact.
- **Required permissions & error handling:** AWS `kms:ListKeys`, `kms:DescribeKey`, `kms:ListAliases`, `acm:ListCertificates`/`DescribeCertificate`. GCP `cloudkms.cryptoKeys.list` (Cloud KMS Viewer). AccessDenied → name action; not-enabled (no KMS keys) → note + artifact fallback.
- **Alternative satisfiers:** External HSM (CloudHSM, Thales) with CMVP cert; HashiCorp Vault (detected in `third-party-tools.ts`) with documented FIPS mode.
- **OSCAL / NIST:** sc-12, sc-12.2, sc-13, sc-8.1. High-derivation via family.
- **Module connections:** New `providers/aws/crypto.ts` + `providers/gcp/crypto.ts` (small) OR extend `providers/aws/secrets.ts` (already does SVC-ASM/KMS-adjacent reads); register `KSI-AFR-UCM`. Cross-KSI: KSI-SVC-ASM, KSI-SVC-SNT.
- **Recommended implementation:** hybrid (KMS FIPS signal + CMVP cert artifact); rationale: read-only KMS describe is clean; effort **M**.

### KSI-AFR-VDR — Vulnerability Detection and Response  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: ra-5 + .2/.3/.4/.5/.6/.7/.11, si-2 + .1/.2/.4/.5, si-3/.1/.2, si-4 + .2/.3/.7, ir-4/.1, ir-5/.1, ir-6 + .1/.2, ca-7/.4/.6, ra-2/.1, ra-3/.3, ra-7/9/10, pm-3/5/31)
- **Requirement (plain English):** Document the *vulnerability detection* (FRD: discovering/identifying vulnerabilities via scanning, threat-intel, disclosure, bug bounty, supply-chain monitoring) and *vulnerability response* (FRD: track→evaluate→mitigate→monitor→remediate→report) methodology used in the offering, per the FedRAMP VDR process.
- **Testability:** hybrid
- **Automated validation:** Aggregate the existing detection/response signals into one VDR roll-up: Inspector enabled + finding lifecycle (`supplychain.ts collectScrMon`/`collectCmtVtd`), Security Hub finding lifecycle (`config.ts collectSvcEis`, `logging.ts collectMlaEvc`), GuardDuty detector enabled. PASS = ≥1 detection source live across scan/threat-intel categories AND a response lifecycle is closing findings (resolved-ratio threshold). The documented methodology is the artifact.
- **Required permissions & error handling:** `inspector2:GetConfiguration`/`ListFindings`, `securityhub:GetFindings`/`GetEnabledStandards`, `guardduty:ListDetectors`/`GetDetector`; GCP Security Command Center `findings.list`. Each call wrapped with `diagnoseAwsError`/`diagnoseGcpError`; SCC not-enabled → recommend enabling.
- **Alternative satisfiers:** GRC/CNAPP that owns the VDR lifecycle (Vanta, Drata, Wiz) — already mapped to KSI-AFR-VDR in `third-party-tools.ts`; bug-bounty platform (HackerOne/Bugcrowd) as a detection source artifact.
- **OSCAL / NIST:** the large ra-5/si-2/si-4/ir-4 set. High-derivation: ra-5.4/.5, si-4.7, ir-6.2 etc. are High-baseline.
- **Module connections:** New roll-up finding set spanning `supplychain.ts` + `config.ts` + `logging.ts`, or a meta-collector beside `pva-collector.ts`; register `KSI-AFR-VDR`. Cross-KSI: KSI-SCR-MIT, KSI-SCR-MON, KSI-MLA-EVC, KSI-CMT-VTD.
- **Recommended implementation:** hybrid (aggregate detection+response signals + methodology doc); rationale: signals already collected elsewhere — this is an aggregator; effort **M**.

### KSI-CED-DET — Reviewing Development and Engineering Training  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: cp-3, ir-2, ps-6)
- **Requirement (plain English):** Persistently review the *effectiveness* of role-specific training for dev/engineering staff on delivering secure software.
- **Testability:** process-artifact
- **Automated validation:** No read-only cloud API touches an LMS. Collector holds an artifact slot for: training-platform completion export for eng roles + the effectiveness-review minutes (e.g., post-training assessment scores, secure-coding-defect trend). Optional: read-only LMS API pull (KnowBe4/Pluralsight) if a token is provided — but that is an external-tool integration, not a cloud collector.
- **Required permissions & error handling:** None cloud-side. If an LMS API token is configured, 401/403 surfaced as external-tool auth errors (reuse `network`/`access_denied` classes generically).
- **Alternative satisfiers:** **KnowBe4** (FedRAMP-Moderate authorized; exposes phish-prone % + completion as effectiveness metrics), Pluralsight/Secure Code Warrior, internal LMS export; HRIS completion report.
- **OSCAL / NIST:** cp-3, ir-2, ps-6. High-derivation: ps-6 + cp-3 carry High enhancements (cp-3.1).
- **Module connections:** No existing collector — **new process-artifact tracker entry** in `ksi-map.ts` with `process_artifacts_required`; optionally a new `core/detect` LMS connector. Group with the other 3 CED items.
- **Recommended implementation:** process-artifact-tracker (+ optional external-tool LMS pull); rationale: training lives outside cloud; effort **S** (artifact), **M** (with LMS API).

### KSI-CED-RGT — Reviewing General Training  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: at-2, at-2.2, at-2.3, at-3.5, at-4, ir-2.3)
- **Requirement (plain English):** Persistently review the effectiveness of training given to ALL employees on policies, procedures, and security topics.
- **Testability:** process-artifact
- **Automated validation:** Artifact slot for all-staff awareness-training completion rate + phishing-simulation results (the canonical effectiveness metric) + the review minutes. Same optional-LMS-pull note as CED-DET.
- **Required permissions & error handling:** None cloud-side.
- **Alternative satisfiers:** **KnowBe4** (phish-prone % is the literal effectiveness signal), Proofpoint Security Awareness, Hoxhunt; SSO-attestation that 100% of active IdP users completed (IdP group/attribute read could *proxy* coverage but not effectiveness).
- **OSCAL / NIST:** at-2/.2/.3, at-3.5, at-4, ir-2.3. High-derivation: at-2.2/.3, at-3.5 are higher-baseline enhancements.
- **Module connections:** New process-artifact entry; group with CED. Optional cross-signal: IdP user count (from IAM collectors) as a denominator for completion %.
- **Recommended implementation:** process-artifact-tracker; rationale: effectiveness review is human; effort **S**.

### KSI-CED-RRT — Reviewing Response and Recovery Training  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: ir-2, ir-2.3, cp-3 via family)
- **Requirement (plain English):** Persistently review the effectiveness of role-specific training for staff involved in incident response or disaster recovery.
- **Testability:** process-artifact
- **Automated validation:** Artifact slot for IR/DR role-holder training records + drill participation. Strong corroboration available from the collector: the **RPL-TRC DR-test AAR** and **INR-AAR** already-collected/required artifacts demonstrate the trained staff executed — cross-link them.
- **Required permissions & error handling:** None cloud-side.
- **Alternative satisfiers:** Tabletop-exercise platform (AttackIQ, RangeForce) records; PagerDuty post-incident review participation.
- **OSCAL / NIST:** ir-2.*, cp-3 lineage. High-derivation via ir-2.3.
- **Module connections:** New process-artifact entry; explicit cross-KSI to KSI-RPL-TRC and KSI-INR-AAR (drills/AARs are the practical proof).
- **Recommended implementation:** process-artifact-tracker; rationale: ties to existing DR/IR artifacts; effort **S**.

### KSI-CED-RST — Reviewing Role-Specific Training  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: at-2, at-2.3, at-3, sr-11.1)
- **Requirement (plain English):** Persistently review the effectiveness of role-specific training for high-risk roles — at minimum, roles with privileged access.
- **Testability:** process-artifact
- **Automated validation:** Artifact slot for privileged-role training completion + review minutes. **Useful cloud proxy for the denominator:** enumerate privileged principals via the existing IAM collectors (admin-policy holders, KSI-IAM-ELP/AAM data) to define "who needs role-specific training," then the artifact proves they got it. PASS-with-artifact = every privileged principal observed has a training record.
- **Required permissions & error handling:** Reuses IAM reads — AWS `iam:ListUsers`/`ListRoles`/`ListAttachedRolePolicies`; GCP `iam.roles.list`/`getIamPolicy`. AccessDenied named per action.
- **Alternative satisfiers:** Secure Code Warrior / role-based LMS tracks; sr-11.1-aligned developer/supplier training (also touches SCR-MIT).
- **OSCAL / NIST:** at-2/.3, at-3, sr-11.1. High-derivation: at-2.3 + at-3 enhancements.
- **Module connections:** New process-artifact entry; cross-signal to KSI-IAM-ELP/AAM for the privileged-principal roster.
- **Recommended implementation:** hybrid-leaning process-artifact-tracker (privileged-roster proxy + training artifact); rationale: roster is auto-derivable, effectiveness is human; effort **S**.

### KSI-CMT-RVP — Reviewing Change Procedures  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: cm-3, cm-3.2, cm-3.4, cm-5, cm-7.1, cm-9)
- **Requirement (plain English):** Persistently review the effectiveness of documented change-management procedures.
- **Testability:** hybrid
- **Automated validation:** Effectiveness proxy = the change process is actually operating and not being bypassed: (1) change events logged (CMT-LMC CloudTrail/Config), (2) low/zero IaC drift (CNA-EIS/SVC-ACM CloudFormation `DriftInformation` + Config rules) — drift = changes outside the procedure, (3) deploy gates exist (CMT-VTD pipeline test/scan/approval stages). PASS-with-artifact = change-log healthy + drift below threshold + ≥1 approval/gate signal + the review minutes attached.
- **Required permissions & error handling:** Reuses `config:DescribeConfigRules`/`DescribeConformancePackCompliance`, `cloudformation:DescribeStacks` (drift), `cloudtrail:*` status, `codepipeline:ListPipelines`/`GetPipeline`. GCP equivalents (Config Controller / Cloud Build triggers). Each via `diagnoseAwsError`; not-enabled Config → recommend enabling.
- **Alternative satisfiers:** **ArgoCD / Flux** GitOps (declared-vs-live drift), **Terraform Cloud / Atlantis / Spacelift** drift detection, **Wiz** config-drift — detection signals already in `config.ts` alt-satisfiers; ITSM change-approval metrics (ServiceNow).
- **OSCAL / NIST:** cm-3/.2/.4, cm-5, cm-7.1, cm-9. High-derivation: cm-3.2 (automated) is a Moderate/High enhancement; cm-9 plan.
- **Module connections:** Extend **`providers/aws/config.ts`** with a `cmt.change_procedure_effectiveness` finding aggregating drift + gate signals; register `KSI-CMT-RVP`. Cross-KSI: KSI-CMT-LMC, KSI-CMT-VTD, KSI-CNA-EIS, KSI-SVC-ACM, KSI-AFR-SCN.
- **Recommended implementation:** hybrid; rationale: drift + gate signals already collected — aggregate + review artifact; effort **M**.

### KSI-INR-AAR — Generating After Action Reports  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: ir-3, ir-4, ir-4.1, ir-8)
- **Requirement (plain English):** Generate incident after-action reports and persistently incorporate lessons learned.
- **Testability:** hybrid
- **Automated validation:** Cloud signal = an incident-detection substrate exists and surfaces an incident corpus: GuardDuty findings, Security Hub incidents, CloudWatch alarms in ALARM history (reuse `logging.ts collectInrRir`). Then artifact slot for the AAR template + recent AARs + a lessons-learned change log. PASS-with-artifact = for incidents in the observed corpus (above a severity bar), an AAR exists. If zero incidents, vacuously pass the generation check but still require the AAR *process* artifact.
- **Required permissions & error handling:** `guardduty:ListDetectors`/`ListFindings`, `securityhub:GetFindings`, `cloudwatch:DescribeAlarmHistory`; GCP SCC `findings.list`, Cloud Monitoring incidents. AccessDenied/not-enabled named via diagnostics.
- **Alternative satisfiers:** **PagerDuty** post-mortems (mapped to KSI-INR-AAR in `third-party-tools.ts`), incident.io / FireHydrant retrospectives, Jira/Confluence post-incident docs.
- **OSCAL / NIST:** ir-3, ir-4, ir-4.1, ir-8. High-derivation: ir-3.2 (coordination), ir-4.* High enhancements.
- **Module connections:** Extend **`providers/aws/logging.ts`** (INR-RIR already here) with `inr.aar_corpus_and_process`; register `KSI-INR-AAR`. Cross-KSI: KSI-INR-RPI, KSI-INR-RIR, KSI-CED-RRT, KSI-AFR-ICP.
- **Recommended implementation:** hybrid; rationale: incident corpus auto-derivable, AAR content is artifact; effort **M**.

### KSI-INR-RPI — Reviewing Past Incidents  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: ir-3, ir-4, ir-4.1, ir-5, ir-8)
- **Requirement (plain English):** Persistently review past incidents for patterns or *vulnerabilities* (FRD: any weakness enabling defeat of controls — includes misconfigs, KSI gaps, etc.).
- **Testability:** hybrid
- **Automated validation:** Same incident-corpus signal as INR-AAR, but the assertion is the *trend/pattern review*: the collector can compute repeat-finding-type counts from GuardDuty/Security Hub history (e.g., same finding type recurring = an unaddressed pattern) and flag them; the human review of those patterns + recorded systemic actions is the artifact. PASS-with-artifact = pattern-review minutes attached AND no high-severity finding type recurring beyond a documented threshold.
- **Required permissions & error handling:** Same as INR-AAR (`guardduty:*` list/get, `securityhub:GetFindings`; GCP SCC). Diagnostics per call.
- **Alternative satisfiers:** SIEM trend dashboards (Splunk/Datadog/Elastic — in `third-party-tools.ts`); PagerDuty/incident.io retrospective trend reports.
- **OSCAL / NIST:** ir-3/4/4.1/5/8. High-derivation: ir-5.1 (automated tracking), ir-4.* High enhancements.
- **Module connections:** Extend **`providers/aws/logging.ts`** with `inr.recurring_pattern_review`; register `KSI-INR-RPI`. Cross-KSI: KSI-INR-AAR, KSI-AFR-VDR.
- **Recommended implementation:** hybrid; rationale: recurrence computable from finding history; effort **M**.

### KSI-PIY-RES — Reviewing Executive Support  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: pm-1, pm-2, pm-3 family — governance)
- **Requirement (plain English):** Persistently review executive support for achieving the org's security objectives.
- **Testability:** process-artifact
- **Automated validation:** No cloud API. Artifact slot for: executive sign-off on the security program, security-steering-committee minutes, budget-approval evidence, named security executive (CISO). Pure governance.
- **Required permissions & error handling:** None cloud-side.
- **Alternative satisfiers:** GRC platform governance module (Vanta/Drata "policies + approvals"); board/steering-committee minutes; signed ISMS management-review (ISO 27001 §9.3 crosswalk).
- **OSCAL / NIST:** pm-1/2/3 governance family (note: dump `controls[]` empty — derivation rests on the PM family). High-derivation: PM controls are baseline-independent (org-level), so applies at High.
- **Module connections:** New process-artifact entry in `ksi-map.ts`; group with PIY governance. Cross-KSI: KSI-PIY-RIS.
- **Recommended implementation:** process-artifact-tracker; rationale: governance is non-technical; effort **S**.

### KSI-PIY-RIS — Reviewing Investments in Security  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: pm-3, sa-2, sa-3, ac-5, ca-2, cp-2.1, cp-4.1, ir-3.2, sr-2.1)
- **Requirement (plain English):** Persistently review the effectiveness of the org's investments in achieving security objectives.
- **Testability:** process-artifact
- **Automated validation:** No cloud API measures ROI/investment. Artifact slot for security-budget-vs-outcome review (spend mapped to risk reduction, tooling utilization). Optional weak corroboration: cloud-security tooling spend (Cost Explorer is read-only) — but cost data is out of the read-only collector's clean scope and noisy; keep as artifact.
- **Required permissions & error handling:** None cloud-side (recommend NOT wiring Cost Explorer to avoid scope creep).
- **Alternative satisfiers:** GRC platform spend/coverage analytics; FinOps tooling (CloudHealth) tagged security spend; the PVA pass-rate trend as an "are investments working" outcome metric.
- **OSCAL / NIST:** pm-3 (resources), sa-2/3, ca-2. High-derivation: cp-2.1/4.1, ir-3.2, sr-2.1 are higher-baseline.
- **Module connections:** New process-artifact entry; cross-KSI to KSI-PIY-RES (same governance review) and KSI-AFR-PVA (outcome metric).
- **Recommended implementation:** process-artifact-tracker; rationale: investment review is financial/governance; effort **S**.

### KSI-PIY-RSD — Reviewing Security in the SDLC  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: sa-3, sa-8, pl-8, pm-7, ac-5, au-3.3, cm-3.4, sc-4, sc-18, si-10, si-11, si-16)
- **Requirement (plain English):** Persistently review the effectiveness of building security/privacy into the SDLC and aligning with CISA Secure-by-Design.
- **Testability:** hybrid
- **Automated validation:** Cloud/pipeline signal = SDLC security gates operate: pipeline test+scan+approval stages (CMT-VTD `supplychain.ts`), branch-protection/required-checks (GitHub — external), scan-on-push + Inspector (SCR-MON). PASS-with-artifact = ≥1 SAST/SCA + ≥1 review gate observed in pipelines AND the Secure-by-Design alignment review minutes attached.
- **Required permissions & error handling:** Reuses CMT-VTD reads — `codepipeline:ListPipelines`/`GetPipeline`, `codebuild:ListProjects`/`BatchGetProjects`, `inspector2:GetConfiguration`, `ecr:DescribeRepositories`. GCP Cloud Build triggers, Artifact Registry scanning. Diagnostics per call; off-AWS CI → alt-satisfier path (already modeled in `supplychain.ts`).
- **Alternative satisfiers:** GitHub Advanced Security / GitLab CI security stages, **Snyk**, Secure Code Warrior training tie-in (CED-DET); CISA Secure-by-Design self-attestation form as artifact.
- **OSCAL / NIST:** sa-3/8, pl-8, pm-7, si-10/11/16, sc-18. High-derivation: au-3.3, cm-3.4, si-16 higher-baseline.
- **Module connections:** Extend **`providers/aws/supplychain.ts`** (CMT-VTD here) with `piy.sdlc_security_gates_present`; register `KSI-PIY-RSD`. Cross-KSI: KSI-CMT-VTD, KSI-SCR-MON, KSI-CED-DET.
- **Recommended implementation:** hybrid; rationale: pipeline gate signals already collected; effort **M**.

### KSI-PIY-RVD — Reviewing Vulnerability Disclosures  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: ra-5.11)
- **Requirement (plain English):** Persistently review the effectiveness of the provider's vulnerability-disclosure program (VDP).
- **Testability:** hybrid
- **Automated validation:** Light cloud signal = a VDP intake channel is reachable: read-only HTTPS GET of the org's `/.well-known/security.txt` (RFC 9116) and the published VDP/`/security` page returns 200 with a contact. The effectiveness review (intake volume, time-to-triage, resolution) is the artifact. PASS-with-artifact = security.txt resolves + VDP-review minutes attached.
- **Required permissions & error handling:** None cloud-side; an outbound HTTPS probe. 404/timeout on security.txt → `not_found`/`network` warning ("publish RFC 9116 security.txt").
- **Alternative satisfiers:** **HackerOne / Bugcrowd / Intigriti** managed VDP/bug-bounty (their dashboard = effectiveness evidence); disclosure mailbox tie-in to AFR-FSI.
- **OSCAL / NIST:** ra-5.11 (public disclosure program). High-derivation: ra-5.11 is in the High baseline.
- **Module connections:** New thin `core/detect` security.txt probe OR extend `supplychain.ts`; register `KSI-PIY-RVD`. Cross-KSI: KSI-AFR-VDR (response side), KSI-AFR-FSI (inbox).
- **Recommended implementation:** hybrid (security.txt reachability + VDP review artifact); rationale: intake presence is cheaply testable; effort **S**.

### KSI-RPL-ARP — Aligning Recovery Plan  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: cp-2 + .1/.3, cp-4.1, cp-6 + .1/.3, cp-7 + .1/.2/.3, cp-8 + .1/.2, cp-10 + .2)
- **Requirement (plain English):** Persistently review the alignment of recovery plans with defined recovery objectives.
- **Testability:** hybrid
- **Automated validation:** Cloud signal = backup/replication config exists and matches the documented plan: reuse KSI-RPL-ABO/CNA-OFA (`backup.ts`) — AWS Backup plans + selections, RDS automated backups, cross-region replication, multi-AZ; GCP backup/DR + regional configs. PASS-with-artifact = backup/replication present for in-scope resources AND the recovery-plan-alignment review minutes attached (plan covers what's deployed). FAIL = critical data store with no backup/replication, or plan references resources not backed up.
- **Required permissions & error handling:** `backup:ListBackupPlans`/`ListBackupSelections`, `rds:DescribeDBInstances`, `s3:GetBucketReplication`, `ec2:DescribeSnapshots`; GCP Backup-and-DR + `compute.disks.list`. AccessDenied named; not-enabled (no AWS Backup) → check native per-service backups before failing.
- **Alternative satisfiers:** Druva / Cohesity / Veeam managed backup; Terraform-declared DR topology as the plan-of-record.
- **OSCAL / NIST:** the full cp-2/6/7/8/10 set. High-derivation: cp-6.3, cp-7.3, cp-8.2, cp-10.2 are High-baseline enhancements (this is the most clearly High-relevant set in the batch).
- **Module connections:** Extend **`providers/aws/backup.ts`** (RPL-ABO/CNA-OFA here) with `rpl.recovery_plan_alignment`; register `KSI-RPL-ARP`. Cross-KSI: KSI-RPL-ABO, KSI-RPL-RRO, KSI-RPL-TRC, KSI-CNA-OFA.
- **Recommended implementation:** hybrid; rationale: backup/replication config already collected; effort **M**.

### KSI-RPL-RRO — Reviewing Recovery Objectives  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: cp-2.3, cp-10)
- **Requirement (plain English):** Persistently review the desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO).
- **Testability:** hybrid
- **Automated validation:** RPO is partially measurable: backup *frequency* observed (AWS Backup plan schedule / RDS backup window / snapshot cadence) implies achievable RPO; compare to documented RPO. RTO is artifact (proven by RPL-TRC restore tests). PASS-with-artifact = documented RTO/RPO attached AND observed backup cadence ≤ documented RPO for in-scope stores.
- **Required permissions & error handling:** `backup:ListBackupPlans` (schedule), `rds:DescribeDBInstances` (BackupRetentionPeriod/window); GCP backup schedules. Same diagnostics as RPL-ARP.
- **Alternative satisfiers:** DR-orchestration tooling (AWS Elastic Disaster Recovery, Azure Site Recovery) reporting RTO/RPO; backup vendor SLA reports.
- **OSCAL / NIST:** cp-2.3 (resume time), cp-10 (recovery/reconstitution). High-derivation: cp-2.3 + cp-10.2 are High enhancements.
- **Module connections:** Extend **`providers/aws/backup.ts`** with `rpl.rpo_cadence_vs_documented`; register `KSI-RPL-RRO`. Cross-KSI: KSI-RPL-ARP, KSI-RPL-ABO, KSI-RPL-TRC.
- **Recommended implementation:** hybrid; rationale: RPO inferable from backup cadence, RTO is artifact; effort **M**.

### KSI-SCR-MIT — Mitigating Supply Chain Risk  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ H:derived(rev5: sa-9, sa-10, sa-11, sa-15.3, sa-22, ac-20, ra-3.1, si-7.1, sr-5, sr-6, ca-7.4, sc-18)
- **Requirement (plain English):** Persistently identify, review, and mitigate potential supply-chain risks (FKA KSI-TPR-03 — third-party risk).
- **Testability:** hybrid
- **Automated validation:** Several signals: (1) **subprocessor inventory** is current — read the org's authoritative subprocessor Google Sheet (already planned via `core/subprocessors-sheet.ts`) and confirm freshness; (2) upstream-dependency monitoring live — Inspector/ECR scan + SCR-MON; (3) artifact-integrity/provenance — image signing (`supplychain.ts` Lambda code-signing / cosign-verify SBOM module already in repo), SLSA provenance. PASS-with-artifact = subprocessor sheet current + scanning live + a documented mitigation/review process (vendor risk assessments). 
- **Required permissions & error handling:** Sheets API read (Viewer-grant SA) — auth errors via `diagnoseGcpError`; `inspector2:*`, `ecr:DescribeRepositories`, `signer:ListSigningProfiles`. AccessDenied named; sheet-unreachable → warning to re-grant Viewer.
- **Alternative satisfiers:** **Snyk / Aqua / Wiz Code** SCA (mapped to KSI-SCR-MON), **Sigstore/cosign + SLSA provenance** for build attestation, vendor-risk platform (OneTrust/Whistic) for subprocessor assessments, Dependabot/Renovate.
- **OSCAL / NIST:** sa-9/10/11, sr-5/6, sa-22, sc-18. High-derivation: sa-9.*, sr-6, sa-15.3 are higher-baseline; ra-3.1 (SC risk assessment).
- **Module connections:** Extend **`providers/aws/supplychain.ts`** (SCR-MON here) + wire `core/subprocessors-sheet.ts`; register `KSI-SCR-MIT`. Cross-KSI: KSI-SCR-MON, KSI-CMT-VTD, KSI-AFR-VDR, KSI-CED-RST(sr-11.1 supplier training).
- **Recommended implementation:** hybrid; rationale: scanning + signing + subprocessor-sheet signals largely exist (SCR-MON, SBOM/cosign module); MIT is the mitigation-review aggregator; effort **M**.

### KSI-SVC-PRR — Preventing Residual Risk  [MUST]
- **Track / actor / levels:** 20x / Providers / L:✓ M:✓ **H:applies=false (dump)** / NIST sc-4
- **Requirement (plain English):** (Statement null in dump; per name + sc-4 + FRD terms) Prevent residual risk from *federal customer data* (FRD) and other *information resources* (FRD) — i.e., ensure data does not persist in shared/reused resources where it could be exposed (information-remnance / object-reuse, sc-4).
- **Testability:** hybrid
- **Automated validation:** Signals against data remnance: S3 lifecycle/expiration rules + bucket no-public + default encryption; EBS/snapshot encryption + deletion policy; ephemeral-compute (no long-lived disks carrying customer data); memory/temp not persisted. Reuse KSI-SVC-RUD (`data.ts`) deletion-capability signal. PASS-with-artifact = encryption-at-rest everywhere + lifecycle expiration on data buckets + documented sanitization-on-decommission procedure (artifact).
- **Required permissions & error handling:** `s3:GetBucketLifecycleConfiguration`/`GetBucketEncryption`/`GetBucketPolicyStatus`, `ec2:DescribeVolumes`/`DescribeSnapshots`; GCP `storage.buckets.get` (lifecycle/encryption), `compute.disks.list`. Each via diagnostics; `not_found` lifecycle (no rule) is itself the gap.
- **Alternative satisfiers:** DSPM tooling (Wiz DSPM, BigID, Cyera) proving no residual sensitive data; CMK + crypto-shredding (ties to AFR-UCM); DLP scan reports.
- **OSCAL / NIST:** sc-4 (information in shared resources). **High-derivation note: the dump explicitly sets `levels.high.applies = false`** — do NOT assert at High from the dump; if sc-4 enhancements are in scope at High elsewhere, state that separately. At L/M it applies.
- **Module connections:** Extend **`providers/aws/data.ts`** (SVC-RUD here) + `providers/aws/network.ts` data-encryption signals; register `KSI-SVC-PRR`. Cross-KSI: KSI-SVC-RUD, KSI-SVC-VRI, KSI-AFR-UCM.
- **Recommended implementation:** hybrid; rationale: encryption/lifecycle reads are clean and partly collected for SVC-RUD; sanitization-on-decommission is the artifact; effort **M**.

---

## Registration & module summary

| New collector work | File to extend | KSIs |
|---|---|---|
| AFR roll-ups (process pointers) | `core/pva-collector.ts` | ADS, CCM, FSI, ICP, SCG (+ VDR aggregator) |
| Inventory diff | `providers/{aws,gcp}/inventory.ts` | AFR-MAS |
| Change/drift aggregate | `providers/aws/config.ts` | CMT-RVP, AFR-SCG |
| Change-log substrate | `providers/aws/logging.ts` | AFR-SCN |
| KMS/FIPS | new `crypto.ts` or `secrets.ts` | AFR-UCM |
| Detection+response aggregate | `supplychain.ts`+`config.ts`+`logging.ts` | AFR-VDR |
| Incident corpus | `providers/aws/logging.ts` | INR-AAR, INR-RPI |
| Pipeline gates | `providers/aws/supplychain.ts` | PIY-RSD |
| security.txt probe | new thin `core/detect` | PIY-RVD |
| Backup/recovery alignment | `providers/aws/backup.ts` | RPL-ARP, RPL-RRO |
| Subprocessor + scan + sign | `supplychain.ts` + `core/subprocessors-sheet.ts` | SCR-MIT |
| Data remnance/lifecycle | `providers/aws/data.ts` | SVC-PRR |
| Pure process-artifact tracker entries (no collector) | `core/ksi-map.ts` only | CED-DET, CED-RGT, CED-RRT, CED-RST, PIY-RES, PIY-RIS |

Every new entry must keep the read-only guarantee (List/Get/Describe only) and carry `process_artifacts_required` for the human-attached half, matching the HYBRID pattern already used for IAM-JIT / MLA-LET / RPL-ABO in `ksi-map.ts`.
