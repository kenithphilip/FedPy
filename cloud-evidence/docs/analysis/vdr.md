# VDR — Vulnerability Detection and Response

The VDR family (39 requirements) governs how a Provider **systematically, persistently, and promptly** discovers vulnerabilities (Detection) and then tracks/evaluates/mitigates/reports them (Response) across its Cloud Service Offering. Most VDR requirements describe a *process discipline* (timeframes, evaluation factors, reporting cadence, KEV avoidance) rather than a single configurable cloud control, so this family skews heavily toward **process-artifact** and **hybrid** testability — a read-only collector can prove that the *machinery exists and is enabled* (Inspector/ECR scan, Artifact Analysis/SCC, KEV cross-reference, a VDP) but cannot prove the *human policy* (acceptance decisions, agency reporting, disclosure judgment). The collector's value is to ingest the scanner inventory as ground truth, cross-reference CISA KEV, and attach a structured ledger that the process-artifact tracker tracks against the timeframe SLAs. Note: several VDR requirements (`VDR-AGM-*`, `VDR-FRP-*`) target **Agencies/FedRAMP**, not the Provider — for a CSP user these are out-of-scope-to-satisfy and tracked only as awareness items. All High levels are not 20x-published except the `VDR-TFR-*` timeframe requirements (which publish explicit L/M/H values); elsewhere High is **DERIVED from NIST 800-53 Rev5 High baseline via controls[]**, and VDR maps cleanly to the **RA-5 / RA-5(2)(11) / SI-2 / SI-3 / SI-5 / CA-7** control set even though the dump carries `controls: []`.

## Coverage table

| ID | Name | L/M/H | Testability | Primary signal |
|----|------|-------|-------------|----------------|
| VDR-AGM-DRE | Do Not Request Extra Info | ✓/✓/derived | process-artifact | Agency-actor; CSP awareness only |
| VDR-AGM-MAP | Maintain Agency POA&M | ✓/✓/derived | process-artifact | Agency-actor; out of CSP scope |
| VDR-AGM-NFR | Notify FedRAMP | ✓/✓/derived | process-artifact | Agency-actor; out of CSP scope |
| VDR-AGM-RVR | Review Vulnerability Reports | ✓/✓/derived | process-artifact | Agency-actor; out of CSP scope |
| VDR-BST-ADT | Automate Detection | ✓/✓/derived | api-testable | Inspector/ECR + Artifact Analysis enabled |
| VDR-BST-AKE | Avoid KEVs | ✓/✓/derived | hybrid | New images scanned; 0 KEV CVEs at deploy |
| VDR-BST-DAC | Detect After Changes | ✓/✓/derived | hybrid | Scan-on-push + CI/CD scan gate |
| VDR-BST-DFR | Design For Resilience | ✓/✓/derived | process-artifact | Architecture attestation |
| VDR-BST-MSP | Maintain Security | ✓/✓/derived | process-artifact | Negative attestation; config drift signal |
| VDR-BST-SIR | Sampling | ✓/✓/derived | process-artifact | Sampling methodology doc |
| VDR-CSO-DET | Vulnerability Detection | ✓/✓/derived | hybrid | Scanner coverage across all resource classes |
| VDR-CSO-DOC | Documentation for Recommendations | ✓/✓/derived | process-artifact | Deviation rationale in authorization data |
| VDR-CSO-RES | Vulnerability Response | ✓/✓/derived | hybrid | Findings ledger w/ lifecycle states |
| VDR-EVA-EFA | Evaluation Factors | ✓/✓/derived | process-artifact | Evaluation schema covers 8 factors |
| VDR-EVA-EFP | Evaluate False Positives | ✓/✓/derived | hybrid | Suppression/FP-disposition records |
| VDR-EVA-EIR | Evaluate Internet-Reachability | ✓/✓/derived | hybrid | IRV flag derivable from exposure topology |
| VDR-EVA-ELX | Evaluate Exploitability | ✓/✓/derived | hybrid | LEV flag from KEV/EPSS + reachability |
| VDR-EVA-EPA | Estimate Potential Adverse Impact | ✓/✓/derived | process-artifact | N1–N5 rating on each finding |
| VDR-EVA-GRV | Group Vulnerabilities | ✓/✓/derived | process-artifact | Grouping/dedup in ledger |
| VDR-FRP-ADV | Sensitive Details | ✓/✓/derived | process-artifact | FedRAMP-actor; out of CSP scope |
| VDR-FRP-ARP | Additional Requirements | ✓/✓/derived | process-artifact | FedRAMP-actor; out of CSP scope |
| VDR-RPT-AVI | Accepted Vulnerability Info | ✓/✓/derived | process-artifact | Report contains 8 AVI fields |
| VDR-RPT-HLO | High-Level Overviews | ✓/✓/derived | process-artifact | VDP/bug-bounty/pentest summaries |
| VDR-RPT-NID | Responsible Disclosure | ✓/✓/derived | process-artifact | Disclosure policy + redaction |
| VDR-RPT-PER | Persistent Reporting | ✓/✓/derived | process-artifact | Cadence + ADS submission record |
| VDR-RPT-RPD | Responsible Public Disclosure | ✓/✓/derived | process-artifact | Public-disclosure decision record |
| VDR-RPT-VDT | Vulnerability Details | ✓/✓/derived | process-artifact | Report contains 11 VDT fields |
| VDR-TFR-EVU | Evaluate Vulnerabilities Quickly | ✓/✓/✓ (7/5/2d) | hybrid | detection→evaluation latency |
| VDR-TFR-IRI | Internet-Reachable Incidents | ✓/✓/✓ | process-artifact | IRV+LEV+N4/N5 → incident bridge |
| VDR-TFR-KEV | Remediate KEVs | ✓/✓/derived | hybrid | KEV CVEs vs CISA due dates |
| VDR-TFR-MAV | Mark Accepted Vulnerabilities | ✓/✓/derived | hybrid | Open >192d → must be "accepted" |
| VDR-TFR-MHR | Monthly Activity Report | ✓/✓/derived | process-artifact | Human-readable monthly report exists |
| VDR-TFR-MRH | Historical Activity | ✓/✓/✓ (mo/14d/7d) | process-artifact | Machine-readable API feed freshness |
| VDR-TFR-NRI | Non-Internet-Reachable Incidents | ✓/✓/✓ | process-artifact | non-IRV+LEV+N5 → incident bridge |
| VDR-TFR-PCD | Persistent Complete Detection | ✓/✓/✓ (6mo/mo/mo) | hybrid | Last-scan age for non-drift resources |
| VDR-TFR-PDD | Persistent Drift Detection | ✓/✓/✓ (mo/14d/7d) | hybrid | Last-scan age for drift-prone resources |
| VDR-TFR-PSD | Persistent Sample Detection | ✓/✓/✓ (7/3/1d) | hybrid | Sample-scan cadence |
| VDR-TFR-PVR | Mitigation/Remediation Expectations | ✓/✓/✓ (PAIN table) | hybrid | open-finding age vs PAIN/IRV/LEV SLA |
| VDR-TFR-RMN | Remaining Vulnerabilities | ✓/✓/derived | process-artifact | Routine-ops remediation evidence |

Testability breakdown: **api-testable 1**, **hybrid 14**, **process-artifact 24**.

---

### VDR-AGM-DRE — Do Not Request Extra Info  [SHOULD NOT]
- **Track / actor / levels:** both / AGM (Agency) / L:✓ M:✓ H:derived(rev5: n/a — agency-side)
- **Requirement (plain English):** Agencies SHOULD NOT ask a Provider for vulnerability info beyond what the FedRAMP process requires unless the agency head (or delegate) determines a demonstrable need. This binds the *Agency* (`Agency` = a federal executive agency consuming the CSO), not the CSP.
- **Testability:** process-artifact
- **Automated validation:** Not satisfiable by the CSP collector — the actor is the Agency. The collector should surface this as an *awareness/inbound-request* item: if the CSP receives an extra-info request, log it as an artifact (ticket/email) so the CSP can confirm the agency attached its own determination. No cloud API proves this.
- **Required permissions & error handling:** None (no cloud call). Tracker-only; nothing to AccessDenied on.
- **Alternative satisfiers:** Process evidence = the agency's documented determination memo attached to any out-of-band request; detectable signal = an entry in the CSP's customer-request ticket queue tagged `vdr-extra-info`.
- **OSCAL / NIST:** controls[]=∅; map awareness to CA-7 (Continuous Monitoring) / PM-? agency program. High derived from Rev5 only nominally — agency-side, n/a.
- **Module connections:** new process-artifact tracker (inbound-request ledger).
- **Recommended implementation:** process-artifact-tracker; agency-actor, CSP only records the request and the agency's determination; effort S.

### VDR-AGM-MAP — Maintain Agency POA&M  [SHOULD]
- **Track / actor / levels:** both / AGM (Agency) / L:✓ M:✓ H:derived(rev5: n/a — agency-side)
- **Requirement (plain English):** Agencies SHOULD fold Provider-reported vulnerability info (esp. `Accepted Vulnerability` = a vuln the Provider won't fully fix, or won't fix within the FedRAMP overdue window) into their own POA&Ms when relevant. Agency obligation.
- **Testability:** process-artifact
- **Automated validation:** Out of CSP scope to *satisfy*. The collector's only contribution is upstream: emit the machine-readable accepted-vulnerability feed (see VDR-RPT-AVI / VDR-TFR-MRH) the agency consumes. Validate by confirming that feed exists and is current, not the agency's POA&M.
- **Required permissions & error handling:** None at the CSP for the agency action; reuse VDR-TFR-MRH feed checks.
- **Alternative satisfiers:** Agency-side GRC (e.g. eMASS POA&M export); detectable signal = none from CSP cloud.
- **OSCAL / NIST:** controls[]=∅; relates to CA-5 (POA&M) on the agency side. High n/a (agency).
- **Module connections:** new process-artifact tracker (cross-reference to VDR-RPT-AVI emitter).
- **Recommended implementation:** process-artifact-tracker; agency consumes CSP output, CSP cannot validate; effort S.

### VDR-AGM-NFR — Notify FedRAMP  [MUST]
- **Track / actor / levels:** both / AGM (Agency) / L:✓ M:✓ H:derived(rev5: n/a — agency-side)
- **Requirement (plain English):** Agencies MUST email info@fedramp.gov after requesting any extra vulnerability info/materials beyond FedRAMP's baseline. Agency obligation; pairs with VDR-AGM-DRE.
- **Testability:** process-artifact
- **Automated validation:** Not CSP-satisfiable. Collector records the CSP-visible half: when an extra-info request arrives, capture it so the CSP can later confirm FedRAMP was copied. No cloud signal.
- **Required permissions & error handling:** None (no cloud call).
- **Alternative satisfiers:** Process evidence = the CSP's copy of the agency's FedRAMP notification; detectable signal = ticket annotation.
- **OSCAL / NIST:** controls[]=∅; agency program-mgmt control (PM). High n/a.
- **Module connections:** new process-artifact tracker (same inbound-request ledger as VDR-AGM-DRE).
- **Recommended implementation:** process-artifact-tracker; agency-actor; effort S.

### VDR-AGM-RVR — Review Vulnerability Reports  [SHOULD]
- **Track / actor / levels:** both / AGM (Agency) / L:✓ M:✓ H:derived(rev5: n/a — agency-side)
- **Requirement (plain English):** Agencies SHOULD review Provider vulnerability reports at intervals matching their ATO risk posture, and SHOULD use automated processing of the machine-readable feed. Agency obligation; depends on the `Potential Adverse Impact` ratings the CSP supplies.
- **Testability:** process-artifact
- **Automated validation:** Out of CSP scope. Collector ensures the *consumable* artifact exists: a machine-readable report (VDR-TFR-MRH) that an agency *can* auto-process. Validate feed presence/freshness/schema, not the agency review.
- **Required permissions & error handling:** None at CSP for the agency review; reuse MRH feed checks.
- **Alternative satisfiers:** Agency automation (SOAR/GRC ingest); detectable signal = none from CSP.
- **OSCAL / NIST:** controls[]=∅; CA-7 on agency side. High n/a.
- **Module connections:** new process-artifact tracker (links to VDR-TFR-MRH emitter).
- **Recommended implementation:** process-artifact-tracker; agency-actor; effort S.

### VDR-BST-ADT — Automate Detection  [SHOULD]
- **Track / actor / levels:** both / BST (Provider) / L:✓ M:✓ H:derived(rev5: RA-5(2) automated update of vuln scanned, RA-5 automation)
- **Requirement (plain English):** Providers SHOULD use automated services to streamline `Vulnerability Detection` (systematic discovery via scanning/threat-intel/VDP/bug-bounty/supply-chain) and `Vulnerability Response`. This is the most directly api-testable VDR item: prove automated scanners are *enabled and running*.
- **Testability:** api-testable
- **Automated validation:** AWS — `inspector2:BatchGetAccountStatus` shows Inspector2 enabled for EC2/ECR/Lambda; `ecr:GetRegistryScanningConfiguration` shows ENHANCED scanning + scanFrequency. GCP — Container Analysis enabled (`serviceusage` shows `containeranalysis.googleapis.com` + `containerscanning.googleapis.com` active) and SCC active. K8s — EKS/GKE node-image scanning via the same registry signal. PASS = at least one automated scanner enabled per running resource class (compute, container images, serverless).
- **Required permissions & error handling:** AWS `inspector2:BatchGetAccountStatus`, `inspector2:ListCoverage`, `ecr:DescribeRegistry`/`ecr:GetRegistryScanningConfiguration` (grant via `AmazonInspector2ReadOnlyAccess` + `AWSReadOnlyAccess`). GCP `serviceusage.services.list`, `containeranalysis.occurrences.list`. On AccessDenied → diagnoseAwsError surfaces the exact action (`inspector2:BatchGetAccountStatus`); on `not_enabled` (OptInRequired / SubscriptionRequiredException) → treat as a real FAIL here (scanner truly off), unlike most collectors where not_enabled is silent.
- **Alternative satisfiers:** Wiz / Prisma Cloud / Orca / Lacework (agentless CSPM+CWPP), Tenable/Qualys (host scanning), Snyk (SCA/container). Detectable via `detect()` IAM-role/SA name signatures (`wiz-*`, `lacework`, `snyk`, plus new `prisma`/`orca`/`tenable`/`qualys` rules). Process evidence = scanner SaaS config export.
- **OSCAL / NIST:** controls[]=∅ → assign RA-5, RA-5(2). High DERIVED from Rev5 High baseline via these controls.
- **Module connections:** extend `providers/aws/supplychain.ts` + `providers/gcp/supplychain.ts` (already host CMT-VTD/SCR-MON) with a new VDR scanner-enablement collector; add detector rules in `core/detect/third-party-tools.ts`.
- **Recommended implementation:** collector; scanner enablement is a pure list/describe check; effort M.

### VDR-BST-AKE — Avoid KEVs  [SHOULD NOT]
- **Track / actor / levels:** both / BST (Provider) / L:✓ M:✓ H:derived(rev5: SI-2, RA-5)
- **Requirement (plain English):** Providers SHOULD NOT deploy/activate **new** `Machine-Based` `Information Resource`s carrying a `Known Exploited Vulnerability` (KEV = any CVE in CISA's KEV catalog per BOD 22-01). Tests freshly-deployed images/instances against the KEV list.
- **Testability:** hybrid
- **Automated validation:** Pull the latest scan findings for recently-deployed resources (ECR images pushed in window, EC2 launched in window, Lambda updated) via Inspector2 `ListFindings` (filter on KEV / `fixAvailable`) and GCP `containeranalysis occurrences.list`. Cross-reference each CVE against the CISA KEV feed `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. PASS = no resource created/changed in the lookback window has an open KEV-listed CVE. "New" inferred from resource creation/push timestamps.
- **Required permissions & error handling:** AWS `inspector2:ListFindings`, `ecr:DescribeImages` (pushedAt), `ec2:DescribeInstances` (launchTime), `lambda:ListFunctions` (lastModified). GCP `containeranalysis.occurrences.list`, `artifactregistry.repositories.list`. KEV feed is an unauthenticated HTTPS GET — wrap in retry; on fetch failure record a `missing_evidence` warning (don't silently pass). AccessDenied on ListFindings → grant `AmazonInspector2ReadOnlyAccess`.
- **Alternative satisfiers:** Admission controllers blocking KEV images (Kyverno/OPA Gatekeeper policy, GKE Binary Authorization, ECR pull-through+scan-on-push gate); Wiz/Prisma KEV-aware deploy policy. Detectable: GKE BinAuthz policy via `binaryauthorization.policy.get`; admission-webhook config via K8s `get validatingwebhookconfigurations`. Process evidence = CI/CD KEV gate logs.
- **OSCAL / NIST:** controls[]=∅ → SI-2, RA-5. High DERIVED via SI-2/RA-5 Rev5 High.
- **Module connections:** extend `supplychain.ts` (new KEV cross-reference helper in `core/`, e.g. `core/kev-feed.ts`); reuse `inventory.ts` for creation timestamps.
- **Recommended implementation:** hybrid; collector flags open KEVs on new resources, tracker confirms the deploy-gate policy; effort M.

### VDR-BST-DAC — Detect After Changes  [SHOULD]
- **Track / actor / levels:** both / BST (Provider) / L:✓ M:✓ H:derived(rev5: RA-5, SI-2, CM-3)
- **Requirement (plain English):** Providers SHOULD automatically run `Vulnerability Detection` on representative samples of new or significantly changed `Information Resource`s. Ties detection to the change pipeline.
- **Testability:** hybrid
- **Automated validation:** Confirm scan-on-push is configured: AWS `ecr:GetRegistryScanningConfiguration` scanFrequency=`SCAN_ON_PUSH` (or CONTINUOUS_SCAN); GCP Artifact Analysis automatic scanning enabled. Cross-check that recently-pushed images actually have a scan occurrence with `scanCompletedAt` close to push time (proves it fires on change). PASS = scan-on-push enabled AND recent pushes show post-push scans.
- **Required permissions & error handling:** AWS `ecr:GetRegistryScanningConfiguration`, `ecr:DescribeImages`, `inspector2:ListCoverage`. GCP `containeranalysis.occurrences.list`, `artifactregistry.dockerimages.list`. On `not_enabled` (scan-on-push off) → FAIL with remediation to enable enhanced scanning. AccessDenied → surface exact ECR action.
- **Alternative satisfiers:** CI/CD scan stage (GitHub Actions/GitLab CI running Trivy/Grype/Snyk before deploy — detect OIDC provider + pipeline config); Wiz/Prisma change-triggered scan. Process evidence = pipeline YAML showing the scan gate.
- **OSCAL / NIST:** controls[]=∅ → RA-5, SI-2, CM-3. High DERIVED via Rev5 High.
- **Module connections:** extend `supplychain.ts` (shares scanner-config calls with VDR-BST-ADT); CI/CD detection via `core/detect/third-party-tools.ts`.
- **Recommended implementation:** hybrid; collector proves scan-on-push, tracker covers the CI/CD path; effort M.

### VDR-BST-DFR — Design For Resilience  [SHOULD]
- **Track / actor / levels:** both / BST (Provider) / L:✓ M:✓ H:derived(rev5: SA-8, SC-7, CM-6)
- **Requirement (plain English):** Providers SHOULD make architecture/design choices that mitigate vulnerability risk by default and reduce the cost/complexity of detection and response (immutable infra, minimal images, network segmentation, managed services). A design philosophy, not a control.
- **Testability:** process-artifact
- **Automated validation:** No single PASS condition. Collector can supply *supporting indicators* an assessor reads as resilience: immutable infra (ECR image tag immutability `imageTagMutability=IMMUTABLE`, ASG/launch-template usage), minimal base images (distroless detection via image metadata), segmentation (already in `network.ts`), managed-service share. Emit these as observations; final judgment is human attestation.
- **Required permissions & error handling:** AWS `ecr:DescribeRepositories` (imageTagMutability), `autoscaling:DescribeAutoScalingGroups`, reuse network.ts perms. GCP `artifactregistry.repositories.list`. Read-only; AccessDenied → surface action; absence of a signal is informational, not FAIL.
- **Alternative satisfiers:** Architecture decision records (ADRs), well-architected review output; detectable signal = immutable-tag + managed-service ratios only.
- **OSCAL / NIST:** controls[]=∅ → SA-8 (security engineering), SC-7, CM-6. High DERIVED via Rev5 High.
- **Module connections:** new process-artifact tracker, augmented by indicators from `supplychain.ts`/`network.ts`.
- **Recommended implementation:** process-artifact-tracker; design intent isn't API-provable, collector only supplies hints; effort M.

### VDR-BST-MSP — Maintain Security  [SHOULD NOT]
- **Track / actor / levels:** both / BST (Provider) / L:✓ M:✓ H:derived(rev5: CM-6, RA-5, SC-7)
- **Requirement (plain English):** Providers SHOULD NOT weaken `Information Resource` security merely to enable scanning/detection (e.g. opening firewalls for an external scanner, disabling auth for an agent). A negative requirement — prove the *absence* of security degradation done for scanning.
- **Testability:** process-artifact
- **Automated validation:** Negative requirements are hard to prove true. Collector supplies a heuristic counter-signal: detect scanner-related weakening — overly broad ingress rules referencing scanner IP ranges, scanner principals with excessive IAM, disabled controls correlated to scanner SAs. Absence of these is supporting evidence; the affirmative claim is a CSP attestation.
- **Required permissions & error handling:** Reuse `network.ts` (`ec2:DescribeSecurityGroups`) + `iam` describes for scanner-principal privilege. Read-only; nothing special on errors beyond standard diagnostics.
- **Alternative satisfiers:** Agentless scanning (Wiz/Orca side-scanning — needs no inbound holes) is itself the strongest evidence of compliance; detectable via scanner role + zero scanner-specific ingress. Process evidence = scanner-access design doc.
- **OSCAL / NIST:** controls[]=∅ → CM-6, RA-5, SC-7. High DERIVED via Rev5 High.
- **Module connections:** new process-artifact tracker + heuristic from `network.ts`/`iam.ts`.
- **Recommended implementation:** process-artifact-tracker; negative attestation with collector counter-signals; effort M.

### VDR-BST-SIR — Sampling  [MAY]
- **Track / actor / levels:** both / BST (Provider) / L:✓ M:✓ H:derived(rev5: RA-5)
- **Requirement (plain English):** Providers MAY sample effectively-identical `Information Resource`s (especially `Machine-Based`) during detection, UNLESS sampling would reduce detection efficiency/effectiveness. Permissive — establishes the legitimacy of sampling that VDR-TFR-PSD then times.
- **Testability:** process-artifact
- **Automated validation:** A MAY with an UNLESS caveat — not a pass/fail control. Collector can describe the *fleet homogeneity* that justifies sampling: group instances by AMI/launch-template/instance-profile, images by digest, to show "effectively identical" cohorts. The sampling *methodology* (which representative is scanned) is a documented decision the tracker stores.
- **Required permissions & error handling:** AWS `ec2:DescribeInstances` (ImageId, LaunchTemplate), `ecr:DescribeImages` (digests). GCP `compute.instances.list`. Read-only; standard diagnostics.
- **Alternative satisfiers:** Scanner-native sampling config (e.g. Inspector coverage by tag). Process evidence = sampling methodology document.
- **OSCAL / NIST:** controls[]=∅ → RA-5. High DERIVED via Rev5 High.
- **Module connections:** new process-artifact tracker, fleet-grouping helper reused from `inventory.ts`.
- **Recommended implementation:** process-artifact-tracker; MAY + methodology doc; collector only supplies cohort grouping; effort S.

### VDR-CSO-DET — Vulnerability Detection  [MUST]
- **Track / actor / levels:** both / CSO (Provider) / L:✓ M:✓ H:derived(rev5: RA-5, RA-5(2), SI-5, SR-6)
- **Requirement (plain English):** Providers MUST `Persistently` (firm, steady, repeated, status always known) and `Promptly` (without unnecessary delay) discover/identify `Vulnerabilit`ies across the whole CSO using appropriate techniques — assessment, scanning, threat intel, VDP, bug bounty, supply-chain monitoring. The umbrella MUST for the whole detection process.
- **Testability:** hybrid
- **Automated validation:** Prove *coverage breadth*: enumerate running resource classes (compute, containers, serverless, registries) via `inventory.ts`, then confirm each has an enabled detection mechanism (Inspector2 coverage per resource, Artifact Analysis per repo, SCC). Compute a coverage ratio (scanned resources / total in-scope resources). PASS = ≥ near-complete coverage AND at least one technique per technique-class the CSO uses. The "VDP/bug-bounty/threat-intel" arms are process-artifact (existence of a VDP page, HackerOne/Bugcrowd program, threat-intel feed).
- **Required permissions & error handling:** AWS `inspector2:ListCoverage`, `inspector2:BatchGetAccountStatus`, plus inventory perms. GCP `containeranalysis.occurrences.list`, `securitycenter.findings.list`, `serviceusage.services.list`. Uncovered resource = FAIL (gap). AccessDenied on ListCoverage → grant `AmazonInspector2ReadOnlyAccess`; SCC AccessDenied → grant `roles/securitycenter.findingsViewer`.
- **Alternative satisfiers:** Wiz/Prisma/Orca/Lacework (full-stack coverage), Tenable/Qualys (host), Snyk (code/SCA); VDP via security.txt / HackerOne / Bugcrowd program page; threat-intel via Recorded Future/Mandiant. Detect cloud scanners by IAM role/SA; VDP/bug-bounty are process artifacts.
- **OSCAL / NIST:** controls[]=∅ → RA-5, RA-5(2), SI-5, SR-6 (supply-chain). High DERIVED via Rev5 High.
- **Module connections:** extend `supplychain.ts` (coverage rollup) + `inventory.ts`; VDP/bug-bounty in process-artifact tracker.
- **Recommended implementation:** hybrid; collector proves scanner coverage, tracker covers VDP/bug-bounty/threat-intel arms; effort L.

### VDR-CSO-DOC — Documentation for Recommendations  [MUST]
- **Track / actor / levels:** both / CSO (Provider) / L:✓ M:✓ H:derived(rev5: PL-2, CA-1)
- **Requirement (plain English):** When a Provider chooses NOT to meet a FedRAMP *recommendation* (a SHOULD) in this process, it MUST document the reason and customer implications, and include that in the CSO's `Authorization data`. A documentation MUST tied to every SHOULD the CSP declines.
- **Testability:** process-artifact
- **Automated validation:** Not cloud-testable. The collector's contribution: for each VDR SHOULD that fails its automated check (e.g. scan-on-push off, KEV present), auto-generate a "recommendation-not-met" stub the CSP must annotate with rationale, and verify a rationale entry exists in the authorization-data store before marking the SHOULD as accepted-deviation. Track completeness = every failed SHOULD has a linked rationale.
- **Required permissions & error handling:** None cloud; tracker reads the authorization-data repo / Paramify. No AccessDenied path.
- **Alternative satisfiers:** Paramify / OSCAL SSP narrative entries (detectable: Paramify already in `detect()`); process evidence = the deviation register.
- **OSCAL / NIST:** controls[]=∅ → PL-2, CA-1. High DERIVED nominally; this is a documentation control.
- **Module connections:** new process-artifact tracker, fed by failed-SHOULD list from all VDR collectors; ties to `core/paramify-push.ts`.
- **Recommended implementation:** process-artifact-tracker; collector auto-stubs deviations, human writes rationale; effort M.

### VDR-CSO-RES — Vulnerability Response  [MUST]
- **Track / actor / levels:** both / CSO (Provider) / L:✓ M:✓ H:derived(rev5: SI-2, RA-5, CA-7, IR-4)
- **Requirement (plain English):** Providers MUST `Persistently`/`Promptly` track, evaluate, monitor, mitigate, remediate, assess-exploitation-of, report, and otherwise manage **all** detected `Vulnerabilit`ies (`Vulnerability Response`). The umbrella MUST for the response lifecycle.
- **Testability:** hybrid
- **Automated validation:** The collector builds the *findings ledger* from scanner output (Inspector2/ECR/Artifact Analysis/SCC) — one record per detected vuln with lifecycle state (detected→evaluated→mitigated→remediated→accepted). PASS = every detected finding has a tracked disposition and no finding sits in "detected, never evaluated." The ledger is the spine VDR-EVA/VDR-TFR requirements measure against. The *tracking/ticketing* link (each finding → Jira/ServiceNow) is process-artifact via `core/ticket-push.ts`.
- **Required permissions & error handling:** AWS `inspector2:ListFindings` (all states incl. SUPPRESSED). GCP `containeranalysis.occurrences.list`, `securitycenter.findings.list`. AccessDenied → grant Inspector2/SCC read role. Empty findings with scanner enabled = legitimately clean (note, not FAIL); scanner disabled = FAIL (can't respond to what you don't detect).
- **Alternative satisfiers:** Wiz/Prisma issue lifecycle, DefectDojo/vuln-mgmt platform, ticketing integration (Jira/ServiceNow detected via webhook/role). Process evidence = ledger export with state transitions.
- **OSCAL / NIST:** controls[]=∅ → SI-2, RA-5, CA-7, IR-4. High DERIVED via Rev5 High.
- **Module connections:** new `core/vdr-ledger.ts` (normalizes findings across scanners) fed by `supplychain.ts`; pushes via `core/ticket-push.ts`.
- **Recommended implementation:** hybrid; collector builds ledger, tracker proves ticket/lifecycle workflow; effort L.

### VDR-EVA-EFA — Evaluation Factors  [SHOULD]
- **Track / actor / levels:** both / EVA (Provider) / L:✓ M:✓ H:derived(rev5: RA-3, RA-5)
- **Requirement (plain English):** When evaluating detected vulns in CSO context, Providers SHOULD consider ≥8 named factors: Criticality, Reachability, Exploitability, Detectability, Prevalence, Privilege, Proximate Vulnerabilities, Known Threats. Defines the evaluation rubric used by the other VDR-EVA items.
- **Testability:** process-artifact
- **Automated validation:** Not a pass/fail cloud control — it's a rubric. Collector validates that the *evaluation schema* in the ledger carries fields for all 8 factors (so each finding's evaluation can record them) and can auto-populate several: Reachability (from `network.ts` exposure), Exploitability (from KEV/EPSS), Prevalence (count of affected resources), Privilege (IAM scope of affected resource). Criticality/Known Threats/Proximate remain analyst-entered. PASS = schema complete + auto-factors populated.
- **Required permissions & error handling:** Reuse network.ts/iam.ts/inventory.ts perms for auto-factors; KEV/EPSS feeds over HTTPS. No new AccessDenied paths beyond those collectors.
- **Alternative satisfiers:** Wiz/Prisma contextual risk scoring (toxic combinations), CVSS+EPSS+reachability engines; detectable via scanner presence. Process evidence = evaluation rubric doc.
- **OSCAL / NIST:** controls[]=∅ → RA-3 (risk assessment), RA-5. High DERIVED via Rev5 High.
- **Module connections:** schema fields in `core/vdr-ledger.ts`; auto-factor enrichment from `network.ts`/`iam.ts`.
- **Recommended implementation:** hybrid (lean process-artifact); collector enriches factors, analyst completes; effort M.

### VDR-EVA-EFP — Evaluate False Positives  [SHOULD]
- **Track / actor / levels:** both / EVA (Provider) / L:✓ M:✓ H:derived(rev5: RA-5, RA-5(?))
- **Requirement (plain English):** Providers SHOULD evaluate detected vulns in CSO context to determine `False Positive Vulnerabilit`ies (vuln not actually exploitable — e.g. vulnerable code present but not loaded/running). Distinguishes real from spurious findings.
- **Testability:** hybrid
- **Automated validation:** Scanners expose FP/suppression state. Inspector2 `ListFindingAggregations` / suppression rules; ECR/Inspector findings have `status` SUPPRESSED with a suppression rule reason. GCP occurrences can be marked. PASS-supporting = every suppressed finding has a documented suppression *reason* (not blanket suppression). The judgment of *whether* it's truly FP is analyst work; collector proves suppressions are reasoned and inventoried.
- **Required permissions & error handling:** AWS `inspector2:ListFindings` (status filter), `inspector2:ListFilters` (suppression rules), `inspector2:GetFindingsReportStatus`. GCP `containeranalysis.occurrences.list`. AccessDenied on ListFilters → grant `inspector2:ListFilters`. Suppression with empty reason → flag as gap.
- **Alternative satisfiers:** Wiz/Prisma/DefectDojo FP-disposition workflow with audit trail; detectable via scanner. Process evidence = FP-disposition log.
- **OSCAL / NIST:** controls[]=∅ → RA-5. High DERIVED via Rev5 High.
- **Module connections:** `core/vdr-ledger.ts` (suppression-reason completeness) reading `supplychain.ts` finding states.
- **Recommended implementation:** hybrid; collector inventories suppressions+reasons, analyst owns FP calls; effort M.

### VDR-EVA-EIR — Evaluate Internet-Reachability  [MUST]
- **Track / actor / levels:** both / EVA (Provider) / L:✓ M:✓ H:derived(rev5: RA-5, SC-7, CA-3)
- **Requirement (plain English):** Providers MUST evaluate each detected vuln to decide if it's an `Internet-Reachable Vulnerability` (IRV = on a `Machine-Based` resource that could be triggered by a payload originating from the public internet, including indirect/relayed triggers). A MUST classification driving the VDR-TFR SLAs.
- **Testability:** hybrid
- **Automated validation:** Internet-reachability is *derivable* from cloud topology — a strong collector play. For each affected resource: public IP (`ec2:DescribeInstances` association), security-group ingress 0.0.0.0/0, ALB/NLB front (`elbv2`), public ECR/registry, API Gateway/CloudFront exposure, GCP external IP + firewall + LB. Compute an IRV flag per finding by joining the vuln's resource to its network exposure (already partly in `network.ts`). PASS = every finding carries a computed IRV flag; gaps = findings whose resource exposure couldn't be determined.
- **Required permissions & error handling:** AWS `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `elbv2:DescribeLoadBalancers`/`DescribeTargetGroups`, `apigateway:GET`, `cloudfront:ListDistributions`. GCP `compute.instances.list`, `compute.firewalls.list`, `compute.forwardingRules.list`. AccessDenied → surface exact action; undetermined exposure → conservative IRV=true + warning, never silently drop.
- **Alternative satisfiers:** Wiz/Orca attack-path/exposure analysis (network reachability graph) — the gold standard; detectable via scanner role. Process evidence = exposure-analysis export.
- **OSCAL / NIST:** controls[]=∅ → RA-5, SC-7, CA-3. High DERIVED via Rev5 High.
- **Module connections:** new IRV-derivation helper joining `core/vdr-ledger.ts` findings to `network.ts` exposure facts.
- **Recommended implementation:** hybrid; topology-derivable so collector does most of it; effort L.

### VDR-EVA-ELX — Evaluate Exploitability  [MUST]
- **Track / actor / levels:** both / EVA (Provider) / L:✓ M:✓ H:derived(rev5: RA-5, RA-3)
- **Requirement (plain English):** Providers MUST evaluate each detected vuln to decide if it's a `Likely Exploitable Vulnerability` (LEV = not fully mitigated AND reachable by a likely threat actor AND a knowledgeable likely actor could likely gain unauthorized access/cause harm). `Likely` = reasonable probability based on context. MUST classification feeding VDR-TFR SLAs and incident bridges.
- **Testability:** hybrid
- **Automated validation:** Derive LEV signals: KEV membership (CISA feed = actively exploited ⇒ strong LEV), EPSS score (FIRST EPSS API, exploitation probability), exploit-availability (`fixAvailable`/`exploitAvailable` flags in Inspector findings), plus the IRV reachability from VDR-EVA-EIR. PASS = every non-fully-mitigated finding carries an LEV determination with its supporting signals; final "likely threat actor" judgment is analyst-reviewable but auto-seeded.
- **Required permissions & error handling:** AWS `inspector2:ListFindings` (exploitAvailable/fixAvailable fields). GCP occurrences. KEV + EPSS over HTTPS (retry; feed failure → missing_evidence, not pass). AccessDenied → Inspector2 read role.
- **Alternative satisfiers:** Wiz/Prisma exploitability scoring (EPSS+KEV+reachability fused), VulnCheck/Tenable VPR. Detectable via scanner; process evidence = exploitability rubric.
- **OSCAL / NIST:** controls[]=∅ → RA-5, RA-3. High DERIVED via Rev5 High.
- **Module connections:** `core/vdr-ledger.ts` LEV enrichment; shares KEV feed with VDR-TFR-KEV, reachability with VDR-EVA-EIR.
- **Recommended implementation:** hybrid; auto-seed LEV from KEV/EPSS/reachability, analyst confirms; effort L.

### VDR-EVA-EPA — Estimate Potential Adverse Impact  [MUST]
- **Track / actor / levels:** both / EVA (Provider) / L:✓ M:✓ H:derived(rev5: RA-3, RA-2)
- **Requirement (plain English):** Providers MUST evaluate each detected vuln and assign a `Potential Adverse Impact` (PAIN) rating N1–N5 estimating cumulative harm to agency customers: N1 negligible, N2 limited, N3 serious(1 agency), N4 catastrophic(1)/serious(>1), N5 catastrophic(>1). MUST that drives both PVR remediation SLAs and the incident bridges.
- **Testability:** process-artifact
- **Automated validation:** The N1–N5 rating fuses data-classification + blast-radius + customer-multiplicity — inherently a Provider judgment, not API-derivable. Collector enforces *completeness*: every finding in the ledger must carry an N-rating before it's considered evaluated; surface inputs (count of affected resources = prevalence, whether resource holds `Federal Customer Data`, number of agency tenants) to seed the analyst. PASS = no evaluated finding lacks an N-rating.
- **Required permissions & error handling:** Inputs from `inventory.ts`/`data.ts` (data classification tags), tenant count from CSP metadata. No new cloud call mandatory; the rating itself is entered, not fetched.
- **Alternative satisfiers:** Wiz/Prisma business-impact scoring with crown-jewel tagging; process evidence = the impact-rating rubric + per-finding N-rating ledger.
- **OSCAL / NIST:** controls[]=∅ → RA-3, RA-2 (impact categorization). High DERIVED via Rev5 High.
- **Module connections:** `core/vdr-ledger.ts` (N-rating field + completeness check); seed inputs from `data.ts`/`inventory.ts`.
- **Recommended implementation:** process-artifact-tracker (collector enforces completeness); rating is human judgment; effort M.

### VDR-EVA-GRV — Group Vulnerabilities  [SHOULD]
- **Track / actor / levels:** both / EVA (Provider) / L:✓ M:✓ H:derived(rev5: RA-5)
- **Requirement (plain English):** Providers SHOULD group detected vulns by logical clusters of affected `Information Resource`s to make response more efficient; subsequent VDR requirements then apply to the *group* rather than each instance. An efficiency mechanism for the ledger.
- **Testability:** process-artifact
- **Automated validation:** Collector can *propose* groupings (dedup by CVE across identical images/AMIs, cluster by shared base layer, by instance-profile cohort) — directly reusing the fleet-homogeneity grouping from VDR-BST-SIR. PASS-supporting = ledger supports a group entity and findings are deduped (e.g. one CVE across 200 identical pods = one group). Whether the grouping is *appropriate* is the analyst's SHOULD.
- **Required permissions & error handling:** Reuse `inventory.ts` cohort grouping + ECR digest grouping. Read-only; standard diagnostics.
- **Alternative satisfiers:** Wiz/Prisma issue-grouping by image/package; DefectDojo finding-grouping. Detectable via scanner; process evidence = grouping rationale.
- **OSCAL / NIST:** controls[]=∅ → RA-5. High DERIVED via Rev5 High.
- **Module connections:** `core/vdr-ledger.ts` group entity; grouping helper shared with VDR-BST-SIR.
- **Recommended implementation:** hybrid (collector proposes groups); SHOULD with analyst sign-off; effort M.

### VDR-FRP-ADV — Sensitive Details  [MAY]
- **Track / actor / levels:** both / FRP (FedRAMP) / L:✓ M:✓ H:derived(rev5: n/a — FedRAMP-side)
- **Requirement (plain English):** FedRAMP MAY require Providers to share extra/sensitive vulnerability detail (including info that would `Likely` lead to exploitation) for review/response/investigation by necessary parties. The actor is *FedRAMP*; the CSP's obligation is only to comply if asked.
- **Testability:** process-artifact
- **Automated validation:** Not CSP-satisfiable as a control. Collector ensures the *capability* exists: the CSP can export detailed (sensitive) findings on demand (the full ledger incl. fields normally redacted under VDR-RPT-NID). Validate that a secure-export path and an access-controlled sensitive-detail store exist; the actual sharing is event-driven.
- **Required permissions & error handling:** None routinely; export uses the ledger already built. No AccessDenied path.
- **Alternative satisfiers:** Secure data-room / ADS submission channel; process evidence = a record that sensitive detail was shared when FedRAMP requested.
- **OSCAL / NIST:** controls[]=∅; FedRAMP-program. High n/a.
- **Module connections:** process-artifact tracker (sensitive-export capability check on `core/vdr-ledger.ts`).
- **Recommended implementation:** process-artifact-tracker; FedRAMP-actor, CSP proves capability only; effort S.

### VDR-FRP-ARP — Additional Requirements  [MAY]
- **Track / actor / levels:** both / FRP (FedRAMP) / L:✓ M:✓ H:derived(rev5: n/a — FedRAMP-side)
- **Requirement (plain English):** FedRAMP MAY require extra vuln info, alternative reports, or alternative reporting frequency as a condition of a Corrective Action Plan or agency agreement. FedRAMP-actor; CSP complies if directed.
- **Testability:** process-artifact
- **Automated validation:** Not CSP-satisfiable. Collector ensures reporting is *parameterizable*: report frequency/format are config-driven (so an alternative cadence per VDR-FRP-ARP can be honored) and any CAP-driven requirements are tracked. Validate config flexibility + CAP register, not the FedRAMP directive itself.
- **Required permissions & error handling:** None cloud. Tracker-only.
- **Alternative satisfiers:** Configurable reporting pipeline; process evidence = the CAP and the adjusted report cadence record.
- **OSCAL / NIST:** controls[]=∅; FedRAMP-program. High n/a.
- **Module connections:** process-artifact tracker (CAP register) + reporting-config flags shared with VDR-RPT-PER/VDR-TFR-MHR.
- **Recommended implementation:** process-artifact-tracker; FedRAMP-actor; effort S.

### VDR-RPT-AVI — Accepted Vulnerability Info  [MUST]
- **Track / actor / levels:** both / RPT (Provider) / L:✓ M:✓ H:derived(rev5: CA-5, PM-4, RA-5)
- **Requirement (plain English):** When reporting, Providers MUST include 8 fields for each `Accepted Vulnerability`: (1) internal tracking ID, (2) time+source of detection, (3) time of completed evaluation, (4) IRV yes/no, (5) LEV yes/no, (6) current PAIN, (7) explanation of why accepted, (8) supplementary risk info for agencies. A schema-completeness MUST on the accepted-vuln slice of the report.
- **Testability:** process-artifact
- **Automated validation:** Schema-completeness check on the generated report. Collector auto-fills fields 1–6 from the ledger (tracking ID, detection time/source from scanner, evaluation time, IRV/LEV/PAIN from VDR-EVA enrichment); fields 7–8 (acceptance rationale, supplementary info) are analyst text. PASS = every accepted-vuln report row has all 8 fields populated and non-empty. The collector both *produces* and *validates* the report.
- **Required permissions & error handling:** Reads ledger only; no new cloud call. Missing field → block report emission with a clear which-finding/which-field error.
- **Alternative satisfiers:** Wiz/DefectDojo "risk accepted" records with required metadata; process evidence = the AVI report section.
- **OSCAL / NIST:** controls[]=∅ → CA-5 (POA&M), PM-4, RA-5. High DERIVED via Rev5 High.
- **Module connections:** new `core/vdr-report.ts` (report builder + field-completeness validator) over `core/vdr-ledger.ts`.
- **Recommended implementation:** hybrid; collector auto-fills 6/8 fields + validates completeness, analyst writes rationale; effort M.

### VDR-RPT-HLO — High-Level Overviews  [SHOULD]
- **Track / actor / levels:** both / RPT (Provider) / L:✓ M:✓ H:derived(rev5: CA-7, RA-5)
- **Requirement (plain English):** Reports SHOULD include high-level overviews of **all** detection/response activity in the period — VDP programs, bug bounty, pentests, assessments, etc. Narrative coverage of activity, including the non-cloud detection arms.
- **Testability:** process-artifact
- **Automated validation:** Collector auto-summarizes the cloud-native half (scans run, findings opened/closed, KEVs handled, counts by PAIN) into the overview. The VDP/bug-bounty/pentest/assessment arms are external — collector verifies their *summaries are present* (a VDP section, a bug-bounty stats section, a pentest-date entry exist and are non-empty). PASS = overview includes both the auto cloud summary and non-empty sections for each declared program.
- **Required permissions & error handling:** Reads ledger for cloud summary; HackerOne/Bugcrowd stats are external attestations. No new cloud call.
- **Alternative satisfiers:** HackerOne/Bugcrowd program dashboards (API stats), pentest vendor reports; detectable signal = configured program identifiers; process evidence = the report overview section.
- **OSCAL / NIST:** controls[]=∅ → CA-7, RA-5. High DERIVED via Rev5 High.
- **Module connections:** `core/vdr-report.ts` (auto cloud summary + presence checks for external sections).
- **Recommended implementation:** hybrid; collector writes cloud summary, tracker holds program summaries; effort M.

### VDR-RPT-NID — Responsible Disclosure  [MUST NOT]
- **Track / actor / levels:** both / RPT (Provider) / L:✓ M:✓ H:derived(rev5: SI-5, RA-5(5))
- **Requirement (plain English):** Providers MUST NOT irresponsibly disclose sensitive vuln detail that would `Likely` lead to exploitation, but MUST disclose enough for `All Necessary Parties` (always FedRAMP + agency customers, sometimes more) to make informed risk decisions. A redaction discipline on the reports.
- **Testability:** process-artifact
- **Automated validation:** Negative + judgment requirement. Collector enforces a *redaction policy on the report generator*: sensitive fields (exploit PoC, exact exploit path) are excluded from the standard report and only present in the sensitive-export (VDR-FRP-ADV) path; the standard report still carries IRV/LEV/PAIN/disposition for decision-making. PASS-supporting = report generator applies the redaction profile and the recipient list maps to All Necessary Parties. The "irresponsible" judgment is policy.
- **Required permissions & error handling:** Reads ledger; recipient list from config. No cloud call.
- **Alternative satisfiers:** Tiered-disclosure workflow in GRC; process evidence = disclosure policy + redaction profile.
- **OSCAL / NIST:** controls[]=∅ → SI-5, RA-5(5). High DERIVED via Rev5 High.
- **Module connections:** `core/vdr-report.ts` redaction profile; pairs with VDR-FRP-ADV sensitive export.
- **Recommended implementation:** process-artifact-tracker (collector applies redaction profile); judgment is policy; effort M.

### VDR-RPT-PER — Persistent Reporting  [MUST]
- **Track / actor / levels:** both / RPT (Provider) / L:✓ M:✓ H:derived(rev5: CA-7, PM-31)
- **Requirement (plain English):** Providers MUST `Persistently` report detection/response activity to `All Necessary Parties`, each report summarizing **all** activity since the previous one; these reports are `Authorization data` subject to the FedRAMP ADS process. A cadence + completeness + delivery MUST.
- **Testability:** process-artifact
- **Automated validation:** Collector can drive the cadence (already runs on a GitHub Actions schedule; `diff-report.ts` produces since-last-run deltas) and prove *delivery*: a record that each report was submitted to the ADS channel / Trust Center. PASS = report generated each period with non-overlapping/no-gap coverage windows AND a delivery receipt per necessary party. Persistence is provable from the run history.
- **Required permissions & error handling:** Reads ledger + prior-run snapshot (`previous-run-snapshot.json`); delivery via existing push adapters. Delivery failure → recorded, surfaced, retried (push retry already exists).
- **Alternative satisfiers:** Trust Center / Vanta/Drata continuous reporting; detectable (Vanta/Drata in `detect()`); process evidence = ADS submission receipts.
- **OSCAL / NIST:** controls[]=∅ → CA-7, PM-31. High DERIVED via Rev5 High.
- **Module connections:** `core/vdr-report.ts` + `core/diff-report.ts` (delta) + push adapters (`paramify-push.ts`/`tracker-push.ts`); scheduled workflow drives cadence.
- **Recommended implementation:** hybrid; collector generates+delivers on schedule, human confirms ADS receipt; effort M.

### VDR-RPT-RPD — Responsible Public Disclosure  [MAY]
- **Track / actor / levels:** both / RPT (Provider) / L:✓ M:✓ H:derived(rev5: SI-5)
- **Requirement (plain English):** Providers MAY publicly disclose vulns (or share with other parties) if they determine doing so will NOT `Likely` lead to exploitation. Permissive; gated by a Provider judgment.
- **Testability:** process-artifact
- **Automated validation:** MAY + judgment — not a pass/fail control. Collector records public-disclosure events (CVE advisories published, security bulletins) and confirms each has a logged "not-likely-to-lead-to-exploitation" determination. No cloud signal; tracker captures the decision record.
- **Required permissions & error handling:** None cloud. Tracker-only.
- **Alternative satisfiers:** CVE Numbering Authority workflow, public security advisory page; process evidence = disclosure-decision log.
- **OSCAL / NIST:** controls[]=∅ → SI-5. High DERIVED via Rev5 High.
- **Module connections:** process-artifact tracker (disclosure-decision register).
- **Recommended implementation:** process-artifact-tracker; MAY with decision log; effort S.

### VDR-RPT-VDT — Vulnerability Details  [MUST]
- **Track / actor / levels:** both / RPT (Provider) / L:✓ M:✓ H:derived(rev5: CA-7, RA-5, PM-4)
- **Requirement (plain English):** For each detected vuln (UNLESS it's an `Accepted Vulnerability`, which uses VDR-RPT-AVI), reports MUST include 11 fields (if applicable): tracking ID; detection time+source; evaluation time; IRV?; LEV?; historical+current PAIN; time+level of each completed PAIN reduction; estimated time+target of next reduction; whether it is/will become `Overdue`; supplementary risk info; final disposition. The richest schema-completeness MUST.
- **Testability:** process-artifact
- **Automated validation:** Schema-completeness over the active-vuln report rows. Collector auto-fills tracking ID, detection time/source, evaluation time, IRV/LEV (from VDR-EVA), current+historical PAIN (from ledger state history), overdue prediction (from VDR-TFR-PVR SLA math — open age vs PAIN/IRV/LEV timeframe), disposition (from finding state). Analyst supplies next-reduction estimate + supplementary info. PASS = each non-accepted finding row has all applicable fields; the collector flags any "applicable but empty."
- **Required permissions & error handling:** Reads ledger w/ state-transition history; no new cloud call. Missing applicable field → block emission with per-finding/per-field error.
- **Alternative satisfiers:** Wiz/Prisma/DefectDojo finding export mapped to the 11 fields; process evidence = the VDT report section.
- **OSCAL / NIST:** controls[]=∅ → CA-7, RA-5, PM-4. High DERIVED via Rev5 High.
- **Module connections:** `core/vdr-report.ts` (11-field validator) over `core/vdr-ledger.ts` with state history; overdue calc shared with VDR-TFR-PVR.
- **Recommended implementation:** hybrid; collector auto-fills most fields + validates, analyst completes 2; effort M.

### VDR-TFR-EVU — Evaluate Vulnerabilities Quickly  [SHOULD]
- **Track / actor / levels:** both / TFR (Provider) / L:✓ M:✓ **H:✓ (20x-published)** — L 7d / M 5d / H 2d
- **Requirement (plain English):** Providers SHOULD complete VDR-EVA evaluation of **all** vulns within 7 days (Low) / 5 days (Moderate) / 2 days (High) of detection. A latency SLA on detection→evaluation. (This `VDR-TFR-*` item publishes explicit High, so High is NOT derived.)
- **Testability:** hybrid
- **Automated validation:** Compute per-finding latency = (evaluation-completed time) − (detection time) from the ledger. PASS = ≥ target % of findings evaluated within the level threshold (7/5/2 days). Detection time from scanner `firstObservedAt`; evaluation-completed from the ledger's evaluated-state timestamp. Findings still unevaluated past threshold = FAIL with age.
- **Required permissions & error handling:** AWS `inspector2:ListFindings` (firstObservedAt). GCP occurrence createTime. Evaluation timestamp is ledger-internal. AccessDenied → Inspector2 read role. If ledger lacks evaluation timestamps (no eval workflow) → cannot measure → FAIL/gap.
- **Alternative satisfiers:** Wiz/Prisma SLA dashboards measuring triage time; DefectDojo SLA. Process evidence = SLA report.
- **OSCAL / NIST:** controls[]=∅ → RA-5, RA-3. **High is 20x-published, not derived.**
- **Module connections:** `core/vdr-ledger.ts` (timestamp diff) + level-aware SLA config.
- **Recommended implementation:** hybrid; latency from timestamps if eval workflow records them; effort M.

### VDR-TFR-IRI — Internet-Reachable Incidents  [MAY (L) / SHOULD (M,H)]
- **Track / actor / levels:** both / TFR (Provider) / L:MAY M:SHOULD **H:SHOULD (20x-published)**
- **Requirement (plain English):** Providers should treat an IRV that is also LEV with PAIN N4/N5 as a **security `Incident`** until partially mitigated to N3 or below. (MAY at Low, SHOULD at Moderate/High.) Bridges VDR into the incident-response process (INR family / IR-4).
- **Testability:** process-artifact
- **Automated validation:** Collector *detects the trigger condition* — any open finding with IRV=true AND LEV=true AND PAIN∈{N4,N5} — and asserts an incident should exist. PASS-supporting = every such finding has a linked incident record (ticket/PagerDuty) until mitigated ≤N3. Collector raises the flag; the incident *handling* is the INR process (reuse `core/notify.ts` PagerDuty + `logging.ts` INR-RIR).
- **Required permissions & error handling:** Derived from ledger (IRV from VDR-EVA-EIR, LEV from ELX, PAIN from EPA). Incident linkage via ticket/notify adapters. No new cloud call; incident-existence is process.
- **Alternative satisfiers:** SOAR auto-incident creation (Tines/Torq — in `detect()`), PagerDuty incidents; process evidence = incident records.
- **OSCAL / NIST:** controls[]=∅ → IR-4, IR-6, RA-5. **High 20x-published.**
- **Module connections:** `core/vdr-ledger.ts` trigger detection → `core/notify.ts` + INR-RIR collector in `logging.ts`.
- **Recommended implementation:** hybrid (collector flags trigger); incident handling is INR process; effort M.

### VDR-TFR-KEV — Remediate KEVs  [SHOULD]
- **Track / actor / levels:** both / TFR (Provider) / L:✓ M:✓ H:derived(rev5: SI-2, RA-5)
- **Requirement (plain English):** Providers SHOULD remediate `Known Exploited Vulnerabilit`ies by the due dates in the CISA KEV Catalog (even if already fully mitigated), per BOD 22-01 or successor. A hard deadline pegged to CISA's per-CVE due date.
- **Testability:** hybrid
- **Automated validation:** Join open scanner findings' CVEs to the CISA KEV feed (which carries `dateAdded` + `dueDate` per CVE). For each open KEV-listed CVE in the environment, compare today vs the KEV due date. PASS = no open KEV-listed CVE is past its CISA due date. This is one of the most defensible automated VDR checks — both sides (your findings, CISA dates) are machine-readable.
- **Required permissions & error handling:** AWS `inspector2:ListFindings` (CVE IDs). GCP `containeranalysis.occurrences.list`. CISA KEV feed over HTTPS (retry; on fetch failure → missing_evidence, never pass-by-default). AccessDenied → Inspector2/Container Analysis read role.
- **Alternative satisfiers:** Wiz/Prisma/Tenable KEV-prioritized remediation SLA tracking (most have native KEV enrichment); process evidence = KEV remediation report.
- **OSCAL / NIST:** controls[]=∅ → SI-2, RA-5. High DERIVED via Rev5 High.
- **Module connections:** new `core/kev-feed.ts` (fetch+cache KEV) joined to `core/vdr-ledger.ts`; shared with VDR-BST-AKE/VDR-EVA-ELX.
- **Recommended implementation:** collector; both inputs machine-readable, near-fully automatable; effort M.

### VDR-TFR-MAV — Mark Accepted Vulnerabilities  [MUST]
- **Track / actor / levels:** both / TFR (Provider) / L:✓ M:✓ H:derived(rev5: CA-5, RA-5)
- **Requirement (plain English):** Providers MUST categorize any vuln not (or won't be) fully mitigated/remediated within **192 days of evaluation** as an `Accepted Vulnerability`. A hard state-transition MUST keyed to a 192-day clock.
- **Testability:** hybrid
- **Automated validation:** For each open finding, compute age = today − evaluation-completed time. PASS = every finding with age > 192 days is marked `accepted` in the ledger (and thus carries VDR-RPT-AVI fields). FAIL = any finding older than 192 days still in an active (non-accepted) state — that's a categorization gap. Fully data-driven once evaluation timestamps exist.
- **Required permissions & error handling:** Ledger timestamps; scanner `firstObservedAt` as a floor if evaluation time missing. No new cloud call. Missing evaluation timestamp → conservative age from detection + warning.
- **Alternative satisfiers:** Wiz/DefectDojo auto-aging into "risk accepted"; process evidence = accepted-vuln register.
- **OSCAL / NIST:** controls[]=∅ → CA-5, RA-5. High DERIVED via Rev5 High.
- **Module connections:** `core/vdr-ledger.ts` (192-day aging rule + state check); feeds VDR-RPT-AVI.
- **Recommended implementation:** collector; pure date arithmetic on ledger; effort S.

### VDR-TFR-MHR — Monthly Activity Report  [MUST]
- **Track / actor / levels:** both / TFR (Provider) / L:✓ M:✓ H:derived(rev5: CA-7, PM-31)
- **Requirement (plain English):** Providers MUST report detection/response activity to `All Necessary Parties` in a **consistent, human-readable** format **at least monthly**. A cadence + format MUST (human-readable companion to VDR-TFR-MRH's machine-readable feed).
- **Testability:** process-artifact
- **Automated validation:** Collector already emits `report.html` (human-readable) per run; validate that a human-readable report is produced on a ≤monthly cadence with a consistent template. PASS = a report exists for each calendar month with the standard sections (overview, VDT, AVI). Cadence provable from run history / scheduled workflow.
- **Required permissions & error handling:** Reads ledger; uses `core/html-report.ts`. No cloud call. Missed month (no run) → gap.
- **Alternative satisfiers:** Trust Center monthly bulletin, Vanta/Drata report export; process evidence = the monthly reports.
- **OSCAL / NIST:** controls[]=∅ → CA-7, PM-31. High DERIVED via Rev5 High.
- **Module connections:** `core/html-report.ts` + `core/vdr-report.ts`; cadence from scheduled workflow.
- **Recommended implementation:** hybrid; collector emits report, human confirms monthly delivery; effort S.

### VDR-TFR-MRH — Historical Activity  [SHOULD]
- **Track / actor / levels:** both / TFR (Provider) / L:✓ M:✓ **H:✓ (20x-published)** — refresh ≤ monthly (L) / ≤14d (M) / ≤7d (H)
- **Requirement (plain English):** Providers SHOULD make recent historical detection/response activity available in a `Machine-Readable` format for automated retrieval by `All Necessary Parties` (e.g. an API), refreshed `Persistently` — at least monthly (Low) / every 14 days (Moderate) / every 7 days (High). The machine feed agencies auto-process (VDR-AGM-RVR).
- **Testability:** process-artifact
- **Automated validation:** Collector already emits machine-readable JSON/OSCAL each run and can publish to an endpoint/bucket (`tracker-push.ts`). Validate (a) a machine-readable feed (JSON/OSCAL) is published, (b) its `last-modified` freshness ≤ the level threshold (monthly/14d/7d). PASS = feed present + freshness within SLA. Freshness is the level-sensitive automatable part.
- **Required permissions & error handling:** Reads emitted evidence files; publishing via push adapter. Stale feed (older than threshold) → FAIL with age. Publish failure → surfaced + retried.
- **Alternative satisfiers:** Trust Center API, Vanta/Drata continuous feed, an S3/GCS published OSCAL bucket; process evidence = the feed URL + access-control config.
- **OSCAL / NIST:** controls[]=∅ → CA-7, PM-31. **High 20x-published.**
- **Module connections:** `core/oscal.ts` (machine-readable) + `core/tracker-push.ts` publish; freshness check in orchestrator.
- **Recommended implementation:** hybrid; collector produces feed, freshness auto-checked, human confirms access for parties; effort M.

### VDR-TFR-NRI — Non-Internet-Reachable Incidents  [MAY (L,M) / SHOULD (H)]
- **Track / actor / levels:** both / TFR (Provider) / L:MAY M:MAY **H:SHOULD (20x-published)**
- **Requirement (plain English):** Providers should treat a LEV that is NOT internet-reachable with PAIN **N5** as a security `Incident` until partially mitigated to N4 or below. MAY at Low/Moderate, SHOULD at High. Counterpart to VDR-TFR-IRI for internal-only blast.
- **Testability:** process-artifact
- **Automated validation:** Same machinery as VDR-TFR-IRI, different trigger: open finding with IRV=false AND LEV=true AND PAIN=N5. PASS-supporting = each such finding has a linked incident until ≤N4. Collector flags trigger; INR process handles.
- **Required permissions & error handling:** Ledger-derived (IRV/LEV/PAIN). No new cloud call. Incident linkage via ticket/notify.
- **Alternative satisfiers:** SOAR auto-incident (Tines/Torq), PagerDuty; process evidence = incident records.
- **OSCAL / NIST:** controls[]=∅ → IR-4, IR-6, RA-5. **High 20x-published.**
- **Module connections:** `core/vdr-ledger.ts` trigger → `core/notify.ts` + INR-RIR.
- **Recommended implementation:** hybrid (collector flags trigger); incident handling is INR; effort S (shares IRI code).

### VDR-TFR-PCD — Persistent Complete Detection  [SHOULD]
- **Track / actor / levels:** both / TFR (Provider) / L:✓ M:✓ **H:✓ (20x-published)** — every 6mo (L) / monthly (M) / monthly (H)
- **Requirement (plain English):** Providers SHOULD `Persistently` perform detection on all `Information Resource`s that are NOT `Likely` to `Drift` (drift = deviations from intended/assessed state), at least every 6 months (Low) / monthly (Moderate, High). A scan-recency SLA for stable resources.
- **Testability:** hybrid
- **Automated validation:** For each non-drift-prone resource (stable infra — VPCs, IAM baselines, KMS, immutable images not redeployed), compute last-scan age from the scanner's last `scanCompletedAt`/occurrence time. PASS = every such resource scanned within the level interval (6mo/1mo/1mo). "Not likely to drift" classification is partly heuristic (immutable-tag, no recent change) + partly analyst tag.
- **Required permissions & error handling:** AWS `inspector2:ListCoverage` (lastScannedAt), `inspector2:ListFindings`. GCP `containeranalysis.occurrences.list` (updateTime). AccessDenied → Inspector2 read role. Resource with no scan record → FAIL (never scanned).
- **Alternative satisfiers:** Wiz/Orca continuous agentless scan (always-fresh), Tenable scheduled scans; process evidence = scan-schedule config + last-run log.
- **OSCAL / NIST:** controls[]=∅ → RA-5, RA-5(2), CA-7. **High 20x-published.**
- **Module connections:** `supplychain.ts` scan-recency rollup + `inventory.ts` resource classification.
- **Recommended implementation:** hybrid; scan-age from coverage API + drift-class tagging; effort M.

### VDR-TFR-PDD — Persistent Drift Detection  [SHOULD]
- **Track / actor / levels:** both / TFR (Provider) / L:✓ M:✓ **H:✓ (20x-published)** — monthly (L) / 14d (M) / 7d (H)
- **Requirement (plain English):** Providers SHOULD `Persistently` perform detection on all `Information Resource`s that ARE `Likely` to `Drift` (configs, running software, privileges, processes), at least monthly (Low) / every 14 days (Moderate) / every 7 days (High). Tighter recency SLA for mutable resources.
- **Testability:** hybrid
- **Automated validation:** Same as PCD but on drift-prone resources (running EC2/GKE/EKS nodes, mutable images, configs) with the tighter interval. Continuous scanners (Inspector2 CONTINUOUS, Artifact Analysis continuous) inherently satisfy this; for periodic scanners compute last-scan age vs monthly/14d/7d. PASS = every drift-prone resource scanned within the level interval. Reuses `anomaly.ts`/`diff-report.ts` drift signals to classify drift-prone resources.
- **Required permissions & error handling:** AWS `inspector2:ListCoverage` (scanStatus=CONTINUOUS, lastScannedAt). GCP occurrences updateTime. AccessDenied → Inspector2 read role. Stale scan → FAIL with age.
- **Alternative satisfiers:** Wiz/Orca continuous scanning, runtime CWPP (CrowdStrike/Lacework — in `detect()`); process evidence = continuous-scan config.
- **OSCAL / NIST:** controls[]=∅ → RA-5, RA-5(2), CM-3, CA-7. **High 20x-published.**
- **Module connections:** `supplychain.ts` recency rollup; drift classification via `core/anomaly.ts`.
- **Recommended implementation:** hybrid; continuous-scan presence + age math; effort M.

### VDR-TFR-PSD — Persistent Sample Detection  [SHOULD]
- **Track / actor / levels:** both / TFR (Provider) / L:✓ M:✓ **H:✓ (20x-published)** — 7d (L) / 3d (M) / 1d (H)
- **Requirement (plain English):** Providers SHOULD `Persistently` detect on representative samples of similar `Machine-Based` `Information Resource`s at least every 7 days (Low) / 3 days (Moderate) / daily (High). The fastest cadence; pairs with VDR-BST-SIR sampling legitimacy.
- **Testability:** hybrid
- **Automated validation:** For each homogeneity cohort (from VDR-BST-SIR grouping), confirm the representative sample has a scan within 7/3/1 days. Continuous scanning trivially satisfies. PASS = every cohort's sample scanned within the level interval. Needs the cohort grouping + last-scan age.
- **Required permissions & error handling:** AWS `inspector2:ListCoverage` + `ec2:DescribeInstances` (cohort by AMI/launch-template). GCP occurrences + `compute.instances.list`. AccessDenied → Inspector2 read role. No recent sample scan → FAIL with age.
- **Alternative satisfiers:** Continuous scanners (Wiz/Orca/Inspector CONTINUOUS); process evidence = sample-scan schedule.
- **OSCAL / NIST:** controls[]=∅ → RA-5, RA-5(2). **High 20x-published.**
- **Module connections:** `supplychain.ts` recency + cohort grouping shared with VDR-BST-SIR/VDR-EVA-GRV.
- **Recommended implementation:** hybrid; cohort + sample-scan age; effort M.

### VDR-TFR-PVR — Mitigation and Remediation Expectations  [SHOULD]
- **Track / actor / levels:** both / TFR (Provider) / L:✓ M:✓ **H:✓ (20x-published)** — full PAIN×reachability×LEV day-table per level
- **Requirement (plain English):** Providers SHOULD reduce each vuln's `Potential Adverse Impact` (partially mitigate / fully mitigate / remediate) within timeframes (days from evaluation) that vary by current PAIN (N2–N5), internet-reachability, and likely-exploitability. The core remediation-SLA matrix. Example Low table — N5 IRV+LEV: 4d, nIRV+LEV: 8d, non-LEV: 32d; N4: 8/32/64; N3: 32/64/192; N2: 96/160/192. Moderate/High tighten these (e.g. Moderate N5 IRV+LEV = 2d).
- **Testability:** hybrid
- **Automated validation:** The richest automatable SLA. For each open finding, compute age = today − evaluation time, look up the allowed days from the level's PAIN-timeframe table keyed on (PAIN, IRV, LEV), and compare. PASS = no open finding exceeds its allowed remediation window for its (PAIN, IRV, LEV) tuple. This requires all three classifications (EPA, EIR, ELX) plus the timestamp — the collector computes the whole thing once the ledger is enriched.
- **Required permissions & error handling:** Ledger-derived (no new cloud call beyond what EVA collectors already use). Embed the L/M/H PAIN-timeframe tables (from FRMR) as config keyed on the selected level. Missing PAIN/IRV/LEV → can't compute SLA → gap, not pass.
- **Alternative satisfiers:** Wiz/Prisma/DefectDojo SLA engines with custom (FedRAMP) policy tables; process evidence = SLA-breach report.
- **OSCAL / NIST:** controls[]=∅ → SI-2, RA-5, CA-5. **High 20x-published (distinct High table).**
- **Module connections:** `core/vdr-ledger.ts` SLA evaluator + embedded FRMR PAIN-timeframe tables (level-selectable); consumes EPA/EIR/ELX enrichment; feeds overdue prediction in VDR-RPT-VDT.
- **Recommended implementation:** collector; deterministic table lookup once ledger enriched — high-value automatable check; effort M.

### VDR-TFR-RMN — Remaining Vulnerabilities  [SHOULD]
- **Track / actor / levels:** both / TFR (Provider) / L:✓ M:✓ H:derived(rev5: SI-2, RA-5)
- **Requirement (plain English):** Providers SHOULD mitigate/remediate **remaining** vulns (those below the PVR-tabled thresholds — e.g. N1, or non-LEV low-impact) during routine operations as the provider deems necessary. The catch-all for low-priority vulns handled in normal patching.
- **Testability:** process-artifact
- **Automated validation:** Discretionary ("as determined necessary by the provider") — no hard SLA. Collector can show *that remaining (low) findings are trending down* (open low-severity count over time via `diff-report.ts`) as supporting evidence of routine remediation. No pass/fail threshold; the judgment is the provider's.
- **Required permissions & error handling:** Ledger trend + diff snapshots. No new cloud call.
- **Alternative satisfiers:** Patch-management cadence (SSM Patch Manager / GCP OS patch — partly in `data.ts`), Wiz/DefectDojo backlog burn-down; process evidence = routine-ops remediation log.
- **OSCAL / NIST:** controls[]=∅ → SI-2, RA-5. High DERIVED via Rev5 High.
- **Module connections:** `core/diff-report.ts` low-severity trend over `core/vdr-ledger.ts`.
- **Recommended implementation:** process-artifact-tracker (collector shows trend only); discretionary SHOULD; effort S.
