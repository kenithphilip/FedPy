# PVA / SCG / UCM — Read-Only Evidence-Collector Design Analysis

Scope: every requirement in **PVA** (Persistent Validation and Assessment, 18), **SCG** (Secure Configuration Guide, 9), and **UCM** (Using Cryptographic Modules, 3) = **30 total**. Source of truth: `cloud-evidence/docs/frmr-requirements.generated.json` (filtered to family ∈ {PVA, SCG, UCM}); term definitions from `docs/FRMR.documentation.json` (`d.FRD.data`). Hard constraint: **strictly read-only** collection. Org = SaaS CI/CD on AWS + GCP + Kubernetes with subprocessors; the org is the CSP (Provider/`CSX`/`CSO`/`ENH` actor).

## Level model (applies to every section)

- **Low / Moderate** statements are taken verbatim from the dump's `levels.low` / `levels.moderate`. For all 30 these match the top-level statement EXCEPT the two requirements whose top-level `statement` is `null` and whose meaning lives only in the per-level blocks:
  - **PVA-CSX-PMV** — cadence varies: Low MUST every 7 days / Moderate MUST every 3 days / High SHOULD (more frequent, TBD).
  - **UCM-CSX-UVM** — keyword varies: Low **MAY** / Moderate **SHOULD** / High **MUST** (all three published in `20x-machine-readable`).
- **High** = for 28 of 30 the dump carries `source: "derived-rev5-pending"` with `controls: []` — i.e. High is **DERIVED from NIST 800-53 Rev5 High baseline via `controls[]`**, but no controls are mapped yet in the dump, so the derivation is *pending*. The two exceptions are **PVA-CSX-PMV** and **UCM-CSX-UVM**, which carry an **explicit published** High statement (`source: "20x-machine-readable"`) — used as-is and called out.
- All 30 have `controls: []` in the dump. NIST mappings below are the analyst's recommended traceability (CA-7, RA-5, CM-6, SC-13, SC-12, SA-4(7), CM-2, etc.), not values present in the FRMR file.

---

## Family overviews

### PVA — Persistent Validation and Assessment (18)
PVA is the *process family*: the Provider must persistently validate its Key Security Indicators (KSIs) and treat any failure as a vulnerability, and an independent assessor must verify that the validation process actually works. Two actor tracks:
- **PVA-CSX-\*** (8) — Provider obligations. **This is the family the cloud-evidence collector itself partially fulfills.** Running the collector on a cadence over every CLOUD/HYBRID KSI *is* persistent machine validation. `core/pva-collector.ts` already synthesizes a `KSI-AFR-PVA` meta-evidence file with run cadence, drift, and pass/fail rollup.
- **PVA-TPX-\*** (10) — **Assessor** obligations (3PAO / FedRAMP). The Provider/CSP cannot self-test these; they are about how the *assessor* conducts the evaluation. For a CSP-operated read-only collector these are almost entirely **process-artifact** items — the collector's role is to *produce the verifiable, process-generated evidence the assessor consumes* (which satisfies PVA-TPX-STE's "no static screenshots" bar), not to grade the assessor.

`Persistent Validation` (FRD) = "the systematic and persistent process of validating that information resources … are operating in a secure manner as expected … against FedRAMP Key Security Indicators." `Machine-Based information resource` (FRD) = anything relying primarily on computers; the collector covers machine-based KSIs; non-machine KSIs (policies, people) need the separate quarterly tracker (PVA-CSX-NMV).

### SCG — Secure Configuration Guide (9)
SCG is *hybrid*: the Provider must publish a **Secure Configuration Guide** (the "RSC") describing recommended secure configuration for top-level administrative + privileged accounts, ship secure defaults, and (SHOULD) offer API/export/compare/machine-readable/versioned enhancements. Two actor tracks: **SCG-CSO-\*** (4, core MUST/SHOULD on the guide artifact) and **SCG-ENH-\*** (5, all SHOULD enhancements). The deliverable is fundamentally a **document/artifact** the CSP authors — the collector's job is to **detect that the artifact and its enhancements exist** (published URL, machine-readable export, version history, API capability) and to cross-check the CSP's own product against its stated secure defaults. Track = `both` (applies to 20x and Rev5).

`Secure Configuration Guide` is not in FRD as a standalone term, but `SCG-CSO-RSC` defines it inline ("recommendations for securely configuring their cloud services"). `Top-level administrative account` (FRD) = most-privileged customer account; `Privileged account` (FRD) = elevated-privilege account; `Machine-Readable` (FRD, 44 USC 3502(18)) = computer-processable without human intervention, no semantic loss.

### UCM — Using Cryptographic Modules (3)
UCM is the most **api-testable** family: the Provider must (CMD) document which cryptographic modules protect federal customer data and whether they are **CMVP-validated** (NIST Cryptographic Module Validation Program, FIPS 140-2/140-3), (CAT) default agency tenants to validated modules, and (UVM) actually use validated modules — at a level-scaled obligation (Low MAY / Moderate SHOULD / High MUST). `Federal Customer Data` (FRD) = electronic content an agency uploads for processing/storage (excludes provider telemetry/metadata). "Cryptographic module" and "validated" are CMVP terms, not in FRD — grounded externally: AWS KMS HSMs are FIPS 140-3 Level 3 validated (CMVP cert #4884; `hsm1.medium` moved to the CMVP *historical* list 2026-01-04, migrate to `hsm2m.medium`); AWS-LC backs the ELB `*-FIPS-*` TLS policies; GCP Cloud KMS software keys use BoringCrypto (FIPS 140-3 cert #5104, Level 1) and Cloud HSM is FIPS 140-2 Level 3. "Update streams of cryptographic modules" is the FedRAMP allowance to apply latest patches as long as the major version is submitted to CMVP within 6 months.

---

## Coverage table

| ID | Name | L/M/H | Testability | Primary signal |
|----|------|-------|-------------|----------------|
| PVA-CSX-VAL | Persistent Validation | MUST/MUST/MUST(derived) | hybrid | The collector itself runs on a cadence (pva-collector.ts) |
| PVA-CSX-PMV | Persistent Machine Validation | MUST(7d)/MUST(3d)/SHOULD(published) | api-testable | Collector run-cadence ≤ level threshold |
| PVA-CSX-NMV | Non-Machine Validation | MUST/MUST/MUST(derived) | process-artifact | Quarterly attestation log for non-machine KSIs |
| PVA-CSX-FAV | Issues As Vulnerabilities | MUST/MUST/MUST(derived) | hybrid | Failed findings + VDR ticket linkage |
| PVA-CSX-RPV | Report Persistent Validation | MUST/MUST/MUST(derived) | hybrid | Run summary pushed into VDR reporting |
| PVA-CSX-PTE | Provide Technical Evidence | SHOULD/SHOULD/SHOULD(derived) | process-artifact | Evidence-export package given to assessors |
| PVA-CSX-RAD | Receiving Advice | MAY/MAY/MAY(derived) | process-artifact | Assessor-advice log (CSP side) |
| PVA-CSX-IVV | Independent Verification & Validation | MUST/MUST/MUST(derived) | process-artifact | Assessor report attached to authorization data |
| PVA-TPX-UNP | Underlying Processes | MUST/MUST/MUST(derived) | process-artifact | Assessor-produced; collector supplies inputs |
| PVA-TPX-PDK | Processes Derived from KSIs | MUST/MUST/MUST(derived) | process-artifact | Assessor-produced |
| PVA-TPX-OUC | Outcome Consistency | MUST/MUST/MUST(derived) | process-artifact | Assessor-produced; drift history is the input |
| PVA-TPX-MME | Mixed Methods Evaluation | MUST/MUST/MUST(derived) | process-artifact | Assessor-produced |
| PVA-TPX-PEX | Provider Experts | SHOULD/SHOULD/SHOULD(derived) | process-artifact | Assessor-produced |
| PVA-TPX-STE | Static Evidence | MUST NOT/MUST NOT/MUST NOT(derived) | process-artifact | Collector design satisfies (process-generated, signed) |
| PVA-TPX-PAD | Procedure Adherence | MUST/MUST/MUST(derived) | process-artifact | Assessor-produced; run history is the input |
| PVA-TPX-SUM | Assessment Summary | MUST/MUST/MUST(derived) | process-artifact | Assessor-produced summary in authorization data |
| PVA-TPX-NOR | No Overall Recommendation | MUST NOT/MUST NOT/MUST NOT(derived) | process-artifact | Assessor behavior; not CSP-testable |
| PVA-TPX-SHA | Sharing Advice | MAY/MAY/MAY(derived) | process-artifact | Assessor behavior; not CSP-testable |
| SCG-CSO-RSC | Recommended Secure Configuration | MUST/MUST/MUST(derived) | hybrid | Published SCG artifact exists + content checklist |
| SCG-CSO-AUP | Use Instructions | MUST/MUST/MUST(derived) | process-artifact | "How to obtain/use SCG" section in auth package |
| SCG-CSO-PUB | Public Guidance | SHOULD/SHOULD/SHOULD(derived) | hybrid | Public URL reachable (read-only HTTP GET) |
| SCG-CSO-SDF | Secure Defaults | SHOULD/SHOULD/SHOULD(derived) | hybrid | Tenant/account defaults vs SCG-stated defaults |
| SCG-ENH-API | API Capability | SHOULD/SHOULD/SHOULD(derived) | hybrid | Security-settings API endpoint exists |
| SCG-ENH-EXP | Export Capability | SHOULD/SHOULD/SHOULD(derived) | hybrid | Machine-readable settings export exists |
| SCG-ENH-CMP | Comparison Capability | SHOULD/SHOULD/SHOULD(derived) | hybrid | Current-vs-recommended compare capability |
| SCG-ENH-MRG | Machine-Readable Guidance | SHOULD/SHOULD/SHOULD(derived) | hybrid | SCG offered in machine-readable format |
| SCG-ENH-VRH | Versioning & Release History | SHOULD/SHOULD/SHOULD(derived) | hybrid | SCG version/changelog artifact |
| UCM-CSX-CMD | Cryptographic Module Documentation | MUST/MUST/MUST(derived) | hybrid | Crypto-module inventory + CMVP-validation flag |
| UCM-CSX-CAT | Configuration of Agency Tenants | SHOULD/SHOULD/SHOULD(derived) | api-testable | Default tenant config uses validated modules |
| UCM-CSX-UVM | Using Validated Cryptographic Modules | MAY/SHOULD/MUST(published) | api-testable | KMS/ACM/TLS specs map to CMVP-validated modules |

**Testability breakdown (30 total):** api-testable = **3** (PVA-CSX-PMV, UCM-CSX-CAT, UCM-CSX-UVM); hybrid = **12** (PVA-CSX-VAL, PVA-CSX-FAV, PVA-CSX-RPV, SCG-CSO-RSC, SCG-CSO-PUB, SCG-CSO-SDF, SCG-ENH-API, SCG-ENH-EXP, SCG-ENH-CMP, SCG-ENH-MRG, SCG-ENH-VRH, UCM-CSX-CMD); process-artifact = **15** (the 8 remaining PVA-CSX/TPX inputs + 2 PVA-TPX out-of-scope prohibitions + PVA-CSX-NMV/RAD/PTE/IVV + SCG-CSO-AUP). 3 + 12 + 15 = 30.

---

# PVA — Persistent Validation and Assessment

### PVA-CSX-VAL — Persistent Validation  [MUST]
- **Track / actor / levels:** 20x / CSX (Providers) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider must *persistently* (FRD: firm, steady, repeated over time, status always known) perform validation of its Key Security Indicators. This recurring process is named "persistent validation" and is defined as part of vulnerability detection. This is the umbrella obligation the whole cloud-evidence tool exists to discharge.
- **Testability:** hybrid
- **Automated validation:** The existence of a scheduled collector run is the evidence. Check: ≥1 successful run exists in the run-history store within the documented cadence window AND every CLOUD/HYBRID KSI produced an evidence file in that run. PASS = `pva-collector` emitted a `KSI-AFR-PVA.json` with `pva.collector_executed_persistently` passed (`totalKsis ≥ 1`) and the run timestamp is within cadence. The cadence document + reviewer sign-off remain process artifacts.
- **Required permissions & error handling:** No cloud permission — meta-collector reads `outDir` evidence files. On `outDir` empty / unreadable: surface "no KSI evidence produced — collector run failed" (already handled in pva-collector.ts).
- **Alternative satisfiers:** 3rd-party continuous-compliance platform (Vanta, Drata, Paramify, SecureFrame) driving the validation cycle; signal = platform scan-history export + coverage matrix. `third-party-tools.ts` already detects these GRC vendors.
- **OSCAL / NIST:** suggest CA-7, CA-7.6, RA-5. High: derive from Rev5 High once `controls[]` populated (currently pending).
- **Module connections:** **Already implemented** — `core/pva-collector.ts` (`buildPvaEvidence`). Extend only to assert cadence-window freshness explicitly.
- **Recommended implementation:** hybrid (collector + process artifact). Rationale: tool's existence + cadence is the machine half; PVA plan doc + sign-off is the human half. Effort: **S** (already built; add freshness assertion).

### PVA-CSX-PMV — Persistent Machine Validation  [varies: Low MUST / Moderate MUST / High SHOULD]
- **Track / actor / levels:** 20x / CSX (Providers) / L:MUST(every 7 days) M:MUST(every 3 days) H:SHOULD (published: "plan for more frequent at 20x High; requirements not yet established"). Top-level `statement` is `null`; meaning lives entirely in the per-level blocks.
- **Requirement (plain English):** The Provider must complete the validation process for the KSIs of **machine-based** information resources (FRD: systems/software/cloud-native capabilities) at least once every **7 days at Low, every 3 days at Moderate**. High has no fixed number yet — plan for more frequent.
- **Testability:** api-testable (against the collector's own run history)
- **Automated validation:** Compute the max gap between consecutive successful runs over the trailing window from the run-history store. PASS = max inter-run gap ≤ selected level's threshold (Low 7d / Moderate 3d) for every machine-based KSI. This is the **strongest machine-checkable PVA item** because it's purely a cadence assertion over the tool's own logs.
- **Required permissions & error handling:** None (reads local run metadata / tracker run records). If only one run exists: WARN "cadence not yet demonstrable — need ≥2 runs". If gap exceeded: FAIL with the offending interval.
- **Alternative satisfiers:** GRC platform with documented machine-scan cadence; signal = scheduler config + scan timestamps.
- **OSCAL / NIST:** CA-7, CA-7(4)/(6), SI-4. High: **explicit published SHOULD** (not derived) — use the published statement and note High target is not yet numerically defined.
- **Module connections:** Extend `core/pva-collector.ts` to read `previousRunPath` *history* (not just last run) and compute inter-run gap; or add a small cadence assertion in the orchestrator's run-summary writer. New field: `cadence_window_days`, `max_run_gap_days`.
- **Recommended implementation:** collector. Rationale: deterministic cadence math over run logs. Effort: **S**.

### PVA-CSX-NMV — Non-Machine Validation  [MUST]
- **Track / actor / levels:** 20x / CSX (Providers) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider must complete the validation process for KSIs of **non-machine-based** information resources (policies, procedures, employees — the parts that don't run on computers) at least **once every 3 months**.
- **Testability:** process-artifact
- **Automated validation:** No cloud API can attest a quarterly human review of policies. Track via an attestation record: artifact = a per-non-machine-KSI sign-off log (reviewer, date, KSI id). PASS criterion (machine-checkable on the *artifact*) = each non-machine KSI has an attestation dated within the last 92 days. The collector should *flag the requirement and surface staleness* rather than judge content.
- **Required permissions & error handling:** None cloud-side. If no attestation store configured: emit `process_artifacts_required: ["Quarterly non-machine KSI validation log"]` and mark missing_evidence.
- **Alternative satisfiers:** GRC platform task/recurring-review module (Vanta/Drata "controls review" cadence); signal = exported review-task completion history.
- **OSCAL / NIST:** CA-7, PL-2, PM-14. High: derive from Rev5 High (pending).
- **Module connections:** **New tracker** — a non-machine-KSI attestation tracker (extend the tracker app's item model with a "last validated" date + 92-day staleness rule), surfaced through `pva-collector.ts` as a process_artifact_required.
- **Recommended implementation:** process-artifact-tracker. Rationale: inherently human; only staleness is automatable. Effort: **M** (tracker schema + staleness check).

### PVA-CSX-FAV — Issues As Vulnerabilities  [MUST]
- **Track / actor / levels:** 20x / CSX (Providers) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** Any issue detected during persistent validation — and any *failure of the validation process itself* — must be treated as a **vulnerability** and routed through the FedRAMP Vulnerability Detection and Response (VDR) process.
- **Testability:** hybrid
- **Automated validation:** The collector already produces failing findings (`passed=false`) with severity. Check = every failing finding (and every collector parse_error/run failure) has a corresponding VDR ticket. PASS = for each `passed:false` finding in the latest run, a linked ticket id exists in the ticket system (the existing `ticket-push` integration to Jira/ServiceNow/GitHub Issues). The collector emits the failures; the linkage check confirms they entered VDR.
- **Required permissions & error handling:** Ticket-system read token (out of cloud scope). On ticket-API failure: WARN, do not fail the KSI (linkage unverifiable ≠ violation).
- **Alternative satisfiers:** GRC/SOAR auto-ticketing (PagerDuty, Tines, Torq); signal = webhook/notification config already in `core/notify.ts`.
- **OSCAL / NIST:** RA-5, SI-2, CA-7. High: derive from Rev5 High (pending).
- **Module connections:** `core/pva-collector.ts` (aggregates failures) + Phase-F ticket-push adapters; add a "failure→ticket linkage" assertion.
- **Recommended implementation:** hybrid. Rationale: failures are machine-detected; VDR routing proof is a ticket linkage. Effort: **M**.

### PVA-CSX-RPV — Report Persistent Validation  [MUST]
- **Track / actor / levels:** 20x / CSX (Providers) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider must include persistent-validation activity in the vulnerability-detection-and-response reports the VDR process already requires. I.e. PVA output feeds the VDR report, not a separate report.
- **Testability:** hybrid
- **Automated validation:** Check that each run summary is published to the reporting sink. PASS = latest `pva-run-summary` (or its push) is present in the tracker / Paramify / SIEM target within the reporting period. The collector already has `tracker-push.ts`, `paramify-push.ts`, and OCSF SIEM push — confirm the push succeeded.
- **Required permissions & error handling:** Push-target token. On push failure: surface push error (push retry already implemented); WARN.
- **Alternative satisfiers:** GRC platform that ingests evidence and rolls it into its own continuous-monitoring report; signal = successful API push receipt.
- **OSCAL / NIST:** CA-7, RA-5, PM-31. High: derive from Rev5 High (pending).
- **Module connections:** `core/pva-collector.ts` runSummary + `paramify-push.ts` / `tracker-push.ts` adapters. Assert push receipt.
- **Recommended implementation:** hybrid. Rationale: report generation is automated; inclusion-in-VDR is a delivery assertion. Effort: **S**.

### PVA-CSX-PTE — Provide Technical Evidence  [SHOULD]
- **Track / actor / levels:** 20x / CSX (Providers) / L:SHOULD M:SHOULD H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider should give *all necessary assessors* (FRD: FedRAMP + the recognized 3PAO) technical explanations, demonstrations, and supporting information for the technical capabilities it uses to meet KSIs and provide validation.
- **Testability:** process-artifact
- **Automated validation:** Not gradeable by API, but the collector *manufactures the deliverable*: a signed, timestamped, OSCAL-formatted evidence package (already produced by `core/oscal.ts` + Ed25519 manifest + RFC 3161 timestamp) is exactly the "technical evidence" an assessor consumes. Track = an exportable assessor package exists for the current run. PASS = OSCAL `assessment-results.json` + signing manifest present.
- **Required permissions & error handling:** None new. If signing/timestamp disabled: WARN "evidence export unsigned — assessor may not accept".
- **Alternative satisfiers:** Read access to a GRC tenant where the assessor self-serves; signal = assessor-role granted in platform.
- **OSCAL / NIST:** CA-2, CA-7, SA-4(7). High: derive from Rev5 High (pending).
- **Module connections:** `core/oscal.ts` + evidence-signing/timestamp modules — already produce the package. No new code; document the export as the PTE deliverable.
- **Recommended implementation:** process-artifact (auto-generated). Rationale: the package is built; delivery to assessors is manual. Effort: **S**.

### PVA-CSX-RAD — Receiving Advice  [MAY]
- **Track / actor / levels:** 20x / CSX (Providers) / L:MAY M:MAY H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider *may* ask for and accept advice from its assessor during assessment about improving security posture or the clarity/accuracy of its validation procedures — UNLESS that would compromise assessment objectivity (paired with PVA-TPX-SHA).
- **Testability:** process-artifact
- **Automated validation:** Permissive (MAY) and human-interaction-based — nothing to test in cloud. If the CSP chooses to accept advice, track an "assessor advice received" log (date, topic, objectivity note). No PASS/FAIL; informational tracker entry only.
- **Required permissions & error handling:** None.
- **Alternative satisfiers:** n/a (process choice).
- **OSCAL / NIST:** CA-2, CA-7. High: derive from Rev5 High (pending).
- **Module connections:** New tracker (advice log) — optional; lowest priority.
- **Recommended implementation:** process-artifact-tracker (optional). Rationale: MAY + interpersonal. Effort: **S**.

### PVA-CSX-IVV — Independent Verification and Validation  [MUST]
- **Track / actor / levels:** 20x / CSX (Providers) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider must have the implementation of its goals and validation processes assessed by a **FedRAMP-recognized independent assessor OR by FedRAMP directly**, and must include those results *unmodified* in its authorization data (FRD: the collective info FedRAMP needs for A&A, incl. the authorization package).
- **Testability:** process-artifact
- **Automated validation:** The assessment is performed by a third party — not CSP-testable. Track = the assessor's report artifact is attached to the authorization-data store, with an integrity hash to prove "without modification." PASS (on the artifact) = a recognized-assessor report exists and its stored hash matches the delivered file.
- **Required permissions & error handling:** None cloud-side. If no assessor report attached: `missing_evidence`.
- **Alternative satisfiers:** FedRAMP-direct assessment in lieu of a 3PAO; signal = FedRAMP-issued assessment artifact.
- **OSCAL / NIST:** CA-2, CA-2(1) (independent assessor), CA-7. High: derive from Rev5 High (pending).
- **Module connections:** New tracker (authorization-data artifact registry + integrity hash). Reuse the evidence-signing hash machinery.
- **Recommended implementation:** process-artifact-tracker. Rationale: third-party deliverable; only attachment + integrity is automatable. Effort: **M**.

### PVA-TPX-UNP — Underlying Processes  [MUST]
- **Track / actor / levels:** 20x / **TPX (Assessors)** / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The **assessor** must verify and validate the underlying processes (machine-based and non-machine-based) the provider uses to validate KSIs (statement is truncated with "this should include at least:" — sub-items live in the FedRAMP PVA standard, not the dump). This is an assessor obligation, not a CSP self-test.
- **Testability:** process-artifact
- **Automated validation:** The CSP cannot self-validate the assessor's work. The collector's role is to *supply the assessor's inputs*: the per-KSI process documentation + the live run history that demonstrates the underlying process actually executes. PASS criterion is the assessor's, not the tool's. Tool deliverable = complete, signed evidence + process docs bundle.
- **Required permissions & error handling:** None; surface only "assessor input package generated".
- **Alternative satisfiers:** n/a (assessor activity).
- **OSCAL / NIST:** CA-2, CA-7. High: derive from Rev5 High (pending).
- **Module connections:** Provides input via `core/oscal.ts` export; no CSP-side check.
- **Recommended implementation:** process-artifact (assessor-owned; tool feeds inputs). Effort: **S** (no new collector).

### PVA-TPX-PDK — Processes Derived from Key Security Indicators  [MUST]
- **Track / actor / levels:** 20x / TPX (Assessors) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The assessor must verify/validate the implementation of processes derived from KSIs to confirm the provider accurately documented its process and goals.
- **Testability:** process-artifact
- **Automated validation:** Assessor-owned. Tool support = a cross-map from each KSI to the collector check(s) that exercise it, so the assessor can trace "documented process → implemented check." PASS is the assessor's judgment. Deliverable = KSI→check traceability matrix (the ksi-map registry already encodes this).
- **Required permissions & error handling:** None.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** CA-2, CA-7. High: derive from Rev5 High (pending).
- **Module connections:** `core/ksi-map.ts` is the traceability source; export it as the matrix.
- **Recommended implementation:** process-artifact (assessor-owned). Effort: **S**.

### PVA-TPX-OUC — Outcome Consistency  [MUST]
- **Track / actor / levels:** 20x / TPX (Assessors) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The assessor must verify/validate whether the underlying processes are *consistently* producing the security outcome the provider documented.
- **Testability:** process-artifact
- **Automated validation:** Assessor-owned, but the **drift history** the collector already computes (`pva.no_negative_drift_since_previous_run` + per-run pass/fail trend in `pva-collector.ts`) is the precise quantitative input for "consistency." Tool deliverable = multi-run drift/consistency timeline per KSI. PASS is the assessor's.
- **Required permissions & error handling:** None new.
- **Alternative satisfiers:** GRC platform trend/consistency dashboards; signal = export of historical pass-rate per control.
- **OSCAL / NIST:** CA-7, CA-7(4). High: derive from Rev5 High (pending).
- **Module connections:** `core/pva-collector.ts` drift logic + `core/diff-report.ts` — extend to multi-run consistency timeline.
- **Recommended implementation:** process-artifact (assessor-owned; tool supplies consistency timeline). Effort: **S–M**.

### PVA-TPX-MME — Mixed Methods Evaluation  [MUST]
- **Track / actor / levels:** 20x / TPX (Assessors) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The assessor must evaluate using a mix of quantitative and expert-qualitative assessment, documenting which method applies to which aspect.
- **Testability:** process-artifact
- **Automated validation:** Purely assessor methodology — nothing for a CSP read-only collector to test. The tool supplies the *quantitative* half (pass/fail counts, drift metrics) the assessor mixes with qualitative judgment. No PASS/FAIL.
- **Required permissions & error handling:** None.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** CA-2. High: derive from Rev5 High (pending).
- **Module connections:** none (assessor-owned).
- **Recommended implementation:** process-artifact (assessor-owned). Effort: **N/A** for collector.

### PVA-TPX-PEX — Provider Experts  [SHOULD]
- **Track / actor / levels:** 20x / TPX (Assessors) / L:SHOULD M:SHOULD H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The assessor should engage provider experts to understand decisions and inform qualitative assessment, and should do independent research to test that information.
- **Testability:** process-artifact
- **Automated validation:** Assessor behavior; not CSP-testable. Optional CSP-side tracker of expert-interview sessions for completeness. No PASS/FAIL.
- **Required permissions & error handling:** None.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** CA-2. High: derive from Rev5 High (pending).
- **Module connections:** none.
- **Recommended implementation:** process-artifact (assessor-owned). Effort: **N/A**.

### PVA-TPX-STE — Static Evidence  [MUST NOT]
- **Track / actor / levels:** 20x / TPX (Assessors) / L:MUST NOT M:MUST NOT H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The assessor MUST NOT rely on screenshots, config dumps, or other static output as evidence — EXCEPT when evaluating the accuracy/reliability of the *process that generates* such artifacts.
- **Testability:** process-artifact
- **Automated validation:** This is the requirement the **collector's design directly satisfies**: the cloud-evidence tool produces *process-generated, signed, timestamped* evidence (live SDK reads → OSCAL + Ed25519 manifest + RFC 3161 timestamp), which is exactly the "process that generates artifacts" the exception blesses. There is no CSP PASS/FAIL; rather, the tool's architecture is the *defense* that the evidence is non-static. Deliverable note: emphasize signing/timestamp so the assessor can verify provenance.
- **Required permissions & error handling:** None new; ensure signing + timestamp are enabled (WARN if off).
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** CA-2, CA-7. High: derive from Rev5 High (pending).
- **Module connections:** evidence-signing + RFC-3161 timestamp + `core/oscal.ts` — the satisfaction mechanism.
- **Recommended implementation:** process-artifact (tool design satisfies). Effort: **S** (enforce signing-on).

### PVA-TPX-PAD — Procedure Adherence  [MUST]
- **Track / actor / levels:** 20x / TPX (Assessors) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The assessor must assess whether procedures are *consistently followed* (including the processes that ensure this) — and must NOT rely solely on the existence of a procedure document.
- **Testability:** process-artifact
- **Automated validation:** Assessor-owned. Tool support = run-history + drift demonstrate procedures are *executed* (not just documented) — the anti-"document-only" evidence. No CSP PASS/FAIL.
- **Required permissions & error handling:** None.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** CA-2, CA-7. High: derive from Rev5 High (pending).
- **Module connections:** `core/pva-collector.ts` run history supplies adherence evidence.
- **Recommended implementation:** process-artifact (assessor-owned; tool supplies execution proof). Effort: **S**.

### PVA-TPX-SUM — Assessment Summary  [MUST]
- **Track / actor / levels:** 20x / TPX (Assessors) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The assessor must deliver a high-level summary of assessment process + findings *for each KSI*; this summary goes into the authorization data for the cloud service offering.
- **Testability:** process-artifact
- **Automated validation:** Assessor-authored deliverable. Tool support = the per-KSI evidence files + `summary_for_llm` fields give the assessor a per-KSI scaffold to summarize. Track attachment of the assessor's summary to authorization data (integrity hash). PASS is on the artifact's presence, not content.
- **Required permissions & error handling:** None cloud-side.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** CA-2, CA-7. High: derive from Rev5 High (pending).
- **Module connections:** envelope `summary_for_llm` per KSI feeds the scaffold; authorization-data tracker holds the assessor file.
- **Recommended implementation:** process-artifact (assessor-owned). Effort: **S**.

### PVA-TPX-NOR — No Overall Recommendation  [MUST NOT]
- **Track / actor / levels:** 20x / TPX (Assessors) / L:MUST NOT M:MUST NOT H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The assessor MUST NOT deliver an overall recommendation on whether the cloud service offering meets FedRAMP authorization requirements (FedRAMP makes that call).
- **Testability:** process-artifact
- **Automated validation:** Pure assessor-conduct prohibition; **nothing for a CSP collector to test**. Documented here for completeness only. No signal, no PASS/FAIL.
- **Required permissions & error handling:** None.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** CA-2. High: derive from Rev5 High (pending).
- **Module connections:** none.
- **Recommended implementation:** process-artifact (out of CSP scope). Effort: **N/A**.

### PVA-TPX-SHA — Sharing Advice  [MAY]
- **Track / actor / levels:** 20x / TPX (Assessors) / L:MAY M:MAY H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The assessor *may* share improvement advice with the provider being assessed, UNLESS it would compromise assessment objectivity (paired with PVA-CSX-RAD).
- **Testability:** process-artifact
- **Automated validation:** Assessor-conduct, permissive — not CSP-testable. Mirror of PVA-CSX-RAD (CSP-side advice log). No PASS/FAIL.
- **Required permissions & error handling:** None.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** CA-2. High: derive from Rev5 High (pending).
- **Module connections:** mirror of CSX-RAD advice log (optional).
- **Recommended implementation:** process-artifact (assessor-owned). Effort: **N/A**.

---

# SCG — Secure Configuration Guide

### SCG-CSO-RSC — Recommended Secure Configuration  [MUST]
- **Track / actor / levels:** both / CSO (Providers) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider must create, maintain, and make available recommendations for securely configuring its cloud services — the **Secure Configuration Guide** — covering at least the listed information (statement truncated; the FedRAMP RSC/SCG standard enumerates: how to securely access/configure/operate/decommission top-level administrative accounts; security settings only top-level admins can change and their implications; recommended secure defaults for privileged accounts). FRD: `Top-level administrative account` / `Privileged account`.
- **Testability:** hybrid
- **Automated validation:** The guide is a CSP-authored artifact, so detect-and-checklist: (1) confirm an SCG artifact is registered (URL or file in the artifact tracker); (2) run a content checklist (does it cover top-level admin access/config/operate/decommission + privileged-account defaults). The collector can *cross-check the CSP's own AWS/GCP org defaults* against the SCG's stated recommendations (e.g. does the SCG say "root has hardware MFA + no access keys" and does the account match — reuse IAM-MFA findings). PASS = SCG artifact present AND content-checklist complete; cross-check is advisory.
- **Required permissions & error handling:** Artifact registry read; for cross-check reuse existing IAM/org read perms (`iam:GetAccountSummary`, `organizations:Describe*`). On artifact missing: `missing_evidence`.
- **Alternative satisfiers:** Published vendor hardening/CIS-benchmark-aligned guide; signal = public URL + machine-readable benchmark file (OSCAL/SCAP). GRC platform that hosts the SCG; signal = platform doc link.
- **OSCAL / NIST:** CM-2, CM-6, CM-6(1), SA-5. High: derive from Rev5 High (pending).
- **Module connections:** New SCG-artifact tracker + content-checklist; cross-check reuses `providers/*/iam.ts` + `config.ts` findings.
- **Recommended implementation:** hybrid. Rationale: artifact existence + content checklist (manual/semi-auto) plus optional config cross-check (auto). Effort: **M**.

### SCG-CSO-AUP — Use Instructions  [MUST]
- **Track / actor / levels:** both / CSO (Providers) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider must include, in the FedRAMP **authorization package** (FRD: essential info an agency uses to decide on authorization), instructions explaining how to *obtain and use* the Secure Configuration Guide.
- **Testability:** process-artifact
- **Automated validation:** Presence check on a package section. Artifact = the "how to obtain/use the SCG" section/URL referenced in the authorization package. PASS (on artifact) = the section exists and resolves (if a URL, read-only HTTP GET returns 200). Tracked as a checklist item.
- **Required permissions & error handling:** None cloud-side; optional outbound HTTP GET for URL liveness (network errors → WARN, not FAIL).
- **Alternative satisfiers:** Link to the public SCG (overlaps SCG-CSO-PUB) embedded in the package; signal = reachable URL.
- **OSCAL / NIST:** SA-5, CM-6. High: derive from Rev5 High (pending).
- **Module connections:** SCG-artifact tracker (same as RSC) — add an "auth-package instructions present" flag.
- **Recommended implementation:** process-artifact-tracker (+ optional URL liveness). Effort: **S**.

### SCG-CSO-PUB — Public Guidance  [SHOULD]
- **Track / actor / levels:** both / CSO (Providers) / L:SHOULD M:SHOULD H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider should make the Secure Configuration Guide available publicly.
- **Testability:** hybrid
- **Automated validation:** Read-only outbound HTTP GET to the configured public SCG URL. PASS = URL returns 200 and content-type is a document/page (not a login wall). This is genuinely automatable without cloud creds.
- **Required permissions & error handling:** Outbound network only. On 401/403/redirect-to-login: FAIL "SCG URL not publicly accessible (auth wall detected)". On network error: WARN "could not reach SCG URL — check connectivity".
- **Alternative satisfiers:** SCG hosted on a public docs site / GitHub Pages / vendor trust center; signal = reachable public URL.
- **OSCAL / NIST:** SA-5, CM-6. High: derive from Rev5 High (pending).
- **Module connections:** New tiny URL-liveness checker (reuse the generic-webhook HTTP client). Config: `SCG_PUBLIC_URL`.
- **Recommended implementation:** collector (URL liveness) + artifact config. Rationale: a public-reachability probe is fully automatable read-only. Effort: **S**.

### SCG-CSO-SDF — Secure Defaults  [SHOULD]
- **Track / actor / levels:** both / CSO (Providers) / L:SHOULD M:SHOULD H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider should set all settings to its recommended secure defaults for top-level administrative and privileged accounts *when initially provisioned* (secure-by-default at provisioning time).
- **Testability:** hybrid
- **Automated validation:** Compare the live state of top-level admin / privileged accounts against the SCG-declared secure defaults. Concretely reuse existing checks: root/owner MFA on, no root access keys, org SCPs/IAM password policy, etc. PASS = sampled top-level admin + privileged accounts conform to the SCG's stated defaults. (Caveat: a read-only collector observes *current* state, not *initial-provisioning* state — surface this as a proxy, with the provisioning template/IaC as the true evidence.)
- **Required permissions & error handling:** `iam:GetAccountSummary`, `iam:GetAccountPasswordPolicy`, `organizations:DescribePolicy`, GCP `resourcemanager`/org-policy read. AccessDenied → diagnose with exact action (existing `diagnoseAwsError`/`diagnoseGcpError`). Not-enabled (no Organizations) → WARN, expected.
- **Alternative satisfiers:** IaC/landing-zone module (AWS Control Tower, Terraform Landing Zone, GCP org-policy bundles) enforcing defaults at provisioning; signal = detected control-tower/landing-zone resources or IaC templates.
- **OSCAL / NIST:** CM-2, CM-6, CM-6(1), AC-6. High: derive from Rev5 High (pending).
- **Module connections:** `providers/aws/iam.ts` + `providers/aws/config.ts` + GCP equivalents; add a "defaults-vs-SCG" comparator driven by the SCG machine-readable doc (ties to SCG-ENH-MRG).
- **Recommended implementation:** hybrid. Rationale: current-state conformance is auto; "at provisioning" needs the IaC template artifact. Effort: **M**.

### SCG-ENH-API — API Capability  [SHOULD]
- **Track / actor / levels:** both / ENH (Providers) / L:SHOULD M:SHOULD H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider should offer customers the capability to view and adjust security settings via an API (or similar). This is about the CSP's *own product*, not the AWS/GCP it runs on.
- **Testability:** hybrid
- **Automated validation:** Detect that a security-settings API surface exists in the CSP's product — e.g. an OpenAPI/Swagger spec advertising security-config endpoints (the tracker already has an OpenAPI spec). PASS = an API spec (or documented endpoint set) covering view+adjust of security settings is registered. Cannot fully auto-verify a third-party SaaS product's API from cloud reads — treat as artifact + spec presence.
- **Required permissions & error handling:** None cloud-side; read the product's published OpenAPI artifact. Missing spec → `missing_evidence`.
- **Alternative satisfiers:** Terraform/Pulumi provider for the CSP's product (config-as-code = the "similar capability"); signal = published provider/registry entry.
- **OSCAL / NIST:** CM-6, AC-3, SA-5. High: derive from Rev5 High (pending).
- **Module connections:** New product-capability tracker; reuse OpenAPI-spec presence check.
- **Recommended implementation:** hybrid (artifact + optional spec parse). Effort: **S–M**.

### SCG-ENH-EXP — Export Capability  [SHOULD]
- **Track / actor / levels:** both / ENH (Providers) / L:SHOULD M:SHOULD H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider should offer the capability to export all security settings in a **machine-readable** format (FRD: computer-processable without human intervention, no semantic loss).
- **Testability:** hybrid
- **Automated validation:** Detect a settings-export endpoint/feature producing JSON/YAML/SCAP. PASS = export capability registered AND a sample export validates as well-formed machine-readable (parseable JSON/YAML). The collector can validate a *sample* export artifact's format.
- **Required permissions & error handling:** None cloud-side; validate a provided sample export. Malformed sample → FAIL "export not machine-readable".
- **Alternative satisfiers:** Config-as-code export (Terraform state/HCL) of security settings; signal = sample export file.
- **OSCAL / NIST:** CM-6, AU-7, SA-5. High: derive from Rev5 High (pending).
- **Module connections:** Product-capability tracker; reuse the schema-validation (ajv) machinery for format check.
- **Recommended implementation:** hybrid (artifact + format validation). Effort: **S**.

### SCG-ENH-CMP — Comparison Capability  [SHOULD]
- **Track / actor / levels:** both / ENH (Providers) / L:SHOULD M:SHOULD H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider should offer the capability to compare *all current settings* for top-level admin + privileged accounts against the recommended secure defaults (a drift/diff feature for customers).
- **Testability:** hybrid
- **Automated validation:** Detect a compare/drift feature in the product. The collector can *demonstrate the capability internally* by running the SCG-SDF comparator (current settings vs SCG machine-readable defaults) and emitting the diff — which simultaneously proves the comparison is feasible. PASS = compare capability registered OR the collector's own defaults-vs-SCG diff runs successfully.
- **Required permissions & error handling:** Same reads as SCG-CSO-SDF. AccessDenied → diagnose exact action.
- **Alternative satisfiers:** CSPM/posture tool the customer runs (Prowler, Steampipe/Powerpipe, SCC, Security Hub) producing the same diff; signal = detected CSPM tool. (`third-party-tools.ts` detects several.)
- **OSCAL / NIST:** CM-6, CM-2(2), CA-7. High: derive from Rev5 High (pending).
- **Module connections:** Same comparator as SCG-CSO-SDF + `core/diff-report.ts` (already produces diffs); Powerpipe integration (already present) is a strong alt-satisfier signal.
- **Recommended implementation:** hybrid. Rationale: comparator is buildable from existing diff machinery; product-feature attestation is artifact. Effort: **M**.

### SCG-ENH-MRG — Machine-Readable Guidance  [SHOULD]
- **Track / actor / levels:** both / ENH (Providers) / L:SHOULD M:SHOULD H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider should *also* provide the Secure Configuration Guide itself in a machine-readable format usable by customers or third-party tools to compare against current settings.
- **Testability:** hybrid
- **Automated validation:** Detect a machine-readable SCG artifact (OSCAL component-definition, SCAP/XCCDF, or structured JSON/YAML) and validate it parses + has the expected schema. PASS = machine-readable SCG registered AND validates. This is the artifact that *powers* SCG-CSO-SDF and SCG-ENH-CMP comparators, so it's the keystone enhancement.
- **Required permissions & error handling:** None cloud-side; format/schema validation of the provided file (reuse ajv). Malformed → FAIL.
- **Alternative satisfiers:** Publishing the guide as a CIS-benchmark-style SCAP/OVAL or OSCAL profile; signal = valid SCAP/OSCAL file. AWS Config conformance pack / GCP SCC posture as machine-readable analog.
- **OSCAL / NIST:** CM-6, SA-5. High: derive from Rev5 High (pending).
- **Module connections:** SCG-artifact tracker; `core/oscal.ts` can model the SCG as an OSCAL component-definition; ajv schema validation.
- **Recommended implementation:** hybrid (artifact + schema validation). Effort: **M**.

### SCG-ENH-VRH — Versioning and Release History  [SHOULD]
- **Track / actor / levels:** both / ENH (Providers) / L:SHOULD M:SHOULD H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider should provide versioning and a release history for the recommended secure default settings (for top-level admin + privileged accounts) as they change over time.
- **Testability:** hybrid
- **Automated validation:** Detect a version identifier + changelog for the SCG. If the SCG is in a git repo or a versioned doc store, read-only detect: a semantic version field in the machine-readable SCG AND ≥2 dated history entries. PASS = current version present AND release-history list non-empty/dated. Git-hosted SCG makes this fully automatable (read commit/tag history read-only).
- **Required permissions & error handling:** Repo read or doc-store read. On no version metadata: FAIL "SCG has no version/changelog".
- **Alternative satisfiers:** Git tags / GitHub Releases on the SCG repo; signal = tag + release list. CHANGELOG.md alongside the SCG.
- **OSCAL / NIST:** CM-2(3), CM-6, SA-5, SA-10. High: derive from Rev5 High (pending).
- **Module connections:** SCG-artifact tracker (version + history fields); could reuse `core/diff-report.ts` to auto-generate the history between published versions.
- **Recommended implementation:** hybrid (artifact metadata check). Effort: **S–M**.

---

# UCM — Using Cryptographic Modules

### UCM-CSX-CMD — Cryptographic Module Documentation  [MUST]
- **Track / actor / levels:** 20x / CSX (Providers) / L:MUST M:MUST H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider must document the cryptographic modules used in each service (or group of services sharing modules) *wherever cryptographic services protect federal customer data* (FRD: agency-uploaded content), including whether each module is **CMVP-validated** or is an *update stream* of such a module. This is the inventory-and-label obligation; UVM is the use obligation.
- **Testability:** hybrid
- **Automated validation:** Enumerate the cryptographic modules in play and label each CMVP status. Concrete read-only checks:
  - **AWS KMS:** `ListKeys` + `DescribeKey` → `KeySpec`/`Origin`/`KeyManager`; AWS KMS HSMs are CMVP-validated (FIPS 140-3 Level 3, cert #4884). Flag `Origin=EXTERNAL`/`CUSTOM_KEY_STORE` for manual review.
  - **GCP Cloud KMS:** `keyRings.cryptoKeys` `protectionLevel` (SOFTWARE=BoringCrypto FIPS 140-3 L1 cert #5104; HSM=FIPS 140-2 L3; EXTERNAL=manual).
  - **AWS ACM:** `ListCertificates`+`DescribeCertificate` → `KeyAlgorithm` (RSA_2048/EC_*); ELB `DescribeSSLPolicies`/listener SSL policy → flag `*-FIPS-*` (AWS-LC FIPS module) vs non-FIPS.
  - PASS = an inventory exists mapping each data-protecting crypto service → module → {validated | update-stream | not-validated}. The collector *builds the inventory*; the human confirms completeness.
- **Required permissions & error handling:** `kms:ListKeys`, `kms:DescribeKey`; `acm:ListCertificates`, `acm:DescribeCertificate`; `elasticloadbalancing:DescribeSSLPolicies`, `:DescribeListeners`; GCP `cloudkms.cryptoKeys.list`, `cloudkms.keyRings.list`. AccessDenied → diagnose exact action (existing helpers). Not-enabled (no KMS/ACM) → WARN, expected.
- **Alternative satisfiers:** Subprocessor attestations (the org uses subprocessors) — a documented inheritance of the subprocessor's CMVP certs; signal = subprocessor crypto attestation in the subprocessors sheet (`core/subprocessors-sheet.ts`).
- **OSCAL / NIST:** SC-13, SC-12, SC-8(1), IA-7, SA-9 (for subprocessors). High: derive from Rev5 High (pending).
- **Module connections:** **New `providers/*/crypto.ts`** (or extend `providers/aws/secrets.ts`, which already reads KMS/ACM) to build a crypto-module inventory with CMVP labels; reuse `core/subprocessors-sheet.ts` for inherited modules.
- **Recommended implementation:** hybrid (collector inventories cloud-native modules; human confirms full coverage incl. app-layer + subprocessors). Effort: **M**.

### UCM-CSX-CAT — Configuration of Agency Tenants  [SHOULD]
- **Track / actor / levels:** 20x / CSX (Providers) / L:SHOULD M:SHOULD H:derived(rev5: controls[] empty — pending)
- **Requirement (plain English):** The Provider should configure agency tenants (FRD: `Agency` = federal executive-branch entity) *by default* to use cryptographic services backed by CMVP-validated modules (or update streams thereof) **when such modules are available**.
- **Testability:** api-testable
- **Automated validation:** Inspect the default configuration applied to agency tenants and confirm it selects validated-module-backed crypto. Concrete checks:
  - **AWS:** default KMS key spec for new tenant resources is a KMS-managed/CMK (validated HSM), not BYOK-external by default; ELB/API Gateway default TLS policy is a `*-FIPS-*` policy; default region uses FIPS endpoints (`*-fips.*.amazonaws.com`) where the tenant requires them.
  - **GCP:** default CMEK `protectionLevel` for agency projects is SOFTWARE(BoringCrypto)/HSM (both validated), not EXTERNAL.
  - PASS = the default-tenant template/baseline selects validated-module crypto for in-scope services, *where available*. Note the "by default + when available" scoping: not-available services are exempt.
- **Required permissions & error handling:** Same KMS/ACM/ELB/GCP-KMS reads as CMD, plus read of the tenant-provisioning baseline (IaC template or org policy). AccessDenied → diagnose exact action. If FIPS endpoint not available in region → WARN, expected (the "when available" clause).
- **Alternative satisfiers:** A landing-zone/provisioning module pinning validated crypto defaults; signal = detected IaC baseline. FIPS-enabled GKE node pools / FIPS AMIs for agency tenants; signal = node-pool/AMI flags.
- **OSCAL / NIST:** SC-13, CM-6, CM-6(1). High: derive from Rev5 High (pending).
- **Module connections:** Extend the new `crypto.ts` to evaluate *default* tenant config (vs UVM which checks *actual* usage); cross-reference SCG-CSO-SDF (secure defaults).
- **Recommended implementation:** collector (api-testable against default config), with IaC baseline as supporting artifact. Effort: **M**.

### UCM-CSX-UVM — Using Validated Cryptographic Modules  [varies: Low MAY / Moderate SHOULD / High MUST]
- **Track / actor / levels:** 20x / CSX (Providers) / L:**MAY** M:**SHOULD** H:**MUST** — **all three are explicitly published** (`source: "20x-machine-readable"`), NOT derived. Top-level `statement` is `null`; the obligation lives in the per-level blocks.
- **Requirement (plain English):** When using cryptographic services to protect federal customer data, the Provider uses cryptographic modules (or update streams of modules) with **active CMVP validations**. The strength scales by impact level: **Low — MAY** (optional/encouraged), **Moderate — SHOULD** (expected unless justified), **High — MUST** (mandatory). The collector must report against the *selected level's* keyword.
- **Testability:** api-testable
- **Automated validation:** For every cryptographic service that protects federal customer data, confirm the backing module has an **active** CMVP validation. Concrete checks (read-only):
  - **AWS KMS:** keys resolve to AWS KMS HSM (CMVP cert #4884, FIPS 140-3 L3, *active*). Flag any key whose backing is `EXTERNAL`/custom key store as needing manual CMVP proof. Note operational caveat: `hsm1.medium` HSM class moved to the CMVP *historical* list on 2026-01-04 — "active validation" now means the `hsm2m.medium` stream; surface this as an advisory.
  - **AWS ACM/ELB:** in-transit protection uses a `*-FIPS-*` SSL policy (AWS-LC FIPS module) for in-scope endpoints; cert `KeyAlgorithm` is an approved algorithm.
  - **GCP Cloud KMS:** `protectionLevel` ∈ {SOFTWARE (BoringCrypto cert #5104, *active*), HSM (FIPS 140-2 L3)}; EXTERNAL → manual.
  - **PASS criterion scales by level:** Low — informational (report coverage %, never FAIL on MAY); Moderate — FAIL only if validated modules are *available but not used* without justification; High — FAIL if *any* in-scope crypto service uses a non-validated / inactive module.
- **Required permissions & error handling:** `kms:ListKeys`, `kms:DescribeKey`, `acm:ListCertificates`, `acm:DescribeCertificate`, `elasticloadbalancing:DescribeSSLPolicies`/`:DescribeListeners`; GCP `cloudkms.cryptoKeys.list`/`.get`, `cloudkms.keyRings.list`. AccessDenied → diagnose exact action via `diagnoseAwsError`/`diagnoseGcpError`. Not-found/not-enabled (no ACM certs, no CMKs) → WARN, expected. Region without FIPS endpoint → note the "when using" + availability nuance.
- **Alternative satisfiers:** Subprocessor inheritance — federal-data crypto handled by a subprocessor whose modules are CMVP-validated; signal = subprocessor CMVP attestation (`core/subprocessors-sheet.ts`). FIPS-mode AWS-LC / OpenSSL FIPS provider in the app layer / FIPS-enabled GKE; signal = build flags / node-pool config (not fully cloud-API-visible — artifact).
- **OSCAL / NIST:** SC-13 (cryptographic protection), SC-12, SC-8/SC-8(1), IA-7 (cryptographic module authentication). High: **explicit published MUST** — use the published High statement; this is the *only* family where High is firmly mandated and numerically/keyword-defined in the dump.
- **Module connections:** Core of the new `providers/*/crypto.ts`; level-aware PASS logic must read the org's selected impact level (Low/Moderate/High) to pick MAY/SHOULD/MUST. Reuse `secrets.ts` KMS/ACM readers + `data.ts` KMS reader.
- **Recommended implementation:** collector (most api-testable item in the 30), level-aware. Rationale: KMS/ACM/TLS specs are directly observable; CMVP status is a static lookup table; only EXTERNAL/app-layer/subprocessor modules fall back to artifact. Effort: **M** (collector + CMVP reference table + level selector).

---

## Cross-cutting implementation notes

1. **PVA-CSX is mostly already built.** `core/pva-collector.ts` already discharges VAL (cadence existence), the spine of PMV (drift/run-history — extend for cadence-gap math), and supplies the inputs every PVA-TPX assessor item consumes. The signed/timestamped/OSCAL output is the *mechanism* that satisfies PVA-TPX-STE's anti-static-evidence bar.
2. **PVA-TPX (10) are assessor obligations** — a CSP read-only collector cannot self-grade them. Treat 8 as "tool feeds assessor inputs" (UNP, PDK, OUC, MME, PEX, STE, PAD, SUM) and 2 as wholly out-of-CSP-scope behavior prohibitions (NOR, SHA). None need a new collector; they need the existing evidence-export package + traceability matrix.
3. **SCG (9) needs a new SCG-artifact tracker** (URL/file registry + content checklist + version/history) — most ENH items hang off the *machine-readable SCG* (MRG) which then powers SDF/CMP comparators against live config. Public-URL liveness (PUB) is the one fully-automatable SCG check.
4. **UCM (3) is the highest-value automation target** — a new `providers/{aws,gcp}/crypto.ts` (extending `secrets.ts`/`data.ts` KMS+ACM readers) builds a CMVP-labeled crypto-module inventory (CMD), checks default tenant config (CAT), and evaluates actual usage with **level-aware MAY/SHOULD/MUST logic** (UVM). Bake in a small CMVP reference table (AWS KMS #4884, AWS-LC FIPS, GCP BoringCrypto #5104) with the 2026 `hsm1.medium`→`hsm2m.medium` historical-list caveat. Subprocessor crypto inheritance is the key alt-satisfier (`core/subprocessors-sheet.ts`).
5. **Level selector:** UVM and PMV are the two requirements where the chosen impact level changes the *keyword/threshold*, so the collector's PASS logic for those two must read the org's selected level. All other 28 are level-invariant in statement (High pending Rev5 controls derivation).

_Sources consulted: AWS FIPS 140-3 (aws.amazon.com/compliance/fips, KMS FIPS 140-3 L3 blog, CMVP cert #4884/#4884-series), ELB security policies (docs.aws.amazon.com ALB/NLB describe-ssl-policies), GCP FIPS 140-2/3 (cloud.google.com/security/compliance/fips-140-2-validated, KMS protection levels, BoringCrypto cert #5104), FedRAMP 20x SCG / RSC (RFC-0015) / PVA (RFC-0017) documentation._
