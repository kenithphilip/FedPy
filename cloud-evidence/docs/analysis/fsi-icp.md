# FSI + ICP — Evidence-Collector Design Analysis

Scope: all 16 **FSI** (FedRAMP Security Inbox) + 9 **ICP** (Incident Communications Procedures) requirements = **25 total**. Source of truth: `cloud-evidence/docs/frmr-requirements.generated.json` (family ∈ {FSI, ICP}) enriched with FRD term definitions from `docs/FRMR.documentation.json`.

> **Honesty note up front.** FSI and ICP are *communications / process* families, not cloud-control families. There is **no cloud API that proves** "we monitor an inbox" or "we emailed FedRAMP within 1 hour." The collector cannot make these PASS by inspecting AWS/GCP/K8s. What the READ-ONLY collector *can* do is: (1) **detect partial automation signals** that make the process credible (an IR/on-call tool wired into the cloud event fabric, a monitored distribution list, a notification-workflow integration, anomaly→alert plumbing); and (2) act as a **process-artifact tracker** that records the required attestation/artifact (documented FSI address + monitoring SLA, IR comms runbook, agency/CISA contact records, dated notification logs) and surfaces it as `process_artifacts_required[]` in the envelope so the human reviewer / Trust Center / Paramify submission carries the proof. Everything below stays strictly read-only.

## Level model (applies to every row)
- **Low / Moderate** come straight from each requirement's `levels.{low,moderate}.applies` in the dump — for all 25, both are `applies: true`.
- **High** is **not** in the dump as an explicit `applies` flag (`levels.high.applies: null`, `source: derived-rev5-pending`). Per the level model, **High = DERIVED from the NIST 800-53 Rev5 High baseline via `controls[]`.** Every FSI/ICP requirement ships with an **empty `controls[]`**, so High is *derived by family mapping* (IR-6 incident reporting, IR-4 handling, IR-8 plan, SI-5 alerts, AC-21 info sharing) rather than per-requirement control IDs. Stated explicitly as `H:derived(rev5: <control or n/a>)` per requirement.

## Actor split (drives testability)
- **FSI-CSO-\*** (8): actor = CSO, `affects: Providers` — the org **must do** these. Trackable/partially-automatable.
- **FSI-FRP-\*** (8): actor = FRP, `affects: FedRAMP` — these are **FedRAMP's obligations**, not the CSP's. The collector does not test FedRAMP's behavior; it records them as **inbound-context / non-applicable-to-CSP** so the level selector doesn't flag the org for something FedRAMP owns. (Two have a thin CSP-side hook: VRE/UFS define *expected sender identities* the org's mail filtering should trust — see TFG/RCV.)
- **ICP-CSX-\*** (9): actor = CSX, `affects: Providers`, track = `20x` only — the org must do these. Highest automation potential (notification plumbing, machine-readable reports).

---

## FSI — coverage table

| ID | name | L/M/H | testability | primary signal |
|----|------|-------|-------------|----------------|
| FSI-CSO-INB | Maintain a FedRAMP Security Inbox | ✓/✓/derived | process-artifact | documented FSI address + monitored mailbox/DL detection |
| FSI-CSO-RCV | Receive Email Without Disruption | ✓/✓/derived | hybrid | mail-flow / no-block attestation; SES/Workspace inbound config |
| FSI-CSO-TFG | Trust @fedramp.gov and @gsa.gov | ✓/✓/derived | hybrid | allowlist/quarantine-exception attestation for the two domains |
| FSI-CSO-NOC | Notification of Changes | ✓/✓/derived | process-artifact | dated record of info@fedramp.gov change-notice email |
| FSI-CSO-ACK | Acknowledge Receipt | ✓/✓/derived | hybrid | auto-acknowledge rule / ticketing auto-reply detection |
| FSI-CSO-EMR | Emergency Message Routing | ✓/✓/derived | hybrid | mail rule routing Emergency→senior security official + on-call |
| FSI-CSO-CRA | Complete Required Actions | ✓/✓/derived | process-artifact | per-message completion log within stated timeframe |
| FSI-CSO-IMA | Important Message Actions | ✓/✓/derived | process-artifact | per-message completion log (Important designators) |
| FSI-FRP-VRE | Verified Emails | ✓/✓/derived | process-artifact | FedRAMP obligation; record as inbound context (SPF/DKIM/DMARC) |
| FSI-FRP-CDS | Criticality Designators | ✓/✓/derived | process-artifact | FedRAMP obligation; designator taxonomy reference |
| FSI-FRP-UFS | Use FedRAMP_Security Email in Emergencies | ✓/✓/derived | process-artifact | FedRAMP obligation; expected-sender allowlist seed |
| FSI-FRP-PNT | Public Notice of Emergency Tests | ✓/✓/derived | process-artifact | FedRAMP obligation; non-applicable to CSP |
| FSI-FRP-RQA | Required Actions | ✓/✓/derived | process-artifact | FedRAMP obligation; non-applicable to CSP |
| FSI-FRP-ERT | Elevated Reaction Timeframes | ✓/✓/derived | process-artifact | FedRAMP obligation; supplies CRA/IMA SLA clocks |
| FSI-FRP-COR | Explain Corrective Actions | ✓/✓/derived | process-artifact | FedRAMP obligation; non-applicable to CSP |
| FSI-FRP-RPM | Reaction Metrics | ✓/✓/derived | process-artifact | FedRAMP obligation (MAY); non-applicable to CSP |

## ICP — coverage table

| ID | name | L/M/H | testability | primary signal |
|----|------|-------|-------------|----------------|
| ICP-CSX-IRF | Incident Reporting to FedRAMP | ✓/✓/derived | process-artifact | dated email-to-fedramp_security log; 1h-clock attestation |
| ICP-CSX-IRA | Incident Reporting to Agencies | ✓/✓/derived | process-artifact | per-agency contact registry + 1h notification records |
| ICP-CSX-IRC | Incident Reporting to CISA | ✓/✓/derived | hybrid | CISA IRF submission record; attack-vector decision log |
| ICP-CSX-ICU | Incident Updates | ✓/✓/derived | hybrid | daily-cadence update log until resolved; reminder-job detection |
| ICP-CSX-RPT | Incident Report Availability | ✓/✓/derived | process-artifact | Trust Center / secure-repo URL hosting reports |
| ICP-CSX-RSD | Responsible Disclosure (MUST NOT) | ✓/✓/derived | process-artifact | disclosure-review policy + redaction sign-off record |
| ICP-CSX-FIR | Final Incident Report | ✓/✓/derived | process-artifact | final report w/ 5 required fields; template detection |
| ICP-CSX-AUR | Automated Reporting (SHOULD) | ✓/✓/derived | hybrid | IR/SOAR→notification automation detected (PagerDuty/Opsgenie/Tines) |
| ICP-CSX-HRM | Human + Machine-Readable (SHOULD) | ✓/✓/derived | hybrid | JSON+human report pair; OCSF/machine-readable export detection |

---

## FSI requirements (16)

### FSI-CSO-INB — Maintain a FedRAMP Security Inbox  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a — empty controls[]; map IR-6 / IR-7)
- **Requirement (plain English):** The provider MUST establish and keep running an email address that meets the *FedRAMP Security Inbox* (FRD-FSI) requirements — i.e. an address FedRAMP can reach to send urgent security messages.
- **Testability:** process-artifact (the *existence* of an inbox is declared, not API-provable). Light hybrid lift if the FSI is hosted on org-managed mail infra the collector can see.
- **Automated validation:** No cloud API confirms "this is *the* FedRAMP inbox." Partial automation: if the FSI is an AWS SES inbound / WorkMail / Google Workspace distribution list, detect (a) the address resolves to a **distribution list / shared mailbox with ≥2 recipients** (avoids single-point-of-failure), and (b) it is **not** a personal account. Primary artifact: a recorded `fsi_address`, monitoring-SLA statement, and the most recent quarterly Emergency-Test pass. Tracked as a `process_artifacts_required[]` entry + a config-supplied `fsi_address` field surfaced in the envelope.
- **Required permissions & error handling:** n/a — process artifact. (If SES/Workspace detection is enabled: `ses:DescribeReceiptRuleSet` (AWS, read-only) / Google `admin.directory.group.readonly` — both optional, fail-soft via `diagnoseAwsError`/`diagnoseGcpError` to a warning, never a hard fail.)
- **Alternative satisfiers:** Managed mailbox via Google Workspace shared inbox or M365 shared mailbox routed to a ticket queue (Jira/ServiceNow) — detectable signal: ticket-system inbound-email integration recorded in `ticket-push.ts` config; SES receipt rule → SNS → ticketing.
- **OSCAL / NIST:** controls[] empty; family-map IR-6 (incident reporting), IR-7 (assistance), CP-? n/a. High note: derived from Rev5 High IR baseline, not a per-requirement control.
- **Module connections:** new **process-artifact-tracker** (records `fsi_address` + monitoring SLA); optionally a tiny read-only inbox-detector that can reuse `core/detect/third-party-tools.ts` signal style. `notify.ts` is the consumer that *exercises* the inbox in the Emergency-Test simulation.
- **Recommended implementation:** **process-artifact-tracker** (with optional detector hook). Rationale: the binding fact is a declared, monitored address; cloud signals only corroborate. Effort **S**.

### FSI-CSO-RCV — Receive Email Without Disruption  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a; map IR-6 / SC-7)
- **Requirement (plain English):** The provider MUST be able to receive and react to FedRAMP email *without disruption* and *without FedRAMP having to do anything extra* (no challenge-response gates, no greylisting that bounces FedRAMP, no per-message allowlist requests).
- **Testability:** hybrid — the *outcome* is process, but mail-flow configuration is partially inspectable.
- **Automated validation:** If FSI mail flows through org-controlled infra, detect absence of disruptive controls: no challenge-response / no aggressive quarantine that would block fedramp.gov/gsa.gov, inbound delivery enabled. On AWS SES: receipt rules don't drop the sender; on Workspace: domains in TFG allowlist (see FSI-CSO-TFG). Otherwise: attestation that the FSI provider does not require sender verification, plus the quarterly Emergency-Test delivery confirmation as evidence of "no disruption."
- **Required permissions & error handling:** n/a — process artifact for hosted mail; optional `ses:DescribeReceiptRule*` read-only if on SES, fail-soft to warning.
- **Alternative satisfiers:** Mail-security vendor (Proofpoint/Mimecast/Google) with the two FedRAMP domains explicitly allowlisted — detectable only via the vendor's exported config (operator-supplied artifact), not via cloud API.
- **OSCAL / NIST:** controls[] empty; family-map IR-6, SC-7 (boundary protection not blocking trusted senders). High: derived.
- **Module connections:** **process-artifact-tracker**; shares the TFG allowlist artifact.
- **Recommended implementation:** **hybrid** — tracker + optional SES/Workspace read. Rationale: config can corroborate but cannot fully prove. Effort **S**.

### FSI-CSO-TFG — Trust @fedramp.gov and @gsa.gov  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a; map SI-3 / SC-7)
- **Requirement (plain English):** The provider MUST treat any email from `@fedramp.gov` or `@gsa.gov` as genuinely from FedRAMP by default (so it isn't silently spam-filtered); if a message is *confirmed* to be a spoof from a non-FedRAMP party, FSI requirements stop applying to it.
- **Testability:** hybrid — an allowlist/quarantine-exception is a concrete, sometimes-inspectable config.
- **Automated validation:** Where mail filtering is org-controlled and visible: detect an allowlist / safe-sender / quarantine-exception entry for both `fedramp.gov` and `gsa.gov`. SES has no native allowlist concept, so this is mostly vendor config (Workspace `Trusted senders`, M365 connector). Primary: attestation + screenshot/export of the safe-sender rule recorded as a `process_artifacts_required[]` item with the two domains enumerated.
- **Required permissions & error handling:** n/a — process artifact (vendor-side config not reachable read-only via cloud API). If Workspace: `gmail.settings.basic.readonly` optional, fail-soft.
- **Alternative satisfiers:** Mail gateway (Proofpoint/Mimecast) safe-sender policy — operator-supplied export.
- **OSCAL / NIST:** controls[] empty; family-map SI-3 (malicious-code/filter handling), SC-7. High: derived.
- **Module connections:** **process-artifact-tracker**; the recorded domain allowlist also satisfies RCV.
- **Recommended implementation:** **process-artifact-tracker**. Rationale: config lives in the mail vendor, outside the cloud read-only surface. Effort **S**.

### FSI-CSO-NOC — Notification of Changes  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a; map IR-6)
- **Requirement (plain English):** If the FSI address changes, the provider MUST immediately email `info@fedramp.gov` with the CSO name, FedRAMP ID, and the new address.
- **Testability:** process-artifact — a one-off email event, fully outside cloud APIs.
- **Automated validation:** None possible from cloud. The tracker can *detect that a change occurred* by diffing the recorded `fsi_address` across runs (git history of the artifact is the drift archive, consistent with the locked CSX-SUM decision); when the address changes and no `info@fedramp.gov` notice artifact is attached, raise a finding "FSI address changed — confirm change-notice was sent." Primary artifact: the dated outbound email (.eml / screenshot) plus FedRAMP ID.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** None — this is a fixed FedRAMP channel (`info@fedramp.gov`).
- **OSCAL / NIST:** controls[] empty; family-map IR-6. High: derived.
- **Module connections:** **process-artifact-tracker** (with a diff check on `fsi_address` — reuse the diffing pattern from `core/diff-report.ts`).
- **Recommended implementation:** **process-artifact-tracker**. Rationale: event-driven, no cloud surface. Effort **S** (diff hook is the only code).

### FSI-CSO-ACK — Acknowledge Receipt  [SHOULD]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a; map IR-6)
- **Requirement (plain English):** The provider SHOULD *promptly* (FRD-PRO: "without unnecessary delay") and *automatically* acknowledge receipt of messages arriving in the FSI.
- **Testability:** hybrid — "automatically" implies a detectable auto-reply / ticket-creation mechanism.
- **Automated validation:** Detect an auto-acknowledge mechanism: SES receipt rule → Lambda/SNS auto-reply, Workspace vacation/auto-reply on the FSI, or a ticketing inbound-email rule that fires an auto-response. Where the FSI feeds a ticket queue, the inbound-email→auto-reply config is the signal. Primary artifact: the auto-reply rule export or a sample acknowledgment from the last Emergency Test.
- **Required permissions & error handling:** n/a — process artifact; optional SES/Workspace read, fail-soft.
- **Alternative satisfiers:** Ticketing auto-response (ServiceNow/Jira inbound email action) — detectable via `ticket-push.ts` config presence (already a known integration).
- **OSCAL / NIST:** controls[] empty; family-map IR-6. High: derived.
- **Module connections:** **process-artifact-tracker**; cross-reference `ticket-push.ts` config.
- **Recommended implementation:** **hybrid**. Rationale: SHOULD + an automation that is sometimes detectable. Effort **S**.

### FSI-CSO-EMR — Emergency Message Routing  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a; map IR-4 / IR-6)
- **Requirement (plain English):** The provider MUST route any **Emergency**-designated message to a *senior security official* for awareness. (Emergency designator defined in FSI-FRP-CDS.)
- **Testability:** hybrid — routing-to-a-person is a mail rule + on-call escalation, partially detectable.
- **Automated validation:** Detect routing plumbing: a mail filter that forwards subject-line `Emergency`/`Emergency Test` to a senior-security DL, and/or the FSI wired into an on-call escalation (PagerDuty/Opsgenie) so a paged human is reached. This overlaps strongly with the existing **INR-RIR** alert-routing detection in `providers/aws/logging.ts` (CloudWatch subscription filters → SNS → PagerDuty, EventBridge → SOAR) and the PagerDuty rule in `third-party-tools.ts`. Primary artifact: the routing rule + the named senior security official + a sample escalation from the last Emergency Test.
- **Required permissions & error handling:** n/a for the mail rule; for the on-call wiring, reuse INR-RIR's existing read-only calls (`logs:DescribeSubscriptionFilters`, EventBridge target reads) with their existing `diagnoseAwsError` handling.
- **Alternative satisfiers:** PagerDuty / Opsgenie escalation policy targeting the security on-call — **already detected** by `third-party-tools.ts` PagerDuty rule (`satisfies_ksis: [INR-RIR, INR-AAR]`); extend `satisfies_ksis` to include `FSI-CSO-EMR`.
- **OSCAL / NIST:** controls[] empty; family-map IR-4 (handling), IR-6. High: derived.
- **Module connections:** extend **`providers/aws/logging.ts` collectInrRir** alt-satisfier set + **`core/detect/third-party-tools.ts`** (add FSI-CSO-EMR to PagerDuty/Opsgenie `satisfies_ksis`); plus process-artifact for the mail-side rule.
- **Recommended implementation:** **hybrid**. Rationale: the on-call leg is genuinely detectable via existing INR-RIR plumbing; the mail-filter leg is an artifact. Effort **S** (reuse INR-RIR), **M** if adding a dedicated mail-rule reader.

### FSI-CSO-CRA — Complete Required Actions  [MUST]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a; map IR-4)
- **Requirement (plain English):** The provider MUST complete the required actions in **Emergency** or **Emergency Test** messages within the timeframe stated in the message (default SLAs from FSI-FRP-ERT: High ≤12h; Moderate by 3pm ET 2nd business day; Low by 3pm ET 3rd business day).
- **Testability:** process-artifact — completion is a human/operational outcome, not a cloud state.
- **Automated validation:** None directly. The tracker records, per Emergency message: received-at, stated deadline, completed-at, evidence link — and computes met/missed against the FSI-FRP-ERT clock. If the required action happens to be a config change (e.g. "disable X"), a *subsequent* normal collector run may corroborate the end-state, but the collector must not claim it proves timeliness. Primary artifact: the per-message completion log.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Ticketing SLA tracking (ServiceNow SIR / Jira) with the message logged as a ticket and SLA timer — detectable via `ticket-push.ts` config; the SLA record is the artifact.
- **OSCAL / NIST:** controls[] empty; family-map IR-4. High: derived.
- **Module connections:** **process-artifact-tracker** (message-completion ledger); SLA clock seeded from FSI-FRP-ERT.
- **Recommended implementation:** **process-artifact-tracker**. Rationale: outcome is operational. Effort **S**.

### FSI-CSO-IMA — Important Message Actions  [SHOULD]
- **Track / actor / levels:** both / CSO / L:✓ M:✓ H:derived(rev5: n/a; map IR-4)
- **Requirement (plain English):** The provider SHOULD complete the required actions in **Important**-designated messages within the message's stated (reasonable) timeframe.
- **Testability:** process-artifact — same shape as CRA, lower (SHOULD) priority and looser timeframes.
- **Automated validation:** Same ledger as CRA, filtered to `Important` designator. No cloud signal. Primary artifact: per-message completion log.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Ticketing SLA tracking (as CRA).
- **OSCAL / NIST:** controls[] empty; family-map IR-4. High: derived.
- **Module connections:** **process-artifact-tracker** (same ledger as CRA, shared schema).
- **Recommended implementation:** **process-artifact-tracker**. Rationale: shares CRA's mechanism. Effort **S** (reuse CRA).

### FSI-FRP-VRE — Verified Emails  [MUST]
- **Track / actor / levels:** both / **FRP** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** **FedRAMP** (not the CSP) MUST send from an official `@fedramp.gov`/`@gsa.gov` address with properly configured SPF, DKIM, and DMARC.
- **Testability:** process-artifact — and it is **FedRAMP's** obligation, not the org's.
- **Automated validation:** The collector does **not** test FedRAMP's mail authentication. It records VRE as **inbound context** that informs the org's own TFG/RCV posture: the org may *verify* that received FedRAMP mail passed SPF/DKIM/DMARC (recorded in mail headers) as supporting evidence for "I correctly trusted a verified sender." Optionally surfaced as a reference, marked `actor: FedRAMP — not CSP-applicable`.
- **Required permissions & error handling:** n/a — not a CSP obligation.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** controls[] empty. High: derived. Map (FedRAMP-side) SC-8 / IA-? — informational only.
- **Module connections:** **process-artifact-tracker** records as non-applicable-to-CSP context; level selector must exclude FRP-actor items from the org's gap count.
- **Recommended implementation:** **process-artifact-tracker** (context-only). Rationale: FedRAMP obligation. Effort **S**.

### FSI-FRP-CDS — Criticality Designators  [MUST]
- **Track / actor / levels:** both / **FRP** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** **FedRAMP** MUST signal message criticality in the subject line using one of: **Emergency** (urgent — potential incident/crisis), **Emergency Test** (urgent — tests the FSI), **Important** (address it, reasonable timeframe). Messages without a designator are general comms needing no elevated reaction.
- **Testability:** process-artifact — FedRAMP's obligation; defines the taxonomy the org's EMR/CRA/IMA rules key off.
- **Automated validation:** Not tested against FedRAMP. The collector **stores the designator taxonomy as reference data** so EMR routing rules and the CRA/IMA completion ledger can classify inbound messages consistently. Surfaced as a static reference block, `actor: FedRAMP — not CSP-applicable`.
- **Required permissions & error handling:** n/a.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** controls[] empty. High: derived.
- **Module connections:** **process-artifact-tracker** reference data feeding EMR/CRA/IMA.
- **Recommended implementation:** **process-artifact-tracker** (reference/context). Rationale: FedRAMP obligation; useful as classification seed. Effort **S**.

### FSI-FRP-UFS — Use FedRAMP_Security Email in Emergencies  [MUST]
- **Track / actor / levels:** both / **FRP** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** **FedRAMP** MUST send Emergency / Emergency Test messages from `fedramp_security@gsa.gov` OR `fedramp_security@fedramp.gov`.
- **Testability:** process-artifact — FedRAMP's obligation; thin CSP hook = expected-sender seed.
- **Automated validation:** Not tested against FedRAMP. The two addresses are **recorded as the expected-Emergency-sender allowlist** that seeds the org's TFG safe-sender rule and EMR routing trigger. These are the *same* addresses the org sends *to* for ICP-CSX-IRF (reverse direction). Surfaced as reference, `actor: FedRAMP — not CSP-applicable`.
- **Required permissions & error handling:** n/a.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** controls[] empty. High: derived.
- **Module connections:** **process-artifact-tracker**; seeds TFG allowlist and the IRF outbound target.
- **Recommended implementation:** **process-artifact-tracker** (context/seed). Rationale: FedRAMP obligation, but the addresses are operationally load-bearing for EMR + IRF. Effort **S**.

### FSI-FRP-PNT — Public Notice of Emergency Tests  [MUST]
- **Track / actor / levels:** both / **FRP** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** **FedRAMP** MUST post a public notice ≥10 business days before sending an Emergency Test, including the likely expected actions and timeframes.
- **Testability:** process-artifact — purely FedRAMP's obligation.
- **Automated validation:** None — not a CSP obligation. Recorded as `actor: FedRAMP — not CSP-applicable`. (Operationally, the org may *watch* for these notices to pre-stage, but that's optional and untracked.)
- **Required permissions & error handling:** n/a.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** controls[] empty. High: derived.
- **Module connections:** **process-artifact-tracker** (non-applicable marker).
- **Recommended implementation:** **process-artifact-tracker** (context-only). Rationale: FedRAMP obligation. Effort **S**.

### FSI-FRP-RQA — Required Actions  [MUST]
- **Track / actor / levels:** both / **FRP** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** **FedRAMP** MUST clearly state the required actions in the body of any message that requires an elevated reaction.
- **Testability:** process-artifact — FedRAMP's obligation.
- **Automated validation:** None — not a CSP obligation. Recorded as `actor: FedRAMP — not CSP-applicable`. (It is the source of the "action" field in the org's CRA/IMA ledger.)
- **Required permissions & error handling:** n/a.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** controls[] empty. High: derived.
- **Module connections:** **process-artifact-tracker** (non-applicable; feeds CRA/IMA ledger fields).
- **Recommended implementation:** **process-artifact-tracker** (context-only). Effort **S**.

### FSI-FRP-ERT — Elevated Reaction Timeframes  [MUST]
- **Track / actor / levels:** both / **FRP** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** **FedRAMP** MUST state the expected completion timeframe; default estimated resolution times for Emergency/Emergency Test: **High Impact ≤12 hours**; **Moderate Impact by 3:00pm ET on the 2nd business day**; **Low Impact by 3:00pm ET on the 3rd business day** (FRD-CAE: catastrophic adverse effect drives the High urgency).
- **Testability:** process-artifact — FedRAMP's obligation; but it supplies the **SLA clock** the org's CRA/IMA ledger measures against.
- **Automated validation:** Not tested against FedRAMP. The three default timeframes are **encoded as the SLA table** the CRA/IMA completion ledger uses to compute met/missed (level-aware: the org's authorization impact level picks the row). Surfaced as reference, `actor: FedRAMP — not CSP-applicable`.
- **Required permissions & error handling:** n/a.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** controls[] empty. High: derived.
- **Module connections:** **process-artifact-tracker** SLA reference table consumed by CRA/IMA.
- **Recommended implementation:** **process-artifact-tracker** (context/SLA seed). Rationale: FedRAMP obligation but operationally critical to CRA timing. Effort **S**.

### FSI-FRP-COR — Explain Corrective Actions  [MUST]
- **Track / actor / levels:** both / **FRP** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** **FedRAMP** MUST state, in elevated-reaction messages, the corrective actions that follow failure (ranging from negative Marketplace ratings to suspension of authorization).
- **Testability:** process-artifact — FedRAMP's obligation.
- **Automated validation:** None — not a CSP obligation. Recorded as `actor: FedRAMP — not CSP-applicable`. (Context for risk-weighting CRA misses: a missed Emergency action can mean ≥30-day Marketplace suspension — surfaced as a severity hint on CRA findings.)
- **Required permissions & error handling:** n/a.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** controls[] empty. High: derived.
- **Module connections:** **process-artifact-tracker** (non-applicable; severity hint for CRA).
- **Recommended implementation:** **process-artifact-tracker** (context-only). Effort **S**.

### FSI-FRP-RPM — Reaction Metrics  [MAY]
- **Track / actor / levels:** both / **FRP** / L:✓ M:✓ H:derived(rev5: n/a)
- **Requirement (plain English):** **FedRAMP** MAY track and publicly publish how long CSPs take to act on elevated-reaction messages.
- **Testability:** process-artifact — FedRAMP's discretionary (MAY) activity.
- **Automated validation:** None — not a CSP obligation. Recorded as `actor: FedRAMP — not CSP-applicable`. Motivates the org to keep an accurate CRA/IMA ledger (the org's own metrics mirror what FedRAMP may publish).
- **Required permissions & error handling:** n/a.
- **Alternative satisfiers:** n/a.
- **OSCAL / NIST:** controls[] empty. High: derived.
- **Module connections:** **process-artifact-tracker** (non-applicable marker).
- **Recommended implementation:** **process-artifact-tracker** (context-only). Effort **S**.

---

## ICP requirements (9)

### ICP-CSX-IRF — Incident Reporting to FedRAMP  [MUST]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a — empty controls[]; map IR-6)
- **Requirement (plain English):** The provider MUST *responsibly report* an **Incident** (FRD-INT: per 44 USC §3552(b)(2), an event jeopardizing CIA of federal customer data) to FedRAMP **within 1 hour of identification** by emailing `fedramp_security@fedramp.gov` or `fedramp_security@gsa.gov`.
- **Testability:** process-artifact — the act of emailing within 1h is not cloud-observable.
- **Automated validation:** None directly. The tracker records, per incident: identified-at, reported-to-FedRAMP-at, 1h-met flag, the .eml/message-id of the notification. Partial automation: if the org wires incident detection (GuardDuty/Security Command Center/SIEM) → notification automation, the **detection→page latency** is detectable via the INR-RIR plumbing and corroborates a fast clock — but the collector must not claim it proves the email was sent. Primary artifact: dated notification record + 1h attestation.
- **Required permissions & error handling:** n/a — process artifact. (Detection-latency corroboration reuses INR-RIR read-only calls + `diagnoseAwsError`.)
- **Alternative satisfiers:** SOAR auto-notify (Tines/Torq) that emails `fedramp_security@…` on incident open — detectable via SOAR signal in `third-party-tools.ts`; export of the playbook is the artifact. See ICP-CSX-AUR.
- **OSCAL / NIST:** controls[] empty; family-map IR-6 (incident reporting). High: derived from Rev5 High IR-6 baseline.
- **Module connections:** **process-artifact-tracker** (incident-notification ledger); corroborated by `providers/aws/logging.ts` (INR-RIR) latency; `notify.ts` is the org's *internal* alerting analog (not the FedRAMP channel itself).
- **Recommended implementation:** **hybrid** — tracker (binding) + INR-RIR corroboration. Rationale: the report is an email, but automation latency is real evidence. Effort **M**.

### ICP-CSX-IRA — Incident Reporting to Agencies  [MUST]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a; map IR-6)
- **Requirement (plain English):** The provider MUST report incidents to **all agency customers** (FRD-AGY) **within 1 hour of identification**, using each agency's provided incident-communications point of contact.
- **Testability:** process-artifact — depends on a maintained per-agency contact registry + outbound notifications.
- **Automated validation:** None directly. The tracker maintains an **agency-contact registry** (agency, FedRAMP-authorization, incident POC, channel) and, per incident, records a notification row per agency with timestamps + 1h-met. Gap finding: agencies with no recorded POC. Partial automation: a notification-workflow integration (PagerDuty stakeholder notifications, ServiceNow customer-comms) that fans out to the agency list is detectable as a wired channel. Primary artifact: contact registry + per-incident per-agency notification log.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Status-page / customer-comms tool (Statuspage, ServiceNow Customer Service) broadcasting to agency contacts — operator-supplied config + send logs.
- **OSCAL / NIST:** controls[] empty; family-map IR-6, AC-21 (info sharing). High: derived.
- **Module connections:** **process-artifact-tracker** (agency-contact registry + notification ledger). Conceptually parallels the subprocessors Google Sheet pattern (`core/subprocessors-sheet.ts`) — the agency registry could be a read-only Sheet too.
- **Recommended implementation:** **process-artifact-tracker** (optionally backed by a read-only registry source). Rationale: the registry + dated sends are the proof. Effort **M**.

### ICP-CSX-IRC — Incident Reporting to CISA  [MUST]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a; map IR-6)
- **Requirement (plain English):** The provider MUST report to **CISA within 1 hour of identification** *if* the incident is confirmed/suspected to result from an attack vector in the CISA taxonomy, following the CISA Federal Incident Notification Guidelines, via the CISA Incident Reporting System (`myservices.cisa.gov/irf`).
- **Testability:** hybrid — conditional (attack-vector gated) + an external portal submission; the *decision* and the submission record are artifacts, but the attack-vector classification can be partly informed by detection tooling.
- **Automated validation:** The tracker records, per incident: attack-vector classification (against the CISA taxonomy), the CISA-applicable yes/no decision + rationale, CISA submission timestamp + IRF tracking number, 1h-met. Partial automation: GuardDuty/Security Command Center finding *types* and SIEM detections can **suggest** the attack vector (e.g. "credential access," "exploitation of public-facing app") to pre-populate the classification — read-only detection metadata, never an auto-submission. Primary artifact: attack-vector decision log + CISA IRF confirmation.
- **Required permissions & error handling:** n/a for the submission; optional read-only finding-type reads (`guardduty:GetFindings` AWS / SCC `securitycenter.findings.list` GCP) to seed the vector hint — fail-soft via diagnostics.
- **Alternative satisfiers:** SOAR playbook that files the CISA IRF (some orgs automate the IRF web form via API) — playbook export + IRF confirmation as artifact.
- **OSCAL / NIST:** controls[] empty; family-map IR-6, IR-6(1)/(2) (automated reporting). High: derived.
- **Module connections:** **process-artifact-tracker** (CISA decision/submission ledger) + optional read-only finding-type reader for vector hints (extend `providers/*/logging.ts`).
- **Recommended implementation:** **hybrid**. Rationale: conditional logic + external submission, but detection tooling can seed the attack-vector decision. Effort **M**.

### ICP-CSX-ICU — Incident Updates  [MUST]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a; map IR-6)
- **Requirement (plain English):** Until the incident is resolved and recovery is complete, the provider MUST update **all necessary parties** (FRD-ANP: at least FedRAMP, CISA if applicable, and all agency customers) **at least once per calendar day**.
- **Testability:** hybrid — a recurring cadence obligation; the *cadence mechanism* (reminder/scheduler) is detectable, the content is artifact.
- **Automated validation:** The tracker records an update timeline per open incident and flags any calendar day with no recorded update to a required party until `resolved_at`. Partial automation: a daily reminder job (scheduled task / cron / PagerDuty recurring notification) that prompts the update is detectable as a wired cadence control. Primary artifact: per-day update log + recipient list reconciled against the FRD-ANP party set.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Status-page incident with daily update posts; ServiceNow major-incident comms cadence — operator-supplied logs.
- **OSCAL / NIST:** controls[] empty; family-map IR-6, IR-4. High: derived.
- **Module connections:** **process-artifact-tracker** (update-cadence ledger; daily-gap detector). Shares the FRD-ANP party set with IRA/IRF/IRC.
- **Recommended implementation:** **process-artifact-tracker** (with cadence-gap finding). Rationale: cadence is a ledger computation. Effort **M**.

### ICP-CSX-RPT — Incident Report Availability  [MUST]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a; map IR-6 / AC-21)
- **Requirement (plain English):** The provider MUST make incident-report information available in their secure FedRAMP repository (e.g. USDA Connect) or **Trust Center** (FRD-TRC: the definitive, FedRAMP-compatible authorization-data repository).
- **Testability:** process-artifact — availability in an external repo/Trust Center, outside cloud APIs.
- **Automated validation:** None directly. The tracker records the Trust Center / secure-repo URL and, per incident, whether the report was posted there (link + posted-at). Partial automation: if the Trust Center is self-hosted on org cloud (e.g. an S3 static site / GCS bucket behind auth), a read-only existence check of the report object is possible — but most Trust Centers are SaaS (SafeBase/Vanta Trust). Primary artifact: repository URL + per-incident posted-report link.
- **Required permissions & error handling:** n/a — process artifact; optional read-only object-existence check (`s3:GetObject`/`storage.objects.get`) if self-hosted, fail-soft.
- **Alternative satisfiers:** SafeBase / Vanta Trust Center / USDA Connect — operator-supplied URL + access screenshot.
- **OSCAL / NIST:** controls[] empty; family-map IR-6, AC-21. High: derived.
- **Module connections:** **process-artifact-tracker** (repo URL + posting ledger). Same Trust Center concept referenced elsewhere in the envelope's `customer_visible` notes.
- **Recommended implementation:** **process-artifact-tracker**. Rationale: hosting lives outside the read-only cloud surface in most cases. Effort **S**.

### ICP-CSX-RSD — Responsible Disclosure  [MUST NOT]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a; map AC-21 / IR-6)
- **Requirement (plain English):** The provider **MUST NOT** irresponsibly disclose sensitive incident details that would *likely* (FRD-LKY: reasonable probability given context) increase the incident's impact — **but MUST** still disclose enough for informed risk-based decisions to all necessary parties (FRD-ANP). A balance/redaction obligation.
- **Testability:** process-artifact — a judgment + review obligation, not cloud-observable.
- **Automated validation:** None. The tracker records a disclosure-review policy reference and, per outbound incident communication, a sign-off that a reviewer balanced "enough to decide" vs. "not so much it worsens impact" (e.g. exploit details withheld, scope/impact disclosed). This is a *negative* (MUST NOT) requirement: evidence is the existence of the review gate, not a passing scan. Primary artifact: disclosure-review policy + per-incident redaction/approval record.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** Legal/comms review workflow in ticketing (approval step on incident-comms tickets) — detectable via `ticket-push.ts` workflow config; the approval record is the artifact.
- **OSCAL / NIST:** controls[] empty; family-map AC-21 (info sharing), IR-6, PM-? n/a. High: derived.
- **Module connections:** **process-artifact-tracker** (disclosure-review gate + per-comm sign-off).
- **Recommended implementation:** **process-artifact-tracker**. Rationale: pure judgment/governance control. Effort **S**.

### ICP-CSX-FIR — Final Incident Report  [MUST]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a; map IR-6 / IR-4)
- **Requirement (plain English):** Once the incident is resolved and recovery complete, the provider MUST provide a **final report** describing at least: **(1) What occurred, (2) Root cause, (3) Response, (4) Lessons learned, (5) Changes needed.** (Relates to FRD-VLR Vulnerability Response: the systematic manage/report lifecycle.)
- **Testability:** process-artifact — a document with required sections; structural completeness is checkable, content is human.
- **Automated validation:** None at the cloud layer. The tracker validates that each resolved incident has a final report present and that the report contains the **5 required fields** (schema/template completeness check — a structural lint, not content judgment). Partial automation: detect a standard final-report template in the ticketing system (ServiceNow post-incident review / Jira PIR template) as evidence the structure is enforced. Primary artifact: the final report (links/attachment) with the 5-field schema satisfied.
- **Required permissions & error handling:** n/a — process artifact.
- **Alternative satisfiers:** ServiceNow Post-Incident Review / Jira PIR / Blameless / Incident.io retro export — detectable via ticketing config; export is the artifact.
- **OSCAL / NIST:** controls[] empty; family-map IR-6, IR-4 (lessons learned). High: derived.
- **Module connections:** **process-artifact-tracker** (final-report schema check — reuse the structural-validation pattern from `core/schema.ts`/ajv). Pairs with HRM for the machine-readable variant.
- **Recommended implementation:** **process-artifact-tracker** (with 5-field schema lint). Rationale: structural completeness is the one automatable angle. Effort **S–M**.

### ICP-CSX-AUR — Automated Reporting  [SHOULD]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a; map IR-6(1))
- **Requirement (plain English):** The provider SHOULD use **automated mechanisms** to report incidents and provide updates to **all necessary parties** including CISA (FRD-ANP).
- **Testability:** hybrid — "automated mechanism" is exactly the kind of wired tooling the collector already detects.
- **Automated validation:** **Best automation candidate in the family.** Detect IR/notification automation: SOAR (Tines/Torq — already in `third-party-tools.ts`), PagerDuty/Opsgenie notification rules, EventBridge/SNS → notification Lambda, ServiceNow SIR auto-notify, GuardDuty/SCC → notification pipeline. The existing **INR-RIR** alert-routing detector and the `third-party-tools.ts` SOAR/PagerDuty rules already surface most of this — extend their `satisfies_ksis` to include `ICP-CSX-AUR`. Finding: PASS-ish if ≥1 automated incident-notification path is wired; otherwise SHOULD-gap. Primary signal: detected SOAR/on-call/event-pipeline integration.
- **Required permissions & error handling:** reuse INR-RIR's read-only calls (`logs:DescribeSubscriptionFilters`, EventBridge target reads, optional `guardduty:GetDetector`) with existing `diagnoseAwsError`/`diagnoseGcpError`.
- **Alternative satisfiers:** Tines/Torq/Swimlane SOAR, PagerDuty Event Orchestration, ServiceNow Flow — **already detected**; just map them to AUR.
- **OSCAL / NIST:** controls[] empty; family-map IR-6(1) (automated incident reporting). High: derived.
- **Module connections:** extend **`providers/aws/logging.ts` collectInrRir** + **`core/detect/third-party-tools.ts`** (add `ICP-CSX-AUR` to SOAR/PagerDuty/Opsgenie `satisfies_ksis`); tracker records the SHOULD attestation.
- **Recommended implementation:** **hybrid** — detector-driven, leaning on existing INR-RIR/3pp plumbing. Rationale: genuinely detectable automation. Effort **S** (mostly reuse).

### ICP-CSX-HRM — Human and Machine-Readable  [SHOULD]
- **Track / actor / levels:** 20x / CSX / L:✓ M:✓ H:derived(rev5: n/a; map IR-6 / SI-5)
- **Requirement (plain English):** The provider SHOULD make incident-report information available in **consistent human-readable AND machine-readable** formats (FRD-MRD: machine-readable = computer-processable without human intervention, no semantic loss).
- **Testability:** hybrid — the existence of a machine-readable export is a concrete, checkable format property.
- **Automated validation:** The tracker checks that each incident report exists in both a human-readable form (PDF/HTML/Markdown) and a machine-readable form (JSON/OSCAL/OCSF) with a consistent schema across incidents. Partial automation: detect a machine-readable emission path — the collector's own **`core/oscal.ts`** (OSCAL Assessment Results) and **`core/siem-push.ts`** (OCSF) already prove the org can emit machine-readable security data; an incident-report JSON schema fits the same pattern. Primary signal: presence of a JSON/OSCAL incident export + matching human report.
- **Required permissions & error handling:** n/a — process artifact (format check on supplied reports).
- **Alternative satisfiers:** Incident.io / ServiceNow exporting both PDF and JSON; OCSF incident objects to SIEM — detectable via the existing OCSF push config (`siem-push.ts`).
- **OSCAL / NIST:** controls[] empty; family-map IR-6, SI-5 (alerts/advisories in usable form). High: derived.
- **Module connections:** **process-artifact-tracker** (dual-format check) + reuse `core/oscal.ts` / `core/siem-push.ts` machine-readable patterns; pairs with FIR (the FIR final report is a prime candidate for dual-format).
- **Recommended implementation:** **hybrid**. Rationale: SHOULD + the machine-readable leg aligns with existing OSCAL/OCSF emitters. Effort **S–M**.

---

## Cross-cutting implementation notes

1. **One shared process-artifact-tracker module** should back nearly all 25. Suggested home: `cloud-evidence/core/process-artifact-tracker.ts` emitting the standard `EvidenceFile` envelope with `scope: 'PROCESS'`, `process_artifacts_required[]` populated, and `findings[]` that are attestation-state (artifact present/absent, SLA met/missed, schema complete) rather than cloud findings. This keeps FSI/ICP first-class in OSCAL output, the HTML report, Paramify push, and drift detection without violating read-only.
2. **Reuse, don't rebuild, the automation detectors.** EMR, IRF (corroboration), AUR, and HRM all lean on existing assets: `providers/aws/logging.ts::collectInrRir` (alert-routing plumbing), `core/detect/third-party-tools.ts` (PagerDuty/SOAR signatures — just widen `satisfies_ksis`), `core/oscal.ts` + `core/siem-push.ts` (machine-readable proof). Minimal new code.
3. **Actor-aware level selector.** The 8 **FSI-FRP-\*** items are FedRAMP's obligations (`affects: FedRAMP`). The selector must mark them non-applicable to the org's gap count (record as context/reference), or the org gets dinged for things it cannot control. Several still seed CSP-side data (ERT→SLA clocks, UFS→sender allowlist, CDS→designator taxonomy).
4. **Shared data sets.** FRD-ANP "all necessary parties" (FedRAMP + CISA-if-applicable + all agency customers) is the recipient set reused by IRF/IRA/IRC/ICU/RSD. The agency-contact registry (IRA) could be a read-only Google Sheet, mirroring the locked subprocessors-sheet decision.
5. **Read-only is preserved throughout.** No new write paths. Optional corroboration reads (SES/Workspace/GuardDuty/SCC/S3-GCS existence) are all `Get*`/`List*`/`Describe*` and fail-soft through `error-diagnostics.ts`; they never gate a PASS, only enrich evidence.

## Testability tally (total = 25)
- **api-testable = 0.** No FSI/ICP requirement is provable by cloud API alone — these are communications/process families.
- **process-artifact = 16:** FSI-CSO-INB, FSI-CSO-NOC, FSI-CSO-CRA, FSI-CSO-IMA, FSI-FRP-VRE, FSI-FRP-CDS, FSI-FRP-UFS, FSI-FRP-PNT, FSI-FRP-RQA, FSI-FRP-ERT, FSI-FRP-COR, FSI-FRP-RPM, ICP-CSX-IRA, ICP-CSX-RPT, ICP-CSX-RSD, ICP-CSX-FIR.
- **hybrid = 9:** FSI-CSO-RCV, FSI-CSO-TFG, FSI-CSO-ACK, FSI-CSO-EMR, ICP-CSX-IRF, ICP-CSX-IRC, ICP-CSX-ICU, ICP-CSX-AUR, ICP-CSX-HRM (artifact + a detectable automation/config signal).
