# LOOP-G — AFR Family (FedRAMP 20x Deliverables)

> Self-contained spec. A future session may resume LOOP-G work by reading
> only (1) `cloud-evidence/CLAUDE.md` (REO standard), (2) this file, and
> (3) `CHANGELOG.md` "Unreleased". No other context required.
>
> Author: planning pass on 2026-06-05. R1 classification
> (`docs/AFR-FAMILY-CLASSIFICATION.md`) is already locked. All 10 AFR-*
> families are REQUIRED at Moderate. LOOP-G ships emitters/integrations
> for the 6 families that are NOT already collector-covered (PVA, VDR,
> UCM, SCN have existing collectors and are out of scope here).

---

## 1. Why this loop exists

### The gap

R1 (`docs/AFR-FAMILY-CLASSIFICATION.md`) confirmed all 10 AFR-* families
are REQUIRED at Moderate — 85 MUST entries across 160 total. Today the
codebase has cloud-side collectors for:

- AFR-PVA — `core/pva-collector.ts` + `core/csx-sum-aggregator.ts`
- AFR-VDR — `providers/{aws,gcp,azure}/vdr-scan.ts` + `core/kev-feed.ts` + `core/vdr-ledger.ts`
- AFR-UCM — `providers/{aws,gcp}/crypto.ts` + `providers/azure/crypto.ts`
- AFR-SCN — `core/scn-classifier.ts` (LOOP-E.E6 will add the formal .docx emitter)

Partial scaffolds exist for:

- AFR-ADS — `core/ads-probe.ts` (URL probe only, not a publication artifact)
- AFR-MAS — `core/mas-reconcile.ts` (set-diff only, not a scope document)
- AFR-SCG — `core/scg-comparator.ts` + `providers/{aws,gcp,azure}/reference-arch.ts` (settings diff only, not a published guide)

The 6 families with no end-to-end emitter or with a partial scaffold that
does NOT produce the FedRAMP-required deliverable are:

| Slice | Family | Why CSP-actionable | MUSTs | Existing scaffold |
|---|---|---|---|---|
| G.G1 | AFR-FSI | CSP must own the security inbox endpoint + receipt SLA | 6 CSO MUSTs | none |
| G.G2 | AFR-ICP | CSP must own incident comms templates + routing | 6 CSX MUSTs | none |
| G.G3 | AFR-ADS | CSP must publish authorization data | 6 CSO/CSX MUSTs | `ads-probe.ts` (probe only) |
| G.G4 | AFR-MAS | CSP must publish the scope doc + info-flow + 3rd-party list | 4 CSO MUSTs | `mas-reconcile.ts` (diff only) |
| G.G5 | AFR-SCG | CSP must publish the Secure Configuration Guide + use instructions | 2 CSO MUSTs | `scg-comparator.ts` + `reference-arch.ts` (diff + arch only) |
| G.G6 | AFR-CCM | CSP must publish the Ongoing Authorization Report + feedback + quarterly meeting integration | 4 CSP-actionable OAR/QTR MUSTs | partial (`core/conmon-*` lands in LOOP-E) |

### Artifacts this loop delivers

Six new top-level artifacts under `out/`:

1. `afr-fsi/inbox-config.json` + tracker DB tables + per-message receipt log
2. `afr-icp/incident-comms-procedures.docx` + tracker incident DB + routing playbook
3. `afr-ads/service-list.json` + `afr-ads/historical-archive/<YYYY-MM>/authorization-data.json` + `afr-ads/public-info.md` + Trust-Center linkage
4. `afr-mas/minimum-assessment-scope.json` + `afr-mas/info-flow-diagram.svg` + `afr-mas/third-party-resources.json` + `afr-mas/minimum-assessment-scope.docx`
5. `afr-scg/secure-configuration-guide.docx` + `afr-scg/use-instructions.md` + `afr-scg/scg-baseline.json`
6. `afr-ccm/oar-<YYYY-MM>.pdf` + `afr-ccm/oar-<YYYY-MM>.json` + `afr-ccm/feedback-summary.json` + tracker feedback form + `afr-ccm/quarterly-review-schedule.json`

### Authorization-package gaps closed

- **FedRAMP onboarding** today requires an explicit FSI endpoint and acknowledged emergency-routing posture (FSI-CSO-INB + FSI-CSO-EMR + FSI-CSO-TFG). Without G.G1 a CSP cannot pass the FedRAMP "verified email" pre-condition (FSI-FRP-VRE).
- **Incident response** today blocks ATO renewal if the CSP cannot demonstrate evidence of the 1-hour-to-CISA path (ICP-CSX-IRC) and the daily-update path (ICP-CSX-ICU). G.G2 provides the templates + audit trail.
- **Authorization data publication** is the keystone of the 20x "public + machine-readable" model (ADS-CSO-PUB + ADS-CSO-CBF). Without G.G3 a CSP has no defensible published service list.
- **Minimum Assessment Scope doc** is the operator-readable counterpart to the inventory (MAS-CSO-IIR + MAS-CSO-FLO + MAS-CSO-MDI + MAS-CSO-TPR). G.G4 produces it.
- **Secure Configuration Guide** is what a customer reads to deploy securely (SCG-CSO-RSC + SCG-CSO-AUP). G.G5 generates it from real reference-arch data.
- **OAR + quarterly review** (CCM-OAR-AVL + CCM-OAR-FBM + CCM-OAR-NRD + CCM-QTR-REG) gate continuous ATO. G.G6 wires the publication + feedback loop.

---

## 2. Dependencies

### Hard prerequisites (must complete BEFORE LOOP-G slices start)

- **LOOP-A complete** — every slice. Specifically:
  - `core/oscal-ssp.ts` (system identity, system-id, AO contacts) for G.G1/G.G2/G.G3/G.G6 metadata
  - `core/oscal-ap.ts` (assessor + assessment period metadata) for G.G2/G.G3/G.G6 back-matter
  - `core/submission-bundle.ts` (catalogue add-points) for every slice
  - `core/sign.ts` (manifest signing) — every artifact this loop emits is signed
  - `core/roe-emit.ts` + `core/ssp-docx.ts` — the dependency-free .docx pattern G.G2 + G.G4 + G.G5 mirror
  - `core/timestamp.ts` (RFC 3161 timestamp) for every emitted artifact

- **REO-0 complete** — `cloud-evidence/CLAUDE.md` standard + 3 CI guardrails (`scripts/lint-no-stubs.mjs` + `scripts/check-provenance.mjs` + `scripts/check-coverage-regression.mjs`) are wired into CI. Every LOOP-G slice runs under REO.

- **R1 (AFR family classification) complete** — `docs/AFR-FAMILY-CLASSIFICATION.md` is the per-MUST source of truth.

### Existing files this loop READS

- `cloud-evidence/docs/frmr-requirements.generated.json` — per-FRMR-id `statement`, `key_word`, `levels.moderate.applies`, `actor`, `fka`. Every G slice cites this file when constructing requirement text.
- `cloud-evidence/core/ksi-map.ts` — registered KSI list (used by G.G4 to mark which KSIs cover which info-flows; G.G5 to mark which scope is in the guide).
- `cloud-evidence/core/control-benchmark.ts` — FedRAMP Rev5 + 20x baseline. G.G5 cites baseline parameter overlays.
- `cloud-evidence/out/inventory.json` — produced by the orchestrator. G.G3 service-list publication, G.G4 info-resource inventory, G.G5 reference-arch baseline all read this.
- `cloud-evidence/out/ssp.json` — produced by `core/oscal-ssp.ts`. G.G1 inbox config, G.G2 incident contacts, G.G3 system identity, G.G6 OAR identity read this.
- `cloud-evidence/out/ap.json` — produced by `core/oscal-ap.ts`. G.G3 historical-archive cites the AP id.
- `cloud-evidence/out/poam.json` — produced by `core/oscal-poam.ts`. G.G3 service list cites open POA&M counts; G.G6 OAR aggregates the month.
- `cloud-evidence/core/subprocessors-sheet.ts` — read by G.G4 (third-party-resources) as the canonical subprocessor list.
- `cloud-evidence/core/scn-classifier.ts` — read by G.G1 (FSI-CSO-NOC notifies FedRAMP on classified changes).
- `cloud-evidence/core/ads-probe.ts` — kept and extended by G.G3 (the URL probe stays; G.G3 adds the publication artifact).
- `cloud-evidence/core/mas-reconcile.ts` — kept and consumed by G.G4 (the diff stays; G.G4 wraps it into a scope doc).
- `cloud-evidence/core/scg-comparator.ts` + `providers/{aws,gcp,azure}/reference-arch.ts` — kept and consumed by G.G5 (the diff + baseline arch stay; G.G5 emits the published guide).

### Existing files this loop EXTENDS

- `cloud-evidence/core/orchestrator.ts` — new flags `--afr-fsi`, `--afr-icp`, `--afr-ads`, `--afr-mas`, `--afr-scg`, `--afr-ccm`. Each is also exposed via a `CLOUD_EVIDENCE_AFR_<X>` env variable.
- `cloud-evidence/core/submission-bundle.ts` — well-known catalogue gains six roles + filenames (`afr-fsi-config`, `afr-icp-procedures-docx`, `afr-ads-service-list`, `afr-ads-public-info`, `afr-mas-scope-doc`, `afr-mas-info-flow-svg`, `afr-scg-guide-docx`, `afr-ccm-oar`, `afr-ccm-feedback`). Each is marked `required: false` at the L1 ATO baseline and `required: true` for the 1-year-renewal bundle (R2 ConMon mode).
- `cloud-evidence/tracker/server/schema.sql` — new tables: `fsi_inbox_config`, `fsi_message_log`, `icp_incidents`, `icp_incident_updates`, `icp_incident_final_reports`, `afr_ccm_feedback`, `afr_ccm_quarterly_meetings`.
- `cloud-evidence/tracker/server/routes/` — new routes per slice (`afr-fsi.ts`, `afr-icp.ts`, `afr-ccm-feedback.ts`).
- `cloud-evidence/tracker/client/src/pages/` — new UI: `FsiInbox.tsx`, `IcpIncidents.tsx`, `CcmFeedback.tsx`.

### Loops UNBLOCKED when LOOP-G completes

- **LOOP-E (ConMon)** — E.E1 monthly ConMon report aggregates the G.G6 OAR; E.E6 SCN .docx emitter cross-references the G.G1 FSI-CSO-NOC channel.
- **LOOP-F.F4** (evidence walk-through) — uses G.G2 incident records to demonstrate "we exercise the procedure". F.F7 (SAR draft) cites the G.G3 published service list as the assessment scope of record.
- **LOOP-J.J2** (subprocessor expansion) — G.G4's third-party-resources artifact is the canonical input to J.J2's risk-tier classifier.
- **LOOP-I.I1** (executive posture dashboard) — surfaces the G.G6 OAR cadence + G.G1 inbox health as posture tiles.

LOOP-G has NO dependency on LOOP-B (risk engine), LOOP-C (document
templates), LOOP-D (diagrams), or LOOP-H (storage). It is a parallel-safe
work-stream.

---

## 3. Authoritative sources

Every requirement text quoted below is verbatim from the source. Cite
both the FRMR id and the FedRAMP-published doc URL.

### Spec documents

| Source | URL | Used for |
|---|---|---|
| FedRAMP RFC-0006 — Continuous Reporting Standard (FedRAMP Security Inbox) | https://www.fedramp.gov/rfcs/0006/ | G.G1: FSI semantics + emergency-routing definition |
| FedRAMP RFC-0014 — Key Security Indicators (Phase Two Moderate) | https://www.fedramp.gov/rfcs/0014/ | G.G6: OAR cadence + automated validation language |
| FedRAMP RFC-0024 — Machine-Readable Submissions (OSCAL) | https://www.fedramp.gov/rfcs/0024/ | G.G3 + G.G4: machine-readable format obligation; G.G6: OSCAL-friendly JSON |
| FRMR.documentation.json (github.com/FedRAMP/docs, v0.9.43-beta) | https://github.com/FedRAMP/docs | G.G1–G.G6: per-MUST `statement` text |
| CISA Federal Incident Notification Guidelines | https://www.cisa.gov/federal-incident-notification-guidelines | G.G2: ICP-CSX-IRC reporting flow |
| CISA Incident Reporting System | https://myservices.cisa.gov/irf | G.G2: ICP-CSX-IRC submission endpoint |
| FedRAMP Rev5 Playbook — ConMon Overview | https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/ | G.G6: OAR cadence + repository |
| FedRAMP Rev5 Playbook — Authorization SAP | https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sap/ | G.G4: scope-doc semantics |
| OSCAL v1.1.2 — Component Definition Model | https://pages.nist.gov/OSCAL/concepts/layer/implementation/component-definition/ | G.G3 service list back-matter; G.G5 SCG baseline references |
| NIST SP 800-53 Rev5 (controls CA-7, CP-2, IR-6, IR-8) | https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final | G.G6 control mapping (CA-7); G.G2 control mapping (IR-6, IR-8) |

### Verbatim MUST language (cite in code comments + emitted-artifact provenance)

Each line is the literal `statement` field from `FRMR.documentation.json`
v0.9.43-beta. Quote unchanged in code comments + in the `provenance.requirementText` field of every emitted artifact.

**FSI (G.G1):**

- `FSI-CSO-INB` (FRR-FSI-09):
  > "Providers MUST establish and maintain an email address to receive messages from FedRAMP; this inbox is a FedRAMP Security Inbox (FSI)."
- `FSI-CSO-TFG` (FRR-FSI-10):
  > "Providers MUST treat any email originating from an @fedramp.gov or @gsa.gov email address as if it was sent from FedRAMP by default; if such a message is confirmed to originate from someone other than FedRAMP then FedRAMP Security Inbox requirements no longer apply."
- `FSI-CSO-RCV` (FRR-FSI-11):
  > "Providers MUST receive and react to email messages from FedRAMP without disruption and without requiring additional actions from FedRAMP."
- `FSI-CSO-NOC` (FRR-FSI-12):
  > "Providers MUST immediately notify FedRAMP of any changes in addressing for their FedRAMP Security Inbox by emailing info@fedramp.gov with the name and FedRAMP ID of the cloud service offering and the updated email address."
- `FSI-CSO-CRA` (FRR-FSI-14):
  > "Providers MUST complete the required actions in Emergency or Emergency Test designated messages sent by FedRAMP within the timeframe included in the message."
- `FSI-CSO-EMR` (FRR-FSI-15):
  > "Providers MUST route Emergency designated messages sent by FedRAMP to a senior security official for their awareness."

**ICP (G.G2):**

- `ICP-CSX-IRF` (FRR-ICP-01):
  > "Providers MUST responsibly report incidents to FedRAMP within 1 hour of identification by sending an email to fedramp_security@fedramp.gov or fedramp_security@gsa.gov."
- `ICP-CSX-IRA` (FRR-ICP-02):
  > "Providers MUST responsibly report incidents to all agency customers within 1 hour of identification using the incident communications points of contact provided by each agency customer."
- `ICP-CSX-IRC` (FRR-ICP-03):
  > "Providers MUST responsibly report incidents to CISA within 1 hour of identification if the incident is confirmed or suspected to be the result of an attack vector listed at https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy, following the CISA Federal Incident Notification Guidelines at https://www.cisa.gov/federal-incident-notification-guidelines, by using the CISA Incident Reporting System at https://myservices.cisa.gov/irf."
- `ICP-CSX-ICU` (FRR-ICP-04):
  > "Providers MUST update all necessary parties, including at least FedRAMP, CISA (if applicable), and all agency customers, at least once per calendar day until the incident is resolved and recovery is complete."
- `ICP-CSX-RPT` (FRR-ICP-05):
  > "Providers MUST make incident report information available in their secure FedRAMP repository (such as USDA Connect) or trust center."
- `ICP-CSX-FIR` (FRR-ICP-07):
  > "Providers MUST provide a final report once the incident is resolved and recovery is complete that describes at least: …"
  > (the "at least" list is enumerated in FRMR sub-bullets and re-quoted in G.G2 implementation.)

**ADS (G.G3):**

- `ADS-CSO-PUB` (FRR-ADS-01):
  > "Providers MUST publicly share up-to-date information about the cloud service offering in both human-readable and machine-readable formats, including at least: …"
  > (13-field checklist enumerated in `core/ads-probe.ts:ADS_CSO_PUB_FIELDS` — already implemented as the probe pass-list.)
- `ADS-CSO-CBF` (FRR-ADS-02):
  > "Providers MUST use automation to ensure information remains consistent between human-readable and machine-readable formats when authorization data is provided in both formats."
- `ADS-CSO-SVC` (FRR-ADS-03):
  > "Providers MUST publicly share a detailed list of specific services and their security objectives that are included in the cloud service offering using clear feature or service names that align with standard public marketing materials; this list MUST be complete enough for a potential customer to determine which services are and are not included in the FedRAMP Minimum Assessment Scope without requesting access to underlying authorization data."
- `ADS-CSO-RIS` (FRR-ADS-05):
  > "Providers MUST provide sufficient information in authorization data to support authorization decisions but SHOULD NOT include sensitive information that would likely enable a threat actor to gain unauthorized access, cause harm, disrupt operations, or otherwise have a negative adverse impact on the cloud service offering."
- `ADS-CSX-UTC` (FRR-ADS-07):
  > "Providers MUST use a FedRAMP-compatible trust center to store and share authorization data with all necessary parties."
- `ADS-CSO-HAD` (FRR-ADS-09):
  > "Providers MUST make historical versions of authorization data available for three years to all necessary parties UNLESS otherwise specified by applicable FedRAMP requirements; deltas between versions MAY be consolidated quarterly."

**MAS (G.G4):**

- `MAS-CSO-IIR` (FRR-MAS-01):
  > "Providers MUST identify a set of information resources to assess for FedRAMP authorization that includes all information resources that are likely to handle federal customer data or likely to impact the confidentiality, integrity, or availability of federal customer data handled by the cloud service offering; this set of information resources is the cloud service offering."
- `MAS-CSO-TPR` (FRR-MAS-02 + FRR-MAS-03):
  > "Providers MUST address the potential impact to federal customer data from third-party information resources used by the cloud service offering, ONLY IF MAS-CSO-IIR APPLIES, by documenting the following information about each applicable third-party information resource: …"
- `MAS-CSO-MDI` (FRR-MAS-04):
  > "Providers MUST include metadata (including metadata about federal customer data) in the Minimum Assessment Scope ONLY IF MAS-CSO-IIR APPLIES."
- `MAS-CSO-FLO` (FRR-MAS-05):
  > "Providers MUST clearly identify, document, and explain information flows and security objectives for ALL information resources or sets of information resources in the cloud service offering."

**SCG (G.G5):**

- `SCG-CSO-AUP` (no FRR fka):
  > "Providers MUST include instructions in the FedRAMP authorization package that explain how to obtain and use the Secure Configuration Guide."
- `SCG-CSO-RSC` (FRR-RSC-01 + FRR-RSC-02 + FRR-RSC-03):
  > "Providers MUST create, maintain, and make available recommendations for securely configuring their cloud services (the Secure Configuration Guide) that includes at least the following information: …"

**CCM (G.G6) — CSP-actionable subset:**

- `CCM-OAR-AVL` (FRR-CCM-01):
  > "Providers MUST make an Ongoing Authorization Report available to all necessary parties every 3 months, covering the entire period since the previous summary, in a consistent format that is human readable; this report MUST include high-level summaries of at least the following information: …"
- `CCM-OAR-NRD` (FRR-CCM-03):
  > "Providers MUST publicly include the target date for their next Ongoing Authorization Report with other public authorization data."
- `CCM-OAR-FBM` (FRR-CCM-04):
  > "Providers MUST establish and share an asynchronous mechanism for all necessary parties to provide feedback or ask questions about each Ongoing Authorization Report."
- `CCM-OAR-AFS` (FRR-CCM-05):
  > "Providers MUST maintain an anonymized and desensitized summary of the feedback, questions, and answers about each Ongoing Authorization Report as an addendum to the Ongoing Authorization Report."
- `CCM-QTR-REG` (FRR-CCM-QR-05):
  > "Providers MUST include either a registration link or a downloadable calendar file with meeting information for Quarterly Reviews in the authorization data available to all necessary parties required by ADS-CSL-UCP and ADS-CSO-FCT."

---

## 4. Per-slice implementation specs

### Slice G.G1 — AFR-FSI (FedRAMP Security Inbox)

**Why this slice:** Without a verified, monitored FSI endpoint the CSP
cannot receive FedRAMP-originated emergency notifications (FSI-CSO-INB)
and cannot demonstrate the SLA on closing required actions
(FSI-CSO-CRA). The deliverable is a config-of-record + a receipt-log audit
trail; the inbox itself lives on the CSP's email infrastructure.

**Files to create:**

- `cloud-evidence/core/afr-fsi.ts` — pure builder + disk emitter for the FSI
  config-of-record JSON; pure validators for inbox-config fields; pure
  routine to dump the `fsi_message_log` rows to a signed `fsi-receipt-ledger.json`.
- `cloud-evidence/tests/core/afr-fsi.test.ts` — unit tests for builder + validators + ledger dump.
- `cloud-evidence/tracker/server/routes/afr-fsi.ts` — REST endpoints: GET/POST `/api/afr-fsi/config`, POST `/api/afr-fsi/messages` (webhook receive), GET `/api/afr-fsi/messages?since=…`, POST `/api/afr-fsi/messages/:msg_id/ack`.
- `cloud-evidence/tracker/server/routes/afr-fsi.test.ts` — route tests + DB-constraint tests.
- `cloud-evidence/tracker/client/src/pages/FsiInbox.tsx` — operator UI: configure inbox endpoint, view receipt log, mark actions complete.
- `cloud-evidence/tracker/server/schema.sql` — additive: `fsi_inbox_config`, `fsi_message_log` tables.
- `cloud-evidence/docs/loops/AFR-FSI-RUNBOOK.md` — operator runbook (how to point an SES/SendGrid/Microsoft-365 inbox at the tracker webhook; how to verify @fedramp.gov DKIM/SPF/DMARC).

**Files to extend:**

- `core/orchestrator.ts` — new `--afr-fsi` flag + `CLOUD_EVIDENCE_AFR_FSI` env. Calls `emitAfrFsi(outDir, ctx)`. Console output reports inbox endpoint + receipt-log size + open required-actions count.
- `core/submission-bundle.ts` — well-known catalogue rows for `afr-fsi/inbox-config.json` (`role: 'afr-fsi-config'`) + `afr-fsi/receipt-ledger.json` (`role: 'afr-fsi-ledger'`).
- `core/scn-classifier.ts` — when a classified change touches the FSI endpoint (Source IP, MX record, email address), trigger an `FSI-CSO-NOC` notification record in `fsi_message_log` so the change is logged at-source.

**Schemas / standards:**

- `FsiInboxConfig` (defined in `core/afr-fsi.ts`):
  - `email_endpoint: string` — RFC 5321 mailbox. REQUIRES-OPERATOR-INPUT.
  - `csp_id: string` — FedRAMP-issued cloud-service-offering id. REQUIRES-OPERATOR-INPUT.
  - `csp_name: string` — must match the SSP `system-name`. Auto-derived from `out/ssp.json` when present.
  - `senior_security_official_email: string` — for FSI-CSO-EMR emergency routing. REQUIRES-OPERATOR-INPUT.
  - `trust_list: Array<{ pattern: '@fedramp.gov' | '@gsa.gov'; verified_at: ISOString; verified_by: string }>` — fixed pattern per FSI-CSO-TFG; `verified_at` is operator-attested.
  - `verified_no_disruption_runbook_url: string` — link to CSP runbook proving FSI-CSO-RCV (e.g. monitored 24/7, on-call rotation).
  - `last_noc_notification_sent_at: ISOString | null` — most recent `info@fedramp.gov` notification per FSI-CSO-NOC.
  - `provenance: { emitter: 'cloud-evidence/core/afr-fsi.ts'; emittedAt: ISO; sourceCalls: ['tracker:fsi_inbox_config']; requirementTexts: { [musts: string]: string } }`.

- `FsiMessageLogRow` (DB shape mirrored in JSON dump):
  - `msg_id: string PRIMARY KEY` — sha256(from + subject + received_at) for dedup.
  - `from: string` — RFC 5322 From header.
  - `to: string` — RFC 5322 To header (must match `inbox_config.email_endpoint`).
  - `subject: string`
  - `classification: 'Emergency' | 'EmergencyTest' | 'Routine' | 'Unclassified'` — derived from subject (per FedRAMP standard "[FedRAMP-EMERGENCY] " / "[FedRAMP-EMERGENCY-TEST] " / default routine).
  - `received_at: ISOString` — RFC 3339, from the webhook receive timestamp; cross-verified against the Received-trace headers (informational).
  - `dkim_pass: boolean | null` — from the email provider's DKIM verification. When null, the message is held until operator-verified.
  - `routed_to: string[]` — emails the message was forwarded to (must include `senior_security_official_email` for `Emergency`).
  - `required_action_summary: string | null` — operator-extracted summary of the action.
  - `required_action_deadline: ISOString | null` — operator-extracted deadline (per the FedRAMP message body).
  - `action_completed_at: ISOString | null` — operator marks complete.
  - `action_completed_by_user_id: string | null` — tracker user.

**Build steps:**

1. Define interfaces `FsiInboxConfig`, `FsiMessageLogRow`, `FsiEmitOptions`, `FsiEmitResult` in `core/afr-fsi.ts`. Stable JSON shape; deterministic field order via `Object.fromEntries(sortedKeys.map(k => [k, v[k]]))`.
2. Pure builder `buildFsiArtifacts(input: FsiInputs, opts: FsiEmitOptions): FsiEmitResult` returning `{ inboxConfig: FsiInboxConfig; receiptLedger: { rows: FsiMessageLogRow[]; checksum: string; requires_operator_input: string[] }; ready_for_signature: boolean; requires_operator_input: string[] }`. Pure, no I/O.
3. Disk emitter `emitAfrFsi(outDir: string, ctx: OrchestratorContext): Promise<FsiEmitResult>`:
   - Read `out/ssp.json` if present → seed `csp_name` + `csp_id` from `metadata.title` + `system-id`.
   - Query tracker DB for current `fsi_inbox_config` row + all `fsi_message_log` rows since the last run.
   - Call `buildFsiArtifacts`.
   - Write `out/afr-fsi/inbox-config.json` + `out/afr-fsi/receipt-ledger.json`.
   - Append `provenance` block.
4. Wire orchestrator: `--afr-fsi` flag + `CLOUD_EVIDENCE_AFR_FSI` env. Runs BEFORE signing so the artifacts are covered by the manifest.
5. Add to `core/submission-bundle.ts` catalogue: 2 new role rows.
6. Schema migration in `tracker/server/schema.sql` (additive, `CREATE TABLE IF NOT EXISTS`).
7. Tracker routes: validate inbox endpoint with RFC-5321 regex; webhook auth via HMAC-SHA256 of a shared secret stored in tracker env `CLOUD_EVIDENCE_FSI_WEBHOOK_SECRET` (rotated quarterly per operator runbook). On receive, derive `classification` from subject prefix; auto-route to `senior_security_official_email` for Emergency.
8. Tracker UI page: form to set inbox + senior-security-official, table of received messages, "Acknowledge action complete" button.

**REQUIRES-OPERATOR-INPUT fields:**

- `email_endpoint`: source = tracker UI form field `inbox_endpoint`, persisted in `fsi_inbox_config`.
- `csp_id`: source = CLI flag `--csp-id` (passed to orchestrator) OR tracker UI form. Auto-derived from SSP `system-id` when SSP exists.
- `senior_security_official_email`: source = tracker UI form field `senior_security_official_email`.
- `trust_list[].verified_at` + `verified_by`: source = tracker UI verification dialog (operator confirms they sent a test message from @fedramp.gov / @gsa.gov and received it).
- `verified_no_disruption_runbook_url`: source = tracker UI form.
- `dkim_pass` for incoming messages: source = email provider header parser (SES `mail.dkim.verdict`, Microsoft 365 `Authentication-Results` header). When unparseable, the row stays held until operator confirms.

**Test specifications (~13):**

1. `it('builds inbox config from SSP-derived csp_name + csp_id', …)` — assert config matches SSP metadata; provenance.sourceCalls includes `out/ssp.json`.
2. `it('emits REQUIRES-OPERATOR-INPUT for email_endpoint when no tracker row exists', …)` — `requires_operator_input` contains `email_endpoint` with explanation referencing the tracker UI.
3. `it('emits REQUIRES-OPERATOR-INPUT for senior_security_official_email when missing', …)` — and `ready_for_signature` is false.
4. `it('verifies trust_list contains both @fedramp.gov and @gsa.gov patterns', …)` — both required per FSI-CSO-TFG; missing either → `requires_operator_input`.
5. `it('classifies "[FedRAMP-EMERGENCY] Patch required" as Emergency', …)` — derived classification matches.
6. `it('classifies "[FedRAMP-EMERGENCY-TEST] …" as EmergencyTest', …)`.
7. `it('classifies bare subject as Routine', …)`.
8. `it('rejects messages with dkim_pass = false from @fedramp.gov pattern', …)` — sets `held` flag, never auto-routes.
9. `it('computes msg_id as sha256(from+subject+received_at)', …)` — deterministic; idempotent on re-ingest.
10. `it('flags overdue required-action rows', …)` — `action_completed_at = null AND required_action_deadline < now` → `overdue` row appears in result.
11. `it('writes receipt-ledger checksum that matches body sha256', …)` — checksum integrity.
12. `it('records provenance.requirementTexts for all 6 FSI-CSO MUSTs verbatim', …)` — every MUST text from FRMR appears in provenance.
13. `it('webhook HMAC-validates request signature', …)` — route test with valid + invalid HMAC.

**REO compliance:**

- Every emitted field traces to: (a) SSP-derived auto-value, (b) tracker DB row, OR (c) `REQUIRES-OPERATOR-INPUT` marker. Never substitute a placeholder email.
- `provenance.requirementTexts` carries the verbatim FRMR statement for each MUST so a 3PAO can cite the obligation directly from the artifact.
- The webhook never auto-acknowledges actions — operators must click in the UI; the click is captured in `action_completed_by_user_id` (real human action).
- No silent fallbacks: a missing inbox config → ready_for_signature = false → orchestrator exit code 4 in `--strict-bundle` mode.

**Verification commands:**

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/afr-fsi.test.ts
npm test -- tracker/server/routes/afr-fsi.test.ts
npm run check:reo
```

**Estimated effort:** 5 days (1d schema+builder, 1d routes+HMAC, 1d UI, 1d tests, 1d docs+verify).

---

### Slice G.G2 — AFR-ICP (Incident Communications Procedures)

**Why this slice:** ICP-CSX-IRF + IRA + IRC require the CSP to demonstrate
a 1-hour-to-FedRAMP, 1-hour-to-agencies, and 1-hour-to-CISA incident-
reporting path, with daily updates (ICU) and a final report (FIR). The
deliverable is (a) a published Incident Communications Procedures
document the 3PAO references in the AR, and (b) a tracker incident
log + per-incident report-routing audit trail.

**Files to create:**

- `cloud-evidence/core/afr-icp.ts` — pure builder for the ICP procedures
  document data shape + dependency-free .docx emitter (mirrors
  `core/roe-emit.ts` OOXML + `core/zip.ts` zipStore pattern). Pure
  routine to emit a per-incident "report packet" JSON when called from
  the tracker.
- `cloud-evidence/tests/core/afr-icp.test.ts` — unit tests.
- `cloud-evidence/tracker/server/routes/afr-icp.ts` — REST endpoints for
  incidents: POST `/api/afr-icp/incidents` (create), POST
  `/api/afr-icp/incidents/:id/updates` (daily update), POST
  `/api/afr-icp/incidents/:id/final-report` (close), GET
  `/api/afr-icp/incidents` (list, with filters).
- `cloud-evidence/tracker/server/routes/afr-icp.test.ts`.
- `cloud-evidence/tracker/client/src/pages/IcpIncidents.tsx` — operator
  UI: incident create + update + final-report; cadence reminder for
  daily updates; one-click "generate report packet" → downloads a
  JSON ready for upload to USDA Connect (per ICP-CSX-RPT).
- `cloud-evidence/tracker/server/schema.sql` — additive: `icp_incidents`,
  `icp_incident_updates`, `icp_incident_final_reports`,
  `icp_agency_contacts` tables.
- `cloud-evidence/docs/loops/AFR-ICP-RUNBOOK.md` — operator runbook.

**Files to extend:**

- `core/orchestrator.ts` — new `--afr-icp` flag + env. Generates the ICP
  procedures .docx + dumps the closed-incident packet JSON into
  `out/afr-icp/`.
- `core/submission-bundle.ts` — catalogue rows for
  `afr-icp/incident-comms-procedures.docx` + `afr-icp/incident-log.json`.

**Schemas / standards:**

- `IcpProceduresInput` (in `core/afr-icp.ts`):
  - `systemName: string` — from SSP.
  - `csoFedRampId: string` — from SSP.
  - `fedRampSecurityEmail: 'fedramp_security@fedramp.gov' | 'fedramp_security@gsa.gov'` — operator picks (fixed FedRAMP list per ICP-CSX-IRF). Default: `fedramp_security@fedramp.gov`.
  - `cisaReportingUrl: 'https://myservices.cisa.gov/irf'` — fixed (per ICP-CSX-IRC).
  - `cisaGuidelineUrl: 'https://www.cisa.gov/federal-incident-notification-guidelines'` — fixed.
  - `cisaAttackVectorsUrl: 'https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy'` — fixed.
  - `agencyContacts: Array<{ agency: string; pocName: string; pocEmail: string; pocPhone: string }>` — REQUIRES-OPERATOR-INPUT (per ICP-CSX-IRA each agency customer's PoC).
  - `repositoryUrl: string` — secure repository for incident reports per ICP-CSX-RPT (defaults to "USDA Connect.gov" + REQUIRES-OPERATOR-INPUT path).
  - `incidentResponseTeam: Array<{ name: string; role: string; email: string; phone: string; escalation: boolean }>` — REQUIRES-OPERATOR-INPUT.

- `icp_incidents` DB table:
  - `id TEXT PK` (UUIDv4)
  - `system_id TEXT NOT NULL`
  - `discovered_at DATETIME NOT NULL`
  - `discovered_by_user_id TEXT NOT NULL`
  - `summary TEXT NOT NULL`
  - `severity TEXT CHECK (severity IN ('low','moderate','high','critical'))`
  - `attack_vector TEXT` — from CISA taxonomy enum.
  - `confirmed_or_suspected_attack INTEGER NOT NULL CHECK (confirmed_or_suspected_attack IN (0,1))`
  - `reported_to_fedramp_at DATETIME` (must be ≤ 1h after discovered_at; constraint check raises a `late_report` finding flagged in evidence)
  - `reported_to_cisa_at DATETIME` (when applicable)
  - `reported_to_agencies_at_json TEXT` (per-agency timestamps)
  - `status TEXT CHECK (status IN ('open','contained','resolved'))`
  - `resolved_at DATETIME`

- `icp_incident_updates` table: `id TEXT PK`, `incident_id TEXT FK`, `update_at DATETIME NOT NULL`, `update_text TEXT NOT NULL`, `posted_to_fedramp INTEGER`, `posted_to_cisa INTEGER`, `posted_to_agencies INTEGER`, `update_by_user_id TEXT NOT NULL`.
- `icp_incident_final_reports` table: `incident_id TEXT PK FK`, `narrative TEXT NOT NULL`, `root_cause TEXT NOT NULL`, `mitigations_taken TEXT NOT NULL`, `lessons_learned TEXT NOT NULL`, `compensating_controls_added_json TEXT`, `submitted_at DATETIME NOT NULL`, `submitted_by_user_id TEXT NOT NULL`, `submission_url TEXT`.

**Build steps:**

1. Define interfaces + DB shape in `core/afr-icp.ts`.
2. Pure builder `buildIcpProceduresDocx(input: IcpProceduresInput): { docxBytes: Uint8Array; requires_operator_input: string[]; ready_for_signature: boolean }`. Mirror `core/roe-emit.ts` section structure:
   - §1 System Identity (auto from SSP).
   - §2 Reporting Channels (fixed: FedRAMP email, CISA URL, agency PoCs).
   - §3 1-hour SLA Procedures (verbatim ICP-CSX-IRF/IRA/IRC text + step-by-step).
   - §4 Daily Update Cadence (verbatim ICP-CSX-ICU).
   - §5 Final Report Template (verbatim ICP-CSX-FIR + required-fields list).
   - §6 Secure Repository Reference (per ICP-CSX-RPT).
   - §7 Incident Response Team Roster (operator-supplied).
   - §8 Document Provenance (tool name + run id + commit hash).
3. Disk emitter `emitAfrIcp(outDir, ctx)`:
   - Read SSP metadata.
   - Query `icp_incidents` + child rows for the report period (default: last 12 months).
   - Build docx + serialize closed-incident packet JSON per ICP-CSX-RPT format.
   - Write to `out/afr-icp/incident-comms-procedures.docx` + `out/afr-icp/incident-log.json`.
4. Orchestrator: `--afr-icp` flag. Runs BEFORE signing.
5. Tracker routes:
   - POST create: enforces required fields; calculates `reported_to_fedramp_at - discovered_at` and emits a tracker audit event when > 1h.
   - POST update: cadence enforcer (cron job hits the route once per day per open incident and raises a `missed_daily_update` event if the last update is > 24h old per ICP-CSX-ICU).
   - POST final-report: closes the incident; requires `narrative`, `root_cause`, `mitigations_taken`, `lessons_learned`. Emits the FedRAMP-required "at least" fields per ICP-CSX-FIR.
6. UI: incident-create form, incident-list table, daily-update modal, final-report editor.
7. Submission bundle catalogue: 2 new rows.

**REQUIRES-OPERATOR-INPUT fields:**

- `agencyContacts`: source = tracker UI table per agency customer.
- `repositoryUrl`: source = CLI flag `--csp-secure-repo-url` or `CLOUD_EVIDENCE_SECURE_REPO_URL` env (e.g. USDA Connect.gov-issued path).
- `incidentResponseTeam`: source = tracker UI.
- `fedRampSecurityEmail`: source = CLI flag `--fedramp-security-email` (must be one of the two FedRAMP-published addresses).

**Test specifications (~14):**

1. `it('renders procedures docx with all 6 ICP MUST texts verbatim', …)` — parse the body XML, assert each FRMR statement is present.
2. `it('emits REQUIRES-OPERATOR-INPUT for agencyContacts when empty', …)`.
3. `it('emits REQUIRES-OPERATOR-INPUT for incidentResponseTeam', …)`.
4. `it('hard-codes CISA URLs from spec', …)` — assert the three CISA URLs appear unaltered.
5. `it('rejects fedRampSecurityEmail values outside the two allowed addresses', …)`.
6. `it('flags late_report when reported_to_fedramp_at - discovered_at > 1h', …)`.
7. `it('treats reported_to_cisa_at = null as OK when confirmed_or_suspected_attack = 0', …)`.
8. `it('requires reported_to_cisa_at when confirmed_or_suspected_attack = 1', …)`.
9. `it('emits missed_daily_update when no update in 24h on open incident', …)`.
10. `it('final report rejects empty root_cause', …)`.
11. `it('incident-log.json serializes deterministically for byte-identical output across runs', …)`.
12. `it('writes docx with correct OOXML zip structure (store-only)', …)` — open with the bundled zip parser; assert parts present.
13. `it('records discovered_by_user_id + each update_by_user_id from real tracker auth context', …)`.
14. `it('omits incidents outside the report period', …)` — only last-12-months closed incidents in the published packet.

**REO compliance:**

- Every emitted incident row traces to a real tracker DB record (human-entered + auth-stamped).
- All CISA / FedRAMP URLs + email addresses come from FedRAMP spec (allowed fixed-data per CLAUDE.md Rule 3).
- No auto-fabricated incidents.
- The 1-hour-to-FedRAMP SLA is computed from real `discovered_at` + `reported_to_fedramp_at` timestamps; the system never back-dates.

**Verification commands:**

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/afr-icp.test.ts
npm test -- tracker/server/routes/afr-icp.test.ts
npm run check:reo
```

**Estimated effort:** 6 days (1d schema+builder, 1d .docx emitter, 1d routes+SLA enforcer, 1d UI, 1d tests, 1d runbook+verify).

---

### Slice G.G3 — AFR-ADS (Authorization Data Sharing)

**Why this slice:** ADS-CSO-PUB requires public publication of 13 specific
fields about the cloud service offering (already enumerated in
`core/ads-probe.ts:ADS_CSO_PUB_FIELDS`). ADS-CSO-CBF requires automation
guaranteeing the human + machine-readable formats stay consistent.
ADS-CSO-SVC requires a published, customer-self-service service list.
ADS-CSO-HAD requires a 3-year historical archive. ADS-CSX-UTC requires
that all of this lives behind a Trust-Center workflow.

The existing `core/ads-probe.ts` only validates that the published URLs
return the right bytes; it does NOT generate the bytes. G.G3 generates
+ archives them.

**Files to create:**

- `cloud-evidence/core/afr-ads.ts` — pure builders for:
  - `buildServiceListJson(input: AdsServiceListInput): ServiceListJson` — machine-readable per ADS-CSO-SVC.
  - `buildPublicInfoMarkdown(input: AdsPublicInfoInput): string` — human-readable cover page per ADS-CSO-PUB (13 fields).
  - `buildAuthorizationDataPacket(input: AdsPacketInput): AuthorizationDataPacket` — combined data structure that gets archived per ADS-CSO-HAD.
  - `consistencyCheck(humanMd: string, machineJson: ServiceListJson): ConsistencyDiff` — automated diff per ADS-CSO-CBF (ensures every service in the markdown appears in the JSON and vice versa).
  - `archivePeriod(outDir: string, period: 'YYYY-MM'): string` — writes the period-stamped archive directory.
- `cloud-evidence/tests/core/afr-ads.test.ts`.
- `cloud-evidence/docs/loops/AFR-ADS-RUNBOOK.md` — operator runbook for the Trust-Center linkage + 3-year retention enforcement (ties into LOOP-H.H2).

**Files to extend:**

- `core/ads-probe.ts` — add an "ingest-mode" function `verifyPublishedMatchesLocal(localServiceListPath, publicUrl)` that probes the public URL and diffs against the local artifact. This closes ADS-CSO-CBF (consistency between formats AND between local + published copies).
- `core/orchestrator.ts` — new `--afr-ads` flag + env. Emits the service list + public info + period archive. Optionally probes the public URLs (gated by `--afr-ads-probe-public` to skip in offline CI).
- `core/submission-bundle.ts` — catalogue rows for `afr-ads/service-list.json`, `afr-ads/public-info.md`, `afr-ads/historical-archive-index.json`.
- `core/subprocessors-sheet.ts` — extend to feed the service-list "subprocessor exposure" rows.

**Schemas / standards:**

- `ServiceListJson` (machine-readable per ADS-CSO-SVC, OSCAL-friendly):
  - `$schema: 'https://fedramp.gov/schemas/afr-ads/service-list/2026.json'`
  - `system_id: string` — from SSP.
  - `csp_name: string`
  - `marketplace_url: string` (FedRAMP Marketplace link, required by ADS-CSO-PUB).
  - `service_model: 'SaaS' | 'PaaS' | 'IaaS'` — from SSP `system-implementation`.
  - `deployment_model: 'public' | 'government-community' | 'private' | 'hybrid'` — from SSP.
  - `services: Array<{ name: string; description: string; service_model: 'SaaS'|'PaaS'|'IaaS'; in_minimum_assessment_scope: boolean; security_objectives: { confidentiality: 'Low'|'Moderate'|'High'; integrity: 'Low'|'Moderate'|'High'; availability: 'Low'|'Moderate'|'High' }; underlying_components: string[] (component UUIDs from SSP); marketing_url: string }>` — one row per service.
  - `oar_next_target_date: ISOString` — from G.G6 OAR scheduler. Required by CCM-OAR-NRD.
  - `quarterly_review_registration_url: string` — from G.G6 QTR scheduler. Required by CCM-QTR-REG.
  - `published_at: ISOString` — when the file was emitted.
  - `provenance: { emitter, sourceCalls, requirementTexts }`.

- `AdsPublicInfoMarkdown` shape — 13 sections matching `core/ads-probe.ts:ADS_CSO_PUB_FIELDS` exactly. Re-uses the field keys so the probe diff is trivial.

- Historical-archive layout: `out/afr-ads/historical-archive/<YYYY-MM>/{service-list.json, public-info.md, sha256.txt}` + top-level `out/afr-ads/historical-archive-index.json` listing each period + sha256 + retention-expiry date (published_at + 3 years per ADS-CSO-HAD).

**Build steps:**

1. Define interfaces. Determinism: sort `services[]` by `name` ASC; ISO timestamps RFC 3339 with seconds precision.
2. Pure builder `buildServiceListJson(input): ServiceListJson` — pulls services from SSP `system-implementation.components[]` filtered by an operator-supplied "is-customer-facing" tag (operator marks via inventory tag `customer_facing=true` OR via tracker UI; default: NOT in service list).
3. Pure builder `buildPublicInfoMarkdown(input): string` — renders the 13 fields verbatim from `ADS_CSO_PUB_FIELDS`. Each field is operator-supplied OR auto-derived (e.g. `marketplace_link` is REQUIRES-OPERATOR-INPUT; `service_model` is auto from SSP).
4. Pure consistency check `consistencyCheck(humanMd, machineJson): { ok: boolean; missing_from_md: string[]; missing_from_json: string[] }` per ADS-CSO-CBF.
5. Pure builder `buildAuthorizationDataPacket(input)` — combines service list + public info + a copy of SSP+AP+POA&M metadata into a snapshot JSON.
6. Disk emitter `emitAfrAds(outDir, ctx)`:
   - Build the 3 artifacts.
   - Run `consistencyCheck`; reject (raise) on inconsistency in `--strict-bundle` mode.
   - Write to `out/afr-ads/`.
   - Append to `out/afr-ads/historical-archive/<YYYY-MM>/` (idempotent; same-period rewrite OK).
   - Update `out/afr-ads/historical-archive-index.json` (append-only).
7. Optional public-URL probe via the extended `core/ads-probe.ts`; output a `published-vs-local-diff.json` showing any divergence.
8. Orchestrator wiring + submission-bundle catalogue.

**REQUIRES-OPERATOR-INPUT fields:**

- `marketplace_url`: source = CLI flag `--marketplace-url` or `CLOUD_EVIDENCE_MARKETPLACE_URL` env (the public FedRAMP Marketplace page for this CSO).
- `services[].marketing_url`: source = inventory tag `customer_marketing_url` OR tracker UI per-component edit.
- `services[].security_objectives.{c,i,a}`: source = SSP `system-characteristics.system-information.information-types[]` aggregated by component, OR inventory tag `cia_{low,mod,high}`. When ambiguous, REQUIRES-OPERATOR-INPUT.
- `quarterly_review_registration_url`: source = G.G6 (operator schedules a meeting via the tracker).
- `oar_next_target_date`: source = G.G6 OAR scheduler.

**Test specifications (~12):**

1. `it('builds service list JSON with sorted services from SSP components', …)` — determinism + sort order.
2. `it('only includes components flagged customer_facing=true', …)` — filter behavior.
3. `it('emits REQUIRES-OPERATOR-INPUT for marketplace_url when missing', …)`.
4. `it('renders the 13 ADS-CSO-PUB fields in the public info markdown', …)` — assert every key in `ADS_CSO_PUB_FIELDS` appears in the output.
5. `it('passes consistency check when md mentions every service in json and vice versa', …)`.
6. `it('detects services in md missing from json', …)` — flag-and-fail.
7. `it('detects services in json missing from md', …)`.
8. `it('archives a per-period snapshot under historical-archive/<YYYY-MM>/', …)`.
9. `it('appends to historical-archive-index.json without rewriting old rows', …)` — append-only invariant.
10. `it('computes retention_expiry as published_at + 3 years', …)` — per ADS-CSO-HAD.
11. `it('records provenance.requirementTexts for all 6 ADS MUSTs', …)`.
12. `it('verifyPublishedMatchesLocal flags drift between local artifact and public URL', …)` — probe diff (uses injected fake fetch).

**REO compliance:**

- The service list mirrors real SSP components — no fabricated services.
- 13 public-info fields are operator-supplied OR auto-derived from SSP; never placeholder marketing text.
- Consistency-check enforces ADS-CSO-CBF: any disagreement between markdown + JSON is surfaced as a finding (not silently reconciled).
- Historical-archive entries are append-only + sha256-locked; can never be retroactively modified.

**Verification commands:**

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/afr-ads.test.ts
npm run check:reo
```

**Estimated effort:** 5 days.

---

### Slice G.G4 — AFR-MAS (Minimum Assessment Scope)

**Why this slice:** MAS-CSO-IIR is the anchor: the CSP must identify "the
cloud service offering" = the set of information resources likely to
handle federal data. MAS-CSO-FLO requires info-flow diagrams + security
objectives per resource. MAS-CSO-MDI requires metadata about federal data
to be included. MAS-CSO-TPR requires every third-party information
resource to be documented with specific fields.

The existing `core/mas-reconcile.ts` produces a documented-vs-discovered
diff. G.G4 wraps that diff into a published scope document with all 4
MUSTs covered.

**Files to create:**

- `cloud-evidence/core/afr-mas.ts` — pure builders for:
  - `buildScopeJson(input: MasScopeInput): MasScopeJson` — machine-readable scope doc.
  - `buildScopeDocx(input: MasScopeInput): { bytes: Uint8Array }` — human-readable .docx (mirrors `core/roe-emit.ts` pattern).
  - `buildInformationFlowSvg(input: InfoFlowInput): string` — pure PlantUML-source-string emitter; SVG rendered downstream (or operator runs `plantuml` separately). For G.G4 we ship the .puml + a simplified SVG generated from inventory edges only (no external plantuml dep — same constraint as LOOP-D).
  - `buildThirdPartyResourcesJson(input: ThirdPartyInput): ThirdPartyResourcesJson` — per MAS-CSO-TPR field list.
- `cloud-evidence/tests/core/afr-mas.test.ts`.
- `cloud-evidence/docs/loops/AFR-MAS-RUNBOOK.md`.

**Files to extend:**

- `core/mas-reconcile.ts` — re-exported into `core/afr-mas.ts` for the scope-doc body. No new code in mas-reconcile.
- `core/subprocessors-sheet.ts` — feed third-party resources from the registered subprocessor list (mapping subprocessor → MAS-CSO-TPR's required fields: legal entity name, FedRAMP marketplace status, data types handled, processing location, supply-chain risk score).
- `core/orchestrator.ts` — `--afr-mas` flag + env.
- `core/submission-bundle.ts` — catalogue rows for `afr-mas/minimum-assessment-scope.json`, `.docx`, `afr-mas/info-flow-diagram.svg`, `afr-mas/info-flow-diagram.puml`, `afr-mas/third-party-resources.json`.

**Schemas / standards:**

- `MasScopeJson`:
  - `system_id, system_name` (from SSP).
  - `information_resources: Array<{ id: string; name: string; kind: 'compute'|'storage'|'database'|'network'|'identity'|'logging'|'integration'; handles_federal_data: boolean; data_types: string[]; security_objectives: { c: 'Low'|'Moderate'|'High'; i: '…'; a: '…' }; provider: 'aws'|'gcp'|'azure'|'subprocessor'; location: string; component_uuids: string[] }>` — one row per inventoried resource OR per group.
  - `information_flows: Array<{ from: string (resource id); to: string; data_classification: string; transport: 'TLS-1.2'|'TLS-1.3'|'mTLS'|'private-network'|'other'; security_objective: 'C'|'I'|'A'|'CIA' }>` — per MAS-CSO-FLO.
  - `metadata_in_scope: Array<{ resource_id: string; metadata_about: 'federal-customer-data'|'system-operations'|'audit'; description: string }>` — per MAS-CSO-MDI.
  - `third_party_resources_ref: string` — pointer to `third-party-resources.json`.
  - `documented_vs_discovered_diff: MasReconcileResult` — from `core/mas-reconcile.ts`.
  - `provenance`.

- `ThirdPartyResourcesJson` — array of:
  - `entity_name: string`
  - `fedramp_marketplace_status: 'authorized'|'in-process'|'not-listed'`
  - `data_types_processed: string[]`
  - `processing_location: { country: string; region: string }`
  - `contract_id: string` (REQUIRES-OPERATOR-INPUT)
  - `supply_chain_risk_tier: 'low'|'moderate'|'high'|'critical'` (from `subprocessors-sheet.ts` mapping)
  - `notes: string`

**Build steps:**

1. Define interfaces. Sort all arrays deterministically.
2. Pure `buildScopeJson(input)`:
   - Read `out/inventory.json` → `information_resources[]` (one row per inventoried asset OR aggregated per provider×type).
   - Read SSP `system-implementation.components[]` for component-uuid linkage.
   - Read tracker `mas_info_flows` table (operator-curated flows) OR auto-derive flows from inventory edges (S3→Lambda, RDS→EC2, etc.).
   - Call `mas-reconcile.reconcileMas({ documented, discovered })` to embed the drift.
3. Pure `buildInformationFlowSvg(flows)`:
   - Emit PlantUML source (deterministic, sorted).
   - Generate a simple SVG (boxes per resource, arrows per flow). Mirror the LOOP-D pattern (planned): pure-JS no-deps SVG by composing `<svg><g><rect><text><line>` elements. Same OOXML-no-deps philosophy.
4. Pure `buildThirdPartyResourcesJson(subprocessorList)`:
   - One row per subprocessor; pull MAS-CSO-TPR required fields from `subprocessors-sheet.ts`.
   - REQUIRES-OPERATOR-INPUT for `contract_id` (since contracts aren't in cloud SDKs).
5. Pure `buildScopeDocx` — sections: §1 Identity, §2 Information Resources (table), §3 Information Flows (table + reference to SVG), §4 Metadata Inclusion, §5 Third-Party Resources (table), §6 Documented-vs-Discovered Reconciliation, §7 Provenance.
6. Disk emitter `emitAfrMas(outDir, ctx)`.
7. Orchestrator + bundle wiring.

**REQUIRES-OPERATOR-INPUT fields:**

- `information_flows[]`: source = tracker `mas_info_flows` table (operator curates) OR derived from inventory edges. When neither yields rows, emit REQUIRES-OPERATOR-INPUT for the flows section.
- `metadata_in_scope[]`: source = tracker `mas_metadata_in_scope` table (operator describes what metadata-about-federal-customer-data is processed).
- `third_party_resources[].contract_id`: source = operator-supplied (subprocessor contract identifier).
- `data_types[]` per resource: source = inventory tag `fedramp_data_types` OR tracker.
- `handles_federal_data` per resource: source = inventory tag `handles_federal_data` (boolean). Default: `false` (REO Rule 4 — never silently assume yes).

**Test specifications (~13):**

1. `it('builds scope JSON from inventory + SSP', …)` — one resource per inventory asset.
2. `it('aggregates inventory by provider×type when --mas-aggregate flag is set', …)`.
3. `it('emits REQUIRES-OPERATOR-INPUT for information_flows when no tracker rows and no derivable edges', …)`.
4. `it('embeds reconcileMas drift result', …)` — drift surfaces in JSON + .docx.
5. `it('emits one third_party row per registered subprocessor', …)`.
6. `it('REQUIRES-OPERATOR-INPUT for contract_id', …)`.
7. `it('quotes verbatim MAS-CSO-IIR/FLO/MDI/TPR statements in provenance.requirementTexts', …)`.
8. `it('renders deterministic info-flow SVG with sorted nodes + edges', …)`.
9. `it('writes valid PlantUML source', …)` — parseable by the spec grammar (regex sanity check).
10. `it('respects handles_federal_data tag default=false', …)`.
11. `it('docx contains the third-party resources table', …)`.
12. `it('archives prior-period scope-doc for delta tracking', …)`.
13. `it('records provenance.requirementTexts for all 4 MAS MUSTs', …)`.

**REO compliance:**

- `information_resources[]` is derived strictly from real `inventory.json`; no synthetic resources.
- `documented_vs_discovered_diff` comes from `mas-reconcile.ts` (pure set diff). Drift items aren't silently reconciled — they surface as findings.
- `handles_federal_data` defaults FALSE — operator must explicitly tag TRUE (REO Rule 4: no silent yes).

**Verification commands:**

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/afr-mas.test.ts
npm run check:reo
```

**Estimated effort:** 6 days.

---

### Slice G.G5 — AFR-SCG (Secure Configuration Guide)

**Why this slice:** SCG-CSO-RSC requires the CSP to publish a Secure
Configuration Guide with specific minimum content (encryption,
authentication, network, logging, etc.). SCG-CSO-AUP requires
instructions in the authorization package explaining how to obtain and
use the guide. The existing `providers/{aws,gcp,azure}/reference-arch.ts`
emits an architecture-of-record (what the CSP runs) and
`core/scg-comparator.ts` diffs declared-vs-observed; neither produces
the published guide.

**Files to create:**

- `cloud-evidence/core/afr-scg.ts` — pure builders for:
  - `buildScgBaseline(input: ScgBaselineInput): ScgBaseline` — combines `providers/{aws,gcp,azure}/reference-arch.ts` outputs + the FedRAMP Moderate parameter overlay (from `core/control-benchmark.ts`) into a single machine-readable baseline that `core/scg-comparator.ts` already consumes.
  - `buildScgGuideDocx(input: ScgGuideInput): { bytes: Uint8Array }` — human-readable .docx (mirrors `core/roe-emit.ts`).
  - `buildUseInstructionsMarkdown(input): string` — per SCG-CSO-AUP.
- `cloud-evidence/tests/core/afr-scg.test.ts`.
- `cloud-evidence/docs/loops/AFR-SCG-RUNBOOK.md`.

**Files to extend:**

- `core/scg-comparator.ts` — extend `loadScgBaseline` to accept the new `afr-scg/scg-baseline.json` path directly (currently accepts any path; just document the canonical location).
- `providers/{aws,gcp,azure}/reference-arch.ts` — add a `getReferenceArchBaseline(): ReferenceArchBaseline` exporter that G.G5 reads. (Each file already constructs the data; expose it as a structured return alongside the existing finding emit.)
- `core/orchestrator.ts` — `--afr-scg` flag + env.
- `core/submission-bundle.ts` — catalogue rows for `afr-scg/secure-configuration-guide.docx`, `afr-scg/use-instructions.md`, `afr-scg/scg-baseline.json`.

**Schemas / standards:**

- `ScgGuideInput`:
  - System identity from SSP.
  - `baseline: ScgBaseline` (re-uses `core/scg-comparator.ts` shape).
  - Per-cloud architecture sections (from `reference-arch.ts`).
  - Operator-supplied sections (REQUIRES-OPERATOR-INPUT when absent):
    - `customer_responsibilities: string` — what the customer must configure (e.g. IAM roles, network ACLs).
    - `secure_defaults_rationale: string` — why these defaults.
    - `deviation_request_process: string` — how a customer requests a deviation.
    - `customer_support_contact: string`.
  - Mandatory FedRAMP-specified sections (auto-rendered):
    - Encryption (FIPS-validated module IDs from `providers/{aws,gcp,azure}/crypto.ts`, AES-256, RSA-2048+).
    - Authentication (MFA from IAM collectors).
    - Network (segmentation from CNA collectors).
    - Logging (from MLA collectors).
    - Vulnerability response (from VDR collectors).
    - Patching cadence.

- `ScgBaseline` format — already defined in `core/scg-comparator.ts:ScgBaseline` (version + settings map). G.G5 produces a fully-populated baseline; the comparator pre-existed for the diff.

**Build steps:**

1. Define interfaces.
2. Pure `buildScgBaseline`:
   - Call `getReferenceArchBaseline()` from each registered provider.
   - Merge with FedRAMP Moderate parameter overlay from `core/control-benchmark.ts` (e.g. SC-7 baseline parameter "Boundary protection devices = network firewall + WAF").
   - Output a flat map: `setting_key → expected value`.
   - Tag every setting with `source: 'reference-arch' | 'control-benchmark' | 'operator'`.
3. Pure `buildScgGuideDocx`:
   - §1 Overview + System Identity.
   - §2 How to Obtain (per SCG-CSO-AUP).
   - §3 How to Use (deployment steps, version-tracking).
   - §4 Mandatory Secure Defaults (encryption, auth, network, logging, VDR).
   - §5 Customer Responsibilities (operator-supplied).
   - §6 Deviation Request Process (operator-supplied).
   - §7 Version History.
   - §8 Provenance.
4. Pure `buildUseInstructionsMarkdown` — short doc with TOC, contact, version, retrieval URL.
5. Disk emitter `emitAfrScg(outDir, ctx)`.
6. Orchestrator + bundle wiring.

**REQUIRES-OPERATOR-INPUT fields:**

- `customer_responsibilities`, `secure_defaults_rationale`, `deviation_request_process`, `customer_support_contact`: source = tracker `afr_scg_narratives` table (operator types in UI) OR `org-profile.yaml`.
- `scg_publish_url`: source = CLI flag `--scg-publish-url` (where the guide is hosted for customers).

**Test specifications (~12):**

1. `it('merges reference-arch outputs from AWS+GCP+Azure into one baseline', …)`.
2. `it('flat-map setting keys are sorted for determinism', …)`.
3. `it('every setting carries a source attribution', …)`.
4. `it('emits REQUIRES-OPERATOR-INPUT for customer_responsibilities when missing', …)`.
5. `it('renders the 7 mandatory secure-defaults sections in the docx', …)`.
6. `it('quotes verbatim SCG-CSO-RSC + SCG-CSO-AUP statements in provenance', …)`.
7. `it('uses FIPS-validated module IDs from crypto.ts collectors', …)`.
8. `it('use-instructions markdown contains the publish URL when supplied', …)`.
9. `it('version-history section appends without rewriting prior rows', …)`.
10. `it('docx zip structure is valid + store-only', …)`.
11. `it('scg-comparator.ts can round-trip the emitted baseline', …)` — feed `scg-baseline.json` back into `loadScgBaseline` + run a diff.
12. `it('records provenance.requirementTexts for both SCG MUSTs', …)`.

**REO compliance:**

- Every setting value traces to: reference-arch (real SDK observation), control-benchmark (FedRAMP-published parameter), or operator. No fabricated security defaults.
- The baseline is signed; the comparator round-trips the same bytes back for the diff.
- REQUIRES-OPERATOR-INPUT used for customer-facing narrative only.

**Verification commands:**

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/afr-scg.test.ts
npm run check:reo
```

**Estimated effort:** 5 days.

---

### Slice G.G6 — AFR-CCM (Continuous Monitoring per 20x)

**Why this slice:** CCM-OAR-AVL requires a published Ongoing Authorization
Report every 3 months. CCM-OAR-NRD requires the next-report date to be
publicly stated. CCM-OAR-FBM requires an asynchronous feedback mechanism.
CCM-OAR-AFS requires an anonymized summary of feedback. CCM-QTR-REG
requires a registration link / calendar file for Quarterly Review
meetings. G.G6 ships all five.

This slice is intentionally tight-loop with **LOOP-E** (the monthly
ConMon agent): LOOP-E.E1 emits the monthly ConMon report; G.G6 emits the
quarterly OAR that aggregates 3 months of those reports. The OAR is the
CSP's customer-facing 3-month rollup; LOOP-E.E1 is the internal monthly
delivery.

**Files to create:**

- `cloud-evidence/core/afr-ccm.ts` — pure builders for:
  - `buildOarJson(input: OarInput): OarJson` — machine-readable OAR per CCM-OAR-AVL.
  - `buildOarMarkdown(input: OarInput): string` — human-readable OAR (also rendered to PDF in a later post-step; G.G6 ships .md + .json; PDF generation is left to operator + LOOP-E.E1 pipeline).
  - `computeNextOarTargetDate(lastOarDate: ISOString): ISOString` — last + 3 months per CCM-OAR-AVL cadence.
  - `buildFeedbackSummary(input: FeedbackInput): AnonymizedFeedbackSummary` — anonymized per CCM-OAR-AFS.
  - `buildQuarterlyMeetingPacket(input): { ics_bytes: Uint8Array; registration_url: string; meeting_info_json: object }` — RFC 5545 .ics file + registration URL per CCM-QTR-REG.
- `cloud-evidence/tests/core/afr-ccm.test.ts`.
- `cloud-evidence/tracker/server/routes/afr-ccm-feedback.ts` — POST `/api/afr-ccm/feedback` (anonymous receipt), GET `/api/afr-ccm/feedback?period=…`. The route auto-strips IP + user-agent + timestamp to the nearest day (anonymization per CCM-OAR-AFS).
- `cloud-evidence/tracker/server/routes/afr-ccm-feedback.test.ts`.
- `cloud-evidence/tracker/client/src/pages/CcmFeedback.tsx` — public feedback form (no auth required).
- `cloud-evidence/tracker/server/schema.sql` — additive: `afr_ccm_feedback`, `afr_ccm_quarterly_meetings`.
- `cloud-evidence/docs/loops/AFR-CCM-RUNBOOK.md`.

**Files to extend:**

- `core/orchestrator.ts` — `--afr-ccm` flag + env. Default cadence: quarterly. Flag `--afr-ccm-period=YYYY-Qn` selects the period.
- `core/submission-bundle.ts` — catalogue rows for `afr-ccm/oar-<YYYY-Qn>.json`, `.md`, `afr-ccm/feedback-summary-<YYYY-Qn>.json`, `afr-ccm/quarterly-meeting-<YYYY-Qn>.ics`.
- `core/oscal-poam.ts` — read by G.G6 to compute "open POA&M counts by severity for the report period" (required OAR field).
- `core/inventory-coverage.ts` — read by G.G6 to compute "inventory coverage trend over the report period".

**Schemas / standards:**

- `OarJson` (machine-readable, OSCAL-friendly):
  - `system_id`, `system_name`, `csp_name`.
  - `report_period: { start: ISO; end: ISO }` — last 3 months.
  - `next_report_target_date: ISOString` — per CCM-OAR-NRD.
  - `summary_sections: { posture_summary, control_assessment_summary, vulnerability_summary, incident_summary, change_summary, audit_findings_summary, planned_activities_summary }` — high-level per CCM-OAR-AVL "at least" list.
  - `feedback_mechanism: { url: string; description: string }` — per CCM-OAR-FBM.
  - `feedback_summary_ref: string` — pointer to the anonymized summary.
  - `quarterly_review: { date: ISOString; registration_url: string; calendar_file: string }` — per CCM-QTR-REG.
  - `provenance`.

- `AnonymizedFeedbackSummary` (per CCM-OAR-AFS): array of `{ category: string; question_or_feedback_summary: string; response: string; date_bucket: 'YYYY-MM' }`. No `submitted_by`, no `ip_address`, no exact timestamps.

- `.ics` file: hand-rolled RFC 5545 string (no external dep — same philosophy as our other no-dep emitters). Required properties: `BEGIN:VCALENDAR`, `VERSION:2.0`, `PRODID:-//FedRAMP 20x cloud-evidence//EN`, one `VEVENT` per meeting with `UID`, `DTSTAMP`, `DTSTART`, `DTEND`, `SUMMARY`, `DESCRIPTION`, `URL`, `END:VEVENT`, `END:VCALENDAR`. Line-folded at 75 octets.

**Build steps:**

1. Define interfaces. Period IDs are `YYYY-Qn` (e.g. `2026-Q3`).
2. Pure `computeNextOarTargetDate`: takes last OAR date (ISO) + adds exactly 3 months (handling Feb 28/29).
3. Pure `buildOarJson`:
   - Aggregate POA&M open counts from `out/poam.json` for the report period.
   - Aggregate findings + incidents + SCN events + audit findings + KSI coverage from real evidence.
   - Build the 7 summary sections per CCM-OAR-AVL.
4. Pure `buildOarMarkdown` — renders the JSON to human-readable markdown.
5. Pure `buildFeedbackSummary`:
   - Strip raw user details from `afr_ccm_feedback` rows (no IP, no UA, no exact timestamp).
   - Bucket by month (`YYYY-MM`).
   - Group by `category` (per the feedback form's category select).
6. Pure `buildQuarterlyMeetingPacket`:
   - Inputs: meeting date, registration URL, description.
   - Emit RFC 5545 `.ics` (hand-rolled).
7. Disk emitter `emitAfrCcm(outDir, ctx)`.
8. Tracker route POST `/feedback` accepts anonymous submissions; rate-limited by tracker's existing limiter. Strips IP at write time.
9. UI public form (no auth) embedded as a tracker route at `/feedback`.

**REQUIRES-OPERATOR-INPUT fields:**

- `feedback_mechanism.url`: source = CLI flag `--ccm-feedback-url` (default = `<tracker-base-url>/feedback`).
- `quarterly_review.date` + `registration_url`: source = tracker `afr_ccm_quarterly_meetings` table (operator schedules).
- `summary_sections.posture_summary`: composed from auto-derived metrics; if any underlying metric is missing, the section row carries REQUIRES-OPERATOR-INPUT.

**Test specifications (~13):**

1. `it('computes next OAR target date as last + 3 months', …)` — including Feb 29 case.
2. `it('aggregates open POA&M counts for the report period', …)` — from real `poam.json`.
3. `it('renders all 7 summary sections in OAR markdown', …)`.
4. `it('writes deterministic OAR JSON', …)` — byte-stable on same inputs.
5. `it('quotes verbatim CCM-OAR-AVL + NRD + FBM + AFS + QTR-REG statements in provenance', …)`.
6. `it('strips IP + UA from feedback rows during anonymization', …)`.
7. `it('buckets feedback by month (YYYY-MM) only', …)` — no exact timestamps in output.
8. `it('groups feedback by category', …)`.
9. `it('emits valid RFC 5545 .ics with required properties', …)` — parse + assert each prop present.
10. `it('line-folds .ics at 75 octets', …)`.
11. `it('feedback POST does not require auth', …)`.
12. `it('feedback POST is rate-limited per tracker config', …)`.
13. `it('emits REQUIRES-OPERATOR-INPUT for quarterly_review when no scheduled meeting', …)`.

**REO compliance:**

- OAR sections sourced from real `poam.json` + KSI coverage + inventory; no fabricated metrics.
- Feedback anonymization is enforced at write time (database constraint + route logic). No raw PII archived.
- `.ics` file is constructed from operator-supplied date + URL only — never auto-scheduled.
- `next_report_target_date` is computed deterministically — no rounding to "approximately".

**Verification commands:**

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/afr-ccm.test.ts
npm test -- tracker/server/routes/afr-ccm-feedback.test.ts
npm run check:reo
```

**Estimated effort:** 6 days (1d schema+builders, 1d feedback route+anonymization, 1d .ics emitter, 1d UI, 1d tests, 1d runbook+verify).

---

## 5. Loop-wide acceptance criteria

LOOP-G is **complete** when ALL of:

1. Every G.G1–G.G6 slice ships with all CHANGELOG entries + STATUS.md updates per Section 8.
2. `npm run typecheck` passes; `npm test` passes; `npm run check:reo` returns 0.
3. Every AFR-* family has a corresponding `out/<family>/…` artifact set (FSI: 2, ICP: 2, ADS: 3 + archive, MAS: 5, SCG: 3, CCM: 4) wired into `core/submission-bundle.ts` catalogue.
4. `tracker/server/schema.sql` migrations applied; tracker UI exposes the 3 new pages (FsiInbox, IcpIncidents, CcmFeedback).
5. For each of the 35 CSP-actionable AFR MUST entries cited in Section 3, there is a corresponding emit-field OR tracker-row mapping in code, **and** a verbatim FRMR statement quoted in `provenance.requirementTexts` of the emitting artifact.
6. `npm run lint:no-stubs` returns 0; no LOOP-G slice introduces forbidden tokens in production paths.
7. `npm run check:provenance` returns 0; every new emit-field carries provenance.
8. An end-to-end orchestrator dry-run with `--afr-fsi --afr-icp --afr-ads --afr-mas --afr-scg --afr-ccm --submission-bundle --sign` produces a single signed tarball that includes every AFR artifact + the OAR is reachable via `INDEX.json` lookup.
9. The submission bundle's `INDEX.json.gaps` for the AFR roles is empty when all operator inputs are supplied.
10. Cross-loop dependencies are documented: LOOP-E.E1 references G.G6 OAR cadence; LOOP-F.F4 references G.G2 incident records; LOOP-I.I1 surfaces G.G1 inbox health + G.G6 OAR cadence as posture tiles.

---

## 6. Open questions / caveats

1. **FSI webhook spec stability** (G.G1) — FedRAMP has not published a
   standardized inbound-webhook schema for FSI senders. Today the CSP
   chooses the receive endpoint (any RFC-5321 mailbox). G.G1 ships an
   HMAC-validated tracker webhook that any email provider can forward
   to. If FedRAMP publishes a standard sender format later, only the
   `classification` derivation logic in `afr-fsi.ts` needs to change.

2. **CISA Incident Reporting System API** (G.G2) — `myservices.cisa.gov/irf`
   is currently a web form, not an API. G.G2 generates the report packet
   in the format CISA expects and the operator manually submits. If CISA
   publishes an API later, G.G2 can add a submitter module without
   shape-breaking the tracker data.

3. **OSCAL Component Definition mapping for SCG-CSO-RSC** (G.G5) — the
   OSCAL Component Definition model can represent secure-configuration
   baselines, but the FRR-RSC-01/02/03 enumerated content list maps
   imperfectly. G.G5 emits both `scg-baseline.json` (flat map) AND a
   companion OSCAL Component Definition file when `--scg-oscal` is set
   (deferred from primary G.G5 scope; a quick follow-up if 3PAO adoption
   demands it).

4. **OAR PDF rendering** (G.G6) — generating PDFs without an external
   dep is hard. G.G6 ships .md + .json; the operator can render to PDF
   via the FedRAMP-published markdown→PDF template, or LOOP-E.E1 can
   inherit a pure-JS PDF emitter later.

5. **3-year retention enforcement** (G.G3) — ADS-CSO-HAD requires 3-year
   retention. G.G3 stamps `retention_expiry` on each archived snapshot,
   but the actual enforcement (immutable storage, write-once) is
   LOOP-H.H2's responsibility. G.G3 does not delete anything; LOOP-H
   does the retention audit.

6. **Trust-Center vs USDA Connect choice** (G.G3 + G.G2) — ADS-CSX-UTC
   requires a "FedRAMP-compatible trust center"; the CSP can either use
   the USDA Connect.gov repository (Low/Mod) or a vendor Trust Center.
   G.G3 supports both via the `--trust-center-url` flag; the artifact
   shape is the same either way.

7. **OAR cadence + ConMon overlap** (G.G6 + LOOP-E.E1) — the OAR is
   quarterly; LOOP-E.E1 is monthly. The OAR aggregates 3 LOOP-E reports;
   the exact aggregation rules are still being clarified by FedRAMP.
   G.G6 defaults to "concatenate-summarize" but exposes the aggregation
   function so it can be re-tuned without re-emitting prior periods.

---

## 7. Status tracking

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| G.G1 | AFR-FSI (FedRAMP Security Inbox) | pending | — | — |
| G.G2 | AFR-ICP (Incident Communications Procedures) | pending | — | — |
| G.G3 | AFR-ADS (Authorization Data Sharing) | pending | — | — |
| G.G4 | AFR-MAS (Minimum Assessment Scope) | pending | — | — |
| G.G5 | AFR-SCG (Secure Configuration Guide) | pending | — | — |
| G.G6 | AFR-CCM (Continuous Monitoring per 20x) | pending | — | — |

---

## 8. Slice completion procedure (REO-enforced)

When a LOOP-G slice ships, the implementer MUST do all of the following,
in order:

1. **Verify green** — from `cloud-evidence/`:
   ```bash
   npm run typecheck
   npm test
   npm run check:reo
   ```
   All three must return 0. If any test fails or REO guardrail trips,
   FIX the underlying issue + retry. Do not skip + do not amend.

2. **Update Section 7 status table** — set the slice's status to `done`,
   replace `—` with the short commit hash, replace `—` with the ISO
   completion date.

3. **Add a CHANGELOG.md "Unreleased" entry** under
   `### Added — LOOP-G.<slice-id>: <title>` following the LOOP-A
   precedent. Include:
   - 1-paragraph "why this slice".
   - Bulleted list of every new file + module name + role.
   - For tracker-DB-touching slices: list the migrations + new tables.
   - For artifact-emitting slices: list the new well-known catalogue roles.
   - Verification footer: typecheck clean; N tests passing (+M from this slice); `npm run check:reo` returns 0.

4. **Update `cloud-evidence/docs/STATUS.md`** — set the slice status to
   `done` and the loop-completion percentage. (If `STATUS.md` does not
   yet exist when LOOP-G work begins, create it during G.G1 with the
   table format shown in Section 7.)

5. **Commit** with message:
   ```
   LOOP-G.<slice-id>: <title>
   ```
   Single-slice-per-commit. No mixed scopes. Sign-off line per repo
   convention.

6. **Push to origin/main** (or open a PR if branch protection is enabled
   for that environment).

7. **Run the orchestrator end-to-end smoke** locally before declaring
   the slice merged:
   ```bash
   cd cloud-evidence
   npm run collect -- --impact-level moderate --afr-<slice>
   ls -la out/afr-<family>/
   ```
   Confirm the artifact lands + is signed + appears in the submission
   bundle when `--submission-bundle` is added.

If ANY step blocks for > 1h, surface a Section 6 caveat or escalate to
the EXECUTION-PLAN open-caveats list rather than fudging the slice
"done" criteria. The REO standard is enforceable, not aspirational
(per `cloud-evidence/CLAUDE.md`).
