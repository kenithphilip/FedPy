# SECTION F — FedRAMP 20x specific deliverables

> **Scope:** This section enumerates the artifacts that are *unique to the
> FedRAMP 20x program* — i.e. obligations that did not exist (or existed only
> in narrative form) under Rev5, and that the 20x machine-readable + Phase-Two
> "automated and opinionated validation" mandate now require as first-class,
> emit-able deliverables.
>
> SECTION A covers the Word document template pack (SSP / SAP / SAR / CMP /
> ISCP / IRP / PIA / etc.). SECTION B covers the 3PAO assessor experience.
> SECTION F is the 20x-specific overlay: FRMR ingestion, 60-KSI evidence
> envelopes, the CSX-SUM aggregator, the ten AFR-* families, and the
> Phase-Two 8-KSI delta.
>
> **Authority:** RFC-0014 (Phase Two automated validation), RFC-0024 (OSCAL
> mandate), the FRMR machine-readable catalog
> (`github.com/FedRAMP/docs` v0.9.43-beta), and the FedRAMP 20x Phase Two
> Pilot Operating Guidelines.

---

## 1. Purpose

FedRAMP 20x reframes authorization away from human-narrative attestation
toward continuously-verifiable, machine-readable Key Security Indicators
(KSIs). Where Rev5 evaluated the body of NIST 800-53 controls against a
narrative SSP, 20x evaluates a much smaller set of KSI rules — each backed
by a real, automated technical check — and demands that every CSP emit the
evidence trail itself, not assemble it from external scan reports after the
fact.

This section catalogues the artifacts that this re-framing creates. They
fall into three buckets:

1. **FRMR ingestion and the 60-KSI evidence chain (F1–F3).** The
   FedRAMP Machine-Readable (FRMR) catalog *is* the new authoritative
   requirements source. Every downstream emitter — SSP, AP, AR, POA&M,
   ConMon — pulls from FRMR-ID-keyed evidence envelopes. If FRMR
   ingestion is wrong, every other 20x artifact is wrong.
2. **The AFR-* family deliverables (F5–F13).** Authorization-Framework-
   Related (AFR) families are the operational obligations that wrap the
   technical KSI evaluations: how the CSP receives FedRAMP communications
   (FSI), how incidents are reported (ICP), how authorization data is
   shared (ADS), what's in scope (MAS), how monitoring is published (CCM),
   how the offering is securely configured (SCG), how significant changes
   are notified (SCN), how vulnerabilities are detected + responded to
   (VDR), and how cryptography is validated (UCM). Per R1, all ten are
   REQUIRED at Moderate.
3. **The Phase-Two 8-KSI delta (F14).** RFC-0014 introduced 8 new KSIs
   (5 Moderate-only + 3 Low+Moderate) since the initial 20x KSI set.
   These exist in FRMR v0.9.43-beta under renamed 3-letter IDs and are
   already in our collector set; F14 tracks them as a named deliverable
   so a future RFC-0014 revision is auditable.

Why this section exists in the FedRAMP authorization framework: without
the F-family artifacts, FedRAMP 20x degenerates into "Rev5 with extra
JSON." The KSI evidence chain, the FRMR ingestion guarantee, and the AFR
operational deliverables are what make 20x *truly automated and opinionated*
per RFC-0014.

---

## 2. Artifact catalogue (F1–F14)

| ID | Artifact | Required | Consumer(s) | Format(s) | Source obligation | FedPy status | Implementing loop.slice |
|---|---|---|---|---|---|---|---|
| **F1** | FRMR catalog ingestion (FRMR.documentation.json + KSI / FRR extracts) | ✅ | CSP-internal (every other emitter) | JSON (committed snapshot) + TypeScript bindings | FRMR repo (`github.com/FedRAMP/docs` v0.9.43-beta); RFC-0024 §3 (machine-readable source-of-truth) | **HAVE** — `scripts/extract-frmr-requirements.mjs`, `docs/frmr-requirements.generated.json` (60 KSI + 163 FRR), `core/ksi-map.ts` | Pre-LOOP-A (shipped); FRMR refresh under E.E1 monthly job |
| **F2** | 60-KSI evidence envelopes (per-KSI signed JSON) | ✅ | 3PAO, PMO, AO | JSON (signed Ed25519 + RFC 3161 timestamp) | RFC-0014 §2 ("truly automated and opinionated validation of Key Security Indicators"); FRMR KSI section | **HAVE** — `core/collectors.ts`, `providers/{aws,gcp,azure}/*.ts`, 44 collector-tracked KSIs at AWS+GCP+Azure parity; 16 process-artifact KSIs via tracker | LOOP-A (shipped); ongoing maintenance under E |
| **F3** | CSX-SUM (Implementation Summary aggregator) | ✅ | 3PAO, PMO | JSON (signed) + Markdown rollup | FRR-PVA-17 (`PVA-TPX-SUM`); FRMR FRR.KSI section MAS/ORD/SUM meta-rules | **HAVE** — `core/csx-sum-aggregator.ts` emits `KSI-CSX-SUM.json`; classifier note recorded (FRR-class, not 60-KSI inflation) | Pre-LOOP-A (shipped); SAR-draft linkage under F.F7 |
| **F4** | OSCAL POA&M v1.1.2 (20x wire format) | ✅ | 3PAO, PMO, AO via USDA Connect.gov | OSCAL JSON + XML + companion `.xlsx` | OSCAL v1.1.2 `plan-of-action-and-milestones` schema (NIST `usnistgov/OSCAL`); RFC-0024; FedRAMP Rev5 Playbook ConMon Overview | **HAVE** — `core/oscal-poam.ts` (LOOP-A.A1) | LOOP-A.A1 (shipped); risk-score props extension at LOOP-B.B1; monthly re-emit at LOOP-E.E2 |
| **F5** | AFR-PVA (Persistent Validation and Assessment) | ✅ | 3PAO, PMO | JSON (signed); CSX-SUM rollup; AR observations | FRMR family PVA (R1: 12 MUSTs at Moderate; 6 CSX + 6 TPX); RFC-0014 §2 | **HAVE** — `core/pva-collector.ts` + `core/csx-sum-aggregator.ts` cover 6 CSX MUSTs (FAV / IVV / NMV / PMV / RPV / VAL). 6 TPX MUSTs surfaced in assessor UI but not auto-fulfilled. | LOOP-G.G0 (verification slice — confirm 6 CSX MUSTs map to emitters; surface 6 TPX MUSTs in tracker — partial); LOOP-F.F1 (3PAO sign-off UI) for TPX-side |
| **F6** | AFR-FSI (FedRAMP Security Inbox) | ✅ | FedRAMP PMO | Inbox-config JSON + receipt log + required-action log (tracker DB) | FRMR family FSI (R1: 13 MUSTs at Moderate; 6 CSO MUSTs CSP-side: CRA, EMR, INB, NOC, RCV, TFG) | **MISSING** — no current module | **LOOP-G.G1** |
| **F7** | AFR-ICP (Incident Communications Procedures) | ✅ | FedRAMP PMO, CISA, agency POCs | .docx incident templates + tracker DB tables (incidents, updates, finals) | FRMR family ICP (R1: 6 MUSTs at Moderate, all CSX/CSP-side: FIR, ICU, IRA, IRC, IRF, RPT) | **MISSING** — no current module; RoE (LOOP-A.A5) already cross-references ICP | **LOOP-G.G2** |
| **F8** | AFR-ADS (Authorization Data Sharing) | ✅ | Agencies, Trust Centers, public | Machine-readable service-list JSON + historical archive + Trust-Center connector | FRMR family ADS (R1: 14 MUSTs at Moderate; 6 CSO/CSX MUSTs CSP-side: CBF, HAD, PUB, RIS, SVC, UTC) | **PARTIAL** — `core/signal-emitter.ts` placeholder only | **LOOP-G.G3** (replaces signal-emitter placeholder) |
| **F9** | AFR-MAS (Minimum Assessment Scope) | ✅ | 3PAO, PMO | Scope doc (.docx) + info-flow diagram + IR inventory + 3rd-party resource enumeration | FRMR family MAS (R1: 4 MUSTs at Moderate, all CSO/CSP-side: FLO, IIR, MDI, TPR) | **PARTIAL** — `core/signal-emitter.ts` placeholder; IR-inventory partially covered by Appendix M (inventory.json); third-party partial via `core/subprocessors-sheet.ts` | **LOOP-G.G4** (replaces signal-emitter placeholder; D.D3 data-flow diagram feeds MAS-CSO-FLO) |
| **F10** | AFR-CCM (Continuous Monitoring per 20x) | ✅ | FedRAMP PMO, agencies | OAR (Ongoing Authorization Report) JSON + feedback form + next-report-date schedule + QTR meeting registration | FRMR family CCM (R1: 10 MUSTs at Moderate; CSP-actionable subset: OAR-AVL, OAR-FBM, OAR-NRD, QTR-REG) | **PARTIAL** — monthly reports exist (existing scan-aggregation pipeline); publication SLA + feedback mechanism + next-date scheduling + quarterly meeting hooks all missing | **LOOP-G.G6** + **LOOP-E.E1** (monthly ConMon analysis report) + **LOOP-E.E3** (annual assessment generator) |
| **F11** | AFR-SCG (Secure Configuration Guide) | ✅ | Agencies, CSP-internal | .docx SCG + recommended-secure-configuration baseline | FRMR family SCG (R1: 2 MUSTs at Moderate; both CSO/CSP-side: AUP "Use Instructions", RSC "Recommended Secure Configuration") | **PARTIAL** — `providers/*/reference-arch.ts` partial; full SCG doc + FedRAMP-Moderate-baseline defaults missing | **LOOP-G.G5** + **LOOP-C.C9** (baseline configuration document overlap) |
| **F12** | AFR-SCN (Significant Change Notification) | ✅ | FedRAMP PMO, agencies | SCN classification JSON + .docx formal notification + signed audit-records archive | FRMR family SCN (R1: 11 MUSTs at Moderate; 5 CSO MUSTs CSP-side: Evaluate Changes / Historical Notifications / Human-and-Machine-Readable / Required Information / Audit Records) | **PARTIAL** — `core/scn-classifier.ts` emits JSON classification; .docx formal-notification format + audit archive missing | **LOOP-E.E6** (formal SCN .docx emitter, extends existing classifier) |
| **F13** | AFR-VDR (Vulnerability Detection and Response) | ✅ | 3PAO, PMO, AO | Per-VDR-class KSI evidence + reconciled CISA KEV catalog + recommendation-documentation .docx + EVA evaluator hooks | FRMR family VDR (R1: 12 MUSTs at Moderate; 3 CSO MUSTs CSP-side: DET, DOC, RES; 3 EVA MUSTs feed risk-scoring) | **PARTIAL** — `providers/{aws,gcp,azure}/vdr-scan.ts` cover DET; CISA KEV reconcile shipped (`docs/cisa-kev.generated.json`); RES partial via POA&M deadline math; **DOC missing** (recommendation-documentation artifact); EVA-EIR / EVA-ELX / EVA-EPA feed risk score | **LOOP-B.B1** (CVSS+EPSS+criticality+exposure scoring → EVA evaluations) + **LOOP-B.B2** (KEV/PAIN/IRV/LEV deadline math → CSO-RES) + LOOP-G addendum for VDR-CSO-DOC .docx |
| **F14** | AFR-UCM (Using Cryptographic Modules) | ✅ | 3PAO, PMO | Per-cloud cryptography evidence + FIPS-validated module attestation | FRMR family UCM (R1: 1 MUST at Moderate: UCM-CSX-FIP "FIPS-validated cryptographic modules") | **HAVE** — `providers/azure/crypto.ts` + AWS/GCP equivalents cover UCM-CSX-FIP | LOOP-G (verification-only; no new slice) |
| **F15** | RFC-0014 Phase-Two 8-KSI delta tracking | ✅ | CSP-internal traceability | Verification report (Markdown) + ksi-map asserted rows | RFC-0014 §2 (5 Moderate-only KSIs: CNA-08 / MLA-08 / SVC-08/09/10 + 3 Low+Mod: CED-03 / IAM-07 / MLA-07) → renamed to FRMR 3-letter IDs (CNA-EIS, MLA-LET, MLA-ALA, SVC-PRR, SVC-VCM, SVC-RUD, CED-DET, IAM-AAM) | **HAVE** — all 8 present in FRMR v0.9.43-beta; all covered by existing collectors / playbooks (per RFC-0014-VERIFY changelog entry); ksi-map.ts has azure slot wired for SVC-PRR / SVC-VCM / SVC-RUD; AWS/GCP coverage at parity | Pre-LOOP-A (shipped); doc-only artifact under **LOOP-G** (lightweight verification report) |

> **Total artifacts: 15** (F1–F15). The original prompt enumerates 14
> distinct families; F15 (Phase-Two 8-KSI delta tracking) is split out
> because RFC-0014's KSI delta is a named obligation independent of the
> AFR-VDR/UCM mappings.

---

## 3. Per-artifact detail

### F1 — FRMR catalog ingestion

**Source citation:** FedRAMP Machine-Readable Repository,
`https://github.com/FedRAMP/docs`, file `FRMR.documentation.json`,
release **v0.9.43-beta**.

RFC-0024 §3:
> "The Federal Risk and Authorization Management Program (FedRAMP) shall
> publish its requirements in a machine-readable format (FRMR) as the
> authoritative source. All implementations, validators, and reporting
> tools shall consume FRMR directly rather than transcribing requirements
> from narrative documents."

**What the CSP delivers:** a committed snapshot of FRMR at the version
asserted in the SSP / AP / AR / POA&M `metadata.frmr_version` field, plus
a derived `frmr-requirements.generated.json` extract used by every
downstream emitter and validator.

**What FedRAMP authors:** the FRMR catalog itself (versioned releases),
the FRR catalog, and the KSI catalog.

**Cross-references:** every other F-artifact reads from F1. F2's collector
set is keyed by FRMR KSI ID. F3's CSX-SUM rollup quotes FRR-PVA-17 verbatim.
F5–F13 each filter FRMR by `family` field.

**Implementation:** `scripts/extract-frmr-requirements.mjs` walks
`FRMR.documentation.json`, emits 60 ksi-indicator + 163 frr-requirement
rows into `docs/frmr-requirements.generated.json`; `core/ksi-map.ts`
binds each KSI ID to a TypeScript collector function; `tests/core/level-coverage.test.ts`
asserts 60 KSIs to prevent regression to the prior over-counted "63 KSI"
claim (see CSX-PURGE changelog entry).

---

### F2 — 60-KSI evidence envelopes

**Source citation:** RFC-0014 (open RFC) §2:
> "During Phase Two, FedRAMP will expect truly automated and opinionated
> validation of Key Security Indicators for a Moderate authorization."

The FRMR KSI section enumerates 60 KSI IDs (per R1 + the CSX-PURGE
correction). Each KSI has zero or more cloud-evaluatable rules; HYBRID
KSIs also accept alternative-satisfier evidence from operator config.

**Envelope shape (REO-enforced):** every emitted `KSI-<id>.json` carries:

```
{
  "ksi_id": "KSI-...",
  "run_id": "...",
  "collected_at": "ISO-8601",
  "frmr_version": "v0.9.43-beta",
  "providers": [
    { "name": "aws|gcp|azure|tracker",
      "evidence": [{ "source": "<SDK call or DB query>", "data": {...} }] }
  ],
  "findings": [{ "rule_id", "status", "severity", "evidence_refs": [] }]
}
```

**What the CSP delivers:** one signed envelope per KSI, per run, in
`out/`. Signed Ed25519 + RFC 3161 timestamp via `core/sign.ts`.

**What 3PAO / PMO consumes:** the AR cites each envelope by sha256 from the
signed manifest. POA&M findings cite envelopes via `observation.relevant-evidence.href`.

**Cross-references:** F3 (CSX-SUM) aggregates F2 envelopes by family. F4
(POA&M) cites F2 envelopes as `observations`. F5 (AFR-PVA) requires F2
envelopes for the 6 CSX MUSTs. F13 (AFR-VDR) requires VDR-class F2
envelopes joined against the CISA KEV catalog.

**Implementation:** `core/collectors.ts` orchestrates; per-cloud
`providers/{aws,gcp,azure}/*.ts` modules emit per-KSI. Cross-provider
parity now 44/44/44 (AWS+GCP+Azure, all collector-tracked KSIs). The
remaining 16 KSIs are process-artifact (operator-supplied via tracker DB
or config.yaml).

---

### F3 — CSX-SUM Implementation Summary aggregator

**Source citation:** FRR-PVA-17 (`PVA-TPX-SUM` in FRMR, renamed from the
legacy `KSI-CSX-SUM` slot). The FRMR FRR.KSI section also defines
`KSI-CSX-MAS` (Minimum Assessment Scope) and `KSI-CSX-ORD` (AFR Order)
as meta-rules about KSI assessment — these stay categorized as
`frr-requirement` per the CSX-PURGE correction; the synthetic
`KSI-CSX-SUM.json` aggregator file the orchestrator emits is a
legitimate orchestration choice, not a catalog claim.

**What the CSP delivers:** a single signed `KSI-CSX-SUM.json` envelope
that rolls every per-KSI envelope into an implementation summary
(passing / failing / partial counts per family, by impact tier, by
provider).

**What 3PAO / PMO consumes:** the SAR-draft pre-fills its
implementation-summary section from CSX-SUM (LOOP-F.F7). The PMO
dashboard reads the rollup directly.

**Cross-references:** depends on F2 (every KSI envelope). Feeds F4
(POA&M risk dashboard), F5 (AFR-PVA / PVA-TPX-SUM 3PAO sign-off
surface), and SECTION B's assessor UI.

**Implementation:** `core/csx-sum-aggregator.ts`; comment in
`tracker/server/ingest.ts` explains why the tracker still surfaces
CSX as a 12th informational domain despite the authoritative KSI
count being 60.

---

### F4 — OSCAL POA&M v1.1.2 (20x wire format)

**Source citation:** OSCAL v1.1.2 `plan-of-action-and-milestones`
schema, `https://github.com/usnistgov/OSCAL/releases/tag/v1.1.2`,
file `oscal_poam_schema.json`.

RFC-0024 §3 (OSCAL mandate). FedRAMP Rev5 Playbook ConMon Overview:
> "Each month, the CSP uploads an up-to-date POA&M and inventory, along
> with raw vulnerability scan files (when required by agreements with
> agency customers) and reports to the secure repository."

R2 decision (`docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`): full-document
re-emission semantics, OSCAL JSON + XML, with Excel companion shipped
in the LOOP-A.A4 submission bundle for CSPs that prefer the Excel
upload path to USDA Connect.gov.

**What the CSP delivers:** signed OSCAL JSON + XML POA&M, every
failing finding mapped to a `poam-item` + `observation` + `finding` +
optional `risk` with deterministic FedRAMP severity-based deadlines
(Critical 30d / High 60d / Medium 90d / Low 180d / Info 365d from
`envelope.collected_at`).

**Cross-references:** depends on F2 (per-KSI envelopes); feeds the
LOOP-A.A4 submission bundle (`oscal-poam` role in the well-known
catalogue); risk-score props extension at LOOP-B.B1 + B.B2;
monthly re-emit at LOOP-E.E2; risk-acceptance status mapping at LOOP-B.B3.

**Implementation:** `core/oscal-poam.ts`; orchestrator `--oscal-poam`
flag; ajv-validated against committed schema at `docs/oscal/oscal_poam_schema.v1.1.2.json`.

---

### F5 — AFR-PVA (Persistent Validation and Assessment)

**Source citation:** FRMR family PVA. Per R1: 18 Mod-applicable entries,
12 MUSTs. CSP-actionable subset (6 CSX MUSTs):
- `PVA-CSX-FAV` (FRR-PVA-02) "Issues As Vulnerabilities"
- `PVA-CSX-IVV` (FRR-PVA-05) "Independent Verification and Validation"
- `PVA-CSX-NMV` (FRR-PVA-TF-LO/MO-01) "Non-Machine Validation"
- `PVA-CSX-PMV` (FRR-PVA-TF-LO/MO-02) "Persistent Machine Validation"
- `PVA-CSX-RPV` (FRR-PVA-03) "Report Persistent Validation"
- `PVA-CSX-VAL` (FRR-PVA-01) "Persistent Validation"

6 TPX (3PAO) MUSTs: MME, OUC, PAD, PDK, SUM, UNP — surfaced in
assessor UI but **not** auto-fulfilled (REO Rule 1.10: no auto-
generated 3PAO sign-offs).

**What the CSP delivers:** the 6 CSX MUSTs are satisfied by the
existing `core/pva-collector.ts` + `core/csx-sum-aggregator.ts`
emitting machine-readable envelopes that prove persistent validation
is running, that issues map to vulnerabilities (FAV), that an
independent verification path exists (IVV), that non-machine and
machine validation are both covered (NMV + PMV).

**What 3PAO authors:** the 6 TPX MUSTs (Mixed Methods, Outcome
Consistency, Procedure Adherence, Processes Derived from KSIs,
Assessment Summary, Underlying Processes) — sign-offs captured via
tracker (LOOP-F.F1).

**Cross-references:** depends on F2; feeds F3 (CSX-SUM rollup); 3PAO
sign-off surface at LOOP-F.F1.

**Implementation:** verification-only slice (LOOP-G.G0 conceptual) to
confirm each of the 6 CSX MUSTs maps to a real evidence-producing
emitter; LOOP-F.F1 surfaces the 6 TPX MUSTs in the assessor sign-off
UI.

---

### F6 — AFR-FSI (FedRAMP Security Inbox)

**Source citation:** FRMR family FSI. Per R1: 16 Mod-applicable
entries, 13 MUSTs. CSP-actionable subset (6 CSO MUSTs):
- `FSI-CSO-CRA` (FRR-FSI-14) "Complete Required Actions"
- `FSI-CSO-EMR` (FRR-FSI-15) "Emergency Message Routing"
- `FSI-CSO-INB` (FRR-FSI-09) "Maintain a FedRAMP Security Inbox"
- `FSI-CSO-NOC` (FRR-FSI-12) "Notification of Changes"
- `FSI-CSO-RCV` (FRR-FSI-11) "Receive Email Without Disruption"
- `FSI-CSO-TFG` (FRR-FSI-10) "Trust @fedramp.gov and @gsa.gov"

**What the CSP delivers:** an operational inbox endpoint the CSP commits
to monitoring (FSI-CSO-INB), email routing rules that elevate emergency
FedRAMP messages (FSI-CSO-EMR), a notification to FedRAMP whenever the
inbox config changes (FSI-CSO-NOC), receipt confirmation (FSI-CSO-RCV),
explicit trust-list inclusion of `@fedramp.gov` and `@gsa.gov`
(FSI-CSO-TFG), and a closed-loop completion log for FedRAMP-mandated
actions (FSI-CSO-CRA).

**What FedRAMP authors:** the 7 FRP-side MUSTs (CDS, COR, ERT, PNT,
RQA, UFS, VRE) — not CSP-side.

**Cross-references:** RoE (LOOP-A.A5) already references AFR-ICP for
incident handling during testing; F6's emergency routing intersects
with F7 (ICP) for incident reporting flows.

**Implementation:** **LOOP-G.G1** — new `core/afr-fsi.ts` + tracker
routes:
- DB: `fsi_inbox_config (email_endpoint, trust_list[], operator_acknowledged)`
- DB: `fsi_message_log (msg_id, from, subject, received_at, classification, required_action, action_completed_at)`
- Webhook for inbound FedRAMP email; auto-route by classification;
  notification on missed required-action SLA.

---

### F7 — AFR-ICP (Incident Communications Procedures)

**Source citation:** FRMR family ICP. Per R1: 9 Mod-applicable
entries, 6 MUSTs, **all CSX/CSP-side**:
- `ICP-CSX-FIR` (FRR-ICP-07) "Final Incident Report"
- `ICP-CSX-ICU` (FRR-ICP-04) "Incident Updates"
- `ICP-CSX-IRA` (FRR-ICP-02) "Incident Reporting to Agencies"
- `ICP-CSX-IRC` (FRR-ICP-03) "Incident Reporting to CISA"
- `ICP-CSX-IRF` (FRR-ICP-01) "Incident Reporting to FedRAMP"
- `ICP-CSX-RPT` (FRR-ICP-05) "Incident Report Availability"

**What the CSP delivers:** incident reporting templates that route to
FedRAMP (via F6 FSI inbox), CISA, and agency POCs; an incident update
workflow; a final-report archival mechanism with availability per
ICP-CSX-RPT.

**What FedRAMP / CISA / agencies consume:** the reports themselves.

**Cross-references:** depends on F6 (FSI inbox is the FedRAMP delivery
channel for ICP-CSX-IRF). LOOP-C.C3 ships the Incident Response Plan
(IR-8 + IR-3) Word document — IRP narrative; F7 ships the
operational reporting plumbing.

**Implementation:** **LOOP-G.G2** — new `core/afr-icp.ts` + tracker
DB tables: `incidents`, `incident_updates`, `incident_final_reports`.
Workflow: discover → report → update → final → archive. .docx
templates per FedRAMP IR-8 reporting baseline.

---

### F8 — AFR-ADS (Authorization Data Sharing)

**Source citation:** FRMR family ADS. Per R1: 20 Mod-applicable
entries, 14 MUSTs. CSP-actionable subset (6 CSO/CSX MUSTs):
- `ADS-CSO-CBF` (FRR-ADS-02) "Consistency Between Formats"
- `ADS-CSO-HAD` (FRR-ADS-09) "Historical Authorization Data"
- `ADS-CSO-PUB` (FRR-ADS-01) "Public Information"
- `ADS-CSO-RIS` (FRR-ADS-05) "Responsible Information Sharing"
- `ADS-CSO-SVC` (FRR-ADS-03) "Service List"
- `ADS-CSX-UTC` (FRR-ADS-07) "Use Trust Centers"

**What the CSP delivers:** machine-readable service-list publication
(ADS-CSO-SVC), historical authorization archive (ADS-CSO-HAD), public-
information disclosure (ADS-CSO-PUB), responsible-information-sharing
policy enforcement (ADS-CSO-RIS), format-consistent publication
(ADS-CSO-CBF — same data in JSON + .docx + .xlsx), and Trust-Center
usage workflow (ADS-CSX-UTC).

**What Trust-Centers (TRC) / Using-Trust-Centers (UTC) actors author:**
the 8 TRC/UTC/CSL MUSTs (AAI, ACL, PAC, USH, AAD, PGD, TCM, UCP) —
typically not the CSP unless self-managed.

**Cross-references:** ADS-CSO-HAD historical archive overlaps with
LOOP-H.H1 (immutable evidence archive) — H.H1 satisfies the underlying
retention obligation; F8's job is to expose the archive via a
discoverable feed.

**Implementation:** **LOOP-G.G3** — new `core/afr-ads.ts` replacing the
existing `core/signal-emitter.ts` ADS placeholder. Emits machine-
readable service-list JSON + historical archive index + Trust-Center
connector hooks.

---

### F9 — AFR-MAS (Minimum Assessment Scope)

**Source citation:** FRMR family MAS. Per R1: 5 Mod-applicable
entries, 4 MUSTs, **all CSO/CSP-side**:
- `MAS-CSO-FLO` (FRR-MAS-05) "Information Flows and Security Objectives"
- `MAS-CSO-IIR` (FRR-MAS-01) "Identify Information Resources"
- `MAS-CSO-MDI` (FRR-MAS-04) "Metadata Inclusion"
- `MAS-CSO-TPR` (FRR-MAS-03 + FRR-MAS-02) "Third-Party Information Resources"

**What the CSP delivers:** an information-flow diagram + security-
objective tagging (MAS-CSO-FLO — could reuse LOOP-D.D3 data-flow
diagram); information-resource inventory (MAS-CSO-IIR — partially
covered by Appendix M / `out/inventory.json`); metadata inclusion in
the scope doc (MAS-CSO-MDI); third-party resource enumeration
(MAS-CSO-TPR — partially covered by `core/subprocessors-sheet.ts`).

**What 3PAO consumes:** the scope doc forms the basis of the AP's
`reviewed-controls` + `assessment-subjects[]` selections.

**Cross-references:** D.D3 (data flow diagram) feeds MAS-CSO-FLO.
LOOP-J.J2 (subprocessor inventory expansion) feeds MAS-CSO-TPR. F9
unifies all four into the scope artifact required by the AP.

**Implementation:** **LOOP-G.G4** — new `core/afr-mas.ts` replacing
the `core/signal-emitter.ts` MAS placeholder.

---

### F10 — AFR-CCM (Continuous Monitoring per 20x)

**Source citation:** FRMR family CCM. Per R1: 24 Mod-applicable
entries, 10 MUSTs. CSP-actionable subset (4 OAR/QTR):
- `CCM-OAR-AVL` (FRR-CCM-01) "Report Availability"
- `CCM-OAR-FBM` (FRR-CCM-04) "Feedback Mechanism"
- `CCM-OAR-NRD` (FRR-CCM-03) "Next Report Date"
- `CCM-QTR-REG` (FRR-CCM-QR-05) "Meeting Registration Info"

The 3 AGM (Agency) MUSTs and the QTR-MTG / QTR-NRD MUSTs are
partly PMO / partly agency.

**What the CSP delivers:** an Ongoing Authorization Report (OAR)
published on a documented availability SLA (CCM-OAR-AVL); a feedback
mechanism so consumers can submit comments (CCM-OAR-FBM); the next
report date communicated (CCM-OAR-NRD); quarterly review meeting
registration info maintained (CCM-QTR-REG).

**What FedRAMP authors:** the quarterly review meeting itself
(CCM-QTR-MTG); the AGM-side notifications.

**Cross-references:** tightly coupled with **LOOP-E** (continuous
monitoring agent). LOOP-E.E1 emits the monthly ConMon analysis
report; LOOP-E.E3 emits the annual assessment package. F10 wraps
those in the AFR-CCM availability + feedback + scheduling
obligations.

**Implementation:** **LOOP-G.G6** — new `core/afr-ccm.ts` for the 4
OAR/QTR CSP-actionable entries; LOOP-E.E1 + E.E3 provide the
underlying monthly + annual report content.

---

### F11 — AFR-SCG (Secure Configuration Guide)

**Source citation:** FRMR family SCG. Per R1: 9 Mod-applicable
entries, 2 MUSTs, **both CSO/CSP-side**:
- `SCG-CSO-AUP` (no FRR fka) "Use Instructions"
- `SCG-CSO-RSC` (FRR-RSC-01 / 02 / 03) "Recommended Secure Configuration"

**What the CSP delivers:** a use-instructions document explaining how
to securely configure + use the offering (SCG-CSO-AUP); the recommended
secure configuration itself — extending `providers/*/reference-arch.ts`
to a full SCG document with FedRAMP-Moderate-baseline-aligned defaults
(SCG-CSO-RSC).

**What agencies consume:** the SCG when deploying the offering.

**Cross-references:** overlaps with LOOP-C.C9 (CM-2 Baseline
Configuration document). C.C9 is the CSP-internal baseline-config
record; F11 is the customer-facing secure-configuration guide. Both
share the underlying `reference-arch.ts` output.

**Implementation:** **LOOP-G.G5** — new `core/afr-scg.ts` (.docx).

---

### F12 — AFR-SCN (Significant Change Notification)

**Source citation:** FRMR family SCN. Per R1: 17 Mod-applicable
entries, 11 MUSTs. CSP-actionable subset (5 CSO MUSTs):
- Evaluate Changes
- Historical Notifications
- Human-and-Machine-Readable
- Required Information
- Maintain Audit Records

Plus 1 ADP MUST and 5 TRF MUSTs (Transformation-related actors —
partly CSP, partly FedRAMP).

**What the CSP delivers:** an evaluation workflow for significant
changes (the existing `core/scn-classifier.ts` does this);
historical-notification archive (tracker DB); human-and-machine-
readable notification format (we emit JSON + Markdown — F12 adds
the .docx formal-notification format per FedRAMP CMP); all
required information per the FRMR SCN required-info schema;
signed audit-records of every notification.

**Cross-references:** the SCN classifier output is already emitted;
F12 wraps it in the .docx formal-notification format and archives
the signed audit trail.

**Implementation:** **LOOP-E.E6** — new `core/scn-doc.ts` (.docx)
that consumes `core/scn-classifier.ts` JSON.

---

### F13 — AFR-VDR (Vulnerability Detection and Response)

**Source citation:** FRMR family VDR. Per R1: 39 Mod-applicable
entries (the largest family), 12 MUSTs. CSP-actionable subset (3 CSO):
- `VDR-CSO-DET` (FRR-VDR-01) "Vulnerability Detection"
- `VDR-CSO-DOC` (FRR-VDR-11) "Documentation for Recommendations"
- `VDR-CSO-RES` (FRR-VDR-02) "Vulnerability Response"

Three EVA MUSTs (Evaluate Internet-Reachability / Exploitability /
Estimate Potential Adverse Impact) feed into the risk scoring at
LOOP-B.B1.

**What the CSP delivers:** detection evidence per VDR-CSO-DET (the
existing `providers/{aws,gcp,azure}/vdr-scan.ts` reconcile against
CISA KEV); response evidence per VDR-CSO-RES (POA&M deadline math
honoring KEV / PAIN / IRV / LEV cadence — LOOP-B.B2); recommendation
documentation per VDR-CSO-DOC (new .docx artifact under LOOP-G).

**What 3PAO (EVA) authors:** internet-reachability, exploitability,
and potential-adverse-impact evaluations per finding. These feed F4's
risk props but are 3PAO-authored.

**Cross-references:** depends on F2 (VDR-class envelopes); F4
(POA&M) carries the response evidence; LOOP-B.B1 / B.B2 provide
the EVA-evaluation hooks.

**Implementation:**
- VDR-CSO-DET: **shipped** in `providers/*/vdr-scan.ts` + CISA KEV
  reconcile.
- VDR-CSO-RES: **LOOP-B.B2** (KEV / PAIN / IRV / LEV deadline math).
- VDR-CSO-DOC: **LOOP-G addendum** — new `core/vdr-recommendation-doc.ts`
  (.docx) summarizing each open VDR-class finding's recommendation
  language for AO + agency review.
- EVA hooks: **LOOP-F.F1** (assessor sign-off UI captures the three
  EVA evaluations per finding); **LOOP-B.B1** (consumes them).

---

### F14 — AFR-UCM (Using Cryptographic Modules)

**Source citation:** FRMR family UCM. Per R1: 3 Mod-applicable
entries, 1 MUST: `UCM-CSX-FIP` (FRR-UCM-01) "FIPS-validated
cryptographic modules".

**What the CSP delivers:** evidence per UCM-CSX-FIP that all
cryptographic modules in use are FIPS-140-3 (or 140-2 transition)
validated. `providers/azure/crypto.ts` + AWS/GCP equivalents
already collect this.

**Cross-references:** depends on F2 (per-cloud crypto envelopes);
SCG (F11) cites UCM evidence as part of the secure-configuration
narrative.

**Implementation:** **shipped** under pre-LOOP-A Azure parity
(`providers/azure/crypto.ts`). No new slice; LOOP-G performs
verification only.

---

### F15 — Phase-Two 8-KSI delta tracking (RFC-0014)

**Source citation:** RFC-0014 §2 introduced 8 KSIs beyond the
original 20x KSI set:
- 5 Moderate-only: KSI-CNA-08, KSI-MLA-08, KSI-SVC-08 / 09 / 10
- 3 Low + Moderate: KSI-CED-03, KSI-IAM-07, KSI-MLA-07

These have been merged to FRMR v0.9.43-beta under renamed 3-letter
IDs (per the RFC-0014-VERIFY changelog entry):

| RFC-0014 ID | FRMR ID | Coverage |
|---|---|---|
| KSI-CNA-08 | KSI-CNA-EIS | shipped (AWS / GCP / Azure) |
| KSI-MLA-08 | KSI-MLA-LET | shipped |
| KSI-MLA-07 | KSI-MLA-ALA | shipped |
| KSI-SVC-08 | KSI-SVC-PRR | shipped (Azure parity slice closed) |
| KSI-SVC-09 | KSI-SVC-VCM | shipped |
| KSI-SVC-10 | KSI-SVC-RUD | shipped |
| KSI-CED-03 | KSI-CED-DET | shipped |
| KSI-IAM-07 | KSI-IAM-AAM | shipped |

**What the CSP delivers:** per-KSI envelopes (F2) for each of the 8;
no separate artifact required beyond F2.

**Cross-references:** F1 (FRMR ingestion confirms 8/8 present); F2
(8 envelopes per run).

**Implementation:** **shipped** pre-LOOP-A. Doc-only verification
artifact under LOOP-G: a Markdown report asserting the 8 ID
renames + the corresponding ksi-map rows + the per-cloud collector
presence. Useful when RFC-0014 publishes a revision that adds / removes
KSIs — a fixed reference point for traceability.

---

## 4. Acceptance criteria for SECTION F

SECTION F is **complete** when *all* of the following are true:

1. **F1 (FRMR ingestion):** the committed `docs/frmr-requirements.generated.json`
   tracks the latest FRMR release (currently v0.9.43-beta); the extractor
   script regenerates byte-identical output from the source; the 60-KSI
   assertion in `tests/core/level-coverage.test.ts` passes.
2. **F2 (60-KSI evidence):** every collector-tracked KSI emits an envelope
   on a real-evidence run; every process-artifact KSI has a tracker
   form + operator-supplied audit record path. `inventory-coverage.json`
   shows no regression; `npm run check:reo` is green.
3. **F3 (CSX-SUM):** `KSI-CSX-SUM.json` aggregates every per-KSI envelope
   with passing / failing / partial counts per family and per impact tier;
   tests assert no double-counting.
4. **F4 (OSCAL POA&M):** ✅ shipped LOOP-A.A1. Extension under B.B1 + B.B2
   (risk-score props + KEV/PAIN/IRV/LEV deadline math) lands before
   first Phase-Two-pilot-grade submission.
5. **F5 (AFR-PVA):** all 6 CSX MUSTs map to a real evidence-producing
   emitter; 6 TPX MUSTs surfaced in the assessor sign-off UI (LOOP-F.F1).
6. **F6 (AFR-FSI):** `core/afr-fsi.ts` ships; tracker DB tables
   exist; inbound webhook live; trust-list assertion includes
   `@fedramp.gov` + `@gsa.gov`; required-action SLA enforcement runs.
7. **F7 (AFR-ICP):** `core/afr-icp.ts` ships; incident-reporting
   templates emit .docx for FedRAMP + CISA + agencies; tracker
   workflow (discover → report → update → final → archive) exercised
   end-to-end in tests.
8. **F8 (AFR-ADS):** `core/afr-ads.ts` ships; `core/signal-emitter.ts`
   ADS placeholder removed; service-list JSON published; historical
   archive indexed; Trust-Center connector configured.
9. **F9 (AFR-MAS):** `core/afr-mas.ts` ships; scope doc emits with
   info-flow diagram reference (LOOP-D.D3), IR inventory reference
   (Appendix M), metadata inclusion, third-party enumeration
   (LOOP-J.J2).
10. **F10 (AFR-CCM):** `core/afr-ccm.ts` ships; report availability
    SLA tracked; feedback form live; next-report-date scheduling
    runs; quarterly meeting registration link maintained;
    LOOP-E.E1 + E.E3 dependencies satisfied.
11. **F11 (AFR-SCG):** `core/afr-scg.ts` ships; use-instructions
    .docx generated; recommended-secure-configuration extends
    `reference-arch.ts` to a full SCG document.
12. **F12 (AFR-SCN):** `core/scn-doc.ts` ships (LOOP-E.E6); .docx
    formal-notification format emitted from existing classifier JSON;
    signed audit-records archive integrates with H.H1.
13. **F13 (AFR-VDR):** VDR-CSO-DET ✅ shipped; VDR-CSO-RES lands
    with B.B2; VDR-CSO-DOC ships as LOOP-G addendum; EVA hooks
    captured via F.F1.
14. **F14 (AFR-UCM):** ✅ shipped pre-LOOP-A; verification report
    asserts AWS + GCP + Azure crypto collectors all present.
15. **F15 (Phase-Two 8-KSI delta):** ✅ shipped; verification report
    asserts 8/8 ID renames + collector presence.
16. **REO compliance:** every F-artifact passes `npm run check:reo`
    (G1 lint, G2 coverage non-regression, G3 provenance). No
    placeholder strings, no fabricated evidence, no auto-3PAO-sign-offs.
17. **End-to-end bundle:** LOOP-A.A4 submission bundler classifies
    every F-artifact under a known role in the well-known catalogue;
    no F-artifact is bundled as `unrecognized`.

---

## 5. Open questions

1. **AFR-FSI inbound trust verification.** FRR-FSI-VRE is a FedRAMP-PMO
   obligation (FSI-FRP-VRE: "Verified Emails"), but the CSP has to
   trust the PMO's verification chain. Practically: do we require
   DMARC + DKIM + SPF on inbound `@fedramp.gov`? RFC-0014 doesn't
   specify. **Decision pending.** Default: enforce DMARC `p=reject`
   alignment + SPF `~all` or stricter; document the policy in the
   FSI inbox config.

2. **AFR-CCM report availability SLA.** FRR-CCM-01 (CCM-OAR-AVL)
   requires "Report Availability" without specifying a downtime
   tolerance. We default to 99.5% monthly availability for the
   report endpoint; operator-overrideable via config.

3. **AFR-VDR-CSO-DOC format.** FRR-VDR-11 mandates "Documentation
   for Recommendations" but the format is not specified. We will
   emit a .docx summarizing each open VDR-class finding's
   recommendation language and citation chain; if the PMO later
   publishes a structured schema, we add an OSCAL projection.

4. **AFR-MAS-CSO-MDI metadata-inclusion schema.** FRR-MAS-04 names
   "metadata inclusion" without enumerating required fields. We will
   emit the metadata set the AP already requires (CSP name, system
   id, impact tier, FRMR version, 3PAO, assessment period); operator-
   supplied additions flow through `config.yaml`.

5. **Phase-Two pilot post-retrospective format shift.** R3 caveat
   stands. If the post-pilot retrospective publishes a revised
   submission-package format before GA, F4 + LOOP-A.A4 need a clean
   `package_format_version` bump. The `"20x.phase-two.preview.2026"`
   marker is already in INDEX.json so a future bump is mechanical.

6. **AFR-ADS Trust Center connector authentication.** ADS-CSX-UTC
   "Use Trust Centers" requires connecting to a FedRAMP-recognized
   Trust Center; the auth protocol (OIDC? mTLS? signed JWT?) is
   not yet published. Defer until the first Trust Center publishes
   its connector spec.

7. **AFR-PVA-TPX UI surfacing.** The 6 TPX MUSTs (MME, OUC, PAD,
   PDK, SUM, UNP) are 3PAO-side. The current plan is to surface
   them in the LOOP-F.F1 assessor sign-off UI as named sign-off
   items. Open question: does FedRAMP require the CSP-side tracker
   to *expose* these sign-offs, or only the 3PAO's own system?
   Default: expose (read-only) in the tracker so a CSP can confirm
   the 3PAO is on track.

8. **FRMR catalog re-ingestion cadence.** Currently the FRMR snapshot
   is updated on demand. Open question: do we automate weekly /
   monthly re-ingestion with a diff alert? Default: manual on a
   tagged FRMR release, with the diff committed alongside.

---

## Appendix — Artifact ↔ slice traceability matrix

| Artifact | Implementing loop.slice(s) | Status |
|---|---|---|
| F1 FRMR ingestion | pre-LOOP-A | shipped |
| F2 60-KSI envelopes | pre-LOOP-A + ongoing | shipped |
| F3 CSX-SUM | pre-LOOP-A | shipped |
| F4 OSCAL POA&M | LOOP-A.A1 (+ B.B1 / B.B2 / E.E2) | shipped (extensions pending) |
| F5 AFR-PVA | LOOP-G.G0 verification + LOOP-F.F1 (TPX) | partial (CSX shipped) |
| F6 AFR-FSI | LOOP-G.G1 | not started |
| F7 AFR-ICP | LOOP-G.G2 | not started |
| F8 AFR-ADS | LOOP-G.G3 | placeholder only |
| F9 AFR-MAS | LOOP-G.G4 (+ D.D3 + J.J2) | placeholder only |
| F10 AFR-CCM | LOOP-G.G6 (+ E.E1 + E.E3) | partial |
| F11 AFR-SCG | LOOP-G.G5 (+ C.C9 overlap) | partial |
| F12 AFR-SCN | LOOP-E.E6 (extends classifier) | partial |
| F13 AFR-VDR | DET shipped + B.B2 (RES) + LOOP-G addendum (DOC) + F.F1 (EVA) | partial |
| F14 AFR-UCM | pre-LOOP-A | shipped |
| F15 Phase-Two 8-KSI delta | pre-LOOP-A + LOOP-G verification report | shipped |
