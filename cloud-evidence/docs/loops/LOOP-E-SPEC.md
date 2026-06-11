# LOOP-E — Continuous Monitoring Agent

> **Self-contained implementation spec.** Any future session can read this
> file and implement every slice in LOOP-E without re-reading the planning
> conversation, the auth-time loops, or the EXECUTION-PLAN.md snapshot.
> Every quote is cited; every file path is absolute under
> `cloud-evidence/`; every operator-input field is named.

---

## 1. Why this loop exists

LOOP-A delivered a complete **authorization-time** submission package: SSP
+ AP + AR + POA&M + IIW + RoE + signed manifest + RFC 3161 timestamp,
wrapped in a single signed tarball ready for USDA Connect.gov upload.
Authorization is a one-time event.

**Continuous Monitoring (ConMon) is the rest of the system's life.** Per
the FedRAMP Rev5 Playbook ConMon Overview:

> "Each month, the CSP uploads an up-to-date POA&M and inventory, along
> with raw vulnerability scan files (when required by agreements with
> agency customers) and reports to the secure repository."
> — fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/

And from the FedRAMP ConMon Evidence Guide (2026 ed., synthesized from
the current ConMon Playbook v1.0, 2025-11-17):

> "Monthly comprehensive scans across entire system inventory ...
> Internet-reachable resources more often – at least every three days
> for both authenticated and unauthenticated assessments ... Non-internet-
> reachable resources need weekly checks at minimum."
> "Critical/High findings: 30 days; Moderate findings: 90 days; Low
> findings: 180 days. Any vulnerability not fixed within 192 days
> becomes an 'accepted vulnerability'."

The codebase already emits the **artifacts** (POA&M, inventory, AR, SSP),
but nothing publishes them on the recurring cadence FedRAMP mandates, no
deltas are computed across months, no annual-cycle artifacts are produced,
and the SCN / Deviation Request emitters that close the policy-side gaps
do not yet exist. **LOOP-E closes all of these gaps**:

| Gap LOOP-E closes | Slice | Artifact delivered |
|---|---|---|
| Monthly aggregated ConMon analysis (executive summary of the cycle) | E.E1 | `out/conmon-monthly-<YYYY-MM>.{pdf,md,json}` |
| Monthly POA&M re-emission + month-over-month delta | E.E2 | `out/poam.json` (re-emitted) + `out/poam-delta-<YYYY-MM>.md` |
| Annual Assessment package (12-month roll-up) | E.E3 | `out/annual-assessment-<YYYY>/` directory + signed bundle |
| Annual SSP review + diff (CSP attests the SSP is current) | E.E4 | `out/ssp-annual-diff-<YYYY>.md` + updated `ssp.json` |
| Deviation Request (DR) Word docs (FP / RA / OR / VD) | E.E5 | `out/deviation-requests/<id>.docx` |
| Formal SCN notification Word document (extends classifier) | E.E6 | `out/scn-notice-<id>.docx` |
| Annual IRP + ISCP test cadence runner | E.E7 | `out/iscp-test-<YYYY>.docx` + `out/irp-test-<YYYY>.docx` |

After LOOP-E lands, the **monthly USDA Connect.gov upload** is a single
orchestrator command (`npm run collect -- --conmon-monthly --month
2026-07`) and the **annual assessment cycle** is fully scaffolded.

---

## 2. Dependencies

### Loops/slices that must complete first

- **LOOP-A.A1 (OSCAL POA&M v1.1.2 emitter)** — `core/oscal-poam.ts` already
  ships. LOOP-E.E2 extends it with monthly delta logic + revisions
  threading; without A.A1, there is no POA&M shape to re-emit.
- **LOOP-A.A2 (OSCAL AP emitter)** — `core/oscal-ap.ts` already ships.
  LOOP-E.E3 (annual assessment package) bundles the AP alongside the
  AR + POA&M.
- **LOOP-A.A3 (AR chain wiring)** — `core/oscal.ts` already emits AR with
  `import-ap` resolved. E.E3 ingests AR.
- **LOOP-A.A4 (Submission bundler)** — `core/submission-bundle.ts` already
  ships with a 24-role well-known catalogue + chain integrity check.
  LOOP-E.E1 + E.E3 add new well-known artifact rolls
  (`conmon-monthly-report`, `annual-assessment-package`,
  `deviation-request-docx`, `scn-notice-docx`, `iscp-test-aar`,
  `irp-test-aar`).
- **LOOP-A.A5 (RoE template)** — `core/roe-emit.ts` ships the dependency-
  free `.docx` pattern (zip-store + OOXML strings) that E.E5 + E.E6 + E.E7
  reuse verbatim.
- **C.C6 (ConMon Strategy + Plan document, CA-7)** — LOOP-C slice that
  emits the ConMon Strategy `.docx`. E.E1 references it in the monthly
  report's "ConMon strategy reference" section. **If C.C6 has not yet
  shipped at the time E.E1 starts**, E.E1 emits a
  `REQUIRES-OPERATOR-INPUT` marker for the ConMon strategy href instead
  of fabricating one — this is the REO contract.
- **Existing `core/scn-classifier.ts`** — emits `scn-classification.json`
  + `scn-notice-draft.md`. E.E6 reads the classification output and
  renders the formal `.docx` notification.
- **Existing `providers/*/vdr-scan.ts` + `core/vdr-ledger.ts` + CISA KEV
  reconcile (`docs/cisa-kev.generated.json`)** — feed the monthly scan
  deliverables that E.E1 aggregates.
- **Existing `core/diff-report.ts`** — month-over-month change source for
  E.E2's POA&M delta + E.E6's SCN material.

### Files this loop reads from but does NOT extend

- `core/envelope.ts` + `core/findings.ts` — schema unchanged.
- `core/inventory-emit.ts` + `inventory.json` — read for the monthly
  scan-coverage table.
- `core/ksi-map.ts` — read for the controls-in-scope list.
- `core/oscal.ts` — uses `deterministicUuid()` for stable IDs.
- `core/oscal-xml.ts` — uses `oscalJsonToXml()` for XML projections.
- `core/zip.ts` — uses `zipStore()` + `xmlEscape()` for `.docx` rendering.
- `core/sign.ts` — every E.x output is included in the signed manifest.
- `core/timestamp.ts` — RFC 3161 timestamp covers monthly bundle.
- `core/run-ledger.ts` — historical run metadata for delta computation.

### Loops unblocked when LOOP-E completes

- **LOOP-F (3PAO Assessor Experience)** — F.F1 sign-off UI needs E.E3
  annual-assessment artifacts to point at. F.F7 SAR draft consumes
  E.E3 outputs.
- **LOOP-G.G6 (AFR-CCM Continuous Monitoring per 20x)** — tightly
  coupled with E.E1 (the monthly report IS the FedRAMP OAR-AVL +
  OAR-NRD + OAR-FBM deliverable).
- **LOOP-I.I2 (Finding burndown + deadline pipeline)** — visualizes the
  POA&M cadence E.E2 establishes.
- **LOOP-H.H1 (Immutable evidence archive)** — pushes E.E1 + E.E3
  packages to S3 Glacier / GCS Coldline / Azure Archive.

---

## 3. Authoritative sources

Every URL / spec consulted, with verbatim quotes where helpful.

### FedRAMP

1. **FedRAMP Rev5 Playbook — Continuous Monitoring Overview**
   <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/>
   - Verbatim: *"Each month, the CSP uploads an up-to-date POA&M and
     inventory, along with raw vulnerability scan files (when required
     by agreements with agency customers) and reports to the secure
     repository."*
   - Verbatim: *"CSPs with cloud offerings categorized at LI-SaaS, Low,
     or Moderate use the FedRAMP secure repository on USDA Connect.gov
     for posting ConMon deliverables. CSPs with cloud offerings
     categorized at High use their own secure repository."*

2. **FedRAMP Rev5 Playbook — Continuous Monitoring Vulnerability Scanning**
   <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/>
   - Verbatim: *"FedRAMP vulnerability scanning guidelines require at
     least monthly scans of 100% of inventory components."*
   - Verbatim: *"The scan output must display all scan findings with a
     low risk or higher in a structured, machine-readable format (such
     as XML, CSV, or JSON)."*
   - Verbatim: *"FedRAMP recommends that externally accessible (outside
     of the boundary, without the use of a VPN) system components do
     not use this sampling methodology; 100% of externally accessible
     system components should be scanned."*

3. **FedRAMP Rev5 Playbook — POA&M**
   <https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/poam/>
   - Verbatim: *"FedRAMP requires Critical and High risks to be
     remediated within 30 days of discovery, Moderate risks within 90
     days of discovery, and Low risks within 180 days of discovery."*
   - Verbatim: *"For FPs validated by the 3PAO during the assessment,
     select 'Yes' in Column W (False Positive) and move the risk to the
     POA&M's 'Closed' tab."*
   - Verbatim: *"For RAs validated by the 3PAO during the assessment,
     select 'Yes' in Column V (Risk Adjustment)."*
   - Verbatim: *"For ORs validated by the 3PAO during the assessment,
     select 'Yes' in Column X (Operational Requirement)."*
   - Verbatim: *"High-risk VDs must be mitigated to a Moderate level
     through compensating controls within thirty (30) days."*
   - Verbatim: *"Pending FPs must be approved by the federal agency AO
     prior to authorization."* (same applies to RAs + ORs)
   - Verbatim: *"CSPs are required to check in with the vendor at least
     once a month to determine the status of the patch/fix."*

4. **FedRAMP CSP Continuous Monitoring Strategy Guide** (PDF)
   <https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf>
   - Canonical source for the Critical/High/Moderate/Low remediation
     table our `core/oscal-poam.ts` `REMEDIATION_DEADLINE_DAYS` constant
     cites. Re-fetch quarterly; the table version we encode is committed
     to `docs/fedramp-conmon-strategy.generated.json` (see slice E.E1
     build step 1).

5. **FedRAMP Continuous Monitoring Playbook v1.0, 2025-11-17** (PDF)
   <https://www.fedramp.gov/resources/documents/Continuous_Monitoring_Playbook.pdf>
   - 888 KB PDF; the December 2025 ConMon Playbook supersedes earlier
     Rev5 guidance. We fetch + commit a parsed JSON projection under
     `docs/fedramp-conmon-playbook.generated.json` so the catalog (not
     hard-coded strings) drives the report templates.

6. **FedRAMP ConMon Evidence Guide (2026)** — secondary synthesis
   <https://elevateconsult.com/insights/fedramp-conmon-deliverables-essential-evidence-requirements-guide-2026/>
   - Verbatim: *"All submissions occur on the same day each month to
     the secure repository."* (single-day submission cadence)
   - Verbatim: *"Internet-reachable resources more often – at least
     every three days for both authenticated and unauthenticated
     assessments. Non-internet-reachable resources need weekly checks
     at minimum."*
   - Verbatim: *"Annual Assessment costs will be about 80% of your
     original Assessment ..."* — drives E.E3 scope (we generate as
     much of the package as possible to cut that cost).
   - Verbatim: *"129 predefined Core Controls; Additional control
     subsets selected to ensure full baseline review within three-year
     cycle; Fresh evidence each year (previous assessment evidence
     cannot be reused); Security Assessment Report documenting all
     findings."* — drives E.E3's control-selection logic.
   - Verbatim deviation taxonomy: *"Risk Adjustments (RA): When
     mitigating factors reduce exploitation likelihood; False Positives
     (FP): When vulnerabilities don't actually exist; Operational
     Requirements (OR): When fixes would affect system functionality;
     Vendor Dependencies (VD): High-risk must reduce to Moderate within
     30 days."* — drives E.E5 four-type form.

7. **FedRAMP Significant Change Notification — SCR / SCN required content**
   <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/significant-changes/>
   - Verbatim required SCR fields: *"Service Offering FedRAMP ID;
     Assessor Name; Related POA&M (if the change is being implemented
     to address a known risk); Significant Change type and explanation
     of categorization; Short description of change; Reason for
     change; Summary of customer impact, including changes to services
     and customer configuration responsibilities; Plan and timeline
     for the change, including for the verification, assessment,
     and/or validation of impacted security controls; Copy of the
     security impact analysis; Name and title of CSP approver
     (typically the system owner)."*
   - Verbatim NIST definition cited: *"a change that is likely to
     substantively affect the security or privacy posture of a
     system"* (NIST SP 800-37 Rev. 2).

8. **FedRAMP POA&M Template (.xlsx)**
   <https://www.fedramp.gov/resources/templates/FedRAMP-POAM-Template.xlsx>
   - Column letters (we hard-code these — they are FedRAMP-published
     constants per REO Rule 3 "FedRAMP-published constants"): **Column V
     = Risk Adjustment**, **Column W = False Positive**, **Column X =
     Operational Requirement**, **Column Q = Vendor Dependency**,
     **Column R = Last Vendor Check-in Date**, **Column S = Vendor
     Dependent Product Name**.

9. **FedRAMP Annual Assessment Guidance** (PDF)
   <https://www.fedramp.gov/assets/resources/documents/CSP_Annual_Assessment_Guidance.pdf>
   - Drives E.E3 scope (Core Controls list, control-selection worksheet
     reference, 3-year full-baseline cycle).

10. **FedRAMP ISCP Template (Rev5)**
    <https://www.fedramp.gov/resources/documents/rev4/REV_4_SSP-A06-FedRAMP-ISCP-Template.docx>
    - Structure E.E7 follows for ISCP test AAR scaffold.

### NIST + OSCAL

11. **NIST SP 800-137: ISCM for Federal Information Systems and
    Organizations** (Sep 2011)
    <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-137.pdf>
    - Foundational ConMon framework — six-step process (Define →
      Establish → Implement → Analyze → Respond → Review).

12. **NIST SP 800-37 Rev. 2 — RMF**
    <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf>
    - §3.6 significant-change definition cited by FedRAMP SCN.

13. **NIST SP 800-53 Rev. 5** — CA-7 (Continuous Monitoring), CP-2 / CP-4
    (ISCP + ISCP testing), IR-3 / IR-8 (IRP + IRP testing), CA-5
    (POA&M).

14. **OSCAL v1.1.2 Plan of Action and Milestones — JSON Reference**
    <https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/>
    - Verbatim root required: *"plan-of-action-and-milestones [1]:
      uuid [1], metadata [1], poam-items [1]; remarks note: Either an
      OSCAL-based SSP must be imported, or a unique system-id must be
      specified."*
    - Verbatim metadata required: *"title [1], last-modified [1],
      version [1], oscal-version [1]"*; revisions array entries
      require `version [1]`.
    - Root cardinalities: `observations [0 or 1]`, `risks [0 or 1]`,
      `findings [0 or 1]`, `poam-items [1]` (MINIMUM ONE).
    - `risk.status` enum (from the v1.1.2 schema we ship at
      `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json` —
      already on disk): `open | investigating | remediating |
      deviation-requested | deviation-approved | closed`. E.E5 (DR
      emitter) flips POA&M items to `deviation-requested` on creation
      and `deviation-approved` on AO sign-off.

15. **OSCAL POA&M concept layer**
    <https://pages.nist.gov/OSCAL/concepts/layer/assessment/poam/>
    - Reference for the monthly re-emission pattern
      (`metadata.last-modified` bumped + `metadata.revisions[]`
      appended), already implemented for LOOP-A.A1 and threaded by
      E.E2.

### Submission target

16. **USDA Connect.gov** (FedRAMP secure repository for LI-SaaS / Low /
    Moderate) — referenced by every FedRAMP ConMon page; no public API
    spec. Operator drag-drops the LOOP-E bundle. We do NOT auto-push
    (operator opt-in via `--push-fedramp-repo` flag deferred to a
    future loop — REO Rule 4 keeps us out of unauthenticated egress
    paths).

---

## 4. Per-slice implementation specs

> Pattern recap (read `core/oscal-poam.ts`, `core/ssp-docx.ts`,
> `core/roe-emit.ts`, `core/submission-bundle.ts`, `core/scn-classifier.ts`
> before starting any slice). Pure builder + disk emitter; OSCAL outputs
> get a `.xml` sibling via `oscalJsonToXml()` unless
> `CLOUD_EVIDENCE_DISABLE_OSCAL_XML=1`; `.docx` outputs use
> `zipStore()` + the OOXML helpers in `core/zip.ts`. Every operator
> field that cannot be derived emits the literal string
> `REQUIRES-OPERATOR-INPUT` (constant: `TBD` in `roe-emit.ts`). Each
> slice wires an orchestrator `--<flag>` + `CLOUD_EVIDENCE_<FLAG>` env
> mirroring the pattern in `core/orchestrator.ts` lines 260–446.

---

### Slice E.E1 — Monthly ConMon Analysis Report

**Why this slice**: FedRAMP requires *"the CSP uploads an up-to-date
POA&M and inventory, along with raw vulnerability scan files ... and
reports to the secure repository"* every month (Rev5 Playbook —
Continuous Monitoring Overview). Today the codebase emits POA&M +
inventory but not the human-readable monthly **analysis report**
(executive summary + trend + open-risk profile) that the agency POC
expects to see attached to the upload.

**Files to create**:
- `cloud-evidence/core/conmon-report.ts` — pure builder + disk emitter.
- `cloud-evidence/core/conmon-pdf.ts` — minimal pure-JS PDF generator
  (PDF 1.4 ASCII subset; no external `pdfkit` / `pdfmake`). Emits text,
  page-break, and a simple table renderer. Same dependency-free
  pattern as `core/submission-bundle.ts` (POSIX ustar) and
  `core/roe-emit.ts` (OOXML). Reuse this generator in E.E3 + E.E7.
- `cloud-evidence/tests/core/conmon-report.test.ts` — ~13 tests.
- `cloud-evidence/tests/core/conmon-pdf.test.ts` — ~10 tests (PDF
  primitive validation: header bytes, xref, stream lengths).
- `cloud-evidence/scripts/fetch-conmon-playbook.mjs` — fetches the
  Nov-2025 ConMon Playbook PDF, parses it (poppler-style text extract
  is NOT available without deps; we instead pin the URL + sha256 +
  committed text excerpts in `docs/fedramp-conmon-playbook.generated.json`
  via the same pattern as `scripts/extract-frmr-requirements.mjs`).

**Files to extend**:
- `cloud-evidence/core/submission-bundle.ts`: add Role
  `'conmon-monthly-report'` + `'conmon-monthly-report-pdf'` +
  `'conmon-monthly-report-json'` entries to the `WELL_KNOWN` array
  (filenames `conmon-monthly-<YYYY-MM>.md`,
  `conmon-monthly-<YYYY-MM>.pdf`, `conmon-monthly-<YYYY-MM>.json`).
- `cloud-evidence/core/orchestrator.ts`: add `--conmon-monthly` and
  `--month <YYYY-MM>` flags + `CLOUD_EVIDENCE_CONMON_MONTHLY` /
  `CLOUD_EVIDENCE_CONMON_MONTH` envs.

**Schemas / standards**:
- Aggregates real data from existing files in `outDir`:
  - `poam.json` → open POA&M items per severity + per category.
  - `KSI-*.json` envelopes → pass/fail counts; failing-finding list.
  - `vdr-ledger.json` (existing) → CVE list with KEV markers.
  - `inventory.json` → asset count + coverage by class.
  - `inventory-coverage.json` → Appendix-M fill rate per (column,cloud).
  - `diff-report.json` (when present) → prior-month delta hints.
  - `scn-classification.json` (when present from E.E6 / SCN classifier)
    → change events of the month.
- Report sections (drawn from FedRAMP ConMon Playbook §monthly content,
  re-projected through `docs/fedramp-conmon-playbook.generated.json`):
  1. **Header** — System name, CSP, system-id, impact level, report
     month (YYYY-MM), FedRAMP package ID, ConMon strategy reference
     URL (REQUIRES-OPERATOR-INPUT if C.C6 not shipped).
  2. **Posture snapshot** — KSI pass-rate %, open POA&M count by
     severity, KEV exposure count, count of POA&M items past deadline.
  3. **Vulnerability scan coverage** — assets scanned vs total
     inventory, per-class breakdown (OS / web / database / container),
     internet-reachable assets at 100% (FedRAMP MUST), internal-only
     sampling % (from `--sampling-pct` env, default 100% pending
     LOOP-F.F3).
  4. **POA&M activity** — items opened in the month, items closed in
     the month, items changed status (open → remediating → closed),
     items past deadline (and by how many days).
  5. **Deviation requests** — DRs submitted in the month, DRs approved,
     DRs expiring within next 30 days (driven by E.E5 ledger).
  6. **SCN events** — significant changes notified in the month
     (driven by E.E6 ledger + `scn-classification.json`).
  7. **Incident summary** — incidents from the tracker `incidents`
     table (LOOP-G.G2; until then, REQUIRES-OPERATOR-INPUT row).
  8. **Annual cycle progress** — months elapsed in current
     authorization year, items remaining for annual review (E.E4 + E.E7).
  9. **Provenance** — emitter name, run id, frmr version, signed
     manifest sha256, RFC 3161 timestamp file.

**Build steps**:
1. **Pin the ConMon Playbook reference data**: write
   `scripts/fetch-conmon-playbook.mjs` that pins the PDF URL + sha256
   + content extraction prompts; the script (run by humans, not at
   build time) regenerates `docs/fedramp-conmon-playbook.generated.json`
   with: `{remediation_table: {critical:30, high:30, moderate:90,
   low:180, accepted_threshold_days:192}, scan_cadence:
   {monthly_inventory:1.0, internet_reachable_days:3,
   internal_days:7}, monthly_deliverables: [...], playbook_version:
   "1.0", playbook_published: "2025-11-17", fetched_at: <ISO>,
   sha256: <hash>}`. Same shape as
   `docs/frmr-requirements.generated.json`.
2. **Define types** in `core/conmon-report.ts`:
   ```ts
   export interface ConmonMonthlyReport {
     run_id: string;
     report_month: string;      // "YYYY-MM"
     generated_at: string;      // ISO
     system: { name?: string; id?: string; impactLevel: 'low'|'moderate'|'high'; csp?: string; fedrampId?: string };
     posture: {
       ksi_pass_rate: number;        // 0..1
       open_poam_count: number;
       open_by_severity: Record<'critical'|'high'|'medium'|'low'|'info', number>;
       past_deadline_count: number;
       kev_exposure_count: number;
     };
     scan_coverage: { assets_total: number; assets_scanned: number; by_class: Record<string, { total: number; scanned: number }>; internet_reachable_compliant: boolean; sampling_pct: number };
     poam_activity: { opened: number; closed: number; status_changes: number; past_deadline_items: Array<{ poam_id: string; days_past: number; severity: string }> };
     deviation_requests: { submitted: number; approved: number; expiring_within_30d: Array<{ dr_id: string; expires: string }> };
     scn_events: { significant: number; advisory: number; classifications: Array<{ change_id: string; significance: string }> };
     incident_summary: Array<{ id: string; status: string; reported_to: string[] }> | 'REQUIRES-OPERATOR-INPUT';
     annual_cycle: { months_elapsed: number; next_assessment_due: string; ssp_last_reviewed: string | 'REQUIRES-OPERATOR-INPUT' };
     provenance: { emitter: 'core/conmon-report.ts'; tool: string; frmrVersion: string; conmonPlaybookVersion: string; sourceCalls: string[] };
   }
   ```
3. **Pure builder**:
   `buildConmonMonthlyReport(opts: ConmonReportBuildOpts): ConmonMonthlyReport`
   that takes already-loaded snapshots (POA&M doc, KSI envelopes, VDR
   ledger, inventory, diff-report, SCN classification, conmon-playbook
   pin). Deterministic on same inputs.
4. **Disk emitter**:
   `emitConmonMonthlyReport(opts: ConmonReportEmitOpts):
   {jsonPath, mdPath, pdfPath}` that reads from `outDir`, builds the
   report, writes `.json` (JSON.stringify with `provenance`), `.md`
   (rendered via simple template), and `.pdf` (via
   `core/conmon-pdf.ts`).
5. **PDF generator** in `core/conmon-pdf.ts`: 1.4 ASCII PDF with a
   Catalog + Pages + per-page Page + Font (Helvetica 1F) + Contents
   stream. Tables = drawn lines (line operator `l`) + text show
   operators (`Tj`). Single function `renderPdf(sections: Section[]):
   Buffer` where `Section = { kind: 'heading'|'paragraph'|'table',
   ... }`.
6. **Wire into orchestrator** with `--conmon-monthly` +
   `--month <YYYY-MM>` (default = current month). Run AFTER POA&M /
   VDR / inventory but BEFORE signing so the report is in the manifest.
7. **Wire into `submission-bundle.ts`**: add the 3 well-known artifact
   rows so monthly bundles classify the report correctly.
8. **Operator can supply** the ConMon Strategy doc href via
   `--conmon-strategy-href <url>` / `CLOUD_EVIDENCE_CONMON_STRATEGY_HREF`
   (this populates the cited reference at the top of the report; when
   C.C6 lands, the orchestrator auto-resolves to the locally-emitted
   doc).

**REQUIRES-OPERATOR-INPUT fields**:
- `system.fedrampId`: CLI flag `--fedramp-package-id` or env
  `CLOUD_EVIDENCE_FEDRAMP_PACKAGE_ID` — the FedRAMP-assigned package
  identifier (not derivable). Marker emitted in the JSON `system`
  block when absent.
- `incident_summary`: until LOOP-G.G2 ships the tracker `incidents`
  table, the report literal `incident_summary:
  'REQUIRES-OPERATOR-INPUT'` with operator-fillable text in the .md.
- `annual_cycle.ssp_last_reviewed`: from tracker `ssp_reviews` table
  (E.E4 builds this; until E.E4 ships, REQUIRES-OPERATOR-INPUT).
- `system.csp`: CLI flag `--csp-name` / `CLOUD_EVIDENCE_CSP_NAME`.
- `conmon_strategy_href`: CLI flag `--conmon-strategy-href` /
  `CLOUD_EVIDENCE_CONMON_STRATEGY_HREF`.
- `sampling_pct`: CLI flag `--sampling-pct` / `CLOUD_EVIDENCE_SAMPLING_PCT`
  (numeric 0..100, default 100; LOOP-F.F3 will compute this per-class).

**Test specifications** (~13):
1. `it('builds a posture snapshot from KSI envelopes', ...)` — feed 3
   real KSI envelopes (1 pass, 2 fail mixed severity); assert
   `ksi_pass_rate === 1/3`, `open_poam_count === 2`,
   `open_by_severity.high === 1`.
2. `it('aggregates POA&M activity month-over-month from diff-report', ...)`
   — feed `diff-report.json` with 2 new + 1 closed; assert
   `poam_activity.opened === 2`, `closed === 1`.
3. `it('computes scan_coverage from inventory.json and ksi-map', ...)`
   — feed inventory of 20 assets; assert
   `scan_coverage.assets_total === 20`.
4. `it('flags internet_reachable_compliant=false when any internet-reachable asset missing from scan list', ...)`.
5. `it('emits REQUIRES-OPERATOR-INPUT for incident_summary when tracker integration absent', ...)`.
6. `it('emits REQUIRES-OPERATOR-INPUT for system.fedrampId when --fedramp-package-id missing', ...)`.
7. `it('writes JSON + MD + PDF files with the expected names', ...)`
   — assert files at `conmon-monthly-2026-07.{json,md,pdf}`.
8. `it('PDF starts with %PDF-1.4 magic bytes and ends with %%EOF', ...)`.
9. `it('PDF contains the system name + report month in a text stream', ...)`.
10. `it('JSON output carries a provenance block naming this emitter', ...)`.
11. `it('throws when --month is malformed (not YYYY-MM)', ...)`.
12. `it('uses pinned playbook version from docs/fedramp-conmon-playbook.generated.json', ...)`.
13. `it('deterministic — same inputs produce byte-identical JSON', ...)`.

**REO compliance checks specific to this slice**:
- Every counted POA&M item traces to a real `poam.json` item-uuid.
- Every scan-coverage number traces to a real inventory.json asset id.
- KEV exposure count cites the committed `docs/cisa-kev.generated.json`
  catalog version.
- Playbook reference comes from a committed JSON projection (real
  fetched-and-pinned PDF), not a hard-coded string in source.
- No fabricated deadlines: when `conmon-playbook.generated.json` is
  stale (sha256 mismatch on re-fetch), the report carries a
  `provenance.warnings: ["conmon-playbook-stale"]` field.
- `incident_summary` REQUIRES-OPERATOR-INPUT is the literal sentinel;
  no "TODO" or "TBD" tokens.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/conmon-report.test.ts tests/core/conmon-pdf.test.ts
npm run check:reo
```

**Estimated effort**: 5 days (PDF generator is the largest chunk: ~2
days. Builder + tests: 2 days. Playbook pin + plumbing: 1 day).

---

### Slice E.E2 — Monthly POA&M Delta Workflow

**Why this slice**: Per R2 (`docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`), the
monthly POA&M submission is a **full re-upload** with bumped
`metadata.last-modified` and an appended `metadata.revisions[]` entry.
Currently `core/oscal-poam.ts` accepts `revisionsHistory` as a
`PoamEmitOptions` field but **nothing computes the prior history**.
This slice closes the loop: it reads the prior month's POA&M from a
ledger, threads revisions forward, re-emits the full document, AND
produces a Markdown delta for operator review before submission.

**Files to create**:
- `cloud-evidence/core/poam-monthly.ts` — orchestrator wrapper around
  `emitOscalPoam()` that adds the cross-month delta layer.
- `cloud-evidence/core/poam-ledger.ts` — append-only JSONL ledger at
  `out/poam-ledger.jsonl` recording each month's POA&M emission
  (run_id, last_modified, version, sha256, path).
- `cloud-evidence/tests/core/poam-monthly.test.ts` — ~12 tests.
- `cloud-evidence/tests/core/poam-ledger.test.ts` — ~8 tests.

**Files to extend**:
- `cloud-evidence/core/oscal-poam.ts`: NO schema change (revisions
  already supported). Add an exported helper
  `extractRevisionEntries(doc) → array` so the ledger can read prior
  documents.
- `cloud-evidence/core/orchestrator.ts`: gate the monthly delta behind
  `--conmon-monthly` (set in E.E1) — when monthly mode is on, call
  `runPoamMonthly()` instead of the raw `emitOscalPoam()` path.
- `cloud-evidence/core/submission-bundle.ts`: add Role
  `'poam-delta-md'` with filename matcher `/^poam-delta-\d{4}-\d{2}\.md$/`.

**Schemas / standards**:
- OSCAL POA&M v1.1.2 (already covered in §3).
- FedRAMP POA&M cadence: *"Each month, the CSP uploads an up-to-date
  POA&M ..."* (Rev5 Playbook).
- Severity remediation: *"Critical and High risks ... within 30 days
  ..., Moderate ... within 90 days ..., Low ... within 180 days"*
  (Rev5 Playbook POA&M page). Already encoded in
  `REMEDIATION_DEADLINE_DAYS` in `core/oscal-poam.ts`.

**Build steps**:
1. **Ledger** (`core/poam-ledger.ts`):
   - `appendPoamLedger(outDir, entry: { run_id, report_month,
     last_modified, version, sha256, path })` — appends one JSON line
     to `out/poam-ledger.jsonl`. Uses `fs.appendFileSync` (atomic on
     POSIX for our small writes).
   - `readPoamLedger(outDir): LedgerEntry[]` — reads + parses.
   - `loadPriorMonthPoam(outDir, currentMonth): { doc, entry } | null`
     — finds the most recent entry strictly before `currentMonth`,
     loads its file (still in `outDir` under
     `archive/poam-<YYYY-MM>.json`).
2. **Monthly emitter** (`core/poam-monthly.ts`):
   - `runPoamMonthly(opts: PoamMonthlyOptions): PoamMonthlyResult`
     that:
     a. Loads the prior ledger entry + prior POA&M doc.
     b. Calls `emitOscalPoam()` with `revisionsHistory` =
        `extractRevisionEntries(priorDoc) + [priorAsRevision]`.
     c. Computes the delta:
        `{added: PoamItem[], closed: PoamItem[], status_changed:
        Array<{uuid, prev_status, new_status}>, severity_changed:
        Array<{uuid, prev, new}>, past_deadline_items:
        PoamItem[]}` by comparing item-uuids across the two docs.
     d. Renders Markdown `poam-delta-<YYYY-MM>.md` from the delta.
     e. Archives the just-emitted POA&M to `outDir/archive/poam-<YYYY-MM>.json`
        and appends a ledger entry.
3. **Markdown delta template**: 6 sections — header (system, month,
   tool version), summary counts, added items (table: poam-id, severity,
   rule, ksi, deadline), closed items, status changes, past-deadline
   items (with "days past deadline" column highlighted). All values
   pulled from real OSCAL JSON.
4. **Deterministic UUIDs**: existing `deterministicUuid()` pattern
   preserved — same finding produces the same poam-item.uuid month
   over month, which is exactly what makes the diff possible.
5. **Wire into orchestrator**: when `--conmon-monthly` AND
   `--oscal-poam` are both set, the orchestrator routes through
   `runPoamMonthly()` instead of the bare `emitOscalPoam()` call.
6. **Submission-bundle**: register the delta MD so it ships in the
   monthly bundle.

**REQUIRES-OPERATOR-INPUT fields**: none — the entire workflow runs on
auto-derived data (the prior POA&M is on disk in the ledger). If the
ledger is empty (first month of operation), the delta MD emits a
single line "First month of ConMon operation; no prior POA&M to
compare against." That is a real true statement, not a placeholder.

**Test specifications** (~12 for poam-monthly + ~8 for ledger):
1. `it('appends a ledger entry with sha256 + path + last_modified', ...)`.
2. `it('reads back appended entries in insertion order', ...)`.
3. `it('loads the prior month POA&M from archive directory', ...)`.
4. `it('returns null when no prior month exists', ...)`.
5. `it('runPoamMonthly threads revisions history forward', ...)` — assert
   new doc's `metadata.revisions[]` length === prior length + 1.
6. `it('preserves deterministic UUIDs across months', ...)` — same
   finding → same uuid across two emissions.
7. `it('computes added items correctly', ...)` — uuid in current but
   not prior.
8. `it('computes closed items correctly', ...)` — uuid in prior but
   not current.
9. `it('detects status_changed items', ...)` — risk.status flip from
   open to remediating.
10. `it('detects past_deadline items', ...)` — items with deadline <
    now, status != closed.
11. `it('renders a Markdown delta with all 6 sections', ...)` — section
    headers present.
12. `it('first-month case emits "no prior POA&M" delta cleanly', ...)`.
13. `it('archives the POA&M to archive/poam-<YYYY-MM>.json', ...)`.
14. `it('ledger entry sha256 matches archived file sha256', ...)`.
15. `it('throws when --month is malformed', ...)`.
16. `it('skipped_reason=no-failing-findings propagates without ledger growth', ...)`.
17. `it('does not double-write a ledger entry on idempotent re-run', ...)`.
18. `it('passes through revisions[].oscal-version unchanged', ...)`.
19. `it('past_deadline severity rollup matches REMEDIATION_DEADLINE_DAYS', ...)`.
20. `it('integrates with --oscal-poam end-to-end on real fixtures', ...)`.

**REO compliance checks specific to this slice**:
- The delta is derived entirely from two real OSCAL POA&M docs (no
  parallel "shadow" diff database). Item uuids are the diff key.
- The archive directory is part of the signed manifest scope (extend
  `core/sign.ts` if not already covering `archive/**`).
- No silent fallbacks: a failed-load of prior POA&M (corrupt JSON)
  raises a typed `PriorPoamCorruptError` naming the file path —
  never silently treats it as "first month".

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/poam-monthly.test.ts tests/core/poam-ledger.test.ts
npm run check:reo
```

**Estimated effort**: 3 days (ledger + delta + orchestrator wiring + tests).

---

### Slice E.E3 — Annual Assessment Package Generator

**Why this slice**: Per the 2026 ConMon Evidence Guide, *"Third-party
assessor testing covers: 129 predefined Core Controls; Additional
control subsets selected to ensure full baseline review within three-
year cycle; Fresh evidence each year (previous assessment evidence
cannot be reused); Security Assessment Report documenting all
findings."* The CSP must produce a 12-month aggregate package each
year. Today's submission-bundle (LOOP-A.A4) emits a per-run bundle;
LOOP-E.E3 emits an annual-cycle bundle that aggregates all monthly
bundles + the annual SSP review (E.E4) + IRP test AAR (E.E7) + ISCP
test AAR (E.E7).

**Files to create**:
- `cloud-evidence/core/annual-assessment.ts` — annual package builder
  + emitter.
- `cloud-evidence/core/annual-control-selection.ts` — implements the
  FedRAMP Annual Assessment Control Selection rule (129 Core Controls
  + rotating non-core subset). Pure function.
- `cloud-evidence/docs/fedramp-annual-core-controls.generated.json` —
  pinned list of the 129 Core Controls (extracted via a fetched
  Annual Assessment Guidance projection; same shape as
  `docs/frmr-requirements.generated.json`).
- `cloud-evidence/scripts/fetch-annual-assessment-guidance.mjs` —
  fetches + pins the Core Controls list.
- `cloud-evidence/tests/core/annual-assessment.test.ts` — ~13 tests.
- `cloud-evidence/tests/core/annual-control-selection.test.ts` —
  ~10 tests.

**Files to extend**:
- `cloud-evidence/core/submission-bundle.ts`: add Roles
  `'annual-assessment-package'` (the tarball itself),
  `'annual-control-selection'` (the JSON listing what's in scope this
  year), `'annual-iscp-test-aar'`, `'annual-irp-test-aar'`,
  `'annual-ssp-diff'`. Add an aggregated wrapper
  `buildAnnualBundle()` that calls the existing
  `emitSubmissionBundle()` after staging 12 months of bundles under a
  scratch directory.
- `cloud-evidence/core/orchestrator.ts`: `--annual-assessment` flag +
  `--annual-year <YYYY>` flag + envs.

**Schemas / standards**:
- FedRAMP Annual Assessment Guidance (CSP_Annual_Assessment_Guidance.pdf
  v3.0 2024-02-15) — Core Control list + control-selection worksheet
  schema.
- The package follows the same `INDEX.json` shape as LOOP-A.A4 with
  `package_format_version = "20x.annual.preview.<YYYY>"`.
- Control selection rule (cited in 2026 Evidence Guide): *"Fresh
  evidence each year (previous assessment evidence cannot be
  reused)"* — drives the "evidence collected after annual-cycle-start"
  filter.

**Build steps**:
1. **Pin the 129 Core Controls**: write
   `scripts/fetch-annual-assessment-guidance.mjs` that downloads
   `CSP_Annual_Assessment_Guidance.pdf`, pins sha256, and writes
   `docs/fedramp-annual-core-controls.generated.json` with
   `{core_controls: ["AC-1", "AC-2", ...], guidance_version: "3.0",
   guidance_published: "2024-02-15", fetched_at: <ISO>, sha256: <hash>}`.
2. **Control selection** (`core/annual-control-selection.ts`):
   `selectAnnualControls(opts: { year: number; impactLevel: 'low'|'moderate'|'high'; coreControls: string[]; priorYears: { year: number; controls: string[] }[] }): { in_scope: string[]; rationale_per_control: Record<string, 'core'|'rotation-year-X'|'sample-N-percent'>; coverage_pct_three_year: number }`.
   - Always include all 129 Core Controls.
   - Add a rotating non-core subset so the 3-year window covers 100%
     of the baseline. Mathematically: take the controls NOT in `core`
     and NOT touched in `priorYears` covering the last 2 years; if the
     remaining set is smaller than (baseline - core)/3, fall back to
     sampling stratified by family.
3. **Annual builder** (`core/annual-assessment.ts`):
   `buildAnnualAssessment(opts: AnnualAssessmentOptions): AnnualAssessmentManifest`
   that:
   a. Reads the monthly POA&M ledger (E.E2) for the year.
   b. Reads every monthly bundle's `INDEX.json` for the year (from
      `archive/<YYYY-MM>/` or operator-supplied `--annual-input-dir`).
   c. Aggregates: count of monthly bundles, list of POA&M items
      opened-then-closed within year, items opened-and-still-open at
      year-end, KEV remediation timeline compliance, scan-coverage
      compliance per month.
   d. Calls `selectAnnualControls()` to compute the
      in-scope-this-year control list.
   e. Stages: latest `ssp.json` + `ssp.docx`, latest `ap.json`, latest
      `assessment-results.json` (which should be the 3PAO's annual AR),
      `annual-control-selection.json`, the E.E4 `ssp-annual-diff.md`,
      the E.E7 IRP + ISCP test AARs, all monthly POA&Ms (archived),
      all monthly inventories.
   f. Calls `emitSubmissionBundle()` against the staged dir with
      `package_format_version = "20x.annual.preview.<YYYY>"`.
4. **Disk emitter**: `emitAnnualAssessment(opts) → {bundlePath, manifestPath, indexJsonPath}`.
5. **Submission-bundle integration**: ensures the annual bundle is
   classified as `annual-assessment-package` when nested into a
   higher-level package.
6. **Orchestrator wiring**: `--annual-assessment --annual-year 2026`
   produces `out/annual-assessment-2026.tar.gz` + a sibling
   `out/annual-assessment-2026/INDEX.json` for inspection.

**REQUIRES-OPERATOR-INPUT fields**:
- `annual-input-dir`: defaults to `outDir/archive`. CLI
  `--annual-input-dir <path>` / `CLOUD_EVIDENCE_ANNUAL_INPUT_DIR` —
  needed when the operator runs annual roll-up from a multi-month
  archive that is not in the default location.
- `ssp_annual_review_signed_off_by`: from tracker; until E.E4 ships,
  REQUIRES-OPERATOR-INPUT marker.
- `assessor_organization` + `assessment_period_start` + `assessment_period_end`:
  via CLI flags (same as LOOP-A.A2's `--3pao-name`).

**Test specifications** (~13 for annual-assessment + ~10 for control-selection):
1. `it('selectAnnualControls always includes all core controls', ...)`.
2. `it('selectAnnualControls covers 100% of baseline across 3 years', ...)`.
3. `it('selectAnnualControls deduplicates across prior years', ...)`.
4. `it('annual assessment aggregates 12 monthly POA&M ledger entries', ...)`.
5. `it('annual assessment counts opened-then-closed within year correctly', ...)`.
6. `it('emits INDEX.json with package_format_version=20x.annual.preview.YYYY', ...)`.
7. `it('throws when fewer than 1 monthly bundle is present (--strict-annual)', ...)`.
8. `it('non-strict mode warns + still emits when months missing', ...)`.
9. `it('reads ssp-annual-diff.md from E.E4 and stages it', ...)`.
10. `it('reads E.E7 IRP/ISCP AARs and stages them', ...)`.
11. `it('emits REQUIRES-OPERATOR-INPUT for assessor_organization when --3pao-name missing', ...)`.
12. `it('annual bundle round-trips through gunzip + tar parser', ...)`.
13. `it('annual bundle sha256 is stable on identical inputs', ...)`.
14. `it('selectAnnualControls falls back to stratified sampling when rotation pool empty', ...)`.
15. `it('honors --annual-input-dir when archive is non-default', ...)`.
16. `it('core controls list comes from pinned generated JSON', ...)`.

**REO compliance checks specific to this slice**:
- Every aggregated number traces to a real monthly bundle's INDEX.json.
- Control selection is reproducible: same year + same priorYears →
  same in_scope list (deterministic).
- No fabricated KEV deadline-compliance %: derived only from real
  POA&M deadlines + closure timestamps.
- The 129 Core Controls list is pinned + cited (`provenance.pinned_in:
  docs/fedramp-annual-core-controls.generated.json`).

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/annual-assessment.test.ts tests/core/annual-control-selection.test.ts
npm run check:reo
```

**Estimated effort**: 5 days.

---

### Slice E.E4 — Annual SSP Review / Update Workflow

**Why this slice**: NIST SP 800-53 Rev5 control PL-2 + the FedRAMP
ConMon strategy require an **annual SSP review**. The CSP attests the
SSP is current; if changes were made, the SSP must be diffed against
the prior annual version + the diff signed off. Without this slice,
there is no auditable mechanism for "the SSP I'm submitting at year-2
of authorization is current".

**Files to create**:
- `cloud-evidence/core/ssp-annual-review.ts` — annual diff + sign-off
  workflow.
- `cloud-evidence/core/ssp-diff.ts` — pure OSCAL SSP diff function
  (compares two SSP JSON docs and emits an `SspDiff` shape: changed
  controls, added components, removed components, narrative diffs).
- `cloud-evidence/tests/core/ssp-annual-review.test.ts` — ~12 tests.
- `cloud-evidence/tests/core/ssp-diff.test.ts` — ~10 tests.

**Files to extend**:
- `cloud-evidence/core/oscal-ssp.ts`: add an exported helper
  `extractSspIndex(doc) → { controlImplementations: Map<id, hash>;
  components: Map<uuid, hash>; users: Map<uuid, hash> }` so the diff
  doesn't need to re-walk the entire doc twice.
- `cloud-evidence/core/orchestrator.ts`: `--ssp-annual-review` +
  `--prior-ssp-path <path>` flags + envs.
- `cloud-evidence/core/submission-bundle.ts`: Role `'ssp-annual-diff'`
  (filename `ssp-annual-diff-<YYYY>.md`).

**Schemas / standards**:
- OSCAL SSP v1.1.2 (already covered by `core/oscal-ssp.ts`).
- NIST SP 800-53 Rev5 control PL-2.b (system security plans reviewed
  and updated). FedRAMP Rev5 ConMon Strategy section "Annual SSP
  Update".

**Build steps**:
1. **Diff function** (`core/ssp-diff.ts`):
   `diffSsp(prior: OscalSsp, current: OscalSsp): SspDiff` where
   `SspDiff = { changed_controls: Array<{ control_id: string;
   prev_hash: string; new_hash: string; field_changes: string[] }>;
   added_components: Component[]; removed_components: Component[];
   added_users: User[]; removed_users: User[]; metadata_changes:
   string[]; summary: { controls_changed: number; components_delta:
   number; users_delta: number; narrative_changed: boolean } }`.
   Uses content hash (sha256 of canonical JSON) per control
   implementation, per component, per user.
2. **Annual review** (`core/ssp-annual-review.ts`):
   `runSspAnnualReview(opts: {outDir, runId, year, priorSspPath?}):
   {diffPath, hadChanges, requiresAttestation}` that:
   a. Loads current `ssp.json` from `outDir`.
   b. Loads prior SSP from `priorSspPath` (operator-supplied) OR from
      `outDir/archive/ssp-<YYYY-1>.json` (auto).
   c. Computes the diff.
   d. Renders `ssp-annual-diff-<YYYY>.md` with 5 sections: changed
      controls (table), added components (table), removed components
      (table), narrative changes (per-section text diff), attestation
      block (REQUIRES-OPERATOR-INPUT for signature).
   e. Archives the current SSP to `outDir/archive/ssp-<YYYY>.json`.
3. **Attestation block**: 4 fields — `reviewed_by`, `reviewed_at`,
   `attestation_statement` ("I attest that the System Security Plan
   reflects the current as-built state of the system as of <date>"),
   `signature`. All four are `REQUIRES-OPERATOR-INPUT` unless
   operator supplies via CLI flags or the tracker UI (deferred until
   LOOP-F.F1 lands; until then, operator edits the .md directly).
4. **Orchestrator wiring**: `--ssp-annual-review` triggers after
   `--oscal-ssp`. When `--prior-ssp-path` is set, that's the diff
   source; otherwise look in archive.
5. **No fabrication**: if no prior SSP exists, emit a clear .md
   stating "First annual cycle; no prior SSP to diff against. The
   current SSP is the baseline for next year's review." — REAL.

**REQUIRES-OPERATOR-INPUT fields**:
- `attestation.reviewed_by`: CLI `--ssp-attested-by <name>` /
  `CLOUD_EVIDENCE_SSP_ATTESTED_BY`.
- `attestation.signature`: never auto-emitted; always REQUIRES-OPERATOR-INPUT
  in the rendered .md (operator signs out-of-band).
- `prior-ssp-path`: when archive lookup fails AND operator hasn't
  supplied, the slice emits a `REQUIRES-OPERATOR-INPUT` diagnostic
  (does not silently treat as "first year").

**Test specifications** (~10 ssp-diff + ~12 ssp-annual-review):
1. `it('diffSsp returns empty diff for identical docs', ...)`.
2. `it('diffSsp detects changed control implementation', ...)` — flip
   one control's `description`; assert one `changed_controls` entry.
3. `it('diffSsp detects added component', ...)`.
4. `it('diffSsp detects removed user', ...)`.
5. `it('diffSsp detects metadata.title change', ...)`.
6. `it('diffSsp is deterministic on shuffled input arrays', ...)`.
7. `it('extractSspIndex hashes are stable across JSON serialization', ...)`.
8. `it('diffSsp summary counts match the detailed arrays', ...)`.
9. `it('diffSsp handles missing optional fields gracefully', ...)`.
10. `it('diffSsp.narrative_changed flips only on prose changes', ...)`.
11. `it('runSspAnnualReview emits ssp-annual-diff-<YYYY>.md with 5 sections', ...)`.
12. `it('runSspAnnualReview archives the current SSP', ...)`.
13. `it('runSspAnnualReview surfaces requiresAttestation=true when changes detected', ...)`.
14. `it('runSspAnnualReview first-year case emits a clean "no prior" .md', ...)`.
15. `it('runSspAnnualReview honors --prior-ssp-path override', ...)`.
16. `it('attestation block contains all four REQUIRES-OPERATOR-INPUT cells when no operator inputs', ...)`.
17. `it('attestation reviewed_by is populated when CLI flag set', ...)`.
18. `it('throws when current ssp.json missing and --oscal-ssp not in run', ...)`.
19. `it('integrates with submission-bundle.ts ssp-annual-diff role', ...)`.
20. `it('diff Markdown escapes control characters in narratives', ...)`.
21. `it('archive directory is included in signed manifest', ...)`.
22. `it('does not auto-bump metadata.version of the SSP', ...)`.

**REO compliance checks specific to this slice**:
- Diff is content-derived (sha256 of canonical JSON per element),
  never narrative-paraphrased.
- Attestation `signature` is NEVER auto-emitted (Rule 1 — no fake
  cryptographic operations).
- Archive directory grows append-only; old SSPs are never silently
  overwritten.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/ssp-annual-review.test.ts tests/core/ssp-diff.test.ts
npm run check:reo
```

**Estimated effort**: 4 days.

---

### Slice E.E5 — Deviation Request (DR) Emitter

**Why this slice**: Per FedRAMP, when a POA&M item cannot be remediated
within the standard window, the CSP files a Deviation Request. There
are **four DR types** (verbatim from the 2026 ConMon Evidence Guide):
*"Risk Adjustments (RA): When mitigating factors reduce exploitation
likelihood; False Positives (FP): When vulnerabilities don't actually
exist; Operational Requirements (OR): When fixes would affect system
functionality; Vendor Dependencies (VD): High-risk must reduce to
Moderate within 30 days."* The standard format is a Word document
submitted with the monthly POA&M. Today's codebase has no DR emitter
— operators write them by hand.

**Files to create**:
- `cloud-evidence/core/deviation-request.ts` — `.docx` renderer (one
  document per DR) + ledger.
- `cloud-evidence/core/deviation-ledger.ts` — append-only ledger of
  DRs created + their states (`submitted | approved | denied |
  expired`).
- `cloud-evidence/tests/core/deviation-request.test.ts` — ~15 tests.
- `cloud-evidence/tests/core/deviation-ledger.test.ts` — ~8 tests.

**Files to extend**:
- `cloud-evidence/core/oscal-poam.ts`: when a DR is approved (ledger
  state `approved`), the next POA&M emission must set the affected
  item's `risk.status = 'deviation-approved'`. Add a
  `deviationOverrides: Map<itemUuid, 'deviation-requested' | 'deviation-approved'>`
  parameter to `PoamEmitOptions` and use it in `severityToRiskStatus`.
- `cloud-evidence/core/submission-bundle.ts`: Roles
  `'deviation-request-docx'` (filename regex
  `/^deviation-requests\/DR-\d+-(RA|FP|OR|VD)\.docx$/`),
  `'deviation-ledger'` (`deviation-ledger.jsonl`).
- `cloud-evidence/core/orchestrator.ts`: `--emit-deviation-request
  <DR-spec.json>` flag — reads operator-authored DR spec JSON and
  emits the .docx.

**Schemas / standards**:
- FedRAMP POA&M Template columns (per §3 source 8):
  - **Column V** = Risk Adjustment (Y/N)
  - **Column W** = False Positive (Y/N)
  - **Column X** = Operational Requirement (Y/N)
  - **Column Q** = Vendor Dependency (Y/N)
  - **Column R** = Last Vendor Check-in Date
  - **Column S** = Vendor Dependent Product Name
- Verbatim FedRAMP guidance:
  - *"FedRAMP will not approve an OR for a High vulnerability"* —
    enforce in `validateDeviationRequest()`.
  - *"High-risk VDs must be mitigated to a Moderate level through
    compensating controls within thirty (30) days"* — enforce
    on VD type.
  - *"CSPs are required to check in with the vendor at least once a
    month"* — VD type requires `last_vendor_check_in_date` <= 30 days
    from now.
- Word .docx via existing `core/zip.ts` (zip-store) + OOXML strings —
  same pattern as `core/roe-emit.ts`.

**Build steps**:
1. **Types** (`core/deviation-request.ts`):
   ```ts
   export type DrType = 'RA' | 'FP' | 'OR' | 'VD';
   export interface DeviationRequest {
     dr_id: string;                          // human-readable, e.g. "DR-2026-0001-RA"
     dr_type: DrType;
     poam_item_uuid: string;                 // the POA&M item this DR covers
     finding_rule: string;
     ksi_id: string;
     severity: 'critical'|'high'|'medium'|'low';
     original_finding_summary: string;
     justification: string;                  // operator-supplied prose
     compensating_controls?: string[];       // NIST control IDs
     supporting_evidence_refs?: string[];    // URLs / file refs
     // RA-specific:
     adjusted_severity?: 'medium'|'low';
     adjustment_rationale?: string;
     // VD-specific:
     vendor_name?: string;
     vendor_product?: string;
     vendor_advisory_url?: string;
     last_vendor_check_in_date?: string;     // ISO; must be <= 30d
     // OR-specific:
     operational_impact_if_remediated?: string;
     // FP-specific:
     reason_finding_does_not_exist?: string;
     // Workflow:
     csp_approver_name: string;
     csp_approver_title: string;
     submitted_at: string;
     ao_approval_status: 'pending' | 'approved' | 'denied';
     ao_approval_date?: string;
     expires_at?: string;                    // when approval expires (default 12m)
   }
   ```
2. **Validation** (`validateDeviationRequest(dr) → Error[]`):
   - All required fields per type populated.
   - OR + severity=high → ERROR (FedRAMP prohibits).
   - VD + severity=high → require compensating_controls AND
     adjustment_rationale (mitigation to moderate within 30d).
   - VD + last_vendor_check_in_date > 30d from `now` → ERROR.
   - All four types: `justification` non-empty.
3. **Renderer** (`renderDeviationRequestDocx(dr): Buffer`):
   - Reuse OOXML helpers from `roe-emit.ts`: `para()`, `heading()`,
     `table()`, `fieldTable()`.
   - 7 sections: 1. Identification table (dr_id, dr_type, system,
     CSP, POA&M item ref). 2. Original finding (rule, KSI, severity,
     summary). 3. Deviation justification (per-type fields). 4.
     Compensating controls (table). 5. Supporting evidence (links).
     6. CSP approver block (name, title, signature ←
     REQUIRES-OPERATOR-INPUT). 7. AO sign-off block (4 cells, all
     REQUIRES-OPERATOR-INPUT).
4. **Disk emitter** (`emitDeviationRequest(opts: { outDir, dr }):
   { path: string }`):
   - Writes to `outDir/deviation-requests/<dr_id>.docx`.
   - Appends to `outDir/deviation-ledger.jsonl`.
5. **Ledger** (`core/deviation-ledger.ts`): append-only JSONL with
   columns `{dr_id, dr_type, poam_item_uuid, state, transitions: [{
   state, at, by }], expires_at}`. Helpers:
   `appendDr`, `transitionDr(dr_id, new_state, by)`,
   `readDeviationLedger(outDir): Entry[]`,
   `activeDeviations(outDir): Entry[]` (state === 'approved' AND
   expires_at > now).
6. **POA&M integration**: extend `core/oscal-poam.ts` to accept the
   `deviationOverrides` map; when an item's uuid is in the map with
   state=approved, the risk status becomes `'deviation-approved'`
   and `risk.deadline` is replaced with the DR `expires_at`.
7. **Operator workflow**:
   - Operator authors `dr-spec.json` (one file per DR) and runs
     `--emit-deviation-request dr-spec.json`. The orchestrator
     validates + emits the .docx + appends ledger entry as
     `state=pending`.
   - When the AO returns an approved DR, the operator runs
     `--update-deviation-state <dr_id> approved <ao_name>`. The
     ledger logs the transition (with signed audit trail flowing into
     the tracker when LOOP-F.F1 lands).

**REQUIRES-OPERATOR-INPUT fields**:
- `csp_approver_signature` cell in the .docx: never auto-emitted.
- `ao_approval_signature` cell: never auto-emitted.
- `ao_approval_date`, `expires_at`: populated only by the
  `--update-deviation-state` workflow.
- The four type-specific narrative fields (`justification`,
  `adjustment_rationale`, `reason_finding_does_not_exist`,
  `operational_impact_if_remediated`): operator-authored in
  dr-spec.json; validator REJECTS empty strings.

**Test specifications** (~15 deviation-request + ~8 deviation-ledger):
1. `it('validates RA requires adjusted_severity + adjustment_rationale', ...)`.
2. `it('validates OR + severity=high throws "FedRAMP will not approve"', ...)`.
3. `it('validates VD + last_vendor_check_in_date > 30d ago throws', ...)`.
4. `it('validates FP requires reason_finding_does_not_exist', ...)`.
5. `it('renders .docx with all 7 sections', ...)` — parse OOXML parts,
   assert headings present.
6. `it('docx is a valid store-only ZIP with [Content_Types].xml + word/document.xml', ...)`.
7. `it('docx contains the dr_id + poam_item_uuid in word/document.xml body', ...)`.
8. `it('CSP approver signature cell is literally REQUIRES-OPERATOR-INPUT', ...)`.
9. `it('AO sign-off cells are all REQUIRES-OPERATOR-INPUT', ...)`.
10. `it('emitDeviationRequest writes to outDir/deviation-requests/<dr_id>.docx', ...)`.
11. `it('emitDeviationRequest appends a ledger entry with state=pending', ...)`.
12. `it('transitionDr appends a transitions[] entry (does not mutate existing rows)', ...)`.
13. `it('activeDeviations excludes expired approvals', ...)`.
14. `it('VD with severity=high requires compensating_controls', ...)`.
15. `it('deterministic: same dr-spec → byte-identical .docx (ZIP store + fixed mtime)', ...)`.
16. `it('integrates with oscal-poam: approved DR flips item status to deviation-approved', ...)`.
17. `it('VD adjusted to medium produces a separate audit record', ...)`.
18. `it('submission-bundle picks up the deviation-requests/ dir', ...)`.
19. `it('ledger handles concurrent appends safely (append-only)', ...)`.
20. `it('reject DR pointing at non-existent POA&M item uuid', ...)`.
21. `it('reject DR with empty justification', ...)`.
22. `it('renderDeviationRequestDocx escapes XML special chars in narratives', ...)`.
23. `it('expires_at defaults to submitted_at + 12 months when omitted', ...)`.

**REO compliance checks specific to this slice**:
- Every emitted DR traces to a real `poam_item_uuid` in
  `out/poam.json`. The validator rejects unknown uuids.
- No "fake" approvals: the ledger transition function signs the
  transition with a deterministic structural record only — actual
  CSP / AO signatures stay REQUIRES-OPERATOR-INPUT.
- High-severity OR rejection is hard-coded per FedRAMP MUST.
- No silent expiration: when a DR's `expires_at < now` is detected
  during a monthly run, the POA&M item flips back to `open` and
  `core/conmon-report.ts` (E.E1) flags it under
  `deviation_requests.expiring_within_30d` proactively.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/deviation-request.test.ts tests/core/deviation-ledger.test.ts
npm run check:reo
```

**Estimated effort**: 5 days (4 narrative types × validation + .docx +
POA&M integration + ledger + tests).

---

### Slice E.E6 — Formal SCN Document Emitter (extends existing classifier)

**Why this slice**: `core/scn-classifier.ts` already (a) harvests
changes from finding-diff + inventory-diff + operator-proposed inputs,
(b) classifies them via a rule library, (c) emits a
`scn-notice-draft.md`. What it does NOT emit is the **formal Word
document** that goes to the authorizing agency on agency letterhead-
style stationery with the SCR fields the playbook mandates.

**Files to create**:
- `cloud-evidence/core/scn-doc.ts` — `.docx` renderer using the
  classifier's `ScnReport` as input.
- `cloud-evidence/core/scn-ledger.ts` — append-only ledger of SCNs
  submitted (mirrors deviation-ledger).
- `cloud-evidence/tests/core/scn-doc.test.ts` — ~12 tests.
- `cloud-evidence/tests/core/scn-ledger.test.ts` — ~6 tests.

**Files to extend**:
- `cloud-evidence/core/scn-classifier.ts`: NO type changes. Export
  `ScnReport` (already exported). Add `renderScnSubmissionBundle()`
  helper that drives the new `.docx` emitter from the existing report.
- `cloud-evidence/core/submission-bundle.ts`: Roles `'scn-doc-docx'`
  (filename regex `/^scn-notice-SCN-\d+\.docx$/`), `'scn-ledger'`
  (`scn-ledger.jsonl`). (`scn-classification.json` + `scn-notice-draft.md`
  already registered.)
- `cloud-evidence/core/orchestrator.ts`: `--scn-doc` flag (implies
  `--scn`); reads classifier output + emits .docx.

**Schemas / standards** (from §3 source 7 — FedRAMP SCN page,
verbatim required content):
1. **Service Offering FedRAMP ID**
2. **Assessor Name**
3. **Related POA&M (if the change is being implemented to address a
   known risk)**
4. **Significant Change type and explanation of categorization**
5. **Short description of change**
6. **Reason for change**
7. **Summary of customer impact, including changes to services and
   customer configuration responsibilities**
8. **Plan and timeline for the change, including for the verification,
   assessment, and/or validation of impacted security controls**
9. **Copy of the security impact analysis**
10. **Name and title of CSP approver (typically the system owner)**

Plus FedRAMP CITED definition: *"a change that is likely to
substantively affect the security or privacy posture of a system"*
(NIST SP 800-37 Rev. 2) — quoted verbatim in the SCN doc body.

**Build steps**:
1. **Types** (`core/scn-doc.ts`):
   ```ts
   export interface ScnDocOptions {
     outDir: string;
     runId: string;
     scnId: string;                          // e.g. "SCN-2026-0001"
     fedrampPackageId: string;               // operator
     systemName: string;
     csp: string;
     // From classifier (real):
     classification: ScnClassification;      // re-exported from scn-classifier
     // Operator-supplied required fields:
     assessorName?: string;
     relatedPoamUuids?: string[];
     reasonForChange?: string;
     customerImpactSummary?: string;
     planAndTimeline?: string;
     securityImpactAnalysisPath?: string;    // path to operator-authored SIA
     cspApproverName?: string;
     cspApproverTitle?: string;
   }
   ```
2. **Renderer** (`renderScnDocx(opts): Buffer`):
   - 10 sections matching the 10 verbatim required fields above, in
     order. Each missing operator field emits the literal
     `REQUIRES-OPERATOR-INPUT` constant.
   - Section 0 (front matter): scn_id, fedrampPackageId, system, CSP,
     submission date, classification verdict (significant /
     advisory), recommended notice days from classifier.
   - Section 9: Security Impact Analysis — if path provided, embed
     summary + reference; if not, REQUIRES-OPERATOR-INPUT block
     describing how to author one.
   - Section 11 (final): NIST SP 800-37 Rev. 2 verbatim quoted
     definition + acknowledgement signature block (CSP system owner
     + AO acknowledgement, both REQUIRES-OPERATOR-INPUT).
3. **Disk emitter** (`emitScnDoc(opts): { path, ledgerEntry }`):
   - Writes to `outDir/scn-notice-<scnId>.docx`.
   - Appends `scn-ledger.jsonl` with `{scn_id, classification_rule_id,
   significance, submitted_at, state: 'submitted', transitions: []}`.
4. **Ledger** (`core/scn-ledger.ts`): same shape as deviation-ledger.
   States: `submitted | acknowledged | denied | applied | reverted`.
5. **Orchestrator wiring**: `--scn-doc <scn-spec.json>` reads the
   operator-supplied spec (which references a classification from
   `scn-classification.json` by `change.id`), validates, emits the
   `.docx`.
6. **Conditional emission**: when classifier finds zero significant
   changes, `--scn-doc` exits with code 0 + a clear log line and does
   NOT write a .docx (parallel to LOOP-A.A1 "no failing findings ==
   clean skip" pattern).

**REQUIRES-OPERATOR-INPUT fields**:
- `assessorName`, `reasonForChange`, `customerImpactSummary`,
  `planAndTimeline`, `securityImpactAnalysisPath`, `cspApproverName`,
  `cspApproverTitle` — all CLI flags / scn-spec.json fields.
- AO acknowledgement signature: always REQUIRES-OPERATOR-INPUT.
- `relatedPoamUuids`: optional — if omitted, the section reads "No
  related POA&M item; this change is not addressing a known risk."
  (a real true statement, not a placeholder).

**Test specifications** (~12 + ~6):
1. `it('renderScnDocx produces a valid store-only ZIP with [Content_Types].xml', ...)`.
2. `it('document includes all 10 verbatim FedRAMP-required SCR fields as section headers', ...)`.
3. `it('NIST SP 800-37 Rev. 2 definition quoted verbatim in the doc body', ...)`.
4. `it('REQUIRES-OPERATOR-INPUT marker emitted for missing assessorName', ...)`.
5. `it('CSP approver signature cell is always REQUIRES-OPERATOR-INPUT', ...)`.
6. `it('classification verdict surfaces in front matter', ...)`.
7. `it('related POA&M items listed when relatedPoamUuids provided', ...)`.
8. `it('related POA&M section reads "No related POA&M item" when uuids omitted', ...)`.
9. `it('emitScnDoc writes to outDir/scn-notice-<scnId>.docx', ...)`.
10. `it('emitScnDoc appends ledger entry with state=submitted', ...)`.
11. `it('--scn-doc with zero significant changes exits 0 without writing', ...)`.
12. `it('integrates with submission-bundle: scn-doc-docx role recognized', ...)`.
13. `it('deterministic: same input → byte-identical .docx', ...)`.
14. `it('docx XML escapes special chars in operator narratives', ...)`.
15. `it('ledger transitionScn appends without mutating prior states', ...)`.
16. `it('readScnLedger returns entries in chronological order', ...)`.
17. `it('activeScns excludes denied / reverted entries', ...)`.
18. `it('ledger sha256 of .docx matches written file', ...)`.

**REO compliance checks specific to this slice**:
- Classification (significance + rationale + recommended_notice_days)
  comes entirely from the real classifier output — no override path in
  the doc emitter.
- AO acknowledgement signature is NEVER auto-filled.
- FedRAMP SCR field list is hardcoded as a constant array in
  `core/scn-doc.ts` with a citation comment pointing at §3 source 7.
  Per REO Rule 3, FedRAMP-published constants are an allowed
  exception.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/scn-doc.test.ts tests/core/scn-ledger.test.ts
npm run check:reo
```

**Estimated effort**: 3 days.

---

### Slice E.E7 — Annual IRP / ISCP Test Cadence Runner

**Why this slice**: NIST SP 800-53 Rev5 IR-3 (Incident Response
Testing) and CP-4 (Contingency Plan Testing) require **annual**
exercises with documented results — the After-Action Report (AAR).
FedRAMP annual assessment requires the AAR as a referenced artifact.
Without this slice, AARs are written from scratch every year — and
miss the prefilled context (test participants from tracker,
prior-year findings ledger, planned exercise scope) that the test
team needs.

**Files to create**:
- `cloud-evidence/core/annual-test-runner.ts` — orchestrates emission
  of two AAR templates (IRP + ISCP) per year.
- `cloud-evidence/core/iscp-test-aar.ts` — ISCP AAR `.docx` renderer.
- `cloud-evidence/core/irp-test-aar.ts` — IRP AAR `.docx` renderer.
- `cloud-evidence/core/annual-test-ledger.ts` — per-year ledger of
  scheduled + completed exercises.
- `cloud-evidence/tests/core/iscp-test-aar.test.ts` — ~10 tests.
- `cloud-evidence/tests/core/irp-test-aar.test.ts` — ~10 tests.
- `cloud-evidence/tests/core/annual-test-runner.test.ts` — ~8 tests.

**Files to extend**:
- `cloud-evidence/core/submission-bundle.ts`: Roles
  `'irp-test-aar'` (filename regex `/^irp-test-\d{4}\.docx$/`),
  `'iscp-test-aar'` (filename regex `/^iscp-test-\d{4}\.docx$/`),
  `'annual-test-ledger'` (`annual-test-ledger.jsonl`).
- `cloud-evidence/core/orchestrator.ts`: `--annual-irp-test
  --annual-year YYYY` and `--annual-iscp-test --annual-year YYYY`
  flags + envs.

**Schemas / standards**:
- NIST SP 800-53 Rev5 IR-3 (a/b/c) and CP-4 (a/b/c).
- FedRAMP ISCP Template structure (Rev4 template still authoritative
  for Rev5 ISCP; §3 source 10).
- IRP test cycle: typical scope is `tabletop` (annual) and
  `functional/full` (rotating multi-year). The AAR template carries
  both options.

**Build steps**:
1. **ISCP AAR types + renderer** (`core/iscp-test-aar.ts`):
   ```ts
   export interface IscpTestAar {
     year: number;
     test_date: string;                      // ISO
     test_type: 'tabletop' | 'functional' | 'full-recovery';
     scope_summary: string;
     participants: Array<{ name: string; role: string; organization: string }>;
     scenarios_executed: Array<{ id: string; description: string; outcome: 'pass'|'fail'|'partial'; notes: string }>;
     rto_target_minutes: number;
     rpo_target_minutes: number;
     observed_rto_minutes?: number;
     observed_rpo_minutes?: number;
     findings: Array<{ id: string; severity: string; description: string; remediation_owner: string; target_date: string }>;
     lessons_learned: string[];
     prior_year_findings_status: Array<{ id: string; status: 'closed'|'in-progress'|'open' }>;
   }
   ```
   Renderer follows the FedRAMP ISCP Template structure. 11 sections
   per the template TOC.
2. **IRP AAR types + renderer** (`core/irp-test-aar.ts`):
   ```ts
   export interface IrpTestAar {
     year: number;
     test_date: string;
     test_type: 'tabletop' | 'functional';
     scenario: string;                       // e.g. "ransomware in customer-data tier"
     participants: Array<{ name: string; role: string; organization: string }>;
     timeline: Array<{ time_offset_min: number; action: string; actor: string }>;
     evaluation: {
       detection_time_min: number;
       containment_time_min: number;
       eradication_time_min: number;
       recovery_time_min: number;
       reporting_compliance: { fedramp: boolean; cisa: boolean; agency: boolean };
     };
     findings: Array<{ id: string; severity: string; description: string; remediation_owner: string; target_date: string }>;
     lessons_learned: string[];
     prior_year_findings_status: Array<{ id: string; status: 'closed'|'in-progress'|'open' }>;
   }
   ```
   8-section AAR following IR-3 outline.
3. **Runner** (`core/annual-test-runner.ts`):
   `runAnnualIrpTest(opts: { outDir, year, runId, scenario?,
   participants?, priorYearLedger? }): { docxPath, ledgerEntry }`
   and parallel `runAnnualIscpTest(opts)`. Each loads prior-year
   findings from `annual-test-ledger.jsonl`, prefills the AAR with
   participant list (from tracker if available, else
   REQUIRES-OPERATOR-INPUT), and emits the .docx.
4. **Ledger** (`core/annual-test-ledger.ts`): one entry per (year,
   exercise_type). Fields: `{year, exercise_type: 'irp'|'iscp',
   scheduled_date, completed_date?, aar_path, findings_count,
   sha256}`. Helpers: `appendTestEntry`, `priorYearFindings(year,
   type): {id, status}[]`.
5. **Orchestrator wiring**: `--annual-irp-test` + `--annual-iscp-test`
   each emit one .docx into `outDir/` and append the ledger.
6. **First-year case**: when no prior ledger exists, the AAR's
   "prior-year findings status" section reads "First annual test
   cycle; no prior findings to report." (REAL).

**REQUIRES-OPERATOR-INPUT fields**:
- `participants`: CLI flag `--test-participants <path-to-json>` or
  populated from tracker (LOOP-F.F4 will surface the test team in
  the tracker). Until then, REQUIRES-OPERATOR-INPUT row.
- `scenario` (IRP): CLI `--irp-scenario`.
- `scope_summary` (ISCP): CLI `--iscp-scope`.
- `scenarios_executed[].outcome`: CLI / tracker. The runner emits
  empty rows with REQUIRES-OPERATOR-INPUT before the test, then the
  operator fills outcomes after.
- All `observed_*` timing fields: post-test operator input.
- `findings[]`: operator-authored after the test (NEVER fabricated).

**Test specifications** (~10 + ~10 + ~8):
1. `it('iscp AAR renders all 11 sections per FedRAMP template', ...)`.
2. `it('iscp AAR prior_year_findings_status reads from ledger', ...)`.
3. `it('iscp AAR participants section emits REQUIRES-OPERATOR-INPUT when none provided', ...)`.
4. `it('iscp AAR includes RTO + RPO target rows', ...)`.
5. `it('iscp AAR observed_* fields are REQUIRES-OPERATOR-INPUT when omitted', ...)`.
6. `it('iscp AAR is a valid store-only ZIP', ...)`.
7. `it('iscp AAR is deterministic on identical inputs', ...)`.
8. `it('iscp AAR escapes XML in scope_summary', ...)`.
9. `it('iscp AAR findings table renders all severity columns', ...)`.
10. `it('iscp AAR first-year case emits "First annual test cycle" line', ...)`.
11. `it('irp AAR renders all 8 sections per IR-3 outline', ...)`.
12. `it('irp AAR includes timeline table with time_offset_min', ...)`.
13. `it('irp AAR reporting_compliance row enumerates fedramp/cisa/agency', ...)`.
14. `it('irp AAR emits REQUIRES-OPERATOR-INPUT for scenario when --irp-scenario missing', ...)`.
15. `it('irp AAR participants block honors --test-participants JSON', ...)`.
16. `it('irp AAR detection/containment/eradication/recovery minute fields render as numbers', ...)`.
17. `it('irp AAR is a valid store-only ZIP', ...)`.
18. `it('irp AAR is deterministic on identical inputs', ...)`.
19. `it('irp AAR prior-year ledger lookup excludes other exercise_type', ...)`.
20. `it('irp AAR findings table includes remediation_owner + target_date', ...)`.
21. `it('annual-test-runner emits both irp + iscp via runAnnualIrpTest + runAnnualIscpTest', ...)`.
22. `it('annual-test-runner appends one ledger entry per exercise', ...)`.
23. `it('annual-test-runner integrates with submission-bundle', ...)`.
24. `it('annual-test-runner throws when --annual-year < 2020 or > current+1', ...)`.
25. `it('annual-test-runner does not double-emit for the same (year, type)', ...)`.
26. `it('annual-test-runner respects --strict-annual (errors when participants missing)', ...)`.
27. `it('annual-test-runner ledger sha256 matches AAR file', ...)`.
28. `it('annual-test-runner stages AARs into E.E3 annual-assessment package', ...)`.

**REO compliance checks specific to this slice**:
- Prior-year status comes from a real ledger, never invented.
- Observed timing fields are REQUIRES-OPERATOR-INPUT until the
  exercise actually happens.
- The AAR is **pre-fillable** before the exercise (scope, participants,
  scenarios, prior-year findings) AND **post-fillable** after (outcomes,
  observed timings, lessons-learned, new findings). Operator opens
  the .docx, fills, re-runs `--annual-irp-test --commit-results
  <path-to-filled-docx>` (which appends the completion fields to the
  ledger; deferred ledger logic — first ship just the pre-fill).

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/iscp-test-aar.test.ts tests/core/irp-test-aar.test.ts tests/core/annual-test-runner.test.ts
npm run check:reo
```

**Estimated effort**: 5 days (two .docx renderers + runner + ledger +
~28 tests).

---

## 5. Loop-wide acceptance criteria

When every slice E.E1–E.E7 is complete:

1. **Monthly cycle is automatable**: a single command
   `npm run collect -- --conmon-monthly --month 2026-07 --oscal-poam
   --inventory-workbook --crosswalk --scn --scn-doc <scn-spec.json>
   --submission-bundle` produces the entire monthly submission
   package (POA&M + inventory + scans + ConMon report + SCN docs +
   DR docs) signed, timestamped, and ready for USDA Connect.gov.
2. **Month-over-month delta** is computed automatically — operators
   can see exactly what changed before each upload.
3. **Annual cycle is automatable**: `npm run collect --
   --annual-assessment --annual-year 2026 --annual-irp-test
   --annual-iscp-test --ssp-annual-review` produces the annual roll-up
   bundle.
4. **Deviation Request workflow** has 4 working types (RA / FP / OR /
   VD) with the FedRAMP-defined rejection rules enforced (High-OR
   blocked; VD vendor check-in ≤ 30 days).
5. **SCN workflow** has a formal .docx output with all 10 verbatim
   FedRAMP-required SCR fields.
6. **Annual test AARs** (IRP + ISCP) pre-fill from real participants
   + prior-year findings; post-fill by operator.
7. **REO discipline preserved**: `npm run check:reo` returns 0; every
   field traces to real evidence, the FedRAMP catalog
   (`docs/fedramp-conmon-playbook.generated.json`,
   `docs/fedramp-annual-core-controls.generated.json`), or operator
   input.
8. **Test count grows by ~120**: ~13 (E1) + ~20 (E2) + ~16 (E3) + ~22
   (E4) + ~23 (E5) + ~18 (E6) + ~28 (E7) = **~140 new tests** with
   all green.
9. **submission-bundle.ts well-known catalogue** grows from 24 roles
   to ~36 roles covering every E.E* artifact.
10. **CHANGELOG.md** Unreleased section has one entry per slice
    naming the module + verification counts.

---

## 6. Open questions / caveats

1. **PDF generator complexity**: `core/conmon-pdf.ts` (E.E1) is a
   non-trivial pure-JS PDF writer. If the team determines this is
   higher-risk than the value justifies, alternative: emit only `.md`
   + `.html` (the .html via existing `core/html-report.ts` pattern).
   The FedRAMP playbook does not mandate PDF specifically — `.md`
   converted by the operator via Pandoc is acceptable. RECOMMEND
   shipping PDF since uploads to USDA Connect.gov are commonly PDF.
2. **USDA Connect.gov push**: this loop does NOT push to USDA.
   FedRAMP does not publish a public API spec; operators upload
   manually. A future LOOP-H.H1 or LOOP-E.E8 may add a
   `--push-fedramp-repo` path once the spec lands.
3. **Test participants from tracker**: E.E7 currently REQUIRES-OPERATOR-INPUT
   for participants. LOOP-F.F4 (evidence walk-through artifacts) and
   the broader LOOP-G.G2 (incident records) will likely add a
   tracker DB table the runner reads from. Until then, operator
   supplies via JSON.
4. **Annual-year boundary semantics**: the spec assumes a calendar
   year. Some CSPs run on a fiscal year. Currently `--annual-year YYYY`
   covers Jan 1–Dec 31. A future enhancement adds `--annual-year-start
   MM-DD`. Track as caveat.
5. **DR auto-approval**: AO approvals in production come via email or
   Connect.gov UI, not API. The `--update-deviation-state` workflow
   is operator-driven. When LOOP-F.F1 (3PAO/AO sign-off UI) lands,
   the tracker can feed the ledger directly.
6. **ConMon Playbook version**: we pin Nov-2025 v1.0. If FedRAMP
   publishes v1.1 / v2.0, re-run `scripts/fetch-conmon-playbook.mjs`
   and update the pinned JSON. The provenance block in E.E1 output
   surfaces the pinned version.
7. **Phase 2 pilot post-retrospective format** (per R3): if FedRAMP
   publishes a revised submission bundle format between LOOP-E start
   and GA, `package_format_version` in `INDEX.json` lets us version
   cleanly.

---

## 7. Status tracking

| Slice ID | Status | Commit hash | Completed date |
|---|---|---|---|
| E.E1 — Monthly ConMon Analysis Report | done | ddfa499 | 2026-06-11 |
| E.E2 — Monthly POA&M Delta Workflow | done | fb6831a | 2026-06-11 |
| E.E3 — Annual Assessment Package Generator | pending | — | — |
| E.E4 — Annual SSP Review / Update Workflow | pending | — | — |
| E.E5 — Deviation Request (DR) Emitter | pending | — | — |
| E.E6 — Formal SCN Document Emitter | pending | — | — |
| E.E7 — Annual IRP/ISCP Test Cadence Runner | pending | — | — |

---

## 8. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST:

1. Run all three guardrails locally and ensure they are green:
   ```bash
   cd cloud-evidence
   npm run typecheck && npm test && npm run check:reo
   ```
2. Update the Section 7 status table:
   - Set `Status` to `done`.
   - Set `Commit hash` to the 7-char short hash of the slice's commit.
   - Set `Completed date` to today's ISO date (`YYYY-MM-DD`).
3. Add a `CHANGELOG.md` entry under the `Unreleased` section with the
   pattern matching prior LOOP-A entries:
   - `### Added — LOOP-E.<slice-id>: <slice title>`
   - 1-2 paragraph summary of the gap closed.
   - Bulleted list of every module added/extended with file paths.
   - REO compliance paragraph naming the operator-input fields.
   - Verification line: `Verification: typecheck clean; <N>/<N> tests
     passing (+<delta> from LOOP-E.<slice-id>); npm run check:reo
     returns 0.`
4. Update `cloud-evidence/docs/STATUS.md` (create if missing —
   parallel to `docs/EXECUTION-PLAN.md`'s "Status snapshot" table) to
   set this slice's status to `done`.
5. Commit with the conventional message:
   ```
   LOOP-E.<slice-id>: <slice title>
   ```
   (no trailing description block; the CHANGELOG carries the prose).
6. Push to `origin/main`.

If any guardrail fails (typecheck, test, REO), the slice is NOT done
— fix the issue, re-stage, and create a NEW commit (never amend,
per REO Rule 2 + the CLAUDE.md Git Safety Protocol).
