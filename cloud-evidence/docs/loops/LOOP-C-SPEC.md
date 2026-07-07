# LOOP-C — Document Template Pack

> **Single-source spec for LOOP-C.** Any future Claude session must be able to
> read THIS FILE and implement every slice (C.C1–C.C9) end-to-end without
> consulting the original planning conversation. Nothing assumed, nothing
> inferred. All file paths are absolute-from-repo-root. All schemas are cited
> with URL + section. All operator-input fields are explicit.

---

## 1. Why this loop exists

The FedRAMP 20x authorization package and the Rev5 baseline that backs it
require ~12 Word-format policy/procedure documents in addition to the OSCAL
machine-readable artifacts already emitted by LOOP-A (SSP, AP, AR, POA&M, IIW,
RoE). Section A of the original requirements doc lists these as REQUIRED
deliverables; without them a 3PAO cannot fully assess the CSP against the
NIST SP 800-53 Rev5 Moderate baseline controls those documents satisfy
(CM-2, CM-9, CP-2, CP-4, IR-3, IR-8, PT-2, PT-3, PT-6, CA-7, PM-9, PM-10).
Today these documents are hand-authored from blank templates copied off
fedramp.gov, which is the largest single source of authorization-package
busywork and the largest single source of stale data risk (an SSP component
list that disagrees with the CMP component list will fail 3PAO sampling).

**Artifacts delivered by LOOP-C (one .docx per slice unless noted):**

| Slice | Artifact filename(s) | NIST control(s) | Auto-fill primary source |
|---|---|---|---|
| C.C1 | `cmp.docx` | CM-9, CM-2, CM-3, CM-4, CM-8 | `inventory.json`, `ksi-map`, tracker |
| C.C2 | `iscp.docx`, `iscp-test-aar.docx` | CP-2, CP-4, CP-9, CP-10 | RPL-* collectors (ABO/TRC/RRO/ARP) |
| C.C3 | `irp.docx`, `irp-test-aar.docx` | IR-8, IR-3, IR-4, IR-6 | INR-RIR collector, tracker incidents |
| C.C4 | `pta.docx` (+ conditional `pia.docx`) | PT-2, PT-3, PT-6, AR-2 | `inventory.json` data-class tags |
| C.C5 | `fips199.docx` | RA-2, SC-7 | operator config + SP 800-60 V2 catalog |
| C.C6 | `conmon-strategy.docx` | CA-7, CA-7(1), PM-31 | `ksi-map`, POA&M cadence |
| C.C7 | `rms.docx` | PM-9 | B.B5 risk register + B.B3/B.B4 |
| C.C8 | `auth-request-cover-letter.docx` | PM-10 | `INDEX.json` + system identity |
| C.C9 | `baseline-config.docx` | CM-2 | `inventory.json`, `reference-arch.ts`, AFR-SCG |

**Authorization-package gaps closed by LOOP-C:**
1. CM-9 Configuration Management Plan (currently a 3PAO-flagged gap during sampling).
2. CP-2 Contingency Plan + CP-4 annual test record (today missing for 20x submissions).
3. IR-8 Incident Response Plan + IR-3 annual exercise AAR (gating for ATO).
4. PT-2/3/6 Privacy artifacts (NIST 800-53 Rev5 reorganized privacy into PT family — many CSPs still ship Rev4 PIAs).
5. FIPS 199 categorization worksheet (the worksheet itself, distinct from the SSP's `security-impact-level` field).
6. CA-7 ConMon Strategy (referenced from SSP §15 but historically a separate Word document).
7. PM-9 Risk Management Strategy (organizational layer above the per-finding POA&M).
8. PM-10 Authorization Boundary / Authorization Decision artifacts (cover letter / transmittal).
9. CM-2 Baseline Configuration (distinct from CM-8 Inventory — Rev5 split these into separate artifacts).

---

## 2. Dependencies

### Must complete first (hard prerequisites)
- **LOOP-A.A1** (POA&M emitter, `core/oscal-poam.ts`) — C.C6 ConMon Strategy
  cites the POA&M monthly-cadence wire format LOOP-A.A1 produces.
- **LOOP-A.A4** (Submission bundler, `core/submission-bundle.ts`) — C.C8 cover
  letter reads the same `INDEX.json` the bundler emits to enumerate package
  contents; the bundler well-known catalogue must be extended for each LOOP-C
  artifact.
- **SSP-1** (`core/oscal-ssp.ts`) and **INV-1..S6** (`core/inventory-emit.ts`,
  `core/inventory-coverage.ts`) — every doc auto-fills from `ssp.json` and
  `inventory.json`.
- **REO-0** (`cloud-evidence/CLAUDE.md` + `scripts/lint-no-stubs.mjs` +
  `scripts/check-coverage-regression.mjs` + `scripts/check-provenance.mjs`)
  — the standard every emitter must satisfy.

### Soft prerequisites (auto-fill quality degrades without them)
- **B.B3** + **B.B4** + **B.B5** (LOOP-B risk register, risk acceptances,
  compensating controls). C.C7 RMS still emits without LOOP-B but every
  risk-related section becomes a REQUIRES-OPERATOR-INPUT block. If LOOP-B
  ships first, the RMS pulls real data.
- **G.G5** (AFR-SCG `core/afr-scg.ts`). C.C9 Baseline Configuration shares
  the secure-configuration recommendations table with AFR-SCG. The two
  emitters share the same source-of-truth (`providers/<cloud>/reference-arch.ts`).

### Files this loop reads (do NOT modify)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-emit.ts` (asset enumeration)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` (scope of automated controls)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` (system identity, sensitivity level)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/zip.ts` (`zipStore`, `xmlEscape`)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/log.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal.ts` (`deterministicUuid`)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/aws/reference-arch.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/gcp/reference-arch.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/azure/reference-arch.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/aws/backup.ts` (RPL-ABO/TRC/RRO/ARP)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/aws/logging.ts` (INR-RIR)

### Files this loop extends (modify in place)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add one `WellKnownArtifact` entry per LOOP-C `.docx` (9 new entries +
  2 AAR entries = 11 new well-known artifacts; update the `Role` union type).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — add 9 CLI flags + 9 env vars (one per slice) + console-output blocks
  + run-ledger entries (`record(<slice>.emit, ...)`).
- `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md` — Unreleased entry per
  slice (REO Rule 2.7).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` — slice
  status when complete (REO done-procedure §8).

### Loops unblocked WHEN C completes
- **LOOP-E** (ConMon agent) — needs `cmp.docx`, `conmon-strategy.docx`,
  `iscp.docx`, `irp.docx` as templates the monthly workflow updates.
- **LOOP-G.G5** (AFR-SCG) — shares the secure-config recommendations table
  with C.C9; C.C9 establishes the table structure.
- **LOOP-G.G6** (AFR-CCM) — extends C.C6 with the 20x-specific report-availability
  + feedback mechanism.
- **LOOP-F.F7** (SAR draft generator) — needs `irp.docx` + `iscp.docx` for
  reference; SAR cites the tested IR/CP plans.

### Loops that are parallel-safe with C (no dependency)
- LOOP-D (diagrams) — independent.
- LOOP-H (storage) — independent.
- LOOP-J (supply chain) — independent.

---

## 3. Authoritative sources

Every emitter in this loop cites at least one of the sources below verbatim
in its module-header JSDoc. The citation includes URL + section + the
publication's identifier as listed below.

### 3.1 FedRAMP-published templates and playbooks

- **FedRAMP Rev5 Documents & Templates index** — https://www.fedramp.gov/rev5/documents-templates/ — landing page for all CSP authorization-package templates. (Crawled 2026-06; URL stable since 2024-12.)
- **FedRAMP SSP Appendix G — Information System Contingency Plan (ISCP) Template** — https://www.fedramp.gov/assets/resources/templates/SSP-Appendix-G-Information-System-Contingency-Plan-(ISCP)-Template.docx — the only FedRAMP-published .docx the C.C2 emitter mirrors section-for-section. (FedRAMP Rev5, .docx, ~150 KB.)
- **FedRAMP SSP Attachment A04 — Privacy Impact Assessment (PIA) Template** — https://www.fedramp.gov/assets/resources/templates/SSP-A04-FedRAMP-PIA-Template.docx — C.C4 PIA shape. (Rev4 template; Rev5 has not been released — FedRAMP help-desk article 28907995813275 states "There are no current plans to provide a Rev. 5 PTA/PIA template for CSPs to complete." LOOP-C uses the Rev4 structure with PT-2/3/6 Rev5 control identifiers.)
- **FedRAMP SSP Attachment 10 — FIPS 199 Categorization Template** — https://www.fedramp.gov/resources/documents/rev4/REV_4_SSP-A10-FedRAMP-FIPS-199-Categorization-Template.docx — C.C5 structure. Tables: Information Types (with SP 800-60 V2 codes), Overall System CIA, Rationale.
- **FedRAMP Continuous Monitoring Strategy Guide v3.2 (2018-04-04)** — https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf — C.C6 source. Quote (Section 3.1, page 11): *"The CSP is required to perform continuous monitoring of all security controls in the SSP at the frequency identified by the FedRAMP requirements and as stated in the [CSP] System Security Plan."*
- **FedRAMP Continuous Monitoring Playbook v1.0 (2025-11-17)** — https://www.fedramp.gov/resources/documents/Continuous_Monitoring_Playbook.pdf — C.C6 monthly cadence + collaborative ConMon language.
- **RFC-0026 Clarifying CA-7 Continuous Monitoring Expectations for Rev5 Providers** — https://www.fedramp.gov/rfcs/0026/ — informs C.C6 deviation-request mention.
- **FedRAMP Agency Authorization Playbook v4.1 (2025-11-17)** — https://www.fedramp.gov/resources/documents/Agency_Authorization_Playbook.pdf — C.C8 cover-letter shape.
- **FedRAMP ATO Letter Template** — https://www.fedramp.gov/assets/resources/templates/FedRAMP-ATO-Letter-Template.docx — C.C8 destination-side template; the cover letter we emit is the CSP-side companion that *accompanies* the package, not the AO's ATO letter itself.
- **FedRAMP Initial Authorization Package Checklist** — https://www.fedramp.gov/assets/resources/templates/FedRAMP-Initial-Authorization-Package-Checklist.xlsx — C.C8 enumerates this checklist's items as the cover-letter's "package contents" table.
- **FedRAMP Incident Communications Procedures (CSP_Incident_Communications_Procedures.pdf)** — https://www.fedramp.gov/assets/resources/documents/CSP_Incident_Communications_Procedures.pdf — C.C3 communications-plan section + LOOP-G.G2 AFR-ICP reference.

### 3.2 NIST Special Publications

- **NIST SP 800-34 Rev. 1 (Updated 2010-11-11), Contingency Planning Guide for Federal Information Systems** — https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final and https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-34r1.pdf — C.C2 structure. NIST sample ISCP at https://csrc.nist.gov/CSRC/media/Publications/sp/800-34/rev-1/final/documents/sp800-34-rev1_cp_template_moderate_impact_system.docx (the Moderate-impact ISCP template). Quote (§3.1, page 17): *"The information system contingency planning process includes the following seven steps: 1) Develop the contingency planning policy; 2) Conduct the business impact analysis (BIA); 3) Identify preventive controls; 4) Create contingency strategies; 5) Develop an information system contingency plan; 6) Ensure plan testing, training, and exercises; 7) Ensure plan maintenance."*
- **NIST SP 800-61 Rev. 3 (2025-04, released 2025), Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile** — https://csrc.nist.gov/pubs/sp/800/61/r3/final and https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf — C.C3 structure (Rev. 2 was officially withdrawn April 2025). C.C3 lists Rev.3's Govern / Identify / Protect / Detect / Respond / Recover phases for the IR life-cycle table.
- **NIST SP 800-60 Vol. 1 Rev. 1 + Vol. 2 Rev. 1, Guide for Mapping Types of Information and Information Systems to Security Categories** — https://csrc.nist.gov/pubs/sp/800/60/v1/r1/final and https://csrc.nist.gov/pubs/sp/800/60/v2/r1/final — C.C5 information-type catalogue. (NIST is publishing Rev.2 IWD as of Jan 2024; until Rev.2 final, LOOP-C ships Rev.1 codes — operator can pin via config.)
- **NIST SP 800-128 + Update 1 (2019-10), Guide for Security-Focused Configuration Management of Information Systems** — https://csrc.nist.gov/pubs/sp/800/128/upd1/final and https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-128.pdf — C.C1 + C.C9 structure. NIST states (§3.3 + Appendix D): the CMP outline contains §1 Introduction, §2 Roles & Responsibilities, §3 SecCM Processes (Identification, Baseline, Change Control, Monitoring), §4 SecCM Tools, §5 SecCM Plan Maintenance. CM-2 baseline-configuration appendix is referenced; LOOP-C mirrors it.
- **NIST SP 800-137 (2011-09), Information Security Continuous Monitoring (ISCM) for Federal Information Systems and Organizations** — https://csrc.nist.gov/pubs/sp/800/137/final — C.C6 three-tier (Org / Mission / System) structure.
- **NIST SP 800-137A (2020-05), Assessing ISCM Programs** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-137A.pdf — C.C6 program-assessment table.
- **NIST SP 800-39 (2011-03), Managing Information Security Risk** — https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-39.pdf — C.C7 RMS three-tier risk hierarchy.
- **NIST SP 800-37 Rev. 2 (2018-12), Risk Management Framework for Information Systems and Organizations** — https://csrc.nist.gov/pubs/sp/800/37/r2/final — C.C7 + C.C8 (the authorization step references SP 800-37 Step 6).
- **NIST SP 800-53 Rev. 5 (Updated 2020-12), Security and Privacy Controls** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — every slice cites at least one Rev5 control as the satisfaction target.
- **NIST SP 800-53A Rev. 5 (2022-01), Assessing Security and Privacy Controls** — https://csrc.nist.gov/pubs/sp/800/53/a/r5/final — C.C6 assessment-method references.

### 3.3 FIPS publications

- **FIPS PUB 199 (2004-02), Standards for Security Categorization of Federal Information and Information Systems** — https://csrc.nist.gov/pubs/fips/199/final and https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf — C.C5 structure. Verbatim impact definitions:

  > **LOW** — "The loss of confidentiality, integrity, or availability could be expected to have a **limited** adverse effect on organizational operations, organizational assets, or individuals."
  >
  > **MODERATE** — "The loss of confidentiality, integrity, or availability could be expected to have a **serious** adverse effect on organizational operations, organizational assets, or individuals."
  >
  > **HIGH** — "The loss of confidentiality, integrity, or availability could be expected to have a **severe or catastrophic** adverse effect on organizational operations, organizational assets, or individuals."

  Security-category formula (FIPS 199 §3, page 3): `SC information_type = {(confidentiality, impact), (integrity, impact), (availability, impact)}` where each `impact` ∈ {LOW, MODERATE, HIGH, NOT APPLICABLE} (NOT APPLICABLE is permitted only for confidentiality).

  Loss definitions (FIPS 199 §3, page 2): *"A loss of confidentiality is the unauthorized disclosure of information. A loss of integrity is the unauthorized modification or destruction of information. A loss of availability is the disruption of access to or use of information or an information system."*

- **FIPS PUB 200 (2006-03), Minimum Security Requirements for Federal Information and Information Systems** — https://csrc.nist.gov/pubs/fips/200/final — C.C5 cites this as the bridge from FIPS 199 categorization to SP 800-53 control selection.

### 3.4 OSCAL references (for the cross-references this loop emits)

- **OSCAL 1.1.2 SSP model** — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/ — `system-characteristics.security-impact-level` is the field C.C5 worksheet cross-references.
- **OSCAL 1.1.2 POA&M model** — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/ — C.C6 ConMon Strategy references the POA&M metadata-revisions chain that LOOP-A.A1 emits.

---

## 4. Per-slice implementation specs

Each slice follows the **same disk + module pattern** established by SSP-2
(`core/ssp-docx.ts`) and LOOP-A.A5 (`core/roe-emit.ts`):

1. One pure renderer function returning `{ buffer: Buffer; stats: ... }`.
2. One disk-emitter wrapper that calls the renderer and writes to `outDir`.
3. The .docx is built via `zipStore` from `core/zip.ts` (no external `docx`
   package). The 5 OOXML parts (`[Content_Types].xml`, `_rels/.rels`,
   `word/document.xml`, `word/styles.xml`, `word/_rels/document.xml.rels`)
   are produced as strings.
4. The shared OOXML primitives (`para`, `heading`, `table`, `fieldTable`,
   `stylesXml`, `CONTENT_TYPES`, `ROOT_RELS`, `DOC_RELS`) are LIFTED into a
   shared helper module **before C.C1 ships**.

### Pre-slice — shared `core/docx-primitives.ts`

**Why this exists first:** today the OOXML primitives are duplicated between
`core/ssp-docx.ts` and `core/roe-emit.ts`. The REO standard prohibits placeholder
code, but duplication of 80-line blocks across 11 new emitters is a maintenance
disaster. Before C.C1 lands, extract the shared primitives.

**File to create:**
- `cloud-evidence/core/docx-primitives.ts` — exports `para(text, style?)`,
  `heading(text, level)`, `table(headers, rows, widths, opts?)`,
  `fieldTable(rows)`, `bulletList(items)`, `pageBreak()`,
  `stylesXml(extra?)`, `CONTENT_TYPES`, `ROOT_RELS`, `DOC_RELS`,
  `W_NS`, `TBD` (`= 'REQUIRES-OPERATOR-INPUT'`), `buildDocx(parts: string[], opts?)`.

**Files to extend:** `core/ssp-docx.ts` and `core/roe-emit.ts` — replace
local OOXML helpers with imports from `core/docx-primitives.ts`. Verify
existing SSP-2 + LOOP-A.A5 tests still pass byte-identical output (the .docx
content is unchanged; only the source modularization changes).

**Tests to add:** `tests/core/docx-primitives.test.ts` — 8 tests:
1. `para` produces a single `<w:p>` with run + escaped text.
2. `para` with style emits `<w:pPr><w:pStyle w:val="X"/></w:pPr>`.
3. `para` with newline emits `<w:br/>` between runs.
4. `heading(text, 1|2|3)` selects `Heading1/2/3`.
5. `table` builds `<w:tbl>` with grid + border + header-row shading.
6. `fieldTable` produces 2-column table without header row.
7. `bulletList` emits `<w:numPr>` references with numbering ID.
8. `xmlEscape` round-trips `<&>"'` correctly when fed into `para`.

**Estimated effort:** 0.5 day.

---

### Slice C.C1 — Configuration Management Plan (CMP)

**Why this slice:** CM-9 mandates the CSP develop and document a CMP that
addresses roles, responsibilities, and configuration-management processes
(NIST SP 800-128 §2.1). Without a CMP, the 3PAO has no document to sample
against during the CM-3 (Configuration Change Control) and CM-4 (Security
Impact Analyses) tests. The CMP also references the baseline-config artifact
C.C9 emits.

**Files to create** (exact paths, no abbreviation):
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/cmp-emit.ts` — pure
  renderer + disk emitter for `cmp.docx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/cmp-emit.test.ts`
  — 14 tests (see Test specifications below).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fixtures/cmp/inventory.sample.json`
  — fixture inventory.json with 6 components across 2 providers, used by
  tests; this fixture is under `tests/` so REO Rule 1.3 (no fixtures in
  production paths) is satisfied.

**Files to extend:**
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add to `Role` union: `'cmp-docx'`. Add to `WELL_KNOWN`:
  `{ role: 'cmp-docx', filename: 'cmp.docx', description: 'Configuration Management Plan (CM-9) — auto-filled from inventory + ksi-map; operator completes process narratives.' }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — add `args.cmp: boolean`, `--cmp` flag, `CLOUD_EVIDENCE_CMP` env, dispatch
  block calling `emitCmpDocx({ outDir, runId, frmrVersion, systemName, systemId,
  cspOrganization, impactLevel, approvalWorkflow, rollbackAuthority,
  changeWindowsDescription })`, console output naming bytes + component count
  + REQUIRES-OPERATOR-INPUT count.

**Schemas / standards:**
- NIST SP 800-128 §2.1 Role/Responsibilities (verbatim): *"The roles and responsibilities for SecCM should be clearly identified within the organization. These roles often include configuration control board, change initiator, change implementer, and change approver."* — used to size the §3 Roles table.
- NIST SP 800-128 Appendix D outline §1–§5 — drives the document's section structure.
- NIST SP 800-53 Rev5 CM-9 satisfaction language — quoted in cover paragraph.

**Build steps** (numbered, concrete):
1. Define interface `CmpEmitOptions` with: `outDir: string; outPath?: string; runId: string; frmrVersion: string; systemName?: string; systemId?: string; cspOrganization?: string; impactLevel: 'low'|'moderate'|'high'; approvalWorkflowNarrative?: string; rollbackAuthority?: string; changeWindowsDescription?: string; baselineConfigHref?: string; cmTooling?: Array<{ name: string; purpose: string }>`.
2. Define interface `CmpEmitResult` with: `path: string; bytes: number; component_count: number; ksi_count: number; ready_for_signature: boolean; requires_operator_input: string[]`.
3. Implement `function readInventoryComponents(outDir: string): Array<{ uniqueId: string; type: string; provider: string; location: string; assetType: string; }>` — same pattern as `roe-emit.ts:readInventoryIps`. Reads `out/inventory.json`. Group by `(provider, assetType)` for the §4 Configuration Items table.
4. Implement `function readKsiScope(): string[]` — REUSE the same grep-against-ksi-map.ts approach used in `roe-emit.ts:readKsiScope`. Used in §6 (Configuration Monitoring) to list controls under continuous monitoring.
5. Implement pure builder `function buildCmpBodyXml(opts: CmpEmitOptions): { xml: string; stats: Omit<CmpEmitResult, 'path'|'bytes'> }` producing the 11-section document:
   - §1 Document Information (title, version, last-modified, system identity).
   - §2 Purpose & Scope (quotes CM-9 + 800-128 §2.1).
   - §3 Roles & Responsibilities (4-row table: CCB Chair, Change Initiator, Change Implementer, Change Approver — operator must fill names/orgs).
   - §4 Configuration Items (auto-derived from inventory.json — one row per component group with count, type, provider, location).
   - §5 Baseline Configuration Reference (link to `baseline-config.docx` from C.C9; if `baselineConfigHref` not supplied, REQUIRES-OPERATOR-INPUT).
   - §6 Configuration Change Control Process (operator-supplied `approvalWorkflowNarrative`; if absent, REQUIRES-OPERATOR-INPUT with NIST SP 800-128 §3.2 quoted as the model).
   - §7 Configuration Monitoring (auto-list of KSI domains from ksi-map; cites the `out/inventory-coverage.json` per-run report).
   - §8 Change Windows (operator-supplied `changeWindowsDescription`).
   - §9 Rollback Authority (operator-supplied `rollbackAuthority`).
   - §10 Configuration Management Tooling (operator-supplied `cmTooling[]`; if none, surface CSP cloud-native services derived from inventory provider list — AWS Systems Manager, Azure Arc, GCP Config Connector — but mark them REQUIRES-OPERATOR-INPUT-VERIFY since the system can't confirm operator actually uses them).
   - §11 Plan Maintenance (annual review + on-change triggers per SP 800-128 §3.5).
6. Implement disk emitter `function emitCmpDocx(opts: CmpEmitOptions): CmpEmitResult` — call `buildCmpBodyXml`, wrap parts with shared `CONTENT_TYPES`/`ROOT_RELS`/`DOC_RELS` (now from `core/docx-primitives.ts`), zip via `zipStore`, write to `outPath ?? resolve(outDir, 'cmp.docx')`, `log.info({event: 'cmp.emitted', path, bytes, ...})`.
7. Wire into orchestrator (see Files to extend).
8. Add `cmp-docx` to `core/submission-bundle.ts` `WELL_KNOWN`.

**REQUIRES-OPERATOR-INPUT fields** (cannot be auto-derived):
- `systemName`, `systemId`, `cspOrganization`: CLI flags `--system-name`, `--system-id`, `--csp-name` already exist in orchestrator (used by SSP-1) — reuse.
- `approvalWorkflowNarrative`: CLI flag `--cmp-approval-narrative` or env `CLOUD_EVIDENCE_CMP_APPROVAL_NARRATIVE` or `config.yaml:cmp.approval_narrative`.
- `rollbackAuthority`: CLI flag `--cmp-rollback-authority` or env `CLOUD_EVIDENCE_CMP_ROLLBACK_AUTHORITY`.
- `changeWindowsDescription`: CLI flag `--cmp-change-windows` or env.
- `baselineConfigHref`: CLI flag `--cmp-baseline-config-href` (defaults to `./baseline-config.docx` IFF C.C9 was emitted in the same run — auto-link). The orchestrator dispatch order is C.C9 before C.C1.
- `cmTooling[]`: `config.yaml:cmp.tooling[]` (each entry `{name, purpose}`).
- CCB roster (§3): NOT in CLI; surfaced through `config.yaml:cmp.ccb_roster[]` or REQUIRES-OPERATOR-INPUT rows.

**Test specifications** (14 tests in `tests/core/cmp-emit.test.ts`):
1. `it('produces a valid .docx (round-trip through zip-store reader)')` — emit `cmp.docx`, read back via the same `zipStore`-compatible parser pattern existing in `tests/core/zip.test.ts`, assert `[Content_Types].xml` + 4 other parts present.
2. `it('emits 11 numbered sections in document.xml in order')` — grep document.xml body for `Heading1` paragraphs, assert sequence matches §1..§11 expected titles.
3. `it('auto-derives component groups from inventory.json')` — fixture inventory has 6 assets across 2 providers + 3 asset types; assert §4 table has 3 rows (one per (provider,assetType)) with correct counts.
4. `it('falls back to REQUIRES-OPERATOR-INPUT when inventory.json is missing')` — point `outDir` at a temp dir with no inventory; §4 emits a single row with TBD marker explaining the fix.
5. `it('emits REQUIRES-OPERATOR-INPUT for approvalWorkflowNarrative when omitted')` — assert `stats.requires_operator_input` contains `'approvalWorkflowNarrative'`; document body contains the literal `'REQUIRES-OPERATOR-INPUT'`.
6. `it('renders operator-supplied narrative verbatim')` — pass `approvalWorkflowNarrative: 'CCB convenes every Tuesday'`, assert document body contains the literal string.
7. `it('cross-links to C.C9 baseline-config.docx when both emitted')` — pass `baselineConfigHref: './baseline-config.docx'`; assert §5 contains the hyperlink target.
8. `it('reads ksi-map.ts for the §7 monitored-controls list')` — fixture verifies the KSI count matches the real ksi-map.ts pattern (>20 entries).
9. `it('marks cmTooling as REQUIRES-OPERATOR-INPUT-VERIFY when not operator-supplied but inferred')` — verify the verify-marker (distinct from plain REQUIRES-OPERATOR-INPUT) appears in the §10 row.
10. `it('uses deterministic UUID in metadata when same inputs given twice')` — call `emitCmpDocx` twice with identical opts; document.xml `<w:title>` metadata identical (achieved via deterministicUuid).
11. `it('writes to outPath when supplied')` — pass custom outPath, assert file at that path.
12. `it('logs structured event with bytes + component_count')` — spy on `log.info`, assert event fields.
13. `it('ready_for_signature = false when any operator field omitted')` — omit one field, assert false.
14. `it('ready_for_signature = true when every field supplied + inventory has ≥1 component')` — supply all, assert true + `requires_operator_input` is empty array.

**REO compliance checks specific to this slice:**
- Every Configuration Item row in §4 traces to a real asset in `inventory.json` — no synthetic component types.
- KSI list in §7 traces to real `core/ksi-map.ts` source — same trick `roe-emit.ts` uses.
- §3, §6, §8, §9, §10 default to REQUIRES-OPERATOR-INPUT when the operator hasn't supplied content. NO Lorem-Ipsum, no "TODO: insert approval workflow here", no sample data.
- Document provenance footer cites: `core/cmp-emit.ts`, inventory.json sha256, ksi-map.ts grep timestamp, runId.
- `cmp-emit.ts:emitCmpDocx` returns `stats` consumed by orchestrator console output; orchestrator passes the doc through manifest signing (same code path SSP-2 + RoE use).

**Verification commands:**
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/cmp-emit.test.ts
npm run check:reo
```

**Estimated effort:** 1.5 days (largest LOOP-C slice due to 11-section depth).

---

### Slice C.C2 — Information System Contingency Plan (ISCP) + Test AAR template

**Why this slice:** CP-2 mandates a documented contingency plan; CP-4 mandates
annual testing of that plan. The 3PAO samples both the plan AND the most-recent
test results. Today CSPs hand-author both from the FedRAMP SSP Appendix G
template — a multi-hour transcription job per assessment cycle.

**Files to create:**
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/iscp-emit.ts` — pure renderer + disk emitter for `iscp.docx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/iscp-test-aar.ts` — pure renderer + disk emitter for `iscp-test-aar.docx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/iscp-emit.test.ts` — 13 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/iscp-test-aar.test.ts` — 10 tests.

**Files to extend:**
- `core/submission-bundle.ts` — add roles `'iscp-docx'` (`iscp.docx`), `'iscp-test-aar-docx'` (`iscp-test-aar.docx`) to `Role` + `WELL_KNOWN`.
- `core/orchestrator.ts` — flags `--iscp`, `--iscp-test-aar`; envs `CLOUD_EVIDENCE_ISCP`, `CLOUD_EVIDENCE_ISCP_TEST_AAR`; dispatch blocks for both.

**Schemas / standards:**
- **FedRAMP SSP Appendix G — ISCP Template** — drives section structure. Sections we mirror: §1 Introduction & Scope, §2 Concept of Operations, §3 Activation & Notification, §4 Recovery, §5 Reconstitution, §6 Plan Maintenance, Appendix A Personnel Contact List, Appendix B Vendor Contacts, Appendix C Detailed Recovery Procedures, Appendix D Alternate Site Procedures, Appendix E System Validation Test Plan, Appendix F Contingency Plan Test Report.
- **NIST SP 800-34 Rev. 1 §3.1** verbatim seven-step process — quoted in §1.3 (Methodology).
- **NIST SP 800-53 Rev5 CP-2 + CP-4** — quoted at the head of the ISCP + AAR docs as the satisfaction targets.
- **NIST SP 800-34 Rev. 1 Appendix C Moderate-impact ISCP template** at https://csrc.nist.gov/CSRC/media/Publications/sp/800-34/rev-1/final/documents/sp800-34-rev1_cp_template_moderate_impact_system.docx — referenced as the upstream NIST equivalent.

**Build steps for `iscp-emit.ts`:**
1. Define interface `IscpEmitOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; impactLevel; rto?: { hours: number; rationale: string }; rpo?: { hours: number; rationale: string }; recoveryPriority?: 'mission-critical'|'mission-essential'|'standard'; alternateSite?: { type: 'hot'|'warm'|'cold'|'cloud'; location: string; activationProcedure: string }; activationAuthority?: string; activationCriteria?: string[]; cpCoordinator?: { name: string; org: string; email: string; phone: string }; teamRoster?: Array<{ role: string; name: string; org: string; email: string; phone: string; alternate?: string }>; vendorContacts?: Array<{ vendor: string; contact: string; role: string; phone: string; sla: string }>; backupStrategySummary?: string`.
2. Auto-fill backup-strategy summary from the existing RPL-* collector evidence files when present:
   - Read `outDir + '/KSI-RPL-ABO.signed.json'` for "Automated Backups Configured" evidence.
   - Read `outDir + '/KSI-RPL-TRC.signed.json'` for "Tested Recovery Capability".
   - Read `outDir + '/KSI-RPL-RRO.signed.json'` for "Recovery RPO/RTO Objectives".
   - Read `outDir + '/KSI-RPL-ARP.signed.json'` for "Alternate Recovery Processing".
   - Build a §4.2 table: KSI ID | passed | last-collected-at | evidence-citation.
3. Implement `function readRplEvidence(outDir: string): { abo?: KsiEvidence; trc?: KsiEvidence; rro?: KsiEvidence; arp?: KsiEvidence; }` — JSON-parse-safe reads, no throw on missing.
4. Implement pure builder `function buildIscpBodyXml(opts: IscpEmitOptions): { xml; stats }`. Sections:
   - §1 Introduction (1.1 Background, 1.2 Scope, 1.3 Methodology = the SP 800-34 7-step quote, 1.4 Assumptions).
   - §2 Concept of Operations (system description from `out/ssp.json` if present; component table from inventory).
   - §3 Activation & Notification Phase (activation criteria + roster + sequence-of-events flowchart-as-table).
   - §4 Recovery Phase (RPL-* evidence table + RTO/RPO commitments + recovery sequence).
   - §5 Reconstitution Phase (validation tests + return-to-normal-operations checklist).
   - §6 Plan Maintenance (annual review + on-change triggers).
   - Appendix A — Personnel Contact List (operator-supplied teamRoster + auto-flagged escalations).
   - Appendix B — Vendor / Subprocessor Contacts (auto-pull from existing `core/subprocessors-sheet.ts` output if present — `out/subprocessors.json`).
   - Appendix C — Detailed Recovery Procedures (REQUIRES-OPERATOR-INPUT; framework only).
   - Appendix D — Alternate Site Procedures (from `alternateSite` opts).
   - Appendix E — System Validation Test Plan (cross-references Appendix F).
   - Appendix F — Contingency Plan Test Report (cross-references `iscp-test-aar.docx`).
5. Implement `emitIscpDocx(opts) -> IscpEmitResult` — write `out/iscp.docx`.

**Build steps for `iscp-test-aar.ts`:**
1. Define `IscpTestAarOptions`: `outDir; outPath?; runId; testDate?: string; testType?: 'tabletop'|'functional'|'full-interruption'; participants?: Array<{ role; name; org }>; scenarios?: Array<{ id; description; rto_target_hours; rto_actual_hours; rpo_target_hours; rpo_actual_hours; outcome: 'pass'|'fail'|'partial' }>; lessonsLearned?: Array<{ id; finding; severity; recommendation; owner; due_date }>; testCoordinator?: string`.
2. Implement pure builder. Sections per FedRAMP Appendix G Appendix F structure:
   - §1 Test Overview (date, type, participants, scope).
   - §2 Scenarios Executed (one row per scenario with RTO/RPO target+actual+outcome).
   - §3 Test Results Summary (pass/fail/partial counts).
   - §4 Lessons Learned (one row per finding feeding POA&M).
   - §5 Recommendations & Action Items.
   - §6 Sign-off block (Test Coordinator, IT Director, System Owner, 3PAO Observer).
3. Auto-emit a REQUIRES-OPERATOR-INPUT row when no scenarios supplied: "Operator must populate scenarios[] before circulating for signature. AAR template generated <runId>."
4. When lessons-learned items have `severity ∈ {high, critical}`, emit a footer note that they should be filed as POA&M items via LOOP-A.A1's tracker.

**REQUIRES-OPERATOR-INPUT fields:**
- `rto`, `rpo`, `recoveryPriority`, `alternateSite`, `activationAuthority`,
  `activationCriteria`, `cpCoordinator`, `teamRoster`: CLI flags
  `--iscp-rto-hours`, `--iscp-rpo-hours`, etc.; preferred surface is
  `config.yaml:iscp.{rto, rpo, alternate_site, ...}`.
- For test AAR: CLI flag `--iscp-test-date`, `--iscp-test-type`; surfaces
  through tracker DB table `iscp_tests(id, test_date, test_type, ...)` once
  LOOP-E.E7 lands. Until then, operator passes via config.

**Test specifications** (ISCP — 13 tests):
1. `it('emits 6 sections + 6 appendices in order')`.
2. `it('auto-fills §4.2 backup-strategy table from RPL-ABO/TRC/RRO/ARP evidence')`.
3. `it('emits TBD when none of the RPL evidence files exist')`.
4. `it('renders RTO/RPO opts verbatim into §4.1')`.
5. `it('renders teamRoster Appendix A')`.
6. `it('auto-pulls vendor contacts from out/subprocessors.json when present')`.
7. `it('handles alternateSite.type="cloud" with cross-region detail')`.
8. `it('cross-references iscp-test-aar.docx in Appendix F')`.
9. `it('rejects unknown impactLevel (must be low|moderate|high)')`.
10. `it('ready_for_signature requires every required-for-signature field')`.
11. `it('produces deterministic output for same inputs')`.
12. `it('quotes NIST SP 800-34 §3.1 verbatim in §1.3')`.
13. `it('logs structured emission event')`.

**Test specifications** (Test AAR — 10 tests):
1. `it('produces 6-section AAR structure')`.
2. `it('scenarios table reflects RTO/RPO target vs actual')`.
3. `it('flags scenarios with outcome=fail in §3 summary')`.
4. `it('lessons-learned of severity=high gets POA&M footer note')`.
5. `it('TBD scenarios[] when not supplied')`.
6. `it('renders participants verbatim')`.
7. `it('signature block has 4 rows with TBD signature/date cells')`.
8. `it('rejects scenarios with negative RTO actual')`.
9. `it('writes to outPath when supplied')`.
10. `it('deterministic output for same inputs + frozen testDate')`.

**REO compliance checks:**
- §4.2 backup-strategy table: each row must trace to a real signed evidence
  file on disk. NO synthesized "backup is configured" rows.
- Test AAR scenarios MUST come from operator input — no fabricated test
  results.
- Vendor contacts in Appendix B trace to real `subprocessors.json` rows OR
  emit REQUIRES-OPERATOR-INPUT.

**Verification commands:**
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/iscp-emit.test.ts tests/core/iscp-test-aar.test.ts
npm run check:reo
```

**Estimated effort:** 2 days (two emitters with shared structural patterns).

---

### Slice C.C3 — Incident Response Plan (IRP) + Test AAR template

**Why this slice:** IR-8 mandates a documented incident-response plan; IR-3
mandates annual testing. The 3PAO requires both. NIST SP 800-61 Rev.3 (April
2025, current standard) restructured the IR life-cycle into the CSF 2.0
phases (Govern, Identify, Protect, Detect, Respond, Recover) — LOOP-C ships
the Rev.3 structure since Rev.2 was officially withdrawn.

**Files to create:**
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/irp-emit.ts` — `irp.docx` emitter.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/irp-test-aar.ts` — `irp-test-aar.docx` emitter.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/irp-emit.test.ts` — 13 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/irp-test-aar.test.ts` — 10 tests.

**Files to extend:**
- `core/submission-bundle.ts` — roles `'irp-docx'`, `'irp-test-aar-docx'`.
- `core/orchestrator.ts` — `--irp`, `--irp-test-aar` flags + envs.

**Schemas / standards:**
- **NIST SP 800-61 Rev. 3** — CSF 2.0 phase mapping. Quote (§2.1, page 5): *"This publication provides recommendations for managing incident response throughout the incident lifecycle, structured around the NIST Cybersecurity Framework (CSF) 2.0 Functions: Govern, Identify, Protect, Detect, Respond, and Recover."*
- **NIST SP 800-53 Rev5 IR-8 + IR-3 + IR-4 + IR-6** — control identifiers and assignment statements.
- **FedRAMP Incident Communications Procedures (CSP_Incident_Communications_Procedures.pdf)** — drives the §5 (Communications) section: required notification timelines to FedRAMP PMO + CISA + agency customers.

**Build steps for `irp-emit.ts`:**
1. Define `IrpEmitOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; impactLevel; irTeamRoster?: Array<{ role: 'IR Lead'|'IR Analyst'|'Forensics'|'Communications'|'Legal'|'Executive'; name; org; email; phone; on_call: boolean }>; escalationMatrix?: Array<{ severity: 'critical'|'high'|'medium'|'low'; sla_minutes: number; notify: string[] }>; externalContacts?: Array<{ entity: 'FedRAMP PMO'|'CISA'|'US-CERT'|'Agency POC'|'Law Enforcement'; contact: string; channel: 'email'|'phone'|'web-form'; sla_hours: number }>; communicationsPlan?: { internal: string; external: string; media: string }; classificationLevels?: Array<{ severity: string; definition: string; examples: string[] }>`.
2. Auto-fill the §4 Detection Sources table from the existing INR-RIR collector evidence (`out/KSI-INR-RIR.signed.json`) — each detection source becomes a row.
3. Implement pure builder. Sections:
   - §1 Introduction (purpose, scope, NIST SP 800-61r3 reference + CSF 2.0 phase quote).
   - §2 Roles & Responsibilities (irTeamRoster table; required roles: IR Lead, Analyst, Forensics, Comms, Legal, Exec Liaison).
   - §3 Incident Classification (severity definitions + examples; default rows from FedRAMP ICP doc).
   - §4 Detect (auto from INR-RIR; logging coverage table).
   - §5 Respond (per-CSF-phase procedures: Govern/Identify/Protect/Detect/Respond/Recover sub-sections).
   - §6 Communications Plan (internal + external + media).
   - §7 External Contacts (FedRAMP PMO, CISA, agency POC, etc. — populated from `externalContacts` opts).
   - §8 Escalation Matrix (severity → SLA-minutes → notify-list).
   - §9 Reporting Requirements (FedRAMP ICP-mandated 1-hour-to-PMO + 1-hour-to-customer-agency + 4-hour CISA US-CERT).
   - §10 Lessons Learned (post-incident review procedure).
   - §11 Plan Maintenance + Testing (annual cadence + cross-link to `irp-test-aar.docx`).
4. Implement `emitIrpDocx(opts) -> IrpEmitResult`.

**Build steps for `irp-test-aar.ts`:**
1. Define `IrpTestAarOptions`: `outDir; outPath?; runId; testDate?: string; testType?: 'tabletop'|'functional'|'red-team'; scenarios?: Array<{ id; description; severity; detection_time_minutes; response_time_minutes; containment_time_minutes; eradication_time_minutes; recovery_time_minutes; outcome: 'pass'|'fail'|'partial' }>; participants?: Array<{ role; name; org }>; lessonsLearned?: Array<{ id; phase: 'detect'|'respond'|'recover'|'lessons'; finding; severity; recommendation; owner; due_date }>; testCoordinator?: string`.
2. Pure builder (same shape as ISCP AAR but with IR-specific timing metrics).
3. AAR sections: Overview, Scenarios, Timing Metrics (5-phase elapsed-time table), Outcomes, Lessons Learned, Recommendations, Sign-off.

**REQUIRES-OPERATOR-INPUT fields:**
- `irTeamRoster`: `config.yaml:irp.team_roster[]`.
- `escalationMatrix`: `config.yaml:irp.escalation[]` or auto-default to FedRAMP ICP-compliant matrix with REQUIRES-OPERATOR-INPUT-VERIFY marker.
- `externalContacts`: `config.yaml:irp.external_contacts[]`.
- `communicationsPlan`: `config.yaml:irp.communications`.

**Test specifications** (IRP — 13 tests):
1. `it('emits 11 sections in CSF 2.0 phase order')`.
2. `it('auto-fills §4 detection-sources from INR-RIR evidence')`.
3. `it('emits TBD when no INR-RIR evidence')`.
4. `it('renders irTeamRoster with on_call flag visible')`.
5. `it('emits FedRAMP ICP-mandated SLAs in §9 even when escalationMatrix not supplied')`.
6. `it('quotes NIST SP 800-61r3 CSF 2.0 phase definition verbatim')`.
7. `it('escalationMatrix sorts by severity descending')`.
8. `it('externalContacts groups CISA + FedRAMP PMO + Agency POC')`.
9. `it('writes outPath when supplied')`.
10. `it('deterministic output')`.
11. `it('logs structured emit event')`.
12. `it('ready_for_signature = false when irTeamRoster empty')`.
13. `it('classificationLevels override defaults when supplied')`.

**Test specifications** (IRP AAR — 10 tests): analogous to ISCP AAR but with the 5-phase timing table being the central assertion.

**REO compliance checks:**
- Detection sources in §4 trace to real INR-RIR evidence or REQUIRES-OPERATOR-INPUT.
- External-contact SLA rows trace to FedRAMP ICP doc verbatim — cite URL in document footer.
- AAR scenarios: no fabricated timing data; operator-supplied OR REQUIRES-OPERATOR-INPUT row.

**Verification commands:**
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/irp-emit.test.ts tests/core/irp-test-aar.test.ts
npm run check:reo
```

**Estimated effort:** 2 days.

---

### Slice C.C4 — Privacy Threshold Analysis (PTA) + Privacy Impact Assessment (PIA)

**Why this slice:** PT-2 (Authority to Process), PT-3 (Personally Identifiable
Information Processing Purposes), and PT-6 (System of Records Notice) require
a documented PTA. If PII is processed (positive PTA), a PIA is also required.
The FedRAMP help-desk article 28907995813275 confirms FedRAMP has no Rev5
PTA/PIA template; the LOOP-C emitter ships the Rev4 PIA structure with Rev5
PT-family control identifiers wrapped over it.

**Files to create:**
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pta-pia-emit.ts` — both renderers + emitters in one module (PTA always emitted; PIA conditionally emitted based on PTA determination).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pta-pia-emit.test.ts` — 14 tests.

**Files to extend:**
- `core/submission-bundle.ts` — roles `'pta-docx'`, `'pia-docx'`.
- `core/orchestrator.ts` — `--pta-pia` flag + env.
- `core/inventory-emit.ts` — extend asset metadata with `data_classification`
  enum value `'pii'` if not already present (verify in source — likely
  present per INV-S2/S3 enrichers).

**Schemas / standards:**
- **FedRAMP SSP A04 PIA Template (Rev4)** — section structure (PTA decision form + PIA per-question expansion).
- **NIST SP 800-53 Rev5 PT-2, PT-3, PT-6** — control identifiers in document headers.
- **OMB Memorandum M-03-22 (E-Government Act §208)** — referenced as the policy origin (the FedRAMP template itself cites this).
- **NIST Privacy Framework v1.0 (2020-01)** — referenced for the Govern/Identify/Protect/Communicate/Respond crosswalk.

**Build steps:**
1. Define `PtaPiaEmitOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; impactLevel; piaForceMode?: 'auto'|'always-emit'|'never-emit'; ptaResponses?: { collectsPII: boolean; identifiableData: boolean; sharingWithExternalEntities: boolean; persistentUserIdentifiers: boolean; reusedForSecondaryPurposes: boolean; }; piaResponses?: { authorityToCollect: string; purposesOfCollection: string[]; categoriesOfPII: string[]; sourcesOfPII: string[]; sharing: Array<{ recipient: string; purpose: string; mechanism: string }>; consentMechanism: string; accessAndCorrection: string; retentionPeriod: string; disposalMethod: string; safeguards: string[]; }`.
2. Auto-derive PTA-Q1 (`collectsPII`) from inventory:
   - Walk `out/inventory.json` for assets with `data_classification === 'pii'` or `data_classification === 'phi'`.
   - If ≥1 such asset, default `ptaResponses.collectsPII = true` and note in document body which assets triggered the determination.
   - If 0 such assets, default `collectsPII = false` and note "no PII-tagged assets in inventory at run time — operator confirms".
3. PTA determination rule: PIA emitted IFF (any of Q1-Q5 = true) OR (`piaForceMode === 'always-emit'`). Otherwise only PTA emitted with "no PIA required" determination.
4. Implement pure builders:
   - `buildPtaBodyXml(opts) -> { xml, stats, requiresPIA }`. Sections: §1 System Overview, §2 PTA Determination (5-question form), §3 PII Inventory Evidence (auto-derived from inventory), §4 Determination + Signature.
   - `buildPiaBodyXml(opts) -> { xml, stats }`. Sections: §1 Authority + Purpose (PT-2), §2 PII Categories + Sources (PT-3), §3 Sharing + Use (PT-3), §4 Notice & Consent (PT-6 SORN reference), §5 Access & Correction, §6 Retention & Disposal, §7 Safeguards & Compensating Controls, §8 Privacy Risk Assessment, §9 Signature.
5. `emitPtaPiaDocx(opts) -> PtaPiaEmitResult` writes `pta.docx` always; writes `pia.docx` iff `requiresPIA === true`.

**REQUIRES-OPERATOR-INPUT fields:**
- `ptaResponses`: when omitted entirely, default to `collectsPII` inferred from inventory + all other booleans REQUIRES-OPERATOR-INPUT.
- `piaResponses`: when PIA is required and `piaResponses` omitted, every section emits REQUIRES-OPERATOR-INPUT placeholder rows with the FedRAMP A04 template prompts verbatim.
- Surfaces: `--pta-pia` flag triggers emission; per-question values come from `config.yaml:privacy.{pta, pia}` or tracker `privacy_responses` table (future LOOP-E enhancement).

**Test specifications** (14 tests):
1. `it('emits PTA only when no PII detected and operator did not force PIA')`.
2. `it('emits both PTA + PIA when inventory has PII-tagged assets')`.
3. `it('emits both when piaForceMode = "always-emit"')`.
4. `it('emits PTA only when piaForceMode = "never-emit" even if PII present (with warning note)')`.
5. `it('PTA §3 lists which assets triggered the PII determination')`.
6. `it('PIA §2 categories of PII default to REQUIRES-OPERATOR-INPUT')`.
7. `it('PIA §6 retention period verbatim from opts')`.
8. `it('quotes Rev5 PT-2 + PT-3 + PT-6 control IDs in §1 header')`.
9. `it('cross-references SSP system-name and system-id')`.
10. `it('document footer cites FedRAMP A04 template URL')`.
11. `it('writes to outPath dir when supplied')`.
12. `it('deterministic output')`.
13. `it('ready_for_signature requires every PTA + (if applicable) every PIA field')`.
14. `it('handles inventory.json missing gracefully — emit PTA with TBD §3')`.

**REO compliance checks:**
- PTA §3 PII-evidence table traces to real `inventory.json` `data_classification` tags. NO substituted values.
- PIA §2 categories empty when not operator-supplied — never invent "name, email, SSN" as a default.
- Document footer cites: FedRAMP A04 URL + inventory.json sha256 + runId + emitter module path.

**Verification commands:**
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/pta-pia-emit.test.ts
npm run check:reo
```

**Estimated effort:** 1.5 days.

---

### Slice C.C5 — FIPS 199 categorization worksheet

**Why this slice:** RA-2 (Security Categorization) requires the system owner
to categorize the information system per FIPS 199 + SP 800-60. The
categorization drives baseline selection per FIPS 200 (and therefore the
entire control catalogue). The SSP carries the *result* in
`system-characteristics.security-impact-level`; FIPS 199 is the *worksheet*
that shows the work. 3PAOs cross-check the worksheet against the SSP value.

**Files to create:**
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/fips199-emit.ts` — pure renderer + disk emitter for `fips199.docx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/fips199-types.ts` — typed constants: information-type catalogue from SP 800-60 V2 Rev. 1 (subset most likely to apply to a SaaS CSP — D.1.x Information Dissemination, D.2.x System Development, D.3.x General Government, D.4.x Information Sharing, C.2.x Service Delivery Support). NOTE per REO Rule 3 (allowed exceptions): NIST-published information-type codes + names are allowed fixed data; cite SP 800-60 V2 §C and §D explicitly in the module header.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/fips199-emit.test.ts` — 12 tests.

**Files to extend:**
- `core/submission-bundle.ts` — role `'fips199-docx'`.
- `core/orchestrator.ts` — `--fips199` flag + env.

**Schemas / standards:**
- **FIPS PUB 199 §3** — impact-level definitions (LOW/MOD/HIGH), SC formula, Information Type definitions. All quoted verbatim in document body §1.2.
- **NIST SP 800-60 V1 Rev. 1 §3.1** — information identification process. Quoted in §2 Methodology.
- **NIST SP 800-60 V2 Rev. 1 Appendix C + D** — information-type catalogue. `fips199-types.ts` exports the subset SaaS-relevant codes.
- **FedRAMP Rev4 SSP-A10 template** — section ordering (Information Types table → Overall Categorization → Rationale → Signature).

**Build steps:**
1. Define `Fips199EmitOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; informationTypes?: Array<{ code: string; name: string; confidentiality: 'low'|'moderate'|'high'|'n/a'; integrity: 'low'|'moderate'|'high'; availability: 'low'|'moderate'|'high'; rationale: string }>; overallConfidentialityRationale?: string; overallIntegrityRationale?: string; overallAvailabilityRationale?: string; categorizationApprover?: { name; role; org; date }`.
2. Implement helper `function computeOverallSC(types: InformationType[]): { c: Impact; i: Impact; a: Impact }` — high-water-mark per FIPS 199 §3.1 ("System Security Category = HIGH-WATER-MARK of all Information Type Security Categories"). Pure function, exported for unit testing.
3. Implement pure builder. Sections:
   - Title page (system identity + FIPS 199 logo header).
   - §1 Introduction (1.1 Purpose, 1.2 FIPS 199 Impact Definitions — verbatim quotes from FIPS 199 §3).
   - §2 Methodology (cite SP 800-60 V1 §3.1).
   - §3 Information Types Identified (one row per informationType opt, with SP 800-60 code + name + C/I/A + rationale).
   - §4 System Security Categorization (overall SC computed via `computeOverallSC`, displayed as `SC = {(C, X), (I, Y), (A, Z)}` formatted per FIPS 199 §3 formula).
   - §5 Categorization Rationale (per-objective rationale from operator).
   - §6 Approval Signatures (Categorization Approver + System Owner).
4. Auto-fallback: if `informationTypes` omitted, emit a single TBD row with the SP 800-60 V2 selection guidance quoted verbatim — operator pulls from `fips199-types.ts` exported catalogue.
5. Cross-reference: if `out/ssp.json` exists, read `system-characteristics.security-impact-level` and emit a §4.1 sanity-check note ("SSP claims `<level>`; this worksheet computes `<level>`; CONSISTENT/MISMATCH").
6. Implement `emitFips199Docx(opts) -> Fips199EmitResult`.

**REQUIRES-OPERATOR-INPUT fields:**
- `informationTypes[]`: `config.yaml:fips199.information_types[]` or CLI repeat flag `--fips199-info-type "C.2.5.1:Service Delivery Management:moderate:moderate:low:rationale text"` (colon-separated, repeatable). Operator MUST select from SP 800-60 V2 catalogue — types not in `fips199-types.ts` produce an `UNKNOWN-TYPE-CODE` warning logged.
- `overall*Rationale`: `config.yaml:fips199.{c,i,a}_rationale`.
- `categorizationApprover`: `config.yaml:fips199.approver`.

**Test specifications** (12 tests):
1. `it('emits 6 sections in order with FIPS 199 §3 verbatim quotes')`.
2. `it('computeOverallSC takes the high-water-mark across all info types')`.
3. `it('computeOverallSC handles c=n/a per FIPS 199 (only for confidentiality)')`.
4. `it('SC formula displays as {(confidentiality, MODERATE), (integrity, LOW), (availability, LOW)} when computed')`.
5. `it('emits TBD row + SP 800-60 V2 selection note when no information types supplied')`.
6. `it('flags MISMATCH when SSP security-impact-level disagrees with worksheet overall SC')`.
7. `it('flags CONSISTENT when SSP matches')`.
8. `it('rejects information type with C+I+A all "n/a" (invalid per FIPS 199 — integrity + availability must always have a level)')`.
9. `it('rejects unknown impact level value')`.
10. `it('writes to outPath when supplied')`.
11. `it('deterministic output')`.
12. `it('ready_for_signature requires ≥1 info type + 3 rationales + approver')`.

**REO compliance checks:**
- SC overall computation traces to real `computeOverallSC()` invocation over operator-supplied types — NO hardcoded "moderate/moderate/moderate" default.
- SSP cross-reference cites real `ssp.json` value via sha256 + path in document footer.
- Impact-level definition quotes are verbatim from FIPS 199 §3 — cite URL + page in module-header JSDoc.
- SP 800-60 V2 codes in `fips199-types.ts` are NIST-published constants per REO Rule 3 (allowed exception).

**Verification commands:**
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/fips199-emit.test.ts
npm run check:reo
```

**Estimated effort:** 1.5 days (FIPS 199-types catalog extraction is the main work).

---

### Slice C.C6 — Continuous Monitoring Strategy + Plan

**Why this slice:** CA-7 mandates a continuous-monitoring program. FedRAMP
requires a written ConMon Strategy + Plan that describes WHICH controls are
under continuous monitoring, at WHAT frequency, with WHAT escalation. The
Strategy is the umbrella; the Plan is the executable cadence. LOOP-E (ConMon
agent) consumes this document as the configuration for monthly runs.

**Files to create:**
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/conmon-strategy-emit.ts` — `conmon-strategy.docx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/conmon-strategy-emit.test.ts` — 13 tests.

**Files to extend:**
- `core/submission-bundle.ts` — role `'conmon-strategy-docx'`.
- `core/orchestrator.ts` — `--conmon-strategy` flag + env.

**Schemas / standards:**
- **FedRAMP Continuous Monitoring Strategy Guide v3.2** — primary structure source. §3 (Performance Management) drives the document's §5.
- **FedRAMP ConMon Playbook v1.0 (2025-11)** — current cadence language (monthly POA&M + monthly inventory + monthly scan + annual SSP + 3-year reauth). Quoted verbatim in §3.
- **NIST SP 800-137 §3** — three-tier hierarchy (Organization/Mission/System) — drives §2 structure.
- **NIST SP 800-137A §2** — assessment-method classifications — drives §6.
- **NIST SP 800-53 Rev5 CA-7 + CA-7(1) + PM-31** — control identifiers.
- **RFC-0026** — deviation request process — drives §8.

**Build steps:**
1. Define `ConmonStrategyOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; impactLevel; conmonTeamRoster?: Array<{ role: 'ConMon Lead'|'POA&M Coordinator'|'Scan Operator'|'Risk Reviewer'; name; org; email }>; escalationThresholds?: Array<{ trigger: string; sla: string; notify: string[] }>; deviationRequestProcess?: string; reportingEndpoint?: 'usda-connect.gov'|'agency-direct'|'other'; agencyCustomers?: Array<{ agency: string; ato_letter_date: string }>; collaborativeConmon?: boolean`.
2. Auto-fill from real evidence:
   - §4 Controls Under Continuous Monitoring: derived from `core/ksi-map.ts` (one row per KSI — id, family, frequency, evidence-type).
   - §5 Scan Cadence: derived from `out/KSI-VDR-*.signed.json` evidence files (real scanner output). Each row cites the scanner + last-collected-at + frequency.
   - §6 POA&M Cadence: cites LOOP-A.A1 monthly re-emission semantics + R2 finding ("monthly full-document re-upload to USDA Connect.gov for Low/Moderate").
   - §7 Inventory Cadence: cites monthly INV-S1 coverage report.
3. Implement pure builder. Sections:
   - §1 Introduction (CA-7 + 800-137 cite).
   - §2 Three-Tier Strategy (Org/Mission/System per SP 800-137 §3).
   - §3 FedRAMP Cadence (verbatim playbook quote on monthly cadence).
   - §4 Controls Under Continuous Monitoring (KSI table from ksi-map).
   - §5 Vulnerability Scanning (VDR evidence summary).
   - §6 POA&M Management (cite LOOP-A.A1).
   - §7 Inventory Management (cite INV-S1).
   - §8 Deviation Requests (RFC-0026 + operator-supplied process).
   - §9 Reporting Endpoint (USDA Connect.gov for Low/Mod per R2; agency-direct otherwise).
   - §10 ConMon Team Roster.
   - §11 Escalation Thresholds.
   - §12 Collaborative ConMon (when `collaborativeConmon === true`, cite RFC-0026 collaborative-monitoring language).
   - §13 Plan Maintenance.
4. Implement `emitConmonStrategyDocx(opts) -> ConmonStrategyResult`.

**REQUIRES-OPERATOR-INPUT fields:**
- `conmonTeamRoster`: `config.yaml:conmon.team[]`.
- `escalationThresholds`: `config.yaml:conmon.escalation[]`. Defaults to FedRAMP-baseline (KEV: 21d, Critical: 30d, etc.) with REQUIRES-OPERATOR-INPUT-VERIFY marker.
- `deviationRequestProcess`: narrative; defaults to RFC-0026-citation REQUIRES-OPERATOR-INPUT-VERIFY.
- `agencyCustomers`: `config.yaml:conmon.agency_customers[]`. If empty, §12 defaults `collaborativeConmon=false`.

**Test specifications** (13 tests):
1. `it('emits 13 sections in order')`.
2. `it('§4 KSI table has ≥20 rows from real ksi-map.ts')`.
3. `it('§5 scan-cadence row per VDR-* evidence file found')`.
4. `it('TBD when no VDR evidence found')`.
5. `it('§3 quotes ConMon Playbook v1.0 cadence verbatim')`.
6. `it('§9 endpoint = USDA Connect.gov for Low/Moderate')`.
7. `it('§9 endpoint = agency-direct for High')`.
8. `it('§12 enables collaborative ConMon when >1 agency customer + flag set')`.
9. `it('escalation defaults to FedRAMP-baseline values with verify marker')`.
10. `it('writes to outPath when supplied')`.
11. `it('deterministic output for same inputs')`.
12. `it('ready_for_signature requires team + escalation + deviation process')`.
13. `it('cites RFC-0026 in §8 and §12')`.

**REO compliance checks:**
- §4 KSI list traces to `core/ksi-map.ts` source (grep approach).
- §5 scanner rows trace to real evidence files on disk.
- No invented deviation-request workflow; defaults to RFC-0026-citation only.
- Cadence quotes from ConMon Playbook v1.0 are verbatim with URL cited.

**Verification commands:**
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/conmon-strategy-emit.test.ts
npm run check:reo
```

**Estimated effort:** 1.5 days.

---

### Slice C.C7 — Risk Management Strategy (RMS)

**Why this slice:** PM-9 mandates an organization-level Risk Management
Strategy. NIST SP 800-39 + SP 800-37 Rev2 define the three-tier risk
hierarchy (Organization → Mission/Business Process → Information System).
The RMS sits above the per-finding POA&M and the per-system SSP.

**Files to create:**
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/rms-emit.ts` — `rms.docx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/rms-emit.test.ts` — 12 tests.

**Files to extend:**
- `core/submission-bundle.ts` — role `'rms-docx'`.
- `core/orchestrator.ts` — `--rms` flag + env.

**Schemas / standards:**
- **NIST SP 800-39 §2** — Risk-management process verbatim: *"The risk management process involves four components: (i) framing risk; (ii) assessing risk; (iii) responding to risk; (iv) monitoring risk."* Each becomes a section.
- **NIST SP 800-37 Rev. 2 §3** — RMF steps that the RMS supervises.
- **NIST SP 800-53 Rev5 PM-9 + PM-8 + RA-1 + RA-3** — control identifiers.

**Build steps:**
1. Define `RmsEmitOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; impactLevel; riskTolerance?: { confidentiality: 'low'|'moderate'|'high'; integrity: 'low'|'moderate'|'high'; availability: 'low'|'moderate'|'high' }; executiveOversight?: Array<{ role: string; name: string; org: string }>; riskRegisterHref?: string; riskAcceptancePolicyHref?: string`.
2. Auto-fill from LOOP-B output when present:
   - `out/risk-register.json` (B.B5) → §5.
   - `out/risk-acceptances.json` (B.B3) → §6.
   - `out/compensating-controls.json` (B.B4) → §6.
   - When absent: REQUIRES-OPERATOR-INPUT marker + cross-link to "Generate via LOOP-B".
3. Auto-fill POA&M summary from `out/poam.json` (LOOP-A.A1):
   - count by severity, count overdue, oldest open finding.
4. Implement pure builder. Sections:
   - §1 Introduction (PM-9 + 800-39 quote).
   - §2 Risk Framing (organizational context: SaaS CSP, FedRAMP impact level, agency customer count).
   - §3 Risk Assessment Methodology (cite RA-3 + 800-30).
   - §4 Risk Response Strategy (Accept / Avoid / Mitigate / Transfer matrix).
   - §5 Risk Register Reference (link or REQUIRES-OPERATOR-INPUT).
   - §6 Risk Acceptance Policy (B.B3 + B.B4 if available).
   - §7 Continuous Risk Monitoring (cite C.C6 ConMon Strategy).
   - §8 Risk Tolerance (operator-supplied levels per CIA).
   - §9 Executive Oversight + Governance (operator-supplied).
   - §10 POA&M Summary (auto from poam.json).
   - §11 Plan Maintenance.
5. Implement `emitRmsDocx(opts) -> RmsResult`.

**REQUIRES-OPERATOR-INPUT fields:**
- `riskTolerance`: `config.yaml:rms.tolerance`.
- `executiveOversight`: `config.yaml:rms.executive_oversight[]`.
- `riskRegisterHref`: defaults to `./risk-register.json` IFF that file exists; else REQUIRES-OPERATOR-INPUT.
- `riskAcceptancePolicyHref`: similar.

**Test specifications** (12 tests):
1. `it('emits 11 sections')`.
2. `it('quotes SP 800-39 §2 four-component process verbatim')`.
3. `it('§5 risk register link present when risk-register.json exists')`.
4. `it('§5 REQUIRES-OPERATOR-INPUT when risk-register.json absent')`.
5. `it('§10 POA&M summary counts by severity from poam.json')`.
6. `it('§10 TBD when poam.json absent')`.
7. `it('§8 renders riskTolerance verbatim')`.
8. `it('§9 renders executiveOversight roster')`.
9. `it('§4 risk-response matrix is 4-row hard-coded standard table')`.
10. `it('writes to outPath when supplied')`.
11. `it('deterministic output')`.
12. `it('ready_for_signature requires tolerance + executive + register link + acceptance policy')`.

**REO compliance checks:**
- §10 POA&M counts trace to real `out/poam.json`.
- §5/§6 links trace to real LOOP-B output files; never fabricated.
- §4 matrix uses NIST SP 800-39 terminology — verbatim.

**Verification commands:**
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/rms-emit.test.ts
npm run check:reo
```

**Estimated effort:** 1 day.

---

### Slice C.C8 — Authorization request cover letter / package transmittal

**Why this slice:** PM-10 (Authorization Process). The CSP-side cover letter
that accompanies the authorization package transmitted to the FedRAMP PMO
(or agency AO) — distinct from the AO's ATO letter (which the FedRAMP ATO
Letter Template covers). The cover letter formally requests review,
enumerates package contents (sourced from `INDEX.json` emitted by LOOP-A.A4),
identifies the 3PAO, and lists key contacts.

**Files to create:**
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/auth-cover-letter-emit.ts` — `auth-request-cover-letter.docx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/auth-cover-letter-emit.test.ts` — 11 tests.

**Files to extend:**
- `core/submission-bundle.ts` — role `'auth-cover-letter-docx'`. NOTE: the cover letter is emitted AFTER the bundle's INDEX.json is built, so the dispatch order is INDEX-build → cover-letter-emit → bundle-pack-into-tar. Existing bundler reads from `outDir` — verify the file lands before tarball write.
- `core/orchestrator.ts` — `--auth-cover-letter` flag + env.

**Schemas / standards:**
- **FedRAMP Agency Authorization Playbook v4.1 §3** — formal request structure (CSP letterhead + AO addressee + requested action + package summary + signatures).
- **FedRAMP Initial Authorization Package Checklist** — enumerates package contents; the cover letter's "Package Contents" table mirrors the checklist plus actual sha256 from `INDEX.json`.
- **FedRAMP ATO Letter Template** — the counterpart document the AO returns; cover-letter §5 references the expected ATO response format.
- **NIST SP 800-53 Rev5 PM-10** — control id.

**Build steps:**
1. Define `AuthCoverLetterOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; cspOrganization?; cspAddress?: string; cspExecutiveSignatory?: { name; title; email; phone }; thirdPartyAssessor?: string; thirdPartyAssessorLead?: { name; title; email }; aoAddressee?: { name; title; agency; address }; requestedAtoType?: 'initial-ato'|'continued-ato'|'reauthorization'; impactLevel; submissionDate?: string`.
2. Auto-read `out/INDEX.json` (LOOP-A.A4) — enumerate every artifact with role + sha256 + bytes. Render as the "Package Contents" table in §4.
3. Implement pure builder. Sections:
   - Letterhead block (CSP org + address).
   - Date line (operator-supplied submissionDate OR runId-derived ISO date).
   - Addressee block (AO name + agency + address — REQUIRES-OPERATOR-INPUT when absent).
   - §1 Subject Line ("FedRAMP Moderate Authorization Request — `<systemName>`").
   - §2 Request Summary (`requestedAtoType` + system identity + impact level).
   - §3 3PAO Statement (named 3PAO + lead assessor + summary of assessment dates from `out/ap.json` if present).
   - §4 Package Contents (auto-table from INDEX.json: artifact filename + role + sha256-short + bytes).
   - §5 Requested Action (e.g., "We respectfully request your authorization decision within FedRAMP-baseline review timeline").
   - §6 Primary Contacts (CSP exec signatory + technical lead + 3PAO).
   - §7 Closing + Signature (CSP exec signatory signature line).
4. Implement `emitAuthCoverLetterDocx(opts) -> AuthCoverLetterResult`.

**REQUIRES-OPERATOR-INPUT fields:**
- `cspExecutiveSignatory`: `config.yaml:auth_request.executive_signatory`.
- `cspAddress`: `config.yaml:org.address`.
- `aoAddressee`: `config.yaml:auth_request.ao_addressee` (per-target agency).
- `thirdPartyAssessor` + `thirdPartyAssessorLead`: `config.yaml:auth_request.tpa` — also reuses `--third-party-assessor` flag if present.
- `requestedAtoType`: CLI flag `--auth-request-type initial-ato` (default).

**Test specifications** (11 tests):
1. `it('emits 7 sections + letterhead + addressee')`.
2. `it('§4 Package Contents reflects INDEX.json artifacts')`.
3. `it('§4 TBD with note when INDEX.json absent')`.
4. `it('§3 3PAO statement reads from out/ap.json metadata when present')`.
5. `it('§2 requestedAtoType reflects opts')`.
6. `it('addressee REQUIRES-OPERATOR-INPUT when aoAddressee omitted')`.
7. `it('cspExecutiveSignatory REQUIRES-OPERATOR-INPUT when omitted')`.
8. `it('subject line includes systemName + impactLevel')`.
9. `it('writes to outPath when supplied')`.
10. `it('deterministic output for same INDEX.json + opts')`.
11. `it('ready_for_signature requires signatory + addressee + tpa + addressee + atoType')`.

**REO compliance checks:**
- §4 Package Contents traces to real `INDEX.json` rows. NO synthetic artifacts.
- Sha256-short values are real (first 12 hex chars of full sha256).
- 3PAO statement traces to `ap.json` metadata when present.

**Verification commands:**
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/auth-cover-letter-emit.test.ts
npm run check:reo
```

**Estimated effort:** 1 day.

---

### Slice C.C9 — Baseline Configuration document (CM-2)

**Why this slice:** CM-2 mandates a documented baseline configuration for
every information system. In Rev5 this is distinct from CM-8 (inventory):
inventory is "what assets exist"; baseline is "what configuration each
asset is approved to run". 3PAO samples both. AFR-SCG (LOOP-G.G5) covers
the recommended-secure-configuration side; this slice covers the baseline-
of-record.

**Files to create:**
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/baseline-config-emit.ts` — `baseline-config.docx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/baseline-config-emit.test.ts` — 13 tests.

**Files to extend:**
- `core/submission-bundle.ts` — role `'baseline-config-docx'`.
- `core/orchestrator.ts` — `--baseline-config` flag + env.
- (No extension to AFR-SCG — that slice independently consumes the same `reference-arch.ts` source.)

**Schemas / standards:**
- **NIST SP 800-128 §3.2 (Establishing the Baseline)** — drives the document structure.
- **NIST SP 800-53 Rev5 CM-2 + CM-2(2) + CM-2(7)** — control identifiers and assignment statements.
- **CIS Benchmarks** — referenced as the upstream standard reference architectures pull from (not copied verbatim — REO Rule 3 doesn't extend to CIS).

**Build steps:**
1. Define `BaselineConfigOptions`: `outDir; outPath?; runId; frmrVersion; systemName?; systemId?; impactLevel; baselineApprover?: { name; role; org; date }; deviationLogLocation?: string; baselineReviewCadence?: 'monthly'|'quarterly'|'annually'; configurationItemsOverride?: Array<{ component: string; baseline: string; deviations: string[] }>`.
2. Auto-derive baseline rows from THREE sources:
   - **Real inventory** (`out/inventory.json`): each asset's current `image`, `osVersion`, `instanceType`, etc.
   - **Reference architecture** (`providers/aws/reference-arch.ts`, `providers/gcp/reference-arch.ts`, `providers/azure/reference-arch.ts`): each provider's documented "expected baseline" entries.
   - **AFR-SCG comparator** (`core/scg-comparator.ts` existing module): deviation summary between inventory and reference-arch.
3. Implement `function readReferenceArchitecturesAllProviders(): Array<{ provider; component; baselineImage; baselineConfig; controls: string[] }>` — same grep-against-source technique as `roe-emit.ts:readKsiScope` to avoid pulling SDK clients at emit time.
4. Implement `function readInventoryBaselineRows(outDir): Array<{ uniqueId; provider; component; currentImage; currentConfig }>`.
5. Implement `function diffInventoryVsReference(inv, ref): Array<{ component; baseline; current; deviation }>` — pure.
6. Implement pure builder. Sections:
   - §1 Introduction (CM-2 + 800-128 §3.2 cite).
   - §2 Methodology (cite `reference-arch.ts` provenance + SCG-comparator).
   - §3 Baseline Configuration Items (one row per (provider, component-type) group — current count + baseline image + baseline config summary).
   - §4 Reference Architecture (auto from `providers/<cloud>/reference-arch.ts`).
   - §5 Deviations from Baseline (auto from SCG-comparator output).
   - §6 Baseline Maintenance (review cadence + on-change triggers).
   - §7 Deviation Approval Process (cross-link to C.C1 CMP §6 Change Control).
   - §8 Approval Signatures (`baselineApprover`).
7. Implement `emitBaselineConfigDocx(opts) -> BaselineConfigResult`.

**REQUIRES-OPERATOR-INPUT fields:**
- `baselineApprover`: `config.yaml:baseline_config.approver`.
- `deviationLogLocation`: `config.yaml:baseline_config.deviation_log` (URL or path to operator's deviation tracking system).
- `baselineReviewCadence`: defaults to `annually` per CM-2 baseline; operator can tighten.
- `configurationItemsOverride`: rarely used; operators can override the auto-derivation when reference-arch is incomplete.

**Test specifications** (13 tests):
1. `it('emits 8 sections')`.
2. `it('§3 component-group rows derived from inventory.json')`.
3. `it('§4 reference architecture rows derived from providers/*/reference-arch.ts source greps')`.
4. `it('§5 deviation rows from diffInventoryVsReference')`.
5. `it('TBD when inventory.json absent')`.
6. `it('TBD when no reference-arch.ts files readable')`.
7. `it('§7 cross-links to cmp.docx when present')`.
8. `it('renders baselineApprover signature block')`.
9. `it('quotes SP 800-128 §3.2 verbatim in §1')`.
10. `it('handles multi-cloud (AWS+GCP+Azure) reference-arch parsing')`.
11. `it('writes to outPath when supplied')`.
12. `it('deterministic output')`.
13. `it('ready_for_signature requires approver + deviation-log + cadence')`.

**REO compliance checks:**
- §3, §4, §5 trace to real inventory + reference-arch + SCG-comparator output.
- NO fabricated baseline values; if reference-arch.ts has no entry for a component, document says so explicitly.
- Document footer cites sha256 of every source file read.

**Verification commands:**
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/baseline-config-emit.test.ts
npm run check:reo
```

**Estimated effort:** 1.5 days.

---

## 5. Loop-wide acceptance criteria

LOOP-C is **complete** when ALL of the following are true:

1. **Files exist on disk** (all paths absolute):
   - `cloud-evidence/core/docx-primitives.ts` (pre-slice).
   - `cloud-evidence/core/cmp-emit.ts` (C.C1).
   - `cloud-evidence/core/iscp-emit.ts` + `cloud-evidence/core/iscp-test-aar.ts` (C.C2).
   - `cloud-evidence/core/irp-emit.ts` + `cloud-evidence/core/irp-test-aar.ts` (C.C3).
   - `cloud-evidence/core/pta-pia-emit.ts` (C.C4).
   - `cloud-evidence/core/fips199-emit.ts` + `cloud-evidence/core/fips199-types.ts` (C.C5).
   - `cloud-evidence/core/conmon-strategy-emit.ts` (C.C6).
   - `cloud-evidence/core/rms-emit.ts` (C.C7).
   - `cloud-evidence/core/auth-cover-letter-emit.ts` (C.C8).
   - `cloud-evidence/core/baseline-config-emit.ts` (C.C9).
   - All corresponding `tests/core/<name>-emit.test.ts` files.
2. **Orchestrator wiring complete**: 9 new CLI flags (`--cmp`, `--iscp`, `--iscp-test-aar`, `--irp`, `--irp-test-aar`, `--pta-pia`, `--fips199`, `--conmon-strategy`, `--rms`, `--auth-cover-letter`, `--baseline-config` — 11 flags total counting AARs and dual-doc PTA/PIA flag) + matching `CLOUD_EVIDENCE_*` envs + console-output blocks + run-ledger entries.
3. **Submission bundler catalogue extended**: 11 new `WellKnownArtifact` entries (one per LOOP-C `.docx`).
4. **Tests passing**: at least 130 new tests (8 pre-slice + 14 C.C1 + 13 C.C2-ISCP + 10 C.C2-AAR + 13 C.C3-IRP + 10 C.C3-AAR + 14 C.C4 + 12 C.C5 + 13 C.C6 + 12 C.C7 + 11 C.C8 + 13 C.C9 = ~133 new tests). Existing test count (874) plus LOOP-B count if landed first must rise accordingly.
5. **REO checks green**: `npm run check:reo` returns 0 — no new stub-lint hits, no coverage regressions, every new emit field has a `provenance` entry or `coverage_source` row.
6. **Typecheck clean**: `npm run typecheck` returns 0.
7. **Orchestrator end-to-end run** in a fresh outDir produces 11 new `.docx` files + matching `INDEX.json` rows + the bundle tarball includes them.
8. **CHANGELOG.md "Unreleased" section** has 9 entries (one per slice) naming the modules + verification counts.
9. **`cloud-evidence/docs/STATUS.md`** has every C.Cx row marked `done`.
10. **Section 7 status table in THIS FILE** updated with commit hashes and dates.

---

## 6. Open questions / caveats

1. **Rev5 PTA/PIA template doesn't exist.** Per FedRAMP help-desk article
   28907995813275 (verified June 2026): "There are no current plans to provide
   a Rev. 5 PTA/PIA template for CSPs to complete." C.C4 ships the Rev4
   structure with Rev5 PT-family identifiers. If FedRAMP publishes a Rev5
   PTA/PIA template mid-LOOP, C.C4 must re-target.
2. **SP 800-60 Rev. 2 is in draft (IWD as of 2024-01).** C.C5 ships Rev. 1
   information-type catalogue in `fips199-types.ts`. When Rev. 2 finalizes,
   the catalogue file must be re-extracted. The module-header documents
   this with a `// SOURCE-VERSION: SP 800-60 V2 Rev. 1` constant for easy
   later bump.
3. **NIST SP 800-61 Rev. 3 (April 2025) replaces Rev. 2.** C.C3 IRP ships
   Rev. 3 CSF 2.0 phase structure. Some 3PAOs may still reference Rev. 2's
   four-phase model (Preparation / Detection-Analysis / Containment-
   Eradication-Recovery / Post-Incident); the emitter could optionally
   support a `--irp-spec-version=800-61r2|800-61r3` flag if pushback
   materializes. Default is r3.
4. **CMP `.docx` template choice**: FedRAMP does NOT publish a CMP template
   (search confirmed June 2026 — "FedRAMP does not provide a template for
   the Configuration Management Plan"). C.C1 follows NIST SP 800-128
   Appendix D outline instead. The 3PAO may flag the absence of a FedRAMP-
   specific template; document this in the cover letter's caveats.
5. **C.C7 RMS without LOOP-B**: if C.C7 is implemented BEFORE B.B3/B.B4/B.B5,
   the §5/§6/§10 sections degrade to REQUIRES-OPERATOR-INPUT for risk
   register data. This is acceptable per REO Rule 4 — operators MUST not
   see an emitted RMS with synthesized risk scores. Operators are warned
   in orchestrator console output ("--rms emitted but LOOP-B risk register
   not present; RMS sections 5/6/10 require operator completion").
6. **Multi-CSO handling (LOOP-H.H3 prerequisite)**: every emitter accepts
   `systemId` + `systemName`; when LOOP-H lands, the orchestrator's per-CSO
   loop will call each emitter once per `--cso` value, writing into
   `out/<cso-id>/`. C.C* emitters need NO changes for multi-CSO when
   LOOP-H ships, because they accept `outDir` as an option.
7. **Page-break + headers/footers**: current OOXML primitives (in `roe-emit.ts`
   and `ssp-docx.ts`) don't emit headers/footers. LOOP-C documents would
   benefit from a footer with `page X of Y + system name`. Decision: scope
   this OUT of LOOP-C; add a follow-up slice (LOOP-C.C10?) only if 3PAO
   feedback demands it. Compatible with REO since absence of header/footer
   is not a fabrication.
8. **Hyperlinks in OOXML**: cross-references (e.g., CMP § cross-link to
   baseline-config.docx) currently emit as text references, not active
   hyperlinks. Active hyperlinks need additional `_rels/document.xml.rels`
   relationships. Decision: emit BOTH the visible text AND a hyperlink
   `r:id` reference; the shared primitives module gets a `hyperlink(href,
   text)` helper.

---

## 7. Status tracking

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| Pre | Shared `core/docx-primitives.ts` | deferred | — | — (see LOOP-C-RISKS C-C1-6 / C-X-1 — C.C1 shipped with local OOXML constants per the four shipped docx-emitter precedent) |
| C.C1 | Configuration Management Plan (CMP) | done | `99c283a` | 2026-07-07 |
| C.C2 | ISCP + Test AAR | done | `e660109` | 2026-07-07 |
| C.C3 | IRP + Test AAR | done | `f521fe3` | 2026-07-07 |
| C.C4 | PTA + PIA (conditional) | done | `ed26d8d` | 2026-07-07 |
| C.C5 | FIPS 199 categorization worksheet | done | `bbfdaad` | 2026-07-07 |
| C.C6 | ConMon Strategy + Plan | done | `TBDCOMMIT` | 2026-07-07 |
| C.C7 | Risk Management Strategy (RMS) | pending | — | — |
| C.C8 | Authorization request cover letter | pending | — | — |
| C.C9 | Baseline Configuration | pending | — | — |

---

## 8. Slice completion procedure (REO-enforced)

When a LOOP-C slice ships, the implementer (human or Claude session) MUST
execute these steps in order, ALL six:

1. **Verify locally** — run, in this exact order, from `cloud-evidence/`:
   ```bash
   cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
   npm run typecheck                              # must return 0
   npm test                                       # must return 0; total test count rises by the slice's test count
   npm run check:reo                              # G1 + G2 + G3 all green
   ```
   If ANY of these fail, the slice is NOT done. Per REO Rule 2 ("A slice is
   done only when ALL of [the 7 done criteria]"), partial completion is not
   a state — fix and re-verify.

2. **Update Section 7 status table** in this file: set `Status = done`,
   `Commit hash = <short-hash>` (after step 5 runs), `Completed date = <ISO YYYY-MM-DD>`.

3. **Add CHANGELOG.md "Unreleased" entry** — pattern (mirror existing LOOP-A entries):
   ```markdown
   ### Added — LOOP-C.<slice-id>: <slice title>
   <2-3 sentence summary>
     - `cloud-evidence/core/<module>.ts`: <line count>, <pattern reuse note>, <REO compliance note>
     - `cloud-evidence/core/orchestrator.ts`: new `--<flag>` flag + `CLOUD_EVIDENCE_<ENV>` env.
     - `cloud-evidence/core/submission-bundle.ts`: added `<role>` role + `<filename>` filename to well-known catalogue.
     - `tests/core/<module>.test.ts`: N tests covering <list>.

   Verification: typecheck clean; <total>/<total> tests passing (+N from
   LOOP-C.<slice-id>); `npm run check:reo` returns 0.
   ```

4. **Update `cloud-evidence/docs/STATUS.md`** — set the slice's row status to `done`.

5. **Commit with the canonical message format** (HEREDOC) — pattern:
   ```bash
   git add -A   # only when no .env or credentials are in the diff; verify with git status first
   git commit -m "$(cat <<'EOF'
   LOOP-C.<slice-id>: <slice title>

   <2-3 line body matching CHANGELOG entry>

   Verification:
   - typecheck: clean
   - tests: <total>/<total> passing (+N new)
   - check:reo: green
   EOF
   )"
   ```

6. **Push to origin/main**:
   ```bash
   git push origin main
   ```
   Then capture the short hash for Section 7. If pre-push hooks fail
   (lint, REO, tests), the commit object is already made; fix issues and
   create a NEW commit (never amend per repo rules) — the bad commit stays
   in local history as a record of the failure.

**Important per REO + repo rules:**
- NEVER `--amend`, NEVER `--no-verify`, NEVER `--force` push.
- NEVER skip step 1; the typecheck-test-reo trifecta is the load-bearing
  guarantee that the slice meets the Real Slice Contract (REO §Rule 2).
- If step 1 fails after the implementation looks "done", the slice scope
  was wrong — split it, not stub it (REO Rule 1.2).

---

*End of LOOP-C-SPEC.md. Read top-to-bottom before starting any slice.
Each slice is independently executable; pre-slice docx-primitives runs first;
ordering of C.C1..C.C9 among themselves is independent except C.C1 cross-
links to C.C9 (orchestrator dispatch order: C.C9 before C.C1 so the cross-
link resolves).*
