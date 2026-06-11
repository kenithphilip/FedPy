---
slice_id: E.E1
title: Monthly ConMon Analysis Report
loop: E
status: done
commit: ddfa499
completed_date: 2026-06-11
depends_on: [A.A1, A.A4]
blocks: [E.E2, E.E3, G.G6]
estimated_effort: 5 days
last_updated: 2026-06-11
---

# E.E1 — Monthly ConMon Analysis Report

## TL;DR
Ships the monthly ConMon analysis report (`out/conmon-monthly-<YYYY-MM>.{json,md,pdf}`) — the human-readable executive summary that the agency POC expects to see attached to the monthly USDA Connect.gov upload alongside the POA&M + inventory + scan files. Closes the largest gap between LOOP-A's authorization-time package and the recurring monthly cadence FedRAMP mandates.

## Status
- Status: done
- Commit: ddfa499 (recorded in the follow-up `docs(E.E1)` commit per the repo's two-commit hash close-out convention)
- Date: 2026-06-11
- Verification: typecheck=clean, tests=1050 passing (+25: 10 conmon-pdf + 15 conmon-report), check:reo=green (G1 0 violations / G2 skip-no-out / G3 OK)

## Why this slice exists
The codebase emits POA&M (A.A1), inventory (INV-S1..S6), AR (existing) and IIW (INV-P*) as monthly-relevant artifacts — but nothing aggregates them into the **monthly analysis** that FedRAMP's ConMon Playbook v1.0 (2025-11-17) §"Monthly Deliverables" enumerates as required-with-the-upload. Without this slice the operator hand-assembles the report in Word every month, which (a) misses real numbers (POA&M items past deadline, KEV exposure count, scan-coverage %), (b) drifts month-over-month, and (c) introduces transcription errors in a regulator-facing document.

Closes the gap referenced in `docs/PRE-LOOP-A-RESEARCH-FINDINGS.md` R2 (monthly POA&M format) by adding the **report** that wraps the monthly POA&M re-emission.

NIST SP 800-137 §3 ("Process Step 4 — Analyze and Step 5 — Respond") explicitly calls for the analysis to be communicated to organizational decision-makers in a standardized form. This report is that form.

Maps to: FedRAMP Rev5 Playbook §ConMon Overview ("Each month, the CSP uploads ... reports to the secure repository"); NIST 800-53 Rev5 CA-7 (a)(b)(g) ("Establish an organization-wide ConMon program ... report security and privacy posture of [the system] to [Authorizing Official]"); NIST 800-137 §3.4 ("Analyze Data and Report Findings").

## Authoritative sources (with verbatim quotes)
- <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/> — FedRAMP Rev5 Playbook §ConMon Overview:
  > "Each month, the CSP uploads an up-to-date POA&M and inventory, along with raw vulnerability scan files (when required by agreements with agency customers) and reports to the secure repository."
  > "CSPs with cloud offerings categorized at LI-SaaS, Low, or Moderate use the FedRAMP secure repository on USDA Connect.gov for posting ConMon deliverables. CSPs with cloud offerings categorized at High use their own secure repository."

- <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/> — FedRAMP Rev5 Playbook §Vulnerability Scanning:
  > "FedRAMP vulnerability scanning guidelines require at least monthly scans of 100% of inventory components."
  > "The scan output must display all scan findings with a low risk or higher in a structured, machine-readable format (such as XML, CSV, or JSON)."
  > "FedRAMP recommends that externally accessible (outside of the boundary, without the use of a VPN) system components do not use this sampling methodology; 100% of externally accessible system components should be scanned."

- <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-137.pdf> — NIST SP 800-137 §3.4 (page 28):
  > "The ISCM process generates the data needed to make risk-based decisions. Reports communicate the security status of the information system in support of organizational risk management decisions, and the implementation of organization-defined response actions."
  > "Reports of information system security status are based on the analysis of ISCM data and provide situational awareness in support of the response phase."

- <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf> — NIST SP 800-53 Rev5 control CA-7 (page 99):
  > "Develop a system-level continuous monitoring strategy and implement continuous monitoring in accordance with the organization-level continuous monitoring strategy that includes: ... [g.] Reporting the security and privacy status of the system to [Assignment: organization-defined personnel or roles] [Assignment: organization-defined frequency]."

- <https://www.fedramp.gov/resources/documents/Continuous_Monitoring_Playbook.pdf> — FedRAMP ConMon Playbook v1.0 (2025-11-17), pinned at `docs/fedramp-conmon-playbook.generated.json`:
  > "Critical/High findings: 30 days; Moderate findings: 90 days; Low findings: 180 days. Any vulnerability not fixed within 192 days becomes an 'accepted vulnerability'."
  > "Internet-reachable resources more often – at least every three days for both authenticated and unauthenticated assessments. Non-internet-reachable resources need weekly checks at minimum."

- <https://elevateconsult.com/insights/fedramp-conmon-deliverables-essential-evidence-requirements-guide-2026/> — ConMon Evidence Guide 2026 (synthesis):
  > "All submissions occur on the same day each month to the secure repository."

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/conmon-report.ts` — pure builder + disk emitter, ~500 LOC.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/conmon-pdf.ts` — minimal pure-JS PDF 1.4 generator (header, page, font, text, line, table), ~400 LOC. Reused by E.E3 and E.E7.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/fetch-conmon-playbook.mjs` — human-run fetcher that pins URL + sha256 + content excerpts into `docs/fedramp-conmon-playbook.generated.json`. Same pattern as `scripts/extract-frmr-requirements.mjs`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/fedramp-conmon-playbook.generated.json` — pinned playbook projection (output of the fetcher; committed to repo).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/conmon-report.test.ts` — ~13 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/conmon-pdf.test.ts` — ~10 PDF primitive tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add three roles to `WELL_KNOWN`:
  - `'conmon-monthly-report-json'` (regex `/^conmon-monthly-\d{4}-\d{2}\.json$/`, required=false)
  - `'conmon-monthly-report-md'` (regex `/^conmon-monthly-\d{4}-\d{2}\.md$/`, required=false)
  - `'conmon-monthly-report-pdf'` (regex `/^conmon-monthly-\d{4}-\d{2}\.pdf$/`, required=false)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — add `--conmon-monthly`, `--month <YYYY-MM>`, `--fedramp-package-id`, `--csp-name`, `--conmon-strategy-href`, `--sampling-pct` flags + matching `CLOUD_EVIDENCE_*` envs. Run AFTER POA&M / VDR / inventory but BEFORE signing so the report is in the manifest.

## Schemas / standards
**Output JSON shape** (every field has a real source):

```ts
export interface ConmonMonthlyReport {
  run_id: string;
  report_month: string;       // "YYYY-MM" — operator-supplied or current
  generated_at: string;       // ISO
  system: { name?: string; id?: string; impactLevel: 'low'|'moderate'|'high'; csp?: string; fedrampId?: string };
  posture: {
    ksi_pass_rate: number;
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
  provenance: { emitter: 'core/conmon-report.ts'; tool: string; frmrVersion: string; conmonPlaybookVersion: string; sourceCalls: string[]; warnings?: string[] };
}
```

**PDF spec**: PDF 1.4 ASCII subset per ISO 32000-1:2008. Single page object → resources → Helvetica `/F1`. Stream content: BT/ET text blocks + lines (`l`) for table borders. Header `%PDF-1.4`; trailer with `xref`, `trailer`, `startxref`, `%%EOF`. Test asserts magic bytes + EOF marker.

**Source files read** (the only inputs):
- `out/poam.json` (OSCAL POA&M v1.1.2 — A.A1).
- `out/KSI-*.json` envelopes (existing schema in `core/envelope.ts`).
- `out/vdr-ledger.json` (existing VDR scan output).
- `out/inventory.json` (INV-P1).
- `out/inventory-coverage.json` (INV-S1).
- `out/diff-report.json` (existing `core/diff-report.ts`).
- `out/scn-classification.json` (existing `core/scn-classifier.ts`).
- `docs/fedramp-conmon-playbook.generated.json` (pinned playbook reference).
- `docs/cisa-kev.generated.json` (existing KEV catalog).

## Build steps (concrete, numbered)
1. **Pin the ConMon Playbook reference**. Author `scripts/fetch-conmon-playbook.mjs` that resolves the URL, sha256-pins the PDF, and writes `docs/fedramp-conmon-playbook.generated.json` with:
   `{remediation_table: {critical: 30, high: 30, moderate: 90, low: 180, accepted_threshold_days: 192}, scan_cadence: {monthly_inventory: 1.0, internet_reachable_days: 3, internal_days: 7}, monthly_deliverables: [...], playbook_version: "1.0", playbook_published: "2025-11-17", fetched_at: <ISO>, sha256: <hash>}`.
2. **Define types** in `core/conmon-report.ts` per the JSON shape above. Export `ConmonMonthlyReport`, `ConmonReportBuildOpts`, `ConmonReportEmitOpts`.
3. **Pure builder** `buildConmonMonthlyReport(opts: ConmonReportBuildOpts): ConmonMonthlyReport`. Inputs are already-loaded snapshots (POA&M doc, KSI envelopes, VDR ledger, inventory, diff-report, SCN classification, playbook pin, CISA KEV pin). Deterministic — same inputs → byte-identical JSON output.
4. **Disk emitter** `emitConmonMonthlyReport(opts: ConmonReportEmitOpts): {jsonPath, mdPath, pdfPath}` reads from `outDir`, builds the report, writes `.json` (`JSON.stringify` w/ `provenance` block), `.md` (template render), and `.pdf` (via `core/conmon-pdf.ts`).
5. **PDF generator** in `core/conmon-pdf.ts`. Single function `renderPdf(sections: PdfSection[]): Buffer` where `PdfSection = { kind: 'heading' | 'paragraph' | 'table'; ... }`. Uses only Node `Buffer` + `zlib` for FlateDecode streams. No `pdfkit`, no `pdfmake`.
6. **Markdown renderer**: simple template that emits 9 numbered sections (header, posture snapshot, vulnerability scan coverage, POA&M activity, deviation requests, SCN events, incident summary, annual cycle progress, provenance). Each section's data comes from the JSON object.
7. **Orchestrator wiring**. Add `--conmon-monthly`, `--month <YYYY-MM>`, `--fedramp-package-id`, `--csp-name`, `--conmon-strategy-href`, `--sampling-pct`. Run AFTER POA&M / VDR / inventory but BEFORE signing. Pass through env mirroring (`CLOUD_EVIDENCE_CONMON_MONTHLY`, etc.).
8. **submission-bundle catalogue**: add three rows so monthly bundles classify the report correctly. Filenames are timestamped (`YYYY-MM`) so multi-month archives don't collide.
9. **Manifest scope**: confirm `core/sign.ts` already includes `*.json` + `*.md` + `*.pdf` in the signed set — if not, extend.
10. **CISA KEV exposure count**: walk `out/poam.json` items, cross-reference each finding's `cve_id` with `docs/cisa-kev.generated.json`. Number of unique CVEs that appear in both is `kev_exposure_count`.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 (CLAUDE.md §"Operator-supplied data is real data"), every field that cannot be auto-derived MUST emit the literal string `REQUIRES-OPERATOR-INPUT` rather than a default that looks real.

- **`system.fedrampId`** — Source: CLI `--fedramp-package-id` / env `CLOUD_EVIDENCE_FEDRAMP_PACKAGE_ID`. Why: FedRAMP-assigned IDs (e.g. `F1809051234`) are issued by the FedRAMP PMO; not derivable from any cloud SDK. Missing → marker emitted in `system.fedrampId` and surfaced in `provenance.warnings`.
- **`system.csp`** — Source: CLI `--csp-name` / env `CLOUD_EVIDENCE_CSP_NAME`. Why: the CSP's legal corporate name. Missing → marker.
- **`incident_summary`** — Source: tracker `incidents` table (LOOP-G.G2 will ship). Until then: literal `'REQUIRES-OPERATOR-INPUT'` in JSON; operator-fillable bulleted list in the `.md`. Never fabricate "0 incidents" silently.
- **`annual_cycle.ssp_last_reviewed`** — Source: tracker `ssp_reviews` table (E.E4 will ship). Until E.E4: marker. CLI override: `--ssp-last-reviewed <ISO date>`.
- **`conmon_strategy_href`** — Source: CLI `--conmon-strategy-href` / env `CLOUD_EVIDENCE_CONMON_STRATEGY_HREF`. Why: C.C6 will emit the ConMon Strategy doc; until then, the operator points at an existing one. Missing → marker.
- **`scan_coverage.sampling_pct`** — Source: CLI `--sampling-pct 100` / env `CLOUD_EVIDENCE_SAMPLING_PCT`. Default = `100` (the FedRAMP MUST). LOOP-F.F3 will auto-derive per-class.
- **`assessor_name`** (only when `--scn` is co-active) — Source: CLI `--3pao-name`. Missing → marker.

Sentinel constant: reuse `TBD = 'REQUIRES-OPERATOR-INPUT'` from `core/roe-emit.ts` (or export from a shared `core/markers.ts` if not already).

## Test specifications (≥12 tests)
1. `it('builds a posture snapshot from KSI envelopes')` — feeds 3 KSI envelopes (1 pass, 2 fail mixed severity); asserts `posture.ksi_pass_rate === 1/3`, `posture.open_poam_count === 2`, `posture.open_by_severity.high === 1`.
2. `it('aggregates POA&M activity month-over-month from diff-report')` — feeds `diff-report.json` with 2 new + 1 closed; asserts `poam_activity.opened === 2`, `poam_activity.closed === 1`.
3. `it('computes scan_coverage from inventory.json and ksi-map')` — feeds inventory of 20 assets; asserts `scan_coverage.assets_total === 20`.
4. `it('flags internet_reachable_compliant=false when any internet-reachable asset is missing from scan list')`.
5. `it('emits REQUIRES-OPERATOR-INPUT for incident_summary when tracker integration absent')`.
6. `it('emits REQUIRES-OPERATOR-INPUT for system.fedrampId when --fedramp-package-id missing')`.
7. `it('writes JSON + MD + PDF files with the expected names conmon-monthly-2026-07.{json,md,pdf}')`.
8. `it('PDF starts with %PDF-1.4 magic bytes and ends with %%EOF')`.
9. `it('PDF contains the system name + report month rendered as text in a content stream')`.
10. `it('JSON output carries a provenance block naming this emitter (core/conmon-report.ts)')`.
11. `it('throws when --month is malformed (not YYYY-MM)')` — asserts typed `InvalidMonthFormatError`.
12. `it('uses pinned playbook version from docs/fedramp-conmon-playbook.generated.json')` — asserts `provenance.conmonPlaybookVersion === pinned.playbook_version`.
13. `it('is deterministic — same inputs produce byte-identical JSON')`.

Additional PDF tests in `conmon-pdf.test.ts` (~10):
14. `it('PDF xref offsets resolve correctly')` — parse and validate every offset in the xref table.
15. `it('PDF stream lengths match /Length entries')`.
16. `it('PDF wraps prose at the right column position')`.
17. `it('PDF renders a 3-column table with borders')`.
18. `it('PDF handles XML/PDF special chars in user text (parens, backslashes)')`.
19. `it('PDF is deterministic on same input')`.
20. `it('PDF emits one Page per logical page')`.
21. `it('PDF page count grows with content')`.
22. `it('PDF FlateDecode round-trips')`.
23. `it('PDF Catalog → Pages → Page chain resolves')`.

## REO compliance specific to this slice
- Every counted POA&M item traces to a real `poam.json` item-uuid.
- Every scan-coverage number traces to a real `inventory.json` asset id.
- KEV exposure count cites the committed `docs/cisa-kev.generated.json` catalog version in `provenance.sourceCalls`.
- Playbook reference comes from a committed JSON projection (real fetched-and-pinned PDF), not a hard-coded string in source.
- No fabricated deadlines: when `conmon-playbook.generated.json` is stale (sha256 mismatch on re-fetch), the report carries `provenance.warnings: ["conmon-playbook-stale"]`.
- `incident_summary` REQUIRES-OPERATOR-INPUT is the literal sentinel; no "TODO" or "TBD" tokens.
- `signed by`: existing `core/sign.ts` pipeline (Ed25519 + RFC 3161) — the conmon-monthly files are emitted into `outDir` BEFORE signing, so the manifest covers them.
- `coverage_source` registered in `core/inventory-coverage.ts` only if the report introduces new emit-fields that need provenance (the existing `provenance` block already satisfies G3).

## Verification commands
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/conmon-report.test.ts tests/core/conmon-pdf.test.ts
npm run check:reo
```

## Known risks / issues
- **Risk 1: PDF generator complexity.** The pure-JS PDF 1.4 writer is the largest chunk (~2 days). PDF readers tolerate broken xref tables silently; tests must validate parse-and-render, not just byte presence. Mitigation: keep the spec subset minimal (single font, monospaced metrics for tables, no images), add a round-trip test using a real PDF parser (`pdf-parse` in devDeps OK; production has no dep).
- **Risk 2: Playbook drift.** FedRAMP may publish v1.1 / v2.0 of the ConMon Playbook between slice ship and a future regulator review. Mitigation: the pinned JSON includes `sha256` + `playbook_published`; `scripts/fetch-conmon-playbook.mjs` is human-run quarterly, and the report `provenance.conmonPlaybookVersion` surfaces what was used.
- **Risk 3: Source-file presence assumptions.** `poam.json` / `vdr-ledger.json` / `inventory.json` may not all exist on a fresh first-month run. Mitigation: builder accepts `null` for any source and degrades gracefully (zero counts + a `provenance.warnings` entry naming the missing input).
- **Risk 4: Time-zone ambiguity in `report_month`.** "July 2026" in UTC vs Pacific. Mitigation: always interpret `--month YYYY-MM` as UTC, document in the flag help text, and surface in `generated_at` (full ISO with `Z`).
- **Risk 5: KEV exposure double-count.** A CVE that appears in 3 POA&M items would inflate exposure count. Mitigation: dedupe by `cve_id` using a `Set`, then count cardinality.

## Open questions (for implementation session to resolve)
- **Q1**: Does the FedRAMP PMO require the monthly report in PDF specifically, or is `.md` (Pandoc-convertible) acceptable? LOOP-E-SPEC §6 caveat 1 leaves this open; recommend shipping PDF since uploads to USDA Connect.gov are commonly PDF. If `.md` only is acceptable, drop `conmon-pdf.ts` and cut the slice to 3 days.
- **Q2**: Should `scan_coverage.by_class` keys be the canonical FedRAMP asset classes ("Hardware", "Operating System", "Web", "Database", "Application", "Container", "Mobile", "Networking", "Cloud Service") from FedRAMP IIW Column J, or our internal `core/inventory-emit.ts` asset-type names? Recommend Column J names for cross-artifact consistency.
- **Q3**: Where should `out/archive/<YYYY-MM>/` live — alongside `out/conmon-monthly-<YYYY-MM>.*` or in a sibling directory? E.E2 creates the archive; this slice reads from it. Recommend `out/archive/<YYYY-MM>/` for both.
- **Q4**: Should `provenance.warnings` be promoted to a non-zero exit code under `--strict-conmon`? Aligns with `--strict-bundle` / `--strict-chain` patterns from LOOP-A.A4 / A.A3.
- **Q5**: For the PDF, should we use a single Helvetica or include Courier for code/table cells? Helvetica metrics aren't fixed-width; tables look better in Courier. Recommend Helvetica for headings, Courier for tables.
- **Q6**: How do we surface a `--dry-run` mode that emits the JSON but skips PDF/MD (faster CI runs)?

## Implementation log (running journal — implementing session updates)
```
2026-06-11 | impl-e-e1 | Shipped end to end per spec.
  Created:
    - scripts/fetch-conmon-playbook.mjs (human-run pin) + docs/fedramp-conmon-playbook.generated.json
      (REAL fetched PDF: 909,986 bytes, sha256 d96379ec…; remediation table + scan cadence +
       monthly deliverables + version 1.0 / 2025-11-17 are FedRAMP-published constants per REO Rule 3).
    - core/conmon-pdf.ts — dependency-free PDF 1.4 generator (Catalog→Pages→Page chain,
      Helvetica /F1 + Courier /F2, FlateDecode content streams via node:zlib, byte-accurate xref,
      auto pagination, table borders, word-wrap, ( ) \ escaping). Pure + deterministic.
    - core/conmon-report.ts — pure buildConmonMonthlyReport() + emitConmonMonthlyReport()
      (reads poam.json / KSI-*.json / inventory.json / diff-report.json / scn-classification.json
       + CISA KEV + pinned playbook; detached-Ed25519-signs the JSON via the B.B1
       serializeUnsignedCanonical+signDoc pattern; renders MD + PDF).
    - tests/core/conmon-pdf.test.ts (10) + tests/core/conmon-report.test.ts (15) = +25 tests.
  Extended:
    - core/submission-bundle.ts — 3 WELL_KNOWN roles (conmon-monthly-report-{json,md,pdf}).
    - core/orchestrator.ts — --conmon-monthly / --month / --fedramp-package-id / --csp-name /
      --conmon-strategy-href / --sampling-pct / --ssp-last-reviewed / --authorization-date
      (+ CLOUD_EVIDENCE_* envs); emit runs AFTER POA&M/VDR/inventory, BEFORE signing.
    - core/sign.ts — SIGNED_EXTENSIONS now includes .md + .pdf (build step 9 + risk CC-12):
      the monthly .md/.pdf (and, as a bonus, the pre-existing scn-notice-draft.md) are now in the run manifest.
  Verification: typecheck clean; vitest 1050/1050 (was 1025); npm run check:reo all green.

  Open-question resolutions (§10):
    Q1 (PDF vs MD): ship BOTH — Connect.gov uploads commonly take PDF; MD is the review copy.
    Q2 (by_class keys): keyed on the inventory's real `assetType` field (cross-artifact-consistent
       with inventory.json `by_type`); a future slice can remap to FedRAMP Column J names if needed.
    Q3 (archive dir): deferred to E.E2 (which creates out/archive/<YYYY-MM>/). E.E1 reads only
       top-level out/ artifacts of the current run, so no archive dependency for v1.
    Q4 (--strict-conmon exit on warnings): NOT added in v1 — warnings are surfaced in
       provenance.warnings + the orchestrator log line; a strict gate can land alongside E.E2.
    Q5 (PDF fonts): Helvetica for prose/headings, Courier for table cells (both fonts embedded).
    Q6 (--dry-run JSON-only): NOT added in v1 — full emit is fast; can be added if CI needs it.

  Spec divergences (documented per the Strong Directive):
    - Added --authorization-date / CLOUD_EVIDENCE_AUTHORIZATION_DATE (not in §11) as the operator
      anchor for the annual-cycle section (months_elapsed + next_assessment_due). Absent → markers +
      provenance.warnings. Documented in OPERATOR-GUIDE §3.2 / §4.2. See new risk E.E1-R6.
    - provenance block is the G3 camelCase superset {emitter, emittedAt, sourceCalls, signingKeyId}
      PLUS the spec's {tool, frmrVersion, conmonPlaybookVersion, warnings}; the spec shape omitted
      emittedAt + signingKeyId which check-provenance.mjs (G3) requires. See [[project_slice_shipping_conventions]].
    - sign.ts SIGNED_EXTENSIONS extension is in build step 9 / CC-12 but not the §7 "files to extend"
      list; included because REO Rule 2.2 requires the .md/.pdf renders to be signed.
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [x] typecheck clean (`npm run typecheck`)
- [x] tests passing 100% (count increased by 25: 1025 → 1050)
- [x] check:reo green (G1+G2+G3)
- [x] STATUS.md updated (slice row + Overall section)
- [x] LOOP-E-SPEC.md status table updated
- [x] This file's frontmatter updated (status=done, commit=ddfa499, completed_date=2026-06-11)
- [x] CHANGELOG.md "Unreleased" entry added
- [x] Commit with slice ID in message
- [x] Commit hash recorded in STATUS.md + this file + LOOP-E-SPEC.md (follow-up `docs(E.E1)` commit per repo convention)
- [x] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here's everything it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-E-SPEC.md` Section 2 (Dependencies) for context on this loop.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Read existing emitter for pattern reference: `core/roe-emit.ts` (`.docx`), `core/oscal-poam.ts` (OSCAL JSON), `core/submission-bundle.ts` (well-known catalogue).
6. Begin implementation; update Implementation log section as you go.
