# LOOP-E — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with status=resolved + resolution note.
> Last updated: 2026-06-06 (initial drafting)
> Owner: whoever is currently in-flight on a LOOP-E slice

## How to use this register
- **Cross-cutting risks** apply to every slice in LOOP-E. Implementer should review before starting any slice.
- **Per-slice risks** are scoped to a single slice. They duplicate severity / mitigation from the slice doc only when shared across multiple slices; otherwise they live in the slice doc and the register simply names them.
- **External dependencies** lists upstream spec / library / regulatory changes that could invalidate work mid-stream.
- **Resolved** section is empty initially; entries move there with a `[resolved <date>: <commit>]` note when mitigated.

Severity scale: **high** (could block the slice or invalidate emitted artifacts), **medium** (correctness / UX concern; ship with workaround), **low** (cosmetic or future-proofing).

---

## Cross-cutting risks (apply to ALL LOOP-E slices)

### CC-1: REO Rule 1.6 — auto-signing temptation
- **Severity**: high
- **Description**: Every LOOP-E slice emits operator-facing artifacts (DR `.docx`, SCN `.docx`, AAR `.docx`, attestation `.md`) with signature cells. The temptation to auto-fill a "signed by orchestrator" stamp is high; doing so violates REO Rule 1.6 (no fake cryptographic operations) and the artifact becomes inadmissible for a 3PAO / AO review.
- **Mitigation**: Every signature cell renders the literal `REQUIRES-OPERATOR-INPUT` sentinel. Test assertions explicitly check for this string in the rendered XML. The Ed25519 signing pipeline in `core/sign.ts` covers the *envelope* (manifest), NOT the contents of individual cells.
- **Status**: open

### CC-2: REO Rule 1.5 — silent fallback when source file missing
- **Severity**: high
- **Description**: LOOP-E slices read many on-disk files (`poam.json`, `inventory.json`, `vdr-ledger.json`, `scn-classification.json`, `annual-test-ledger.jsonl`, etc.). When one is missing, the temptation to default to zero / empty / "first month" is real. REO Rule 1.5 forbids this — every missing-source case must emit either a typed error or a `provenance.warnings` marker.
- **Mitigation**: Each slice defines typed errors (`MissingPriorSspError`, `PriorPoamCorruptError`, `MissingClassificationError`, etc.). Builders never accept `undefined` silently. Where genuinely first-time-run is valid (first month POA&M, first annual SSP review), the rendered output contains a real true statement ("First month of ConMon operation; no prior POA&M to compare against.") — NOT a marker.
- **Status**: open

### CC-3: REO Rule 1.10 — auto-generated 3PAO / AO sign-offs
- **Severity**: high
- **Description**: LOOP-E artifacts go to 3PAOs (E.E3 annual assessment) and AOs (E.E5 DR approvals, E.E6 SCN acknowledgements). Auto-generating sign-off would be a catastrophic REO violation.
- **Mitigation**: Sign-off cells stay `REQUIRES-OPERATOR-INPUT`. Ledger state transitions (`--update-deviation-state`, `--update-scn-state`) only record structural state changes; they NEVER touch the `.docx` signature cells. Future LOOP-F.F1 will provide a tracker UI to capture sign-offs as DB rows (signed audit log) — but even then, the `.docx` signature cell is operator-applied.
- **Status**: open

### CC-4: Determinism across slices
- **Severity**: medium
- **Description**: Multiple LOOP-E slices emit `.docx` files. ZIP + OOXML produce non-deterministic bytes if mtime, file ordering, or any internal ID is non-deterministic. Tests must assert byte-identical output on identical input.
- **Mitigation**: Reuse `zipStore()` from `core/zip.ts` with fixed mtime (`0`) and deterministic file ordering. Any internal UUIDs go through `deterministicUuid()` from `core/oscal.ts`. Each slice has at least one "deterministic on identical input" test.
- **Status**: open

### CC-5: FedRAMP publication drift between slice start and AO review
- **Severity**: high
- **Description**: LOOP-E pins multiple FedRAMP publications: ConMon Playbook v1.0 (2025-11-17), Annual Assessment Guidance v3.0 (2024-02-15), POA&M Template, ISCP Template. If FedRAMP publishes new versions during a 3PAO review cycle, our pinned constants drift.
- **Mitigation**: Every pinned doc lives in a `docs/fedramp-*.generated.json` projection with `sha256`, `published_date`, `fetched_at`, `pinned_version`. `scripts/fetch-*.mjs` are human-run quarterly. The orchestrator surfaces the pinned version in every artifact's `provenance.*Version` block. RUNBOOK includes a quarterly check.
- **Status**: open

### CC-6: ECMA-376 strict-vs-transitional schema confusion
- **Severity**: medium
- **Description**: ECMA-376 has two profiles: **strict** (ECMA-376 5th edition, 2016) and **transitional** (legacy compatibility). Some Word readers reject strict; some federal agencies use very old Word versions.
- **Mitigation**: Stick to ECMA-376 strict mode (no transitional schema extensions). Test the generated XML against a real Word reader (manually) before declaring a slice done. Document in RUNBOOK that LibreOffice / Word 2016+ are required for review.
- **Status**: open

### CC-7: Submission-bundle role drift
- **Severity**: medium
- **Description**: Every LOOP-E slice adds 1-3 well-known roles to `core/submission-bundle.ts`. The catalogue is growing from 24 → ~36 roles. Risk of name collisions, regex overlaps, and inconsistent naming.
- **Mitigation**: Follow the naming convention `<artifact-family>-<format>` (e.g. `conmon-monthly-report-pdf`, `deviation-request-docx`, `scn-doc-docx`). Add a unit test that asserts no two regexes overlap on a representative filename set.
- **Status**: open

### CC-8: Ledger format choice (JSONL vs JSON)
- **Severity**: low
- **Description**: LOOP-E introduces 4 new ledgers: `poam-ledger.jsonl` (E.E2), `deviation-ledger.jsonl` (E.E5), `scn-ledger.jsonl` (E.E6), `annual-test-ledger.jsonl` (E.E7). JSONL chosen for append-only safety, but transition operations (E.E5/E.E6) require rewriting the whole file.
- **Mitigation**: Add file-lock (`proper-lockfile`) around every transition / rewrite. The slice docs explicitly call this out. JSONL preserved as the on-disk format; concurrent appends are safe via POSIX `O_APPEND` atomicity for < 4KB lines.
- **Status**: open

### CC-9: Cross-slice timing dependency (E.E2 archive used by E.E1, E.E4)
- **Severity**: medium
- **Description**: E.E1's monthly conmon report reads from `out/archive/<YYYY-MM>/`. E.E2 produces the archive. E.E4 reads from `out/archive/ssp-<YYYY-1>.json`. If slices are implemented out of order (E.E1 before E.E2), tests pass but real runs miss the archive.
- **Mitigation**: STATUS.md "Next priority" ordering enforces E.E1 → E.E2 → E.E3 → E.E4 → E.E5 → E.E6 → E.E7. Each slice doc's `depends_on` frontmatter is enforced by a CI script (future): refuse to merge slice X if its dependencies are not `done` in STATUS.md.
- **Status**: open

### CC-10: REQUIRES-OPERATOR-INPUT marker discovery
- **Severity**: medium
- **Description**: Operators may not realize a docx still contains `REQUIRES-OPERATOR-INPUT` cells before submitting to FedRAMP. The marker is grep-able but easily missed in a 20-page Word doc.
- **Mitigation**: Add a CLI sub-command `npm run validate-docx <path>` that scans for the literal sentinel and reports findings. Add a watermark on the cover page of any docx that contains `REQUIRES-OPERATOR-INPUT` markers ("DRAFT — operator input required").
- **Status**: open

### CC-11: Coverage regression on REO guardrails
- **Severity**: high
- **Description**: LOOP-E introduces ~12 new artifact families. Each must register a `coverage_source` per REO Rule 6 (`scripts/check-provenance.mjs`). Easy to miss.
- **Mitigation**: Each slice's "REO compliance" section explicitly lists provenance fields. The slice cannot be marked done until `npm run check:reo` is green.
- **Status**: open

### CC-12: `core/sign.ts` glob coverage
- **Severity**: high
- **Description**: LOOP-E creates new output paths: `outDir/archive/`, `outDir/deviation-requests/`, `outDir/scn-notice-*.docx`, `outDir/iscp-test-*.docx`, etc. If `core/sign.ts`'s manifest glob is hardcoded `out/*.{json,md,xml}`, new files won't be signed.
- **Mitigation**: First slice (E.E1) audits `core/sign.ts` and extends the glob if needed. Subsequent slices verify in their tests.
- **Status**: partially resolved [2026-06-11, E.E1] — `SIGNED_EXTENSIONS` extended from `{.json,.xml,.pem}` to also cover `{.md,.pdf}`, so the monthly report's `.md`/`.pdf` (and, as a bonus, the pre-existing top-level `scn-notice-draft.md`) are now in the run manifest. **Still open**: `listSignedFiles()` is top-level-only, so subdirectory outputs introduced by later slices (`out/archive/`, `out/deviation-requests/`, etc.) are NOT yet covered — E.E2/E.E5 must extend the walk to recurse (or sign per-subdir) and verify in their tests.

### CC-13: Calendar-year vs fiscal-year ambiguity
- **Severity**: medium
- **Description**: E.E3 (annual assessment), E.E4 (annual SSP review), E.E7 (annual IRP/ISCP test) all assume calendar Jan-Dec. ~20% of CSPs run on fiscal year (Oct-Sep, Jul-Jun, etc.).
- **Mitigation**: LOOP-E v1 ships calendar-year only. LOOP-E-SPEC §6 caveat 4 tracks. Future enhancement: `--annual-year-start MM-DD` flag.
- **Status**: open

### CC-14: USDA Connect.gov has no public API
- **Severity**: medium
- **Description**: All LOOP-E artifacts feed the monthly USDA Connect.gov upload. FedRAMP does not publish a public API spec for Connect.gov; uploads are manual drag-drop.
- **Mitigation**: LOOP-E v1 does NOT push to Connect.gov. The orchestrator's `--push-fedramp-repo` flag is deferred to a future loop (LOOP-H.H1 or LOOP-E.E8) once FedRAMP publishes the API. Document in RUNBOOK.
- **Status**: open

### CC-15: Test count growth
- **Severity**: low
- **Description**: LOOP-E adds ~140 new tests. CI run time grows. Test suite organization matters.
- **Mitigation**: Each slice scopes tests to its own files. Vitest parallelism handles the load. Slow tests (e.g. PDF parsing in E.E1) live in a separate `tests/slow/` dir if needed.
- **Status**: open

---

## Per-slice risks

### E.E1 — Monthly ConMon Analysis Report
- **E.E1-R1: PDF generator complexity (high)** — Pure-JS PDF 1.4 writer is the largest chunk (~2 days). Mitigation: keep spec minimal, add round-trip parse test.
- **E.E1-R2: Playbook drift (medium)** — Covered by CC-5.
- **E.E1-R3: Source-file presence assumptions (medium)** — Builder accepts `null` for any input and degrades with `provenance.warnings`.
- **E.E1-R4: Time-zone ambiguity in `report_month` (low)** — Always interpret `--month YYYY-MM` as UTC.
- **E.E1-R5: KEV exposure double-count (low)** — Dedupe by `cve_id` via `Set`. [resolved 2026-06-11, TBD-E1: builder uppercases + Set-dedupes the CVE universe before intersecting CISA KEV; test `counts KEV exposure deduped against the catalog` locks it.]
- **E.E1-R6: annual-cycle anchor requires operator input (low)** — `annual_cycle.months_elapsed` + `next_assessment_due` are computed from an operator-supplied `--authorization-date` / `CLOUD_EVIDENCE_AUTHORIZATION_DATE` (YYYY-MM-DD). This flag is NOT in the per-slice doc §11 list; it was added because §6 report section 8 ("months elapsed in current authorization year") has no other anchor (CC-13 calendar-vs-fiscal ambiguity makes deriving one unsafe). When absent: `months_elapsed=0`, `next_assessment_due=REQUIRES-OPERATOR-INPUT`, and a `provenance.warnings: ["authorization-date-absent: …"]` entry — never a fabricated date. Documented in OPERATOR-GUIDE §3.2/§4.2. A future slice (E.E4) may source the authorization date from the tracker.

### E.E2 — Monthly POA&M Delta Workflow
- **E.E2-R1: Deterministic UUID drift if `core/oscal-poam.ts` changes the UUID derivation (high)** — A change to the `deterministicUuid()` salt would re-key every prior month's items, breaking the diff. Mitigation: add a regression test that locks the UUID derivation algorithm.
- **E.E2-R2: Archive directory not in signed scope (high)** — Covered by CC-12.
- **E.E2-R3: Concurrent monthly runs (medium)** — Two operators running `--conmon-monthly --month 2026-07` simultaneously. Mitigation: file lock around archive directory.
- **E.E2-R4: Corrupt prior POA&M (medium)** — Typed `PriorPoamCorruptError`; never silent fallback.
- **E.E2-R5: First-month case (low)** — Real true statement, not a marker.

### E.E3 — Annual Assessment Package Generator
- **E.E3-R1: 12-month aggregation requires all 12 monthly bundles (high)** — If even one month is missing, the rollup is incomplete. Mitigation: `--strict-annual` mode throws; non-strict warns + continues with a `provenance.warnings: ["months-missing:[2026-03,2026-09]"]` entry.
- **E.E3-R2: Core Controls list pinning (medium)** — Covered by CC-5.
- **E.E3-R3: Control selection determinism (medium)** — Same year + same `priorYears` must produce same `in_scope` set. Mitigation: deterministic algorithm tested explicitly.
- **E.E3-R4: Annual bundle size (low)** — 12 months of POA&Ms + inventories + scans could exceed 1 GB. Mitigation: rely on tar+gzip's deduplication; warn if > 2 GB.

### E.E4 — Annual SSP Review / Update Workflow
- **E.E4-R1: Canonical JSON edge cases (high)** — Bad canonicalization invalidates the diff. Mitigation: vetted canonicalizer (RFC 8785 JCS-compatible).
- **E.E4-R2: SSP schema evolution (medium)** — Pin `oscal-version` allowlist.
- **E.E4-R3: Archive not in signed scope (high)** — Covered by CC-12.
- **E.E4-R4: Attestation date timezone (low)** — UTC + ISO-Z.
- **E.E4-R5: Prior-SSP corrupt (medium)** — Typed `PriorSspCorruptError`.
- **E.E4-R6: Field-change reporter explosion (medium)** — Cap at 20 per control with "...and N more" footer.
- **E.E4-R7: First-year heuristic ambiguity (medium)** — Require `--first-year` explicit flag.

### E.E5 — Deviation Request (DR) Emitter
- **E.E5-R1: VD check-in date drift (medium)** — Extend `expireStaleDr` to flag staleness.
- **E.E5-R2: Ledger rewrite race (medium)** — File lock via `proper-lockfile`.
- **E.E5-R3: OOXML rendering edge cases (low)** — `splitParas(text)` helper.
- **E.E5-R4: DR-against-multiple-POA&M-items (high, out of scope)** — Future enhancement.
- **E.E5-R5: AO email approval workflow (medium)** — Hand-edit until LOOP-F.F1.
- **E.E5-R6: Severity downgrade abuse (high, policy)** — Cannot enforce in code; document + LOOP-F.F1 visibility.
- **E.E5-R7: Numbered ID collisions (medium)** — `DrIdCollisionError`.
- **E.E5-R8: Expired DR rehydration (low)** — Documented behavior.

### E.E6 — Formal SCN Document Emitter
- **E.E6-R1: Classifier-doc desynchronization (medium)** — Embed `rules_version` in custom properties.
- **E.E6-R2: SIA path validity (low)** — Resolve + verify file exists; marker if missing.
- **E.E6-R3: Concurrent SCN ledger updates (medium)** — File lock.
- **E.E6-R4: Agency Word version compatibility (medium)** — Covered by CC-6.
- **E.E6-R5: 10-field list drifts (low)** — Covered by CC-5.
- **E.E6-R6: Advisory SCN gating (low)** — `--allow-advisory-scn` opt-in.
- **E.E6-R7: Hardcoded NIST 800-37 quote (low)** — Pin `nist_sp_800_37_rev2_published='2018-12'`.
- **E.E6-R8: Multi-change rollup (medium)** — Auto-numbering per fiscal year.

### E.E7 — Annual IRP / ISCP Test Cadence Runner
- **E.E7-R1: Operator-filled docx round-trip (high, out of scope for v1)** — Deferred to E.E7-b.
- **E.E7-R2: AAR template drift (low)** — Pin `fedramp_iscp_template_version`.
- **E.E7-R3: Calendar-year vs fiscal-year (medium)** — Covered by CC-13.
- **E.E7-R4: Participants tracker integration (low)** — Wait for LOOP-F.F4.
- **E.E7-R5: Reporting-compliance ambiguity (low)** — Footnote citing FedRAMP + CIRCIA.
- **E.E7-R6: Multi-tabletop per year (medium)** — Future `--suffix Q1`.
- **E.E7-R7: Scenario template library (low)** — Future `core/scenario-library.ts`.
- **E.E7-R8: Date/timezone confusion (low)** — UTC.
- **E.E7-R9: Findings ID collision across years (medium)** — Require year prefix in finding IDs.
- **E.E7-R10: Pre-fill docx attractiveness (medium)** — Watermark "DRAFT — DO NOT SUBMIT".

---

## External dependencies that may change

### FedRAMP guidance
- **FedRAMP Continuous Monitoring Playbook v1.0 (2025-11-17)** — pinned in `docs/fedramp-conmon-playbook.generated.json`. A v1.1 / v2.0 publication would re-set: remediation deadlines, scan cadence, monthly deliverables list. Quarterly check via `scripts/fetch-conmon-playbook.mjs`.
- **FedRAMP Annual Assessment Guidance v3.0 (2024-02-15)** — pinned in `docs/fedramp-annual-core-controls.generated.json`. A v3.1 / v4.0 would re-set: Core Controls list (129 controls), 3-year cycle methodology. Quarterly check via `scripts/fetch-annual-assessment-guidance.mjs`.
- **FedRAMP POA&M Template `.xlsx`** — column letters (V/W/X/Q/R/S) hardcoded in E.E5. Major template restructure would break.
- **FedRAMP ISCP Template (Rev4 still authoritative for Rev5)** — when FedRAMP publishes a Rev5 ISCP template, E.E7 section structure may change.
- **FedRAMP Significant Change Notification page** — the 10 verbatim SCR content fields hardcoded in E.E6. A future addition (e.g. "supply chain dependency" field) would require update.
- **FedRAMP Incident Communications Procedures** — the 1-hour US-CERT reporting cadence in E.E7 reporting-compliance.
- **FedRAMP 20x Phase Two pilot retrospective** — when FedRAMP publishes the post-pilot revised submission bundle format, `package_format_version` in `INDEX.json` covers transition cleanly (LOOP-E-SPEC §6 caveat 7).

### NIST publications
- **NIST SP 800-53 Rev. 5.2.0 → 5.3.0** — control IDs (CA-5, CA-7, CM-3, CM-4, CP-4, IR-3, PL-2, RA-5, etc.) are referenced verbatim. Minor revisions OK; major restructure (e.g. control consolidation) would require update.
- **NIST SP 800-37 Rev. 2 → Rev. 3** — significant-change definition quoted verbatim in E.E6 docx. Rev. 3 wording change would require update.
- **NIST SP 800-137 → next revision** — ConMon framework foundation; major restructure would affect E.E1 narrative.
- **NIST SP 800-61 Rev. 2 → Rev. 3** — IR four-phase outline drives E.E7 IRP AAR sections.
- **NIST SP 800-34 Rev. 1 → next revision** — ISCP testing guidance.
- **NIST SP 800-84 → next revision** — AAR structure guidance.
- **OSCAL v1.1.2 → v1.1.3 / v2.0** — JSON schema for POA&M, SSP, AP, AR. Major bump would require ajv schema updates + new schema URL pins.

### Upstream library updates
- **ajv (`^8.x`)** — JSON Schema validator. Major version bump affects `core/oscal-validate.ts`.
- **`json-stable-stringify` (E.E4 canonicalizer dependency)** — minor bumps OK; major bump (or replacement with native `JSON.stringify` with sort) would invalidate prior diff hashes.
- **`proper-lockfile`** — file locking. Used by `core/run-lock.ts` and extended by E.E5 / E.E6 ledger transitions.
- **Node.js `zlib` API** — used by `core/conmon-pdf.ts` FlateDecode streams. Stable for foreseeable future.
- **OSCAL schemas at `pages.nist.gov/OSCAL-Reference/`** — URL stability assumed; future repo move would break re-fetch scripts.

### Regulatory cadences
- **CISA CIRCIA Final Rule** — 72-hour cyber incident reporting + 24-hour ransom payment reporting (effective 2024). Encoded in E.E7 IRP AAR reporting-compliance table. Amendments would require update.
- **FedRAMP 1-hour US-CERT reporting** — encoded in E.E7. Currently authoritative; future FedRAMP guidance may align with CIRCIA 72-hour.

### Tracker integrations (downstream)
- **LOOP-F.F1 (3PAO sign-off UI)** — would unlock E.E4 attestation, E.E5 AO approval, E.E6 SCN acknowledgement via tracker DB (signed audit log).
- **LOOP-F.F4 (evidence walk-through artifacts)** — would unlock E.E7 `participants` auto-population from tracker.
- **LOOP-G.G2 (AFR-ICP — Incident Communications Procedures)** — would unlock E.E1 `incident_summary` auto-population and E.E7 IRP AAR cross-reference.
- **LOOP-H.H1 (Immutable evidence archive)** — would unlock annual bundle long-term storage push (S3 Glacier / GCS Coldline / Azure Archive).

---

## Resolved risks (historical)

_(Empty — populated as risks are resolved.)_

Format when adding:
```
### <ID>: <title>
- **Severity at resolution**: <high/medium/low>
- **Resolution**: <commit hash + brief description>
- **Resolved on**: <ISO date>
- **Resolved in slice**: <slice id>
```
