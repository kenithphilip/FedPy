# FedRAMP 20x execution status

> Updated automatically by the slice-completion procedure (see SLICE-COMPLETION-PROCEDURE.md).
> The values below MUST be kept in sync with CHANGELOG.md "Unreleased" entries.
> When a slice completes: update its row + commit + push (atomic with the slice's own commit).

## Scope (READ CLAUDE.md "Scope Guard" block first)

FedPy is FedRAMP 20x + Rev5 evidence automation. Loops in **Core** are
in-scope for implementation. Loops in **Overlay / Out-of-Core** are
parallel compliance regimes preserved as research / roadmap reference
under `docs/roadmap/` — not part of the FedRAMP authorization pipeline
and not on the implementation queue.

## Overall (Core only)
- Total core slices: 102 base + 1 SEC 8-K overlay = 103 counting overlay
  - 5 LOOP-A done
  - 12 LOOP-B–K base done (B.B1, B.B2, B.B3, B.B4, B.B5, C.C1, C.C2, C.C3, E.E1, E.E2, J.J2, J.J3), 38 LOOP-B-K pending
  - 25 LOOP-L-Q pending
  - 6 LOOP-R+S pending
  - 4 LOOP-W done (W.W1, W.W2, W.W3, W.W4) — LOOP-W COMPLETE
  - 5 LOOP-T done (T.T1, T.T2, T.T3, T.T4, T.T5) — LOOP-T COMPLETE
  - 5 LOOP-X pending
  - 2 CIRCIA-extension slices pending
  - + 4 pre-loop research (R1-R4 done) + REO-0 (done)
- Core loops total: 22 (A through S + T + W + X) + 2 CIRCIA extensions (G.G2.CIRCIA, M.M4.CIRCIA) + 1 SEC 8-K overlay (G.G2-SEC-8K)
- Loops complete: 4 of 22 (LOOP-A, LOOP-W, LOOP-T, LOOP-B); LOOP-C in progress (3 of 9 slices done — C.C1, C.C2, C.C3); LOOP-E in progress (2 of 7 slices done — E.E1, E.E2); LOOP-J in progress (2 of 3 slices done — J.J2, J.J3; J.J1 pending)
- Last shipped: LOOP-C.C3 (commit `<TBD-step6>`)
- Next priority: **C.C4 (Privacy Threshold Analysis (PTA) + Privacy Impact Assessment (PIA))** — the fourth LOOP-C (Document Template Pack) slice; C.C1 (CMP) + C.C2 (ISCP + Test AAR) + C.C3 (IRP + Test AAR) shipped. C.C4 emits `pta.docx` (+ conditional `pia.docx`) (PT-2/PT-3/PT-6/AR-2), driven by the `inventory.json` data-classification tags (Rev4 FedRAMP PTA/PIA template structure with Rev5 control identifiers — FedRAMP has no current plans for a Rev5 PTA/PIA template). LOOP-C.C7 (Risk Management Strategy doc) remains unblocked by B.B5's `risk-register.json`. LOOP-L through LOOP-Q queued behind LOOP-C. LOOP-R (PQC), LOOP-S (DFARS, conditional), LOOP-X (Zero Trust), G.G2-SEC-8K, and CIRCIA extensions queued behind LOOP-L–Q.
  - **C.C3 scope note (2026-07-07):** C.C3 shipped the **full slice** end to end — two signed-by-bundle Word documents: the Incident Response Plan (`out/irp.docx`, IR-8/IR-3/IR-4/IR-6, 11 sections structured per NIST SP 800-61 Rev. 3's CSF 2.0 life-cycle) and the Incident Response Test After-Action Report (`out/irp-test-aar.docx`, IR-3, 7 sections with the 5-phase timing matrix). **cloud-evidence:** `core/irp-emit.ts` (pure `buildIrpBodyXml`/`renderIrpDocx` + disk `emitIrpDocx`) auto-fills the §4 Detect table from the **real** signed `KSI-INR-RIR.json` evidence (`readInrRirEvidence` flattens `providers[].findings[]` into one detection-source row each — rule + pass/fail + `current_state.summary` — and derives a coverage percent from the pass ratio; <95% surfaces a warning row per Risk 4); §5 Respond renders the six CSF 2.0 Functions (Govern/Identify/Protect/Detect/Respond/Recover) as sub-sections (the `--irp-spec-version=800-61r2` flag swaps in the withdrawn four-phase model); §9 Reporting Requirements bakes the FedRAMP Incident Communications Procedures SLAs (1h PMO + 1h agency + 4h CISA US-CERT) as `REQUIRES-OPERATOR-INPUT-VERIFY` baseline rows; §3 classification levels + §7 external contacts (FedRAMP `info@fedramp.gov` + CISA `report@cisa.gov` role-based addresses, no personal PII — Risk 3) + §8 escalation matrix (sorted severity-desc) default to verify-marked FedRAMP baselines; every operator narrative (team roster, communications plan) defaults to a verbatim `REQUIRES-OPERATOR-INPUT` marker. `core/irp-test-aar.ts` renders operator-supplied test scenarios (5-phase timing: detection/response/containment/eradication/recovery minutes since onset — NEVER fabricated; empty `scenarios[]` → a single `REQUIRES-OPERATOR-INPUT` row), flags failed scenarios in §4, routes high/critical lessons to a §6 POA&M footer note, and emits a 4-row §7 sign-off block whose signature/date cells stay `REQUIRES-OPERATOR-INPUT` (the toolkit never auto-signs a human attestation — REO Rule 1.10). Both docs are **fully deterministic** (no wall-clock time): UUIDs are `deterministicUuid('irp:'+systemId+':'+runId)` / `deterministicUuid('irp-test-aar:'+runId+':'+testDate)`; `testType`/`testDate` default to `REQUIRES-OPERATOR-INPUT` rather than `new Date()` (REO Rule 1.7). The AAR anchors to the plan it tested by citing the SHA-256 of `out/irp.docx` when present (Q4). Orchestrator `--irp` / `--irp-test-aar` (envs `CLOUD_EVIDENCE_IRP` / `_IRP_TEST_AAR`) + `--irp-spec-version` dispatch the emitters AFTER the ISCP emit + BEFORE signing (IRP before AAR so the anchor resolves); structured input flows from a new `config.yaml#irp.*` section; two `submission-bundle` WELL_KNOWN roles registered (`irp-docx`, `irp-test-aar-docx`). **REO:** every §4 detection row traces to a real INR-RIR finding (never a fabricated "logging is configured" row); §5/§9 quote NIST SP 800-61 Rev. 3 §2.1 + IR-8/IR-3 verbatim; both `.docx` pass `unzip -t` (valid OOXML, 6 parts). **Spec reconciliation (LOOP-C-RISKS `C-C3-7..8`):** (7) the INR-RIR evidence file name is the real collector output `KSI-INR-RIR.json`, NOT the per-slice-§7 `.signed.json` (reader tries `.json` first, `.signed.json` fallback — same posture as C-C2-7), and the real envelope carries detection capabilities as `providers[].findings[]` with a top-level `collected_at`, NOT the §5-assumed flat `evidence[].detection_source`/`coverage_percent` (same posture as C-C2-9); (8) the shared `core/docx-primitives.ts` was again NOT extracted (per-slice §7 scopes C.C3 to `irp-emit.ts`/`irp-test-aar.ts` + the anti-pattern rule forbids refactoring out-of-scope files) — now 8 emitters to migrate when C-X-1 lands. **Open questions resolved:** Q1 `--irp-spec-version` defaults to r3 (current standard; no SSP auto-detection — avoids added complexity); Q2 §9 keeps a single CISA row with the "federal data" trigger stated in the row text (no separate involving/not-involving split); Q3 §7 emits an aggregate "Agency POC" row (`REQUIRES-OPERATOR-INPUT` — each agency customer has its own POC per the ISA/MOU); Q4 the AAR cites `out/irp.docx` SHA-256 when present; Q5 `testType=red-team` needs no separate authorization block this slice (deferred to the tracker sign-off flow); Q6 §5 Respond cross-references LOOP-G.G2 AFR-ICP by pointing recovery at the ISCP + naming the communications plan (§6) rather than duplicating the AFR artifact. **Deferred** (LOOP-C-RISKS `C-C3-9`): the tracker `irp_tests` table / operator UI for scenario + roster capture lands with LOOP-E.E7 (no tracker subsystem consumes these emitters yet; structured input via `config.yaml#irp.*` as a stop-gap). Tests: cloud-evidence 1433→1457 (+24: 14 IRP + 10 AAR).
  - **C.C2 scope note (2026-07-07):** C.C2 shipped the **full slice** end to end — two signed-by-bundle Word documents: the Information System Contingency Plan (`out/iscp.docx`, CP-2/CP-9/CP-10, 6 sections + 6 appendices per the FedRAMP SSP Appendix G ISCP Template + NIST SP 800-34 Rev. 1) and the Contingency Plan Test After-Action Report (`out/iscp-test-aar.docx`, CP-4, 6 sections per Appendix G Appendix F). **cloud-evidence:** `core/iscp-emit.ts` (pure `buildIscpBodyXml`/`renderIscpDocx` + disk `emitIscpDocx`) auto-fills the §4.2 Recovery-evidence table from the real signed RPL-family KSI files (`readRplEvidence` reads `KSI-RPL-ABO/TRC/RRO/ARP.json`, one row per KSI with pass/fail + `collected_at` + a SHA-256 evidence citation); §2.1 components + Appendix B vendor contacts **compose** the existing readers (`readInventoryComponents`/`groupComponents` imported from `cmp-emit.ts`; `readSubprocessorContacts` reads the real `subprocessor-inventory.json` rows); §1.3 quotes the NIST SP 800-34 §3.1 seven-step process verbatim; every recovery narrative (RTO/RPO, alternate site, activation authority/criteria, rosters) defaults to a verbatim `REQUIRES-OPERATOR-INPUT` marker. `core/iscp-test-aar.ts` renders operator-supplied test scenarios + lessons learned (NEVER fabricated — empty `scenarios[]` → a single `REQUIRES-OPERATOR-INPUT` row naming the runId), flags failed scenarios in §3, routes high/critical lessons to a POA&M footer note, and emits a 4-row §6 sign-off block whose signature/date cells stay `REQUIRES-OPERATOR-INPUT` (the toolkit never auto-signs a human attestation — REO Rule 1.10). Both docs are **fully deterministic** (no wall-clock time): UUIDs are `deterministicUuid('iscp:'+systemId+':'+runId)` / `deterministicUuid('iscp-test-aar:'+runId+':'+testDate)`; `testDate` defaults to `REQUIRES-OPERATOR-INPUT` rather than `new Date()` (REO Rule 1.7). The AAR anchors to the plan it tested by citing the SHA-256 of `out/iscp.docx` when present (Q4). Orchestrator `--iscp` / `--iscp-test-aar` (envs `CLOUD_EVIDENCE_ISCP` / `_ISCP_TEST_AAR`) + four value flags (`--iscp-rto-hours`/`--iscp-rpo-hours`/`--iscp-test-date`/`--iscp-test-type`) dispatch the emitters AFTER the CMP emit + BEFORE signing (ISCP before AAR so the anchor resolves); structured input flows from a new `config.yaml#iscp.*` section; two `submission-bundle` WELL_KNOWN roles registered (`iscp-docx`, `iscp-test-aar-docx`). **REO:** every §4.2 row traces to a real signed evidence file (never a fabricated "backup is configured" row); Appendix B traces to real subprocessor rows (SA-9 inventory has no contact/phone, so those cells are `REQUIRES-OPERATOR-INPUT`, not invented); both `.docx` pass `unzip -t` (valid OOXML). **Spec reconciliation (LOOP-C-RISKS `C-C2-7..10`):** (7) the RPL evidence file name is the real collector output `KSI-RPL-*.json`, NOT the per-slice-§5 `.signed.json` (the collector filters `.signed.json` out as a duplicate; the reader tries `.json` first, `.signed.json` as fallback); (8) Appendix B reads the real `subprocessor-inventory.json` (`{rows:[…]}`), NOT the spec-named `out/subprocessors.json` (read as a fallback, both shapes tolerated); (9) the narrow `KsiEvidence` interface consumes the envelope's top-level `collected_at` + `rollup.pass`, NOT the §5-assumed `findings[].metadata.last_collected_at`; (10) the shared `core/docx-primitives.ts` was again NOT extracted (per-slice §7 scopes C.C2 to `iscp-emit.ts`/`iscp-test-aar.ts` + the anti-pattern rule forbids refactoring out-of-scope files) — now 6 emitters to migrate when C-X-1 lands. **Open questions resolved:** Q1 no per-row RFC 3161 TST in §4.2 (kept compact; chain-of-custody via the SHA-256 citations + bundle INDEX.json); Q2 the ISCP §2 is the canonical contingency narrative, seeded from `out/ssp.json` `system-characteristics.description` when present (`readSspDescription`); Q3 §4.2 groups by KSI ID (one row per RPL KSI, matching each envelope's own multi-provider aggregation); Q4 the AAR cites `out/iscp.docx` SHA-256 when present; Q5 `testType` defaults to `REQUIRES-OPERATOR-INPUT` (no `tabletop` default — avoids fabrication); Q6 Appendix C is framework-only `REQUIRES-OPERATOR-INPUT` (per-cloud runbook linking deferred — no config surface added this slice). **Deferred** (LOOP-C-RISKS `C-C2-11`): the tracker `iscp_tests` table / operator UI for scenario capture lands with LOOP-E.E7 (no tracker subsystem consumes these emitters yet). Tests: cloud-evidence 1409→1433 (+24: 14 ISCP + 10 AAR).
  - **C.C1 scope note (2026-07-07):** C.C1 shipped the **core deliverable** end to end — the signed-by-bundle Configuration Management Plan (`out/cmp.docx`), an 11-section CM-9 Word document. **cloud-evidence:** `core/cmp-emit.ts` (pure `buildCmpBodyXml`/`renderCmpDocx` + disk `emitCmpDocx`) auto-derives §4 Configuration Items from the real `out/inventory.json` (CM-8), grouped by `(provider, assetType)` with per-group counts + distinct locations; §7 Configuration Monitoring lists the real KSI domains grepped from `core/ksi-map.ts` (44 domains; the emitter throws `CmpKsiScopeError` if <20 resolve). Every process-narrative section — §3 CCB roster (NIST SP 800-128 §2.1 four roles), §6 change-control (CM-3/CM-4), §8 change windows, §9 rollback authority, §10 tooling — defaults to a verbatim `REQUIRES-OPERATOR-INPUT` marker; inferred cloud-native CM tooling (§10, from the inventory provider set) uses the distinct `REQUIRES-OPERATOR-INPUT-VERIFY` marker so the operator confirms actual use. The document is **fully deterministic** (no wall-clock time): the `docProps/core.xml` `<dc:title>` carries `deterministicUuid('cmp:'+systemId+':'+runId)` and the §1 provenance cites the inventory content SHA-256, so identical inputs yield a byte-identical `.docx`. Orchestrator `--cmp` (env `CLOUD_EVIDENCE_CMP`) + four value flags (`--cmp-approval-narrative`/`--cmp-rollback-authority`/`--cmp-change-windows`/`--cmp-baseline-config-href`, each with an env + a `config.yaml#cmp.*` fallback) dispatch the emitter AFTER the RoE emit + BEFORE signing; `submission-bundle` WELL_KNOWN role `cmp-docx` registered; `config.yaml` gained the `cmp:` section. **REO:** every §4 row traces to a real inventory asset (never fabricated); §7 traces to the live ksi-map; narratives are operator-supplied-or-marked; the operator/CSP is author-of-record (the system never auto-approves — CM-9.d). **Spec reconciliation (LOOP-C-RISKS `C-C1-6..8`):** (6) the LOOP-C-SPEC §4 "pre-slice" shared `core/docx-primitives.ts` was **not** extracted — the per-slice-doc §7 file list scopes C.C1 to `cmp-emit.ts` only, and the four shipped docx emitters (`ssp-docx`/`roe-emit`/`section889-rep-docx`/`section889-report-docx`) each keep local OOXML constants; C.C1 follows that precedent (cross-cutting C-X-1 remains a future refactor); (7) `deterministicUuid` takes a single seed string (not the `(slice, systemId, runId)` triple C-X-3 assumed) — composed as `cmp:${systemId}:${runId}`; (8) `.docx` is not in `core/sign.ts` `SIGNED_EXTENSIONS` (`.json`/`.xml`/`.pem`/`.md`/`.pdf`), so `cmp.docx` is a printable companion like `roe.docx`/`ssp.docx` — its integrity is anchored by the signed submission-bundle `INDEX.json` (which SHA-256s + Ed25519-signs every included file), not a per-file `.sig`. §5 cross-link to `baseline-config.docx` is a text reference (the C-X-9 active-hyperlink helper is deferred with the primitives). **Open questions resolved:** Q1 §3 emits only the four `REQUIRES-OPERATOR-INPUT` role rows when the roster is empty (no fabricated FedRAMP RBAC roster); Q2 §6 cites CM-3/CM-4 directly (LOOP-E.E5 Deviation Request flow not yet shipped); Q3 §4 aggregates by `(provider, assetType)` with a Location(s) column (compact + sampling-friendly, no per-region row explosion); Q4 account/subscription IDs not enumerated (current inventory shape exposes `provider`+`location`; a future enricher can add them); Q5 `--cmp-baseline-config-href` accepts any string (relative path or URL). Tests: cloud-evidence 1391→1409 (+18).
  - **B.B5 scope note (2026-07-02):** B.B5 shipped the **full slice** end to end across BOTH workspaces (COMPLETING LOOP-B, per the [[B.B4 scope note]] full-stack precedent). **cloud-evidence:** the pure aggregator `core/risk-register.ts` (`buildRiskRegister`/`emitRiskRegister`) JOINS the just-emitted OSCAL POA&M risks (B.B1+B.B2, band-derived from each risk's `epss-percentile`→likelihood + `criticality`→impact props), the signed B.B3 acceptance snapshot, the B.B4 compensating-control snapshot, and the new operator-entered organisational-risk snapshot into a signed `out/risk-register.json` + `out/risk-register.xlsx` (NIST RA-3 deliverable). Likelihood/impact use the NIST SP 800-30 Rev 1 qualitative tokens VERBATIM; inherent = `INHERENT_RISK_MATRIX` (Table I-2, pinned constant); residual drops one band per active compensating control (two for transfer/avoid). **De-dup:** an acceptance covering a poam-item suppresses the finding entry (prefer treatment=accept). A `REQUIRES-OPERATOR-INPUT` B.B1 source marker propagates through to the band (visible, never a silent zero). New `core/risk-register-xlsx.ts` renders the single "Risk Register" sheet (20 cols A..T, frozen header pane, red-fill on high/very-high inherent + bold-red on very-high residual, wrapped Description) via the dependency-free store-only OOXML writer (`core/zip.ts`); `core/organisational-risk-reader.ts` pulls `organisational_risks` over HTTP + writes the signed `out/.organisational-risks.json` snapshot. Orchestrator `--risk-register` (env `CLOUD_EVIDENCE_RISK_REGISTER`) runs AFTER the POA&M emit + BEFORE signing; `--pull-organisational-risks <url>` (env `CLOUD_EVIDENCE_ORGANISATIONAL_RISKS_URL`; defaults to the `--pull-risk-acceptances` tracker URL) runs the pull first; three `submission-bundle` WELL_KNOWN roles registered (`risk-register-json`/`risk-register-xlsx`/`organisational-risks-snapshot`); `inventory-coverage.ts` gained the `risk_register_coverage` sibling (G2-safe). **Tracker** (`tracker/`, Hono + better-sqlite3 + React): new `organisational_risks` table (`server/schema.sql`, additive `CREATE TABLE IF NOT EXISTS`); Hono CRUD routes (`server/routes/risk-register.ts` — create/list/detail/update/close + aggregated `GET /api/risk-register` + `GET /api/risk-register/export.xlsx`) with manual validation (no zod), server-side inherent computation from the same Table I-2 matrix (Q5), NIST-catalog + compensating-control cross-checks, and a ≥30-day-forward `review_date` gate; B.B5 permissions added to `server/rbac.ts` (`create`/`close` = iso/ao/admin [risk ownership], `read` = all); `server/risk-register-xlsx.ts` is a tracker-local copy of the renderer (separate workspace — cannot import cloud-evidence); React pages (`client/src/pages/RiskRegister{,}.tsx` + `OrganisationalRisk{Create,Detail}.tsx` + `client/src/lib/risk-register-{api,view}.ts` + App.tsx routes/nav). **REO:** every finding entry traces to a real OSCAL risk (JOIN, not generator); organisational rows are verbatim operator input (title 5-200, description ≥100, server-enforced); air-gapped/no-snapshot ⇒ organisational entries simply absent (logged, never fabricated). **Open questions resolved:** Q1 second By-Category sheet deferred (single sheet; tests pin sheet 1); Q2 aggregated endpoint lives on the tracker server (UI-facing), the orchestrator emits the offline artifact; Q3 aggregator reads only non-`closed` POA&M risks (remediated drop off); Q4 owner = role label (ISO/AO) for finding/acceptance, tracker user name for organisational; Q5 server computes inherent (deterministic), residual operator-set; Q6 per-period trend snapshot deferred to E.E1; Q7 frozen header via OOXML `<pane>`; Q8 expiration-warning column deferred. **Spec reconciliation (LOOP-B-RISKS `B.B5-11..13`):** (11) no SheetJS in either workspace — the spec's "SheetJS round-trip" is realised as valid-OOXML round-trip via the repo zip reader; (12) the XLSX renderer is duplicated tracker-side (separate npm workspace, no cross-import) — a future column change must touch both; (13) the tracker aggregated endpoint returns the tracker-resident subset (organisational + acceptance) — the authoritative finding-inclusive RA-3 register is the collector's `out/risk-register.json`. Tests: cloud-evidence 1372→1391 (+19: 13 aggregator + 4 xlsx + 2 reader), tracker 159→178 (+19: 10 routes + 9 view).
  - **B.B4 scope note (2026-07-02):** B.B4 shipped the **full slice** end to end across BOTH workspaces (the tracker subsystem is real, per the [[B.B3 scope note]]). **Tracker** (`tracker/`, Hono + better-sqlite3 + React): new `compensating_controls` table (`server/schema.sql`, additive `CREATE TABLE IF NOT EXISTS` — verified on fresh + existing DBs); Hono CRUD routes (`server/routes/compensating-controls.ts` — create-draft/list/uuid-exists/detail/verify/update-draft/activate/retire with manual validation, no zod); a **compensating-control signing module** (`server/compensating-control-sign.ts`) that REUSES the B.B3 resident Ed25519 key + RFC-8785 canonicalisation (`risk-acceptance-sign.ts`) and adds the two payload shapes — activation writes a second signature so AO sign-off is non-repudiable; server-side NIST 800-53 Rev 5 validation (`server/nist-catalog.ts` + committed copy `server/data/nist-r5-controls.generated.json`, O(1) Set lookup, `AC-2(3)`↔`ac-2.3` normalisation); B.B4 permissions added to `server/rbac.ts` (`create` = iso/admin, `activate` = ao/admin [separation of duties — an iso implements but cannot self-activate], `retire` = iso/ao/admin, `read` = all); route mounted in `server/index.ts`; React pages (`client/src/pages/CompensatingControl{s,Create,Detail}.tsx` + `client/src/lib/compensating-control-{api,view}.ts` + App.tsx routes/nav). **cloud-evidence:** `core/compensating-control-reader.ts` pulls the tracker's active controls over HTTP, **verifies every record's Ed25519 signature** against the tracker's published public key, and writes the signed `out/.compensating-controls.json` snapshot (provenance-stamped); `core/oscal-poam.ts` fills each accepted risk's `risk.remediations[]` with `lifecycle='completed'` entries carrying the control's title/description + `compensating-control-uuid` + one `nist-control` prop per id + evidence link (`getCompensatingControl` re-checks `status='active'` AND unexpired — defence-in-depth — so a draft/expired/retired/unknown uuid surfaces as a `REQUIRES-OPERATOR-INPUT: unknown uuid` marker, never silently dropped); orchestrator `--pull-compensating-controls <url>` (env `CLOUD_EVIDENCE_COMPENSATING_CONTROLS_URL`; defaults to the `--pull-risk-acceptances` tracker URL) runs the pull before the POA&M emit; `submission-bundle` WELL_KNOWN role `compensating-controls-snapshot` registered; `core/nist-r5.ts` gained the shared `isValidControlId`/`normalizeControlId` primitives. **REO:** all registry content is verbatim operator input (title 5-200, description ≥200, server-enforced); NIST ids validate against the published catalog (invalid → 400 naming the offending value); signatures are real Ed25519; the system never auto-activates; a retired control cited by an active acceptance is 409-blocked (B.B4-4). **Open questions resolved:** Q1 catalog shipped as a static tracker asset; Q2 enhancements validated (`AC-2(3)`); Q4 expiration optional with a UI annual-review nudge; Q6 NIST ids in props not description; Q7 `evidence_sha256` is in the signed payload (forward-compat for H.4-before-create). **Spec reconciliation (LOOP-B-RISKS `B.B4-10/11`):** the per-slice doc assumed Express + a fresh `compensating-control-sign.ts` keypair + `.test.tsx` DOM-render UI tests; reality is Hono + reused B.B3 signing key + pure `compensating-control-view.ts` logic unit-tested in `tests/` (no jsdom). Tests: tracker 130→159 (+29), cloud-evidence 1354→1372 (+18).
  - **B.B3 scope note (2026-07-02):** B.B3 shipped the **full slice** (not core-only) — the risk-acceptance workflow lives end to end across BOTH workspaces. **Tracker** (`tracker/`, Hono + better-sqlite3 + React — a real subsystem that has existed since the initial commit; the prior slices' "no tracker subsystem" deferrals rested on a false premise): new `signing_keys` + `risk_acceptances` + `risk_acceptance_compensating_links` tables (`server/schema.sql`); a **new Ed25519 signing subsystem** the tracker never had (`server/risk-acceptance-sign.ts` — resident-key registry + RFC-8785-compatible canonicalisation byte-identical to `cloud-evidence/core/sign.ts`); Hono routes (`server/routes/risk-acceptance.ts` — create/list/detail/verify/approve/revoke/expire) with manual validation (the tracker has no zod); three FedRAMP separation-of-duties RBAC roles added (`iso` creates/revokes, `ao` approves, `assessor` reads — distinct from `admin` so an ISO cannot self-approve; `server/rbac.ts` + a widened `users.role` CHECK migration in `server/db.ts`, verified additive on both fresh + existing DBs); the hourly expiry enforcer (`server/risk-acceptance-enforcer.ts`, booted from `server/index.ts`); and React pages (`client/src/pages/RiskAcceptance{,Create,Detail}.tsx` + `client/src/lib/risk-acceptance-{api,view}.ts` + App.tsx routes/nav). **cloud-evidence:** `core/risk-acceptance-reader.ts` pulls the tracker's approved acceptances over HTTP, **verifies every record's Ed25519 signature** against the tracker's published public key, and writes the signed `out/.risk-acceptances.json` snapshot (provenance-stamped, camelCase G3); `core/oscal-poam.ts` flips a matching finding's risk to `risk.status="deviation-approved"`, overrides the deadline to the acceptance `expiration_date`, and attaches `acceptance-*` + `compensating-control-uuid` props — only for `status='approved' AND expiration_date>now()` records (defence-in-depth: the reader re-checks expiry so an unswept row never propagates); orchestrator `--pull-risk-acceptances <url>` + `--tracker-api-token` (env `CLOUD_EVIDENCE_TRACKER_URL` / `_TOKEN`) run the pull before the POA&M emit; `submission-bundle` WELL_KNOWN role `risk-acceptances-snapshot` registered. **REO:** signatures are real Ed25519 over canonical JSON; `business_justification` is verbatim operator input (min 100 chars, server-enforced); AO approval requires the `ao`/`admin` permission + writes a second signature; the system never auto-approves and never fabricates an acceptance (air-gapped/no-snapshot ⇒ every risk stays `open`, logged `risk-acceptance:missing-snapshot`). **Spec reconciliation:** the per-slice doc assumed Express + zod + `iso/ao` role-list middleware + a pre-existing `tracker/server/sign.ts` — reality is Hono + manual validation + permission-based RBAC + no prior signing subsystem, so B.B3 added the signing primitive and mapped to permissions (LOOP-B-RISKS `B.B3-11`). **UI-test approach:** the tracker toolchain has no jsdom/@testing-library and vitest only collects `server/**`+`tests/**`, so the components' validation + role-gating logic was extracted to the pure `client/src/lib/risk-acceptance-view.ts` and unit-tested (`tracker/tests/risk-acceptance-view.test.ts`) instead of DOM-render tests (LOOP-B-RISKS `B.B3-12`). **Deferred** (LOOP-B-RISKS `B.B3-EXT-1`): fronting the resident private key with a KMS/HSM (it currently lives PEM-encoded in the `signing_keys` table, as password hashes + session tokens already do). Tests: tracker 99→130 (+31), cloud-evidence 1341→1354 (+13).
  - **T.T5 scope note (2026-07-02):** T.T5 shipped the realizable core deliverable — the signed NIST SP 800-218A SSDF-AI augmentation matrix (`out/ssdf-ai-augmentation.json` + `.sig` + `.xlsx`, plus `out/ssdf-satisfaction-matrix.augmented.json` + `.sig`; detached Ed25519 over RFC-8785 signature-blanked bytes, RFC 3161 coverage via the run manifest TSR). The **real** 800-218A augmentation catalogue is extracted VERBATIM from the published NIST PDFs (`scripts/extract-800-218A.mjs` via `pdf-parse` → `data/ssdf-800-218A-{ipd,final}.json` + `docs/sources/ssdf-800-218A-delta.json`; both source PDFs downloaded from CSRC and committed with `.sha256` siblings). Final catalogue: 20 practices, 48 tasks, 86 R/C/N items, 6 new AI tasks. **Spec reconciliation:** (1) the published 800-218A uses per-task Recommendation/Consideration/Note item ids `<task>.R/.C/.N<n>`, NOT the spec §2.6/§4.1-assumed `<task>.A<n>` (LOOP-T-RISKS `T.T5-16`); (2) 800-218A re-introduces PW.3.1–3.3 + PS.1.2/1.3 + PO.5.3 that base SSDF v1.1 (42 tasks) does not carry, so they are `base_task_present:false` and, absent AI evidence, roll up `requires-operator-input` — never a silent pass (`T.T5-17`); (3) RFC 3161 coverage is the run-manifest TSR (no per-file `.tsr`), consistent with T.T2/T.T3/T.T4 (`T.T5-21`). The pure aggregator (`core/ssdf-ai-extension.ts`) joins the catalogue to the T.T2 matrix + the LOOP-O.O5 model-card registry (`out/model-cards/*.json`) and derives per-augmentation status (satisfied/partially-satisfied/not-satisfied/not-assessed/requires-operator-input/not-applicable) with the §6.6 table; the XLSX renderer (`core/ssdf-ai-extension-xlsx.ts`) emits Summary + per-product (columns A..O) + IPD-vs-final delta + statutory-lineage worksheets. Orchestrator runs T.T5 under the existing `--ssdf-attestation` gate after the T.T2 matrix + before T.T3; three `submission-bundle` WELL_KNOWN roles registered (`ssdf-ai-augmentation-json`, `ssdf-ai-augmentation-xlsx`, `ssdf-satisfaction-matrix-augmented`); `ssdf_ai_augmentation_coverage` sibling added to `inventory-coverage.json` (G2-safe); `config.yaml#ssdf` gained `ai_augmentation_enabled`/`primary_catalogue`/`ai_products_in_scope`. **Realizable-core / graceful degradation (`T.T5-20`):** LOOP-O.O5 is unimplemented, so no model cards exist; the orchestrator step is fully wired + tested against fixtures but no-ops (`coverage:skipped`, reason `no-model-cards`) in a normal run — the same posture as T.T2/T.T3/T.T4/W.W3/W.W4. NEVER fabricates AI evidence (REO Rule 4): an augmentation with no AI-specific evidence inherits its parent task. **Deferred** (tracked LOOP-T-RISKS `T.T5-22`): the React `/ssdf/ai-augmentation` worksheet page (no tracker subsystem in this repo). Shipping T.T5 **completes LOOP-T (5 of 5)**.
  - **T.T4 scope note (2026-07-01):** T.T4 shipped the realizable core regulatory deliverable — the signed SSDF annual re-attestation cadence + material-change detector (`out/ssdf-material-change-events.json` + `.json.sig`, detached Ed25519 over the RFC-8785 signature-blanked bytes, covered by the run manifest + RFC 3161 TSR). Two pure engines per the per-slice §6: (1) `core/ssdf-annual-attestation.ts` — the regime-aware cadence policy table (`m-22-18-mandatory`/`m-23-16-extended` → 365-day general / 270-day EO-critical; `m-26-05-tailored`/`post-m-26-05-future` → 365-day; operator `cadence_override_days` wins) computing the producer's **internal** next-review date (NOT an expiry — the M-23-16 binding clause keeps an attestation in force until the producer notifies the agency; LOOP-T-RISKS T.T4-R1); (2) `core/ssdf-material-change-detector.ts` — diffs successive T.T2 matrix snapshots and emits typed `MaterialChangeEvent`s (`practice_regression` satisfied→not-satisfied [suppressed by an active POA&M override — `requires-operator-input` is a coverage gap, not a regression, T.T4-R2], `new_untestable_practice`, `major_version_bump`, `ai_augmentation_gap`, `regime_change`, `agency_added`) with the §6 Step 7/8 notification-clock (14d / 30d / null) + `triggers_reattestation` policy; event ids are uuid-v5 content-derived for idempotent re-runs (T.T4-T13). The realizable persistence layer stands in for the spec's tracker/storage: prior matrix snapshots are content-addressed at `out/ssdf-attestation-snapshots/<product>/<sha256>.json`, the append-only run index at `out/ssdf-attestation-ledger.jsonl`. Orchestrator runs the detector under the existing `--ssdf-attestation` gate AFTER the T.T2 matrix emit + BEFORE T.T3/signing; three `submission-bundle` WELL_KNOWN roles registered (`ssdf-material-change-events-json`, `ssdf-attestation-ledger`, `ssdf-attestation-snapshot`); `ssdf_material_change_coverage` sibling added to `inventory-coverage.json` (G2-safe). `config.yaml#ssdf.products[]` gained the optional T.T4 cadence fields (`regime` enum, `continuous_delivery`, `major_version_pattern`, `cadence_override_days`, `poam_extension_allowed`, `federal_agencies[]`); an absent `regime` yields a `requires-operator-input` diagnostic (never a fabricated mandatory default, REO Rule 4). **Deferred** (tracked LOOP-T-RISKS `T.T4-21..24`): the four SQLite tables (`ssdf_products`/`ssdf_attestation_submissions`/`ssdf_practice_overrides`/`ssdf_material_change_events`), the REST routes + `ssdf-service`, the three React panes (status/products/material-changes) + RBAC roles, and the operator signed-PDF-SHA-256 / RSAA-submission-id capture + force-reattestation / withdrawal / legal-review actions — no tracker subsystem exists in this repo (no `pg`/`express`/`react`/`better-sqlite3`), the same posture as T.T2/T.T3/W.W3/W.W4. NEVER auto-signs the officer attestation and NEVER files with an agency / CISA RSAA (REO Rule 4) — those are human actions in the deferred tracker layer. The STATUS T.T4 table-row title was reconciled to the per-slice-doc / SPEC §3 title (the prior "Third-party software components attestation appendix" label was stale — that scope belongs to T.T5's AI extension, not T.T4).
  - **T.T3 scope note (2026-06-21):** T.T3 shipped the realizable core regulatory deliverable — the CISA Secure Software Development Attestation Common Form (OMB Control Number `1670-0052`, expiration `03/31/2027`) as an **unsigned** canonical PDF (`out/cisa-common-form-1670-0052.pdf`) + a signed canonical-JSON shadow (`out/cisa-common-form-1670-0052.json` + `.json.sig`, detached Ed25519 over the RFC-8785 signature-blanked bytes, covered by the run manifest + RFC 3161 TSR; the `.pdf` rides the same manifest via `core/sign.ts`'s by-extension signing — no sign-glob edit needed). The four Section IV attestation selections are computed **deterministically from the real T.T2 satisfaction matrix**: each §IV(n) clause's selection ∈ {comply, comply-with-conditions, cannot-comply, not-yet-determined} reduces over the union of its in-scope tasks' statuses (a `requires-operator-input`/`not-assessed` task forces `not-yet-determined` — never a silent `comply`; a `cannot-comply` clause MUST cite ≥1 POA&M item or it throws `MissingPoamReferenceError`). Producer identity comes from `config.yaml#ssdf.producer` (validated up front — every missing required field is collected and thrown as `MissingOperatorInputError`); the signature/date lines are left blank for the corporate officer (REO Rule 1.10 — the system never auto-signs; T.T4 binds the officer signature). New orchestrator `--ssdf-common-form` (env `CLOUD_EVIDENCE_SSDF_COMMON_FORM`; implies `--ssdf-attestation`) runs after the T.T2 matrix + A.A1 POA&M emit and before signing; two `submission-bundle` WELL_KNOWN roles registered (`ssdf-common-form-pdf`, `ssdf-common-form-json`); per-product `ssdf_common_form_fill_rate` sibling added to `inventory-coverage.json` (G2-safe). **Spec reconciliation:** the T.T3.md §4/§5 idealised inputs (`out/ssdf-practice-map.json` + `out/ssdf-evidence-binding.json`; status enum implemented/…/not-applicable; the illustrative per-task `CISA_PRACTICE_TO_SSDF` table at 1.a–4.c granularity) are stale — the real input is the single `ssdf-satisfaction-matrix.json` (statuses satisfied/partially-satisfied/not-satisfied/not-assessed/requires-operator-input), and the authoritative CISA mapping is the T.T1 catalogue's `COMMON_FORM_TASK_MAP` (§IV(1)→Practice 1 … §IV(4)→Practice 4), surfaced per-task as `common_form_section_ref`; the 1.a–1.f / 4.a–4.c sub-items are verbatim form text rendered under each practice, not separately evidence-bound (LOOP-T-RISKS `T.T3-19`). **Deferred** (tracked LOOP-T-RISKS `T.T3-20..22`): the binary CISA template PDF + CISA/OMB logo assets the spec §7 lists are not fetched in this clean-room tree — the verbatim Section IV text is reproduced from the public record (per-slice §2.4) and the PDF renders a text-only header; PDF/A-3b font embedding falls back to dependency-free PDF 1.4 (spec §5.1-permitted); electronic signature binding + RSAA submission are T.T4. NEVER files with CISA/an agency (REO Rule 4) — the operator signs + submits.
  - **T.T2 scope note (2026-06-20):** T.T2 shipped the realizable core deliverable — the signed per-practice × per-task SSDF satisfaction matrix (`out/ssdf-satisfaction-matrix.json` + `.sig` + `.xlsx`, canonical-JSON + detached Ed25519, covered by the run manifest + RFC 3161 TSR), joining the committed T.T1 catalogue to the run's REAL evidence corpus: signed KSI envelopes (`out/KSI-*.json`, joined per-practice via `fedramp_ksi_forward_map`), `risk-scores.json` (B.B1 composite → per-practice open-risk), `subprocessor-inventory.json` (J.J2), `supply-chain-risk-register.json` (J.J3), `sbom-report.json` (E.E2), and `poam.json` (A.A1, control-based secondary join). Status per task ∈ {satisfied, partially-satisfied, not-satisfied, not-assessed, requires-operator-input}; a task with zero pointers is `requires-operator-input` (never a silent pass — enforced by the new `npm run check:ssdf-no-silent-pass` guardrail wired into `check:reo`). Orchestrator `--ssdf-attestation` (env `CLOUD_EVIDENCE_SSDF_ATTESTATION`) wiring runs the pass after all per-loop emitters + before signing; two `submission-bundle` WELL_KNOWN roles registered. **Spec reconciliation:** the T.T2.md §4/§5 idealised schema assumed per-TASK `crosswalk_ksi[]`/`crosswalk_800_53_r5[]` and 43 tasks; the committed T.T1 catalogue carries those crosswalks per-PRACTICE (`fedramp_ksi_forward_map`, `nist_800_53_r5_controls`) with Common Form refs per-task, and 42 active tasks (PW.3 withdrawn in v1.1). The matrix therefore joins evidence at the practice level and attributes the pointer set to each of the practice's tasks (documented in LOOP-T-RISKS `T.T2-16`). The tracker process-artefact pointer kind + per-agency tracker DB (T.T2.md §4 #11 / §11) are **deferred** (no tracker subsystem exists in this repo — no `pg`/`express`/`react`; tracked as `T.T2-17`). Cosign / build-attestation state is not collected as a standalone artefact in this repo, so PS.2/PW.6 release-integrity evidence keys off SBOM presence only (tracked as `T.T2-18`); the coverage boundary is surfaced in `provenance.coverageDiagnostics`.
  - **W.W4 scope note (2026-06-18):** W.W4 shipped the realizable core regulatory deliverable — the signed FAR 52.204-26 annual representation pair (canonical-JSON envelope + printable `.docx`) driven deterministically from the W.W2 screen's non-suppressed matches: the (c)(1) "provides" answer keys off the subprocessor-sheet + inventory provider-tag surfaces, the (c)(2) "uses" answer off every non-suppressed match (FAR 4.2102 "use" is broader than provision-to-Government); plus W.W3 incident linking (read from the `section889-1bd-reports.jsonl` ledger by `match_id`), the append-only `section889-annual-reps.jsonl` ledger (delta + flip detection), the LOOP-Q.Q1 `marketplace-section889-badge.json` feed (enabled iff both answers "does not" AND within validity), SR-1/3/5/6/11 control cross-reference, 365-day `valid_until` (FAR 52.204-8(d)), submission-bundle registration, and orchestrator `--section889-annual-rep` wiring. Mandatory operator fields (UEI, officer block, methodology doc) are validated before any write; the actual input is the real `out/prohibited-vendors-screen-result.json` (the spec §4.1 `out/prohibited-vendors-matches.json` name was stale — same posture as W.W3). The tracker DB table (`section889_annual_reps`) / REST routes / React review-sign-off UI / SAM-receipt paste-back + officer-keyring expiry checks described in the per-slice §5.3/§7 are **deferred** (no tracker subsystem exists in this repo — no `pg`/`express`/`react`); tracked as LOOP-W-RISKS `W.W4-EXT-1..4`. NEVER files the representation in SAM.gov (REO Rule 4) — the operator submits.
  - **W.W3 scope note (2026-06-18):** W.W3 shipped the realizable core regulatory deliverable — the signed FAR 52.204-25(d) report pair (canonical JSON + `.docx`) per (match × affected contract), federal-business-day deadline (`core/section889-clock.ts` composing `bizdays.ts`), statutory citations, append-only ledger (idempotency + audit), inventory-coverage augmentation, submission-bundle registration, orchestrator `--prohibited-vendor-1bd-report` wiring, and an injectable notification seam. The tracker DB / REST routes / React countdown UI / `scheduled_notifications` daemon described in the per-slice §5.4/§7 are **deferred** (no tracker subsystem exists in this repo — no `pg`/`express`/`react`); tracked as LOOP-W-RISKS `W.W3-17`. The STATUS row title was reconciled to the per-slice-doc title (the prior "SBOM crosscheck" label was stale; SBOM walking is owned by W.W2 per W.W3.md §3.2).
  - **Dependency-metadata note (discovered 2026-06-10; RESOLVED 2026-06-18):** the W.W2 row's `Dependencies` column previously read `W.W1, J.J2`, inconsistent with the W.W2 per-slice-doc frontmatter (`W.W1, E.E2, J.J3, A.A1, A.A5, B.B1`). The W.W2 row was reconciled to the frontmatter when W.W2 shipped (this session). No further action; see `docs/loops/LOOP-B-RISKS.md` risk B.B1-EXT-1.

## Out-of-Core / Roadmap (NOT on the implementation queue)
Parallel compliance regimes; preserved as research material under
`docs/roadmap/`. See `docs/roadmap/README.md` for the scope-fence
rationale.

| Out-of-core loop | What it is | Roadmap doc |
|---|---|---|
| LOOP-U Privacy frameworks | FERPA / COPPA / GLBA / CCPA / CPRA / GDPR / UK GDPR / NY SHIELD / 50-state breach matrix / Schrems II | `docs/roadmap/loops/LOOP-U-{SPEC,RISKS}.md` + `docs/roadmap/slices/U/` |
| LOOP-V Healthcare overlay | HIPAA Security Rule + Breach Notification + BAA + NIST SP 800-66 R2 + HITRUST CSF v11.2.0 | `docs/roadmap/loops/LOOP-V-{SPEC,RISKS}.md` + `docs/roadmap/slices/V/` |
| LOOP-Y Sector overlays | CJIS Security Policy v5.9.5 + IRS Publication 1075 | `docs/roadmap/loops/LOOP-Y-{SPEC,RISKS}.md` + `docs/roadmap/slices/Y/` |
| LOOP-Z International | ISO/IEC 27001:2022 + 27017 + 27018 + 27701 + ENISA EUCS | `docs/roadmap/loops/LOOP-Z-{SPEC,RISKS}.md` + `docs/roadmap/slices/Z/` |
| FIFTH-PASS-AUDIT candidates | PCI-DSS, CMMC, FedRAMP Tailored, TIC 3.0, SOC 2, ISMAP/IRAP/TISAX, StateRAMP, NSM-22, AI EOs, Section 508, FIPS 140-3, CISA CPGs, etc. | `docs/roadmap/FIFTH-PASS-AUDIT.md` |

> **Note on LOOP-L through LOOP-Q (2026-06-07):** `ADDITIONAL-LOOPS-AUDIT.md`
> (2026-06-06) surfaced 6 net-new loops (L–Q). The human has ratified the
> audit and all six are now fully specified (`docs/loops/LOOP-{L,M,N,O,P,Q}-SPEC.md`
> + 25 per-slice docs under `docs/slices/{L,M,N,O,P,Q}/` + 6 risks registers).
> LOOP-M (Privacy/SORN/DPIA) and LOOP-O (AI/ML Governance) are now
> **confirmed applicable** (no longer conditional on operator decisions).
> Next-priority remains LOOP-B.B1 — risk scoring is still the highest-priority
> enabling slice for I, F, E, and (now) N + O. LOOP-L.L1 is queued
> immediately behind B.B1. A second-pass audit (`docs/SECOND-PASS-AUDIT.md`)
> ran after L-Q specification to confirm nothing else is still missing.

> **Note on LOOP-R, LOOP-S, CIRCIA extensions (2026-06-07):** A third-pass
> audit (`docs/THIRD-PASS-AUDIT.md`) surfaced three additional bodies of
> work that the second-pass audit missed: (a) Post-Quantum Cryptography
> migration per NIST IR 8547 + OMB M-23-02 + NSM-10 + NSA CNSA 2.0
> (LOOP-R, 3 slices, applicable to all CSPs because PQC migration is
> federally mandated), (b) DFARS 252.204-7012 Cloud Equivalency for
> DoD-prime customers (LOOP-S, 3 slices, **conditional** — only required
> when the CSP has or pursues DoD-prime customers running Covered Defense
> Information workloads on the CSO), and (c) **CIRCIA Final Rule 72-hour
> incident reporting** extensions to G.G2 (Incident Communications
> Procedures) and M.M4 (Privacy incident response) — these are
> **HIGH-PRIORITY** because CIRCIA's effective date is May 2026 and any
> CSP processing critical-infrastructure-related workloads is a Covered
> Entity. CIRCIA extensions are tracked as overlay slices that MUST ship
> in the same commit as the parent slice (G.G2 / M.M4) or be explicitly
> tracked as a follow-up. The human may elevate CIRCIA extensions above
> LOOP-B.B1 once basic CSP operations need to be CIRCIA-compliant.

## Pre-flight
| ID | Title | Status | Commit | Date |
|---|---|---|---|---|
| REO-0 | Real-Evidence-Only standard + CI guardrails | done | `794457b` | (per CHANGELOG) |
| R1 | FRMR walk for AFR family classification | done | `794457b` | (per CHANGELOG) |
| R2 | Monthly POA&M delta format research | done | `7a95221` | (per CHANGELOG) |
| R3 | Phase Two pilot output format check | done | `7a95221` | (per CHANGELOG) |
| R4 | Sample selection methodology research | done | `7a95221` | (per CHANGELOG) |

## LOOP-A — OSCAL Package Completeness (COMPLETE)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| A.A1 | OSCAL POA&M emitter | done | `7a95221` | — | (in EXECUTION-PLAN.md) | — |
| A.A2 | OSCAL Assessment Plan emitter | done | `4f2170b` | — | (in EXECUTION-PLAN.md) | — |
| A.A3 | AR import-AP chain wiring | done | `553637c` | — | (in EXECUTION-PLAN.md) | — |
| A.A4 | Submission package bundler | done | `ecf1525` | — | (in EXECUTION-PLAN.md) | — |
| A.A5 | Rules of Engagement template seed | done | `469049f` | — | (in EXECUTION-PLAN.md) | — |

## LOOP-B — Risk + Remediation Engine (COMPLETE)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| B.B1 | Per-finding CVSS+EPSS+criticality+exposure scoring | done | `22b6590` | 2026-06-10 | `docs/loops/LOOP-B-SPEC.md` | `docs/slices/B/B.B1.md` |
| B.B2 | Remediation deadline math (KEV/PAIN/IRV/LEV) | done | `f25255d` | 2026-06-11 | `docs/loops/LOOP-B-SPEC.md` | `docs/slices/B/B.B2.md` |
| B.B3 | Risk acceptance workflow (tracker DB + signed audit record + OSCAL deviation-approved propagation) | done | `99f5afe` | 2026-07-02 | `docs/loops/LOOP-B-SPEC.md` | `docs/slices/B/B.B3.md` |
| B.B4 | Compensating-controls registry | done | `6b5168d` | 2026-07-02 | `docs/loops/LOOP-B-SPEC.md` | `docs/slices/B/B.B4.md` |
| B.B5 | Central Risk Register (RA-3) | done | `d16ae8d` | 2026-07-02 | `docs/loops/LOOP-B-SPEC.md` | `docs/slices/B/B.B5.md` |

## LOOP-C — Document Template Pack
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| C.C1 | Configuration Management Plan (CMP) | done | `99c283a` | 2026-07-07 | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C1.md` |
| C.C2 | Information System Contingency Plan (ISCP) + Test AAR | done | `e660109` | 2026-07-07 | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C2.md` |
| C.C3 | Incident Response Plan (IRP) + Test AAR | done | `<TBD-step6>` | 2026-07-07 | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C3.md` |
| C.C4 | Privacy Threshold Analysis (PTA) + PIA | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C4.md` |
| C.C5 | FIPS 199 categorization worksheet | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C5.md` |
| C.C6 | Continuous Monitoring Strategy + Plan | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C6.md` |
| C.C7 | Risk Management Strategy (RMS) | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C7.md` |
| C.C8 | Authorization request cover letter | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C8.md` |
| C.C9 | Baseline Configuration document (CM-2) | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C9.md` |

## LOOP-D — Diagram Auto-Generation
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| D.D1 | Authorization Boundary Diagram | pending | — | — | `docs/loops/LOOP-D-SPEC.md` | `docs/slices/D/D.D1.md` |
| D.D2 | Network Diagram | pending | — | — | `docs/loops/LOOP-D-SPEC.md` | `docs/slices/D/D.D2.md` |
| D.D3 | Data Flow Diagram | pending | — | — | `docs/loops/LOOP-D-SPEC.md` | `docs/slices/D/D.D3.md` |

## LOOP-E — Continuous Monitoring Agent
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| E.E1 | Monthly ConMon analysis report | done | `ddfa499` | 2026-06-11 | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E1.md` |
| E.E2 | Monthly POA&M delta workflow | done | `fb6831a` | 2026-06-11 | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E2.md` |
| E.E3 | Annual Assessment package generator | pending | — | — | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E3.md` |
| E.E4 | Annual SSP review/update workflow | pending | — | — | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E4.md` |
| E.E5 | Deviation Request (DR) emitter | pending | — | — | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E5.md` |
| E.E6 | Formal SCN doc emitter | pending | — | — | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E6.md` |
| E.E7 | Annual IRP/ISCP test cadence runner | pending | — | — | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E7.md` |

## LOOP-F — 3PAO Assessor Experience
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| F.F1 | 3PAO sign-off UI in tracker | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F1.md` |
| F.F2 | Comment threads on findings | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F2.md` |
| F.F3 | Sample selection methodology auto-derive | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F3.md` |
| F.F4 | Evidence walk-through artifacts | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F4.md` |
| F.F5 | 3PAO recommendation letter template | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F5.md` |
| F.F6 | Full ATO workflow tracker (PM-10) | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F6.md` |
| F.F7 | SAR draft generator | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F7.md` |

## LOOP-G — AFR Family (20x deliverables)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| G.G1 | AFR-FSI (FedRAMP Security Inbox) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G1.md` |
| G.G2 | AFR-ICP (Incident Communications Procedures) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G2.md` |
| G.G3 | AFR-ADS (Authorization Data Sharing) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G3.md` |
| G.G4 | AFR-MAS (Minimum Assessment Scope) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G4.md` |
| G.G5 | AFR-SCG (Secure Configuration Guide) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G5.md` |
| G.G6 | AFR-CCM (Continuous Monitoring per 20x) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G6.md` |

## LOOP-H — Long-Term Storage + Multi-CSO
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| H.H1 | Immutable evidence archive | pending | — | — | `docs/loops/LOOP-H-SPEC.md` | `docs/slices/H/H.H1.md` |
| H.H2 | Audit retention policy enforcement (AU-11) | pending | — | — | `docs/loops/LOOP-H-SPEC.md` | `docs/slices/H/H.H2.md` |
| H.H3 | Multi-CSO support | pending | — | — | `docs/loops/LOOP-H-SPEC.md` | `docs/slices/H/H.H3.md` |

## LOOP-I — Stakeholder Dashboards
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| I.I1 | Executive posture dashboard | pending | — | — | `docs/loops/LOOP-I-SPEC.md` | `docs/slices/I/I.I1.md` |
| I.I2 | Finding burndown + deadline pipeline | pending | — | — | `docs/loops/LOOP-I-SPEC.md` | `docs/slices/I/I.I2.md` |
| I.I3 | Longitudinal trend analysis | pending | — | — | `docs/loops/LOOP-I-SPEC.md` | `docs/slices/I/I.I3.md` |
| I.I4 | SSP narrative library completion | pending | — | — | `docs/loops/LOOP-I-SPEC.md` | `docs/slices/I/I.I4.md` |

## LOOP-J — Supply Chain + Privileges
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| J.J1 | User Roles & Privileges matrix (AC-2 + AC-6) | pending | — | — | `docs/loops/LOOP-J-SPEC.md` | `docs/slices/J/J.J1.md` |
| J.J2 | Subprocessor inventory expansion (SA-9) | done | `3e3d6c5` | 2026-06-11 | `docs/loops/LOOP-J-SPEC.md` | `docs/slices/J/J.J2.md` |
| J.J3 | Supply chain risk register (SR-3) + SBOM | done | `a635da4` | 2026-06-11 | `docs/loops/LOOP-J-SPEC.md` | `docs/slices/J/J.J3.md` |

## LOOP-K — Test Artifact Ingestion
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| K.K1 | PenTest report ingest schema + tracker display | pending | — | — | `docs/loops/LOOP-K-SPEC.md` | `docs/slices/K/K.K1.md` |
| K.K2 | 3PAO test results matrix → OSCAL AR test-result-objects | pending | — | — | `docs/loops/LOOP-K-SPEC.md` | `docs/slices/K/K.K2.md` |

## LOOP-L — Customer Responsibility Matrix + Leveraged-Authorization Inheritance
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| L.L1 | CRM Workbook generator (SSP Appendix J) | pending | — | — | `docs/loops/LOOP-L-SPEC.md` | `docs/slices/L/L.L1.md` |
| L.L2 | Inherited-controls tracker + Leveraged-Authorization enumeration | pending | — | — | `docs/loops/LOOP-L-SPEC.md` | `docs/slices/L/L.L2.md` |
| L.L3 | CRM Gap Report | pending | — | — | `docs/loops/LOOP-L-SPEC.md` | `docs/slices/L/L.L3.md` |
| L.L4 | Per-control Responsibility Split Renderer | pending | — | — | `docs/loops/LOOP-L-SPEC.md` | `docs/slices/L/L.L4.md` |

## LOOP-M — Privacy Package Extension (SORN + DPIA) — CONFIRMED APPLICABLE
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| M.M1 | System of Records Notice (SORN) emitter — Privacy Act §552a | pending | — | — | `docs/loops/LOOP-M-SPEC.md` | `docs/slices/M/M.M1.md` |
| M.M2 | Data Protection Impact Assessment (DPIA) for cross-border / agency-partner data | pending | — | — | `docs/loops/LOOP-M-SPEC.md` | `docs/slices/M/M.M2.md` |
| M.M3 | PT-family controls inventory (PT-1..PT-8) beyond PTA/PIA scope | pending | — | — | `docs/loops/LOOP-M-SPEC.md` | `docs/slices/M/M.M3.md` |
| M.M4 | Privacy incident response procedures (PT-7 + breach notification per OMB M-17-12) | pending | — | — | `docs/loops/LOOP-M-SPEC.md` | `docs/slices/M/M.M4.md` |

## LOOP-N — Threat Modeling + Adversarial Validation
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| N.N1 | STRIDE threat model generator (per-component, from inventory + DFD) | pending | — | — | `docs/loops/LOOP-N-SPEC.md` | `docs/slices/N/N.N1.md` |
| N.N2 | Attack surface enumeration (boundary entry points + exposed services) | pending | — | — | `docs/loops/LOOP-N-SPEC.md` | `docs/slices/N/N.N2.md` |
| N.N3 | PASTA / red-team adversarial test framework (automated adversarial runs) | pending | — | — | `docs/loops/LOOP-N-SPEC.md` | `docs/slices/N/N.N3.md` |
| N.N4 | MITRE ATT&CK technique mapping (which techniques apply to our boundary) | pending | — | — | `docs/loops/LOOP-N-SPEC.md` | `docs/slices/N/N.N4.md` |

## LOOP-O — AI/ML Governance per NIST AI RMF + OMB M-24-10 — CONFIRMED APPLICABLE
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| O.O1 | AI/ML asset inventory (models, training data, inference endpoints) | pending | — | — | `docs/loops/LOOP-O-SPEC.md` | `docs/slices/O/O.O1.md` |
| O.O2 | NIST AI RMF alignment (GOVERN / MAP / MEASURE / MANAGE) | pending | — | — | `docs/loops/LOOP-O-SPEC.md` | `docs/slices/O/O.O2.md` |
| O.O3 | AI risk register (bias, fairness, robustness, adversarial) | pending | — | — | `docs/loops/LOOP-O-SPEC.md` | `docs/slices/O/O.O3.md` |
| O.O4 | AI evaluation per OMB M-24-10 (pre-deployment + ongoing) | pending | — | — | `docs/loops/LOOP-O-SPEC.md` | `docs/slices/O/O.O4.md` |
| O.O5 | Model card + datasheet emitter | pending | — | — | `docs/loops/LOOP-O-SPEC.md` | `docs/slices/O/O.O5.md` |

## LOOP-P — Insider Threat + PS-family Workforce Security
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| P.P1 | Insider Threat Program documentation + tracker workflow | pending | — | — | `docs/loops/LOOP-P-SPEC.md` | `docs/slices/P/P.P1.md` |
| P.P2 | Position risk designation per role (PS-2 + PS-3 screening) | pending | — | — | `docs/loops/LOOP-P-SPEC.md` | `docs/slices/P/P.P2.md` |
| P.P3 | Personnel transfer + termination procedures (PS-4 + PS-5) | pending | — | — | `docs/loops/LOOP-P-SPEC.md` | `docs/slices/P/P.P3.md` |
| P.P4 | Access agreements + acknowledgments + NDA (PS-6) | pending | — | — | `docs/loops/LOOP-P-SPEC.md` | `docs/slices/P/P.P4.md` |
| P.P5 | Continuous workforce monitoring + behavioral analytics | pending | — | — | `docs/loops/LOOP-P-SPEC.md` | `docs/slices/P/P.P5.md` |

## LOOP-Q — Marketplace + Post-ATO Publication
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| Q.Q1 | FedRAMP Marketplace listing emitter (per RFC-0021 format) | pending | — | — | `docs/loops/LOOP-Q-SPEC.md` | `docs/slices/Q/Q.Q1.md` |
| Q.Q2 | Post-ATO ConMon publication (monthly delivery to FedRAMP secure repository) | pending | — | — | `docs/loops/LOOP-Q-SPEC.md` | `docs/slices/Q/Q.Q2.md` |
| Q.Q3 | Agency authorization tracking (who is using the CSO + their authorization documents) | pending | — | — | `docs/loops/LOOP-Q-SPEC.md` | `docs/slices/Q/Q.Q3.md` |

## LOOP-R — Post-Quantum Cryptography Migration
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| R.R1 | Cryptographic Inventory Collector | pending | — | — | `docs/loops/LOOP-R-SPEC.md` | `docs/slices/R/R.R1.md` |
| R.R2 | Migration Plan Emitter | pending | — | — | `docs/loops/LOOP-R-SPEC.md` | `docs/slices/R/R.R2.md` |
| R.R3 | Annual PQC Report Emitter | pending | — | — | `docs/loops/LOOP-R-SPEC.md` | `docs/slices/R/R.R3.md` |

## LOOP-S — DFARS 252.204-7012 Cloud Equivalency (conditional: DoD-prime customers)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| S.S1 | NIST 800-171 Rev 3 → FedRAMP Moderate Crosswalk | pending | — | — | `docs/loops/LOOP-S-SPEC.md` | `docs/slices/S/S.S1.md` |
| S.S2 | Cyber Incident Reporting per DFARS 252.204-7012(c) | pending | — | — | `docs/loops/LOOP-S-SPEC.md` | `docs/slices/S/S.S2.md` |
| S.S3 | Cloud Equivalency Attestation Package | pending | — | — | `docs/loops/LOOP-S-SPEC.md` | `docs/slices/S/S.S3.md` |

## LOOP-W — Prohibited Vendors (COMPLETE — statutorily gates submission package)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc | Dependencies | Last updated |
|---|---|---|---|---|---|---|---|---|
| W.W1 | Prohibited-vendor catalog ingester + canonical-JSON emitter (OFAC SDN + BIS Entity List + SAM Exclusions + FAR 52.204-25 + NDAA §889 + NDAA §1634 + FASCSA) | done | `be78723` | 2026-06-08 | `docs/loops/LOOP-W-SPEC.md` | `docs/slices/W/W.W1.md` | — | 2026-06-08 |
| W.W2 | Subprocessor + SBOM + OCI image screening against prohibited-vendor catalog | done | `5e7d2e2` | 2026-06-18 | `docs/loops/LOOP-W-SPEC.md` | `docs/slices/W/W.W2.md` | W.W1, E.E2, J.J3, A.A1, A.A5, B.B1 | 2026-06-18 |
| W.W3 | FAR 52.204-25(d) 1-Business-Day Prohibited-Vendor Discovery Reporter | done | `235c397` | 2026-06-18 | `docs/loops/LOOP-W-SPEC.md` | `docs/slices/W/W.W3.md` | W.W1, W.W2, A.A1, A.A4, A.A5, B.B1, tracker DB | 2026-06-18 |
| W.W4 | Section 889 Part B Annual Representation (FAR 52.204-26) — signed JSON envelope + printable `.docx` | done | `e44cd85` | 2026-06-18 | `docs/loops/LOOP-W-SPEC.md` | `docs/slices/W/W.W4.md` | W.W2, A.A5 | 2026-06-18 |

## LOOP-T — NIST SSDF + CISA Secure Software Development Attestation Common Form (COMPLETE)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc | Dependencies | Last updated |
|---|---|---|---|---|---|---|---|---|
| T.T1 | NIST SSDF (SP 800-218) practice inventory + control mapping | done | `9bbbcd1` | 2026-06-10 | `docs/loops/LOOP-T-SPEC.md` | `docs/slices/T/T.T1.md` | — | 2026-06-10 |
| T.T2 | Per-Practice Evidence Aggregator + Satisfaction Matrix | done | `9744702` | 2026-06-20 | `docs/loops/LOOP-T-SPEC.md` | `docs/slices/T/T.T2.md` | T.T1, B.B1, J.J2, J.J3 | 2026-06-20 |
| T.T3 | CISA Secure Software Development Attestation Common Form emitter (OMB M-22-18 / M-23-16) | done | `4feaa6f` | 2026-06-21 | `docs/loops/LOOP-T-SPEC.md` | `docs/slices/T/T.T3.md` | T.T1, T.T2 | 2026-06-21 |
| T.T4 | Annual SSDF Re-Attestation Workflow + Material-Change Detector (OMB M-23-16 §III cadence + binding-clause trigger) | done | `ed4f906` | 2026-07-01 | `docs/loops/LOOP-T-SPEC.md` | `docs/slices/T/T.T4.md` | T.T3, A.A4; Tracker DB deferred | 2026-07-01 |
| T.T5 | SP 800-218A SSDF-AI Extension — augment the T.T2 satisfaction matrix with 800-218A AI-model R/C/N items for LOOP-O.O5-in-scope products | done | `b5e9b03` | 2026-07-02 | `docs/loops/LOOP-T-SPEC.md` | `docs/slices/T/T.T5.md` | T.T2, LOOP-O.O5 (graceful-degrade) | 2026-07-02 |

## LOOP-X — Zero Trust Architecture compliance (OMB M-22-09 + NIST SP 800-207/207A + CISA ZTMM v2.0)
| Slice | Title | Status | Commit | Spec | Doc | Dependencies | Last updated |
|---|---|---|---|---|---|---|---|
| X.X1 | ZT pillar inventory (Identity / Devices / Networks / Apps / Data + cross-cutting capabilities) | proposed | TBD | `docs/loops/LOOP-X-SPEC.md` | `docs/slices/X/X.X1.md` | A.A5 | 2026-06-08 |
| X.X2 | NIST SP 800-207 architecture mapping (PDP/PEP placement + trust algorithm) | proposed | TBD | `docs/loops/LOOP-X-SPEC.md` | `docs/slices/X/X.X2.md` | X.X1, INV-S | 2026-06-08 |
| X.X3 | NIST SP 800-207A cloud-native ZTA (service mesh, sidecar, k8s admission, API gateway) | proposed | TBD | `docs/loops/LOOP-X-SPEC.md` | `docs/slices/X/X.X3.md` | X.X2, E.1, J.J3 | 2026-06-08 |
| X.X4 | CISA ZTMM v2.0 maturity scoring (per-pillar Traditional/Initial/Advanced/Optimal scorecard .docx) | proposed | TBD | `docs/loops/LOOP-X-SPEC.md` | `docs/slices/X/X.X4.md` | X.X1-X.X3, A.A4, A.A5 | 2026-06-08 |
| X.X5 | PDP / PEP integration evidence (k8s NetworkPolicy, AWS VPC SG, GCP firewall, Azure NSG, OPA/Gatekeeper, Istio AuthorizationPolicy) | proposed | TBD | `docs/loops/LOOP-X-SPEC.md` | `docs/slices/X/X.X5.md` | X.X2, X.X3, INV-S | 2026-06-08 |

## Out-of-Core / Overlay loops — see `docs/roadmap/`

LOOP-U (Privacy frameworks), LOOP-V (HIPAA Healthcare), LOOP-Y
(CJIS + IRS Pub 1075), and LOOP-Z (ISO 27001/27017/27018/27701 +
ENISA EUCS) were scope-fenced out of core FedPy and relocated to
`cloud-evidence/docs/roadmap/loops/` + `cloud-evidence/docs/roadmap/slices/`.
They are preserved as research / roadmap reference, not as
implementation work. The FIFTH-PASS-AUDIT.md candidates
(LOOP-AA through LOOP-GG: PCI-DSS / CMMC / FedRAMP Tailored / TIC 3.0
/ SOC 2 / ISMAP/IRAP/TISAX / StateRAMP / NSM-22 / AI EOs / Section 508 /
FIPS 140-3 / CISA CPGs / etc.) are also roadmap-only.

Read `docs/roadmap/README.md` and the **Scope Guard** block in
`cloud-evidence/CLAUDE.md` before referencing anything in that folder.
The scope-fence policy is: do not propose moving these back to core
without an explicit mission re-statement from the user.

## CIRCIA Extensions + Overlays (HIGH PRIORITY — May 2026 effective for CIRCIA; SEC 8-K is in force today)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| G.G2.CIRCIA | CIRCIA 72-hour incident reporting extension | pending | — | — | `docs/CIRCIA-WORKFLOW.md` | `docs/slices/G/G.G2-CIRCIA-EXTENSION.md` |
| M.M4.CIRCIA | CIRCIA + Privacy Act incident harmonization | pending | — | — | `docs/CIRCIA-WORKFLOW.md` | `docs/slices/M/M.M4-CIRCIA-EXTENSION.md` |
| G.G2-SEC-8K | SEC Item 1.05 Form 8-K cyber-incident disclosure overlay (four-business-day clock; applies when CSP is an SEC-registrant or subsidiary thereof) | proposed | TBD | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G2-SEC-8K-EXTENSION.md` |

## Per-loop risks registers
Each loop has a dedicated risks register listing implementation,
schedule, dependency, and external risks discovered during planning +
slice authoring. Update the register every time a slice surfaces a new
risk (per the Strong-Directive in `cloud-evidence/CLAUDE.md`).

| Register | Loop | Path |
|---|---|---|
| LOOP-B risks | Risk + Remediation Engine | `docs/loops/LOOP-B-RISKS.md` |
| LOOP-C risks | Document Template Pack | `docs/loops/LOOP-C-RISKS.md` |
| LOOP-D risks | Diagram Auto-Generation | `docs/loops/LOOP-D-RISKS.md` |
| LOOP-E risks | Continuous Monitoring Agent | `docs/loops/LOOP-E-RISKS.md` |
| LOOP-F risks | 3PAO Assessor Experience | `docs/loops/LOOP-F-RISKS.md` |
| LOOP-G risks | AFR Family | `docs/loops/LOOP-G-RISKS.md` |
| LOOP-H risks | Long-Term Storage + Multi-CSO | `docs/loops/LOOP-H-RISKS.md` |
| LOOP-I risks | Stakeholder Dashboards | `docs/loops/LOOP-I-RISKS.md` |
| LOOP-J risks | Supply Chain + Privileges | `docs/loops/LOOP-J-RISKS.md` |
| LOOP-K risks | Test Artifact Ingestion | `docs/loops/LOOP-K-RISKS.md` |
| LOOP-L risks | CRM + Leveraged-Authorization Inheritance | `docs/loops/LOOP-L-RISKS.md` |
| LOOP-M risks | Privacy Package Extension (SORN + DPIA) | `docs/loops/LOOP-M-RISKS.md` |
| LOOP-N risks | Threat Modeling + Adversarial Validation | `docs/loops/LOOP-N-RISKS.md` |
| LOOP-O risks | AI/ML Governance | `docs/loops/LOOP-O-RISKS.md` |
| LOOP-P risks | Insider Threat + PS-family | `docs/loops/LOOP-P-RISKS.md` |
| LOOP-Q risks | Marketplace + Post-ATO Publication | `docs/loops/LOOP-Q-RISKS.md` |
| LOOP-R risks | Post-Quantum Cryptography Migration | `docs/loops/LOOP-R-RISKS.md` |
| LOOP-S risks | DFARS 252.204-7012 Cloud Equivalency | `docs/loops/LOOP-S-RISKS.md` |

## Cross-cutting references
Reference docs that span every loop. Read these whenever planning
across loops, onboarding a new contributor, or answering a "where
does X term come from" question.

| Doc | Purpose | Path |
|---|---|---|
| Dependency graph | Mermaid + tabular dependency map for every slice; critical path; parallelization streams | `docs/DEPENDENCY-GRAPH.md` |
| Glossary | A–Z of every FedRAMP / NIST / OSCAL / internal term used in the spec corpus (90+ terms) | `docs/GLOSSARY.md` |
| Implementation log template | Format + cadence for the per-slice "Implementation log" running journal | `docs/IMPLEMENTATION-LOG-TEMPLATE.md` |
| Additional loops audit | Audit of FedRAMP/NIST corpus for items missing from the LOOP-A..K roadmap; proposes LOOP-L..Q + §3 extensions | `docs/ADDITIONAL-LOOPS-AUDIT.md` |
| Second-pass audit | Post-LOOP-L..Q audit confirming nothing else is still missing after L-Q specification | `docs/SECOND-PASS-AUDIT.md` |

## Sections (artifact requirements layer)
| Section | Title | Spec doc |
|---|---|---|
| A | Submission package artifacts | `docs/sections/SECTION-A.md` |
| B | 3PAO assessment workflow | `docs/sections/SECTION-B.md` |
| C | Post-authorization ConMon | `docs/sections/SECTION-C.md` |
| D | Audit agent UX | `docs/sections/SECTION-D.md` |
| E | NIST 800-53 Rev5 control mapping | `docs/sections/SECTION-E.md` |
| F | FedRAMP 20x specific deliverables | `docs/sections/SECTION-F.md` |
