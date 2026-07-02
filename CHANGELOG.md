# Changelog

All notable changes to the FedRAMP 20x tooling (cloud-evidence + tracker) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — LOOP-B.B5: Central Risk Register (RA-3 aggregated deliverable — JSON + XLSX + tracker UI); COMPLETES LOOP-B

Shipped the Central Risk Register end to end across both workspaces, completing LOOP-B (B.B1–B.B5 all done). **cloud-evidence:** new `core/risk-register.ts` — a pure aggregator (`buildRiskRegister`) + signed disk emitter (`emitRiskRegister`) that JOINs four real evidence streams into `out/risk-register.json`: the just-emitted OSCAL POA&M `risks[]` (B.B1+B.B2, one `source='finding'` entry per open risk, with likelihood derived from the risk's `epss-percentile` prop and impact from `criticality`), the signed B.B3 risk-acceptance snapshot (`source='acceptance'`, treatment=accept), the B.B4 compensating-control snapshot (an active, unexpired control drops the residual band), and a new operator-entered organisational-risk snapshot (`source='organisational'`, copied verbatim). Likelihood/impact use the NIST SP 800-30 Rev 1 qualitative scale VERBATIM; inherent risk is the published Table I-2 5×5 matrix pinned as `INHERENT_RISK_MATRIX`; residual drops one band per active compensating control (two for treatment transfer/avoid). An acceptance covering a POA&M item suppresses the duplicate finding entry (de-dup prefers treatment=accept); a `REQUIRES-OPERATOR-INPUT` B.B1 source marker propagates through to the band (visible in JSON + XLSX, never a silent zero). New `core/risk-register-xlsx.ts` renders the single "Risk Register" sheet (20 columns A..T, frozen header pane, red fill on high/very-high inherent, bold-red on very-high residual, wrapped Description) via the dependency-free store-only OOXML writer (`core/zip.ts`). New `core/organisational-risk-reader.ts` pulls `organisational_risks` over HTTP and writes the signed `out/.organisational-risks.json` snapshot. Extended `core/inventory-coverage.ts` (`risk_register_coverage` sibling — G2-safe), `core/submission-bundle.ts` (WELL_KNOWN roles `risk-register-json` / `risk-register-xlsx` / `organisational-risks-snapshot`), and `core/orchestrator.ts` (`--risk-register` + `--pull-organisational-risks <url>`; env `CLOUD_EVIDENCE_RISK_REGISTER` / `CLOUD_EVIDENCE_ORGANISATIONAL_RISKS_URL`) — the register runs AFTER the POA&M emit and BEFORE signing so both artifacts are covered by the run manifest.

**tracker:** new `organisational_risks` table (additive `CREATE TABLE IF NOT EXISTS` in `server/schema.sql`, verified on fresh + existing DBs), Hono CRUD routes (`server/routes/risk-register.ts` — create / list / detail / update / close-out for organisational risks, plus the aggregated `GET /api/risk-register` and `GET /api/risk-register/export.xlsx`), with manual validation (no zod), server-side inherent computation from the same Table I-2 matrix (Q5 — the operator sets only likelihood/impact/residual), NIST-800-53-catalog + compensating-control cross-checks, and a ≥30-day-forward `review_date` gate. B.B5 permissions added to `server/rbac.ts` (`create:organisational_risk` / `close:organisational_risk` = iso/ao/admin [executive risk ownership]; `read:risk_register` = all authenticated roles). `server/risk-register-xlsx.ts` is a tracker-local copy of the renderer (the tracker is a separate npm workspace and cannot import the cloud-evidence module). Three React pages (`RiskRegister`, `OrganisationalRiskCreate`, `OrganisationalRiskDetail`) + `lib/risk-register-{api,view}.ts` + App.tsx routes/nav; the pages import the pure `risk-register-view.ts` (form validation, the deterministic inherent hint, role-gated CTAs, inherent-descending sort) which is unit-tested directly (the tracker toolchain has no jsdom).

**Statutory / regulatory drivers** (per the per-slice doc §2, cited verbatim): NIST SP 800-53 Rev 5 RA-3 (Risk Assessment) — "Conduct a risk assessment, including: identifying threats to and vulnerabilities in the system; the likelihood and magnitude of harm ... Document risk assessment results in [Selection: security and privacy plans; risk assessment report; ...]" — the emitted `risk-register.json` + `.xlsx` IS the documented result; NIST SP 800-30 Rev 1 §3.2 + Appendix G/H/I (qualitative Very Low … Very High likelihood/impact scale + Table I-2 risk combination); NIST SP 800-39 §2.3 (Tier 1/2/3 risk-management hierarchy → the organisational-risk `category` enum); ISO 31000:2018 §6.5.3 (risk-treatment options accept/mitigate/transfer/avoid); the FedRAMP Risk Management Strategy Template (LOOP-C.C7 will consume `risk-register.json`); OSCAL POA&M v1.1.2 (cross-traceability via `risk.uuid` + `poam-item.uuid`).

**REO compliance:** every finding entry traces to a real OSCAL risk in `poam.json` (the aggregator is a JOIN, not a generator); every acceptance entry traces to a signed `risk_acceptances` row; every organisational entry traces to an audit-tracked tracker row; NIST 800-30 enum tokens are used verbatim in both JSON and XLSX; `risk-register.json` carries a `provenance` block (emitter, emittedAt, sourceCalls, signingKeyId) and is signed by `core/sign.ts` (Ed25519 + RFC 3161 via the run manifest); an air-gapped run with no organisational-risk snapshot simply omits organisational entries (logged `organisational-risk:missing-snapshot`, never fabricated). Spec reconciliations recorded in `docs/loops/LOOP-B-RISKS.md` B.B5-11 (no SheetJS → the round-trip test uses the repo zip reader on the valid OOXML), B.B5-12 (XLSX renderer duplicated across the two workspaces), B.B5-13 (the tracker aggregated endpoint returns the tracker-resident organisational + acceptance subset; the authoritative finding-inclusive RA-3 register is the collector's signed `out/risk-register.json`). §10 open questions Q1–Q8 all resolved (see the per-slice doc). Verification: cloud-evidence typecheck clean, 1391/1391 tests passing (+19: 13 aggregator + 4 XLSX + 2 reader), `npm run check:reo` returns 0 (G1 lint:no-stubs + G2 coverage-regression + G3 provenance); tracker typecheck clean, 178/178 tests passing (+19: 10 route + 9 view).

### Added — LOOP-B.B4: Compensating-controls registry (tracker DB + UI + OSCAL risk.remediations[] emission)

Shipped the full compensating-controls registry end to end across both workspaces, closing the auditability gap where B.B3 acceptances referenced compensating controls only by free-text UUID. A compensating control is now a structured, AO-signed record — title, description, referenced NIST 800-53 Rev 5 control ids (validated against the published catalog), implementer + AO sign-offs, evidence URL/SHA-256, an expiration lifecycle, and an immutable UUID that B.B3 acceptances reference and the OSCAL POA&M cites.

**Tracker** (`tracker/`, Hono + better-sqlite3 + React): new `compensating_controls` table (`server/schema.sql`, additive `CREATE TABLE IF NOT EXISTS`); `server/routes/compensating-controls.ts` — Hono CRUD (create-draft / list / uuid-exists / detail / verify / update-draft / activate / retire) with manual validation (5–200 char title, ≥200 char description, per-id NIST validation naming the offending value on failure), draft-only edits, immutable active rows, and a retirement guard that 409-blocks a control still cited by an active acceptance; `server/compensating-control-sign.ts` reuses the B.B3 resident Ed25519 key + RFC-8785 canonicalisation and adds the record + activation payload shapes (activation writes a second signature so AO sign-off is non-repudiable); `server/nist-catalog.ts` + committed copy `server/data/nist-r5-controls.generated.json` validate control ids O(1) with `AC-2(3)`↔`ac-2.3` normalisation; `server/rbac.ts` gained `read/create/activate/retire:compensating_control` (create = iso/admin, activate = ao/admin [separation of duties — an ISO implements but cannot self-activate], retire = iso/ao/admin, read = all); route mounted in `server/index.ts`; React `CompensatingControls{,Create,Detail}.tsx` + `lib/compensating-control-{api,view}.ts` + App.tsx routes/nav.

**cloud-evidence**: `core/compensating-control-reader.ts` pulls the tracker's active controls over HTTP, verifies every record's Ed25519 signature against the tracker's published public key, and writes the signed, provenance-stamped `out/.compensating-controls.json` snapshot (hard-fails the pull on any bad signature); `core/oscal-poam.ts` `buildCompensatingControlRemediations()` fills each accepted risk's `risk.remediations[]` with `lifecycle='completed'` entries carrying the control's title/description + `compensating-control-uuid` + one `nist-control` prop per id + evidence link — with `getCompensatingControl()` re-checking `status='active'` AND unexpired so a draft/expired/retired/unknown UUID surfaces a `REQUIRES-OPERATOR-INPUT: unknown uuid` marker rather than silently dropping; `core/orchestrator.ts` adds `--pull-compensating-controls <url>` (env `CLOUD_EVIDENCE_COMPENSATING_CONTROLS_URL`, defaults to the `--pull-risk-acceptances` tracker URL) running the pull before the POA&M emit; `core/submission-bundle.ts` registers the `compensating-controls-snapshot` WELL_KNOWN role; `core/nist-r5.ts` adds the shared `isValidControlId`/`normalizeControlId` primitives.

Verification: tracker `tsc --noEmit` clean, 130 → 159 tests (+29); cloud-evidence `tsc --noEmit` clean, 1354 → 1372 tests (+18); `npm run check:reo` returns 0 (G1 lint:no-stubs 0 violations, G3 check:provenance satisfied; G2 check:coverage-regression SKIP — no local collector run in this environment).

Statutory / regulatory drivers (per B.B4.md §2, cited verbatim): NIST SP 800-53 Rev 5 CA-5 ("Document the planned remediation actions of the organization to correct weaknesses or deficiencies noted during the assessment of the controls…") + CA-5(1) Automation Support ("Ensure the accuracy, currency, and availability of the plan of action and milestones for the system using [Assignment: organization-defined automated mechanisms]") + CA-2 + PL-2; NIST SP 800-53A Rev 5 §2.4 ("Compensating controls are management, operational, or technical controls … employed by an organization in lieu of recommended controls … which provide equivalent or comparable protection"); OSCAL POA&M v1.1.2 `risk.remediations[]` (lifecycle one of recommendation, planned, completed); FedRAMP ConMon Strategy & Guide §4 Deviation Requests; FIPS 186-5 (Ed25519); RFC 8785 (JSON Canonicalization Scheme).

REO compliance: all registry content is verbatim operator input (no system-default titles/descriptions); NIST ids validate against the published catalog (invalid → 400 naming the value); signatures are real Ed25519 over RFC-8785 canonical JSON with a non-repudiable second activation signature; the system never auto-activates; unknown/expired/draft UUIDs surface as `REQUIRES-OPERATOR-INPUT`, never silently dropped; the `.compensating-controls.json` snapshot carries a provenance block (emitter, fetched_at, tracker_url, public_key_fingerprint) and is signed by the existing `core/sign.ts` pipeline.

### Added — LOOP-B.B3: Risk acceptance workflow (tracker DB + signed audit record + OSCAL deviation-approved propagation)

Shipped the end-to-end signed risk-acceptance workflow — the documented "accept"
branch of NIST SP 800-53 Rev 5 **RA-7 (Risk Response)** and the structured record
that makes **CA-5 (Plan of Action and Milestones)** honest, mirroring the FedRAMP
Continuous Monitoring Strategy & Guide Deviation Request / Risk Adjustment Request
fields (finding id, justification, proposed expiration/annual-review, compensating
control, AO approval signature). The OSCAL POA&M v1.1.2 `risk.status="deviation-approved"`
value is now a real, signed state instead of one the emitter could never produce.
This is the first slice to build *into* the repo's Hono + better-sqlite3 + React
tracker (which has existed since the initial commit); the user elected to ship the
full slice across both workspaces rather than defer the tracker layer.

**Tracker (`tracker/`):** new `signing_keys` + `risk_acceptances` +
`risk_acceptance_compensating_links` tables (`server/schema.sql`); a brand-new
Ed25519 signing subsystem the tracker never had (`server/risk-acceptance-sign.ts`
— resident-key registry + RFC-8785-compatible canonicalisation byte-identical to
`cloud-evidence/core/sign.ts` — real Ed25519 per FIPS 186-5, no mocked crypto);
Hono routes (`server/routes/risk-acceptance.ts`) for create / list / detail /
verify / approve / revoke / expire with manual validation (min-100-char
justification, 7–365-day expiration window, deviation-request ⇒ ≥1 compensating
control); three FedRAMP separation-of-duties RBAC roles (`iso` creates/revokes,
`ao` approves, `assessor` reads — distinct from `admin` so an ISO cannot
self-approve; `server/rbac.ts` + an additive `users.role` CHECK migration in
`server/db.ts`, verified non-destructive on both fresh and pre-existing DBs); an
hourly expiry enforcer (`server/risk-acceptance-enforcer.ts`, booted from
`server/index.ts`); and React pages + a typed API client + extracted pure
view-logic (`client/src/pages/RiskAcceptance{,Create,Detail}.tsx`,
`client/src/lib/risk-acceptance-{api,view}.ts`, App.tsx routes + nav).

**cloud-evidence (`cloud-evidence/`):** `core/risk-acceptance-reader.ts` pulls the
tracker's approved acceptances over HTTP, **verifies every record's Ed25519
signature** against the tracker's published public key, and writes the signed,
provenance-stamped `out/.risk-acceptances.json` snapshot (refusing to write if any
signature fails); `core/oscal-poam.ts` flips a matching finding's risk to
`deviation-approved`, overrides the deadline to the acceptance `expiration_date`,
and attaches `acceptance-uuid` / `acceptance-type` / `acceptance-justification`
(240-char) / `acceptance-approved-by` / `acceptance-approved-at` /
`compensating-control-uuid` props — only for `status='approved' AND
expiration_date>now()` records, re-checked on the read side (defence-in-depth);
orchestrator `--pull-risk-acceptances <url>` + `--tracker-api-token` (env
`CLOUD_EVIDENCE_TRACKER_URL` / `CLOUD_EVIDENCE_TRACKER_TOKEN`) run the pull before
the POA&M emit, falling back to the cached snapshot for air-gapped runs;
`submission-bundle` WELL_KNOWN role `risk-acceptances-snapshot` registered.

**Verification:** typecheck clean in both workspaces; tests **tracker 99→130
(+31)** (routes 14, view 8, enforcer 4, sign 4, migration 1) and **cloud-evidence
1341→1354 (+13)** (reader 8, POA&M 5), all passing; `npm run check:reo` green in
cloud-evidence (G1 lint:no-stubs 0 violations, G3 check:provenance OK, G2
coverage-regression SKIP — no local `out/` report, the documented offline state,
G4 ssdf-no-silent-pass OK). REO: `business_justification` is verbatim operator
input; AO approval requires the `ao`/`admin` permission + writes a second Ed25519
signature; the system never auto-approves and never fabricates an acceptance (no
snapshot ⇒ every risk stays `open`, logged `risk-acceptance:missing-snapshot`).
Statutory drivers: NIST SP 800-53 Rev 5 CA-5 + RA-7; NIST SP 800-37 Rev 2 Task
R-2; OSCAL POA&M v1.1.2 `risk.status`; FedRAMP Continuous Monitoring Strategy &
Guide (Deviation Request); FIPS 186-5 (Ed25519); RFC 8785 (JCS). Commit `99f5afe`.

### Added — LOOP-T.T5: SP 800-218A SSDF-AI Extension (completes LOOP-T, 5 of 5)

Shipped the AI-model augmentation layer of the SSDF self-attestation programme —
NIST SP 800-218A ("Secure Software Development Practices for Generative AI and
Dual-Use Foundation Models: An SSDF Community Profile", final 2024-07-26). T.T5
augments the T.T2 per-practice satisfaction matrix with the 800-218A
AI-model-specific Recommendation / Consideration / Note items for any in-scope
product whose LOOP-O.O5 model card declares an AI use case or dual-use
foundation-model status, so a producer signing the CISA Common Form for an
AI-bearing product can machine-verifiably attest to the full augmented framework
rather than the base SSDF alone. Statutory lineage: EO 14028 §4(e) → EO 14110
§4.2(a)(i) (rescinded by EO 14148, 2025-01-20) → NIST SP 800-218A (not withdrawn)
→ OMB M-26-05 (risk-based tailored regime). The augmentation catalogue is
extracted **verbatim** from the published NIST PDFs (both the IPD and the final
publication were downloaded from the pinned CSRC URLs and committed to
`docs/sources/` with `.sha256` siblings) — no augmentation text, id, priority, or
informative reference is invented (REO Rule 1).

**New files.** `scripts/extract-800-218A.mjs` (offline, deterministic extractor
via `pdf-parse` — the T.T1 convention) emits `data/ssdf-800-218A-ipd.json`,
`data/ssdf-800-218A-final.json`, and `docs/sources/ssdf-800-218A-delta.json`
(final catalogue: 20 practices, 48 tasks, 86 R/C/N items, 6 new AI tasks; wired
as `npm run build:ssdf-ai-catalog`). `core/ssdf-ai-extension.ts` is the pure
aggregator (catalogue loader + integrity check, model-card walker with graceful
absence, the §6.6 derivation engine, evidence-pointer merge, roll-up,
guardrail-safe augmented-matrix re-emit, provenance + detached Ed25519 signing,
additive `inventory-coverage.json` augmentation). `core/ssdf-ai-extension-xlsx.ts`
renders the operator workbook (Summary + per-product columns A..O + IPD-vs-final
delta + statutory-lineage worksheets). Tests: `tests/core/ssdf-ai-extension.test.ts`
(29) + `tests/core/ssdf-ai-extension-xlsx.test.ts` (4) with two catalogue
fixtures. **Modified files.** `core/orchestrator.ts` (+new step under the existing
`--ssdf-attestation` gate, after T.T2, before T.T3), `core/submission-bundle.ts`
(+3 `WELL_KNOWN` roles), `core/ssdf-common-form.ts` (minimal reader diff — skip
`.augmented.json` to avoid double-counting), `config.yaml` (+`ssdf.ai_augmentation_enabled`
/`primary_catalogue`/`ai_products_in_scope`), `package.json`, `scripts/lint-no-stubs.mjs`
(allowlist the verbatim-catalogue extractor).

**Outputs** (all under the run manifest + RFC 3161 TSR): `out/ssdf-ai-augmentation.json`
(+`.sig`), `out/ssdf-ai-augmentation.xlsx`, `out/ssdf-satisfaction-matrix.augmented.json`
(+`.sig`). Per-augmentation status ∈ {satisfied, partially-satisfied, not-satisfied,
not-assessed, requires-operator-input, not-applicable}. Augmentations interleave
under each base task as `ai_augmentations[]` (not sibling task rows) so
`check:ssdf-no-silent-pass` still sees only the base tasks; the 6 new 800-218A AI
tasks (PW.3.1–3.3, PS.1.2/1.3, PO.5.3 — absent from base SSDF v1.1) append as
`requires-operator-input` rows when evidence-less.

**Verification.** `npx tsc --noEmit` clean; **1341/1341 tests passing** (+33);
`npm run check:reo` returns 0 (G1 lint:no-stubs, G3 check:provenance, G2
coverage-regression skip, check:ssdf-no-silent-pass all green).

**Spec reconciliation + REO posture.** (1) The published 800-218A uses per-task
Recommendation/Consideration/Note ids `<task>.R/.C/.N<n>` — NOT the spec
§2.6/§4.1-assumed `<task>.A<n>` (LOOP-T-RISKS T.T5-16). (2) 800-218A re-introduces
tasks absent from base SSDF v1.1; these are `base_task_present:false` and roll up
`requires-operator-input` when evidence-less (T.T5-17). (3) RFC 3161 coverage is
the run-manifest TSR, not a per-file `.tsr` (T.T5-21). (4) **Realizable-core /
graceful degradation** (T.T5-20): LOOP-O.O5 is unimplemented, so no model cards
exist — the orchestrator step is fully wired + fixture-tested but no-ops
(`coverage:skipped`, reason `no-model-cards`) in a normal run, the same posture as
T.T2/T.T3/T.T4/W.W3/W.W4; it never fabricates AI evidence (REO Rule 4). Deferred:
the React `/ssdf/ai-augmentation` worksheet page (no tracker subsystem in this
repo — T.T5-22). Shipping T.T5 **completes LOOP-T (5 of 5)**.

### Added — LOOP-T.T4: Annual SSDF Re-Attestation Workflow + Material-Change Detector

Shipped the lifecycle layer of the SSDF self-attestation programme — the
regime-aware annual re-attestation cadence engine and the material-change
detector that watches the T.T2 satisfaction matrix for the changes that force
interim re-attestation. This is the producer-side instrument for the OMB M-23-16
§III binding clause: an attestation is "binding for future versions of the named
software product unless and until the software producer notifies the agencies ...
that its development practices no longer conform to the required elements", and a
material change in the SSDF posture is what triggers that notification obligation.

Two pure engines land per the per-slice §6. `core/ssdf-annual-attestation.ts`
carries the regime cadence table — `m-22-18-mandatory` / `m-23-16-extended` →
365-day general / 270-day EO-critical software (the two memos' §III collection
windows); `m-26-05-tailored` / `post-m-26-05-future` → 365-day (no
critical-software acceleration once the collection is voluntary) — and computes
`next_due_at = submitted_at + cadence` as the producer's INTERNAL review date, not
an expiry (the M-23-16 binding clause keeps the attestation in force until
notification; LOOP-T-RISKS T.T4-R1), plus `computeDueState`
(current / due_soon / due_now / overdue / never_submitted). The operator regime is
required (config.yaml `ssdf.products[].regime`); an absent or unrecognised regime
throws `InvalidRegimeError` rather than defaulting to a mandatory cadence (REO
Rule 4). `core/ssdf-material-change-detector.ts` diffs successive matrix snapshots
and emits typed `MaterialChangeEvent`s — `practice_regression` (satisfied →
not-satisfied, suppressed by an active POA&M-extension override because
`requires-operator-input` is a coverage gap not a regression, T.T4-R2),
`new_untestable_practice`, `major_version_bump`, `ai_augmentation_gap`,
`regime_change`, `agency_added` — with the §6 Step 7/8 notification clock
(14-day regressions / 30-day version+regime / null informational) and
`triggers_reattestation` policy; event ids are uuid-v5 content-derived so re-runs
are idempotent.

The evidence path: the orchestrator runs the detector under the existing
`--ssdf-attestation` gate (env `CLOUD_EVIDENCE_SSDF_ATTESTATION`) AFTER the T.T2
matrix emit and BEFORE T.T3 / signing, so the output is covered by the Ed25519 run
manifest + RFC 3161 TSR. It loads every `out/ssdf-satisfaction-matrix*.json`, diffs
each against its most recent prior snapshot, and emits the signed
`out/ssdf-material-change-events.json` (+ `.json.sig`, detached Ed25519 over the
RFC-8785 signature-blanked bytes) carrying the per-(product × agency) cadence rows
and the `MaterialChangeEvent[]`. The realizable persistence layer stands in for the
spec's tracker storage: prior matrices are archived as content-addressed snapshots
at `out/ssdf-attestation-snapshots/<product>/<sha256>.json` and the append-only run
index is `out/ssdf-attestation-ledger.jsonl`. Three `submission-bundle` WELL_KNOWN
roles registered (`ssdf-material-change-events-json`, `ssdf-attestation-ledger`,
`ssdf-attestation-snapshot`); an `ssdf_material_change_coverage` sibling added to
`inventory-coverage.json` (a sibling field, never an Appendix-M fillRate cell, so
G2-safe). `config.yaml#ssdf.products[]` gained the optional T.T4 cadence fields
(`regime` enum, `continuous_delivery`, `major_version_pattern`,
`cadence_override_days`, `poam_extension_allowed`, `federal_agencies[]`).

Statutory / regulatory drivers (per-slice §2, all accessed 2026-06-07): EO 14028
§4(n) (attest-to-complying FAR direction); OMB M-22-18 §II/§III (Sep 14 2022 —
270-day critical / 365-day general collection windows); OMB M-23-16 §III (Jun 9
2023 — the "binding ... unless and until the software producer notifies" clause +
the three scope triggers + the POA&M safety valve); OMB M-26-05 (Jan 23 2026 —
"Memoranda M-22-18 and M-23-16 are rescinded. Agencies may continue to use the
Common Form ... on a tailored, risk-based basis"); NIST SP 800-218 v1.1 (Feb 2022,
the PO/PS/PW/RV substrate); CISA Secure Software Development Attestation Common Form
(OMB 1670-0052); CISA RSAA.

Verification: typecheck clean; 1308/1308 tests passing (+29 new — 12 cadence-engine
+ 17 detector/status/signed-emit, per-slice §8 rows T01–T17 adapted to the
realizable-core surface); `npm run check:reo` returns 0 (G1 lint:no-stubs +
G2 coverage-regression + G3 check:provenance + check:ssdf-no-silent-pass). New
files: `core/ssdf-annual-attestation.ts`, `core/ssdf-material-change-detector.ts`,
`tests/core/ssdf-annual-attestation.test.ts`,
`tests/core/ssdf-material-change-detector.test.ts`. Modified:
`core/orchestrator.ts` (detector wiring), `core/submission-bundle.ts` (3 roles),
`core/inventory-coverage.ts` (coverage sibling), `config.yaml` (product cadence
fields).

REO / realizable-core posture: the per-slice §5.1 four SQLite tables, the §6 REST
routes + `ssdf-service`, the three React panes + RBAC, and the operator
signed-PDF-SHA-256 / RSAA-submission-id capture + force-reattestation / withdrawal /
legal-review actions are **deferred** — no tracker subsystem exists in this repo
(no `pg`/`express`/`react`/`better-sqlite3`), the same posture as T.T2/T.T3/W.W3/W.W4
(tracked LOOP-T-RISKS T.T4-21..24). The detector never auto-signs a producer
attestation and never files with an agency / CISA RSAA (REO Rule 4). The STATUS
T.T4 table-row title was reconciled to the per-slice-doc / SPEC §3 title (the prior
"Third-party software components attestation appendix" label was stale — that scope
is T.T5's AI extension).

### Added — LOOP-T.T3: CISA Self-Attestation Common Form (OMB 1670-0052) PDF emitter

Shipped the CISA Secure Software Development Attestation Common Form (OMB Control
Number `1670-0052`, expiration `03/31/2027`) as an **unsigned** deterministic PDF
plus a signed canonical-JSON shadow — the corporate-officer-signable artifact a
software producer submits to a federal agency under OMB M-22-18 (as amended by
M-23-16), or attaches to a risk-tier package an agency requests under the
successor M-26-05 risk-based regime. With `--ssdf-common-form` (env
`CLOUD_EVIDENCE_SSDF_COMMON_FORM`; implies `--ssdf-attestation`), the orchestrator
projects the T.T2 satisfaction matrix (`out/ssdf-satisfaction-matrix*.json`) plus
the operator's `config.yaml#ssdf.producer` block into
`out/cisa-common-form-1670-0052.pdf` + `out/cisa-common-form-1670-0052.json`
(+ `.json.sig`). New modules: `core/ssdf-common-form.ts` (operator-config
validation collecting every missing field into `MissingOperatorInputError`; the
matrix-driven canonical builder; `emitSsdfCommonForm` sign-and-write) and
`core/ssdf-common-form-pdf.ts` (a byte-deterministic PDF 1.4 renderer composing
the `escapePdfText`/`wrapText` primitives from `core/conmon-pdf.ts`, with a forced
page per Section, an OMB-control footer on every page, and a `/ID`+`/Info` seeded
from the canonical digest). Modified `core/orchestrator.ts` (flag/env/emit block,
running after the T.T2 matrix + A.A1 POA&M and before signing),
`core/submission-bundle.ts` (two new WELL_KNOWN roles — `ssdf-common-form-pdf`,
`ssdf-common-form-json`), `core/inventory-coverage.ts` (a G2-safe per-product
`ssdf_common_form_fill_rate` sibling), and `config.yaml` (an `ssdf.producer`
template).

The real evidence path: each of the four Section IV attestations maps to a Common
Form clause §IV(1)…§IV(4) (Practice 1 secure environments → 4 automated
vulnerability tooling) via the T.T1 catalogue's `COMMON_FORM_TASK_MAP`, surfaced
per-task on the matrix as `common_form_section_ref`. A clause's selection
(∈ {comply, comply-with-conditions, cannot-comply, not-yet-determined}) reduces
over the union of its in-scope tasks' real statuses — any `requires-operator-input`
or `not-assessed` task forces `not-yet-determined` (REO Rule 1.5: never a silent
`comply`), and a `cannot-comply` clause must cite ≥1 POA&M item (from `out/poam.json`
or `poam_reference_overrides`) or the emit throws `MissingPoamReferenceError`. The
PDF's signature + date lines are left blank — the system never auto-signs the human
attestation (REO Rule 1.10; the officer signs out of band, captured by T.T4) and
never files with CISA / an agency (REO Rule 4). The signed sidecar JSON carries a
camelCase `provenance` block citing every input's SHA-256, so G3 passes without an
allowlist edit; the `.pdf` + `.json` ride the existing run manifest via
`core/sign.ts`'s by-extension signing (no signing-glob change needed).

Spec reconciliations (documented in T.T3.md §12 + the STATUS T.T3 scope note +
LOOP-T-RISKS `T.T3-19..22`): the per-slice doc §4.2 inputs
(`ssdf-practice-map.json`/`ssdf-evidence-binding.json`), its status enum
(implemented/…/not-applicable), and its illustrative §6.5 `CISA_PRACTICE_TO_SSDF`
table (1.a–4.c) are stale — the real input is the single `ssdf-satisfaction-matrix.json`,
the real enum is satisfied/partially-satisfied/not-satisfied/not-assessed/
requires-operator-input, and the authoritative mapping is the catalogue's §IV(1..4)
table (the 1.a–1.f / 4.a–4.c sub-items are verbatim form text, not separately
evidence-bound). The binary CISA template PDF + CISA/OMB logo assets are not
fetched in this clean-room tree (verbatim §IV text reproduced from the public
record per T.T3.md §2.4; text-only PDF header); PDF/A-3b font embedding falls back
to dependency-free PDF 1.4 (spec §5.1-permitted); electronic-signature binding +
RSAA submission are T.T4.

Statutory / regulatory drivers (verbatim per T.T3.md §2): OMB M-22-18 (Sept 14
2022) — "Federal agencies must only use software provided by software producers who
can attest to complying with the Government-specified secure software development
practices, as described in the NIST Guidance"; OMB M-23-16 (June 9 2023) — Common
Form anchor + third-party-component exclusion; Executive Order 14028 §4(e) (May 12
2021); CISA Secure Software Development Attestation Common Form (OMB Control
1670-0052, expiration 03/31/2027) Section IV Practices 1–4 + the penalty-of-perjury
signature block; NIST SP 800-218 v1.1 (Feb 2022) practice identifiers; OMB M-26-05
(Jan 23 2026) risk-based successor regime. Verification: `npm run typecheck` clean;
**1279/1279 tests passing (was 1241, +38** across
`tests/core/ssdf-common-form.test.ts` (27) and
`tests/core/ssdf-common-form-pdf.test.ts` (11)); `npm run check:reo`
(lint:no-stubs + check:provenance + check:coverage-regression +
check:ssdf-no-silent-pass) all green; a real emission additionally verified against
`check:provenance` + `check:ssdf-no-silent-pass`.

### Added — LOOP-T.T2: Per-Practice Evidence Aggregator + Satisfaction Matrix

Shipped the SSDF per-practice × per-task satisfaction matrix — the data backbone
of the CISA Secure Software Development Attestation Common Form (T.T3) and the OMB
M-22-18 paragraph III.E POA&M safety valve. With `--ssdf-attestation` (env
`CLOUD_EVIDENCE_SSDF_ATTESTATION`), the orchestrator joins the T.T1 SSDF practices
catalogue (`data/ssdf-800-218-v1.1.json`, 19 practices / 42 active tasks) to the
run's REAL evidence corpus and emits a signed canonical-JSON matrix
(`out/ssdf-satisfaction-matrix.json` + `.json.sig`) plus an operator-readable
two-sheet workbook (`out/ssdf-satisfaction-matrix.xlsx` — Per-Task Matrix +
Per-Practice Summary) and an append-only emission ledger. New modules:
`core/ssdf-satisfaction-matrix.ts` (typedefs + RFC 4122 v5 deterministic
`matrix_id` + canonical serializer + `.xlsx` renderer composing the OOXML writer
in `core/supply-chain-risk.ts`) and `core/ssdf-evidence-aggregator.ts`
(`buildSsdfSatisfactionMatrix` join/compute + `emitSsdfSatisfactionMatrix`
sign-and-write). The pass runs after every per-loop emitter and before signing,
so the matrix is covered by the run manifest + RFC 3161 timestamp; two
`submission-bundle` WELL_KNOWN roles (`ssdf-satisfaction-matrix-json`,
`ssdf-satisfaction-matrix-xlsx`) register it in the FedRAMP submission package.

The real evidence path: each SSDF practice's `fedramp_ksi_forward_map` joins to the
signed per-KSI evidence envelopes on disk (`out/KSI-*.json`); a failing
high/critical finding marks the practice `not-satisfied`; the LOOP-B.B1
`risk-scores.json` composite supplies the per-practice open-risk; the LOOP-A.A1
`poam.json` supplies a control-based secondary join (an open POA&M item →
`partially-satisfied`); `subprocessor-inventory.json` (J.J2),
`supply-chain-risk-register.json` (J.J3), and `sbom-report.json` (E.E2) attach to
the organisational-toolchain / third-party-component / release-integrity
practices respectively. Per-task status ∈ {satisfied, partially-satisfied,
not-satisfied, not-assessed, requires-operator-input}; a task with zero evidence
pointers is `requires-operator-input` — never a silent pass. That REO invariant is
enforced by a new guardrail, `scripts/check-ssdf-no-silent-pass.mjs`
(`npm run check:ssdf-no-silent-pass`), wired into the `check:reo` aggregate: it
fails the build if any `satisfied` cell lacks an evidence pointer. Every input
file read is cited in the camelCase `provenance` block with its SHA-256; when a
run `manifest.json` is present, an evidence file whose on-disk hash does not match
its manifest entry throws `EnvelopeSignatureError` (the matrix refuses to ship
over tampered evidence). The matrix carries the machine signature only — the
producer-officer attestation is signed on the T.T3 Common Form, never auto-signed
here (REO Rule 1.10).

Statutory / regulatory drivers (verbatim per T.T2.md §2): Executive Order 14028
§4(e)/§4(n) (Improving the Nation's Cybersecurity, May 12 2021); OMB M-22-18
(Sept 14 2022) paragraph II scope + paragraph III.E POA&M safety valve + III.D
third-party software; OMB M-23-16 (June 9 2023) paragraph II Common Form anchor;
NIST SP 800-218 v1.1 (Feb 2022) §2 practice-group definitions; CISA Secure
Software Development Attestation Common Form (OMB Control 1670-0052, March 11 2024)
Section III.1–III.4; NIST IR 8397 (Oct 2021); CISA RSAA (March 18 2024).
Verification: `npm run typecheck` clean; 1241/1241 tests passing (+30 across
`tests/core/ssdf-evidence-aggregator.test.ts` (22) and
`tests/core/ssdf-satisfaction-matrix.test.ts` (8)); `npm run check:reo`
(lint:no-stubs + check:provenance + check:coverage-regression +
check:ssdf-no-silent-pass) returns 0. Files created: `core/ssdf-satisfaction-matrix.ts`
(~300 lines), `core/ssdf-evidence-aggregator.ts` (~560 lines),
`scripts/check-ssdf-no-silent-pass.mjs` (~110 lines), two test files (~430 lines).
Files modified: `core/orchestrator.ts` (`--ssdf-attestation` flag/env + emit pass),
`core/submission-bundle.ts` (2 WELL_KNOWN roles), `package.json` (guardrail
script + `check:reo` wiring).

REO compliance + spec reconciliation: the T.T2.md §4/§5 idealised schema assumed
per-TASK KSI/800-53 crosswalks and 43 tasks; the committed T.T1 catalogue carries
those crosswalks per-PRACTICE (`fedramp_ksi_forward_map`,
`nist_800_53_r5_controls`), Common Form refs per-task, and 42 active tasks (PW.3
withdrawn in v1.1). The matrix therefore joins at the practice level and
attributes the pointer set to each task (LOOP-T-RISKS `T.T2-16`). The tracker
process-artefact pointer kind + per-agency tracker DB (no tracker subsystem in
this repo) and the cosign/build-attestation collector are deferred (`T.T2-17`,
`T.T2-18`); both coverage boundaries are surfaced in `provenance.coverageDiagnostics`.

### Added — LOOP-W.W4: Section 889 Part B Annual Representation (FAR 52.204-26)

Closed LOOP-W (the FAR §889 prohibited-vendor loop is now COMPLETE: W.W1 catalog
→ W.W2 screen → W.W3 1-business-day reporter → W.W4 annual representation). With
`--section889-annual-rep` (env `CLOUD_EVIDENCE_SECTION889_ANNUAL_REP`), the
orchestrator ingests the W.W2 screen result
(`out/prohibited-vendors-screen-result.json`), verifies its detached Ed25519
signature (a forged screen could fabricate or mask a covered-vendor match in a
legal representation made to the Government), and emits the FAR 52.204-26
"Covered Telecommunications Equipment or Services — Representation" artifact pair:
a signed canonical-JSON envelope (`out/section889-annual-rep.json` + `.sig`) and a
printable OOXML `.docx` (`out/section889-annual-rep.docx`) the authorized officer
signs and carries to SAM.gov. The two FAR 52.204-26(c) "does / does not" answers
are computed deterministically from the screen's non-suppressed matches: (c)(1)
"provides to the Government" keys off the subprocessor-sheet + inventory
provider-tag surfaces; (c)(2) "uses" is broader and keys off every non-suppressed
match (FAR 4.2102 prohibits "use" regardless of contract performance). The
envelope embeds the catalog snapshot id + SHA-256 for 3PAO verification, links any
W.W3 1-business-day incidents that reference the driving matches (read from the
`section889-1bd-reports.jsonl` ledger by `match_id`), records a 365-day
`valid_until` per FAR 52.204-8(d), and lists the SR-1/SR-3/SR-5/SR-6/SR-11
controls it evidences. The emitter also writes an append-only
`section889-annual-reps.jsonl` ledger (delta + representation-flip detection vs
the prior representation) and the LOOP-Q.Q1 `marketplace-section889-badge.json`
feed (badge enabled iff both answers are "does not" AND the representation is
within its validity window). The system NEVER files the representation in SAM.gov
on the operator's behalf (REO Rule 4) — it produces the artifact pair; the
operator submits.

New modules: `core/section889-annual-rep.ts` (pure builder
`composeAnnualRepEnvelope` + `computeRepresentation` does/does-not split +
`validateOperatorInputs` + detached-Ed25519 signing + linked-incident collection
+ Marketplace-badge builder + ledger/delta/flip detection + inventory-coverage
augmentation + the `emitSection889AnnualRep` entry point) and
`core/section889-rep-docx.ts` (OOXML/zip-store renderer on `core/zip.ts` — header,
title, verbatim recitals, the two ■/□ screen-driven checkbox representations with
computed rationale, reasonable-inquiry methodology + scope table, SAM-review
footer, optional linked-incident + Kaspersky annexes, an 18 U.S.C. §1001
attestation block, and a reserved `signature-block` bookmark). Extended
`core/orchestrator.ts` (flag/env, runs after W.W3 + before signing) and
`core/submission-bundle.ts` (five new `section889-annual-rep-*` /
`marketplace-section889-badge` WELL_KNOWN roles). Seeded
`docs/section889/reasonable-inquiry-methodology.md` (operator-authored,
SHA-256-embedded), `docs/section889/annual-rep-runbook.md` (the annual ceremony),
and `section889-annual-rep.example.yaml` (the `config.yaml#section_889` template).

Statutory / regulatory drivers (verbatim sources, accessed 2026-06-07):
**FAR 52.204-26(a)** ("'Covered telecommunications equipment or services' and
'reasonable inquiry' have the meaning provided in the clause 52.204-25…");
**FAR 52.204-26(b)** ("The Offeror shall review the list of excluded parties in
the System for Award Management (SAM) (https://www.sam.gov)…"); **FAR
52.204-26(c)(1)/(c)(2)** (the two "[ ] does, [ ] does not" representations —
provision to the Government, and use); **FAR 52.204-25(a)** ("Covered
telecommunications equipment or services means—" the Huawei/ZTE/Hytera/Hikvision/
Dahua enumeration + "Covered foreign country means The People's Republic of
China" + the "Reasonable inquiry means an inquiry designed to uncover any
information in the entity's possession…" definition); **FAR 52.204-8(d)** (the SAM
12-month annual cycle → the 365-day `valid_until`); **NDAA FY2019 §889(a)(1)(A)/(B)**
(Pub. L. 115-232); **NDAA FY2018 §1634** (Pub. L. 115-91 — the Kaspersky
supplement) + **DHS BOD 17-01**; **NIST SP 800-53 Rev 5 SR family** (SR-1/3/5/6/11).

Verification: typecheck clean; 1211/1211 tests passing (+39 in
`tests/core/section889-annual-rep.test.ts`, exceeding the spec's 15-test target);
`npm run check:reo` (G1 lint:no-stubs + G2 coverage-regression + G3
check:provenance) returns 0; an end-to-end `check:provenance` run on the real
emitted artifacts confirms both `section889-annual-rep.json` and the new
non-allowlisted `marketplace-section889-badge.json` carry a compliant camelCase
provenance block. REO compliance: the W.W2 envelope signature is verified before
any output is written; every emitted value derives from the verified screen,
operator config, or operator signing material; mandatory operator fields (UEI,
officer block, methodology doc) are validated BEFORE any write so a missing field
throws `requires_operator_input:<field>` and emits no partial artifact; the
`.docx` reserves a wet-signature region (no human attestation is auto-signed).
Scope reconciliation: the tracker DB table (`section889_annual_reps`) / REST
routes / React review-sign-off UI / SAM-receipt paste-back / officer-keyring
expiry check (per-slice §5.3/§7) are deferred — no tracker subsystem exists in
this repo (no `pg`/`express`/`react` deps); the append-only ledger is the interim
delta/continuity substrate (see LOOP-W-RISKS W.W4-EXT-1..4). The W.W2 input is the
real `out/prohibited-vendors-screen-result.json` (the spec §4.1
`out/prohibited-vendors-matches.json` name was stale — same posture as W.W3); the
`.docx` emits the proven 5-part byte-reproducible OOXML structure; the envelope's
`rfc3161_timestamp` is `pending` (the manifest-level TST covers it at run signing).

### Added — LOOP-W.W3: FAR 52.204-25(d) 1-Business-Day Prohibited-Vendor Discovery Reporter

Shipped the operational fulcrum of LOOP-W: the reporter that produces the
regulatory deliverable FAR 52.204-25(d) obliges a contractor to file within one
business day of identifying covered telecommunications equipment or services.
With `--prohibited-vendor-1bd-report` (env
`CLOUD_EVIDENCE_PROHIBITED_VENDOR_1BD_REPORT`), the orchestrator ingests the
W.W2 screen result (`out/prohibited-vendors-screen-result.json`), verifies its
detached Ed25519 signature (a forged screen could fabricate or mask a reportable
hit), filters the reportable matches (non-suppressed, high-confidence, Section
889 / NDAA §1634 / operator-addition source), and for each (match × affected
contract) emits a signed canonical-JSON report plus a rendered `.docx` under
`out/section889-1bd-reports/`. Each report carries the nine FAR 52.204-25(d)(2)(i)
data elements (read from the W.W2 match record, with `REQUIRES-OPERATOR-INPUT`
markers preserved — never auto-filled), the statutory citation array
(Huawei/ZTE → FAR 52.204-25(a)(1) + NDAA §889(f)(2)(A); Hytera/Hikvision/Dahua →
(a)(2) + (f)(2)(B); Kaspersky → NDAA §1634 + DHS BOD 17-01, reported under the
live FAR framework), and the federal-business-day deadline. The reporter NEVER
auto-transmits to a federal endpoint (REO Rule 4) — it produces the artifact
pair; the operator transmits.

New modules: `core/section889-clock.ts` (federal-business-hour deadline math —
Mon–Fri 09:00–17:00 ET, 8 business hours/day, weekends + the 11 observed
5 U.S.C. §6103 holidays skipped, operator agency-closure overrides, DST-correct
via IANA `America/New_York`; composes `core/bizdays.ts:usFederalHolidays` so the
holiday calendar is computed, not maintained as a signed JSON file),
`core/section889-report-json.ts` (reportable-match filter + statutory-basis
routing + canonical-JSON composer with a top-level camelCase `provenance` block
for G3), `core/section889-report-docx.ts` (OOXML/zip-store renderer on
`core/zip.ts` — cover page, summary table, per-finding section quoting the
operative FAR 52.204-25(a) / NDAA §889(f)(2) / §1634 / BOD 17-01 text verbatim,
18 U.S.C. §1001 attestation block, reserved `signature-block` bookmark),
`core/section889-contacts.ts` + `core/section889-closures.ts` (typed YAML
loaders), and `core/section889-1bd-reporter.ts` (the end-to-end emit + detached
Ed25519 signing + `.sig` sidecar + append-only `section889-1bd-reports.jsonl`
ledger for idempotency/dedupe + inventory-coverage augmentation + injectable
notification seam + 10-business-day FAR (d)(2)(ii) follow-up composer). Extended
`core/orchestrator.ts` (flag/env, runs after W.W2 + before signing),
`core/submission-bundle.ts` (four new `section889-1bd-report-*` WELL_KNOWN roles
+ `listOutDir` scans the report subdir). Added `section889-contacts.example.yaml`
+ `section889-agency-closures.example.yaml`.

Statutory / regulatory drivers (verbatim sources, accessed 2026-06-07):
FAR 52.204-25(d)(1)–(d)(2)(ii) (https://www.acquisition.gov/far/52.204-25 — the
one-business-day + ten-business-day reporting clock + the nine (d)(2)(i)
elements); FAR 4.2105(b) (clause is universal for solicitations/contracts since
2020-08-13); NDAA FY2019 §889(f)(2)/(f)(3) (Pub. L. 115-232 — covered
telecommunications equipment + covered foreign country = PRC); NDAA FY2018
§1634 (Pub. L. 115-91 — Kaspersky prohibition); DHS BOD 17-01 (Kaspersky
removal directive); 5 U.S.C. §6103 (federal holidays + the in-lieu-of rule —
the business-day clock).

Verification: typecheck clean; 1172/1172 tests passing (+45 — `section889-clock`
19, `section889-report-docx` 6, `section889-1bd-reporter` 20, exceeding the
spec's 20-test target); `npm run check:reo` (G1 lint:no-stubs + G2
coverage-regression + G3 check:provenance) returns 0. REO compliance: the W.W2
envelope signature is verified before any output is written; emitted JSON
carries a camelCase `provenance` block (G3); the nine (d)(2)(i) elements are
read from real W.W2 evidence with operator markers preserved; no human
attestation is auto-signed (the operator's name/title flow from
`config.yaml:section_889.signing` and the `.docx` reserves a wet-signature
region). Scope reconciliation: the tracker DB / REST routes / React countdown UI
/ `scheduled_notifications` daemon / pgcrypto-at-rest in the per-slice §5.4/§7
are deferred — no tracker subsystem exists in this repo (no `pg`/`express`/`react`
deps); the append-only ledger is the interim idempotency + audit index and
notification is an injectable seam (see LOOP-W-RISKS W.W3-17..20). The STATUS.md
row title was reconciled to the per-slice-doc title (the prior "SBOM crosscheck"
label was stale; SBOM walking is owned by W.W2).

### Added — LOOP-W.W2: Subprocessor + SBOM + OCI Image Screening against Prohibited-Vendor Catalog

Closed the largest remaining gap in the FedPy supply-chain story: until now
FedPy emitted zero artifacts demonstrating the "reasonable inquiry" of FAR
4.2101 — operators hand-screened vendors against the Section 889 clause. With
`--prohibited-vendor-screen`, the orchestrator screens four surfaces — the
operator's subprocessor sheet, every package in the SBOM (transitively, to
`--sbom-max-depth`, default 8), every OCI image publisher attested by
cosign/Rekor under `out/oci-attestations/`, and every inventory asset's
`provider_tag`/`sku` — against the W.W1 prohibited-vendor catalog. It emits a
signed `out/prohibited-vendors-screen-result.json` envelope (one match record
per hit, carrying a confidence band, the catalog→surface provenance chain, the
FAR 52.204-25(d)(1) report data elements pre-filled for W.W3 with
`REQUIRES-OPERATOR-INPUT` markers where the operator must supply UEI/CAGE/brand/
model, a deterministic `discovered_at` that drives the W.W3 one-business-day
clock, and `reportable_under_far_52_204_25_d` / `reportable_under_ndaa_1634` /
`reasonable_inquiry_attested` roll-up flags), an operator-readable 3-sheet
`.xlsx`, and an append-only `prohibited-vendor-screens.jsonl` ledger. The screen
NEVER auto-submits anything to a federal endpoint — it produces the evidence;
the operator submits (W.W3/W.W4 own the report + the FAR 52.204-26 annual
representation).

New modules: `core/vendor-name-normalizer.ts` (NFKC + Cyrillic→Latin
transliteration + corporate-suffix strip + diacritics), `core/prohibited-vendors-screen.ts`
(boundary-respecting token-subsequence matcher index + subprocessor/inventory
walkers + dedupe/suppression/assembly + reportable flags), `core/sbom-prohibited-screen.ts`
(SPDX/CycloneDX dependency-graph walk + maintainer-field extraction with a
per-hop depth penalty), `core/oci-publisher-screen.ts` (cosign fingerprint →
OIDC registrable-domain → subject identity, fingerprint-first),
`core/prohibited-vendors-overrides.ts` (typed `prohibited-vendors-overrides.yaml`
loader — false-positive suppression with mandatory justification + expiry,
operator manual additions, fingerprint + transliteration overrides),
`core/prohibited-vendors-screen-emit.ts` (load + verify the W.W1 catalog, run
the four surfaces, sign with a detached Ed25519 signature over the canonical
signature-blanked bytes, write JSON + `.sig` + `.xlsx` + ledger, augment
inventory-coverage), and `core/prohibited-vendors-screen-xlsx.ts`. Extended
`core/subprocessors-sheet.ts` (`screenAgainstProhibitedVendors`),
`core/submission-bundle.ts` (two new `WELL_KNOWN` roles),
`core/inventory-coverage.ts` (`augmentCoverageWithProhibitedVendorScreen` +
`prohibited_vendor_screen_coverage` sibling field), `core/oscal-poam.ts`
(`buildVendorScreenPoamItems` + `vendorScreenItems` option — one high-severity
"Prohibited Vendor Detected" POA&M item per non-suppressed match citing SR-1/
SR-3/SR-5/SR-6/SR-11 and a `discovered_at + 1 business day` FAR 52.204-25(d)(2)
deadline), and `core/orchestrator.ts` (`--prohibited-vendor-screen` +
`--sbom-max-depth` + `--max-subsidiary-depth` flags, `CLOUD_EVIDENCE_*` env
vars, and the emit pass that runs after the W.W1 catalog and before signing).

Verification: `npm run typecheck` clean; `npm test` 1127/1127 passing (+54 new —
`vendor-name-normalizer` 11, `prohibited-vendors-overrides` 7,
`sbom-prohibited-screen` 6, `oci-publisher-screen` 5, `prohibited-vendors-screen`
25, well above the slice's ≥30 target); `npm run check:reo` returns 0 (G1
lint:no-stubs, G2 coverage-regression, G3 provenance — the screen envelope's
top-level `provenance` block uses the camelCase G3 contract, verified with
`check:provenance --dir` against a real `out/prohibited-vendors-screen-result.json`).

Statutory / regulatory drivers (verbatim from W.W2.md §2): **FAR 52.204-25(a)**
(covered telecommunications equipment from Huawei, ZTE, Hytera, Hikvision, Dahua,
or a covered-foreign-country-connected entity) + **(d)** (one-business-day
report of identified covered equipment); **FAR 52.204-26** ("After conducting a
reasonable inquiry … the offeror represents that it does/does not use covered
telecommunications equipment or services"); **FAR 4.2101** ("Reasonable inquiry
means an inquiry designed to uncover any information in the entity's possession
about the identity of the producer or provider of covered telecommunications
equipment or services"); **FAR 4.2102** (the "uses" prohibition that drives the
transitive SBOM walk); **NDAA FY2019 §889** (Pub. L. 115-232); **NDAA FY2018
§1634** (Pub. L. 115-91 — Kaspersky Lab and successor/common-control/majority-
owned entities); **DHS BOD 17-01** (Kaspersky removal); **OFAC SDN List** (IEEPA,
50 U.S.C. §§1701-1707); **BIS Entity List** (15 CFR Part 744, Supplement No. 4);
**SAM.gov Exclusions** (FAR Subpart 9.4); **NIST SP 800-161r1** (SR-1/3/5/6/11
controls on each emitted POA&M item); **SPDX 2.3** + **CycloneDX 1.6** (SBOM
dialects); **cosign + Rekor** (OCI publisher attestations).

REO compliance notes: every match traces to a real catalog row × a real surface
entry; FAR data elements default to `REQUIRES-OPERATOR-INPUT` (never a fabricated
UEI/CAGE/brand). The implementation was adapted to the shipped codebase, not the
spec's idealized interfaces — the matcher targets the real `ProhibitedVendorEntity`
shape (subsidiary walk fires only on operator-supplied `manual_additions`); there
is no `tracker/` subsystem in this checkout, so screen results persist via the
signed envelope + JSONL ledger (the `poam-ledger.ts`/`run-ledger.ts` pattern)
rather than a fabricated SQL migration; the SBOM walker parses SPDX/CycloneDX
directly because `core/sbom.ts` flattens components; and the OCI screener reads
attestation files when present and returns zero matches (no fabrication) when
absent. These divergences + the resolutions of §10 open questions Q1/Q4 are
recorded in `docs/slices/W/W.W2.md` §12 and risks W.W2-EXT-1/EXT-2 in
`docs/loops/LOOP-W-RISKS.md`.

### Added — LOOP-E.E2: Monthly POA&M Delta Workflow

Closed the monthly POA&M re-emission loop. The FedRAMP Rev5 ConMon cadence is a
**full re-upload** each month with a bumped `metadata.last-modified` and an
appended `metadata.revisions[]` entry; until now `core/oscal-poam.ts` accepted a
`revisionsHistory` option but nothing computed the prior history, so each
monthly POA&M shipped as a "fresh" document with no version chain — a
regulator-facing chain-of-custody break. With `--conmon-monthly --oscal-poam`,
the POA&M pass now routes through the new `runPoamMonthly()` workflow: it loads
the prior month's document from a durable ledger + archive, threads its
`metadata.revisions[]` forward (the prior month becomes a revision entry,
`priorAsRevision.version = prior.metadata.version`), re-emits the full OSCAL
POA&M, computes a month-over-month delta keyed on the A.A1 deterministic
poam-item UUIDs, renders an operator-review Markdown delta
(`out/poam-delta-<YYYY-MM>.md`, six sections — header/provenance, summary counts,
added, closed, status changes, past-deadline — plus a severity-changes section),
archives the document to `out/archive/poam-<YYYY-MM>.json`, and appends
`out/poam-ledger.jsonl`.

New modules: `core/poam-ledger.ts` (append-only JSONL ledger + monthly archive
loader; `appendPoamLedger` is idempotent by `(run_id, report_month)`;
`loadPriorMonthPoam` verifies the archived file's sha256 against the ledger and
that it parses, raising typed `PoamLedgerCorruptError` / `PoamArchiveTamperedError`
/ `PriorPoamCorruptError` — never a silent "first month" fallback) and
`core/poam-monthly.ts` (`runPoamMonthly` + the pure `computePoamDelta` /
`renderPoamDeltaMarkdown`; `past_deadline_items` are evaluated against the current
document's `metadata.last-modified`, deterministically; the first month of
operation renders the real true statement *"First month of ConMon operation; no
prior POA&M to compare against."*, not a marker). Extended `core/oscal-poam.ts`
(exported `OscalPoam` / `OscalPoamItem` / `OscalRisk` / `OscalPoamDocument`; added
`RevisionEntry`, `extractRevisionEntries(doc)` which rejects non-`Z` timestamps via
`RevisionTimezoneError`, and NO schema change), `core/orchestrator.ts` (route the
POA&M pass through `runPoamMonthly()` in monthly mode; the underlying
`PoamEmitResult` drives the existing validation/logging; added `poam_monthly.delta`
/ `poam_monthly.skip` run-ledger records), `core/submission-bundle.ts` (three new
`WELL_KNOWN` roles: `poam-delta-md`, `poam-ledger`, `poam-archive`), and
`core/sign.ts` (`listSignedFiles()` now also walks `out/archive/` so archived
POA&Ms join the signed run manifest — chain-of-custody for the version chain;
resolves LOOP-E risk CC-12's open item for `archive/`).

Verification: `npm run typecheck` clean; **1073/1073 tests passing (was 1050,
+23: 8 `poam-ledger` + 15 `poam-monthly`)**; `npm run check:reo` green (G1
lint:no-stubs 0 violations across 145 files; G3 check:provenance satisfied; G2
check-coverage-regression SKIP — no local `out/` report, the documented expected
state). No new CLI flags or env vars (reuses `--conmon-monthly` / `--oscal-poam` /
`--month`). New output files documented in OPERATOR-GUIDE §7. Open questions
Q1–Q5 resolved in `docs/slices/E/E.E2.md`; new risk E.E2-R6 (`out/archive/`
signing-scope coupling, low) recorded in `docs/loops/LOOP-E-RISKS.md`.

Statutory / regulatory drivers (verbatim): OSCAL v1.1.2 POA&M JSON reference —
*"metadata [1]: title [1], last-modified [1], version [1], oscal-version [1];
revisions [0 or 1]: an array of revision entries, each with version [1] and
last-modified [1]."* FedRAMP Rev5 Playbook — Continuous Monitoring Overview:
*"Each month, the CSP uploads an up-to-date POA&M and inventory, along with raw
vulnerability scan files (when required by agreements with agency customers) and
reports to the secure repository."* FedRAMP Rev5 Playbook — POA&M: *"FedRAMP
requires Critical and High risks to be remediated within 30 days of discovery,
Moderate risks within 90 days of discovery, and Low risks within 180 days of
discovery."* NIST SP 800-53 Rev5 CA-5: *"Develop a plan of action and milestones
for the system … and Update existing plan of action and milestones [Assignment:
organization-defined frequency] based on the findings from control assessments,
independent audits or reviews, and continuous monitoring activities."* OSCAL POA&M
concept layer: *"The plan of action and milestones, often known as POA&M, … shows
progress over time as findings are remediated."*

REO compliance: the delta is derived entirely from two real OSCAL POA&M documents
(the archived prior + the freshly-emitted current) — no shadow diff database;
poam-item UUIDs are the deterministic, traceable diff key. The archive is part of
the signed run manifest. Zero-failing-findings propagates the structured emitter
skip without writing an archive, delta, or ledger line (no fabricated "empty"
month). A corrupt/tampered prior archive raises a typed error rather than being
treated as the first month.

### Added — LOOP-E.E1: Monthly ConMon Analysis Report

Shipped the monthly Continuous Monitoring analysis report — the human-readable
executive summary the agency POC expects attached to the monthly FedRAMP secure-
repository (USDA Connect.gov) upload alongside the POA&M + inventory + scan files.
A single `npm run collect -- --conmon-monthly --month 2026-07` now emits
`out/conmon-monthly-<YYYY-MM>.{json,md,pdf}` aggregating, from the run's OWN
artifacts, nine sections: header, KSI posture snapshot, vulnerability-scan
coverage, POA&M activity, deviation requests, SCN events, incident summary,
annual-cycle progress, and provenance. New modules: `core/conmon-report.ts`
(pure `buildConmonMonthlyReport()` + disk `emitConmonMonthlyReport()`) and
`core/conmon-pdf.ts` (a dependency-free, deterministic PDF 1.4 generator —
Catalog→Pages→Page object chain, Helvetica + Courier, FlateDecode content
streams via node `zlib`, byte-accurate xref, auto pagination, table borders).
`scripts/fetch-conmon-playbook.mjs` pins the FedRAMP ConMon Playbook PDF and
writes `docs/fedramp-conmon-playbook.generated.json` (real fetched bytes:
909,986 B, sha256 `d96379ec…`). Extended `core/orchestrator.ts` with
`--conmon-monthly` / `--month` / `--fedramp-package-id` / `--csp-name` /
`--conmon-strategy-href` / `--sampling-pct` / `--ssp-last-reviewed` /
`--authorization-date` (+ `CLOUD_EVIDENCE_*` envs), running the emit AFTER
POA&M/VDR/inventory but BEFORE signing; `core/submission-bundle.ts` with three
`WELL_KNOWN` roles (`conmon-monthly-report-{json,md,pdf}`); and
`core/sign.ts` `SIGNED_EXTENSIONS` to add `.md` + `.pdf` so the report renders
join the run manifest.

Statutory / regulatory drivers (verbatim): FedRAMP Rev5 Playbook — Continuous
Monitoring Overview: *"Each month, the CSP uploads an up-to-date POA&M and
inventory, along with raw vulnerability scan files (when required by agreements
with agency customers) and reports to the secure repository."* FedRAMP Rev5
Playbook — Vulnerability Scanning: *"FedRAMP vulnerability scanning guidelines
require at least monthly scans of 100% of inventory components."* and *"100% of
externally accessible system components should be scanned."* NIST SP 800-137
§3.4: *"Reports communicate the security status of the information system in
support of organizational risk management decisions, and the implementation of
organization-defined response actions."* NIST SP 800-53 Rev5 CA-7(g):
*"Reporting the security and privacy status of the system to [organization-
defined personnel or roles] [organization-defined frequency]."* The remediation
table + scan cadence + monthly-deliverables list driving the report come from
the pinned FedRAMP ConMon Playbook v1.0 (2025-11-17), not hard-coded strings
(REO Rule 3 FedRAMP-published constants).

REO compliance: every posture count traces to a real `KSI-*.json` failing
finding (or the `poam.json` risks when present); every scan-coverage number to a
real `inventory.json` asset; KEV exposure to the committed CISA KEV catalog,
deduped by CVE id; the playbook version to the pinned projection. Operator-only
fields emit the literal `REQUIRES-OPERATOR-INPUT` sentinel (`incident_summary`
until G.G2, `system.fedrampId`, `system.csp`, `conmon_strategy_href`,
`annual_cycle.ssp_last_reviewed`); a missing source file records a
`provenance.warnings` entry rather than a silent zero. The JSON carries the G3
camelCase provenance block (`emitter`, `emittedAt`, `sourceCalls`,
`signingKeyId`) plus `tool`/`frmrVersion`/`conmonPlaybookVersion`/`warnings`, and
a detached Ed25519 signature via the LOOP-B.B1 `serializeUnsignedCanonical` +
`signDoc` convention. Verification: `npm run typecheck` clean; vitest
**1050/1050** passing (was 1025, +25: 10 `conmon-pdf` + 15 `conmon-report`);
`npm run check:reo` returns 0 (G1 lint:no-stubs 0 violations, G2
coverage-regression skip-no-out, G3 check:provenance OK). New risk recorded:
LOOP-E-RISKS E.E1-R6 (annual-cycle anchor requires operator `--authorization-date`);
CC-12 (`core/sign.ts` glob coverage) partially resolved.

### Added — LOOP-B.B2: Remediation deadline math (KEV / PAIN-IRV-LEV / FedRAMP CMP)

Replaced LOOP-A.A1's single hardcoded `Severity → days` map in `core/oscal-poam.ts`
with a priority-cascading deadline engine (`core/deadline-engine.ts`
`computeDeadline()`) that honours, in order: (1) an operator risk-acceptance
override (B.B3 hook) — capped by a CISA KEV federal mandate so an override may
make a deadline stricter but never extend it past the KEV dueDate; (2) a CISA
KEV match — BOD 22-01 requires remediation by the catalog's per-entry `dueDate`,
read VERBATIM (earliest when several CVEs match), no synthetic +21d math;
(3) a PAIN/IRV/LEV acceleration — when `risk_score.composite_score ≥ 9.0` AND
IRV (internet-reachable) AND LEV (likely-exploitable, derived from EPSS
percentile ≥ 0.95 or KEV membership), treat as critical-equivalent;
(4) the FedRAMP Continuous Monitoring Strategy & Guide severity table; and
(5) an observable severity-fallback. Every emitted OSCAL risk + poam-item now
carries a `deadline-source` prop (plus `kev-cve-id`/`kev-due-date`,
`pain`/`irv`/`lev`, or `operator-override-acceptance-uuid` as applicable) so a
3PAO can audit WHICH table drove every deadline, and a signed, G3-provenanced
`out/deadline-audit.json` logs the source + rationale per finding. A new
`--strict-risk` flag (`CLOUD_EVIDENCE_STRICT_RISK`) fails the run (exit 5) if any
finding fell through to severity-fallback — a sign the FedRAMP CMP table was not
loaded — so an unverified gap can never reach a submission package. The
orchestrator loads the CISA KEV catalog and passes the index into the POA&M
emitter.

The FedRAMP CMP table (`core/deadline-table.ts` `FEDRAMP_CMP_DEADLINES`, REO
Rule 3 FedRAMP-published constants) is: **Critical = 15 days, High = 30 days,
Moderate = 90 days, Low = 180 days, Info = 365 days** — notably High = 30
(NOT LOOP-A.A1's 60). Source: FedRAMP Continuous Monitoring Strategy & Guide
(Rev 5) §3.3 "Vulnerability Scanning" — "High vulnerabilities — 30 days.
Moderate vulnerabilities — 90 days. Low vulnerabilities — 180 days." (the source
PDF returns HTTP 403 to anonymous fetches; the `critical: 15` value carries a
`REQUIRES-OPERATOR-INPUT` docstring note to confirm against a manually
downloaded copy at `docs/sources/fedramp-conmon-strategy-guide.pdf`, pinned by
`deadline-table.test.ts`). The original A.A1 values are retained as
`SEVERITY_FALLBACK_DEADLINES` only for the observable fallback path.

New files: `core/deadline-engine.ts`, `core/deadline-table.ts`,
`tests/core/deadline-engine.test.ts` (13 tests),
`tests/core/deadline-table.test.ts` (3 tests). Modified: `core/oscal-poam.ts`
(engine integration + deadline-audit.json + props), `core/envelope.ts` (Finding
+= optional `irv`/`lev`/`pain` VDR signals), `core/submission-bundle.ts`
(`deadline-audit-json` WELL_KNOWN role), `core/orchestrator.ts` (`--strict-risk`
+ KEV load), `tests/core/oscal-poam.test.ts` (+5 integration tests; the
pre-existing critical-deadline assertion updated from A.A1's 30d to the FedRAMP
CMP 15d — an intended behaviour change). Verification: `npm run typecheck`
clean; `vitest` 1025/1025 (was 1004, +21); `npm run check:reo` returns 0.

Statutory / regulatory drivers (verbatim from `docs/slices/B/B.B2.md` §2): CISA
BOD 22-01 ("Remediate each vulnerability according to the timelines set forth in
the CISA-managed vulnerability catalog … remediated within two weeks unless
otherwise specified"); the CISA KEV JSON feed (`dueDate`); the FedRAMP ConMon
Strategy & Guide (Rev 5) §3.3 + Rev5 Playbook ConMon Vulnerability Scanning;
NIST SP 800-53 Rev 5 RA-5(2) + RA-7 (Risk Response); and FIRST EPSS (consumed
via B.B1's `risk_score.epss.percentile` for the LEV signal).

### Added — LOOP-J.J3: Supply chain risk register (SR-3) + SBOM integration

Shipped the supply-chain risk register slice of LOOP-J. A new
`core/supply-chain-risk.ts` builds a signed, canonical
`out/supply-chain-risk-register.json` + a multi-sheet
`out/supply-chain-risk-register.xlsx` (one sheet per RiskCategory + Summary +
SBOM-Provenance) — the NIST SP 800-53 Rev 5 SR-3 "supply chain processes and
controls" document and the NIST SP 800-161r1 Tier-3 per-system C-SCRM Plan. The
builder joins: SBOM-derived CVEs (parsed from `core/sbom.ts` output, severity
flowing through the existing NVD correlation — `UNKNOWN` mapped to `medium` and
FLAGGED, never silently downgraded); CISA KEV exposure (`core/kev-feed.ts`,
elevating matched CVEs to `sbom-cve-kev` / `critical` and stamping the published
`dueDate`, deduped so a KEV-matched CVE never double-emits); unsigned SBOMs
(distinguishing cosign-`unverified` from signature-`absent`); J.J2 subprocessor
risk tiers (tier-1-critical + expired-SOC2 entries); and operator-asserted risks
from a `--risks-config` (REO Rule 4 input) with `status`/`mitigation_summary`
mitigation overrides (severity is never operator-overridable). Coverage reports
open critical/high/medium/low, kev_exposed, unsigned_sboms, tier-1 counts, and
`entries_missing_mitigation`; a per-SBOM `sbom_provenance[]` block records the
seven NTIA SBOM minimum-element flags computed from the real parse.

The register feeds two existing emitters: `core/oscal-poam.ts` now emits a
`poam-item` per open critical/high register entry with
`props.risk-source=supply-chain` and a remediation deadline anchored at the
entry's `first_seen` (Critical +30d, High +60d) — NOT the run timestamp — and
the POA&M now emits even when there are no failing KSI findings but open
supply-chain risks exist; `core/oscal-ssp.ts` adds a `back-matter.resources[]`
reference to the register (`.json` + `.xlsx` rlinks). Both register artifacts
are registered in the submission-bundle `WELL_KNOWN` catalogue, and a
`--supply-chain-risk` flag + `--risks-config <path>` (+
`CLOUD_EVIDENCE_SUPPLY_CHAIN_RISK` / `CLOUD_EVIDENCE_RISKS_CONFIG` envs) schedule
the emitter after the SBOM + subprocessor passes and before the SSP/POA&M +
signing.

New files: `core/supply-chain-risk.ts` (≈760 lines),
`tests/core/supply-chain-risk.test.ts` (20 tests), four fixtures under
`tests/fixtures/supply-chain-risk/`, and `examples/risks-config.yaml`. Modified:
`core/oscal-poam.ts` (supply-chain poam-items + pre-flight), `core/oscal-ssp.ts`
(back-matter resource), `core/submission-bundle.ts` (2 WELL_KNOWN roles),
`core/orchestrator.ts` (flags + env + emit step). Verification: `npm run
typecheck` clean; `vitest` 1004/1004 (was 984, +20 — incl. POA&M + SSP
integration tests confirming the SSP still validates against the committed NIST
OSCAL 1.1.2 schema); `npm run check:reo` returns 0. The register JSON carries a
G3 provenance block (`emitter`/`emittedAt`/`sourceCalls`/`signingKeyId`) + a
self-contained detached Ed25519 signature. New risks J3-R-EXT-1 (tier-2
subprocessors register-omitted) + J3-R-EXT-2 (POA&M deadline via props;
`deadline_overdue` deferred) added to LOOP-J-RISKS.md.

Statutory / regulatory drivers (verbatim from `docs/slices/J/J.J3.md` §2): NIST
SP 800-53 Rev 5 §SR-3.a/.b/.c (establish a process to identify/address supply
chain weaknesses; employ controls; document them in a security/SCRM plan),
§SR-4 (Provenance), §SR-6 (Supplier Assessments and Reviews); NIST SP 800-161r1
§1.5 (C-SCRM Document Set) + §2.3.5 (Tier-3 system-level C-SCRM Plan); the NTIA
"Minimum Elements For a Software Bill of Materials (SBOM)" seven baseline fields
(per EO 14028 §4(f), July 12 2021); the CISA SBOM program + CISA Known Exploited
Vulnerabilities Catalog (reading the published `dueDate`); and CycloneDX 1.5 /
SPDX 2.3 as the ingested SBOM formats.

### Added — LOOP-J.J2: Subprocessor inventory expansion (SA-9)

Shipped the SA-9 Subprocessor Inventory slice of LOOP-J. The existing
Google-Sheets-only subprocessor reader (`core/subprocessors-sheet.ts`) is
extended with first-class operator YAML/JSON config and the FedRAMP SA-9 fields
(`risk_tier`, `data_residency`, `last_audit_date`, `monitoring_methods`,
`incident_notification_sla_hours`, `subprocessor_subprocessors`,
`contracted_controls`, `oversight_party_uuid`, `user_roles_responsibilities`,
plus `source`/`source_ref` provenance). A new emitter
(`core/subprocessor-inventory.ts`) reads both surfaces (sheet rows first, config
rows win on a canonical-name conflict — recorded as a warning), computes SA-9
coverage (risk-tier gaps, expired SOC2, tier-1/2/3 counts, FedRAMP-auth count),
and writes a signed, canonical `out/subprocessor-inventory.json` plus a
FedRAMP-style `out/subprocessor-inventory.xlsx` (single sheet, parameterized
`COLUMN_ORDER`). When neither source yields a row, a single explicit
`REQUIRES-OPERATOR-INPUT` row names both surfaces rather than masking the gap;
missing SA-9 fields render the `REQUIRES-OPERATOR-INPUT` literal in the XLSX.
The OSCAL SSP emitter (`core/oscal-ssp.ts`) now reads the inventory and
populates `system-implementation.leveraged-authorizations[]` (plus backing
`metadata.parties[]`) for every `fedramp_authorized: yes` row carrying a real
`last_audit_date` — never fabricating a `date-authorized`, and omitting the
field entirely when empty to honour the OSCAL `minItems: 1` constraint. The two
artifacts are registered in the submission-bundle `WELL_KNOWN` catalogue, and a
`--subprocessors-config <path>` flag + `CLOUD_EVIDENCE_SUBPROCESSORS_CONFIG`
env var + `config.yaml` `subprocessors` block wire the emitter to run before the
SSP and before signing (so both are covered by the run manifest).

New files: `core/subprocessor-inventory.ts` (≈430 lines),
`tests/core/subprocessor-inventory.test.ts` (20 tests),
`tests/fixtures/subprocessors/example.{yaml,json}`,
`tests/fixtures/subprocessor-config.schema.json`, `examples/subprocessors.yaml`.
Modified: `core/subprocessors-sheet.ts` (+SA-9 fields + provenance stamping),
`core/oscal-ssp.ts` (leveraged-authorizations integration),
`core/submission-bundle.ts` (2 WELL_KNOWN roles), `core/orchestrator.ts` (flag +
env + config block + emit step). Verification: `npm run typecheck` clean;
`vitest` 984/984 passing (was 964, +20 — the SSP integration test confirms the
output still validates against the committed NIST OSCAL 1.1.2 SSP schema);
`npm run check:reo` returns 0 (lint:no-stubs + check:provenance; the
coverage-regression check skips with no `out/` present). The emitted JSON carries
a G3 provenance block (`emitter`/`emittedAt`/`sourceCalls`/`signingKeyId`) and a
self-contained detached Ed25519 signature composed from the run signing key.

Statutory / regulatory drivers (verbatim from `docs/slices/J/J.J2.md` §2):
NIST SP 800-53 Rev 5 §SA-9.a ("Require that providers of external system
services comply with organizational security and privacy requirements and
employ the following controls: [Assignment: organization-defined controls]."),
§SA-9.b ("Define and document organizational oversight and user roles and
responsibilities with regard to external system services."), §SA-9.c ("Employ
the following processes, methods, and techniques to monitor control compliance
by external service providers on an ongoing basis: [Assignment: …]."),
§SA-9(5) Processing/Storage/Service Location (drives `data_residency`); NIST SP
800-161 Rev 1 §2.3.5 tiered supplier identification (drives `risk_tier`); the
FedRAMP Rev 5 SSP Leveraged Authorizations / Subservice Organizations section;
the OSCAL 1.1.2 `leveraged-authorization` model (required fields uuid / title /
party-uuid / date-authorized); and NTIA SBOM Minimum Elements "Supplier Name".

### Added — LOOP-T.T1: NIST SP 800-218 v1.1 (SSDF) practice catalog + 800-53 + KSI crosswalk emitter

Shipped the foundation slice of LOOP-T (NIST SSDF self-attestation via the CISA
Secure Software Development Attestation Common Form). T.T1 extracts the NIST SP
800-218 v1.1 Secure Software Development Framework into a canonical,
Ed25519-signed catalog (`data/ssdf-800-218-v1.1.json`) that downstream slices
(T.T2 Common Form generator, T.T3 evidence aggregator, T.T5 KSI↔SSDF gap matrix)
consume. New files: `core/ssdf-practices-catalog.ts` (488 lines — typed
loader/validator/lookup + shared builder + Ed25519 sign/verify),
`scripts/extract-ssdf-practices.mjs` (276 lines — offline extractor that parses
Table 1 verbatim from the committed PDF and signs via `core/sign.ts`),
`scripts/data/ssdf-ksi-mapping.json` (curated SSDF→FedRAMP KSI forward map with
per-pair confidence + rationale), `tests/core/ssdf-practices-catalog.test.ts`
(25 tests) + 3 fixtures, and the committed published sources
`docs/sources/NIST.SP.800-218.pdf` (sha256 `617746e5…`) +
`docs/sources/Self_Attestation_Common_Form_FINAL_508c.pdf` (sha256 `a8d6b568…`).
Modified: `core/submission-bundle.ts` (role `ssdf-practice-catalog-json`),
`package.json` (`build:ssdf-catalog` script + `pdf-parse` devDependency),
`.gitignore` (un-ignore the committed catalog), `CLAUDE.md` reading list, and
`docs/OPERATOR-GUIDE.md` §7.

The catalog is real evidence end to end: all 19 practice intents, 42 active task
statements, and the SP 800-53 Rev 5 control mappings are parsed verbatim from
`docs/sources/NIST.SP.800-218.pdf` (the extractor re-verifies each of the 19
practice names appears verbatim in the PDF text and pins `source_pdf_sha256`, so
a 3PAO can confirm the catalog traces to the NIST-signed PDF). The catalog
carries a G3-compliant `provenance` block (camelCase emitter/emittedAt/
sourceCalls/signingKeyId) + a detached Ed25519 signature over the canonical
(RFC 8785) signature-blanked bytes, self-verifying via its embedded public key.
The curated KSI forward map references only ids that exist in `core/ksi-map.ts`
(extractor fails `ERR_SSDF_KSI_UNKNOWN` otherwise); `reviewed: true` is required.

Verification: `npm run typecheck` clean, **964/964 tests passing (+25)**,
`npm run check:reo` (lint:no-stubs G1 + check:coverage-regression G2 +
check:provenance G3) all return 0. Three spec assumptions were corrected against
the authoritative NIST PDF per REO (documented in `docs/slices/T/T.T1.md` §10):
the real active-task count is **42** (not 43) plus 5 withdrawn "Moved to" tasks;
**PW.2 and PW.5 carry no SP 800-53 mapping** (their Table 1 References cite other
frameworks), so 17 of 19 practices are mapped; and the Common Form Section IV
maps to 11 of 19 practices at the practice level. Statutory/regulatory drivers:
EO 14028 §4(e)/(n) (May 12 2021); NIST SP 800-218 v1.1 (Feb 2022, DOI
10.6028/NIST.SP.800-218); OMB M-22-18 (Sep 14 2022) + M-23-16 (Jun 9 2023);
CISA Secure Software Development Attestation Common Form (OMB Control No.
1670-0052, finalized Mar 11 2024); NIST SP 800-53 Rev 5; FedRAMP KSI catalog.

### Added — LOOP-B.B1: Per-finding CVSS+EPSS+criticality+exposure scoring
First slice of LOOP-B (Risk + Remediation Engine). Replaces the LOOP-A.A1
severity-only POA&M sort with a defensible, operator-tunable composite risk
score on every Finding. Four real signals combine per the documented formula
(`composite = w_cvss·cvss_base + w_epss·(epss·10) + w_criticality·(criticality·10) + w_exposure·(exposure·10)`,
default weights `0.4/0.3/0.2/0.1`): FIRST CVSS (3.1 + 4.0) base parsed from a
collector- or operator-supplied vector, FIRST EPSS exploitation probability,
inventory-derived organisational criticality (`data_classification` / `asset_tier`),
and inventory-derived exposure (`public_facing` / `internet_reachable`). The
new `--risk-score` flag emits `out/risk-scores.json` (Ed25519-signed + provenance
block) and rewrites each `KSI-*.json` envelope in place with a `risk_score`
block; `core/oscal-poam.ts findingProps()` surfaces the score as OSCAL props
(`composite-score`, `cvss-version`, `cvss-base`, `cvss-vector`, `epss-score`,
`epss-percentile`, `criticality`, `exposure`, `risk-score-source-*`,
`risk-score-formula`) so a 3PAO can sort/filter the POA&M on numeric severity.

Real-evidence path: CVSS base scores are computed from real FIRST vector strings
(CVSS 3.1 Equations 1-7 + metric constants §7.4 + Roundup per Appendix A; the
spec example `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` pins to 9.8 and a
Scope-Changed vector to 6.4). EPSS is a live HTTPS `GET` to
`https://api.first.org/data/v1/epss` (batched ≤100 CVEs, `core/retry.ts withRetry`
backoff on 429/5xx) with a 24h on-disk cache at `out/.epss-cache.json`.
Criticality + exposure read real `out/inventory.json` asset metadata. Per REO
Rule 4, every signal that cannot be derived from real evidence is marked
`REQUIRES-OPERATOR-INPUT` and its term is dropped from the composite (remaining
weights re-normalised to sum to 1.0) — except CVSS, which always anchors the
score via a clearly-flagged severity fallback; on persistent EPSS failure the
CVE is reported missing rather than substituting `epss=0`. CVSS 4.0 ships a
documented first-cut qualitative approximation (`approximate:true`; full
MacroVector table deferred — risk B.B1-1/B.B1-EXT-2). Both `risk-scores.json`
and the provenance-stamped `.epss-cache.json` are registered in the submission
bundle `WELL_KNOWN` catalogue and covered by the run manifest.

Statutory / regulatory drivers (verbatim citations in `docs/slices/B/B.B1.md`):
FIRST CVSS v3.1 Specification Document (June 2019), FIRST CVSS v4.0
Specification Document (Nov 2023), FIRST EPSS (`https://api.first.org/data/v1/epss`),
NIST SP 800-30 Rev 1 §3.2 ("Risk = function of Threat × Vulnerability ×
Likelihood × Impact"), NIST SP 800-53 Rev 5 RA-3 + RA-5, and CISA BOD 22-01
(KEV `cve_ids` stored for the downstream B.B2 branch).

Files created: `core/risk-score.ts` (pure scorer + EPSS lookup/cache),
`core/risk-config.ts` (typed `risk-config.yaml` loader/validator),
`core/risk-score-emit.ts` (disk emitter), `risk-config.example.yaml`, and three
test files under `tests/core/` plus `tests/fixtures/risk-score/`. Files extended:
`core/envelope.ts` (`Finding.risk_score?` + `references[].cve_id`/`cvss_vector`),
`core/findings.ts` (`FindingInput.risk_score`), `core/oscal-poam.ts`
(`findingProps()` risk props), `core/orchestrator.ts` (`--risk-score` /
`--risk-config` / `--risk-no-epss` + env vars; emit runs before POA&M + signing),
`core/submission-bundle.ts` (`risk-scores-json` + `epss-cache` roles).
Verification: `npm run typecheck` clean; `npm test` 939/939 passing (was 903,
+36 new tests covering §8 T1-T20); `npm run check:reo` returns 0 (G1
lint:no-stubs 0 violations, G2 coverage-regression skip with no local `out/`, G3
check:provenance OK). Shipped out of queue order because the originally-next
W.W2 is blocked on pending dependencies (E.E2 + J.J3); see STATUS.md "Next
priority" and risk B.B1-EXT-1.

### Added — LOOP-W.W1: Prohibited-vendor catalog ingester + canonical-JSON emitter
First slice of LOOP-W (Prohibited-Vendor Screening + Section 889 Reporting).
Builds the single, canonical, Ed25519-signed prohibited-vendor catalog that
every downstream W slice reads (W.W2 subprocessor screen, W.W3 1-business-day
reporter, W.W4 FAR 52.204-26 annual representation). It merges seven
authoritative federal sources into one deterministic, deduplicated, normalized
JSON file (`out/prohibited-vendors-catalog.json`) with a provenance block
pinning per-source SHA-256 digests and a detached Ed25519 signature over the
canonical (signature-blanked) bytes. No interpretation, no inference — the
catalog is the raw substrate; matching logic lives in the downstream slices.

Real-evidence path: the offline-first ingester reads the committed statutory
constants under `data/` (`far-52-204-25-named-entities.json`,
`ndaa-1634-named-entities.json`, `fascsa-orders.json`) plus a snapshot
directory of the live OFAC SDN / BIS Entity List / SAM Exclusions feeds staged
by `scripts/extract-prohibited-vendors.mjs` (one-shot `fetch` + `core/retry.ts`
`withRetry`, then SHA-256-digested into a `MANIFEST.json`). Per-source parsers
normalize names (NFKC + uppercase + whitespace collapse), join OFAC aliases and
addresses on `ent_num`, filter the trade.gov consolidated screening list to BIS
Entity List rows, flatten paginated SAM exclusion pages, and emit the FAR/NDAA
named entities as statutory constants. Malformed rows are kept and flagged with
`requires_operator_input` rather than silently dropped (REO Rule 1.5); terminal
network failures throw typed `OfacFetchError` / `BisFetchError` /
`SamFetchError` / `ConfigError` rather than emitting a stale or partial catalog.

Statutory & regulatory drivers (verbatim citations, accessed 2026-06-07; see
`docs/slices/W/W.W1.md` §2): FAR 52.204-25 — Prohibition on Contracting for
Certain Telecommunications and Video Surveillance Services or Equipment
(https://www.acquisition.gov/far/52.204-25); FAR 52.204-26 — Covered
Telecommunications Equipment or Services — Representation; FAR 52.204-23 —
Prohibition on Contracting for Hardware, Software, and Services Developed or
Provided by Kaspersky Lab Covered Entities; Pub. L. 115-91, Div. A, Title XVI,
§1634, Dec. 12, 2017, 131 Stat. 1738 (NDAA FY2018 Kaspersky prohibition);
Pub. L. 115-232, Div. A, Title VIII, §889, Aug. 13, 2018, 132 Stat. 1917 (NDAA
FY2019 §889); OFAC Specially Designated Nationals and Blocked Persons List
(IEEPA, 50 U.S.C. §§1701-1707; TWEA, 50 U.S.C. App. §§1-44); BIS Entity List,
15 CFR Part 744, Supplement No. 4 (EAR; 15 CFR §744.16); SAM.gov Exclusions,
FAR Subpart 9.4 / 48 CFR §9.404; and the Federal Acquisition Supply Chain
Security Act (FASCSA), 41 U.S.C. §1323, FAR Subpart 4.23, 41 CFR Part 201-1.
NIST SP 800-161 Rev 1 (May 2022) is the C-SCRM cross-reference.

New files: `core/prohibited-vendors-catalog.ts` (builder + signer + disk
emitter + typed loader + injectable fetch seam), `core/prohibited-vendors-parsers.ts`
(seven per-source parsers + RFC-4180 CSV parser + name normalization + schema-
drift detection), `core/prohibited-vendors-config.ts` (typed YAML loader +
validator), `scripts/extract-prohibited-vendors.mjs` (offline snapshot fetcher),
`data/{far-52-204-25,ndaa-1634}-named-entities.json` + `data/fascsa-orders.json`
(committed statutory constants), `prohibited-vendors-config.example.yaml`, and
`tests/core/prohibited-vendors-{catalog,parsers}.test.ts` (+ 6 fixtures).
Modified: `core/sign.ts` (added `signDetached`/`verifyDetached` detached-Ed25519
helpers), `core/inventory-coverage.ts` (added the pure
`augmentCoverageWithProhibitedVendors` merge — sibling counts, no fillRate
regression), `core/submission-bundle.ts` (WELL_KNOWN `prohibited-vendors-catalog`
role), and `core/orchestrator.ts` (`--prohibited-vendors-catalog` flag +
`CLOUD_EVIDENCE_PROHIBITED_VENDORS_CATALOG` env; the catalog emits before
signing so it is covered by the run manifest).

Verification: `npm run typecheck` clean; `npm test` 903/903 passing (+29 new
tests across the two suites, ≥20 per the slice contract); `npm run check:reo`
returns 0 (G1 lint:no-stubs, G2 check:coverage-regression, G3 check:provenance
all green). REO compliance: the emitted catalog carries a top-level camelCase
`provenance` block (`emitter`, `emittedAt`, `sourceCalls`, `signingKeyId`)
satisfying G3, plus a self-verifying detached Ed25519 signature; FAR/NDAA named
entities are statutory constants (REO Rule 3, like NIST control IDs); FASCSA is
operator-supplied real data (REO Rule 4) via the PR-reviewed register because
live PDF auto-extraction awaits `core/pdf-table-extract.ts` (LOOP-C.C3). Three
implementation-discovered risks (W.W1-19/20/21) were filed in
`docs/loops/LOOP-W-RISKS.md`.

### Added — LOOP-A.A5: Rules of Engagement template seed (closes LOOP-A)
Fifth and final slice of LOOP-A. Produces a Word .docx Rules of Engagement
template pre-filled with system identity, authorization-boundary narrative,
IP ranges auto-derived from real `inventory.json`, scan windows, escalation
contacts, and the full controls-in-scope KSI list. The 3PAO opens the
document, completes any `REQUIRES-OPERATOR-INPUT` markers, and obtains
CSP + 3PAO signatures — the RoE is formally 3PAO-authored, but seeding
it from real data eliminates the busywork of transcribing boundaries
and IP ranges from the SSP/inventory.

  - `core/roe-emit.ts`: ~500 lines, dependency-free `.docx` (same OOXML
    + zip-store pattern the SSP-2 renderer uses; no `python-docx`, no
    `docx` npm package). The document is structured as 10 sections:
    1. **System Identity** — name, ID, impact level, CSP, 3PAO, run id,
       FRMR version (auto-filled when provided; REQUIRES-OPERATOR-INPUT
       otherwise).
    2. **Assessment Scope** — boundary narrative + controls-in-scope
       table (one row per KSI in the ksi-map, real and current).
    3. **Assessment Period & Scan Windows** — start/end dates + scan
       window table (operator-supplied; REQUIRES-OPERATOR-INPUT row when
       absent).
    4. **In-Scope Network Addresses** — IP table auto-derived from
       `out/inventory.json` (deduplicated). Each row cites the asset
       type / location / provider for context. When inventory is
       missing or empty, a REQUIRES-OPERATOR-INPUT row explains the fix.
       Operator-supplied `ipRanges` override the inventory list.
    5. **Testing Authorization** — 8-row table of activities × authorized
       × constraints. Standard FedRAMP authorizations (read-only IAM
       enumeration, authenticated scans, configuration capture) hard-
       coded; controversial ones (penetration testing, social
       engineering) emit REQUIRES-OPERATOR-INPUT for explicit CSP
       acknowledgement.
    6. **Out of Scope / Prohibited Activities** — bulleted list of
       things requiring written CSP approval.
    7. **Escalation Contacts** — 6-row default contacts table with
       escalation roles flagged ⚡. Operator-supplied contacts render
       verbatim.
    8. **Incident Handling During Testing** — 5-step procedure
       referencing the FedRAMP Incident Communications Procedures
       (AFR-ICP) the LOOP-G.G2 slice will implement.
    9. **Signatures** — CSP + 3PAO signature/date block.
    10. **Document Provenance** — tool name, run id, inventory source,
        published RoE URL.
  - `RoEEmitOptions`: every operator-supplied field optional;
    `RoEEmitResult.requires_operator_input[]` lists what's still missing.
    `ready_for_signature` is true only when every operator field is
    supplied AND scan windows + IP ranges are populated.
  - **REO compliance**: zero fabricated data. Every IP comes from real
    inventory; every contact field defaults to `REQUIRES-OPERATOR-INPUT`
    when missing (never substitutes "John Doe" or a fake phone number);
    every signature cell is `REQUIRES-OPERATOR-INPUT`; KSI scope list
    is read from real `core/ksi-map.ts`.
  - `core/orchestrator.ts`: new `--roe` flag + `CLOUD_EVIDENCE_ROE`
    env. Runs BEFORE signing so the RoE is covered by the manifest +
    included in the submission bundle. Console output shows IP count,
    contact count, scan window count, and ready-for-signature status.
  - `core/submission-bundle.ts`: added `rules-of-engagement-docx`
    role + `roe.docx` filename to the well-known artifact catalogue
    so the LOOP-A.A4 bundler classifies it correctly.
  - `tests/core/roe-emit.test.ts`: 16 tests covering REQUIRES-OPERATOR-INPUT
    marker emission, operator-supplied verbatim rendering, IP
    derivation from inventory (with dedup), inventory-empty fallback,
    operator override of inventory IPs, default vs supplied contacts
    (with ⚡ escalation flag), KSI scope read, ready_for_signature
    computation, custom outPath, document.xml body content probing,
    and store-only ZIP structure validation via raw OOXML part listing.

Verification: typecheck clean; 874/874 tests passing (+16 from
LOOP-A.A5); `npm run check:reo` returns 0.

**LOOP-A is now complete.** All 5 slices delivered:
  A.1 (POA&M emitter) + A.2 (AP emitter) + A.3 (AR chain wiring) +
  A.4 (submission bundler) + A.5 (RoE template). The full FedRAMP 20x
  submission package — SSP → AP → AR → POA&M → IIW → RoE → signed
  manifest → RFC 3161 timestamp → INDEX.json, all wrapped in a single
  signed tarball — is now emit-able end-to-end with one orchestrator
  run. Next loops (LOOP-B risk engine, LOOP-C document templates,
  LOOP-D diagrams, LOOP-E ConMon, LOOP-F 3PAO UX, LOOP-G AFR family,
  LOOP-H storage + multi-CSO, LOOP-I dashboards, LOOP-J supply chain,
  LOOP-K test ingestion) remain — but LOOP-A delivers a complete
  authorization-time submission package today.

### Added — LOOP-A.A4: FedRAMP 20x submission package bundler
Fourth slice of LOOP-A. Produces a single uploadable artifact — a signed,
timestamped, gzipped tarball — that contains EVERYTHING a 3PAO / FedRAMP
PMO / Authorizing Official needs to review a submission: OSCAL SSP + AP +
AR + POA&M, the Integrated Inventory Workbook (Appendix M), every per-KSI
evidence envelope, the Ed25519-signed manifest, the RFC 3161 timestamp,
and an `INDEX.json` enumerating each artifact with sha256 + role +
in-manifest flag + chain integrity verdict.

The FedRAMP secure repository (USDA Connect.gov for Low/Moderate per R2
findings) expects one upload per submission, not a loose directory. The
bundler also performs chain integrity verification at bundle time — if
the AR's `import-ap` is synthetic, or any required artifact is missing,
`--strict-bundle` mode refuses to write.

  - `core/submission-bundle.ts`: ~500 lines, pure-JS POSIX ustar tar
    writer (no external dependency — node's built-in `zlib` handles
    gzip). Walks `outDir` + `summaries/` for files, classifies each
    against a 24-role well-known catalogue (`oscal-ssp`, `oscal-ap`,
    `oscal-ar`, `oscal-poam`, `inventory-workbook-xlsx`,
    `signed-manifest`, `rfc3161-timestamp`, `ksi-evidence`, etc.),
    computes sha256 per artifact, and emits an `INDEX.json` at the top
    of the archive so a consumer streaming the tarball sees the
    manifest before any payload.
  - **Chain integrity check**: at bundle time, validates that
    `ap.import-ssp.href`, `ar.import-ap.href`, and the POA&M's
    system-id/import-ssp pair all resolve. Synthetic AR import-ap
    (`#cloud-evidence-no-external-ap` from LOOP-A.A3 when no AP exists)
    is flagged as a chain break — the submission package would ship
    with a dangling reference. `--strict-bundle` rejects the bundle in
    that state with a typed error naming the fix.
  - **Required-artifact gap detection**: cross-references the actual
    files in `outDir` against the well-known catalogue's `required:
    true` set (SSP, AP, AR, IIW, manifest, manifest.sig). Each missing
    file is recorded in `INDEX.json.gaps[]` with a description + role
    name. Strict mode refuses to write a bundle with gaps.
  - **Package format versioning**: `INDEX.json.package_format_version =
    "20x.phase-two.preview.2026"` per R3 (no post-Phase-Two-pilot
    guidance published yet). A future format shift produces a clean
    version bump rather than silently changing the structure.
  - **Reproducibility**: when `mtime` is supplied via
    `BundleEmitOptions.mtime`, every tar header gets that fixed seconds-
    since-epoch value + uid/gid/uname/gname=0/root for byte-stable
    bundles across machines. Tests verify byte-identical payload
    sections across two separate runs with the same inputs.
  - **REO compliance**: bundler never synthesizes content — only
    packages what already exists on disk. `INDEX.json.provenance`
    names the bundler module + cites every read. Files outside the
    well-known catalogue (operator-added) are still bundled with role
    = `'unrecognized'` rather than silently dropped.
  - `core/orchestrator.ts`: new `--submission-bundle` flag +
    `CLOUD_EVIDENCE_SUBMISSION_BUNDLE` env. Runs AFTER signing so the
    bundle includes the manifest+sig+RFC3161 timestamp. `--strict-bundle`
    (and `CLOUD_EVIDENCE_STRICT_BUNDLE` env) implies
    `--submission-bundle` and forces exit-code 4 on incomplete
    submissions. Console output shows chain status, gap count, bundle
    sha256, and KB.
  - `tests/core/submission-bundle.test.ts`: 20 new tests covering the
    file catalogue, sha256 + bytes accuracy, in-manifest flag, gap
    detection, chain check (complete + broken-by-synthetic-AR), strict
    mode throwing on gaps + chain breaks, reproducibility (same inputs
    → byte-identical payload sections), tarball round-trip through
    gunzip + POSIX ustar parser, INDEX.json equality on-disk vs in-tar,
    summaries/ subdir traversal, ustar 100-byte name limit, EOF
    zero-trailer padding, and the raw `writeTar()` POSIX ustar writer.

Verification: typecheck clean; 858/858 tests passing (+20 from
LOOP-A.A4); `npm run check:reo` returns 0. OSCAL chain SSP→AP→AR→POA&M
is now packageable as a single signed deliverable.

### Added — LOOP-A.A3: SSP → AP → AR chain wiring via import-ap
Third slice of LOOP-A. Closes the OSCAL chain: `SSP ✅ → AP ✅ → AR ✅ → POA&M ✅`.
The AR's mandatory `import-ap` element now resolves to a real Assessment
Plan reference when one was co-emitted in the same orchestrator run, an
operator-supplied URI when explicit, or a clearly-labelled synthetic anchor
with descriptive remarks when no AP exists. A `--strict-chain` mode refuses
to emit an AR with a synthetic AP reference at all — the right setting for
production submission packages.

  - `core/oscal.ts`: `OscalEmitOptions` gains `strictChain?: boolean`;
    `OscalEmitResult` gains `ap_link?: 'local-ap' | 'explicit-href' | 'synthetic'`.
    The emit body now resolves `import-ap.href` in priority order:
    (1) operator-supplied `assessmentPlanHref`, (2) co-emitted local
    `ap.json`, (3) synthetic anchor `#cloud-evidence-no-external-ap` +
    descriptive remarks. Each path also gets a matching `ap-link`
    prop in `metadata.props` so downstream consumers can read the
    resolution status without re-parsing the href.
  - `strictChain: true` throws a typed error explaining the resolution
    failure when no AP can be resolved. The error names the flags that
    would fix it. The orchestrator passes this when `--strict-chain` is
    set — preventing a submission package from shipping with a synthetic
    AP reference.
  - `core/orchestrator.ts`: new `--strict-chain` flag +
    `CLOUD_EVIDENCE_STRICT_CHAIN` env. AR console output now reports the
    import-ap resolution status (`local-ap` / `explicit-href` / `synthetic`).
    When `--oscal-ap` runs in the same invocation, the AR auto-resolves to
    the local `ap.json` without any further configuration.
  - `tests/core/oscal.test.ts`: +6 tests covering all three resolution
    paths, `strictChain` enforcement (throws on synthetic, accepts
    local-ap, accepts explicit-href), and the `ap-link` metadata prop.

Verification: typecheck clean; 838/838 tests passing (+6 from LOOP-A.A3);
`npm run check:reo` returns 0. OSCAL chain SSP→AP→AR→POA&M is now
end-to-end complete and operator-controllable.

### Added — LOOP-A.A2: OSCAL Assessment Plan v1.1.2 emitter
Second slice of LOOP-A. Closes the missing middle of the OSCAL chain:
`SSP ✅ → AP ✅ → AR ⚠️ → POA&M ✅`. The Assessment Plan describes WHAT the
3PAO will assess, by WHAT methods, against WHICH controls — historically a
Word .docx, but RFC-0024 mandates OSCAL JSON for 20x submissions. This
emitter bootstraps a draft AP from the same evidence the SSP / AR / POA&M
already use, so the 3PAO refines + signs rather than authoring from scratch.

  - `core/oscal-ap.ts`: ~700 lines, schema-driven against the OSCAL v1.1.2
    assessment-plan schema. Required-by-spec emit: `uuid` + `metadata` +
    `import-ssp` (min/max=1) + `reviewed-controls.control-selections`.
    Optional emit (all populated when inputs available): `local-definitions`
    (with `activities[]` — one per registered KSI), `terms-and-conditions`
    (RoE + Sampling Methodology parts), `assessment-subjects[]` (derived
    from real `inventory.json`), `assessment-assets` (collector + tracker +
    leveraged-cloud components), `tasks[]` (default 4-phase FedRAMP plan:
    Scoping → Discovery → Testing → Reporting), `back-matter` (RoE +
    Sampling + signed manifest links).
  - Reviewed-controls enumerates EVERY control in the FedRAMP baseline at
    the impact tier via `buildControlBenchmark()` — 149 controls at Low,
    >150 at Moderate. No synthetic IDs; the control list mirrors the same
    benchmark the SSP and AR use.
  - `local-definitions.activities[]`: one OSCAL activity per registered
    KSI (44 today), each carrying `method=TEST` + `ksi-id` props. The
    activity description names the SDK calls the collector will execute.
    Uses `activities[]` (canonical AP slot per the v1.1.2 schema), not
    the `assessment-methods[]` slot which lives in AR not AP.
  - `assessment-subjects[]`: when `inventory.json` exists, derives
    component-group subjects (one per provider×asset-type) + per-asset
    inventory-item subjects (capped at 1000 for compactness). When
    inventory is absent, emits a single `include-all` subject with a
    `REQUIRES-OPERATOR-INPUT:` marker — per the REO rule, never
    silently substitutes fake subjects.
  - Operator-supplied inputs flow through CLI flags + env: `--ap-roe-href`
    populates the RoE back-matter resource + terms-and-conditions prose;
    `--ap-sampling-href` populates the Sampling Methodology resource;
    `--3pao-name` records a 3PAO party in metadata. Each is OPTIONAL —
    when missing, a `REQUIRES-OPERATOR-INPUT:` marker is emitted naming
    the field + the flag to set, so a 3PAO sees the gap at-a-glance.
  - Tasks: when `tasks[]` is operator-supplied with dates, emit real
    `timing.within-date-range`. When dates are omitted, emit
    `REQUIRES-OPERATOR-INPUT:` in `task.remarks` instead of fabricating
    a date. Default 4-phase plan covers FedRAMP scoping → discovery →
    testing → reporting.
  - Deterministic UUIDs throughout via `deterministicUuid()`; same
    inputs → byte-identical document.
  - `scripts/extract-oscal-schemas.mjs`: added `assessment-plan` to the
    pinned-model list; `core/oscal-validate.ts`: `OscalModel` now
    includes `'assessment-plan'`. The committed schema
    (`docs/oscal/oscal_assessment-plan_schema.v1.1.2.json`, 94 KB) is
    sourced from `usnistgov/OSCAL` v1.1.2 release assets, same OSC-2
    pattern as the other models.
  - `core/orchestrator.ts`: new `--oscal-ap` flag +
    `CLOUD_EVIDENCE_OSCAL_AP` env. Runs BEFORE signing so the AP is
    covered by the run manifest. `--ap-roe-href` /
    `--ap-sampling-href` / `--3pao-name` flags wire to optional AP
    inputs (+ env equivalents). ajv-validated against the committed
    OSCAL schema; `--strict-schema` forces exit-code 2 on validation
    failure.
  - `tests/core/oscal-ap.test.ts`: 17 new tests covering schema validity
    at Low + Moderate, required metadata, import-ssp + sspHref override,
    full baseline-control enumeration (no synthetic IDs), activities per
    KSI from real ksi-map source, REQUIRES-OPERATOR-INPUT marker emission
    when RoE / sampling / dates are omitted, operator-supplied inputs
    populating real back-matter resources, real subject derivation from
    `inventory.json`, fallback include-all subject when inventory is
    missing, determinism, XML emission parity, custom outPath,
    `CLOUD_EVIDENCE_DISABLE_OSCAL_XML` toggle.

Verification: typecheck clean; 832/832 tests passing (+17 from LOOP-A.A2);
`npm run check:reo` returns 0.

### Added — LOOP-A.A1: OSCAL POA&M v1.1.2 emitter
First slice of LOOP-A (OSCAL package completeness). Closes the highest-
leverage gap in the FedRAMP authorization + monthly Continuous Monitoring
submission package: every CSP must submit a Plan of Action and Milestones
documenting open findings with remediation deadlines. RFC-0024 mandates
OSCAL JSON; this slice ships full OSCAL v1.1.2 conformance + an XML
projection via the existing oscal-xml.ts.

  - `core/oscal-poam.ts`: 600+ lines, schema-driven. Reads every
    `KSI-*.json` evidence file from outDir, maps each FAILING finding to:
    (1) a `poam-item` (always), (2) an `observation` per `RawEvidence`
    cited (deduplicated across findings citing the same SDK call), (3) a
    `finding` per (rule × NIST control) pair so each item traces back to
    baseline controls, (4) a `risk` for any severity > info with a
    deterministic FedRAMP remediation deadline (Critical 30d, High 60d,
    Medium 90d, Low 180d, Info 365d counted from envelope.collected_at).
  - Deterministic UUIDs via `oscal.ts` `deterministicUuid()` — re-running
    on identical evidence produces an identical document, supporting
    LOOP-E.E2 (monthly POA&M workflow) full-document re-emission semantics
    per `docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`.
  - Emits both `import-ssp` (when an SSP is co-emitted in the same run)
    AND `system-id` so the chain works whether or not the SSP exists yet.
  - back-matter references the signed evidence manifest when signing is
    enabled — the 3PAO can follow the chain from POA&M → manifest →
    per-KSI evidence file → SDK call.
  - `metadata.revisions[]` history can be threaded through monthly runs
    via `PoamEmitOptions.revisionsHistory` so a single POA&M document
    captures the full version chain (LOOP-E.E2 wiring).
  - OSCAL schema's `poam-items.minItems=1` constraint is handled
    correctly: when there are zero failing findings, `emitOscalPoam()`
    returns a structured `{path: null, skipped_reason: "no-failing-findings"}`
    result rather than writing an invalid document. The orchestrator
    logs this as a clean-state event, NOT a missing-evidence error.
  - `core/orchestrator.ts`: new `--oscal-poam` flag +
    `CLOUD_EVIDENCE_OSCAL_POAM` env. Emitter runs BEFORE signing so the
    POA&M is covered by the manifest. ajv validates against the
    committed OSCAL v1.1.2 schema; failure under `--strict-schema`
    forces exit-code 2.
  - `tests/core/oscal-poam.test.ts`: 18 new tests covering schema
    validity, required metadata fields, import-ssp+system-id wiring,
    back-matter signed-manifest reference, per-finding poam-item +
    observation + risk creation, severity-based deadline math
    (deterministic), empty-state skip semantics, XML emission parity,
    `CLOUD_EVIDENCE_DISABLE_OSCAL_XML` toggle, and selective file-
    name pattern matching (KSI-*.json only).

Verification: typecheck clean; 815/815 tests passing (+18 from LOOP-A.A1);
`npm run check:reo` returns 0.

### Added — R1 + R2 + R3 + R4: pre-loop research findings
Before LOOP-A.A1 started, four research blockers were resolved via direct
catalog walks + fedramp.gov fetches:

  - **R1** — `docs/AFR-FAMILY-CLASSIFICATION.md`: walked
    `FRMR.documentation.json` directly. All 10 AFR-* families (PVA, FSI,
    ICP, ADS, MAS, CCM, SCG, SCN, VDR, UCM) are REQUIRED at Moderate —
    85 MUST entries across 160 total, each family has at least one MUST.
    LOOP-G scope confirmed: G1 through G6 all stay as REQUIRED slices.
  - **R2** — Monthly POA&M format: full-document re-emission to USDA
    Connect.gov repository (Low/Mod CSOs). OSCAL JSON + XML supported.
    LOOP-A.A1 implements this semantics. The Excel POA&M template is a
    companion artifact for LOOP-A.A4 (submission bundler).
  - **R3** — Phase Two pilot output format: no post-pilot guidance
    available publicly. RFC-0014 remains authoritative. LOOP-A.A4 will
    emit `package_format_version: "20x.phase-two.preview.2026"` so a
    future format shift can be cleanly versioned.
  - **R4** — Sampling: 100% of inventory monthly is baseline; sampling
    permitted for internal-only assets (NOT externally accessible) per
    methodology in SAP Appendix B with AO approval. LOOP-F.F3 will
    auto-derive this with a stratified-by-asset-class minimum-10% floor.
  - `docs/PRE-LOOP-A-RESEARCH-FINDINGS.md` consolidates all four findings
    + cites primary sources.

### Added — REO-0: Real-Evidence-Only standard + 3 CI guardrails
Foundational rule + enforcement layer for the 46-week LOOP-A through LOOP-K
execution plan. The REO standard codifies the no-stubs / no-fixed-data /
no-lazy-work directive: every byte emitted by this repo must trace back to
real evidence (cloud SDK call, FRMR catalog read, NIST publication, tracker
DB query) or to operator-supplied configuration. Placeholder strings, sample
data, mock SDKs in production paths, fake signatures, and "TODO: implement
later" comments are explicitly forbidden in `core/`, `providers/`,
`tracker/`, and `scripts/`.

  - `cloud-evidence/CLAUDE.md`: new standard doc loaded by every session.
    Rule 1 (no stubs/placeholders/fake-data in production paths), Rule 2
    (per-slice Real Slice Contract — done means real evidence flows
    end-to-end, signed, tested on the real path, no new lint hits), Rule 3
    (narrow allowed exceptions: OSCAL/FedRAMP/NIST/cloud-published
    constants), Rule 4 (operator-supplied data flows through tracker DB,
    config.yaml, cloud tags, or CLI flags — never silently defaulted).
  - `scripts/lint-no-stubs.mjs` (G1): greps production paths for forbidden
    tokens with an allowlist for the standard's own files. JSX/HTML
    `placeholder="..."` attributes excluded via negative lookahead.
  - `scripts/check-provenance.mjs` (G3): every emitted artifact under
    `out/` must carry a top-level `provenance` block (emitter, emittedAt,
    sourceCalls, signingKeyId) — OR be a recognized envelope (KSI evidence:
    ksi_id + run_id + collected_at + frmr_version + providers[].evidence[].source;
    OSCAL: uuid + metadata.last-modified + version + oscal-version) with
    structural provenance equivalents.
  - `scripts/check-coverage-regression.mjs` (G2): diffs current
    `out/inventory-coverage.json` against `coverage-baseline.json`; fails
    if any (column, cloud) fill-rate decreased. SKIPs cleanly when no
    current report exists (dev env without cloud creds).
  - `package.json`: new scripts `lint:no-stubs`, `check:provenance`,
    `check:coverage-regression`, `check:reo`.
  - `.github/workflows/ci.yml`: G1 + G3 wired as required checks on every
    push and PR. `.github/workflows/cloud-evidence.yml`: G1 + G2 + G3 wired
    after `npm run collect` so production regressions surface immediately.
  - `core/oscal-ssp.ts`: removed two REO violations. Authorization-boundary
    description + system-implementation.users[] now accept
    `SspEmitOptions.authorizationBoundaryDescription` and
    `SspEmitOptions.userRoles[]`. When omitted, an explicit
    `REQUIRES-OPERATOR-INPUT:` marker is emitted (with the name of the
    missing field + how the operator provides it) instead of placeholder
    text. A 3PAO sees the gap at-a-glance instead of mistaking placeholder
    prose for finalized narrative.
  - 9 wording corrections across `core/csx-sum-aggregator.ts`,
    `core/pva-collector.ts`, `core/scn-classifier.ts`,
    `providers/aws/{logging,network,vdr-scan}.ts`,
    `providers/gcp/{logging,network}.ts`: `KSI-XXX` → `KSI-<id>`;
    "Sample finding lifecycle" → "Representative finding lifecycle"; etc.
  - `tests/scripts/reo-guardrails.test.ts`: 15 new tests covering G1 / G2 /
    G3 behavior including KSI envelope structural check + JSX placeholder
    exclusion. `tests/core/oscal-ssp.test.ts`: 4 new tests covering
    REQUIRES-OPERATOR-INPUT marker + operator-supplied override.

Verification: typecheck clean; 797/797 tests passing (+19 from REO-0);
`npm run check:reo` returns 0 against the current tree (lint OK, provenance
OK, coverage-regression SKIP because no live collection run in dev env).

### Added — INV-S1..S6: full FedRAMP Appendix M inventory coverage across all three clouds
Six-slice sequential delivery closes every cloud-side cell in the FedRAMP
Integrated Inventory Workbook (24 of 25 columns; column T "Comments" stays
operator-supplied with a tag override available). Adds a Coverage Contract
registry that makes "assumed blank" regressions impossible going forward.

INV-S1 — Coverage Contract + per-run report
  - `core/inventory-coverage.ts`: typed registry of all 25 columns × 3 clouds
    × source-per-cell + status. Module-load invariant fails if order or
    count drifts from `APPENDIX_M_COLUMNS`.
  - `core/inventory-coverage-report.ts`: per-run measurement → `out/inventory-coverage.json` + 1-line console summary (e.g. "AWS 96% · GCP 84% · Azure 72%").
  - Orchestrator wired between snapshot build and workbook write.

INV-S2 — Azure depth (9 new enrichers)
  - NIC IPs + MAC + Public-IP resolve + subnet/vnet path for VMs.
  - Azure SQL (Server + DB), Cosmos DB, AKS, App Service / Function Apps,
    Application Gateway, Load Balancer, Managed Disks, ACR, Key Vault.
  - Closes Azure columns C, G, H, N, P, Q, V.

INV-S3 — GCP OS Config + MAC enrichment
  - Compute Instance NIC MAC pulled from CAI passthrough (column G).
  - OS Config inventories.list → osNameVersion (K) + netbiosName for
    Windows hosts (F) + patchLevel (R). `roles/osconfig.inventoryViewer`
    documented as optional permission.

INV-S4 — Azure VM osProfile + patchassessmentresults
  - `osProfile.computerName` → netbiosName (column F).
  - `patchassessmentresources.osName + osVersion` supersedes
    imageReference for live OS (column K full).
  - `lastAssessmentResult + missing-patch count` → patchLevel (column R).

INV-S5 — Azure VDR scan reconcile
  - `assessedResourceId(assessmentId, resourceDetails.Id)` extracts the
    underlying assessed VM/disk/etc id from each Defender assessment.
  - `providers/azure/vdr-scan.ts` surfaces `assessed_resource_ids` on
    evidence; `core/inventory-workbook.ts:readInventoryContext` now walks
    `evidence[].data.assessed_resource_ids` for VDR-class KSIs in addition
    to the existing gap.affected_resources path.
  - Result: every Defender-assessed Azure resource (healthy + unhealthy)
    flips `inLatestScan = true` + `authenticatedScan = true` →
    columns I + O filled.

INV-S6 — Diagram Label auto-synth + Comments tag passthrough
  - `synthesizeDiagramLabel` derives `<friendly-type>-<name>@<location>`.
  - `applyDiagramLabelAndComments` honours operator overrides via tags:
    `diagram_label` / `DiagramLabel` / `inventory_label` / `fedramp_label`
    (column S). `inventory_comments` / `fedramp_comments` / `comments`
    tags pass through to column T verbatim.
  - Orchestrator runs the new pass right after `enrichFromTags` so every
    asset gets a sensible non-blank Diagram Label by default.

Net: 24/25 columns filled for every asset across AWS+GCP+Azure. Column T
stays blank when no operator tag is set (FedRAMP-defined as operator-
supplied); even that has a documented override path.

Coverage Contract guarantees:
  1. Every blank cell in the workbook has a documented `blank_reason`
     or a slice id that ships the source.
  2. The per-run `inventory-coverage.json` shows the exact fill rate
     per (column, cloud) — operators + CI can detect any regression.
  3. Subsequent provider edits that drop a cell raise a measurable
     drop, not a silent failure.

Tests: 778 total (up from 733 before INV-S1). Per-slice breakdown:
  - INV-S1: 13 coverage-registry + report tests
  - INV-S2: 11 Azure enricher tests
  - INV-S3: 6 GCP OS Config + MAC tests
  - INV-S4: 3 Azure osProfile/patchassessment tests
  - INV-S5: 4 Azure VDR-scan reconcile + helper tests
  - INV-S6: 10 Diagram Label + Comments tests

### Fixed — Authoritative KSI count (60, not 63) + Phase 4 / High-impact clarification
Reconciles three FedRAMP-20x state-of-the-program issues surfaced by a
deep-research audit against the authoritative FRMR sources (github.com/FedRAMP/docs
v0.9.43-beta, fedramp.gov/20x/phases, RFC-0014). Net: the codebase now matches
the upstream catalog exactly, no fabricated counts, no implied High-tier scope.

- **CSX-PURGE — extractor no longer reclassifies 3 FRR entries as KSIs.**
  `scripts/extract-frmr-requirements.mjs` previously flagged `KSI-CSX-MAS`,
  `KSI-CSX-ORD`, `KSI-CSX-SUM` (which live in `FRR.KSI`, not the top-level
  KSI section) as `category: 'ksi-indicator'` to inflate the count to "63
  KSIs". Direct inspection of FRMR.documentation.json v0.9.43-beta confirms
  the authoritative KSI section contains exactly 60 entries; the 3 CSX
  entries are FRR-class meta-rules about the KSI assessment process
  (Minimum Assessment Scope, AFR Order, Implementation Summaries). They
  stay categorized as `frr-requirement` now. The orchestrator continues to
  emit a synthetic `KSI-CSX-SUM.json` aggregator file — that's a
  legitimate orchestration choice, not a catalog claim.
  - `docs/frmr-requirements.generated.json` regenerated: now 60 ksi-indicator
    + 163 frr-requirement (was 63 + 160).
  - `tests/core/level-coverage.test.ts` updated: asserts 60 KSIs; the 3
    `KSI-CSX-*` entries are now expected as `frr-requirement`.
  - `tracker/server/ingest.ts` comment refreshed: explains why the tracker
    still surfaces CSX as a 12th informational domain even though the
    authoritative KSI count is 60.

- **RFC-0014-VERIFY — confirms all 8 RFC-0014 KSIs are in the JSON.** The
  deep-research had flagged as an open question whether RFC-0014's 5
  Moderate-only KSIs (KSI-CNA-08, KSI-MLA-08, KSI-SVC-08/09/10) and 3
  Low+Mod KSIs (KSI-CED-03, KSI-IAM-07, KSI-MLA-07) had been merged to
  v0.9.43-beta. Direct `fka` lookup confirms: all 8 are present under
  their renamed 3-letter ids (KSI-CNA-EIS, KSI-MLA-LET, KSI-MLA-ALA,
  KSI-SVC-PRR, KSI-SVC-VCM, KSI-SVC-RUD, KSI-CED-DET, KSI-IAM-AAM). All 8
  are already covered by our collectors / playbooks. No code change
  required; documented here so future audits can skip the question.

- **HIGH-CLARIFY — `--impact-level high` startup warning + design doc.**
  FedRAMP 20x Phase 4 (Class D / High pilot) is scheduled FY27 Q1–Q2 and
  has not been published. `core/orchestrator.ts` now emits an explicit
  3-line NOTICE on `--impact-level high` runs explaining that High
  applicability is sourced from the NIST 800-53 Rev5 High baseline
  parameter overlay (via `core/control-benchmark.ts`), NOT from
  20x-specific High obligations (which don't exist yet). The new
  `cloud-evidence/docs/IMPACT-LEVEL-NOTES.md` documents the design of
  record: how the tool is structured for High today, exactly what
  audit-package consumers should cite, and what will change when Phase 4
  lands. Audit packages produced at `--impact-level high` should cite
  NIST SP 800-53 Rev5 High as the authoritative controlling baseline.

**Empirical correctness: tsc clean; 733 tests pass (with the count
assertion updated to 60).**

### Added — AZ-PARITY: 7 Azure HYBRID collectors close the cross-provider gap (44 KSIs all 3-cloud)
Closes the 7-KSI Azure parity gap surfaced by the FedRAMP 20x coverage audit.
With this slice, every collector-tracked KSI in ksi-map.ts has AWS + GCP +
Azure provider coverage (44/44 across all three clouds).

- **`providers/azure/ksi-hybrids.ts`** (new) — 5 HYBRID collectors mirroring
  `providers/{aws,gcp}/ksi-hybrids.ts`:
  - `collectCmtRvp` (Reviewing Change Procedures) — policy assignments +
    policystates table non-empty (change-management baseline actively running).
  - `collectInrAar` (Generating After Action Reports) — Sentinel automation
    rules OR Monitor/Defender alert rules present.
  - `collectInrRpi` (Reviewing Past Incidents) — Log Analytics workspace
    retention ≥ 90 days (past-incident review window).
  - `collectScrMit` (Mitigating Supply Chain Risk) — ACR trust/quarantine
    policy enabled OR Defender for Containers on Standard tier.
  - `collectSvcPrr` (Preventing Residual Risk) — storage accounts deny
    public network + anonymous blob access.
- **`providers/azure/crypto.ts`** (new) — 1 collector for KSI-AFR-UCM:
  - `collectUcm` — at least one of: Key Vault keys (enabled), Application
    Gateway with modern TLS-1.2-min SSL policy, or storage account with
    `requireInfrastructureEncryption = true`. Alternative satisfier covers
    external HSM (Thales Luna / nCipher).
- **`providers/azure/vdr-scan.ts`** (new) — 1 collector for KSI-AFR-VDR:
  - `collectVdrScan` — Defender for Cloud `microsoft.security/assessments`
    joined with the committed CISA KEV catalog
    (`docs/cisa-kev.generated.json`). Passes only when there are zero
    Unhealthy assessments referencing a KEV CVE. Matches the AWS/GCP
    `vdr-scan.ts` join semantics exactly.
- **`ksi-map.ts`** — azure slot wired for KSI-CMT-RVP, KSI-INR-AAR,
  KSI-INR-RPI, KSI-SCR-MIT, KSI-SVC-PRR, KSI-AFR-UCM, KSI-AFR-VDR.
- **IAM-PERMISSIONS-CATALOG** — 3 new rows. `Reader` covers ksi-hybrids
  (except SCR-MIT's pricings read) + crypto entirely; `Security Reader`
  covers SCR-MIT + VDR-scan (`securityresources` table).
- **27 new dedicated tests** (16 ksi-hybrids + 6 crypto + 5 vdr-scan)
  exercising pass/fail/vacuous/escape paths and the KEV-join logic.

**Cross-provider parity now: AWS 44 / GCP 44 / Azure 44 (all 44 collector-
tracked KSIs). 209 dedicated Azure tests; 733 total. tsc clean; CI green
once the push lands.**

### Added — OSC-3: OSCAL XML output (zero open backlog)
Closes the last open backlog row. Both OSCAL emitters now write an XML
representation alongside the JSON by default, so downstream FedRAMP tooling
(oscalkit / GoComply/fedramp / older 3PAO pipelines) can consume the output
without operator format-conversion friction.

- **New `core/oscal-xml.ts`** — pure-JS JSON→XML converter targeting the
  OSCAL 1.1.2 metaschema mapping:
  1. **Flag keys → XML attributes** (`uuid`, `id`, `name`, `value`, `class`,
     `href`, `rel`, `type`, `ns`, `level`, `state`, `media-type`, `scheme`,
     `version`, `target-id`, `subject-uuid`, `observation-uuid`,
     `risk-uuid`, `party-uuid`, `role-id`, `control-id`, `sequence`).
  2. **Plural keys → repeated singular elements** via a hand-curated table
     covering the surface area both `assessment-results` and SSP emitters
     produce (`results` → `<result>`, `findings` → `<finding>`,
     `responsible-parties` → `<responsible-party>`, etc.).
  3. **Prose wrapping**: `description` / `remarks` / `rationale` /
     `guidance` strings get a `<p>…</p>` wrapper to satisfy the inline-prose
     content model.
  4. **Namespace**: root element gets `xmlns="http://csrc.nist.gov/ns/oscal/1.0"`
     plus an `xmlns:fedramp="https://fedramp.gov/ns/oscal"` alias for our
     custom props.
  5. Full XML escaping (`& < > " '`) on both attribute values and element
     bodies; safe for arbitrary observation text from real cloud SDK output.
- **`core/oscal.ts`** + **`core/oscal-ssp.ts`** — both emitters now write a
  sibling `.xml` next to the `.json` by default. Opt out via
  `CLOUD_EVIDENCE_DISABLE_OSCAL_XML=1`. The XML path is returned on
  `OscalEmitResult` / `SspEmitResult` (new optional `xml_path` field).
- **`core/sign.ts`** — manifest now signs `.json` **plus** `.xml` **plus**
  `.pem` (the ephemeral signing key files). The order of operations was
  corrected: ephemeral keys are now materialized **before** the file
  enumeration so they're part of the signed set. Defense-in-depth: a
  verifier can detect substitution of the key material itself.
- **`core/oscal-validate.ts`** — comment refresh clarifying that the XML
  derived by `oscal-xml.ts` is correct by construction (the JSON we validate
  is the single source of truth; XML is a deterministic projection), so no
  XSD/Schematron pass and no Saxon/Java dependency is needed.
- **14 new dedicated tests** for the converter:
  - 11 mapping/escaping/well-formedness tests (namespace, flag→attribute,
    plural→singular, prose wrapping, party-uuids string array, XML escaping,
    XML declaration, error on missing wrapper key, null/undefined skip,
    plural→singular heuristic fallback, balanced-tag invariant).
  - 3 end-to-end tests (`emitOscalAssessmentResults` + `emitOscalSsp` write
    XML by default; `CLOUD_EVIDENCE_DISABLE_OSCAL_XML=1` opts out).
- **`tests/core/sign.test.ts`** updated: expected `files_signed` for the
  baseline case grew from 2 to 4 (2 KSI evidence files + 2 ephemeral pem
  files) reflecting the broader, more-correct signing scope.

**706 tests pass; tsc clean. 00-INDEX implementation table now has zero
backlog rows.**

### Cleaned — stale "later phase" markers (no deferred work in source/docs)
Five deferred-work markers found in the audit have been resolved:

- `providers/aws/supplychain.ts` header — "SCR-MON will land here in a
  later phase" → header now lists CMT-RMV + CMT-VTD + SCR-MON.
- `providers/aws/backup.ts` header — "RPL-ABO and RPL-TRC will live here
  too in a later phase" → header now lists CNA-OFA + RPL-ABO + RPL-TRC.
- `providers/aws/backup.ts` `note: 'PITR per-table check pending Phase 5
  (RPL-ABO)'` → rewritten as a clean cross-reference to KSI-RPL-ABO's
  `aws.dynamodb.pitr_enabled_for_prod` (and clarifying that CNA-OFA stays
  inventory-only by design to avoid double-counting).
- `providers/gcp/iam.ts` (two collectors) —
  `workforce_pool_providers: [] // expand when we enumerate WIF providers
  in later phase` is now real enumeration via
  `iam.workforcePools.providers.list` per pool. IdP attribution
  (okta-saml / azure-ad-oidc / …) flows into the 3rd-party tool detector
  for both org-scoped and project-scoped pool lookups.
- `docs/RSI-COVERAGE-ANALYSIS.md` header — "Implementation pending
  approval" → updated to reflect the per-requirement coverage rollout's
  completion.

### Added — Azure RPL-ARP + RPL-RRO (closes out the AZ-2 family; 37 KSIs Azure-covered)
Two HYBRID recovery closeouts land in `providers/azure/backup.ts`. With this
slice, **every cloud-enforceable KSI in the FRMR catalog has an Azure
collector** — Azure now sits at parity with AWS and GCP on the per-KSI
evidence surface.

- **`collectRplArp`** (Aligning Recovery Plan — HYBRID) — 1 finding +
  KSI-level alt satisfier:
  - `azure.rpl.arp.alternate_processing_posture` (medium) — at least one
    Recovery Services Vault has `redundancySettings.standardTierStorageRedundancy`
    containing "Geo" (GeoRedundant / GeoZoneRedundant). The vault layer
    is where an alternate-processing site actually lives for restores.
  - Alt satisfier: Azure SQL geo-replicas / Cosmos multi-region writes /
    Storage RA-GZRS — the data-tier failover path.
- **`collectRplRro`** (Reviewing Recovery Objectives — HYBRID) — 1 finding:
  - `azure.rpl.rro.backup_policy_codifies_rpo` (medium) — at least one
    backup policy under a Recovery Services Vault has a non-empty
    `schedulePolicy.scheduleRunFrequency`. The backup cadence is the
    machine-readable codification of the achieved RPO; the documented
    target RPO + the cadence-vs-target review are tracked as process
    artifacts in ksi-map.ts.
- `ksi-map.ts`: `azure` slot wired for KSI-RPL-ARP and KSI-RPL-RRO.
- IAM-PERMISSIONS-CATALOG: backup.ts row updated to cover all four RPL
  collectors; `Reader` remains sufficient.
- 8 new dedicated tests (4 RPL-ARP: geo pass / GeoZoneRedundant pass /
  LRS+ZRS fail / no-vault fail with alt satisfier; 4 RPL-RRO: Daily
  passes / empty schedFreq fails / no policies fails vacuously / multi-
  frequency aggregation).

**AZ-2 family complete: 37 KSIs Azure-covered, 182 dedicated Azure tests
+ smoke, 692 tests total. Azure is now at full parity with AWS + GCP for
the cloud-side per-KSI evidence surface.**

### Added — Azure SCR-MON + PIY-GIV (supply-chain monitoring + inventory)
Two more Azure KSI collectors. KSI-PIY-GIV is now AWS + GCP + Azure;
KSI-SCR-MON (HYBRID) is too.

- **`collectScrMon`** (Monitoring Supply Chain Risk — HYBRID) extends
  `providers/azure/supplychain.ts` — 2 findings + KSI-level alt
  satisfiers:
  1. `azure.scr.mon.defender_mdvm_active` (high) — at least one of
     Defender for VirtualMachines / Servers / Containers /
     ContainerRegistry on Standard tier. These plans are the carriers
     for Microsoft Defender Vulnerability Management (MDVM) — the Azure-
     native upstream-CVE feed.
  2. `azure.scr.mon.security_contact_configured` (medium) — at least one
     `microsoft.security/securitycontacts` row has a non-empty email AND
     `alertNotifications.state` not equal to `Off`.
  - Alt satisfiers: 3rd-party vuln-feed (Snyk Advisor / Dependabot /
    Mend Renovate); vendor-advisory mailing lists (CISA / MSRC / NVD
    RSS) routed to security@.
- **`collectPiyGiv`** (Generating Inventories) in new
  `providers/azure/inventory.ts` — 1 finding:
  - `azure.piy.giv.inventory_signal_active` (high) — Resource Graph
    returns non-zero assets across the configured subscriptions, with a
    by-type breakdown captured as observations (top 20 types). Resource
    Graph is the Azure-canonical authoritative real-time inventory; the
    KSI signal is simply "is the inventory query path live and the
    runner principal bound to Reader everywhere?".
- `ksi-map.ts`: `azure` slot wired for KSI-SCR-MON and KSI-PIY-GIV.
- IAM-PERMISSIONS-CATALOG: SCR-MON on `Security Reader`; PIY-GIV on
  `Reader` (same backbone the inventory-workbook generator uses).
- 10 new dedicated tests (6 SCR-MON: full pass / accept VM plan /
  reject unrelated plan / no-email contact / alert-off / alt satisfiers;
  4 PIY-GIV: non-zero / zero / many types aggregation / no-subscriptions
  warning). **174 dedicated Azure tests, 684 total. 35 Azure KSIs
  covered.**

### Added — Azure SVC-RUD + SVC-VCM + SVC-VRI (data plane KSIs)
Three Azure data-plane KSI collectors land in new `providers/azure/data.ts`.
KSI-SVC-RUD and KSI-SVC-VRI are now AWS + GCP + Azure; KSI-SVC-VCM (HYBRID)
is too. All via Resource Graph management-plane reads — no Storage Blob
Data role needed (we read metadata, not blob contents).

- **`collectSvcRud`** (Removing Unwanted Data) — 2 findings + KSI-level
  alt satisfier:
  1. `azure.svc.rud.blob_soft_delete_finite_window` (medium) — every
     storage account has blob soft-delete enabled with retention between
     1 and 90 days (audit window without blocking actual deletion under
     customer-SLA).
  2. `azure.svc.rud.lifecycle_management_present` (medium) — at least
     one `microsoft.storage/storageaccounts/managementpolicies` exists
     (retention/deletion is automated, not manual).
  - Alt satisfier: application-layer deletion + DB TTL with audit log.
- **`collectSvcVcm`** (Validating Communications — HYBRID) — 1 finding
  + KSI-level alt satisfiers:
  - `azure.svc.vcm.mtls_or_service_mesh_present` (medium) — at least one
    of: Application Gateway with SSL profile (mTLS), API Management with
    `negotiateClientCertificate=true`, OR an AKS cluster with
    `serviceMeshProfile.mode = "Istio"`.
  - Alt satisfiers: external service mesh (Linkerd / Consul / Cilium /
    OSM) on AKS; code-level mTLS via shared CA.
- **`collectSvcVri`** (Validating Resource Integrity) — 1 finding +
  KSI-level alt satisfier:
  - `azure.svc.vri.storage_integrity_present` (medium) — every storage
    account has blob versioning enabled OR is covered by at least one
    immutability policy. ID-substring matcher reconciles the
    storage-account container ↔ child immutability-policy id.
  - Alt satisfier: Azure Confidential Compute TEE attestation for
    VM/container workloads.
- `ksi-map.ts`: `azure` slot wired for KSI-SVC-RUD, KSI-SVC-VCM, KSI-SVC-VRI.
- IAM-PERMISSIONS-CATALOG: one row added covering all three collectors —
  `Reader` is sufficient.
- 15 new dedicated tests (5 SVC-RUD: full pass / soft-delete off / overly
  long retention / no lifecycle / vacuous; 5 SVC-VCM: AGW mTLS / APIM
  client-cert / AKS Istio / all-off / alt satisfiers; 5 SVC-VRI:
  versioning on / immutability covers unversioned account / unprotected
  failure / vacuous / alt satisfier). **164 dedicated Azure tests, 674
  total. 33 Azure KSIs covered.**

### Added — Azure CMT-RMV + CMT-VTD (ACR + Defender for DevOps)
Two more Azure KSI collectors land in new `providers/azure/supplychain.ts`.
KSI-CMT-RMV is now AWS + GCP + Azure; KSI-CMT-VTD (HYBRID) is too.

- **`collectCmtRmv`** (Redeploying vs Modifying) — 2 findings + KSI-level
  alt satisfier:
  1. `azure.cmt.rmv.acr_present` (medium) — ≥ 1 Azure Container Registry
     inventoried.
  2. `azure.cmt.rmv.acr_admin_user_disabled` (high) — every ACR has the
     legacy admin user disabled. `null` treated as disabled (ACR default).
     RBAC-only push/pull is the IAM-ELP story applied at the registry.
  - Alt satisfier: off-Azure registry (ECR / GCR / GHCR / Docker Hub)
    with signing + immutability enforced upstream.
- **`collectCmtVtd`** (Validating Throughout Deployment — HYBRID) —
  2 findings + KSI-level alt satisfiers:
  1. `azure.cmt.vtd.defender_devops_connector_present` (medium) — at
     least one `microsoft.security/securityconnectors` for ADO / GitHub /
     GitLab exists. JS-side env allow-list so a non-DevOps connector
     (e.g. AWS) is correctly rejected.
  2. `azure.cmt.vtd.defender_for_containers_enabled` (high) — Defender
     for Containers on Standard tier in at least one in-scope sub.
  - Alt satisfiers: GitHub Advanced Security / GitLab Ultimate (without
    Defender for DevOps), and 3rd-party CI gates (Snyk / Aqua / Trivy /
    Checkov / Anchore).
- `ksi-map.ts`: `azure` slot wired for KSI-CMT-RMV and KSI-CMT-VTD.
- IAM-PERMISSIONS-CATALOG: two rows added — CMT-RMV on `Reader`; CMT-VTD
  on `Security Reader` (same constraint as MLA-EVC / SVC-EIS).
- 11 new dedicated tests (5 CMT-RMV: ACR+admin-off / no-ACR / admin-on /
  null-admin-as-disabled / alt-satisfier; 6 CMT-VTD: full pass / ADO env
  accepted / non-DevOps env rejected / Free tier / no pricing row /
  alt-satisfier exposure). **149 dedicated Azure tests, 659 total.
  30 Azure KSIs covered.**

### Added — Azure SVC-EIS + SVC-ACM (security improvement + config management)
Two more Azure KSIs land in `providers/azure/config.ts`. KSI-SVC-ACM is now
AWS + GCP + Azure; KSI-SVC-EIS (HYBRID) is too. SVC-ACM stays on AZ-1's
`Reader`; SVC-EIS needs `Security Reader` to read the `securityresources`
table (same constraint MLA-EVC already documents).

- **`collectSvcAcm`** (Automating Configuration Management) — 2 findings +
  KSI-level alternative satisfier:
  1. `azure.svc.acm.deployment_history_present` (medium) — at least one
     `microsoft.resources/deployments` row in the last 90 days. JS-side
     time-window filter so the mock pattern keeps working.
  2. `azure.svc.acm.policy_compliance_acceptable` (medium) — ≥ 80% of
     `policyresources/policystates` evaluations report `Compliant`. Reuses
     the same table CNA-EIS hits, but focuses on the ratio rather than
     presence. Vacuously passes when no policy-state rows exist (CNA-EIS
     already flags that scenario).
  - Alternative satisfier: Terraform Cloud / GitHub Actions / Azure DevOps
     pipelines as the IaC source of truth.
- **`collectSvcEis`** (Evaluating and Improving Security — HYBRID) —
  2 findings + KSI-level alternative satisfier:
  1. `azure.svc.eis.defender_secure_score_present` (high) — at least one
     `microsoft.security/securescores` row exists (Defender for Cloud is
     producing a posture signal).
  2. `azure.svc.eis.defender_secure_score_acceptable` (medium) — aggregate
     current/max ratio ≥ 50% (Microsoft's own "needs attention" band).
     Vacuously passes when no signal is present.
  - Alternative satisfier: 3rd-party CSPM (Wiz / Lacework / Orca / Prisma)
     driving the improvement loop.
- `ksi-map.ts`: `azure` slot wired for both KSI-SVC-ACM and KSI-SVC-EIS.
- IAM-PERMISSIONS-CATALOG: two rows added (SVC-ACM on `Reader`; SVC-EIS on
  `Security Reader`).
- 11 new dedicated tests (6 SVC-ACM: passing / stale-deployment / low
  compliance / vacuous / alt satisfier / multi-sub aggregation; 5 SVC-EIS:
  passing / no-signal / low ratio / multi-sub aggregation / alt satisfier).
  **138 dedicated Azure tests, 648 total. 28 Azure KSIs covered.**

### Added — Azure INR-RIR + SVC-ASM (incident response routing + Key Vault)
Two more Azure KSI collectors. KSI-INR-RIR and KSI-SVC-ASM are now AWS + GCP
+ Azure. Both via Resource Graph; no new permissions beyond AZ-1's `Reader`
role — we deliberately stay on the management plane for Key Vault (no
secrets / keys / certs contents are read).

- **`collectInrRir`** (Reviewing Incident Response Procedures — HYBRID) in
  `providers/azure/logging.ts` — 1 finding + KSI-level alternative satisfiers:
  - `azure.inr.rir.alert_routing_plumbing_present` (high) — at least one
    Azure Monitor Action Group with a populated receiver (email / SMS /
    webhook / Logic App / Function / EventHub) OR a Sentinel automation
    rule exists. Vacant Action Groups are flagged as "plumbing without
    routing" rather than passing silently.
  - Alternative satisfiers: PagerDuty / OpsGenie via webhook or ITSM
    receiver (always exposed), and Sentinel automation rules + Logic App
    playbooks (auto-detects via Resource Graph). The IR runbook + last
    procedure-review minutes remain `process_artifacts_required`.
- **`collectSvcAsm`** (Automating Secret Management) in new
  `providers/azure/secrets.ts` — 3 findings:
  1. `azure.svc.asm.key_vault_present` (high) — at least one Key Vault
     exists.
  2. `azure.svc.asm.key_vault_soft_delete_enabled` (high) — every vault
     has soft-delete enabled (treats `null` as enabled to handle older API
     shapes; only explicit `false` fails).
  3. `azure.svc.asm.key_vault_rbac_or_purge_protection` (medium) — every
     vault uses RBAC authorization (modern least-privilege) OR purge
     protection (backstop for legacy access-policy vaults).
  - Alternative satisfier: HC Vault running in-cluster (with audit log
     evidence).
- `ksi-map.ts`: `azure` slot wired for KSI-INR-RIR and KSI-SVC-ASM.
- IAM-PERMISSIONS-CATALOG: two rows added (logging.ts INR-RIR + the new
  secrets.ts file) — both `Reader` is sufficient.
- 12 new dedicated tests (5 INR-RIR: Action Group receivers / Sentinel
  automation / vacant action groups / nothing / alt-satisfier exposure;
  7 SVC-ASM: all-passing vault / RBAC-only / purge-only / no-vault /
  soft-delete off / legacy unprotected / null-soft-delete). **127
  dedicated Azure tests, 637 total. 26 Azure KSIs covered.**

### Added — Azure RPL family: RPL-ABO + RPL-TRC (backup + restore recovery)
Two Azure recovery KSIs land in `providers/azure/backup.ts`. KSI-RPL-ABO and
KSI-RPL-TRC are now AWS + GCP + Azure. All via Resource Graph's `Resources`
+ `RecoveryServicesResources` tables; no new permissions beyond AZ-1's
`Reader` role.

- **`collectRplAbo`** (Aligning Backups with Objectives — HYBRID) — 3 findings:
  1. `azure.rpl.abo.recovery_vault_present` (high) — at least one
     `microsoft.recoveryservices/vaults` or `microsoft.dataprotection/backupvaults`
     exists across the configured subscriptions.
  2. `azure.rpl.abo.protected_items_present` (high) — backup-protected items
     are registered under a vault (so backups are actually happening), unless
     the vault finding has already failed (vacuous pass to avoid double-counting).
  3. `azure.rpl.abo.recent_backup_jobs_clean` (high) — Backup jobs in the
     last 30 days show ≥ 1 Completed and zero Failed. JS-authoritative time
     + operation filter so the mock doesn't need to honour the KQL `where`.
- **`collectRplTrc`** (Testing Recovery Capabilities — HYBRID) — 1 finding +
  KSI-level alternative satisfier:
  1. `azure.rpl.trc.recent_successful_restore` (medium) — at least one
     successful Restore job in the last 90 days.
  - KSI-level `alternative_satisfier`: documented gameday / tabletop DR
     exercise with AAR, captured via `process_artifacts_required` in
     `ksi-map.ts` so the operator can satisfy via either path.
- `ksi-map.ts`: `azure` slot wired for both KSI-RPL-ABO and KSI-RPL-TRC.
- IAM-PERMISSIONS-CATALOG: row added for the `RecoveryServicesResources`
  Resource Graph table used by the new collectors.
- 11 new dedicated tests (vaults present / absent, items absent under vault,
  failed-job in window, no jobs in window, newer Backup Vault recognised,
  successful restore, no restores, only-failed restores, alternative
  satisfier exposed, stale >90d restores ignored). **115 dedicated Azure
  tests, 625 total. 24 Azure KSIs covered.**

### Added — Azure CNA closeouts: CNA-DFP + CNA-OFA + MLA-EVC
Three more Azure KSI collectors land in tight, single-finding slices. KSI-CNA-DFP,
KSI-CNA-OFA, and KSI-MLA-EVC are now AWS + GCP + Azure. All via Resource Graph;
no new permissions beyond what each table already needs.

- **`collectCnaDfp`** (Defining Functionality and Privileges) in `config.ts` —
  1 finding:
  - `azure.cna.dfp.custom_role_definitions_present` (medium) — at least one
    custom RBAC role definition exists (`properties.type == "CustomRole"`).
    Proxy for "operators have authored narrow least-privilege roles instead
    of relying on Azure built-ins". Cross-KSI link to KSI-IAM-ELP.
- **`collectCnaOfa`** (Optimizing for Availability) in new `backup.ts` —
  2 findings:
  1. `azure.cna.ofa.vms_use_availability_zones` (medium) — every VM is
     zone-pinned **and** the fleet spans ≥ 2 distinct zones.
  2. `azure.cna.ofa.storage_redundant_replication` (medium) — no storage
     account uses Standard_LRS / Premium_LRS (single-datacenter).
- **`collectMlaEvc`** (Evaluating Configurations) in `logging.ts` — 1 finding:
  - `azure.mla.evc.defender_assessments_running` (high) — Microsoft Defender
    for Cloud is producing `microsoft.security/assessments` entries
    (richer than the Azure Policy engine alone: per-resource Healthy /
    Unhealthy / NotApplicable status). Surfaces `unhealthy` count.
- IAM-PERMISSIONS-CATALOG: rows added for the new `backup.ts` file and the
  `securityresources` table for MLA-EVC (`Security Reader` required).
- 11 new dedicated tests. **104 dedicated Azure tests, 614 total. 22 Azure
  KSIs covered.**

### Added — Azure CNA-EIS + CNA-IBP (Azure Policy + Microsoft Cloud Security Benchmark)
Two more Azure KSIs land. KSI-CNA-EIS and KSI-CNA-IBP are now AWS + GCP + Azure.
All via Resource Graph's `policyresources` table; no new permissions beyond
AZ-1's `Reader` role.

- **`providers/azure/config.ts`** (new):
  - **`collectCnaEis`** (Enforcing Intended State) — 2 findings:
    1. `azure.cna.eis.policy_assignments_present` (high) — at least one Azure
       Policy assignment exists somewhere in the configured subscriptions.
    2. `azure.cna.eis.policy_evaluations_running` (medium) — the
       `microsoft.policyinsights/policystates` table is non-empty (Azure Policy
       is actively scanning), with `non_compliant` count surfaced in
       observations.
  - **`collectCnaIbp`** (Implementing Best Practices) — 2 findings:
    1. `azure.cna.ibp.mcsb_assigned` (high) — the Microsoft Cloud Security
       Benchmark (MCSB) initiative is assigned. Matched by the well-known
       built-in initiative GUID `1f3afdf9-…-89da613e70a8`.
    2. `azure.cna.ibp.regulatory_initiative_assigned` (medium) — a regulatory
       initiative whose displayName / policyDefinitionId matches
       `/fedramp.?(moderate|high)/`, `/nist.?sp.?800.?53/`, or
       `/nist.?sp.?800.?171/` is also assigned, giving compliance-state
       evidence keyed to the authorization-package controls.
- IAM-PERMISSIONS-CATALOG row added for the new `config.ts` file.
- 9 new dedicated tests (passing, failing, mixed, regulatory-via-displayName,
  regulatory-via-defId paths). 603 tests pass.

### Added — Azure CNA-MAT + CNA-RNT (network segmentation + traffic restriction)
Two more Azure network KSIs. KSI-CNA-MAT and KSI-CNA-RNT are now AWS + GCP + Azure.
All Resource Graph; no new permissions beyond AZ-1's Reader role.

- **`collectCnaMat`** (Minimizing Attack Surface) — 2 findings:
  1. `azure.cna.mat.all_subnets_have_nsg` (high) — every user-managed subnet has
     an NSG attached. **System subnets** (GatewaySubnet / AzureFirewallSubnet /
     AzureBastionSubnet / RouteServerSubnet) are exempt because Azure rejects
     NSG attachment on them.
  2. `azure.cna.mat.no_nsg_allow_all_rule` (critical) — no NSG carries the
     poster-child `Allow * from * to *` wildcard rule that effectively
     nullifies the NSG.

- **`collectCnaRnt`** (Restricting Network Traffic) — 2 findings:
  1. `azure.cna.rnt.no_unrestricted_ingress` (high) — no NSG inbound `Allow`
     rule permits all ports from `*` / `Internet` / `0.0.0.0/0`.
  2. `azure.cna.rnt.no_unrestricted_egress` (medium) — no NSG outbound `Allow`
     rule permits all ports to `*` / `Internet` / `0.0.0.0/0`. Remediation
     steers toward centralised Azure Firewall + FQDN allow-list egress.
  **JS-authoritative `access == "Allow"` filter** — Deny rules with broad
  wildcards (which are good security) are never flagged, even if the mock
  bypasses the KQL `where access == "Allow"` gate.

- 9 new dedicated tests (system-subnet exemption, allow-all rule, wildcard
  ingress/egress with `*` and `Internet` source/destination, Deny-rule
  exclusion). 594 tests pass.

### Added — Azure network family start (AZ-CNA-ULN + AZ-CNA-RVP + AZ-SVC-SNT)
First three Azure CNA / SVC network KSIs land. KSI-CNA-ULN / KSI-CNA-RVP /
KSI-SVC-SNT are now AWS + GCP + Azure. All via Resource Graph; no new
permissions beyond AZ-1's Reader role.
- **`providers/azure/network.ts`** (new) — three collectors:
  - **`collectCnaUln`** (Using Logical Networking) — 1 finding:
    - `azure.cna.uln.nsg_flow_logs_enabled` (high) — at least one enabled NSG
      flow log. Reports the `with_workspace` (Traffic Analytics) sub-count.
  - **`collectCnaRvp`** (Reviewing Protections / DoS) — 1 finding:
    - `azure.cna.rvp.waf_present` (high) — at least one **enabled** Azure WAF
      policy (Application Gateway WAF **or** Azure Front Door WAF). Matches
      the `policySettings.state` (AGW) or `policySettings.enabledState` (FD)
      shape difference between the two Azure WAF flavors.
  - **`collectSvcSnt`** (Securing Network Traffic) — 2 findings:
    - `azure.svc.snt.appgateway_https_only` (high) — no Application Gateway
      `httpListener` accepts plaintext `Http`.
    - `azure.svc.snt.storage_https_only` (high) — every storage account has
      `supportsHttpsTrafficOnly = true`.
- IAM-PERMISSIONS-CATALOG row added covering the network ARM tables; Reader
  remains sufficient.
- 12 new dedicated tests covering all three (passing, failing, mixed,
  empty-tenant vacuously-passes paths). 585 tests pass.

### Added — Azure logging closeout (AZ-MLA-ALA + AZ-MLA-RVL + AZ-CMT-LMC)
Three more Azure logging KSI collectors land on the AZ-MLA-LET/OSM foundation —
all via Resource Graph (no new permissions beyond Reader + RBAC read).
- **`collectMlaAla`** (Authorizing Log Access) — 2 findings:
  1. `azure.mla.ala.log_analytics_reader_assigned` — at least one explicit
     `Log Analytics Reader` role assignment (`73c42c96-…`) exists at a Log
     Analytics workspace scope. Strong signal that operators use the dedicated
     read-only role for log access.
  2. `azure.mla.ala.no_broad_workspace_admins` — no Owner / Contributor role
     assignments scope directly at a workspace (admin scopes should inherit
     from above, not be granted at the workspace itself).
- **`collectMlaRvl`** (Reviewing Logs) — 2 findings:
  1. `azure.mla.rvl.workspace_retention_at_floor` (high) — at least one Log
     Analytics workspace has retention ≥ 90 days.
  2. `azure.mla.rvl.alert_rules_present` (high) — at least one Azure Monitor
     `scheduledQueryRules` OR Sentinel `securityinsights/alertrules` rule is
     actively querying logs on a schedule (active review, not just collection).
- **`collectCmtLmc`** (Logging Changes) — 2 findings:
  1. `azure.cmt.lmc.activity_log_exported` (high) — every configured
     subscription has a **subscription-scope** diagnostic setting exporting the
     Activity Log. Filter is JS-authoritative (the regex anchor on
     `/subscriptions/{id}/providers/microsoft.insights/diagnosticsettings`
     correctly rejects resource-scope child diag settings).
  2. `azure.cmt.lmc.change_tracking_enabled` (medium) — a Change Tracking
     solution (`microsoft.operationsmanagement/solutions` with name starting
     `ChangeTracking`) is deployed.
- IAM-PERMISSIONS-CATALOG: row added noting `authorizationresources` table
  needs an RBAC-read role; `Reader and Data Access` (or any role granting
  `Microsoft.Authorization/roleAssignments/read`) is sufficient.
- 13 new dedicated tests covering all three (passing, failing, mixed,
  no-subs, child-resource diag-setting exclusion). 573 tests pass.

### Added — Azure logging collectors (AZ-MLA-LET + AZ-MLA-OSM)
First non-IAM Azure family. Both KSIs run a couple of Azure Resource Graph
queries — **no new permissions** beyond AZ-1's `Reader` role. KSI-MLA-LET and
KSI-MLA-OSM are now AWS + GCP + Azure.

- **`providers/azure/logging.ts`** — new file.
- **`collectMlaLet`** (Logging Event Types) — 2 findings:
  1. `azure.diagnostic_settings_present` (high) — at least one
     `microsoft.insights/diagnosticsettings` child resource exists somewhere in
     the configured subscriptions. Reports the count + how many subscriptions
     have any diagnostic settings.
  2. `azure.log_analytics_workspace_present` (high) — at least one Log
     Analytics workspace exists as the substrate for diagnostic-setting output.
- **`collectMlaOsm`** (Operating SIEM Capability) — 2 findings:
  1. `azure.siem.workspace_substrate_present` — workspace ready for Sentinel.
  2. `azure.siem.sentinel_deployed` (high) — Microsoft Sentinel is onboarded
     on a workspace, detected via either the legacy
     `microsoft.operationsmanagement/solutions` (name starts with
     `SecurityInsights`) **or** the newer
     `microsoft.securityinsights/onboardingstates` resource. 3rd-party SIEM
     consumers (Splunk, Datadog, etc.) surfaced as an awareness alternative
     satisfier — this collector can't see those flows from ARM data alone.
- **Multi-subscription support**: `CollectorContext.azure.subscription_ids:
  string[]` plumbed through the orchestrator so Resource Graph collectors query
  the entire configured subscription set (orchestrator dispatch sets it).
  Backward-compatible: collectors that only carry `subscription_id` still work.
- 10 new tests (passing, failing, fall-back-to-`subscription_id`, no-subs
  warning, alternative-satisfier surface). tsc clean; 560 tests pass.

### Added — Azure IAM family completion (IAM-APM / IAM-SNU / IAM-JIT / IAM-SUS)
Last four KSIs in the Entra ID / Microsoft Graph track land — **every IAM KSI is
now AWS + GCP + Azure** (7 of 7). No new auth infrastructure; reuses the Graph
helper + per-KSI Azure dispatch shipped earlier.
- **`collectIamApm`** (Adopting Passwordless Methods) — 2 findings on the same
  CA-policies endpoint already used by IAM-MFA:
  1. `aad.ca_uses_authentication_strength` — pass when ≥1 enabled CA policy
     references `grantControls.authenticationStrength` (FIDO2 / Windows Hello /
     cert-based) instead of the legacy `mfa` built-in.
  2. `aad.ca_authentication_strength_for_admins` (severity `high`) — same but
     specifically targeting privileged directory roles.
- **`collectIamSnu`** (Securing Non-User Authentication) — service-principal
  credential hygiene via `/applications`:
  1. `aad.sp_no_expired_credentials` — no SP carries a credential past its
     `endDateTime`. Hygiene + reduces audit-log noise.
  2. `aad.sp_credentials_rotated_within_year` — no SP credential is > 365 days
     old. Workload-identity federation surfaced as the preferred remediation.
- **`collectIamJit`** (Authorizing Just-in-Time) — 1 finding on
  `/roleManagement/directory/roleAssignmentScheduleRequests`:
  - `aad.pim_admin_activation_within_30d` — proves JIT is **operationally live**
    by requiring ≥1 granted PIM self-activation on a privileged role in the last
    30 days, not just configured. Cross-KSI link to IAM-ELP (config) / IAM-MFA.
- **`collectIamSus`** (Responding to Suspicious Activity) — 1 finding on the
  CA-policies endpoint:
  - `aad.risk_based_conditional_access` (severity `high`) — pass when ≥1
    enabled CA policy reacts to Entra ID **Identity Protection** signals
    (`signInRiskLevels` / `userRiskLevels`) to automatically block, step-up, or
    force password reset on suspicious sign-ins.
- **IAM-PERMISSIONS-CATALOG**: added the new `Application.Read.All` row;
  Policy.Read.All / RoleManagement.Read.Directory already in place from earlier
  slices.
- 18 new dedicated tests (each KSI: passing, failing, ignore-disabled,
  ignore-non-matching). **AZ-2 IAM family is complete; 550 tests pass.**

### Added — Azure IAM-ELP + IAM-AAM collectors (next AZ-2 slice)
Two more Azure KSI collectors land on the Microsoft Graph + per-KSI Azure
dispatch foundation shipped with AZ-IAM-MFA. KSI-IAM-ELP and KSI-IAM-AAM are
now AWS + GCP + **Azure**.
- **`collectIamElp`** (Ensuring Least Privilege) — two findings:
  1. `aad.global_admin_count_within_threshold` — passes when total Global
     Administrators is ≤ 5 (FedRAMP / Microsoft guidance: ≥ 2 for emergency
     access, ≤ 5 to limit concentration of risk). Warning emitted when the
     role isn't yet activated (no members) so the human reviewer notices the
     emergency-access gap.
  2. `aad.pim_eligible_for_admin_roles` — passes when at least one PIM-eligible
     assignment covers a privileged directory role (Global / Privileged Role /
     Application / Security / User Administrator). Encourages just-in-time
     activation over standing admin grants. Cross-KSI link to KSI-IAM-JIT.
- **`collectIamAam`** (Automating Account Management) — two findings derived
  from the `signInActivity` field on `/users`:
  1. `aad.no_dormant_enabled_accounts` — passes when no enabled member account
     has been silent for > 90 days. Ignores guests (`userType=Guest`) and
     disabled accounts. **Degrades to a "data-missing" warning** (rather than
     false positives) when `signInActivity` is absent on every user —
     reliable signal that `AuditLog.Read.All` is missing.
  2. `aad.no_severely_dormant_accounts` (severity `critical`) — same data with
     a 365-day threshold.
- IAM-PERMISSIONS-CATALOG: added rows for `RoleManagement.Read.Directory`,
  `Directory.Read.All`, `User.Read.All`, `AuditLog.Read.All`.
- 13 new dedicated tests covering both passing + failing scenarios + degraded
  paths (no role activated, AuditLog missing, guests/disabled-users ignored).
  532 tests pass.

### Added — Azure IAM-MFA collector (AZ-IAM-MFA, first slice of AZ-2)
The first per-KSI Azure collector — establishes the Microsoft Graph + KSI-dispatch
infrastructure follow-up Azure KSIs reuse.
- **`core/auth/azure-graph.ts`** — Microsoft Graph access via plain REST (`fetch`)
  using a Graph-scoped token from `DefaultAzureCredential`. No `@microsoft/microsoft-graph-client`
  dep. Read-only by API design: only `graphFetchAll` (paginated, follows
  `@odata.nextLink`) and `graphFetchOne` are exposed. Graph errors are surfaced as
  readable warnings (401 / 403 / 404 / 429 classified).
- **`providers/azure/iam.ts`** — `collectIamMfa(ctx)` returns a `ProviderBlock` with two findings:
  1. `aad.security_defaults_or_ca_mfa_for_all_users` — passes when Security Defaults
     are on **or** an enabled Conditional Access policy enforces MFA on `includeUsers = All`.
  2. `aad.ca_mfa_for_admin_roles` (severity `critical`) — passes when at least one
     enabled CA policy includes a privileged directory-role template (Global Admin,
     Privileged Role Admin, Application Admin, Security Admin, etc.) and grants MFA.
  Authentication-strength references are treated as MFA-equivalent. Disabled policies
  are ignored. External SAML/OIDC IdPs are surfaced as a `ksi_level_alternatives` entry.
- **KSI dispatch wired through:** `KsiEntry` and `CollectorContext` gain an `azure?`
  slot in `core/ksi-map.ts`; `runOneKsi` gets an Azure branch (single tenant-scoped
  call, mirrors the GCP per-project branch). `KSI-IAM-MFA` is now AWS + GCP + **Azure**.
- 9 new dedicated tests + Azure smoke iterating all `ksi.azure` collectors (no-data
  degraded path, schema-valid output). 519 tests pass.

### Added — Significant Change Notification (SCN) classifier (SCN-1)
A new opt-in classifier (`--scn`, env `CLOUD_EVIDENCE_SCN`) takes the run's existing diff
outputs and labels each change with a FedRAMP **significance level**, a recommended
notification window, and the artifacts the change requires. Emits a starting-point
notice email so the CSP can complete + send to the authorizing agency before applying.
Clean-room from the huntridge-labs/argus AGPL project (research report 08 — idea source
only, no code copied).

- **`core/scn-classifier.ts`** — pure `classifyChange`/`classifyChanges`/`harvestChanges`/
  `draftNotice` + a thin disk reader/emitter (`buildScnReport`/`writeScnReport`).
- **Harvest sources:** `diff-report.json` (regressed / new-failing / fixed findings),
  `inventory-diff.json` (added / removed / mutated assets), and an optional
  operator-supplied proposed-changes JSON (forward-looking — `--scn-proposed <path>` or
  env `CLOUD_EVIDENCE_SCN_PROPOSED_PATH`).
- **Categories:** boundary · authentication · cryptography · network · data-flow ·
  personnel · platform-version · subprocessor · configuration · improvement. Field-aware
  categorization on inventory diffs (e.g. `publicFacing` change → `network`; `kmsKeyId`
  change → `cryptography`; `osNameVersion` change → `platform-version`).
- **Default rule library** (10 rules) covers the FedRAMP "significant change" taxonomy
  (SP 800-37 r2 § 3.6 + the FedRAMP SCR guide), with each rule mapping a category to:
  significance (`significant` / `advisory` / `not-significant`), a recommended
  notice-days window (30 for boundary/auth/crypto/network/data-flow/subprocessor/personnel,
  14 for platform-major upgrades, 7 for config regressions), and the required artifacts
  (updated SSP narratives, updated FIPS-199, POA&M entries, FIPS 140-3 cert, network
  diagrams, etc.). Caller can pass a custom rule set.
- **Outputs:** `out/scn-classification.json` (structured) + `out/scn-notice-draft.md`
  (markdown notice the CSP refines). Wired into the orchestrator after the diff-report
  block (`--scn` implies `--diff-report`).
- 18 new tests (rule matching, harvesting from real diff shapes, categorisation
  heuristics, totals aggregation, draft-notice render, end-to-end disk reader,
  proposed-changes JSON in both array and `{changes:[...]}` shapes). tsc clean;
  509 tests pass.

### Added — Azure FedRAMP reference-architecture audit (AZ-CHK)
Third leg of the multi-cloud reference-arch trio. Joins the existing AWS-CHK / GCP-CHK
audits behind the same `--reference-arch` flag (env `CLOUD_EVIDENCE_REFERENCE_ARCH`)
and emits `AUDIT-REFARCH-AZURE.json` whose findings flow into the NIST 800-53
benchmark, family roll-up (`REFARCH`), crosswalk, OSCAL, and the signed manifest.
Derived **clean-room** from the Coalfire Azure RAMPpak reference architecture
(research report 03 — idea source, MIT, no code copied).

- **`providers/azure/reference-arch.ts`** → `AUDIT-REFARCH-AZURE.json` (11 checks):
  Defender for Cloud enabled, FedRAMP policy initiative assigned, storage no
  public-blob, storage HTTPS-only + TLS 1.2+, storage public-network-access
  restricted, Key Vault soft-delete + purge protection + RBAC, CMK in use, managed
  disk encryption (not platform-key-only), NSGs with no SSH/RDP open to the
  Internet, no public IPs attached directly to VM NICs, Log Analytics workspace
  with retention ≥ 90 days.
- Every check is a **single Azure Resource Graph KQL query** against the
  `Resources` / `PolicyResources` / `SecurityResources` tables — no extra SDK deps
  beyond the AZ-1 scaffolding. Reuses the existing read-only Azure Proxy
  guardrail. Each check try/catch → warning (fail-open contract), so a missing
  RBAC grant for one table doesn't break the run.
- Excluded from the KSI pass/fail rollup (hardening audit, not a KSI obligation)
  — same convention as AWS-CHK / GCP-CHK.
- 5 new tests (passing scenario, degraded/empty fail-open, storage offender
  detection, NSG offender detection, no-subscriptions warning). tsc clean;
  491 tests pass.

### Added — Azure collector scaffolding (AZ-1)
Third-cloud foundation. The collector can now enumerate Azure subscriptions and feed
the inventory workbook (`--inventory-workbook`) alongside AWS + GCP. KSI collectors
land in AZ-2.
- **`core/auth/azure.ts`** — `DefaultAzureCredential` (env / workload identity / managed
  identity / `az login` / azd / PowerShell). `whoAmIAzure` is JWT-based (no API call —
  decodes the ARM token) so it works even without subscription-list permission. Client
  factories `resourceGraph()` and `resources(subscriptionId)`. Every client is wrapped
  in the read-only guardrail.
- **`core/readonly-guardrail-azure.ts`** — Azure-flavoured mirror of the GCP guardrail.
  Adds the Azure long-running-operation `begin*` prefix family (`beginCreate`,
  `beginCreateOrUpdate`, `beginDeleteAndWait`, …) to the write denylist. Disable with
  `CLOUD_EVIDENCE_DISABLE_AZURE_GUARDRAIL=1` only for debugging.
- **`providers/azure/discover.ts`** — Azure Resource Graph as the breadth discovery
  backbone (the Azure analog of AWS Config Advanced Query and GCP CAI
  `searchAllResources`). One KQL query across all configured subscriptions returns every
  resource with the projection the inventory workbook needs.
- **`providers/azure/inventory-assets.ts`** — depth enricher for storage accounts
  (public-blob access, encryption key source, CMK URI, TLS floor) and virtual machines
  (image / SKU / provisioning state).
- Orchestrator: `azure` is now a third provider alongside `aws`/`gcp` (default
  `--providers aws,gcp,azure`; silently skipped unless `config.azure.enabled` is true).
  `Config.azure` block in `config.yaml` (`enabled`, `subscriptions`, `tenant_id?`).
  Schema: `azure` added to `ProviderName` (validator unblocks it as a provider value).
- 19 new tests (12 Azure guardrail classification + wrap/throw, 7 discover + inventory
  pagination + row → CloudAsset mapping). tsc clean; 486 tests pass.

### Added — OSCAL SSP → FedRAMP Word (.docx) renderer (SSP-2)
Renders the draft OSCAL SSP (SSP-1) into a human-readable Word document so a system
owner can review/circulate it without a GRC tool.
- **`core/ssp-docx.ts`** — pure `renderSspDocx(ssp)` + disk emitter `emitSspDocx(opts)`.
  A `.docx` is a ZIP of WordprocessingML (OOXML) parts, so it's built **dependency-free**
  (no `docx`/python-docx, no network) and packed with the same **store-only ZIP** writer
  used for the inventory `.xlsx`. The idea (OSCAL → FedRAMP template prose) is drawn
  clean-room from the CC0 GoComply/fedramp tool; no code copied.
- **`core/zip.ts`** — extracted the shared store-only ZIP writer + `xmlEscape` (previously
  private to `inventory-workbook.ts`); both the xlsx and docx writers now use it.
- The document renders: a title page, document-information table, system characteristics
  (FIPS-199 impact, information types, status, authorization boundary), system
  implementation (components + users tables), and a control-implementation section with a
  status summary + a per-control table (control id/name, status, implementation statement).
- Wired behind `--ssp-docx` (env `CLOUD_EVIDENCE_SSP_DOCX`), which **implies `--oscal-ssp`**;
  emitted in the SSP block after the JSON is written + schema-validated. The `.docx` is not
  in the signed manifest (the signer covers `*.json`), but it's a faithful render of the
  signed `ssp.json` — reproducible from the signed source. 4 new tests (valid store-only
  ZIP + required OOXML parts, rendered content, XML escaping, wrapped/unwrapped input).

### Added — OSCAL System Security Plan emitter (SSP-1)
A new opt-in emitter (`--oscal-ssp`, env `CLOUD_EVIDENCE_OSCAL_SSP`) generates a **draft**
OSCAL 1.1.2 System Security Plan (`out/ssp.json`) directly from the run's evidence.
- **`core/oscal-ssp.ts`** — pure `buildOscalSsp(benchmark, opts)` + disk emitter
  `emitOscalSsp(opts)`. The SSP documents the **whole FedRAMP Rev5 baseline** for the
  run's impact level (so it always benchmarks `framework='rev5'`, independent of
  `--framework`): one `implemented-requirement` per baseline control.
- **Status mapping** (from the NIST 800-53 control benchmark): satisfied→`implemented`,
  partially-satisfied→`partial`, not-satisfied→`planned`, not-assessed→`planned` (with a
  remark to assess manually or document as inherited from the underlying CSP). Each
  requirement carries a FedRAMP `implementation-status` prop + a `by-component` narrative
  citing the KSIs/rules and pass counts that produced the evidence.
- Pre-populates `metadata` (roles/parties), `import-profile` (the published FedRAMP Rev5
  Low/Moderate/High baseline profile href), `system-characteristics` (FIPS-199 impact,
  information types, status, boundary placeholder), and `system-implementation`
  (this-system + leveraged AWS/GCP components, a placeholder user).
- Emitted **before signing** (covered by the manifest) and **validated against the
  committed NIST OSCAL SSP schema** (`validateOscalFile(path,'ssp')`); fails the run under
  `--strict-schema`. New flags `--system-name` / `--system-id` (+ env
  `CLOUD_EVIDENCE_SYSTEM_NAME`/`_ID`/`_DESCRIPTION`).
- Deterministic UUIDs (re-running on the same evidence yields a stable diff). Clearly
  framed as a **starting point** for the system owner, not a final SSP. 4 new tests
  (schema-valid output, status mapping, required structure, determinism).

### Added — FedRAMP reference-architecture audit (AWS-CHK / GCP-CHK)
A new opt-in audit (`--reference-arch`, env `CLOUD_EVIDENCE_REFERENCE_ARCH`) checks the
**running** AWS/GCP environment against the hardening a FedRAMP-compliant build is
expected to have — derived **clean-room** from the Coalfire AWS/GCP RAMPpak reference
architectures (research reports 02 & 04; idea source only, MIT, no code copied).
- **`providers/aws/reference-arch.ts`** → `AUDIT-REFARCH-AWS.json` (10 checks):
  customer-managed KMS keys in use, Security Hub CIS + AWS FSBP standards, AWS Network
  Firewall present, active VPC flow logs, Organizations SCPs + delegated admin,
  org trusted access for core security services, CloudTrail→CloudWatch delivery,
  AWS Backup selection coverage, Terraform-state bucket integrity (SSE + lock table),
  and approved/STIG AMI provenance (`CLOUD_EVIDENCE_APPROVED_AMI_PATTERN`).
- **`providers/gcp/reference-arch.ts`** → `AUDIT-REFARCH-GCP.json` (13 checks):
  Assured Workloads (FedRAMP regime), baseline Org Policy constraints, VPC Service
  Controls perimeter, per-service CMEK, data-access audit logging, Security Command
  Center, private egress (Cloud NAT / no external IPs), no primitive-role service
  accounts, DNS query logging, curated-API allow-list (`CLOUD_EVIDENCE_GCP_API_ALLOWLIST`),
  private-only Cloud SQL, group-based org admin, and Terraform-state bucket integrity.
- **Read-only** (guardrail-wrapped AWS clients / GCP Proxy). Every check **degrades to
  a warning, never a false failure** when its API isn't accessible (e.g. not an
  Organizations management account, service not enabled). GCP org-scoped checks
  skip-with-warning when no `organization_id` is configured; across multiple GCP
  projects the org-scoped checks run once and project-scoped checks run per project.
- Emitted as their own evidence files so the findings flow into the NIST 800-53
  **benchmark** (`control-benchmark.json`), the **family roll-up** (a new `REFARCH`
  family), the **crosswalk**, **OSCAL**, and the **signed manifest** — but, being
  hardening *audits* rather than KSI obligations, they are intentionally **excluded
  from the KSI pass/fail rollup**.
- IAM catalog regenerated (`npm run gen:iam-actions`); all new read actions are
  covered by AWS `ReadOnlyAccess` / GCP viewer roles. 5 new tests (passing,
  fail-open/degraded, AMI-pattern, GCP org-skip, GCP org-present).

### Added — OSCAL schema validation + fixed the OSCAL document wrapper (OSC-1/2)
- **`core/oscal-validate.ts`** validates the OSCAL we emit against NIST's official
  JSON Schema using the already-vendored `ajv` — no new dependency, no runtime
  network. Schemas are committed offline (`docs/oscal/oscal_*_schema.v1.1.2.json`,
  assessment-results + ssp + poam) by **`scripts/extract-oscal-schemas.mjs`**
  (`npm run gen:oscal-schemas`), mirroring our "commit data, validate offline" pattern.
- The orchestrator validates `assessment-results.json` after emitting it (under the
  signed manifest); reports any errors and fails the run under `--strict-schema`.
- **Bug fix (surfaced by OSC-1):** the emitter now wraps the document in the
  required top-level `{ "assessment-results": … }` key — previously it wrote the
  inner object directly, which is **not** a schema-valid OSCAL document and would
  be rejected by NIST tooling / Paramify. Emitted docs now pass NIST schema
  validation. 4 validator tests + updated emitter tests.

### Added — Organization-grade cloud inventory (FedRAMP workbook + full asset inventory)
A complete cloud asset inventory for any org, not just FedRAMP — enabled by
`--inventory-workbook` (env `CLOUD_EVIDENCE_INVENTORY_WORKBOOK`) or the fast
`--inventory-only`. Emits, all under the signed manifest:
`inventory.json` (rich superset, source of truth), `inventory-workbook.{csv,xlsx}`
(FedRAMP **Appendix M** 25-column projection), `inventory-oscal.json` (OSCAL
inventory-items), `inventory-cmdb.json` (ServiceNow/CSDM CI records),
`inventory-diff.json` (run-over-run change tracking), and `inventory-cost.json`
(month-to-date cost by service).

- **Generic discovery backbone** (breadth = *every* resource type): AWS
  `providers/aws/discover.ts` (Config Advanced Query → Resource Explorer → Tagging
  API fallback chain) and GCP `providers/gcp/discover.ts` (Cloud Asset Inventory
  `searchAllResources`); merged with per-service **depth enrichers** via
  `dedupeAssets`.
- **Depth enrichers** (`providers/aws/inventory-assets.ts`): EC2(+ENI IP/MAC), EBS,
  RDS, S3, Lambda, ELBv2, DynamoDB, ECR, EKS, CloudFront — with multi-region sweep
  (global-once), security-group **network exposure** (open-to-internet ports), S3
  **public-access + encryption/KMS**, and **SSM Inventory** OS enrichment.
- **Rich data model + FedPy-native enrichment** (`core/inventory-workbook.ts`):
  lifecycle (created/state/**EOL**), security (KMS/encryption/exposure), ownership
  (tag-driven env/criticality/cost-center + **required-tag governance**), **scan
  reconciliation** vs our own VDR evidence, **KSI-finding cross-linking**, **data
  classification** (tags + AWS **Macie**), a **relationship graph** (`edges`), and
  a dependency-free `.xlsx` writer (`zlib.crc32` + inline-string OOXML).
- **Cost** (`providers/aws/inventory-cost.ts`): month-to-date by service via Cost
  Explorer (honest service-level summary). **Change tracking** + **OSCAL/CMDB**
  emitters in `core/inventory-emit.ts`. Tracker collector-runs view surfaces the
  inventory headline.
- All new SDK clients are read-only + guardrail-wrapped. Field mapping is clean-room
  from the Apache-2.0 reference designs (aws-samples / google) per the Path A
  licensing decision. ~50 inventory unit tests; design in
  `research/reports/12-inventory-completeness.md`.

### Added — turn the four deferred in-collector TODOs into real detectors
- **AWS Security Lake** (MLA-OSM): `collectMlaOsm` now probes `securitylake:ListDataLakes`
  (+ `ListSubscribers`) directly — a configured data lake counts as SIEM plumbing and
  grounds the Security Lake alternative-satisfier. Added `@aws-sdk/client-securitylake`
  + a read-only auth factory.
- **AWS EKS service mesh** (SVC-VCM): `collectSvcVcm` enumerates EKS clusters and their
  managed add-ons (`eks:ListClusters` + `eks:ListAddons`) and detects mesh add-ons
  (istio/linkerd/cilium/appmesh/consul); the Istio/Linkerd alternative-satisfier is now
  evidence-grounded instead of "deferred", pointing Helm-installed-mesh validation at the
  K8s collector.
- **GCP deletion events** (SVC-RUD): `collectSvcRud` queries Cloud Audit Logs
  (`logging.entries.list`) over a 90-day window for delete methods (storage/SQL/KMS/
  BigQuery/Compute) and reports real counts + samples, replacing the "sample query needed"
  placeholder. Degrades to a warning on permission/availability error.
- **IAM-permission auto-inventory**: `scripts/extract-iam-actions.mjs` +
  `docs/iam-actions.generated.json` (137 AWS actions / 39 services, 42 GCP roles) statically
  derive the permissions the code references — turning the catalog's "future enhancement"
  note into real, unit-tested tooling (`npm run gen:iam-actions`, `--check` for CI drift).

## [0.2.0] - 2026-05-28

### Changed — documentation accuracy
- Refreshed stale docs to match the shipped code: `cloud-evidence/README.md`
  (was "35+ KSIs / Phase 1 — IAM only"; now reflects 63 KSIs / 44 cloud collectors
  / 223 requirements + level selector + benchmark), `tracker/README.md` (evidence
  uploads / 2FA / RBAC / audit search / backup are shipped, not "out of v0.1"),
  `ARCHITECTURE.md` (test counts 396/99, correct workflow filenames, benchmark +
  ledger in the pipeline), and a status banner on `GAP-ANALYSIS.md` noting §1–§12
  are largely implemented.

### Added — Deno runtime support for the collector
- The cloud-evidence collector now runs on **Deno 2.8+** in addition to Node and Bun.
  npm dependencies resolve from the existing `node_modules`; Deno's secure-by-default
  model needs explicit permission flags, bundled as `collect:deno` / `verify:deno`
  npm scripts (`--allow-read,-env,-sys,-net,-write` for collection; add `--allow-run`
  only for the optional RFC 3161 `openssl` timestamp — Ed25519 signing uses `node:crypto`).
  Verified on Deno 2.8.1: a full dry-run plans all 44 KSIs and the offline control
  benchmark + `verify` run clean. `.tool-versions` and RUNBOOK updated. Bun remains
  the production recommendation.

### Added — NIST 800-53 control benchmark (Low / Moderate / High, for both 20x and Rev5)
- **`core/control-benchmark.ts` + `control-benchmark.json`:** every run now rolls the cloud
  findings UP to NIST 800-53 controls and scores each control at the chosen impact level, so a
  user can benchmark their cloud infrastructure against the baseline. Per-control status is
  `satisfied` / `partially-satisfied` / `not-satisfied` / `not-assessed`, derived from the
  findings that map to it (via each finding's / file's `nist_controls`); awareness-only
  attestations are listed but never satisfy a control on their own. `totals` report both
  `assessed_pass_rate` (of controls with evidence) and `baseline_coverage_rate` (of the whole
  in-scope set).
- **Two framings (`--framework`, env `CLOUD_EVIDENCE_FRAMEWORK`, default `20x`):**
  `20x` scores only the controls the evaluated 20x KSIs/FRRs reference; `rev5` scores the full
  NIST SP 800-53B Rev5 baseline for the level (Low 149 / Moderate 287 / High 370 controls),
  honestly surfacing which baseline controls have automated cloud evidence vs. which still need
  manual assessment.
- **Committed baseline membership** (`docs/nist-r5-baselines.generated.json`) + reproducible
  extractor (`scripts/extract-nist-baselines.mjs`) sourced from NIST's official OSCAL
  resolved-profile catalogs (usnistgov/oscal-content). No network at runtime; re-run to refresh.
- Orchestrator emits the benchmark after the family roll-up (covered by the signed manifest),
  records a `control_benchmark.complete` ledger event, and adds `framework` to the run summary.
  21 new unit tests in `tests/core/control-benchmark.test.ts`.

### Added — Completeness, NIST grounding, production hardening, Bun runtime
- **Corrected KSI count to 63** (was 60): `KSI-CSX-SUM/MAS/ORD` live under the `FRR.KSI`
  family and were mis-classified — they are KSIs. Registry now reports 63 KSIs; a
  completeness regression test asserts 63 KSIs + **zero generic-stub gaps** (every one of
  the 223 requirements resolves to a collector, the aggregator/meta, a specific playbook,
  or awareness-only). Added specific playbooks for the 6 previously-generic KSIs
  (CSX-MAS/ORD, PIY-RES/RIS/RSD/RVD).
- **NIST 800-53 Rev5 enrichment** (`core/nist-r5.ts` + `docs/nist-r5-controls.generated.json`
  from the GovReady r5 dataset): High-derived findings now carry official Rev5 control
  names (e.g. "ra-5 — Vulnerability Monitoring and Scanning") as grounding evidence.
- **Production-hardening layer:** `core/run-ledger.ts` (append-only JSONL audit trail of
  every action + outcome + timing, crash-durable → `out/run-ledger.jsonl`), `core/run-lock.ts`
  (prevents overlapping runs clobbering the same out dir; TTL + PID-liveness; auto-released on
  exit), `core/rate-control.ts` (token bucket + AIMD adaptive concurrency on throttle + TTL
  in-run memoization). Orchestrator records run.start / per-collector run / run.complete and
  surfaces ledger + throttle telemetry in the run summary.
- **Bun runtime for the collector** (`collect:bun` / `verify:bun`, `.tool-versions`): the
  sqlite-free collector runs on Bun 1.3+ (recommended for production — native TS, faster I/O);
  verified end-to-end at High tier. Node + tsx remains the default; the tracker stays on Node.

### Added — FedRAMP 20x full-level coverage (Low / Moderate / High)
Expands the collector from the 35 implemented KSIs toward the full **223-requirement**
FedRAMP 20x set (60 KSI indicators + 163 FRR requirements) with a setup-time impact-tier selector.

- **Impact-level selector**: `impact_level: low|moderate|high` in `config.yaml` + `--impact-level`
  CLI flag (env `CLOUD_EVIDENCE_IMPACT_LEVEL`). Low/Moderate come from the 20x machine-readable
  data; **High is DERIVED from the NIST 800-53 Rev5 baseline** via each requirement's `controls[]`
  and always labeled `derived-rev5` (or `derived-rev5-pending` when there's no control to anchor).
- **Requirement registry** (`core/requirements-registry.ts`) + reproducible extractor
  (`scripts/extract-frmr-requirements.mjs`) producing `docs/frmr-requirements.generated.json`.
- **Process-artifact tracker** (`core/process-artifact-tracker.ts`): emits signed, schema-valid,
  OSCAL-mapped, LLM-readable `scope: PROCESS` evidence for the ~99 governance requirements —
  artifact + attestation register, SLA/deadline monitoring (`core/bizdays.ts`), and
  alternative-satisfier detection. Requirements that obligate FedRAMP/agency/3PAO are tracked as
  **awareness-only** and excluded from the provider's pass/fail rollup.
- **Requirement playbooks** (`core/requirement-playbooks.ts`): 174 per-requirement playbooks with
  concrete artifacts, practical FedRAMP-aligned remediation steps, real vendor alternative
  satisfiers (Vanta/Drata/Paramify, KnowBe4, HackerOne/Bugcrowd, ServiceNow/Jira, PagerDuty,
  Wiz/Tenable/Snyk, CMVP/CloudHSM), and 38 SLA windows.
- **UCM crypto collectors** (`providers/{aws,gcp}/crypto.ts`, registered as `KSI-AFR-UCM`):
  read-only FIPS/CMVP validation of KMS/ACM/TLS against a CMVP cert reference table, with
  per-level obligation strength (Low MAY / Moderate SHOULD / High MUST).
- **VDR modules** (`core/kev-feed.ts`, `vdr-ledger.ts`, `vdr-report.ts`): CISA KEV feed (offline-cacheable),
  normalized vulnerability ledger with VDR-TFR-* SLA day-tables, and a breach summary.
- Deep per-requirement analysis for all 188 gap requirements in
  `cloud-evidence/docs/RSI-COVERAGE-ANALYSIS.md` + `docs/analysis/*.md`.
- Schema + envelope gained `impact_level`, `applicable_key_word`, `actor_scope`, `level_source`,
  `category`, `family`, `awareness_only` (all ajv-validated). Read-only guardrails unchanged.
- **7 KSI hybrid collectors** (`providers/{aws,gcp}/ksi-hybrids.ts`): read-only cloud signals for
  KSI-CMT-RVP, INR-AAR, INR-RPI, RPL-ARP, RPL-RRO, SCR-MIT, SVC-PRR.
- **VDR live-scan collectors** (`providers/{aws,gcp}/vdr-scan.ts`, `KSI-AFR-VDR`): Inspector v2 /
  Container Analysis → the VDR ledger + CISA KEV join + SLA-breach detection.
- **ADS / MAS / SCG automated signals** wired into the orchestrator (env-gated, read-only):
  Trust-Center reachability probe, assessment-scope-drift reconciliation, Secure-Config-Guide diff.
- **Family roll-up** (`core/family-rollup.ts`, `family-rollup.json`): per-family pass-rate posture,
  awareness items excluded.
- New third-party detector rules (Okta/Entra, Wiz/Prisma/Orca/Tenable/Snyk, Terraform Cloud/ArgoCD,
  Vanta/Drata, KnowBe4, HackerOne, PagerDuty, Sigstore) so alternative satisfiers auto-detect.

### Fixed — Hardening pass #3 (all-severity error-handling sweep, 2026-05)
Resolved every remaining finding (high → info) from the error-handling audit, in four batches:

**Batch 1 — collector granularity (cloud-evidence):**
- Converted every bare `catch {}` / `catch (e) { warnings.push(e.message) }` in the AWS
  `data.ts`/`iam.ts`/`config.ts` and **all 9 GCP collectors** (95 catches) to
  `diagnoseAwsError` / `diagnoseGcpError` / `warnIfActionable` — warnings now name the
  exact IAM action or GCP role (e.g. `compute.instances.list (roles/compute.viewer)`).
- Pagination loops (Lambda `ListFunctions`, IAM SSO/identity-store, 4 IsTruncated loops)
  hardened with repeated-marker detection + a `MAX_PAGINATION_ITERATIONS` cap.
- K8s ClusterRoleBinding parsing null-safety; EKS inventory filters undefined names.

**Batch 2 — core robustness (cloud-evidence):**
- `writeFileSafe` / `mkdirSafe` translate `ENOSPC`/`EACCES`/`EROFS`/`EMFILE` into actionable
  messages instead of opaque stack traces mid-run. `core/orchestrator.ts`.
- `pva-run-summary.json` now carries explicit `failed_ksis` + `schema_invalid_ksis` arrays;
  the PVA collector records `parse_error_ksis` for corrupt evidence files.
- Signing key: loose file permissions (group/world-readable) warn; malformed PEM and
  `EACCES` produce clear errors. `verifyRun` no longer throws on a corrupt/unreadable
  manifest or signature — it returns an error result. `core/sign.ts`.
- Paramify + tracker push gained `withRetry` (5xx/429/network) with URL-in-error reporting;
  ticket-push wraps the 6 previously-silent `JSON.parse` sites; SIEM/webhook errors now
  surface `ECONNREFUSED`/`ETIMEDOUT` codes. Plugin-loader survives an unreadable dir.

**Batch 3 — server robustness (tracker):**
- Input validation: token name length, `collector-runs` datetime + integer coercion,
  invalid-JSON guards (signup/login/tokens/admin/collector-runs), password upper-bound
  (scrypt CPU-DoS guard), domain/user-id `NaN` guards.
- CSRF middleware rejects duplicated (comma-joined) `X-CSRF-Token` headers explicitly.
- Rate-limit falls back to the TCP peer address when proxy headers are absent (no shared
  `unknown` bucket). Attachment downloads use RFC 5987 `filename*` Content-Disposition.
- Backup checkpoints the WAL before snapshotting; restore validates the SQLite magic header
  before clobbering, writes atomically (temp + rename), and clears stale `-wal`/`-shm`
  sidecars. `db()` sets `busy_timeout`, runs a startup health check, and gives an actionable
  open-failure message.

**Batch 4 — regression tests:** +13 cloud-evidence (push retry, sign hardening, PVA summary)
and +8 tracker (collector-run validation, CSRF duplicate, restore magic-header) tests.
Totals: **cloud-evidence 202** tests / **tracker 86** tests; both projects `tsc --noEmit` clean.

### Fixed — Hardening pass #2 (error handling + edge cases, 2026-05)
Following a focused error-handling / edge-case audit:
- **SECURITY: backup-code replay race.** `consumeBackupCode` did a read-modify-write
  that let two concurrent `/api/2fa/verify` requests accept the same backup code.
  Replaced with an atomic `INSERT OR IGNORE` into a new `totp_backup_codes_used`
  table (unique constraint). `tracker/server/totp.ts`, `db.ts`.
- **SECURITY: restore symlink overwrite.** `restore()` could write through a symlink
  at the DB path, overwriting arbitrary files. Now refuses symlink targets +
  gives a clear error on truncated gzip. `tracker/server/backup.ts`.
- **Unguarded `JSON.parse`** in IAM policy decode, diff-report run-id read, and Lambda
  resource-policy parse now wrapped — a malformed policy/file no longer crashes the run.
- **Exit code 4** when a collector throws an exception (vs. merely emitting failing
  findings, which stays exit 0 — findings are data). CI runners now catch broken collectors.
- **Pagination safety** on `ListUsers` (and pattern documented): max-iteration cap +
  repeated-marker detection to prevent infinite loops on broken API responses.
- **`core/error-diagnostics.ts`**: centralized AWS/GCP/K8s error → actionable-message
  translator. Access-denied warnings now name the exact IAM action / GCP role / K8s
  verb to grant. Wired into the orchestrator's per-collector catch + the K8s collector.
- **Startup-time integration validation**: missing env vars for `--llm-generate-prs`,
  `--ticket-push`, `--webhook-url`, `--push-paramify`, `--push-tracker` now abort
  BEFORE collection instead of wasting compute then erroring.
- **`config.yaml` schema validation**: malformed YAML / missing `frmr_version` /
  empty `aws.regions` fail fast with a clear message.
- **AWS/GCP auth-failure messages** now classify the error (access_denied / network /
  expired) and print the specific recovery command.
- **NaN guards** on `TRACKER_MAX_ATTACHMENT_MB` and audit-search `limit`/`offset`/`actor`
  query params (garbage input no longer cascades to `NaN`).
- **K8s API timeout** (`CLOUD_EVIDENCE_K8S_TIMEOUT_MS`, default 10s) so an unreachable
  cluster doesn't hang the run; clear "cluster unreachable" warning on timeout.
- **Client `ApiError`** class carrying HTTP status + server error code + Retry-After,
  so the SPA can distinguish 401/403/429/5xx and network failures. `fetch()` wrapped
  to surface offline errors clearly. `tracker/client/src/lib/api.ts`.
- **`docs/IAM-PERMISSIONS-CATALOG.md`**: authoritative per-collector AWS action / GCP
  role / K8s verb reference for least-privilege policy construction.

### Fixed — Hardening pass #1 (completeness audit, 2026-05)
- OpenAPI spec malformation (duplicate `components:` block) corrected.
- 2FA login bypass closed: enrolled users get a 5-min pre-auth session that only
  `/api/2fa/verify` can elevate. `sessions.preauth_until` column + middleware gating.
- `routes/audit.test.ts` now exercises the real `auditRoutes` module (was a stubbed
  re-implementation). Admin self-demotion + last-admin protection added.
- Provider smoke test (`tests/providers/smoke.test.ts`) added — caught 6 collectors
  emitting schema-invalid findings (missing gap/remediation/data); all fixed.
- 19 TypeScript strict-mode errors across both projects resolved.
- Dead code removed (`neutralizedByAlternative`, 6 legacy findings helpers, `backup.ts.bak`).

### Added — Phase A: Foundation
- Vitest test harness for `cloud-evidence`. 33 reference tests across retry, schema, log, sign, timestamp, oscal, crosswalk, coverage-check.
- `core/schema.ts`: ajv-based EvidenceFile JSON Schema validator. Wired into orchestrator with `--strict-schema` flag.
- `core/retry.ts`: decorrelated-jitter retry middleware applied to every AWS SDK call via `readonly-guardrail.ts`.
- `core/log.ts`: structured pino logger with pretty/JSON modes, redaction, file sink. Configurable via `LOG_LEVEL`, `LOG_PRETTY`, `LOG_FILE`.
- p-limit-based parallel KSI collection in the orchestrator. CLI: `--concurrency <N>`.

### Added — Phase B: Audit defensibility
- `core/sign.ts`: Ed25519 signing of every run's evidence files. Emits `manifest.json` + `manifest.sig`. Self-verifies after writing.
- `core/verify-cli.ts`: standalone verifier CLI (`npm run verify <out-dir>`).
- `core/timestamp.ts`: RFC 3161 trusted timestamps via `openssl ts -query` + configurable TSA (default DigiCert). Graceful degradation when openssl/TSA unavailable.
- `core/oscal.ts`: NIST OSCAL 1.1 Assessment Results emitter. CLI: `--oscal`.
- `core/coverage-check.ts`: hardened with 6 silent-failure detectors (missing accounts/projects/regions/KSIs, zero-finding KSIs, excess collector warnings); persists `coverage-report.json`.

### Added — Phase C: Coverage breadth
- `core/crosswalk.ts`: NIST 800-53 → SOC 2 / ISO 27001 / HIPAA mapping (28+ controls). CLI: `--crosswalk`.
- `core/aws-org-fanout.ts`: AWS Organizations multi-account fan-out with include/exclude filters + cross-account `AssumeRole`. CLI: `--aws-org-fanout`, `--aws-include`, `--aws-exclude`, `--aws-cross-account-role`.
- `core/readonly-guardrail-gcp.ts`: recursive Proxy guardrail for every GCP client method dispatched. Verb-prefix classifier (~50 read verbs / 30 write verbs).
- `core/powerpipe-emitter.ts`: auto-generated Powerpipe HCL mod (`out/powerpipe/`). One control per KSI; benchmarks grouped by domain. CLI: `--powerpipe`.
- Refactored every AWS collector's `setupCtx` to honor `c.aws?.auth` (enables fan-out).

### Added — Phase D: Tracker hardening
- `server/rate-limit.ts`: SQLite-backed sliding-window rate limiter. Per-IP / per-user / per-API-token policies; `X-RateLimit-*` + `Retry-After` headers.
- `server/csrf.ts`: double-submit cookie CSRF middleware. Skip-paths for bootstrap; client API helper auto-attaches `X-CSRF-Token`.
- `server/totp.ts`: RFC 6238 TOTP with 8 single-use SHA-256-hashed backup codes. `/api/2fa/*` routes. Verified against RFC 6238 canonical test vector.
- `server/rbac.ts`: 5 granular roles (viewer, contributor, ksi-owner, auditor, admin) + per-KSI-domain assignments + `requirePermission()` middleware. Audit-logged role changes. Idempotent SQLite migration relaxes legacy `users.role` CHECK.
- `server/backup.ts`: online SQLite `.backup()` + gzip; `npm run backup` / `npm run restore`. Integrity-check on restore.
- `server/routes/audit.ts`: filter/search/CSV-export endpoints over `audit_log`.

### Added — Phase E: K8s + advanced
- `core/auth/k8s.ts`: kubeconfig loader + per-context auth (kubectl-compatible).
- `providers/k8s/security.ts`: `collectK8sIamElp` enumerates cluster-admin bindings + custom wildcard ClusterRoles (KSI-IAM-ELP).
- `core/sbom.ts`: CycloneDX 1.4 + SPDX 2.3 SBOM parser; CVE correlation via `SBOM_NVD_INDEX_PATH`; cosign signature verification when `COSIGN_PUBLIC_KEY` is set. CLI: `--sbom-dir`.
- `core/anomaly.ts`: rolling-baseline anomaly detector (persistent regressions, spikes, new rules, KSI full-regression). Persists `anomaly-history.jsonl`. CLI: `--anomaly`.

### Added — Phase F: Ecosystem integrations
- `core/llm-pr-generator.ts`: Anthropic Claude API integration. Builds a strict-JSON-schema remediation PR per failing finding.
- `core/ticket-push.ts`: generic ticket-driver interface + GitHub Issues, Jira (Atlassian REST v3), ServiceNow (Now REST) drivers. Idempotent via stable `external_key`; create/update/reopen flows.
- `core/siem-push.ts`: OCSF v1.2 `compliance_finding` events. Batched POST; supports `ocsf-jsonl`, `ocsf-array`, `splunk-hec` wire formats.
- `core/webhook-push.ts`: Stripe-style HMAC-SHA256 signing over `<timestamp>.<body>`. Ships `verifySignature` helper.

### Added — Phase G: DX + polish
- `core/plugin-loader.ts`: opt-in custom KSI collector plugin system. CLI: `--plugins-dir`. Example plugin under `plugins.example/`.
- `tracker/server/openapi.yaml`: OpenAPI 3.0.3 spec for the tracker API. Served at `/api/openapi.yaml`.
- Initial `CHANGELOG.md` + `ARCHITECTURE.md`.

### Test counts
| Project          | Files | Tests |
|------------------|-------|-------|
| cloud-evidence   | 20    | 161   |
| tracker          | 6     | 48    |
| **Total**        | **26**| **209** |

## [0.1.0] - 2026-05-15
Initial scaffold: 37-KSI cloud-evidence collector + multi-user tracker over FRMR JSON.
