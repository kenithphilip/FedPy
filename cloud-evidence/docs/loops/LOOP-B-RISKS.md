# LOOP-B — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with `status=resolved` + resolution note. Severity: high = ship-blocking; med = should fix in-loop; low = file as follow-up.

> Authoritative companion to `docs/loops/LOOP-B-SPEC.md` and the per-slice docs at `docs/slices/B/B.B[1-5].md`. Read those for context before acting on any risk here.

> Last updated: 2026-06-06.

---

## Cross-cutting risks (apply to ALL slices in LOOP-B)

### B-X1 — FedRAMP CMP PDF gated by 403 on anonymous fetch
- **Description**: The FedRAMP Continuous Monitoring Strategy & Guide (Rev 5) PDF — the authoritative source for the severity → days table B.B2 needs and for the Deviation Request fields B.B3 mirrors — returns HTTP 403 to anonymous HTTPS fetches. The PDF must be downloaded manually by an operator into `cloud-evidence/docs/sources/fedramp-conmon-strategy-guide.pdf` before B.B2 or B.B3 can pin verbatim quotes.
- **Severity**: high (B.B2 blocker; B.B3 partial blocker).
- **Mitigation**: Each affected slice (B.B2, B.B3) carries a `REQUIRES-OPERATOR-INPUT: confirm-against-fedramp-cmp-pdf` marker on its constants until the PDF is downloaded; `--strict-risk` orchestrator mode fails the build if the marker remains; CHANGELOG entry for B.B2 quotes the table values verbatim with PDF page + section, atomically.
- **Status**: open. **(B.B2 shipped 2026-06-11 with the published values in `core/deadline-table.ts` — High=30/Moderate=90/Low=180 (well-established FedRAMP-published constants), Critical=15/Info=365 per the per-slice doc — and a `REQUIRES-OPERATOR-INPUT` docstring note + a pinning test (`deadline-table.test.ts`). The PDF download into `docs/sources/fedramp-conmon-strategy-guide.pdf` + verbatim re-quotation of the `critical` value remains the open operator step.)**

### B-X-EXT-1 — IRV signal not yet plumbed from vdr-ledger to POA&M findings [discovered impl-b-b2, 2026-06-11]
- **Description**: B.B2's deadline engine reads PAIN/IRV/LEV from optional per-finding fields on the envelope `Finding` (`irv`/`lev`/`pain`) and derives LEV from `risk_score.epss.percentile ≥ 0.95` / KEV membership. The Internet-Reachable Verdict (IRV) lives in `core/vdr-ledger.ts` `LedgerEntry` and is NOT yet written onto the KSI envelope findings the POA&M reads — so the PAIN/IRV/LEV deadline override only fires for findings that already carry `irv: true`. In practice today that is rare, so most non-KEV findings take the FedRAMP CMP path.
- **Severity**: medium.
- **Mitigation**: A follow-on (extend `core/vdr-ledger.ts` or the VDR collector) should stamp `irv`/`lev`/`pain` onto the findings it evaluates (or emit an `out/vdr-signals.json` snapshot the POA&M joins on). The engine + props + tests already support the full override; only the per-finding IRV plumbing is deferred. Open-question Q4 documents the decision.
- **Status**: open (deferred follow-on).

### B-X2 — OSCAL POA&M v1.1.2 schema constraints on props
- **Description**: All LOOP-B slices attach new props to `risk.props[]` and `poam-item.props[]` arrays. OSCAL v1.1.2 requires every prop to have a `name`, optional `ns`, optional `value`. The schema allows arbitrary `ns`-namespaced props but `ajv` strict mode rejects unknown property names without `ns` set. A typo (missing `ns: CE_NS`) would silently fail the bundle.
- **Severity**: high (all slices).
- **Mitigation**: `core/oscal-validate.ts` runs after every slice's POA&M re-emission; `ns: CE_NS` is required by lint rule (add to `scripts/lint-no-stubs.mjs` allowlist enforcement); CI fails if any new prop lacks `ns`.
- **Status**: open.

### B-X3 — Ed25519 signing-key rotation across cloud-evidence + tracker
- **Description**: B.B3 + B.B4 + B.B5 all sign records in the tracker using a tracker-resident Ed25519 key, while cloud-evidence side has its own key for the OSCAL output signing. The reader (`risk-acceptance-reader.ts`, `compensating-control-reader.ts`, `organisational-risk-reader.ts`) must verify tracker signatures using the tracker's PUBLISHED public key. If the tracker rotates its signing key without exposing a historical key registry, snapshots written under the old key fail verification.
- **Severity**: med (impacts B.B3, B.B4, B.B5).
- **Mitigation**: Tracker exposes `GET /api/sign/public-keys` returning ALL historical public keys keyed by `key_id`; reader cross-references each record's `signing_key_id` against the registry. Key rotation events written to `audit_log`; runbook documents the rotation procedure.
- **Status**: open.

### B-X4 — Cross-system snapshot age skew
- **Description**: B.B3 snapshot (`risk-acceptances`), B.B4 snapshot (`compensating-controls`), and B.B5 snapshot (`organisational-risks`) are pulled at different times in the orchestrator run. If the tracker is being actively edited during a run, snapshots could be inconsistent — e.g. an acceptance references a CC that was retired between two pulls.
- **Severity**: med.
- **Mitigation**: Each reader records `fetched_at`; orchestrator's `--strict-risk` mode requires all three snapshots within a 5-minute window; CHANGELOG entry for B.B5 documents the skew bound; UI surfaces "Stale snapshot" warning when bound exceeded.
- **Status**: open.

### B-X5 — RBAC role definitions drift between tracker and operator's identity provider
- **Description**: B.B3 (acceptance create/approve/revoke) and B.B4 (CC create/activate/retire) depend on the `iso` and `ao` roles. The tracker's `rbac.ts` defines these constants, but the operator's identity provider (Okta / Azure AD / GitHub OIDC) may not map any user to these roles, leaving the tracker with admin-only access and no audit-meaningful sign-offs.
- **Severity**: med.
- **Mitigation**: First boot prompts admin to assign at least one `iso` and one `ao`; tracker UI's "Settings → Roles" page documents the mapping; the operator runbook explains the IDP-side configuration. CHANGELOG calls out the role requirement.
- **Status**: open.

### B-X6 — `process.env.NODE_ENV === 'test'` branch creep
- **Description**: REO Rule 1.8 prohibits this branch in production code. New cross-cutting infrastructure (signing, HTTP fetch, snapshot writes) is exactly where developers reach for `if (NODE_ENV === 'test')` shortcuts.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal; tests inject seams via dependency-injected HTTP fetcher + filesystem helper; CI gate is non-bypassable.
- **Status**: open.

### B-X7 — Existing collectors must continue passing under extended Finding type
- **Description**: B.B1 extends `Finding` with optional `risk_score?: RiskScore`. While additive and backward-compatible by design, every collector (~ 200 files) silently inherits the field. A future PR could inadvertently rely on its presence; B.B1 ship must not trigger any test failure in existing collectors.
- **Severity**: med.
- **Mitigation**: `risk_score` field is OPTIONAL; existing collectors don't reference it; B.B1's typecheck pass over the whole repo catches any breakage; tests `tests/core/envelope.test.ts` exercise the optional path.
- **Status**: open.

### B-X8 — Submission bundle role count growth
- **Description**: LOOP-B adds 7-8 new roles to `submission-bundle.ts:WELL_KNOWN` (risk-scores-json, epss-cache, deadline-audit-json, risk-acceptances-snapshot, compensating-controls-snapshot, risk-register-json, risk-register-xlsx, organisational-risks-snapshot). Each role must have a stable canonical filename + description; collisions would corrupt the bundle.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the role table; per-slice tests assert presence; CHANGELOG entry for B.B5 lists the final role inventory at loop close.
- **Status**: open.

### B-X9 — Provenance schema drift
- **Description**: Every new emit artifact (`risk-scores.json`, `deadline-audit.json`, `.risk-acceptances.json`, `.compensating-controls.json`, `.organisational-risks.json`, `risk-register.json`, `risk-register.xlsx`) must carry a `provenance` block per REO Rule 2.6. `scripts/check-provenance.mjs` enforces the schema (emitter, emittedAt, sourceCalls, signingKeyId). A missed block fails the slice.
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via `check:provenance`; pattern reused from `core/inventory-coverage.ts`; CHANGELOG entry per slice cites the provenance block contents.
- **Status**: open.

### B-X10 — Tracker schema migration on existing installs
- **Description**: LOOP-B adds 4 new tables (`risk_acceptances`, `risk_acceptance_compensating_links`, `compensating_controls`, `organisational_risks`). Existing tracker installs have user data — migrations must be additive only. The repo uses idempotent `CREATE TABLE IF NOT EXISTS`; any non-additive change is a breaking change.
- **Severity**: high.
- **Mitigation**: All four ALTERs are additive; CHANGELOG documents the upgrade path; smoke test on a copy of a production DB; no DROP / ALTER COLUMN under any circumstance in LOOP-B; future `H.H3` multi-tenant work batches all cross-loop migrations.
- **Status**: open.

### B-X11 — Inventory tags absent on existing fleet
- **Description**: B.B1 derives criticality + exposure from `inventory.assets[].data_classification`, `asset_tier`, `public_facing`, `internet_reachable`. Real CSPs have not back-tagged all assets; large fractions will return `REQUIRES-OPERATOR-INPUT`.
- **Severity**: med (correctness signal, not a blocker).
- **Mitigation**: REQUIRES-OPERATOR-INPUT is observable on every affected risk's prop; coverage-regression CI guardrail tracks fill rates; documented in operator runbook with example tagging commands per provider (AWS `aws ec2 create-tags`, GCP `gcloud labels`).
- **Status**: open.

### B-X12 — EPSS / FIRST API availability
- **Description**: B.B1 calls `https://api.first.org/data/v1/epss`. If FIRST is unreachable, slow, or rate-limits, B.B1's behaviour is REQUIRES-OPERATOR-INPUT marker — defensible, but every run during an outage emits unscored rows.
- **Severity**: low.
- **Mitigation**: 24-hour on-disk cache amortises across runs; `core/retry.ts` exponential backoff on 429/5xx; explicit fallback marker is NOT silent; CHANGELOG entry for B.B1 documents the dependency.
- **Status**: open.

### B-X13 — Test count expectations / CI thresholds
- **Description**: LOOP-B adds ≥65 new tests across cloud-evidence + tracker. Existing CI may have hard-coded "expected test count" assertions or coverage thresholds that need bumping.
- **Severity**: low.
- **Mitigation**: Per slice, the implementing session updates any test-count assertion; CHANGELOG entries cite the new totals; STATUS.md "Overall → tests" line bumped atomically with each slice ship.
- **Status**: open.

### B-X14 — POA&M XML emitter coverage
- **Description**: `core/oscal-xml.ts` projects POA&M JSON to XML. New props from B.B1-B.B4 must survive the JSON→XML pipeline; an unhandled prop name would silently drop in XML output.
- **Severity**: med.
- **Mitigation**: Per-slice test re-emits POA&M XML; asserts presence of all new prop names; pattern from LOOP-A.A1 mirrored.
- **Status**: open.

### B-X15 — Multi-CSO tenant isolation deferred to H.H3
- **Description**: All four LOOP-B tables omit a `tenant_id` column. When multi-CSO ships (H.H3), all four need migration in a single cross-loop sweep. If LOOP-B users start storing multi-tenant data via app-level filtering, the H.H3 migration becomes destructive.
- **Severity**: med (long-tail).
- **Mitigation**: Documented in LOOP-B-SPEC.md §6.7; H.H3 spec must enumerate every LOOP-B table; LOOP-B ship in single-tenant deployments only (documented in runbook).
- **Status**: open.

---

## Per-slice risks

### B.B1 — Per-finding CVSS+EPSS+criticality+exposure scoring

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| B.B1-1 | med | CVSS 4.0 MacroVector table is ~270 entries; full implementation deferred | First-cut uses qualitative-band derivation; `cvss-version=4.0-approximate` prop is honest | open |
| B.B1-2 | med | EPSS rate limits not published by FIRST | Batch up to 100 CVEs/request; retry/backoff; cache 24h; REQUIRES-OPERATOR-INPUT on persistent failure | open |
| B.B1-3 | high | Severity-derived CVSS fallback could be mistaken for real CVSS | `cvss-source: REQUIRES-OPERATOR-INPUT` prop on every affected risk; runbook documents | open |
| B.B1-4 | low | Composite formula version drift mid-authorization-cycle | `formula_version: "risk-score.v1"` field; CHANGELOG entry pins the version | open |
| B.B1-5 | low | EPSS API spec drift | Permissive parser for extras; strict on the 4 fields we use; missing field → REQUIRES-OPERATOR-INPUT | open |
| B.B1-6 | low | Operator confuses `risk-config.yaml` (gitignored) with `risk-config.example.yaml` (committed) | README + runbook documents; defaults work without operator config | open |
| B.B1-7 | med | When `affected_resources[]` matches multiple inventory assets, aggregation rule (max vs mean vs median) could surprise operators | Spec pins max; code comment cites decision | open |
| B.B1-EXT-1 | high | **Dependency-metadata inconsistency surfaced while shipping B.B1.** `docs/slices/W/W.W2.md` frontmatter `depends_on` = [W.W1, E.E2, J.J3, A.A1, A.A5, B.B1] but STATUS.md's W.W2 row + next-priority line cite only [W.W1, J.J2]; the two lists disagree (J.J2 absent from frontmatter; E.E2/J.J3 absent from STATUS), and STATUS's W→T→B queue order places B.B1 *after* W.W2 even though W.W2 depends on B.B1 (a cycle). Caused this session's auto-detect to flag W.W2 unshippable. | Reconcile the W.W2 dependency records (pick the per-slice-doc frontmatter as source of truth) and re-derive the W-loop critical path (J.J2 → J.J3 + E.E2 → W.W2) before scheduling W.W2; tracked in STATUS.md "Next priority" note. | open |
| B.B1-EXT-2 | low | NVD CVE→CVSS auto-lookup is out of B.B1 scope (B.B1 only consumes collector-cited / operator-supplied vectors, else severity fallback). Findings with a CVE but no vector get a REQUIRES-OPERATOR-INPUT CVSS. | Untracked-work pointer (Q4): a future slice may add an NVD lookup feeding `references[].cvss_vector`; revisit at STATUS "next priority" review. No speculative B.B6 stub created. | open |
| B.B1-8 | med | NVD CVE→CVSS lookup deferred; collectors must populate `cvss_vector` natively | Documented in §6 of LOOP-B-SPEC.md; follow-up slice (B.B6 candidate) | open |

### B.B2 — Remediation deadline math (KEV / PAIN / IRV / LEV / FedRAMP CMP)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| B.B2-1 | high | FedRAMP CMP PDF returns 403; operator must download manually (cross-ref B-X1) | REQUIRES-OPERATOR-INPUT marker; `--strict-risk` blocks ship | open |
| B.B2-2 | med | KEV catalog could be stale | `core/kev-feed.ts` records `fetched_at`; warning at 7d; `--strict-risk` fails the build | open |
| B.B2-3 | med | VDR pipeline may not emit all of PAIN/IRV/LEV today | Verify during build; extend `vdr-ledger.ts` if missing; pin with tests | open |
| B.B2-4 | high | `severity-fallback` could silently fire | `--strict-risk` exits non-zero; CI default sets the flag | open |
| B.B2-5 | low | LOOP-A.A1's `REMEDIATION_DEADLINE_DAYS` lingers as dead code | B.B2 deletes it; CHANGELOG calls out removal | open |
| B.B2-6 | med | KEV match could over-match (CVE substring) or under-match (case) | Exact-string match on uppercase CVE-YYYY-NNNNN; CVE IDs normalised at input | open |
| B.B2-7 | low | PAIN/IRV/LEV threshold (composite ≥ 9.0) is org-dependent | Tunable via `risk-config.yaml`; tests pin default; CHANGELOG documents | open |
| B.B2-8 | med | Operator override could be EARLIER than KEV dueDate — which wins? | Spec resolution: KEV wins (federal mandate); Q1 in B.B2.md | open |
| B.B2-9 | med | PAIN/IRV/LEV override hard-codes 30 days; would diverge from CMP table updates | Derive override from `FEDRAMP_CMP_DEADLINES.critical` instead of literal 30 | open |

### B.B3 — Risk acceptance workflow

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| B.B3-1 | med | Cross-repo signing-key drift (cross-ref B-X3) | Tracker exposes `/api/sign/public-keys` with full key registry | open |
| B.B3-2 | high | Tracker schema migration on existing DBs (cross-ref B-X10) | Additive only; smoke test on production DB copy | open |
| B.B3-3 | med | AO approval signature replay | Per-approval includes `approved_at` (server-set) + uuid; status transition rejects replay | open |
| B.B3-4 | med | Enforcer drift if server is down at expiration moment | cloud-evidence side ALSO filters `expiration_date > now()` | open |
| B.B3-5 | med | CC UUID references precede B.B4 ship | UI gracefully degrades when `/api/compensating-controls` 404s | open |
| B.B3-6 | low | Justification 240-char truncation in OSCAL prop | Full text in tracker; `acceptance-uuid` prop is the link | open |
| B.B3-7 | med | RBAC mis-configuration | Per-route `requireRole` is unit-tested; `audit_log` records each role-checked action | open |
| B.B3-8 | low | HTTP fetch cross-system dependency | Reader falls back to cached snapshot; air-gapped runs supported | open |
| B.B3-9 | med | AO approval lacks second-factor | Out of scope for B.B3 ship; existing session + role + signature sufficient; file follow-up (Q1) | open |
| B.B3-10 | low | Orphaned acceptance (finding remediated separately) | Out of scope; UI surfaces stale review item; follow-up task (Q3) | open |
| B.B3-11 | med | **Tracker stack diverges from the per-slice spec** [discovered impl-b-b3, 2026-07-02]. Spec assumed Express + zod + `requireRole(['iso','ao'])` middleware + a pre-existing `tracker/server/sign.ts`. Reality: **Hono** + **manual validation (no zod)** + **permission-based RBAC** (`hasPermission(role, perm)`; roles were `viewer/contributor/ksi-owner/auditor/admin`) + **NO signing subsystem**. | Adapted to reality: added `read/create/approve/revoke:risk_acceptance` permissions + `iso/ao/assessor` roles to `rbac.ts`; built the Ed25519 signing subsystem from scratch (`server/risk-acceptance-sign.ts` + `signing_keys` table). Future tracker slices (B.B4/B.B5/F.F1/K.K1) reuse these primitives — do NOT re-derive from the idealized specs. | mitigated |
| B.B3-12 | low | **No jsdom / @testing-library in the tracker toolchain; vitest only collects `server/**` + `tests/**`** [discovered impl-b-b3, 2026-07-02]. The spec's `.test.tsx` DOM-render UI tests cannot run without new deps + a vitest env + an include-glob change. | Extracted the components' decision logic (form validation + role-gated CTAs) to the pure `client/src/lib/risk-acceptance-view.ts` and unit-tested it in `tracker/tests/risk-acceptance-view.test.ts` (node env). The React pages import those tested helpers, so the rendered behaviour IS the tested logic. Adding jsdom is a follow-up if true render tests are wanted. | mitigated |
| B.B3-EXT-1 | med | **Resident tracker private key stored PEM-encoded in the `signing_keys` DB table** [discovered impl-b-b3, 2026-07-02]. The tracker had no key store; B.B3 added one. For a local single-node tracker this matches how password hashes + hashed session tokens already live in the DB, but a production deployment should not keep the raw Ed25519 private key at rest in SQLite. | DEFERRED: front the signing key with a KMS/HSM (read the private key from a mounted path / KMS at boot, keep only public key + key_id in `signing_keys`). `getSigningKey()` is the single seam to change. Not blocking for B.B3's local-tracker scope. | open |

### B.B4 — Compensating-controls registry

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| B.B4-1 | low | NIST control catalog drift (Rev 5 → Rev 6 hypothetical) | Catalog versioned; `catalog-version` prop on each record | open |
| B.B4-2 | med | Evidence URL link rot | `evidence_sha256` provides immutable backup via H.4 attachment | open |
| B.B4-3 | med | Activation lacks second-factor | File as follow-up; session + role + signature sufficient | open |
| B.B4-4 | high | Retired control cited by active acceptance | Retirement route enforces "no active links"; 409 if so | open |
| B.B4-5 | low | Active control count unbounded | Pagination + infinite scroll | open |
| B.B4-6 | low | Lorem ipsum description bypasses ≥ 200 char check | Reviewer + AO sign-off catch; future enhancement: similarity check | open |
| B.B4-7 | low | NIST control id validation expensive for large arrays | Catalog loaded into Map at boot; O(1) lookups | open |
| B.B4-8 | med | Cross-repo schema drift between `compensating_controls` UUIDs and acceptance references | Tracker exposes `/uuid-exists?uuids=...`; reader cross-references | open |
| B.B4-9 | med | H.4 attachment SHA-256 signed at CC create; if uploaded after, signature invalidates | UI flow forces upload BEFORE submit; `evidence_sha256` is part of the signed payload so an upload-before-create flow signs it in (Q7). H.4 wiring itself deferred. | open |
| B.B4-10 | med | **Tracker stack diverges from the per-slice spec** [discovered impl-b-b4, 2026-07-02]. Spec §7 assumed Express CRUD + a standalone `tracker/server/sign.ts`-style keypair for `compensating-control-sign.ts`. Reality (per B.B3-11): **Hono** + **manual validation** + **permission-based RBAC** + a single resident Ed25519 key in `signing_keys`. | Adapted to reality: built the routes on Hono, added `read/create/activate/retire:compensating_control` permissions to `rbac.ts`, and **reused the B.B3 signing key** (`compensating-control-sign.ts` re-exports `risk-acceptance-sign.ts`'s `signPayload`/`verifyPayload`/`getPublicKeyPem` + `canonicalize`, adding only the two payload shapes) so one tracker key signs acceptances + compensating controls and the cloud-evidence reader verifies both against the same published public key. Future tracker slices (B.B5/F.F1) reuse these primitives — do NOT re-derive from the idealized specs. | mitigated |
| B.B4-11 | low | **No jsdom / @testing-library in the tracker toolchain; vitest only collects `server/**` + `tests/**`** [discovered impl-b-b4, 2026-07-02]. The spec's `.test.tsx` DOM-render UI tests cannot run. | Extracted the components' decision logic (form validation, description-≥200 nudge, role-gated Activate/Retire CTAs, NIST-id normalisation + autocomplete filtering) to the pure `client/src/lib/compensating-control-view.ts` and unit-tested it in `tracker/tests/compensating-control-view.test.ts` (node env). The React pages import those tested helpers, so the rendered behaviour IS the tested logic. Same posture as B.B3-12. | mitigated |
| B.B4-12 | low | **NIST catalog shipped as a committed copy under `tracker/server/data/`** [discovered impl-b-b4, 2026-07-02; resolves Q1]. The tracker validates control ids against a copy of `cloud-evidence/docs/nist-r5-controls.generated.json` rather than fetching it from cloud-evidence at boot — single source of truth in-repo, no runtime cross-system dependency, but the two copies must stay in sync on a future Rev 6 regen. | The copy + `cloud-evidence/core/nist-r5.ts` share the same normaliser + key form; a future `scripts/extract-nist-r5.mjs` regen MUST update both files. `nist-catalog.ts:catalogVersion()` tags the size so drift is observable. Tracked with B.B4-1 (catalog drift). | open |

### B.B5 — Central Risk Register

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| B.B5-1 | med | Band-derivation defaults may differ from operator org policy | Tunable in `risk-config.yaml`; `formula_version` propagates | open |
| B.B5-2 | low | NIST 800-30 Table I-2 interpretation differs across orgs | Typed constant `INHERENT_RISK_MATRIX` with NIST citation; override via config | open |
| B.B5-3 | low | XLSX output not visually polished (no pivots, no charts) | Conditional formatting on high/very-high; matches `inventory-workbook.ts` baseline | open |
| B.B5-4 | med | Aggregator could double-count finding with acceptance + CC | De-dupe step prefers acceptance entry; finding entry suppressed | open |
| B.B5-5 | low | Organisational risks unbounded | Pagination; closed risks hidden by default in UI | open |
| B.B5-6 | low | Review date enforcement varies by org policy | Minimum 30 days forward; org policy via `risk-config.yaml` | open |
| B.B5-7 | med | Snapshot age skew (cross-ref B-X4) | 5-min window enforced under `--strict-risk` | open |
| B.B5-8 | low | NIST 800-30 Rev 2 hypothetical breaking change | `nist-800-30-version: "Rev 1"` prop; future migration is separate slice | open |
| B.B5-9 | med | XLSX signed but mutable on open in Excel | Documented; signed file is archive; working copies unsigned | open |
| B.B5-10 | med | LOOP-C.C7 (RMS doc) depends on this artifact; release order matters | Documented in dependency graph; LOOP-C.C7 must not start until B.B5 ships | open |

---

## External dependencies that may change

### FedRAMP guidance updates that could affect LOOP-B
- **FedRAMP Continuous Monitoring Strategy & Guide (Rev 5)** — current source for B.B2 deadline table + B.B3 Deviation Request field set. A Rev 6 publication would require re-extracting the table verbatim into `deadline-table.ts` and updating B.B3 DR field validation. URL: https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf
- **FedRAMP Rev5 Playbook — ConMon Vulnerability Scanning** — secondary reinforcement of CMP table. URL: https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/
- **FedRAMP Risk Management Strategy Template** — consumed by LOOP-C.C7; format changes here ripple into LOOP-B.B5 XLSX columns. URL: https://www.fedramp.gov/assets/resources/templates/CSP_Risk_Management_Strategy_Template.docx
- **FedRAMP Deviation Request Form Template** — drives B.B3 schema. Field additions / removals would require schema migration. URL: https://www.fedramp.gov/assets/resources/templates/FedRAMP-Deviation-Request-Form-Template.docx
- **FedRAMP 20x Phase Two requirements** — published RFCs (RFC-0014 already incorporated) could redefine "validated KSI" semantics, affecting B.B1 source-priority cascade.

### NIST publication versions
- **NIST SP 800-30 Rev 1 (2012)** — current source for likelihood/impact bands + Table I-2 matrix. A Rev 2 publication would update the qualitative tokens or matrix; B.B5 schema would need migration. URL: https://csrc.nist.gov/pubs/sp/800/30/r1/final
- **NIST SP 800-53 Rev 5 (Sep 2020, errata Dec 2023)** — current source for CA-5, RA-3, RA-5, RA-7, PL-2 control statements. Rev 6 is in the long-tail; would require catalog regeneration (`nist-r5-controls.generated.json`) + B.B4 NIST control-id validation refresh. URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- **NIST SP 800-53A Rev 5 (errata Dec 2023, currently 5.2.0 → 5.3.0 in progress)** — assessment guide. Updates affect 3PAO procedures referenced from B.B3/B.B4 audit trails. URL: https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final
- **NIST SP 800-39 (2011)** — risk management hierarchy. Stable; very unlikely to change in LOOP-B horizon.
- **NIST SP 800-37 Rev 2 (2018)** — RMF; cited in B.B3 for risk-response task. Stable.

### Upstream library updates
- **ajv (^8.x)** — used by `core/oscal-validate.ts`. Schema validation behaviour changes are rare but possible; lock major version. https://ajv.js.org
- **OSCAL JSON Schema v1.1.2** — committed at `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json`. NIST OSCAL Working Group periodically publishes new minor versions (v1.2.x in progress as of source date). Migration to v1.2 is a separate cross-loop refactor; pin v1.1.2 within LOOP-B. https://pages.nist.gov/OSCAL/
- **better-sqlite3 (~9.x or ~11.x)** — used by tracker. SQL dialect stable; CREATE TABLE syntax compatible across versions.
- **rfc8785 (canonical JSON) library** — multiple JS implementations exist (e.g. `canonicalize`, `json-canonicalize`). Signature compatibility depends on byte-exact canonicalization; pin one library across both cloud-evidence + tracker.
- **noble-ed25519 (^2.x) or @noble/ed25519** — Ed25519 signing. Stable API; performance improvements in minor releases.
- **CISA KEV JSON feed** — schema documented at https://www.cisa.gov/known-exploited-vulnerabilities. Field additions (e.g. `cwes`) handled by permissive parser. Removals would require `core/kev-feed.ts` update.
- **FIRST EPSS API v1** — `https://api.first.org/data/v1/epss`. EPSS team publishes a `v3` model annually (current is v3.0 as of 2023-03); rev'd models continue to use the v1 API endpoint. Backward-compatible expected.
- **XLSX pure-JS renderer** — using OOXML compose helpers, no external dep. SheetJS reused only for test round-trip.
- **React (^18.x)** — tracker UI. v19 ships routinely; pin major version within LOOP-B.

### Cloud provider / infrastructure
- **AWS / GCP / Azure resource-tag schemas** — `fedramp_data_classification`, `fedramp_asset_tier`, `fedramp_exposure_override` are operator-defined custom tags. No upstream change risk; tag name conventions documented in operator runbook.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the appropriate per-slice section with a fresh ID (e.g. `B.B3-11`); commit alongside the slice's implementation log update.
2. Risks resolved during implementation: move the row to the "Resolved risks" table at the bottom with date + resolution note + responsible session/commit. Do NOT delete the original entry — historical record matters.
3. Severity bump (low → med → high): add a `note` line under the original entry describing why; do not edit history.
4. Cross-cutting risks that affect multiple slices: keep in the cross-cutting section; reference from per-slice tables via "(cross-ref B-X<n>)".

---

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-B-SPEC.md` Section 6 (open questions) — overlaps with this register.
3. Read the specific per-slice doc at `docs/slices/B/B.B<n>.md` for the slice you're implementing — risks here are the LIVE working set; risks in the per-slice docs are the spec snapshot.
4. Before shipping a slice, update this file's per-slice section + move any resolved risks to the resolved table atomically with the slice's commit (per SLICE-COMPLETION-PROCEDURE.md).
