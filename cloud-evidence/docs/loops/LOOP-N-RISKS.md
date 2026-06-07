# LOOP-N — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with `status=resolved` + resolution note. Severity: high = ship-blocking; med = should fix in-loop; low = file as follow-up.

> Authoritative companion to `docs/loops/LOOP-N-SPEC.md` and the per-slice docs at `docs/slices/N/N.N[1-4].md`. Read those for context before acting on any risk here.

> Last updated: 2026-06-07.

---

## Cross-cutting risks (apply to ALL slices in LOOP-N)

### N-X1 — NIST SP 800-30 r1 + NIST SP 800-154 PDFs gated by 403 on anonymous fetch
- **Description**: NIST SP 800-30 Rev 1 (the authoritative source for the App. D threat-source taxonomy N.N1 cites) and NIST SP 800-154 (the DCSTM 4-step methodology N.N1 + N.N2 cite) PDFs return binary content / 403 to anonymous HTTPS fetches. Implementer must manually download into `cloud-evidence/docs/sources/nist-sp-800-30r1.pdf` + `cloud-evidence/docs/sources/nist-sp-800-154-draft.pdf` before N.N1's docstring + STRIDE catalog + N.N2's module docstring can pin verbatim page + section citations.
- **Severity**: high (N.N1 + N.N2 blocker for verbatim quotes).
- **Mitigation**: Each affected slice carries a `REQUIRES-OPERATOR-INPUT: confirm-against-nist-800-30r1-pdf` (or `nist-800-154-pdf`) marker on its constants until the PDFs are downloaded; `--strict-threat` orchestrator mode fails the build if the marker remains; CHANGELOG entry for N.N1 quotes the relevant taxonomy verbatim with PDF page + section, atomically with download.
- **Status**: open.

### N-X2 — OSCAL v1.1.2 props + back-matter extension token registration
- **Description**: LOOP-N introduces new `back-matter.resources[type]` tokens (`threat-model` in N.N1, `attack-surface` in N.N2) and new `props[name]` values (`threat-stride-category`, `attack-surface-category`, `adversarial-scenario-id`, `attack-technique`, `attack-tactic`, etc.) — all in the `CE_NS` namespace. OSCAL v1.1.2 allows arbitrary `ns`-namespaced extensions but a typo (missing `ns: CE_NS`) silently fails strict ajv validation; an unregistered `type` token is legal but a 3PAO reviewing the artifact has no canonical reference to disambiguate.
- **Severity**: high (all slices; integrity of the OSCAL chain).
- **Mitigation**: `docs/oscal/extensions.md` registers every new `type` token + every new `props[name]` value, committed alongside the first slice that introduces the token (N.N1 ships the doc; N.N2/N.N3/N.N4 amend in their commits). `core/oscal-validate.ts` runs after every slice's OSCAL re-emission; `ns: CE_NS` enforced via `scripts/lint-no-stubs.mjs` rule. CI fails if any new prop lacks `ns`.
- **Status**: open.

### N-X3 — STRIDE catalog completeness + currency
- **Description**: N.N1's `core/stride-catalog.ts` covers 11 × 6 = 66 cells of the ComponentClass × STRIDE matrix; ~36 cells have meaningful threats; the remaining ~30 are documented "n/a — no plausible threat at this category × class". A future inventory addition (e.g. a new `quantum-key-distribution` ComponentClass) requires a catalog update. The catalog must stay current as the FRMR catalog updates KSI IDs and as NIST SP 800-53 evolves (Rev 5 → Rev 6 hypothetical).
- **Severity**: med (long-tail correctness).
- **Mitigation**: Catalog rows carry `citation { spec, section, url }` so freshness is auditable; catalog tests assert ≥30 high-signal rows; a "catalog version" prop is emitted on every `threat-model.json` for traceability. FRMR catalog regeneration triggers catalog review (documented in operator runbook). N.N1 CHANGELOG entry lists which cells are populated and why others are n/a.
- **Status**: open.

### N-X4 — Submission bundle role count growth
- **Description**: LOOP-N adds 5 new roles to `submission-bundle.ts:WELL_KNOWN`: `threat-model-json`, `threat-model-docx`, `attack-surface-json`, `adversarial-results-json`, `attack-mapping-json`. Each role must have a stable canonical filename + description; collisions would corrupt the bundle. The pre-LOOP-N count is the LOOP-A.A4 + LOOP-B baseline; LOOP-N pushes the total to ~25 roles.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the role table; per-slice tests assert presence + uniqueness of new role; CHANGELOG entry per slice cites the running role count; N.N4 CHANGELOG closes the LOOP with the final role inventory.
- **Status**: open.

### N-X5 — Tracker schema migrations + RBAC role requirements
- **Description**: LOOP-N adds 3 new tracker tables (`threat_models` + `threat_model_narratives` from N.N1; `attack_surface_inventory` from N.N2; `adversarial_test_runs` from N.N3). Existing tracker installs have user data — migrations must be additive only. The repo uses idempotent `CREATE TABLE IF NOT EXISTS`. The ISO role (used by N.N1 sign-off; carried over from LOOP-B) must be assigned in the operator's IDP; if no user maps to ISO, every threat-model row stays `operator_signed_off: false` and `--strict-threat` blocks the ship.
- **Severity**: high (schema migration on existing installs; potential RBAC drift).
- **Mitigation**: All ALTERs are additive only; CHANGELOG documents the upgrade path; smoke test on a copy of a production DB before merge; first-boot prompts admin to assign at least one ISO; tracker UI "Settings → Roles" documents the mapping; operator runbook explains IDP-side configuration. Future `H.H3` multi-tenant work batches all cross-loop migrations.
- **Status**: open.

### N-X6 — External catalog drift (MITRE ATT&CK, CISA KEV, CTID mappings)
- **Description**: N.N4 depends on three pinned upstream sources: MITRE ATT&CK STIX (https://github.com/mitre/cti), CTID ATT&CK→NIST mapping, CTID `attack_to_cve` mapping. ATT&CK ships ~6 months; CTID mappings ship irregularly. Stale subsets produce stale coverage matrices; outright deletion of a technique upstream + reuse of the T-id (rare but possible) corrupts the catalog.
- **Severity**: med (long-tail correctness).
- **Mitigation**: `scripts/refresh-attack-mappings.mjs` operator-run script + scheduled GitHub Actions PR to refresh; `provenance.sources.stix_pinned_version` + `mapping_pinned_version` makes the pin visible; a 9-month-old pin triggers a CI warning; CHANGELOG entries pin versions at each refresh; if T-id deletion is detected, refresh script raises an error rather than silently dropping rows.
- **Status**: open.

### N-X7 — Adversarial scenario CI build-time + flakiness
- **Description**: N.N3 adds ≥10 adversarial scenarios to CI under `CLOUD_EVIDENCE_STRICT_ADVERSARIAL=1`. Each runs the FULL production code path under attack. Total CI time growth could exceed budget. Network-dependent scenarios (RFC 3161 timestamp; FIRST EPSS poisoning) can flake on transient upstream failures.
- **Severity**: med.
- **Mitigation**: Scenarios run in parallel where independent; runner supports `--workers <n>`; CI uses cached timestamp tokens for fixture envelopes (committed alongside fixtures); live-network scenarios run only in a nightly scheduled CI job; `--scenario-filter` skips listed scenarios and records skip in provenance.
- **Status**: open.

### N-X8 — `process.env.NODE_ENV === 'test'` branch creep in adversarial paths
- **Description**: REO Rule 1.8 prohibits this branch. The natural temptation in N.N3 is to add a "if test, accept mutated envelope" shortcut — exactly the opposite of what we want. The adversarial runner MUST exercise the same production code path.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal; N.N3 includes an explicit meta-test that greps production paths for the forbidden literal; mutators inject through PUBLIC APIs only (verifyEnvelope, verifySignature, importAp, parseKevFeed, etc.); CI gate is non-bypassable.
- **Status**: open.

### N-X9 — Provenance schema drift across LOOP-N artifacts
- **Description**: Every new emit artifact (`threat-model.json`, `threat-model.docx`, `attack-surface.json`, `adversarial-results.json`, `attack-mapping.json`) must carry a `provenance` block per REO Rule 2.6. `scripts/check-provenance.mjs` enforces the schema. A missed block fails the slice.
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via `check:provenance`; pattern reused from `core/inventory-coverage.ts`; CHANGELOG entry per slice cites the provenance block contents.
- **Status**: open.

### N-X10 — Cross-system snapshot age skew between cloud-evidence + tracker
- **Description**: N.N1 reads the tracker snapshot (`out/.threat-model-snapshot.json`) for kill_chain_narrative + per-row sign-off; N.N2 reads the tracker snapshot (`out/.attack-surface-snapshot.json`) for operator-supplied subprocessor flows. If the tracker is being actively edited during a run, snapshots could be inconsistent — e.g. a sign-off occurring mid-run lands in the threat-model snapshot but not in the attack-surface snapshot.
- **Severity**: med.
- **Mitigation**: Each reader records `fetched_at`; orchestrator's `--strict-threat` mode requires snapshots within a 5-minute window; CHANGELOG entries document the skew bound; UI surfaces "stale snapshot" warning when bound exceeded. Pattern reused from LOOP-B `B-X4`.
- **Status**: open.

### N-X11 — Inventory tag absence on existing fleet (cascading from B-X11)
- **Description**: N.N1 + N.N2 read `inventory.assets[].data_classification`, `asset_tier`, `fedramp_component_class`. Real CSPs have not back-tagged all assets; LOOP-N inherits the same risk LOOP-B identified. Untagged assets produce `ComponentClass: 'unknown'` (or fall back to a generic class) and `data_classes_in_transit: REQUIRES-OPERATOR-INPUT`.
- **Severity**: med (correctness signal, not a blocker).
- **Mitigation**: REQUIRES-OPERATOR-INPUT observable on every affected row's prop; coverage-regression CI guardrail tracks tag fill rates; operator runbook documents tagging commands per provider (AWS `aws ec2 create-tags`, GCP `gcloud labels`, Azure `az tag`). Cross-ref `B-X11`.
- **Status**: open.

### N-X12 — Ed25519 signing-key registry across cloud-evidence + tracker (cascading from B-X3)
- **Description**: N.N1 + N.N2 + N.N3 sign tracker rows using a tracker-resident Ed25519 key; cloud-evidence side signs OSCAL outputs with its own key. The reader (`threat-model-emit.ts`, `attack-surface-emit.ts`, `adversarial-test-runner.ts`) must verify tracker signatures using the tracker's published key. Rotation without a historical-key registry breaks verification on snapshots written under the prior key.
- **Severity**: med.
- **Mitigation**: Reuse the LOOP-B `GET /api/sign/public-keys` registry pattern; reader cross-references each record's `signing_key_id` against the registry; key rotation events written to `audit_log`; runbook documents the rotation procedure. Cross-ref `B-X3`.
- **Status**: open.

### N-X13 — Multi-CSO tenant isolation deferred to H.H3
- **Description**: All three new LOOP-N tables (`threat_models`, `attack_surface_inventory`, `adversarial_test_runs`) omit `tenant_id`. When multi-CSO ships (H.H3), all three need migration in one cross-loop sweep. Single-tenant deployments only at LOOP-N ship.
- **Severity**: med (long-tail).
- **Mitigation**: Documented in `LOOP-N-SPEC.md §7 open question 7`; H.H3 spec must enumerate every LOOP-N table; runbook documents the single-tenant requirement.
- **Status**: open.

### N-X14 — Test count expectations + CI thresholds
- **Description**: LOOP-N adds ≥85 new tests across cloud-evidence + tracker (≥18 N.N1 + ≥18 N.N2 + ≥20 N.N3 + ≥20 N.N4 + ≥8 tracker). Existing CI may have hard-coded "expected test count" assertions or coverage thresholds that need bumping.
- **Severity**: low.
- **Mitigation**: Per slice, the implementing session updates any test-count assertion; CHANGELOG entries cite running totals; STATUS.md "Overall → tests" line bumped atomically with each slice ship.
- **Status**: open.

### N-X15 — AR observation count growth at scale
- **Description**: N.N1 emits per-(component, stride) AR observations (potentially 500 components × 6 STRIDE = 3000); N.N2 emits per-entry-point observations (could be 100+); N.N3 emits per-scenario observations (10+); N.N4 emits per-technique observations (50+). Total AR observation count growth could push ajv validation and OSCAL rendering past performance budgets.
- **Severity**: med.
- **Mitigation**: Emitter measures elapsed and warns at > 5s; chunked OSCAL emission is a future enhancement; `--strict-threat` mode does not block on perf; CHANGELOG entry per slice cites measured time on a reference inventory.
- **Status**: open.

### N-X16 — Adversarial scenario expected_outcome regressions cascade across slices
- **Description**: An expected_outcome `fail-closed` for ADV-005 (OSCAL chain corruption) depends on LOOP-A.A3 chain check existing and working. A future refactor of `core/oscal.ts` that loosens chain validation would flip ADV-005 to `verdict: 'fail'`. This is GOOD (it caught the regression) but the failure mode requires CI tooling to surface the actual diff.
- **Severity**: low (good failure mode; UX risk).
- **Mitigation**: Failure manifest emits `observed_outcome` + `observed_diagnostic` verbatim; CI failure message extracts the diff and renders it in the PR comment; runbook documents debugging procedure (re-run with `--scenario-filter ADV-005 --verbose`).
- **Status**: open.

### N-X17 — OSCAL `back-matter.resources[type=*]` token namespace collision risk
- **Description**: We register `threat-model` (N.N1) and `attack-surface` (N.N2) as `type` tokens. If NIST OSCAL publishes a future canonical `type` value with the same name and different semantics, our extension diverges. The OSCAL namespace policy does not currently namespace `type` values (unlike `props.ns`).
- **Severity**: low.
- **Mitigation**: `docs/oscal/extensions.md` lists every token + its semantics; review at OSCAL minor-version bumps; if collision occurs, migrate to a `ce-threat-model` / `ce-attack-surface` token in a single cross-LOOP-N commit; CHANGELOG documents.
- **Status**: open.

---

## Per-slice risks

### N.N1 — STRIDE threat model generator (per-component, from inventory + DFD)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| N.N1-1 | med | LOOP-D.D3 DFD overlay sequencing — N.N1 may ship before D.D3 | Slice ships without overlay; docstring forward-links to D.D3; D.D3 CHANGELOG entry back-fills the overlay | open |
| N.N1-2 | high | NIST SP 800-30 r1 PDF gated by 403 (cross-ref N-X1) | REQUIRES-OPERATOR-INPUT marker; `--strict-threat` blocks ship until PDF downloaded + citations verbatim | open |
| N.N1-3 | med | STRIDE catalog completeness (~36 cells of 66 populated) | Catalog comments document n/a cells; tests assert ≥30 high-signal rows; CHANGELOG lists populated cells | open |
| N.N1-4 | med | Operator may misconfigure ISO role in IDP, blocking sign-off (cross-ref N-X5) | First-boot prompt; tracker UI documents; `--strict-threat` blocks if rows unsigned | open |
| N.N1-5 | med | AR observation count growth at scale (cross-ref N-X15) | Emitter measures + warns; chunking is future enhancement | open |
| N.N1-6 | low | docx renderer test brittleness (heading text changes) | Test asserts heading existence by ID, not exact text | open |
| N.N1-7 | low | Catalog drift vs FRMR catalog regeneration | Catalog rows carry citation; FRMR regen triggers catalog review per runbook | open |
| N.N1-8 | med | Deterministic UUID v5 collision risk if component_id format changes | UUID is over (component_id, stride); component_id stability documented in INV-P1 spec; pin with test | open |

### N.N2 — Attack surface enumeration (boundary entry points + exposed services)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| N.N2-1 | med | Operator-supplied annotation drift vs cloud reality (mTLS claim, real flow is oidc) | Tracker row signed; LOOP-K pen test exercises actual auth; mismatches surface in K results | open |
| N.N2-2 | med | Network evidence file format drift between providers | Per-provider adapter; tests pin shapes; new provider requires adapter slice | open |
| N.N2-3 | low | Internet-reachable-unauthenticated diagnostic could overwhelm SAR §3.4 | Diagnostics surfaced separately; SAR §3.4 summary aggregates by count, not detail | open |
| N.N2-4 | med | 0.0.0.0/0 with `authentication: 'mtls'` flagged inaccurately (NLB mTLS) | Cross-reference NLB target-group attributes; if missing, mark unknown + REQUIRES-OPERATOR-INPUT | open |
| N.N2-5 | low | Subprocessor flow row lacks structured subprocessor_id | Free-text `operator_notes` carries the name; future slice adds `subprocessors` table | open |
| N.N2-6 | med | IPv4 + IPv6 dual-stack rule aggregation could miss heterogeneous cases | Per-(component, protocol, port) collapse; pin with a test | open |
| N.N2-7 | low | AR observation deduplication between N.N1 + N.N2 on same component | Distinct UUIDs; observation.description disambiguates; pin with a test | open |

### N.N3 — PASTA/red-team adversarial test framework (automated runs)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| N.N3-1 | med | RFC 3161 ADV-003 replay scenario flakiness on transient TSR failures (cross-ref N-X7) | Cached TSR for fixture envelopes; CI uses cached path; live TSR in nightly job | open |
| N.N3-2 | high | Production-path hardening (ADV-005 OSCAL chain corruption) may expose pre-existing bugs in LOOP-A.A3 | Dependency frontmatter pins A.A3; spec-driven ordering | open |
| N.N3-3 | high | NODE_ENV branch creep in production paths (cross-ref N-X8) | Lint catches; meta-test greps; CI rejects | open |
| N.N3-4 | med | Scenario catalog growth burden across loops | Catalog is extensible; future slices that touch sign-off/signing add scenarios in same commit | open |
| N.N3-5 | med | False-positive verdicts from upstream library version bumps (ajv) | Pin major versions; per-scenario test asserts SPECIFIC diagnostic text; upstream changes surface as test failures | open |
| N.N3-6 | med | Mutator purity drift produces order-dependent results | Deep-clone input per scenario; deterministic order; meta-test asserts clone semantics | open |
| N.N3-7 | med | CI build time growth from ≥10 adversarial runs (cross-ref N-X7) | Parallel execution; `--workers <n>`; CI timeout documented | open |
| N.N3-8 | low | Diagnostic CODE vs free-text matching ambiguity | Match on typed enum from `core/diagnostics.ts`; cross-ref LOOP-A registry | open |
| N.N3-9 | low | ADV-010 bundle-merge between distinct CSO bundles (multi-tenant) deferred | Deferred to LOOP-H.H3; cross-ref in CHANGELOG | open |
| N.N3-10 | med | `observed_outcome: 'inconclusive'` should produce verdict fail in strict mode | Hard-coded in runner; pin with a test | open |

### N.N4 — MITRE ATT&CK technique mapping (techniques applicable to our boundary)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| N.N4-1 | med | MITRE ATT&CK release cadence drift (cross-ref N-X6) | Refresh script + runbook + 9-month staleness CI warning | open |
| N.N4-2 | med | CVE → technique mapping incomplete in CTID repo | REQUIRES-OPERATOR-INPUT on unmapped; operator supplies; future NLP-suggest enhancement | open |
| N.N4-3 | med | Subset curation burden (~100+ techniques in Cloud sub-matrix) | Refresh script accepts `--platforms <list>`; CHANGELOG documents included platforms | open |
| N.N4-4 | med | STIX 2.1 schema drift in MITRE CTI | Shape validator in attack-stix-loader; pin major STIX version | open |
| N.N4-5 | low | ATT&CK→NIST mapping deprecation in CTID | Pin file version + commit hash; refresh script flags non-additive changes | open |
| N.N4-6 | low | Heat-map UX overload at full matrix render | Default to tactic summary; click-through expands; pin in client | open |
| N.N4-7 | med | Coverage status double-counting (finding maps to multiple techniques) | `tactic_summary.covered` counts distinct techniques; pin with a test | open |
| N.N4-8 | med | POA&M prop count growth (finding × CVE × technique fanout) | Deduplicate props via set semantics per finding; pin with a test | open |
| N.N4-9 | low | Pinned subset commit size (500 KB - 2 MB) | Document size budget; `--platforms` scoping minimises | open |
| N.N4-10 | low | `mitigates` vs `detects` ATT&CK→NIST mapping_type ambiguity | Use only `mitigates` for coverage; `detects` informs ConMon (LOOP-E.E1 + LOOP-I.I3) | open |
| N.N4-11 | med | Container host-OS techniques inclusion ambiguity (EKS-only inventory) | Include container host-OS techniques; pin with EKS-only fixture test | open |

---

## External dependencies that may change

### FedRAMP guidance updates that could affect LOOP-N
- **FedRAMP Rev5 SSP Template (§13 narrative for RA-3, PL-2)** — current source for the docx layout N.N1 emits. Template version bumps could rename sections or add required fields. URL: https://www.fedramp.gov/assets/resources/templates/SSP-A1-FedRAMP-System-Security-Plan-Template.docx
- **FedRAMP SAR Template §3.4 Attack Surface Analysis** — drives the format LOOP-F.F7 SAR draft generator consumes from N.N2. Format changes would require re-shaping `out/attack-surface.json` columns. URL: https://www.fedramp.gov/assets/resources/templates/SAR-FedRAMP-Security-Assessment-Report-Template.docx
- **FedRAMP Penetration Test Guidance v3.0** — drives LOOP-K.K1 PenTest RoE; LOOP-K consumes N.N2 attack surface. URL: https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf
- **RFC-0014 (FedRAMP 20x Phase Two)** — the basis of N.N3's trust claim. Future RFCs could redefine "validated KSI" semantics, requiring scenario catalog updates. URL: https://www.fedramp.gov/rfcs/0014/

### NIST publication versions
- **NIST SP 800-30 Rev 1 (2012)** — current source for Appendix D threat-source taxonomy and the TASK 2-1..2-3 step structure N.N1 implements. A Rev 2 publication would update tokens; N.N1 catalog would need rework. URL: https://csrc.nist.gov/pubs/sp/800/30/r1/final
- **NIST SP 800-154 (Draft, ongoing)** — DCSTM methodology cited by N.N1 + N.N2. Draft status means future revisions are likely; pin against current draft + flag updates. URL: https://csrc.nist.gov/CSRC/media/Publications/sp/800-154/draft/documents/sp800_154_draft.pdf
- **NIST SP 800-53 Rev 5 (Sep 2020, errata Dec 2023)** — RA-3, RA-5, RA-10, CA-8, SA-11, SC-7, SI-3, SI-4 cited across N.N1/N.N3/N.N4. Rev 6 in long-tail would require benchmark + catalog regeneration. URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- **NIST SP 800-115 (2008)** — Technical Guide to Information Security Testing. Stable; cited by N.N2 + N.N3. Very unlikely to change.
- **NIST SP 800-218 v1.1 (SSDF)** — PW.1.1 cited by N.N1 + N.N2. Stable.
- **NIST SP 800-37 Rev 2 (2018)** — RMF; cited by N.N1 for Task C-3 threat identification. Stable.

### Upstream library / catalog updates
- **MITRE ATT&CK Enterprise + Cloud Matrices** — ships ~6 months. Pinned subset committed at `docs/sources/mitre-attack-cloud.subset.json`; refresh script + CHANGELOG cadence. URL: https://attack.mitre.org/
- **MITRE CTI STIX 2.1 Repository** — https://github.com/mitre/cti — pinned by release tag.
- **Center for Threat-Informed Defense ATT&CK→NIST 800-53 Rev 5 Mappings** — https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings — pinned by commit + tag.
- **Center for Threat-Informed Defense `attack_to_cve` Repository** — https://github.com/center-for-threat-informed-defense/attack_to_cve — pinned by commit; incomplete by nature.
- **CISA KEV JSON feed** — https://www.cisa.gov/known-exploited-vulnerabilities — schema field additions handled permissively by existing `core/kev-feed.ts`.
- **CWE Top 25** — https://cwe.mitre.org/top25/ — used by N.N1 STRIDE catalog for CWE citations. Annual release; CWE IDs are stable.
- **ajv (^8.x)** — OSCAL validation. Strict-mode behaviour changes are rare but possible; lock major version. Cross-ref `B-X` upstream library risk.
- **OSCAL JSON Schema v1.1.2** — committed at `cloud-evidence/docs/oscal/oscal_*_schema.v1.1.2.json`. New minor versions in flight (v1.2.x); migration is a cross-loop refactor; pin v1.1.2 within LOOP-N.
- **docx library used by SSP-2 + N.N1 docx renderer** — pin major version.
- **better-sqlite3** — tracker DB; stable SQL dialect.
- **noble-ed25519 / @noble/ed25519 (^2.x)** — signing. Stable API.
- **rfc8785 canonical JSON library** — required for byte-exact canonicalization; pin one library across cloud-evidence + tracker.

### Cloud provider / infrastructure
- **AWS / GCP / Azure resource-tag schemas** — `fedramp_component_class`, `fedramp_data_classification`, `fedramp_asset_tier`, `fedramp_admin_interface`, `auth_boundary` are operator-defined custom tags. No upstream change risk; tag name conventions documented in operator runbook.
- **AWS Security Group / GCP firewall / Azure NSG rule shapes** — stable; consumed via existing `providers/{aws,gcp,azure}/network.ts` evidence files. New rule attributes (e.g. AWS prefix-list IDs) handled by permissive parser.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the appropriate per-slice section with a fresh ID (e.g. `N.N3-11`); commit alongside the slice's implementation log update.
2. Risks resolved during implementation: move the row to the "Resolved risks" table at the bottom with date + resolution note + responsible session/commit. Do NOT delete the original entry — historical record matters.
3. Severity bump (low → med → high): add a `note` line under the original entry describing why; do not edit history.
4. Cross-cutting risks that affect multiple slices: keep in the cross-cutting section; reference from per-slice tables via "(cross-ref N-X<n>)".

---

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-N-SPEC.md` §7 (Open questions) — overlaps with this register.
3. Read the specific per-slice doc at `docs/slices/N/N.N<n>.md` for the slice you're implementing — risks here are the LIVE working set; risks in the per-slice docs are the spec snapshot.
4. Before shipping a slice, update this file's per-slice section + move any resolved risks to the resolved table atomically with the slice's commit (per SLICE-COMPLETION-PROCEDURE.md).
