# LOOP-Q — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with `status=resolved` + resolution note. Severity: high = ship-blocking; med = should fix in-loop; low = file as follow-up.

> Authoritative companion to `docs/loops/LOOP-Q-SPEC.md` and the per-slice docs at `docs/slices/Q/Q.Q[1-3].md`. Read those for context before acting on any risk here.

> Last updated: 2026-06-07.

---

## Cross-cutting risks (apply to ALL slices in LOOP-Q)

### Q-X1 — FedRAMP CR26 Marketplace JSON Schema not yet published
- **Description**: NTC-0005 commits FedRAMP to publishing the Consolidated Rules for 2026 (CR26), including the Marketplace JSON Schema, "by the end of June, 2026". As of 2026-06-07 the schema is not published. Q.Q1 ships against a forward-compatible FedPy-local `marketplace-listing.v1` schema; when CR26 publishes, the implementer migrates to `marketplace-listing.cr26.v1`. If CR26 introduces required fields FedPy did NOT anticipate, Q.Q1 needs a follow-up slice to capture them.
- **Severity**: high (Q.Q1 forward-compat risk).
- **Mitigation**: `package_format_version: "20x.phase-two.preview.2026"` field on every listing surfaces lineage; CHANGELOG migration note documents every field rename when CR26 publishes; LOOP-Q-SPEC.md §7 Q1 documents the migration plan.
- **Status**: open.

### Q-X2 — Trust Center direct-ingest API undefined
- **Description**: NTC-0005 mentions the JSON Schema "along with information about validation" but does not yet specify an authentication model for direct Marketplace ingest (OAuth? mTLS? signed-payload-upload?). Q.Q1 emits the listing as a signed artifact the operator uploads manually until the PMO publishes the ingest API; Q.Q2 emits to local mirror only. Cross-ref `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.12.
- **Severity**: med (operational friction; manual upload step).
- **Mitigation**: operator runbook documents the manual upload path; LOOP-G.G3 ADS provides Trust Center serving as an alternative; CHANGELOG documents the pending dependency.
- **Status**: open.

### Q-X3 — Sponsoring-agency identity unknown at first run
- **Description**: 20x eliminated the JAB; replacement is single-agency sponsorship + PMO P-ATO. Per LOOP-Q-SPEC.md §7 Q3 + `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.4, the operator must declare the sponsoring agency before the first Q.Q1 run. If unknown, `marketplace_status` cannot be `authorized` and Q.Q1 must force `in_process` + emit REQUIRES-OPERATOR-INPUT.
- **Severity**: high (conditional loop applicability; Q.Q1 + Q.Q3 both gated).
- **Mitigation**: Q.Q3 tracker UI captures sponsoring agency at first run with prominent prompt; `--strict-marketplace` orchestrator mode blocks Q.Q1 `authorized` emission until set; LOOP-Q-SPEC.md §7 documents the conditional-applicability semantics.
- **Status**: open.

### Q-X4 — Cross-repo Ed25519 signing-key drift (tracker ↔ cloud-evidence)
- **Description**: Q.Q3 signs agency-authorization records in the tracker using a tracker-resident Ed25519 key; cloud-evidence side has its own key for OSCAL output signing. The cloud-evidence reader (`agency-authorization-reader.ts`) must verify tracker signatures using the tracker's PUBLISHED public-key registry. Without a registry endpoint, key rotation breaks verification of records written under the old key. Cross-ref LOOP-B-RISKS.md#B-X3 (LOOP-B has the same pattern).
- **Severity**: med (impacts Q.Q3 → Q.Q1 → Q.Q2 chain).
- **Mitigation**: tracker exposes `GET /api/sign/public-keys` returning ALL historical public keys keyed by `key_id`; reader cross-references each record's `signing_key_id` against the registry; key rotation events written to `audit_log`; runbook documents the rotation procedure.
- **Status**: open.

### Q-X5 — FedRAMP CMP PDF gated by 403 on anonymous fetch
- **Description**: The FedRAMP Continuous Monitoring Strategy & Guide (Rev 5) PDF — Q.Q2's authoritative source for monthly artifact list + cadence — returns HTTP 403 to anonymous HTTPS fetches. Must be downloaded manually by an operator into `cloud-evidence/docs/sources/fedramp-conmon-strategy-guide.pdf` before Q.Q2 can pin verbatim quotes in module docstrings. Cross-ref LOOP-B-RISKS.md#B-X1.
- **Severity**: high (Q.Q2 documentation completeness).
- **Mitigation**: Q.Q2 carries a `REQUIRES-OPERATOR-INPUT: confirm-against-fedramp-cmp-pdf` marker on its constants until the PDF is downloaded; `--strict-marketplace` fails the build if marker remains; CHANGELOG entry quotes the artifact list verbatim with PDF page + section atomically when downloaded.
- **Status**: open.

### Q-X6 — Tracker schema migration on existing installs
- **Description**: Q.Q3 adds 4 new tables (`agency_authorizations`, `agency_reuse_events`, `marketplace_listing_history`, `conmon_publication_log`). Existing tracker installs have user data — migrations must be additive only. The repo uses idempotent `CREATE TABLE IF NOT EXISTS`; any non-additive change is breaking. Cross-ref LOOP-B-RISKS.md#B-X10.
- **Severity**: high.
- **Mitigation**: all four CREATE TABLEs are additive; CHANGELOG documents the upgrade path; smoke test on a copy of a production DB; no DROP / ALTER COLUMN; H.H3 multi-tenant work batches all cross-loop migrations.
- **Status**: open.

### Q-X7 — Multi-CSO tenant isolation deferred to H.H3
- **Description**: All four LOOP-Q tracker tables omit a `tenant_id` column. When multi-CSO ships (H.H3), all four need migration in a single cross-loop sweep. If LOOP-Q users start storing multi-tenant data via app-level filtering, the H.H3 migration becomes destructive. Cross-ref LOOP-B-RISKS.md#B-X15.
- **Severity**: med (long-tail).
- **Mitigation**: documented in LOOP-Q-SPEC.md §7 Q5; H.H3 spec must enumerate every LOOP-Q table; LOOP-Q ships in single-tenant deployments only (documented in runbook).
- **Status**: open.

### Q-X8 — `process.env.NODE_ENV === 'test'` branch creep
- **Description**: REO Rule 1.8 prohibits this branch in production code. New cross-cutting infrastructure (signing, HTTP fetch from tracker, snapshot writes, tar bundling) is exactly where developers reach for `if (NODE_ENV === 'test')` shortcuts. Cross-ref LOOP-B-RISKS.md#B-X6.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal; tests inject seams via dependency-injected HTTP fetcher + filesystem helper; CI gate is non-bypassable.
- **Status**: open.

### Q-X9 — Provenance schema drift
- **Description**: Every new emit artifact (`marketplace-listing.json`, `marketplace-listing.md`, `conmon-publication-<period>.manifest.json`, `agency-authorizations.json`) must carry a `provenance` block per REO Rule 2.6. `scripts/check-provenance.mjs` enforces the schema (emitter, emittedAt, sourceCalls, signingKeyId). A missed block fails the slice. Cross-ref LOOP-B-RISKS.md#B-X9.
- **Severity**: high.
- **Mitigation**: per-slice test verifies provenance via `check:provenance`; pattern reused from `core/inventory-coverage.ts`; CHANGELOG entry per slice cites the provenance block contents.
- **Status**: open.

### Q-X10 — Submission-bundle role count growth
- **Description**: LOOP-Q adds 5 new roles to `submission-bundle.ts:WELL_KNOWN` (marketplace-listing-json, marketplace-listing-md, conmon-publication-tarball, conmon-publication-manifest, agency-authorizations-json). Each role must have a stable canonical filename + description; collisions would corrupt the bundle. Cross-ref LOOP-B-RISKS.md#B-X8.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the role table; per-slice tests assert presence; CHANGELOG entry for the last slice lists final role inventory at loop close.
- **Status**: open.

### Q-X11 — Conditional loop applicability (CSO not yet ATO'd)
- **Description**: LOOP-Q is conditional on the CSO being on the post-ATO path (or actively pursuing one). CSPs in "Pre-Pursuit" or "FedRAMP Ready (not yet In Process)" states should NOT run Q.Q2 (monthly ConMon publication) — there's no obligation yet. Q.Q1 may run with `marketplace_status: in_process` or `fedramp_ready`. Q.Q3 may run always (sponsoring-agency tracking starts at the In-Process Request).
- **Severity**: med (operational confusion).
- **Mitigation**: orchestrator's `--marketplace-status <enum>` flag (or Q.Q3-derived default) controls which slices run; LOOP-Q-SPEC.md §7 Q9 documents the conditional logic; operator runbook surfaces the dependency.
- **Status**: open.

### Q-X12 — RFC 3161 TSA cascade availability
- **Description**: Q.Q2 monthly publication is timestamped via the multi-TSA cascade (DigiCert → GlobalSign → Sectigo → FreeTSA per `docs/ADDITIONAL-LOOPS-AUDIT.md` §3.12 recommendation). If all four TSAs are unreachable on monthly-publish day, Q.Q2 emit emits a `gaps[]` entry but cannot be ship-fully-timestamped. Subsequent re-emission on next attempt would invalidate the prior period's chain anchor.
- **Severity**: low.
- **Mitigation**: cascade reduces single-point failure; on full-cascade failure, emit `gaps[]` entry + delay publish 24h with operator notification; LOOP-H.H2 long-term retention guarantees prior manifests survive.
- **Status**: open.

### Q-X13 — Trust Center URL drift between Q.Q1 (config.yaml) and Q.Q3 (tracker)
- **Description**: Q.Q1 reads `config.yaml marketplace.trust_center.url`; Q.Q3 captures `trust_center_url` per agency (each leveraging agency may have its OWN Trust Center). The CSP's primary Trust Center URL is in config; each agency's Trust Center URL is in the tracker. Confusing the two leads to wrong destinations in Q.Q2.
- **Severity**: med.
- **Mitigation**: schema field names distinguish them: `trust_center.url` in `MarketplaceListing` is the CSP's; `trust_center_url` in `AgencyAuthorization` is the agency's. CHANGELOG entry clarifies; operator runbook diagrams the two-level Trust Center model.
- **Status**: open.

### Q-X14 — Prior-period chain break in Q.Q2
- **Description**: Q.Q2's `prior_period_reference` builds an integrity chain a Marketplace consumer can verify back to the original ATO bundle. If a previously published manifest is lost (operator deleted `out/`, archive corruption, accidental rm), the chain anchor is broken — consumer cannot verify across the gap.
- **Severity**: med.
- **Mitigation**: LOOP-H.H2 long-term retention archives every monthly manifest to cold storage at publish-time; CHANGELOG documents archive recovery procedure; runbook step "before deleting out/, run npm run archive:conmon".
- **Status**: open.

### Q-X15 — POA&M XML / JSON parity for Marketplace ingest
- **Description**: Q.Q1 reads POA&M from `poam.json` (JSON projection); the XML projection (`poam.xml`) is ignored. When/if the FedRAMP PMO Marketplace ingest requires XML instead of JSON, Q.Q1 needs to emit XML via `core/oscal-xml.ts` reuse.
- **Severity**: low.
- **Mitigation**: documented in LOOP-Q-SPEC.md §7 Q8; verify with PMO before first ship; future follow-up slice if XML required.
- **Status**: open.

### Q-X16 — Subprocessor / leveraged-IaaS attribution overlap with LOOP-L.L2
- **Description**: RFC-0021 + LOOP-L.L2 (CRM + Inheritance) overlap with Q.Q1's `services_in_scope` when the CSO inherits from a leveraged IaaS (e.g. AWS GovCloud). Q.Q1 does NOT enumerate the leveraged underlying services; that's L.L2's scope. Q.Q1's `services_in_scope` is the CSP's *own* service inventory. If L.L2 ships first and operator expects L.L2 → Q.Q1 wiring, there's no auto-population yet.
- **Severity**: low.
- **Mitigation**: documented in LOOP-Q-SPEC.md §7 Q10; CHANGELOG entry for Q.Q1 clarifies scope boundary; follow-up slice if L.L2 → Q.Q1 wiring needed.
- **Status**: open.

### Q-X17 — Test count expectations / CI thresholds
- **Description**: LOOP-Q adds ≥56 new tests across cloud-evidence + tracker (Q.Q1: ≥24; Q.Q2: ≥20; Q.Q3: ≥22 + ≥12 reader/emitter). Existing CI may have hard-coded "expected test count" assertions or coverage thresholds that need bumping. Cross-ref LOOP-B-RISKS.md#B-X13.
- **Severity**: low.
- **Mitigation**: per slice, the implementing session updates any test-count assertion; CHANGELOG entries cite the new totals; STATUS.md "Overall → tests" line bumped atomically with each slice ship.
- **Status**: open.

---

## Per-slice risks

### Q.Q1 — FedRAMP Marketplace listing emitter (per RFC-0021 format)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Q.Q1-1 | high | CR26 schema not yet published (cross-ref Q-X1) | `marketplace-listing.v1` forward-compat; migration path documented | open |
| Q.Q1-2 | med | Sponsoring-agency identity may be unknown (cross-ref Q-X3) | Force `marketplace_status=in_process`; REQUIRES-OPERATOR-INPUT marker | open |
| Q.Q1-3 | med | 3PAO identity drift between RoE signature block and `config.yaml` | `config.yaml` wins; precedence pinned by test; CHANGELOG documents | open |
| Q.Q1-4 | med | Trust Center URL overlap with LOOP-G.G3 ADS slice | Both read from `config.yaml marketplace.trust_center.*`; single source of truth | open |
| Q.Q1-5 | low | Markdown renderer formatting drift across engines (GitHub vs PMO Trust Center) | Pin to CommonMark + GFM tables; CommonMark validator in tests | open |
| Q.Q1-6 | med | HIGH impact level emission semantics conflict with existing HIGH-CLARIFY warning | Q.Q1 marker matches existing HIGH-CLARIFY language; CHANGELOG cross-reference | open |
| Q.Q1-7 | low | `customer_responsibility_summary` overlap with LOOP-L.L1 CRM workbook (when ratified) | Q.Q1 reads `config.yaml` directly; switch to L.L1 source when L.L1 ships | open |
| Q.Q1-8 | low | `business_category` controlled vocabulary not authoritatively published by FedRAMP | Q.Q1 ships with `docs/marketplace-business-categories.json` operator-tunable list; CR26 may publish a canonical list | open |

### Q.Q2 — Post-ATO ConMon publication (monthly delivery)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Q.Q2-1 | high | FedRAMP CMP PDF returns 403 (cross-ref Q-X5) | REQUIRES-OPERATOR-INPUT marker; `--strict-marketplace` blocks ship | open |
| Q.Q2-2 | med | LOOP-E.E1 + LOOP-E.E2 not yet shipped (analysis report + POA&M delta missing) | Graceful `gaps[]` entries; non-strict mode allows ship; CHANGELOG documents dependency | open |
| Q.Q2-3 | med | Scan-file naming conventions differ across CSPs | Operator-tunable glob patterns via `config.yaml conmon.scan_patterns[]`; unrecognized files bundled with `role: 'unrecognized'` | open |
| Q.Q2-4 | high | FedRAMP secure repository (Connect.gov) ingest API not yet documented | Manual upload step documented; LOOP-G.G3 ADS provides Trust Center serving alternative | open |
| Q.Q2-5 | low | Tar reproducibility drift across Node versions / filesystems | LOOP-A.A4 pinned `mtime` + sort-by-path discipline reused unchanged; per-OS test in CI matrix | open |
| Q.Q2-6 | low | RFC 3161 TSA cascade outage (cross-ref Q-X12) | Multi-TSA cascade; on failure emit `gaps[]` + delay 24h | open |
| Q.Q2-7 | med | Idempotency could mask a genuine re-emit need (operator edited meeting-notes after publish) | `--force` flag overrides; revision counter in manifest | open |
| Q.Q2-8 | low | Trust Center mirror file proliferation (12 agencies × 12 months = 144 dirs/year) | LOOP-H.H2 rotated archive after 90 days; mirror cleanup script ships with Q.Q2 | open |
| Q.Q2-9 | med | Prior-period chain break (cross-ref Q-X14) | LOOP-H.H2 archives every monthly manifest; runbook documents recovery | open |
| Q.Q2-10 | low | Meeting-notes format ambiguity (`.md` vs `.docx`) | Accept both extensions; record actual filename in `artifacts[]` | open |
| Q.Q2-11 | low | Per-agency notification beyond URL+email (e.g. SIEM webhook) | Deferred to LOOP-G.G3 ADS; Q.Q2 mirrors URL + email only | open |

### Q.Q3 — Agency authorization tracking

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| Q.Q3-1 | med | Cross-repo signing-key drift (cross-ref Q-X4) | `/api/sign/public-keys` registry; reader cross-references | open |
| Q.Q3-2 | high | Tracker schema migration on existing DBs (cross-ref Q-X6) | Additive only; smoke test on production DB copy | open |
| Q.Q3-3 | med | AO revoke replay | Server-set `revoked_at` + uuid; status transition rejects replay; audit-log records every attempt | open |
| Q.Q3-4 | med | Sponsoring-agency invariant ergonomics (operator hits 409 unexpectedly) | UI "Mark as sponsoring" toggle prompts confirmation that demotes prior sponsoring row atomically | open |
| Q.Q3-5 | low | ATO letter PDFs could exceed 10 MB H.4 attachment cap | UI displays size estimate before upload; doc warns about size | open |
| Q.Q3-6 | low | Agency reuse events grow unbounded | Pagination (50/page); LOOP-H.H2 archives > 12 months old | open |
| Q.Q3-7 | med | Multi-CSO tenant isolation deferred (cross-ref Q-X7) | Documented; single-tenant only until H.H3 | open |
| Q.Q3-8 | med | RBAC mis-configuration (cross-ref LOOP-B-RISKS.md#B-X5) | Per-route `requireRole` unit-tested; `audit_log` records each role-checked action; first-boot prompt | open |
| Q.Q3-9 | med | LOOP-B.B3 must establish signing-key registry pattern BEFORE Q.Q3 ships | Frontmatter dependency declared; fallback "trust-on-first-use" if shipping Q.Q3 first | open |
| Q.Q3-10 | low | When sponsoring agency revokes, who becomes new sponsoring? | Route enforces "no zero-sponsoring state" — revoke requires `new_sponsoring_uuid` OR rejects 409 | open |
| Q.Q3-11 | low | `agencies_requested_access[]` auto-aging window ambiguous | Show events within 12-month report-cycle window per RFC-0021 wording | open |
| Q.Q3-12 | low | ATO auto-expiration could surprise operator | Daily cron job flips status to `expired`; operator can manually override; email notification | open |

---

## External dependencies that may change

### FedRAMP guidance updates that could affect LOOP-Q
- **FedRAMP CR26 Marketplace JSON Schema** — committed publication end of June 2026 per NTC-0005. When published, Q.Q1 schema migrates to `marketplace-listing.cr26.v1`; CHANGELOG entry documents diff. URL: https://www.fedramp.gov/notices/0005/
- **RFC-0021 final outcome** — additional MKT-* requirement clarifications may follow; revisions could reshape Q.Q1 field set. URL: https://www.fedramp.gov/rfcs/0021/
- **FedRAMP Continuous Monitoring Strategy & Guide (Rev 5 → potential Rev 6)** — Q.Q2 reads the monthly artifact list verbatim from CMP. Rev 6 publication would require re-extracting the list into module docstrings + updating `role` enum. URL: https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf
- **RFC-0026 final outcome** — CA-7 clarification may evolve; affects Q.Q2 cadence + artifact list. URL: https://www.fedramp.gov/rfcs/0026/
- **FedRAMP 20x Authorization Data Sharing standard (RFC-0011 finalized)** — direct ingest authentication model still pending; Q.Q2 mirror payload format may need to align with PMO ingest API once published. URL: https://www.fedramp.gov/docs/20x/authorization-data-sharing/
- **FedRAMP Agency Authorization Playbook (next revision)** — defines statuses Q.Q1 emits (`fedramp_ready`, `in_process`, `authorized`); revision could add states. URL: https://www.fedramp.gov/resources/documents/Agency_Authorization_Playbook.pdf

### NIST publication versions
- **NIST SP 800-53 Rev 5 (Sep 2020, errata Dec 2023) — CA-7** — current source for Continuous Monitoring control statement Q.Q2 satisfies. Rev 6 would require catalog regeneration + Q.Q2 module docstring update. URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- **NIST SP 800-37 Rev 2 (2018) — RMF Step 6 + 7** — referenced for AO sign-off semantics (Q.Q3 ATO event fields) + ConMon program definition (Q.Q2). Stable. URL: https://csrc.nist.gov/pubs/sp/800/37/r2/final
- **NIST SP 800-137 (2011) — ISCM** — Q.Q2 monthly publication is ISCM step 5 + 6 instrumentation. Stable; very unlikely to change in LOOP-Q horizon. URL: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-137.pdf
- **FIPS 199** — Q.Q1 impact-level derivation uses high-water-mark rule. Stable. URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf
- **OSCAL JSON Schema v1.1.2** — Q.Q1 reads SSP / AP / AR / POA&M from JSON projection; Q.Q2 references AR for prior-period anchor. Migration to v1.2 is a separate cross-loop refactor; pin v1.1.2 within LOOP-Q. URL: https://pages.nist.gov/OSCAL/

### Upstream library updates
- **ajv (^8.x)** — used by `core/oscal-validate.ts` for `marketplace-listing.v1.json` + `conmon-publication.v1.json` + `agency-authorizations.v1.json` validation. Schema validation behaviour changes are rare; lock major version. https://ajv.js.org
- **better-sqlite3 (~9.x or ~11.x)** — used by tracker. Q.Q3 SQL is standard CREATE TABLE + partial unique index; compatible across versions.
- **rfc8785 (canonical JSON) library** — Q.Q3 signing canonicalizes payload before Ed25519 sign. Multiple JS implementations exist (e.g. `canonicalize`, `json-canonicalize`); signature compatibility depends on byte-exact canonicalization. Pin one library across both cloud-evidence + tracker (per LOOP-B precedent).
- **noble-ed25519 (^2.x) or @noble/ed25519** — Ed25519 signing for Q.Q3 records. Stable API.
- **Pure-JS POSIX tar writer** (from LOOP-A.A4) — Q.Q2 reuses unchanged.
- **RFC 3161 TSA cascade** — multi-TSA (DigiCert / GlobalSign / Sectigo / FreeTSA). Each TSA could change root cert / URL independently; `core/timestamp.ts` cascade tolerates one-TSA failures. Audit cascade health quarterly.
- **React (^18.x)** — tracker UI. v19 ships routinely; pin major version within LOOP-Q.

### External services (network dependencies at run-time)
- **FedRAMP Marketplace registry (https://marketplace.fedramp.gov/)** — Q.Q1 emits the artifact the registry will ingest; no direct API dependency at emit-time. Manual upload by operator.
- **FedRAMP secure repository (Connect.gov)** — Q.Q2 mirror payload, not direct push. No API dependency at emit-time.
- **TSA endpoints (DigiCert / GlobalSign / Sectigo / FreeTSA)** — Q.Q2 timestamp via `core/timestamp.ts` cascade. Cross-ref Q-X12.
- **Tracker `/api/sign/public-keys` registry** — cloud-evidence Q.Q3 reader cross-references each record's `signing_key_id`. Cross-ref Q-X4.

### Cloud provider / infrastructure
- **AWS / GCP / Azure service-name catalogues** — Q.Q1 `services_in_scope` derives from real `inventory.json`; display-name lookup table operator-tunable. No upstream change risk.
- **No new cloud collectors added** — LOOP-Q is a CONSUMER of existing collector outputs. No SDK version pins beyond what LOOP-A through LOOP-K already requires.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the appropriate per-slice section with a fresh ID (e.g. `Q.Q1-9`); commit alongside the slice's implementation log update.
2. Risks resolved during implementation: move the row to the "Resolved risks" table at the bottom with date + resolution note + responsible session/commit. Do NOT delete the original entry — historical record matters.
3. Severity bump (low → med → high): add a `note` line under the original entry describing why; do not edit history.
4. Cross-cutting risks that affect multiple slices: keep in the cross-cutting section; reference from per-slice tables via "(cross-ref Q-X<n>)".
5. Cross-loop risks (e.g. shared signing-key registry with LOOP-B): cross-reference `LOOP-B-RISKS.md#B-X<n>` so a future session reading either register finds the other.

---

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-Q-SPEC.md` Section 7 (open questions) — overlaps with this register.
3. Read the specific per-slice doc at `docs/slices/Q/Q.Q<n>.md` for the slice you're implementing — risks here are the LIVE working set; risks in the per-slice docs are the spec snapshot.
4. Cross-reference `docs/loops/LOOP-B-RISKS.md` for shared cross-cutting patterns (signing-key registry, additive-only migrations, NODE_ENV branch creep) — LOOP-Q reuses LOOP-B precedent extensively.
5. Before shipping a slice, update this file's per-slice section + move any resolved risks to the resolved table atomically with the slice's commit (per SLICE-COMPLETION-PROCEDURE.md).
