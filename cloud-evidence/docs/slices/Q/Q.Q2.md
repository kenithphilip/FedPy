---
slice_id: Q.Q2
title: Post-ATO ConMon publication (monthly delivery to FedRAMP secure repository)
loop: Q
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A3, LOOP-A.A4, Q.Q1, Q.Q3, LOOP-E.E1, LOOP-E.E2]
blocks: [LOOP-H.H2, LOOP-G.G3]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
applicable_conditional: true
---

# Q.Q2 — Post-ATO ConMon publication (monthly delivery to FedRAMP secure repository)

## TL;DR
Bundle the monthly ConMon delivery (POA&M update + vulnerability scans + KSI envelopes + analysis report + meeting notes) into a signed `out/conmon-publication-<YYYY-MM>.tar.gz` + RFC 3161-timestamped `out/conmon-publication-<YYYY-MM>.manifest.json`. Reuses LOOP-A.A4's pure-JS POSIX tar writer + INDEX.json pattern + `core/sign.ts` + `core/timestamp.ts`. Writes a trust-center mirror per leveraging agency (Q.Q3 destination list) and a `conmon_publication_log` row in the tracker. Idempotent re-runs are a no-op. Without this slice, the CSP has no canonical artifact to ship to the FedRAMP secure repo every month per RFC-0026.

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
Q.Q2 is a CONSUMER of every existing FedPy output. It does NOT add a single cloud collector; it bundles + signs + ships. Reads monthly KSI envelopes (`out/KSI-*.json`) from the existing AWS/GCP/Azure collectors; reads LOOP-A.A1 OSCAL POA&M (`out/poam.json`); reads LOOP-A.A3 AR (`out/assessment-results.json`) for prior-period baseline; reads LOOP-E.E1 monthly analysis report (when shipped) + LOOP-E.E2 POA&M delta (when shipped) — gracefully degrades to `gaps[]` markers when LOOP-E slices not present. Reuses Q.Q1 marketplace listing as "current authorization status" header in the manifest; reuses Q.Q3 agency_authorizations as destination list. Every byte ships under the REO standard; every artifact's sha256 + bytes recorded; missing artifacts become `gaps[]` entries, never silently dropped.

## Why this slice exists
RFC-0026 (CA-7 clarification, 2026) and the FedRAMP Continuous Monitoring Strategy & Guide (Rev 5) obligate every Authorized CSP to deliver monthly ConMon artifacts to (a) the FedRAMP secure repository (Connect.gov for Low/Moderate) and (b) every leveraging agency's POC + Trust Center. The artifact set is: POA&M update, OS scans, DB scans, Web App scans, Container scans, Service Config scans, analysis report, meeting recording or notes. LOOP-A.A4 produced the *one-shot* submission package. LOOP-E produces the per-period analysis. Today nothing bundles, signs, manifests, and ships them as the canonical monthly delivery — every CSP would have to assemble + sign + ship by hand each month, defeating the FedPy automation thesis. Q.Q2 closes the gap: one CLI flag emits the bundle + manifest + mirror + tracker row; subsequent months reference prior periods to build an integrity chain a Marketplace consumer can verify back to the original ATO bundle.

## Authoritative sources (with verbatim quotes)

- **RFC-0026 "Clarifying CA-7 (Continuous Monitoring)"** — https://www.fedramp.gov/rfcs/0026/
  - Monthly meeting + sharing:
    > "host a traditional monthly ConMon meeting open to all agency customers and FedRAMP during any given month"
    > "Sharing Operating System, Database, Web Application, Container, and Service Configuration Scans, at least monthly; AND sharing updated Plans of Action and Milestones (POA&Ms), at least monthly"
    > "recurring monitoring information (including meetings) to all agency customers and FedRAMP"
  - Q.Q2's role enum mirrors this artifact list verbatim.

- **FedRAMP Continuous Monitoring Strategy & Guide (Rev 5)** — https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf
  - HTTP 403 anonymous (cross-ref `docs/loops/LOOP-B-RISKS.md#B-X1`); operator downloads + stores at `cloud-evidence/docs/sources/fedramp-conmon-strategy-guide.pdf`.
  - Pre-existing R2 quote (`docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`):
    > "Monthly CSP-submitted artifacts include the updated POA&M, monthly vulnerability scan files (OS / DB / Web App / Container / Service Config), and supporting documentation; deliveries occur via the FedRAMP secure repository (Connect.gov for Low/Moderate)."

- **NIST SP 800-53 Rev 5 — CA-7 (Continuous Monitoring)** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - > "Develop a system-level continuous monitoring strategy and implement continuous monitoring in accordance with the organization-level continuous monitoring strategy"
  - > "Establish the following metrics to be monitored: [Assignment: organization-defined metrics]"
  - Q.Q2 satisfies CA-7e ("Reporting the security and privacy status of the system to [Assignment: organization-defined personnel or roles] [Assignment: organization-defined frequency]") at monthly cadence by bundling + signing + shipping.

- **NIST SP 800-37 Rev 2 — Risk Management Framework, Step 7 (Monitor)** — https://csrc.nist.gov/pubs/sp/800/37/r2/final
  - > "The continuous monitoring program is implemented and provides ongoing awareness of threats, vulnerabilities, and information security to support organizational risk management decisions."

- **NIST SP 800-137 — ISCM** — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-137.pdf
  - Defines six-step ISCM process; Q.Q2's publication artifact is the operational instrumentation for step 5 ("Respond") + step 6 ("Review and Update").

- **FedRAMP 20x Authorization Data Sharing standard** — https://www.fedramp.gov/docs/20x/authorization-data-sharing/
  - Trust Center serving requirement:
    > "Trust centers SHOULD make authorization data available to view and download in both human-readable and machine-readable formats"
    > "Providers SHOULD share the authorization package with agencies upon request"
  - Q.Q2 writes `out/trust-center-mirror/<agency_uei>/<period>/manifest.json` for the G.G3 Trust Center to serve.

- **OSCAL Plan of Action and Milestones v1.1.2** — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
  - Q.Q2 includes the existing `out/poam.json` in the bundle; no schema changes.

- **OSCAL Assessment Results v1.1.2** — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/
  - Q.Q2 references prior-period AR for the integrity chain anchor.

- **RFC 3161 — Time-Stamp Protocol** — https://datatracker.ietf.org/doc/html/rfc3161
  - Existing `core/timestamp.ts` (DigiCert/GlobalSign/Sectigo/FreeTSA cascade) reused.

## Files to create (exact paths under cloud-evidence/)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/conmon-publication.ts` — bundler + manifest emitter. Reuses `core/submission-bundle.ts` POSIX tar writer (`tarWriter()` helper from LOOP-A.A4).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/conmon-publication-manifest.ts` — manifest schema + builder. Pure function: `buildConmonPublicationManifest(inputs): ConmonPublicationManifest`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/schemas/conmon-publication.v1.json` — manifest JSON Schema (ajv).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/conmon-publication.test.ts` — ≥14 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/conmon-publication-manifest.test.ts` — ≥4 tests for the pure manifest builder.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/conmon-publication/` — fixture per-period artifacts (KSI envelopes, poam.json, sample scan JSONs, meeting notes, prior manifest).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/conmon-publications.ts` — log endpoint: `POST /api/conmon-publications`, `GET /api/conmon-publications`, `GET /api/conmon-publications/:period`, `POST /api/conmon-publications/:period/acknowledge`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/conmon-publications.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/ConmonPublicationLog.tsx` — table view.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/ConmonPublicationLog.test.tsx`.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add roles `conmon-publication-tarball` (filename `conmon-publication-<period>.tar.gz`) + `conmon-publication-manifest` (filename `conmon-publication-<period>.manifest.json`) to `WELL_KNOWN`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — `--conmon-publication` flag + env `CLOUD_EVIDENCE_CONMON_PUBLICATION`; `--conmon-period <YYYY-MM>` (default current month); `--conmon-prior <path>`; `--conmon-destination <comma-list>` (optional override for Trust Center notification).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CHANGELOG.md` — "Unreleased" entry.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` — slice row + Overall section.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-Q-SPEC.md` — Section 8 status row.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — table `conmon_publication_log` (additive).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount `conmon-publications.ts` route.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/rbac.ts` — `iso` gets `conmon:publish`; `ao` gets `conmon:acknowledge`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — route `/conmon-publication-log`.

## Schemas / standards
- **Locally-authored `conmon-publication.v1` manifest schema** at `cloud-evidence/docs/schemas/conmon-publication.v1.json`. Top-level fields:
  - `schema_version`: const `conmon-publication.v1`.
  - `package_format_version`: const `20x.phase-two.preview.2026`.
  - `period`: pattern `^\d{4}-\d{2}$` (YYYY-MM).
  - `cso_name`, `csp_uei`, `sponsoring_agency`: strings.
  - `emitted_at`: ISO datetime.
  - `artifacts[]`: array of `{filename, role, sha256, bytes, description}` — `role` enum mirrors RFC-0026 list verbatim: `poam-update | os-scan | db-scan | web-app-scan | container-scan | service-config-scan | conmon-analysis-report | ksi-envelope | meeting-notes | signed-manifest | rfc3161-timestamp | unrecognized`.
  - `prior_period_reference`: nullable object `{period, manifest_sha256}`.
  - `destinations[]`: array of `{agency_name, trust_center_url, notified_at, notification_method}` — `notification_method` enum: `trust-center-publish | email | api-call`.
  - `gaps[]`: array of `{role, description}` (missing artifact classes surfaced).
  - `provenance`: `{emitter, emitted_at, source_calls[], signing_key_id}`.
- **FedRAMP CMP** quoted verbatim in module docstring; `role` enum traces 1:1 to the CMP monthly artifact list.
- **RFC-0026** quoted verbatim in module docstring as the 2026 live source.

## Build steps (concrete, numbered)

1. Define `ConmonPublicationManifest` TypeScript type matching the schema.
2. Pure builder:
   ```ts
   export function buildConmonPublicationManifest(inputs: {
     period: string;
     outDir: string;
     cso_name: string;
     csp_uei: string;
     sponsoring_agency: string;
     priorPeriodPath?: string;
     destinations: AgencyAuthorization[];
     emittedAt?: string;
     discoveredArtifacts: Array<{filename: string; role: ConmonRole; sha256: string; bytes: number; description: string}>;
   }): ConmonPublicationManifest;
   ```
3. **File discovery + role classification**: walk `outDir` (and `outDir/summaries`) for files matching per-period globs:
   - `KSI-*.json` → role `ksi-envelope`
   - `poam.json` → role `poam-update`
   - `conmon-analysis-*.md` → role `conmon-analysis-report` (LOOP-E.E1 output)
   - `poam-delta-*.json` → role `poam-update` sub-class (LOOP-E.E2 output)
   - `*os-scan*.json` → role `os-scan`
   - `*db-scan*.json` → role `db-scan`
   - `*web-app-scan*.json` → role `web-app-scan`
   - `*container-scan*.json` → role `container-scan`
   - `*service-config-scan*.json` → role `service-config-scan`
   - `meeting-notes-<YYYY-MM>.md` → role `meeting-notes`
   - Files outside the role table bundled with `role: 'unrecognized'` (not silently dropped; LOOP-A.A4 precedent).
4. **Prior-period reference**: when `--conmon-prior <path>` given, read prior manifest; embed `period` + `manifest_sha256` in `prior_period_reference`. When prior period absent, set to `null` + emit a `gaps[]` warning (not blocking).
5. **Destination list**: read Q.Q3 `out/.agency-authorizations.json` snapshot; for each `status='active'` row emit `destinations[]` entry with `trust_center_url` from row. When Q.Q3 snapshot absent OR no agencies, single entry `[{agency_name: "FedRAMP PMO (sponsoring agency)", trust_center_url: <config.marketplace.trust_center.url>, notified_at: null, notification_method: "trust-center-publish"}]`.
6. **Bundle** artifacts into `out/conmon-publication-<YYYY-MM>.tar.gz` using LOOP-A.A4's POSIX ustar writer (reuse `tarWriter()` helper; same `mtime` reproducibility option for byte-stable headers). Emit top-level `INDEX.json` (= the manifest) inside tarball; also write same manifest to `out/conmon-publication-<YYYY-MM>.manifest.json` outside tarball.
7. **Sign + timestamp**: outer manifest signed by `core/sign.ts` (Ed25519 detached); timestamp via `core/timestamp.ts` (multi-TSA cascade per `docs/ADDITIONAL-LOOPS-AUDIT.md` §3.12 recommendation).
8. **Record in tracker**: `POST /api/conmon-publications` with `{period, manifest_sha256, tarball_sha256, tarball_bytes, artifact_count, destination_count, gap_count, rfc3161_timestamp_path}`. Tracker stores row in `conmon_publication_log`; writes `audit_log` entry.
9. **Trust Center mirror**: for each destination, write `out/trust-center-mirror/<agency_uei>/<period>/manifest.json` containing the signed manifest. Actual HTTP push to remote Trust Centers deferred to LOOP-G.G3; Q.Q2 only materializes the mirror payload.
10. **Idempotency**: re-running with same `--conmon-period` is safe — emitter computes sha256, compares with prior manifest at the same path, skips write if unchanged + records `no-op` in tracker via `acknowledged_by_agency_count` increment vs new row.
11. **`--strict-marketplace`** (cross-loop flag) also blocks Q.Q2 emit when meeting-notes file absent OR any required scan class missing OR `requires_operator_input[]` non-empty in the inner manifest.
12. **Submission-bundle integration**: register roles in `WELL_KNOWN`. The LOOP-A.A4 bundler can include the conmon publication as a separate role; useful when operator wants a single super-bundle (submission + first monthly delivery).
13. **Validation**: ajv-validate the manifest against `conmon-publication.v1.json` schema. Failure under `--strict-marketplace` exits non-zero.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| `cso_name`, `csp_uei`, `sponsoring_agency` | `config.yaml` `marketplace.*` (Q.Q1 reuses) | Marker emitted; `--strict-marketplace` blocks |
| `destinations[].trust_center_url` | Q.Q3 tracker `agency_authorizations.trust_center_url` | Marker emitted per missing agency; `notification_method: 'trust-center-publish'` falls back to `'email'` with operator-supplied `notification_email` |
| `priorPeriodPath` | CLI flag `--conmon-prior <path>` OR auto-detect from `out/conmon-publication-<prev-month>.manifest.json` | When absent + no prior month auto-detected, `prior_period_reference: null` + warning (not blocking; first month is the chain anchor) |
| Scan artifacts (OS / DB / Web App / Container / Service Config) | LOOP-E.E1 / E.E2 / existing VDR pipeline | Each missing class becomes a `gaps[]` entry with `role` + descriptive message; `--strict-marketplace` blocks |
| `meeting-notes-<YYYY-MM>.md` | Operator drops file into `outDir/meeting-notes-<YYYY-MM>.md` | When absent, `gaps[]` entry; `--strict-marketplace` blocks (RFC-0026 requires meeting) |
| Meeting cadence + topics | Operator-supplied via config | When absent, marker; not strict-blocking (meeting required but content authored by CSP) |
| `conmon-analysis-<YYYY-MM>.md` | LOOP-E.E1 (when shipped) | When absent (E.E1 pending), `gaps[]` entry with `role: 'conmon-analysis-report'`; not strict-blocking (graceful E.E1 dependency) |
| `poam-delta-<YYYY-MM>.json` | LOOP-E.E2 (when shipped) | When absent (E.E2 pending), `gaps[]` entry; not strict-blocking |

## Test specifications (≥12 tests)

1. `it('discovers and classifies every per-period artifact under WELL_KNOWN role table')`.
2. `it('emits manifest.json with all required fields and provenance block')`.
3. `it('signs the manifest via core/sign.ts (Ed25519) and timestamps via core/timestamp.ts (RFC 3161)')`.
4. `it('embeds prior_period_reference when prior manifest exists in outDir or via --conmon-prior')`.
5. `it('emits prior_period_reference: null + warning when no prior period')`.
6. `it('reads destinations[] from Q.Q3 agency_authorizations snapshot (status=active only)')`.
7. `it('falls back to single sponsoring-agency entry when Q.Q3 snapshot absent')`.
8. `it('emits gaps[] entry for each missing scan class (OS / DB / Web App / Container / Service Config)')`.
9. `it('--strict-marketplace blocks emit when meeting-notes file absent')`.
10. `it('--strict-marketplace blocks emit when any required scan class missing')`.
11. `it('idempotent: re-running with same period + identical inputs skips write + records no-op in tracker')`.
12. `it('reproducibility: BundleEmitOptions.mtime produces byte-stable tar header (sha256 identical across two runs)')`.
13. `it('tracker route POST /api/conmon-publications records a row with audit-log entry')`.
14. `it('tracker route GET /api/conmon-publications/:period returns the manifest sha256 + timestamps')`.
15. `it('--conmon-publication flag wires into orchestrator AFTER POA&M emit and AFTER agency-auth-export')`.
16. `it('submission-bundle WELL_KNOWN includes both conmon-publication-tarball + conmon-publication-manifest roles')`.
17. `it('trust-center mirror layout writes <agency_uei>/<period>/manifest.json with signed bytes')`.
18. `it('rejects period strings not matching YYYY-MM regex (e.g. "26-07", "2026-7", "2026/07")')`.
19. `it('manifest artifacts[].sha256 matches actual file sha256 (integrity check)')`.
20. `it('UI ConmonPublicationLog renders rows in reverse-chronological order with gap badge')`.

## REO compliance
- Every artifact in the tarball comes from real `outDir` — no synthesized content; no `process.env.NODE_ENV === 'test'` branches.
- Every file's sha256 + bytes recorded; mismatch between tarball and manifest fails the bundle.
- Provenance fields populated: `emitter: "conmon-publication.ts"`, `emitted_at` (ISO), `source_calls[]` (every file globbed), `signing_key_id` (Ed25519 fingerprint).
- Signed by existing `core/sign.ts` (Ed25519 + manifest).
- Timestamped by existing `core/timestamp.ts` (RFC 3161; multi-TSA cascade per audit recommendation).
- Missing artifacts surface as `gaps[]` — never silently dropped, never substituted.
- Schema-validated: `conmon-publication.v1.json` via `core/oscal-validate.ts` ajv harness.
- Tracker side: every publication row is RBAC-checked (`conmon:publish` for `iso`+; `conmon:acknowledge` for `ao`+).

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/conmon-publication.test.ts tests/core/conmon-publication-manifest.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/conmon-publications.test.ts client/src/pages/ConmonPublicationLog.test.tsx
```

## Known risks / issues
- **Risk 1: FedRAMP secure repository (Connect.gov) API not yet documented for direct upload.** Q.Q2 emits the signed tarball + manifest; operator uploads manually until PMO publishes an automated ingest API. Mitigation: documented in operator runbook; LOOP-G.G3 ADS provides the Trust Center serving path as an alternative. Cross-ref `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.12.
- **Risk 2: LOOP-E.E1 + LOOP-E.E2 not yet shipped.** Without them, `conmon-analysis-report` + `poam-delta` artifacts will surface as `gaps[]` entries. Mitigation: graceful degradation — Q.Q2 ships with non-strict mode allowing E gaps; `--strict-marketplace` is opt-in. CHANGELOG entry documents the dependency.
- **Risk 3: Scan-file naming conventions differ across CSPs (e.g. `aws-inspector-2026-07.json` vs `os-scan-2026-07.json`).** Mitigation: discovery uses glob patterns matching common conventions + operator-tunable patterns via `config.yaml conmon.scan_patterns[]`; unrecognized files bundled with `role: 'unrecognized'`.
- **Risk 4: Tar reproducibility drift across Node versions / filesystems.** Mitigation: LOOP-A.A4 pinned `mtime` + sort-by-path discipline; Q.Q2 reuses the same `tarWriter()` helper unchanged; per-OS test in CI matrix.
- **Risk 5: RFC 3161 TSA outage on the day of monthly publish.** Mitigation: multi-TSA cascade (DigiCert → GlobalSign → Sectigo → FreeTSA); on full-cascade failure, emit `gaps[]` entry + delay publish 24h with operator notification.
- **Risk 6: Idempotency could mask a genuine re-emit need (e.g. operator edited meeting-notes after first publish).** Mitigation: `--force` flag overrides idempotency check; CHANGELOG documents.
- **Risk 7: Trust Center mirror file proliferation (12 agencies × 12 months = 144 directories/year).** Mitigation: rotated archive after 90 days via LOOP-H.H2 long-term retention; mirror cleanup script ships with Q.Q2.
- **Risk 8: Prior-period chain break.** If a previously published manifest is lost (operator deleted `out/`), the chain anchor is broken. Mitigation: LOOP-H.H2 long-term retention guarantees prior manifests survive; CHANGELOG documents archive recovery procedure.

## Open questions
- **Q1**: Tarball compression level — gzip default (6) vs max (9)? Recommendation: 6 (faster; size delta < 5% for typical scans).
- **Q2**: Should the manifest also embed the Q.Q1 marketplace listing sha256 as a cross-reference? Recommendation: yes — embed in `current_marketplace_listing_sha256` field so consumers can verify the listing was current at publication.
- **Q3**: When meeting-notes file is `.docx` instead of `.md`, how does Q.Q2 detect? Recommendation: accept both `.md` and `.docx` extensions; record actual filename in `artifacts[]`.
- **Q4**: For `--force` re-emit, do we increment a `revision` counter in the manifest? Recommendation: yes — `revision: int` defaulting to 1, increments on `--force`; original sha256 chain remains intact via `prior_period_reference` to the *previous month* not the *previous revision of same month*.

## Implementation log
(empty — implementing session fills this in as work progresses)

## Completion checklist
- [ ] typecheck clean
- [ ] tests passing 100% (count increased by ≥20 cloud-evidence + ≥6 tracker)
- [ ] check:reo green
- [ ] check:provenance green
- [ ] STATUS.md updated
- [ ] LOOP-Q-SPEC.md Section 8 status row updated
- [ ] This file's frontmatter updated
- [ ] CHANGELOG.md "Unreleased" entry
- [ ] Commit with slice ID
- [ ] Commit amended with hash recorded
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-Q-SPEC.md` Sections 1-5 for loop context + Q.Q2 narrative.
3. This file gives you: sources, files to create, build steps, tests, REO checks, REQUIRES-OPERATOR-INPUT table, risks.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/submission-bundle.ts` for the `tarWriter()` helper + WELL_KNOWN + INDEX.json pattern.
6. Read `cloud-evidence/core/sign.ts` for the Ed25519 + manifest signing pipeline you'll reuse unchanged.
7. Read `cloud-evidence/core/timestamp.ts` for the RFC 3161 TSA cascade.
8. Read `cloud-evidence/docs/slices/Q/Q.Q3.md` for the agency-authorization snapshot format (`out/.agency-authorizations.json`) Q.Q2 reads for `destinations[]`.
9. Read `cloud-evidence/docs/slices/Q/Q.Q1.md` for the marketplace listing format Q.Q2 cross-references via `current_marketplace_listing_sha256`.
10. Begin implementation; update Implementation log as you go.

## Cross-references
- **LOOP-A.A4 pure-JS POSIX tar writer**: `cloud-evidence/core/submission-bundle.ts` exposes `tarWriter()` + `INDEX.json` pattern. Q.Q2 reuses unchanged; same `mtime` reproducibility option for byte-stable headers.
- **LOOP-E.E1 + LOOP-E.E2 (pending)**: when shipped, populate `conmon-analysis-<period>.md` + `poam-delta-<period>.json` artifacts Q.Q2 discovers + classifies. Until then, both surface as `gaps[]` entries.
- **LOOP-H.H2 (pending)**: archives every monthly publication tarball + manifest to cold storage at publish-time; prevents prior-period chain breaks (Q-X14).
- **LOOP-G.G3 (pending)**: AFR-ADS Trust Center serving infrastructure consumes Q.Q2's `out/trust-center-mirror/` payload. Until G.G3 ships, the mirror is materialized but not served — operator manually publishes via existing static hosting.
- **LOOP-B.B3 + LOOP-B-RISKS.md#B-X3**: signing-key registry pattern Q.Q3 mirrors; Q.Q2 reads the destinations list signed by that key. Cross-repo signature verification flows the same way.
