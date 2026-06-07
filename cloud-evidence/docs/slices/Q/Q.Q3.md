---
slice_id: Q.Q3
title: Agency authorization tracking (who is using the CSO + their authorization documents)
loop: Q
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A4, LOOP-B.B3]
blocks: [Q.Q1, Q.Q2, LOOP-I.I1, LOOP-H.H2]
estimated_effort: 4-5 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# Q.Q3 — Agency authorization tracking (who is using the CSO + their authorization documents)

## TL;DR
Track every agency that issues an ATO leveraging the CSP's existing FedRAMP authorization. Tracker DB tables `agency_authorizations` + `agency_reuse_events` + `marketplace_listing_history` + `conmon_publication_log` (additive only). CRUD + event-log routes signed via Ed25519, RBAC-gated (`iso` creates, `ao` revokes). Cloud-evidence-side reader (`core/agency-authorization-reader.ts`) pulls + verifies signatures; emitter (`core/agency-authorization-emitter.ts`) writes `out/agency-authorizations.json` for Q.Q1 listing consumption + LOOP-H.H2 long-term retention. Without this slice, RFC-0021 MKT-GEN-DOD ("list of all agencies directly using the product" + "list of all agencies that have requested access to authorization data") cannot be satisfied.

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
Q.Q3 is a tracker-side process-artifact slice (consistent with `core/process-artifact-tracker.ts` precedent). It does NOT add any cloud collectors. It DOES add: (a) structured records of each agency's ATO event entered by an operator via tracker UI, signed via the existing Ed25519 tracker key with `signing_key_id` provenance; (b) an emitter `core/agency-authorization-emitter.ts` that reads the tracker DB through the existing read-only API token pattern + produces `out/agency-authorizations.json` for inclusion in Q.Q1 marketplace listing + LOOP-H.H2 retention archive; (c) a timeline view (per-agency event log) that LOOP-I.I1 exec dashboard consumes for the "agencies leveraging this CSO" widget. Every value is operator-supplied via the tracker UI — nothing is synthesized from a default.

## Why this slice exists
RFC-0021 MKT-GEN-DOD requires the Marketplace listing to publish "a list of all _agencies_ that are directly using the product" + "agencies that have requested access to _authorization data_, covering the period since the previous _Ongoing Authorization Report_". Today the FedPy pipeline has nowhere to track per-agency authorization events: each new ATO that leverages the existing FedRAMP authorization, each access request for the authorization package, each subsequent revocation. Q.Q1 cannot populate `agencies_directly_using[]` or `agencies_requested_access[]` without a tracker source; Q.Q2 cannot populate `destinations[]` without one either. Q.Q3 creates the tracker workflow + signed-record pattern + reader/emitter pair that unblocks both Q.Q1 and Q.Q2.

## Authoritative sources (with verbatim quotes)

- **RFC-0021 "Expanding the FedRAMP Marketplace"** — https://www.fedramp.gov/rfcs/0021/
  - MKT-GEN-DOD verbatim:
    > "A list of all _agencies_ that are directly using the product"
    > "A list of all _agencies_ that have requested access to _authorization data_, covering the period since the previous _Ongoing Authorization Report_"

- **RFC-0026 "Clarifying CA-7 (Continuous Monitoring)"** — https://www.fedramp.gov/rfcs/0026/
  - Distribution-list verbatim:
    > "recurring monitoring information (including meetings) to all agency customers and FedRAMP"
  - Q.Q3 produces that "all agency customers" list as a single authoritative source for Q.Q2.

- **FedRAMP Agency Authorization Playbook v4.1 (2025-11-17)** — https://www.fedramp.gov/resources/documents/Agency_Authorization_Playbook.pdf
  - Defines the agency authorization process; Q.Q3 fields trace 1:1 to playbook-required ATO metadata: sponsoring-agency identity, AO name + title, ATO date, ATO letter PDF, leveraged-package ID, impact level.

- **FedRAMP 20x Authorization Data Sharing standard** — https://www.fedramp.gov/docs/20x/authorization-data-sharing/
  - Trust Center per leveraging agency:
    > "Providers SHOULD share the authorization package with agencies upon request"
  - Q.Q3 captures the `trust_center_url` per agency so Q.Q2's per-agency mirror layout has a destination.

- **OMB M-22-09 ("Moving the U.S. Government Toward Zero Trust Cybersecurity Principles")** — https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf
  - Federated read-endpoint posture (Trust Center per agency) — referenced for the post-ATO agency-sharing model Q.Q3 supports.

- **OMB Circular A-130 §III.A.2** — https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/circulars/A130/a130revised.pdf
  - Federal agencies must use FedRAMP-authorized services; the leverage event Q.Q3 tracks is the regulatory mechanism for this.

- **BOD 23-01 (CISA)** — https://www.cisa.gov/news-events/directives/bod-23-01-improving-asset-visibility-and-vulnerability-detection-federal-networks
  - Federal civilian agencies' asset visibility obligations. Each agency leveraging the CSO inherits BOD 23-01 obligations; Q.Q3's per-agency record helps the leveraging agency satisfy the BOD via the Trust Center publication.

- **NIST SP 800-37 Rev 2 — RMF Step 6 (Authorize)** — https://csrc.nist.gov/pubs/sp/800/37/r2/final
  - Authorization event definition + AO sign-off semantics — Q.Q3 fields `ato_signing_official_name` + `ato_signing_official_title` derive from this step's role definitions.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/agency-authorizations.ts` — CRUD + events + revoke endpoints (5 routes).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/marketplace-listings.ts` — `marketplace_listing_history` read/write (3 routes).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/agency-authorizations.test.ts` — ≥18 tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/marketplace-listings.test.ts` — ≥4 tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/AgencyAuthorizations.tsx` — list + create UI.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/AgencyAuthorizationDetail.tsx` — per-agency detail with timeline.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/MarketplaceListing.tsx` — view-only listing history.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/AgencyAuthorizations.test.tsx`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/AgencyAuthorizationDetail.test.tsx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/agency-authorization-reader.ts` — read-only client pulling active authorizations from tracker (mirrors `core/risk-acceptance-reader.ts` pattern from LOOP-B.B3).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/agency-authorization-emitter.ts` — writes `out/agency-authorizations.json` with provenance.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/schemas/agency-authorizations.v1.json` — JSON Schema for the emitted artifact.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/agency-authorization-reader.test.ts` — ≥6 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/agency-authorization-emitter.test.ts` — ≥6 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/agency-authorizations/` — fixture snapshots used by tests.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — append `agency_authorizations`, `agency_reuse_events`, `marketplace_listing_history`, `conmon_publication_log` tables (DDL in LOOP-Q-SPEC.md Section 5 Q.Q3 verbatim). Additive only — no DROP / ALTER COLUMN (per LOOP-B-RISKS.md#B-X10).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount three new routes.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/rbac.ts` — new permissions `marketplace:edit`, `agency-auth:create`, `agency-auth:revoke`, `marketplace:view`. Assign: `iso` → `agency-auth:create` + `marketplace:edit`; `ao` → `agency-auth:revoke` + `marketplace:edit`; `assessor` → `marketplace:view`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — routes `/agency-authorizations`, `/agency-authorizations/:uuid`, `/marketplace-listing`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add role `agency-authorizations-json` (filename `agency-authorizations.json`) to `WELL_KNOWN`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — `--agency-auth-export` flag + env `CLOUD_EVIDENCE_AGENCY_AUTH_EXPORT`; runs BEFORE `--marketplace-listing` so Q.Q1 picks up the snapshot.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CHANGELOG.md` — "Unreleased" entry.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` — slice row + Overall section.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-Q-SPEC.md` — Section 8 status row.

## Schemas / standards
- **Locally-authored `agency-authorizations.v1.json` JSON Schema** at `cloud-evidence/docs/schemas/agency-authorizations.v1.json`. Top-level fields verbatim per LOOP-Q-SPEC.md §5 Q.Q3 (schema_version, emitted_at, cso_name, authorizations[], provenance, requires_operator_input[]).
- **OSCAL POA&M does NOT have an "agency" concept** — Q.Q3 records live OUTSIDE the OSCAL chain. The Marketplace listing (Q.Q1) is where the records surface to FedRAMP.
- **Ed25519 signing key registry pattern** (per LOOP-B.B3 + LOOP-B-RISKS.md#B-X3): tracker exposes `GET /api/sign/public-keys` returning ALL historical keys keyed by `key_id`; reader cross-references each record's `signing_key_id` against the registry.
- **Sponsoring-agency invariant**: exactly one row may have `is_sponsoring_agency = 1`. Enforced via:
  - SQL: `CREATE UNIQUE INDEX idx_aa_sponsoring_unique ON agency_authorizations(is_sponsoring_agency) WHERE is_sponsoring_agency = 1;` (SQLite partial unique index).
  - Route: pre-check + 409 on violation.
- **H.4 attachment pattern** for ATO letter PDF upload: sha256 stored on row; download endpoint requires `assessor`+ role.

## Build steps (concrete, numbered)

1. **Tracker DB migration**: `CREATE TABLE IF NOT EXISTS` for all 4 tables (DDL verbatim from LOOP-Q-SPEC.md §5 Q.Q3). Idempotent + additive only.
2. **CRUD route logic** in `tracker/server/routes/agency-authorizations.ts`:
   - `POST /api/agency-authorizations` (create): RBAC `iso`+; validates `agency_name` non-empty, `ato_date` valid ISO date, `impact_level` ∈ allowed enum; canonical-JSON encode `{uuid, agency_name, ato_date, ato_signing_official_name, created_by_user_id, created_at}`; sign with resident Ed25519 key; store row.
   - `GET /api/agency-authorizations`: RBAC `assessor`+; supports `?status=active|expired|revoked` filter.
   - `GET /api/agency-authorizations/:uuid`: RBAC `assessor`+; returns row + events.
   - `POST /api/agency-authorizations/:uuid/events`: RBAC `iso`+; appends event with `event_type` enum-validated. When `actor_user_id` set (logged-in user), payload signed; when external event (actor_user_id null), `actor_name` required + signature null.
   - `POST /api/agency-authorizations/:uuid/revoke`: RBAC `ao`+; requires `revocation_reason` (422 if absent); records `revoked_at`, `revoked_by_user_id`, `revocation_reason`; flips `status` to `revoked`. Subsequent Q.Q1 emission removes the row from `agencies_directly_using[]`.
3. **Sponsoring-agency invariant enforcement**: route-level pre-check + SQL partial unique index. Multi-row violation returns 409 with `error.code = 'sponsoring-agency-invariant'`.
4. **ATO letter upload**: reuse H.4 attachment pattern (`tracker/server/routes/attachments.ts`); sha256 stored on `agency_authorizations.ato_letter_sha256`; download endpoint requires `assessor`+.
5. **Marketplace listing history routes** in `tracker/server/routes/marketplace-listings.ts`:
   - `POST /api/marketplace-listings` (RBAC `iso`+): record listing emission; called by cloud-evidence Q.Q1 emitter via API token.
   - `GET /api/marketplace-listings`: RBAC `assessor`+; chronological list.
   - `GET /api/marketplace-listings/latest`: RBAC `assessor`+; most recent row.
6. **Reader** `core/agency-authorization-reader.ts`:
   ```ts
   export interface PulledAgencyAuthorization {
     uuid: string;
     agency_name: string;
     agency_uei?: string;
     agency_short_name?: string;
     ato_date: string;
     ato_expiration_date?: string;
     ato_signing_official_name: string;
     ato_signing_official_title?: string;
     impact_level: 'low'|'moderate'|'high';
     is_sponsoring_agency: boolean;
     leveraged_package_id?: string;
     status: 'active'|'expired'|'revoked';
     trust_center_url?: string;
     notification_email?: string;
     events: AgencyReuseEvent[];
     signature: string;
     signing_key_id: string;
   }
   export async function pullAgencyAuthorizations(
     trackerUrl: string,
     apiToken: string,
     outDir: string,
   ): Promise<PulledAgencyAuthorization[]>;
   ```
   Writes `out/.agency-authorizations.json` snapshot + verifies every record's signature against the tracker's published public-key registry (LOOP-B-X3 pattern). On signature mismatch, throws typed error + emits diagnostic `REQUIRES-OPERATOR-INPUT: tracker-signature-verification-failed`.
7. **Emitter** `core/agency-authorization-emitter.ts`:
   ```ts
   export interface AgencyAuthorizationEmitOptions {
     outDir: string;
     trackerUrl?: string;
     apiToken?: string;
     snapshotPath?: string;          // default outDir/.agency-authorizations.json
     runId: string;
   }
   export interface AgencyAuthorizationEmitResult {
     path: string;
     authorization_count: number;
     active_count: number;
     event_count: number;
   }
   export function emitAgencyAuthorizations(opts: AgencyAuthorizationEmitOptions): Promise<AgencyAuthorizationEmitResult>;
   ```
   Reads snapshot, produces `out/agency-authorizations.json` with provenance. Pure builder separated from disk wrapper (mirrors `core/risk-register.ts` pattern from LOOP-B.B5).
8. **Orchestrator wiring**: `--agency-auth-export` runs BEFORE `--marketplace-listing` so Q.Q1 has fresh data. CLI examples documented in `--help`.
9. **UI — `AgencyAuthorizations.tsx`**: table with columns Agency, Short Name, Status, ATO Date, Expiration, Sponsoring (badge), Last Event. "Add agency" button → modal form. Filter by status (radio: All / Active / Expired / Revoked).
10. **UI — `AgencyAuthorizationDetail.tsx`**: detail view with: ATO letter download button, ATO letter upload (H.4 pattern), timeline of `agency_reuse_events` (reverse-chronological), "Add event" form (event_type dropdown + details JSON editor), "Revoke" button (AO only, modal with `revocation_reason` required), Trust Center URL editor.
11. **UI — `MarketplaceListing.tsx`**: read-only history view of `marketplace_listing_history` rows.
12. **Audit log**: every create / event-append / revoke / ATO-letter-upload writes to existing `audit_log` table.
13. **Snapshot validation under `--strict-marketplace`**:
    - At least one row with `is_sponsoring_agency=1` (else reject).
    - Every active row has `trust_center_url` set (Q.Q2 destination list requires it).
    - Every signature verified against the tracker public-key registry.
    - On any failure: emit `REQUIRES-OPERATOR-INPUT` markers + non-zero exit.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| All agency rows | Operator UI input (tracker `/agency-authorizations`) | Empty snapshot → marker; Q.Q1 emits empty `agencies_directly_using[]` |
| `is_sponsoring_agency` | Operator selects exactly one row | Validation rejects multiple; `--strict-marketplace` rejects zero |
| `trust_center_url` | Operator UI input per agency | Per-row marker; Q.Q2 destination loses that agency + falls back to `notification_email` |
| ATO letter attachment | Operator uploads PDF via H.4 pattern | Optional but recommended; absence not blocking but visible in detail page |
| `revocation_reason` | Operator UI on revoke | Required at revoke; route returns 422 if absent |
| `leveraged_package_id` | Operator enters FedRAMP-assigned package ID | Optional; null until known |
| `agency_uei` | Operator enters from sam.gov | Optional; null until operator records |
| `ato_expiration_date` | Operator enters | Optional; null when ATO is open-ended |

## Test specifications (≥12 tests)

1. `it('creates an agency_authorization with iso role and signs the canonical-JSON payload')`.
2. `it('rejects create when user lacks iso role (403)')`.
3. `it('enforces single is_sponsoring_agency=1 invariant (409 on second sponsoring row)')`.
4. `it('appends agency_reuse_events and stores signed signature when actor is logged-in user')`.
5. `it('records external events with actor_user_id=null + actor_name set')`.
6. `it('revoke flips status to revoked, records revoked_at + revoked_by + reason')`.
7. `it('rejects revoke without revocation_reason (422)')`.
8. `it('only ao role can revoke (403 for iso)')`.
9. `it('reader writes .agency-authorizations.json with every record signature verified')`.
10. `it('reader rejects snapshot when any record signature invalid')`.
11. `it('reader cross-references signing_key_id against tracker /api/sign/public-keys registry')`.
12. `it('emitter writes agency-authorizations.json with provenance + counts')`.
13. `it('emitter excludes revoked rows from active_count')`.
14. `it('emitter includes revoked rows in authorization_count for historical record')`.
15. `it('--strict-marketplace rejects emission when zero sponsoring agencies (exit 2)')`.
16. `it('--strict-marketplace rejects emission when any active agency has no trust_center_url')`.
17. `it('submission-bundle WELL_KNOWN includes agency-authorizations-json role after Q.Q3 ships')`.
18. `it('UI AgencyAuthorizations list filters by status (active / expired / revoked)')`.
19. `it('UI AgencyAuthorizationDetail renders event timeline in reverse-chronological order')`.
20. `it('UI attaches ATO letter via H.4 attachment pattern with sha256 recorded on row')`.
21. `it('POST /api/marketplace-listings records history row with listing_sha256')`.
22. `it('GET /api/marketplace-listings/latest returns most recent emission row')`.

## REO compliance
- Every agency record is operator-supplied through the tracker UI; nothing is synthesized from a default.
- Every record is signed (Ed25519) with `signing_key_id` provenance recorded at create-time.
- Events are append-only; no UPDATE/DELETE on `agency_reuse_events` (revocation is a row-level state change with its own audit-log entry).
- ATO letter attachments mirror H.4 pattern; sha256 stored at upload time (LOOP-B-X9 pattern).
- Sponsoring-agency invariant enforced at schema layer (partial unique index) + route layer (pre-check).
- `--strict-marketplace` blocks emission when sponsoring-agency or trust-center URLs absent.
- All four new tables are additive only (per LOOP-B-RISKS.md#B-X10); existing tracker installs upgrade non-destructively.
- Provenance fields populated on `agency-authorizations.json`: `emitter: "agency-authorization-emitter.ts"`, `emitted_at`, `source_calls: ["tracker GET /api/agency-authorizations", "tracker GET /api/sign/public-keys"]`, `signing_key_id`.
- No `process.env.NODE_ENV === 'test'` branches.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/tracker
npm run typecheck
npm test -- server/routes/agency-authorizations.test.ts server/routes/marketplace-listings.test.ts client/src/pages/AgencyAuthorizations.test.tsx client/src/pages/AgencyAuthorizationDetail.test.tsx
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/agency-authorization-reader.test.ts tests/core/agency-authorization-emitter.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues
- **Risk 1: Cross-repo signing-key drift between tracker + cloud-evidence (cross-ref LOOP-B-RISKS.md#B-X3).** Mitigation: tracker exposes `/api/sign/public-keys` with full historical key registry; reader cross-references each record's `signing_key_id`; key rotation events written to `audit_log`.
- **Risk 2: Tracker schema migration on existing DBs (cross-ref LOOP-B-RISKS.md#B-X10).** Mitigation: all four ALTERs are `CREATE TABLE IF NOT EXISTS` additive; smoke test on production DB copy; no DROP / ALTER COLUMN under any circumstance.
- **Risk 3: AO approval signature replay (cross-ref LOOP-B-RISKS.md B.B3-3).** Mitigation: per-approval includes `revoked_at` (server-set) + uuid; status transition rejects replay; audit-log records every revoke attempt.
- **Risk 4: Cross-loop schema drift if LOOP-Q.Q3 ships before LOOP-B.B3 (which establishes signing-key registry pattern).** Mitigation: dependency declared in frontmatter; if shipping Q.Q3 first, reader includes a fallback "trust-on-first-use" with operator-acknowledged seed key recorded in `config.yaml`.
- **Risk 5: Sponsoring-agency UI ergonomics (operator could accidentally create a second sponsoring row + see a 409).** Mitigation: UI "Add agency" form shows current sponsoring row; "Mark as sponsoring" toggle prompts confirmation that demotes the prior sponsoring row in a single atomic transaction.
- **Risk 6: ATO letter PDFs could exceed attachment size limits.** Mitigation: H.4 attachment subsystem has 10 MB per-file cap; ATO letters typically < 1 MB; UI displays size estimate before upload.
- **Risk 7: Agency reuse events grow unbounded over time.** Mitigation: pagination in detail view (50/page); LOOP-H.H2 archives events > 12 months old to cold storage.
- **Risk 8: Multi-CSO tenant isolation deferred to H.H3 (cross-ref LOOP-B-RISKS.md#B-X15).** Mitigation: all Q.Q3 tables omit `tenant_id` column; documented in operator runbook; LOOP-Q ships in single-tenant deployments only; H.H3 batches LOOP-B + LOOP-Q tables in a single migration sweep.
- **Risk 9: RBAC mis-configuration (cross-ref LOOP-B-RISKS.md#B-X5).** Mitigation: per-route `requireRole` is unit-tested; `audit_log` records each role-checked action; first-boot prompt assigns `iso` + `ao` roles.

## Open questions
- **Q1**: Do we need a per-agency "notification channel" beyond `trust_center_url` + `notification_email` (e.g. SIEM webhook for Q.Q2 monthly publish)? Recommendation: defer to LOOP-G.G3 ADS; Q.Q3 captures URL + email only.
- **Q2**: When a sponsoring agency revokes, who becomes the new sponsoring agency? Recommendation: route enforces "no zero-sponsoring state" — revoke of sponsoring row requires `new_sponsoring_uuid` in payload OR rejects with 409; UI prompts operator to select replacement.
- **Q3**: For `agencies_requested_access[]` (Q.Q1 consumer), should the event be auto-resolved (when access granted, drop from `requested_access`) or shown forever? Recommendation: per RFC-0021 MKT-GEN-DOD wording "since the previous _Ongoing Authorization Report_", show events within last report-cycle window (12 months); auto-aging.
- **Q4**: When ATO expires (date in past), do we auto-flip `status` to `expired`? Recommendation: yes, via daily cron job in tracker; operator can manually override.

## Implementation log
(empty — implementing session fills this in as work progresses)

## Completion checklist
- [ ] typecheck clean (tracker + cloud-evidence)
- [ ] tests passing 100% (count increased by ≥22 tracker + ≥12 cloud-evidence)
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
2. Read `cloud-evidence/docs/loops/LOOP-Q-SPEC.md` Sections 1-5 for loop context + Q.Q3 narrative.
3. This file gives you: sources, files to create, build steps, tests, REO checks, REQUIRES-OPERATOR-INPUT table, risks.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `tracker/server/routes/risk-acceptances.ts` (LOOP-B.B3 reference pattern for signed-record CRUD) + `tracker/server/rbac.ts` + `tracker/server/schema.sql` (existing structure). Read `core/risk-acceptance-reader.ts` for the reader pattern.
6. Begin implementation; update Implementation log as you go.
