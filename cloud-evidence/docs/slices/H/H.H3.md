---
slice_id: H.H3
title: Multi-CSO / tenant isolation (cso_id everywhere)
loop: H
status: pending
commit: —
completed_date: —
depends_on: [D.4, D.5]
blocks: [I.I1, I.I2, I.I3, I.I4, F.F6]
estimated_effort: 6 working days (1 senior engineer)
last_updated: 2026-06-06
---

# H.H3 — Multi-CSO / tenant isolation

## TL;DR
Introduce a first-class `cso_id` concept that flows through the orchestrator output path, the tracker DB schema, the bundler INDEX, the OSCAL metadata, and the H.H1 archive prefix. A single deployment serves multiple CSO tenants without cross-tenant data visibility. Backward-compatible: when `--cso` is omitted, behavior is identical to today's single-tenant mode (one implicit `default` CSO).

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
A CSP or MSP operating multiple Cloud Service Offerings under a single org can't use today's tool without running N separate checkouts: the orchestrator hard-codes `outDir`, the tracker DB has no tenant column, and there's no concept of per-CSO bundle / archive scope. The result is operationally painful (N CI pipelines, N tracker installations) and structurally unsafe (cross-tenant data leakage in the tracker DB is impossible to *prevent* — there's no field to filter on).

H.H3 implements NIST SP 800-145 multi-tenant *resource pooling* at our tooling layer:

- **NIST SP 800-145 §2** — multi-tenant resource pooling: "different physical and virtual resources dynamically assigned and reassigned according to consumer demand."
- **NIST SP 800-53 Rev 5 SC-4 (Information in Shared Resources)** — every tracker DB read is `cso_id`-scoped.
- **NIST SP 800-53 Rev 5 AC-3 (Access Enforcement)** — per-CSO scope is an RBAC dimension orthogonal to role.
- **NIST SP 800-53 Rev 5 AC-4 (Information Flow Enforcement)** — cross-tenant reads are denied + audit-logged.

This is **not** new cloud isolation — the underlying clouds already provide that. This is *tenant isolation inside our tool*.

## Authoritative sources (with verbatim quotes)

- <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-145.pdf> — NIST SP 800-145 The NIST Definition of Cloud Computing, §2 Essential Characteristics → Resource pooling:
  > "The provider's computing resources are pooled to serve multiple consumers using a multi-tenant model, with different physical and virtual resources dynamically assigned and reassigned according to consumer demand. There is a sense of location independence in that the customer generally has no control or knowledge over the exact location of the provided resources but may be able to specify location at a higher level of abstraction (e.g., country, state, or datacenter)."

- <https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-4/> — NIST SP 800-53 Rev 5 §SC-4 Information in Shared System Resources:
  > "Prevent unauthorized and unintended information transfer via shared system resources."

- <https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-3/> — NIST SP 800-53 Rev 5 §AC-3 Access Enforcement:
  > "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies."

- <https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-4/> — NIST SP 800-53 Rev 5 §AC-4 Information Flow Enforcement:
  > "Enforce approved authorizations for controlling the flow of information within the system and between connected systems based on [Assignment: organization-defined information flow control policies]."

- <https://csf.tools/reference/nist-sp-800-53/r5/au/au-12/> — NIST SP 800-53 Rev 5 §AU-12 Audit Record Generation:
  > "Provide audit record generation capability for the event types... [the system shall produce] audit records containing the information specified in AU-3..."
  > (Used for the `rbac.cross_cso_denied` audit event that H.H3 emits.)

- <https://pages.nist.gov/OSCAL/concepts/layer/control/profile/> — OSCAL metadata model:
  > "Metadata provides a standardized data model for the contextual information about an OSCAL document, including identification, dates, version, parties involved, and properties."
  > (Used for the `cso-id` prop H.H3 adds to SSP/AP/AR/POA&M metadata.)

- <https://www.fedramp.gov/assets/resources/documents/CSP_FedRAMP_Authorization_Boundary_Guidance.pdf> — FedRAMP Authorization Boundary Guidance:
  > Each authorization boundary corresponds to a single CSO; multi-CSO orgs maintain separate authorization boundaries per CSO. (Anchors the per-CSO scope as the natural authorization unit.)

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/cso-config.ts` — pure `resolveCsoContext(args, env, config)` + `loadCsosFromConfig(configPath)` + `validateCsoEntry(entry)`. ~200 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/db/migrations/0XX_add_cso_id.sql` — adds `cso_id` columns + `csos` reference table + indexes. Numbered as the next available migration sequence.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/db/migrations/0XX_add_cso_id.down.sql` — down migration (for safe rollback, idempotent).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/csos.ts` — CRUD endpoints for CSO registration (admin-only). ~250 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/CsosAdmin.tsx` — admin UI for listing + adding CSOs + scope-binding users. ~300 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/cso-config.test.ts` — ≥10 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/tracker/server/routes/csos.test.ts` — ≥12 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/tracker/server/rbac-cso-scope.test.ts` — ≥15 tests verifying cross-CSO read denial.

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`:
  - Add `--cso <id>` flag + `CLOUD_EVIDENCE_CSO` env.
  - Resolution order: CLI > env > `config.yaml:default_cso` > literal `"default"` (notice emitted explaining single-tenant mode).
  - `outDir` derivation: `args.outDir = resolve(PROJECT_ROOT, 'out', cso_id)` when `cso_id !== 'default'`; falls back to `out/` when `default` (back-compat).
  - Every emitted artifact carries `provenance.csoId` (envelope-level) and `metadata.props: [{ name: 'cso-id', value: <id>, ns: 'https://fedramp.gov/ns/oscal/cloud-evidence' }]` (OSCAL artifacts).
  - The run ledger records `cso_id` on every event.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts` — manifest body adds top-level `cso_id` so a verifier can refuse a manifest that doesn't match the expected tenant.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`:
  - `INDEX.json` gains top-level `cso_id`.
  - When archived (H.H1), the key becomes `cso-<id>/YYYY/MM/<run-id>.tar.gz`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/archive-push.ts` (from H.H1) — when `cso_id` is present in the orchestrator context, archive prefix becomes `cso-<id>/`. Per-CSO buckets supported via `config.yaml:csos[].archive_target_override`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/schema.sql` — add `csos` table + `cso_id TEXT NOT NULL DEFAULT 'default'` on per-evidence tables (`items`, `attestations`, `findings`, `attachments`, `audit_events`, `collector_runs`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/rbac.ts` — extend permission predicates so every query gets a `cso_id IN (<bound-csos>)` filter. Admins bound to all CSOs; regular users get a per-CSO scope set on user record.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/db.ts` — add the migration runner invocation.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/ingest.ts` — read `cso_id` from envelopes + reject ingest when missing AND the installation is in multi-CSO mode.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts`, `core/oscal-ap.ts`, `core/oscal-poam.ts` — add `cso-id` prop to `metadata.props[]`.

## Schemas / standards

### DB migration shape
- New table:
  ```sql
  CREATE TABLE IF NOT EXISTS csos (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    impact_level TEXT NOT NULL CHECK (impact_level IN ('Low','Moderate','High')),
    authorized_org_name TEXT NOT NULL,
    authorized_system_id TEXT NOT NULL,
    primary_3pao TEXT,
    archive_target_override TEXT,
    subprocessor_list_override TEXT,
    created_at TEXT NOT NULL,
    deleted_at TEXT
  );
  INSERT OR IGNORE INTO csos (id, display_name, impact_level, authorized_org_name, authorized_system_id, created_at)
    VALUES ('default', 'Default (single-tenant)', 'Moderate', '', '', strftime('%Y-%m-%dT%H:%M:%fZ','now'));
  ```
- Per-evidence tables get:
  ```sql
  ALTER TABLE items ADD COLUMN cso_id TEXT NOT NULL DEFAULT 'default';
  CREATE INDEX IF NOT EXISTS items_cso_id_idx ON items (cso_id, item_id);
  -- (repeat for attestations, findings, attachments, audit_events, collector_runs)
  ```
- User scope binding:
  ```sql
  CREATE TABLE IF NOT EXISTS user_cso_scope (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cso_id TEXT NOT NULL REFERENCES csos(id),
    PRIMARY KEY (user_id, cso_id)
  );
  ```

### OSCAL metadata.props extension
- Each OSCAL artifact (SSP, AP, AR, POA&M) adds:
  ```json
  {
    "name": "cso-id",
    "ns": "https://fedramp.gov/ns/oscal/cloud-evidence",
    "value": "<cso_id>",
    "class": "tenant-scope"
  }
  ```
- Namespace declared as cloud-evidence local; OSCAL has no spec for multi-tenant.

### Route shape
- `POST /api/csos` — body: `{ id, display_name, impact_level, authorized_org_name, authorized_system_id, primary_3pao?, archive_target_override? }`. Validates: id slug `/^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/`, impact in {Low, Moderate, High}, optional fields non-empty when supplied.
- `GET /api/csos` — admin returns all; non-admin returns only bound CSOs.
- `DELETE /api/csos/:id` — admin only; refuses with 409 if evidence exists for the CSO.
- `POST /api/csos/:id/users` — admin only; body: `{ user_id, role }`.

## Build steps (concrete, numbered)

1. Define interfaces in `core/cso-config.ts`:
   ```ts
   export interface CsoEntry {
     id: string;
     display_name: string;
     impact_level: 'Low' | 'Moderate' | 'High';
     archive_target_override?: ArchiveTarget;
     subprocessor_list_override?: string;
     primary_3pao?: string;
     authorized_org_name: string;
     authorized_system_id: string;
     created_at: string;
   }
   export interface CsoContext {
     id: string;
     entry: CsoEntry | null;    // null for the implicit 'default'
     outDir: string;
     archive_prefix: string;
   }
   ```
2. Pure `resolveCsoContext(args, env, config)`:
   - Reads `--cso <id>` (highest priority) → env → config default → `"default"`.
   - If id matches a `config.yaml:csos[]` entry, returns its `CsoEntry`; otherwise returns null (implicit single-tenant).
   - When id `!= 'default'` AND no matching entry exists, throws `UnknownCsoError` with help text naming the config path.
3. DB migration — every per-evidence table gets `cso_id TEXT NOT NULL DEFAULT 'default'` + an index on `(cso_id, item_id)`. Default applied only to existing rows; new rows must supply `cso_id` via the ingest path. Idempotent + has a `.down.sql` companion.
4. `tracker/server/routes/csos.ts` — POST/GET/DELETE endpoints with admin-only RBAC; CRUD writes `audit_events`.
5. `tracker/server/rbac.ts` — every existing permission check gets a `cso_scope: string[]` argument; queries filter `WHERE cso_id IN (?,?,?)`. Cross-CSO read attempt → **404** (NOT 403, to avoid leaking existence) + audit event `rbac.cross_cso_denied`.
6. UI `CsosAdmin.tsx` — list CSOs, add CSO form (id slug, display name, impact, 3PAO, system-id, archive override), per-CSO user assignment (multi-select). Admin-only route guarded by `useRole('admin')`.
7. Orchestrator:
   - Initialize `CsoContext` early in `main()`.
   - Pass context to every emitter that records provenance: SSP, AP, AR, POA&M, IIW, RoE, bundle, manifest, archive.
   - When `cso_id != 'default'`, console prefix every log line with `[cso=<id>]` via the existing `log` shim.
8. Backwards compatibility:
   - Single-tenant operators see no behavioral change as long as they never pass `--cso` and never have `csos[]` in config.
   - Migration seeds an implicit `default` CSO entry; existing rows default to `cso_id = 'default'`.
9. CSV/export: every existing tracker export (D.6) gains a `cso_id` column.
10. OSCAL metadata patch: extend `core/oscal-ssp.ts`, `core/oscal-ap.ts`, `core/oscal-poam.ts` to write the `cso-id` prop.

## REQUIRES-OPERATOR-INPUT fields

- **`csos[].id`** — slug for the CSO. Source: `config.yaml:csos[]` or tracker admin UI. No silent default; missing → orchestrator stays in single-tenant mode (`default`).
- **`csos[].display_name`, `authorized_org_name`, `authorized_system_id`** — operator-supplied per CSO; surfaced as `REQUIRES-OPERATOR-INPUT` in SSP metadata when missing.
- **`csos[].archive_target_override`** — optional per-CSO archive bucket (data-residency requirements). When unset, uses the global `--archive-target`.
- **User → CSO scope binding** — only an admin can assign; missing binding means user has no CSO scope and sees no evidence.
- **`csos[].primary_3pao`** — optional 3PAO contact per CSO; surfaces in 3PAO sign-off UI (LOOP-F).

## Test specifications (≥10 + ≥12 + ≥15 = ≥37 tests)

`tests/core/cso-config.test.ts`:
1. `it('resolves --cso CLI flag with highest priority')`.
2. `it('falls back to CLOUD_EVIDENCE_CSO env when CLI omitted')`.
3. `it('falls back to config.yaml:default_cso when env omitted')`.
4. `it('falls back to literal "default" when nothing supplied')`.
5. `it('throws UnknownCsoError when --cso <id> is not in config.yaml:csos[]')`.
6. `it('returns null .entry for the implicit "default" CSO')`.
7. `it('returns CsoEntry .entry for a registered CSO')`.
8. `it('outDir for cso=acme = out/acme')`.
9. `it('outDir for cso=default = out (back-compat)')`.
10. `it('archive_prefix for cso=acme = cso-acme/')`.
11. `it('archive_prefix for cso=default = "" (back-compat)')`.
12. `it('validates id slug pattern (rejects uppercase, special chars)')`.

`tests/tracker/server/routes/csos.test.ts`:
1. `it('POST /api/csos requires admin role')`.
2. `it('POST /api/csos validates id slug pattern')`.
3. `it('POST /api/csos rejects duplicate id')`.
4. `it('GET /api/csos returns the list to an admin')`.
5. `it('GET /api/csos returns only bound CSOs to a non-admin')`.
6. `it('DELETE refuses (409) when evidence exists for the CSO')`.
7. `it('DELETE allowed for an empty CSO')`.
8. `it('writes an audit event on every CRUD action')`.
9. `it('POST validates authorized_org_name as non-empty when provided')`.
10. `it('archive_target_override is optional and validated as a URL when provided')`.
11. `it('rejects invalid impact_level (e.g. "Foo")')`.
12. `it('writes the entry with a deterministic created_at when supplied via clock seam')`.

`tests/tracker/server/rbac-cso-scope.test.ts`:
1. `it('admin reads see every CSO')`.
2. `it('editor with scope=[acme] reads only ACME rows')`.
3. `it('editor with scope=[acme] cannot read globex rows (returns 404)')`.
4. `it('logs rbac.cross_cso_denied event on cross-CSO read attempt')`.
5. `it('viewer with no scope sees no rows')`.
6. `it('ingest of an envelope with cso_id=acme rejects when uploader scope omits acme')`.
7. `it('ingest of an envelope without cso_id is rejected in multi-CSO mode')`.
8. `it('back-compat: ingest of an envelope without cso_id is accepted in single-tenant mode')`.
9. `it('export CSV is filtered by cso_id scope')`.
10. `it('attachment download enforces cso_id scope')`.
11. `it('dashboard counters reflect only scoped CSOs')`.
12. `it('a deleted CSO cannot accept new evidence')`.
13. `it('user scope changes are audit-logged')`.
14. `it('cso_id is required in collector_runs table')`.
15. `it('scope set is comma-separated string parsed into array')`.
16. `it('SQL injection in cso_id parameter is rejected by ajv input validator')`.

## REO compliance specific to this slice

- `cso_id` originates from operator-supplied config / CLI / DB record; the orchestrator never invents one. The literal `"default"` is documented as the explicit single-tenant marker.
- Every cross-CSO read attempt produces an `audit_events` record — never a silent 404 with no trace.
- DB migration is idempotent + reversible via `0XX_add_cso_id.down.sql`.
- OSCAL metadata `cso-id` prop traces to the same `cso_id` value the manifest carries — schema parity across files.
- Archive prefix in H.H1 is derived from the same `CsoContext` — single source of truth.
- No silent fallback for missing `cso_id` in multi-tenant mode — ingest rejects.
- User scope bindings are auditable through `audit_events`.

## Verification commands

```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/cso-config.test.ts
npm test -- tests/tracker/server/routes/csos.test.ts
npm test -- tests/tracker/server/rbac-cso-scope.test.ts
npm run check:reo

# Multi-tenant end-to-end (manual, requires DB):
tsx core/orchestrator.ts --cso acme --inventory-only
tsx core/orchestrator.ts --cso globex --inventory-only
ls out/acme out/globex
# Tracker: log in as a user scoped to acme; verify globex assets are not visible.
```

## Known risks / issues

- **Risk 1 — DB migration on existing tracker installations.** The cso_id column defaults to `default` for existing rows. Operators migrating from single-tenant to multi-tenant must re-bind each user to the appropriate CSO scope. **Mitigation:** an admin one-time CLI script `tracker/scripts/migrate-cso.ts` (out of scope for this slice; track as follow-up).
- **Risk 2 — RBAC predicate refactor is invasive.** Every existing query gets a new argument; a missed query is a leakage bug. **Mitigation:** introduce a single `withCsoScope(stmt, scope)` helper; refactor existing routes via this helper. Add a CI check that scans `tracker/server/routes/` for any raw query string lacking `cso_id`.
- **Risk 3 — Cross-CSO leakage via JOIN.** A query that joins items + attestations could inadvertently leak across CSO if only the items side is filtered. **Mitigation:** require both sides of every join to carry the `cso_id` filter; test exhaustively.
- **Risk 4 — UI scope confusion.** A user with multi-CSO scope sees rows from multiple CSOs in the same view; they may not realize. **Mitigation:** dashboard explicitly labels every row with a `cso_id` chip; filter dropdown defaults to "all-bound" with explicit per-CSO scoping.
- **Risk 5 — Back-compat regression.** A single-tenant operator might see different bundle filenames or different OSCAL output. **Mitigation:** existing reproducibility tests in `tests/core/oscal-*.test.ts` re-run; any byte-level diff is a regression. The `cso-id` prop is omitted from OSCAL output entirely when `cso_id === 'default'`.
- **Risk 6 — Per-CSO archive buckets multiply costs.** Some operators may not want a bucket per CSO; spec supports both shared bucket with `cso-<id>/` prefix AND per-CSO bucket via `archive_target_override`. Default is shared bucket with prefix.
- **Risk 7 — CSO ID slug collisions with reserved words.** `default`, `all`, `none`, `system`, `admin` should be reserved. **Mitigation:** `RESERVED_CSO_IDS` constant in `cso-config.ts`; POST rejects with 400 if attempted.
- **Risk 8 — Audit log volume from cross-CSO denials.** A misconfigured user could generate thousands of `rbac.cross_cso_denied` events per minute. **Mitigation:** rate-limit per (user, target_cso) pair to 1 event/minute via existing audit dedup logic.
- **Risk 9 — Migration on a large DB takes time.** ALTER TABLE ADD COLUMN with DEFAULT is fast on SQLite; CREATE INDEX is O(N log N). Document expected times in RUNBOOK.md.

## Open questions (for implementation session to resolve)

- **Q1**: Should the `cso_id` slug pattern allow underscores? Spec proposes `^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$` (hyphen-only). Confirm hyphens are sufficient for org naming conventions.
- **Q2**: For OSCAL metadata, should we use `metadata.parties` (party-uuid per CSO) instead of or in addition to a custom `cso-id` prop? Parties carry more structure (name, type, addresses). Confirm preferred shape.
- **Q3**: Should the tracker UI offer a "CSO switcher" in the global header (like GitHub's org switcher) or page-level filter? Recommend header switcher for clarity.
- **Q4**: For the DELETE refusal when evidence exists, should we offer a "soft delete + retain evidence" mode? Default: hard 409 refusal; operator must export+delete evidence first.
- **Q5**: For backward compat: should we OMIT the `cso-id` metadata prop entirely when `cso_id === 'default'`, or always include it? Recommend omit for byte-level reproducibility against pre-H.H3 runs.
- **Q6**: Cross-account discovery — when a single CSO spans multiple AWS accounts, does the `--cso` flag interact with C.2 (org-wide AWS fan-out)? Default: a CSO can span multiple accounts; the fan-out config is per-CSO.
- **Q7**: Should the migration script also seed `csos` rows from a `config.yaml:csos[]` block at migration time? Cleaner than admin-UI flow for the first run; one-shot only.
- **Q8**: Schema migration ordering — does our DB migration runner currently support `0XX` numbering with sub-letters (e.g. `015a`, `015b`)? Confirm via reading `tracker/server/db.ts`.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~40 for this slice's new tests: 12 cso-config + 12 csos route + 16 rbac-cso-scope)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (H.H3 row + Overall → Next priority; LOOP-H title gets `(COMPLETE)`)
- [ ] LOOP-H-SPEC.md §7 status table updated (H.H3 row + close-out note)
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-H.H3: Multi-CSO / tenant isolation` + roll-up entry noting LOOP-H closure
- [ ] Commit with `LOOP-H.H3:` prefix in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-H-SPEC.md
- [ ] Pushed to origin/main
- [ ] RUNBOOK.md updated with multi-CSO operational guidance (migration steps, user-scope binding flow)
- [ ] EXECUTION-PLAN.md status snapshot updated to mark LOOP-H COMPLETE

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-H-SPEC.md` Section 2 (Dependencies) for context on D.4 (granular RBAC) and D.5 (tracker backup/restore).
4. Read `cloud-evidence/tracker/server/rbac.ts` to see the existing permission predicate pattern (D.4).
5. Read `cloud-evidence/tracker/server/schema.sql` for the existing schema this slice extends.
6. Read `cloud-evidence/tracker/server/db.ts` to see the migration runner.
7. Read `cloud-evidence/core/orchestrator.ts` for the outDir derivation point to change.
8. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
9. Begin implementation; update Implementation log section as you go.
