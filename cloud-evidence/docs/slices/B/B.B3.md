---
slice_id: B.B3
title: Risk acceptance workflow (tracker DB + signed audit record + OSCAL deviation-approved propagation)
loop: B
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A3, B.B1, B.B2]
blocks: [B.B4, B.B5, E.E5, F.F1, C.C7]
estimated_effort: 6-7 working days
last_updated: 2026-06-06
---

# B.B3 — Risk acceptance workflow (tracker DB + signed audit record + OSCAL deviation-approved propagation)

## TL;DR
Ship the end-to-end signed risk-acceptance workflow: tracker SQLite tables + REST routes + React UI + Express RBAC + hourly enforcer + cloud-evidence reader that snapshots active acceptances into `out/.risk-acceptances.json`. The OSCAL POA&M emitter flips affected risks to `risk.status = "deviation-approved"`, overrides the deadline to the acceptance's `expiration_date`, and attaches `acceptance-uuid`/`acceptance-type`/`business-justification`/`compensating-control-uuid` props — replacing today's silent absence with a fully-audited NIST CA-5 / FedRAMP Deviation Request artifact.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
Today there is no system path for "we accept this finding's residual risk because X, expires Y, with compensating control Z." Operators record decisions in tickets or email; nothing flows through to the POA&M; nothing carries a signed audit trail; nothing expires automatically. This violates two authoritative requirements:

- **NIST SP 800-53 Rev 5, CA-5 (Plan of Action and Milestones)** requires the POA&M to "document the planned remediation actions of the organization to correct weaknesses or deficiencies … and to reduce or eliminate known vulnerabilities." The risk-acceptance path is the documented exception to "remediate." Without a structured record, the POA&M cannot truthfully claim CA-5 coverage.
- **FedRAMP Continuous Monitoring Strategy & Guide** mandates the Deviation Request (DR) and Risk Adjustment Request (RAR) workflows for exactly this purpose — both with explicit fields (justification, proposed expiration, compensating control, AO approval signature) and an annual review cadence.

The OSCAL POA&M v1.1.2 schema defines `risk.status = "deviation-approved"` for precisely this case. LOOP-A.A1 today only emits `risk.status = "open"`. B.B3 is what makes `deviation-approved` an honest, signed value.

## Authoritative sources (with verbatim quotes)
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, CA-5 (Plan of Action and Milestones)**:
  > "a. Develop a plan of action and milestones for the system to document the planned remediation actions of the organization to correct weaknesses or deficiencies noted during the assessment of the controls and to reduce or eliminate known vulnerabilities in the system; and
  > b. Update existing plan of action and milestones [Assignment: organization-defined frequency] based on the findings from control assessments, security impact analyses, and continuous monitoring activities."
  > "CA-5(1) Automation Support for Accuracy and Currency — Ensure the accuracy, currency, and availability of the plan of action and milestones for the system using [Assignment: organization-defined automated mechanisms]."

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, RA-7 (Risk Response)**:
  > "Respond to findings from security and privacy assessments, monitoring, and audits in accordance with organizational risk tolerance."
  Risk acceptance is the documented "accept" branch of RA-7.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf — **NIST SP 800-37 Rev 2 (Risk Management Framework), Task R-2 (Risk Response)**:
  > "Identify and implement appropriate risk response decisions … The risk response decisions are documented in the security and privacy plans, plan of action and milestones, and risk assessment report."
  B.B3's signed audit record IS the documentation of that decision.

- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/ — **OSCAL POA&M v1.1.2, `risk.status`**:
  > "The current operating status of the risk. … One of: open, investigating, remediating, deviation-requested, deviation-approved, closed."
  B.B3 transitions items from `open` → `investigating` (acceptance created, pending AO) → `deviation-requested` (submitted to AO) → `deviation-approved` (AO signed) via real signed tracker actions; OSCAL only ever sees the final state.

- https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf — **FedRAMP Continuous Monitoring Strategy & Guide (Rev 5), Section 4 "Deviation Requests"**:
  PDF returns 403 to anonymous fetches; implementer downloads to `cloud-evidence/docs/sources/fedramp-conmon-strategy-guide.pdf`. Key required fields B.B3 mirrors verbatim in the `risk_acceptances` schema:
  - Finding identifier (CSP CVE / scan ID / POA&M item)
  - Justification / explanation (operator-supplied free text, minimum length enforced)
  - Proposed remediation OR rationale for non-remediation
  - Compensating control(s) reference
  - Proposed expiration / annual-review date
  - AO approval signature

- https://www.fedramp.gov/assets/resources/templates/FedRAMP-Deviation-Request-Form-Template.docx — **FedRAMP Deviation Request Form (template)**:
  Lists the explicit field set. B.B3's `CreateAcceptanceBody` interface mirrors these fields 1:1; the tracker UI's create-form renders these labels.

- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf — **FIPS 186-5 (Digital Signature Standard)**: Ed25519 is the algorithm B.B3 uses to sign acceptance records; same Ed25519 key pipeline as `core/sign.ts`. Verifiers reuse the existing key-id resolution.

- https://datatracker.ietf.org/doc/html/rfc8785 — **RFC 8785 (JSON Canonicalization Scheme)**: B.B3 canonicalises the acceptance payload BEFORE signing so signatures are stable across re-serialization.

## Files to create (exact paths)

### Tracker server (Express + better-sqlite3)
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/risk-acceptance.ts` — Express route handler. Endpoints:
  - `POST /api/risk-acceptances` — create pending acceptance.
  - `GET  /api/risk-acceptances` — list (filterable by status, ksi_id, expiration window).
  - `GET  /api/risk-acceptances/:id` — detail view + audit history.
  - `POST /api/risk-acceptances/:id/approve` — AO approval (requires `ao` role + second signature).
  - `POST /api/risk-acceptances/:id/revoke` — revoke (any iso/ao; records reason + signature).
  - `POST /api/risk-acceptances/:id/expire` — admin-only manual expire (in addition to enforcer).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/risk-acceptance-enforcer.ts` — recurring task (run on server boot + every hour via `setInterval`) that scans `risk_acceptances` for `status='approved' AND expiration_date < now()`, transitions status to `expired`, and writes an `audit_log` row per expiration.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/risk-acceptance-sign.ts` — sign / verify helper: canonicalises payload via RFC 8785 + signs with the tracker's resident Ed25519 key (re-uses `tracker/server/sign.ts`).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/risk-acceptance.test.ts` — Vitest route tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/risk-acceptance-enforcer.test.ts` — enforcer tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/risk-acceptance-sign.test.ts` — signing tests.

### Tracker client (Vite + React + React Router)
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/RiskAcceptance.tsx` — list view, filter sidebar, "create new" CTA (visible only if user has `iso` or higher role).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/RiskAcceptanceCreate.tsx` — create form: finding picker, justification textarea (min 100 chars enforced client + server), expiration date picker (7-365 day window), compensating-control multi-select (sourced from B.B4 registry; placeholder until B.B4 ships), acceptance-type radio.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/RiskAcceptanceDetail.tsx` — per-acceptance detail with signed-audit-record display, approval CTA (visible only if user has `ao` role and status='pending'), revoke CTA.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/RiskAcceptance.test.tsx` — UI tests (Testing Library + Vitest).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/RiskAcceptanceCreate.test.tsx` — form validation tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/RiskAcceptanceDetail.test.tsx` — detail / approval flow tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/lib/risk-acceptance-api.ts` — typed fetch client (called by all three pages).

### cloud-evidence side
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/risk-acceptance-reader.ts` — read-only client the POA&M emitter uses:
  - `pullActiveAcceptances(trackerUrl, apiToken, outDir): Promise<PulledAcceptance[]>` — HTTP GET → verify every record's Ed25519 signature against the tracker's public key → write `out/.risk-acceptances.json` snapshot.
  - `loadCachedAcceptances(outDir): PulledAcceptance[]` — read snapshot, no network.
  - `activeAcceptanceFor(ksiId, rule, provider, list): PulledAcceptance | null` — lookup helper.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/risk-acceptance-reader.test.ts` — reader tests.

## Files to extend

### Tracker
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — append the two tables described in **Schemas / standards**.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount the route:
  ```ts
  import { riskAcceptanceRouter } from './routes/risk-acceptance.js';
  app.use('/api/risk-acceptances', requireAuth, riskAcceptanceRouter);
  // Boot the enforcer
  startRiskAcceptanceEnforcer(db);
  ```
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/rbac.ts` — add role permissions:
  - `iso` (Information System Owner) can create + revoke acceptances.
  - `ao` (Authorizing Official) can approve.
  - `assessor` (3PAO) can view (read-only).
  - `admin` retains all.
  Add new role constants if not already present; document in `tracker/README.md`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add routes:
  ```tsx
  <Route path="/risk-acceptance" element={<RiskAcceptance/>} />
  <Route path="/risk-acceptance/new" element={<RiskAcceptanceCreate/>} />
  <Route path="/risk-acceptance/:id" element={<RiskAcceptanceDetail/>} />
  ```
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/components/NavBar.tsx` — add "Risk Acceptances" nav link (conditional on `iso`/`ao`/`assessor` role).

### cloud-evidence
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts`:
  - Load `out/.risk-acceptances.json` at build time (graceful absence: empty list).
  - In `buildOscalPoam()`, after computing per-finding deadline (B.B2's `computeDeadline`), look up `activeAcceptanceFor(ksiId, f.rule, prov.provider, acceptances)`.
  - If a match exists:
    - Set `risk.status = 'deviation-approved'`.
    - Override `risk.deadline` to `acceptance.expiration_date`.
    - Append props: `acceptance-uuid`, `acceptance-type`, `acceptance-justification` (truncated to 240 chars), `acceptance-approved-by` (user id), `acceptance-approved-at`, `compensating-control-uuid` (one prop per linked CC), `deadline-source = "operator-override"`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`:
  - New `--pull-risk-acceptances <tracker-url>` flag + env `CLOUD_EVIDENCE_TRACKER_URL`.
  - New `--tracker-api-token <token>` flag + env `CLOUD_EVIDENCE_TRACKER_TOKEN`.
  - When set, calls `pullActiveAcceptances()` BEFORE `--oscal-poam`. When unset, POA&M emitter still loads any cached snapshot at `out/.risk-acceptances.json` (so air-gapped runs work).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add role `risk-acceptances-snapshot` (filename `.risk-acceptances.json`).

## Schemas / standards

### SQLite tables (appended to `tracker/server/schema.sql`)

```sql
CREATE TABLE IF NOT EXISTS risk_acceptances (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,                       -- v4 uuid; written to OSCAL acceptance-uuid prop
  finding_uuid TEXT NOT NULL,                      -- matches oscal finding.uuid
  poam_item_uuid TEXT NOT NULL,                    -- matches oscal poam-item.uuid
  ksi_id TEXT NOT NULL,                            -- e.g. KSI-IAM-MFA
  rule TEXT NOT NULL,                              -- e.g. iam-mfa-aws-root
  provider TEXT NOT NULL,                          -- aws | gcp | azure
  accepted_by_user_id INTEGER NOT NULL REFERENCES users(id),
  accepted_at TEXT NOT NULL,                       -- ISO datetime
  expiration_date TEXT NOT NULL,                   -- ISO datetime; ≥ now+7d AND ≤ now+365d
  business_justification TEXT NOT NULL,            -- min 100 chars (server-enforced)
  acceptance_type TEXT NOT NULL CHECK (acceptance_type IN ('deviation-request','risk-adjustment','false-positive','operational-requirement')),
  status TEXT NOT NULL CHECK (status IN ('pending','approved','expired','revoked')),
  approved_by_user_id INTEGER REFERENCES users(id),
  approved_at TEXT,
  signature TEXT NOT NULL,                         -- base64 Ed25519 signature of canonical-JSON payload
  signing_key_id TEXT NOT NULL,                    -- maps to tracker's resident key registry
  approval_signature TEXT,                         -- second signature over (uuid, approved_by_user_id, approved_at)
  approval_signing_key_id TEXT,
  revoked_at TEXT,
  revoked_by_user_id INTEGER REFERENCES users(id),
  revocation_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_ra_finding ON risk_acceptances(finding_uuid);
CREATE INDEX IF NOT EXISTS idx_ra_poam_item ON risk_acceptances(poam_item_uuid);
CREATE INDEX IF NOT EXISTS idx_ra_status ON risk_acceptances(status);
CREATE INDEX IF NOT EXISTS idx_ra_expiration ON risk_acceptances(expiration_date);
CREATE INDEX IF NOT EXISTS idx_ra_ksi ON risk_acceptances(ksi_id);

CREATE TABLE IF NOT EXISTS risk_acceptance_compensating_links (
  acceptance_id INTEGER NOT NULL REFERENCES risk_acceptances(id) ON DELETE CASCADE,
  compensating_control_uuid TEXT NOT NULL,         -- foreign UUID to B.B4 registry
  PRIMARY KEY (acceptance_id, compensating_control_uuid)
);
CREATE INDEX IF NOT EXISTS idx_ra_cc_acceptance ON risk_acceptance_compensating_links(acceptance_id);
```

### Wire-format types

```ts
// tracker/server/routes/risk-acceptance.ts
export interface CreateAcceptanceBody {
  finding_uuid: string;
  poam_item_uuid: string;
  ksi_id: string;
  rule: string;
  provider: string;
  expiration_date: string;                         // ISO datetime
  business_justification: string;
  acceptance_type: 'deviation-request' | 'risk-adjustment' | 'false-positive' | 'operational-requirement';
  compensating_control_uuids: string[];
}

export interface ApproveAcceptanceBody {
  approval_notes?: string;
}

export interface RevokeAcceptanceBody {
  revocation_reason: string;                       // min 30 chars
}

// cloud-evidence/core/risk-acceptance-reader.ts
export interface PulledAcceptance {
  uuid: string;
  finding_uuid: string;
  poam_item_uuid: string;
  ksi_id: string;
  rule: string;
  provider: string;
  accepted_by_user_id: number;
  accepted_at: string;
  expiration_date: string;
  business_justification: string;
  acceptance_type: 'deviation-request' | 'risk-adjustment' | 'false-positive' | 'operational-requirement';
  status: 'pending' | 'approved' | 'expired' | 'revoked';
  approved_by_user_id: number | null;
  approved_at: string | null;
  signature: string;
  signing_key_id: string;
  approval_signature: string | null;
  approval_signing_key_id: string | null;
  compensating_control_uuids: string[];
}
```

### OSCAL POA&M v1.1.2 prop emissions
Namespace `CE_NS = "https://cloud-evidence.example/oscal-ns"` (already declared in `core/oscal-poam.ts`). Props attached when an active acceptance exists:
- `acceptance-uuid` — the acceptance row UUID.
- `acceptance-type` — one of `deviation-request | risk-adjustment | false-positive | operational-requirement`.
- `acceptance-justification` — first 240 chars (truncated; full text lives in the tracker, link via `acceptance-uuid`).
- `acceptance-approved-by` — user id of the AO.
- `acceptance-approved-at` — ISO datetime of approval.
- `compensating-control-uuid` — one prop per linked compensating control (B.B4 registry).
- `deadline-source` — overrides B.B2's emission to `operator-override`.

## Build steps (concrete, numbered)

1. **Add schema** — open `tracker/server/schema.sql`, append the two CREATE TABLE statements + indexes. The `schema.sql` model in this repo is "single file, idempotent CREATE IF NOT EXISTS" — no migrations directory.

2. **Server route module** — write `tracker/server/routes/risk-acceptance.ts`:
   - Use `better-sqlite3` prepared statements.
   - All handlers run inside `requireAuth`; per-handler RBAC enforced via existing `requireRole(['iso','ao','admin'])` middleware (extend `rbac.ts` if `iso`/`ao` roles aren't already defined).
   - Validate `CreateAcceptanceBody` with the existing `zod` schema pattern (mirror `tracker/server/routes/items.ts` for tone).
   - Enforce:
     - `expiration_date` ≥ now + 7 days (operators can't accept for "today only").
     - `expiration_date` ≤ now + 365 days (FedRAMP annual review).
     - `business_justification.length >= 100`.
     - `acceptance_type === 'deviation-request' ⇒ compensating_control_uuids.length >= 1`.
     - User role in `{iso, admin}` for create; `{ao, admin}` for approve; `{iso, ao, admin}` for revoke.

3. **Signing**:
   - Canonicalise the payload `{finding_uuid, accepted_by_user_id, accepted_at, expiration_date, business_justification, acceptance_type, compensating_control_uuids}` via `rfc8785.canonicalize()` (use the existing `canonical-json` helper if present, else add as a thin wrapper).
   - Sign with the tracker's resident Ed25519 key from `tracker/server/sign.ts` (same key pipeline `core/sign.ts` uses for evidence-side signatures).
   - Store base64 signature + `signing_key_id` on the row. The signature IS the audit record — re-verification is anyone's read.

4. **Approval flow**:
   - `POST /:id/approve` requires `ao` role.
   - Server canonicalises `{acceptance_uuid: uuid, approved_by_user_id: req.user.id, approved_at: nowIso}` and signs as `approval_signature`. Same key, separate signature.
   - Transition `status: pending → approved`. Reject if current status ≠ `pending`.
   - Write `audit_log` row `{event: 'risk-acceptance-approved', acceptance_uuid, approved_by, approved_at}`.

5. **Revoke flow** — `POST /:id/revoke` records `revoked_at`, `revoked_by_user_id`, `revocation_reason` (min 30 chars). Status → `revoked`. The POA&M emitter excludes revoked rows.

6. **Enforcer task** — `tracker/server/risk-acceptance-enforcer.ts`:
   ```ts
   export function startRiskAcceptanceEnforcer(db: Database): NodeJS.Timeout {
     runOnce(db);
     return setInterval(() => runOnce(db), 60 * 60 * 1000);  // every hour
   }
   function runOnce(db: Database): void {
     const expired = db.prepare(`
       SELECT id, uuid, finding_uuid FROM risk_acceptances
       WHERE status = 'approved' AND expiration_date < ?
     `).all(nowIso()) as Array<{ id: number; uuid: string; finding_uuid: string }>;
     for (const row of expired) {
       db.prepare(`UPDATE risk_acceptances SET status='expired' WHERE id=?`).run(row.id);
       writeAuditLog(db, { event: 'risk-acceptance-expired', acceptance_uuid: row.uuid, finding_uuid: row.finding_uuid, at: nowIso() });
     }
   }
   ```

7. **React UI**:
   - `RiskAcceptance.tsx` — call `GET /api/risk-acceptances?status=...`; render a table with columns: Finding KSI, Rule, Provider, Status, Expiration, Acceptance Type, Linked CCs. Filter sidebar. "New Acceptance" CTA if user role permits.
   - `RiskAcceptanceCreate.tsx` — form with:
     - Finding picker (autocomplete sourced from the existing items API filtered to failing findings).
     - Justification textarea with live character count (red-tint until ≥ 100).
     - Expiration date picker (HTML `<input type="date">`); client-side validation 7-365 days from today.
     - Acceptance-type radio.
     - Compensating-controls multi-select (sourced from `/api/compensating-controls?status=active`; placeholder list with "B.B4 not yet shipped" notice if endpoint 404s).
     - Submit → POST → on success, redirect to detail page.
   - `RiskAcceptanceDetail.tsx` — read-only display + signed-payload viewer (renders the canonical-JSON payload + signature + signing-key-id; a "Verify signature" button calls a `/api/risk-acceptances/:id/verify` endpoint for re-verification). "Approve" CTA visible only to `ao` role + status='pending'. "Revoke" CTA visible to `iso`/`ao`/`admin`.

8. **cloud-evidence reader** — `core/risk-acceptance-reader.ts`:
   ```ts
   export async function pullActiveAcceptances(
     trackerUrl: string,
     apiToken: string,
     outDir: string,
   ): Promise<PulledAcceptance[]> {
     const res = await fetch(`${trackerUrl}/api/risk-acceptances?status=approved`, {
       headers: { 'Authorization': `Bearer ${apiToken}` },
     });
     if (!res.ok) throw new RiskAcceptanceFetchError(res.status, await res.text());
     const data = await res.json() as { items: PulledAcceptance[]; public_key: string };
     for (const acc of data.items) {
       verifyAcceptanceSignature(acc, data.public_key);  // throws on bad sig
     }
     const snapshotPath = path.join(outDir, '.risk-acceptances.json');
     await writeCanonicalJson(snapshotPath, { fetched_at: nowIso(), items: data.items, public_key: data.public_key });
     return data.items;
   }
   ```

9. **OSCAL POA&M integration** — extend `core/oscal-poam.ts:buildOscalPoam()`:
   ```ts
   const acceptances = loadCachedAcceptances(opts.outDir);
   // ... within the per-finding loop:
   const acc = activeAcceptanceFor(ksiId, f.rule, prov.provider, acceptances);
   if (acc) {
     riskStatus = 'deviation-approved';
     overrideDeadline = acc.expiration_date;
     extraProps.push(
       { name: 'acceptance-uuid', ns: CE_NS, value: acc.uuid },
       { name: 'acceptance-type', ns: CE_NS, value: acc.acceptance_type },
       { name: 'acceptance-justification', ns: CE_NS, value: acc.business_justification.slice(0, 240) },
       { name: 'acceptance-approved-by', ns: CE_NS, value: String(acc.approved_by_user_id) },
       { name: 'acceptance-approved-at', ns: CE_NS, value: acc.approved_at ?? '' },
       { name: 'deadline-source', ns: CE_NS, value: 'operator-override' },
     );
     for (const ccUuid of acc.compensating_control_uuids) {
       extraProps.push({ name: 'compensating-control-uuid', ns: CE_NS, value: ccUuid });
     }
   }
   ```

10. **Bundler integration** — `submission-bundle.ts`:
    ```ts
    { role: 'risk-acceptances-snapshot', filename: '.risk-acceptances.json', description: 'Signed risk-acceptance snapshot (LOOP-B.B3)' },
    ```

11. **Validation pass**:
    - Re-emit POA&M → run through `core/oscal-validate.ts` → must still pass v1.1.2 ajv (new props in `CE_NS` are schema-legal).
    - Run `check:provenance` on `.risk-acceptances.json` snapshot (top-level provenance block: emitter, fetched_at, tracker_url, signing_key_id, source).

12. **Signed + timestamped** by existing `core/sign.ts` pipeline — `.risk-acceptances.json` is captured in the manifest glob.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

| Field | Source | Behavior when missing |
|---|---|---|
| `business_justification` | Tracker create-form (operator types) | Server rejects POST with 400 if < 100 chars; no default text ever inserted. |
| `expiration_date` | Tracker create-form | Server rejects if outside [now+7d, now+365d]; no default. |
| `compensating_control_uuids` | Tracker create-form multi-select (sourced from B.B4 registry) | When `acceptance_type='deviation-request'`, server rejects empty array. |
| `approved_by_user_id` | Tracker AO approval action | Acceptance stays `pending`; OSCAL emitter ignores pending acceptances (only `approved` propagate to `deviation-approved`). |
| Tracker URL + API token | CLI flag / env (`--pull-risk-acceptances`, `--tracker-api-token`) | When unset, cloud-evidence side falls back to cached `out/.risk-acceptances.json` snapshot; if absent, emits no acceptance props (every risk remains `open`) — observable, never silent. |

## Test specifications (≥18 tests)

### Server-side route tests (`tracker/server/routes/risk-acceptance.test.ts`)
1. `it('creates a pending acceptance when iso submits valid body')` — assert row inserted, signature non-empty, status='pending'.
2. `it('rejects expiration_date < 7 days from now')` — POST → 400 with specific error message.
3. `it('rejects expiration_date > 365 days from now')` — POST → 400.
4. `it('rejects justification < 100 chars')` — POST → 400.
5. `it('rejects when user lacks iso role')` — assessor user → POST → 403.
6. `it('rejects deviation-request type with empty compensating_control_uuids')` — POST → 400.
7. `it('signs the canonical JSON with the tracker Ed25519 key')` — signature verifies against the public key.
8. `it('allows ao to transition pending → approved with second signature')` — approve endpoint → row's `status='approved'`, `approval_signature` non-empty, audit_log row written.
9. `it('rejects ao approval replay (uuid + approved_at must change)')` — POST same body twice → second attempt fails idempotency check.
10. `it('rejects non-ao user from approving')` — iso role → POST /approve → 403.
11. `it('allows revoke with reason ≥ 30 chars')` — sets `status='revoked'`, audit_log row.
12. `it('rejects revoke with reason < 30 chars')` — 400.
13. `it('RBAC: assessor can GET but cannot POST')` — GET /api/risk-acceptances → 200; POST → 403.
14. `it('GET /:id returns full signed payload including audit history')`.

### Enforcer tests (`tracker/server/risk-acceptance-enforcer.test.ts`)
15. `it('flips status to expired when expiration_date past for approved rows')`.
16. `it('does NOT touch pending or revoked rows')`.
17. `it('writes audit-log row on expiration')`.
18. `it('handles empty result set without errors')`.

### Signing tests (`tracker/server/risk-acceptance-sign.test.ts`)
19. `it('canonicalises payload deterministically across key order')`.
20. `it('signature verifies against published public key')`.
21. `it('detects tampered payload (signature verify returns false)')`.

### Reader tests (`cloud-evidence/tests/core/risk-acceptance-reader.test.ts`)
22. `it('pullActiveAcceptances writes .risk-acceptances.json with verified sigs')` — wire-layer HTTP mock per CLAUDE.md Rule 2.4.
23. `it('refuses to write snapshot for any record whose signature is invalid')` — single bad sig → throws, no snapshot written.
24. `it('loadCachedAcceptances reads previously-written snapshot')`.
25. `it('activeAcceptanceFor lookup matches by (ksi_id, rule, provider) tuple')`.
26. `it('activeAcceptanceFor filters out status != approved')`.
27. `it('activeAcceptanceFor filters out expiration_date < now()')`.

### POA&M integration tests (`cloud-evidence/tests/core/oscal-poam.test.ts` — extend existing)
28. `it('POA&M emitter flips risk.status to deviation-approved when active acceptance exists')`.
29. `it('POA&M emitter overrides risk.deadline with acceptance.expiration_date')`.
30. `it('POA&M emitter attaches acceptance-uuid + acceptance-type + compensating-control-uuid props')`.
31. `it('does NOT flip status when acceptance is pending (not yet approved)')`.
32. `it('does NOT flip status when acceptance is expired')`.

### UI tests (`tracker/client/src/pages/RiskAcceptance*.test.tsx`)
33. `it('renders create form with all required fields')`.
34. `it('disables submit until justification ≥ 100 chars')`.
35. `it('hides Approve CTA from non-ao users')`.

## REO compliance specific to this slice
- **Signatures are real Ed25519** over RFC-8785 canonical JSON. No mocked crypto in production paths. The tracker's resident key is the same Ed25519 key the existing `tracker/server/sign.ts` exposes (key-id provenance recorded in `signing_key_id` column).
- **`business_justification` is verbatim operator input** — never auto-populated; server enforces minimum length.
- **AO approval requires the `ao` role**; the system never auto-approves. Each approval generates an `approval_signature` over `(uuid, approved_by_user_id, approved_at)` so the audit trail is non-repudiable.
- **`deviation-approved` only propagates to OSCAL when a signed, approved, unexpired record exists** — the lookup explicitly filters `status='approved' AND expiration_date > now()`.
- **Provenance block on `.risk-acceptances.json`** populated with: emitter name, fetched_at, tracker_url, public_key_fingerprint, item count.
- **Signed by existing `core/sign.ts` pipeline** (Ed25519 + RFC 3161 timestamp) — `.risk-acceptances.json` lands in the manifest glob.
- **No silent fallbacks**: if the tracker is unreachable AND no cached snapshot exists, the POA&M emitter logs `risk-acceptance:missing-snapshot` and emits zero acceptance props — every risk stays `open`. Visible to `check:reo`.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/risk-acceptance-reader.test.ts tests/core/oscal-poam.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs

cd /Users/kenith.philip/FedRAMP\ 20x/tracker
npm run typecheck
npm test -- server/routes/risk-acceptance.test.ts server/risk-acceptance-enforcer.test.ts server/risk-acceptance-sign.test.ts client/src/pages/RiskAcceptance.test.tsx client/src/pages/RiskAcceptanceCreate.test.tsx client/src/pages/RiskAcceptanceDetail.test.tsx
```

## Known risks / issues
- **Risk 1: Cross-repo signing-key drift.** The tracker has its own Ed25519 key; cloud-evidence has its own. B.B3 reader verifies tracker signatures using the tracker's published public key (returned alongside the items in the GET response). If the tracker rotates keys without publishing the rotation event, verification fails for snapshots written under the old key. Mitigation: tracker exposes `GET /api/sign/public-keys` returning ALL historical public keys with `key_id`; reader cross-references by `signing_key_id` on each record.
- **Risk 2: Schema migration on existing tracker DBs.** The `CREATE TABLE IF NOT EXISTS` idempotency works for fresh DBs, but existing tracker installs have user data — the columns must be additive only. Mitigation: this slice ONLY adds tables (no ALTER TABLE on existing); user `rbac.ts` extensions add new role constants only, no removal.
- **Risk 3: AO approval signature replay.** Without per-approval nonces, an attacker with the AO's signing material could replay. Mitigation: the `approval_signature` payload includes `approved_at` (server-set, monotonic) + `uuid` (unique per acceptance); same approval cannot be issued twice without a fresh `approved_at`. Server rejects approval if `status ≠ 'pending'`.
- **Risk 4: Enforcer drift.** If the server is down at the expected expiration moment, an acceptance lingers `approved` past expiration until the next boot. Mitigation: the `activeAcceptanceFor` lookup in cloud-evidence side also enforces `expiration_date > now()`; the OSCAL emitter never propagates an actually-expired acceptance even if the DB row hasn't been transitioned yet.
- **Risk 5: Compensating-control UUID references precede B.B4 ship.** Mitigation: the create form's multi-select gracefully degrades when `/api/compensating-controls` 404s — operator can paste UUIDs as free text with a UI warning; B.B4 ships the registry and references resolve cleanly.
- **Risk 6: Justification truncation could hide critical context from the OSCAL prop.** Mitigation: full text remains in tracker DB; the `acceptance-uuid` prop is the link; the 240-char truncation is documented.
- **Risk 7: RBAC mis-configuration.** A user with the wrong role could create or approve acceptances. Mitigation: each route's `requireRole` middleware is unit-tested; the tracker's existing `audit_log` table records every role-checked action.
- **Risk 8: HTTP fetch from cloud-evidence to tracker is a new cross-system dependency.** Mitigation: the reader falls back to the cached `out/.risk-acceptances.json` when the tracker URL is unset OR unreachable; air-gapped runs explicitly supported.

## Open questions (for implementation session to resolve)
- **Q1**: Should the AO approval require a second-factor (TOTP) prompt at approval time, in addition to the role check? Recommend: yes, as a follow-up enhancement; for B.B3 ship, the existing session-auth + role check + signature audit trail is sufficient. File as follow-up.
- **Q2**: Should the tracker auto-create a corresponding tracker `item` linked to the acceptance, so the SO can see all acceptance decisions in their item view? Recommend: yes — add `tracker_item_uuid` column or use the existing `audit_log` for cross-linking.
- **Q3**: What happens to an acceptance when its underlying finding disappears from the next collection run (because the issue was actually fixed)? Recommend: enforcer detects "orphaned" acceptances and surfaces them in the tracker UI as a stale review item; out of scope for B.B3 ship but file as follow-up.
- **Q4**: The reader writes `.risk-acceptances.json` to `outDir`. Is `outDir` always present when the orchestrator invokes the reader? Verify against the existing orchestrator flow.
- **Q5**: How does the React UI handle pagination when there are thousands of acceptances? Recommend: server-side pagination with `?limit=50&offset=N`; React list uses infinite scroll. Pattern mirrors existing `Items.tsx`.
- **Q6**: Should we emit the acceptance's `business_justification` as an OSCAL `risk.description` field instead of (or in addition to) a `acceptance-justification` prop? OSCAL spec defines `risk.description` as a free-text narrative. Recommend: also append to `risk.description` (with the existing severity description) so the artifact is human-readable without consulting the props.
- **Q7**: Should the `revocation_reason` flow into OSCAL when a once-approved acceptance is revoked? Recommend: include via prop `acceptance-revocation-reason` on the affected risk (now back to `status='open'`).

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (both `cloud-evidence` AND `tracker` workspaces)
- [ ] tests passing 100% (cloud-evidence count increased by ≥6 for reader/POA&M; tracker count increased by ≥30 for routes/enforcer/sign/UI)
- [ ] check:reo green (G1+G2+G3) in cloud-evidence
- [ ] STATUS.md updated (B.B3 row + Overall section)
- [ ] LOOP-B-SPEC.md status table updated (Section 7)
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with slice ID `LOOP-B.B3: <title>` in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-B-SPEC.md
- [ ] Pushed to origin/main
- [ ] Tracker schema migration verified on a fresh DB (`rm tracker/data/dev.db && npm run dev` boots cleanly)
- [ ] Tracker schema migration verified on an existing DB with prior user data (no data loss)

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: full schema + routes + UI + reader + POA&M integration + tests + risks.
3. Read `cloud-evidence/docs/loops/LOOP-B-SPEC.md` Section 2 (Dependencies) + Section 4 §B.B3.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the 7-step commit pattern.
5. Read `cloud-evidence/core/oscal-poam.ts` — `buildOscalPoam()` is your extension point; `findingProps()` line 377 is where new props attach.
6. Read `tracker/server/schema.sql` — append new tables at the end.
7. Read `tracker/server/index.ts` — see how other routes mount; mirror the pattern.
8. Read `tracker/server/sign.ts` — re-use the Ed25519 key resolver.
9. Read `tracker/server/rbac.ts` — extend with `iso`/`ao` constants if absent.
10. Read `tracker/client/src/App.tsx` — see how routes register.
11. Read existing `tracker/client/src/pages/Items.tsx` as a UI pattern reference.
12. Begin implementation; update Implementation log as you go.

---
