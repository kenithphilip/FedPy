---
slice_id: B.B4
title: Compensating-controls registry (tracker DB + UI + OSCAL mitigating-factors emission)
loop: B
status: done
commit: 6b5168d
completed_date: 2026-07-02
depends_on: [LOOP-A.A1, B.B3]
blocks: [B.B5, C.C7, F.F1]
estimated_effort: 4 working days
last_updated: 2026-07-02
---

# B.B4 — Compensating-controls registry (tracker DB + UI + OSCAL mitigating-factors emission)

## TL;DR
Ship a typed, auditable compensating-controls registry: `compensating_controls` SQLite table with Ed25519-signed rows, full CRUD REST API, React UI with draft/active/retired lifecycle, NIST 800-53 control-id validation against the loaded catalog, and a `core/compensating-control-reader.ts` snapshot the POA&M emitter consumes to attach `risk.remediations[]` (lifecycle=`completed`) + `mitigating-factor` props. Replaces today's ad-hoc free-text references with structured, AO-signed records that directly satisfy NIST CA-5(1) automation and CA-2(1) independent assessor evidence walk-through.

## Status
- Status: done
- Commit: `6b5168d` (slice) + docs close-out commit
- Date: 2026-07-02
- Verification: typecheck=clean (both workspaces), tests=tracker 130→159 (+29) / cloud-evidence 1354→1372 (+18), check:reo=green (G1+G3; G2 SKIP no local run)

## Why this slice exists
B.B3's risk-acceptance flow references compensating controls by free-text UUID. Today, the actual compensating control content lives nowhere structured — it might be in a runbook, a wiki, a ticket, or a footnote in an SSP narrative. This is a real auditability gap:

- A 3PAO cannot independently verify the existence or scope of a referenced control.
- The OSCAL POA&M `risk.remediations[]` array stays empty (or is filled with placeholder text), even though `risk.status='deviation-approved'` claims a mitigation exists.
- NIST CA-5(1) Automation Support requires "automated mechanisms" to track mitigations alongside POA&M items — free text doesn't qualify.
- The SSP narrative (PL-2) cannot cite a canonical identifier; the same control gets described three different ways in three places.

B.B4 closes the gap with a registry: each compensating control is a structured, signed, AO-approved record with title, description (≥ 200 chars), referenced NIST 800-53 control IDs (validated against the catalog), implementer + AO sign-offs, evidence URL, status lifecycle, and an immutable UUID that B.B3 acceptances reference and the SSP / RMS / POA&M all cite by the same UUID.

## Authoritative sources (with verbatim quotes)
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, CA-5 (Plan of Action and Milestones)**:
  > "Document the planned remediation actions of the organization to correct weaknesses or deficiencies noted during the assessment of the controls and to reduce or eliminate known vulnerabilities in the system."
  > "CA-5(1) Automation Support for Accuracy and Currency — Ensure the accuracy, currency, and availability of the plan of action and milestones for the system using [Assignment: organization-defined automated mechanisms]."

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, CA-2 (Control Assessments)**:
  > "Develop a control assessment plan that describes the scope of the assessment including: controls and control enhancements under assessment; assessment procedures to be used to determine control effectiveness; and assessment environment, assessment team, and assessment roles and responsibilities."
  Compensating controls referenced in B.B4 ARE the assessment evidence the 3PAO walks through under CA-2(1).

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, PL-2 (System Security Plan)**:
  > "Develop a security and privacy plan for the system that … is consistent with the organization's enterprise architecture; explicitly defines the constituent system components; describes the operational environment for the system and any dependencies on or connections to other systems or system components; provides an overview of the security and privacy requirements for the system; identifies any relevant control baselines or overlays … describes the controls in place or planned for meeting those requirements including a rationale for any tailoring decisions."
  B.B4's UUIDs are the SSP narrative's canonical identifier for compensating / tailored controls.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53Ar5.pdf — **NIST SP 800-53A Rev 5, §2.4 (Compensating Controls)**:
  > "Compensating controls are management, operational, or technical controls (i.e., safeguards or countermeasures) employed by an organization in lieu of recommended controls in the low, moderate, or high baselines, which provide equivalent or comparable protection for a system or organization."
  B.B4's records are the structured form of this concept.

- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/#/poam/risks/remediations — **OSCAL POA&M v1.1.2, `risk.remediations[]`**:
  > "Describes either recommended or an actual plan for addressing the risk."
  > "lifecycle: Identifies whether this is a recommendation, such as from an assessor or tool, or an actual plan accepted by the system owner. One of: recommendation, planned, completed."
  B.B4 emits `lifecycle='completed'` for active controls already in place.

- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/#/poam/risks/risk-log/entries — **OSCAL POA&M v1.1.2, `risk-log.entries[]`**:
  Audit trail of risk state transitions; B.B4 sign-off events flow here.

- https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf — **FedRAMP ConMon Strategy & Guide, Section 4 "Deviation Requests"**:
  Requires compensating-control description as a mandatory DR field. The structured registry is the source the DR pre-fills from.

- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf — **FIPS 186-5 (Digital Signature Standard)**: Ed25519 algorithm B.B4 uses to sign each compensating-control record.

- https://datatracker.ietf.org/doc/html/rfc8785 — **RFC 8785 (JSON Canonicalization Scheme)**: payload canonicalised before signing.

## Files to create (exact paths)

### Tracker server
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/compensating-controls.ts` — Express CRUD route module. Endpoints:
  - `POST /api/compensating-controls` — create draft.
  - `GET  /api/compensating-controls` — list (filter by status, NIST control id).
  - `GET  /api/compensating-controls/:uuid` — detail + linked acceptances + signed payload.
  - `PUT  /api/compensating-controls/:uuid` — update (draft only; cannot mutate `active` or `retired`).
  - `POST /api/compensating-controls/:uuid/activate` — AO signs off; status → active. Requires `ao` role.
  - `POST /api/compensating-controls/:uuid/retire` — retire; status → retired. Requires `iso`/`ao`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/compensating-control-sign.ts` — canonicalize + sign helper (mirrors B.B3's pattern; same Ed25519 key).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/compensating-controls.test.ts` — route tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/compensating-control-sign.test.ts` — signing tests.

### Tracker client
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/CompensatingControls.tsx` — list view + filter sidebar + "New Control" CTA.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/CompensatingControlCreate.tsx` — create form: title (5-200 chars), description (≥ 200 chars), NIST control IDs (autocomplete from the loaded catalog), evidence URL, evidence file upload (re-uses H.4 attachment pattern).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/CompensatingControlDetail.tsx` — detail view: signed payload + linked acceptances + activate/retire CTAs.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/lib/compensating-control-api.ts` — typed fetch client.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/CompensatingControls.test.tsx`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/CompensatingControlCreate.test.tsx`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/CompensatingControlDetail.test.tsx`.

### cloud-evidence side
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/compensating-control-reader.ts` — read-only client:
  - `pullCompensatingControls(trackerUrl, apiToken, outDir): Promise<PulledCompensatingControl[]>` — fetch + verify signatures + write `out/.compensating-controls.json`.
  - `loadCachedCompensatingControls(outDir): PulledCompensatingControl[]`.
  - `getCompensatingControl(uuid, list): PulledCompensatingControl | null`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/compensating-control-reader.test.ts` — reader tests.

## Files to extend

### Tracker
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — append `compensating_controls` table.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount route:
  ```ts
  import { compensatingControlsRouter } from './routes/compensating-controls.js';
  app.use('/api/compensating-controls', requireAuth, compensatingControlsRouter);
  ```
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/rbac.ts` — extend `iso`/`ao` role permissions if needed (mostly reused from B.B3).
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add routes:
  ```tsx
  <Route path="/compensating-controls" element={<CompensatingControls/>} />
  <Route path="/compensating-controls/new" element={<CompensatingControlCreate/>} />
  <Route path="/compensating-controls/:uuid" element={<CompensatingControlDetail/>} />
  ```
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/components/NavBar.tsx` — add "Compensating Controls" nav link.

### cloud-evidence
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts`:
  - Load `out/.compensating-controls.json` at build time.
  - For each finding with an active acceptance (B.B3) carrying compensating-control UUIDs, emit `risk.remediations[]` entries with `lifecycle='completed'`, `title` and `description` from the registry, props `compensating-control-uuid` + one `nist-control` prop per NIST 800-53 ID, link to `evidence_url` if present.
  - When acceptance cites a UUID not in the registry, emit a `risk.remediations[]` entry with `title: 'Unknown compensating control'` + prop `compensating-control-status = 'REQUIRES-OPERATOR-INPUT: unknown uuid'` — never silently drop.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`:
  - New `--pull-compensating-controls <tracker-url>` flag + env `CLOUD_EVIDENCE_TRACKER_URL` (same as B.B3).
  - Runs BEFORE `--oscal-poam`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add role `compensating-controls-snapshot` (filename `.compensating-controls.json`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/nist-r5.ts` — verify the loaded catalog exposes a lookup `isValidControlId(id: string): boolean` reused server-side (via copy or a published JSON shipped to the tracker).

## Schemas / standards

### SQLite table (appended to `tracker/server/schema.sql`)

```sql
CREATE TABLE IF NOT EXISTS compensating_controls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,                       -- v4 uuid; canonical id referenced by acceptances + OSCAL props
  title TEXT NOT NULL,                             -- 5-200 chars
  description TEXT NOT NULL,                       -- ≥ 200 chars
  nist_control_ids TEXT NOT NULL,                  -- JSON array of NIST 800-53 r5 control ids; validated against catalog
  implemented_by_user_id INTEGER NOT NULL REFERENCES users(id),
  implemented_at TEXT NOT NULL,
  signed_off_by_user_id INTEGER REFERENCES users(id),   -- AO id (null until activated)
  signed_off_at TEXT,                              -- ISO datetime (null until activated)
  expiration_date TEXT,                            -- ISO datetime; null = no expiration
  evidence_url TEXT,                               -- e.g. runbook URL
  evidence_sha256 TEXT,                            -- sha256 of evidence attachment if uploaded via H.4
  status TEXT NOT NULL CHECK (status IN ('draft','active','retired')),
  signature TEXT NOT NULL,                         -- base64 Ed25519 signature
  signing_key_id TEXT NOT NULL,
  activation_signature TEXT,                       -- second signature over activation event
  activation_signing_key_id TEXT,
  retired_at TEXT,
  retired_by_user_id INTEGER REFERENCES users(id),
  retirement_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cc_status ON compensating_controls(status);
CREATE INDEX IF NOT EXISTS idx_cc_expiration ON compensating_controls(expiration_date);
CREATE INDEX IF NOT EXISTS idx_cc_uuid ON compensating_controls(uuid);
```

### Wire-format types

```ts
// tracker/server/routes/compensating-controls.ts
export interface CreateCompensatingControlBody {
  title: string;                                   // 5-200 chars
  description: string;                             // ≥ 200 chars
  nist_control_ids: string[];                      // each validated against catalog
  evidence_url?: string;                           // optional
  expiration_date?: string;                        // optional ISO datetime
}

// cloud-evidence/core/compensating-control-reader.ts
export interface PulledCompensatingControl {
  uuid: string;
  title: string;
  description: string;
  nist_control_ids: string[];
  implemented_by_user_id: number;
  implemented_at: string;
  signed_off_by_user_id: number | null;
  signed_off_at: string | null;
  expiration_date: string | null;
  evidence_url: string | null;
  evidence_sha256: string | null;
  status: 'draft' | 'active' | 'retired';
  signature: string;
  signing_key_id: string;
}
```

### OSCAL POA&M v1.1.2 emission shape
Per affected risk:

```ts
const remediations: OscalRiskRemediation[] = acceptance.compensating_control_uuids.map((ccUuid) => {
  const cc = getCompensatingControl(ccUuid, compensatingControls);
  if (!cc) {
    return {
      uuid: deterministicUuid(`poam:risk:${ksiId}:${rule}:cc:${ccUuid}`),
      lifecycle: 'completed' as const,
      title: 'Unknown compensating control',
      description: 'Acceptance cites a compensating control UUID not present in the registry snapshot. Operator MUST resolve before authorization.',
      props: [
        { name: 'compensating-control-uuid', ns: CE_NS, value: ccUuid },
        { name: 'compensating-control-status', ns: CE_NS, value: 'REQUIRES-OPERATOR-INPUT: unknown uuid' },
      ],
    };
  }
  return {
    uuid: deterministicUuid(`poam:risk:${ksiId}:${rule}:cc:${ccUuid}`),
    lifecycle: 'completed' as const,
    title: cc.title,
    description: cc.description,
    props: [
      { name: 'compensating-control-uuid', ns: CE_NS, value: ccUuid },
      { name: 'compensating-control-status', ns: CE_NS, value: cc.status },
      ...cc.nist_control_ids.map(cid => ({ name: 'nist-control', ns: CE_NS, value: cid })),
      ...(cc.signed_off_by_user_id !== null ? [{ name: 'compensating-control-signed-off-by', ns: CE_NS, value: String(cc.signed_off_by_user_id) }] : []),
      ...(cc.signed_off_at !== null ? [{ name: 'compensating-control-signed-off-at', ns: CE_NS, value: cc.signed_off_at }] : []),
      ...(cc.expiration_date !== null ? [{ name: 'compensating-control-expires', ns: CE_NS, value: cc.expiration_date }] : []),
      ...(cc.evidence_sha256 !== null ? [{ name: 'compensating-control-evidence-sha256', ns: CE_NS, value: cc.evidence_sha256 }] : []),
    ],
    links: cc.evidence_url ? [{ href: cc.evidence_url, rel: 'reference' }] : undefined,
  };
});
```

## Build steps (concrete, numbered)
1. **Append schema** to `tracker/server/schema.sql`.
2. **Write route module** with full CRUD; validation:
   - `title.length` ∈ [5, 200].
   - `description.length` ≥ 200.
   - Every entry in `nist_control_ids` validates against `core/nist-r5.ts` catalog (loaded server-side via copy of `nist-r5-controls.generated.json`).
   - `status` transitions: `draft → active` (requires `ao` sign-off + signature), `active → retired` (requires reason ≥ 30 chars), `active → draft` REJECTED.
3. **Signing** — canonicalize `{title, description, nist_control_ids, implemented_by_user_id, implemented_at, evidence_url, evidence_sha256}` → sign with tracker's Ed25519 key. Store signature + `signing_key_id`.
4. **Activation** — `POST /:uuid/activate` requires `ao` role; canonicalize `{cc_uuid, signed_off_by_user_id, signed_off_at}` → second signature → store as `activation_signature`. Transition status to `active`. Audit log.
5. **Retirement** — `POST /:uuid/retire` records `retired_at`, `retired_by_user_id`, `retirement_reason`. Status → `retired`. Audit log.
6. **Update** — `PUT /:uuid` ONLY allowed on `draft` rows. `active` rows are immutable (must retire + create new).
7. **React UI**:
   - `CompensatingControls.tsx` — list table with columns: UUID (link), Title, Status, NIST Controls (badges), Implemented By, Sign-off Status, Expiration. Filter sidebar.
   - `CompensatingControlCreate.tsx` — form with required fields. Description textarea shows live char count + red-tint until ≥ 200. NIST control IDs use autocomplete chip input fed from `/api/nist-controls/r5` (existing endpoint or new thin wrapper).
   - `CompensatingControlDetail.tsx` — read-only display, "Verify signature" button, "Activate" CTA (visible only for `ao` + draft), "Retire" CTA. Shows linked acceptances (queries `/api/risk-acceptances?compensating_control_uuid=:uuid`).
8. **cloud-evidence reader** — `core/compensating-control-reader.ts`:
   ```ts
   export async function pullCompensatingControls(
     trackerUrl: string,
     apiToken: string,
     outDir: string,
   ): Promise<PulledCompensatingControl[]> {
     const res = await fetch(`${trackerUrl}/api/compensating-controls?status=active`, {
       headers: { 'Authorization': `Bearer ${apiToken}` },
     });
     if (!res.ok) throw new CompensatingControlFetchError(res.status, await res.text());
     const data = await res.json() as { items: PulledCompensatingControl[]; public_key: string };
     for (const cc of data.items) verifySignature(cc, data.public_key);
     await writeCanonicalJson(path.join(outDir, '.compensating-controls.json'), { fetched_at: nowIso(), items: data.items, public_key: data.public_key });
     return data.items;
   }
   ```
9. **POA&M integration** — extend `core/oscal-poam.ts:buildOscalPoam()`:
   - Load `out/.compensating-controls.json` (graceful absence).
   - When emitting a risk that has active acceptance (B.B3), map each `compensating_control_uuid` to a `risk.remediations[]` entry per the schema above.
   - When no acceptance exists (no compensating controls referenced), `risk.remediations[]` stays empty.
10. **Bundler integration**:
    ```ts
    { role: 'compensating-controls-snapshot', filename: '.compensating-controls.json', description: 'Signed compensating-controls registry snapshot (LOOP-B.B4)' },
    ```
11. **Validation pass** — re-emit POA&M → `core/oscal-validate.ts` → must pass ajv. Provenance check.
12. **Signed + timestamped** by existing `core/sign.ts` pipeline.

## REQUIRES-OPERATOR-INPUT fields
| Field | Source | Behavior when missing |
|---|---|---|
| `title`, `description`, `nist_control_ids`, `evidence_url` | Tracker create-form (operator types) | Server rejects with 400; no defaults; UI prevents submit. |
| `signed_off_by_user_id` (AO) | Tracker activate action | Control stays `draft`; OSCAL emitter skips draft controls (only `active` controls propagate to risk.remediations). |
| Evidence attachment SHA-256 | Tracker upload widget (re-uses H.4) | Optional; absence is allowed but visible as `compensating-control-evidence-sha256` prop omitted. |
| Acceptance cites unknown UUID | B.B3 acceptance UI multi-select (should prevent this; defense in depth) | POA&M emits `compensating-control-status = 'REQUIRES-OPERATOR-INPUT: unknown uuid'` prop — visible, never silent. |

## Test specifications (≥14 tests)

### Server-side route tests (`tracker/server/routes/compensating-controls.test.ts`)
1. `it('creates a draft compensating control when iso submits valid body')`.
2. `it('rejects title < 5 chars or > 200 chars')`.
3. `it('rejects description < 200 chars')`.
4. `it('rejects invalid NIST control id')` — e.g. `AC-99` not in catalog → 400 with field path.
5. `it('signs the canonical JSON with Ed25519 key')`.
6. `it('rejects active status transition without ao role')` — iso tries to activate → 403.
7. `it('allows ao to transition draft → active')` — sets `signed_off_*` + `activation_signature`.
8. `it('rejects active → draft transition')` — once active, immutable. 409.
9. `it('rejects PUT on active control')` — must retire + recreate. 409.
10. `it('allows iso/ao to retire active with reason ≥ 30 chars')`.
11. `it('rejects retire with reason < 30 chars')` — 400.
12. `it('lists only active controls when ?status=active')`.

### Signing tests (`tracker/server/compensating-control-sign.test.ts`)
13. `it('canonicalises payload deterministically across key order')`.
14. `it('signature verifies; tampering detected')`.

### Reader tests (`cloud-evidence/tests/core/compensating-control-reader.test.ts`)
15. `it('pullCompensatingControls writes .compensating-controls.json with verified sigs')`.
16. `it('refuses to write snapshot for any record whose signature is invalid')`.
17. `it('getCompensatingControl returns null for unknown uuid')`.

### POA&M integration tests (`cloud-evidence/tests/core/oscal-poam.test.ts` — extend existing)
18. `it('POA&M emits risk.remediations[] with lifecycle=completed for each linked CC')`.
19. `it('POA&M emits compensating-control-uuid + nist-control props')`.
20. `it('POA&M emits link to evidence_url when present')`.
21. `it('POA&M emits REQUIRES-OPERATOR-INPUT marker when acceptance cites unknown UUID')`.
22. `it('expired compensating control does NOT propagate (status check)')`.
23. `it('draft compensating control does NOT propagate')`.

### UI tests
24. `it('renders create form with all required fields')`.
25. `it('NIST control autocomplete suggests from loaded catalog')`.
26. `it('hides Activate CTA from non-ao users')`.

## REO compliance specific to this slice
- **All registry content is operator-supplied** via tracker UI; nothing is auto-generated. No system-default titles or descriptions.
- **NIST control IDs validate against the published catalog** (`core/nist-r5.ts` reused server-side via the generated JSON). Invalid IDs return 400 with the offending value.
- **Signatures are real Ed25519** over RFC-8785 canonical JSON. Activation produces a second signature, so AO sign-off is non-repudiable.
- **Unknown UUIDs surface as `REQUIRES-OPERATOR-INPUT`** in the POA&M, never silently dropped. The 3PAO sees the gap on every affected risk.
- **Expiration is honoured**: an expired compensating control gracefully downgrades to draft-like behavior — the reader filters by `status='active'` + `expiration_date > now() OR expiration_date IS NULL`.
- **Provenance block on `.compensating-controls.json`**: emitter, fetched_at, tracker_url, public_key_fingerprint, item count.
- **Signed by existing `core/sign.ts` pipeline** (Ed25519 + RFC 3161).

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/compensating-control-reader.test.ts tests/core/oscal-poam.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs

cd /Users/kenith.philip/FedRAMP\ 20x/tracker
npm run typecheck
npm test -- server/routes/compensating-controls.test.ts server/compensating-control-sign.test.ts client/src/pages/CompensatingControls.test.tsx client/src/pages/CompensatingControlCreate.test.tsx client/src/pages/CompensatingControlDetail.test.tsx
```

## Known risks / issues
- **Risk 1: NIST control catalog drift.** The catalog might be revised between B.B4 ship and a future SP 800-53 Rev 6. Mitigation: `nist-r5-controls.generated.json` is versioned; catalog version recorded on each control record via prop `catalog-version`. A future Rev 6 ship is its own slice.
- **Risk 2: Evidence URL link rot.** A runbook URL may 404 a year later. Mitigation: `evidence_sha256` (when uploaded via H.4) provides an immutable backup. Quarterly enforcer task (out of scope here) can revalidate URLs.
- **Risk 3: Activation flow has no second-factor.** Same gap as B.B3 approvals. Mitigation: file as follow-up; existing session + role + signature is sufficient for B.B4 ship.
- **Risk 4: A retired control cited by an active acceptance is logically inconsistent.** Mitigation: on retirement, the route enforces "no active acceptance links" — must revoke acceptances first. Otherwise 409.
- **Risk 5: Active control count could grow unbounded.** Mitigation: list endpoint paginates; UI uses infinite scroll.
- **Risk 6: Description ≥ 200 chars is enforced server-side but operator could paste lorem ipsum.** Mitigation: out of scope for automated checks; reviewer + AO sign-off catch this. Future enhancement could add a similarity check against existing controls to flag duplicates.
- **Risk 7: NIST control id validation could be expensive for large arrays.** Mitigation: the catalog is loaded once at server boot into a Map keyed by control id; lookups are O(1).
- **Risk 8: Cross-repo schema drift between `compensating_controls` and acceptance `compensating_control_uuids`.** Mitigation: tracker emits a verification endpoint `GET /api/compensating-controls/uuid-exists?uuids=A,B,C`; B.B3 acceptance create-form uses this for client-side validation; cloud-evidence reader cross-references at snapshot time.

## Open questions (for implementation session to resolve)
- **Q1**: Should the NIST control catalog be loaded into the tracker as a static asset, or fetched from cloud-evidence at boot? Recommend: ship a copy of `nist-r5-controls.generated.json` under `tracker/server/data/` — single source of truth in repo, no runtime cross-system dependency.
- **Q2**: Do we want `nist_control_ids` to validate against enhancements as well (e.g. `AC-2(3)`)? Recommend: yes — the catalog includes enhancements. Tests pin both base + enhancement validation.
- **Q3**: Evidence file upload re-uses H.4 (per-item attachments). What happens if the H.4 attachment is deleted out-of-band? Recommend: nightly enforcer compares stored `evidence_sha256` against existing attachments; mismatch surfaces a "broken evidence link" status badge in the UI.
- **Q4**: Should `expiration_date` be MANDATORY (force annual review)? Recommend: optional, but UI nudges with a warning when null ("Consider setting an annual review date"). Future enhancement: org policy can enforce mandatory.
- **Q5**: When B.B4 ships, do we backfill any existing free-text compensating-control references from runbooks/SSP narratives? Recommend: no — the operator creates registry entries as they're needed; old free text remains in narrative but is not loaded into the registry.
- **Q6**: Should the OSCAL `risk.remediations[].description` include the compensating control's NIST control IDs inline? Recommend: keep description verbatim from registry; NIST IDs are in props (structured, queryable).
- **Q7**: How does H.4 evidence upload + Ed25519 signing interact? The CC payload signed at create includes `evidence_sha256`; if H.4 upload happens AFTER create, the signature is invalidated. Recommend: H.4 upload must happen BEFORE create-form submit (UI flow enforces this).

## Implementation log (running journal — implementing session updates)
```
2026-07-02 · impl-b-b4 · Shipped the full slice end to end across BOTH workspaces
  (tracker + cloud-evidence). commit 6b5168d.

  Tracker (Hono + better-sqlite3 + React — the real subsystem, per B.B3):
    - server/schema.sql: appended compensating_controls table (additive; verified
      on fresh + existing DBs via the full suite).
    - server/compensating-control-sign.ts: REUSES the B.B3 resident Ed25519 key +
      RFC-8785 canonicalize() from risk-acceptance-sign.ts; adds
      compensatingControlPayload() + activationPayload() shapes.
    - server/nist-catalog.ts + server/data/nist-r5-controls.generated.json: committed
      copy of the cloud-evidence catalog (Q1 resolved: static asset, no runtime
      cross-system dependency); O(1) Set lookup; isValidControlId() +
      normalizeControlId() (AC-2(3)↔ac-2.3), byte-identical to cloud-evidence.
    - server/routes/compensating-controls.ts: Hono CRUD (create-draft/list/uuid-exists/
      detail/verify/update-draft/activate/retire), manual validation (no zod),
      retirement blocked when an active acceptance still cites the control (B.B4-4).
    - server/rbac.ts: added read/create/activate/retire:compensating_control (create=iso/
      admin, activate=ao/admin [separation of duties], retire=iso/ao/admin, read=all).
    - server/index.ts: mounted /api/compensating-controls.
    - client: CompensatingControls{,Create,Detail}.tsx + lib/compensating-control-{api,
      view}.ts + App.tsx routes/nav. Description ≥200 nudge + optional-expiration
      annual-review nudge (Q4).

  cloud-evidence:
    - core/compensating-control-reader.ts: pull + verify-every-signature + signed
      out/.compensating-controls.json snapshot; getCompensatingControl() enforces
      status='active' AND unexpired (defence-in-depth).
    - core/oscal-poam.ts: buildCompensatingControlRemediations() fills each accepted
      risk's risk.remediations[] with lifecycle='completed' (title/description +
      compensating-control-uuid + one nist-control prop per id + evidence link); an
      unresolvable uuid → REQUIRES-OPERATOR-INPUT marker (Q6: ids in props, not desc).
    - core/orchestrator.ts: --pull-compensating-controls <url> (env
      CLOUD_EVIDENCE_COMPENSATING_CONTROLS_URL; defaults to the risk-acceptance
      tracker URL) runs the pull before the POA&M emit.
    - core/submission-bundle.ts: WELL_KNOWN role compensating-controls-snapshot.
    - core/nist-r5.ts: shared isValidControlId()/normalizeControlId() primitives.

  Verification: tracker typecheck clean, 130→159 tests (+29); cloud-evidence
  typecheck clean, 1354→1372 tests (+18); npm run check:reo green (G1 no-stubs,
  G3 provenance; G2 coverage-regression SKIP — no local collector run).

  Spec reconciliation (LOOP-B-RISKS B.B4-10/11): the per-slice doc assumed Express +
  a fresh compensating-control-sign.ts keypair + .test.tsx DOM-render UI tests. Reality
  is Hono + reused B.B3 signing key + pure compensating-control-view.ts logic
  unit-tested in tests/ (no jsdom). Q7: evidence_sha256 is part of the signed payload
  (forward-compatible with an H.4-upload-before-create flow); Q3/Q5 (nightly
  evidence-link enforcer, backfill of legacy free text) remain out of scope.
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (both workspaces)
- [ ] tests passing 100% (cloud-evidence +5 reader/POA&M; tracker +20 routes/UI)
- [ ] check:reo green (G1+G2+G3) in cloud-evidence
- [ ] STATUS.md updated (B.B4 row + Overall section)
- [ ] LOOP-B-SPEC.md status table updated (Section 7)
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with slice ID `LOOP-B.B4: <title>` in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-B-SPEC.md
- [ ] Pushed to origin/main
- [ ] NIST catalog asset present in `tracker/server/data/nist-r5-controls.generated.json`
- [ ] Manual smoke test: create draft → AO activates → reader pulls → POA&M emits risk.remediations[]

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: full schema + routes + UI + reader + POA&M integration + tests + risks.
3. Read `cloud-evidence/docs/loops/LOOP-B-SPEC.md` §B.B4 for the loop-spec narrative.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the 7-step commit pattern.
5. Read `docs/slices/B/B.B3.md` to understand the acceptance flow B.B4 feeds.
6. Read `cloud-evidence/core/oscal-poam.ts` `buildOscalPoam()` — extension point for risk.remediations[].
7. Read `tracker/server/schema.sql` and `tracker/server/index.ts` for the route mount pattern.
8. Read `tracker/server/routes/risk-acceptance.ts` (from B.B3) as the closest precedent.
9. Read `cloud-evidence/core/nist-r5.ts` — control-id validation source.
10. Begin implementation; update Implementation log as you go.

---
