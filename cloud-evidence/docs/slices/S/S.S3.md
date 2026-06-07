---
slice_id: S.S3
title: DoD CIO Equivalency Memorandum attestation package emitter
loop: S
status: pending
commit: —
completed_date: —
applicable_conditional: true
condition: CSP has at least one DoD-prime customer (DFARS Subpart 204.73 applicable) AND wishes to deliver a signed DoD CIO Equivalency attestation package
trigger_flag: "--dfars-equivalency"
trigger_env: CLOUD_EVIDENCE_DFARS_EQUIVALENCY
depends_on: [S.S1, S.S2, LOOP-A.A4]
blocks: []
estimated_effort: 5-6 working days
last_updated: 2026-06-07
---

# S.S3 — DoD CIO Equivalency Memorandum attestation package emitter

## TL;DR

The DoD CIO Memorandum (December 21, 2023, "FedRAMP Moderate
Equivalency for Cloud Service Providers in Support of the DoD")
prescribes a specific deliverable shape for a CSP claiming
FedRAMP Moderate Equivalency under DFARS 252.204-7012: a signed
Equivalency Letter, the FedRAMP submission bundle, a Body of Evidence
(BoE) crosswalk, the 3PAO equivalency assessment letter, and a written
operational runbook covering DFARS 7012(c)-(g). S.S3 produces the
**Equivalency Letter** (`out/dfars-equivalency-letter.docx`), the
**operational runbook** (`out/dfars-equivalency-runbook.docx`), a
signed **manifest** (`out/dfars-equivalency-manifest.json`), and
extends the LOOP-A.A4 submission bundler to build a nested
**DFARS Equivalency Package** archive
(`out/dfars-equivalency-package.zip`) containing all five DoD CIO
required artifacts plus the prior-12-month S.S2 incident report
history. The Equivalency Letter requires a real CSP officer signature
captured through the tracker (CISO, CTO, or higher role); the
operational runbook narrative is operator-typed per DFARS 7012 sub-
clause; the 3PAO letter is operator-uploaded; the manifest is signed
Ed25519 + RFC 3161 timestamped.

## Status

- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists

DFARS 252.204-7012(b)(2)(ii)(D) requires the CSP serving a DoD-prime
customer to provide "security requirements equivalent to those
established by the Government for the Federal Risk and Authorization
Management Program (FedRAMP) Moderate baseline". The DoD CIO
Memorandum (Dec 21 2023) clarifies the operational form of that
equivalency claim:

1. A signed Equivalency Letter from a CSP officer (CISO / CTO or
   equivalent).
2. The FedRAMP submission package (SSP, SAP, AR, POA&M — already
   produced by LOOP-A.A1-A.A4).
3. A Body of Evidence (BoE) crosswalk demonstrating implementation of
   every FedRAMP Moderate control (produced by LOOP-S.S1).
4. A 3PAO assessment letter affirming the equivalency claim
   (operator-uploaded — engaged externally with a FedRAMP-recognized
   3PAO).
5. An operational runbook documenting how the CSP complies with
   DFARS 252.204-7012(c) through (g) — cyber-incident reporting,
   malicious-software submission, media preservation, access for
   forensic analysis, and damage assessment.

Today the existing LOOP-A.A4 submission bundler emits a generic
FedRAMP-shaped archive that does NOT include:

- A CSP-officer-signed Equivalency Letter.
- The 800-171 crosswalk (S.S1 fixes this on the input side).
- The 3PAO equivalency assessment letter.
- The operational runbook for DFARS 7012(c)-(g).
- The prior-12-month DFARS incident report history (audit trail).

S.S3 closes all five gaps. It also implements an annual expiration
enforcer: the DoD CIO memo expects attestations to be refreshed at
least annually + within 30 days of any material change. Stale
attestations auto-expire and prevent the bundler from shipping a
stale package.

## Authoritative sources (with verbatim quotes)

- **DFARS 252.204-7012(b)(2)(ii)(D)** —
  https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting
  > "If the Contractor intends to use an external cloud service provider
  > to store, process, or transmit any covered defense information in
  > performance of this contract, the Contractor shall require and
  > ensure that the cloud service provider meets security requirements
  > equivalent to those established by the Government for the Federal
  > Risk and Authorization Management Program (FedRAMP) Moderate
  > baseline (https://www.FedRAMP.gov) and that the cloud service
  > provider complies with requirements in paragraphs (c) through (g)
  > of this clause."

- **DoD CIO Memorandum, "FedRAMP Moderate Equivalency for Cloud Service
  Providers in Support of the DoD"** — December 21, 2023, published
  via https://dodcio.defense.gov/library/.
  Required content (downloaded PDF; quotes carried verbatim in
  `core/dfars-equivalency-attestation.ts` docstring):
  > "Body of Evidence (BoE) ... must include evidence that the CSP has
  > implemented each FedRAMP Moderate control."
  > "The BoE must include the results of a third-party assessment by a
  > FedRAMP-recognized 3PAO."
  > "Equivalency status expires one year after the date of attestation
  > unless reaffirmed."

- **DoD Cloud Computing Security Requirements Guide (CC SRG) v1r4** —
  https://dodcio.defense.gov/Portals/0/Documents/DD/CloudComputingSRG_v1r4.pdf
  - Defines IL2 / IL4 / IL5 / IL6 impact levels. CUI under DFARS 7012
    cloud-equivalency operates at IL4-equivalent.
  - IL5 requires FedRAMP High baseline PLUS additional DoD overlays;
    most CSPs cannot claim IL5-equivalent without additional work.
    S.S3 defaults to IL4-equivalent; an explicit
    `--confirm-il5` flag is required to claim IL5.

- **DFARS 252.204-7012(c)** — referenced in S.S2 for the cyber-
  incident reporting flow; covered in S.S3's runbook section (c).
- **DFARS 252.204-7012(d) (Malicious Software)** — DC3 submission
  procedure; covered in S.S3's runbook section (d).
- **DFARS 252.204-7012(e) (Media Preservation)** — 90-day retention;
  covered in S.S3's runbook section (e) (and tracked per-artifact by
  S.S2's `dfars_incident_artifacts.retention_until` column).
- **DFARS 252.204-7012(f) (Access for Forensic Analysis)** —
  obligation to provide DoD access on request; covered in S.S3's
  runbook section (f).
- **DFARS 252.204-7012(g) (Damage Assessment)** — obligation to
  cooperate; covered in S.S3's runbook section (g).

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-equivalency-attestation.ts`
  — orchestrator-side emitter that reads the FedRAMP submission bundle,
  the S.S1 crosswalk, the 3PAO equivalency assessment letter, the
  attested record from the tracker, and emits the letter, the manifest,
  and the runbook. ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-equivalency-letter-docx.ts`
  — OOXML renderer per the DoD CIO Memo template. ~300 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dfars-equivalency-runbook-docx.ts`
  — OOXML renderer for the operational runbook covering DFARS 7012
  (c) through (g). ~400 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/templates/dfars-equivalency-letter.template.json`
  — operator-editable paragraph headings + prompts.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/templates/dfars-runbook.template.json`
  — runbook section seeds (verbatim DFARS clauses + operator-
  attestation prompts).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-equivalency-attestation.test.ts`
  — ≥10 emitter tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-equivalency-letter-docx.test.ts`
  — ≥4 OOXML round-trip tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/dfars-equivalency-runbook-docx.test.ts`
  — ≥4 OOXML round-trip tests.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/dfars-equivalency.ts`
  — `POST /api/dfars/equivalency/attestations`, `POST
  /api/dfars/equivalency/attestations/:uuid/attest`, `GET
  /api/dfars/equivalency/attestations`, `POST
  /api/dfars/equivalency/attestations/:uuid/revoke`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/dfars-equivalency.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/dfars-attestation-enforcer.ts`
  — annual expiration enforcer (mirrors B.B3 enforcer).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/dfars-attestation-enforcer.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/DfarsEquivalency.tsx`
  — UI for officer review + signature.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/DfarsEquivalencyDetail.tsx`
  — per-attestation detail.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/DfarsRunbookEditor.tsx`
  — section editor for the 7012(c)-(g) narrative.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/DfarsEquivalency.test.tsx`.

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add roles to `WELL_KNOWN`:
  ```ts
  { role: 'dfars-equivalency-letter-docx', filename: 'dfars-equivalency-letter.docx', description: 'CSP officer-signed Equivalency Letter per DoD CIO Memo Dec 21 2023 (LOOP-S.S3)' },
  { role: 'dfars-equivalency-manifest-json', filename: 'dfars-equivalency-manifest.json', description: 'Signed manifest of the DFARS equivalency package (LOOP-S.S3)' },
  { role: 'dfars-equivalency-runbook-docx', filename: 'dfars-equivalency-runbook.docx', description: 'Operational runbook covering DFARS 252.204-7012(c)-(g) (LOOP-S.S3)' },
  ```
  Plus the directory-role logic that builds the nested
  `dfars-equivalency-package.zip` when `--dfars-equivalency` is set.

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — when `--dfars-equivalency` is set, AFTER S.S1 crosswalk emit AND
  AFTER any pending S.S2 incident reports are written, call
  `emitDfarsEquivalencyAttestation()` BEFORE the bundler step.

- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql`
  — append tables:
  - `dfars_equivalency_attestations` (per `LOOP-S-SPEC.md` § S.S3)
  - `dfars_equivalency_runbook_sections` — operator-typed narrative,
    keyed by `(attestation_uuid, section_id IN
    ('c','d','e','f','g'))`, signed per section.

- `/Users/kenith.philip/FedRAMP 20x/tracker/server/rbac.ts`
  — new `officer` role (CISO, CTO, or higher) — can sign attestation;
  `iso` can edit runbook sections; `assessor` can view.

- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx`
  — add `/dfars/equivalency` route gated by `DFARS_ENABLED=true`.

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CHANGELOG.md`
  — Unreleased entry per Section 8 of LOOP-S-SPEC.md.

## Schemas / standards

- **Tracker `dfars_equivalency_attestations` table** — per
  `LOOP-S-SPEC.md` § S.S3 Files-to-extend (full schema there).

- **Tracker `dfars_equivalency_runbook_sections` table**:
  ```sql
  CREATE TABLE IF NOT EXISTS dfars_equivalency_runbook_sections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attestation_uuid TEXT NOT NULL,
    section_id TEXT NOT NULL CHECK (section_id IN ('c','d','e','f','g')),
    narrative_markdown TEXT NOT NULL,                -- operator-typed
    edited_by_user_id INTEGER NOT NULL REFERENCES users(id),
    edited_at TEXT NOT NULL,
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    UNIQUE (attestation_uuid, section_id)
  );
  ```

- **Equivalency Letter content** (per DoD CIO Memo Dec 21 2023) —
  see `LOOP-S-SPEC.md` § S.S3 Build step 3 for the full template body.

- **Equivalency Manifest shape** — see `LOOP-S-SPEC.md` § S.S3 Build
  step 4 for the full `DfarsEquivalencyManifest` interface.

- **Nested archive contents** (`dfars-equivalency-package.zip`):
  1. `dfars-equivalency-letter.docx`
  2. `dfars-equivalency-manifest.json`
  3. `dfars-equivalency-runbook.docx`
  4. `dfars-crosswalk.json` + `dfars-crosswalk.xlsx`
  5. `dfars-incident-report-*.json` + `*.docx` (prior 12 months)
  6. `fedramp-submission.zip` (nested — the full LOOP-A.A4 archive)
  7. `threepao-equivalency-letter.{pdf|docx}` (operator-uploaded)

## Build steps (concrete, numbered)

1. **Tracker schema migration**: append the two new tables to
   `schema.sql`. Idempotent `CREATE TABLE IF NOT EXISTS`. Run migration
   test on a populated DB.

2. **POST `/api/dfars/equivalency/attestations`**:
   ```ts
   interface CreateBody {
     csp_name: string;
     csp_legal_entity: string;
     cso_name: string;
     fedramp_package_id: string;          // SSP uuid
     threepao_letter_uri: string;          // operator-uploaded
     threepao_letter_sha256: string;
     threepao_name: string;
     threepao_assessment_date: string;
     runbook_uri: string;                  // resolves to the docx that S.S3 generates
     runbook_sha256: string;
     operating_impact_level: 'IL4-equivalent' | 'IL5-equivalent';
     dod_prime_customers: string[];
     attesting_officer_user_id: number;
     attesting_officer_title: string;
   }
   ```
   Validation:
   - Caller has `officer` or higher role.
   - `attesting_officer_user_id` must reference a user with `officer`
     role.
   - `dod_prime_customers.length >= 1`.
   - If `operating_impact_level === 'IL5-equivalent'`, the body must
     ALSO include `confirm_il5: true`; emitter further requires
     `--confirm-il5` flag on the orchestrator command.
   - Runbook sections (c)-(g) must all be present with
     `narrative_markdown.length >= 200` each.
   Compute `expiration_date = attested_at + 365d`. Sign canonical
   JSON with Ed25519. Insert row `status='draft'`. Audit log.

3. **POST `/api/dfars/equivalency/attestations/:uuid/attest`**:
   officer re-signs `{uuid, attested_at}`; transitions
   `status='attested'`. Audit log.

4. **Letter emitter** `core/dfars-equivalency-attestation.ts`:
   ```ts
   export interface DfarsAttestationEmitOptions {
     outDir: string;
     trackerUrl: string;
     trackerToken: string;
     fedrampBundlePath: string;         // path to fedramp-submission.zip
     crosswalkJsonPath: string;          // path to dfars-crosswalk.json (S.S1)
     runbookTemplatePath?: string;
     letterTemplatePath?: string;
     cspProfilePath: string;
     runId: string;
   }
   export interface DfarsAttestationEmitResult {
     letter_docx_path: string;
     manifest_json_path: string;
     runbook_docx_path: string;
     attestation_uuid: string;
     attested_officer: string;
     expiration_date: string;
     dod_prime_customers: string[];
   }
   export async function emitDfarsEquivalencyAttestation(opts: DfarsAttestationEmitOptions): Promise<DfarsAttestationEmitResult>;
   ```
   Steps:
   - Pull the active (`status='attested'`, `expiration_date > now`)
     attestation from the tracker.
   - If none, throw typed error (REO Rule 5: visible diagnostic).
   - Read the FedRAMP bundle path + crosswalk path; compute SHA-256
     of each (verify against attestation's recorded SHA-256).
   - Read the 3PAO letter at `attestation.threepao_letter_uri`;
     compute SHA-256; verify against record.
   - Pull runbook sections (c)-(g) from the tracker; assert all five
     present.
   - Render letter docx via `dfars-equivalency-letter-docx.ts`.
   - Render runbook docx via `dfars-equivalency-runbook-docx.ts`.
   - Build manifest JSON per the shape in `LOOP-S-SPEC.md` § S.S3
     Build step 4.
   - Write all three to `outDir`.
   - Return result.

5. **Letter renderer** `core/dfars-equivalency-letter-docx.ts`. Five
   paragraph blocks per the DoD CIO Memo template (the verbatim
   language is in `LOOP-S-SPEC.md` § S.S3 Build step 3):
   1. FedRAMP Moderate equivalency claim.
   2. 3PAO assessment statement.
   3. DFARS 7012(c)-(g) compliance statement.
   4. Operating impact level statement.
   5. DoD-prime customers + contract vehicles listed.
   Officer signature block at bottom.

6. **Runbook renderer** `core/dfars-equivalency-runbook-docx.ts`. Five
   sections corresponding to DFARS 7012(c)-(g):
   - **§(c) Cyber Incident Reporting** — references S.S2 emitter +
     the DC3/DIBNet path; operator narrative explains internal
     escalation procedures.
   - **§(d) Malicious Software** — DC3 sample submission procedure;
     operator narrative explains containment + chain-of-custody.
   - **§(e) Media Preservation** — 90-day retention; operator
     narrative explains the storage tier + retention enforcement
     (per S.S2 `dfars_incident_artifacts.retention_until`).
   - **§(f) Access for Forensic Analysis** — operator narrative
     explains the legal + procedural path for DoD-requested access.
   - **§(g) Damage Assessment** — operator narrative explains
     cooperation procedure.
   Each section opens with the verbatim DFARS clause + an
   operator-typed CSP-specific procedure block (pulled from
   `dfars_equivalency_runbook_sections.narrative_markdown`).
   Renderer refuses to ship if any section's narrative is empty.

7. **Manifest emit**: signed JSON per the
   `DfarsEquivalencyManifest` shape in `LOOP-S-SPEC.md` § S.S3 Build
   step 4. Provenance block per REO Rule 2.6:
   ```ts
   provenance: {
     emitter: 'dfars-equivalency-attestation';
     emittedAt: string;
     sourceCalls: Array<{
       kind: 'tracker' | 'fedramp-bundle' | 'crosswalk' | '3pao-letter' | 'runbook';
       path: string;
       sha256: string;
     }>;
     signingKeyId: string;
   }
   ```

8. **Bundler integration**: in `submission-bundle.ts`, when
   `--dfars-equivalency` is set, after the normal FedRAMP bundle is
   built, build a nested archive
   `dfars-equivalency-package.zip` containing:
   - `dfars-equivalency-letter.docx`
   - `dfars-equivalency-manifest.json`
   - `dfars-equivalency-runbook.docx`
   - `dfars-crosswalk.json` + `dfars-crosswalk.xlsx`
   - `dfars-incident-report-*.json` + `*.docx` from the last 12 months
   - `fedramp-submission.zip` nested
   - `threepao-equivalency-letter.{pdf|docx}` from the operator-
     uploaded path
   Manifest signature covers the SHA-256 of every contained artifact.

9. **Attestation expiration enforcer** `dfars-attestation-enforcer.ts`.
   Runs on boot + every hour. For each attestation where
   `status='attested' AND expiration_date < now()`:
   - Update `status='expired'`.
   - Audit log `event='dfars-attestation-expired'`.
   - Notify (via `core/notify.ts`) the officer + ISO that the
     attestation must be re-affirmed.

10. **Orchestrator wiring**: when `--dfars-equivalency` is set, the
    order is:
    1. Collect (if requested).
    2. POA&M emit (LOOP-A.A1).
    3. Control benchmark (existing).
    4. DFARS crosswalk emit (S.S1).
    5. DFARS incident report emit (S.S2, on-demand only if
       `--dfars-incident-report <uuid>` is also set).
    6. DFARS equivalency attestation emit (S.S3).
    7. Bundle submission (LOOP-A.A4) including nested DFARS package.
    8. Sign + RFC 3161 timestamp.

11. **UI** (`DfarsEquivalency.tsx`):
    - List view shows attestations + statuses + expiration countdowns.
    - "Create attestation" form pulls SSP id, runbook URI, 3PAO letter
      URI (operator uploads first); validates required fields.
    - Runbook section editor (`DfarsRunbookEditor.tsx`) shows the
      verbatim DFARS clause + a markdown editor for the operator's
      narrative. Save signs the section.
    - Detail view shows the letter preview, attest button (officer
      only, requires re-signature), revoke button.

12. **Sign + timestamp**: all three artifacts (letter docx, manifest
    json, runbook docx) flow through `core/sign.ts` glob +
    `core/timestamp.ts` RFC 3161 pipeline. The bundle's manifest
    re-signs the SHA-256 of the whole archive.

## REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4, every field that cannot be auto-derived:

| Field | Source | Behavior when missing |
|---|---|---|
| `csp_name`, `csp_legal_entity`, `cso_name` | `config.yaml` `dfars.csp_name` etc. | Required — emitter errors clearly when absent |
| `attesting_officer_user_id` | Tracker — must reference a user with `officer` role | Required — emitter rejects if no attested record |
| `attesting_officer_title` | Tracker UI input | Required |
| `dod_prime_customers[]` | `config.yaml` `dfars.dod_prime_customers` (also S.S1) | Required (≥1) — emitter errors when empty |
| `threepao_letter_uri` + `threepao_letter_sha256` + `threepao_name` + `threepao_assessment_date` | Operator uploads in tracker | Required — bundler refuses to ship without it |
| `operating_impact_level` | `config.yaml`; defaults to `IL4-equivalent` | If `IL5-equivalent` claimed, emitter refuses without `--confirm-il5` flag + additional High-baseline evidence verification |
| Runbook sections (c)-(g) `narrative_markdown` | Tracker UI per-section editor (≥200 chars each) | Required — renderer refuses to ship empty sections |
| Letter paragraph customizations | `templates/dfars-equivalency-letter.template.json` | Defaults to DoD CIO Memo verbatim language; operator can customize within bounds |

## Test specifications (≥12 tests)

### Route handler tests
1. `it('rejects POST without runbook sections (c) through (g) all present')`.
2. `it('rejects POST when narrative_markdown < 200 chars')`.
3. `it('rejects POST without 3PAO letter sha256')`.
4. `it('rejects POST with empty dod_prime_customers[]')`.
5. `it('rejects POST when caller lacks officer role')`.
6. `it('rejects IL5-equivalent without confirm_il5 flag')`.
7. `it('computes expiration_date = attested_at + 365d')`.
8. `it('signs canonical JSON with Ed25519')`.

### Enforcer tests
9. `it('flips status to expired when expiration_date past')`.
10. `it('notifies officer + iso on expiration')`.
11. `it('does not re-process already-expired records')`.

### Emitter tests
12. `it('refuses emit when no attested record in tracker')`.
13. `it('refuses emit when attestation status=expired')`.
14. `it('refuses emit when threepao_letter_sha256 mismatch')`.
15. `it('refuses emit when any runbook section narrative is empty')`.
16. `it('writes letter docx with all 5 paragraph blocks')`.
17. `it('writes manifest with sha256 of every embedded artifact')`.
18. `it('writes runbook docx with 5 sections corresponding to 7012(c)-(g))`.
19. `it('emits provenance block per REO Rule 2.6')`.

### Bundler tests
20. `it('builds nested dfars-equivalency-package.zip when --dfars-equivalency set')`.
21. `it('includes prior-12-month dfars-incident-report-*.json files')`.
22. `it('signs the nested archive manifest with Ed25519')`.

### UI tests
23. `it('hides equivalency routes when DFARS_ENABLED=false')`.
24. `it('officer-only attest button when caller has lesser role')`.

## REO compliance specific to this slice

- Officer attestation is a real signed human action; never auto-
  generated.
- 3PAO assessment letter is operator-uploaded; the bundler verifies
  the SHA-256 matches the manifest claim — mismatch fails the bundle.
- Runbook narrative for each of DFARS 7012(c)-(g) is operator-authored
  via tracker UI; renderer refuses to ship empty sections.
- DFARS quote text + DoD CIO Memo language are REO Rule 3 allowed
  fixed-data (NIST / DoD published constants) and are quoted with
  citation.
- Signatures are real Ed25519 + RFC 3161 timestamps.
- Annual expiration enforcer flips status on real timestamp comparison;
  no fudging.
- IL5-equivalent path requires both DB flag AND CLI flag (defense in
  depth); the system never silently upgrades the impact-level claim.
- No `process.env.NODE_ENV === 'test'` branches.
- Provenance block populated end-to-end.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/dfars-equivalency-attestation.test.ts tests/core/dfars-equivalency-letter-docx.test.ts tests/core/dfars-equivalency-runbook-docx.test.ts
cd ../tracker
npm run typecheck
npm test -- server/routes/dfars-equivalency.test.ts server/dfars-attestation-enforcer.test.ts client/src/pages/DfarsEquivalency.test.tsx
cd ../cloud-evidence
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues

- **Risk 1: DoD CIO Memo PDF reachability.** The Dec 21 2023 memo
  may be HTTP-403 to anonymous fetches. Until the implementer
  downloads the PDF to
  `cloud-evidence/docs/sources/dod-cio-memo-fedramp-equivalency-2023-12-21.pdf`,
  S.S3's emitter carries a `REQUIRES-OPERATOR-INPUT:
  confirm-against-dod-cio-memo-pdf` marker on the verbatim-quote
  constants (visible to `check:reo` reviewers; not a silent
  fallback).
- **Risk 2: 3PAO engagement lead time.** Procuring a 3PAO assessment
  is operator-side and can take months. Mitigation: S.S3 ship
  procedure includes a documented pre-flight requiring 3PAO letter
  on file BEFORE attestation creation; UI hint surfaces.
- **Risk 3: Officer signing-key rotation.** The officer signs through
  the tracker's Ed25519 key. If the key rotates without the public-
  key registry being updated, historical attestations fail
  verification. Mitigation: tracker exposes
  `GET /api/sign/public-keys` returning ALL historical public keys
  (mirrors B-X3 from LOOP-B risks); reader cross-references
  signing_key_id.
- **Risk 4: Letter language drift.** DoD CIO may update the memo
  template. Mitigation: emitter version-pins the template; CHANGELOG
  documents the active template version; the operator updates the
  letter template when DoD CIO publishes a new memo.
- **Risk 5: Multi-tenant attestation collision.** When LOOP-H.H3
  multi-CSO ships, attestations need a `tenant_id` migration.
  Mitigation: S.S3 ships single-tenant; H.H3 sweeps all S tables in
  one atomic migration.
- **Risk 6: IL5-equivalent path.** A CSP that mistakenly claims
  IL5-equivalent without High-baseline evidence + DoD overlays is
  exposed. Mitigation: defense-in-depth flag — both DB
  `operating_impact_level='IL5-equivalent'` AND `--confirm-il5` CLI
  flag required; UI warning + officer second sign-off required.
- **Risk 7: Subprocessor 3PAO scope.** If a subprocessor's CSO is
  in scope, its own 3PAO letter must also be carried. Mitigation:
  manifest's `threepao_letter` field is an array; multiple letters
  supported.
- **Risk 8: Expired attestation in flight.** A run that began before
  expiration but emitted after expiration: the emitter checks at
  emit time and refuses. Mitigation: emit-time check; runbook
  documents the renewal trigger 30 days before expiration.
- **Risk 9: Bundler nested-archive disk size.** The nested archive
  can be hundreds of MB (FedRAMP package + crosswalk + 12 months of
  incidents). Mitigation: streaming archive writer; LOOP-H long-term
  storage classifier picks up the artifact for archival.

## Open questions (for implementation session to resolve)

- **Q1**: Should the officer sign-off require a second hardware-key
  factor (YubiKey + PIV)? Recommend: yes for IL5-equivalent; optional
  for IL4-equivalent; operator config flag.
- **Q2**: Should the manifest include cryptographic chain-of-custody
  to the FedRAMP package's RFC 3161 timestamp? Recommend: yes — link
  the FedRAMP package's manifest_uuid and the DFARS manifest's
  manifest_uuid.
- **Q3**: How do we handle attestation revocation by the officer?
  Recommend: signed revoke action; status=revoked; downstream
  bundler refuses to use revoked attestations.
- **Q4**: Should the runbook be Marketplace-publishable (LOOP-Q.Q1)
  as a public summary? Recommend: only the section headings + the
  attestation existence — not the full operator narrative (it
  contains operational details that may be sensitive).
- **Q5**: Should we emit a separate cover letter per prime customer
  (so each customer gets a personalized envelope)? Recommend: yes,
  optional `--per-prime-letters` flag; one letter per entry in
  `dod_prime_customers[]`.
- **Q6**: How do we handle attestation versioning when material
  changes occur mid-year? Recommend: each material change creates a
  new attestation row; the prior row is `superseded`; bundler picks
  the active row.

## Implementation log (running journal — implementing session updates)

```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

The implementing session MUST check every box:

- [ ] typecheck clean (`npm run typecheck`) in both cloud-evidence + tracker
- [ ] tests passing 100% (count increased by ≥24 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + LOOP-S conditional gate noted)
- [ ] LOOP-S-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
  completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (opens with conditional gate
  statement)
- [ ] Commit with slice ID in message
- [ ] Commit amended with commit hash recorded
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build
   steps + tests + risks + completion checklist + conditional gate.
3. Read `cloud-evidence/docs/loops/LOOP-S-SPEC.md` Section 2
   (Dependencies) for cross-loop context AND § S.S3 Build steps for
   the verbatim DoD CIO Memo letter template.
4. Read the per-slice docs for S.S1 (crosswalk that feeds this
   slice) and S.S2 (incident reports that bundle alongside).
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
6. Read `cloud-evidence/core/oscal-ssp-docx.ts` (the OOXML pattern
   S.S3's docx renderers mirror).
7. Read `cloud-evidence/core/submission-bundle.ts` (the bundler this
   slice extends with the nested DFARS package).
8. Confirm `docs/sources/dod-cio-memo-fedramp-equivalency-2023-12-21.pdf`
   exists; if not, download from
   https://dodcio.defense.gov/library/ before writing the verbatim
   language constants.
9. Confirm the operator has a 3PAO letter ready to upload (operator-
   side pre-flight; LOOP-S.S3 is not deliverable without it).
10. Begin implementation; update Implementation log section as you go.

---
