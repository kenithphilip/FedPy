---
slice_id: F.F4
title: Evidence walk-through artifacts
loop: F
status: pending
commit: —
completed_date: —
depends_on: [A.A3, F.F1]
blocks: [F.F7, K.K1, I.I1]
estimated_effort: 3 days
last_updated: 2026-06-06
---

# F.F4 — Evidence walk-through artifacts

## TL;DR
Ships a tracker upload pipeline (DB table + REST routes + React uploader +
gallery) that lets a 3PAO attach screenshots, transcripts, HAR/PCAP captures
and JSON outputs to specific OSCAL finding-uuids, then surfaces them in the
emitted OSCAL Assessment Results as `observation.relevant-evidence[]` entries
referenced by relative paths the submission bundler ships verbatim inside
`evidence-walkthrough/<finding>/<artifact>/...`. This is what makes findings
independently verifiable per NIST SP 800-115 §4 (today this evidence lives
in ad-hoc zip files on shared drives).

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
**Gap closed**: OSCAL AR `observation.relevant-evidence[]` is the spec's
mandated channel for linking real testing evidence (commands, screenshots,
transcripts, sample outputs) to each finding. Without F.F4 the AR's
`observation` entries are limited to whatever pass/fail metadata the
collector emitted — which is sufficient for "did the SDK return what we
expected" but insufficient for "we walked through the production console,
captured the screenshot, recorded the command, here is the on-disk file
the AO can re-verify". NIST SP 800-115 §4 explicitly requires findings to be
documented "with sufficient detail to allow another technical professional
to verify them independently"; the FedRAMP Penetration Test Guidance §6
requires that captured artifacts redact credentials. F.F4 implements both:
real on-disk artifacts with verifiable sha256, plus a regex redactor for
known credential patterns in command strings.

The slice also closes the REO Rule 1.3 / 1.10 gap that would otherwise
appear: an `observation` entry that *claims* evidence exists but doesn't
ship the file with the bundle is a "placeholder return" / "synthetic emit
field". F.F4 ensures every `relevant-evidence.href` points at a file the
bundler will actually include.

## Authoritative sources (with verbatim quotes)
- **NIST SP 800-115 §4 Findings (PDF p. 4-1)** —
  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf
  > "Findings should be documented with sufficient detail to allow another
  > technical professional to verify them independently."

  §6 *Reporting* (PDF p. 6-1) further requires:
  > "The report should include the methodology used to perform the
  > assessment, the tools used (along with their versions), the findings,
  > and the rationale for each finding."

- **NIST OSCAL Assessment Results v1.1.2 — `observation.relevant-evidence`** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/#/assessment-results/results/observations/relevant-evidence
  > "An evidence resource that supports the observation. The reference can
  > be a URI pointing to the resource, including a uniform resource name
  > (URN) or a relative reference to a resource in the back-matter."

  And the parent `observation` element:
  > "Describes one or more observations. … `methods`: Identifies how the
  > observation was made. Possible values: `EXAMINE`, `INTERVIEW`, `TEST`,
  > `UNKNOWN`."

- **FedRAMP CSP Penetration Test Guidance** —
  https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf
  Verbatim (Section 5 *Reporting*):
  > "Sensitive data (e.g., credentials, customer data, PII) discovered or
  > leveraged during the assessment must be redacted from any artifacts
  > shared outside the testing team's authorized custody chain."

- **OSCAL Reference — `observation.methods`** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/
  Enumerated values per NIST 800-53A Rev 5 Appendix D: `EXAMINE` /
  `INTERVIEW` / `TEST` / `UNKNOWN`. Walk-through evidence is `EXAMINE` (the
  assessor reviewed an artifact); penetration-test transcripts are `TEST`.

- **NIST SP 800-53A Rev 5 Appendix D — Assessment Methods** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53Ar5.pdf
  > "The examine method is the process of reviewing, inspecting, observing,
  > studying, or analyzing one or more assessment objects (i.e.,
  > specifications, mechanisms, or activities)."

- **CIS Benchmark for evidence retention** —
  https://www.cisecurity.org/cis-benchmarks/ (referenced for the 25 MiB
  default upload cap: typical CIS benchmark screenshot bundles fit under
  20 MiB per artifact; 25 MiB matches the GitHub release-asset suggested
  cap and stays well under the 100 MiB hard limit common to corporate
  network appliances).

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/db/migrations/0FF4_walkthrough_evidence.sql`
  — DDL for `walkthrough_artifacts` table.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/walkthrough.ts`
  — REST routes: `POST /api/findings/:uuid/walkthrough` (multipart),
  `GET /api/findings/:uuid/walkthrough` (list),
  `GET /api/walkthrough/:id/download` (stream from disk with sha256 verify),
  `DELETE /api/walkthrough/:id` (author within edit window only).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/services/walkthrough-service.ts`
  — pure business logic; depends on `walkthrough-storage.ts` for I/O.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/services/walkthrough-storage.ts`
  — on-disk storage handler; writes to
  `tracker/uploads/walkthrough/<finding-uuid>/<artifact-uuid>/<sanitized-filename>`
  and records sha256 + bytes.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/services/walkthrough-redactor.ts`
  — regex-based redactor for credential patterns in `command` strings;
  exports `redactCommand(input: string): { redacted: string; redactionApplied: boolean }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/components/WalkthroughUploader.tsx`
  — drag-and-drop uploader with mandatory form fields (description,
  captured_at, tool_name, tool_version, command).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/components/WalkthroughGallery.tsx`
  — per-finding gallery with file-type aware preview (image tile for
  `.png/.jpg`, code panel for `.txt/.json/.har`, download link for `.pcap`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/walkthrough-bundle.ts`
  — pure reader: `loadWalkthroughFromTracker(url, runId): Promise<WalkthroughBundle>`
  + `materializeWalkthroughBundle(bundle, outDir): MaterializeResult`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/walkthrough-bundle.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/tracker/server/walkthrough.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/tracker/server/walkthrough-redactor.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/tracker/client/WalkthroughUploader.test.tsx`.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal.ts` — extend
  `OscalEmitOptions` with `walkthroughSource?: WalkthroughBundle`. When
  supplied, for each finding-uuid present in the bundle, append one
  `observation` per artifact (one method=`EXAMINE`, types=`['evidence']`)
  whose `relevant-evidence[].href` points at
  `evidence-walkthrough/<finding-uuid>/<artifact-uuid>/<sanitized-filename>`.
  Link from the matching `finding.related-observations[]`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  new flag `--ingest-walkthrough[=<tracker-url>]` + env
  `CLOUD_EVIDENCE_TRACKER_URL`. When set, the orchestrator calls
  `loadWalkthroughFromTracker(url, runId)` then
  `materializeWalkthroughBundle(bundle, outDir)` BEFORE `--oscal-ar`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — include the `evidence-walkthrough/` subdirectory under `outDir` in the
  bundler walk; add a new well-known catalogue entry
  `{ role: 'evidence-walkthrough-bundle', filenamePattern: /^evidence-walkthrough\/.+/, description: 'Per-finding walk-through evidence (screenshots, transcripts, HAR, PCAP)' }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/db/schema.ts`
  — append the new table to the type-exported schema so the rest of the
  tracker can reference `WalkthroughArtifact` rows.

## Schemas / standards
- **OSCAL `observation` shape** (verbatim from
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/#/assessment-results/results/observations):
  ```
  {
    "uuid": "<v4 uuid>",
    "title": "<optional>",
    "description": "<required Markdown>",
    "methods": ["EXAMINE"|"INTERVIEW"|"TEST"|"UNKNOWN"],
    "types": ["finding"|"evidence"|"control-objective"|"mitigation"|"assumption"|"risk"|...],
    "collected": "<ISO datetime>",
    "expires": "<optional ISO datetime>",
    "props": [...],
    "links": [...],
    "relevant-evidence": [{
      "href": "<URI or back-matter reference>",
      "description": "<required Markdown>",
      "props": [...]
    }]
  }
  ```
- **DB row shape** for `walkthrough_artifacts` — see the migration in §Build
  steps below.
- **Allowed file extensions**: `.png .jpg .jpeg .txt .json .har .pcap`. The
  list is REO-cleared per Rule 3 (standard MIME types; not org-specific).
  Operator override via env `CLOUD_EVIDENCE_WALKTHROUGH_ALLOWED_EXTS`.
- **Size cap**: 25 MiB default (`26214400` bytes). Operator override via env
  `CLOUD_EVIDENCE_WALKTHROUGH_MAX_BYTES`.
- **Credential redaction patterns** (initial list, all from public sources):
  - `AKIA[0-9A-Z]{16}` — AWS access key ID format (AWS docs).
  - `ASIA[0-9A-Z]{16}` — AWS temporary credential.
  - `[A-Za-z0-9/+=]{40}` when preceded by `aws_secret_access_key`.
  - `password=\S+` / `Password=\S+` — generic.
  - `token=\S+` / `Token=\S+` — generic.
  - `Bearer\s+[A-Za-z0-9._~+/=-]+` — bearer tokens.
  - `xox[baprs]-[A-Za-z0-9-]+` — Slack tokens.
  - `ghp_[A-Za-z0-9]{36}` — GitHub PAT.

## Build steps (concrete, numbered)
1. **DB migration** `0FF4_walkthrough_evidence.sql`:
   ```
   CREATE TABLE walkthrough_artifacts (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,           -- deterministic uuid from sha256
     run_id TEXT NOT NULL,
     finding_uuid TEXT NOT NULL,
     uploader_user_id INTEGER NOT NULL REFERENCES users(id),
     filename TEXT NOT NULL,              -- post-sanitization
     mime_type TEXT NOT NULL,
     bytes INTEGER NOT NULL,
     sha256 TEXT NOT NULL,
     description TEXT NOT NULL,
     captured_at TEXT NOT NULL,           -- ISO-8601, operator-supplied
     tool_name TEXT NOT NULL,             -- e.g. "aws cli"
     tool_version TEXT NOT NULL,          -- e.g. "2.16.1"
     command TEXT NOT NULL,               -- redacted command string
     command_redaction_applied INTEGER NOT NULL DEFAULT 0,
     stored_path TEXT NOT NULL,           -- relative to tracker uploads dir
     created_at TEXT NOT NULL,
     deleted_at TEXT
   );
   CREATE INDEX idx_walk_finding ON walkthrough_artifacts (finding_uuid);
   CREATE INDEX idx_walk_run ON walkthrough_artifacts (run_id);
   ```
2. **Pure redactor** in `walkthrough-redactor.ts`:
   `redactCommand(input)` iterates the published patterns. Each match
   replaces the matched substring with `<REDACTED:<pattern-name>>` and
   sets `redactionApplied=true`. Returns the cleaned string and the bool.
3. **Storage** in `walkthrough-storage.ts`:
   - Sanitize filename: lowercase, replace anything outside
     `[a-z0-9._-]` with `_`, cap length 64.
   - Compute sha256 streaming.
   - Reject if `bytes > MAX_BYTES` BEFORE writing (stream the body, abort
     on overrun; do not buffer entire file in memory).
   - Write to
     `<UPLOAD_ROOT>/walkthrough/<finding-uuid>/<artifact-uuid>/<sanitized>`.
   - Return `{ storedPath, sha256, bytes }`.
4. **Service** `walkthrough-service.ts`:
   - `createArtifact(input, ctx)` validates:
     - `finding_uuid` exists in the most recent on-disk AR
       (`out/assessment-results.json` mirrored into the tracker by the
       orchestrator post-emit).
     - Extension is in allowlist.
     - `tool_name`, `tool_version`, `command`, `captured_at`, `description`
       all non-empty (SP 800-115 reproducibility rule).
     - User role is `assessor` (RBAC).
   - Redacts `command` via `redactCommand`.
   - Persists row, returns the artifact record. The original (pre-redaction)
     command is NEVER persisted (REO Rule 1.10 + FedRAMP PenTest §5
     redaction rule).
5. **REST routes**:
   - `POST /api/findings/:uuid/walkthrough` — multipart upload; 400 with
     `{ error: 'REQUIRES-OPERATOR-INPUT', missing_fields: [...] }` when
     reproducibility fields are absent; 413 when oversize; 415 when
     extension not in allowlist; 403 when role mismatch; 200 with the
     record on success.
   - `GET /api/findings/:uuid/walkthrough` — list active artifacts for
     the finding.
   - `GET /api/walkthrough/:id/download` — stream the file; verify sha256
     before piping; 502 if disk file disagrees with DB sha256 (treat as
     evidence tampering).
   - `DELETE /api/walkthrough/:id` — author within 15-minute edit window
     (mirrors F.F2 comment edit window); soft-delete (`deleted_at`).
6. **Ingest** in `walkthrough-bundle.ts`:
   `loadWalkthroughFromTracker(url, runId)` calls
   `GET /api/runs/:runId/walkthrough/manifest` (new aggregated endpoint
   that lists every artifact for the run). For each artifact, calls the
   download endpoint, verifies sha256, returns `WalkthroughBundle =
   { artifacts: WalkthroughArtifact[], outDirSubpath: 'evidence-walkthrough' }`.
   `materializeWalkthroughBundle(bundle, outDir)` writes each artifact to
   `<outDir>/evidence-walkthrough/<finding-uuid>/<artifact-uuid>/<filename>`
   and verifies sha256 after write.
7. **Orchestrator wire**:
   - Flag `--ingest-walkthrough[=<url>]` + env `CLOUD_EVIDENCE_TRACKER_URL`.
   - When set, fetches + materializes BEFORE `--oscal-ar`, then passes the
     bundle to `emitOscalAR()` via `walkthroughSource`.
8. **AR integration** in `core/oscal.ts`:
   For each finding-uuid in `walkthroughSource`, for each artifact, append
   to `result.observations[]`:
   ```
   {
     uuid: deterministicUuid(`walkthrough:${artifact.uuid}`),
     description: artifact.description,
     methods: ['EXAMINE'],
     types: ['evidence'],
     collected: artifact.captured_at,
     'relevant-evidence': [{
       href: `evidence-walkthrough/${artifact.finding_uuid}/${artifact.uuid}/${artifact.filename}`,
       description: `${artifact.tool_name} ${artifact.tool_version} :: ${artifact.command}`,
       props: [
         { name: 'sha256', ns: CE_NS, value: artifact.sha256 },
         { name: 'bytes', ns: CE_NS, value: String(artifact.bytes) },
         { name: 'redaction-applied', ns: CE_NS, value: artifact.command_redaction_applied ? 'true' : 'false' }
       ]
     }]
   }
   ```
   And in the parent finding, append
   `related-observations[].observation-uuid = <new uuid>`.
9. **Bundler integration** in `submission-bundle.ts`:
   - Extend the `listOutDir()` walk to descend into
     `evidence-walkthrough/<finding-uuid>/<artifact-uuid>/`.
   - Add the well-known catalogue entry (regex pattern, not exact filename).
   - At pack time, for each AR `observation.relevant-evidence[].href`
     starting with `evidence-walkthrough/`, verify the file exists in the
     bundle root; if missing, emit `coverage:miss` and the bundle's
     `provenance.diagnostics[]` lists the dangling href.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:
- `tool_name`, `tool_version`, `command`, `captured_at`, `description`:
  source = multipart form fields from the assessor UI. If absent, upload
  fails with 400 + body
  `{ error: 'REQUIRES-OPERATOR-INPUT', missing_fields: [...] }`.
  No default substitution. (SP 800-115 reproducibility rule.)
- `uploader_user_id`: tracker session — must be `assessor` role. No CLI
  / config substitute (REO Rule 1.10).
- When `--ingest-walkthrough` is set but the tracker returns zero
  artifacts for a finding-uuid that appears in the AR with status
  `not-satisfied`, the AR's finding props array gets
  `{ name: 'walkthrough-missing', value: 'REQUIRES-OPERATOR-INPUT' }`
  AND the orchestrator log emits `coverage:miss` naming the finding.

## Test specifications (≥12 tests)
1. `it('rejects upload with bytes > CLOUD_EVIDENCE_WALKTHROUGH_MAX_BYTES with 413')` — assertions: status 413, no row in DB, no file on disk.
2. `it('rejects upload with file extension not in allowlist with 415')` — assertions: status 415; assert all eight default-allowed extensions (`png`, `jpg`, `jpeg`, `txt`, `json`, `har`, `pcap`, plus uppercase variants) succeed.
3. `it('rejects upload without required reproducibility fields with 400 REQUIRES-OPERATOR-INPUT')` — assertions: each missing field appears in the `missing_fields` response array; no row persisted.
4. `it('rejects upload when finding_uuid is absent from out/assessment-results.json')` — assertions: status 404; specific error body.
5. `it('writes file at <UPLOAD_ROOT>/walkthrough/<finding>/<uuid>/<sanitized> and the on-disk sha256 matches the stored DB sha256')`.
6. `it('applies AKIA-pattern redaction in command and sets command_redaction_applied=1; persisted command contains <REDACTED:aws-akid>')`.
7. `it('applies password=<value> redaction')` + `it('applies Bearer <token> redaction')` + `it('applies Slack xoxb redaction')` — three assertions in three sub-tests.
8. `it('only assessor role can upload (403 for reviewer, csp-admin, viewer)')`.
9. `it('download endpoint streams the file and verifies sha256; mismatched on-disk sha256 returns 502 evidence-tamper')`.
10. `it('soft-delete sets deleted_at; deleted rows do not appear in list nor in walkthrough-bundle ingest')`.
11. `it('loadWalkthroughFromTracker downloads every artifact for the run and sha256-verifies each')`.
12. `it('materializeWalkthroughBundle writes files to outDir/evidence-walkthrough/<finding>/<uuid>/ and post-write sha256 matches bundle metadata')`.
13. `it('AR emit with walkthroughSource appends one observation per artifact with methods=["EXAMINE"], types=["evidence"], collected=captured_at')`.
14. `it('AR emit links each observation to its parent finding via finding.related-observations[].observation-uuid')`.
15. `it('AR emit observation uuid is deterministic: same artifact uuid yields same observation uuid across runs')`.
16. `it('bundler includes evidence-walkthrough/** files under role evidence-walkthrough-bundle and the regex catalogue matches')`.
17. `it('bundler emits coverage:miss for an AR href starting with evidence-walkthrough/ when the file is absent from outDir')`.
18. `it('UI: WalkthroughUploader rejects unsupported extensions client-side before submitting (no network call)')`.
19. `it('UI: WalkthroughGallery renders one tile per artifact, shows sha256 + bytes, and disables the delete button outside the 15-minute window')`.
20. `it('redactor does not over-redact: a 40-character random hex string NOT preceded by aws_secret_access_key is NOT redacted')` — proves precision, not just recall.

## REO compliance specific to this slice
- Every artifact has a real on-disk file with verifiable sha256 (the
  bundler verifies sha256 at pack time; missing file => coverage:miss).
- Tool name + version + command are required and operator-supplied; no
  auto-substitution and no defaults.
- Redaction is applied at write time; the original unredacted command is
  never persisted to disk OR to the DB (single-pass redactor; the request
  buffer is overwritten before insert).
- The AR's `observation.relevant-evidence[]` href points to a file that
  exists in the submission bundle; the bundler verifies at pack time and
  emits `coverage:miss` for any missing referenced file.
- Provenance: every observation has `sha256` + `bytes` + `redaction-applied`
  props derived from real file metadata.
- No system-generated uploads: the upload endpoint requires an
  authenticated assessor user (`uploader_user_id`); the orchestrator
  cannot insert rows directly.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/walkthrough-bundle.test.ts tests/tracker/server/walkthrough.test.ts tests/tracker/server/walkthrough-redactor.test.ts tests/tracker/client/WalkthroughUploader.test.tsx
npm run check:reo
```

## Known risks / issues
- **Risk 1 — Image-content credentials**: the regex redactor only inspects
  `command` strings. PNG/JPG screenshots may contain visible credentials,
  customer names, or PII captured in browser console output. Mitigation:
  document a pre-upload visual-review requirement in the UI tooltip; emit
  a UI warning on every `.png`/`.jpg` upload reminding the assessor to
  visually review. F.F4 explicitly does NOT attempt OCR-based content
  redaction (out of scope; LOOP-K could add).
- **Risk 2 — Bundle size explosion**: 100 findings × 5 artifacts each ×
  20 MiB = 10 GiB. Mitigation: per-run guardrail in the bundler that
  warns when `evidence-walkthrough/**` exceeds 2 GiB; operator can opt
  out of bundling walk-through artifacts and instead ship a manifest of
  external-storage URLs (future enhancement; not in F.F4).
- **Risk 3 — Storage path traversal**: a malicious filename like
  `../../../etc/passwd` could escape the upload directory. Mitigation:
  the sanitization in `walkthrough-storage.ts` rejects any
  `.` / `/` / null bytes and caps length 64. Tested in
  test #5 with adversarial inputs.
- **Risk 4 — sha256 race condition**: if two assessors upload the same
  file concurrently to the same finding, the deterministic uuid
  (`sha256(file_contents)`) collides. Mitigation: uuid is
  `sha256(file_contents + uploader_user_id + created_at)` so concurrent
  uploads remain distinct AND auditable.
- **Risk 5 — Tracker→bundle drift**: an artifact deleted in the tracker
  after the AR was emitted but before the bundle is packed leaves a
  dangling `relevant-evidence` href. Mitigation: bundler verifies
  every `evidence-walkthrough/` href and emits `coverage:miss`; the
  build still succeeds (the bundle ships honestly with a diagnostic).
- **Risk 6 — Redactor regex over-fitting**: a 40-character random hex
  string adjacent to the `aws_secret_access_key` literal gets redacted
  even if it is not actually a secret. Mitigation: test #20 covers
  this; the redactor is conservative (high recall over precision is
  the right default for credential handling).
- **Risk 7 — Upload-DOS via large file**: an oversized stream could
  exhaust disk before the 413 fires. Mitigation: storage helper aborts
  the stream after `MAX_BYTES + 1`; partial file is deleted on abort.

## Open questions (for implementation session to resolve)
- **Q1**: Should the tracker stream the file via the orchestrator's HTTP
  client during `loadWalkthroughFromTracker`, or instead provide a
  pre-signed download URL that the orchestrator passes to a local
  fetch helper? Pre-signed is faster for large bundles but adds a
  new dependency on `core/sign.ts` URL signing.
- **Q2**: Does the bundler tar the `evidence-walkthrough/` tree as-is,
  or compress each artifact subdirectory? Tar-as-is preserves sha256
  verifiability post-extraction. Compression saves space but
  complicates sha256 verification.
- **Q3**: Should `materializeWalkthroughBundle` skip artifacts whose
  on-disk file already exists with matching sha256 (idempotency)?
  Proposal: yes; log a `skip:cached` line per skipped artifact.
- **Q4**: Should the `redactor` regex list live in a JSON file under
  `cloud-evidence/core/redaction-patterns.json` so operators can extend
  it without touching code? Or stay in-code so the test suite locks
  the canonical pattern set? Proposal: in-code for v1; extract to JSON
  in a follow-up slice once stable.
- **Q5**: When the 3PAO uploads a `.pcap`, should the gallery render
  the first 100 packets? Tracker does not currently parse PCAP;
  proposal: no preview, download-only link, future enhancement.
- **Q6**: Should `deleted_at` artifacts still ship in the bundle (as
  evidence of intent + audit), or be excluded? Proposal: exclude from
  the AR but include a `walkthrough-deleted-manifest.json` in the
  bundle listing every deletion with timestamp + actor.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥20)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-F-SPEC.md Section 7 status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-F.F4: Evidence walk-through artifacts`
- [ ] Commit amended with hash recorded in STATUS.md + this file + LOOP-F-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: sources + files + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-F-SPEC.md` §2 Dependencies.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Confirm F.F1 is `done` in STATUS.md (the AR signoff dependency).
6. Verify `out/assessment-results.json` exists and contains finding
   uuids the uploads will reference.
7. Begin implementation; update Implementation log section as you go.
