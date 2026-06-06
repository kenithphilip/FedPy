---
slice_id: F.F2
title: Comment threads on findings
loop: F
status: pending
commit: —
completed_date: —
depends_on: [F.F1, A.A1]
blocks: [F.F4, F.F7]
estimated_effort: 3 days
last_updated: 2026-06-06
---

# F.F2 — Comment threads on findings

## TL;DR
Adds the `finding_comments` + `finding_comment_attachments` DB tables,
threaded REST API, Slack/email notifier, and React thread UI so 3PAO
questions, evidence requests, and resolutions are auditable per OSCAL
finding-uuid. Threads freeze automatically when the parent finding gets
F.F1 sign-off. AR emission with `--ingest-comments` embeds each comment
into `finding.remarks` Markdown with a back-pointer prop.

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
**Gap closed**: Today, 3PAO clarifications and evidence requests travel
via email + Word-document margin comments. There is no audit trail. The
FedRAMP RAR Guide v3.2 expects the 3PAO to "directly and clearly answer
RAR requirements and questions, stating what they found (observations
and evidence) during their review and HOW they came about determining
if a CSP adequately addresses the question area." This requires a
durable conversation record, not lost email threads.

The freeze-after-sign-off rule maintains the SAR's authoritative
status: once F.F1 signs off on a finding, additional comments would
modify the basis of authorization. The slice enforces append-only after
freeze; further discussion goes into a new finding-uuid (typically a
post-authorization POA&M item or a future ConMon finding).

## Authoritative sources (with verbatim quotes)
- **NIST OSCAL Assessment Results v1.1.2** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/
  > "`finding/remarks` — Additional commentary on the containing
  > object. Allowed value: prose (Markdown)."
- **FedRAMP 3PAO Readiness Assessment Report Guide v3.2** —
  https://www.fedramp.gov/assets/resources/documents/3PAO_Readiness_Assessment_Report_Guide.pdf
  > "3PAOs should directly and clearly answer RAR requirements and
  > questions, stating what they found (observations and evidence)
  > during their review and HOW they came about determining if a CSP
  > adequately addresses the question area."
- **FedRAMP Rev5 SAR Playbook** —
  https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/sar/
  > "The SAR documents the results of the security assessment for the
  > CSO, including a summary of the risks remaining at the conclusion
  > of the assessment."
  > (Authoritative status of the SAR is why the comment thread freezes
  > on sign-off — modifying the basis of an authoritative finding after
  > the fact would compromise the SAR.)
- **NIST SP 800-53 Rev 5 AU-10 Non-Repudiation** —
  > "Protect against an individual (or process acting on behalf of an
  > individual) falsely denying having performed [Assignment:
  > organization-defined actions to be covered by non-repudiation]."
  > (The signed-author + frozen-at audit record satisfies the
  > non-repudiation requirement for assessor conversations.)

## Files to create (exact paths)
- `cloud-evidence/tracker/server/db/migrations/0FF2_finding_comments.sql`
  — DDL for `finding_comments` + `finding_comment_attachments` tables.
- `cloud-evidence/tracker/server/routes/finding-comments.ts` — REST
  routes:
  - `GET /api/findings/:uuid/comments`
  - `POST /api/findings/:uuid/comments`
  - `PATCH /api/comments/:id` (15-min edit window after creation)
  - `DELETE /api/comments/:id` (author within edit window only)
- `cloud-evidence/tracker/server/services/comment-service.ts` — pure
  business logic.
- `cloud-evidence/tracker/server/services/comment-notifier.ts` — Slack +
  email dispatch via `core/notify.ts`.
- `cloud-evidence/tracker/client/src/components/FindingCommentThread.tsx`
  — chronological thread component.
- `cloud-evidence/tracker/client/src/pages/FindingDetail.tsx` — page
  embedding the thread.
- `cloud-evidence/tests/tracker/server/finding-comments.test.ts`.
- `cloud-evidence/tests/tracker/server/comment-notifier.test.ts`.
- `cloud-evidence/tests/tracker/client/FindingCommentThread.test.tsx`.

## Files to extend
- `cloud-evidence/core/notify.ts` — add
  `notifyFindingComment(input: { findingUuid, commentId, author, body, mentionedUserIds })`.
- `cloud-evidence/core/oscal.ts` — when ingesting comments at AR emit
  time (orchestrator flag `--ingest-comments`), embed each comment as
  an OSCAL `finding.remarks` Markdown fragment plus a `props[]` entry
  `{ name: 'comment-uuid', ns: 'urn:fedramp:cloud-evidence', value: comment.id }`
  so the comment chain is recoverable from the AR alone.
- `cloud-evidence/core/orchestrator.ts` — new `--ingest-comments` flag
  mirroring `--ingest-signoffs`.
- `cloud-evidence/tracker/server/services/signoff-service.ts` — F.F1's
  `createSignoff` writes
  `UPDATE finding_comments SET frozen_at = ? WHERE finding_uuid = ?`
  once every (statement × method) for a finding is signed off.

## Schemas / standards
- OSCAL AR `finding.remarks` Markdown field per the json-reference URL
  above.
- 15-minute edit window — chosen to match common GRC tool behavior
  (Jira, ServiceNow). FedRAMP does not publish a number; configurable
  via env `CLOUD_EVIDENCE_COMMENT_EDIT_WINDOW_MS`.
- Markdown subset: CommonMark + GFM tables (rendered client-side); the
  server stores raw Markdown text and does NOT sanitize at write time
  (output sanitization is the client's job per OWASP defense-in-depth).
- `@username` mention pattern: `/(^|\s)@([a-zA-Z0-9._-]+)/g` extracted
  at write time, persisted in a denormalized `mentioned_user_ids`
  array on the comment row.

## Build steps (concrete, numbered)
1. **DB migration** `0FF2_finding_comments.sql`:
   ```sql
   CREATE TABLE finding_comments (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,            -- deterministic uuid (sha1 of (finding_uuid, author, body_md, created_at))
     finding_uuid TEXT NOT NULL,
     author_user_id INTEGER NOT NULL REFERENCES users(id),
     body_md TEXT NOT NULL,
     parent_comment_id INTEGER REFERENCES finding_comments(id),
     created_at TEXT NOT NULL,
     edited_at TEXT,
     deleted_at TEXT,
     frozen_at TEXT
   );
   CREATE INDEX idx_fc_finding ON finding_comments (finding_uuid);
   CREATE TABLE finding_comment_attachments (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     comment_id INTEGER NOT NULL REFERENCES finding_comments(id),
     filename TEXT NOT NULL,
     mime_type TEXT NOT NULL,
     bytes INTEGER NOT NULL,
     sha256 TEXT NOT NULL,
     stored_path TEXT NOT NULL
   );
   ```
2. **`createComment` service**:
   - Validates `body_md` non-empty, ≤ 16 KiB.
   - Validates `finding_uuid` exists in the most recent AR (queried
     against the tracker's cached `out/assessment-results.json`).
   - Rejects with `409 Locked` if `frozen_at` is populated.
   - Parses `@username` mentions; resolves to user ids; persists.
3. **15-minute edit window** in `editComment`:
   - Accepts only if `now - created_at < CLOUD_EVIDENCE_COMMENT_EDIT_WINDOW_MS`
     AND user is author.
   - Outside the window → `403 EditWindowExpired`.
4. **Sign-off freeze hook**: F.F1's `createSignoff` calls
   `freezeFindingComments(finding_uuid)` when all
   `(statement × method)` tuples for that finding now have active
   signoffs. The freeze writes `frozen_at = now()`.
5. **Notifier** in `comment-notifier.ts`:
   - On every `POST /api/findings/:uuid/comments`, dispatches:
     (a) Slack to channel `#fedramp-findings` (URL via env
     `CLOUD_EVIDENCE_SLACK_FINDINGS_WEBHOOK`).
     (b) Email to: POA&M responsible-party (from
     `out/poam.json` `poam-item.responsible-parties[]`), prior
     authors in the thread (deduped), and every `@username`
     mentioned.
   - Failures bubble as `partial-failure` warnings; the comment
     persists.
6. **UI** `FindingCommentThread.tsx`:
   - Chronological list; each comment shows author + timestamp +
     Markdown body + edit / delete buttons (conditional on author +
     edit window).
   - "New comment" textarea at the bottom; disabled with explanation
     when `frozen_at` is set.
7. **Orchestrator wire** `--ingest-comments`:
   - Mirrors `--ingest-signoffs`; reads tracker URL + token from env.
   - Calls `loadCommentsFromTracker(url, runId): Promise<CommentBundle>`
     and passes via `OscalEmitOptions.commentSource`.
8. **AR integration** in `core/oscal.ts`: for each finding-uuid in
   `commentSource`, append a Markdown block to `finding.remarks`:
   ```
   ## Assessor commentary
   ### {author} — {timestamp}
   {body_md}
   [comment-uuid: {uuid}]
   ```
   Add a `props[]` entry `{ name: 'comment-uuid', ns: 'urn:fedramp:cloud-evidence', value: comment.uuid }`
   per comment.
9. **Validation pass**: AR continues to validate via
   `core/oscal-validate.ts`; the `remarks` field accepts any Markdown,
   so no schema change is required.
10. **Sign + timestamp**: AR is signed + RFC 3161 timestamped by the
    existing pipeline; comments themselves are NOT individually signed
    (the audit log on the tracker is the signed record).

## REQUIRES-OPERATOR-INPUT fields
- `author_user_id`: real authenticated tracker user; no operator
  substitution.
- `body_md`: required; the comment body.
- Tracker URL + token (same env as F.F1).
- When `--ingest-comments` finds zero comments for a finding-uuid the
  AR emits, that is a NORMAL case (no comments → no remarks); not an
  error.

## Test specifications (≥14 tests)
1. `it('createComment inserts a row when body is non-empty and finding exists')`.
2. `it('createComment rejects body > 16 KiB')`.
3. `it('createComment rejects when finding_uuid is unknown')`.
4. `it('createComment rejects when finding is frozen with 409 Locked')`.
5. `it('editComment succeeds within 15 minutes for the author')`.
6. `it('editComment fails outside 15-minute window with EditWindowExpired')`.
7. `it('editComment fails for non-author with 403')`.
8. `it('deleteComment soft-deletes (sets deleted_at) and the comment no longer renders')`.
9. `it('signing off on a finding sets frozen_at on every comment for that finding')`.
10. `it('comment-notifier sends Slack + email to POA&M owner + prior authors')`.
11. `it('comment-notifier parses @username mentions and notifies them')`.
12. `it('AR emit with --ingest-comments embeds each comment as finding.remarks Markdown with the comment-uuid prop')`.
13. `it('UI: new-comment textarea is disabled with explanation when frozen')`.
14. `it('UI: edit / delete buttons render only for the author within the edit window')`.

## REO compliance specific to this slice
- Every comment traces to a real authenticated user; no system-
  generated comments; no placeholder threads.
- Comments are append-only after freeze; the freeze is the artifact of
  a real sign-off action (F.F1).
- Notifier failures bubble as `partial-failure` warnings; the comment
  is still persisted (a flaky Slack endpoint must not lose audit
  trail).
- Provenance: every `finding.remarks` Markdown block carries the
  `comment-uuid` prop pointing back to the DB row.
- Signed by: AR is signed by `core/sign.ts` + `core/timestamp.ts`;
  comments themselves are audited via the tracker's signed audit log
  (separate from AR signing).

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/tracker/server/finding-comments.test.ts tests/tracker/server/comment-notifier.test.ts tests/tracker/client/FindingCommentThread.test.tsx
npm run check:reo
```

## Known risks / issues
- **Risk 1 — body Markdown injection**: a malicious body could include
  HTML / XSS. Mitigation: server stores raw; client renders through a
  sanitizing Markdown renderer (e.g. `remark-rehype` + `rehype-sanitize`
  with a strict allowlist). AR emit Markdown subset is restricted
  (no raw HTML, no `<script>`).
- **Risk 2 — freeze race**: if a comment is in flight when sign-off
  completes, the comment could land after freeze. Mitigation:
  `createComment` re-checks `frozen_at` inside the same transaction as
  the insert; second writer hits the lock and gets 409.
- **Risk 3 — notifier delivery failures**: Slack outage or email
  bounce. Mitigation: store the dispatch attempt in a
  `notification_attempts` table with retry-with-backoff (matches the
  pattern in `core/notify.ts`); never block the API response on the
  notifier.
- **Risk 4 — comment thread size in AR**: 50+ comments per finding ×
  100+ findings could bloat the AR Markdown by megabytes. Mitigation:
  paginate by setting `CLOUD_EVIDENCE_AR_COMMENT_LIMIT` (default 50
  per finding); the rest are referenced by URL pointer to the tracker
  detail page.
- **Risk 5 — mention mismatch**: `@username` could match a user who
  no longer exists. Mitigation: resolve at write time and persist the
  user-id; if user is deleted later, the notifier skips them silently.

## Open questions (for implementation session to resolve)
- **Q1**: Does the comment thread support attachments at create time,
  or are attachments separated into the F.F4 walk-through upload?
  Proposal: F.F2 attachments are small inline images (≤ 1 MiB),
  walk-through is the big tool-transcript bundle.
- **Q2**: How is "thread depth" rendered — flat chronological, or
  nested via `parent_comment_id`? Proposal: nested only one level deep
  (matches GitHub PR review threads).
- **Q3**: Should the freeze include a freeze justification, or is the
  sign-off implicit justification?
- **Q4**: When AR comment Markdown exceeds the per-finding limit, do
  we emit a `props[]` entry counting the elided comments, or only the
  URL pointer?

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥14)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-F-SPEC.md Section 7 status table updated
- [ ] This file's frontmatter updated (status=done, commit, date)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-F.F2: Comment threads on findings`
- [ ] Commit amended with hash in STATUS.md + this file + LOOP-F-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: sources + files + build steps + tests + risks.
3. Read `cloud-evidence/docs/loops/LOOP-F-SPEC.md` §2 Dependencies.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Confirm F.F1 is `done` in STATUS.md (this slice's freeze hook hooks
   into F.F1's `createSignoff`).
6. Begin implementation; update Implementation log as you go.
