---
slice_id: P.P4
title: Access agreements + acknowledgments + NDA (PS-6)
loop: P
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A5, P.P2]
blocks: [P.P5]
estimated_effort: 4-5 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# P.P4 — Access agreements + acknowledgments + NDA (PS-6)

## TL;DR
Ship the NIST 800-53 Rev5 PS-6 access-agreement workflow: tracker tables
`access_agreements` (org-authored agreement versions with SHA-pinned
body) + `access_agreement_signatures` (per-user × version signature
ledger). New `.docx` emitter `core/access-agreements.ts` (NDA / AUP /
NDA-with-clearance / rules-of-behavior templates). KSI envelope
`out/KSI-PIY-AGM.json` flags users with IAM access lacking current
signatures (`psFindingKind: 'ps-6-missing'`). Auto-resign enforcer flips
signatures to `requires-resign` when agreement version supersedes;
captures `ip_address` + `user_agent` per signature; SHA-256 pinned body
prevents post-signature agreement edits.

## Status
- Status: pending
- Commit: — (filled when shipped per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
P.P4 reuses the existing `.docx` OOXML emitter pattern from
`core/roe-emit.ts` + `core/insider-threat-program.ts` (LOOP-A.A5 +
P.P1). Adds a new KSI token `PIY-AGM` to `core/ksi-map.ts` mapped to
NIST 800-53 PS-6. The KSI envelope correlates against the IAM-SUS
output (`providers/*/iam.ts` inventory) — users with active IAM
principals but no current signature for any required agreement type
emit Findings. The new `access-agreements-docx` + `access-agreements-
snapshot` roles in `core/submission-bundle.ts:WELL_KNOWN` make both
artifacts first-class submission-bundle outputs.

## Why this slice exists
NIST SP 800-53 Rev5 PS-6 ("Develop and document access agreements …
Verify that individuals requiring access … Sign appropriate access
agreements prior to being granted access; and Re-sign access agreements
… when access agreements have been updated …") is in the FedRAMP
Moderate baseline. Today FedPy has no agreement template, no signature
ledger, no re-sign cadence enforcement; SSP PS-6 implementation cannot
be truthfully cited. P.P4 ships the .docx template emitter + the
tracker signature ledger with canonical-JSON signature evidence per
user × agreement version, closing the gap.

## Authoritative sources (with verbatim quotes)

- **NIST SP 800-53 Rev5 — PS-6 (Access Agreements)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  Verbatim:
  > "a. Develop and document access agreements for organizational
  > systems;
  > b. Review and update the access agreements [Assignment:
  > organization-defined frequency]; and
  > c. Verify that individuals requiring access to organizational
  > information and systems:
  > 1. Sign appropriate access agreements prior to being granted
  > access; and
  > 2. Re-sign access agreements to maintain access to organizational
  > systems when access agreements have been updated or [Assignment:
  > organization-defined frequency]."

- **NIST SP 800-53 Rev5 — PL-4 (Rules of Behavior)** — referenced (not
  primary):
  > "a. Establish and provide to individuals requiring access to the
  > system, the rules that describe their responsibilities and expected
  > behavior for information and system usage, security, and privacy."

  Rules-of-Behavior agreement type ships under PS-6 + PL-4 jointly.

- **FedRAMP Rules of Behavior Template** — typical access-agreement
  content (operator may seed; we don't ship FedRAMP-licensed verbiage,
  only the structural template).
  https://www.fedramp.gov/assets/resources/templates/FedRAMP-Rules-of-Behavior-and-Access-Agreement-Template.docx

- **OSCAL SSP — `implemented-requirements`** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/
  Used for PS-6 implementation statement; carries our extension props
  `agreement-snapshot-uuid`, `signature-ledger-uuid` namespaced `CE_NS`.

## Files to create (exact paths under cloud-evidence/)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/access-agreements.ts`
  — .docx template emitter (OOXML + zip-store pattern). Configurable:
  which agreement types (NDA / AUP / NDA-with-clearance / rules-of-
  behavior). ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/access-agreements-evidence.ts`
  — KSI envelope builder. Pulls tracker snapshots + IAM-SUS inventory;
  emits Findings; writes `out/KSI-PIY-AGM.json`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/access-agreements.ts`
  — Express CRUD routes for `access_agreements` (org-authored).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/access-agreement-signatures.ts`
  — per-signature ledger CRUD (sign + view; immutable after creation).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/access-agreement-resign-enforcer.ts`
  — flips signature status to `requires-resign` when agreement version
  bumps.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/AccessAgreements.tsx`
  — list + version history UI.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/pages/AccessAgreementSign.tsx`
  — per-user sign flow (user reads agreement → confirms → server
  records signature with ip + user_agent).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/access-agreements.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/access-agreements-evidence.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/access-agreements.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/routes/access-agreement-signatures.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/access-agreement-resign-enforcer.test.ts`

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` —
  register `PIY-AGM` token with PS-6 mapping (+ PL-4 secondary mapping).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` —
  new `--access-agreements` flag + env `CLOUD_EVIDENCE_ACCESS_AGREEMENTS`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` —
  PS-6 implementation statement reads agreement metadata + signature
  counts; populates `implementation-statement.description` + adds props
  `agreement-snapshot-uuid`, `signature-ledger-uuid`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — add roles `access-agreements-docx` (filename `access-agreements.docx`)
  + `access-agreements-snapshot` (filename `.access-agreements-snapshot.json`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/config/workforce-policy.example.yaml`
  — add `required_agreement_types: ['nda','acceptable-use']` (array) +
  per-type `resign_cadence_days` (default 365).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/schema.sql` — two
  new tables (DDL below).
- `/Users/kenith.philip/FedRAMP 20x/tracker/server/index.ts` — mount
  routes with `requireRole`.
- `/Users/kenith.philip/FedRAMP 20x/tracker/client/src/App.tsx` — add
  `/access-agreements` + `/access-agreements/sign/:uuid` routes.

## Schemas / standards

- **NIST 800-53 Rev5 PS-6** — verbatim above.
- **NIST 800-53 Rev5 PL-4** — verbatim above (secondary).
- **OOXML .docx** — same pattern as `core/insider-threat-program.ts`
  (P.P1) + `core/roe-emit.ts` (LOOP-A.A5).
- **OSCAL SSP** — JSON-reference URL above; extension prop names.
- **rfc8785 canonical JSON** — for signatures (already used across
  cloud-evidence + tracker).

## Build steps (concrete, numbered)

1. **Tracker schema** (idempotent additive DDL):
   ```sql
   CREATE TABLE IF NOT EXISTS access_agreements (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     agreement_type TEXT NOT NULL CHECK (agreement_type IN ('nda','acceptable-use','rules-of-behavior','non-disclosure','contractor-conduct','operator-defined')),
     version TEXT NOT NULL,                  -- e.g. '2026.1'
     title TEXT NOT NULL,
     body_markdown TEXT NOT NULL,            -- operator-authored body
     body_sha256 TEXT NOT NULL,              -- pinned content hash (server-computed)
     effective_at TEXT NOT NULL,
     review_cadence_days INTEGER NOT NULL DEFAULT 365,
     next_review_due TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('draft','active','retired')),
     superseded_by_uuid TEXT,                -- when status flips to retired
     created_by_user_id INTEGER NOT NULL REFERENCES users(id),
     approved_by_user_id INTEGER REFERENCES users(id),  -- AO
     approved_at TEXT,
     signature TEXT NOT NULL,
     signing_key_id TEXT NOT NULL,
     UNIQUE (agreement_type, version)
   );

   CREATE TABLE IF NOT EXISTS access_agreement_signatures (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     uuid TEXT NOT NULL UNIQUE,
     agreement_uuid TEXT NOT NULL REFERENCES access_agreements(uuid),
     user_id INTEGER NOT NULL REFERENCES users(id),
     signed_at TEXT NOT NULL,
     ip_address TEXT NOT NULL,               -- captured from request
     user_agent TEXT NOT NULL,               -- captured from request
     attestation_text TEXT NOT NULL,         -- short verbatim acknowledgement text
     signature TEXT NOT NULL,                -- Ed25519 over canonical JSON
     signing_key_id TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('current','requires-resign','revoked')) DEFAULT 'current',
     UNIQUE (agreement_uuid, user_id)
   );
   CREATE INDEX IF NOT EXISTS idx_sig_user ON access_agreement_signatures(user_id);
   CREATE INDEX IF NOT EXISTS idx_sig_status ON access_agreement_signatures(status);
   ```

2. **Resign enforcer** (`tracker/server/access-agreement-resign-enforcer.ts`):
   - Periodic task (every hour with jitter).
   - When an `access_agreements` row's status flips to `retired` AND a
     `superseded_by_uuid` is set, flip all current signatures for that
     agreement to `requires-resign` (single SQL UPDATE in transaction).
   - Audit log captures each transition.
   - notify.ts fires `access-agreement-resign-required` to affected
     users via email/Slack (existing notification pipeline).
   - When the new agreement version is signed, a fresh row appears in
     `access_agreement_signatures` for the new uuid (not an update).

3. **.docx emitter** (`core/access-agreements.ts`):
   - Inputs: agreement type, version, title, body markdown, signature
     block.
   - Output sections:
     1. Cover page (system, CSP, version, effective_at, AO approval)
     2. Acknowledgements (boilerplate template; operator overrides via
        body_markdown)
     3. Rules / Provisions (verbatim operator body)
     4. Signature block (REQUIRES-OPERATOR-INPUT for ink signatures;
        electronic signatures via tracker ledger)
     5. Provenance (tool name, run id, ksi-map entry, NIST cite)
   - Body markdown rendered to OOXML via a minimal markdown→OOXML
     mapper (paragraphs, bold/italic, lists, links; same pattern as
     core/ssp-2.ts for narrative blocks).

4. **KSI envelope builder** (`core/access-agreements-evidence.ts`):
   - For each tracker user with IAM access (cross-ref IAM-SUS inventory):
     - For each active agreement type the org requires (per
       `workforce-policy.yaml: required_agreement_types`):
       - Lookup current signature → if missing or `requires-resign`,
         emit Finding `psFindingKind: 'ps-6-missing'`.
   - Aggregate: % users with current signature for each agreement type.
   - Emit envelope with provenance block listing tracker URL + IAM-SUS
     inventory path.

5. **SSP integration** (`core/oscal-ssp.ts`): PS-6 implementation
   statement reads agreement metadata + signature counts; populates
   `implementation-statement.description` with templated narrative;
   adds props `agreement-snapshot-uuid` + `signature-ledger-uuid`.

6. **Bundler integration**: add `access-agreements-docx` +
   `access-agreements-snapshot` roles to `submission-bundle.ts:WELL_KNOWN`.

7. **Orchestrator wiring**: `--access-agreements` flag runs AFTER
   providers collect (so IAM cross-ref is fresh), BEFORE POA&M emission.

8. **UI sign-flow** (`AccessAgreementSign.tsx`):
   - User reads the rendered agreement (markdown → HTML, sanitized).
   - User clicks "I have read and agree" button.
   - Client POSTs `{ agreement_uuid, attestation_text }`.
   - Server captures `ip_address` (X-Forwarded-For if proxied; else
     `req.socket.remoteAddress`) + `user_agent` (req headers); generates
     uuid; signs row with Ed25519 over canonical JSON; inserts.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| `body_markdown` per agreement | Operator authors via tracker UI | Agreement cannot be `status='active'` without body; .docx renders REQUIRES-OPERATOR-INPUT in §3 |
| `body_sha256` | Server-computed at agreement create | Server rejects on mismatch; UI shows "body changed since draft" |
| AO approval (`approved_by_user_id`, `approved_at`) | AO clicks approve in UI | `status` cannot flip to `active` without AO approval |
| `required_agreement_types: []` | `config/workforce-policy.yaml` | Default: `['nda','acceptable-use']`; documented |
| Per-type `resign_cadence_days` | `config/workforce-policy.yaml` | Default 365; per-type override allowed |
| Per-user signature | User clicks sign in UI | Missing → KSI Finding `psFindingKind: 'ps-6-missing'` |

## Test specifications

1. `it('rejects agreement_type not in enum')` — POST type=`gdpr` → 422.
2. `it('rejects active status without AO approval')` — flip
   draft→active without `approved_by_user_id` set → 422.
3. `it('body_sha256 must match canonical sha of body_markdown')` —
   server re-computes; mismatch → 422.
4. `it('signature row enforces UNIQUE(agreement_uuid, user_id)')` —
   duplicate POST → 409.
5. `it('signing a new version creates a new signature row')` — version
   2026.1 → 2026.2, both signature rows coexist.
6. `it('retiring an agreement flips all signatures to requires-resign')`
   — N=5 signatures, retire, assert N=5 status=`requires-resign`.
7. `it('reader emits psFindingKind=ps-6-missing for IAM user lacking signature')`
   — IAM-SUS shows active principal, no signature row → Finding.
8. `it('reader respects workforce-policy.yaml required_agreement_types')` —
   `['nda']` only → assert no AUP Finding emitted.
9. `it('reader emits ps-6-missing for requires-resign status')`.
10. `it('.docx body matches body_markdown rendered to OOXML')` — round-trip
    fixture markdown through emitter; assert text content preserved.
11. `it('signs agreement row + signature row with Ed25519')` — verify
    via `core/sign.ts`.
12. `it('captures ip + user_agent verbatim from request')` — X-Forwarded-For
    chain handled (rightmost public IP).
13. `it('KSI-PIY-AGM envelope provenance.emitter set')` — `check:provenance`
    script exits 0.
14. `it('--strict-workforce fails build (exit 2) on any ps-6-missing finding')`.
15. `it('SSP PS-6 implementation statement carries agreement-snapshot-uuid prop')`.
16. `it('UI sign-flow rejects signing of draft or retired agreements')`.

## REO compliance specific to this slice

- Every agreement body operator-authored; sha-pinned at create;
  immutable thereafter. Status transitions (draft→active→retired) are
  signed individually.
- Every signature row signed (Ed25519 over canonical JSON); ip +
  user_agent captured to make spoofing visible at audit time.
- No system-generated signatures; we never auto-sign on behalf of a
  user (REO Rule 1.10).
- KSI envelope provenance block lists tracker URL + snapshot time +
  IAM-SUS inventory path + signingKeyId.
- Signed by existing `core/sign.ts` pipeline.
- No `process.env.NODE_ENV === 'test'` branches.

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/access-agreements.test.ts tests/core/access-agreements-evidence.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd ../tracker
npm run typecheck
npm test -- server/routes/access-agreements.test.ts server/routes/access-agreement-signatures.test.ts server/access-agreement-resign-enforcer.test.ts
```

## Known risks / issues

- **Risk 1: Body SHA-256 calculated server-side vs operator-supplied.**
  Operator could pre-compute and submit a stale hash matching an old
  body. Mitigation: server always recomputes from the submitted markdown
  and writes the recomputed value; operator-supplied `body_sha256` is
  ignored on write, compared on read.
- **Risk 2: ip_address spoofing via X-Forwarded-For header.**
  Mitigation: tracker config declares trusted proxy CIDR ranges; only
  the trusted-most-recent value is taken (right-most after stripping
  trusted proxies); fallback to `req.socket.remoteAddress`; documented
  in CHANGELOG; signature still binds to canonical JSON including the
  ip recorded.
- **Risk 3: Signature ledger grows unbounded.**
  Mitigation: index on `user_id` + `status`; pagination + filter UI;
  archival policy in runbook (signatures older than 7 years moved to
  cold storage via LOOP-H.H1 retention slice).
- **Risk 4: Agreement markdown could include malicious links / scripts.**
  Mitigation: client-side sanitization in `AccessAgreementSign.tsx`
  (DOMPurify with strict allowlist); .docx emitter strips raw HTML.
- **Risk 5: User signs an agreement, then admin retires the agreement
  before audit pull.** Signature row's status flips to `requires-resign`,
  but the audit needs to verify the user DID sign the prior version.
  Mitigation: signature rows are immutable; the historical `signed_at` +
  agreement_uuid preserves the original signing event; the status field
  only reflects current applicability.
- **Risk 6: PS-6 (c)(2) "re-sign at organization-defined frequency"
  could conflict with version-supersession trigger.**
  Mitigation: both conditions are OR'd; resign required when EITHER
  (a) version superseded OR (b) signature age > `resign_cadence_days`;
  enforcer task implements both.
- **Risk 7: AO approval workflow could be bypassed via direct SQL.**
  Mitigation: RBAC enforced at HTTP layer; SQL write paths route through
  Express handlers that validate session role; CHANGELOG warns about
  manual SQL edits.

## Open questions

- **Q1**: Should the .docx ship a baseline NDA template (operator
  starting point), or empty by default? Recommendation: ship a minimal
  template that says "REPLACE THIS WITH YOUR ORGANIZATION'S NDA" + cite
  NIST PS-6 control statement — operator edits to fit.
- **Q2**: When agreement version supersedes, should the resign enforcer
  send a single notification per user, or per (user × agreement_type)?
  Recommendation: per (user × agreement_type) with templated language
  describing what changed.
- **Q3**: Should we capture the user's typed `attestation_text` to
  ensure they read the agreement (e.g. "type the title of this
  agreement to confirm")? Or rely on click-through? Recommendation:
  click-through for v1; type-to-confirm is a follow-up enhancement.

## Implementation log

```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist

- [ ] typecheck clean (cloud-evidence + tracker)
- [ ] tests passing 100% (≥16 new tests this slice)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (P.P4 slice row + Overall section)
- [ ] LOOP-P-SPEC.md §8 status table updated (P.P4 row)
- [ ] This file's frontmatter updated (status, commit, completed_date)
- [ ] CHANGELOG.md "Unreleased" entry added (cites PS-6 + PL-4 verbatim)
- [ ] Commit with `LOOP-P.P4:` slice ID in message
- [ ] Commit amended hash recorded in STATUS.md + this file + LOOP-P-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read this file (P.P4.md).
3. Read `cloud-evidence/docs/loops/LOOP-P-SPEC.md` §5 P.P4 + §4 sources.
4. Read `cloud-evidence/docs/loops/LOOP-P-RISKS.md` — live risks register.
5. Read `cloud-evidence/docs/slices/P/P.P1.md` — pattern for the .docx
   OOXML emitter (insider-threat-program.ts mirrors here).
6. Read `cloud-evidence/docs/slices/P/P.P2.md` — pattern for the KSI
   envelope builder + IAM-SUS correlation (personnel-evidence.ts mirrors).
7. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
8. Read `cloud-evidence/core/roe-emit.ts` — the .docx OOXML pattern.
9. Read `tracker/server/schema.sql` — add the two new tables additively.
10. Begin implementation; update Implementation log section as you go.
