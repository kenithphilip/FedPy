---
slice_id: G.G1
title: AFR-FSI (FedRAMP Security Inbox)
loop: G
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A3, LOOP-A.A4, REO-0]
blocks: [LOOP-E.E6, LOOP-F.F4, LOOP-I.I1]
estimated_effort: 5 days
last_updated: 2026-06-06
---

# G.G1 — AFR-FSI (FedRAMP Security Inbox)

## TL;DR
Ships the FedRAMP Security Inbox config-of-record + a webhook-fed, HMAC-validated receipt
ledger so the CSP can prove it owns a monitored, classification-aware mailbox that meets all
six FSI MUSTs (INB, TFG, RCV, NOC, CRA, EMR). Without this slice the CSP cannot pass the
FedRAMP "verified email" precondition for onboarding (FSI-FRP-VRE).

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
FedRAMP 20x onboarding (RFC-0006 §"Continuous Reporting Standard") requires every Cloud
Service Offering to operate a monitored email endpoint to receive FedRAMP-originated
messages. The FSI is the single channel FedRAMP uses to send emergency directives, test
notices, and routine bulletins. Six MUSTs in FRMR.documentation.json v0.9.43-beta apply
at Moderate (FSI-CSO-INB/TFG/RCV/NOC/CRA/EMR — see source quotes below). Today the
codebase has no FSI artifact; this slice closes that gap by emitting a config-of-record
(`out/afr-fsi/inbox-config.json`) plus a receipt ledger (`out/afr-fsi/receipt-ledger.json`)
that maps directly to those MUSTs. NIST SP 800-53 Rev5 §IR-6 ("Incident Reporting") is
the closest underlying control, but FSI is FedRAMP-specific scope.

## Authoritative sources (with verbatim quotes)

- https://www.fedramp.gov/rfcs/0006/ — FedRAMP RFC-0006 "Continuous Reporting Standard":
  > "Providers must establish a verified email inbox to receive messages from FedRAMP and
  > respond to messages without disruption to the cloud service offering."
  (Context: §"Required reporting channels", retrieved 2026-06-06.)

- https://github.com/FedRAMP/docs (file: `FRMR.documentation.json` v0.9.43-beta, FSI-CSO-INB / FRR-FSI-09):
  > "Providers MUST establish and maintain an email address to receive messages from FedRAMP;
  > this inbox is a FedRAMP Security Inbox (FSI)."

- https://github.com/FedRAMP/docs (FSI-CSO-TFG / FRR-FSI-10):
  > "Providers MUST treat any email originating from an @fedramp.gov or @gsa.gov email
  > address as if it was sent from FedRAMP by default; if such a message is confirmed to
  > originate from someone other than FedRAMP then FedRAMP Security Inbox requirements no
  > longer apply."

- https://github.com/FedRAMP/docs (FSI-CSO-RCV / FRR-FSI-11):
  > "Providers MUST receive and react to email messages from FedRAMP without disruption
  > and without requiring additional actions from FedRAMP."

- https://github.com/FedRAMP/docs (FSI-CSO-NOC / FRR-FSI-12):
  > "Providers MUST immediately notify FedRAMP of any changes in addressing for their
  > FedRAMP Security Inbox by emailing info@fedramp.gov with the name and FedRAMP ID of
  > the cloud service offering and the updated email address."

- https://github.com/FedRAMP/docs (FSI-CSO-CRA / FRR-FSI-14):
  > "Providers MUST complete the required actions in Emergency or Emergency Test
  > designated messages sent by FedRAMP within the timeframe included in the message."

- https://github.com/FedRAMP/docs (FSI-CSO-EMR / FRR-FSI-15):
  > "Providers MUST route Emergency designated messages sent by FedRAMP to a senior
  > security official for their awareness."

- https://datatracker.ietf.org/doc/html/rfc5321 — RFC 5321 "Simple Mail Transfer Protocol",
  §4.1.2 (Mailbox = local-part "@" Domain). Used for the `email_endpoint` validator regex.

- https://datatracker.ietf.org/doc/html/rfc6376 — RFC 6376 "DomainKeys Identified Mail
  (DKIM) Signatures", §3.5 (verifier result reporting). Used for `dkim_pass` cell semantics.

- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — NIST SP 800-53 Rev5 §IR-6
  Incident Reporting:
  > "Require personnel to report suspected incidents to the organizational incident response
  > capability within [Assignment: organization-defined time period]."
  (Indirect control mapping — FSI is FedRAMP-specific, but IR-6 establishes the broader
  obligation to operate an incident-reporting channel.)

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/afr-fsi.ts` — pure builder + disk emitter for the FSI config-of-record JSON; pure validators for inbox-config fields; pure routine to dump `fsi_message_log` rows to a signed `fsi-receipt-ledger.json`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/afr-fsi.test.ts` — unit tests for builder + validators + ledger dump (≥13 cases).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-fsi.ts` — REST endpoints: GET/POST `/api/afr-fsi/config`, POST `/api/afr-fsi/messages` (webhook receive), GET `/api/afr-fsi/messages?since=…`, POST `/api/afr-fsi/messages/:msg_id/ack`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-fsi.test.ts` — route tests (HMAC, DB constraints, classification).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/FsiInbox.tsx` — operator UI: configure inbox endpoint, view receipt log, mark required actions complete.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/AFR-FSI-RUNBOOK.md` — operator runbook (how to point SES / SendGrid / Microsoft 365 inbox at the tracker webhook; how to verify @fedramp.gov DKIM/SPF/DMARC).

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--afr-fsi` flag + `CLOUD_EVIDENCE_AFR_FSI` env. Calls `emitAfrFsi(outDir, ctx)`. Console output reports inbox endpoint + receipt-log size + open required-actions count.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — well-known catalogue rows for `afr-fsi/inbox-config.json` (`role: 'afr-fsi-config'`) + `afr-fsi/receipt-ledger.json` (`role: 'afr-fsi-ledger'`). Marked `required: false` at L1 ATO baseline, `required: true` at the 1-year renewal bundle.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/scn-classifier.ts` — when a classified change touches the FSI endpoint (Source IP, MX record, email address), trigger an `FSI-CSO-NOC` notification record in `fsi_message_log` so the change is logged at-source.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/schema.sql` — additive `CREATE TABLE IF NOT EXISTS fsi_inbox_config (...)` + `CREATE TABLE IF NOT EXISTS fsi_message_log (...)`. Includes idx on `received_at` and unique on `msg_id`.

## Schemas / standards

### `FsiInboxConfig` (defined in `core/afr-fsi.ts`)

| Field | Type | Source | Required |
|---|---|---|---|
| `email_endpoint` | RFC 5321 mailbox string | tracker UI / `fsi_inbox_config.email_endpoint` | REQUIRES-OPERATOR-INPUT |
| `csp_id` | string (FedRAMP-issued CSO id) | CLI `--csp-id` OR SSP `system-id` | REQUIRES-OPERATOR-INPUT when SSP absent |
| `csp_name` | string | SSP `metadata.title` | auto |
| `senior_security_official_email` | RFC 5321 mailbox | tracker UI | REQUIRES-OPERATOR-INPUT |
| `trust_list[]` | `{pattern, verified_at, verified_by}` | tracker verification dialog | REQUIRES-OPERATOR-INPUT (must contain both @fedramp.gov + @gsa.gov) |
| `verified_no_disruption_runbook_url` | URL | tracker UI | REQUIRES-OPERATOR-INPUT |
| `last_noc_notification_sent_at` | ISO 8601 / RFC 3339 | derived from `fsi_message_log` | nullable |
| `provenance` | `{emitter, emittedAt, sourceCalls, requirementTexts}` | computed | required (REO Rule 1, CLAUDE.md §) |

Deterministic field order via `Object.fromEntries(sortedKeys.map(...))`. RFC 3339 timestamps
with seconds precision.

### `FsiMessageLogRow` (DB shape mirrored in JSON dump)

| Column | Type | Source |
|---|---|---|
| `msg_id` | TEXT PRIMARY KEY | `sha256(from + subject + received_at)` |
| `from` | TEXT NOT NULL | RFC 5322 From header |
| `to` | TEXT NOT NULL | RFC 5322 To header (must match `email_endpoint`) |
| `subject` | TEXT NOT NULL | RFC 5322 Subject |
| `classification` | TEXT CHECK IN ('Emergency','EmergencyTest','Routine','Unclassified') | derived from subject prefix |
| `received_at` | TEXT NOT NULL | RFC 3339 — webhook receive timestamp |
| `dkim_pass` | INTEGER NULLABLE | DKIM verdict from provider |
| `routed_to` | TEXT (JSON array) | emails the message was forwarded to |
| `required_action_summary` | TEXT NULLABLE | operator-extracted |
| `required_action_deadline` | TEXT NULLABLE | operator-extracted |
| `action_completed_at` | TEXT NULLABLE | operator click |
| `action_completed_by_user_id` | TEXT NULLABLE | tracker auth context |

Subject-prefix classification rules (from FedRAMP RFC-0006 §Message classes):
- `[FedRAMP-EMERGENCY] *` → `Emergency`
- `[FedRAMP-EMERGENCY-TEST] *` → `EmergencyTest`
- Any other recognized prefix → `Routine`
- Unparseable → `Unclassified` (held until operator triage)

## Build steps (concrete, numbered)

1. Define interfaces `FsiInboxConfig`, `FsiMessageLogRow`, `FsiEmitOptions`, `FsiEmitResult`,
   `FsiInputs` in `core/afr-fsi.ts`. All shapes deterministic.
2. Pure builder `buildFsiArtifacts(input: FsiInputs, opts: FsiEmitOptions): FsiEmitResult`
   returning `{ inboxConfig, receiptLedger: { rows, checksum, requires_operator_input }, ready_for_signature, requires_operator_input }`. No I/O.
3. Disk emitter `emitAfrFsi(outDir: string, ctx: OrchestratorContext): Promise<FsiEmitResult>`:
   - Read `out/ssp.json` if present → seed `csp_name` + `csp_id` from `metadata.title` + `system-id`.
   - Query tracker DB for current `fsi_inbox_config` row + all `fsi_message_log` rows since last run.
   - Call `buildFsiArtifacts`.
   - Write `out/afr-fsi/inbox-config.json` + `out/afr-fsi/receipt-ledger.json`.
   - Append `provenance` block (emitter path, RFC 3339 emittedAt, sourceCalls list, requirementTexts map).
4. Wire orchestrator: `--afr-fsi` flag + `CLOUD_EVIDENCE_AFR_FSI` env. Runs BEFORE signing so artifacts are covered by the manifest.
5. Add to `core/submission-bundle.ts` catalogue:
   - row 1: `role='afr-fsi-config'`, `filename='afr-fsi/inbox-config.json'`
   - row 2: `role='afr-fsi-ledger'`, `filename='afr-fsi/receipt-ledger.json'`
6. Schema migration in `tracker/server/schema.sql` (`CREATE TABLE IF NOT EXISTS …`).
7. Tracker routes: validate inbox endpoint with RFC 5321 regex; webhook auth via HMAC-SHA256
   of shared secret stored in env `CLOUD_EVIDENCE_FSI_WEBHOOK_SECRET` (rotated quarterly per
   operator runbook). On receive, derive `classification` from subject prefix; auto-route to
   `senior_security_official_email` for `Emergency`.
8. Tracker UI page: form to set inbox + senior-security-official, table of received messages,
   "Acknowledge action complete" button (records `action_completed_at` + `action_completed_by_user_id`).
9. Validation pass: JSON schema check on inbox-config (no ajv needed; hand-rolled validator
   in `core/afr-fsi.ts:validateInboxConfig`).
10. Sign+timestamp: covered by existing `core/sign.ts` pipeline (Ed25519 + RFC 3161).

## REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4 (CLAUDE.md §Rule 4):

| Field | Source | What happens when missing |
|---|---|---|
| `email_endpoint` | tracker UI form field `inbox_endpoint`, persisted in `fsi_inbox_config` | `requires_operator_input` includes `email_endpoint` with explanation pointing at the tracker UI; `ready_for_signature=false`; orchestrator exits 4 in `--strict-bundle` |
| `csp_id` | CLI `--csp-id` OR tracker UI; auto from SSP `system-id` when SSP exists | same — REQUIRES-OPERATOR-INPUT marker emitted, never a fake CSO id |
| `senior_security_official_email` | tracker UI | same — emitter raises REQUIRES-OPERATOR-INPUT; FSI-CSO-EMR cannot be evidenced |
| `trust_list[].verified_at` + `verified_by` | tracker UI verification dialog (operator confirms a test message from @fedramp.gov / @gsa.gov was received) | row stays with `verified_at=null` and emitter marks REQUIRES-OPERATOR-INPUT for FSI-CSO-TFG |
| `verified_no_disruption_runbook_url` | tracker UI form | REQUIRES-OPERATOR-INPUT for FSI-CSO-RCV |
| `dkim_pass` per incoming message | email provider header parser (SES `mail.dkim.verdict`, Microsoft 365 `Authentication-Results`) | when unparseable the row is `held=true` and never auto-routes; operator triages |

## Test specifications (≥13 tests)

1. `it('builds inbox config from SSP-derived csp_name + csp_id')` — feed a synthetic SSP JSON; assert `csp_name`+`csp_id` match SSP metadata; assert `provenance.sourceCalls` includes `out/ssp.json`.
2. `it('emits REQUIRES-OPERATOR-INPUT for email_endpoint when no tracker row exists')` — `requires_operator_input` contains the field name and a tracker-UI explanation; `ready_for_signature=false`.
3. `it('emits REQUIRES-OPERATOR-INPUT for senior_security_official_email when missing')` — and assert that `Emergency` messages cannot be routed (route audit log shows hold).
4. `it('verifies trust_list contains both @fedramp.gov and @gsa.gov patterns')` — both required per FSI-CSO-TFG; missing either → `requires_operator_input`.
5. `it('classifies "[FedRAMP-EMERGENCY] Patch required" as Emergency')` — derived classification matches.
6. `it('classifies "[FedRAMP-EMERGENCY-TEST] …" as EmergencyTest')` — derived classification matches.
7. `it('classifies bare subject as Routine')` — falls through to default class.
8. `it('rejects messages with dkim_pass=false from @fedramp.gov pattern')` — sets `held=true`, never auto-routes; emits an alert event row.
9. `it('computes msg_id as sha256(from+subject+received_at)')` — deterministic; idempotent on re-ingest (same input → upsert, not duplicate).
10. `it('flags overdue required-action rows')` — `action_completed_at=null AND required_action_deadline < now` → `overdue` row appears in result; FSI-CSO-CRA breach surfaced.
11. `it('writes receipt-ledger checksum that matches body sha256')` — checksum integrity (compute sha256 of the serialized rows array and compare against `checksum`).
12. `it('records provenance.requirementTexts for all 6 FSI-CSO MUSTs verbatim')` — every FRMR statement (INB/TFG/RCV/NOC/CRA/EMR) appears in `provenance.requirementTexts`.
13. `it('webhook HMAC-validates request signature')` — route test with valid HMAC accepts; invalid HMAC returns 401 and writes nothing.
14. `it('auto-routes Emergency messages to senior_security_official_email')` — `routed_to[]` includes the configured address for `classification=Emergency`.
15. `it('does NOT auto-route Routine messages')` — `routed_to[]` is empty unless operator explicitly forwards.

## REO compliance specific to this slice

- Every value in `inbox-config.json` traces to: (a) SSP-derived auto-value, (b) tracker DB row, OR (c) `REQUIRES-OPERATOR-INPUT` marker. The emitter NEVER substitutes a default email like `security@example.com`.
- `provenance.requirementTexts` carries the verbatim FRMR statement for each of the 6 MUSTs so a 3PAO can cite the obligation directly from the artifact.
- The webhook never auto-acknowledges required actions — operators must click in the UI; the click is captured in `action_completed_by_user_id` (real human action, REO Rule 1.10).
- No silent fallbacks: a missing inbox config → `ready_for_signature=false` → orchestrator exit code 4 in `--strict-bundle` mode.
- Signed by: existing `core/sign.ts` pipeline (Ed25519 + RFC 3161 timestamp).
- Provenance fields populated: `emitter`, `emittedAt`, `sourceCalls`, `requirementTexts`, `runId`.

## Verification commands

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/afr-fsi.test.ts
npm test -- tracker/server/routes/afr-fsi.test.ts
npm run check:reo
```

## Known risks / issues

- **Risk 1 — FSI webhook spec is not standardized.** FedRAMP has not published a normalized inbound-webhook schema for FSI senders; each email provider (SES, SendGrid, Microsoft 365, Google Workspace) emits a different JSON envelope. Mitigation: the HMAC-validated tracker webhook accepts a minimal canonical shape (`{from, to, subject, received_at, headers}`) and operator runbook explains how to map provider-specific webhooks into it. If FedRAMP later publishes a sender format, only the `classification` derivation in `afr-fsi.ts` needs to change.
- **Risk 2 — DKIM result unavailability.** Some providers (older SMTP relays, self-hosted Postfix) don't surface DKIM verdicts in webhook payloads. Mitigation: `dkim_pass=null` triggers `held=true` and the message is queued for operator triage; never auto-routed.
- **Risk 3 — Senior security official email is a single point of failure.** If the configured address is wrong or the SSO is unavailable, Emergency directives are not seen. Mitigation: support an array `senior_security_official_emails[]` (multi-recipient) in a follow-up, but for G.G1 v1 a single address is sufficient — runbook recommends a distribution list.
- **Risk 4 — Webhook secret rotation.** Quarterly rotation per operator runbook is operator-driven; missed rotation could leak. Mitigation: tracker emits a `secret_age_days` metric; LOOP-I.I1 dashboard surfaces it.
- **Risk 5 — Late notification of FSI endpoint changes (FSI-CSO-NOC).** Operator forgets to email `info@fedramp.gov` when changing the inbox. Mitigation: `scn-classifier.ts` extension catches MX-record / address changes and inserts a `FSI-CSO-NOC` reminder row in `fsi_message_log`.

## Open questions (for implementation session to resolve)

- **Q1**: Do we expose a `--fsi-webhook-secret` CLI flag or strictly require the env var? Recommendation: env var only (avoid CLI history leakage).
- **Q2**: Should `held=true` messages auto-expire after N days, or stay forever for audit? Recommendation: forever for audit; LOOP-H.H2 will enforce retention.
- **Q3**: For `subject` prefixes that mix Emergency + Test (e.g. "[FedRAMP-EMERGENCY-TEST]"), should we treat the prefix check as case-sensitive? Recommendation: case-sensitive to match FedRAMP's published convention; document in runbook.
- **Q4**: When SSP `system-id` is missing AND CLI `--csp-id` is missing AND tracker `csp_id` is empty, do we throw or emit a marker? Recommendation: emit a marker (`ready_for_signature=false`) and continue producing the receipt ledger — never throw mid-pipeline.
- **Q5**: For the receipt-ledger JSON dump, do we include `routed_to[]` recipient addresses (PII concern) or strip them? Recommendation: include them (they are CSP-internal SSO addresses, not customer PII; the artifact is internal-only at this stage).

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~15 for this slice's new tests + ~4 route tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section: increment next-priority to G.G2)
- [ ] LOOP-G-SPEC.md §7 status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-G.G1: AFR-FSI (FedRAMP Security Inbox)`
- [ ] Commit with `LOOP-G.G1:` in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-G-SPEC.md
- [ ] Pushed to origin/main
- [ ] AFR-FSI-RUNBOOK.md authored
- [ ] End-to-end orchestrator smoke: `npm run collect -- --impact-level moderate --afr-fsi` produces `out/afr-fsi/inbox-config.json` + `out/afr-fsi/receipt-ledger.json` + signed manifest entries.

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context, here's everything it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-G-SPEC.md` §2 (Dependencies) and §4 (Slice G.G1) for context.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Read `cloud-evidence/core/roe-emit.ts` to understand the dependency-free `.docx` and pure-builder pattern; mirror for any docs.
6. Read `cloud-evidence/core/submission-bundle.ts` to understand the catalogue-row pattern.
7. Read `cloud-evidence/core/sign.ts` to understand how artifacts get signed + timestamped.
8. Read `cloud-evidence/tracker/server/schema.sql` to understand additive migration style.
9. Begin implementation; update Implementation log section as you go.
