---
slice_id: H.H2
title: Audit retention policy enforcement (AU-11 ConMon control)
loop: H
status: pending
commit: —
completed_date: —
depends_on: [H.H1]
blocks: [E.E3]
estimated_effort: 4 working days (1 senior engineer)
last_updated: 2026-06-06
---

# H.H2 — Audit retention policy enforcement (AU-11)

## TL;DR
A monthly (default cadence) verifier that walks every entry in `archive-catalog.json`, calls the cloud provider's get-retention API for each archived bundle, and emits a `KSI-AU-11.json` evidence envelope plus a `retention-compliance-report.json`. Drift (mode wrong, retain-until shortened, storage-class downgraded, legal-hold flipped off) raises findings + notify events. Closes the AU-11 *ongoing-conformance* gap and the CA-7 *evidence-availability* gap.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
H.H1 *creates* the immutable archive; H.H2 *proves* it stays immutable. Initial WORM setup is necessary but not sufficient — AU-9 + AU-11 are ongoing controls. A 3PAO assessor on an annual reassessment, or the PMO on a ConMon spot check, will ask "show me that every retention-protected bundle remains protected as of last month's run." H.H2 produces the evidence:

- **NIST SP 800-53 Rev 5 AU-11** — ongoing retention conformance, not just initial setup.
- **NIST SP 800-53 Rev 5 AU-9 + AU-9(2) + AU-9(3)** — verify on a schedule that lock-mode, separation, and crypto-protection remain intact.
- **NIST SP 800-53 Rev 5 CA-7** — continuous monitoring control under which audit-record availability is itself an evidence stream. H.H2 emits its findings as a `KSI-AU-11.json` envelope so the existing manifest/sign/coverage pipeline picks it up unchanged.
- **FedRAMP Rev5 ConMon Playbook** — monthly cadence for evidence upload aligns the H.H2 default cadence with the published expectation.

## Authoritative sources (with verbatim quotes)

- <https://csf.tools/reference/nist-sp-800-53/r5/au/au-11/> — AU-11 control statement:
  > "Retain audit records for [Assignment: organization-defined time period] to provide support for after-the-fact investigations of incidents and to meet regulatory and organizational information retention requirements."

- <https://csf.tools/reference/nist-sp-800-53/r5/ca/ca-7/> — CA-7 Continuous Monitoring:
  > "Develop a system-level continuous monitoring strategy and implement continuous monitoring in accordance with the organization-level continuous monitoring strategy that includes: a. Establishing the following system-level metrics to be monitored... e. Ongoing monitoring of organizationally-defined metrics in accordance with the continuous monitoring strategy..."

- <https://csf.tools/reference/nist-sp-800-53/r5/au/au-9/> — AU-9 (also requires *Alert* on unauthorized modification, which H.H2 implements via the existing `core/notify.ts` channel).

- <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectRetention.html> — AWS S3 GetObjectRetention:
  > "Retrieves an object's retention settings. Permissions: You must have the `s3:GetObjectRetention` permission to use this operation."
  > Response includes `Retention.Mode` (`GOVERNANCE` | `COMPLIANCE`) and `Retention.RetainUntilDate`.

- <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLegalHold.html> — AWS S3 GetObjectLegalHold:
  > "Gets an object's current legal hold status."

- <https://cloud.google.com/storage/docs/json_api/v1/objects/get> — GCS objects.get:
  > Response includes `retention` object: `retention.mode` (`Locked` | `Unlocked`) + `retention.retainUntilTime`.

- <https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob-properties> — Azure Get Blob Properties:
  > Response headers include `x-ms-immutability-policy-until-date`, `x-ms-immutability-policy-mode` (`unlocked` | `locked`), `x-ms-legal-hold`.

- <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/> — FedRAMP ConMon Playbook:
  > "Each month, the CSP uploads an up-to-date POA&M and inventory, along with raw vulnerability scan files (when required by agreements with agency customers) and reports to the secure repository."

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/retention-policy.ts` — pure `verifyRetention(entry, providerResponse)` + `buildRetentionReport(entries, opts)` + disk emitter `emitRetentionReport()`. ~350 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/retention-collector.ts` — pulls live state from the archive bucket for every entry in `archive-catalog.json`, reconciles vs the catalog, returns findings. Emits `out/KSI-AU-11.json`. ~300 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/retention-policy.test.ts` — ≥12 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/retention-collector.test.ts` — ≥10 tests.

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — `--verify-retention` flag + `CLOUD_EVIDENCE_VERIFY_RETENTION` env. Runs **after** `--archive` (or standalone). Emits per-entry one-line summary + a roll-up `[ok N | warn N | fail N]`. `--annual` modifier produces an additional human-readable annual roll-up.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ksi-map.ts` — register `KSI-AU-11` with new `audit-retention` category, mapped to NIST controls `AU-9`, `AU-9(2)`, `AU-9(3)`, `AU-11`. Multi-cloud collector.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts` — add `retention-coverage` registry block: 4 columns × 3 clouds = 12 cells (lock-mode-correct, retain-until-correct, storage-class-correct, manifest-sig-still-verifies).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add `audit-retention-report` (filename `retention-compliance-report.json`) and `audit-retention-evidence` (filename `KSI-AU-11.json`) to `WELL_KNOWN`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/notify.ts` — extend so a `retention-violation` event type routes Slack/PagerDuty when configured.

## Schemas / standards

### KSI-AU-11 envelope
- Standard `core/envelope.ts` shape used by every other KSI emitter:
  ```json
  {
    "ksi_id": "KSI-AU-11",
    "category": "audit-retention",
    "run_id": "<runId>",
    "collected_at": "<iso>",
    "frmr_version": "<version>",
    "providers": [
      { "name": "aws", "evidence": [{ "kind": "retention-status", "source": "S3.GetObjectRetention", "data": {...} }] }
    ],
    "findings": [...]
  }
  ```
- Signed + manifested + coverage-reported by the existing pipeline.

### Per-cloud read APIs
- **AWS:** `GetObjectRetention` + `GetObjectLegalHold` + `HeadObject` (for StorageClass). Required permissions: `s3:GetObjectRetention`, `s3:GetObjectLegalHold`, `s3:GetObject` (HEAD), `s3:GetBucketObjectLockConfiguration`. These can be granted to the read-only role (no write privileges needed).
- **GCS:** `storage.objects.get` with `fields=retention,storageClass,customer Metadata` + `storage.buckets.get` for the bucket-level lock state. Permissions: `storage.objects.get`, `storage.buckets.get`.
- **Azure:** `BlobClient.getProperties()` (returns immutability-policy headers) + `ContainerClient.getProperties()` (returns container-level lock state). Permissions: `Microsoft.Storage/storageAccounts/blobServices/containers/read`, `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`.

### Drift severity rules (table baked into `SEVERITY_RULES`)
- Mode wrong (`COMPLIANCE` → `GOVERNANCE` / `Unlocked`): **critical**.
- Retain-until shortened vs catalog: **high**.
- Storage class downgraded (`DEEP_ARCHIVE` → `STANDARD`, `ARCHIVE` → `STANDARD`): **medium**.
- Legal hold flipped off when previously on: **medium**.
- Bucket lock-state un-locked (GCS `retentionPolicy.isLocked = false` after being true): **critical**.

### Annual report shape
- When `--verify-retention --annual` is set, additionally write `out/au-11-annual-<YYYY>.json` + `out/au-11-annual-<YYYY>.md`: human-readable roll-up across the prior 12 months of archives — count, bytes, projected expiry calendar, control mapping (AU-9 / AU-9(2) / AU-9(3) / AU-11) with explicit compliant / non-compliant verdicts per control.

## Build steps (concrete, numbered)

1. Define interfaces in `core/retention-policy.ts`:
   ```ts
   export interface RetentionStatus {
     entry: ArchiveEntry;
     observed_lock_mode: string;
     observed_retain_until: string;
     observed_storage_class: string;
     observed_legal_hold: boolean;
     drift: Array<{ field: string; expected: string; observed: string; severity: 'low' | 'medium' | 'high' | 'critical' }>;
     manifest_signature_still_valid: boolean | 'not-checked';
     verified_at: string;
   }
   export interface RetentionReport {
     run_id: string;
     verified_at: string;
     entries_total: number;
     entries_compliant: number;
     entries_with_drift: number;
     entries_expired_or_unprotected: number;
     drift_summary: RetentionStatus[];
     provenance: { emitter: string; emittedAt: string; sourceCalls: string[]; signingKeyId: string };
   }
   ```
2. Pure `verifyRetention(entry, providerResponse)`:
   - AWS: expect `providerResponse.ObjectLockMode === 'COMPLIANCE'` + `providerResponse.ObjectLockRetainUntilDate >= entry.retain_until`.
   - GCS: expect `providerResponse.retention.mode === 'Locked'` + `retainUntilTime >= entry.retain_until`.
   - Azure: expect `providerResponse.immutabilityPolicy.policyMode === 'Locked'` + `expiriesOn >= entry.retain_until`.
   - Drift array populated per field; severity assigned from `SEVERITY_RULES` table.
3. `core/retention-collector.ts`:
   - Reads `out/archive-catalog.json` (or path passed via `--catalog-path`).
   - For each entry, constructs a **read-only** SDK client (NOT the archive-writer; just standard read-only Proxy) and calls the get-retention API.
   - Aggregates via `buildRetentionReport()`.
   - Emits findings to a `KSI-AU-11.json` evidence envelope.
4. Disk emitter `emitRetentionReport()` writes `out/retention-compliance-report.json` + `out/KSI-AU-11.json`.
5. Annual report logic — when `--annual` is set, additionally write the `au-11-annual-<YYYY>.{json,md}` pair.
6. Wire into orchestrator: new `--verify-retention` flag triggers `emitRetentionReport()` after archive (in same run) or as a stand-alone job. Add `--annual` and `--deep` modifiers.
7. Notification: when `entries_expired_or_unprotected > 0`, call `notify.notifyDrift({ type: 'retention-violation', ...summary })` so Slack/PagerDuty alert operators immediately.
8. Coverage: update `core/inventory-coverage.ts` with the 12 new cells.
9. Validation pass — ajv-validate emitted `KSI-AU-11.json` against the standard envelope schema; ajv-validate `retention-compliance-report.json` against its own schema.

## REQUIRES-OPERATOR-INPUT fields

- **`production_accounts[]`** — list of AWS account IDs / GCP project IDs / Azure subscription IDs the production evidence pipeline runs from. H.H2 asserts the archive bucket account is NOT in this list (AU-9(2) physical separation). Source: `config.yaml:archive.production_accounts[]`. Missing → emit `REQUIRES-OPERATOR-INPUT` in the report's `au_9_2_separation` field.
- **`retention_parameter_declared_years`** — the value the SSP declares in AU-11. Source: `config.yaml:ssp.controls.AU-11.parameter_years`. Mismatch with `archive.retention_years` surfaces a finding.
- **`personnel_to_alert[]`** — for AU-9 violation alerts. Source: `config.yaml:ssp.controls.AU-9.personnel_to_alert`. Missing → `notifyDrift` falls back to the default Slack/PagerDuty channels declared in `notify.ts` config; report includes `REQUIRES-OPERATOR-INPUT` in `au_9_alerting_personnel` field.
- **Archive bucket account ownership** — operator declares which AWS account / GCP project / Azure subscription owns the archive target. H.H2 cross-checks via `s3:GetBucketAcl` / `storage.buckets.get` / `Microsoft.Storage/storageAccounts/read`.

## Test specifications (≥12 + ≥10 = ≥22 tests)

`tests/core/retention-policy.test.ts`:
1. `it('passes a compliant S3 entry with mode=COMPLIANCE + retain >= planned')`.
2. `it('emits a critical drift when S3 mode is GOVERNANCE')`.
3. `it('emits a critical drift when S3 mode is NONE / unset')`.
4. `it('emits a high drift when observed_retain_until < planned')`.
5. `it('emits a medium drift when storage class downgraded to STANDARD')`.
6. `it('passes a GCS entry with retention.mode=Locked + retain ok')`.
7. `it('emits critical when GCS retention.mode === Unlocked')`.
8. `it('passes an Azure blob with policyMode=Locked + expiriesOn >= planned')`.
9. `it('emits critical when Azure policyMode === Unlocked')`.
10. `it('aggregates entries into RetentionReport with correct counts')`.
11. `it('annual report enumerates 12 months of archives chronologically')`.
12. `it('emits REQUIRES-OPERATOR-INPUT when production_accounts is missing')`.
13. `it('severity rules table is consulted, not ad-hoc classification')` — patches `SEVERITY_RULES`, asserts emitted severity follows the patched table.
14. `it('drift entries are deterministic for the same provider responses')`.

`tests/core/retention-collector.test.ts`:
1. `it('reads archive-catalog.json from outDir and verifies every entry')`.
2. `it('emits KSI-AU-11.json with the standard envelope shape')`.
3. `it('a passing run produces zero findings')`.
4. `it('a drifted entry produces a finding with the correct NIST control mapping AU-9/AU-9(2)/AU-9(3)/AU-11')`.
5. `it('aborts cleanly when archive-catalog.json is missing')` — returns `{ skipped_reason: 'no-archive-catalog' }`, NOT an exception.
6. `it('uses the read-only Proxy SDK — never the archive-writer')` — asserts no `archive-writer` import.
7. `it('cross-checks AU-9(2) separation against production_accounts[]')`.
8. `it('--deep mode downloads the bundle and re-verifies the manifest signature')`.
9. `it('calls notify.notifyDrift on retention-violation event when violations > 0')`.
10. `it('contributes 12 cells to inventory-coverage.json under retention-coverage')`.
11. `it('does not call notifyDrift when violations === 0')`.
12. `it('manifest_signature_still_valid is "not-checked" when --deep not set, not fabricated true')`.

## REO compliance specific to this slice

- Every `observed_*` field traces to a real SDK call (`S3.GetObjectRetention`, `storage.objects.get`, `BlobClient.getProperties`).
- `manifest_signature_still_valid` is computed from a real `verifyRun()` call against the re-downloaded bundle when `--deep` is set; otherwise emitted as literal string `'not-checked'` — never fabricated `true`.
- Drift severities derive from a documented table in `core/retention-policy.ts` (`SEVERITY_RULES`) — no ad-hoc classification.
- `production_accounts[]` is operator-supplied; absent → emit `REQUIRES-OPERATOR-INPUT` rather than assume "everything's fine."
- The notifier consumes a structured event; the message body is composed from real `RetentionReport` fields, not template strings with placeholders.
- Read-only SDK clients only — H.H2 cannot mutate the archive.
- `KSI-AU-11.json` provenance fields populated: emitter, emittedAt, sourceCalls (per provider HEAD/GET request id), signingKeyId.

## Verification commands

```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/retention-policy.test.ts
npm test -- tests/core/retention-collector.test.ts
npm run check:reo

# Integration (manual, requires a prior --archive run):
tsx core/orchestrator.ts --verify-retention
tsx core/orchestrator.ts --verify-retention --annual
tsx core/orchestrator.ts --verify-retention --deep
```

## Known risks / issues

- **Risk 1 — `--deep` downloads can be slow and expensive.** Re-downloading the bundle from Deep Archive triggers a 12-hour restore + egress fees. **Mitigation:** `--deep` defaults to off; runbook recommends quarterly cadence; the report explicitly notes when `--deep` was used vs metadata-only.
- **Risk 2 — Multi-region / multi-account auth.** Verifier may need to query buckets across accounts. **Mitigation:** `config.yaml:archive.verifier_role_arns[]` lists cross-account roles; the collector assumes each role with `sts:AssumeRole` (read-only) per entry. AssumeRole calls are themselves audit-logged.
- **Risk 3 — Catalog drift vs reality.** If an archive entry was created outside the orchestrator (manual push), the catalog won't reference it. **Mitigation:** the verifier supports `--reconcile` which lists objects under the configured prefix and flags un-cataloged ones as findings (severity=medium).
- **Risk 4 — Notify storms.** A bucket-wide misconfiguration could trigger N findings → N notifications. **Mitigation:** the notifier coalesces per-run findings into a single notification with a summary count + top-3 entries.
- **Risk 5 — Bucket-level lock state vs object-level.** Operator may have the bucket policy locked but individual objects un-locked (rare but possible during early adoption). **Mitigation:** verifier checks BOTH bucket-level (via `GetBucketObjectLockConfiguration` / `buckets.get` / container `getProperties`) AND per-object; mismatch flagged as critical.
- **Risk 6 — Time zone confusion in retain_until comparison.** ISO strings must be compared as UTC. **Mitigation:** all comparisons go through `new Date(...).getTime()`; tests cover TZ-stripped strings explicitly.
- **Risk 7 — Annual report cardinality.** A CSP with many CSOs may have thousands of archive entries; the annual `.md` becomes unwieldy. **Mitigation:** annual report groups by cso_id (when H.H3 active) and includes per-CSO expanded sections; top-level summary stays short.

## Open questions (for implementation session to resolve)

- **Q1**: Should `KSI-AU-11.json` participate in `ksi-map.ts`'s standard category list (e.g. routed to `family-rollup.ts`)? AU-11 isn't a KSI in the FedRAMP 20x KSI catalog — it's a NIST control. We'd be borrowing the envelope shape. Confirm category name `audit-retention` is acceptable to the existing pipeline.
- **Q2**: For AU-9 "Alert" sub-requirement: the spec says SMS / PagerDuty / Slack. Should we add an "email" channel via SES/SNS/SendGrid? `notify.ts` currently supports Slack + PagerDuty only.
- **Q3**: When the verifier finds a missing entry (catalog references a key that doesn't exist in the bucket), is that critical (object was deleted illegally) or could it be a never-archived run? Default critical; confirm.
- **Q4**: For monthly cadence, do we rely on cron / GitHub Actions schedule, or implement an in-process scheduler? Recommend external scheduler (cron / GHA / k8s CronJob) per industry norms.
- **Q5**: When the operator first runs H.H2 against an existing legacy bucket (no prior `archive-catalog.json`), should we offer a `--bootstrap-catalog-from-bucket` flag that enumerates objects and synthesizes a catalog? Likely out of scope; track as follow-up.
- **Q6**: Should we cross-check the RFC 3161 timestamp via re-verification? The timestamp.tsr can be re-validated against the TSA's certificate even years later, providing strong AU-9(3) crypto-protection evidence. Adds latency.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~26 for this slice's new tests: 14 retention-policy + 12 retention-collector)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (H.H2 row + Overall → Next priority)
- [ ] LOOP-H-SPEC.md §7 status table updated (H.H2 row)
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-H.H2: Audit retention policy enforcement (AU-11)`
- [ ] Commit with `LOOP-H.H2:` prefix in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-H-SPEC.md
- [ ] Pushed to origin/main
- [ ] RUNBOOK.md updated with H.H2 verifier role permissions (read-only get-retention scope) + cross-account AssumeRole patterns

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-H-SPEC.md` Section 2 (Dependencies) for context on H.H1 (the catalog this slice reads).
4. Read `cloud-evidence/core/envelope.ts` to see the KSI envelope shape that H.H2 emits.
5. Read `cloud-evidence/core/inventory-coverage.ts` to see the coverage registry pattern this slice extends.
6. Read `cloud-evidence/core/notify.ts` to see the notification channel API.
7. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
8. Begin implementation; update Implementation log section as you go.
