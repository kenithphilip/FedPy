---
slice_id: H.H1
title: Immutable evidence archive (S3 Object Lock / GCS Bucket Lock / Azure Immutable Blob)
loop: H
status: pending
commit: —
completed_date: —
depends_on: [A.A4, B.1, B.2]
blocks: [H.H2, E.E3]
estimated_effort: 5 working days (1 senior engineer)
last_updated: 2026-06-06
---

# H.H1 — Immutable evidence archive

## TL;DR
Push every signed submission bundle to a cloud WORM (write-once-read-many) store — S3 Object Lock in COMPLIANCE mode / GCS Bucket Lock / Azure Immutable Blob — with a retain-until date computed from the FedRAMP-Moderate AU-11 baseline (3 years from `manifest.json.signed_at`). Closes the AU-11 retention gap and the AU-9 protection-of-audit-information gap by making post-hoc modification structurally impossible.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
FedRAMP 20x and the underlying NIST 800-53 Rev 5 baseline require **provably immutable** retention of every audit-relevant artifact. Today the orchestrator writes its signed evidence bundle into a local `out/` directory that is mutable by any process running as the operator. This violates:

- **NIST SP 800-53 Rev 5 AU-9** — "Protect audit information and audit logging tools from unauthorized access, modification, and deletion."
- **NIST SP 800-53 Rev 5 AU-9(2)** — "Store audit records in repositories on physically separate systems or components."
- **NIST SP 800-53 Rev 5 AU-9(3)** — "Use cryptographic mechanisms to protect [the] integrity of audit information."
- **NIST SP 800-53 Rev 5 AU-11** — "Retain audit records for [Assignment: organization-defined time period]..." (FedRAMP Moderate baseline parameter: **3 years minimum**).

Pushing the signed bundle to a cloud WORM bucket simultaneously satisfies all four: the storage is physically/administratively separate (AU-9(2)), the bundle's existing Ed25519 signature + RFC 3161 timestamp (LOOP-B.1 + B.2) carry over to provide the cryptographic protection (AU-9(3)), and the WORM lock prevents modification or deletion (AU-9 + AU-11) for the configured retention window.

## Authoritative sources (with verbatim quotes)

- <https://csf.tools/reference/nist-sp-800-53/r5/au/au-11/> — NIST SP 800-53 Rev 5 §AU-11 (csf.tools mirror; NIST source is the binary PDF at nvlpubs.nist.gov):
  > "Retain audit records for [Assignment: organization-defined time period] to provide support for after-the-fact investigations of incidents and to meet regulatory and organizational information retention requirements."

- <https://csf.tools/reference/nist-sp-800-53/r5/au/au-9/> — NIST SP 800-53 Rev 5 §AU-9:
  > "Protect audit information and audit logging tools from unauthorized access, modification, and deletion; and Alert [Assignment: organization-defined personnel or roles] upon detection of unauthorized access, modification, or deletion of audit information."

- <https://csf.tools/reference/nist-sp-800-53/r5/au/au-9/au-9-2/> — NIST SP 800-53 Rev 5 §AU-9(2) Store on Separate Physical Systems or Components:
  > "Store audit records [Assignment: organization-defined frequency] in a repository that is part of a physically different system or system component than the system or component being audited."

- <https://csf.tools/reference/nist-sp-800-53/r5/au/au-9/au-9-3/> — NIST SP 800-53 Rev 5 §AU-9(3) Cryptographic Protection:
  > "Implement cryptographic mechanisms to protect the integrity of audit information and audit tools."

- <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html> — AWS S3 Object Lock User Guide:
  > "S3 Object Lock can help prevent Amazon S3 objects from being deleted or overwritten for a fixed amount of time or indefinitely. Object Lock uses a write-once-read-many (WORM) model to store objects."
  >
  > "In compliance mode, a protected object version can't be overwritten or deleted by any user, including the root user in your AWS account. When an object is locked in compliance mode, its retention mode can't be changed, and its retention period can't be shortened."
  >
  > "Object Lock works only in buckets that have S3 Versioning enabled."

- <https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html> — S3 Storage Classes:
  > "S3 Glacier Deep Archive (DEEP_ARCHIVE) – Use for archiving data that rarely needs to be accessed. Data in this storage class is archived, and not available for real-time access." (11 nines durability, 180-day minimum storage duration.)

- <https://cloud.google.com/storage/docs/bucket-lock> — GCS Bucket Lock:
  > "Bucket Lock lets you configure a Cloud Storage bucket's retention policy. This policy governs how long objects in the bucket must be retained. The feature also lets you lock the bucket's retention policy, permanently preventing the policy from being reduced or removed."
  >
  > "Once you lock a policy, you cannot remove it or reduce the retention period it has. You cannot delete a bucket with a locked policy unless every object in the bucket has met the retention period."
  >
  > "You can set a maximum retention period of 3,155,760,000 seconds (100 years)."

- <https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview> — Azure Blob Immutability Overview:
  > "Immutable storage for Azure Blob Storage enables users to store business-critical data in a WORM (Write Once, Read Many) state. While in a WORM state, data can't be modified or deleted for a user-specified interval."
  >
  > "A time-based retention policy must be locked for the blob to be in a compliant immutable (write and delete protected) state for SEC 17a-4(f) and other regulatory compliance."

- <https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/> — FedRAMP Rev5 ConMon Playbook:
  > "Each month, the CSP uploads an up-to-date POA&M and inventory, along with raw vulnerability scan files (when required by agreements with agency customers) and reports to the secure repository."

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/archive-push.ts` — pure `buildArchivePlan()` + per-provider writers `pushToS3()`, `pushToGcs()`, `pushToAzureBlob()` + disk emitter `emitArchivePush()`. Target ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/archive-catalog.ts` — pure `buildArchiveCatalog(entries, opts)` + disk emitter `emitArchiveCatalog()` writing `out/archive-catalog.json`. Target ~250 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/auth/archive-writer.ts` — opt-in writer-client factory; fails closed unless `CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES=1`. Target ~120 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/archive-push.test.ts` — ≥14 tests (see Test specifications).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/archive-catalog.test.ts` — ≥8 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/auth/archive-writer.test.ts` — ≥5 tests covering the opt-in guardrail.

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — add `--archive`, `--archive-target=<url>`, `--retention-years <int>`, `--archive-storage-class <name>` flags; add env knobs `CLOUD_EVIDENCE_ARCHIVE`, `CLOUD_EVIDENCE_ARCHIVE_TARGET`, `CLOUD_EVIDENCE_RETENTION_YEARS`, `CLOUD_EVIDENCE_ARCHIVE_STORAGE_CLASS`, `CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES`. Archive step runs **after** signing + bundling + RFC 3161 timestamp.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — register new well-known artifact: role=`archive-receipt-json`, filename=`archive-receipt.json` so the next run includes the prior push receipt as evidence-of-archive (continuing chain of custody).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/readonly-guardrail.ts` — add an `ARCHIVE_WRITE_ALLOWLIST` constant + check for the runtime tag `_cloudEvidenceArchiveWriter` on the calling client. The guardrail still rejects every other write.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/readonly-guardrail-gcp.ts` — same allowlist mechanism for `storage.objects.create`, `storage.objects.setRetention`, `storage.buckets.update`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/readonly-guardrail-azure.ts` — same for `Microsoft.Storage/.../blobs/write`, `Microsoft.Storage/.../immutabilityPolicies/write`, `Microsoft.Storage/.../containers/write`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/run-ledger.ts` — emit new event type `archive.pushed` per object with `provider`, `bucket`, `key`, `retain_until`, `bytes`, `manifest_sig_verified`.

## Schemas / standards

### AWS S3 PutObject with Object Lock
- API: `PutObjectCommand` (`@aws-sdk/client-s3`).
- Required input fields:
  - `Bucket` — destination bucket (must have `ObjectLockEnabled: true` set at create time; cannot be added later).
  - `Key` — object key, format `<prefix>YYYY/MM/<run-id>.tar.gz` (or `cso-<id>/YYYY/MM/<run-id>.tar.gz` when H.H3 is active).
  - `Body` — Buffer (the `submission-package.tar.gz` bytes).
  - `StorageClass` — default `DEEP_ARCHIVE`.
  - `ObjectLockMode` — hard-coded `COMPLIANCE` (Governance allows root delete; defeats AU-9).
  - `ObjectLockRetainUntilDate` — JS `Date`, ISO when serialized. Computed `signed_at + retentionYears years`.
  - `ContentLength` — Buffer byte length.
  - `Metadata` — `{ 'x-fedramp-run-id': runId, 'x-fedramp-sha256': bundleSha256, 'x-fedramp-manifest-sig-verified': 'true' }`.
- Required permissions (writer client only): `s3:PutObject`, `s3:PutObjectRetention`, `s3:GetBucketObjectLockConfiguration` (pre-flight).
- Versioning REQUIRED on the bucket; tooling pre-flight asserts it.

### GCS Object retention
- API: `Storage.bucket(name).file(key).save(body, { metadata: { storageClass, retention: { mode: 'Locked', retainUntilTime: <iso> }, customMetadata: {...} } })` (`@google-cloud/storage`).
- Storage class default: `ARCHIVE` (365-day minimum). `COLDLINE` allowed via override (90-day minimum).
- Required permissions: `storage.objects.create`, `storage.objects.setRetention`, `storage.buckets.get`.

### Azure Blob immutability
- API: `containerClient.getBlockBlobClient(name).uploadData(body, { blobHTTPHeaders: { blobContentType: 'application/gzip' }, metadata: {...}, immutabilityPolicy: { expiriesOn: <Date>, policyMode: 'Locked' } })` (`@azure/storage-blob`).
- Container must be created with `enableContainerLevelImmutability = true`.
- Tier default: `Archive`. `Cold` allowed via override.
- Required permissions: `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write`, `Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/write`.

### Bundle unit of archive
- The unit pushed is the LOOP-A.A4 bundle: `submission-package.tar.gz`. Its `INDEX.json` enumerates contents with per-entry sha256. Sidecars also pushed (as separate objects under the same prefix):
  - `manifest.json` + `manifest.sig` (LOOP-B.1).
  - `timestamp.tsr` when present (LOOP-B.2).
  - `archive-receipt.json` is NOT pushed (it is written locally and bundled by the NEXT run).

### Manifest signature verification (pre-push)
- Before any PUT, call `verifyRun(outDir)` from `core/sign.ts`. Push aborts on verification failure with `ArchivePushError` and exit code 5.

### Provenance record
- Every entry in `archive-receipt.json` includes `provenance: { emitter: 'core/archive-push.ts', emittedAt, sourceCalls: ['S3:PutObject:<requestId>', ...], signingKeyId }`.

## Build steps (concrete, numbered)

1. Define interfaces in `core/archive-push.ts`:
   ```ts
   export type ArchiveProvider = 'aws' | 'gcp' | 'azure';
   export type RetentionMode = 'COMPLIANCE' | 'Locked';
   export interface ArchiveTarget {
     provider: ArchiveProvider;
     bucket: string;
     prefix: string;            // '', 'cso-acme/', etc
     storageClass: 'DEEP_ARCHIVE' | 'ARCHIVE' | 'COLDLINE' | 'Archive' | 'Cold';
     retentionYears: number;
   }
   export interface ArchiveEntry {
     run_id: string;
     bundle_sha256: string;
     bundle_bytes: number;
     bundle_filename: string;
     target: ArchiveTarget;
     key: string;
     uploaded_at: string;
     retain_until: string;
     retention_mode: RetentionMode;
     provider_response: { etag?: string; versionId?: string; requestId?: string; generation?: string };
     manifest_signature_verified: boolean;
     rfc3161_timestamp_sha256: string | null;
   }
   ```
2. Pure `buildArchivePlan(outDir, opts)` — walks outDir, asserts `submission-package.tar.gz` + `manifest.json` + `manifest.sig` (+ optional `timestamp.tsr`) all exist, computes sha256 of the bundle, computes `retain_until = opts.now + opts.target.retentionYears years` (use `setUTCFullYear(year + N)` for deterministic year math), returns `{ entries: ArchiveEntry[]; warnings: string[] }`. Does NOT write or upload.
3. Provider writers:
   - `pushToS3(entry, body, client)` — verifies manifest signature first → `PutObjectCommand({ Bucket, Key, Body: body, StorageClass: entry.target.storageClass, ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate: new Date(entry.retain_until), ContentLength: body.length, Metadata: {...} })` → reads `etag`, `versionId`, `requestId` from response → returns updated entry. Throws `ArchivePushError` on signature failure or upload error.
   - `pushToGcs(entry, body, client)` — same shape, uses `bucket.file(key).save(body, {...})`.
   - `pushToAzureBlob(entry, body, client)` — same, uses `getBlockBlobClient(key).uploadData(body, {...})`.
4. Disk emitter `emitArchivePush(opts)`:
   - Reads `submission-package.tar.gz` into a Buffer.
   - Calls `buildArchivePlan()` → routes to the right provider writer → writes the resulting `ArchiveEntry[]` to `out/archive-receipt.json` with stable JSON formatting (2-space indent, sorted keys for determinism).
   - Returns `{ receipt_path, archived_count, target, retain_until, errors }`.
5. Wire into `core/orchestrator.ts`: parse `--archive` + `--archive-target` + `--retention-years` + `--archive-storage-class`. Resolution order: CLI > env > `config.yaml:archive.target_url` > throw with help text naming all three. Archive step runs **after** submission-bundle, sign, and timestamp steps.
6. Add `archive-receipt-json` to `core/submission-bundle.ts` `WELL_KNOWN` catalogue (role + filename `archive-receipt.json`).
7. Create `core/auth/archive-writer.ts`:
   - Reads `CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES`; throws `ArchiveWritesDisabledError` if not exactly `'1'`.
   - Constructs the SDK client *without* the read-only Proxy wrap (each provider has a dedicated factory: `createS3WriterClient`, `createGcsWriterClient`, `createAzureBlobWriterClient`).
   - Sets the runtime tag `client._cloudEvidenceArchiveWriter = true`.
8. Patch the three guardrails (`readonly-guardrail.ts`, `-gcp.ts`, `-azure.ts`): permit a write op ONLY when the calling client has `_cloudEvidenceArchiveWriter === true` AND the op is in the per-provider allowlist constant `ARCHIVE_WRITE_ALLOWLIST`:
   - AWS: `['PutObject', 'PutObjectRetention', 'PutBucketObjectLockConfiguration']`
   - GCP: `['storage.objects.create', 'storage.objects.setRetention', 'storage.buckets.update']`
   - Azure: `['Microsoft.Storage/.../blobs/write', 'Microsoft.Storage/.../immutabilityPolicies/write', 'Microsoft.Storage/.../containers/write']`
9. Telemetry: emit `run-ledger.jsonl` event `archive.pushed` per object via `core/run-ledger.ts`.
10. Validation pass — JSON-schema-validate the emitted `archive-receipt.json` against an inline ajv schema declared in `core/archive-push.ts`.
11. Signing — `archive-receipt.json` is covered by the existing manifest+sign pipeline (it lands in `out/` like every other emitted artifact).

## REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4 (CLAUDE.md):

- **`archive_target.bucket` / target URL** — Source: CLI `--archive-target=<url>` or env `CLOUD_EVIDENCE_ARCHIVE_TARGET` or `config.yaml:archive.target_url`. Missing → throw `ArchiveTargetMissingError` with help text naming all three config paths. No silent default.
- **`archive_target.retentionYears`** — Source: CLI `--retention-years` or env `CLOUD_EVIDENCE_RETENTION_YEARS` or `config.yaml:archive.retention_years`. Default 3 (FedRAMP Moderate AU-11 minimum). The SSP-declared value must match; mismatch emits a warning + `REQUIRES-OPERATOR-INPUT` in the receipt's `parameter_alignment` field.
- **`archive_target.storageClass`** — Source: CLI or env or config. Default per provider: AWS `DEEP_ARCHIVE`, GCS `ARCHIVE`, Azure `Archive`. Operator override allowed; non-standard class emits a warning.
- **`archive_target.prefix`** — Derived from H.H3 `--cso <id>` flag (`cso-<id>/`); falls back to `""` in single-tenant mode.
- **`CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES`** — Source: env. Operator must explicitly set `1`. Absent → archive-writer construction throws `ArchiveWritesDisabledError`. Deliberate safety interlock: the nightly read-only collector role must NOT have archive-write privileges; only the dedicated push job does.
- **Cloud credentials with archive-write scope** — must be issued separately from the read-only role. Documented in RUNBOOK.md as a runbook step, not a tool action.

## Test specifications (≥14 tests)

`tests/core/archive-push.test.ts`:
1. `it('builds a plan with retain_until = uploaded_at + retentionYears years')` — fixed `now`, asserts year math via `Date.toISOString()` equality.
2. `it('throws ArchivePushError when submission-package.tar.gz is missing from outDir')` — empty outDir, expects error with bundle filename in message.
3. `it('throws ArchivePushError when manifest.sig is missing')` — outDir has bundle but no sig.
4. `it('throws ArchivePushError when manifest signature verification fails (tampered manifest)')` — wires a tampered manifest body, expects error.
5. `it('pushes to S3 with ObjectLockMode=COMPLIANCE + StorageClass=DEEP_ARCHIVE')` — mocks `S3Client.send`, captures `PutObjectCommand` input, asserts fields.
6. `it('pushes to S3 with ObjectLockRetainUntilDate matching the plan')` — round-trips ISO date.
7. `it('pushes to GCS with retention.mode=Locked + storageClass=ARCHIVE')` — mocks `@google-cloud/storage`, captures upload options.
8. `it('pushes to Azure Blob with immutabilityPolicy.policyMode=Locked')` — mocks `BlobServiceClient`, captures upload options.
9. `it('emits archive-receipt.json with provider_response.etag/versionId/requestId populated')` — round-trips one push, reads receipt, asserts non-empty.
10. `it('archive entry retain_until is deterministic for fixed now + retentionYears')` — same input → byte-identical ISO output.
11. `it('emits run-ledger.jsonl entry per push with event=archive.pushed')` — asserts event shape + required fields.
12. `it('archive-receipt.json validates against the embedded ajv schema')` — schema check on emitted output.
13. `it('AWS push includes Metadata: x-fedramp-run-id + x-fedramp-sha256')` — captures and asserts metadata.
14. `it('GCS push sets customMetadata with run-id and sha256')` — captures and asserts.
15. `it('manifest_signature_verified is computed from a real verifyRun call, not hardcoded true')` — patches `verifyRun` to return false, asserts ArchivePushError thrown rather than receipt with `true`.

`tests/core/archive-catalog.test.ts`:
1. `it('aggregates multiple ArchiveEntry into archive-catalog.json sorted by uploaded_at')`.
2. `it('catalog is byte-deterministic for the same entries')`.
3. `it('catalog rejects entries missing required fields (ajv-validated)')`.
4. `it('catalog merges with an existing archive-catalog.json without duplicating run_ids')`.
5. `it('catalog updates an existing entry when re-archived (new retain_until)')`.
6. `it('archived_count returns the number of new entries added')`.
7. `it('catalog includes rfc3161_timestamp_sha256 when timestamp.tsr is present')`.
8. `it('catalog includes rfc3161_timestamp_sha256: null when timestamp.tsr is absent')`.

`tests/core/auth/archive-writer.test.ts`:
1. `it('throws ArchiveWritesDisabledError when CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES is unset')`.
2. `it('throws ArchiveWritesDisabledError when CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES === "0"')`.
3. `it('constructs an S3 client with _cloudEvidenceArchiveWriter=true when env is "1"')`.
4. `it('the read-only guardrail still rejects writes from a non-tagged client')` — regular S3 client + PutObject → guardrail throws.
5. `it('the read-only guardrail allows PutObject from a tagged client')` — writer client + PutObject → permitted.
6. `it('the read-only guardrail still rejects DeleteObject from a tagged client (not in allowlist)')` — defense in depth.

## REO compliance specific to this slice

- **Every value in `archive-receipt.json` traces to**: the local signed bundle (sha256 + manifest_signature_verified), the operator config (target bucket/prefix/storageClass/retentionYears), or the cloud-provider response (etag/versionId/requestId/generation). No defaults that look real.
- **No silent fallbacks for**: missing target bucket (throw), missing credentials (throw), missing `CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES` (throw), failed signature verification (throw, do NOT push).
- **Provenance fields populated**: `provenance.emitter`, `provenance.emittedAt`, `provenance.sourceCalls[]` (list of `<Service>:<Op>:<requestId>`), `provenance.signingKeyId`.
- **Signed by**: existing `core/sign.ts` Ed25519 pipeline + `core/timestamp.ts` RFC 3161; `archive-receipt.json` is included in the next run's manifest.
- **No mock SDKs in production**: `core/archive-push.ts` imports the real `@aws-sdk/client-s3`, `@google-cloud/storage`, `@azure/storage-blob`. Tests mock the wire layer (`S3Client.send`) only.
- **No `process.env.NODE_ENV === 'test'` branches**: writer client construction is the same path in tests and prod; tests inject a fake client via dependency injection.

## Verification commands

```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/archive-push.test.ts
npm test -- tests/core/archive-catalog.test.ts
npm test -- tests/core/auth/archive-writer.test.ts
npm run check:reo

# Integration (manual, real bucket required):
CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES=1 \
CLOUD_EVIDENCE_ARCHIVE_TARGET=s3://acme-fedramp-archive-prod \
tsx core/orchestrator.ts --submission-bundle --archive --retention-years 3
```

## Known risks / issues

- **Risk 1 — S3 Object Lock cannot be enabled retroactively.** A bucket without Object Lock at create time will fail the push with `InvalidRequest`. **Mitigation:** pre-flight `GetBucketObjectLockConfiguration` before the first `PutObject`; if it returns empty, throw `ArchiveBucketNotLockedError` with a runbook link explaining the one-time `aws s3api create-bucket --object-lock-enabled-for-bucket` step. Document in RUNBOOK.md.
- **Risk 2 — COMPLIANCE mode is non-deletable, even by root.** If retention parameter is mis-set (e.g. `retentionYears = 100` typo), the operator cannot delete the test object until 2126. **Mitigation:** enforce a maximum sane bound (`retentionYears <= 50`); operator override possible but warning is loud. Test buckets explicitly documented as separate from production.
- **Risk 3 — GCS Bucket Lock retention policy applies to ALL objects in the bucket.** Mixing prod + test data in the same bucket is dangerous. **Mitigation:** require per-CSO buckets in multi-tenant mode (H.H3 `archive_target_override`); default is one bucket per environment (dev / staging / prod), documented in RUNBOOK.md.
- **Risk 4 — Azure version-level vs container-level immutability.** Spec defaults to container-level (`enableContainerLevelImmutability=true`). Some operators may need version-level for account-policy reasons. **Mitigation:** `config.yaml:archive.azure_worm_mode` accepts `container` (default) or `version`.
- **Risk 5 — Storage class retrieval latency for incident response.** `DEEP_ARCHIVE` requires 12-hour restore. **Mitigation:** retain a copy of the latest 90 days in `STANDARD_IA` or `INTELLIGENT_TIERING` via `--hot-copy=<bucket>`; out of scope for this slice but tracked in LOOP-H §6.
- **Risk 6 — Cross-region bucket access fees.** Reading back the archive (H.H2) from a different region costs ingress + retrieval. **Mitigation:** document that the verifier should run in the same region as the archive bucket.
- **Risk 7 — Credentials leak via env.** `CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES=1` + AWS credentials in env may be captured in logs. **Mitigation:** the orchestrator log shim redacts known credential env names; the runbook recommends OIDC / Workload Identity Federation over long-lived keys.
- **Risk 8 — Clock skew affecting retain_until math.** Local wall clock is the basis for `now`; a skewed local clock could shorten retention. **Mitigation:** before computing `retain_until`, query RFC 3161 TSA for a trusted timestamp and use it; alternatively rely on the timestamp.tsr produced by LOOP-B.2. Document NTP requirement.

## Open questions (for implementation session to resolve)

- **Q1**: Should the writer attempt to apply a Legal Hold in addition to time-based retention, for "indefinite, audit-driven" cases? Default off; expose via `--legal-hold` flag?
- **Q2**: When multiple bundles are present in `out/` (e.g. an orchestrator that completed two runs back-to-back), should the push iterate all or only the latest? Current spec says "the bundle named `submission-package.tar.gz`" — implies one per outDir; confirm.
- **Q3**: Should the sidecar `manifest.json` + `manifest.sig` + `timestamp.tsr` be pushed as separate objects, or zipped into the tarball before push? Current spec implies separate objects under the same prefix; verify aligns with H.H2 verifier.
- **Q4**: For GCS, should the writer use uniform bucket-level access (UBLA) and assume the bucket has the right IAM, or set per-object IAM? UBLA simplifies but reduces flexibility.
- **Q5**: For Azure, does the `policyMode='Locked'` apply atomically with the upload, or is there a brief window where a new blob is mutable before the policy attaches? If the latter, the writer needs a follow-up `setImmutabilityPolicy` call.
- **Q6**: Should the push retry on transient network errors? S3 SDK retries by default; GCS less so; Azure has its own. Confirm we accept defaults or wrap with `core/retry.ts`.
- **Q7**: KMS encryption — should the writer require SSE-KMS with a CMK? Cohasset attestation for S3 Object Lock + KMS = stronger SEC 17a-4 posture; FedRAMP Moderate AU-9(3) is silent on key custody.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~29 for this slice's new tests: 15 archive-push + 8 archive-catalog + 6 archive-writer)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (H.H1 row + Overall → Next priority)
- [ ] LOOP-H-SPEC.md §7 status table updated (H.H1 row)
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-H.H1: Immutable evidence archive`
- [ ] Commit with `LOOP-H.H1:` prefix in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-H-SPEC.md
- [ ] Pushed to origin/main
- [ ] RUNBOOK.md updated with one-time bucket-creation steps per cloud (S3 Object Lock create-time enablement; GCS `--retention 94608000s`; Azure `enableContainerLevelImmutability`)

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-H-SPEC.md` Section 2 (Dependencies) for context on LOOP-A.A4 (submission bundle), B.1 (sign), B.2 (timestamp).
4. Read `cloud-evidence/core/submission-bundle.ts` to see the bundle layout that becomes the unit-of-archive.
5. Read `cloud-evidence/core/sign.ts` for `verifyRun()` semantics — used in pre-push verification.
6. Read `cloud-evidence/core/readonly-guardrail.ts` (+ `-gcp.ts`, `-azure.ts`) to see where the allowlist patch goes.
7. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
8. Begin implementation; update Implementation log section as you go.
