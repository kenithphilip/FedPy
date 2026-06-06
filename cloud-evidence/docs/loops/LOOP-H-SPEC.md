# LOOP-H — Long-Term Storage + Multi-CSO

> **Self-contained implementation spec.** This document is the **sole** input
> required to execute every slice of LOOP-H. Any future session opens
> `cloud-evidence/CLAUDE.md` (REO standard), this file, and the per-slice
> source listings — and ships the slice with no further conversation
> context required.
>
> **Loop status:** NOT STARTED. All 3 slices pending.
> **Effort:** 3 weeks (1 senior engineer).
> **Authoritative date of this spec:** 2026-06-06.

---

## 1. Why this loop exists

FedRAMP authorizations are not one-shot events. After the initial submission
is accepted, the CSP must:

1. Retain every signed evidence artifact (KSI envelopes, OSCAL POA&M/SSP/AP/AR,
   manifests, RFC 3161 timestamps, IIW workbooks, submission bundles, RoE)
   for the duration required by NIST SP 800-53 Rev 5 control AU-11 + the
   FedRAMP Rev5 baseline parameter (3 years minimum at Moderate, with the
   organization-defined value documented in the SSP).
2. Prove on demand — to the 3PAO during annual reassessment, to the PMO
   during ConMon, and to the Authorizing Official during a post-incident
   review — that no archived artifact has been modified or deleted since
   the day it was signed.
3. Support MSPs and large CSPs that operate **multiple** Cloud Service
   Offerings (CSOs) under a single org. Today's orchestrator writes to a
   single `out/` directory and assumes a single tenant. Two CSOs sharing
   the same machine clobber each other's evidence; cross-tenant data
   leakage in the tracker DB is structurally impossible to prevent.

**What this loop delivers:**

| Slice | Artifact | Closes |
|---|---|---|
| H.H1 | Immutable archive push (S3 Object Lock / GCS Bucket Lock / Azure Immutable Blob) + queryable catalog | AU-11 evidence-retention gap; AU-9 protection-of-audit-information gap |
| H.H2 | Retention-policy enforcer + annual compliance report + violation alerts | AU-11 ongoing-conformance gap; CA-7 ConMon evidence-availability gap |
| H.H3 | Per-CSO orchestrator/tracker/bundler isolation; `--cso <id>` flag; per-CSO archive prefix; per-CSO RBAC scope | NIST SP 800-145 multi-tenant isolation; SC-4 information-in-shared-resources; AC-3 access enforcement scoped per tenant |

**Authorization-package gaps closed (the verifiable ones):**

- **AU-11 (Audit Record Retention)** — every signed artifact provably retained
  for the org-defined window (FedRAMP Moderate baseline = 3 years).
- **AU-9 (Protection of Audit Information)** — WORM (write-once-read-many)
  immutability removes the "the CSP could have edited it" suspicion.
- **AU-9(2) (Audit Records on Separate Physical Systems)** — archive lives
  in a cloud-provider WORM bucket physically and administratively separated
  from the production `out/` directory + the tracker DB.
- **AU-9(3) (Cryptographic Protection)** — the archive carries the Ed25519
  signature + RFC 3161 timestamp that the manifest already provides; the
  immutability prevents post-hoc key swap.
- **CA-7 (Continuous Monitoring)** — retention enforcer becomes a ConMon
  control: it runs monthly, verifies every archived bundle's lock-status,
  emits findings into the same `KSI-*.json` envelope shape the rest of the
  collector uses.
- **SC-4 / AC-3 (Multi-tenant)** — H.H3 ensures every read + write in the
  tracker DB carries a `cso_id` filter at the row level, and the
  orchestrator + bundler write to per-CSO output directories.

---

## 2. Dependencies

### What must complete first

- **LOOP-A.A1–A.A5 (COMPLETE).** H.H1 archives the LOOP-A.A4 submission
  bundle (`submission-package.tar.gz`) + the LOOP-A.A1 POA&M + the SSP/AP/AR
  chain. The bundle's `INDEX.json` is the input catalog H.H1 reads to know
  what's inside.
- **B.1 (Evidence signing — Ed25519 + manifest) — COMPLETE.** The signed
  manifest is what H.H1 uses as the unit-of-archive. H.H1 never archives an
  unsigned artifact.
- **B.2 (RFC 3161 trusted timestamp) — COMPLETE.** The timestamp anchors
  the archived bundle in time independently of the local clock.
- **D.5 (Tracker backup/restore) — COMPLETE.** H.H3 multi-tenancy
  extends the existing backup logic to per-CSO scope; the framework is
  there already.
- **D.4 (Tracker granular RBAC) — COMPLETE.** H.H3 RBAC extends the
  existing RBAC enforcement to filter by `cso_id`; the role model is
  already in place.

### Files this loop extends / reads from

| File | How LOOP-H touches it |
|---|---|
| `cloud-evidence/core/submission-bundle.ts` | H.H1 reads `submission-package.tar.gz` + `INDEX.json` as the unit-of-archive |
| `cloud-evidence/core/sign.ts` | H.H1 reads `manifest.json` + `manifest.sig` to verify integrity before push |
| `cloud-evidence/core/timestamp.ts` | H.H1 reads `timestamp.tsr` and carries it alongside |
| `cloud-evidence/core/orchestrator.ts` | H.H1 + H.H2 + H.H3 each add flags + env knobs; H.H3 changes `outDir` derivation |
| `cloud-evidence/core/auth/aws.ts` | H.H1 + H.H2 use existing AWS auth (no new credential paths) |
| `cloud-evidence/core/auth/gcp.ts` | H.H1 + H.H2 use existing GCP auth |
| `cloud-evidence/core/auth/azure.ts` | H.H1 + H.H2 use existing Azure auth |
| `cloud-evidence/core/readonly-guardrail.ts` (+ gcp/azure variants) | **Critical:** H.H1 + H.H2 are the **only** modules in `core/` allowed to perform write/PUT operations against cloud storage. They MUST mark themselves as write-allowed via a documented opt-in (`CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES=1`) AND use a separate writer-Proxy that asserts the only mutations are the narrow PutObject + PutObjectRetention + PutBucketObjectLockConfiguration set. Everything else stays read-only. |
| `cloud-evidence/core/envelope.ts` | H.H2 emits its compliance report as a standard `KSI-AU-11.json` envelope (`category: 'audit-retention'`) so the existing manifest/sign/coverage pipeline picks it up unchanged |
| `cloud-evidence/core/inventory-coverage.ts` | H.H2 adds an "AU-11 retention coverage" report (per-archive lock-status fill rate) into the per-run coverage report |
| `cloud-evidence/tracker/server/schema.sql` | H.H3 adds a `cso_id TEXT NOT NULL` column to every relevant tracker table + a `csos` reference table |
| `cloud-evidence/tracker/server/rbac.ts` | H.H3 extends RBAC predicates to filter by `cso_id` and reject cross-CSO reads |

### What LOOP-H unblocks

- **LOOP-I (Stakeholder Dashboards)** — per-CSO dashboards become
  possible only once H.H3's tenancy column exists.
- **LOOP-E.E3 (Annual Assessment package generator)** — relies on H.H1
  having archived 12 months of monthly POA&M emissions to assemble an
  annual aggregate.
- **LOOP-F.F6 (Full ATO workflow tracker)** — wants per-CSO state
  machines; H.H3 provides the tenancy.

---

## 3. Authoritative sources

All quotes are verbatim. Each source URL is the authoritative reference
for the specific claim it backs. Where a control text could not be
retrieved directly during research (NIST 800-53 PDF rendered as binary),
the spec cites the control by section number + the corroborating
secondary source (csf.tools NIST mirror).

### NIST SP 800-53 Rev 5

**URL:** <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf>
**Section:** AU-11, AU-9 (Appendix C, Audit and Accountability family).

**AU-11 Audit Record Retention — control statement** (verbatim, via
csf.tools NIST 800-53 r5 mirror, <https://csf.tools/reference/nist-sp-800-53/r5/au/au-11/>):

> "Retain audit records for [Assignment: organization-defined time
> period] to provide support for after-the-fact investigations of
> incidents and to meet regulatory and organizational information
> retention requirements."

**AU-9 Protection of Audit Information — control statement** (verbatim,
same mirror):

> "Protect audit information and audit logging tools from unauthorized
> access, modification, and deletion; and Alert [Assignment:
> organization-defined personnel or roles] upon detection of
> unauthorized access, modification, or deletion of audit information."

**AU-9(2) Store on Separate Physical Systems or Components:**
> Requires storing audit records "in repositories on physically separate
> systems or components."

**AU-9(3) Cryptographic Protection:**
> Requires "cryptographic mechanisms to protect [the] integrity of audit
> information."

### FedRAMP Rev5 baseline parameter values for AU-11

**Source:** FedRAMP Rev5 Moderate Baseline (parameter overlay published
alongside the FRMR catalog). The org-defined time period parameter at
Moderate impact is **3 years (minimum)** — implementations MAY retain
longer at AO discretion. (LOOP-H uses 3 years as the default; operator
overrides via `--retention-years` to honor a longer SSP commitment.)

The FedRAMP Rev5 Playbook ConMon section
(<https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/overview/>)
states the monthly upload obligation that drives H.H2's monthly enforcer
cadence:

> "Each month, the CSP uploads an up-to-date POA&M and inventory, along
> with raw vulnerability scan files (when required by agreements with
> agency customers) and reports to the secure repository."

### AWS S3 Object Lock + Glacier Deep Archive

**URL:** <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html>

Key verbatim claims:

> "S3 Object Lock can help prevent Amazon S3 objects from being deleted
> or overwritten for a fixed amount of time or indefinitely. Object Lock
> uses a *write-once-read-many* (WORM) model to store objects."

> "S3 Object Lock has been assessed by Cohasset Associates for use in
> environments that are subject to SEC 17a-4, CFTC, and FINRA
> regulations."

> "Object Lock works only in buckets that have S3 Versioning enabled."

> "In *compliance* mode, a protected object version can't be overwritten
> or deleted by any user, including the root user in your AWS account.
> When an object is locked in compliance mode, its retention mode can't
> be changed, and its retention period can't be shortened."

> "Permanent `DELETE` request – If you issued a permanent `DELETE`
> request (a request that specifies a version ID), Amazon S3 returns an
> Access Denied (`403 Forbidden`) error when you try to delete the
> object."

**Required AWS permissions for the H.H1 archiver:**

- `s3:PutObject` (write the archive)
- `s3:PutObjectRetention` (apply per-object retain-until-date)
- `s3:PutBucketObjectLockConfiguration` (initial bucket setup only)
- `s3:GetBucketObjectLockConfiguration` (H.H2 verify mode)
- `s3:GetObjectRetention` (H.H2 verify retention)
- `s3:GetObjectLegalHold` (H.H2 verify legal hold)

**S3 Glacier Deep Archive** storage class
(<https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html>):

> "S3 Glacier Deep Archive (`DEEP_ARCHIVE`) – Use for archiving data
> that rarely needs to be accessed. Data in this storage class is
> archived, and not available for real-time access."

> Durability: 99.999999999% (11 nines).
> Availability: 99.99% (after restore).
> Minimum storage duration: 180 days.
> Retrieval time: hours.

LOOP-H uses Deep Archive as the **default** storage class for the
archive bucket — the 180-day minimum-storage-duration aligns with the
3-year minimum retention (no early-deletion penalty), and the cost
profile (~$0.00099/GB/month) is the right floor for evidence that is
read only on incident or audit.

### GCP Cloud Storage Bucket Lock + Coldline/Archive

**URL:** <https://cloud.google.com/storage/docs/bucket-lock>

Verbatim:

> "Bucket Lock lets you configure a Cloud Storage bucket's retention
> policy. This policy governs how long objects in the bucket must be
> retained. The feature also lets you lock the bucket's retention
> policy, permanently preventing the policy from being reduced or
> removed."

> "Unless a bucket's retention policy is locked, you can increase,
> decrease, or remove the policy."

> "Once you lock a policy, you cannot remove it or reduce the retention
> period it has. You cannot delete a bucket with a locked policy unless
> every object in the bucket has met the retention period."

> "You can set a maximum retention period of 3,155,760,000 seconds (100
> years)."

GCS storage classes for archive:

- **Coldline** — 90-day minimum storage duration; millisecond access.
- **Archive** — 365-day minimum storage duration; millisecond access
  (but high per-GB retrieval cost). LOOP-H default.

**Required GCP permissions** (bound to a dedicated service account; the
H.H1 archiver is the **only** code in `cloud-evidence/` that uses these
write scopes):

- `storage.buckets.update` (initial setup of retention policy)
- `storage.objects.create` (write)
- `storage.objects.setRetention` (per-object hold)
- `storage.buckets.get` (H.H2 verify)
- `storage.objects.getIamPolicy` (H.H2 verify)

### Azure Blob Storage Immutability + Archive tier

**URL:** <https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview>

Verbatim:

> "Immutable storage for Azure Blob Storage enables users to store
> business-critical data in a WORM (Write Once, Read Many) state. While
> in a WORM state, data can't be modified or deleted for a
> user-specified interval."

> "Time-based retention policies: With a time-based retention policy,
> users can set policies to store data for a specified interval. When a
> time-based retention policy is set, objects can be created and read,
> but not modified or deleted. After the retention period has expired,
> objects can be deleted but not overwritten."

> "Legal hold policies: A legal hold stores immutable data until the
> legal hold is explicitly cleared."

> "The minimum retention interval for a time-based retention policy is
> one day, and the maximum is 146,000 days (400 years)."

> "A time-based retention policy must be locked for the blob to be in a
> compliant immutable (write and delete protected) state for SEC
> 17a-4(f) and other regulatory compliance."

> "Cohasset validated that immutable storage, when used to retain blobs
> in a WORM state, meets the relevant storage requirements of CFTC Rule
> 1.31(c)-(d), FINRA Rule 4511, and SEC Rule 17a-4(f)."

Azure storage tiers used:

- **Cool** tier — 30-day min, millisecond access.
- **Cold** tier — 90-day min, millisecond access.
- **Archive** tier — 180-day min, hours-to-restore. LOOP-H default.

**Required Azure permissions** (assigned via a custom RBAC role
`CloudEvidence-Archive-Writer`):

- `Microsoft.Storage/storageAccounts/blobServices/containers/write`
  (initial setup only)
- `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write`
  (write blobs)
- `Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/write`
  (lock the immutability policy)
- `Microsoft.Storage/storageAccounts/blobServices/containers/read`
  (H.H2 verify)

### Multi-tenant SaaS isolation

**URL:** <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-145.pdf>

NIST SP 800-145 §2 "Essential Characteristics" defines multi-tenancy
under **resource pooling**:

> "The provider's computing resources are pooled to serve multiple
> consumers using a multi-tenant model, with different physical and
> virtual resources dynamically assigned and reassigned according to
> consumer demand. There is a sense of location independence in that
> the customer generally has no control or knowledge over the exact
> location of the provided resources but may be able to specify location
> at a higher level of abstraction (e.g., country, state, or
> datacenter)."

LOOP-H.H3 implements this for the cloud-evidence/tracker layer: a single
deployment serves multiple CSO tenants without cross-tenant data
visibility. This is **not** new cloud isolation — the underlying clouds
already provide that — it is **tenant isolation inside our tool**.

---

## 4. Per-slice implementation specs

### Slice H.H1 — Immutable evidence archive

**Why this slice.** Today the orchestrator writes signed evidence to a
local `out/` directory, and `out/` is mutable by the user that ran the
orchestrator. AU-11 + AU-9 require **provably immutable** retention.
H.H1 ships an archiver that pushes every signed run to a WORM bucket
(S3 Object Lock / GCS locked retention / Azure immutability) with a
retain-until-date computed from the FedRAMP-Moderate baseline (3 years
from `manifest.json.signed_at`).

**Files to create:**

- `cloud-evidence/core/archive-push.ts` — pure `buildArchivePlan()` +
  per-provider writers `pushToS3()`, `pushToGcs()`, `pushToAzureBlob()`,
  + disk emitter `emitArchivePush()`. ~500 lines.
- `cloud-evidence/core/archive-catalog.ts` — pure
  `buildArchiveCatalog(entries, opts)` + disk emitter
  `emitArchiveCatalog()`. Writes
  `out/archive-catalog.json` mapping each archived bundle to provider +
  bucket + key + retain-until + sha256 + RFC 3161 timestamp digest.
  ~250 lines.
- `cloud-evidence/core/auth/archive-writer.ts` — thin opt-in wrappers
  around `auth/aws.ts`/`auth/gcp.ts`/`auth/azure.ts` that mark the
  client as "archive-write-allowed". Fails closed if
  `CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES` is not `1`. ~120 lines.
- `cloud-evidence/tests/core/archive-push.test.ts` — ~14 tests (see
  test list below).
- `cloud-evidence/tests/core/archive-catalog.test.ts` — ~8 tests.
- `cloud-evidence/tests/core/auth/archive-writer.test.ts` — ~5 tests
  for the opt-in guardrail.

**Files to extend:**

- `cloud-evidence/core/orchestrator.ts` — add `--archive`,
  `--archive-target=s3://… | gs://… | https://….blob.core.windows.net/…`,
  `--retention-years <int>` flags; add
  `CLOUD_EVIDENCE_ARCHIVE`, `CLOUD_EVIDENCE_ARCHIVE_TARGET`,
  `CLOUD_EVIDENCE_RETENTION_YEARS`,
  `CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES` env. Archive runs **after**
  signing + bundling + timestamp so the archived unit is the complete
  signed bundle. Console output emits one line per archived object:
  `archive: pushed run-id=<x> bundle=submission-package.tar.gz target=s3://… key=…<run-id>.tar.gz retain-until=2029-06-06`.
- `cloud-evidence/core/submission-bundle.ts` — add a new well-known
  artifact catalogue entry: `archive-receipt-json` (filename
  `archive-receipt.json`) describing the destination + retain-until +
  cloud-provider response id. Bundle includes the receipt so the archive
  record itself is part of the next submission package.
- `cloud-evidence/core/readonly-guardrail.ts` (+ gcp + azure variants)
  — add an `allowedWriteOps` allowlist that defaults to empty.
  `core/auth/archive-writer.ts` is the only opt-in producer for this
  allowlist. The guardrail still rejects every other write.

**Schemas / standards** (cite URLs + exact field names):

1. **AWS S3 PutObject + Object Lock retention**
   (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html>):
   - `ObjectLockMode`: `'COMPLIANCE'` (the only mode that prevents
     even the AWS account root from deleting before expiry).
   - `ObjectLockRetainUntilDate`: ISO 8601 datetime, must be ≥ now +
     org-defined retention.
   - `Bucket` must have `ObjectLockEnabled: true` (set at create
     time; cannot be added later).
   - `Versioning` must be enabled.
2. **GCS Object retention**
   (<https://cloud.google.com/storage/docs/object-holds>):
   - The bucket-level retention policy applies to every object on
     upload; per-object overrides via `retention.mode='Locked'` +
     `retention.retainUntilTime`.
3. **Azure Blob immutability policy**
   (<https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-policy-configure-container-scope>):
   - Container property `immutableStorageWithVersioning.enabled =
     true` set at create time.
   - Per-blob `ImmutabilityPolicy.expiryTime` set on upload;
     `policyMode = 'Locked'` after the test window.
4. **Bundle envelope** (LOOP-A.A4 emits this — H.H1 archives a copy):
   - `submission-package.tar.gz` is the unit. Its `INDEX.json`
     enumerates contents with sha256 per entry.
5. **Manifest signature verification**: before pushing, H.H1 calls
   `verifyRun()` from `core/sign.ts` to confirm the manifest signature
   over the bundle is valid. Push aborts on verification failure
   (typed error, exit code 5).

**Build steps:**

1. Define interface `ArchiveTarget`:
   ```ts
   export interface ArchiveTarget {
     provider: 'aws' | 'gcp' | 'azure';
     bucket: string;
     prefix: string;             // e.g. "cso-acme/" or "" if unscoped
     storageClass: 'DEEP_ARCHIVE' | 'ARCHIVE' | 'COLDLINE' | 'COLD' | 'COOL';
     retentionYears: number;     // default 3 (FedRAMP Moderate)
   }
   ```
2. Define interface `ArchiveEntry`:
   ```ts
   export interface ArchiveEntry {
     run_id: string;
     bundle_sha256: string;
     bundle_bytes: number;
     bundle_filename: string;
     target: ArchiveTarget;
     key: string;                // e.g. "cso-acme/2026/06/<run-id>.tar.gz"
     uploaded_at: string;        // ISO 8601
     retain_until: string;       // ISO 8601 = uploaded_at + retentionYears
     retention_mode: 'COMPLIANCE' | 'GOVERNANCE' | 'LOCKED';
     provider_response: { etag?: string; versionId?: string; requestId?: string };
     manifest_signature_verified: boolean;
     rfc3161_timestamp_sha256: string | null;
   }
   ```
3. Pure builder:
   ```ts
   export function buildArchivePlan(
     outDir: string,
     opts: { runId: string; target: ArchiveTarget; now: Date; manifestSig: ManifestSignature }
   ): { entries: ArchiveEntry[]; warnings: string[] };
   ```
   Walks outDir, asserts `submission-package.tar.gz` + `manifest.json` +
   `manifest.sig` + `timestamp.tsr` (when present) all exist. Computes
   `retain_until = now + opts.target.retentionYears years`. Returns the
   plan; does NOT write anything.
4. Provider writers — three pure-of-side-effects (only the actual cloud
   PUT) functions:
   ```ts
   export async function pushToS3(entry: ArchiveEntry, body: Buffer, client: S3Client): Promise<ArchiveEntry>;
   export async function pushToGcs(entry: ArchiveEntry, body: Buffer, client: Storage): Promise<ArchiveEntry>;
   export async function pushToAzureBlob(entry: ArchiveEntry, body: Buffer, client: BlobServiceClient): Promise<ArchiveEntry>;
   ```
   Each:
   - Verifies the manifest signature **before** the PUT call (via
     `verifyRun(outDir)`); throws `ArchivePushError` on verification
     failure.
   - Performs the PUT with the appropriate retention parameter:
     - S3: `PutObjectCommand({ Bucket, Key, Body, StorageClass,
       ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate })`.
     - GCS: `bucket.upload(localPath, { destination, metadata: {
       storageClass, retention: { mode: 'Locked', retainUntilTime } } })`.
     - Azure: `containerClient.uploadData(body, length, {
       blobHTTPHeaders, immutabilityPolicy: { expiriesOn, policyMode:
       'Locked' } })`.
   - Returns the updated `ArchiveEntry` with `provider_response`
     populated.
5. Disk emitter `emitArchivePush()`:
   ```ts
   export async function emitArchivePush(opts: ArchivePushOptions): Promise<ArchivePushResult>;
   ```
   - Reads `submission-package.tar.gz` + reads `manifest.json` for the
     signing key id.
   - Calls `buildArchivePlan()` → calls the right provider writer →
     writes the resulting `ArchiveEntry` array to
     `out/archive-receipt.json`.
   - Returns a `{ receipt_path, archived_count, target, retain_until,
     errors }` summary.
6. Wire into orchestrator: new `--archive` flag triggers the
   call **after** `--submission-bundle` + signing + timestamp. The
   target is resolved from CLI > env > config.yaml >
   throw-with-help-text.
7. Add `archive-receipt-json` to `core/submission-bundle.ts`
   `WELL_KNOWN` catalogue so the next run's bundle includes the prior
   archive receipt as evidence-of-archive — chain of custody continues.
8. New `core/auth/archive-writer.ts` exports
   `createArchiveWriterClient(provider, target)`. It:
   - Reads `CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES`; throws
     `ArchiveWritesDisabledError` if not `1`.
   - Constructs the SDK client **without** the read-only Proxy wrap.
   - Sets a runtime tag `client._cloudEvidenceArchiveWriter = true` so
     the existing guardrail can identify approved write-paths.
   - The read-only guardrail (`core/readonly-guardrail.ts` +
     `-gcp.ts` + `-azure.ts`) is patched to permit write operations
     ONLY when the calling client carries this tag AND the operation
     is in a hard-coded allowlist:
     `['PutObject', 'PutObjectRetention',
       'PutBucketObjectLockConfiguration',
       'storage.objects.create', 'storage.objects.setRetention',
       'storage.buckets.update',
       'Microsoft.Storage/.../blobs/write',
       'Microsoft.Storage/.../immutabilityPolicies/write']`.
9. Telemetry: every push emits a `run-ledger.jsonl` entry with
   `event=archive.pushed`, `provider`, `bucket`, `key`, `retain_until`,
   `bytes`, `manifest_sig_verified`.

**REQUIRES-OPERATOR-INPUT fields:**

- `archive_target.bucket` — source: CLI `--archive-target` or env
  `CLOUD_EVIDENCE_ARCHIVE_TARGET` or `config.yaml:archive.target_url`.
  Format: `s3://<bucket>` / `gs://<bucket>` /
  `https://<account>.blob.core.windows.net/<container>`. There is no
  silent default; missing → throw with help text naming all three
  config paths.
- `archive_target.retentionYears` — source: CLI `--retention-years` or
  env `CLOUD_EVIDENCE_RETENTION_YEARS` or `config.yaml:archive.retention_years`.
  Default 3 (FedRAMP Moderate AU-11 minimum). Spec value MUST be
  declared in SSP's AU-11 parameter; mismatch surfaces a warning.
- `archive_target.storageClass` — source: CLI `--archive-storage-class`
  or env or config. Default per provider: AWS `DEEP_ARCHIVE`, GCS
  `ARCHIVE`, Azure `Archive`.
- `archive_target.prefix` — source: derived from H.H3 `--cso <id>`
  flag (`cso-<id>/`). Falls back to `""` when single-tenant.
- `CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES` — source: env. Operator
  must explicitly set `1` to enable writes. Absent → archive-writer
  client construction throws. This is a **deliberate** safety
  interlock: the runner that performs nightly read-only collection
  should NOT have archive-write privileges; only the dedicated push
  job does.

**Test specifications** (≥ 14, ~14 here):

1. `it('builds a plan with retain_until = uploaded_at + retentionYears years')`
   — feeds fixed `now`, asserts year math.
2. `it('throws when submission-package.tar.gz is missing from outDir')`.
3. `it('throws when manifest.sig is missing or invalid')` — wires a
   tampered manifest, expects `ArchivePushError` naming the bundle.
4. `it('pushes to S3 with ObjectLockMode=COMPLIANCE')` — mocks
   `S3Client.send`, captures `PutObjectCommand` input, asserts
   `ObjectLockMode === 'COMPLIANCE'` + `StorageClass === 'DEEP_ARCHIVE'` +
   correct `ObjectLockRetainUntilDate`.
5. `it('pushes to GCS with retention.mode=Locked')` — mocks the
   `@google-cloud/storage` upload, asserts metadata.
6. `it('pushes to Azure Blob with immutabilityPolicy.policyMode=Locked')` —
   mocks `BlobServiceClient`, asserts upload options.
7. `it('emits archive-receipt.json with the provider_response')` —
   round-trips one push, reads the receipt back, asserts all fields.
8. `it('refuses to construct a writer client when CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES is not 1')` —
   sets env false, expects `ArchiveWritesDisabledError`.
9. `it('the read-only guardrail still rejects writes from a non-tagged client')` —
   constructs a regular S3 client + tries `PutObject`, expects guardrail
   throw.
10. `it('the read-only guardrail allows PutObject from a tagged client')` —
    constructs via `createArchiveWriterClient`, asserts PutObject is
    allowed.
11. `it('the read-only guardrail STILL rejects ListObjects writes (no allowlist op)')` —
    tagged client trying `DeleteObject` is rejected.
12. `it('emits REQUIRES-OPERATOR-INPUT diagnostic when --archive-target is missing')` —
    invokes the orchestrator path without target, asserts the
    diagnostic.
13. `it('emits one run-ledger.jsonl entry per push with event=archive.pushed')`.
14. `it('archive entry retain_until is deterministic for fixed now + years')` —
    same `now` + `years` → same `retain_until` ISO string.

**REO compliance checks specific to this slice:**

- Every entry in `archive-receipt.json` traces to a real
  `PutObject`/`Upload` response (etag + versionId or equivalent).
- `manifest_signature_verified` flag is computed from a **real**
  `verifyRun()` call — never hard-coded `true`.
- No silent fallbacks: if the SDK upload returns no etag/versionId, the
  push is treated as failed and surfaced as an error.
- No mock SDKs in production paths — tests mock the wire layer only;
  `core/archive-push.ts` itself constructs real clients via
  `core/auth/archive-writer.ts`.
- All bucket / region / prefix values flow through operator config —
  never substituted from a placeholder string.

**Verification commands:**

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/archive-push.test.ts
npm test -- tests/core/archive-catalog.test.ts
npm test -- tests/core/auth/archive-writer.test.ts
npm run check:reo
# integration (manual, real bucket required):
CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES=1 \
CLOUD_EVIDENCE_ARCHIVE_TARGET=s3://acme-fedramp-archive-prod \
tsx core/orchestrator.ts --submission-bundle --archive --retention-years 3
```

**Estimated effort:** 5 working days (1 senior engineer). 1.5 days for
the AWS path, 1 day GCP, 1 day Azure, 1 day tests + REO, 0.5 day docs.

---

### Slice H.H2 — Audit retention policy enforcement (AU-11)

**Why this slice.** H.H1 pushes the archive; H.H2 **proves** the archive
stays locked. AU-11 + AU-9 require ongoing verification of retention
state, not just initial setup. H.H2 runs (monthly default, on-demand
flag-driven otherwise) and emits a `KSI-AU-11.json` evidence envelope
plus a `retention-compliance-report.json` showing: every archived
bundle's current lock-status, computed retain-until, time-to-expiry,
storage-class, and any drift from the intended policy. Violations
trigger a finding through the existing tracker push + notify channels.

**Files to create:**

- `cloud-evidence/core/retention-policy.ts` — pure
  `verifyRetention(entry, providerResponse)` +
  `buildRetentionReport(entries, opts)` + disk emitter
  `emitRetentionReport()`. ~350 lines.
- `cloud-evidence/core/retention-collector.ts` — pulls live state from
  the archive bucket for every entry in `archive-catalog.json`,
  reconciles vs the catalog, returns findings. Emits
  `out/KSI-AU-11.json` (REO-compliant envelope, same shape as other
  KSIs). ~300 lines.
- `cloud-evidence/tests/core/retention-policy.test.ts` — ~12 tests.
- `cloud-evidence/tests/core/retention-collector.test.ts` — ~10 tests.

**Files to extend:**

- `cloud-evidence/core/orchestrator.ts` — `--verify-retention` flag +
  `CLOUD_EVIDENCE_VERIFY_RETENTION` env. Runs **after** `--archive`
  (or stand-alone with `--inventory-only`-style scoping). Outputs a
  per-entry one-line summary + a roll-up `[ok N | warn N | fail N]`.
- `cloud-evidence/core/ksi-map.ts` — register `KSI-AU-11` with a new
  `audit-retention` category, mapped to NIST controls
  `AU-9`, `AU-9(2)`, `AU-9(3)`, `AU-11`. Multi-cloud collector — the
  appropriate cloud is whichever the catalog says the archive was
  pushed to.
- `cloud-evidence/core/inventory-coverage.ts` — add `retention-coverage`
  registry block: 4 columns × 3 clouds = 12 cells (lock-mode-correct,
  retain-until-correct, storage-class-correct, manifest-sig-still-verifies).
- `cloud-evidence/core/submission-bundle.ts` — add
  `audit-retention-report` (filename `retention-compliance-report.json`)
  and `audit-retention-evidence` (filename `KSI-AU-11.json`) to
  `WELL_KNOWN`.
- `cloud-evidence/core/notify.ts` — extend so a `retention-violation`
  event type routes Slack/PagerDuty when configured. Existing
  `notifyDrift()` is the pattern.

**Schemas / standards:**

1. **NIST AU-11 control parameter** — operator-supplied
   `retentionYears` (default 3 at FedRAMP Moderate). The verifier
   asserts archived `retain_until >= manifest.signed_at + retentionYears`.
2. **NIST AU-9(2)** — verifies archive bucket is in a different
   account/project/subscription from the production tracker DB
   (operator declares production accounts in
   `config.yaml:archive.production_accounts[]`; H.H2 cross-checks
   the bucket owner).
3. **NIST AU-9(3) Cryptographic Protection** — H.H2 re-runs the
   `verifyRun()` signature verification against a re-downloaded copy of
   the bundle (when `--verify-retention --deep` is set; default is
   metadata-only verification). Detects post-hoc tampering.
4. **AWS S3 GetObjectRetention + GetObjectLegalHold** — H.H2 calls
   both, asserts `Mode === 'COMPLIANCE'` + `RetainUntilDate` matches
   plan.
5. **GCS get bucket retention policy + get object retention** —
   asserts `retentionPolicy.isLocked === true` +
   `effectiveTime + retentionDuration >= signed_at + retentionYears`.
6. **Azure get blob immutability policy** — asserts
   `policyMode === 'Locked'` + `expiriesOn` is in the future and
   meets the parameter.

**Build steps:**

1. Define interfaces:
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
2. Pure builder `verifyRetention(entry, providerResponse)`:
   - AWS: expect `providerResponse.ObjectLockMode === 'COMPLIANCE'` +
     `providerResponse.ObjectLockRetainUntilDate >= entry.retain_until`.
   - GCS: expect `providerResponse.retention.mode === 'Locked'` +
     `retainUntilTime >= entry.retain_until`.
   - Azure: expect `providerResponse.immutabilityPolicy.policyMode ===
     'Locked'` + `expiriesOn >= entry.retain_until`.
   - Drift array populated per field; each entry assigned severity
     (`mode` wrong → `critical`; `retain_until` shortened → `high`;
     storage-class downgraded → `medium`; `legal_hold` flipped off →
     `medium`).
3. `core/retention-collector.ts`:
   - Reads `out/archive-catalog.json` (or a path passed via
     `--catalog-path`).
   - For each entry, constructs a **read-only** SDK client (NOT the
     archive-writer; just standard read-only Proxy) and calls the
     get-retention API.
   - Aggregates via `buildRetentionReport()`.
   - Emits findings to a `KSI-AU-11.json` evidence envelope:
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
       "findings": [...one per drift entry...]
     }
     ```
     The shape matches existing KSI evidence so the signing, manifest,
     and OSCAL AR/POA&M emitters pick it up unchanged.
4. Disk emitter `emitRetentionReport()` writes
   `out/retention-compliance-report.json` + `out/KSI-AU-11.json`.
5. Annual report — when `--verify-retention --annual` is set, additionally
   write `out/au-11-annual-<YYYY>.json` + `.md`: human-readable
   roll-up across the prior 12 months of archives, count of bundles
   archived, total bytes, projected expiry calendar, control mapping
   (AU-9 / AU-9(2) / AU-9(3) / AU-11) with explicit "compliant /
   non-compliant" verdicts.
6. Wire into orchestrator: new `--verify-retention` flag triggers
   `emitRetentionReport()` after archive (in same run) or as a
   stand-alone job. Add `--annual` modifier.
7. Notification: when `entries_expired_or_unprotected > 0`, call
   `notify.notifyDrift({ type: 'retention-violation', ...summary })` so
   Slack/PagerDuty alert operators immediately.
8. Coverage: update `core/inventory-coverage.ts` with the 12 new cells.

**REQUIRES-OPERATOR-INPUT fields:**

- `production_accounts[]` — list of AWS account IDs / GCP project IDs /
  Azure subscription IDs the **production** evidence pipeline runs
  from. H.H2 asserts the archive bucket account is NOT in this list
  (AU-9(2) physical separation). Source: `config.yaml:archive.production_accounts[]`.
  Missing → emit `REQUIRES-OPERATOR-INPUT` in the report's
  `au_9_2_separation` field.
- `retention_parameter_declared_years` — the value the SSP declares in
  AU-11. Source: `config.yaml:ssp.controls.AU-11.parameter_years`.
  Mismatch with `archive.retention_years` surfaces a finding.
- `personnel_to_alert[]` — for AU-9 violation alerts. Source:
  `config.yaml:ssp.controls.AU-9.personnel_to_alert`.

**Test specifications** (~12 retention-policy + 10 retention-collector):

`retention-policy.test.ts`:
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

`retention-collector.test.ts`:
1. `it('reads archive-catalog.json from outDir and verifies every entry')`.
2. `it('emits KSI-AU-11.json with the standard envelope shape')`.
3. `it('a passing run produces zero findings')`.
4. `it('a drifted entry produces a finding with the correct NIST control mapping')`.
5. `it('aborts cleanly when archive-catalog.json is missing')` —
   returns a `{ skipped_reason: 'no-archive-catalog' }` result, NOT an
   exception, so a first run isn't fatal.
6. `it('uses the read-only Proxy SDK — never the archive-writer')` —
   asserts no `archive-writer` import.
7. `it('cross-checks AU-9(2) separation against production_accounts[]')`.
8. `it('--deep mode downloads the bundle and re-verifies the manifest signature')`.
9. `it('calls notify.notifyDrift on retention-violation event when violations > 0')`.
10. `it('contributes 12 cells to inventory-coverage.json under retention-coverage')`.

**REO compliance checks specific to this slice:**

- Every `observed_*` field traces to a real SDK call
  (`S3.GetObjectRetention`, `storage.objects.get`,
  `BlobClient.getProperties`).
- `manifest_signature_still_valid` is computed from a real
  `verifyRun()` call against the re-downloaded bundle when
  `--deep` is set; otherwise emitted as the literal string
  `'not-checked'` — never fabricated `true`.
- Drift severities derive from a documented table in
  `core/retention-policy.ts` (`SEVERITY_RULES`) — no ad-hoc
  classification.
- `production_accounts[]` is operator-supplied; absent → emit
  `REQUIRES-OPERATOR-INPUT` rather than assume "everything's fine".
- The notifier consumes a structured event; the message body is
  composed from real `RetentionReport` fields, not template strings
  with placeholders.

**Verification commands:**

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/retention-policy.test.ts
npm test -- tests/core/retention-collector.test.ts
npm run check:reo
# integration (manual, real bucket required + prior --archive run):
tsx core/orchestrator.ts --verify-retention
tsx core/orchestrator.ts --verify-retention --annual
```

**Estimated effort:** 4 working days. 1 day verifier per-provider
math, 1 day collector + envelope wiring, 1 day notify + annual, 1
day tests + REO.

---

### Slice H.H3 — Multi-CSO / tenant isolation

**Why this slice.** Today's orchestrator hard-codes `outDir` and writes
a single `manifest.json` per run; the tracker DB has no tenant column.
A CSP with 4 CSOs can't operate the tool today without 4 separate
checkouts. H.H3 introduces a single first-class concept — `cso_id` —
that flows through the orchestrator output path, the tracker DB schema,
the bundler INDEX, and the archive prefix. Implementations are
backward-compatible: when `--cso` is omitted, behavior is identical to
today (one implicit `default` CSO).

**Files to create:**

- `cloud-evidence/core/cso-config.ts` — load + validate
  `config.yaml:csos[]` + `csos-registry.json`; pure
  `resolveCsoContext(args, env, config)`. ~200 lines.
- `cloud-evidence/tracker/server/db/migrations/0XX_add_cso_id.sql` —
  add `cso_id` columns + a `csos` reference table + indexes.
- `cloud-evidence/tracker/server/routes/csos.ts` — CRUD endpoints for
  CSO registration (admin-only). ~250 lines.
- `cloud-evidence/tracker/client/src/pages/CsosAdmin.tsx` — admin UI
  for listing + adding CSOs + scope-binding users. ~300 lines.
- `cloud-evidence/tests/core/cso-config.test.ts` — ~10 tests.
- `cloud-evidence/tests/tracker/server/routes/csos.test.ts` — ~12 tests.
- `cloud-evidence/tests/tracker/server/rbac-cso-scope.test.ts` — ~15
  tests verifying cross-CSO read attempts are denied.

**Files to extend:**

- `cloud-evidence/core/orchestrator.ts`:
  - Add `--cso <id>` flag + `CLOUD_EVIDENCE_CSO` env.
  - Resolution order: CLI > env > `config.yaml:default_cso` > literal
    string `"default"` (and emit a notice that single-tenant mode
    is in effect).
  - `outDir` derivation changes:
    `args.outDir = resolve(PROJECT_ROOT, 'out', cso_id)` when `cso_id !==
    'default'`; falls back to `out/` when `default` (back-compat).
  - Every emitted artifact carries the cso_id as
    `provenance.csoId` (envelope-level) and `metadata.props
    [{name: "cso-id", value: <id>}]` (OSCAL artifacts).
  - The run ledger records `cso_id` on every event.
- `cloud-evidence/core/sign.ts` — manifest body adds top-level
  `cso_id` so a verifier can refuse a manifest that doesn't match the
  expected tenant.
- `cloud-evidence/core/submission-bundle.ts`:
  - `INDEX.json` gains top-level `cso_id`.
  - Bundle filename pattern: `submission-package.tar.gz` stays in
    per-CSO output; when archived (H.H1) the key becomes
    `cso-<id>/YYYY/MM/<run-id>.tar.gz`.
- `cloud-evidence/core/archive-push.ts` (H.H1) — when `cso_id` is
  present in the orchestrator context, archive prefix becomes
  `cso-<id>/`. Per-CSO buckets are also supported via
  `config.yaml:csos[].archive_target_override`.
- `cloud-evidence/tracker/server/schema.sql` — add `csos` table +
  `cso_id TEXT NOT NULL DEFAULT 'default'` on the per-evidence tables
  (`items`, `attestations`, `findings`, `attachments`, `audit_events`,
  `collector_runs`).
- `cloud-evidence/tracker/server/rbac.ts` — extend the permission
  predicate functions so every query gets a `cso_id IN (<bound-csos>)`
  filter. Admins are bound to all CSOs; regular users get a
  per-CSO scope set on user record.
- `cloud-evidence/tracker/server/db.ts` — add the migration runner
  invocation.
- `cloud-evidence/tracker/server/ingest.ts` — read `cso_id` from
  envelopes (LOOP-H emit) + reject ingest when missing AND the
  installation is in multi-CSO mode.

**Schemas / standards:**

1. **NIST SP 800-145 multi-tenant resource pooling** — already quoted
   in §3. LOOP-H.H3 explicitly implements row-level tenant filtering
   as the "logical isolation" guarantee.
2. **NIST SP 800-53 SC-4 (Information in Shared Resources)** — every
   tracker DB read is `cso_id`-scoped. Cross-CSO read attempts log to
   `audit_events` with `event_type = 'rbac.cross_cso_denied'`.
3. **NIST SP 800-53 AC-3 (Access Enforcement)** — per-CSO scope is an
   RBAC dimension orthogonal to role. A user with `role=editor` and
   `scope=cso-acme` can edit ACME's data only.
4. **OSCAL metadata** — the per-CSO `cso-id` prop is added to
   `metadata.props[]` of SSP/AP/AR/POA&M; consumers can route by
   tenant.

**Build steps:**

1. Define interfaces:
   ```ts
   export interface CsoEntry {
     id: string;            // slug, e.g. "acme-platform"
     display_name: string;
     impact_level: ImpactTier;
     archive_target_override?: ArchiveTarget;
     subprocessor_list_override?: string;  // path to per-CSO subprocessor sheet
     primary_3pao?: string;
     authorized_org_name: string;
     authorized_system_id: string;
     created_at: string;
   }

   export interface CsoContext {
     id: string;
     entry: CsoEntry | null;   // null for the implicit 'default'
     outDir: string;
     archive_prefix: string;
   }
   ```
2. Pure `resolveCsoContext(args, env, config): CsoContext`:
   - Reads `--cso <id>` (highest priority) → env → config default →
     `"default"`.
   - If id matches a `config.yaml:csos[]` entry, returns its
     `CsoEntry`; otherwise returns null (the implicit single-tenant).
   - When id `!= 'default'` AND no matching entry exists, throws
     `UnknownCsoError` with help text naming the config path.
3. DB migration — every per-evidence table gets `cso_id TEXT NOT NULL
   DEFAULT 'default'` + an index on `(cso_id, item_id)`. The default
   is **only** applied to existing rows; new rows must supply cso_id
   explicitly via the ingest path.
4. `tracker/server/routes/csos.ts` — POST /api/csos (admin),
   GET /api/csos (admin), DELETE /api/csos/:id (admin; refuses when
   evidence exists for the CSO). RBAC: requires `role=admin`.
5. `tracker/server/rbac.ts` — every existing permission check gets a
   `cso_scope: string[]` argument; queries filter
   `WHERE cso_id IN (?,?,?)`. Cross-CSO read attempt → 404 (NOT 403, to
   avoid leaking existence) + audit event.
6. UI `CsosAdmin.tsx` — list CSOs, add CSO form (id slug, display
   name, impact, 3PAO, system-id, archive override), per-CSO user
   assignment (multi-select). Admin-only route.
7. Orchestrator:
   - Initialize `CsoContext` early in `main()`.
   - Pass context to every emitter that records provenance: SSP, AP,
     AR, POA&M, IIW, RoE, bundle, manifest, archive.
   - When `cso_id != 'default'`, console prefix every log line with
     `[cso=<id>]` (uses existing `log` shim).
8. Backwards compatibility:
   - Single-tenant operators see no behavioral change as long as
     they never pass `--cso` and never have `csos[]` in config.
   - Migration script seeds an implicit 'default' CSO entry in DB.
9. CSV/export: every existing tracker export (D.6) gains a `cso_id`
   column.

**REQUIRES-OPERATOR-INPUT fields:**

- `csos[].id` — slug for the CSO. Source: `config.yaml:csos[]` or
  tracker admin UI. No silent default; missing → orchestrator stays
  in single-tenant mode.
- `csos[].display_name` / `authorized_org_name` / `authorized_system_id` —
  operator-supplied per CSO; surfaced as `REQUIRES-OPERATOR-INPUT`
  in SSP metadata when missing.
- `csos[].archive_target_override` — optional per-CSO archive bucket
  (some CSOs may have data-residency requirements). When unset,
  uses the global `--archive-target`.
- User → CSO scope binding — only an admin can assign; missing
  binding means user has no CSO scope and sees no evidence.

**Test specifications** (`cso-config.test.ts` ~10):

1. `it('resolves --cso CLI flag highest priority')`.
2. `it('falls back to CLOUD_EVIDENCE_CSO env when CLI omitted')`.
3. `it('falls back to config.yaml:default_cso when env omitted')`.
4. `it('falls back to literal "default" when nothing supplied')`.
5. `it('throws UnknownCsoError when --cso <id> is not in config.yaml:csos[]')`.
6. `it('returns null .entry for the implicit "default" CSO')`.
7. `it('returns CsoEntry .entry for a registered CSO')`.
8. `it('outDir for cso=acme = out/acme')`.
9. `it('outDir for cso=default = out (back-compat)')`.
10. `it('archive_prefix for cso=acme = cso-acme/')`.

`csos.ts` route tests (~12):
1. `it('POST /api/csos requires admin role')`.
2. `it('POST /api/csos validates id slug pattern')`.
3. `it('POST /api/csos rejects duplicate id')`.
4. `it('GET /api/csos returns the list to an admin')`.
5. `it('GET /api/csos returns only bound CSOs to a non-admin')`.
6. `it('DELETE refuses when evidence exists for the CSO')`.
7. `it('DELETE allowed for an empty CSO')`.
8. `it('writes an audit event on every CRUD action')`.
9. `it('POST validates authorized_org_name as non-empty when provided')`.
10. `it('archive_target_override is optional and validated as a URL when provided')`.
11. `it('rejects invalid impact_level')`.
12. `it('writes the entry with a deterministic created_at when supplied via clock seam')`.

`rbac-cso-scope.test.ts` (~15):
1. `it('admin reads see every CSO')`.
2. `it('editor with scope=[acme] reads only ACME rows')`.
3. `it('editor with scope=[acme] cannot read globex rows (404)')`.
4. `it('logs rbac.cross_cso_denied event on cross-CSO attempt')`.
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

**REO compliance checks specific to this slice:**

- `cso_id` originates from operator-supplied config / CLI / DB record;
  the orchestrator never invents one. The literal `"default"` is
  documented as the explicit single-tenant marker.
- Every cross-CSO read attempt produces an audit-log record — never a
  silent 404 with no trace.
- DB migration is idempotent + reversible via a `down.sql` companion.
- OSCAL metadata `cso-id` prop traces to the same `cso_id` value the
  manifest carries — schema parity across files.
- Archive prefix in H.H1 is derived from the same context — single
  source of truth.

**Verification commands:**

```bash
cd cloud-evidence
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

**Estimated effort:** 6 working days. 1 day CSO config + orchestrator
plumbing, 1.5 days DB migration + RBAC predicate refactor, 1 day
admin UI, 1 day per-CSO bundle + archive integration, 1.5 day tests
+ REO + docs.

---

## 5. Loop-wide acceptance criteria

LOOP-H is complete when ALL of the following are true:

1. **All 3 slices done** per the per-slice Real Slice Contract in
   `cloud-evidence/CLAUDE.md` Rule 2.
2. **Archive round-trip works end-to-end**: orchestrator run →
   submission bundle → archive push → catalog write → next-day verify
   passes (S3 + GCS + Azure each tested at least once against a real
   bucket).
3. **Retention enforcer emits `KSI-AU-11.json`** with valid envelope
   shape; `npm run check:provenance` passes against the envelope.
4. **AU-9 / AU-9(2) / AU-9(3) / AU-11 control IDs** appear in the
   OSCAL AR `findings[].target.target-id` for any retention drift.
5. **Multi-tenant tracker DB** filters cross-CSO reads correctly;
   audit-log records every denial.
6. **Backward compatibility**: a checkout that omits `--cso` produces
   bit-identical output to a pre-H.H3 run for the same inputs
   (verified by the existing reproducibility tests).
7. **CI guardrails**: `npm run lint:no-stubs`, `npm run
   check:provenance`, `npm run check:coverage-regression` all green.
8. **CHANGELOG** has one Unreleased entry per slice naming the file
   paths + verification counts.
9. **CSP archive bucket setup runbook** — one new section in
   `RUNBOOK.md` describing the one-time bucket creation steps per
   cloud (S3 Object Lock requires create-time enablement; GCS lock
   requires `--retention 94608000s` etc.; Azure container-level
   immutability requires `enableContainerLevelImmutability` set at
   create time). This is operator action, not code.
10. **Documentation**: `docs/loops/LOOP-H-SPEC.md` (this file) status
    table in §7 has every row marked `done` with commit hashes +
    dates.

---

## 6. Open questions / caveats

1. **Default retention years.** FedRAMP Rev5 Moderate baseline parameter
   for AU-11 is documented as a minimum (3 years), with the actual
   value declared in the SSP. We default to 3 in code, surface a
   warning when the SSP-declared value differs, and require explicit
   operator override to deviate. If FedRAMP publishes a stricter
   parameter (e.g. 5 years) post-Phase-Two, the default constant
   bumps cleanly.
2. **S3 Object Lock cannot be enabled retroactively.** The bucket MUST
   be created with Object Lock on. We document this in the runbook
   and surface a friendly error when the target bucket lacks it. We
   do NOT attempt to create the bucket programmatically — that's an
   operator action with FedRAMP-account governance implications.
3. **Azure container-level immutability vs version-level.** We use
   container-level WORM as the default (simpler operational model,
   widely supported including ADLS Gen2). Version-level WORM is
   available via an override flag in `config.yaml:archive.azure_worm_mode`
   for operators who need account-level policies.
4. **Compliance Mode vs Governance Mode (S3).** We hard-code
   `COMPLIANCE` because Governance lets the root user delete (defeats
   AU-9). Operators who specifically need Governance for testing must
   use a non-production bucket; the prod target is always Compliance.
5. **Cost model.** A monthly POA&M re-emission archived into Deep
   Archive at 100 KB / month × 3 years = 3.6 MB; even at 1 GB/run the
   3-year retention cost is < $40/CSO. Multi-CSO scaling is sub-linear.
6. **GCS retention vs Object Lifecycle Management.** When both are
   set, retention wins. We document this in the runbook to prevent an
   operator from inadvertently shortening retention via a lifecycle
   rule.
7. **DB migration on existing tracker installations.** The cso_id
   column defaults to `'default'` for existing rows. Operators
   migrating from single-tenant to multi-tenant must re-bind each
   user to the appropriate CSO scope; an admin one-time CLI script
   under `tracker/scripts/migrate-cso.ts` will assist (out of scope
   for this loop — track as a follow-up if multiple operators
   request).
8. **Azure custom RBAC role** for `CloudEvidence-Archive-Writer` is
   operator-created. We document the role JSON in the runbook; the
   tool itself doesn't create roles.
9. **Cross-region replication for archive bucket.** Not in scope for
   this loop. Operators with multi-region resilience requirements
   should enable CRR/turbo-replication at the bucket level; we
   surface a notice when CRR is detected as missing on a production
   archive target.
10. **OSCAL multi-tenant convention.** The `cso-id` prop is a
    cloud-evidence local convention — there is no OSCAL spec for
    multi-tenant. We namespace it under `ns:
    "https://fedramp.gov/ns/oscal/cloud-evidence"` to avoid future
    spec conflicts.

---

## 7. Status tracking

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| H.H1 | Immutable evidence archive | pending | — | — |
| H.H2 | Audit retention policy enforcement (AU-11) | pending | — | — |
| H.H3 | Multi-CSO / tenant isolation | pending | — | — |

Update this table on every commit per Section 8.

---

## 8. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST:

1. Run all three guardrails locally:
   ```bash
   cd cloud-evidence
   npm run typecheck
   npm test
   npm run check:reo
   ```
   All three must return zero. If any one fails, do NOT commit; fix
   the underlying cause. Per `CLAUDE.md` Rule 1, no `process.env.NODE_ENV`
   branches and no stub data may appear in the diff.
2. Update the Section 7 status table in this file: set the slice's
   row to `status=done`, `commit=<full-sha-from-git-log>`, `date=<ISO
   YYYY-MM-DD from this same machine's wall clock>`.
3. Add a CHANGELOG.md "Unreleased" entry under
   `### Added — LOOP-H.<slice-id>: <title>` naming:
   - the new files (full paths from cloud-evidence/),
   - the extended files,
   - the new test count + total test count after the slice,
   - the verification counts (e.g. archived bundle count, retention
     compliance %),
   - the REO compliance notes specific to this slice (which fields
     surface REQUIRES-OPERATOR-INPUT, which paths flow through real
     SDK calls).
4. Update `cloud-evidence/docs/STATUS.md` (create if absent) so the
   slice status is visible without reading this spec. One row per
   slice mirroring Section 7.
5. Commit with message exactly: `LOOP-H.<slice-id>: <title>` — no
   extra prefixes. Body of the commit may reference the CHANGELOG
   section. Do NOT amend prior commits; per CLAUDE.md, create new
   commits.
6. Push to `origin/main`:
   ```bash
   git push origin main
   ```
7. After H.H3 (the last slice) ships, also:
   - Update `docs/EXECUTION-PLAN.md` Status snapshot to mark LOOP-H
     COMPLETE.
   - Update `CHANGELOG.md` with a roll-up entry noting LOOP-H closure
     + the loops it unblocks (LOOP-I per the dependency table).
   - Update the LOOP-H-SPEC.md Section 7 status table to all-done.

### Per-slice CHANGELOG template

```
### Added — LOOP-H.<id>: <title>
<2-3 sentence summary of what shipped + why it closes the AU-11/AU-9/multi-tenant gap>

  - `core/<file>.ts`: ~<N> lines, <summary of behavior>.
  - `tests/core/<file>.test.ts`: <K> tests covering <list>.
  - `core/orchestrator.ts`: <new flag + env + integration point>.
  - REO compliance: <which fields trace to which SDK calls; which
    surface REQUIRES-OPERATOR-INPUT; which guardrail paths were
    extended>.

Verification: typecheck clean; <total> tests passing (+<K> from
LOOP-H.<id>); `npm run check:reo` returns 0; <slice-specific:
archived bundle count / verified entries / etc>.
```

---

## Appendix A — File-tree summary for the implementer

After LOOP-H completes, the following files exist (new) or are
extended (★). Paths absolute under `/Users/kenith.philip/FedRAMP 20x/`.

```
cloud-evidence/
  core/
    archive-push.ts                              [NEW — H.H1]
    archive-catalog.ts                           [NEW — H.H1]
    retention-policy.ts                          [NEW — H.H2]
    retention-collector.ts                       [NEW — H.H2]
    cso-config.ts                                [NEW — H.H3]
    auth/
      archive-writer.ts                          [NEW — H.H1]
    orchestrator.ts                              [★ all 3]
    sign.ts                                      [★ H.H3 cso_id in manifest]
    submission-bundle.ts                         [★ H.H1 receipt + H.H3 cso_id]
    readonly-guardrail.ts                        [★ H.H1 allowlist]
    readonly-guardrail-gcp.ts                    [★ H.H1 allowlist]
    readonly-guardrail-azure.ts                  [★ H.H1 allowlist]
    inventory-coverage.ts                        [★ H.H2 retention cells]
    ksi-map.ts                                   [★ H.H2 KSI-AU-11]
    notify.ts                                    [★ H.H2 retention-violation]
  tests/
    core/
      archive-push.test.ts                       [NEW — H.H1]
      archive-catalog.test.ts                    [NEW — H.H1]
      retention-policy.test.ts                   [NEW — H.H2]
      retention-collector.test.ts                [NEW — H.H2]
      cso-config.test.ts                         [NEW — H.H3]
      auth/
        archive-writer.test.ts                   [NEW — H.H1]
    tracker/
      server/
        routes/
          csos.test.ts                           [NEW — H.H3]
        rbac-cso-scope.test.ts                   [NEW — H.H3]
  tracker/
    server/
      routes/
        csos.ts                                  [NEW — H.H3]
      db/
        migrations/
          0XX_add_cso_id.sql                     [NEW — H.H3]
      schema.sql                                 [★ H.H3 cso_id]
      rbac.ts                                    [★ H.H3 scope filter]
      ingest.ts                                  [★ H.H3 cso_id req]
      db.ts                                      [★ H.H3 migration runner]
    client/src/pages/
      CsosAdmin.tsx                              [NEW — H.H3]
  docs/
    loops/
      LOOP-H-SPEC.md                             [this file]
    STATUS.md                                    [★ on each slice]
RUNBOOK.md                                       [★ H.H1 bucket setup
                                                   + H.H2 RBAC role +
                                                   H.H3 multi-tenant]
CHANGELOG.md                                     [★ per-slice entries]
```

---

## Appendix B — Sanity checklist before starting H.H1

Before the implementer writes the first line of `core/archive-push.ts`,
confirm:

1. ☐ Read `cloud-evidence/CLAUDE.md` (REO rules) end-to-end.
2. ☐ Read `core/submission-bundle.ts` (LOOP-A.A4 — the unit-of-archive).
3. ☐ Read `core/sign.ts` (verifyRun semantics).
4. ☐ Read `core/readonly-guardrail.ts` + the gcp/azure variants —
   understand which API calls are currently intercepted.
5. ☐ Confirm you have an AWS account / GCP project / Azure subscription
   where you are permitted to create a test bucket with WORM
   enabled. The tool itself doesn't create the bucket; you (the
   operator) do.
6. ☐ Confirm `out/submission-package.tar.gz` exists from a recent run
   — you'll archive this file in your local dev round-trip test.

---

End of LOOP-H-SPEC.md.
