# LOOP-H — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with status=resolved + resolution note.
> Last updated: 2026-06-06 (initial population by per-slice context author)

## Cross-cutting risks (apply to ALL slices in this loop)

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| CX-1 | **Cloud SDK breaking changes** — the AWS / GCP / Azure SDKs update frequently; a major version bump could break `archive-push.ts` or `retention-collector.ts`. | medium | Pin SDK versions in `package.json` (no `^`); annual dependency audit; integration tests against real buckets quarterly. | open |
| CX-2 | **Credentials with write scope.** H.H1 introduces the first write path in `core/`. Misuse of `CLOUD_EVIDENCE_ALLOW_ARCHIVE_WRITES=1` could lead to inadvertent writes from a collector role. | high | Documented runbook + the env-var interlock + per-provider allowlist + runtime tag on the writer client. Three layers of defense. | open |
| CX-3 | **Cross-cloud regulatory differences.** S3 Object Lock COMPLIANCE, GCS Bucket Lock, and Azure container-level immutability have subtle semantic differences (e.g. who can shorten retention, restore from delete). A 3PAO may treat them differently. | medium | Documented mapping table in RUNBOOK.md per-provider; the `RetentionStatus.observed_lock_mode` is provider-tagged so the verifier can be precise. | open |
| CX-4 | **Clock skew + retention math.** All three slices use ISO 8601 timestamps. A skewed local clock could shorten retention (H.H1), trigger false drift findings (H.H2), or mis-stamp `cso_id`-scoped audit events (H.H3). | medium | Require NTP-synced host (documented); use RFC 3161 trusted timestamp from LOOP-B.2 as the basis for `signed_at` rather than local clock. | open |
| CX-5 | **REO compliance in tests.** Test fixtures may inadvertently include realistic-looking placeholder data that gets picked up by `npm run lint:no-stubs`. | low | Tests live under `tests/`; allowlist already excludes them. Verify fixtures use obviously-synthetic strings (`acme-archive-test`, `00000000-0000-0000-0000-000000000000`). | open |
| CX-6 | **CHANGELOG drift.** Per-slice CHANGELOG entries may go stale if the slice is reworked after merge. | low | SLICE-COMPLETION-PROCEDURE.md enforces atomicity; reviewer must confirm CHANGELOG matches diff. | open |
| CX-7 | **CI guardrails timing.** REO checks (`check:reo`) may run slowly as the codebase grows. | low | Profile periodically; parallelize the three guardrails in CI if needed. | open |
| CX-8 | **OSCAL spec evolution.** OSCAL is under active spec evolution (currently 1.1.2 in our pipeline); a new spec version could deprecate or change metadata fields. | medium | Pin OSCAL spec version + run `oscal-validate.ts` ajv check; track spec releases. | open |
| CX-9 | **FedRAMP Phase Two guidance updates.** FedRAMP 20x is a moving target; AU-11 retention parameter could be tightened to 5 or 7 years. | medium | Default constant in `core/archive-push.ts`; operator override via flag; runbook notes the SSP-declared value must match. | open |
| CX-10 | **Multi-tenant security review.** H.H3 is the first slice that explicitly serves multiple tenants from one deployment. A subtle RBAC bug could leak data across CSOs. | high | Exhaustive cross-CSO tests (`rbac-cso-scope.test.ts` ≥ 15 cases); recommend a focused security review before H.H3 merge. | open |

## Per-slice risks

### H.H1 — Immutable evidence archive

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| H1-1 | **S3 Object Lock cannot be enabled retroactively.** Bucket without OL at create time → `InvalidRequest`. | high | Pre-flight `GetBucketObjectLockConfiguration`; throw `ArchiveBucketNotLockedError` with runbook link. | open |
| H1-2 | **COMPLIANCE mode is undeletable.** Typo in `retentionYears` could lock test data for decades. | high | Maximum bound (`retentionYears <= 50`) in pure builder; warning if > 10; runbook recommends test buckets are separate. | open |
| H1-3 | **GCS Bucket Lock applies to ALL objects in the bucket.** Mixing prod + test = dangerous. | high | Per-CSO bucket support; default = separate buckets per env (dev/staging/prod); runbook section. | open |
| H1-4 | **Azure container-level vs version-level immutability.** Some operators need version-level. | medium | `config.yaml:archive.azure_worm_mode` accepts `container` (default) or `version`. | open |
| H1-5 | **Deep Archive retrieval latency.** Reading the archive for incident response = 12-hour restore. | medium | Out of scope but tracked: optional `--hot-copy=<bucket>` flag to keep latest 90 days in `STANDARD_IA`. | open |
| H1-6 | **Cross-region bucket access fees.** Verifier in different region = ingress + retrieval. | low | Runbook: run verifier in same region as archive bucket. | open |
| H1-7 | **`ARCHIVE_WRITE_ALLOWLIST` drift.** New cloud APIs added to SDKs may not be in our allowlist; future operations could silently fail. | medium | Allowlist constants are exported; tests fail loudly if a new op is requested without explicit allowlist entry. | open |
| H1-8 | **Bucket pre-flight failure modes.** A non-WORM bucket, a wrong-region bucket, or a credentials-with-no-list-permission bucket all produce different errors. | low | Each pre-flight failure typed as a distinct error class (`ArchiveBucketNotLockedError`, `ArchiveBucketWrongRegionError`, etc.); test cases for each. | open |
| H1-9 | **Concurrent push race.** Two orchestrator runs from different CI pipelines could attempt to push the same key. | medium | Key includes run_id (UUID); collisions are statistically impossible. Pre-flight HEAD check + If-None-Match: * header in PutObject prevents accidental overwrite at the API level. | open |
| H1-10 | **No restore tooling shipped in this slice.** Operators may try to retrieve an archive without a documented restore path. | low | Runbook section: how to restore from each provider, with required IAM. | open |

### H.H2 — Audit retention policy enforcement

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| H2-1 | **`--deep` downloads are slow + expensive.** Re-downloading from Deep Archive triggers 12-hour restore + egress. | medium | Default off; quarterly cadence recommended; report explicitly notes `--deep` vs metadata-only. | open |
| H2-2 | **Multi-region / multi-account auth.** Verifier needs to query buckets across accounts. | medium | `config.yaml:archive.verifier_role_arns[]` lists cross-account roles; collector assumes each role with `sts:AssumeRole` (read-only). | open |
| H2-3 | **Catalog drift vs reality.** Manual pushes outside the orchestrator won't be in the catalog. | medium | `--reconcile` lists objects under the prefix and flags un-cataloged ones (severity=medium). | open |
| H2-4 | **Notify storms.** Bucket-wide misconfig → N notifications. | low | Coalesce per-run findings into a single notification with summary count + top-3. | open |
| H2-5 | **Bucket-level vs object-level lock state.** Bucket locked but objects unlocked = rare but possible. | medium | Check BOTH bucket-level AND per-object; mismatch flagged as critical. | open |
| H2-6 | **TZ confusion in `retain_until` comparison.** | low | All comparisons via `new Date(...).getTime()`; tests cover TZ-stripped strings. | open |
| H2-7 | **Annual report cardinality.** CSP with many CSOs = thousands of entries; `.md` becomes unwieldy. | low | Group by `cso_id` when H.H3 active; per-CSO expanded sections; top-level summary stays short. | open |
| H2-8 | **`KSI-AU-11` is not in FedRAMP 20x KSI catalog.** AU-11 is a NIST control, not a KSI. Borrowing the envelope shape may confuse downstream consumers. | medium | Documented in spec; `category: 'audit-retention'` distinct from real KSI categories; downstream `family-rollup.ts` filter excludes the audit-retention category from the FedRAMP KSI scorecard. | open |
| H2-9 | **Notification dependency on `notify.ts`.** If Slack/PagerDuty config is missing, the violation goes silently unalerted. | medium | When violations > 0 AND notify channels are unconfigured, write `out/REQUIRES-OPERATOR-INPUT.json` with the alert payload + a clear "configure notify channels" message. | open |
| H2-10 | **RFC 3161 timestamp re-verification cost.** Re-validating the timestamp.tsr against the TSA cert chain adds latency. | low | Optional via `--verify-tsr` flag; default off. | open |

### H.H3 — Multi-CSO / tenant isolation

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| H3-1 | **DB migration on existing installations.** Existing rows default to `default`; users must be re-bound to CSO scopes. | medium | Admin migration script `tracker/scripts/migrate-cso.ts` (out of scope; tracked as follow-up); runbook section. | open |
| H3-2 | **RBAC predicate refactor is invasive.** Missed query = data leakage bug. | high | `withCsoScope(stmt, scope)` helper; CI check scans `tracker/server/routes/` for raw queries lacking `cso_id`. | open |
| H3-3 | **Cross-CSO leakage via JOIN.** Join with only one side filtered = leak. | high | Both sides of every join carry `cso_id` filter; exhaustive tests. | open |
| H3-4 | **UI scope confusion.** Multi-CSO user may not realize rows are from multiple CSOs. | medium | Dashboard labels every row with `cso_id` chip; filter dropdown defaults to "all-bound" with explicit per-CSO scoping. | open |
| H3-5 | **Back-compat regression.** Single-tenant operator could see byte-level diffs in OSCAL output. | high | Omit `cso-id` prop entirely when `cso_id === 'default'`; existing reproducibility tests re-run. | open |
| H3-6 | **Per-CSO archive bucket cost.** Bucket per CSO multiplies costs. | low | Default = shared bucket with `cso-<id>/` prefix; override available. | open |
| H3-7 | **CSO ID slug collisions with reserved words.** `default`, `all`, `none`, `system`, `admin` could be confused. | medium | `RESERVED_CSO_IDS` constant; POST rejects with 400. | open |
| H3-8 | **Audit log volume from cross-CSO denials.** Misconfigured user could spam. | low | Rate-limit per `(user, target_cso)` to 1 event/minute via existing audit dedup. | open |
| H3-9 | **Migration time on large DB.** ALTER TABLE + CREATE INDEX is O(N log N). | low | Document expected times in RUNBOOK.md. | open |
| H3-10 | **OSCAL `cso-id` prop is non-standard.** OSCAL spec has no multi-tenant concept; our namespace `https://fedramp.gov/ns/oscal/cloud-evidence` is a local convention. | medium | Documented in spec; if OSCAL publishes a multi-tenant convention later, we re-emit via a migration. | open |
| H3-11 | **Schema migration ordering with sub-letters.** Confirm `tracker/server/db.ts` supports `015a`, `015b` style if needed. | low | Use plain integer numbering; sub-letter migrations are split into separate ints. | open |
| H3-12 | **Implicit `default` CSO collision.** If an operator names a real CSO `default`, behavior is ambiguous. | medium | `RESERVED_CSO_IDS` includes `default`; admin-UI form rejects. | open |

## External dependencies that may change

- **FedRAMP Rev5 baseline parameters** — AU-11 retention parameter could be tightened (currently 3 years at Moderate). Default constant in `core/archive-push.ts` is operator-overridable.
- **FedRAMP 20x guidance** — Phase Two pilot may publish a binding "secure repository upload" specification that supersedes or augments our archive design. Monitor `https://www.fedramp.gov/docs/rev5/playbook/`.
- **NIST SP 800-53 Rev 5 → 5.1 → 5.2** — control text and assignment parameters could change; csf.tools mirror reflects updates within ~1 month. Re-run a quick `npm run check:reo` after spec bumps.
- **OSCAL spec version** — currently 1.1.2 in our pipeline. Future versions may add a `metadata.csoIdentifier` field that supersedes our custom `cso-id` prop.
- **AWS SDK v3 (`@aws-sdk/client-s3`)** — major version bumps may rename `PutObjectCommand` input fields. Pin in package.json.
- **`@google-cloud/storage`** — API changes have historically introduced new permission requirements. Audit on every minor version bump.
- **`@azure/storage-blob`** — same.
- **`ajv` schema validator** — major version bumps may change strict-mode behavior; the embedded ajv schemas in `archive-push.ts` and `retention-policy.ts` must still validate.
- **NIST SP 800-145 multi-tenancy guidance** — could be superseded by NIST SP 1500-series cloud computing standards.

## Resolved risks (historical)

(empty — populated as risks are resolved through implementation and follow-up work)
