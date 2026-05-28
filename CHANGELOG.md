# Changelog

All notable changes to the FedRAMP 20x tooling (cloud-evidence + tracker) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed — Hardening pass #3 (all-severity error-handling sweep, 2026-05)
Resolved every remaining finding (high → info) from the error-handling audit, in four batches:

**Batch 1 — collector granularity (cloud-evidence):**
- Converted every bare `catch {}` / `catch (e) { warnings.push(e.message) }` in the AWS
  `data.ts`/`iam.ts`/`config.ts` and **all 9 GCP collectors** (95 catches) to
  `diagnoseAwsError` / `diagnoseGcpError` / `warnIfActionable` — warnings now name the
  exact IAM action or GCP role (e.g. `compute.instances.list (roles/compute.viewer)`).
- Pagination loops (Lambda `ListFunctions`, IAM SSO/identity-store, 4 IsTruncated loops)
  hardened with repeated-marker detection + a `MAX_PAGINATION_ITERATIONS` cap.
- K8s ClusterRoleBinding parsing null-safety; EKS inventory filters undefined names.

**Batch 2 — core robustness (cloud-evidence):**
- `writeFileSafe` / `mkdirSafe` translate `ENOSPC`/`EACCES`/`EROFS`/`EMFILE` into actionable
  messages instead of opaque stack traces mid-run. `core/orchestrator.ts`.
- `pva-run-summary.json` now carries explicit `failed_ksis` + `schema_invalid_ksis` arrays;
  the PVA collector records `parse_error_ksis` for corrupt evidence files.
- Signing key: loose file permissions (group/world-readable) warn; malformed PEM and
  `EACCES` produce clear errors. `verifyRun` no longer throws on a corrupt/unreadable
  manifest or signature — it returns an error result. `core/sign.ts`.
- Paramify + tracker push gained `withRetry` (5xx/429/network) with URL-in-error reporting;
  ticket-push wraps the 6 previously-silent `JSON.parse` sites; SIEM/webhook errors now
  surface `ECONNREFUSED`/`ETIMEDOUT` codes. Plugin-loader survives an unreadable dir.

**Batch 3 — server robustness (tracker):**
- Input validation: token name length, `collector-runs` datetime + integer coercion,
  invalid-JSON guards (signup/login/tokens/admin/collector-runs), password upper-bound
  (scrypt CPU-DoS guard), domain/user-id `NaN` guards.
- CSRF middleware rejects duplicated (comma-joined) `X-CSRF-Token` headers explicitly.
- Rate-limit falls back to the TCP peer address when proxy headers are absent (no shared
  `unknown` bucket). Attachment downloads use RFC 5987 `filename*` Content-Disposition.
- Backup checkpoints the WAL before snapshotting; restore validates the SQLite magic header
  before clobbering, writes atomically (temp + rename), and clears stale `-wal`/`-shm`
  sidecars. `db()` sets `busy_timeout`, runs a startup health check, and gives an actionable
  open-failure message.

**Batch 4 — regression tests:** +13 cloud-evidence (push retry, sign hardening, PVA summary)
and +8 tracker (collector-run validation, CSRF duplicate, restore magic-header) tests.
Totals: **cloud-evidence 202** tests / **tracker 86** tests; both projects `tsc --noEmit` clean.

### Fixed — Hardening pass #2 (error handling + edge cases, 2026-05)
Following a focused error-handling / edge-case audit:
- **SECURITY: backup-code replay race.** `consumeBackupCode` did a read-modify-write
  that let two concurrent `/api/2fa/verify` requests accept the same backup code.
  Replaced with an atomic `INSERT OR IGNORE` into a new `totp_backup_codes_used`
  table (unique constraint). `tracker/server/totp.ts`, `db.ts`.
- **SECURITY: restore symlink overwrite.** `restore()` could write through a symlink
  at the DB path, overwriting arbitrary files. Now refuses symlink targets +
  gives a clear error on truncated gzip. `tracker/server/backup.ts`.
- **Unguarded `JSON.parse`** in IAM policy decode, diff-report run-id read, and Lambda
  resource-policy parse now wrapped — a malformed policy/file no longer crashes the run.
- **Exit code 4** when a collector throws an exception (vs. merely emitting failing
  findings, which stays exit 0 — findings are data). CI runners now catch broken collectors.
- **Pagination safety** on `ListUsers` (and pattern documented): max-iteration cap +
  repeated-marker detection to prevent infinite loops on broken API responses.
- **`core/error-diagnostics.ts`**: centralized AWS/GCP/K8s error → actionable-message
  translator. Access-denied warnings now name the exact IAM action / GCP role / K8s
  verb to grant. Wired into the orchestrator's per-collector catch + the K8s collector.
- **Startup-time integration validation**: missing env vars for `--llm-generate-prs`,
  `--ticket-push`, `--webhook-url`, `--push-paramify`, `--push-tracker` now abort
  BEFORE collection instead of wasting compute then erroring.
- **`config.yaml` schema validation**: malformed YAML / missing `frmr_version` /
  empty `aws.regions` fail fast with a clear message.
- **AWS/GCP auth-failure messages** now classify the error (access_denied / network /
  expired) and print the specific recovery command.
- **NaN guards** on `TRACKER_MAX_ATTACHMENT_MB` and audit-search `limit`/`offset`/`actor`
  query params (garbage input no longer cascades to `NaN`).
- **K8s API timeout** (`CLOUD_EVIDENCE_K8S_TIMEOUT_MS`, default 10s) so an unreachable
  cluster doesn't hang the run; clear "cluster unreachable" warning on timeout.
- **Client `ApiError`** class carrying HTTP status + server error code + Retry-After,
  so the SPA can distinguish 401/403/429/5xx and network failures. `fetch()` wrapped
  to surface offline errors clearly. `tracker/client/src/lib/api.ts`.
- **`docs/IAM-PERMISSIONS-CATALOG.md`**: authoritative per-collector AWS action / GCP
  role / K8s verb reference for least-privilege policy construction.

### Fixed — Hardening pass #1 (completeness audit, 2026-05)
- OpenAPI spec malformation (duplicate `components:` block) corrected.
- 2FA login bypass closed: enrolled users get a 5-min pre-auth session that only
  `/api/2fa/verify` can elevate. `sessions.preauth_until` column + middleware gating.
- `routes/audit.test.ts` now exercises the real `auditRoutes` module (was a stubbed
  re-implementation). Admin self-demotion + last-admin protection added.
- Provider smoke test (`tests/providers/smoke.test.ts`) added — caught 6 collectors
  emitting schema-invalid findings (missing gap/remediation/data); all fixed.
- 19 TypeScript strict-mode errors across both projects resolved.
- Dead code removed (`neutralizedByAlternative`, 6 legacy findings helpers, `backup.ts.bak`).

### Added — Phase A: Foundation
- Vitest test harness for `cloud-evidence`. 33 reference tests across retry, schema, log, sign, timestamp, oscal, crosswalk, coverage-check.
- `core/schema.ts`: ajv-based EvidenceFile JSON Schema validator. Wired into orchestrator with `--strict-schema` flag.
- `core/retry.ts`: decorrelated-jitter retry middleware applied to every AWS SDK call via `readonly-guardrail.ts`.
- `core/log.ts`: structured pino logger with pretty/JSON modes, redaction, file sink. Configurable via `LOG_LEVEL`, `LOG_PRETTY`, `LOG_FILE`.
- p-limit-based parallel KSI collection in the orchestrator. CLI: `--concurrency <N>`.

### Added — Phase B: Audit defensibility
- `core/sign.ts`: Ed25519 signing of every run's evidence files. Emits `manifest.json` + `manifest.sig`. Self-verifies after writing.
- `core/verify-cli.ts`: standalone verifier CLI (`npm run verify <out-dir>`).
- `core/timestamp.ts`: RFC 3161 trusted timestamps via `openssl ts -query` + configurable TSA (default DigiCert). Graceful degradation when openssl/TSA unavailable.
- `core/oscal.ts`: NIST OSCAL 1.1 Assessment Results emitter. CLI: `--oscal`.
- `core/coverage-check.ts`: hardened with 6 silent-failure detectors (missing accounts/projects/regions/KSIs, zero-finding KSIs, excess collector warnings); persists `coverage-report.json`.

### Added — Phase C: Coverage breadth
- `core/crosswalk.ts`: NIST 800-53 → SOC 2 / ISO 27001 / HIPAA mapping (28+ controls). CLI: `--crosswalk`.
- `core/aws-org-fanout.ts`: AWS Organizations multi-account fan-out with include/exclude filters + cross-account `AssumeRole`. CLI: `--aws-org-fanout`, `--aws-include`, `--aws-exclude`, `--aws-cross-account-role`.
- `core/readonly-guardrail-gcp.ts`: recursive Proxy guardrail for every GCP client method dispatched. Verb-prefix classifier (~50 read verbs / 30 write verbs).
- `core/powerpipe-emitter.ts`: auto-generated Powerpipe HCL mod (`out/powerpipe/`). One control per KSI; benchmarks grouped by domain. CLI: `--powerpipe`.
- Refactored every AWS collector's `setupCtx` to honor `c.aws?.auth` (enables fan-out).

### Added — Phase D: Tracker hardening
- `server/rate-limit.ts`: SQLite-backed sliding-window rate limiter. Per-IP / per-user / per-API-token policies; `X-RateLimit-*` + `Retry-After` headers.
- `server/csrf.ts`: double-submit cookie CSRF middleware. Skip-paths for bootstrap; client API helper auto-attaches `X-CSRF-Token`.
- `server/totp.ts`: RFC 6238 TOTP with 8 single-use SHA-256-hashed backup codes. `/api/2fa/*` routes. Verified against RFC 6238 canonical test vector.
- `server/rbac.ts`: 5 granular roles (viewer, contributor, ksi-owner, auditor, admin) + per-KSI-domain assignments + `requirePermission()` middleware. Audit-logged role changes. Idempotent SQLite migration relaxes legacy `users.role` CHECK.
- `server/backup.ts`: online SQLite `.backup()` + gzip; `npm run backup` / `npm run restore`. Integrity-check on restore.
- `server/routes/audit.ts`: filter/search/CSV-export endpoints over `audit_log`.

### Added — Phase E: K8s + advanced
- `core/auth/k8s.ts`: kubeconfig loader + per-context auth (kubectl-compatible).
- `providers/k8s/security.ts`: `collectK8sIamElp` enumerates cluster-admin bindings + custom wildcard ClusterRoles (KSI-IAM-ELP).
- `core/sbom.ts`: CycloneDX 1.4 + SPDX 2.3 SBOM parser; CVE correlation via `SBOM_NVD_INDEX_PATH`; cosign signature verification when `COSIGN_PUBLIC_KEY` is set. CLI: `--sbom-dir`.
- `core/anomaly.ts`: rolling-baseline anomaly detector (persistent regressions, spikes, new rules, KSI full-regression). Persists `anomaly-history.jsonl`. CLI: `--anomaly`.

### Added — Phase F: Ecosystem integrations
- `core/llm-pr-generator.ts`: Anthropic Claude API integration. Builds a strict-JSON-schema remediation PR per failing finding.
- `core/ticket-push.ts`: generic ticket-driver interface + GitHub Issues, Jira (Atlassian REST v3), ServiceNow (Now REST) drivers. Idempotent via stable `external_key`; create/update/reopen flows.
- `core/siem-push.ts`: OCSF v1.2 `compliance_finding` events. Batched POST; supports `ocsf-jsonl`, `ocsf-array`, `splunk-hec` wire formats.
- `core/webhook-push.ts`: Stripe-style HMAC-SHA256 signing over `<timestamp>.<body>`. Ships `verifySignature` helper.

### Added — Phase G: DX + polish
- `core/plugin-loader.ts`: opt-in custom KSI collector plugin system. CLI: `--plugins-dir`. Example plugin under `plugins.example/`.
- `tracker/server/openapi.yaml`: OpenAPI 3.0.3 spec for the tracker API. Served at `/api/openapi.yaml`.
- Initial `CHANGELOG.md` + `ARCHITECTURE.md`.

### Test counts
| Project          | Files | Tests |
|------------------|-------|-------|
| cloud-evidence   | 20    | 161   |
| tracker          | 6     | 48    |
| **Total**        | **26**| **209** |

## [0.1.0] - 2026-05-15
Initial scaffold: 37-KSI cloud-evidence collector + multi-user tracker over FRMR JSON.
