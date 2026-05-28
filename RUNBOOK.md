# Runbook — operating cloud-evidence + tracker

This is a working operations document. Treat as a reference, not gospel — edit when a procedure proves wrong in practice.

## 0. Prerequisites

| Tool | Why |
|---|---|
| Node 20+ (24 tested) | Both projects |
| AWS CLI v2 | For `aws sso login` |
| gcloud CLI | For `gcloud auth application-default login` |
| openssl | Signature + RFC 3161 timestamps |
| cosign (optional) | SBOM signature verification |
| kubectl (optional) | K8s collector requires kubeconfig |

## 1. First-time setup

```bash
# Clone and install
git clone <repo>
cd FedRAMP\ 20x

cd cloud-evidence && npm install && cd ..
cd tracker && npm install && cd ..

# Bootstrap the tracker DB
cd tracker
npm run ingest      # ingest FRMR JSON
npm run dev:server  # starts on :4000
# In another shell:
npm run dev:client  # starts on :5173

# Bootstrap admin (first signup becomes admin):
#   browse to http://localhost:5173/signup
```

## 2. Required IAM (read-only)

### AWS

The runner principal should hold the AWS-managed `ReadOnlyAccess` policy PLUS the following Allow statement to cover a few read APIs `ReadOnlyAccess` excludes:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:SimulatePrincipalPolicy",
        "organizations:DescribeOrganization",
        "organizations:ListAccounts",
        "sso:Describe*",
        "sso:List*",
        "identitystore:Describe*",
        "identitystore:List*",
        "access-analyzer:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

**For org fan-out**, the management-account role above must be allowed to AssumeRole into a member-account role (default name `OrganizationAccountAccessRole`) holding the same ReadOnlyAccess + extras.

### GCP

Bind the runner SA to these predefined roles at the org level:

- `roles/viewer` (project-level resource read)
- `roles/iam.securityReviewer` (IAM read)
- `roles/logging.viewer` (Cloud Logging read for MLA collectors)
- `roles/cloudasset.viewer` (PIY-GIV inventory)
- `roles/recommender.viewer` (IAM-ELP recommendation read)

DO NOT grant `roles/editor` or any `*.admin` role.

### Kubernetes

For each cluster the collector targets, bind the runner identity to the built-in `view` ClusterRole. The cloud-evidence GCP/AWS Proxy guardrails apply at the SDK layer; the K8s guardrail is implicit because we only call list/get verbs.

## 3. Daily run

```bash
cd cloud-evidence
npm run collect -- \
  --providers aws,gcp \
  --html-report \
  --csv-export \
  --diff-report \
  --oscal \
  --crosswalk \
  --anomaly \
  --strict-schema \
  --push-tracker      # POST to local tracker via TRACKER_API_TOKEN
```

Expected runtime: 4–6 minutes for 37 KSIs at concurrency=4 against ~50 resources per service. Doubles with org fan-out across 4–5 accounts.

## 3a. Optional environment-variable tuning

Most operators don't need these. They exist for incident response, debugging, and CI-runner constraints.

| Variable | Default | Purpose |
|---|---|---|
| `CLOUD_EVIDENCE_RETRY_ATTEMPTS` | 4 | Max attempts per SDK call (incl. first). Lower to fail-fast in CI; raise for slow regions. |
| `CLOUD_EVIDENCE_RETRY_BASE_MS` | 200 | Initial backoff. Bumped to ~1000 for very throttled accounts. |
| `CLOUD_EVIDENCE_RETRY_MAX_MS` | 5000 | Per-attempt backoff cap. Don't exceed AWS' 60-s API throttle window. |
| `CLOUD_EVIDENCE_DISABLE_RETRY` | `0` | Set to `1` to disable retry entirely. Diagnostic only. |
| `EVIDENCE_TSA_URL` | `http://timestamp.digicert.com` | RFC 3161 TSA endpoint. Override to use an internal/eIDAS-certified TSA. |
| `EVIDENCE_TSA_CA_BUNDLE` | (none) | PEM bundle of TSA root certs for offline verification via `core/verify-cli.ts`. |
| `ANTHROPIC_API_URL` | `https://api.anthropic.com/v1/messages` | Override for proxy / VPC endpoints. |
| `LLM_MODEL` | `claude-opus-4-5` | Model selection. Use `claude-haiku-4-5` for cost-sensitive runs (see COST.md). |
| `CLOUD_EVIDENCE_DISABLE_GCP_GUARDRAIL` | `0` | Set to `1` to bypass the GCP read-only Proxy. Use ONLY for diagnosing why a collector throws ReadOnlyGcpViolationError — never in production. |
| `CLOUD_EVIDENCE_K8S_TIMEOUT_MS` | `10000` | Per-call timeout for Kubernetes API requests. Lower in CI so an unreachable cluster fails fast instead of hanging the run. |
| `CLOUD_EVIDENCE_IMPACT_LEVEL` | `moderate` | FedRAMP impact tier: `low`/`moderate`/`high`. Overrides `config.yaml` `impact_level`; `--impact-level` overrides this. High is DERIVED from NIST 800-53 Rev5. |
| `CLOUD_EVIDENCE_ATTESTATIONS` | (none) | Path to a JSON attestation register (array of `{requirement_id, artifact_url, attested_by, attested_at, expires_at}` or an object keyed by requirement id). Proves the ~99 process requirements are met; a fresh attestation makes the requirement PASS. |
| `CLOUD_EVIDENCE_KEV_PATH` | (none) | Path to a cached CISA Known-Exploited-Vulnerabilities JSON (`known_exploited_vulnerabilities.json`) for offline VDR KEV-deadline checks. |
| `CLOUD_EVIDENCE_ADS_URLS` | (none) | Comma-separated public Trust Center / CSO / OSCAL URLs the ADS probe checks for reachability + required fields (read-only GET). Emits `ADS-CSO-PUB` evidence. |
| `CLOUD_EVIDENCE_MAS_DOCUMENTED_PATH` | (none) | JSON array of resource identifiers documented as in the assessment scope. Reconciled against discovered inventory → `MAS-CSO-IIR` scope-drift evidence. |
| `CLOUD_EVIDENCE_MAS_DISCOVERED_PATH` | (auto) | JSON array of discovered identifiers for the MAS reconciliation. If unset, falls back to the live `KSI-PIY-GIV` inventory from the run. |
| `CLOUD_EVIDENCE_SCG_GUIDE_PATH` | (none) | Path to a machine-readable Secure Configuration Guide (JSON `{settings:{key:expected}}`). Diffed vs observed config → `SCG-CSO-RSC` evidence. |
| `CLOUD_EVIDENCE_SCG_OBSERVED_PATH` | (none) | Optional JSON map of observed config values keyed like the SCG, for the SCG comparator. |

**Impact level selection:** pick the tier at setup via `config.yaml` (`impact_level: low|moderate|high`)
or per-run via `--impact-level high`. The collector then scopes all 223 FedRAMP 20x requirements
to that tier: cloud-testable KSIs run their collectors; the ~99 governance requirements emit
process-artifact evidence (tracked via the attestation register); requirements that obligate
FedRAMP/an agency/a 3PAO are recorded as awareness-only and excluded from your pass/fail.

### Tracker environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DB_PATH` | `data/tracker.db` | SQLite database path. `db()` gives an actionable error (not a raw `SQLITE_CANTOPEN`) if the directory is missing or unwritable. |
| `TRACKER_DB_BUSY_TIMEOUT_MS` | `5000` | SQLite `busy_timeout`. Concurrent writers retry internally for this long before returning `SQLITE_BUSY`. Raise for high-write deployments. |
| `TRACKER_MAX_ATTACHMENT_MB` | `25` | Per-file attachment cap (MB). Validated at startup — a non-numeric value throws a clear error rather than silently disabling the cap. |
| `TRACKER_ATTACHMENT_MIME_ALLOWLIST` | pdf/png/jpeg/gif/txt/json/csv/zip/yaml | Comma-separated MIME allowlist for uploads. |
| `TRACKER_ATTACHMENTS_DIR` | `data/attachments` | Content-addressed blob store root. |
| `RL_LOGIN_PER_MIN` / `RL_LOGIN_PER_HOUR` | `5` / `30` | Login rate-limit thresholds (per IP). When no proxy headers are present the limiter keys on the TCP peer address — direct clients no longer share one bucket. |
| `RL_TOKEN_CREATE_PER_HOUR` | `10` | API-token creation rate limit (per user). |
| `RL_API_TOKEN_PER_MIN` | `60` | Per-API-token request rate limit. |

**Restore safety note:** `restore()` validates the SQLite magic header before
overwriting the live DB, writes atomically (temp + rename), refuses symlink
targets, and clears stale `-wal`/`-shm` sidecars so a restored snapshot can't be
corrupted by a leftover write-ahead log. Always stop the server before restoring.

## 3b. Permission errors & exit codes

When a collector emits an `AccessDenied` / `PERMISSION_DENIED` / `403 Forbidden`
warning, it now names the exact action/role/verb to grant. The authoritative
per-collector reference is **`cloud-evidence/docs/IAM-PERMISSIONS-CATALOG.md`** —
look up the failing collector there and add the listed permission.

Orchestrator exit codes (distinct from `process.exit()` in early-failure paths):

| Code | Meaning |
|---|---|
| 0 | Clean run. Failing findings are DATA, not an error. |
| 1 | Fatal pre-run failure (no providers authenticated, missing integration env vars, bad config). |
| 2 | `--strict-schema` set and at least one evidence file failed validation. |
| 3 | Signing self-verify failed. |
| 4 | At least one collector THREW an exception (broken collector — distinct from a compliance gap). CI should fail on this. |

## 4. Troubleshooting

### Symptom: `AWS auth failed: Could not load credentials from any providers`

```bash
aws sso login --profile <your-profile>
export AWS_PROFILE=<your-profile>
# or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in env
```

If using SSO and the session expired during a run, the orchestrator emits per-collector errors but DOES NOT abort. Coverage check will flag missing accounts. Re-run `aws sso login` and re-execute.

### Symptom: `GCP auth failed: Could not load the default credentials`

```bash
gcloud auth application-default login
# or, for service-account use:
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
```

For impersonation:

```bash
export GOOGLE_AUTH_USER=your-user@example.com
gcloud auth application-default login --impersonate-service-account=<sa>@<project>.iam.gserviceaccount.com
```

### Symptom: KSI X has 0 findings + coverage report warns

This is the silent-failure detector. Usually one of:

1. Required IAM permission missing → check the warnings in the per-KSI evidence file (`KSI-IAM-MFA.json` → `providers[*].warnings`).
2. Service not enabled in the queried region/project → enable or skip the KSI with `--ksis` filter.
3. Bug in collector → file an issue with the full warnings list.

### Symptom: `Schema validation: 1 of 37 evidence file(s) failed validation`

Run the orchestrator with `--strict-schema` to see the exact ajv errors per file. Common causes:

- Collector returned a Date object instead of an ISO string (collector bug — patch in `providers/<provider>/<file>.ts`).
- Collector emitted a finding with `passed: false` but missing `gap` or `remediation` — the `if/then` schema rule requires both.

### Symptom: Read-only guardrail blocked operation

The Proxy intercepted a Command whose verb wasn't on the allowlist. This is correct behavior — DO NOT bypass it by widening the allowlist. Instead:

1. Identify the offending Command in the stack trace.
2. If it's genuinely read-only (e.g. a new SDK Command with a verb prefix we don't recognize), add it to `READ_ONLY_EXACT_ALLOW` in `core/readonly-guardrail.ts` with a comment explaining WHY it's read-only.
3. Open a PR.

### Symptom: Tracker login fails with 429

The rate limiter is doing its job. Wait 60 seconds + retry; or increase `RL_LOGIN_PER_MIN` in env if you're operating a high-volume environment.

### Symptom: Tracker DB corrupted

```bash
cd tracker
npm run restore -- backups/tracker-<latest>.db.gz
```

If no backup exists, the worst-case loss is user-entered state (item_state, audit_log). FRMR catalog can always be re-ingested with `npm run ingest`. Admin can be recreated by deleting tracker.db and re-bootstrapping.

### Symptom: Anomaly detection flags a "new_rule" for every finding

This means `anomaly-history.jsonl` is missing (first run or fresh checkout). Expected. Subsequent runs use the file as baseline.

## 5. Scaling

### Org with > 5 AWS accounts

Use `--aws-org-fanout`. The orchestrator will assume `OrganizationAccountAccessRole` in each member account (or override with `--aws-cross-account-role`). For >50 accounts, increase `--concurrency` to 8–16, but watch AWS rate limits — IAM and Organizations are stricter than EC2.

### Org with multiple GCP folders

Configure `config.yaml`'s `gcp.projects` to enumerate all in-scope projects. There's no folder-level fan-out (yet); list projects explicitly or generate them from `gcloud asset` ahead of time.

### Tracker with > 50 active users

The SQLite-on-WAL setup is good to ~500 concurrent connections. Beyond that, swap to PostgreSQL — better-sqlite3 → pg is a single-day migration since the schema is portable.

## 6. Disaster recovery

### Cloud-evidence

It's stateless. Re-clone the repo, re-install deps, re-run. The historical `out/` directory should be archived to S3/GCS for audit; back it up with the same cadence as your other compliance artifacts.

### Tracker

```bash
# Schedule a daily backup in cron:
0 2 * * * cd /opt/tracker && npm run backup -- --retention 30

# Restore (after server stopped):
npm run restore -- /opt/tracker/backups/tracker-<DATE>.db.gz
```

Test the restore monthly. Keeping 30 days of daily backups + 12 monthly snapshots is the conservative posture.

## 7. Onboarding a new admin

1. Existing admin invites the new user (currently: admin emails the invite link manually; future Phase H enhancement).
2. New user signs up via `/signup`.
3. Admin sets role to `admin` via the tracker UI (or directly: `UPDATE users SET role='admin' WHERE email=...`).
4. New admin enrolls 2FA at `/2fa/enroll` and stores backup codes in the team's secure vault.

## 8. Quarterly hygiene

| Task | Cadence |
|---|---|
| Rotate Ed25519 signing key (`EVIDENCE_SIGNING_KEY_PATH`) | Annual |
| Rotate API tokens (tracker `/api/auth/tokens`) | Annual |
| Audit `audit_log` for unexpected role changes | Quarterly |
| Re-baseline anomaly history (delete `anomaly-history.jsonl`) | Annual or after major env change |
| Update FRMR catalog (`npm run ingest`) | Whenever FedRAMP publishes a new revision |
| Test backup-restore (tracker) | Monthly |
| Test signature verify (`npm run verify <out-dir>`) | Per audit cycle |

## 9. Common one-liners

```bash
# Re-run only IAM KSIs against a specific AWS region:
cd cloud-evidence
npm run collect -- --ksis KSI-IAM-MFA,KSI-IAM-ELP --providers aws

# Verify last week's signed evidence:
npm run verify out/

# Dry-run to see what would be collected:
npm run collect -- --dry-run

# Generate Powerpipe mod from current KSI catalog:
npm run collect -- --powerpipe --dry-run    # mod is generated regardless

# Run anomaly detection only (assume KSIs already collected):
node -e "import('./core/anomaly.ts').then(m => m.detectAnomalies({outDir:'./out', runId:'manual', finishedAt: new Date().toISOString()}))"
```

## 10. Escalation contacts

(Local-org-specific; replace with your security & SRE on-call.)
