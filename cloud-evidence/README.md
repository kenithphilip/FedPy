# cloud-evidence — FedRAMP 20x KSI evidence collector

A **read-only** TypeScript collector that captures AWS, GCP, and Kubernetes
configuration evidence for the FedRAMP 20x Key Security Indicators. It accounts
for the full **223-requirement** FedRAMP 20x set (**63 KSIs** + 160 FRRs):
**44 KSIs run live cloud collectors** across IAM, CNA, MLA, CMT, SVC, RPL, PIY,
SCR, INR, AFR, and CSX; the remaining governance/process requirements emit
signed process-artifact evidence (attestation register) or are tracked as
awareness-only. Pick an impact tier (**Low / Moderate / High**) and benchmark the
result against **NIST SP 800-53** — see the [root README](../README.md) and
[RUNBOOK](../RUNBOOK.md) for the full feature set.

> The sections below cover collector setup and the read-only model. For impact
> levels, the `--framework` NIST benchmark, output artifacts, and integrations,
> see the [root README](../README.md).

## Read-only commitments

The collector **must never mutate cloud state**. This is enforced five ways:

1. Every SDK call across `providers/aws/*.ts`, `providers/gcp/*.ts`, and
   `providers/k8s/*.ts` is a read verb: `Get*` / `List*` / `Describe*` /
   `Search*` / `Export*` / `Recommend*`. No `Put`/`Create`/`Update`/
   `Delete`/`Modify`/`Attach`/`Detach`/`Set*` calls anywhere.
2. **AWS runtime guardrail.** Every AWS SDK client is wrapped by
   [`core/readonly-guardrail.ts`](core/readonly-guardrail.ts), which proxies
   `.send()` and inspects the Command class name. Non-read verbs throw
   `ReadOnlyViolationError` before the call leaves the process.
3. **GCP runtime guardrail.** Every GCP client returned by
   `core/auth/gcp.ts::googleClient()` and `guardGcp()` is wrapped by a
   recursive Proxy in
   [`core/readonly-guardrail-gcp.ts`](core/readonly-guardrail-gcp.ts) that
   classifies every method call by verb prefix and throws
   `ReadOnlyGcpViolationError` on anything matching `create*` / `update*` /
   `delete*` / `set*` / `patch*` / `insert*`. Symmetric with the AWS
   guardrail; can be temporarily disabled for debugging via
   `CLOUD_EVIDENCE_DISABLE_GCP_GUARDRAIL=1` (DO NOT use in production).
4. **Required cloud IAM roles are read-only managed policies only.** See
   "Required cloud permissions" below.
5. **No write path to the tracker DB** that bypasses bearer-token-authenticated
   `/api/collector-runs`. Collector cannot directly mutate the tracker.

If you ever add a new collector, both guardrails will block any inadvertent
mutating call at runtime. Lint your changes by running `npm run typecheck`
and a `--dry-run` smoke test.

## Prerequisites

- **Node 22+** (developed against Node 24). The collector also runs on **Bun 1.3+**
  (recommended for production) and **Deno 2.8+** — see the RUNBOOK "Runtime" section.
- **AWS credentials**: the runner has an active session via `aws sso login`
  or `AWS_PROFILE` set to a profile with read-only access (see roles below).
- **GCP credentials**: `gcloud auth application-default login` already run,
  so Application Default Credentials are present.

## Install

```sh
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm install
```

## Configure

Edit `config.yaml`:

```yaml
aws:
  enabled: true
  regions: [us-east-1]            # primary region; expand later
  prod_tag: { key: env, values: [prod, production] }

gcp:
  enabled: true
  organization_id: null           # set if you want org-wide queries
  projects: [your-prod-project-id]
  prod_label: { key: env, values: [prod, production] }
```

`thresholds.yaml` controls per-severity finding rollup behavior. See the
file for documentation; tune the `defaults` block and add per-KSI
`overrides` as needed.

## Run

Plan only (no SDK calls):

```sh
npx tsx core/orchestrator.ts --dry-run
```

Real collection, all supported KSIs across both providers (default tier Moderate):

```sh
npx tsx core/orchestrator.ts
# or pick a tier + NIST benchmark framing:
npx tsx core/orchestrator.ts --impact-level high --framework rev5
```

Select a subset of KSIs:

```sh
npx tsx core/orchestrator.ts --ksis KSI-IAM-MFA,KSI-IAM-AAM
```

One provider only:

```sh
npx tsx core/orchestrator.ts --providers aws
```

Output goes to `./out/` (gitignored). One JSON file per KSI plus a top-level
`pva-run-summary.json`.

## Required cloud permissions (read-only)

### AWS

The simplest setup is the AWS-managed **`ReadOnlyAccess`** policy. It
covers every API the collector calls. If you prefer least-privilege, the
following AWS-managed policies (all read-only) cover Phase 1:

- `IAMReadOnlyAccess`
- `AWSSSOReadOnly`               *(IAM Identity Center)*
- `AWSOrganizationsReadOnlyAccess`
- `AWSSecurityHubReadOnlyAccess`
- `IAMAccessAnalyzerReadOnlyAccess`
- `AmazonGuardDutyReadOnlyAccess`
- `AmazonEventBridgeReadOnlyAccess`
- `AWSLambda_ReadOnlyAccess`
- `AmazonSSMReadOnlyAccess`
- `AmazonCognitoReadOnly`
- `sts:GetCallerIdentity` (in your inline trust)

The collector **does not** require any `Put*`/`Create*`/`Update*`/`Delete*`
permission, and the runtime guardrail blocks such calls even if a policy
were over-broad.

### GCP

Grant your principal (the user behind ADC, or an audit SA) these roles on
each in-scope project:

- `roles/iam.securityReviewer`            *(IAM bindings + SA inventory)*
- `roles/recommender.viewer`              *(Recommender findings)*
- `roles/orgpolicy.policyViewer`          *(Org policy constraints)*
- `roles/accesscontextmanager.policyReader` *(CAA policies)*
- `roles/logging.privateLogViewer`        *(audit logs / IAM Audit Configs read; needed for later phases)*
- `roles/eventarc.viewer`                 *(Eventarc triggers)*

For Identity Platform tenant inspection and Workforce Identity Federation
pool listing, add (at the appropriate scope):

- `roles/identitytoolkit.viewer`
- Org-level: `roles/iam.workloadIdentityPoolViewer` *(if pools are at org level)*

Workspace / Cloud Identity admin APIs (e.g. 2SV enforcement settings) need
admin scopes that ADC may not have. The GCP collectors degrade
gracefully when those are unavailable — affected findings surface as
warnings, not failures.

## Output structure

A run writes one `KSI-*.json` evidence envelope per requirement plus the
roll-ups and (signed) reports:

```
out/
  pva-run-summary.json       # top-level run summary (impact level + framework + benchmark headline)
  family-rollup.json         # per-control-family posture
  control-benchmark.json     # NIST 800-53 control benchmark for this run's framing/level
  KSI-IAM-MFA.json           # per-KSI evidence envelope (one per requirement) …
  manifest.json              # Ed25519-signed inventory of every output file
  manifest.sig
  run-ledger.jsonl           # append-only audit trail of every action + timing
  …                          # OSCAL / crosswalk / coverage / diff / report.html (opt-in)
```

See the [root README](../README.md#output-artifacts) for the full artifact table.
Each per-KSI file follows the envelope shape documented in
[ksi-deep-analysis.md](ksi-deep-analysis.md#output-envelope-final).

## KSI coverage

**44 of the 63 KSIs run live cloud collectors** (the rest are governance/process
requirements satisfied via the attestation register or tracked awareness-only).
Run `npx tsx core/orchestrator.ts --dry-run` to print the exact in-scope set for
your config and tier. Collectors live under `providers/aws/*.ts` and
`providers/gcp/*.ts`, grouped by domain (iam, network, logging, config, data,
secrets, backup, supplychain, inventory), plus `providers/k8s/security.ts`. The
authoritative requirement registry is `docs/frmr-requirements.generated.json`
(regenerated by `scripts/extract-frmr-requirements.mjs`).

## Layout

```
cloud-evidence/
  config.yaml                   # account/project scope        thresholds.yaml  # finding rollup config
  core/
    orchestrator.ts             # CLI entry point
    ksi-map.ts                  # master KSI -> collector map (44 cloud KSIs)
    envelope.ts / findings.ts   # evidence envelope + finding/rule/rollup helpers
    schema.ts / sign.ts / timestamp.ts / oscal.ts   # validation, signing, RFC 3161, OSCAL
    control-benchmark.ts        # NIST 800-53 control benchmark (20x + Rev5)
    requirements-registry.ts / process-artifact-tracker.ts   # level scoping + process evidence
    run-ledger.ts / run-lock.ts / rate-control.ts            # production hardening
    readonly-guardrail.ts / readonly-guardrail-gcp.ts        # runtime read-only enforcement
    auth/ (aws.ts, gcp.ts, k8s.ts)
  providers/
    aws/*.ts  gcp/*.ts  k8s/security.ts                       # per-domain collectors
  scripts/                      # reproducible data extractors (FRMR, NIST r5, baselines)
  docs/                         # committed generated lookups + IAM-PERMISSIONS-CATALOG.md
  tests/                        # vitest suites (38 files, 396 tests)
  out/                          # generated evidence files (gitignored)
```

## Troubleshooting

- **`AWS auth failed`**: run `aws sso login` (if SSO) or `export AWS_PROFILE=<profile>`. Verify with `aws sts get-caller-identity`.
- **`GCP auth failed`**: run `gcloud auth application-default login`. Verify with `gcloud auth application-default print-access-token`.
- **`ReadOnlyViolationError`**: a collector tried to dispatch a non-read-only Command. This is a defect in the collector — file an issue; do not work around the guardrail.
- **Many warnings about "not enabled or no permission"**: expected if a feature isn't in use (e.g. PAM, Identity Platform). Warnings are informational; check `pva-run-summary.json` to see which KSIs actually failed vs. just warned.
- **`getIamPolicy` returns minimal bindings**: pass `requestedPolicyVersion: 3` (already done in code) to receive conditional bindings.
