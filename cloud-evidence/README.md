# cloud-evidence — FedRAMP 20x KSI evidence collector

A **read-only** TypeScript collector that captures AWS, GCP, and Kubernetes
configuration evidence for the FedRAMP 20x Key Security Indicators. Ships 35+
KSIs across IAM, CNA, MLA, CMT, SVC, RPL, PIY, SCR, INR, AFR, and CSX domains.

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

- **Node 20+** (developed against Node 24).
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

Real collection, all 7 IAM KSIs across both providers:

```sh
npx tsx core/orchestrator.ts
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
admin scopes that ADC may not have. The Phase 1 GCP collector degrades
gracefully when those are unavailable — affected findings surface as
warnings, not failures.

## Output structure

```
out/
  pva-run-summary.json       # top-level run summary (AFR-PVA evidence)
  KSI-IAM-AAM.json           # per-KSI evidence envelope
  KSI-IAM-APM.json
  KSI-IAM-ELP.json
  KSI-IAM-JIT.json
  KSI-IAM-MFA.json
  KSI-IAM-SNU.json
  KSI-IAM-SUS.json
```

Each per-KSI file follows the envelope shape documented in
[../cloud-evidence/ksi-deep-analysis.md](../cloud-evidence/ksi-deep-analysis.md#output-envelope-final).

## Phase 1 KSI coverage

| KSI | Scope | AWS coverage | GCP coverage |
|---|---|---|---|
| KSI-IAM-AAM | CLOUD | Credential report, IAM users, access keys, MFA pairing, IAM Identity Center inventory, Access Analyzer unused-access | Service accounts + SA keys, Org Policy `disableSaKeyCreation`, IAM Recommender (idle SAs, over-privilege), WIF pools |
| KSI-IAM-APM | CLOUD | IAM password policy, Cognito user-pool MFA | Org Policy `allowedPolicyMemberDomains`, Identity Platform tenants |
| KSI-IAM-ELP | CLOUD | Customer-managed policy wildcard scan, role-last-used inventory | Primitive role bindings, Policy Recommender findings |
| KSI-IAM-JIT | HYBRID | Permission-set `SessionDuration` audit, SSM Session Manager usage | Conditional IAM bindings, PAM entitlements |
| KSI-IAM-MFA | CLOUD | Root MFA, IAM-user MFA pairing, virtual MFA count, SCP scan for MFA-deny | Access Context Manager policies + access levels |
| KSI-IAM-SNU | CLOUD | IAM access-key total, role inventory | Service-account user-managed keys, WIF pool count |
| KSI-IAM-SUS | HYBRID | GuardDuty enabled, EventBridge rules → response Lambda, Security Hub critical IAM findings | Eventarc security-event triggers, IAM Audit Configs DATA_READ/DATA_WRITE for KMS+IAM |

## Roadmap

Phase 1 (this) — IAM end-to-end. Phases 2–6 are documented in
[../cloud-evidence/ksi-deep-analysis.md](../cloud-evidence/ksi-deep-analysis.md#build-sequence-recommended):

- Phase 2 — CNA domain (8 KSIs)
- Phase 3 — MLA + CMT (logging + change management)
- Phase 4 — SVC (data + crypto, 8 KSIs)
- Phase 5 — RPL + PIY-GIV + the HYBRID extras (AFR-PVA run summary; CSX-SUM aggregator)
- Phase 6 — Tracker push integration (opt-in via `--push-to-tracker`), Paramify adapter

## Layout

```
cloud-evidence/
  package.json
  tsconfig.json
  config.yaml                   # account/project scope
  thresholds.yaml               # per-severity finding rollup config
  README.md
  core/
    orchestrator.ts             # CLI entry point
    envelope.ts                 # output envelope types/helpers
    findings.ts                 # finding/rule/rollup helpers
    ksi-map.ts                  # master KSI->collector map (Phase 1: IAM only)
    readonly-guardrail.ts       # runtime read-only enforcement for AWS SDK
    auth/
      aws.ts                    # AWS client factories (read-only wrapped)
      gcp.ts                    # GCP client factories via googleapis + ADC
  providers/
    aws/iam.ts                  # 7 AWS IAM collectors
    gcp/iam.ts                  # 7 GCP IAM collectors
  out/                          # generated evidence files (gitignored)
```

## Troubleshooting

- **`AWS auth failed`**: run `aws sso login` (if SSO) or `export AWS_PROFILE=<profile>`. Verify with `aws sts get-caller-identity`.
- **`GCP auth failed`**: run `gcloud auth application-default login`. Verify with `gcloud auth application-default print-access-token`.
- **`ReadOnlyViolationError`**: a collector tried to dispatch a non-read-only Command. This is a defect in the collector — file an issue; do not work around the guardrail.
- **Many warnings about "not enabled or no permission"**: expected if a feature isn't in use (e.g. PAM, Identity Platform). Warnings are informational; check `pva-run-summary.json` to see which KSIs actually failed vs. just warned.
- **`getIamPolicy` returns minimal bindings**: pass `requestedPolicyVersion: 3` (already done in code) to receive conditional bindings.
