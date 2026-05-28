# Gap Analysis: cloud-evidence + tracker vs. existing tooling

A thorough survey of what comparable open-source and closed-source tools
do well that this stack doesn't yet, plus security/efficiency/scale
opportunities that surface from a careful read of the current ~19,000-line
codebase.

> **⚠️ Status note (updated 2026-05-28):** This document was the *original* gap
> survey. **Most of §1–§12 has since been implemented** — OSCAL output, Ed25519
> signing + RFC 3161 timestamps, the full test suite (495 tests) + CI, retry/
> parallelism/structured logging, multi-framework crosswalk, AWS org fan-out,
> K8s-direct collectors, SBOM depth, anomaly detection, the GCP read-only Proxy,
> Powerpipe, tracker CSRF/rate-limit/2FA/RBAC/backup/audit-search/uploads, plugin
> architecture, OpenAPI, CHANGELOG, ticket/SIEM/webhook push, LLM PR generation,
> cost model, NIST 800-53 control benchmark, and Bun/Deno runtimes. See
> [CHANGELOG.md](CHANGELOG.md) for what shipped. The remaining open items (kept
> below for the record) are the roadmap ones: Azure/Oracle collectors, real-time
> threat detection, evidence encryption-at-rest, LLM gap-analysis/Paramify
> narratives, an MCP server, persistent caching/incremental collection, and some
> tracker UX (real-time updates, bulk-edit, saved views). The original snapshot
> below is left intact for historical context.

**Original snapshot (2026-05-27):**
- `cloud-evidence/`: 16,470 LOC TypeScript, 37 KSI collectors, no tests
- `tracker/`: ~2,700 LOC TypeScript, web dashboard over FRMR JSON, no tests
- Coverage: AWS + GCP, FedRAMP 20x only, no OSCAL output, no Azure, no K8s-direct

---

## Executive summary — the 10 highest-leverage improvements

These are the ones that move the needle on either audit defensibility, operational reliability, or feature breadth most per unit of effort.

| # | Improvement | Why critical | Effort |
|---|---|---|---|
| 1 | **OSCAL output module** | FedRAMP's official machine-readable standard. Without it, every audit submission requires manual translation. This single feature aligns the project with how FedRAMP actually wants to consume evidence going forward. | Large |
| 2 | **Evidence-file signing + chain-of-custody** | Audit-grade evidence requires tamper-evidence. Hash each evidence file, sign with cosign/HMAC, store hashes in append-only log. | Medium |
| 3 | **Test suite (vitest + fixtures)** | Zero tests for 19k LOC of compliance-critical code is an audit red flag and a maintenance liability. Mock SDK fixtures + finding assertions. | Large |
| 4 | **Parallel collection with rate-limit awareness** | Current sequential SDK calls are ~10-100× slower than necessary for medium orgs. Add p-limit-based concurrency + exponential backoff. | Medium |
| 5 | **Multi-framework control crosswalk** (SOC 2 / ISO 27001 / HIPAA from same evidence) | Each KSI's NIST controls are already captured. Mapping NIST → SOC2 CC controls / ISO 27001 Annex A / HIPAA safeguards is mostly static. Same collection effort, 3-5× framework coverage. | Medium |
| 6 | **Org-wide AWS fan-out** (multi-account assume-role) | Today's collector runs against one account. SaaS CSPs typically have 3-20 accounts. Promote AWS auth from "single profile" to "list accounts + assume role per account." | Medium |
| 7 | **K8s-direct collectors** (EKS + GKE workload-level checks) | Current EKS/GKE coverage is cloud-API only (cluster endpoint, network policy enabled). Real risks (privileged pods, hostNetwork, weak PSA standards, mTLS strict mode) require kubectl access. | Large |
| 8 | **Tracker hardening:** RBAC + audit-log search + rate limiting + 2FA option | Tracker contains FedRAMP-grade audit data with only admin/member roles, no rate limiting, no 2FA. Sufficient for prototype, insufficient for production. | Medium |
| 9 | **LLM-driven remediation PR generator** | The schema is *designed* for LLM consumption but nothing actually consumes it. Add `--generate-prs` that feeds failing findings to Claude/GPT and opens a draft Terraform PR per finding. | Medium |
| 10 | **Steampipe/Powerpipe integration** for free coverage breadth | Steampipe + community mods give us ~1000 additional cloud-config checks for free. Wire them in as supplementary `auxiliary_findings[]` on each KSI. | Small-medium |

If you build only the **top 5**, the tool moves from "comprehensive prototype" to "audit-defensible production system."

---

## 1. Tooling landscape — what we're competing with

### Open-source we should know about

| Tool | What it does | Relevant lessons for us |
|---|---|---|
| **Prowler** | 300+ AWS/GCP/Azure security checks across CIS, NIST, FedRAMP, SOC2, ISO27001, HIPAA, PCI | Has the **multi-framework crosswalk** we lack. Python codebase, MIT license. Maps every check to multiple framework controls. |
| **ScoutSuite** | Multi-cloud security auditing, defensive posture (NCC Group) | Strong HTML report; doesn't enforce policy, just surfaces. **Their HTML report is more polished than ours.** |
| **Steampipe + Powerpipe** | SQL-as-query language over cloud APIs; community mods include FedRAMP, CIS, NIST | **Mod ecosystem** = community-contributed compliance benchmarks. We could embed Powerpipe as a backend for non-KSI checks. |
| **Cloud Custodian** | YAML-rule-based policy enforcement engine | **Policy-as-code** lets non-engineers express compliance rules. Our remediation_options are imperative; YAML rules would let users add custom checks. |
| **OPA (Open Policy Agent) + Rego** | General-purpose policy engine | Could be the **evaluation engine** for findings — replacing our hardcoded TypeScript checks with declarative Rego policies. |
| **fedramp-automation (GSA)** | OSCAL-format FedRAMP package validation | This is the OFFICIAL FedRAMP repo. **We should produce OSCAL output that this tool can ingest.** |
| **compliance-trestle (IBM)** | OSCAL toolkit — read, transform, validate | The toolkit for working with OSCAL. We could use it as our OSCAL writer. |
| **Checkov / tfsec / Terrascan** | IaC scanning | Complementary, not competitive. Our CMT-VTD detects whether they're invoked; we don't run them. |
| **Trivy / Grype / Syft** | Container + SBOM scanning | Same — complementary. Our SCR-MON points at Inspector / Artifact Analysis; could also point at Trivy results. |

### Closed-source / SaaS — feature benchmarks

| Tool | What we're missing vs. them |
|---|---|
| **Wiz** | Agentless deep K8s/container scanning, identity graph, attack-path analysis, real-time threat detection, SBOM, license scanning, 500+ integrations |
| **Lacework** | Behavioral baselining (anomaly detection), CWPP + CSPM in one, vulnerability prioritization by reachability |
| **Prisma Cloud** | Same as above; strong on multi-cloud (AWS/GCP/Azure/Oracle/Alibaba), IaC scanning bundled |
| **Orca Security** | Agentless side-scanning of EBS/disks (we can't see disk contents); identity attack paths |
| **Drata / Vanta / SecureFrame** | GRC-first; auto-evidence collection plus questionnaire/document workflow; vendor risk management built in; SOC2/ISO27001/HIPAA bundled |
| **Paramify** | FedRAMP-specific authoring; SSP generation; control narrative library; KSI tracking. **User already uses this — we just integrate via push adapter.** |
| **Datadog Cloud Security Management** | Real-time alerts; identity threat detection; ties cloud findings to APM traces |
| **Microsoft Defender for Cloud** | Azure-native; multi-cloud via Azure Arc; built-in regulatory compliance dashboard |
| **AWS Audit Manager** | AWS-native automated evidence collection mapped to FedRAMP/HIPAA/SOC2/PCI. **Free with AWS account.** Should evaluate whether we're duplicating effort. |

### Where this stack is genuinely competitive

- **FedRAMP 20x KSI-native data model** — none of the OSS tools above know about FedRAMP 20x KSIs by name. Prowler has FedRAMP rev5 mappings; Powerpipe has a FedRAMP mod but not 20x.
- **LLM-targeted evidence schema** — our v3 schema (current_state / target_state / gap / remediation with cost/availability/customer-visible/effort) is more LLM-friendly than any tool I've seen. Wiz's findings have remediation hints but nothing as structured.
- **Cross-KSI dependency map + alternative-satisfier detection** — most tools assume a single satisfaction path. We model: "if you use Okta, MFA enforcement is upstream."
- **Multi-cloud read-only guardrail with runtime enforcement** — most security tools have read-only IAM roles by convention; few enforce read-only at the SDK Proxy layer like we do for AWS.

---

## 2. Critical gaps (FedRAMP / audit defensibility)

### 2.1 No OSCAL output — **biggest single gap**

OSCAL (Open Security Controls Assessment Language) is OMB/NIST's machine-readable format for security plans, assessments, and continuous monitoring. FedRAMP has invested heavily in it via the [fedramp-automation](https://github.com/GSA/fedramp-automation) repo. The 20x program in particular is designed around OSCAL ingestion.

**Today:** our evidence is bespoke JSON. To submit to FedRAMP automated review, someone manually translates.

**What to build:**
- New `core/oscal-writer.ts` module
- For each evidence file, emit OSCAL Assessment Results (AR) JSON conforming to OSCAL 1.1.x schema
- Map our `findings[]` to OSCAL `findings[]` with `target.target-id` referencing the NIST 800-53 control IDs we already carry
- Map each KSI's `rollup.pass` to an OSCAL `objective-status`
- Reuse our `cross_ksi_dependencies` as OSCAL `related-findings` links

**Value:** direct FedRAMP submission path; can be validated by [GSA's OSCAL validators](https://github.com/GSA/fedramp-automation/tree/main/src/validations); aligns with how Drata/Paramify/SecureFrame are pivoting their output.

**Effort:** large — OSCAL is a substantial spec; budget 2-3 weeks for a first cut.

### 2.2 No evidence-file integrity / chain of custody

**Today:** evidence JSON files are written to disk, then we tell auditors "trust them."

**What to build:**
- Each evidence file gets a SHA-256 hash on write
- Hashes appended to an `evidence-manifest.jsonl` (one line per file, signed)
- Optional cosign integration: sign the manifest with a Sigstore key
- Tracker stores manifest hashes in the `collector_runs` table; auditors can verify out-of-band
- Add a `--verify` mode that re-hashes existing evidence and compares against manifest

**Value:** auditor-grade evidence — "we collected this on date X, here's the cryptographic proof it wasn't modified after."

**Effort:** medium — ~200 LOC + cosign CLI integration.

### 2.3 RFC 3161 timestamps (optional but strong)

**Today:** evidence timestamps come from the local clock.

**What to build:**
- Optional integration with a free RFC 3161 TSA (e.g. DigiCert, Sigstore Rekor)
- Submit hash, receive signed timestamp, store alongside evidence

**Value:** "this evidence was collected before date X" provable to a 3rd party. Required for some auditor workflows.

**Effort:** small — ~50 LOC + http call.

### 2.4 No tests for 19,000 LOC of compliance code

**Today:** zero `*.test.ts` files. The runtime guardrail catches accidental write calls; nothing catches finding-logic regressions.

**What to build:**
- `vitest` configured for the project
- Fixture-driven tests: capture real (or synthetic) SDK responses into `tests/fixtures/aws/iam/*.json`, replay them via a fake SDK, assert findings
- One fixture set per KSI (well-formed env + failing env)
- CI gate: PRs fail if tests don't pass

**Sample test structure:**
```ts
import { describe, it, expect } from 'vitest';
import { collectIamMfa } from './iam.ts';
import { fakeAwsSdk } from '../../test-fixtures/fake-sdk.ts';

describe('KSI-IAM-MFA', () => {
  it('passes when root MFA enabled + all users have MFA + SCP enforces MFA', async () => {
    const ctx = fakeAwsSdk('tests/fixtures/iam-mfa-passing.json');
    const result = await collectIamMfa(ctx);
    expect(result.findings.every((f) => f.passed)).toBe(true);
  });
  it('fails root_mfa_enabled when AccountMFAEnabled=0', async () => {
    const ctx = fakeAwsSdk('tests/fixtures/iam-mfa-no-root.json');
    const result = await collectIamMfa(ctx);
    const root = result.findings.find((f) => f.rule === 'aws.iam.root_mfa_enabled');
    expect(root?.passed).toBe(false);
  });
});
```

**Value:** can confidently refactor; finding-logic regressions are caught; auditors trust the tool more.

**Effort:** large — 2-3 weeks to backfill, but each new KSI added becomes faster after the harness exists.

---

## 3. Operational maturity gaps

### 3.1 Sequential SDK calls (no parallelism, no rate-limit handling)

**Today:** every KSI collector calls its SDK methods serially. For an AWS account with 200 IAM users, IAM-MFA's per-user MFA check is ~200 sequential `ListMFADevices` calls. Same pattern across collectors.

**Math:** 35 collectors × 2 providers × avg 20 SDK calls × 100ms each = ~140 seconds best case. Realistic: 5-15 minutes for a medium org.

**What to build:**
- Wrap collectors with `p-limit` (concurrency 10-25)
- For per-user-style inner loops, batch with `Promise.allSettled`
- Implement exponential backoff on `ThrottlingException` / `RetryableError`
- Use AWS SDK v3 retry strategy (`maxAttempts: 5, retryMode: 'adaptive'`) — currently default
- Add `--max-concurrency` CLI flag

**Value:** 5-20× faster runs; tolerant of rate-limited services (IAM throttles hard).

**Effort:** medium — refactor each collector's inner loops.

### 3.2 No retry / backoff

**Today:** transient errors (network blip, throttling) fail the run.

**What to build:**
- Custom retry middleware in the read-only guardrail wrapper
- Distinguish: retryable (throttling, 503) vs. terminal (403, 404)
- Configurable per-API max retries

**Effort:** small — extend `wrapAwsClient` with retry logic.

### 3.3 No structured logging or observability

**Today:** `console.log` throughout the orchestrator. Run progress is opaque.

**What to build:**
- Replace `console.log` with `pino` (JSON-structured)
- Add OpenTelemetry spans: one per KSI, child spans per SDK call
- Optional OTLP exporter — send to Datadog/Honeycomb/Tempo
- `--log-level` and `--otlp-endpoint` flags

**Value:** debug failed runs faster; track collection time per KSI / per API; aggregate across runs.

**Effort:** small-medium.

### 3.4 No partial-failure recovery / checkpointing

**Today:** if the orchestrator crashes mid-run, the next run starts from scratch.

**What to build:**
- Per-KSI completion tracked in `out/.run-state.json`
- `--resume` flag picks up from last completed KSI
- KSI-level idempotency (each KSI overwrites its own evidence file cleanly)

**Effort:** small.

### 3.5 No memory bounds for large orgs

**Today:** all evidence accumulates in memory. A 50-account, 50-region AWS org would blow out heap.

**What to build:**
- Stream evidence to disk as each KSI completes (already done — good)
- Don't keep full provider blocks in memory after writing
- Add `--max-evidence-records-per-finding` to truncate verbose observations

**Effort:** small.

---

## 4. Feature breadth gaps

### 4.1 Multi-framework crosswalk (highest ROI)

**Today:** every KSI carries NIST 800-53 control IDs. We map FedRAMP 20x → NIST. Nothing else.

**What to build:**
- Static control crosswalk in `core/control-mapping.ts`:
  - NIST 800-53 rev5 → SOC 2 CC (Common Criteria)
  - NIST 800-53 rev5 → ISO 27001:2022 Annex A
  - NIST 800-53 rev5 → HIPAA Security Rule §164.308/.310/.312
  - NIST 800-53 rev5 → PCI DSS 4.0 requirements
- Sources: NIST has [official mappings](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search) for SOC 2 and ISO 27001
- Each evidence file gains a `framework_mappings: { soc2: [...], iso27001: [...], hipaa: [...] }` field
- HTML report adds framework filters

**Value:** same collection effort, 4× framework coverage. Reframe a single run as "compliance evidence for FedRAMP 20x, SOC 2, ISO 27001, HIPAA simultaneously."

**Effort:** medium — mapping is mostly data, code is straightforward.

### 4.2 Org-wide AWS multi-account fan-out

**Today:** single profile / single account.

**What to build:**
- `config.yaml.aws` accepts a list of `assume_role_target_accounts: [...]`
- Orchestrator iterates per account: `STS:AssumeRole` into a read-only role
- Evidence file's `providers[]` now contains N blocks per KSI
- Coverage check (already added) validates all expected accounts produced evidence

**Value:** realistic for SaaS CSPs with 5-20 accounts; matches FedRAMP boundary norms.

**Effort:** medium — refactor `setupCtx` to be account-aware; reuse the `whoAmI` pattern.

### 4.3 K8s-direct collectors

**Today:** EKS/GKE checks are surface-level (`endpoint_public_access`, `network_policy_enabled`). Real lateral-movement risks live inside the cluster.

**What to build:**
- New `providers/k8s/` directory
- Use `@kubernetes/client-node` to connect via current context
- Collect: PodSecurityPolicy / PodSecurityStandards, NetworkPolicy coverage by namespace, privileged pods, hostNetwork pods, ServiceAccount over-grants, RBAC ClusterRoleBinding analysis
- New KSIs satisfied by K8s data: deep CNA-MAT, CNA-RNT, SVC-VRI (admission control)
- Optional Gatekeeper / Kyverno / Polaris findings ingestion

**Value:** real container-platform security findings, not just "is the cluster API private."

**Effort:** large — equivalent to building a 3rd provider module.

### 4.4 Azure / Oracle / IBM Cloud collectors

**Today:** AWS + GCP only.

**What to build:** mirror collectors using `@azure/arm-*`, `oci-sdk`, etc.

**Value:** SaaS CSPs sometimes have Azure as a tertiary cloud. Government often requires multi-cloud.

**Effort:** large per provider (1-2 weeks each).

**Recommendation:** defer unless user actually has Azure/Oracle in scope.

### 4.5 SBOM and supply-chain depth

**Today:** SCR-MON checks Inspector + Artifact Analysis (vuln counts).

**What to build:**
- Generate SBOM (CycloneDX or SPDX) from `package.json` + transitive deps
- Detect known-vulnerable dependencies (npm audit + osv-scanner)
- Check container base-image provenance via cosign verify
- Wire Dependabot/Renovate config detection as alternative satisfier

**Value:** SCR-MON evidence is currently sparse. SBOM is FedRAMP rev5 EO 14028 territory.

**Effort:** medium.

### 4.6 Anomaly detection (baseline-based)

**Today:** all findings are absolute thresholds.

**What to build:**
- Store summary metrics from last N runs in tracker (`collector_runs.summary_json` already does this)
- Statistical baselining: this run's `inspector_critical_findings` is 3σ above the trailing-30-day average → flag
- Implement as a new finding category: `anomaly_findings[]` alongside the absolute findings

**Value:** catches "your env got significantly worse overnight" before threshold-based alerts.

**Effort:** medium.

### 4.7 Real-time threat detection layer

**Today:** snapshot-based; no real-time signal.

**What to build:** out of scope for cloud-evidence's design (it's an inventory tool, not a sensor). Recommendation: integrate at the SIEM layer (MLA-OSM) rather than building duplicate detection.

---

## 5. Security hardening — collector

### 5.1 GCP read-only guardrail is weaker than AWS

**Today:** `core/readonly-guardrail.ts` wraps every AWS SDK client with a Proxy that inspects Command class names. **GCP has no equivalent — we enforce by convention.**

**What to build:**
- A Proxy wrapper around the `googleapis` client object that intercepts method calls
- Whitelist `.get`, `.list`, `.search`, `.export*`, `.recommend*`, `.aggregatedList`
- Reject `.create`, `.update`, `.patch`, `.delete`, `.insert`
- Same `ReadOnlyViolationError` class

**Value:** parity with AWS; defense-in-depth against future contributor mistakes.

**Effort:** small-medium.

### 5.2 No input validation on user config

**Today:** `config.yaml` is parsed and trusted. A malicious config could specify arbitrary AWS role ARNs, arbitrary GCP project IDs, etc.

**What to build:**
- Validate `config.yaml` against a JSON Schema at startup (zod or ajv)
- Reject suspicious patterns (e.g. role ARNs from foreign accounts not on an allowlist)

**Effort:** small.

### 5.3 Sensitive data in evidence files unencrypted at rest

**Today:** evidence files contain IAM principals, account IDs, IP addresses, KMS key ARNs. Stored as plain JSON on disk.

**What to build:**
- Optional `--encrypt-evidence` flag using a CMK
- Option to redact specific fields based on sensitivity tags

**Effort:** medium.

### 5.4 No log of who accessed evidence files

**Today:** anyone with filesystem access can read evidence.

**What to build:**
- If using a shared output bucket (S3/GCS), use audit logging (already covered for the bucket itself by KSI-MLA-ALA)
- For local runs: log evidence-read events to a separate audit log

**Effort:** small.

### 5.5 API token best practices

**Already done:** tokens hashed at rest, shown once at creation, can be revoked.

**Gaps:**
- No automatic expiry by default (you set ttl_days, but new tokens default to no expiry)
- No rotation reminders
- No scope-narrowing per KSI (admin tokens can read all KSIs)

**What to build:**
- Default `ttl_days = 365`
- Background job to notify on tokens expiring in 30 days
- Add per-KSI-prefix scopes (`patch:indicators:KSI-IAM-*`)

**Effort:** small.

---

## 6. Security hardening — tracker

### 6.1 No CSRF tokens (relies on SameSite=Strict only)

**Today:** state-changing endpoints rely entirely on the session cookie's `SameSite=Strict` attribute.

**Risk:** older browsers, browser bugs, subdomain-confused requests could bypass. Defense-in-depth would add explicit CSRF tokens.

**What to build:**
- Issue a CSRF token alongside the session cookie
- Require `X-CSRF-Token` header on all state-changing requests
- Skip CSRF check for Bearer-token (API) auth

**Effort:** small-medium.

### 6.2 No rate limiting on auth endpoints

**Today:** unlimited login attempts. Password brute force possible.

**What to build:**
- Sliding-window rate limiter on `/api/auth/login` and `/api/auth/signup`
- Lock IP for 15 min after 10 failed attempts in 1 min
- Lock account for 1 hour after 20 failed attempts in 24 hours

**Effort:** small.

### 6.3 No 2FA

**Today:** password-only.

**What to build:**
- TOTP-based 2FA (industry standard, no SMS)
- Optional WebAuthn/passkey support (the latter is what KSI-IAM-MFA recommends for AWS — eat our own dogfood)
- Recovery codes

**Effort:** medium.

### 6.4 No granular RBAC

**Today:** `admin` and `member`. No "reviewer," "auditor," "read-only."

**What to build:**
- New roles: `viewer` (read-only), `auditor` (read + export, no edits), `reviewer` (edit assigned KSIs only)
- Per-KSI ownership + per-process scope

**Effort:** medium.

### 6.5 No password complexity / history / rotation

**Today:** 8-char minimum, that's it.

**What to build:**
- Match the KSI-IAM-APM target: ≥14 chars + complexity flags + reuse prevention
- Optional max-age (90 days)
- Use Identity Center / external IdP as alternative (set `auth_mode: federated` in tracker config)

**Effort:** small.

### 6.6 No audit log query UI

**Today:** `audit_log` table is populated but only visible per-KSI in the item detail page.

**What to build:**
- Full audit-log explorer page: filter by user, KSI, time range, action type
- CSV export
- "Who changed status of KSI-IAM-MFA in last 30 days" queries

**Effort:** small.

### 6.7 No backup / disaster recovery for tracker

**Today:** single SQLite file. Lose it, lose everything.

**What to build:**
- `npm run backup` — copies tracker.db to timestamped path
- Scheduled backup via cron / systemd timer
- S3/GCS backup destination option
- Document restore procedure

**Effort:** small.

### 6.8 No data retention policy

**Today:** audit log + collector_runs + sessions grow unbounded.

**What to build:**
- Configurable retention (default: keep audit_log 7 years, sessions 30 days post-expiry, collector_runs 1 year)
- Vacuum job

**Effort:** small.

---

## 7. Developer experience gaps

### 7.1 No tests (mentioned above; impacts every other improvement)

### 7.2 No plugin architecture

**Today:** adding an org-specific KSI requires editing `ksi-map.ts`, creating a collector file, and re-typechecking.

**What to build:**
- `plugins/` directory loaded dynamically at startup
- Each plugin exports `{ ksiEntry: KsiEntry, collectors: { aws?, gcp? } }`
- Orchestrator merges with built-in KSI_MAP

**Value:** users can add custom org-internal KSIs (e.g. "we have an internal CSI-XYZ that requires X") without forking.

**Effort:** small-medium.

### 7.3 No schema validation of evidence output

**Today:** TypeScript types enforce shape at compile time, but the runtime envelope could drift if a collector returns malformed data.

**What to build:**
- Define the envelope schema in `core/envelope.schema.json` (JSON Schema)
- Validate every emitted evidence file before write
- Fail fast on schema drift

**Effort:** small.

### 7.4 No CI for the collector itself

**Today:** `.github/workflows/cloud-evidence.yml` runs the collector, but no CI for the collector's own source.

**What to build:**
- `.github/workflows/ci.yml`: lint + typecheck + tests on every PR
- Coverage threshold gate (e.g. 70%)

**Effort:** small (depends on test suite existing).

### 7.5 No API docs

**Today:** the tracker API is documented only in code.

**What to build:**
- OpenAPI 3.1 spec for tracker API (`/api/openapi.json`)
- Auto-generated from Hono routes (using `@hono/zod-openapi` or hand-written)
- Swagger UI at `/api/docs`

**Effort:** small-medium.

### 7.6 No CHANGELOG / versioning

**Today:** no version bumps, no release notes.

**What to build:**
- Conventional Commits + `release-please` for automatic CHANGELOG generation
- Tag releases that align with FRMR version bumps

**Effort:** small.

### 7.7 No architecture diagram

**Today:** the code structure exists, but a newcomer must read source to understand it.

**What to build:** Mermaid or PlantUML diagrams in `docs/architecture.md` covering:
- Collector data flow (orchestrator → providers → envelope → reports)
- Tracker request lifecycle (auth → API → DB)
- Integration topology (cloud-evidence → tracker → Paramify → Slack/PD)

**Effort:** small.

---

## 8. Ecosystem integration gaps

### 8.1 No Jira / ServiceNow / Linear ticket creation

**Today:** failing findings go to evidence files and tracker notes. No ticket workflow.

**What to build:**
- `core/ticket-push.ts` adapter (similar shape to paramify-push)
- Opt-in: `--push-jira`, `--push-servicenow`, `--push-github-issues`
- One ticket per affected_resource (or one per finding, configurable)
- Idempotent via `external_id = ksi_id + finding_rule + resource_identifier`

**Value:** closes the loop into engineering workflows where work actually happens.

**Effort:** medium per integration.

### 8.2 No SIEM direct push

**Today:** SIEM picks up cloud logs (CloudTrail, Cloud Audit Logs) but not our findings.

**What to build:**
- `core/siem-push.ts` — emit findings as ECS / OCSF JSON to a configured endpoint
- Splunk HEC, Elastic, Datadog Cloud SIEM all consume this format

**Effort:** small.

### 8.3 Webhook out (generic)

**Today:** specific adapters for Paramify, tracker, Slack, PagerDuty.

**What to build:**
- Configurable webhook list in `config.yaml`
- Each gets a POST with the run summary or per-KSI evidence

**Effort:** small.

### 8.4 Powerpipe / Steampipe integration

**Today:** we maintain our own check logic.

**What to build:**
- `cloud-evidence --supplement-with-powerpipe` flag
- Runs Powerpipe's FedRAMP mod alongside; merges findings into our evidence as `auxiliary_findings[]`
- Bonus: ~1000 additional checks for free

**Value:** dramatic coverage breadth increase for minimal effort.

**Effort:** small.

---

## 9. AI/LLM integration — biggest unrealized potential

The v3 schema is *designed* for LLM consumption. Nothing actually consumes it yet.

### 9.1 LLM-driven remediation PR generation

**What to build:**
- New CLI: `cloud-evidence-llm --provider claude|openai --action generate-prs`
- For each failing finding with `remediation.options[*].mechanism = 'terraform'`:
  - Find the relevant `*.tf` file in the user's IaC repo (configured path)
  - Build a Claude prompt: failing finding context + current TF file + remediation.example_code
  - Get back a unified diff
  - Open a draft PR on a per-finding branch
- Plus: a `--draft-only` mode that emits diff files locally

**Value:** the "AI for SRE" loop closes. Failing findings → drafts → human review → merge → next collector run shows fixed. This is the realistic "compliance-as-code" workflow.

**Effort:** medium — Claude API integration + repo path resolution + git operations.

### 9.2 LLM-driven gap-analysis narrative

**What to build:**
- `cloud-evidence-llm --action gap-narrative` produces a human-readable gap summary
- Feeds all failing findings to Claude with a prompt: "produce a 1-page exec summary of the most urgent items"
- Output: `out/gap-narrative.md` — feed to the security committee

**Effort:** small.

### 9.3 LLM-driven Paramify control-narrative authoring

**What to build:**
- For each KSI, generate a draft control-narrative paragraph based on the structured evidence
- Push to Paramify as `narrative` field (already supported in our payload)

**Value:** auto-drafts the SSP narrative. Human edits, doesn't write from scratch.

**Effort:** small-medium.

### 9.4 Embedded MCP server

The schema is also LLM-friendly because it could expose as an MCP server.

**What to build:**
- New `cloud-evidence-mcp/` subproject
- MCP server exposing tools: `query_finding`, `list_failing`, `propose_remediation`
- LLM agents (Claude Desktop, Cursor, etc.) can natively query compliance state

**Effort:** medium.

---

## 10. Efficiency improvements not yet mentioned

### 10.1 Caching

**Today:** no caching. Every run re-fetches everything.

**What to build:**
- TTL'd cache for slow / expensive API calls (`GenerateCredentialReport` takes seconds)
- Cache key includes account + region + API method + args
- `--no-cache` flag for fresh runs

**Effort:** small.

### 10.2 Incremental collection

**Today:** full snapshot every run.

**What to build:**
- For change-detection collectors (CMT-LMC), use last-collection timestamp to query only deltas
- Saves API calls + cost

**Effort:** medium.

### 10.3 Lazy SDK client construction

**Today:** all client factories construct on import.

**What to build:** make `aws.iam(auth)` lazy via `Proxy` (already partly done by the SDK itself, but we could add a `clientCache` layer).

**Effort:** small.

### 10.4 Pagination consistency

**Today:** some collectors paginate, some don't. Inconsistent.

**What to build:** a `paginate(call, extractor)` helper used everywhere.

**Effort:** small.

---

## 11. Tracker / UI improvements

### 11.1 Real-time updates

**Today:** UI polls via TanStack Query on mount.

**What to build:**
- WebSocket or SSE channel: tracker pushes "KSI-X status changed" to all connected clients
- Useful when multiple users are editing simultaneously

**Effort:** medium.

### 11.2 Bulk-edit

**Today:** edit one KSI at a time.

**What to build:**
- Multi-select rows in browse view → bulk action (set status, set owner, add note)

**Effort:** small-medium.

### 11.3 Attachment / file uploads

**Today:** `evidence_url` is a text link only.

**What to build:**
- File-upload endpoint (e.g. PDF, screenshot)
- Stored in `data/uploads/<sha256>.bin` with metadata in DB
- For air-gapped envs: replaces S3

**Effort:** medium.

### 11.4 Saved views / filters

**Today:** filter state lives in URL params but isn't shareable.

**What to build:**
- "Save current filter as view" — names + persists per user
- "Shared views" — admin-defined, visible to all

**Effort:** small.

### 11.5 In-app help / glossary

**Today:** terms like "FRMR," "KSI," "OSCAL" aren't defined inline.

**What to build:**
- Hover-tooltips on FRD term references (we have the data — the tracker already serves `/api/definitions`)
- Already partly implemented in `formatting.tsx` via `annotateTerms`; expand to nav items + headers

**Effort:** small.

---

## 12. Cost transparency

**Today:** no documentation on the AWS/GCP API charges incurred by running the collector.

**What to build:**
- `docs/cost-model.md` with estimated $/run for each enabled feature:
  - GuardDuty: $X / mo per account (varies by usage)
  - Inspector: $X / mo
  - Config + conformance pack: $X / mo
  - CloudTrail data events: $X / 100k events
  - VPC Flow Logs: $X / GB
  - KMS: $X / month per key
- Sum total expected for a "typical SaaS CSP"

**Value:** users can budget; surprises in the AWS bill reduce trust in the tool.

**Effort:** small (mostly research + writing).

---

## 13. Documentation gaps

Missing docs:
- Architecture diagrams (mentioned)
- Runbooks: "Inspector wasn't enabled before this run — how to backfill"
- Migration guide: from a manual spreadsheet to this stack
- Troubleshooting: common error messages → fixes
- Threat model: what attacks is this stack defending against; what's out of scope
- ADRs (Architecture Decision Records) for choices like SQLite vs. Postgres, TS vs. Go, etc.

---

## 14. Recommended prioritization

Given the effort estimates and impact, my recommended sequence for the next ~3-6 months of work:

### Sprint 1 (week 1-2): Critical reliability
1. Test suite scaffolding + 5 reference tests (IAM-MFA, IAM-AAM, CNA-MAT, MLA-OSM, CMT-LMC)
2. Parallel collection (`p-limit`, `--max-concurrency`)
3. Retry/backoff middleware
4. Schema validation of evidence files (ajv)

### Sprint 2 (week 3-4): Audit defensibility
5. Evidence-file signing (HMAC + manifest)
6. OSCAL Assessment Results output module (basic)
7. Tracker rate limiting + 2FA opt-in
8. Multi-framework crosswalk (NIST → SOC 2 + ISO 27001)

### Sprint 3 (week 5-6): Coverage expansion
9. Org-wide AWS multi-account fan-out
10. K8s-direct collectors (basic — admission control, RBAC review)
11. GCP read-only guardrail Proxy parity with AWS
12. Powerpipe/Steampipe integration (auxiliary findings)

### Sprint 4 (week 7-8): Ecosystem
13. LLM-driven remediation PR generator (Claude or GPT)
14. Jira/ServiceNow ticket adapter
15. SIEM direct push (OCSF format)
16. Tracker bulk-edit + saved views

### Sprint 5 (week 9-12): Polish + scale
17. Plugin architecture for custom KSIs
18. Tracker RBAC expansion (viewer, auditor, reviewer)
19. Backup/restore for tracker
20. Cost transparency docs

### Defer or skip
- Azure / Oracle / IBM Cloud connectors (build only if user actually needs them)
- Real-time threat detection (not the right tool category)
- WebSocket UI updates (nice-to-have, not core)
- MCP server (cool but defer until usage justifies)

---

## Summary

The current stack is **production-quality for the FedRAMP 20x KSI-tracking use case** but has identifiable gaps when measured against:
- General CSPM tools (Wiz, Prowler) — breadth of checks, multi-framework coverage
- GRC platforms (Drata, Vanta, Paramify) — workflow + ticket integration, narrative generation
- FedRAMP automation ecosystem (OSCAL) — machine-readable submission format

The biggest single missing piece is **OSCAL output** — it aligns this project with how FedRAMP wants to consume evidence in 2026+, and it's the difference between "great internal tool" and "FedRAMP-submission-ready."

The biggest single risk is **no tests** for 19,000 LOC of compliance-critical code. Every other improvement compounds value of having a test harness.

The biggest unrealized opportunity is **LLM-driven remediation PR generation**. The v3 evidence schema was designed for this; nothing currently does it. Implementing it would close the loop from "compliance signal" to "actual code change" without manual labor in between.
