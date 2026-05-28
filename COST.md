# Cost model — FedRAMP 20x tooling

This document estimates the recurring cost of running cloud-evidence + tracker in production.

## Per-run cost — cloud-evidence

The orchestrator is **dollar-cheap by design**: every AWS / GCP call is on the read-side, where most providers either don't charge or charge negligible amounts. Below are realistic ranges per full run (37 KSIs, ~600 SDK calls, single account / single project).

| Provider | Cost source | Per-run | Notes |
|---|---|---|---|
| AWS API calls (IAM/Organizations/EC2/S3/...) | Mostly free | $0.00 | Read APIs aren't priced individually on most services. STS and AccessAnalyzer are free. |
| AWS Athena (CMT-VTD only, optional) | $5 per TB scanned | $0.00–$0.10 | Only fires if AWS Athena is queried — most orgs skip this. |
| AWS Config (DescribeConfigurationRecorders read) | Free | $0.00 | Read APIs are free; only data-collection is metered. |
| AWS Inspector2 (SVC-VCM read) | Free | $0.00 | Findings list is free; only running scanners costs. |
| GCP API calls (Asset Inventory / IAM / Logging / ...) | Mostly free | $0.00 | Asset Inventory has a free tier of 1000 requests/minute. |
| GCP Cloud Logging exports | $0.50 per GB scanned | $0.00–$0.05 | Only fires if querying recent log volumes (MLA-ALA). |
| Egress (outbound to APIs from your runner) | $0.09/GB AWS, $0.12/GB GCP | <$0.01 | Per-run payload is under 50 MB total. |

**Realistic per-run total: under $0.20**, dominated by Athena/Logging queries when those collectors are exercised. Free-tier accounts and most production accounts hit zero.

## RFC 3161 timestamping

DigiCert's default TSA is free for low-volume use. Other public TSAs (free):

- `http://timestamp.digicert.com` (default)
- `http://timestamp.apple.com/ts01`
- `http://tsa.belgium.be/connect`
- `https://freetsa.org/tsr`

For high-volume or compliance-driven needs (notarization with EU eIDAS certified TSAs), expect $0.001–$0.01 per token. We make one request per **run**, not per finding — so even at $0.01/run a daily collector is $3.65/year.

## LLM PR generator (optional)

Anthropic Claude API pricing (as of 2026-05):

| Model | Input | Output |
|---|---|---|
| claude-opus-4 / 4.5 | $15/M tokens | $75/M tokens |
| claude-sonnet-4-5 | $3/M tokens | $15/M tokens |
| claude-haiku-4-5 | $1/M tokens | $5/M tokens |

A typical PR generation request:
- Input: ~3,000 tokens (system prompt + finding context)
- Output: ~1,500 tokens (PR title + body + 1–2 file diffs)

Per call, by model:
- claude-opus-4.5: ~$0.16
- claude-sonnet-4.5: ~$0.03
- claude-haiku-4.5: ~$0.01

If a daily run has ~10 failing findings and you generate PRs for each, that's $0.30/day with Sonnet ($110/year). Use Haiku for first-pass triage and reserve Opus for human review.

## Tracker hosting

The tracker is a single Node process + SQLite file. Resource needs:

| Component | Footprint |
|---|---|
| CPU | 1 vCPU, idle most of the time |
| RAM | 256 MB (mostly Node + better-sqlite3 buffer cache) |
| Disk | ~50 MB for the DB at 50-user steady state; grows by ~1 MB per 10 000 audit events |

**Production deployment options:**

| Option | Cost/mo | Notes |
|---|---|---|
| AWS Lightsail ($5 plan) | $5 | 1 GB RAM, 40 GB SSD, 2 TB transfer |
| GCP Cloud Run | $0–10 | Free tier covers 50 RPS; metered above |
| Bare metal / on-prem | $0 | Most realistic for FedRAMP boundary deployment |

Backup storage (S3 / GCS): negligible. Daily 5-MB compressed backup × 30-day retention = 150 MB = <$0.01/mo.

## Tracker LLM cost — internal recommendations (planned)

Not yet wired but anticipated:
- "Suggest a remediation note" button next to a failing-KSI: ~$0.02/call with Haiku.

## CI run cost (GitHub Actions)

The included `.github/workflows/collect.yml` runs on a schedule. GitHub-hosted standard runner is free for public repos and $0.008/minute for private. A typical full run takes 4–6 minutes:

- Public repo: $0/run
- Private repo: ~$0.04/run = $14/month for daily runs

OIDC auth (no long-lived secrets) is free.

## TL;DR — annual cost of a daily-collector deployment

| Cost line | Annual (no LLM) | Annual (LLM Sonnet) |
|---|---|---|
| AWS / GCP API calls + egress | <$5 | <$5 |
| RFC 3161 timestamps (free TSAs) | $0 | $0 |
| LLM PR generation | $0 | ~$100–$200 |
| Tracker hosting (Lightsail) | $60 | $60 |
| Backup storage | <$1 | <$1 |
| CI (GitHub Actions, private repo) | $14 | $14 |
| **Total** | **~$80** | **~$280** |

For a CSP processing FedRAMP Moderate workloads, $80–$280/year is rounding error compared to the cost of a single 3PAO engagement. The dominant cost is the engineers' time, which this tooling reduces.

## Cost levers to tune

If you need to cut costs further:
- Skip Athena/Logging-query collectors (`--ksis` to exclude CMT-VTD, MLA-ALA).
- Run weekly instead of daily (5× reduction in CI cost; auditors generally accept this).
- Use Haiku for LLM PRs (~5× cheaper than Sonnet, ~16× cheaper than Opus).
- Disable LLM generation entirely (no functional loss — remediation options are pre-baked in the evidence schema).

## What you should NOT cut

- **Schema validation** (`--strict-schema`) — catches bugs before they ship to Paramify.
- **Evidence signing** — required for audit defensibility.
- **Read-only guardrail** — already free; do not consider disabling.
- **Coverage check** — silent-failure detector; free.
