# FedPy integration research — index & prioritized backlog

Cross-repo synthesis of 11 analyses (reports `01`–`11`). Goal: front-load all
research so implementation can start cold. Each opportunity below maps to a
concrete FedPy surface, an effort size, a **license posture** (can we copy code,
or only the idea?), and the source report.

Raw clones live under `research/clones/` and downloads under `research/downloads/`
(both git-ignored). The reports are the durable artifact.

> **🔒 Licensing decision (locked 2026-05-28) — "Path A".** FedPy stays
> **Apache-2.0**. Copyleft sources are **spec/reference only, never a code source**:
> `manywho/awsinventory` (**GPL-3.0**, report 05) and `huntridge-labs/argus`
> (**AGPL-3.0**, report 08) — including ported code, since a translation is still a
> derivative work. Where we want actual code, we take it from the permissive
> analogs: **Apache-2.0** (`aws-samples/fedramp-integrated-inventory-workbook`,
> `google/asset-inventory-worksheet`, `oscal-content-generation`), **CC0**
> (`oscalkit`, `GoComply/fedramp`), or **MIT** (`python-ssp`, oscalkit/cybercraft
> submodules) — with attribution in `NOTICE` when we port. Implementation status is
> tracked at the bottom of this file.
>
> **Clean-room of copyleft *ideas* is fine.** Copyright protects *expression* (the
> actual code), not ideas, functionality, or facts. So we may freely reimplement
> *what* a GPL/AGPL tool does — including drawing on its good ideas (e.g.
> awsinventory's breadth of services) — and add our own mechanics, as long as we
> write **independent code** and don't transliterate theirs. The "twist" isn't the
> legal shield; independent expression is. Our inventory workbook does exactly this:
> a from-scratch build that adds FedPy-native mechanics absent from every analog —
> **scan reconciliation** (column O/I from our own VDR evidence) and **KSI-finding
> cross-linking** (each asset annotated with the compliance findings touching it).

---

## The 11 sources at a glance

| # | Source | Domain | License | Code-borrowable? | Relevance |
|---|--------|--------|---------|------------------|-----------|
| 01 | brasky/python-ssp | FedRAMP SSP `.docx` read API (python-docx) | MIT | Idea-only (Python; abandoned, Rev4) | Medium — SSP read-side OOXML knowledge |
| 02 | Coalfire-AWS-RAMPpak | FedRAMP AWS Terraform reference arch | MIT | Idea-only (HCL) | **High** — 11 candidate new AWS checks |
| 03 | Coalfire-Azure-RAMPpak | FedRAMP Azure Terraform reference arch | MIT | Idea-only (HCL) | High — spec for a net-new Azure collector |
| 04 | Coalfire-GCP-RAMPpak | FedRAMP GCP Terraform reference arch | MIT | Idea-only (HCL) | **High** — 14 candidate new GCP checks |
| 05 | manywho/awsinventory | AWS → FedRAMP inventory CSV (Go) | **GPL-3.0** | **No** (copyleft) — spec-only | High — inventory column/field spec |
| 06 | FedRAMP Integrated Inventory Workbook | The target `.xlsx` format (Appendix M) | Gov / public domain | Format only | **Highest ROI** — the deliverable to emit |
| 07 | GoComply/oscalkit | Go OSCAL SDK + XML/JSON/YAML convert+validate | CC0 | Yes (but Go → shell-out) | Medium — OSCAL conversion/validation |
| 08 | huntridge-labs/argus | DevSecOps scanner aggregator (+ SCN classifier) | **AGPL-3.0** | **No** — spec-only | Low overall; the SCN piece is Medium |
| 09 | GoComply/fedramp | OSCAL SSP → official FedRAMP Word doc (Go) | CC0 | Yes (Go → shell-out / port) | High — SSP *render* path + bundled templates |
| 10 | brian-ruf/oscal-content-generation | Skeleton OSCAL SSP from a baseline (Python) | Apache-2.0 | **Yes** (port the recipe) | High — SSP *generate* path |
| 11 | brian-ruf/cybercraft-cli | OSCAL validate/convert + offline NIST-schema cache | CLI: none; submodules MIT | Pattern + submodule code only | Medium — offline OSCAL validation design |

**License rule of thumb for implementers:**
- **Freely portable into our Apache-2.0 code:** CC0 (07, 09), Apache-2.0 (10), MIT (01, and oscalkit/cybercraft submodules) — *with attribution where MIT*.
- **Ideas/spec only, NEVER copy code:** GPL-3.0 (05 awsinventory), AGPL-3.0 (08 argus). Re-implement clean-room.
- **No license on the repo = all rights reserved:** cybercraft-cli's top-level CLI (11) — borrow the *design*, take code only from its MIT submodules.

---

## Themes (where the value clusters)

### Theme A — Inventory Workbook generation  ⭐ highest ROI
Reports **06** (the format), **05** (AWS field mapping, spec-only), plus two
Apache-2.0 reference designs surfaced during sourcing: **aws-samples/fedramp-
integrated-inventory-workbook** (AWS) and **google/asset-inventory-worksheet** (GCP).

The Appendix M workbook is a fixed **25-column** contract; **~16/25 columns
auto-fill** from data FedPy already collects (`providers/{aws,gcp}/inventory.ts`
+ network/data/crypto collectors). This directly answers the user's "do the same
for AWS and GCP" ask and is the single best build to start with.

### Theme B — SSP authoring pipeline (evidence → OSCAL SSP → Word)
FedPy's biggest capability gap. Three reports compose into one pipeline:
- **10** (oscal-content-generation, Apache-2.0) — the *recipe* to emit a skeleton
  OSCAL **SSP** (one `implemented-requirement` per baseline control). FedPy already
  has baseline membership (`docs/nist-r5-baselines.generated.json`) + the tracker's
  per-control status/notes to fill the stubs with real content.
- **09** (GoComply/fedramp, CC0) — the *renderer*: fills the official GSA SSP Word
  template in place; ships the templates. Needs an OSCAL SSP as input (which 10
  lets us produce).
- **01** (python-ssp, MIT) — read-side OOXML knowledge (control table pairing,
  checkbox parsing) useful if we render Word natively in TS instead of shelling out.

Sequence: build an **OSCAL-SSP emitter** (Theme B core) → then either shell out to
GoComply/fedramp for Word, or port its template-fill approach to TS.

### Theme C — OSCAL validation & conversion
Reports **07** (oscalkit) and **11** (cybercraft-cli). FedPy emits OSCAL 1.1
Assessment Results as hand-built JSON, **never validated**. Recommendation
(from 11): **borrow cybercraft's offline NIST-schema-cache pattern and validate
our emitted OSCAL JSON with our already-vendored `ajv`** — no new runtime
dependency. Reserve shelling out to oscalkit only if we ever need OSCAL **XML**
output (use NIST's own XSLT converters, don't hand-roll). Watch OSCAL version
drift (both tools track different OSCAL lines).

### Theme D — Cloud control-check expansion (detective coverage)
Reports **02** (AWS, 11 checks), **04** (GCP, 14 checks). The Coalfire reference
architectures are a "what good looks like" catalog → a backlog of concrete new
checks for our existing `providers/{aws,gcp}/*.ts`. Highest-value common theme:
upgrade encryption checks from "encrypted" to "**encrypted under a customer-managed
key (CMK/CMEK)**", plus org-guardrail checks (SCPs / GCP Org Policy / VPC-SC) and
managed-baseline enrollment (Security Hub standards / Assured Workloads).

### Theme E — New Azure collector (net-new cloud)
Report **03**. FedPy is AWS+GCP only. RAMPpak-Azure is the requirements spec for a
`cloud-evidence/providers/azure/*.ts` collector (TS path exists: `@azure/identity`
+ `@azure/arm-*`, read-only `Reader` role, our Proxy guardrail transfers). Large
effort; lower urgency than A–D but the clearest "expand the market" move.

### Theme F — Significant Change Notification (SCN) classifier
Report **08** (argus, AGPL — clean-room only). A FedRAMP 20x change-management
capability FedPy scoped out: diff IaC between git refs and classify changes as
Routine/Adaptive/Transformative/Impact with notification timelines. Pairs well
with our existing diff-report/anomaly features.

---

## Prioritized integration backlog

Effort: S ≤ ~1 day · M ~2–5 days · L > 1 week. Priority: P0 (start here) → P2 (later).

| ID | Item | Theme | FedPy target | License posture | Effort | Priority | Source |
|----|------|-------|--------------|-----------------|--------|----------|--------|
| INV-1 | OSCAL/Appendix-M column contract as typed constant + row model | A | `core/inventory-workbook.ts` (new) | format (public) | S | **P0** | 06 |
| INV-2 | AWS resource→row mapper (reuse inventory.ts + ENI/SSM/RDS/Lambda) | A | `providers/aws/inventory.ts` + new module | clean-room from 05/aws-samples | M | **P0** | 05,06 |
| INV-3 | GCP resource→row mapper (reuse inventory.ts + Cloud Asset Inventory) | A | `providers/gcp/inventory.ts` + new module | mirror google/asset-worksheet (Apache) | M | **P0** | 06 |
| INV-4 | Emit real `.xlsx` (exceljs, MIT) + CSV fallback; `--inventory-workbook` flag | A | `core/inventory-workbook.ts`, `core/orchestrator.ts` | new dep (MIT) | S | P1 | 06 |
| INV-5 | Scan reconciliation for column O (cross-ref VDR/Inspector) | A | `providers/aws/vdr-scan.ts` ↔ inventory | own code | M | P1 | 06 |
| OSC-1 | Validate emitted OSCAL JSON against NIST schema via `ajv` | C | `core/oscal.ts`, `core/schema.ts` | own code + NIST schema | S | **P0** | 11,07 |
| OSC-2 | Offline NIST-schema cache (commit schemas, no runtime net) | C | `scripts/extract-oscal-schemas.mjs` (new) + `docs/` | borrow pattern (11) | S | P1 | 11 |
| OSC-3 | Optional OSCAL XML output via NIST XSLT (only if needed) | C | shell-out / `oscalkit` | CC0 / NIST artifacts | M | P2 | 07 |
| SSP-1 | OSCAL **SSP** emitter: baseline controls → implemented-requirements, filled from tracker data | B | `core/oscal-ssp.ts` (new) + tracker export | port recipe (10, Apache) | L | P1 | 10 |
| SSP-2 | Render OSCAL SSP → FedRAMP Word (shell out to GoComply/fedramp, or port template-fill) | B | new renderer / container call | CC0 (09) + GSA templates | L | P2 | 09,01 |
| AWS-CHK | 11 new AWS checks (CMK-per-service, Security Hub standards, Network Firewall, IMDSv2, …) | D | `providers/aws/{crypto,data,network,config,logging}.ts` | clean-room (HCL idea) | M (batched) | P1 | 02 |
| GCP-CHK | 14 new GCP checks (Assured Workloads, Org Policy baseline, VPC-SC, CMEK parity, SCC) | D | `providers/gcp/{config,network,crypto,logging,iam}.ts` | clean-room (HCL idea) | M (batched) | P1 | 04 |
| AZ-1 | Azure collector scaffolding (auth + read-only guardrail) | E | `providers/azure/`, `core/auth/azure.ts` (new) | own code | M | P2 | 03 |
| AZ-2 | Azure per-domain collectors (iam/network/logging/crypto/config/data/backup/inventory) | E | `providers/azure/*.ts` | own code (spec from 03) | L | P2 | 03 |
| SCN-1 | Significant Change Notification classifier (IaC git-diff → 4-tier triage + timelines) | F | `core/scn-classify.ts` (new), pairs with diff-report | clean-room (AGPL — no copy) | M | P2 | 08 |

### Suggested first sprint (max value, low risk, mostly code we can own)
1. **OSC-1** — validate our OSCAL with `ajv` (S, P0): cheap credibility win, hardens an existing feature.
2. **INV-1 → INV-4** — the inventory workbook for AWS+GCP (P0): the highest-ROI new capability and a direct user ask; ~16/25 columns already auto-fill.
3. **AWS-CHK / GCP-CHK** (P1): batch the Coalfire-derived checks into the existing collectors — incremental, high signal, no new architecture.

Then tackle **SSP-1** (OSCAL SSP emitter) as the foundation for the SSP pipeline,
with **SSP-2** (Word render) and the **Azure collector** (AZ-1/2) and **SCN-1** as
larger follow-on bets.

---

## Cross-cutting notes for implementers

- **Reuse, don't re-collect.** Themes A and B are mostly *re-projections* of data
  FedPy already gathers (inventory evidence; tracker per-control status; baseline
  membership). Wire to existing collectors/the tracker DB before adding API calls.
- **Honor the offline-first invariant.** Anything that needs NIST schemas/catalogs
  (OSC-1/2, SSP-1) should follow the existing pattern: a `scripts/extract-*.mjs`
  that commits generated data so the runtime never needs network.
- **License hygiene.** Keep `NOTICE` updated. GPL/AGPL sources (05, 08) are
  reference specs only — implement clean-room and say so in commit messages.
- **OSCAL version is the recurring risk.** We emit 1.1; the tools target a mix
  (oscalkit ~nightly, GoComply/fedramp milestone3, content-gen 1.1.2). Pin and
  verify the version at every OSCAL boundary.
- **Read-only guardrail must extend to any new cloud** (Azure) and any new AWS/GCP
  service client added for the inventory mappers — every new SDK client goes
  through `wrapAwsClient` / the GCP Proxy.

---

## Implementation status

| Backlog ID | Status | Notes |
|---|---|---|
| (licensing) | ✅ locked | Path A — Apache-2.0 stays; GPL/AGPL sources spec-only |
| INV-1..4 | ✅ done | `core/inventory-workbook.ts` + AWS/GCP asset enumerators + dependency-free xlsx/CSV + `--inventory-workbook` |
| INV-5 (enrich) | ✅ done | tag enrichment + scan reconciliation + KSI-finding cross-link + DynamoDB/ECR/EKS/CloudFront (19 tests) |
| INV-6..21 | ✅ done | org-grade completeness ([`12-inventory-completeness.md`](12-inventory-completeness.md)): generic discovery backbone (AWS Config AQ/Resource Explorer/Tagging; GCP `searchAllResources`), rich `inventory.json` + graph, multi-region sweep, depth enrichers (network exposure, S3 public/KMS, SSM OS), EOL, tag-governance, scan reconciliation, KSI cross-link, data classification (tags + Macie), cost summary, change diff, OSCAL + CMDB emitters, `--inventory-only`, tracker surfacing |
| OSC-1 | ⏳ next | validate emitted OSCAL with `ajv` |
| AWS-CHK / GCP-CHK | ⏳ backlog | batch Coalfire-derived checks into existing collectors |
| SSP-1 / SSP-2 | ⏳ backlog | OSCAL SSP emitter → Word render |
| AZ-1 / AZ-2 | ⏳ backlog | net-new Azure collector |
| SCN-1 | ⏳ backlog | significant-change-notification classifier |
