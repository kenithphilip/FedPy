# 06 — PCI DSS v4.0.1 Scope & Segmentation (Stage 2 research)

> **Filename note:** the prompt asked for `research/05-scope-and-segmentation.md`, but `research/05`
> is already the Stage-1 re-audit gap analysis. To avoid clobbering it this is `06`.
>
> **Re-audit addendum (see `research/07-stage2-reaudit-gap-analysis.md`).** A four-part re-audit
> hardened the engine; the behaviours below reflect the corrected implementation:
> - **IAM:** `NotAction`/`NotResource` are evaluated with correct (negated) semantics; action
>   matching is wildcard/verb-glob aware (`s3:Get*`, `ec2:*`); the sensitive-action set is broad
>   (incl. `kms:GenerateDataKey*`, `iam:PassRole`, `sts:AssumeRole`); roles trusting `*`/`:root`
>   and `*`-principals scoped by a `Condition` are flagged distinctly; unresolved managed policies
>   are surfaced as a caveat. IAM remains a static over-approximation (no SCP/boundary/condition/Deny resolution).
> - **Reachability:** multi-hop chains are composed via transitive closure (bastion→CDE is found);
>   non-EC2 seeds (RDS/ELB/Lambda) resolve to their service-managed ENIs; NACLs evaluate per
>   address-family over all IPs and **fail closed** when no IP is known; cross-VPC requires the
>   *same* pcx/tgw on both sides; egress considers destination public IPs and unions across SGs;
>   a path with an assumed leg (missing egress/NACL data) is CANDIDATE, not DETERMINED.
> - **Classification:** a resource carries the full *set* of applicable categories (primary +
>   secondary); out-of-scope-by-absence is CANDIDATE (UNDETERMINED when network data was lossy),
>   never DETERMINED.
> - **Segmentation:** the inverse check covers **all** out-of-scope resources (declared + tool-derived)
>   across **network and IAM** relationships, with inbound (out-of-scope→CDE) contradictions ranked first.
> - **Infra:** the read-only NACL/route gap-fetch reuses Stage 1's rate-limited, error-capturing
>   `CallContext` + bounded thread pool, and supports multi-account/assume-role. Output is
>   deterministic (path ids + findings sorted before assignment).
>
> **Sources:** PCI DSS v4.0.1 standard + testing procedures, PCI SSC *Information Supplement:
> Guidance for PCI DSS Scoping and Network Segmentation*, the PCI SSC Glossary, AWS networking
> docs, boto3. Standard text is paraphrased — no large copyrighted passages. `[ASSUMPTION]` marks
> anything not verifiable from an authoritative source here.

---

## 0. The premise this stage must respect (and states in code + output)

**PCI scope is driven by where cardholder data (CHD) / sensitive authentication data (SAD) is
stored, processed, or transmitted.** That is a property of *application behaviour and data
content* — it **cannot** be derived from configuration metadata. A subnet's routes don't tell you
whether PAN flows through it; an encrypted bucket may or may not hold CHD.

Therefore this tool **does not originate scope**. Scope originates from **human-declared seeds**
(the resources/networks a person attests store/process/transmit CHD). The tool's job is to:

1. **Expand** from seeds correctly and completely (connected-to + security-impacting).
2. **Prove** connectivity with the *actual* path (SG → subnet → route → peering/TGW + port), not a verdict alone.
3. **Flag** everything warranting review (heuristics), labelled candidate — never asserted.
4. **Validate segmentation** — the inverse check: for anything claimed out-of-scope, search for a path back to the CDE.

**Hard rules, repeated in output caveats:**
- Without seeds, the tool may only **FLAG candidates**, never assert in-scope. This is stated loudly.
- **Isolation evidence ≠ proof of absence of CHD.** "No path to the CDE" proves isolation, not that the resource is CHD-free.
- The tool **assists and proves connectivity; the human + QSA make the final scope determination.**

---

## 1. PCI DSS v4.0.1 scoping definitions (paraphrased)

### 1.1 CDE — Cardholder Data Environment
The people, processes, and technologies that **store, process, or transmit** CHD or SAD — **plus**
system components directly connected to, or that could impact the security of, that environment.

### 1.2 The three scope categories the standard recognises
- **CDE systems** — store/process/transmit CHD/SAD (the seeds, plus anything that itself handles CHD).
- **Connected-to systems** — have connectivity to the CDE (network path), even if they don't
  handle CHD themselves. Examples: jump/bastion hosts, shared services (DNS, NTP, AD, patching),
  monitoring/log collectors, admin workstations.
- **Security-impacting systems** — could affect the security of the CDE **without** a data path.
  Examples: identity providers, the segmentation controllers themselves (firewalls/SGs/NACLs/route
  tables), CI/CD that deploys into the CDE, KMS/secrets stores the CDE depends on, logging &
  monitoring the CDE relies on (Req 10/11 systems).

**Everything is in scope until segmentation/analysis proves otherwise.** Out-of-scope is a
*conclusion that must be justified*, not a default.

### 1.3 Scope confirmation cadence (12.5.2 / 12.5.2.1)
Scope is documented and confirmed ≥ every 12 months (service providers ≥ every 6 months) and on
significant change. Stage 2's output is *substrate* for that confirmation — it does not replace the human attestation.

---

## 2. Segmentation — what it is and what counts as adequate evidence

### 2.1 What segmentation is (paraphrased)
Segmentation isolates the CDE from out-of-scope systems so that, were the out-of-scope system
compromised, the CDE could not be reached. Segmentation is achieved by controls that **prevent
connectivity** — in AWS: security groups, network ACLs, route-table design, separate VPCs/subnets,
absent or restricted peering/TGW routes, no shared NSCs.

If segmentation is used to reduce scope, its **effectiveness must be validated** (and, per Req
11.4.x, penetration-tested — ≥ every 12 months, service providers ≥ every 6 months, and on
change). The pen test is out of band; the tool provides the *configuration* evidence that
underpins it.

### 2.2 What a QSA expects to see for scope + segmentation
- A current, complete **system-component inventory** (Stage 1) with each component's scope category.
- **Data-flow diagrams** and **network diagrams** showing CDE boundaries and all connection points.
- For each connected-to / in-scope determination: **why** — the connection or dependency that put it in scope.
- For each segmentation/isolation claim: **evidence the control prevents the path** — the absence
  of an SG rule / route / NACL allowance that would otherwise connect it, ideally as a tested,
  reproducible analysis.
- Evidence that segmentation was **validated** (config analysis + pen test).

### 2.3 What this tool produces toward that
- **Scope Classification** per resource: category + basis + confidence.
- **Reachability Paths**: for every connected-to candidate, the concrete permitted path and port.
- **Segmentation Findings**: anything believed isolated that is in fact reachable (a finding), plus
  confirmed isolation (supports the claim, doesn't prove no-CHD).
- **IAM-to-CDE Access**: principals able to act on CDE resources + the assume-role chain.

---

## 3. What a "permitted network path" is in AWS — the layering rule

> **A path from A to B exists ONLY where the route tables AND the security groups AND the network
> ACLs ALL permit it. Any single layer denying breaks the path.**

An SG that allows 443 is meaningless without a route to the destination; a route is meaningless if
the NACL denies the return traffic. The engine must layer **all three** before asserting an edge.

### 3.1 The three layers and how each is evaluated

| Layer | Granularity | Stateful? | Evaluation for an edge A→B on proto/port P |
|-------|-------------|-----------|---------------------------------------------|
| **Route table** | per-subnet (or VPC main) | n/a | A's subnet route table must have a route whose destination CIDR/prefix-list covers B's IP, with an *active* target (local / igw / nat / pcx / tgw / eni). For cross-VPC, both sides' route tables must route to each other via the same pcx/tgw. |
| **Security group** | per-ENI (stateful) | **Yes** | B's SG must have an **ingress** rule permitting P from A's source (A's SG id, A's IP, or a CIDR covering A). Because SGs are stateful, the return traffic is automatically allowed — only the *initiating* direction's ingress on the destination is required (plus A's egress, which defaults to allow-all). |
| **NACL** | per-subnet (stateless) | **No** | Both the **outbound** NACL on A's subnet (to B:P) and the **inbound** NACL on B's subnet (from A:P) must allow, **and** the return traffic must be allowed by ephemeral-port rules in the reverse direction on both subnets (because NACLs are stateless). Numbered rules are evaluated low→high; first match wins; default deny at the end. |

### 3.2 Direction & statefulness — precise semantics the engine encodes
- **SG (stateful):** to assert A can *initiate* to B:P, require B-ingress allow(P, from A) ∧ A-egress allow(P, to B). Return path is implicit. Default SG egress is allow-all unless replaced.
- **NACL (stateless):** require A-subnet egress allow(P→B) ∧ B-subnet ingress allow(P from A) ∧ B-subnet egress allow(ephemeral→A) ∧ A-subnet ingress allow(ephemeral from B). The ephemeral range is `1024-65535` (`[ASSUMPTION]` — Linux default; the engine treats `32768-65535` as the conservative subset and notes platform variance).
- **Same-subnet traffic** is **not** filtered by NACLs (NACLs apply at subnet boundaries) — only SGs apply. The engine models this: A→B in the same subnet needs SG only.
- **Same security group** does *not* implicitly allow intra-SG traffic unless a self-referencing rule exists. The engine does not assume it.

### 3.3 Cross-VPC / hybrid topology
- **VPC peering:** non-transitive. A→C through B's peering is not permitted unless A↔C peer directly. Both VPCs need routes to each other's CIDR via the pcx, and SG/NACL must permit. SG references across peered VPCs work only in the same region with referencing enabled.
- **Transit Gateway:** routing depends on TGW route tables + attachment associations/propagations. The engine models VPC→TGW-attachment→TGW→other-attachment→VPC, requiring the VPC route tables to point the destination CIDR at the TGW.
- **IGW / NAT:** an IGW route + a public IP makes a subnet internet-reachable (ingress) / internet-capable (egress). NAT gives egress-only.
- **VPC endpoints (PrivateLink / gateway):** provide a path to an AWS service without internet; relevant when a CDE resource reaches S3/KMS/etc. privately.
- **Direct Connect / VPN:** a path to on-prem; on-prem hosts aren't enumerable, so these are recorded as boundary edges with an external-coverage caveat.

### 3.4 Reachability gaps in the Stage-1 artifact (what Stage 2 must re-fetch)
The Stage-1 `inventory.json` captures SG rules as parseable strings and route targets as a list,
but two pieces are lossy for precise path-proof and will be **re-fetched read-only** when needed:
- **NACL entries** are stored only as a truncated free-text note (first 30). The engine re-fetches
  `ec2:DescribeNetworkAcls` to layer NACLs precisely.
- **Route destination CIDRs** are truncated to 20 in a note (the target list is complete but the
  dest-CIDR↔target association is lossy). The engine re-fetches `ec2:DescribeRouteTables` for exact
  dest→target mapping.
These are the *only* gap-fetches; everything else is read from the artifact. Read-only is preserved.

---

## 4. IAM / relationship graph — security-impacting without a data path (Layer 2)

A principal that can **act on a CDE resource** is security-impacting even with no network path.
The graph resolves, from the IAM data Stage 1 captured (`iam_policy_data`: attached managed +
inline policy documents, role trust policies, resource-based policies):

1. **Principal → permitted actions → resource ARNs.** Evaluate each policy statement's
   `Effect/Action/Resource` (with wildcard expansion) and intersect the resource set with the seed
   set + CDE-derived resources.
2. **Flag security-impacting** when a principal can, on a CDE resource: read/write a CDE bucket
   (`s3:GetObject`/`PutObject`), modify a CDE SG/NACL/route (`ec2:Authorize*`/`*NetworkAcl*`/`*Route*`),
   `kms:Decrypt`/`Encrypt` with the CDE key, `ssm:StartSession`/`SendCommand` onto a CDE instance,
   `rds:*`/`rds-db:connect` on the CDE database, etc.
3. **Resource-based policies** (bucket/key/secret/queue/topic policies) that grant a principal
   access to a CDE resource pull that principal into scope.
4. **Follow the assume chain:** whatever can `sts:AssumeRole` a flagged role is itself
   security-impacting; iterate to a fixpoint.
5. **Always-security-impacting infrastructure** regardless of explicit grants: KMS keys encrypting
   CDE data; CloudTrail/Config/GuardDuty/Security Hub/CloudWatch observing/managing the CDE (Req
   10/11); Route 53 private zones serving the CDE VPC; access paths terminating in the CDE
   (bastions, SSM, VPN, DX).

**Honesty limit:** IAM policy evaluation here is a *static over-approximation* — it does not
evaluate every condition key, SCP intersection, permission-boundary subtraction, or session policy.
It flags **candidate** security-impacting access for human review and records the granting
statement; it does not assert effective access as fact. (Full SCP/boundary intersection is noted as a known simplification.)

---

## 5. Classification, basis, and confidence (the output contract)

Every resource gets exactly one **category**, a **basis**, and a **confidence**.

| Category | Meaning |
|----------|---------|
| `CDE` | A seed, or itself stores/processes/transmits CHD (human-declared). |
| `connected-to` | Has a proven permitted network path to/from a CDE seed. |
| `security-impacting` | Can act on / observe / manage the CDE via IAM or is segmentation/Req-10/11 infrastructure. |
| `out-of-scope` | No path and no IAM/infra relationship found — **isolation supported, not CHD-absence proven**. |
| `undetermined` | Insufficient data to decide (missing graph inputs, unresolved policy, no seeds). |

| Confidence | When |
|------------|------|
| `DETERMINED` | Seed, or proven reachability path, or concrete IAM grant statement. |
| `CANDIDATE` | Heuristic signal only (exposure / co-location / name-tag). |
| `UNDETERMINED` | Inputs insufficient to classify. |

**Basis** is a structured string/record: `seed:config` \| `seed:tag(pci:cde=true)` \|
`reachable-from-seed:<path-id>` \| `iam-principal-with-cde-access:<statement-ref>` \|
`security-impacting-infra:<type>` \| `heuristic:<signal>` \| `no-path-found`.

**No-seed mode:** if zero seeds are supplied, *every* category collapses to `undetermined` or
`CANDIDATE` (heuristic) and the tool emits a loud banner that no in-scope assertion was made.

---

## 6. Seed mechanism + precedence (documented fully in `docs/scope-seed-and-tagging-convention.md`)

Three seed sources, with **precedence: explicit config > tags > CLI flags** (most authoritative
wins; an explicit config entry overrides a conflicting tag).
1. **Seeds config (YAML/JSON):** seed *resources* by ARN/ID and seed *networks* by VPC/subnet/CIDR.
2. **Tag convention:** `pci:cde=true` or `pci:scope=cde|connected|out`, and
   `data-classification=chd|sad|none`. Matching tags are treated as seeds.
3. **CLI flags:** `--seed-arn`, `--seed-vpc`, `--seed-subnet`, `--seed-cidr` for ad hoc additions.

`pci:scope=out` is an explicit human *out-of-scope assertion* — it does not remove a resource from
analysis; it marks it for the **segmentation inverse check** (does a path back to the CDE exist
despite the claim?).

---

## 7. Segmentation validation (Layer 4) — the inverse check

For every resource that is asserted/expected **out-of-scope** (via `pci:scope=out`, the seeds
config out-list, or simply "not reached"), search the reachability graph for **any permitted path
to a CDE seed**:
- **No path** → isolation **supported** (recorded as evidence; still not proof of no CHD).
- **A path exists** → **FINDING**: something believed isolated is in fact reachable. Surfaced
  prominently with the exact offending path + port, because this is often the most audit-valuable output.

---

## 8. Key assumptions to confirm before building

1. **Filename:** `research/06-…` (05 is taken). ✅ assumed.
2. **Ephemeral port range** for stateless NACL return-traffic: model `1024-65535`, treat
   `32768-65535` as the conservative subset, note platform variance. `[ASSUMPTION]`
3. **IAM evaluation is a static over-approximation** (no SCP/boundary/condition-key resolution) —
   flags candidates, records the granting statement, never asserts effective access.
4. **Gap-fetch is allowed and read-only:** re-fetch NACL entries + full route tables when the
   artifact's truncated copies are insufficient. Nothing else is re-collected.
5. **No-seed behaviour:** flag-only, with a loud banner — never assert in-scope.
6. **Out-of-scope is a justified conclusion**, never a default; un-reached resources are
   `out-of-scope (isolation-supported)` only after the inverse check finds no path, else `undetermined`.
