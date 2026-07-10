# 07 — Stage 2 Re-Audit Gap Analysis & Remediation Plan

> Synthesis of four parallel audits of the Stage 2 scope engine (reachability
> correctness vs AWS VPC semantics; IAM-graph correctness vs AWS IAM semantics;
> PCI/QSA alignment of classification + segmentation; and code-quality / infra-reuse
> / efficiency / determinism). **No code changed yet** — this awaits your review.

## Headline conclusions

1. **One semantic-inversion bug is the headline:** the IAM graph merges `NotAction`
   into the granted-action list (`iamgraph.py:174`). `NotAction` means "all actions
   *except* these" — the opposite. This produces **both** false positives (reports
   denied access as granted) and false negatives (misses near-admin grants), in a
   QSA deliverable. Must fix.
2. **The gap-fetch does not reuse Stage 1 infrastructure** — the central prompt
   requirement. It hand-rolls raw boto3 paginators (no token bucket, no
   throttle gate, no error capture), duplicates `auth.py`, runs serially, and
   **supports only the ambient account** (no assume-role) — so multi-account
   inventories get zero live NACL/route data and silently degrade to CANDIDATE.
3. **Reachability is single-hop only.** The docstring claims multi-hop is "represented
   by transitive single-hop edges," but they are never composed. A bastion-fronted
   host (the canonical connected-to case) is silently missed — a false negative
   that matters to a QSA.
4. **Non-EC2 seeds don't resolve to endpoints.** `ENICollector` only sets `attached_to`
   for `InstanceId` attachments, so an RDS/ELB/Lambda CDE *seed* resolves to zero
   endpoints and gets no network paths. Major false negative for the common case
   where the seed is a database.
5. **Several confidence/category overclaims** a QSA will push back on: out-of-scope-by-
   absence labeled `DETERMINED`; every KMS key/trail flagged security-impacting
   regardless of CDE linkage; single category collapses connected-to + security-impacting.
6. **NACL evaluation has a silent-allow bug** on empty peer IP, ignores IPv6, and uses
   only the first private IP.
7. **Determinism is fragile** — path ids and finding order rest on set-iteration luck.
8. **Read-only: PASS.** Only `DescribeNetworkAcls`/`DescribeRouteTables`/`GetCallerIdentity`.

---

## A. CORRECTNESS — Reachability engine

### Critical
- **A-C1 — NACL empty-peer-IP silent match** (`reachability.py` `_nacl_allows`/`_nacl_ok`). When an endpoint has no private IP, `peer_ip=""` and the CIDR test is skipped → the first proto/port-overlapping rule decides regardless of address (false allow *or* deny). **Fix:** fail-closed / note when no IP; evaluate over all private IPs, not `[0]`.
- **A-C2 — IPv6 never evaluated.** Only the first (IPv4) private IP is used; IPv6 NACL/SG rules are silently dropped → IPv6 CDE paths invisible. **Fix:** evaluate per address-family with representative v4 + v6 addresses.
- **A-C3 — Port never validated.** `_sg_ingress_match` returns the first source-matching ingress rule "(any port)"; the recorded port is whichever rule won iteration, not a service port. **Fix:** iterate all source-admitting rules, record the union of (proto,port); document "any-port reachability" semantics if intended.

### High
- **A-H1 — First-match shadowing.** Because only the first ingress rule is returned, egress/NACL are tested only against that rule; a second rule (different port) that *would* pass is missed → false negative. **Fix:** try all source-admitting ingress rules.
- **A-H2 — TGW not actually modeled; peering same-target not enforced.** `_route_ok` checks *a* route on each side but not that both use the *same* pcx/tgw, and never fetches TGW route tables/associations. False positive across TGW; can mask/forge segmentation. **Fix:** match src+dst to the same target id; for TGW fetch route tables or explicitly lower confidence + note.
- **A-H3 — Egress ignores destination public IPs; SG-ref across peering over-trusted.** `_egress_ok` only checks `dst.private_ips` (false negative) and accepts SG-refs across VPCs unconditionally (minor false positive). **Fix:** include `dst.public_ips`; gate SG-ref on same-VPC/same-region-peering.
- **A-H4 — Multi-hop missed** (`expand_from_seeds`, single-hop only; docstring overstates). **Fix:** compute transitive closure (BFS over edges) from seeds and record composed paths, or document the limitation and lower confidence.
- **A-H5 — Non-EC2 seeds resolve to no endpoints** (`ENICollector.attached_to` only for instances; `endpoints_for_resource` keys by owner arn). RDS/ELB/Lambda seeds find nothing. **Fix:** in Stage 1 ENI collector set owner from `InterfaceType`/`RequesterId`/description (RDS/ELB/Lambda/VPC-endpoint ENIs), and/or have service collectors emit explicit `enis` relationships; Stage 2 resolves via those.

### Medium
- **A-M1 — Prefix-list routes ignored** in `_route_ok` (false negative for centralized routing). Resolve/flag.
- **A-M2 — Ephemeral range 1024–65535 is the permissive choice; ICMP has no ports.** Leans false-positive on the return leg. Consider conservative subset; skip port logic for ICMP.
- **A-M3 — main-RT fallback can be wrong** (`gapfetch.route_table_for_subnet`) when a subnet's explicit RT wasn't captured → may use a more-permissive main RT. **Fix:** only fall back when subnet truly has no explicit association.
- **A-M4 — same-VPC always "local" even when live RTs show otherwise** (rare). Optionally verify local route covers dst CIDR when `net.fetched`.
- **A-M5 — egress union across SGs** is masked when one SG has rules and another doesn't. AWS allows if *any* SG permits. **Fix:** evaluate each SG's default-allow independently.

(Confirmed correct: same-VPC implicit local route; blackhole exclusion; default-egress-allow assumption.)

---

## B. CORRECTNESS — IAM graph

### Critical
- **B-C1 — `NotAction` treated as granted Action** (`iamgraph.py:174`). Semantic inversion → false pos + false neg. **Fix:** never merge `NotAction` into actions; treat an `Allow`+`NotAction` statement covering a CDE resource as granting every sensitive action *not* listed (CANDIDATE), and flag `all-actions` unless the sensitive action is in the `NotAction` set.

### High
- **B-H1 — `NotResource` ignored** → statements with `NotResource` (empty `Resource`) are skipped; a near-universal grant including the CDE is dropped (false negative). **Fix:** if a statement has `NotResource` not covering the CDE arn, treat CDE as covered (CANDIDATE).
- **B-H2 — No wildcard/verb-glob action matching** (`s3:Get*`, `ec2:*`, `kms:De*`). Only exact dict keys + `service:*`-that-is-a-key + `*`. The most common real grant forms slip through (false negative). **Fix:** glob-match the action against sensitive keys; treat any `<service>:*` / `<service>:<verb>*` matching a sensitive service as that capability.
- **B-H3 — `_SENSITIVE_ACTIONS` missing high-value actions:** `kms:GenerateDataKey*`, `kms:CreateGrant`, `kms:ReEncrypt*`, `sts:AssumeRole`, `iam:PassRole`, `s3:GetObjectVersion`, `s3:ListBucket`, `ec2:RunInstances`, `lambda:UpdateFunctionCode`, `dynamodb:GetItem/Query/Scan`, `ecs:ExecuteCommand`, `ssm:GetParameter(s)`, `rds:CreateDBSnapshot`. **Fix:** expand the dict (+ B-H2 catches many transitively).
- **B-H4 — Resource-policy `Condition` on `"*"` principal ignored** (inconsistent with `utils.analyze_resource_policy`). Org-scoped policy reported as open `*`. **Fix:** carry `conditioned` into the finding.

### Medium
- **B-M1 — `_unresolved` managed policy skipped silently** → if a principal's only CDE access is via an uncaptured policy, zero findings + no caveat. **Fix:** emit an `UNDETERMINED` finding/caveat listing principals with unresolved policies.
- **B-M2 — `_apply_always_security_impacting` over-broad** (`classifier.py`): every KMS key/trail/detector flagged `DETERMINED` security-impacting regardless of CDE linkage. Account-scoped services (CloudTrail org trail, Config, GuardDuty, Security Hub) genuinely observe the CDE → keep; **per-resource** (KMS keys, R53 zones, VPN/DX/firewalls) should be security-impacting only when linked to a CDE resource, else CANDIDATE. **Fix:** split the set; tie per-resource items to CDE linkage.
- **B-M3 — `"*"`/`:root` trust assumer silently skipped** in `_follow_assume_chain` → a CDE role anyone can assume produces no finding (the most important finding!). **Fix:** emit a CANDIDATE finding for `*`/root trust.
- **B-M4 — S3 bucket-vs-object ARN asymmetry** (`_resource_matches`): seed = bucket ARN, grant on `bucket/*` doesn't match (false negative); `bucket*` over-broad (false positive). **Fix:** normalize bucket↔`bucket/*` equivalence.
- **B-M5 — Principal shapes:** bare-string non-`*` and `CanonicalUser` handled loosely. Add `else: _as_list(principal)`; label canonical-user distinctly.

(Confirmed correct: Deny never misread as grant; `*` action → finding; case-insensitive actions; assume-chain direction + fixpoint termination.)

---

## C. PCI / QSA ALIGNMENT

- **C-1 (High) — Segmentation check too narrow.** Only human-declared `out` resources, network-only, and conflates inbound (`to-cde`) with outbound (`from-cde`). The supplement's core question is "can anything out-of-scope reach *into* the CDE?" **Fix:** inverse-check **all** out-of-scope resources (declared + tool-derived); add an IAM-path arm; rank inbound contradictions first; separate outbound observations.
- **C-2 (High) — Single-category collapse** loses audit info; rank demotes security-impacting (3) under connected-to (4). **Fix:** carry multiple categories (or a "secondary categories" workbook column) so both surface.
- **C-3 (High) — Out-of-scope-by-absence = DETERMINED** overclaims (absence of evidence asserted as firmly as proof; still DETERMINED even when artifact is lossy). **Fix:** distinct label/lower confidence (e.g. `ISOLATION-SUPPORTED`), and downgrade when `net.fetched is False`.
- **C-4 (Med-High) — Single-hop path = DETERMINED with assumed egress/NACL legs.** **Fix:** lower to CANDIDATE per assumed leg (missing egress rules, missing NACL for a subnet), qualify the basis string; keep "connectivity proven, not CHD-flow" per-path.
- **C-5 (Med) — Missing seed types:** no `cde_accounts`, no `data_flows`; `data-classification=none` ignored (doesn't suppress the data-store heuristic). **Fix:** add account seeds + optional data-flow declaration; honor `none`.
- **C-6 (Low) — CIDR seed labeling inconsistent:** `cde_cidrs` used for endpoint expansion but not in `_apply_seeds`/`_cde_arn_set`. **Fix:** include CIDR matching there.
- **C-7 (Low) — Missing caveat** that segmentation findings cover declared-out + network only; the green "no contradictions" cell over-reassures. **Fix:** add caveat; neutralize the green.

(Confirmed strong: no-seed mode is correct + loud; the four mandated caveats are present and prominent; proof artifacts (path+port+SG rule+NACL note) are shown.)

---

## D. CODE QUALITY / INFRA-REUSE / EFFICIENCY / DETERMINISM

### Infra reuse (the central prompt requirement — largely unmet)
- **D-I1 (High) — gap-fetch uses raw boto3 paginators**, no `CallContext`/`TokenBucket`/`ServiceThrottleGate`/`ErrorCollector`. **Fix:** route `describe_network_acls`/`describe_route_tables` through `CallContext.paginate`; errors into the structured report.
- **D-I2 (Med) — gap-fetch is serial** per (account×region). **Fix:** use `run_work_units` with bounded workers.
- **D-I3 (High) — `_session_factory` duplicates `auth.py`** (hard-coded retries, `alias=""`). **Fix:** call `create_default_session`/`resolve_sessions`.
- **D-I4 (High) — no multi-account/assume-role gap-fetch** (ambient account only). **Fix:** accept a config and build `{account_id: AccountSession}` via `resolve_sessions`.
- **D-I5 (Med) — no `AppConfig`/`load_config`** in Stage 2 → concurrency tuning/org targets never reach the fetch. **Fix:** load the same config.

### Correctness/robustness
- **D-E2 (High) — `InventoryIndex.by_id` first-wins** with the promised region-qualified index never built → `get()` can return a wrong-region resource for native-id/name seeds. **Fix:** prefer ARN; resolve native-id seeds to ARNs up front; build a multimap and flag ambiguous ids instead of silent first-wins.
- **D-S1 (High) — `_FLAG_IDS` module-level global** mutated by `load_scope_config`, never cleared → stale state across runs, test pollution, thread-unsafety. **Fix:** carry `flag_ids` on `ScopeConfig`.
- **D-B1 (Med) — `schema_version` not validated** (re-running on an already-scoped file double-processes; non-JSON raises unguarded). **Fix:** validate major version; warn if `scope_schema_version` present or `resources` empty; friendly error on bad JSON.
- **D-B2 (Low) — `_parse_*` bracket access** on id keys → one bad entry aborts a region's fetch. **Fix:** `.get` + skip.
- **D-B3 (Med) — NACL uses only first private IP / empty-IP allow** (= A-C1). 
- **D-B5 (Low) — zero-ENI artifact** degrades sanely (IAM still runs); add a note when seeds resolve to zero endpoints.
- **D-B7 (Low) — egress union across SGs** (= A-M5).

### Efficiency
- **D-E1 (High) — `expand_from_seeds` O(seeds×endpoints)**, double edge eval, no memoization. **Fix:** memoize route by `(src.subnet,src.vpc,dst.vpc)`, SG-pair admittance by `(frozenset(src.sgs),frozenset(dst.sgs))`, NACL verdict by `(src.subnet,dst.subnet,proto,lo,hi)`; index dst endpoints by SG.
- **D-E3 (Med) — segmentation `next(... for p in paths)` per finding** → build `{path_id: path}` once.
- **D-E4 (Med) — `_follow_assume_chain` full dict scan per frontier element** → use `assumable_by.get(target)`.

### Determinism (fragile — rests on set-iteration luck)
- **D-D1 (Med) — account iteration order unsorted** in gap-fetch. `sorted(by_account)`.
- **D-D2/D3 (Med) — path ids depend on set-driven seed/endpoint order.** **Fix:** assign `path_id` *after* sorting paths by a stable key; iterate `sorted(resolver.cde_arns)`.
- **D-D4/D5 (Low) — finding lists in build order** (set `.pop()`). **Fix:** sort all finding lists before serialization.

### Tests (happy-path-heavy)
- **T1 (High) — NACL deny path never exercised** (all tests use allow-all NACLs).
- **T2 (High) — cross-VPC routing never tested** (all endpoints in one VPC).
- **T3–T10 (Med/Low) — artifact-fallback, gap-fetch + `_parse_*`, session factory, resource-policy IAM findings, network seeds, determinism, `_FLAG_IDS` pollution, multi-region duplicate id.**

---

## Recommended execution order

**Phase S1 — Correctness (highest QSA impact, no infra change):**
B-C1 (NotAction), A-C1 (NACL empty-IP), B-H2/B-H3 (action wildcards + missing actions), A-H5 (non-EC2 seed endpoints), A-H4 (multi-hop closure), B-M3 (`*` trust finding), D-E2 (by_id wrong-region), D-S1 (`_FLAG_IDS`).

**Phase S2 — PCI/QSA semantics:**
C-2 (multi-category), C-3 (out-of-scope confidence), C-1 (segmentation scope incl. IAM + all out-of-scope + direction), C-4 (per-leg path confidence), B-M2 (KMS/infra CDE-linkage), B-H1/B-H4 (NotResource, conditioned resource policy).

**Phase S3 — Infra reuse + efficiency + robustness:**
D-I1/I3/I4 (CallContext + auth reuse + assume-role gap-fetch), D-E1 (memoization), A-H2 (TGW same-target), A-H3/A-M* (egress public IP, prefix lists, main-RT fallback), D-B1 (schema validation), determinism D-D*.

**Phase S4 — Tests + docs:**
NACL-deny + cross-VPC + fallback + IAM-resource-policy + determinism tests; update research/06 + docs + caveats; re-run ruff/mypy/pytest.

---

## Open questions for you (before building)

1. **Scope of this pass** — all of S1–S4, or land S1+S2 (correctness + QSA semantics) first and treat S3 infra/efficiency + S4 as a follow-on? S1+S2 fixes everything that produces *wrong answers*; S3 is throughput/robustness.
2. **Multi-hop reachability (A-H4)** — implement full transitive closure (bastion→CDE chains; more compute, more QSA-complete) or keep single-hop but fix the docstring + lower confidence and clearly label the limit?
3. **Multi-category (C-2)** — change the model to carry a *set* of categories (cleaner, but changes the scoped-JSON shape Stage 3 consumes — still additive), or keep single primary category + add a "secondary categories" column/field?
4. **Non-EC2 seed endpoints (A-H5)** — fix in Stage 1 `ENICollector` (re-run needed) or resolve in Stage 2 from service-resource relationships / ENI descriptions? Affects whether Stage 1 must re-run.
5. **Out-of-scope confidence (C-3)** — introduce a new `ISOLATION-SUPPORTED` confidence value, or reuse `CANDIDATE`/down-rank? New value changes the contract slightly.
