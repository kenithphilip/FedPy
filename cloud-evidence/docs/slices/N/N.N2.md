---
slice_id: N.N2
title: Attack surface enumeration (boundary entry points + exposed services)
loop: N
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A2, LOOP-A.A3, INV-P1, INV-P2, INV-P3, INV-P4, INV-P5, INV-S1, INV-S2, INV-S3, INV-S4]
blocks: [N.N3, N.N4, F.F7, K.K1]
estimated_effort: 4-5 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# N.N2 — Attack surface enumeration (boundary entry points + exposed services)

## TL;DR
Aggregate `inventory.json` + the per-provider network collectors into a structured system-level attack-surface inventory. Emit `out/attack-surface.json` with seven `SurfaceCategory` buckets (internet-reachable-endpoint, authentication-boundary, administrative-interface, data-plane-egress, subprocessor-data-flow, partner-integration, physical-interface). Wire into AP `back-matter.resources[type=attack-surface]` and AR `observation.props["attack-surface-uuid"]`. Operator-supplied subprocessor + partner flows flow through the tracker UI. Consumed by SAR §3.4 (LOOP-F.F7), the PenTest RoE (LOOP-K.K1), and the LOOP-D.D1 boundary-diagram cross-check.

## Status
- Status: pending
- Commit: — (filled when shipped, per `docs/SLICE-COMPLETION-PROCEDURE.md`)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
FedPy is "read-only, evidence-grade automation". N.N2 is read-only against the cloud — every input is on-disk JSON from existing collectors (`providers/aws/network.ts`, `providers/gcp/network.ts`, `providers/azure/network.ts`) + the rich `inventory.json` already emitted by INV-P1..S4. No new cloud SDK calls. Output is signed (Ed25519 + RFC 3161). Each `EntryPoint` traces to a real `inventory.assets[].identifier` + the real network rule that exposed it (Security Group rule, firewall rule, NSG rule), so a 3PAO can demand the underlying SDK call. The OSCAL chain gains `back-matter.resources[type=attack-surface]` on the AP + per-entry-point `observation` rows on the AR.

## Why this slice exists
- FedRAMP SAR Template §3.4 requires the 3PAO to "summarize the attack surface examined during testing". Today no structured artifact aggregates the per-asset `public_facing` / `internet_reachable` booleans into a system-level catalog the SAR can quote. LOOP-F.F7 (SAR draft generator) needs this as input.
- NIST SP 800-115 §4 (Target Identification and Analysis Techniques) requires port discovery, service identification, vulnerability scanning. N.N2 produces the catalog those techniques operate on.
- NIST SP 800-154 Step 2 ("Identify and select the attack vectors to be included in the model") is implemented here, complementary to N.N1 Steps 1 + 3.
- FedRAMP Penetration Test Guidance v3.0 §3 RoE field set requires a documented test scope. LOOP-K.K1 PenTest ingest auto-derives scope from `out/attack-surface.json`.
- The LOOP-D.D1 boundary diagram is a visual rendering of the same catalog; N.N2 publishes the authoritative source.

## Authoritative sources (with verbatim quotes)
- **NIST SP 800-154 (Draft)** — Step 2: "Identify and select the attack vectors to be included in the model." N.N2 implements this step verbatim, vector taxonomy quoted in the module docstring.
- **NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment** — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf
  - §4.2 Network Discovery — port discovery procedure.
  - §4.3 Service Identification — service mapping by port/protocol.
  - §4.4 Vulnerability Scanning.
- **FedRAMP SAR Template §3.4 Attack Surface Analysis** — https://www.fedramp.gov/assets/resources/templates/SAR-FedRAMP-Security-Assessment-Report-Template.docx
  > "summarize the attack surface examined during testing."
- **FedRAMP Penetration Test Guidance v3.0** — https://www.fedramp.gov/assets/resources/documents/CSP_Penetration_Test_Guidance.pdf
  - §3 Rules of Engagement field set.
  - §5 Test Methodology.
- **OWASP Attack Surface Analysis Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html
  Six surface categories used as the top-level grouping (with two more — subprocessor + partner — added for SaaS context per FedRAMP supply-chain guidance).
- **OSCAL AR `observation`** v1.1.2 — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/ — extension point for attack-surface-uuid prop.
- **OSCAL AP `back-matter.resources`** v1.1.2 — accepts arbitrary `type` strings; we register `attack-surface` (docs/oscal/extensions.md).
- **AWS Security Group / NACL rule semantics** — https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html — 0.0.0.0/0 + allow → internet-reachable.
- **GCP firewall rule semantics** — https://cloud.google.com/vpc/docs/firewalls — `sourceRanges: ["0.0.0.0/0"]` + `allowed` → internet-reachable.
- **Azure NSG rule semantics** — https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview — `sourceAddressPrefix: "Internet"` or `0.0.0.0/0` + `Allow` → internet-reachable.

## Files to create (exact paths under cloud-evidence/)
- `cloud-evidence/core/attack-surface.ts` — pure builder.
- `cloud-evidence/core/attack-surface-emit.ts` — disk emitter.
- `cloud-evidence/tests/core/attack-surface.test.ts` — pure-builder tests.
- `cloud-evidence/tests/core/attack-surface-emit.test.ts` — emitter tests.
- `cloud-evidence/tests/fixtures/attack-surface/` — fixture inventory + per-provider network evidence.
- `tracker/server/routes/attack-surface.ts` — CRUD for operator-supplied annotations (subprocessor flows, partner integrations).
- `tracker/server/routes/attack-surface.test.ts`.
- `tracker/client/src/pages/AttackSurface.tsx` — UI for operator-supplied surfaces.
- `tracker/client/src/pages/AttackSurface.test.tsx`.

## Files to extend
- `cloud-evidence/core/oscal.ts` (AR builder) — append `observation` per `EntryPoint` with `props["attack-surface-category"]`, `props["attack-surface-protocol"]`, etc.
- `cloud-evidence/core/oscal-ap.ts` — append `back-matter.resources[type=attack-surface]` block.
- `cloud-evidence/core/orchestrator.ts` — `--attack-surface` flag (env `CLOUD_EVIDENCE_ATTACK_SURFACE`), runs AFTER N.N1 (so AR can reference both).
- `cloud-evidence/core/submission-bundle.ts` — add role `attack-surface-json` (filename `attack-surface.json`).
- `cloud-evidence/docs/oscal/extensions.md` — register `attack-surface` `type` token.
- `tracker/server/schema.sql` — additive table `attack_surface_inventory`.
- `tracker/server/index.ts` — mount `routes/attack-surface.ts`.
- `tracker/client/src/App.tsx` — add `/attack-surface` route.

## Schemas / standards
- **`SurfaceCategory`** enum: `internet-reachable-endpoint | authentication-boundary | administrative-interface | data-plane-egress | subprocessor-data-flow | partner-integration | physical-interface`.
- **`EntryPoint`** typed interface per `LOOP-N-SPEC.md §5 N.N2 build step 1`: `{ uuid, category, component_id, protocol, port?, fqdn?, ip_cidrs[], authentication, authorization, data_classes_in_transit[], mitigating_controls[], mitigating_ksis[], sources }`.
- **`authentication`** enum: `none | basic | mtls | oidc | iam | pre-shared-key | unknown`.
- **`authorization`** enum: `none | rbac | abac | allow-list | unknown`.
- **`data_classes_in_transit`** enum array: `public | internal | confidential | cui | pii`.
- **NIST 800-53 controls** referenced: SC-7 (boundary protection), SC-7(3) (access points), SC-7(4) (external telecom), SC-8 (transmission confidentiality), AC-3 (access enforcement), AC-17 (remote access), IA-2 (identification + authentication), IA-3 (device identification), IA-8 (non-organizational users).
- **OSCAL AR observation** v1.1.2 prop namespace `CE_NS`.

## Build steps (concrete, numbered)
1. Define typed interfaces in `core/attack-surface.ts` — `SurfaceCategory`, `EntryPoint`, `AttackSurfaceInventory`, `OperatorAttackSurfaceAnnotation` (per `LOOP-N-SPEC.md §5 N.N2 build step 1`).
2. Pure builder: `buildAttackSurface(inventory, networkEvidence, ksiMap, controlBenchmark, operatorAnnotations): AttackSurfaceInventory`. Algorithm:
   - For each `inventory.assets[]` with `public_facing === true` OR `internet_reachable === true`, emit an `internet-reachable-endpoint` row. Resolve `protocol/port` from inventory `listening_ports[]` enriched in INV-S2/S4, else from the matching network-rule evidence.
   - For each AWS Security Group / GCP firewall rule / Azure NSG rule with `source = 0.0.0.0/0` (or `::/0`) and `action = allow`, emit entry points per protocol/port. Attach `ip_cidrs: ['0.0.0.0/0']` + the rule UUID.
   - For each authentication-bearing surface (inventory tag `auth_boundary=true`, OR detected service: API Gateway authorizer present, GCP IAP enabled, ALB w/ Cognito authentication-action), emit `authentication-boundary` row.
   - For each admin-interface (SSH/22, RDP/3389, WinRM/5985-5986, kubectl/6443, management port via `inventory.tags.fedramp_admin_interface=true`), emit `administrative-interface` row.
   - Egress: skip NAT gateway / VPC endpoint / Private Service Connect / Azure Service Endpoint to non-Internet destinations; for Internet egress carrying sensitive `data_classes_in_transit`, emit `data-plane-egress`.
   - Operator annotations from tracker append `subprocessor-data-flow` and `partner-integration` rows (no cloud signal exists).
3. Disk emitter (`core/attack-surface-emit.ts`): signature in `LOOP-N-SPEC.md §5 N.N2 build step 3`. Reads inventory + per-provider network evidence + tracker snapshot; writes `out/attack-surface.json` with provenance block.
4. AR observation emission (extend `core/oscal.ts`): per `EntryPoint`, emit object per `LOOP-N-SPEC.md §5 N.N2 build step 4`. Props in `CE_NS`: `attack-surface-category`, `attack-surface-protocol`, `attack-surface-port` (when set), `attack-surface-authentication`, `attack-surface-authorization`, `data-class` (one per element), `mitigating-ksi`.
5. AP back-matter (extend `core/oscal-ap.ts`): emit one resource per signed artifact — `{ uuid: deterministicUuid('ap:back-matter:attack-surface'), title, description, props[{ name: 'type', ns: CE_NS, value: 'attack-surface' }], rlinks: [{ href: './attack-surface.json', media-type: 'application/json' }] }`.
6. Bundler integration: add role `attack-surface-json` to `submission-bundle.ts:WELL_KNOWN`.
7. Tracker `attack_surface_inventory` schema per `LOOP-N-SPEC.md §5 N.N2 build step 7`. `source` enum: `auto-derived | operator-supplied`. Ed25519 sign-off optional but required for `operator-supplied` rows.
8. Validation pass: every entry point with `ip_cidrs` containing `0.0.0.0/0` AND `authentication: 'none'` is flagged in `out/attack-surface.json#/diagnostics` as `internet-reachable-unauthenticated` (informational; not POA&M unless an upstream KSI check fails). Diagnostics block is observable, not buried.
9. `--strict-threat` orchestrator mode: counts entry points with `discovery: 'REQUIRES-OPERATOR-INPUT'` and exits non-zero if any exist after operator-config pull. (Reuses the same flag as N.N1.)
10. Signing + timestamping: `attack-surface.json` picked up by existing `core/sign.ts` glob.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

| Field | Source | Behaviour when missing |
|---|---|---|
| `data_classes_in_transit[]` | inventory tag `data_classification` is primary signal | absent → `data_class_source: 'REQUIRES-OPERATOR-INPUT'`; operator tags asset OR supplies via tracker |
| `subprocessor-data-flow` rows | tracker UI; no cloud signal | empty array until operator provides |
| `partner-integration` rows | tracker UI; no cloud signal | empty array until operator provides |
| `authentication` enum | auto-derived for known service types (API GW authorizer, GCP IAP, ALB Cognito action); else `unknown` | `unknown` → `discovery: 'REQUIRES-OPERATOR-INPUT'`; operator confirms via tracker |
| `authorization` enum | same as above | same |
| `physical-interface` rows | tracker UI (e.g. operator-supplied facility access) | empty until operator provides |

## Test specifications (≥12 tests)
1. `it('emits entry point per public_facing/internet_reachable inventory asset', ...)` — given two inventory assets with the flags set, expect two `internet-reachable-endpoint` rows.
2. `it('emits entry point per 0.0.0.0/0 security-group rule', ...)` — AWS SG with `allow tcp 443 0.0.0.0/0` produces a row with `ip_cidrs: ['0.0.0.0/0']`, `protocol: 'tcp'`, `port: 443`.
3. `it('aggregates IPv4 + IPv6 CIDRs', ...)` — both `0.0.0.0/0` and `::/0` rules collapse into a single row with both CIDRs.
4. `it('classifies API Gateway as authentication-boundary when authorizer present', ...)`.
5. `it('classifies SSH (port 22) / RDP (3389) / WinRM (5985) / kubectl (6443) as administrative-interface', ...)`.
6. `it('records data-class-in-transit from inventory tag', ...)` — asset tagged `data_classification: cui` → row carries `['cui']`.
7. `it('emits REQUIRES-OPERATOR-INPUT data_class_source when tag absent', ...)`.
8. `it('appends operator-supplied subprocessor-data-flow rows', ...)` — tracker snapshot row with `category: 'subprocessor-data-flow'` lands in the JSON.
9. `it('produces counts_by_category aggregates that sum to entry_points.length', ...)`.
10. `it('AR observation emits attack-surface-category + protocol + port + authentication props', ...)` — re-emit AR; find props by name.
11. `it('AP back-matter resource type=attack-surface present', ...)`.
12. `it('strict-threat fails when REQUIRES-OPERATOR-INPUT discovery rows exist', ...)`.
13. `it('diagnostics flag internet-reachable-unauthenticated rows', ...)` — 0.0.0.0/0 + auth:none → diagnostic.
14. `it('signs attack-surface.json with Ed25519 + includes in RFC 3161 manifest', ...)`.
15. `it('bundler includes attack-surface-json role', ...)`.
16. `it('GCP firewall rule with sourceRanges=0.0.0.0/0 produces entry point', ...)` — GCP-specific path.
17. `it('Azure NSG rule with sourceAddressPrefix=Internet produces entry point', ...)` — Azure-specific path.
18. `it('writes attack-surface.json with provenance.emitter + sourceCalls per provider', ...)` — `check:provenance` passes.

## REO compliance
- Every entry point traces to a real cloud SDK call (already done by upstream collectors `providers/{aws,gcp,azure}/network.ts`) or to operator-supplied annotation.
- No mocked SDK in production paths; network evidence is read from real on-disk JSON emitted by existing collectors.
- `mitigating_ksis` / `mitigating_controls` resolved through `ksi-map.ts` + `control-benchmark.ts`; unresolved cells surface as `REQUIRES-OPERATOR-INPUT`.
- Diagnostics block carries `internet-reachable-unauthenticated` rows observably; nothing buried.
- Provenance block populated: emitter name, emittedAt (ISO), sourceCalls (inventory path, per-provider network evidence paths, NIST 800-115 + 800-154 + FedRAMP SAR citation refs), signingKeyId.
- No `process.env.NODE_ENV === 'test'` branches anywhere.
- Operator-supplied rows carry Ed25519 sign-off real signatures.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/attack-surface.test.ts tests/core/attack-surface-emit.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd "../tracker"
npm run typecheck
npm test -- server/routes/attack-surface.test.ts client/src/pages/AttackSurface.test.tsx
```

## Known risks / issues
- **Risk 1: Operator annotation drift vs cloud reality.** Operator tags a subprocessor flow as `mtls` but the real flow is `oidc`. Mitigation: tracker row carries `signed_off_by_user_id` + Ed25519 signature; LOOP-K pen test exercises actual auth; mismatches surface in K results.
- **Risk 2: Network evidence file format drift between providers.** Each provider's `network.ts` emits a slightly different shape. Mitigation: per-provider adapter in the pure builder; tests pin shapes per provider; new provider additions require an adapter slice.
- **Risk 3: Operator may inadvertently expose a sensitive entry point via subprocessor-data-flow row.** Mitigation: diagnostics block flags any operator-supplied row with `authentication: 'none'` + `data_classes_in_transit` ⊇ {cui, pii}; emits warning.
- **Risk 4: 0.0.0.0/0 with `authentication: 'mtls'` flagged inaccurately.** mTLS via NLB doesn't fully appear in SG rules. Mitigation: cross-reference with NLB target-group attributes; if missing, mark `authentication: 'unknown'` + REQUIRES-OPERATOR-INPUT.
- **Risk 5: Bundler role count growth.** N.N2 adds `attack-surface-json`; N.N1 added two; N.N3 + N.N4 will add three more (cross-ref `N-X4`). Pin in `submission-bundle.test.ts`; CHANGELOG entry per slice cites running count.

## Open questions
- **Q1**: Should we emit a separate `out/attack-surface.diff.json` showing additions/removals vs prior emit? (Cross-loop ConMon LOOP-E.E1 consumer would benefit.) Recommend: yes, in a follow-up slice; not blocking for N.N2 ship.
- **Q2**: How do we treat IPv6 SG rules that resolve to dual-stack listeners? Mitigation: collapse IPv4 + IPv6 rules per (component_id, protocol, port) into a single row with both CIDRs; pin with a test.
- **Q3**: When N.N1 + N.N2 both ship, who owns the AR `observation` deduplication? A 3PAO would see threat-stride observation + attack-surface observation on the same component. Recommend: distinct UUIDs (no dedup); the `observation.description` text disambiguates; pin with a test asserting both observations present on a shared component.
- **Q4**: Subprocessor flow rows currently lack a "subprocessor name" field — should we add `subprocessor_id` referencing a future `subprocessors` table? Recommend: yes, file as N.N2 follow-up; for ship, free-text `operator_notes` carries the name.

## Worked example — public-facing ALB + admin SSH entry points

Given the inventory assets:

```json
[
  {
    "identifier": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/web/abc",
    "asset_type": "elb.application-load-balancer",
    "data_classification": "pii",
    "public_facing": true,
    "internet_reachable": true,
    "tags": { "fedramp_component_class": "network", "auth_boundary": "true" }
  },
  {
    "identifier": "arn:aws:ec2:us-east-1:123:instance/i-bastion",
    "asset_type": "ec2.instance",
    "asset_tier": "tier-1",
    "public_facing": true,
    "internet_reachable": true,
    "tags": { "fedramp_admin_interface": "true" }
  }
]
```

And the network evidence:
- ALB listener `tcp/443` allowed from `0.0.0.0/0`.
- Bastion SG `tcp/22` allowed from `203.0.113.0/24`.

N.N2 emits:

```json
{
  "entry_points": [
    {
      "uuid": "<v5(component_id, 'tcp/443')>",
      "category": "authentication-boundary",
      "component_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/web/abc",
      "protocol": "tcp",
      "port": 443,
      "ip_cidrs": ["0.0.0.0/0"],
      "authentication": "oidc",
      "authorization": "rbac",
      "data_classes_in_transit": ["pii"],
      "mitigating_controls": ["SC-7", "SC-7(3)", "SC-8", "IA-2"],
      "mitigating_ksis": ["IAM-MFA", "SVC-VRI", "CNA-RVP"],
      "sources": {
        "discovery": "providers/aws/network.ts",
        "data_class_source": "inventory-tag"
      }
    },
    {
      "uuid": "<v5(component_id, 'tcp/22')>",
      "category": "administrative-interface",
      "component_id": "arn:aws:ec2:us-east-1:123:instance/i-bastion",
      "protocol": "tcp",
      "port": 22,
      "ip_cidrs": ["203.0.113.0/24"],
      "authentication": "iam",
      "authorization": "rbac",
      "data_classes_in_transit": ["internal"],
      "mitigating_controls": ["AC-17", "AC-17(1)", "IA-2(1)", "MA-4"],
      "mitigating_ksis": ["IAM-MFA", "IAM-APM"],
      "sources": {
        "discovery": "inventory.json",
        "data_class_source": "operator-supplied"
      }
    }
  ],
  "counts_by_category": {
    "internet-reachable-endpoint": 0,
    "authentication-boundary": 1,
    "administrative-interface": 1,
    "data-plane-egress": 0,
    "subprocessor-data-flow": 0,
    "partner-integration": 0,
    "physical-interface": 0
  },
  "totals": {
    "internet_reachable": 2,
    "authenticated": 2,
    "unauthenticated": 0,
    "cui_in_transit": 0,
    "pii_in_transit": 1
  }
}
```

Diagnostics block: empty (both entry points have non-'none' authentication). If the ALB had no authorizer (`authentication: 'none'`), the diagnostic `internet-reachable-unauthenticated` would fire on row 0.

Downstream:
- SAR §3.4 (LOOP-F.F7) quotes `counts_by_category` and the per-row table.
- LOOP-K.K1 PenTest RoE auto-derives scope = `{443, 22}`.
- LOOP-D.D1 boundary diagram renders the two entry points as labeled arrows into the cloud boundary.
- B.B5 risk register reads `totals.pii_in_transit > 0` and bumps the inherent risk for the PII data flow.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean in both `cloud-evidence/` and `tracker/`
- [ ] tests passing 100% (count increased by ≥18 cloud-evidence + ≥4 tracker for this slice)
- [ ] check:reo green (G1+G2+G3)
- [ ] check:provenance green for `out/attack-surface.json`
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-N-SPEC.md §8 status table updated
- [ ] This file's frontmatter updated (`status: done`, `commit: <hash>`, `completed_date: <ISO>`)
- [ ] LOOP-N-RISKS.md per-slice section updated
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-N.N2` in message
- [ ] Commit amended with commit hash recorded
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-N-SPEC.md` §3 (Dependencies) and §5 N.N2.
3. Read `cloud-evidence/docs/loops/LOOP-N-RISKS.md` cross-cutting + N.N2 sections.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Read `cloud-evidence/providers/aws/network.ts`, `providers/gcp/network.ts`, `providers/azure/network.ts` — output formats this slice consumes.
6. Read `cloud-evidence/core/oscal-ap.ts` (back-matter pattern), `core/oscal.ts` (AR observation pattern), `core/sign.ts` (signing glob).
7. Read `core/inventory-coverage.ts` for the provenance block pattern.
8. Begin implementation; update Implementation log section as you go.

---
