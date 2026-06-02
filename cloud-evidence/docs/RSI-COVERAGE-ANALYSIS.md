# FedRAMP 20x Full-Requirement Coverage Analysis

**Status:** Implementation complete. All phases of the per-requirement coverage
analysis have shipped — AFR/CED/CSX collectors and the process-artifact family
trackers are live; see CHANGELOG for the slice history. This document remains
as the design-of-record for *why* the per-requirement model is shaped the way
it is.
**Source data:** `github.com/FedRAMP/docs` @ `FRMR.documentation.json` v0.9.43-beta (2026-04-08, `main` — verified latest).
**Generated ground truth:** `cloud-evidence/docs/frmr-requirements.generated.json` (run `node scripts/extract-frmr-requirements.mjs`).

---

## 0. Terminology: what "RSI" maps to

The term **RSI does not exist in the FedRAMP machine-readable data.** The real
requirement universe is two categories:

| Category | What it is | Count |
|---|---|---|
| **KSI** — Key Security Indicators | The testable security indicators (11 domains) | 60 |
| **FRR** — FedRAMP Requirements | The broader MUST/SHOULD/MAY statements across 10 families (ADS, CCM, FSI, ICP, MAS, PVA, SCG, SCN, UCM, VDR) + the KSI-CSX summary reqs | 163 |
| | **Total addressable requirements** | **223** |

This analysis treats **"RSI" = the full FedRAMP 20x requirement set (KSI + FRR)**,
which matches the request "all RSIs we haven't covered yet."

---

## 1. Coverage today vs. the full set

We already ship collectors for **35 of 60 KSI indicators**. The gap is **188 requirements**:

| | Total | Covered | Gap |
|---|---|---|---|
| KSI indicators | 60 | 35 | **25** |
| FRR requirements | 163 | 0 | **163** |
| **Total** | **223** | **35** | **188** |

**Uncovered KSI indicators (25):** entire **AFR**(10) + **CED**(4) domains, plus
`KSI-CMT-RVP`, `KSI-INR-AAR/RPI`, `KSI-PIY-RES/RIS/RSD/RVD`, `KSI-RPL-ARP/RRO`,
`KSI-SVC-PRR`, `KSI-SCR-MIT`.

**Uncovered FRR families (163):** ADS 20, CCM 24, FSI 16, ICP 9, KSI-CSX 3, MAS 5,
PVA 18, SCG 9, SCN 17, UCM 3, VDR 39.

---

## 2. Impact-level model

Per your direction:

- **Low + Moderate** — taken directly from the 20x machine-readable `levels` field.
  Most requirements apply uniformly to both; **17 carry `varies_by_level`** with
  per-level statements/keywords (e.g. `UCM-CSX-UVM` = Low **MAY** / Moderate **SHOULD** /
  High **MUST**; `PVA-CSX-PMV` cadence 7d/3d). Those published level variants are used verbatim.
- **High** — **not published as 20x machine-readable.** We **derive** High applicability
  from the **NIST SP 800-53 Rev5 High baseline** via each requirement's `controls[]`,
  and label every High assertion `derived-from-rev5` so an assessor never mistakes it
  for a published 20x High obligation. **Caveat surfaced by the analysis:** ~150 of the
  gap requirements carry **empty `controls[]`**, so for those there is *no* Rev5 anchor —
  the tool will state "High: derived-pending, no controls[] to anchor (n/a)" rather than
  fabricate an obligation.

---

## 3. The headline finding: most of the gap is *process*, not cloud-API state

Testability breakdown of the 188 gap requirements (from the per-family analysis):

| Class | Count | Meaning |
|---|---|---|
| **api-testable** | ~4 | Fully provable from a read-only cloud API call (e.g. scanner enablement, FIPS module specs). |
| **hybrid** | ~85 | A read-only cloud signal proves the *capability exists / hasn't regressed*, but a human artifact completes the evidence. |
| **process-artifact** | ~99 | Governance/reporting/comms — proven by a documented artifact + attestation, not a cloud API. |

Implication: the dominant new subsystem is **not** more cloud collectors — it's a
**process-artifact tracker** that emits the same rich, signed, OSCAL-mapped,
LLM-readable evidence envelopes for non-API requirements (artifact URL/hash +
attestation + due-date/SLA monitoring + alternative-satisfier detection), plus a
**handful of high-value new technical collectors**.

### Actor scope (don't over-count)
Several requirements target **FedRAMP / Agencies / 3PAO assessors**, not the CSP:
`VDR-AGM-*`, `VDR-FRP-*`, `CCM-AGM-*`, `SCN-FRP-CAP`, `FSI-FRP-*`, `PVA-TPX-*`.
These are tracked as **awareness / capability-to-support** items and excluded from the
org's own gap/pass count. (≈26 requirements.)

---

## 4. Per-family detail (deep analysis)

Each requirement has a full work-up — plain-English meaning (via FRD definitions),
testability, automated-validation method, required permissions + error handling,
alternative satisfiers (vendor/IdP/scanner/IaC/drift/process), OSCAL/NIST mapping,
which module it plugs into, and recommended implementation + effort.

| File | Families | Reqs | api / hybrid / process |
|---|---|---|---|
| [`analysis/vdr.md`](analysis/vdr.md) | VDR (Vulnerability Detection & Response) | 39 | 1 / 14 / 24 |
| [`analysis/ccm-scn.md`](analysis/ccm-scn.md) | CCM (Collaborative ConMon), SCN (Significant Change) | 41 | 0 / 20 / 21 |
| [`analysis/ads-mas-csx.md`](analysis/ads-mas-csx.md) | ADS (Auth Data Sharing), MAS (Min Assessment Scope), KSI-CSX | 28 | 0 / 15 / 13 |
| [`analysis/pva-scg-ucm.md`](analysis/pva-scg-ucm.md) | PVA (Persistent Validation), SCG (Secure Config Guide), UCM (Crypto Modules) | 30 | 3 / 12 / 15 |
| [`analysis/fsi-icp.md`](analysis/fsi-icp.md) | FSI (Security Inbox), ICP (Incident Comms) | 25 | 0 / 9 / 16 |
| [`analysis/ksi-gaps.md`](analysis/ksi-gaps.md) | 25 uncovered KSI indicators (AFR, CED, CMT, INR, PIY, RPL, SVC, SCR) | 25 | 0 / 15 / 10 |

---

## 5. Highest-value automation opportunities (the api-testable / strong-hybrid set)

1. **UCM crypto (FIPS/CMVP)** — `providers/{aws,gcp}/crypto.ts`: KMS key specs, ACM cert
   algorithms, TLS policies, FIPS endpoints vs the NIST CMVP validated-module list.
   *Per-level PASS logic* (Low MAY / Mod SHOULD / High MUST).
2. **VDR vulnerability ledger** — `core/vdr-ledger.ts` + `core/kev-feed.ts`: normalize
   Inspector2/ECR + GCP Artifact Analysis/SCC findings, join to CISA KEV + EPSS, and make
   the timeframe SLAs (`VDR-TFR-*`) deterministic date math.
3. **SCG comparator** — diff the published machine-readable Secure Config Guide against live
   config (AWS Config conformance packs / GCP SCC / CIS benchmarks).
4. **MAS reconciliation** — cross-check the documented assessment scope against *discovered
   inventory* already collected by `inventory.ts` + `network.ts`; flag undocumented/drifted resources.
5. **ADS endpoint probe** — read-only outbound HTTPS check of the public CSO page / Trust
   Center / OSCAL endpoint (reachability + required-field checklist).
6. **KSI-domain hybrids** — most uncovered KSI indicators reuse signals already collected
   (inventory, pipeline/change logs, backups, scanning) + an attestation slot.

---

## 6. Proposed architecture

### 6a. Impact-level selector (the setup-time choice you asked for)
- `config.yaml`: new `impact_level: low | moderate | high` (required).
- Orchestrator resolves the **in-scope requirement set** for that level from
  `frmr-requirements.generated.json` (`levels[<level>].applies`), applies `varies_by_level`
  statements, and tags High items `derived-from-rev5`.
- CLI override `--impact-level`; surfaced in the run summary, evidence envelopes, OSCAL, and the tracker.
- Each `Finding`/`EvidenceFile` records the level it was evaluated at + the applicable key word (MUST/SHOULD/MAY).

### 6b. Process-artifact tracker (`core/process-artifact-tracker.ts`)
Emits standard `scope: PROCESS` evidence envelopes for non-API requirements:
`process_artifacts_required[]`, attestation record (who/when/artifact URL+hash),
due-date/SLA monitoring (via shared `core/bizdays.ts`), and `alternative_satisfiers[]`
populated from `detect/third-party-tools.ts`. Flows through OSCAL/OCSF/HTML/Paramify/tracker unchanged.

### 6c. New technical modules
`core/kev-feed.ts`, `core/vdr-ledger.ts`, `core/vdr-report.ts`, `core/bizdays.ts`,
`core/conmon-tracker.ts`, `core/scn-tracker.ts`, `providers/{aws,gcp}/crypto.ts`,
SCG comparator + MAS reconciliation, ADS endpoint probe; new detector rules
(Wiz, Prisma, Orca, Tenable, Qualys, Snyk, KnowBe4, Okta/Entra, ArgoCD/Terraform Cloud).

### 6d. Everything stays on the existing rails
Read-only guardrails, Ed25519 signing, RFC-3161 timestamps, ajv schema validation,
OSCAL 1.1, OCSF SIEM, push adapters, cross-KSI links, and per-call permission diagnostics
(`error-diagnostics.ts`) apply unchanged to every new requirement.

---

## 7. Proposed phased implementation

- **Phase 2 — Foundation:** level selector (config/orchestrator/tracker) + register the 25 KSI indicators + `process-artifact-tracker.ts` + `bizdays.ts` + level-aware schema fields. *(unblocks everything)*
- **Phase 3 — Technical collectors:** UCM crypto, VDR ledger + KEV feed, SCG comparator, MAS reconciliation, ADS probe, KSI-domain hybrids.
- **Phase 4 — Process families:** CCM/SCN/FSI/ICP/ADS/MAS/PVA-TPX trackers (artifact + SLA + alt-satisfier).
- **Phase 5 — Detectors + docs + tests + tracker UI:** new third-party detector rules, IAM-permissions-catalog additions, RUNBOOK/README, full regression tests, tracker level filter.

Every phase ends green on `tsc --noEmit` + `vitest run` for both projects, with new
regression tests, before moving on.
