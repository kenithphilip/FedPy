---
slice_id: N.N1
title: STRIDE threat model generator (per-component, from inventory + DFD)
loop: N
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A2, LOOP-A.A3, INV-P1, INV-P2, INV-P3, INV-P4, INV-P5, INV-S1, INV-S2, INV-S3, INV-S4, INV-S5, INV-S6]
blocks: [N.N2, N.N3, N.N4, C.C7, F.F4, F.F7]
estimated_effort: 6-8 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# N.N1 — STRIDE threat model generator (per-component, from inventory + DFD)

## TL;DR
Auto-generate a system-specific STRIDE per-component threat model from `inventory.json` + the FRMR catalog + the NIST control benchmark. Emit `out/threat-model.json` (consumed by AR observations + dashboard) and `out/threat-model.docx` (consumed by SSP §13 + 3PAO walk-through + the submission bundle). Threat rows cite NIST SP 800-30 Rev 1 App. D threat sources, NIST SP 800-154 step 1, NIST SP 800-218 PW.1.1, and FedRAMP Rev5 SSP Template §13. Operator narratives (kill-chain, organisational actors) flow through the tracker UI; per-row sign-off is Ed25519-signed.

## Status
- Status: pending
- Commit: — (filled when shipped, per `docs/SLICE-COMPLETION-PROCEDURE.md`)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
FedPy mission: "read-only, evidence-grade automation for FedRAMP 20x & Rev5". N.N1 is read-only against the cloud (every input is on-disk JSON already emitted by INV-P1..S6 + the FRMR catalog + the 800-53 benchmark). The output is signed evidence (Ed25519 + RFC 3161) the 3PAO can audit row-by-row. Each threat row anchors a real `inventory.assets[].identifier` so a 3PAO can demand the underlying SDK call and the catalog row that produced the row's `mitigating_ksis`. The OSCAL chain (SSP → AP → AR → POA&M) gains a `back-matter.resources[type=threat-model]` block in SSP and per-row `observation` rows in AR — closing the FedRAMP SSP Template §13 + NIST SP 800-30 r1 §3.2 TASK 2-1..2-3 + NIST SP 800-218 PW.1.1 gaps.

## Why this slice exists
The 49-slice roadmap (LOOP-A done; LOOP-B–K specified) does not produce a CSP-authored, system-specific threat model. `docs/ADDITIONAL-LOOPS-AUDIT.md` §2 LOOP-N flags this verbatim:

> "the CSP-authored threat model (STRIDE / PASTA / kill-chain narrative + attack surface enumeration) has no home … Threat models are also a prerequisite of NIST SSDF (SP 800-218) PW.1.1".

NIST SP 800-30 Rev 1 §3.2 mandates "TASK 2-1 Identify Threat Sources; TASK 2-2 Identify Threat Events; TASK 2-3 Identify Vulnerabilities and Predisposing Conditions" — N.N1 walks all three over every inventory component. FedRAMP Rev5 SSP Template §13 narrative for RA-3 + PL-2 requires the CSP to "describe the threat sources, threat events, and vulnerabilities considered. Include attack surface analysis as appropriate." NIST SP 800-218 PW.1.1: "Use forms of risk modeling — such as threat modeling, attack modeling, or attack surface analysis — to help assess the risk of attack."

Without N.N1 the SSP §13 narrative is hand-authored prose with no cross-reference to actual inventory components — a 3PAO has no way to challenge "is every component in scope covered?" against the authoritative system catalog. N.N1 produces the structured catalog the SSP narrative cites.

## Authoritative sources (with verbatim quotes)
- **Microsoft Threat Modeling Tool — STRIDE model** — https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
  > "To better help you formulate these kinds of pointed questions, Microsoft uses the STRIDE model, which categorizes different types of threats and simplifies the overall security conversations."
  Six STRIDE categories quoted verbatim in `LOOP-N-SPEC.md §4`: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.

- **NIST SP 800-30 Rev 1 — Guide for Conducting Risk Assessments (Sep 2012)** — https://csrc.nist.gov/pubs/sp/800/30/r1/final, PDF: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf
  > §3.2 "Conduct the Risk Assessment" — TASK 2-1 Identify Threat Sources; TASK 2-2 Identify Threat Events; TASK 2-3 Identify Vulnerabilities and Predisposing Conditions.
  Appendix D **Threat Sources** taxonomy: adversarial, accidental, structural, environmental.
  Appendix E **Threat Events** taxonomy. N.N1 cites both verbatim.
  PDF gates anonymous fetches → operator downloads to `cloud-evidence/docs/sources/nist-sp-800-30r1.pdf` (cross-ref `N-X1`).

- **NIST SP 800-154 (Draft) — Guide to Data-Centric System Threat Modeling** — https://csrc.nist.gov/CSRC/media/Publications/sp/800-154/draft/documents/sp800_154_draft.pdf
  Four DCSTM steps: (1) Identify and characterize the system and data of interest, (2) Identify and select the attack vectors, (3) Characterize the security controls for mitigating the attack vectors, (4) Analyze the threat model. N.N1 implements steps 1 + 3; N.N2 implements step 2; N.N4 informs step 3.

- **NIST SP 800-53 Rev 5 — Security and Privacy Controls** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - RA-3 Risk Assessment: "Conduct a risk assessment, including: identifying threats to and vulnerabilities in the system; the likelihood and magnitude of harm …"
  - PL-2 System Security and Privacy Plans references the threat model as required content.
  - SA-11 Developer Testing and Evaluation (Threat Modeling sub-control SA-11(2)).

- **NIST SP 800-218 — Secure Software Development Framework (SSDF) v1.1** — https://csrc.nist.gov/pubs/sp/800/218/final
  > PW.1.1: "Use forms of risk modeling — such as threat modeling, attack modeling, or attack surface analysis — to help assess the risk of attack."

- **FedRAMP Rev5 SSP Template §13 (Control Implementation Description)** — https://www.fedramp.gov/assets/resources/templates/SSP-A1-FedRAMP-System-Security-Plan-Template.docx
  Template narrative for RA-3 + PL-2: "describe the threat sources, threat events, and vulnerabilities considered. Include attack surface analysis as appropriate."

- **OWASP Threat Modeling** — https://owasp.org/www-community/Application_Threat_Modeling — authoritative open-source overview; cited in README for context.

- **CWE Top 25 (2024 release)** — https://cwe.mitre.org/top25/ — STRIDE rows cite the relevant CWE (e.g. Spoofing on auth boundaries → CWE-287; Information Disclosure on data flows → CWE-200/CWE-319).

- **OSCAL SSP v1.1.2 `back-matter.resources`** — https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/ — accepts arbitrary `type` strings; we register `threat-model` (documented in `docs/oscal/extensions.md`).

## Files to create (exact paths under cloud-evidence/)
- `cloud-evidence/core/threat-model.ts` — pure builder: takes `InventoryComponent[]` + `ControlBenchmark` + `KsiMap` + operator config → `ThreatModel` typed value. No IO, no side effects.
- `cloud-evidence/core/threat-model-emit.ts` — disk emitter: walks inventory, calls pure builder, writes `out/threat-model.json`, invokes `core/threat-model-docx.ts`.
- `cloud-evidence/core/threat-model-docx.ts` — `.docx` renderer reusing the `core/ssp-docx.ts` pattern from LOOP-A SSP-2.
- `cloud-evidence/core/stride-catalog.ts` — typed constant catalog of per-component-type STRIDE rules; ≥30 rows; each row cites FRMR/NIST/MITRE source.
- `cloud-evidence/tests/core/threat-model.test.ts` — pure-builder tests.
- `cloud-evidence/tests/core/threat-model-emit.test.ts` — emitter integration tests.
- `cloud-evidence/tests/core/threat-model-docx.test.ts` — docx round-trip tests.
- `cloud-evidence/tests/core/stride-catalog.test.ts` — catalog completeness tests.
- `cloud-evidence/tests/fixtures/threat-model/` — fixture directory.
- `cloud-evidence/threat-model-config.example.yaml` — committed example operator config.
- `cloud-evidence/docs/oscal/extensions.md` — registers the `threat-model` + (later `attack-surface`) `type` tokens.
- `tracker/server/routes/threat-model.ts` — CRUD route for operator narratives + per-row sign-off.
- `tracker/server/routes/threat-model.test.ts`.
- `tracker/client/src/pages/ThreatModel.tsx` — UI for narrative authoring + sign-off.
- `tracker/client/src/pages/ThreatModel.test.tsx`.

## Files to extend
- `cloud-evidence/core/oscal-ssp.ts` — append `back-matter.resources[type=threat-model]` block when `threat-model.json` exists in outDir.
- `cloud-evidence/core/oscal.ts` (AR builder) — for each `ThreatRow`, emit an `observation` with `subjects[type=component]`, `props[name=threat-stride-category]`, `relevant-evidence[].href` → `./threat-model.json#/rows/<idx>`.
- `cloud-evidence/core/orchestrator.ts` — new flags `--threat-model` (env `CLOUD_EVIDENCE_THREAT_MODEL`), `--threat-model-config <path>` (env `CLOUD_EVIDENCE_THREAT_MODEL_CONFIG`), `--strict-threat`.
- `cloud-evidence/core/submission-bundle.ts` — add roles `threat-model-json` (filename `threat-model.json`) + `threat-model-docx` (filename `threat-model.docx`) to `WELL_KNOWN`.
- `tracker/server/schema.sql` — additive tables `threat_models` + `threat_model_narratives`.
- `tracker/server/index.ts` — mount `routes/threat-model.ts`.
- `tracker/client/src/App.tsx` — add `/threat-model` route.

## Schemas / standards
- **STRIDE** — six categories per Microsoft Threat Modeling Tool docs. N.N1 emits one row per (component, STRIDE-category) cross product.
- **NIST SP 800-30 Rev 1 §3.2 TASK 2-1**: N.N1 emits a per-component `threat_sources[]` taxonomy block citing Appendix D verbatim.
- **NIST SP 800-154 Step 1 + Step 3** — implemented in pure builder.
- **OSCAL SSP `back-matter.resources[type]`** — accepts arbitrary `type` strings; we register `threat-model` (docs/oscal/extensions.md).
- **OSCAL AR `observation`** v1.1.2 — `methods: ['EXAMINE']`, `subjects[type=component]`, `props[ns=CE_NS]`, `relevant-evidence[].href` is an in-document JSON Pointer.
- **FedRAMP SSP §13 docx structure** — the docx renderer emits the §13-shaped sections operator pastes into SSP (or auto-merges via SSP-2 docx merge).
- **CE_NS namespace** — `"https://cloud-evidence.example/oscal-ns"` (existing constant in `core/oscal-poam.ts`).

## Build steps (concrete, numbered)
1. Define typed interfaces in `core/threat-model.ts` (verbatim from `LOOP-N-SPEC.md §5 N.N1 build step 1`): `StrideCategory`, `ComponentClass` (compute / storage / network / identity / data-plane / control-plane / monitoring / crypto / human-interface / admin-interface / external-service), `ThreatSource`, `ThreatRow`, `ThreatModel`.
2. Pure builder: `buildThreatModel(inventory, controlBenchmark, ksiMap, opts): ThreatModel`. Classifies every inventory asset to a `ComponentClass` via tag-driven heuristics on `asset_type` (e.g. `ec2.instance` → compute, `s3.bucket` → storage, `iam.user` → identity, `elb.application-load-balancer` → network). Iterates `STRIDE_CATALOG` and emits one row per (component, stride) cross product where a catalog rule exists. `mitigating_ksis` resolved through `ksi-map.ts`; `mitigating_controls` filtered through `controlBenchmark` at the configured impact level (Low / Moderate). Deterministic v5 UUID over `(component_id, stride)`.
3. STRIDE catalog (`core/stride-catalog.ts`): typed constant. ≥30 high-signal rows of 11 × 6 ComponentClass × STRIDE matrix. Each row has `component_class`, `stride`, `default_threat_event` (verbatim text), `cwe_ids[]`, `mitigating_ksi_ids[]`, `mitigating_nist_control_ids[]`, `citation { spec, section, url }`. Rows without meaningful threats documented as catalog comment (n/a). Examples to seed (each cites FRMR / NIST / CWE):
   - `(network, information-disclosure) → CWE-319 + CWE-200; mitigated by SVC-VRI, CNA-RVP; controls SC-8, SC-8(1), SC-12, SC-13.`
   - `(compute, elevation-of-privilege) → CWE-269; mitigated by IAM-ELP, IAM-APM; controls AC-6, AC-6(1), AC-6(2).`
   - `(identity, spoofing) → CWE-287, CWE-308; mitigated by IAM-MFA; controls IA-2, IA-2(1), IA-2(2), IA-2(11).`
   - `(storage, information-disclosure) → CWE-200, CWE-922; mitigated by SVC-RUD, SVC-VRI; controls SC-28, SC-28(1), MP-2.`
   - `(monitoring, repudiation) → CWE-117; mitigated by MLA-LET, CMT-LMC; controls AU-9, AU-10.`
4. Disk emitter (`core/threat-model-emit.ts`): signature in `LOOP-N-SPEC.md §5 N.N1 build step 4`. Reads inventory + config + tracker snapshot; writes `out/threat-model.json` + invokes `threat-model-docx.ts`. Returns `{ jsonPath, docxPath, rowCount, unsigned_rows, requires_operator_input }`.
5. DOCX renderer (`core/threat-model-docx.ts`): mirrors `core/ssp-docx.ts`. Sections: Title page → Executive summary → Threat Sources table (NIST 800-30 r1 App. D taxonomy verbatim) → Per-component STRIDE matrix (one section per `ComponentClass`) → DFD overlay (when supplied by LOOP-D.D3, otherwise documented "deferred to D.D3 ship") → Mitigations cross-reference table → Residual risks (operator-supplied via tracker) → Kill-chain narrative (operator) → Signatures + revision history.
6. AR observation emission (extend `core/oscal.ts`): per `ThreatRow`, emit object per `LOOP-N-SPEC.md §5 N.N1 build step 6`. Each prop in namespace `CE_NS`. `relevant-evidence[].href` is `./threat-model.json#/rows/<idx>`.
7. SSP back-matter (extend `core/oscal-ssp.ts`): emit one resource per signed artifact — `{ uuid: deterministicUuid('ssp:back-matter:threat-model'), title, description, props[{ name: 'type', ns: CE_NS, value: 'threat-model' }], rlinks: [json, docx] }`.
8. Tracker UI: `threat_models` + `threat_model_narratives` schemas per `LOOP-N-SPEC.md §5 N.N1 build step 8`. RBAC: ISO signs each row; AO sign-off optional (the threat model is an SSP appendix, not a separate authorization artifact). Sign-off recorded as `signature` (Ed25519) + `signing_key_id` joined to tracker key registry.
9. Bundler integration: add `threat-model-json` + `threat-model-docx` to `submission-bundle.ts:WELL_KNOWN`.
10. Validation pass: emitted `out/threat-model.json` runs through `scripts/check-provenance.mjs`; modified `out/ssp.json` runs through `core/oscal-validate.ts` (must still pass SSP v1.1.2 ajv); modified `out/ar.json` runs through `core/oscal-validate.ts` (must still pass AR v1.1.2 ajv).
11. Signing + timestamping: both `threat-model.json` + `threat-model.docx` picked up by existing `core/sign.ts` glob + included in the RFC 3161 manifest.
12. `--strict-threat` orchestrator mode: counts rows with any source `REQUIRES-OPERATOR-INPUT`; exits non-zero if any exist after operator-config pull + tracker snapshot apply.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

| Field | Source | Behaviour when missing |
|---|---|---|
| `kill_chain_narrative` | tracker UI (`/threat-model` page → narrative editor) | empty string until operator provides; never auto-substituted |
| `organisational_threat_actors[]` | tracker UI | empty array until operator provides |
| `threat_event` (per row) | `default_threat_event` from `STRIDE_CATALOG` is the seed; operator can override per row via tracker | catalog default used; override flips `stride_catalog_source: 'operator-supplied'` |
| `residual_risk_note` (per row) | tracker UI | empty; never auto-substituted |
| `operator_signed_off` (per row) | tracker UI sign-off | false until operator signs; `--strict-threat` blocks if any row unsigned |
| `mitigating_ksis` (per row) | `STRIDE_CATALOG` cross-referenced with `ksi-map.ts` | unresolved → `REQUIRES-OPERATOR-INPUT: mitigation-mapping`; operator supplies via config |
| `mitigating_controls` (per row) | `STRIDE_CATALOG` cross-referenced with `controlBenchmark` at impact level | unresolved → `REQUIRES-OPERATOR-INPUT: control-mapping`; operator supplies via config |
| DFD overlay | LOOP-D.D3 emitted DFD | absent → docx section reads "deferred to D.D3 ship"; CHANGELOG entry for D.D3 back-fills |

## Test specifications (≥12 tests)
1. `it('classifies inventory assets to ComponentClass via asset_type', ...)` — AWS `ec2.instance` → compute; AWS `s3.bucket` → storage; GCP `compute.instance` → compute; AWS `iam.user` → identity; AWS `elb.application-load-balancer` → network.
2. `it('emits one row per (component, stride) cross product where catalog has a rule', ...)` — verify the seeded inventory produces the expected `rowCount`.
3. `it('cites NIST 800-30 r1 App. D threat-source class on every row', ...)` — every row's `threat_sources[].class` ∈ {adversarial, accidental, structural, environmental}.
4. `it('maps mitigating KSIs from STRIDE catalog cross-checked against ksi-map.ts', ...)` — assert no row has an unknown KSI id.
5. `it('maps mitigating NIST controls to the configured impact level', ...)` — Low-baseline doesn't reference Moderate-only controls.
6. `it('emits REQUIRES-OPERATOR-INPUT mitigation-mapping when catalog row has no KSI match', ...)`.
7. `it('produces deterministic uuid v5 per (component, stride)', ...)` — re-run yields identical UUIDs.
8. `it('writes threat-model.json with provenance.emitter + sourceCalls', ...)` — `check:provenance` passes.
9. `it('writes threat-model.docx with the §13-shaped sections', ...)` — docx parsed via test renderer; assert all eight section headings present.
10. `it('appends SSP back-matter resource type=threat-model', ...)` — re-emit SSP, find the resource entry by `props[name=type,value=threat-model]`.
11. `it('AR observation emits threat-stride-category + cwe-id + mitigating-ksi props', ...)` — re-emit AR; find props by name; assert exact values.
12. `it('respects operator override of threat_event from tracker snapshot', ...)` — snapshot file overrides catalog default; resulting row carries `stride_catalog_source: 'operator-supplied'`.
13. `it('honours kill-chain narrative from threat_model_narratives table', ...)` — narrative populated in JSON + docx.
14. `it('bundler includes threat-model-json + threat-model-docx roles', ...)`.
15. `it('strict-threat mode fails when any row carries REQUIRES-OPERATOR-INPUT', ...)`.
16. `it('docx contains the threat-sources taxonomy table (NIST 800-30 r1 App. D)', ...)` — assert taxonomy rows.
17. `it('signs threat-model.json with Ed25519 + includes in RFC 3161 manifest', ...)` — verify against pinned key.
18. `it('catalog contains ≥30 high-signal rows', ...)` — completeness gate.

## REO compliance
- Every component classified from real `inventory.json` (no synthetic components).
- STRIDE catalog is a typed constant whose every row cites FRMR / NIST / MITRE / CWE source — no placeholder text, no "TODO" rows.
- `mitigating_ksis` / `mitigating_controls` resolve through `ksi-map.ts` + `control-benchmark.ts`; unresolved cells surface as `REQUIRES-OPERATOR-INPUT`, never silent fallback.
- Operator sign-off is real human action recorded in `threat_models` table with Ed25519 signature; never auto-signed.
- `kill_chain_narrative` is verbatim operator text or empty; system never substitutes a "lorem ipsum" placeholder.
- Provenance block populated: emitter name, emittedAt (ISO), sourceCalls (inventory path, control benchmark version, KSI map version, NIST 800-30 r1 + 800-154 + 800-218 citation refs), signingKeyId.
- No `process.env.NODE_ENV === 'test'` branches anywhere.
- Signed by existing `core/sign.ts` pipeline (Ed25519 + RFC 3161 timestamp).

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/threat-model.test.ts tests/core/threat-model-emit.test.ts tests/core/threat-model-docx.test.ts tests/core/stride-catalog.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
cd "../tracker"
npm run typecheck
npm test -- server/routes/threat-model.test.ts client/src/pages/ThreatModel.test.tsx
```

## Known risks / issues
- **Risk 1: STRIDE catalog completeness vs scope.** 11 × 6 = 66 cells; ~36 cells have meaningful threats, the rest are documented "n/a" with a catalog comment. CHANGELOG entry lists which cells are populated and why. (Cross-ref `N-X3`.)
- **Risk 2: NIST SP 800-30 r1 PDF gated by 403 on anonymous fetch.** Operator downloads to `cloud-evidence/docs/sources/nist-sp-800-30r1.pdf` before catalog citations can be pinned verbatim. (Cross-ref `N-X1`.)
- **Risk 3: LOOP-D.D3 DFD overlay sequencing.** N.N1's DFD overlay feature consumes the LOOP-D.D3-emitted Data Flow Diagram. If D.D3 is unshipped at N.N1 time, the slice ships without the overlay (docstring documents the omission with a forward-link); the CHANGELOG entry for D.D3 then adds a "back-fills N.N1 DFD overlay" addendum.
- **Risk 4: AR observation count growth.** A 500-component inventory × 6 STRIDE categories = 3000 potential observations. AR rendering + ajv validation may be slow. Mitigation: emitter measures elapsed and warns at > 5s; chunked OSCAL emission is a future enhancement.
- **Risk 5: Sign-off model RBAC drift.** ISO role must exist in tracker; if IDP doesn't map any user to ISO, all rows stay `operator_signed_off: false` and `--strict-threat` blocks. Mitigation: first-boot prompt + runbook documentation. (Cross-ref `N-X5`.)

## Open questions
- **Q1**: Should we generate a `threat_model_v15_changelog.md` per re-run showing diff vs prior emit (new rows, retired rows, sign-off status changes)? Recommend: yes — this is the artifact a 3PAO needs at the monthly ConMon review (LOOP-E.E1 consumer). File as N.N1 follow-up if not in first cut.
- **Q2**: Where do operator-supplied `organisational_threat_actors` live — `threat_model_narratives` table or a dedicated `threat_actors` table? Recommend: nested JSON in `threat_model_narratives.organisational_threat_actors_json` (single-row-per-system pattern matches kill_chain_narrative).
- **Q3**: Should `stride-catalog.ts` rows that map to KSIs not yet covered by the FRMR catalog (e.g. a future "supply-chain SBOM" KSI) be tracked as `REQUIRES-CATALOG-UPDATE` separately from `REQUIRES-OPERATOR-INPUT`? Recommend: yes — different remediation path (operator can't tag the cloud to fix a missing KSI in the catalog).
- **Q4**: Threat-model UUID stability across catalog version bumps — if we bump `formula_version: "threat-model.v1"` to `v2` and a row's `mitigating_ksis` changes, does the row UUID stay the same? Spec says yes (UUID is over component_id + stride, not the mitigation set). Pin with a code comment.

## Worked example — public-facing ALB Information-Disclosure STRIDE row

To make the slice reviewable end-to-end, the test suite encodes this exact example. Given the inventory asset:

```json
{
  "identifier": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/web/abc",
  "asset_type": "elb.application-load-balancer",
  "data_classification": "pii",
  "asset_tier": "tier-0",
  "public_facing": true,
  "internet_reachable": true,
  "tags": { "fedramp_component_class": "network" }
}
```

The Information-Disclosure row the builder emits:

```json
{
  "uuid": "<v5(component_id, 'information-disclosure')>",
  "component_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/web/abc",
  "component_class": "network",
  "stride": "information-disclosure",
  "threat_sources": [
    { "class": "adversarial", "actor": "external attacker", "capability": "moderate", "intent": "targeted" }
  ],
  "threat_event": "Eavesdropping on PII in transit to the application load balancer",
  "cwe_ids": ["CWE-319", "CWE-200"],
  "mitigating_ksis": ["SVC-VRI", "CNA-RVP"],
  "mitigating_controls": ["SC-8", "SC-8(1)", "SC-12", "SC-13"],
  "operator_signed_off": false,
  "sources": {
    "component_source": "inventory.json",
    "stride_catalog_source": "stride-catalog.ts",
    "mitigation_source": "ksi-map.ts",
    "threat_source_source": "NIST-800-30-r1-App-D"
  }
}
```

Quality of this signal end-to-end:
- SSP §13 narrative for SC-8 gains a concrete component reference + threat-event sentence.
- SAR §3.4 (LOOP-F.F7) cross-references the same component as part of the attack-surface examined during testing.
- 3PAO walking the threat model sees the KSI ↔ control ↔ component chain explicit.
- N.N4 attack mapping cross-references the SAME component under technique T1040 (Network Sniffing) under tactic TA0009 (Collection).
- B.B5 risk register lists the same finding under `inherent_risk = high`, `residual_risk = moderate` after SC-8(1) is implemented.
- N.N2 attack-surface inventory lists the same component as an `internet-reachable-endpoint` with `data_classes_in_transit: ['pii']` — diagnostics block flags `internet-reachable-unauthenticated` if `authentication: 'none'`.

That is the LOOP-N value proposition end-to-end — a single inventory asset surfaces in five distinct authorization artifacts, each pointing back to the same underlying SDK call.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`) in both `cloud-evidence/` and `tracker/`
- [ ] tests passing 100% (count increased by ≥17 cloud-evidence + ≥4 tracker for this slice)
- [ ] check:reo green (G1+G2+G3)
- [ ] check:provenance green for `out/threat-model.json`
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-N-SPEC.md §8 status table updated
- [ ] This file's frontmatter updated (`status: done`, `commit: <hash>`, `completed_date: <ISO>`)
- [ ] LOOP-N-RISKS.md per-slice section updated (any new risks added; any closed risks moved to "Resolved")
- [ ] CHANGELOG.md "Unreleased" entry added (cite module names, test counts, REO notes)
- [ ] Commit with `LOOP-N.N1` in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-N-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-N-SPEC.md` §1, §2, §3, §4 (dependencies + authoritative sources).
3. Read `cloud-evidence/docs/loops/LOOP-N-RISKS.md` cross-cutting + N.N1 sections.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/oscal-ssp.ts` (back-matter resource emission pattern), `core/oscal.ts` (AR observation emission), `core/oscal-poam.ts:84-90` + `core/oscal-poam.ts:377+` (props pattern), `core/inventory-coverage.ts` (provenance block pattern), `core/sign.ts` (signing glob).
6. Read `core/ssp-docx.ts` (LOOP-A SSP-2) — the docx renderer pattern N.N1 mirrors.
7. Read `core/ksi-map.ts` + `core/control-benchmark.ts` + `core/nist-r5.ts` (mapping sources).
8. Begin implementation; update Implementation log section as you go.

---
