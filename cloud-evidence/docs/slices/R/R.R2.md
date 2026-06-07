---
slice_id: R.R2
title: PQC Migration Plan Emitter (per-asset, OMB M-23-02 §IV)
loop: R
status: pending
commit: —
completed_date: —
depends_on: [R.R1, LOOP-A.A1, LOOP-A.A3, LOOP-B.B1, LOOP-B.B2]
blocks: [R.R3, C.C7, Q.Q1]
estimated_effort: 4-5 working days
last_updated: 2026-06-07
---

# R.R2 — PQC Migration Plan Emitter

## TL;DR
For every quantum-vulnerable entry in the R.R1 crypto inventory, emit a per-asset migration plan record carrying target algorithm (one of the FIPS 203 / 204 / 205 parameter sets), target date (default IR 8547 anchors 2030 / 2035; CNSA 2.0 anchors 2025 / 2030 / 2033 when the operator opts in), owner, blockers, and inheritance from upstream cloud-vendor PQC roadmaps. The plan is emitted as `out/pqc-migration-plan.docx` (OMB M-23-02 §IV shape) + `out/pqc-migration-plan.json` (structured twin). Unplanned migration entries (no operator-set target date / owner) emit one OSCAL POA&M item each via `core/oscal-poam.ts`, picking up LOOP-B.B1 risk scoring and LOOP-B.B2 deadline math automatically.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
FedPy emits OSCAL SSP → AP → AR → POA&M chain (LOOP-A) and risk-scored, deadline-bearing POA&M items (LOOP-B). R.R2 plugs PQC migration into that existing risk pipeline: every quantum-vulnerable algorithm in use becomes a POA&M item with a defensible target date derived from IR 8547 / CNSA 2.0. The migration plan `.docx` is the OMB §IV-shape artifact federal agency customers will demand from 2027 onward. By treating PQC migration as just another POA&M-tracked risk, FedPy avoids parallel risk taxonomies and keeps a single source of truth for ConMon.

## Why this slice exists
- **OMB M-23-02 §IV** requires every federal agency / CSP to develop and maintain a plan for migrating prioritized information systems to PQC. The plan must enumerate target algorithm + target date + owner + blockers per asset.
- **R.R1 alone produces inventory** — it does not surface the *forward-looking* plan. Without R.R2, the operator + 3PAO + AO have no system path from "we have 3 RSA keys" to "here's how + when we replace them".
- **LOOP-A POA&M is the existing risk-tracking artifact** — wiring R.R2's unplanned migrations into POA&M items means LOOP-B.B1 risk scoring + LOOP-B.B2 deadline math + LOOP-B.B3 risk-acceptance workflow + LOOP-B.B5 risk register *all* pick them up automatically. Zero new risk infrastructure; only new domain semantics.
- **CSP-side preparation for OMB §V annual report (R.R3)** — R.R3 aggregates planned + unplanned migration progress over time; without R.R2's per-asset records, R.R3 has nothing to aggregate.
- **FedRAMP 20x Consolidated Rules 2026 window** — federal customers serving DoD / Intelligence-Community-adjacent customers will start requiring this artifact inside 18 months.

## Authoritative sources (with verbatim quotes)
- https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf — **OMB M-23-02, Migrating to Post-Quantum Cryptography (Nov 18 2022)**, §IV "Migration Planning":
  PDF returns HTTP 403 / binary to anonymous fetches; implementer downloads to `cloud-evidence/docs/sources/omb-m-23-02.pdf`. §IV obligates the per-asset migration plan with target algorithm + date + owner + blockers. The exact field set is paginated in the PDF; the LOOP-R-SPEC.md §4.R2 schema captures the publicly-known structure and the implementer's PDF download confirms verbatim before ship.

- https://csrc.nist.gov/pubs/ir/8547/ipd — **NIST IR 8547 IPD, §4.2 Transition Timeline**:
  > "Under the transition timeline in NIST IR 8547, NIST will deprecate and ultimately remove quantum-vulnerable algorithms from its standards by 2035, with high-risk systems transitioning much earlier."
  > (Via NIST CSRC PQC project page: https://csrc.nist.gov/projects/post-quantum-cryptography .)
  R.R2 uses 2030 (deprecate, high-risk) and 2035 (disallow) as default target-date anchors for the FedPy mission's Moderate / High customer cohort.

- https://csrc.nist.gov/pubs/fips/203/final — **FIPS 203 ML-KEM**: parameter sets ML-KEM-512 / -768 / -1024. R.R2's default mapping pairs RSA / ECDH instances against the ML-KEM parameter set whose security strength category matches the source. RSA-2048 (≈ 112-bit) → ML-KEM-512 (cat 1); RSA-3072 (≈ 128-bit) → ML-KEM-768 (cat 3); RSA-4096 → ML-KEM-1024 (cat 5).

- https://csrc.nist.gov/pubs/fips/204/final — **FIPS 204 ML-DSA**: parameter sets ML-DSA-44 / -65 / -87. R.R2's default mapping pairs ECDSA / RSA signature instances against ML-DSA: ECDSA-P256 → ML-DSA-44 (cat 2); ECDSA-P384 / RSA-3072 → ML-DSA-65 (cat 3); ECDSA-P521 / RSA-4096 → ML-DSA-87 (cat 5).

- https://csrc.nist.gov/pubs/fips/205/final — **FIPS 205 SLH-DSA**: 12 parameter sets, intended for firmware / code-signing where stateless signing without state management is required.

- https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF — **NSA CNSA 2.0 (Sep 2022)**:
  PDF 403 to anonymous fetches; implementer downloads to `docs/sources/cnsa-2.0.pdf`. Mandates ML-KEM + ML-DSA for NSS by 2033 with 2025 begin and 2030 preference. When operator opts in via `pqc-config.yaml` `cnsa_2_0: true`, R.R2's default target dates swap.

- https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/ — **NSM-10 (May 4 2022)**:
  URL currently 404 to anonymous fetch; implementer downloads canonical text. Anchors the executive direction; cited in the migration plan's Authority section.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, SA-9 (External System Services)**:
  > "Require that providers of external system services comply with organizational security and privacy requirements and employ the following controls: [Assignment]; define and document organizational oversight and user roles and responsibilities …".
  R.R2's `inheritance{}` block captures the SA-9-relevant upstream-provider PQC roadmap signal.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-migration-plan.ts` — pure builder + types (`PqcMigrationPlanEntry`, `MigrationStatus`, default mapping table, default target-date table). ~450 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-migration-plan-docx.ts` — OOXML renderer reusing `core/oscal-ssp-docx.ts` helpers. ~600 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-migration-plan-emit.ts` — disk emitter orchestrating the pure builder + writers; emits `.docx` + `.json` + unplanned POA&M items.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-target-defaults.ts` — typed constant table mapping `(algorithm, purpose) → (target_algorithm, target_fips_standard, default_target_date)`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-migration-plan.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-migration-plan-docx.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-migration-plan-emit.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-target-defaults.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/pqc/migration-plan/` — sample R.R1 inventory + sample `pqc-config.yaml` + sample tracker owner snapshot.

## Files to extend (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — accept `pqc_unplanned_migrations[]: PqcMigrationPlanEntry[]` as an optional input. For each entry whose status is `unplanned`, emit a `poam-item` with `props`:
  - `{ name: 'pqc-asset-id', ns: CE_NS, value: e.asset_id }`
  - `{ name: 'pqc-current-algorithm', ns: CE_NS, value: e.current_algorithm }`
  - `{ name: 'pqc-target-algorithm', ns: CE_NS, value: e.target_algorithm }`
  - `{ name: 'pqc-target-date', ns: CE_NS, value: e.target_date }`
  - `{ name: 'pqc-target-fips-standard', ns: CE_NS, value: e.target_fips_standard }`
  - `{ name: 'pqc-deadline-source', ns: CE_NS, value: e.target_date_source }`
  - `{ name: 'pqc-purpose', ns: CE_NS, value: e.purpose }`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — derive severity for PQC POA&M items:
  - target_date < now() → `critical`
  - target_date < now() + 1y → `high`
  - target_date < now() + 3y → `medium`
  - target_date < 2035-01-01 → `low`
  - else → `info`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/deadline-engine.ts` (LOOP-B.B2) — extend `DeadlineSource` enum with `'pqc-target-date'`. When the finding's source is a PQC unplanned migration, the deadline cascade respects `pqc-target-date` prop and records source accordingly.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--pqc-migration-plan` flag + env `CLOUD_EVIDENCE_PQC_PLAN`; depends on `--pqc-inventory` having run. New `--strict-pqc` flag: when set, exits non-zero if any unplanned entry has `target_date < now()`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — `WELL_KNOWN` adds:
  ```ts
  { role: 'pqc-migration-plan-docx', filename: 'pqc-migration-plan.docx', description: 'Per-asset PQC migration plan per OMB M-23-02 §IV (LOOP-R.R2)' },
  { role: 'pqc-migration-plan-json', filename: 'pqc-migration-plan.json', description: 'Structured twin of pqc-migration-plan.docx (LOOP-R.R2)' },
  ```
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-config.ts` (from R.R1) — extend schema with:
  ```yaml
  migration_targets:
    - asset_id: "kms-abcd-1234"
      target_algorithm: "ml-dsa-65"
      target_date: "2029-06-30"
      owner_email: "crypto-team@acme.example"
      blockers: ["AWS KMS ML-DSA GA pending"]
  algorithm_target_overrides:
    "ecdsa-p256": "ml-dsa-44"      # operator may force SLH-DSA instead
  cnsa_2_0_target_date: "2030-12-31"
  ```

## Schemas / standards
- **`PqcMigrationPlanEntry`** schema (see LOOP-R-SPEC.md §4.R2 step 1 for full definition):
  ```ts
  interface PqcMigrationPlanEntry {
    uuid: string;
    asset_id: string;
    provider: 'aws' | 'gcp' | 'azure';
    resource_id: string;
    current_algorithm: string;
    current_quantum_vulnerable_class: QuantumVulnerableClass;
    target_algorithm: string;
    target_fips_standard: 'FIPS 203' | 'FIPS 204' | 'FIPS 205' | 'FIPS 197' | 'not-applicable';
    target_date: string;
    target_date_source: 'operator-override' | 'omb-m-23-02' | 'ir-8547-deprecate-2030' | 'ir-8547-disallow-2035' | 'cnsa-2.0';
    owner_user_id?: number;
    owner_email?: string;
    blockers: string[];
    inheritance: {
      upstream_provider: 'aws-kms' | 'gcp-cloud-kms' | 'azure-key-vault' | 'in-house' | 'third-party' | 'none';
      upstream_target_date?: string;
      blocked_by_upstream: boolean;
    };
    status: 'unplanned' | 'planned' | 'in-progress' | 'pilot' | 'complete';
    last_updated_at: string;
    sources: {
      target_algorithm_source: 'pqc-config' | 'default-mapping' | 'operator-override' | 'REQUIRES-OPERATOR-INPUT';
      target_date_source_field: 'pqc-config' | 'default-omb' | 'operator-override' | 'REQUIRES-OPERATOR-INPUT';
      owner_source: 'tracker' | 'pqc-config' | 'REQUIRES-OPERATOR-INPUT';
    };
  }
  ```
- **Default mapping table** (`core/pqc-target-defaults.ts`):
  - rsa-2048 (kms-key-wrap | tls-server) → ml-kem-768 (FIPS 203)
  - rsa-2048 (kms-signing | jwt-signing) → ml-dsa-65 (FIPS 204)
  - rsa-3072 (any) → ml-kem-768 / ml-dsa-65
  - rsa-4096 (any) → ml-kem-1024 / ml-dsa-87
  - ecdsa-p256 (signing) → ml-dsa-44
  - ecdsa-p384 (signing) → ml-dsa-65
  - ecdsa-p521 (signing) → ml-dsa-87
  - ecdh-p256 (key-agreement) → ml-kem-512
  - ecdh-p384 (key-agreement) → ml-kem-768
  - ecdh-x25519 (key-agreement) → ml-kem-768
  - dh-* (key-agreement) → ml-kem-768
  - eddsa-ed25519 (signing) → ml-dsa-44
  - code-signing / firmware-signing → slh-dsa-sha2-128s (FIPS 205) regardless of source (stateless preferred for firmware)
- **Default target-date table**:
  - quantum-vulnerable + tls-server / tls-client → 2030-12-31 (ir-8547-deprecate-2030)
  - quantum-vulnerable + kms-key-wrap → 2030-12-31
  - quantum-vulnerable + kms-signing → 2030-12-31
  - quantum-vulnerable + code-signing / firmware-signing → 2030-06-30 (high-risk-tier)
  - quantum-vulnerable + ca-issuance → 2029-12-31 (long-lived cert chains; earlier)
  - quantum-vulnerable + ssh-host-key → 2031-12-31
  - quantum-vulnerable + jwt-signing → 2030-12-31
  - quantum-vulnerable + hsm-backed → 2032-12-31 (HSM firmware-replacement scope)
  - CNSA 2.0 opt-in → all of the above default to cnsa_2_0_target_date (default 2030-12-31)
- **OSCAL POA&M v1.1.2** — `poam-item.props[]` extension namespace `CE_NS = "https://cloud-evidence.example/oscal-ns"`. New prop names `pqc-asset-id`, `pqc-current-algorithm`, `pqc-target-algorithm`, `pqc-target-date`, `pqc-target-fips-standard`, `pqc-deadline-source`, `pqc-purpose`.
- **LOOP-B.B2 `DeadlineSource`** extended with `'pqc-target-date'`. Cascade order updated:
  1. operator-override
  2. KEV match
  3. PAIN/IRV/LEV
  4. **pqc-target-date** (for PQC POA&M items only)
  5. FedRAMP CMP table
  6. severity-fallback

## Build steps (concrete, numbered)
1. Define `PqcMigrationPlanEntry`, `MigrationStatus`, `TargetDateSource` types in `core/pqc-migration-plan.ts`.
2. Define `DEFAULT_TARGET_ALGORITHM` + `DEFAULT_TARGET_DATE` constants in `core/pqc-target-defaults.ts` matching the tables above. Docstring cites FIPS 203/204/205 + IR 8547 §4.2 + OMB M-23-02 §IV verbatim (post-PDF-download).
3. Pure builder `buildPqcMigrationPlan(inventory: CryptoInventoryEntry[], pqcConfig: PqcConfig, ownerSnapshot: PqcMigrationOwner[]) → PqcMigrationPlanEntry[]`:
   - For each quantum-vulnerable entry in R.R1 inventory: derive `target_algorithm` (operator override > default mapping > REQUIRES-OPERATOR-INPUT).
   - Derive `target_date` (operator override > default table > REQUIRES-OPERATOR-INPUT).
   - Derive `owner` (tracker snapshot > pqc-config > REQUIRES-OPERATOR-INPUT).
   - Derive `inheritance` from `pqc-config.yaml inheritance{}` block.
   - Derive `status` (see step 4).
   - Generate deterministic `uuid` from `sha256(asset_id|algorithm|purpose)[:16]`.
4. **Status derivation**:
   - `complete` — inventory contains a quantum-resistant-pqc entry for the same `(asset_id, purpose)` and the legacy is absent.
   - `pilot` — inventory contains BOTH the legacy + a quantum-resistant-pqc entry for the same `(asset_id, purpose)` (dual-key hybrid).
   - `planned` — operator config has a `migration_targets[].asset_id` matching, with target_date + target_algorithm + owner all populated.
   - `unplanned` — none of the above.
5. **Inheritance derivation**:
   - When operator declares `inheritance: { aws-kms: { upstream_target_date: 2028-12-31 } }` and the asset is an AWS KMS key, mark `inheritance.upstream_provider = 'aws-kms'`, `inheritance.upstream_target_date = '2028-12-31'`, `inheritance.blocked_by_upstream = true`.
   - When `blocked_by_upstream === true`, the entry's `target_date` inherits the upstream date (cannot migrate before the upstream supports the target algorithm).
6. **Unplanned-migration POA&M emission**:
   - Pure function `pqcEntriesToPoamItems(entries: PqcMigrationPlanEntry[], collected_at: string) → OscalPoamItem[]`:
     - One `poam-item` per `unplanned` entry.
     - Severity per band derivation.
     - Props per the schema table.
     - Deterministic `uuid` from `sha256("pqc-poam"|entry.uuid)[:16]`.
   - Pure function `pqcEntriesToOscalRisks(entries, collected_at)` producing matching `risk[]` blocks tied to the poam-items.
7. **Integration in `core/oscal-poam.ts:buildOscalPoam()`**:
   - Accept optional `pqc_unplanned_migrations[]` input.
   - Append generated poam-items + risks to the output.
   - LOOP-B.B1 risk scoring runs on them (composite formula treats them as Findings with structured props).
   - LOOP-B.B2 deadline engine reads the `pqc-target-date` prop and emits `deadline-source: 'pqc-target-date'`.
8. **DOCX emitter** in `core/pqc-migration-plan-docx.ts` — 8 sections per LOOP-R-SPEC.md §4.R2:
   1. Cover page (CSP name, system identifier, fiscal year, classification).
   2. Authority — OMB M-23-02 §IV + NSM-10 + IR 8547 §4.2 + CNSA 2.0 + FIPS 203/204/205 verbatim citations.
   3. Scope — inventory summary (count per purpose).
   4. Algorithm migration matrix — table of current × target per `algorithm × purpose` pair.
   5. Per-asset migration plan — one row per `PqcMigrationPlanEntry` with target algo, target date, owner, blockers, inheritance.
   6. Inheritance summary — table of upstream-provider × CSP-side asset count × inherited target date.
   7. POA&M cross-reference — list of unplanned-migration POA&M UUIDs.
   8. Sign-off block — operator name + date + tracker audit-log reference.
   Reuse OOXML helpers from `core/oscal-ssp-docx.ts`.
9. **JSON emitter**:
   ```ts
   interface PqcMigrationPlanJson {
     plan_id: string;
     fiscal_year: string;
     csp_name: string;
     system_id: string;
     generated_at: string;
     entries: PqcMigrationPlanEntry[];
     unplanned_poam_items: string[];   // poam-item uuids
     authority_citations: string[];    // verbatim from sources
     provenance: ProvenanceBlock;
   }
   ```
   Top-level `provenance` block per REO Rule 2.6.
10. **Strict mode**: `--strict-pqc` (shared with R.R1 + R.R3):
    - Exit non-zero if any `unplanned` entry has `target_date < now()`.
    - Exit non-zero if any `target_algorithm_source = 'REQUIRES-OPERATOR-INPUT'`.
    - Exit non-zero if any `owner_source = 'REQUIRES-OPERATOR-INPUT'` AND the operator opted into strict-pqc.
11. **Submission bundle**: both files included via new roles.
12. **Sign + timestamp**: both files flow through `core/sign.ts` glob.
13. Validation:
    - `npm run check:provenance` — verifies provenance block on `pqc-migration-plan.json`.
    - `npm run check:reo` G1+G2+G3.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4:

| Field | Source | Behavior when missing |
|---|---|---|
| `target_algorithm` | Default mapping > `pqc-config.yaml` algorithm_target_overrides > `migration_targets[].target_algorithm` | When default mapping has no entry (e.g. exotic algorithm), `target_algorithm_source: 'REQUIRES-OPERATOR-INPUT'`; visible in POA&M prop |
| `target_date` | Default table > `pqc-config.yaml` > `migration_targets[].target_date` | When default table has no entry, `target_date_source_field: 'REQUIRES-OPERATOR-INPUT'`; entry status forced to `unplanned` |
| `owner_user_id` / `owner_email` | Tracker `pqc_migration_owners` table (R.R3 schema) > `pqc-config.yaml migration_targets[].owner_email` | `owner_source: 'REQUIRES-OPERATOR-INPUT'`; status forced to `unplanned`; UI nag for operator action |
| `inheritance.upstream_target_date` | Operator-supplied via `pqc-config.yaml inheritance{}` | Default missing; entry computes target_date from CSP-side defaults |
| `blockers[]` | Operator-supplied via `pqc-config.yaml migration_targets[].blockers` | Defaults to `[]`; PQC POA&M item carries blockers in description |
| `cnsa_2_0` opt-in | `pqc-config.yaml cnsa_2_0: true` | Defaults to OMB / IR 8547 timeline; operator opts in for accelerated CNSA 2.0 dates |

## Test specifications (≥12 tests)
1. `it('emits one PqcMigrationPlanEntry per quantum-vulnerable R.R1 inventory row')`.
2. `it('skips quantum-resistant-pqc inventory rows')` — already-PQC assets don't need migration entries.
3. `it('maps rsa-2048 (kms-key-wrap) → ml-kem-768 (FIPS 203) by default')`.
4. `it('maps rsa-2048 (kms-signing) → ml-dsa-65 (FIPS 204) by default')`.
5. `it('maps rsa-4096 → ml-kem-1024 (cat 5) for key-wrap purpose')`.
6. `it('maps ecdsa-p384 → ml-dsa-65 by default for signing purpose')`.
7. `it('maps ecdh-p384 → ml-kem-768 by default for key-agreement purpose')`.
8. `it('maps code-signing → slh-dsa-sha2-128s (FIPS 205) regardless of source algorithm')`.
9. `it('respects pqc-config.yaml algorithm_target_overrides')`.
10. `it('respects pqc-config.yaml migration_targets[] per-asset overrides')`.
11. `it('defaults target_date to 2030-12-31 for tls-server purpose')`.
12. `it('defaults target_date to 2030-06-30 for code-signing purpose (high-risk)')`.
13. `it('defaults target_date to 2029-12-31 for ca-issuance (long-lived cert chains)')`.
14. `it('swaps to CNSA 2.0 timeline when pqc-config.yaml cnsa_2_0 true')`.
15. `it('marks status=complete when quantum-resistant-pqc entry exists for same asset_id + purpose')`.
16. `it('marks status=pilot when both legacy + quantum-resistant-pqc present for same asset')`.
17. `it('marks status=planned when migration_targets[] has matching entry with all fields')`.
18. `it('marks status=unplanned when no override and no PQC entry present')`.
19. `it('derives inheritance.upstream_target_date from pqc-config.yaml inheritance{}')`.
20. `it('propagates upstream_target_date to entry.target_date when blocked_by_upstream true')`.
21. `it('emits one unplanned-migration POA&M item per unplanned entry')`.
22. `it('derives POA&M severity=critical when target_date < now()')`.
23. `it('derives POA&M severity=high when target_date < now()+1y')`.
24. `it('derives POA&M severity=low when target_date >= now()+3y and < 2035')`.
25. `it('strict-pqc mode exits non-zero on past-due unplanned entry')`.
26. `it('strict-pqc mode exits non-zero on REQUIRES-OPERATOR-INPUT target_algorithm_source')`.
27. `it('writes pqc-migration-plan.docx with all 8 sections')`.
28. `it('writes pqc-migration-plan.json with provenance.emitter + sourceCalls')`.
29. `it('LOOP-B.B2 deadline-engine records source=pqc-target-date for PQC items')`.

## REO compliance
Per `cloud-evidence/CLAUDE.md`:
- **Rule 1.1** — every entry derives from a real R.R1 inventory row + operator config; no placeholder migration entries.
- **Rule 1.3** — algorithm tokens, target FIPS standard names come from the constants table citing FIPS publications; never hardcoded sample.
- **Rule 1.5** — when target_algorithm / target_date / owner cannot be derived, `*_source: 'REQUIRES-OPERATOR-INPUT'`; status forced to `unplanned`; POA&M item carries the marker.
- **Rule 1.6** — Ed25519 signatures + RFC 3161 timestamps via existing `core/sign.ts` infrastructure.
- **Rule 1.9** — every emit field has end-to-end implementation; schema does not exceed implementation.
- **Rule 2.1** — end-to-end flow: R.R1 inventory → R.R2 plan → POA&M emission → LOOP-B risk scoring + deadline math.
- **Rule 2.6** — provenance block on `pqc-migration-plan.json`; `check:provenance` green.
- **No fake POA&M items** — every POA&M item generated by R.R2 traces back to a real `PqcMigrationPlanEntry` with status=unplanned, which traces to a real R.R1 inventory row.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/pqc-migration-plan.test.ts tests/core/pqc-migration-plan-docx.test.ts tests/core/pqc-migration-plan-emit.test.ts tests/core/pqc-target-defaults.test.ts tests/core/oscal-poam.test.ts tests/core/deadline-engine.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues
- **Risk 1: Default algorithm-mapping table is opinionated.** A CSP may legitimately prefer SLH-DSA-128s over ML-DSA-44 for ECDSA-P256 (more conservative cryptanalytic assumption). Mitigation: `algorithm_target_overrides{}` lets operator force any token-to-token mapping; the entry's `target_algorithm_source = 'operator-override'` makes the override auditable.
- **Risk 2: Default target dates are derived from NIST IR 8547 IPD; finals may shift.** Mitigation: `pqc-target-defaults.ts` constant carries `ir_version = "8547-ipd-2024-11"`; when IR 8547 finalises, bump the constant and run CHANGELOG entry citing the shifts.
- **Risk 3: CNSA 2.0 binding scope is NSS-only; civilian CSP applying it could over-commit.** Mitigation: `cnsa_2_0` is opt-in; default OFF; the .docx Authority section notes the binding scope distinction.
- **Risk 4: Unplanned-migration POA&M items could swamp the existing POA&M.** A CSP with 500 RSA keys generates 500 PQC POA&M items. Mitigation: severity-band aggregation in LOOP-B.B5 risk register; UI surfaces "PQC migration" as a filter facet; ConMon monthly delta groups by `pqc-deadline-source` prop.
- **Risk 5: Inheritance-blocked entries with upstream_target_date past 2035 are noncompliant.** Mitigation: emit a separate POA&M item per blocked entry with severity=critical when upstream_target_date > 2035; operator must either switch vendors or accept residual risk via LOOP-B.B3.
- **Risk 6: LOOP-B.B2 deadline-engine cascade order may surprise — KEV match wins over pqc-target-date.** Mitigation: documented in `core/deadline-engine.ts`; tests pin the order; CHANGELOG entry calls it out.
- **Risk 7: Hybrid TLS suites (X25519MLKEM768) classification ambiguous.** Mitigation: R.R1 classifies as `quantum-resistant-pqc-hybrid`; R.R2 treats as status=`pilot` by default; operator can override to `complete` if their policy considers hybrid sufficient.
- **Risk 8: Code-signing → SLH-DSA mapping locks in slow signatures (SLH-DSA-128s ~ 8KB).** Mitigation: operator can override to ML-DSA when signature size matters more than stateless-ness; runbook documents.
- **Risk 9: Owner assignment depends on R.R3 tracker tables; R.R2 ships before R.R3 ships.** Mitigation: R.R2 reads `pqc-config.yaml migration_targets[].owner_email` as fallback; tracker integration is additive; `owner_source: 'REQUIRES-OPERATOR-INPUT'` marker is visible.

## Open questions (for implementation session to resolve)
- **Q1**: Should an inheritance-blocked entry whose upstream_target_date is 2031 (after our default 2030) inherit 2031 or stay at 2030 and surface as critical? Recommend: inherit 2031; surface as `high` severity because the CSP is structurally blocked.
- **Q2**: Should the .docx render a per-asset row when the inventory has > 500 unplanned entries (file becomes unwieldy)? Recommend: render up to 500; for overflow, render summary count + link to `pqc-migration-plan.xlsx` (future enhancement) or to the JSON twin.
- **Q3**: Do we accept user-supplied `target_algorithm` that is not in the canonical `QUANTUM_CLASSIFICATION` table (operator's in-house PQC scheme)? Recommend: yes but warn; `target_algorithm_source = 'operator-override'` + entry records the unknown token verbatim.
- **Q4**: When status moves from `unplanned` to `planned` (via operator config), should the POA&M item move to `risk.status = 'remediating'`? Recommend: yes; existing OSCAL POA&M status-transition logic handles it.
- **Q5**: Should the migration plan be re-emitted automatically every run, or only on `--pqc-migration-plan` flag? Recommend: only on flag; CHANGELOG documents.
- **Q6**: Where does the operator declare "asset X is exempt from PQC migration" (e.g. internal test fleet)? Recommend: `pqc-config.yaml exemptions[]` block; entries with matching asset_id are filtered out at builder time with a documented `exemption_reason`.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥29 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] check:provenance green for `pqc-migration-plan.json`
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-R-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>, last_updated=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (cites FIPS 203/204/205 + IR 8547 §4.2 + OMB M-23-02 §IV)
- [ ] Commit with slice ID `R.R2` in message
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-R-SPEC.md` §2 (Dependencies) + §3 (Authoritative sources) + §4.R2 for cross-loop context.
4. Read `cloud-evidence/docs/loops/LOOP-R-RISKS.md` cross-cutting section.
5. Read `cloud-evidence/docs/slices/R/R.R1.md` — your input substrate.
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
7. Read `cloud-evidence/core/oscal-poam.ts` end-to-end — your POA&M emission path is the existing `buildOscalPoam()` extended with `pqc_unplanned_migrations` input.
8. Read `cloud-evidence/core/deadline-engine.ts` (LOOP-B.B2) — your `DeadlineSource` extension adds `'pqc-target-date'`.
9. Read `cloud-evidence/core/oscal-ssp-docx.ts` for the OOXML pattern your `pqc-migration-plan-docx.ts` mirrors.
10. Read `cloud-evidence/core/submission-bundle.ts` `WELL_KNOWN` — add two new entries.
11. Confirm the four PDFs (OMB M-23-02, IR 8547 IPD, CNSA 2.0, FIPS 203/204/205) are in `cloud-evidence/docs/sources/` — R.R1 ships should have placed them; if not, download before §3 docstring citations.
12. Begin implementation; update Implementation log section as you go.

---
