---
slice_id: J.J3
title: Supply chain risk register (SR-3) + SBOM integration
loop: J
status: done
commit: a635da4
completed_date: 2026-06-11
depends_on: [A.A1, A.A4, J.J2, SSP-1, INV-P4, E.2-SBOM-depth]
blocks: [B.B5, C.C7, I.I1]
estimated_effort: 1.25 weeks (6-7 working days)
last_updated: 2026-06-11
---

# J.J3 — Supply chain risk register (SR-3) + SBOM integration

## TL;DR
Emits a signed `supply-chain-risk-register.json` + multi-sheet
`supply-chain-risk-register.xlsx` that joins SBOM-derived CVEs (from
`core/sbom.ts`), CISA KEV exposure (from `core/kev-feed.ts`), subprocessor
risk-tier data (from J.J2), and operator-asserted advisory events into a
single per-system C-SCRM Plan artifact — the NIST SP 800-53 Rev 5 SR-3
"supply chain processes and controls" document and the NIST SP 800-161r1
Tier-3 supplier-risk register. The register's open critical/high entries
also flow back as POA&M `risk-source = supply-chain` items.

## Status
- Status: done
- Commit: `a635da4` (filled by the two-pass close-out)
- Date: 2026-06-11
- Verification: typecheck=0 errors, tests=1004 passing (+20), check:reo=green (G1 ✓ / G2 skip-no-out / G3 ✓)

## Why this slice exists
NIST SP 800-53 Rev 5 SR-3 mandates a documented process to "identify and
address weaknesses or deficiencies in the supply chain elements and
processes" of the system, AND to "document the selected and implemented
supply chain processes and controls" in a security plan, supply-chain
risk management plan, or other designated document. NIST SP 800-161 Rev 1
elevates this expectation into a per-system C-SCRM plan (Tier 3 in the
publication's three-tier C-SCRM hierarchy) that includes a
supplier-risk register, continuous supplier monitoring, and incident
response coordination across the supply chain.

Today the cloud-evidence codebase has the raw inputs — `core/sbom.ts`
produces a per-image SbomReport with components + vulnerabilities;
`core/kev-feed.ts` ingests the CISA Known Exploited Vulnerabilities
catalog; `core/subprocessors-sheet.ts` (and J.J2's
`core/subprocessor-inventory.ts`) produce the SA-9 subprocessor inventory
— but there is no register that joins them into the single SR-3 artifact a
3PAO uses as evidence of C-SCRM implementation. 3PAOs currently ask for
this register as a separate hand-authored spreadsheet, which is stale by
the time it lands and impossible to verify against signed evidence.

J.J3 closes the gap by emitting the register as a deterministic,
provenance-tagged, signed artifact that:
1. Walks the real SbomReport.vulnerabilities[] for each ingested SBOM.
2. Cross-references each CVE id against the loaded CISA KEV catalog and
   bumps severity to `critical` plus stamps the CISA-published due-date
   when matched.
3. Walks the J.J2 SubprocessorInventory and emits tier-1-critical
   subprocessor entries plus SOC2-attestation-expired entries.
4. Flags any SBOM whose cosign verification did not succeed.
5. Merges operator-asserted free-form risks from a `--risks-config` YAML.
6. Computes coverage (open-critical / open-high / open-medium / open-low
   / kev-exposed / unsigned-sboms / tier-1-critical subprocessor counts
   + entries-missing-mitigation list).
7. Stamps a per-SBOM `sbom_provenance[]` block whose seven flags mirror
   the NTIA SBOM Minimum Elements (per EO 14028 §4(f), July 12 2021).
8. Feeds open critical+high entries into the existing POA&M emitter
   under `props: [{ name: 'risk-source', value: 'supply-chain' }]` with
   the FedRAMP deadline math anchored at `RiskEntry.first_seen`.

The register is signed by the existing `core/sign.ts` pipeline and
bundled by `core/submission-bundle.ts` into the submission tarball as
two artifacts (`.json` + `.xlsx`).

## Authoritative sources (with verbatim quotes)

- **NIST SP 800-53 Rev 5 §SR-3.a (Supply Chain Controls and Processes)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  — p. 280:
  > "Establish a process or processes to identify and address weaknesses
  > or deficiencies in the supply chain elements and processes of
  > [Assignment: organization-defined system or system component] in
  > coordination with [Assignment: organization-defined supply chain
  > personnel]."

- **NIST SP 800-53 Rev 5 §SR-3.b** — same PDF, p. 280:
  > "Employ the following controls to protect against supply chain risks
  > to the system, system component, or system service and to limit the
  > harm or consequences from supply chain related events: [Assignment:
  > organization-defined supply chain controls]."

- **NIST SP 800-53 Rev 5 §SR-3.c** — same PDF, p. 280:
  > "Document the selected and implemented supply chain processes and
  > controls in [Selection (one or more): security and privacy plans;
  > supply chain risk management plan; [Assignment: organization-defined
  > document]]."

- **NIST SP 800-53 Rev 5 §SR-3 Discussion** — same PDF, p. 280:
  > Supply chain elements "encompass organizations, entities, and tools
  > involved in research, development, manufacturing, acquisition,
  > delivery, operations, and disposal of systems."

- **NIST SP 800-53 Rev 5 §SR-4 (Provenance)** — same PDF, p. 281:
  > "Document, monitor, and maintain valid provenance of the following
  > systems, system components, and associated data: [Assignment:
  > organization-defined systems, system components, and associated
  > data]."

- **NIST SP 800-53 Rev 5 §SR-5 (Acquisition Strategies, Tools, and
  Methods)** — same PDF, p. 282:
  > "Employ the following acquisition strategies, contract tools, and
  > procurement methods to protect against, identify, and mitigate
  > supply chain risks: [Assignment: organization-defined acquisition
  > strategies, contract tools, and procurement methods]."

- **NIST SP 800-53 Rev 5 §SR-6 (Supplier Assessments and Reviews)** —
  same PDF, p. 283:
  > "Assess and review the supply chain-related risks associated with
  > suppliers or contractors and the system, system component, or system
  > service they provide [Assignment: organization-defined frequency]."

- **NIST SP 800-161 Rev 1 §1.5 (C-SCRM Document Set)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1.pdf
  — pp. 12-14:
  > "Organizations should establish a C-SCRM Strategy, a C-SCRM
  > Implementation Plan, and a C-SCRM Policy. … At the system level,
  > organizations document a C-SCRM Plan that addresses supply chain
  > risk management activities pertaining to a specific system or
  > information resource."

- **NIST SP 800-161 Rev 1 §2.3.5 (System-Level C-SCRM Plan)** — same
  PDF, p. 32:
  > "The Tier 3 (system level) is concerned with risk management
  > activities at the information system level. … System-level C-SCRM
  > Plans should be developed and implemented to address the supply
  > chain risks specific to systems and the operating environments in
  > which they reside."

- **NTIA "The Minimum Elements For a Software Bill of Materials (SBOM)"
  (July 12, 2021, per Executive Order 14028 §4(f))** —
  https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report.pdf
  — pp. 8-11, the seven required baseline component data fields:
  > "1. Supplier Name — The name of an entity that creates, defines, and
  > identifies components. 2. Component Name — Designation assigned to a
  > unit of software defined by the original supplier. 3. Version of the
  > Component — Identifier used by the supplier to specify a change in
  > software from a previously identified version. 4. Other Unique
  > Identifiers — Other identifiers that are used to identify a
  > component, or serve as a look-up key for relevant databases. 5.
  > Dependency Relationship — Characterizing the relationship that an
  > upstream component X is included in software Y. 6. Author of SBOM
  > Data — The name of the entity that creates the SBOM data for this
  > component. 7. Timestamp — Record of the date and time of the SBOM
  > data assembly."

- **CISA SBOM program page** — https://www.cisa.gov/sbom:
  > "A Software Bill of Materials (SBOM) has emerged as a key building
  > block in software security and software supply chain risk
  > management."

- **CISA Known Exploited Vulnerabilities (KEV) Catalog** —
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog:
  > "CISA strongly recommends all organizations review and monitor the
  > KEV catalog and prioritize remediation of the listed vulnerabilities
  > to reduce the likelihood of compromise by known threat actors."

- **CISA KEV CSV/JSON feed (canonical machine-readable)** —
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  — schema includes `cveID`, `vendorProject`, `product`,
  `vulnerabilityName`, `dateAdded`, `shortDescription`,
  `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`. The
  register reads `dueDate` for `kev_due_date`.

- **CycloneDX 1.5 JSON specification** — https://cyclonedx.org/docs/1.5/json/
  — top-level required fields: `bomFormat` (`"CycloneDX"` literal) +
  `specVersion` (`"1.5"`). Optional: `serialNumber`, `version`,
  `metadata`, `components`, `services`, `dependencies`,
  `vulnerabilities`, `externalReferences`, `properties`. Root level
  enforces `additionalProperties: false`.

- **CycloneDX 1.5 JSON Schema (canonical)** —
  https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json
  — used at parse-time validation in `core/sbom.ts`.

- **SPDX 2.3 specification** — https://spdx.github.io/spdx-spec/v2.3/ —
  fallback SBOM format; J.J3 surfaces `format: 'spdx'` in
  `sbom_provenance[]`.

- **FedRAMP Rev 5 templates index** — https://www.fedramp.gov/docs/rev5/templates/
  — the RMS (Risk Management Strategy) document (LOOP-C.C7) consumes
  J.J3 output for its "supply chain risks" section.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/supply-chain-risk.ts`
  — pure builder + disk emitter. ~550 lines. Exports
  `buildSupplyChainRiskRegister(input, opts): SupplyChainRiskRegister`,
  `emitSupplyChainRiskRegister(opts): SupplyChainRiskRegisterEmitResult`,
  `readRisksConfig(path: string): OperatorRiskEntry[]`, and types
  `RiskCategory`, `RiskEntry`, `OperatorRiskEntry`, `RegisterCoverage`,
  `SbomProvenance`, `SubprocessorSummary`, `SupplyChainRiskRegister`,
  `SupplyChainRiskRegisterEmitOptions`,
  `SupplyChainRiskRegisterEmitResult`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/supply-chain-risk.test.ts`
  — ≥15 tests covering the contracts below.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/supply-chain-risk/sbom-report.fixture.json`
  — fixture SbomReport with two SBOM files (one CycloneDX, one SPDX),
  three components, three vulnerabilities, one with `signature_status =
  unverified`. One CVE id matches a fixture KEV row.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/supply-chain-risk/subprocessor-inventory.fixture.json`
  — fixture with one tier-1-critical row, one tier-3-routine row, and
  one row with `soc2_expiry` past `opts.now`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/supply-chain-risk/kev-catalog.fixture.json`
  — three KEV entries matching the SBOM fixture's CVE ids in part.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/supply-chain-risk/risks-config.example.yaml`
  — operator config fixture with one `operator-asserted-risk` and one
  mitigation override.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/examples/risks-config.yaml`
  — committed example operator config (under `examples/`, REO-allowed
  per Rule 3).

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — add `--supply-chain-risk` flag + `CLOUD_EVIDENCE_SUPPLY_CHAIN_RISK=1`
  env. Add `--risks-config <path>` + `CLOUD_EVIDENCE_RISKS_CONFIG` env.
  Schedule AFTER `--collect`, AFTER `--sbom-dir`, AFTER
  `--subprocessors` / `--subprocessors-config`, AFTER `--privileges-matrix`,
  and BEFORE `--sign` (so the register is covered by the manifest) and
  BEFORE `--submission-bundle`. Console line on completion:
  `supply-chain-risk: <N> entries · <O> open · <C> critical · <K> kev-exposed · <X> REQUIRES-OPERATOR-INPUT`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — extend the `Role` union with `'supply-chain-risk-register-json'` and
  `'supply-chain-risk-register-xlsx'`. Append two WELL_KNOWN entries:
  - `{ role: 'supply-chain-risk-register-json', filename: 'supply-chain-risk-register.json', description: 'SR-3 / NIST SP 800-161r1 supply chain risk register (per-system C-SCRM Plan)' }`
  - `{ role: 'supply-chain-risk-register-xlsx', filename: 'supply-chain-risk-register.xlsx', description: 'Supply chain risk register — FedRAMP-style Excel (one sheet per category)' }`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts`
  — additive change. After walking per-KSI findings, if
  `out/supply-chain-risk-register.json` exists, walk
  `entries[]` filtered to `status === 'open'` AND
  `severity in {critical, high}`. For each such entry, emit a
  `poam-item` with:
    - `uuid = deterministicUuid('poam:item:supply-chain:' + entry.id)`
    - `title = entry.title`
    - `description = entry.description`
    - `props = [{ name: 'risk-source', value: 'supply-chain' }, { name: 'severity', value: entry.severity }, { name: 'category', value: entry.category }]`
    - `remediation-tracking.remediation-tracking-entries[].date-time-stamp = entry.first_seen`
    - Deadline math: Critical = first_seen + 30 days; High = first_seen +
      60 days (existing FedRAMP cadence used by the emitter, but anchored
      at first_seen NOT run timestamp).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts`
  — when `out/supply-chain-risk-register.json` exists, add a
  `back-matter.resources[]` entry titled
  `"Supply Chain Risk Register (SR-3, NIST SP 800-161r1)"` with
  `rlinks[]` pointing at the `.json` and `.xlsx`. If absent, no change.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-workbook.ts`
  — uses the multi-sheet `rowsToXlsx({ sheets })` extension that J.J1
  introduces; J.J3 is a consumer, not an extender (the sub-task lives in
  J.J1).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sbom.ts`
  — no schema change; J.J3 calls `buildSbomReport()` if not already run
  OR reads `out/sbom-report.json` if it has. Add a tiny helper
  `loadSbomReport(path: string): SbomReport` if not present.

## Schemas / standards

### SR-3 + SR-4 + SR-6 → register field mapping

| Requirement | Register field | REQUIRES-OPERATOR-INPUT when |
|---|---|---|
| SR-3.a (identify weaknesses) | every `RiskEntry` (the act of emitting a register satisfies SR-3.a) | n/a |
| SR-3.b (employ controls) | `RiskEntry.mitigation_summary` | absent and `status !== 'open'` |
| SR-3.c (document) | the artifact itself + SSP back-matter rlink | n/a |
| SR-4 (provenance) | `sbom_provenance[]` per-SBOM block | a flag is `false` (NTIA minimum-element missing); recorded but not a hard fail |
| SR-6 (supplier assessments) | `subprocessor_summary` block | n/a (counts roll up J.J2 data) |

### NTIA SBOM minimum-element flags → register

Each ingested SBOM produces one `sbom_provenance[]` entry with the seven
required NTIA baseline fields as boolean flags. The flags are computed
from the actual parsed SBOM payload, NEVER assumed true:

| NTIA element | CycloneDX 1.5 path | SPDX 2.3 path |
|---|---|---|
| Supplier Name | `components[].supplier.name` | `Packages[].PackageSupplier` |
| Component Name | `components[].name` | `Packages[].PackageName` |
| Version of the Component | `components[].version` | `Packages[].PackageVersion` |
| Other Unique Identifiers | `components[].purl` OR `components[].cpe` OR `components[].swid` | `Packages[].ExternalRefs[].ReferenceCategory == 'PACKAGE-MANAGER'` |
| Dependency Relationship | `dependencies[]` | `Relationships[].relationshipType == 'DEPENDS_ON'` |
| Author of SBOM Data | `metadata.authors[]` OR `metadata.manufacture` | `CreationInfo.Creators[]` |
| Timestamp | `metadata.timestamp` | `CreationInfo.Created` |

### CISA KEV → RiskEntry

| KEV CSV column | RiskEntry field |
|---|---|
| `cveID` | first entry in `cve_ids[]` (others retained too) |
| `dateAdded` | `RiskEntry.first_seen` (when KEV is the source of discovery) |
| `dueDate` | `kev_due_date` (verbatim) |
| `vulnerabilityName` + `shortDescription` | composed into `title` + `description` |

### CycloneDX 1.5 top-level field validation
Per https://cyclonedx.org/docs/1.5/json/ : `bomFormat === 'CycloneDX'`
(string-literal), `specVersion === '1.5'`. Root enforces
`additionalProperties: false`. J.J3 itself does not run ajv validation
on SBOMs (`core/sbom.ts` already does); but it MUST refuse to accept
an SbomFile whose `format` field is neither `'cyclonedx'` nor `'spdx'`.

### Multi-sheet XLSX layout

One sheet per `RiskCategory`, one summary sheet, plus a per-SBOM
provenance sheet:

| Sheet name | Rows |
|---|---|
| `Summary` | the `coverage` block (one row per metric) |
| `SBOM-CVE` | one row per `entries[]` where `category === 'sbom-cve'` |
| `SBOM-CVE-KEV` | one row per `entries[]` where `category === 'sbom-cve-kev'` (the KEV-prioritized list) |
| `Subprocessor-Risk` | one row per `entries[]` where category in `subprocessor-risk-tier`/`subprocessor-soc2-expired` |
| `Unsigned-SBOM` | one row per `entries[]` where `category === 'unsigned-sbom'` |
| `Vendor-Advisory` | one row per `entries[]` where `category === 'vendor-advisory'` |
| `Operator-Asserted` | one row per `entries[]` where `category === 'operator-asserted-risk'` |
| `SBOM-Provenance` | one row per `sbom_provenance[]` entry; columns are the seven NTIA-element flags + signature_status |

### Operator risks-config YAML schema (committed in file header)
```yaml
# examples/risks-config.yaml
risks:
  - id: vendor-advisory-2026-cve-12345
    category: vendor-advisory
    title: "Vendor X advisory CVE-2026-12345"
    description: "Upstream advisory not yet reflected in NVD."
    severity: high
    status: monitoring
    affected_components: ["lib-x@1.2.3"]
    mitigation_summary: "Pinned to 1.2.4 in CI pipeline."
    first_seen: 2026-05-01
    related_nist_controls: ["sr-3", "sr-6", "si-2"]
mitigations:
  - entry_id_match: "sbom-cve-kev:CVE-2026-99999"
    mitigation_summary: "Patched in image rebuild 2026-05-15."
    status: mitigated
```

## Build steps (concrete, numbered)

1. **Define interfaces** in `core/supply-chain-risk.ts`:
   ```ts
   export type RiskCategory =
     | 'sbom-cve'
     | 'sbom-cve-kev'
     | 'subprocessor-risk-tier'
     | 'subprocessor-soc2-expired'
     | 'unsigned-sbom'
     | 'vendor-advisory'
     | 'operator-asserted-risk';
   export interface RiskEntry {
     id: string;                         // deterministicUuid(`scrr:${category}:${stable-key}`)
     category: RiskCategory;
     title: string;
     description: string;
     severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
     status: 'open' | 'monitoring' | 'mitigated' | 'accepted';
     affected_components?: string[];     // 'name@version' when SBOM-derived
     affected_subprocessors?: string[];  // name when subprocessor-derived
     cve_ids?: string[];
     kev_due_date?: string;              // CISA-published due date
     mitigation_summary?: string;        // TBD when status != open and absent
     evidence_source: { module: string; record_id?: string };
     first_seen: string;                 // ISO 8601 date
     last_seen: string;                  // ISO 8601 date
     related_nist_controls: string[];    // ['sr-3','sr-4',...]
   }
   export interface SbomProvenance {
     sbom_file: string;
     format: 'cyclonedx' | 'spdx';
     supplier_name_field_present: boolean;
     component_name_field_present: boolean;
     version_field_present: boolean;
     unique_identifier_field_present: boolean;
     dependency_field_present: boolean;
     author_field_present: boolean;
     timestamp_field_present: boolean;
     signature_status: 'verified' | 'unverified' | 'absent';
   }
   export interface RegisterCoverage {
     total_entries: number;
     open_critical: number;
     open_high: number;
     open_medium: number;
     open_low: number;
     kev_exposed: number;
     unsigned_sboms: number;
     tier_1_critical_subprocessors: number;
     entries_missing_mitigation: string[];
   }
   export interface SubprocessorSummary {
     total: number;
     tier_1_critical: number;
     tier_2_significant: number;
     tier_3_routine: number;
     missing_risk_tier: number;
   }
   export interface SupplyChainRiskRegister {
     generated_at: string;
     system_id?: string;
     run_id: string;
     entries: RiskEntry[];
     coverage: RegisterCoverage;
     sbom_provenance: SbomProvenance[];
     subprocessor_summary: SubprocessorSummary;
     provenance: {
       emitter: 'core/supply-chain-risk.ts';
       emitted_at: string;
       source_modules: string[];
       source_files: string[];
     };
   }
   export interface OperatorRiskEntry {
     id?: string;
     category?: RiskCategory;
     title: string;
     description?: string;
     severity?: RiskEntry['severity'];
     status?: RiskEntry['status'];
     affected_components?: string[];
     affected_subprocessors?: string[];
     mitigation_summary?: string;
     first_seen?: string;
     related_nist_controls?: string[];
   }
   ```

2. **Pure builder** `buildSupplyChainRiskRegister(input, opts)`:
   - Inputs: `sbomReport: SbomReport | null`,
     `subprocessorInventory: SubprocessorInventory | null`,
     `kevCatalog: KevEntry[]`, `operatorRisks?: OperatorRiskEntry[]`.
   - Opts: `runId`, `systemId?`, `now?: () => Date` (default
     `() => new Date()`).
   - Walk `sbomReport.vulnerabilities[]` → one `RiskEntry` per CVE.
     - Severity: `sbomReport`'s `severity` field (already normalized
       from NVD by `core/sbom.ts`). `UNKNOWN` → `medium` + record
       `requires_operator_input` marker on that entry's severity (do
       not silently default to `low`).
     - If CVE id is in `kevCatalog` (Set lookup) → category becomes
       `sbom-cve-kev`; severity bumps to `critical` (KEV elevation per
       CISA guidance); `kev_due_date = kevEntry.dueDate`.
   - Walk `sbomReport.sboms[]` → for each with `signature_status !==
     'verified'`, emit `unsigned-sbom` (severity `medium`,
     status `open`).
   - Walk `subprocessorInventory.rows[]`:
     - Each `risk_tier === 'tier-1-critical'` → `subprocessor-risk-tier`
       entry (severity `high`, status `open`).
     - Each row with `soc2_expiry` past `opts.now()` →
       `subprocessor-soc2-expired` (severity `medium`, status `open`).
   - Merge `operatorRisks[]`:
     - Each entry is its own `RiskEntry` with
       `category = 'operator-asserted-risk'` (unless overridden).
     - Entries whose `id` matches an existing entry → operator block can
       override `status` + `mitigation_summary` only (other fields are
       evidence-derived and immutable).
   - Compute `coverage`:
     - `open_critical/high/medium/low` counts.
     - `kev_exposed` = `entries.filter(e => e.category === 'sbom-cve-kev').length`.
     - `unsigned_sboms` = unique `affected SBOM file` count.
     - `tier_1_critical_subprocessors` = subprocessor entries with
       `affected_subprocessors[]` present.
     - `entries_missing_mitigation` = entries where `status !== 'open'`
       AND `!mitigation_summary` (so an "accepted" risk without a
       documented justification fails the gate).
   - Compute `sbom_provenance[]`: for each `sbomReport.sboms[]`, parse
     the on-disk SBOM file (CycloneDX or SPDX) and compute the seven
     NTIA-element flags via the path tables above.
   - Compute `subprocessor_summary` directly from inventory counts.
   - Sort `entries[]` by `(category, severity, id)` deterministically.
   - Stamp `provenance.source_modules[]` with the modules actually used
     (`'core/sbom.ts'`, `'core/kev-feed.ts'`,
     `'core/subprocessor-inventory.ts'`, `'core/supply-chain-risk.ts'`).
   - Stamp `provenance.source_files[]` with the real files on disk.

3. **Operator-config reader** `readRisksConfig(path: string)`:
   - YAML/JSON. YAML parsed via the `yaml` package (introduced in J.J2
     if not present). Reject unknown top-level keys.
   - Validate each `OperatorRiskEntry`:
     - `title` required (string).
     - `severity` if present must be in the enum.
     - `status` if present must be in the enum.
     - `first_seen` if present must be ISO 8601 date (regex).
   - Apply `mitigations[]` post-pass: each `entry_id_match` overrides
     the matching entry's `mitigation_summary` + `status`.

4. **Disk emitter** `emitSupplyChainRiskRegister(opts)`:
   - Read `outDir/sbom-report.json` if present; if absent, run
     `buildSbomReport({sbomDir: opts.sbomDir})` when `sbomDir` provided.
   - Read `outDir/subprocessor-inventory.json` if present.
   - Read `kevCatalogPath` (default `docs/cisa-kev.generated.json`) via
     `loadKevCatalog`.
   - Read `risksConfigPath` if provided.
   - If ALL FOUR sources are empty (no SBOM, no subprocessor, no KEV
     match, no operator config) → throw a typed error
     `Error('supply-chain-risk: no source data available; rerun with at least one of --sbom-dir / --subprocessors-config / --risks-config / docs/cisa-kev.generated.json present')`.
     Never emit a bare register.
   - Write `outDir/supply-chain-risk-register.json` (deterministic, sorted
     JSON via existing repo serialization helper).
   - Write `outDir/supply-chain-risk-register.xlsx` via the multi-sheet
     `rowsToXlsx({ sheets })` extended writer.

5. **Wire into orchestrator** (`core/orchestrator.ts`):
   - Parse the two new flags + envs.
   - Schedule order:
     1. `--collect ...`
     2. `--sbom-dir`
     3. `--privileges-matrix` (J.J1)
     4. `--subprocessors` / `--subprocessors-config` (J.J2)
     5. `--supply-chain-risk` ← J.J3 runs here
     6. OSCAL emitters (`--oscal-ssp`, `--oscal-ap`, `--oscal-poam`)
        — POA&M reads the register file written by step 5.
     7. `--sign` ← matrix + inventory + register all signed together.
     8. `--submission-bundle`
   - Log line on completion.

6. **POA&M wiring** (`core/oscal-poam.ts`):
   - After walking per-KSI findings, attempt
     `readFileSync(opts.outDir + '/supply-chain-risk-register.json')`.
     If parse succeeds → walk `register.entries[]` filtered to
     `status === 'open'` AND `severity in {critical, high}`.
   - For each emit one `poam-item` per the schema described in the
     "Files to extend" entry for `core/oscal-poam.ts`. Critical → 30-day
     deadline anchored at `entry.first_seen`; High → 60-day deadline
     same anchor.
   - Dedup by `entry.id` (deterministic uuid prevents double-emission
     across runs).

7. **SSP back-matter wiring** (`core/oscal-ssp.ts`):
   - On `buildOscalSsp` entry, attempt `readFileSync(outDir +
     '/supply-chain-risk-register.json')`. If present, add a
     `back-matter.resources[]` entry with title
     `"Supply Chain Risk Register (SR-3, NIST SP 800-161r1)"` and
     `rlinks[]` pointing at the `.json` + `.xlsx`. Dedup by title +
     rlink href.

8. **Bundler catalogue** (`core/submission-bundle.ts`):
   - Add the two WELL_KNOWN entries listed in "Files to extend".
   - The bundler picks up both files automatically via the manifest scan.

9. **Validation pass**:
   - Inline TS guards on every `RiskEntry` construction.
   - No ajv schema (artifact is not OSCAL); structural checks live in
     `tests/core/supply-chain-risk.test.ts`.
   - Verify `kev_due_date` parses as ISO 8601 when present.
   - Verify `first_seen <= last_seen` for every entry.

10. **Signing + timestamping**: already covered by the existing
    `core/sign.ts` pipeline because the emitter runs before `--sign`.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Fallback behavior |
|---|---|---|
| `RiskEntry.mitigation_summary` (when `status !== 'open'`) | `--risks-config` YAML `mitigations[].mitigation_summary` OR tracker UI (LOOP-B.B3) | `REQUIRES-OPERATOR-INPUT` literal in XLSX; entry id added to `coverage.entries_missing_mitigation` |
| `RiskEntry.severity` for SBOM CVEs with NVD severity `UNKNOWN` | `--risks-config` YAML | `medium` mapped + entry id added to `requires_operator_input` (severity defaulting is NEVER silent) |
| Operator-asserted risks (whole entries) | `--risks-config` YAML | not emitted (the partition is simply empty); no stub |
| `Role`-level vendor-advisory entries | `--risks-config` YAML `risks[]` with `category: vendor-advisory` | not emitted; no stub |

The literal is `'REQUIRES-OPERATOR-INPUT'` (define `const TBD =
'REQUIRES-OPERATOR-INPUT'` at the top, matching `core/roe-emit.ts` /
`core/privileges-matrix.ts` precedent).

## Test specifications (≥15 tests)

1. `it('builds a register from a real CycloneDX SBOM report + KEV catalog')`
   — fixtures contain two SBOMs and a KEV catalog where one CVE id
   matches. Assert: one entry with `category === 'sbom-cve-kev'` and
   `severity === 'critical'` and `kev_due_date` is the verbatim CISA
   `dueDate`.
2. `it('emits one unsigned-sbom entry per unverified SBOM file')` —
   fixture with two SBOMs, one with `signature_status === 'unverified'`,
   one `'verified'` → assert exactly one `unsigned-sbom` entry, severity
   `medium`, status `open`.
3. `it('emits subprocessor-risk-tier entries for tier-1-critical subprocessors')`
   — fixture inventory has one tier-1 row + one tier-3 row → assert
   exactly one `subprocessor-risk-tier` entry; `affected_subprocessors`
   names the tier-1 row.
4. `it('emits subprocessor-soc2-expired entries when soc2_expiry is past opts.now')`
   — fixture row `soc2_expiry: '2024-01-01'` with `opts.now = () => new
   Date('2026-06-06')` → assert one `subprocessor-soc2-expired` entry.
5. `it('uses CISA KEV published due-date as kev_due_date')` — assert
   register entry `kev_due_date` matches fixture KEV `dueDate` verbatim.
6. `it('merges operator-asserted-risk entries from --risks-config YAML')`
   — fixture YAML contributes one entry; assert it appears in
   `entries[]` with `category === 'operator-asserted-risk'`.
7. `it('computes coverage.kev_exposed correctly')` — two KEV entries in
   register → `coverage.kev_exposed === 2`.
8. `it('emits REQUIRES-OPERATOR-INPUT in mitigation_summary when status != open and no operator input')`
   — entry with `status: accepted`, no operator mitigation → register
   shows literal `'REQUIRES-OPERATOR-INPUT'` and entry id is in
   `coverage.entries_missing_mitigation`.
9. `it('produces deterministic uuids for the same input set')` — run
   twice with identical inputs → sha256 of
   `supply-chain-risk-register.json` matches byte-for-byte.
10. `it('records sbom_provenance with NTIA minimum-element flags per ingested SBOM')`
    — fixture CycloneDX SBOM missing `metadata.timestamp` → assert
    `sbom_provenance[0].timestamp_field_present === false`; everything
    else true. Verify the seven flags individually.
11. `it('throws a typed error when sbomReport AND subprocessorInventory AND operatorRisks are all empty')`
    — empty inputs → emitter throws Error whose message includes
    `--sbom-dir`, `--subprocessors-config`, and `--risks-config`.
12. `it('records provenance.source_modules listing exactly the modules read')`
    — assert `provenance.source_modules` includes `'core/sbom.ts'` and
    `'core/kev-feed.ts'` and `'core/subprocessor-inventory.ts'` (the
    modules actually consulted) and EXCLUDES any module not consulted.
13. `it('emits POA&M items for open critical/high entries when --oscal-poam runs in same pipeline')`
    — integration: emit register → emit POA&M → parse POA&M JSON → assert
    at least one `poam-item` has `props.find(p => p.name === 'risk-source').value === 'supply-chain'`.
14. `it('uses RiskEntry.first_seen as POA&M deadline anchor, not run timestamp')`
    — fixture `first_seen: '2026-04-01'` for a critical entry → assert
    POA&M deadline = 2026-04-01 + 30 days = `'2026-05-01'`, NOT the run
    timestamp + 30.
15. `it('writes XLSX with one sheet per RiskCategory plus Summary + SBOM-Provenance')`
    — parse the emitted .xlsx as zip; assert
    `xl/worksheets/sheet1.xml … sheetN.xml` parts exist and sheet names
    in the workbook are exactly: `Summary`, `SBOM-CVE`, `SBOM-CVE-KEV`,
    `Subprocessor-Risk`, `Unsigned-SBOM`, `Vendor-Advisory`,
    `Operator-Asserted`, `SBOM-Provenance`.
16. `it('flags SBOMs with signature_status absent as unsigned-sbom only when explicitly absent')`
    — distinguish `'unverified'` (verification ran, failed) from
    `'absent'` (no verification attempted) — both still emit
    `unsigned-sbom` per FedRAMP guidance, but record the distinction in
    `description`.
17. `it('bumps UNKNOWN NVD severity to medium and records requires_operator_input')`
    — fixture CVE with severity `'UNKNOWN'` → entry severity = `medium`
    AND entry id is in `coverage.entries_missing_mitigation` AND
    `result.requires_operator_input[]` lists `<entry.id>:severity`.
18. `it('adds SSP back-matter resource when run alongside --oscal-ssp')`
    — integration: emit register → emit SSP → parse SSP → assert
    `back-matter.resources[]` contains entry titled `"Supply Chain Risk
    Register (SR-3, NIST SP 800-161r1)"`.

## REO compliance specific to this slice

- Every entry traces back to a real source: SBOM report (real Syft /
  Trivy / Grype output ingested by `core/sbom.ts`), CISA KEV catalog
  (committed `docs/cisa-kev.generated.json` synced via
  `core/kev-feed.ts`), subprocessor inventory (J.J2 output, real
  operator config or sheet), or operator YAML (REO Rule 4 input).
- No invented CVE ids — all flow from the parsed SBOM payloads.
- No synthesized severity for SBOM CVEs — severity flows through
  `core/sbom.ts`'s NVD correlation; `UNKNOWN` maps to `medium` and is
  flagged, never silently downgraded.
- KEV elevation (`sbom-cve` → `sbom-cve-kev`, severity → critical) is
  CISA-published guidance, not a fabrication.
- Mitigation language is operator-input only — never auto-generated;
  marker emitted when absent and status is not `open`.
- `provenance.source_files[]` lists actual file paths read; if a file
  is absent and another is present, the absent path is omitted (not
  invented).
- `sbom_provenance[]` per-SBOM NTIA flags are computed from real parse,
  not assumed `true`.
- Operator-input markers are emitted via the exact literal
  `'REQUIRES-OPERATOR-INPUT'` (define `const TBD = 'REQUIRES-OPERATOR-INPUT'`
  at the top mirroring `core/roe-emit.ts`,
  `core/privileges-matrix.ts`).
- No mock SDK calls in production code; tests inject fixture data on
  disk (the REO-allowed seam).
- Provenance fields populated: `emitter`, `emitted_at`,
  `source_modules[]`, `source_files[]`.
- Signed by: existing `core/sign.ts` pipeline (Ed25519 + RFC 3161).

## Verification commands

```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/supply-chain-risk.test.ts
npm run check:reo
```

For the end-to-end integration check (with J.J1 + J.J2 + A.A1 in scope):

```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run collect -- --collect KSI-IAM-AAM,KSI-IAM-ELP,KSI-SCR-MIT \
  --privileges-matrix --roles-config examples/roles-config.yaml \
  --subprocessors-config examples/subprocessors.yaml \
  --sbom-dir ../sbom \
  --supply-chain-risk --risks-config examples/risks-config.yaml \
  --oscal-ssp --oscal-ap --oscal-poam \
  --sign --submission-bundle
ls -la out/supply-chain-risk-register.{json,xlsx}
jq '.entries | length, (.coverage | {kev_exposed, open_critical, open_high})' \
  out/supply-chain-risk-register.json
jq '."poam-items" | map(select(.props[]? | (.name == "risk-source" and .value == "supply-chain"))) | length' \
  out/poam.json
unzip -l out/submission-bundle.tar.gz | grep supply-chain-risk-register
```

## Known risks / issues

- **Risk 1 — SBOM parse cost on large SBOMs**: the
  `sbom_provenance[]` block requires re-reading the SBOM file to compute
  NTIA-element presence flags. For a 200 MB CycloneDX SBOM this is
  expensive. Mitigation: stream the SBOM via the existing chunked
  reader pattern in `core/sbom.ts`; flag the seven booleans on the
  first-pass walk (no second read). Add a perf test with a 10k-component
  fixture.
- **Risk 2 — KEV catalog staleness**: `docs/cisa-kev.generated.json` is
  committed and updated by a separate workflow. If it's >7 days stale,
  the register may miss recent KEV additions. Mitigation: emit a
  `warnings[]` line when `kev_catalog.metadata.last_updated` is older
  than 7 days OR when the catalog file's mtime is older than 7 days.
  Do NOT block emission — staleness is a process concern, not a data
  integrity concern for already-emitted entries.
- **Risk 3 — POA&M deadline math edge case**: when `first_seen` is in
  the future (operator-supplied date), the 30/60-day deadline ends up
  *also* in the future, which is fine; but when `first_seen` is years
  in the past, the deadline is already overdue. Mitigation: when
  computed deadline is in the past at emission time, POA&M emitter
  stamps `deadline_overdue: true` and surfaces it in tracker UI (LOOP-B
  consumer); the deadline value is still the math result, NOT silently
  bumped forward.
- **Risk 4 — Operator override scope**: the `mitigations[]` post-pass
  allows operator to override `status` + `mitigation_summary`. An
  operator could mark an open critical KEV as `accepted` with a one-word
  mitigation. Mitigation: emit a `warnings[]` line whenever an operator
  override changes a KEV entry's status from `open` to `accepted`
  without a `mitigation_summary` of at least 50 chars. This surfaces in
  3PAO review; does NOT block emission (REO Rule 4: operator-supplied
  data is real data even if thin).
- **Risk 5 — SBOM signature_status enum drift**: `core/sbom.ts`
  currently emits `signature_status` as `'verified' | 'unverified' |
  'absent'`. If that enum changes (e.g. adds `'pending'`), J.J3 must
  handle. Mitigation: switch statement with explicit `default` that
  throws a typed error naming the unknown status; tests cover the
  default branch.
- **Risk 6 — Subprocessor name collision**: if two subprocessors have
  the same canonicalized name (lowercase + space-stripped), the J.J2
  dedup logic merges them. The register's
  `affected_subprocessors[]` field could then ambiguously reference
  either. Mitigation: J.J2 records the canonical-collision warning;
  J.J3 propagates it into the register's `warnings[]` field.
- **Risk 7 — CycloneDX vs SPDX field equivalence**: the NTIA-element
  presence flags must be computed correctly for both formats. The path
  tables in the "Schemas / standards" section above MUST be unit-tested
  for both formats with at least one fixture each.
- **Risk 8 — Empty inventory deadlock**: if `--supply-chain-risk` is
  set but no `--sbom-dir`, no `--subprocessors-config`, no
  `--risks-config`, and no KEV catalog is present, the emitter throws
  per build step 4. Risk: this hard-fails an orchestrator run that
  otherwise would succeed. Mitigation: the orchestrator MUST validate
  the flag combination at parse time and emit a clear pre-flight error
  ("`--supply-chain-risk` requires at least one source: `--sbom-dir`,
  `--subprocessors`/`--subprocessors-config`, `--risks-config`, or
  `docs/cisa-kev.generated.json`"). Not at build time.
- **Risk 9 — KEV elevation regression**: tests must guard against a
  regression where a CVE in both SBOM and KEV emits TWO entries (one
  `sbom-cve`, one `sbom-cve-kev`). Mitigation: dedup by CVE id at the
  end of the SBOM walk; KEV-matched CVE id removes the plain
  `sbom-cve` entry, leaves only `sbom-cve-kev`.
- **Risk 10 — POA&M idempotency**: re-running the orchestrator must
  not emit duplicate POA&M items for the same supply-chain entry.
  Mitigation: deterministic uuids (`deterministicUuid('poam:item:supply-chain:'
  + entry.id)`) guarantee idempotency by construction. Test 14 covers.

## Open questions (for implementation session to resolve)

- **Q1**: Should an operator's `--risks-config` `mitigations[]` entry
  also be allowed to override `severity`? Provisional: NO — severity
  flows from NVD / KEV and must not be silently lowered to bypass a
  POA&M deadline. Only `status` + `mitigation_summary` are operator-
  overridable; severity downgrade requires a Deviation Request (LOOP-
  E.E5).
- **Q2**: How does J.J3 interact with the LOOP-B.B5 Central Risk
  Register? Provisional: B.B5 aggregates J.J3 as one of its sub-
  registers; the wire format is the same JSON file; B.B5 reads
  `out/supply-chain-risk-register.json` directly. No schema change
  required in J.J3 for B.B5 to consume.
- **Q3**: Should `accepted` risks > 30 days old surface in the
  Monthly POA&M Delta (LOOP-E.E2)? Provisional: yes, as a "stale risk
  acceptance" line. Out of scope for J.J3 itself; J.J3 emits the
  data, E.E2 consumes it.
- **Q4**: For a CVE present in two SBOMs (e.g. same lib version in two
  images), should the register emit one entry or two? Provisional: ONE
  entry; `affected_components[]` lists both occurrences (with each
  SBOM's component path). De-dup by `(cve_id)` not `(cve_id, sbom_file)`.
- **Q5**: Should the register include CISA KEV entries that DON'T match
  the SBOM (i.e. KEV entries we're not exposed to)? Provisional: NO —
  the register's purpose is to document YOUR risks; non-matching KEV
  entries belong in a separate "watch list", out of scope.
- **Q6**: Does the SSP back-matter reference need OSCAL `media-type`?
  Provisional: yes — `application/json` for the .json and
  `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` for
  the .xlsx. Already the pattern in `core/oscal-ssp.ts` for other
  rlinks; copy verbatim.
- **Q7**: Should the register's `first_seen` for a CVE-derived entry
  be the SBOM's timestamp OR the run timestamp? Provisional: prefer
  the SBOM's `metadata.timestamp` (or SPDX `CreationInfo.Created`)
  when present; fall back to the run timestamp when absent. Document
  this rule in the emitter header.
- **Q8**: What happens when the orchestrator runs J.J3 but
  `core/sbom.ts` `SBOM_NVD_INDEX_PATH` env is unset (NVD severity
  lookup disabled)? Provisional: SBOM CVEs come in with severity
  `UNKNOWN` → entries land at severity `medium` per the rule, all
  flagged as `requires_operator_input: 'severity'`. Operator must
  either set the env (real NVD lookup) or supply severity via
  `--risks-config` overrides.
- **Q9**: Does Tier-2-significant subprocessor exposure warrant an
  entry too? Provisional: NO for the initial cut; tier-2 lives only in
  the `subprocessor_summary` count, and the entries-list focuses on
  the highest-attention items (tier-1 + SOC2-expired). LOOP-B.B5 may
  later cross-tab tier-2 + other signals into a different category.
- **Q10**: How should we treat the case where `kevCatalog` is loaded
  but is empty (the catalog file exists but has zero entries — likely a
  CI generation bug)? Provisional: emit a `warnings[]` line ("KEV
  catalog loaded but empty — verify docs/cisa-kev.generated.json
  freshness") and continue without KEV correlation. Do NOT block; KEV
  staleness is a separate process check (see Risk 2).

### Open-question resolutions (impl-j-j3, 2026-06-11)
- **Q1 (operator severity override)** — RESOLVED as provisional: NO. Only
  `status` + `mitigation_summary` are operator-overridable; severity flows from
  NVD/KEV. A KEV→accepted override without a substantive (≥50 char)
  mitigation_summary emits a `warnings[]` line for 3PAO review.
- **Q2 (B.B5 Central Risk Register)** — RESOLVED as provisional: B.B5 reads
  `out/supply-chain-risk-register.json` directly; no schema change here.
- **Q3 (stale acceptance in E.E2)** — DEFERRED to E.E2 (J.J3 emits the data).
- **Q4 (CVE in two SBOMs)** — RESOLVED: ONE entry per CVE id; deduped by
  `(cve_id)`. KEV elevation removes the plain `sbom-cve` entry for that CVE
  (verified by the no-double-emit test).
- **Q5 (non-matching KEV entries)** — RESOLVED as provisional: NO — only KEV
  entries that match an SBOM CVE are included (verified: the two non-matching
  fixture KEV rows produce no entries).
- **Q6 (SSP back-matter media-type)** — RESOLVED: yes — `application/json` for
  the .json rlink, `…spreadsheetml.sheet` for the .xlsx rlink.
- **Q7 (first_seen source)** — RESOLVED: prefer KEV `dateAdded` for KEV entries,
  else the first SBOM's `metadata.timestamp` / SPDX `CreationInfo.Created`, else
  the run date. Implemented in `buildSupplyChainRiskRegister`.
- **Q8 (NVD index unset)** — RESOLVED as provisional: SBOM CVEs arrive UNKNOWN →
  mapped to `medium` + flagged in `requires_operator_input` (verified).
- **Q9 (tier-2 exposure)** — RESOLVED as provisional: NO entry for tier-2; it
  lives only in `subprocessor_summary`. Filed as LOOP-J risk J3-R-EXT-1.
- **Q10 (empty KEV catalog)** — RESOLVED: emit a `warnings[]` line and continue
  without KEV correlation (does not block). Implemented in the emitter.

## Implementation log (running journal — implementing session updates)
```
2026-06-11 · impl-j-j3 · Shipped end to end per spec.
  Created: core/supply-chain-risk.ts (buildSupplyChainRiskRegister +
    emitSupplyChainRiskRegister + readRisksConfig + multiSheetXlsx/registerToXlsx
    + addDaysIso + detached Ed25519 signing); tests/core/supply-chain-risk.test.ts
    (20 tests — exceeds the ≥15 spec); fixtures (sbom-report, subprocessor-
    inventory, kev-catalog, risks-config.example.yaml); examples/risks-config.yaml.
  Extended: core/oscal-poam.ts (supplyChainPoamItems() reads the register →
    open critical/high → poam-items with props.risk-source='supply-chain';
    pre-flight skip now also emits when supply-chain items exist; deadline
    anchored at entry.first_seen, Critical +30d / High +60d via props);
    core/oscal-ssp.ts (back-matter.resources[] reference to the register);
    core/submission-bundle.ts (2 WELL_KNOWN roles); core/orchestrator.ts
    (--supply-chain-risk + --risks-config + CLOUD_EVIDENCE_SUPPLY_CHAIN_RISK/
    _RISKS_CONFIG; emitter scheduled after SBOM + subprocessor passes, before
    SSP/POA&M + signing).
  Verification: typecheck 0 errors; vitest 1004 passing (was 984, +20 — incl.
    POA&M + SSP integration tests that confirm the SSP still validates against
    the committed NIST OSCAL 1.1.2 schema); check:reo green.
  Spec divergences (documented):
   1. Provenance block uses the binding G3 camelCase contract (emitter/emittedAt/
      sourceCalls/signingKeyId) + sourceModules/sourceFiles extras + a detached
      Ed25519 signature, rather than the doc's snake_case shape — same call as
      LOOP-J.J2 / B.B1 / W.W1.
   2. POA&M deadline is carried as poam-item props (first-seen + remediation-
      deadline + kev-due-date) instead of an OSCAL risk remediation-tracking
      block — props keep the item OSCAL-valid and the anchor auditable without
      synthesizing risk objects. `deadline_overdue` (Risk 3) deferred to keep the
      POA&M deterministic; the deadline value itself shows if it is past.
   3. Multi-sheet XLSX writer built locally in core/supply-chain-risk.ts
      (multiSheetXlsx) composing core/zip.ts — the J.J1 rowsToXlsx({sheets})
      extension the spec assumed is not yet shipped. No zip logic duplicated.
   4. tier-2-significant subprocessors live only in subprocessor_summary (per
      open-question Q9); entries focus on tier-1 + SOC2-expired.
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [x] typecheck clean (`npm run typecheck`) — 0 errors
- [x] tests passing 100% (count increased by ≥15 for this slice's new tests) — 1004 (+20)
- [x] check:reo green (G1+G2+G3) — lint:no-stubs + check:provenance pass; coverage-regression skips (no out/)
- [x] STATUS.md updated (J.J3 row + Overall section) — LOOP-J is 2 of 3 (J.J1 still pending), so NOT marked "(COMPLETE)"
- [x] LOOP-J-SPEC.md Section 7 status table updated
- [x] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [x] LOOP-J-RISKS.md updated (J3 resolutions + J3-R-EXT-1)
- [x] OPERATOR-GUIDE.md updated (§3 flags + §4 env + §7 outputs)
- [x] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-J.J3: Supply chain risk register (SR-3) + SBOM integration`
- [x] Commit with `LOOP-J.J3: Supply chain risk register (SR-3) + SBOM integration` in message
- [x] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-J-SPEC.md
- [x] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here's everything it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-J-SPEC.md` Section 2 (Dependencies) AND §4 J.J3 for context on this loop.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Skim these existing modules before coding:
   - `cloud-evidence/core/sbom.ts` — `SbomReport`, `SbomFile`, `SbomVuln`, `buildSbomReport` exports
   - `cloud-evidence/core/kev-feed.ts` — `KevEntry`, `KevCatalog`, `loadKevCatalog` exports
   - `cloud-evidence/core/subprocessors-sheet.ts` + J.J2's
     `cloud-evidence/core/subprocessor-inventory.ts` — `SubprocessorRow`,
     `SubprocessorInventory` shapes
   - `cloud-evidence/core/oscal-poam.ts` — `deterministicUuid` import +
     POA&M item construction (your new items mirror that pattern)
   - `cloud-evidence/core/oscal-ssp.ts` — back-matter resource emit pattern
   - `cloud-evidence/core/roe-emit.ts` — REQUIRES-OPERATOR-INPUT literal
     pattern (`const TBD = 'REQUIRES-OPERATOR-INPUT'`)
   - `cloud-evidence/core/inventory-workbook.ts` — `rowsToXlsx` xlsx
     writer (note: the multi-sheet extension is a J.J1 sub-task; verify it
     landed before J.J3 starts, or extend in this slice if J.J1 is not
     yet shipped)
   - `cloud-evidence/core/submission-bundle.ts` — `Role` union +
     `WELL_KNOWN` catalogue (where you append two entries)
   - `cloud-evidence/core/sign.ts` — signing pipeline (no changes needed
     here; just verify the register runs before `--sign`)
6. Verify `package.json` includes `yaml` (J.J2 may have introduced it).
   If not, install pure-JS `yaml@^2.6.0` (no native deps).
7. Begin implementation; update Implementation log section as you go.
