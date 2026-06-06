# LOOP-J — Supply Chain + Privileges

> **Status:** Specification (pending execution). Author: planning pass June 2026.
> **Owner loop:** J (LOOP-J in `docs/EXECUTION-PLAN.md`).
> **Slices in scope:** J.J1 (User Roles & Privileges matrix — AC-2/AC-6), J.J2
> (Subprocessor inventory expansion — SA-9), J.J3 (Supply chain risk register
> — SR-3 + SBOM integration).
> **Effort total:** 3 weeks single-thread (per EXECUTION-PLAN).
> **Independent of all other loops.** May be developed in parallel with any
> other LOOP-B…K work.
>
> This document is self-contained. Any future Claude session can read this
> file (plus `cloud-evidence/CLAUDE.md` for the REO standard) and implement
> every slice without re-deriving anything from the original planning
> conversation.

---

## 1. Why this loop exists

LOOP-J closes three concrete authorization-package gaps that LOOP-A
deliberately did **not** address because each requires its own emitter,
schema, and operator-input contract:

1. **A roles × privileges matrix** (NIST SP 800-53 Rev 5 AC-2 + AC-6).
   FedRAMP authorization packages mandate "User Roles & Privileges"
   documentation (Appendix to SSP). Today our SSP emits a roles list and a
   user-types list but does **not** emit the cross-tabulated matrix that
   3PAOs use to verify least-privilege. The existing IAM-AAM and IAM-ELP
   collectors already pull real role/permission data from AWS IAM, GCP
   IAM, and Azure Entra ID/Graph — LOOP-J.J1 normalizes that across all
   three clouds and emits a single auditor-grade `privileges-matrix.xlsx`
   + `.json` + signed envelope.

2. **A FedRAMP-grade subprocessor inventory** (NIST SP 800-53 Rev 5 SA-9
   "External System Services"). Today `core/subprocessors-sheet.ts`
   reads a Google Sheet. That works for a single CSP but: (a) breaks
   multi-CSO operators (LOOP-H.H3 future requirement), (b) does not emit
   the FedRAMP SaaS Subprocessor Inventory schema fields (FedRAMP-author,
   risk-tier, last-attestation-date, in-scope-for-CSI), (c) does not
   sign or attach to the submission bundle. LOOP-J.J2 extends the
   reader so YAML/JSON files in the operator repo are first-class inputs
   AND emits a normalized OSCAL-aware subprocessor inventory artifact
   that the submission-bundle picks up.

3. **A consolidated supply-chain risk register** (NIST SP 800-53 Rev 5 SR-3
   "Supply Chain Controls and Processes" + NIST SP 800-161 Rev 1 C-SCRM
   program guidance). Today `core/sbom.ts` ingests CycloneDX/SPDX SBOMs
   and produces a per-component report. There is **no register** that
   correlates (a) SBOM-derived CVEs, (b) CISA KEV exposure, (c)
   subprocessor risk tier (from J.J2), (d) vendor-advisory feed events
   (from `core/notify.ts`). LOOP-J.J3 emits `supply-chain-risk-register.json`
   + `.xlsx` mirroring the FedRAMP RA-3 / RMS workstream's expected
   shape, signed, attached to the submission bundle.

**Net authorization-package effect:** the SSP appendix on User Roles &
Privileges, the SA-9 subprocessor inventory, and the SR-3 supply-chain
risk register all become emit-able from the same orchestrator run with
no operator hand-authoring. LOOP-J does **not** change any control
satisfaction status — it only emits documentation artifacts that the
3PAO + AO consume.

---

## 2. Dependencies

### Upstream (must exist before LOOP-J starts)

- **LOOP-A.A4 submission bundler** (`core/submission-bundle.ts`) — DONE
  per CHANGELOG. New artifact roles for J.J1/J.J2/J.J3 are appended
  to its `WELL_KNOWN` catalogue.
- **`core/ksi-map.ts`** — DONE. J.J1 reads the `KSI-IAM-AAM` and
  `KSI-IAM-ELP` evidence envelopes from `out/` to derive the matrix.
- **`providers/{aws,gcp,azure}/iam.ts`** — DONE (collectors registered
  for all three clouds). J.J1 reads their `RawEvidence` outputs.
- **`core/subprocessors-sheet.ts`** — DONE. J.J2 *extends* this module
  (does not replace it).
- **`core/sbom.ts`** — DONE. J.J3 *reuses* `buildSbomReport()` output
  and the existing CISA KEV catalog (`docs/cisa-kev.generated.json`).
- **`core/kev-feed.ts`** — DONE. J.J3 calls `loadKevCatalog()` to
  correlate SBOM CVEs against KEV.
- **`core/sign.ts`** + **`core/oscal-validate.ts`** — DONE. Every
  emitted artifact in LOOP-J is signed under the run manifest.
- **`core/zip.ts`** — DONE. J.J1 reuses `zipStore()` for the .xlsx
  writer pattern that `core/inventory-workbook.ts` already uses.
- **`core/inventory-workbook.ts` xlsx writer (`rowsToXlsx`)** — DONE.
  J.J1 + J.J3 import this helper for the .xlsx output.
- **REO standard** (`cloud-evidence/CLAUDE.md`) — DONE. All slices
  comply with Rule 4 (operator input flows through tracker / config /
  CLI / tags only).

### Downstream (unblocked WHEN LOOP-J completes)

- **LOOP-B.B5 (Central Risk Register, RA-3)** — gains the
  supply-chain-risk-register as one of three sub-registers it
  aggregates.
- **LOOP-C.C7 (Risk Management Strategy doc)** — auto-fills the
  "supply chain risks" section from J.J3 output.
- **LOOP-G.G4 (AFR-MAS, Minimum Assessment Scope)** — MAS-CSO-TPR
  ("Third-Party Information Resources") reads J.J2 subprocessor
  output as the canonical third-party list.
- **LOOP-H.H3 (Multi-CSO)** — J.J2's per-CSO config file pattern is
  the prerequisite for multi-tenancy.
- **LOOP-I.I1 (Executive posture dashboard)** — pulls supply-chain
  KEV-exposure count from J.J3.

LOOP-J is **independent of** LOOP-B/C/D/E/F/G/H/I/K execution. It can
ship before or after any of them.

---

## 3. Authoritative sources

### Primary (NIST + CISA + FedRAMP)

| URL | Document | Used in slice |
|---|---|---|
| https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf | NIST SP 800-53 Rev 5 — Security and Privacy Controls (Sept 2020, updated Dec 2020) | J.J1 (AC-2, AC-6), J.J2 (SA-9), J.J3 (SR-3, SR-4, SR-5, SR-6) |
| https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final | NIST SP 800-53 Rev 5.1.1 control catalog (CPRT machine-readable) | All slices — verbatim control text |
| https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1.pdf | NIST SP 800-161 Rev 1 — Cybersecurity Supply Chain Risk Management Practices (May 2022) | J.J3 — C-SCRM program structure |
| https://www.cisa.gov/sbom | CISA Software Bill of Materials (SBOM) program page | J.J3 — minimum elements |
| https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report.pdf | NTIA "The Minimum Elements For a Software Bill of Materials (SBOM)" — July 12, 2021, per Executive Order 14028 §4(f) | J.J3 — SBOM 7 minimum baseline fields |
| https://www.cisa.gov/known-exploited-vulnerabilities-catalog | CISA Known Exploited Vulnerabilities (KEV) Catalog | J.J3 — risk-register exposure layer |
| https://www.fedramp.gov/docs/rev5/templates/ | FedRAMP Rev 5 templates index (System Security Plan Appendix Q "User Roles & Privileges Matrix", Subprocessor Inventory) | J.J1 + J.J2 — submission expectations |

### Secondary (schema sources for J.J3)

| URL | Document | Used in slice |
|---|---|---|
| https://cyclonedx.org/docs/1.5/json/ | CycloneDX 1.5 JSON specification | J.J3 — SBOM ingestion (already used by `core/sbom.ts`) |
| https://spdx.github.io/spdx-spec/v2.3/ | SPDX 2.3 specification | J.J3 — SBOM ingestion (already used by `core/sbom.ts`) |
| https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json | CycloneDX 1.5 JSON Schema (canonical) | J.J3 — field validation |

### Verbatim quotations (used in tests + emitter comments)

#### NIST SP 800-53 Rev 5 — AC-6 (Least Privilege)

> "Employ the principle of least privilege, allowing only authorized
> accesses for users (or processes acting on behalf of users) that are
> necessary to accomplish assigned organizational tasks."
> — NIST SP 800-53 Rev 5, Control AC-6 §3.1.6 (Sept 2020)

#### NIST SP 800-53 Rev 5 — AC-2 (Account Management)

The AC-2 control requires the organization to "Define and document the
types of accounts allowed and specifically prohibited for use within the
system" and to "Assign account managers" plus "Require [Assignment:
organization-defined prerequisites and criteria] for group and role
membership". The matrix LOOP-J.J1 emits is the artifact that makes
these assignments auditable.

#### NIST SP 800-53 Rev 5 — SA-9 (External System Services)

> "Require that providers of external system services comply with
> organizational security and privacy requirements and employ the
> following controls: [Assignment: organization-defined controls]."
> — NIST SP 800-53 Rev 5, Control SA-9.a (Sept 2020)

> "Define and document organizational oversight and user roles and
> responsibilities with regard to external system services."
> — NIST SP 800-53 Rev 5, Control SA-9.b (Sept 2020)

> "Employ the following processes, methods, and techniques to monitor
> control compliance by external service providers on an ongoing basis:
> [Assignment: organization-defined processes, methods, and techniques]."
> — NIST SP 800-53 Rev 5, Control SA-9.c (Sept 2020)

> "Service-level agreements define the expectations of performance for
> implemented controls, describe measurable outcomes, and identify
> remedies and response requirements" for noncompliance.
> — NIST SP 800-53 Rev 5, Control SA-9 Discussion (Sept 2020)

#### NIST SP 800-53 Rev 5 — SR-3 (Supply Chain Controls and Processes)

> "Establish a process or processes to identify and address weaknesses
> or deficiencies in the supply chain elements and processes" of the
> designated systems, coordinating with defined supply chain personnel.
> — NIST SP 800-53 Rev 5, Control SR-3.a (Sept 2020)

> "Employ the following controls to protect against supply chain risks
> to the system, system component, or system service and to limit the
> harm or consequences from supply chain related events: [Assignment:
> organization-defined supply chain controls]."
> — NIST SP 800-53 Rev 5, Control SR-3.b (Sept 2020)

> "Document the selected and implemented supply chain processes and
> controls" in security plans, supply chain risk management plans, or
> other designated documents.
> — NIST SP 800-53 Rev 5, Control SR-3.c (Sept 2020)

> Supply chain elements "encompass organizations, entities, and tools
> involved in research, development, manufacturing, acquisition,
> delivery, operations, and disposal of systems".
> — NIST SP 800-53 Rev 5, Control SR-3 Discussion (Sept 2020)

#### NTIA / CISA — SBOM Minimum Elements (per EO 14028 §4(f), July 12 2021)

The seven minimum baseline component data fields, each REQUIRED in every
SBOM, are:

1. **Supplier Name** — "The name of an entity that creates, defines, and
   identifies components."
2. **Component Name** — "Designation assigned to a unit of software
   defined by the original supplier."
3. **Version of the Component** — "Identifier used by the supplier to
   specify a change in software from a previously identified version."
4. **Other Unique Identifiers** — "Other identifiers that are used to
   identify a component, or serve as a look-up key for relevant databases."
5. **Dependency Relationship** — "Characterizing the relationship that
   an upstream component X is included in software Y."
6. **Author of SBOM Data** — "The name of the entity that creates the
   SBOM data for this component."
7. **Timestamp** — "Record of the date and time of the SBOM data
   assembly."

Plus three categories: **Automation Support** (the SBOM must be
machine-readable in SPDX, CycloneDX, or SWID Tags), **Practices and
Processes** (frequency, depth, known unknowns, distribution, access
controls, accommodation of mistakes), and **the supplemental "as
SBOM evolves" expectations**.

#### NIST SP 800-161 Rev 1 — C-SCRM Program Structure

NIST SP 800-161r1 requires federal agencies (and CSPs serving them) to
maintain a Cybersecurity Supply Chain Risk Management (C-SCRM) plan that
includes:

- A C-SCRM Strategy (Section 1.5),
- A C-SCRM Implementation Plan (Section 1.5),
- A C-SCRM Policy (Section 1.5),
- Per-system C-SCRM Plans (Section 2.3.5),
- Supplier identification + risk tiering (Tier 3 = system level),
- Continuous supplier monitoring + assessment (SR-6),
- Incident response coordination across the supply chain.

LOOP-J.J3's risk register is the per-system C-SCRM Plan artifact (Tier
3 in 800-161r1 parlance).

#### CycloneDX 1.5 — JSON schema top-level fields

The CycloneDX 1.5 BOM JSON schema mandates two top-level fields:
`bomFormat` (constant string `"CycloneDX"`) and `specVersion` (the
specification version, e.g. `"1.5"`). Optional top-level fields used by
LOOP-J.J3 are: `serialNumber` (RFC-4122 UUID), `version` (integer ≥ 1),
`metadata`, `components`, `services`, `dependencies`, `vulnerabilities`,
`externalReferences`, and `properties`. The schema enforces
`additionalProperties: false` at the root level — undeclared fields are
rejected.

---

## 4. Per-slice implementation specs

### Slice J.J1 — User Roles & Privileges matrix (AC-2 + AC-6)

**Why this slice**: Closes the SSP Appendix "User Roles & Privileges
Matrix" gap. Today the SSP emits a roles list but not the
cross-tabulated role × resource × permission matrix that 3PAOs use to
verify least-privilege per AC-6 and account management per AC-2. The
matrix is the single most-requested artifact during 3PAO discovery and
is currently produced by hand from screenshots of the AWS / GCP / Azure
console.

**Files to create** (exact paths):

- `cloud-evidence/core/privileges-matrix.ts` — pure builder + disk
  emitter. ~600 lines. Exports `buildPrivilegesMatrix(input,
  opts): PrivilegesMatrix`, `emitPrivilegesMatrix(opts):
  PrivilegesMatrixEmitResult`, types `Role`, `Privilege`,
  `MatrixCell`, `PrivilegesMatrix`, `PrivilegesMatrixEmitOptions`,
  `PrivilegesMatrixEmitResult`.
- `cloud-evidence/tests/core/privileges-matrix.test.ts` — ~14 tests
  covering the contracts below.

**Files to extend**:

- `cloud-evidence/core/orchestrator.ts` — add `--privileges-matrix`
  flag + `CLOUD_EVIDENCE_PRIVILEGES_MATRIX` env. Runs **before**
  signing so the matrix is covered by the manifest. Add to
  submission-bundle invocation sequence (runs before bundler).
- `cloud-evidence/core/submission-bundle.ts` — append two
  WELL_KNOWN entries:
  - `{ role: 'privileges-matrix-xlsx', filename: 'privileges-matrix.xlsx', description: 'User Roles & Privileges matrix (AC-2/AC-6) — auto-derived from IAM evidence' }`
  - `{ role: 'privileges-matrix-json', filename: 'privileges-matrix.json', description: 'Structured roles × privileges matrix used by the SSP appendix' }`
  - Extend the `Role` union accordingly.
- `cloud-evidence/core/oscal-ssp.ts` — when `out/privileges-matrix.json`
  exists, populate `system-implementation.users[]` with the real role
  list (instead of falling back to operator-supplied or
  REQUIRES-OPERATOR-INPUT). Add a back-matter resource link to the
  emitted .xlsx for the SSP Appendix.

**Schemas / standards** (cite exact URLs + field requirements):

1. **NIST SP 800-53 Rev 5 AC-2** (https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
   - "Define and document the types of accounts allowed and specifically
     prohibited for use within the system" — drives the `Role.type`
     enum: `human-user`, `non-user`, `service-principal`, `break-glass`.
   - "Assign account managers" — drives `Role.account_manager_party_uuid`.
   - "Require [organization-defined prerequisites and criteria] for
     group and role membership" — drives `Role.membership_criteria` (a
     REQUIRES-OPERATOR-INPUT field when blank).
2. **NIST SP 800-53 Rev 5 AC-6** (same URL)
   - "Employ the principle of least privilege..." — drives the
     `MatrixCell.privilege_level` enum (`none`, `read`, `write`,
     `admin`) and the `MatrixCell.justification` field (REQUIRES-OPERATOR-INPUT
     when `admin` is asserted without an operator-supplied justification).
3. **AWS IAM** API (`ListRoles`, `ListAttachedRolePolicies`,
   `GetRole`, `ListUsers`, `ListGroups`, `ListAttachedUserPolicies`) —
   already consumed by `providers/aws/iam.ts:collectIamAam` /
   `collectIamElp`.
4. **GCP IAM** API (`iam.projects.roles.list`,
   `iam.projects.serviceAccounts.list`,
   `cloudresourcemanager.projects.getIamPolicy`) — already consumed by
   `providers/gcp/iam.ts:collectIamAam` / `collectIamElp`.
5. **Azure RBAC + Entra ID** via Microsoft Graph
   (`roleDefinitions`, `roleAssignments`, `users`, `groups`) — already
   consumed by `providers/azure/iam.ts:collectIamAam` /
   `collectIamElp`.

**Build steps** (numbered, concrete):

1. Define the types in `core/privileges-matrix.ts`:
   ```ts
   export interface Role {
     id: string;                    // <cloud>:<role-name> or <cloud>:<group-name>
     name: string;
     type: 'human-user' | 'non-user' | 'service-principal' | 'break-glass';
     cloud: 'aws' | 'gcp' | 'azure';
     account_manager_party_uuid?: string; // REQUIRES-OPERATOR-INPUT marker if absent
     membership_criteria?: string;        // REQUIRES-OPERATOR-INPUT marker if absent
     business_justification?: string;     // operator-supplied
     created_at?: string;
     last_used_at?: string;
     evidence_source: { ksi: 'KSI-IAM-AAM' | 'KSI-IAM-ELP'; envelope_path: string };
   }
   export interface Privilege {
     id: string;                    // <cloud>:<service>:<action> e.g. 'aws:s3:PutObject'
     resource_type: string;         // 's3', 'iam', 'kms', 'projects', 'storage', etc.
     action: string;                // 'PutObject', 'iam.roles.create', etc.
     scope?: string;                // arn pattern / project / subscription
   }
   export interface MatrixCell {
     role_id: string;
     privilege_id: string;
     privilege_level: 'none' | 'read' | 'write' | 'admin';
     granted_via: string;           // policy name / role-binding id
     justification?: string;        // REQUIRES-OPERATOR-INPUT when level === 'admin' and no operator value
     evidence_envelope: string;     // path to KSI-IAM-*.json
   }
   export interface PrivilegesMatrix {
     generated_at: string;
     system_id?: string;
     run_id: string;
     roles: Role[];
     privileges: Privilege[];
     cells: MatrixCell[];
     coverage: {
       total_roles: number;
       roles_with_business_justification: number;
       roles_missing_justification: string[]; // role.id list — REQUIRES-OPERATOR-INPUT
       admin_cells: number;
       admin_cells_missing_justification: string[];
     };
     provenance: {
       emitter: 'core/privileges-matrix.ts';
       emitted_at: string;
       source_envelopes: string[];   // KSI-IAM-AAM.json + KSI-IAM-ELP.json paths
       source_calls: string[];       // verbatim SDK call names from RawEvidence
     };
   }
   ```
2. Pure builder signature:
   ```ts
   export function buildPrivilegesMatrix(
     input: {
       iamAamEnvelopes: KsiEnvelope[]; // KSI-IAM-AAM read from outDir
       iamElpEnvelopes: KsiEnvelope[]; // KSI-IAM-ELP read from outDir
       operatorRoles?: OperatorRoleConfig[]; // optional from --roles-config
     },
     opts: { runId: string; systemId?: string; now?: () => Date }
   ): PrivilegesMatrix
   ```
   - Walk each envelope's `providers[].evidence[].data` for the
     real role list, the real binding list, and the per-role
     attached-policy list. Normalize across clouds into the `Role`
     and `MatrixCell` shape.
   - For AWS: a role with `AdministratorAccess` policy attached yields
     `privilege_level = 'admin'` for `* / *`. A role with
     `ReadOnlyAccess` yields `privilege_level = 'read'` for every
     covered service. A role with a managed policy NOT in the
     standard AWS catalogue yields `privilege_level = 'write'` (the
     default for an unknown custom policy that isn't admin).
   - For GCP: a binding to `roles/owner` or `roles/editor` →
     `privilege_level = 'admin'`. `roles/viewer` → `read`. Custom
     roles → `write` unless the actual permissions list resolves to
     only `*.get` / `*.list` (then `read`).
   - For Azure: a `roleAssignments` row referring to `Owner` or
     `Contributor` or `User Access Administrator` → `admin`. `Reader`
     → `read`. Custom RBAC → `write` unless permissions are all
     `Microsoft.*/read`.
   - Merge operator-supplied `business_justification` per role id from
     `--roles-config <path.yaml>`.
   - Compute `coverage` counts deterministically.
3. Disk emitter:
   ```ts
   export interface PrivilegesMatrixEmitOptions {
     outDir: string;
     runId: string;
     systemId?: string;
     rolesConfigPath?: string;            // YAML/JSON, REQUIRES-OPERATOR-INPUT scheme
     xlsxPath?: string;                   // default: outDir/privileges-matrix.xlsx
     jsonPath?: string;                   // default: outDir/privileges-matrix.json
   }
   export interface PrivilegesMatrixEmitResult {
     json_path: string;
     xlsx_path: string;
     matrix: PrivilegesMatrix;
     bytes_json: number;
     bytes_xlsx: number;
     requires_operator_input: string[];   // names of roles/cells missing input
   }
   export function emitPrivilegesMatrix(opts: PrivilegesMatrixEmitOptions): PrivilegesMatrixEmitResult
   ```
   - Reads `outDir/KSI-IAM-AAM.json` and `outDir/KSI-IAM-ELP.json`
     directly. If either envelope is missing, throws a typed error
     naming the orchestrator flags that produce them
     (`--collect KSI-IAM-AAM` etc.) — NEVER silently emits an
     empty matrix.
   - .xlsx uses the same `rowsToXlsx()` helper that
     `core/inventory-workbook.ts` exports. Sheet 1 = "Roles"
     (one row per Role), Sheet 2 = "Privileges Matrix" (one row
     per MatrixCell), Sheet 3 = "Coverage" (the coverage block).
     If `rowsToXlsx` does not support multi-sheet, extend it (the
     OOXML SpreadsheetML writer is short and adding a second sheet
     entry is straightforward; this counts as a sub-task of J.J1).
   - .json is the full PrivilegesMatrix structure.
4. Wire into orchestrator (`core/orchestrator.ts`):
   - Add CLI flag `--privileges-matrix` + env
     `CLOUD_EVIDENCE_PRIVILEGES_MATRIX=1`.
   - Add CLI flag `--roles-config <path>` + env
     `CLOUD_EVIDENCE_ROLES_CONFIG` for the operator-supplied
     business-justification YAML.
   - Run AFTER `--collect` (need the IAM envelopes on disk) and
     BEFORE `--sign` (so the matrix is covered by the manifest).
   - Console output: `privileges-matrix: <N> roles · <M> cells · <K> admin · <X> REQUIRES-OPERATOR-INPUT`.
5. Add `privileges-matrix-xlsx` and `privileges-matrix-json` to
   `core/submission-bundle.ts WELL_KNOWN`.

**REQUIRES-OPERATOR-INPUT fields**:

- `Role.account_manager_party_uuid` — source = `--roles-config`
  YAML entry per role id; falls back to REQUIRES-OPERATOR-INPUT
  marker in the .xlsx + listed in `coverage.roles_missing_justification`.
- `Role.membership_criteria` — source = `--roles-config`; same fallback.
- `Role.business_justification` — source = `--roles-config`; same fallback.
- `MatrixCell.justification` (only required when `privilege_level === 'admin'`)
  — source = `--roles-config` per `(role_id, privilege_id)` pair;
  same fallback, listed in `coverage.admin_cells_missing_justification`.

The operator-config YAML schema is documented in the file's header
comment. Example (committed in the test fixtures, NOT in production
code):

```yaml
# Example operator roles config — committed at examples/roles-config.yaml
roles:
  - id: aws:my-prod-admin-role
    business_justification: "Production deploy automation"
    account_manager_party_uuid: "5b9c3e1c-..."
    membership_criteria: "Member of #sre-on-call Slack channel + PagerDuty roster"
    cell_justifications:
      - privilege_id: "aws:iam:CreateRole"
        justification: "Bootstrap IaC roles for new AWS sub-accounts; restricted by SCP."
```

**Test specifications** (~14 tests, all in
`tests/core/privileges-matrix.test.ts`):

1. `it('builds a 3-cloud matrix from real KSI-IAM-AAM + KSI-IAM-ELP envelopes', …)`
   — fixture envelopes with one AWS role, one GCP service account,
   one Azure role assignment. Assert: `matrix.roles.length === 3`,
   each `role.cloud` set correctly, `cells.length` ≥ 3.
2. `it('classifies AWS AdministratorAccess as privilege_level=admin', …)` —
   fixture with `arn:aws:iam::aws:policy/AdministratorAccess` →
   assert at least one `cell.privilege_level === 'admin'` and that
   `cell.granted_via` references the policy ARN.
3. `it('classifies GCP roles/viewer as privilege_level=read', …)`.
4. `it('classifies Azure Owner role as admin', …)`.
5. `it('emits REQUIRES-OPERATOR-INPUT when business_justification is missing', …)`
   — no operator config → matrix.coverage.roles_missing_justification
   non-empty AND the .xlsx cell text is literally
   `'REQUIRES-OPERATOR-INPUT'`.
6. `it('honors operator-supplied business_justification from --roles-config', …)`
   — pass a `rolesConfigPath` → assert verbatim string flows to
   `role.business_justification`.
7. `it('flags admin cells missing justification', …)` — operator
   provides role-level justification but not the per-cell admin
   justification → cell stays REQUIRES-OPERATOR-INPUT;
   `coverage.admin_cells_missing_justification` lists it.
8. `it('throws a typed error when KSI-IAM-AAM envelope is missing', …)` —
   empty outDir → throws with message that names `--collect KSI-IAM-AAM`.
9. `it('throws a typed error when KSI-IAM-ELP envelope is missing', …)`.
10. `it('produces a multi-sheet XLSX with Roles / Privileges Matrix / Coverage tabs', …)`
    — read the emitted .xlsx via the zip reader from tests, assert
    three sheet1.xml / sheet2.xml / sheet3.xml parts.
11. `it('produces deterministic JSON given identical envelopes + operator config', …)`
    — run twice, compare sha256 of `privileges-matrix.json`.
12. `it('records provenance.source_envelopes pointing to the actual KSI files', …)`.
13. `it('records provenance.source_calls verbatim from RawEvidence.source', …)`
    — assert `'iam:ListRoles'` (or equivalent per SDK) appears verbatim
    in `provenance.source_calls`.
14. `it('emits a SSP back-matter reference when run alongside --oscal-ssp', …)`
    — integration test through orchestrator harness; assert the
    emitted `ssp.json` `back-matter.resources[]` contains an entry
    with `title` referencing the privileges matrix.

**REO compliance checks specific to this slice**:

- Every Role flows from `KSI-IAM-AAM.json` or `KSI-IAM-ELP.json` —
  no hard-coded role names anywhere in production code.
- The standard AWS / GCP / Azure managed-role *names* (e.g.
  `AdministratorAccess`, `roles/viewer`, `Owner`) are quoted as
  REO-allowed cloud-published constants (Rule 3) — they're not
  fabricated.
- Operator-input markers are emitted via the exact literal
  `'REQUIRES-OPERATOR-INPUT'` (used elsewhere in the codebase as a
  string constant — define `const TBD = 'REQUIRES-OPERATOR-INPUT'`
  at the top of `privileges-matrix.ts` exactly as `roe-emit.ts`
  does).
- No silent fallback when an IAM envelope is missing — throws a typed
  error.
- No mock SDK calls in production code; tests inject fixture
  envelopes already on disk (the REO-allowed seam).

**Verification commands**:

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/privileges-matrix.test.ts
npm run check:reo
```

**Estimated effort**: 1 week (5 working days). XLSX multi-sheet
extension + cross-cloud role normalization are the main work; SSP
back-matter wiring is a small follow-on.

---

### Slice J.J2 — Subprocessor inventory expansion (SA-9)

**Why this slice**: The current `core/subprocessors-sheet.ts` reads a
single Google Sheet, which doesn't scale to multi-CSO operators and
doesn't emit the FedRAMP-aligned SA-9 "Subprocessor Inventory" artifact
with risk tiers + last-attestation dates + SLA-monitoring evidence
links. LOOP-J.J2 adds YAML/JSON config support, normalizes the schema,
and emits a signed artifact bundled with the submission.

**Files to create**:

- `cloud-evidence/core/subprocessor-inventory.ts` — pure builder +
  disk emitter that aggregates rows from `subprocessors-sheet.ts`
  (existing Google Sheets reader) AND from new YAML/JSON config
  sources. ~450 lines. Exports
  `readSubprocessorConfig(path: string): SubprocessorRow[]`,
  `buildSubprocessorInventory(input, opts): SubprocessorInventory`,
  `emitSubprocessorInventory(opts): SubprocessorInventoryEmitResult`.
- `cloud-evidence/tests/core/subprocessor-inventory.test.ts` — ~13
  tests (see below).
- `cloud-evidence/examples/subprocessors.yaml` — committed example
  config file with 3 fictitious rows (clearly marked as examples;
  REO-allowed under Rule 3 because it's under `examples/`, not
  production code).

**Files to extend**:

- `cloud-evidence/core/subprocessors-sheet.ts` — no schema change;
  keep the existing Google Sheets reader. J.J2 wraps it.
- `cloud-evidence/core/orchestrator.ts` — add `--subprocessors-config <path>`
  + env `CLOUD_EVIDENCE_SUBPROCESSORS_CONFIG`. Already exists is the
  per-config-yaml `subprocessors:` block — extend to accept either
  `spreadsheet_id` (existing) OR `config_path` (new).
- `cloud-evidence/core/submission-bundle.ts` — append to WELL_KNOWN:
  - `{ role: 'subprocessor-inventory-json', filename: 'subprocessor-inventory.json', description: 'SA-9 Subprocessor Inventory — auto-emitted with risk tiers' }`
  - `{ role: 'subprocessor-inventory-xlsx', filename: 'subprocessor-inventory.xlsx', description: 'SA-9 Subprocessor Inventory — FedRAMP-style Excel format' }`
- `cloud-evidence/core/oscal-ssp.ts` — when `out/subprocessor-inventory.json`
  exists, populate `system-implementation.leveraged-authorizations[]`
  from the inventory rows tagged `fedramp_authorized === 'yes'`.

**Schemas / standards**:

1. **NIST SP 800-53 Rev 5 SA-9** (https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
   - SA-9.a — "Require that providers of external system services
     comply with organizational security and privacy requirements
     and employ the following controls: [Assignment]." Drives
     `Row.contractually_required_controls[]` (list of NIST control
     IDs in the SLA).
   - SA-9.b — "Define and document organizational oversight and user
     roles and responsibilities with regard to external system
     services." Drives `Row.oversight_party_uuid` +
     `Row.user_roles_responsibilities`.
   - SA-9.c — "Employ the following processes, methods, and
     techniques to monitor control compliance by external service
     providers on an ongoing basis: [Assignment]." Drives
     `Row.monitoring_methods[]`.
2. **FedRAMP SaaS Subprocessor Inventory** template fields (per the
   FedRAMP Rev 5 templates index at
   https://www.fedramp.gov/docs/rev5/templates/):
   `name`, `role`, `data_categories`, `fedramp_authorized`,
   `attestation_doc_url`, `soc2_expiry`, `contract_review_date`,
   `in_scope_for_csi` — already in `SubprocessorRow`.
3. **New (LOOP-J.J2) fields per FedRAMP SA-9 expectations**:
   `risk_tier` (`tier-1-critical` / `tier-2-significant` /
   `tier-3-routine`), `data_residency`, `last_audit_date`,
   `monitoring_methods[]`, `incident_notification_sla_hours`,
   `subprocessor_subprocessors[]` (the chain), `contracted_controls[]`
   (NIST control IDs).

**Build steps**:

1. Add to `SubprocessorRow` (extend the existing interface; do not
   break callers):
   ```ts
   export interface SubprocessorRow {
     // existing
     name: string;
     role?: string;
     data_categories?: string[];
     fedramp_authorized?: 'yes' | 'no' | 'equivalency-attest';
     attestation_doc_url?: string;
     soc2_expiry?: string;
     contract_review_date?: string;
     in_scope_for_csi?: boolean;
     // NEW for J.J2
     risk_tier?: 'tier-1-critical' | 'tier-2-significant' | 'tier-3-routine';
     data_residency?: string;       // e.g. 'us-east-1', 'eu-west-2'
     last_audit_date?: string;
     monitoring_methods?: string[]; // e.g. ['SOC2-Type2', 'quarterly-attestation']
     incident_notification_sla_hours?: number;
     subprocessor_subprocessors?: string[]; // names
     contracted_controls?: string[]; // NIST 800-53 control IDs
     source: 'google-sheet' | 'yaml-config' | 'json-config';
     source_ref: string;            // sheet-id+range OR file-path
   }
   ```
2. New `readSubprocessorConfig(path)` reads YAML or JSON. YAML
   parsing: use the existing YAML library already in the repo (search
   `package.json` for `js-yaml` or `yaml`; both pure-JS). If neither
   is present, depend on `yaml` (pure-JS, dependency-free runtime).
   Schema is committed at the top of the file as a TypeScript
   interface AND mirrored in a JSON Schema fixture under
   `tests/fixtures/subprocessor-config.schema.json` for ajv
   validation in tests.
3. Builder signature:
   ```ts
   export function buildSubprocessorInventory(
     input: { rows: SubprocessorRow[] },
     opts: { runId: string; systemId?: string; csoId?: string; now?: () => Date }
   ): SubprocessorInventory
   ```
   - De-duplicates rows by `name` (canonicalized lower-case + space-stripped).
   - When a duplicate-name conflict occurs between a sheet row and a
     YAML row, the YAML row wins (operator's local source of truth)
     and a `warnings[]` entry is recorded.
   - Computes coverage:
     - `rows_with_risk_tier` count
     - `rows_missing_risk_tier` — list of names → REQUIRES-OPERATOR-INPUT
     - `rows_with_expired_soc2` (compare against `now`)
     - `tier_1_critical_count` etc.
4. Emitter signature:
   ```ts
   export interface SubprocessorInventoryEmitOptions {
     outDir: string;
     runId: string;
     systemId?: string;
     csoId?: string;
     sheetConfig?: SheetConfig | null;
     configPath?: string | null;     // YAML/JSON
     jsonPath?: string;              // default: outDir/subprocessor-inventory.json
     xlsxPath?: string;              // default: outDir/subprocessor-inventory.xlsx
   }
   export interface SubprocessorInventoryEmitResult {
     json_path: string;
     xlsx_path: string;
     inventory: SubprocessorInventory;
     bytes_json: number;
     bytes_xlsx: number;
     warnings: string[];
     requires_operator_input: string[];
   }
   ```
   - When neither `sheetConfig` nor `configPath` is provided, the
     emitter writes a stub-free, schema-valid empty inventory with a
     single REQUIRES-OPERATOR-INPUT entry naming both surfaces — never
     a fake row.
5. Orchestrator wiring: extend the existing
   `--subprocessors` / `subprocessors:` block to recognize
   `configPath` as an alternative to `spreadsheet_id`. New CLI flag
   `--subprocessors-config <path>` is the OPERATOR's switch.
6. Bundler catalogue entries (see "Files to extend" above).

**REQUIRES-OPERATOR-INPUT fields**:

- `risk_tier` — source = operator YAML/JSON or sheet column. Falls
  back to REQUIRES-OPERATOR-INPUT in the .xlsx + lists the row in
  `coverage.rows_missing_risk_tier`.
- `monitoring_methods` — source = operator YAML/JSON. Falls back as
  above.
- `contracted_controls` — source = operator YAML/JSON. Falls back
  as above.
- `oversight_party_uuid` — source = operator YAML/JSON. Falls back
  as above.

If `sheetConfig` is set but Google Sheets API returns 0 rows or fails,
the emitter logs a `warnings[]` entry AND continues with whatever
config-file rows exist — it never silently substitutes data.

**Test specifications** (~13):

1. `it('reads subprocessors from a YAML file', …)` — fixture YAML →
   N rows parsed with `source === 'yaml-config'`.
2. `it('reads subprocessors from a JSON file', …)`.
3. `it('merges sheet rows + YAML rows with YAML precedence on name conflict', …)`.
4. `it('flags rows missing risk_tier as REQUIRES-OPERATOR-INPUT', …)`.
5. `it('flags expired SOC2 attestations based on opts.now', …)`.
6. `it('computes tier_1_critical_count correctly', …)`.
7. `it('emits a JSON + XLSX with the FedRAMP-style columns', …)` —
   assert column header list matches the FedRAMP template field
   list verbatim.
8. `it('writes a single REQUIRES-OPERATOR-INPUT row when no sheet + no config provided', …)`.
9. `it('returns warnings when Sheets API fails but YAML config is valid', …)`.
10. `it('preserves operator-supplied incident_notification_sla_hours', …)`.
11. `it('records the source_ref for each row (sheet-id+range OR file path)', …)`.
12. `it('canonicalizes names for dedup but preserves the displayed name', …)`.
13. `it('validates an operator YAML against the committed JSON schema fixture with ajv', …)`.

**REO compliance**:

- No example subprocessor data is committed under `core/` —
  `examples/subprocessors.yaml` lives under `examples/` and is
  REO-allowed.
- When neither input source provides rows, no fake rows substituted
  — single REQUIRES-OPERATOR-INPUT row emitted naming both surfaces
  (sheet + config) the operator can populate.
- The Google Sheets reader's existing `warnings[]` pattern is
  preserved; the wrapping inventory aggregates warnings into its own
  `warnings[]`.
- Provenance block: `provenance.source_calls` lists `sheets.values.get`
  (if sheets used) AND `fs.readFileSync(<configPath>)` (if config
  used) — both real, both verifiable.

**Verification commands**:

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/subprocessor-inventory.test.ts
npm run check:reo
```

**Estimated effort**: 0.75 weeks (3-4 working days). Mostly schema
work, YAML parsing, dedup logic, and the XLSX writer reuse.

---

### Slice J.J3 — Supply chain risk register (SR-3) + SBOM integration

**Why this slice**: NIST SP 800-53 Rev 5 SR-3 mandates a documented
process to "identify and address weaknesses or deficiencies in the
supply chain elements and processes". NIST SP 800-161 Rev 1 elevates
this into a per-system C-SCRM plan with a supplier-risk register. Today
the codebase has `core/sbom.ts` (per-image component report) + the
CISA KEV catalog + `core/subprocessors-sheet.ts` — but no single
register that joins them. LOOP-J.J3 emits a signed risk register that
3PAOs use as the SR-3 artifact and the SSP back-matter pulls into the
RMS (RMS = LOOP-C.C7).

**Files to create**:

- `cloud-evidence/core/supply-chain-risk.ts` — ~550 lines. Exports
  `buildSupplyChainRiskRegister(input, opts): SupplyChainRiskRegister`,
  `emitSupplyChainRiskRegister(opts): SupplyChainRiskRegisterEmitResult`,
  types `RiskEntry`, `RegisterCoverage`,
  `SupplyChainRiskRegister`,
  `SupplyChainRiskRegisterEmitOptions`,
  `SupplyChainRiskRegisterEmitResult`.
- `cloud-evidence/tests/core/supply-chain-risk.test.ts` — ~15 tests.

**Files to extend**:

- `cloud-evidence/core/orchestrator.ts` — add `--supply-chain-risk`
  flag + `CLOUD_EVIDENCE_SUPPLY_CHAIN_RISK` env. Runs AFTER
  `--sbom-dir` (J.J3 reads the SBOM report) and AFTER `--privileges-matrix`
  + `--subprocessors-config` (J.J3 reads both outputs), and BEFORE
  signing.
- `cloud-evidence/core/submission-bundle.ts` — append to WELL_KNOWN:
  - `{ role: 'supply-chain-risk-register-json', filename: 'supply-chain-risk-register.json', description: 'SR-3 / NIST SP 800-161r1 supply chain risk register' }`
  - `{ role: 'supply-chain-risk-register-xlsx', filename: 'supply-chain-risk-register.xlsx', description: 'Supply chain risk register — FedRAMP-style Excel' }`
- `cloud-evidence/core/oscal-poam.ts` — when a `RiskEntry.status === 'open'`
  AND its `severity in {critical, high}`, embed the entry as a
  POA&M `risk` item with `risk-source = 'supply-chain'` prop. (This
  is a small additive change: the existing POA&M emitter walks per-KSI
  findings; J.J3 adds a new source feed.)
- `cloud-evidence/core/sbom.ts` — no schema change. J.J3 calls
  `buildSbomReport()` if it has not run yet, or reads
  `out/sbom-report.json` if it has.

**Schemas / standards**:

1. **NIST SP 800-53 Rev 5 SR-3** (https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
   — register IS the documented "supply chain processes and controls"
   artifact (SR-3.c).
2. **NIST SP 800-53 Rev 5 SR-4 (Provenance), SR-5 (Acquisition Strategies),
   SR-6 (Supplier Assessments and Reviews)** — register includes
   provenance fields per SR-4, supplier-assessment fields per SR-6.
3. **NIST SP 800-161 Rev 1** (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1.pdf)
   — register IS the per-system C-SCRM Plan artifact (Tier 3).
4. **NTIA SBOM Minimum Elements** (https://www.cisa.gov/sbom) —
   register `sbom_provenance[]` lines cite the seven required fields
   for each ingested SBOM.
5. **CycloneDX 1.5** (https://cyclonedx.org/docs/1.5/json/) — register
   `sbom_format: 'cyclonedx' | 'spdx'` mirrors `core/sbom.ts`
   `SbomFile.format`.
6. **SPDX 2.3** (https://spdx.github.io/spdx-spec/v2.3/) — same.
7. **CISA KEV catalog** (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
   — already ingested via `docs/cisa-kev.generated.json` +
   `core/kev-feed.ts:loadKevCatalog()`.

**Build steps**:

1. Define types:
   ```ts
   export type RiskCategory =
     | 'sbom-cve'                  // CVE in an SBOM component
     | 'sbom-cve-kev'              // CVE on CISA KEV list
     | 'subprocessor-risk-tier'    // tier-1-critical subprocessor exposure
     | 'subprocessor-soc2-expired' // attestation gap
     | 'unsigned-sbom'             // SBOM lacked cosign verification
     | 'vendor-advisory'           // operator-supplied advisory event
     | 'operator-asserted-risk';   // operator-entered free-form
   export interface RiskEntry {
     id: string;                                      // deterministic uuid (deterministicUuid from oscal.ts)
     category: RiskCategory;
     title: string;
     description: string;
     severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
     status: 'open' | 'monitoring' | 'mitigated' | 'accepted';
     affected_components?: string[];                  // name@version when SBOM-derived
     affected_subprocessors?: string[];               // name when subprocessor-derived
     cve_ids?: string[];
     kev_due_date?: string;                           // CISA published due-date for the KEV
     mitigation_summary?: string;                     // REQUIRES-OPERATOR-INPUT when status !== 'open'
     evidence_source: { module: string; record_id?: string }; // 'core/sbom.ts' etc.
     first_seen: string;
     last_seen: string;
     related_nist_controls: string[];                 // ['sr-3','sr-4',…]
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
     entries_missing_mitigation: string[];            // entry.id list
   }
   export interface SupplyChainRiskRegister {
     generated_at: string;
     system_id?: string;
     run_id: string;
     entries: RiskEntry[];
     coverage: RegisterCoverage;
     sbom_provenance: {
       sbom_file: string;
       format: 'cyclonedx' | 'spdx';
       supplier_name_field_present: boolean;          // NTIA min element #1
       component_name_field_present: boolean;
       version_field_present: boolean;
       unique_identifier_field_present: boolean;
       dependency_field_present: boolean;
       author_field_present: boolean;
       timestamp_field_present: boolean;
       signature_status: 'verified' | 'unverified' | 'absent';
     }[];
     subprocessor_summary: {
       total: number;
       tier_1_critical: number;
       tier_2_significant: number;
       tier_3_routine: number;
       missing_risk_tier: number;
     };
     provenance: {
       emitter: 'core/supply-chain-risk.ts';
       emitted_at: string;
       source_modules: string[];   // ['core/sbom.ts', 'core/kev-feed.ts', 'core/subprocessor-inventory.ts']
       source_files: string[];     // actual files read
     };
   }
   ```
2. Builder signature:
   ```ts
   export function buildSupplyChainRiskRegister(
     input: {
       sbomReport: SbomReport | null;        // from core/sbom.ts
       subprocessorInventory: SubprocessorInventory | null; // from J.J2
       kevCatalog: KevEntry[];               // from core/kev-feed.ts
       operatorRisks?: OperatorRiskEntry[];  // from --risks-config YAML
     },
     opts: { runId: string; systemId?: string; now?: () => Date }
   ): SupplyChainRiskRegister
   ```
   - Walk `sbomReport.vulnerabilities[]`. For each CVE → emit one
     `RiskEntry` (category `sbom-cve`). If the CVE id appears in
     `kevCatalog` → category becomes `sbom-cve-kev` and severity
     bumps to `critical`, `kev_due_date` is the CISA-published date.
   - Walk `sbomReport.sboms[]`. Any sbom with `signature_status !== 'verified'`
     → emit a `RiskEntry` (category `unsigned-sbom`).
   - Walk `subprocessorInventory.rows[]`. Each `risk_tier === 'tier-1-critical'`
     row → emit a `RiskEntry` (category `subprocessor-risk-tier`,
     severity `high`). Each row with expired `soc2_expiry` → emit
     `subprocessor-soc2-expired`.
   - Merge operator-supplied risks from `--risks-config` YAML.
3. Emitter signature:
   ```ts
   export interface SupplyChainRiskRegisterEmitOptions {
     outDir: string;
     runId: string;
     systemId?: string;
     sbomReportPath?: string;            // default outDir/sbom-report.json (if exists)
     subprocessorInventoryPath?: string; // default outDir/subprocessor-inventory.json
     kevCatalogPath?: string;            // default docs/cisa-kev.generated.json
     risksConfigPath?: string;
     jsonPath?: string;                  // default outDir/supply-chain-risk-register.json
     xlsxPath?: string;                  // default outDir/supply-chain-risk-register.xlsx
   }
   ```
4. Wire into orchestrator: order matters. Run order after `--collect`,
   after `--sbom-dir`, after `--subprocessors`/`--subprocessors-config`,
   after `--privileges-matrix`, BEFORE `--sign` and BEFORE
   `--submission-bundle`.
5. Bundler catalogue: add the two WELL_KNOWN entries above. Extend
   the `Role` union.
6. POA&M wiring: in `core/oscal-poam.ts`, after walking per-KSI
   findings, if `out/supply-chain-risk-register.json` exists, walk
   `entries[]` filtered to `status === 'open'` and
   `severity in {critical, high}`, and emit one `poam-item` per
   such entry with `props: [{ name: 'risk-source', value: 'supply-chain' }]`
   and the deterministic FedRAMP deadline math already in the emitter
   (Critical 30d, High 60d) but anchored at `RiskEntry.first_seen`.

**REQUIRES-OPERATOR-INPUT fields**:

- `RiskEntry.mitigation_summary` — source = `--risks-config` YAML or
  tracker UI (LOOP-B.B3 workflow). When `status !== 'open'` and no
  mitigation supplied → REQUIRES-OPERATOR-INPUT marker AND entry id
  added to `coverage.entries_missing_mitigation`.
- Operator-asserted risks: source = `--risks-config` YAML only. No
  fallback — when no config, the category-`operator-asserted-risk`
  partition is simply empty (not stubbed).

**Test specifications** (~15):

1. `it('builds a register from a real CycloneDX SBOM report + KEV catalog', …)` —
   fixture with one component matching a fixture KEV CVE → assert
   one entry with `category === 'sbom-cve-kev'` and severity bumped
   to `critical`.
2. `it('emits one unsigned-sbom entry per unverified SBOM file', …)`.
3. `it('emits subprocessor-risk-tier entries for tier-1-critical subprocessors', …)`.
4. `it('emits subprocessor-soc2-expired entries when soc2_expiry is past opts.now', …)`.
5. `it('uses CISA KEV published due-date as kev_due_date', …)`.
6. `it('merges operator-asserted-risk entries from --risks-config YAML', …)`.
7. `it('computes coverage.kev_exposed correctly', …)`.
8. `it('emits REQUIRES-OPERATOR-INPUT in mitigation_summary when status !== open and no operator input', …)`.
9. `it('produces deterministic uuids for the same input set', …)` —
   run twice, compare register sha256.
10. `it('records sbom_provenance with NTIA minimum-element field flags per ingested SBOM', …)`.
11. `it('throws a typed error when sbomReport AND subprocessorInventory AND operatorRisks are all empty', …)` —
    bare register would be meaningless; emitter surfaces the gap.
12. `it('records provenance.source_modules listing exactly the modules read', …)`.
13. `it('emits POA&M items for open critical/high entries when --oscal-poam runs in same pipeline', …)` —
    integration test; assert POA&M has the new items with
    `risk-source = supply-chain` prop.
14. `it('uses RiskEntry.first_seen as POA&M deadline anchor, not run timestamp', …)`.
15. `it('writes XLSX with one sheet per RiskCategory', …)` — multi-sheet
    layout: SBOM-CVE / SBOM-CVE-KEV / Subprocessor-Risk / Unsigned-SBOM /
    Vendor-Advisory / Operator-Asserted.

**REO compliance**:

- Every entry traces back to a real source: SBOM report (real Syft /
  Trivy / Grype output), CISA KEV catalog (committed
  `docs/cisa-kev.generated.json`), subprocessor inventory (real
  operator config or sheet), or operator YAML.
- No invented CVE ids, no synthesized severity for SBOM CVEs (severity
  comes from the SBOM report, which comes from the NVD index via
  `core/sbom.ts` — see the existing module's `correlateVulns`).
- Mitigation language is operator-input only — never auto-generated.
- The `provenance.source_files[]` lists actual file paths read; if a
  file is absent and another is present, that file is omitted from
  the list. No fictitious sources.
- The `sbom_provenance[]` per-SBOM field flags are computed from real
  parse, not assumed `true`.

**Verification commands**:

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/supply-chain-risk.test.ts
npm run check:reo
```

**Estimated effort**: 1.25 weeks (6-7 working days). Most of the work
is the cross-source join + multi-sheet XLSX + POA&M integration
test.

---

## 5. Loop-wide acceptance criteria

LOOP-J is complete when ALL of:

- All three slices ship per the per-slice acceptance above.
- `npm run typecheck && npm test && npm run check:reo` — all green.
- Submission bundle (`out/submission-bundle.tar.gz`) contains:
  - `privileges-matrix.json` + `privileges-matrix.xlsx` (J.J1)
  - `subprocessor-inventory.json` + `subprocessor-inventory.xlsx` (J.J2)
  - `supply-chain-risk-register.json` + `supply-chain-risk-register.xlsx` (J.J3)
  - All three covered by the signed manifest.
  - `INDEX.json` lists all six with correct roles + sha256.
- The OSCAL SSP, when emitted alongside, references the privileges
  matrix in `back-matter` AND populates `system-implementation.users[]`
  from real role data.
- The OSCAL POA&M, when emitted alongside with open critical/high
  supply-chain risks, embeds those risks as `poam-item`s with
  `props.risk-source = 'supply-chain'`.
- CHANGELOG "Unreleased" section gains 3 entries (one per slice) with
  module names + test counts + verification status.
- `cloud-evidence/docs/STATUS.md` shows J.J1 / J.J2 / J.J3 done.
- A single orchestrator invocation:
  ```
  npm run collect -- --collect KSI-IAM-AAM,KSI-IAM-ELP \
    --privileges-matrix --roles-config examples/roles-config.yaml \
    --subprocessors-config examples/subprocessors.yaml \
    --sbom-dir ../sbom \
    --supply-chain-risk --risks-config examples/risks.yaml \
    --oscal-ssp --oscal-ap --oscal-poam \
    --sign --submission-bundle
  ```
  produces a complete signed submission package end-to-end.
- 3PAO acceptance test (manual): a 3PAO can open the .xlsx files in
  Excel without conversion errors; the .json files validate against
  their respective TypeScript interfaces; the multi-sheet workbook
  opens with all named tabs visible.

---

## 6. Open questions / caveats

1. **FedRAMP SaaS Subprocessor Inventory canonical field list**: We
   mirror the existing `SubprocessorRow` shape (already production)
   and add J.J2 fields. If FedRAMP publishes a v2 template with a
   different column order, the XLSX writer is parameterized by a
   column-order array so an update is a one-line patch.
2. **Multi-sheet XLSX writer**: `core/inventory-workbook.ts` currently
   emits a single-sheet workbook. J.J1 + J.J3 + J.J2 all need
   multi-sheet support. A sub-task of J.J1 is to extend `rowsToXlsx`
   to accept `{ sheets: { name: string; rows: string[][] }[] }`. This
   stays REO-compliant (additive feature, no fake data).
3. **YAML library**: `package.json` should be checked first — if
   neither `yaml` nor `js-yaml` is present, J.J2 introduces one (the
   pure-JS `yaml` package is preferred; no native deps).
4. **POA&M integration ordering**: J.J3's POA&M wiring is additive
   to LOOP-A.A1. If LOOP-B.B5 (Central Risk Register) lands later, it
   aggregates J.J3 into a higher-level register; the wire format stays
   the same.
5. **OSCAL SR-3/SR-4 properties**: OSCAL v1.1.2 does not natively
   model a supply-chain risk register. J.J3 emits the register as a
   standalone JSON file referenced from the SSP back-matter — NOT as
   OSCAL "risks" inside an existing model. If a future OSCAL release
   adds a `supply-chain` model, we will retrofit a converter.
6. **NIST SP 800-161 r1 supplier risk tiers**: 800-161r1 does not
   standardize a 3-tier classification — we choose
   `tier-1-critical` / `tier-2-significant` / `tier-3-routine` as
   commonly-used industry naming. Documented in the file's header
   comment with citation.
7. **CVE severity source**: SBOM CVE severities flow through
   `core/sbom.ts`'s `SBOM_NVD_INDEX_PATH` env. If the env is unset,
   severity is `UNKNOWN` — J.J3 maps `UNKNOWN` → `medium` for register
   bookkeeping but flags the entry as
   `requires_operator_input: 'severity'`. Never silently defaults to
   `low`.

---

## 7. Status tracking

| Slice ID | Status | Commit hash | Completed date |
|---|---|---|---|
| J.J1 — Privileges matrix (AC-2/AC-6) | pending | — | — |
| J.J2 — Subprocessor inventory expansion (SA-9) | pending | — | — |
| J.J3 — Supply chain risk register (SR-3) + SBOM integration | pending | — | — |

---

## 8. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST:

1. Run `npm run typecheck && npm test && npm run check:reo` — all
   green. No new lint:no-stubs hits. Provenance and coverage-regression
   guards pass.
2. Update the Section 7 status table:
   - Set `Status` = `done`
   - Set `Commit hash` = the 7-character abbreviated commit hash
   - Set `Completed date` = ISO 8601 date (YYYY-MM-DD)
3. Add a `CHANGELOG.md` "Unreleased" entry under
   `### Added — LOOP-J.<slice-id>: <title>`. Naming convention
   mirrors LOOP-A entries. Required content:
   - Module names created/extended (with file paths)
   - Verification counts (typecheck status, total tests passing
     and the delta from this slice, `npm run check:reo` status)
   - REO compliance summary (operator-input markers used,
     provenance fields, any synthesized fields with opt-in)
4. Update `cloud-evidence/docs/STATUS.md` — set the slice's row to
   `done`. (If `STATUS.md` does not yet exist, create it on the first
   LOOP-J slice with the same Status table format as Section 7
   above.)
5. Commit using a HEREDOC message (matches existing repo style):
   ```bash
   git commit -m "$(cat <<'EOF'
   LOOP-J.<slice-id>: <title>

   <one-paragraph summary mirroring CHANGELOG entry tone>

   Verification: typecheck clean; <total> tests passing
   (+<delta> from LOOP-J.<slice-id>); npm run check:reo returns 0.

   Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
   EOF
   )"
   ```
6. Push to `origin/main` (unless the operator requests otherwise).

REO violations at any of these steps abort the slice: the implementer
must fix the underlying issue and create a NEW commit (never `--amend`
through hook failures).
