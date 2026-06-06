---
slice_id: J.J1
title: User Roles & Privileges matrix (AC-2 + AC-6)
loop: J
status: pending
commit: —
completed_date: —
depends_on: [A.A4, SSP-1, IAM-AAM-AWS, IAM-AAM-GCP, IAM-AAM-AZ, IAM-ELP-AWS, IAM-ELP-GCP, IAM-ELP-AZ]
blocks: [G.G4, B.B5, C.C7, I.I1]
estimated_effort: 1 week (5 working days)
last_updated: 2026-06-06
---

# J.J1 — User Roles & Privileges matrix (AC-2 + AC-6)

## TL;DR
Emits a signed `privileges-matrix.json` + multi-sheet `privileges-matrix.xlsx`
that cross-tabulates every cloud role (AWS IAM / GCP IAM / Azure Entra ID +
RBAC) against the privileges granted to it, with `none` / `read` / `write` /
`admin` levels and operator-supplied least-privilege justifications. This is
the SSP-Appendix-Q artifact every 3PAO requests on day one; it closes the
NIST 800-53 AC-2 (Account Management) + AC-6 (Least Privilege) Appendix gap
that LOOP-A intentionally deferred.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
NIST SP 800-53 Rev 5 control AC-6 ("Least Privilege") and control AC-2
("Account Management") require an authorization package to document the
"types of accounts allowed and specifically prohibited", the "prerequisites
and criteria for group and role membership", and a verifiable least-privilege
posture. The FedRAMP Rev 5 SSP template carries this as **Appendix Q — User
Roles and Privileges** (often called "Table 9.4 / 9.5" depending on template
vintage); 3PAOs use this table to verify AC-2(a)/(c)/(d)/(g)/(h) +
AC-6(1)/(7)/(9) implementation.

Today our SSP emits `system-implementation.users[]` as a roles list, but the
cross-tabulated **role × privilege × level** matrix is missing. The matrix is
the single most-requested artifact during 3PAO discovery interviews; it is
currently produced by hand from console screenshots, which has three
failure modes:

1. **Stale** — screenshots age out within days.
2. **Inconsistent across clouds** — AWS / GCP / Azure each use different
   role-naming and binding conventions.
3. **Unsigned** — there is no manifest-bound, Ed25519-signed version that a
   3PAO can verify came from a specific orchestrator run.

J.J1 closes all three: real IAM evidence flows from existing collectors,
the matrix is computed deterministically, and it is signed under the run
manifest the bundler ships.

## Authoritative sources (with verbatim quotes)

- **NIST SP 800-53 Rev 5 §AC-6 (Least Privilege)** — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — p. 31 (control AC-6 base):
  > "Employ the principle of least privilege, allowing only authorized
  > accesses for users (or processes acting on behalf of users) that are
  > necessary to accomplish assigned organizational tasks."

- **NIST SP 800-53 Rev 5 §AC-6(1) (Authorize Access to Security Functions)** — same PDF, p. 31:
  > "Authorize access for [Assignment: organization-defined individuals or
  > roles] to: (a) [Assignment: organization-defined security functions
  > (deployed in hardware, software, and firmware)]; and (b) [Assignment:
  > organization-defined security-relevant information]."

- **NIST SP 800-53 Rev 5 §AC-6(9) (Log Use of Privileged Functions)** — same PDF, p. 32:
  > "Log the execution of privileged functions."

- **NIST SP 800-53 Rev 5 §AC-2(a) (Account Management — Define account types)** — same PDF, p. 23:
  > "Define and document the types of accounts allowed and specifically
  > prohibited for use within the system."

- **NIST SP 800-53 Rev 5 §AC-2(c) (Account Management — Prerequisites and criteria)** — same PDF, p. 23:
  > "Require [Assignment: organization-defined prerequisites and criteria]
  > for group and role membership."

- **NIST SP 800-53 Rev 5 §AC-2(g) (Account Management — Monitor use)** — same PDF, p. 23:
  > "Monitor the use of accounts."

- **FedRAMP Rev 5 SSP Template (Appendix Q "User Roles and Privileges")** —
  https://www.fedramp.gov/docs/rev5/templates/ — Appendix Q canonical fields:
  `Role Name`, `Internal/External`, `Privileged (Y/N)`, `Sensitivity Level`,
  `Authorized Privileges`, `Functions Performed`. The cross-tabulated matrix
  is required submission content; the bare roles list is insufficient.

- **AWS IAM API reference — ListRoles** — https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRoles.html:
  > "Lists the IAM roles that have the specified path prefix. If there are
  > none, the operation returns an empty list."

- **AWS IAM API reference — ListAttachedRolePolicies** —
  https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedRolePolicies.html
  is the source for the granted-via attribution in `MatrixCell.granted_via`.

- **AWS managed policy ARN — AdministratorAccess** —
  `arn:aws:iam::aws:policy/AdministratorAccess` (cloud-published constant,
  REO Rule 3 allowed) — anchors `privilege_level = 'admin'` classification.

- **GCP IAM predefined roles — roles/owner, roles/editor, roles/viewer** —
  https://cloud.google.com/iam/docs/understanding-roles — cloud-published
  constants. `roles/owner` is "Full access to most Google Cloud resources" —
  classified as `admin`. `roles/viewer` is "Read access to all resources" —
  classified as `read`.

- **Azure built-in RBAC roles** — https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles — `Owner` ("Grants full access to manage all resources"),
  `Contributor` ("Grants full access to manage all resources, but does not
  allow you to assign roles in Azure RBAC"), and `User Access Administrator`
  ("Lets you manage user access to Azure resources") are admin; `Reader`
  is read.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/privileges-matrix.ts`
  — pure builder + disk emitter. ~600 lines. Exports
  `buildPrivilegesMatrix(input, opts): PrivilegesMatrix`,
  `emitPrivilegesMatrix(opts): PrivilegesMatrixEmitResult`, types
  `Role`, `Privilege`, `MatrixCell`, `PrivilegesMatrix`,
  `PrivilegesMatrixEmitOptions`, `PrivilegesMatrixEmitResult`,
  `OperatorRoleConfig`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/privileges-matrix.test.ts`
  — ≥14 tests covering the contracts below.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/privileges-matrix/KSI-IAM-AAM.aws.json`
  — fixture envelope for AWS AAM case.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/privileges-matrix/KSI-IAM-AAM.gcp.json`
  — GCP AAM fixture.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/privileges-matrix/KSI-IAM-AAM.azure.json`
  — Azure AAM fixture.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/privileges-matrix/KSI-IAM-ELP.{aws,gcp,azure}.json`
  — ELP per-cloud fixtures.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/privileges-matrix/roles-config.example.yaml`
  — operator config fixture with business justifications.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/examples/roles-config.yaml`
  — committed example operator config (under `examples/`, REO-allowed).

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — add `--privileges-matrix` flag + `CLOUD_EVIDENCE_PRIVILEGES_MATRIX=1`
  env. Add `--roles-config <path>` + `CLOUD_EVIDENCE_ROLES_CONFIG` env.
  Runs AFTER `--collect KSI-IAM-AAM,KSI-IAM-ELP` (needs the envelopes on
  disk) and BEFORE `--sign` (so the matrix is covered by the manifest).
  Console line on success: `privileges-matrix: <R> roles · <C> cells · <A> admin · <X> REQUIRES-OPERATOR-INPUT`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — extend the `Role` union with `'privileges-matrix-json'` and
  `'privileges-matrix-xlsx'`. Append two entries to the WELL_KNOWN
  artifact catalogue:
  - `{ role: 'privileges-matrix-xlsx', filename: 'privileges-matrix.xlsx', description: 'User Roles & Privileges matrix (AC-2/AC-6) — auto-derived from IAM evidence' }`
  - `{ role: 'privileges-matrix-json', filename: 'privileges-matrix.json', description: 'Structured roles × privileges matrix used by the SSP appendix' }`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts`
  — when `out/privileges-matrix.json` exists, hydrate
  `system-implementation.users[]` from the matrix's `roles[]` (one user
  block per Role) and add a `back-matter.resources[]` entry whose `title`
  is `"User Roles & Privileges Matrix (AC-2 / AC-6)"` and `rlinks[]`
  point at `privileges-matrix.xlsx` and `privileges-matrix.json`. If the
  file is absent, the SSP emitter falls back to its current behaviour
  (REQUIRES-OPERATOR-INPUT marker on users[]).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-workbook.ts`
  — extend `rowsToXlsx` to accept `{ sheets: { name: string; rows: string[][] }[] }`
  so a single workbook can hold the three tabs (Roles / Privileges Matrix /
  Coverage). This is an additive change; existing single-sheet callers
  remain working.

## Schemas / standards

### NIST SP 800-53 Rev 5 AC-2 / AC-6 required fields → matrix mapping

| Requirement | Matrix field | REQUIRES-OPERATOR-INPUT when |
|---|---|---|
| AC-2(a) account type | `Role.type` (enum: `human-user`, `non-user`, `service-principal`, `break-glass`) | derived from cloud (AWS user vs role, GCP user vs service-account, Azure user vs service-principal) — never operator-input |
| AC-2(b) assign account managers | `Role.account_manager_party_uuid` | absent in operator YAML |
| AC-2(c) prerequisites & criteria | `Role.membership_criteria` | absent in operator YAML |
| AC-2(g) monitor use | `Role.last_used_at` | not directly required for matrix (IAM evidence shows last-used) |
| AC-6 base — least privilege | `MatrixCell.privilege_level` enum (`none` / `read` / `write` / `admin`) | derived from cloud — never operator-input |
| AC-6(1) authorize security functions | `MatrixCell.justification` (required when level === 'admin') | level is admin AND no operator entry |
| Business reason for the role | `Role.business_justification` | absent in operator YAML |

### FedRAMP Appendix Q column mapping

| FedRAMP column | Matrix source |
|---|---|
| Role Name | `Role.name` |
| Internal/External | `Role.type` (`human-user`/`non-user`/`service-principal` → Internal; `break-glass` → flagged) |
| Privileged (Y/N) | derived: any `MatrixCell` with `privilege_level === 'admin'` and `role_id === this.id` → Y |
| Sensitivity Level | operator-supplied via `roles-config.yaml` `sensitivity_level` field |
| Authorized Privileges | bullet list rendered from `cells[]` where `role_id === this.id` |
| Functions Performed | `Role.business_justification` (operator YAML) |

### Classification heuristics (REO-compliant, cloud-published constants only)

- **AWS**:
  - Attached policy ARN matches `arn:aws:iam::aws:policy/AdministratorAccess`
    → `admin` (every `*`/`*` cell).
  - `arn:aws:iam::aws:policy/ReadOnlyAccess` → `read` (every covered cell).
  - Any other AWS-managed policy (`arn:aws:iam::aws:policy/*`) → `write`
    unless the `Action` list resolves entirely to `*:Get*` / `*:List*` /
    `*:Describe*` (in which case `read`).
  - Customer-managed policies → use the actual Action list when
    `RawEvidence.data.policy_document` is available; otherwise `write` and
    flag in `coverage.coarse_classification[]`.
- **GCP**:
  - Predefined role `roles/owner` → `admin`.
  - `roles/editor` → `admin` (editor has resource-modification rights;
    FedRAMP rates editor as privileged).
  - `roles/viewer` → `read`.
  - Predefined `roles/*Admin` → `admin`.
  - Custom roles → walk `IncludedPermissions[]` from
    `iam.projects.roles.get`; classify `read` if all permissions end in
    `.get` / `.list` / `.getIamPolicy`, else `write`.
- **Azure**:
  - Built-in role `Owner` → `admin`.
  - `Contributor` → `admin`.
  - `User Access Administrator` → `admin`.
  - `Reader` → `read`.
  - Custom RBAC role → walk `permissions[].actions[]`; classify `read`
    when all actions match `Microsoft.*/read` / `*/list/action`, else
    `write`.

### Multi-sheet XLSX layout

| Sheet name | Rows |
|---|---|
| `Roles` | One row per Role, columns: id, name, type, cloud, account_manager_party_uuid, membership_criteria, business_justification, sensitivity_level, last_used_at |
| `Privileges Matrix` | One row per MatrixCell, columns: role_id, role_name, privilege_id, resource_type, action, privilege_level, granted_via, justification, evidence_envelope |
| `Coverage` | A summary block: total_roles, roles_with_business_justification, admin_cells, admin_cells_missing_justification, roles_missing_justification (one per line). |

## Build steps (concrete, numbered)

1. **Define interfaces** in `core/privileges-matrix.ts` (verbatim from
   LOOP-J-SPEC.md §4 J.J1 Build steps):
   ```ts
   export interface Role {
     id: string;
     name: string;
     type: 'human-user' | 'non-user' | 'service-principal' | 'break-glass';
     cloud: 'aws' | 'gcp' | 'azure';
     account_manager_party_uuid?: string;
     membership_criteria?: string;
     business_justification?: string;
     sensitivity_level?: 'low' | 'moderate' | 'high';
     created_at?: string;
     last_used_at?: string;
     evidence_source: { ksi: 'KSI-IAM-AAM' | 'KSI-IAM-ELP'; envelope_path: string };
   }
   export interface Privilege { id: string; resource_type: string; action: string; scope?: string; }
   export interface MatrixCell {
     role_id: string;
     privilege_id: string;
     privilege_level: 'none' | 'read' | 'write' | 'admin';
     granted_via: string;
     justification?: string;
     evidence_envelope: string;
   }
   export interface PrivilegesMatrix {
     generated_at: string; system_id?: string; run_id: string;
     roles: Role[]; privileges: Privilege[]; cells: MatrixCell[];
     coverage: {
       total_roles: number;
       roles_with_business_justification: number;
       roles_missing_justification: string[];
       admin_cells: number;
       admin_cells_missing_justification: string[];
       coarse_classification: string[];
     };
     provenance: {
       emitter: 'core/privileges-matrix.ts';
       emitted_at: string;
       source_envelopes: string[];
       source_calls: string[];
     };
   }
   ```
2. **Pure builder** `buildPrivilegesMatrix(input, opts)`:
   - Walk `input.iamAamEnvelopes[].providers[].evidence[].data` and
     `input.iamElpEnvelopes[].providers[].evidence[].data` for the real
     role list, the real binding list, and the per-role attached-policy
     list. Normalize across clouds into `Role` + `MatrixCell` shape.
   - Apply classification heuristics (table above).
   - Merge `input.operatorRoles[]` per role id (operator-supplied
     `business_justification`, `account_manager_party_uuid`,
     `membership_criteria`, `sensitivity_level`, and per-cell
     `cell_justifications[]`).
   - Compute `coverage` counts deterministically.
   - Stamp `provenance.source_envelopes[]` with absolute paths and
     `provenance.source_calls[]` with the verbatim SDK call names from
     each `RawEvidence.source`.
3. **Operator-config reader** `readRolesConfig(path: string): OperatorRoleConfig[]`:
   - Accepts YAML or JSON. YAML parsed via the `yaml` dep already in
     `package.json` (^2.6.0 — verified).
   - Validates against an inline TS interface; rejects unknown top-level
     keys to surface typos early.
4. **Disk emitter** `emitPrivilegesMatrix(opts)`:
   - Reads `outDir/KSI-IAM-AAM.json` and `outDir/KSI-IAM-ELP.json`. If
     either is missing, throws `Error('privileges-matrix: KSI-IAM-AAM
     envelope missing at ' + path + '; rerun with --collect KSI-IAM-AAM
     before --privileges-matrix')`.
   - Writes `outDir/privileges-matrix.json` and
     `outDir/privileges-matrix.xlsx`.
   - .xlsx uses extended `rowsToXlsx({ sheets })` (see "Files to extend").
   - Returns `{ json_path, xlsx_path, matrix, bytes_json, bytes_xlsx,
     requires_operator_input: string[] }`.
5. **Wire into orchestrator** (`core/orchestrator.ts`):
   - Parse `--privileges-matrix` flag + `CLOUD_EVIDENCE_PRIVILEGES_MATRIX`
     env. Parse `--roles-config <path>` + `CLOUD_EVIDENCE_ROLES_CONFIG`.
   - Schedule after `--collect` resolution and before `--sign`.
   - Log line on completion.
6. **SSP back-matter wiring** (`core/oscal-ssp.ts`):
   - On `buildOscalSsp` entry, attempt `readFileSync(outDir +
     '/privileges-matrix.json')`. If present, parse + hydrate
     `system-implementation.users[]` and add a `back-matter.resources[]`
     entry. If absent, current behaviour stands.
7. **Bundler catalogue** (`core/submission-bundle.ts`):
   - Add the two WELL_KNOWN entries listed in "Files to extend".
   - The bundler picks up both files automatically via the manifest scan.
8. **Validation pass**:
   - Inline TS guards on every Role / Privilege / MatrixCell construction.
   - No ajv schema for this artifact (it's not OSCAL); structural checks
     live in `tests/core/privileges-matrix.test.ts`.
9. **Signing + timestamping**: already covered by the existing
   `core/sign.ts` pipeline because the emitter runs before `--sign`.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Fallback behavior |
|---|---|---|
| `Role.account_manager_party_uuid` | `--roles-config` YAML per role id | `REQUIRES-OPERATOR-INPUT` literal in XLSX; role.id added to `coverage.roles_missing_justification` |
| `Role.membership_criteria` | `--roles-config` YAML | same |
| `Role.business_justification` | `--roles-config` YAML | same |
| `Role.sensitivity_level` | `--roles-config` YAML | `REQUIRES-OPERATOR-INPUT` |
| `MatrixCell.justification` (when `privilege_level === 'admin'`) | `--roles-config` YAML per `(role_id, privilege_id)` | `REQUIRES-OPERATOR-INPUT`; cell key added to `coverage.admin_cells_missing_justification` |

The literal string is `'REQUIRES-OPERATOR-INPUT'`. A `const TBD =
'REQUIRES-OPERATOR-INPUT'` is defined at the top of `privileges-matrix.ts`
mirroring the pattern in `core/roe-emit.ts`.

## Test specifications (≥14 tests)

1. `it('builds a 3-cloud matrix from real KSI-IAM-AAM + KSI-IAM-ELP envelopes')`
   — fixtures contain one AWS role, one GCP service account, one Azure role
   assignment. Assert: `matrix.roles.length === 3`, each `role.cloud`
   correct, `cells.length >= 3`.
2. `it('classifies AWS AdministratorAccess as privilege_level=admin')` —
   fixture with `arn:aws:iam::aws:policy/AdministratorAccess` attached →
   assert at least one cell has `privilege_level === 'admin'` and
   `granted_via` references the policy ARN string.
3. `it('classifies AWS ReadOnlyAccess as read')`.
4. `it('classifies GCP roles/viewer as read')` — assert `cell.privilege_level
   === 'read'` and `cell.granted_via === 'roles/viewer'`.
5. `it('classifies GCP roles/owner as admin')`.
6. `it('classifies Azure Owner role as admin')`.
7. `it('classifies Azure Reader role as read')`.
8. `it('emits REQUIRES-OPERATOR-INPUT when business_justification is missing')`
   — no `--roles-config` → assert `matrix.coverage.roles_missing_justification`
   non-empty AND the .xlsx Roles sheet cell text is literally
   `'REQUIRES-OPERATOR-INPUT'`.
9. `it('honors operator-supplied business_justification from --roles-config')`
   — pass `rolesConfigPath` → assert verbatim string flows to
   `role.business_justification`.
10. `it('flags admin cells missing justification')` — operator provides
    role-level justification but no per-cell admin justification → cell
    stays REQUIRES-OPERATOR-INPUT and
    `coverage.admin_cells_missing_justification` lists the cell id.
11. `it('throws a typed error when KSI-IAM-AAM envelope is missing')` —
    empty outDir → throws with message containing
    `'--collect KSI-IAM-AAM'`.
12. `it('throws a typed error when KSI-IAM-ELP envelope is missing')`.
13. `it('produces a multi-sheet XLSX with Roles / Privileges Matrix / Coverage tabs')`
    — read the emitted .xlsx as zip; assert `xl/worksheets/sheet1.xml`,
    `sheet2.xml`, `sheet3.xml` parts exist; assert sheet names match.
14. `it('produces deterministic JSON given identical envelopes + operator config')`
    — run twice with same inputs → sha256 of `privileges-matrix.json`
    matches.
15. `it('records provenance.source_envelopes pointing to the actual KSI files')`.
16. `it('records provenance.source_calls verbatim from RawEvidence.source')`
    — assert `'iam:ListRoles'` (or `iam.projects.serviceAccounts.list`,
    or `roleAssignments.list`) appears in `provenance.source_calls[]`.
17. `it('emits a SSP back-matter resource when run alongside oscal-ssp')`
    — integration: emit matrix → emit SSP → parse SSP →
    `back-matter.resources[]` contains entry with title
    `'User Roles & Privileges Matrix (AC-2 / AC-6)'`.
18. `it('hydrates system-implementation.users[] from matrix roles when matrix exists')`
    — same SSP integration; assert one users[] entry per matrix Role.

## REO compliance specific to this slice

- Every value in `roles[]` traces back to a real
  `KSI-IAM-AAM.json` / `KSI-IAM-ELP.json` envelope on disk; no role names
  fabricated.
- Cloud-published role names (`AdministratorAccess`, `roles/viewer`,
  `Owner`, `Contributor`, `Reader`, `User Access Administrator`) are
  REO-allowed under Rule 3 (cloud-published constants).
- Operator-input markers are emitted via the exact literal
  `'REQUIRES-OPERATOR-INPUT'` — define `const TBD = 'REQUIRES-OPERATOR-INPUT'`
  at the top, matching `core/roe-emit.ts` precedent.
- No silent fallback when an IAM envelope is missing — typed error with
  the exact orchestrator flag the operator must run.
- No mock SDK calls in production code; tests inject fixture envelopes
  on disk (the REO-allowed seam).
- Provenance fields populated: `emitter`, `emitted_at`,
  `source_envelopes[]`, `source_calls[]`.
- Signed by: existing `core/sign.ts` pipeline (Ed25519 + RFC 3161).

## Verification commands

```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/privileges-matrix.test.ts
npm run check:reo
```

For the end-to-end integration check:

```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run collect -- --collect KSI-IAM-AAM,KSI-IAM-ELP \
  --privileges-matrix --roles-config examples/roles-config.yaml \
  --oscal-ssp --sign --submission-bundle
ls -la out/privileges-matrix.{json,xlsx}
unzip -l out/submission-bundle.tar.gz | grep privileges-matrix
```

## Known risks / issues

- **Risk 1 — Multi-sheet XLSX writer**: `core/inventory-workbook.ts` currently
  emits a single-sheet workbook. Extending `rowsToXlsx` to support
  `{ sheets }` shape is additive but touches an existing module. Mitigation:
  keep the single-sheet signature working (overload, not replacement); add
  a vitest unit test for the extended signature before wiring J.J1.
- **Risk 2 — Custom AWS managed-policy classification accuracy**: a
  customer-managed policy with a mix of read + write actions could be
  mis-classified as `write` when reality is `admin` (e.g. an `iam:*`
  action). Mitigation: when the `policy_document.Statement[].Action[]`
  list contains any `iam:Create*` / `iam:Delete*` / `iam:Put*` action OR
  any `*` wildcard, escalate to `admin`. Document the heuristic in the
  emitter's header comment. Add a test fixture for the `iam:*` case.
- **Risk 3 — GCP custom-role permission resolution**: getting the
  expanded permissions list for a custom role requires
  `iam.projects.roles.get`, which the AAM collector may not currently
  call. Mitigation: ELP collector does pull `IncludedPermissions[]` — if
  AAM lacks it, the builder reads from ELP envelope only and records
  `coverage.coarse_classification[]` per role missing detail. Do NOT
  add a new SDK call in J.J1; that is collector work.
- **Risk 4 — Service-principal vs non-user classification**: AWS roles
  used by services (e.g. assumed by Lambda) should be `non-user`, not
  `service-principal`. Mitigation: inspect `AssumeRolePolicyDocument`
  for `Service` principals → classify as `non-user`; for `AWS` ARNs
  outside the account → `service-principal`; otherwise `human-user`.
- **Risk 5 — Determinism**: cloud APIs may return roles/bindings in
  unpredictable order. Mitigation: sort `roles[]` by `id` (lexicographic)
  and `cells[]` by `(role_id, privilege_id)` before emission. Test
  `it('produces deterministic JSON given identical envelopes + operator config')`
  verifies this.
- **Risk 6 — Azure subscription scope ambiguity**: Azure roleAssignments
  are scoped (subscription / resource-group / resource). The matrix's
  `Privilege.scope` field captures this; tests must cover all three
  scope levels with separate fixtures.
- **Risk 7 — SSP back-matter idempotency**: if `oscal-ssp` already has a
  back-matter resource for the matrix, re-running must not duplicate it.
  Mitigation: dedup by `title` + `rlinks[].href` when populating.

## Open questions (for implementation session to resolve)

- **Q1**: How does AAM-vs-ELP overlap resolve when both envelopes contain
  the same role? Provisional: ELP wins (more authoritative for least-
  privilege details); record both in `evidence_source` for traceability.
- **Q2**: Should `break-glass` accounts be auto-detected (e.g. by name
  prefix / role tag) or operator-input-only? Provisional: operator-input
  only via `roles-config.yaml` `break_glass: true` flag — auto-detection
  by name is a REO-violation risk (would substitute a heuristic for
  evidence).
- **Q3**: What happens if the operator's roles-config YAML references a
  role id that no longer exists in IAM (stale config)? Provisional:
  emit a `warnings[]` line ("operator config references unknown role
  `<id>`") but do NOT block emission — operator may have just rotated
  the role.
- **Q4**: Should `Role.sensitivity_level` default to `moderate` for an
  AC-6(7)-flagged privileged role with no operator entry? **No** —
  defaulting masks missing input. Stays REQUIRES-OPERATOR-INPUT.
- **Q5**: How granular should `MatrixCell.privilege_id` be when the
  attached policy is `AdministratorAccess`? Provisional: emit one cell
  per resource_type covered in the SSP boundary (S3, EC2, IAM, KMS,
  etc.) all set to admin, so 3PAOs can read it column-by-column.
  Alternative: emit a single cell with `privilege_id = '*:*:*'` — more
  honest but harder to read. Decide during implementation.
- **Q6**: Does the SSP integration test require a real or fixture FRMR
  catalog read? Provisional: fixture (deterministic + offline).

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥14 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (J.J1 row + Overall section)
- [ ] LOOP-J-SPEC.md Section 7 status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added
- [ ] Commit with `LOOP-J.J1: User Roles & Privileges matrix` in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-J-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here's everything it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-J-SPEC.md` Section 2 (Dependencies) for context on this loop.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Skim `cloud-evidence/core/roe-emit.ts` (REQUIRES-OPERATOR-INPUT pattern) and `cloud-evidence/core/inventory-workbook.ts` (xlsx writer pattern) before coding.
6. Sanity-check that `providers/aws/iam.ts`, `providers/gcp/iam.ts`, and
   `providers/azure/iam.ts` collectors actually produce the
   `RawEvidence.data` fields the builder reads (role list, bindings,
   attached-policy ARNs / role-binding role names / roleDefinition ids).
7. Begin implementation; update Implementation log section as you go.
