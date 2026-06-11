# LOOP-J — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status = resolved` + resolution note +
> commit hash. Each per-slice risks register section is the authoritative
> "as of now" view for that slice.

Last updated: 2026-06-06

LOOP-J ships three slices that emit FedRAMP-grade documentation
artifacts: J.J1 (User Roles & Privileges matrix — AC-2 + AC-6), J.J2
(Subprocessor inventory expansion — SA-9), J.J3 (Supply chain risk
register — SR-3 + SBOM integration). The risks below are the
authorization-relevant + implementation-relevant risks across all three.

## Cross-cutting risks (apply to ALL slices in this loop)

### CC-1 — Multi-sheet XLSX writer extension
- **Description**: All three slices need multi-sheet XLSX output, but
  `core/inventory-workbook.ts` `rowsToXlsx` currently emits single-sheet
  only. J.J1 owns the extension; J.J2 + J.J3 consume it. If J.J3 ships
  before J.J1 (out-of-order), J.J3 must extend `rowsToXlsx` itself.
- **Severity**: medium
- **Mitigation**: Extend `rowsToXlsx` as an additive overload (accepts
  EITHER `string[][]` for legacy single-sheet OR
  `{ sheets: { name: string; rows: string[][] }[] }` for multi-sheet).
  Document the new shape in the file header. Add unit tests for both
  shapes. Ensure existing single-sheet callers (inventory workbook,
  any others) are not broken.
- **Status**: open
- **Owner**: J.J1 (primary), J.J2 + J.J3 (consumers)

### CC-2 — YAML dependency introduction
- **Description**: J.J1 (`roles-config.yaml`), J.J2
  (`subprocessors.yaml`), and J.J3 (`risks-config.yaml`) all parse YAML
  operator config. The repo may or may not already include a YAML
  library. If absent, J.J2 introduces `yaml@^2.6.0` (pure-JS, no native
  deps).
- **Severity**: low
- **Mitigation**: J.J2 implementing session checks `package.json` first;
  reuses existing dep if `yaml` or `js-yaml` present. If neither, adds
  `yaml` (pure-JS). J.J1 and J.J3 implementing sessions reuse whichever
  dep J.J2 picked. Document the choice in the per-slice header.
- **Status**: open
- **Owner**: J.J2 (introducer)

### CC-3 — REQUIRES-OPERATOR-INPUT literal consistency
- **Description**: All three slices emit the literal
  `'REQUIRES-OPERATOR-INPUT'` for missing operator inputs. The literal
  must be exact (no whitespace, no case variations) so the
  `npm run lint:no-stubs` allowlist + `check:reo` provenance check
  recognize it.
- **Severity**: high
- **Mitigation**: Each slice defines `const TBD = 'REQUIRES-OPERATOR-INPUT'`
  at the top of its module, mirroring `core/roe-emit.ts`. Tests assert
  the exact literal appears in emitted artifacts. Reviewers grep for
  any drift before merge.
- **Status**: open
- **Owner**: all slices

### CC-4 — Deterministic JSON serialization
- **Description**: All three slices emit JSON that must be byte-
  identical across runs given identical inputs (for sha256-stable
  manifest entries + diff-friendly review). Object key order, array
  sort order, and floating-point representation can break determinism.
- **Severity**: high
- **Mitigation**: Each slice's builder sorts all collections by stable
  keys before emission (e.g. roles by `id`, cells by `(role_id,
  privilege_id)`, entries by `(category, severity, id)`). JSON
  serialization uses the existing repo helper (look for
  `stableStringify` or equivalent; if absent, use `JSON.stringify`
  with a recursive key-sort wrapper). Each slice has a "deterministic
  JSON" test that runs twice and compares sha256.
- **Status**: open
- **Owner**: all slices

### CC-5 — Provenance block completeness
- **Description**: REO Rule 4 + `check:provenance` guardrail (G3)
  require every emitted artifact to have a `provenance` block listing
  `emitter`, `emitted_at`, and source data references. All three slices
  emit a provenance block; missing fields fail G3.
- **Severity**: high
- **Mitigation**: Each slice's emitter populates the provenance block
  unconditionally (never optional). Tests assert the block exists and
  contains the expected source-module / source-file / source-call
  lists. `check:provenance` runs in CI pre-merge.
- **Status**: open
- **Owner**: all slices

### CC-6 — Signing pipeline ordering
- **Description**: Each slice's emitter must run BEFORE `core/sign.ts`
  in the orchestrator schedule so the emitted artifacts are covered by
  the Ed25519 + RFC 3161 manifest. Wrong ordering produces unsigned
  artifacts that the submission bundle would still pick up.
- **Severity**: critical
- **Mitigation**: Orchestrator dispatch logic explicitly schedules
  J.J1 / J.J2 / J.J3 emitters before the `--sign` step. Each slice's
  integration test asserts the emitted file appears in
  `out/manifest.json` `files[]`.
- **Status**: open
- **Owner**: all slices (orchestrator changes)

### CC-7 — Submission bundler well-known catalogue
- **Description**: Each slice appends two entries to
  `core/submission-bundle.ts` WELL_KNOWN: a JSON role and an XLSX role.
  The bundler's `Role` union type must be extended accordingly.
  Forgetting the union extension is a TypeScript build break; forgetting
  the catalogue entry produces a bundle that drops the artifact
  silently.
- **Severity**: high
- **Mitigation**: Per-slice checklist includes "Role union extended"
  AND "WELL_KNOWN entry appended". Integration tests assert the bundle
  contains the emitted artifact and `INDEX.json` lists its sha256 + role.
- **Status**: open
- **Owner**: all slices

### CC-8 — OSCAL SSP back-matter integration drift
- **Description**: J.J1 + J.J3 both add `back-matter.resources[]`
  entries in `core/oscal-ssp.ts`. If implemented twice (once per slice)
  without sharing a helper, the SSP could emit duplicate resources OR
  one slice could clobber the other's entry.
- **Severity**: medium
- **Mitigation**: Both slices use a shared helper
  `appendBackMatterResource(ssp, resource)` that dedups by
  `(title, rlinks[].href)`. Add the helper in J.J1; J.J3 reuses it.
- **Status**: open
- **Owner**: J.J1 (helper), J.J3 (consumer)

### CC-9 — REO Rule 1 false positive on cloud-published constants
- **Description**: J.J1 uses AWS managed-policy ARNs
  (`arn:aws:iam::aws:policy/AdministratorAccess`), GCP role names
  (`roles/owner`, `roles/viewer`), and Azure built-in role names
  (`Owner`, `Reader`). These are cloud-published constants (REO Rule 3
  allowed), but the `lint:no-stubs` G1 guardrail may flag terms like
  `'admin'` or `'sample'` if string matching is naive.
- **Severity**: low
- **Mitigation**: Verify `scripts/lint-no-stubs.mjs` allowlist already
  exempts these patterns. If not, expand the allowlist. Document the
  expansion in `CLAUDE.md` Rule 3 list.
- **Status**: open
- **Owner**: J.J1

### CC-10 — Independence from other loops
- **Description**: LOOP-J is documented as independent of LOOP-B/C/D/E/F/G/H/I/K.
  But LOOP-J slices ALSO unblock LOOP-B.B5, LOOP-C.C7, LOOP-G.G4,
  LOOP-H.H3, LOOP-I.I1. If those loops change their consumption
  contracts mid-flight, LOOP-J ships first but later needs schema
  changes.
- **Severity**: medium
- **Mitigation**: J.J1 + J.J2 + J.J3 JSON schemas are versioned via the
  `provenance.emitter` + `provenance.emitted_at` block. Downstream loops
  must read the schema as published; backward-incompatible changes
  require a bump (e.g. add `schema_version: '1.0'` field to each
  artifact root).
- **Status**: open

## Per-slice risks

### J.J1 — User Roles & Privileges matrix (AC-2 + AC-6)

**J1-R1 — Multi-sheet XLSX writer correctness**
- Description: The extended `rowsToXlsx({ sheets })` writer must produce
  a valid OOXML SpreadsheetML workbook with three named sheets. OOXML
  has strict requirements: `workbook.xml` must list every sheet
  with sequential `sheetId` + unique `name` + `r:id` reference; each
  sheet XML file must conform to `sheet/sheetData/row/c` structure.
- Severity: high
- Mitigation: Unit test loads the emitted .xlsx as a zip, parses
  `xl/workbook.xml`, asserts three `<sheet>` elements; opens each
  `xl/worksheets/sheetN.xml` and asserts it parses as XML. Add a
  manual test: open in Excel and confirm all three tabs render.
- Status: open

**J1-R2 — Cross-cloud role normalization correctness**
- Description: AWS roles, GCP service accounts, and Azure role
  assignments have different ID schemes, naming conventions, and
  hierarchies. The matrix must produce a single `Role[]` array with
  consistent shape across clouds without inventing data.
- Severity: high
- Mitigation: Per-cloud unit tests cover each cloud's IAM evidence
  shape with a fixture envelope. Cross-cloud integration test uses
  all three at once. The `Role.id` prefix (`aws:` / `gcp:` / `azure:`)
  guarantees no collision.
- Status: open

**J1-R3 — Custom AWS managed-policy admin escalation**
- Description: A customer-managed policy with an `iam:*` wildcard or
  `*` action should be classified as `admin`, not `write`. Naive
  classification on policy NAME alone misses this.
- Severity: high
- Mitigation: Implementation walks `policy_document.Statement[].Action[]`
  and escalates to `admin` when any of `iam:Create*` / `iam:Delete*` /
  `iam:Put*` / `iam:Attach*` / `iam:PassRole` / `*` is present. Fixture
  test for the `iam:*` case.
- Status: open

**J1-R4 — Break-glass role detection bias**
- Description: Naming heuristics for break-glass (e.g. role name
  contains "emergency" or "break-glass") could mis-classify a
  legitimately-named role. REO Rule 1 #5 forbids silent fallbacks.
- Severity: medium
- Mitigation: Break-glass is operator-input-only via
  `roles-config.yaml` `break_glass: true` flag. No name-pattern
  heuristic. Open question Q2 in J.J1.md documents the decision.
- Status: open

**J1-R5 — SSP integration test fragility**
- Description: The SSP back-matter integration test depends on both
  J.J1 and the existing SSP emitter being on the same emission cycle.
  Test ordering matters.
- Severity: low
- Mitigation: Integration test runs the matrix emitter first, then the
  SSP emitter, then parses the SSP `back-matter.resources[]`. Test
  fixture pre-populates the matrix JSON before the SSP emitter runs.
- Status: open

**J1-R6 — Determinism under role rotation**
- Description: When the operator rotates a role (deletes old, creates
  new with same business intent), the IAM evidence sees a new role id.
  The matrix's `roles[]` and `cells[]` shift. This breaks the "same
  input → byte-identical output" test invariant only across rotations,
  not within a run.
- Severity: low (acceptable: determinism is within-run, not cross-run)
- Mitigation: Document this behavior in the emitter header. Test
  determinism within-run only.
- Status: open

### J.J2 — Subprocessor inventory expansion (SA-9)

**J2-R1 — Google Sheets vs YAML conflict resolution**
- Description: When both a Google Sheet and a YAML config supply the
  same subprocessor row, which wins? J.J2 specifies "YAML wins; emit a
  warning". A misimplementation could pick sheet-wins or merge fields,
  producing surprising output.
- Severity: medium
- Mitigation: Implementation: YAML wins on name collision; record a
  `warnings[]` entry. Unit test for the collision case asserts YAML
  values + the warning.
- Status: open

**J2-R2 — Canonicalized name collision**
- Description: Canonical-name dedup (lowercase + space-stripped) could
  collide two legitimately distinct subprocessors (e.g. "Acme Corp" vs
  "Acme Corp."). The collision merges them.
- Severity: medium
- Mitigation: Implementation records a `warnings[]` line for any merge.
  Operator can disambiguate by using a discriminating field (e.g.
  appending `(US)` vs `(EU)`). Document in YAML schema header.
- Status: open

**J2-R3 — Empty inventory placeholder vs no-stub rule**
- Description: When neither sheet nor YAML provides rows, J.J2 emits a
  single `REQUIRES-OPERATOR-INPUT` row. REO Rule 1 forbids "placeholder
  returns" — but this is a documented sentinel, not a placeholder. Need
  to ensure the linter / reviewer treats it correctly.
- Severity: low
- Mitigation: Document the sentinel pattern in the emitter header +
  `CLAUDE.md` Rule 3 allowlist. Test that the empty-input case emits
  exactly one row with the literal `'REQUIRES-OPERATOR-INPUT'`.
- Status: open

**J2-R4 — SOC2 expiry timezone ambiguity**
- Description: SOC2 expiry dates may be supplied in operator-local
  timezone but `opts.now()` is UTC. A row that expires "today" in
  PST may not yet be expired in UTC.
- Severity: low
- Mitigation: Dates compared as ISO 8601 date-only (no time-of-day).
  Document: expiry date is the "last calendar day the attestation is
  valid"; comparison is `expiry_date < now_date`.
- Status: open

**J2-R5 — Schema versioning across CSO**
- Description: When LOOP-H.H3 multi-CSO ships, each CSO may have its
  own subprocessor list (and own YAML/sheet). The current single-CSO
  schema doesn't reserve a `cso_id` field.
- Severity: medium
- Mitigation: Add `cso_id` as an optional top-level field in
  `SubprocessorInventory` and per-`SubprocessorRow`. Document as
  future-proofing. When `cso_id` is absent, default scope is the single
  `system_id`.
- Status: open

**J2-R6 — JSON schema fixture vs runtime drift**
- Description: The committed
  `tests/fixtures/subprocessor-config.schema.json` ajv schema must
  match the TS `SubprocessorRow` interface. If the interface changes
  without the fixture updating, runtime succeeds but the test passes a
  stale schema.
- Severity: medium
- Mitigation: Add a meta-test that derives the schema from the TS
  interface (using `typescript-json-schema` or similar) at test time
  and compares to the committed fixture. OR: commit the schema as
  the source of truth and generate the TS type from it.
- Status: open (J.J2 ships an ajv positive + negative test over the
  committed fixture; the derive-from-TS meta-test remains a follow-on)

**J2-R7 — `data_residency` free-form (no region-code validation)** [discovered impl-j-j2, 2026-06-11]
- Description: Resolution of open question Q3 — `data_residency` is a
  free-form string (region code OR geography). A typo (`us-east-2` vs
  `us-east-1`, or a misspelled city) passes silently, so the SA-9(5)
  processing/storage-location field can be wrong without any signal.
- Severity: low
- Mitigation: Out of J.J2 scope by design (a geography can't be enumerated).
  A follow-on slice could add a soft warning when the value looks like a
  cloud region code but matches no known AWS/GCP/Azure region. Until then,
  the operator is responsible for accuracy; the value flows verbatim to the
  inventory + XLSX where a 3PAO can eyeball it.
- Status: open (deferred follow-on)

**J2-R8 — SSP coverage of non-FedRAMP subprocessors + control-baseline cross-check** [discovered impl-j-j2, 2026-06-11]
- Description: Resolution of open questions Q4 + Q6, both deferred out of
  J.J2 scope. (Q4) The SSP only emits `leveraged-authorizations[]` for
  `fedramp_authorized=yes` rows; non-authorized subprocessors that still
  process federal data are NOT surfaced in the SSP (they appear only in
  `subprocessor-inventory.json`/`.xlsx`). (Q6) `contracted_controls[]` is
  not cross-checked against the active Low/Moderate/High baseline, so a
  contractually-referenced control outside the baseline is not flagged.
- Severity: medium (Q4 — a PMO reviewer may expect every data-touching
  subprocessor represented somewhere in the SSP back-matter)
- Mitigation: Follow-on slice (J.J-follow-on or L-loop CRM work): add
  non-authorized subprocessors as `back-matter.resources[]` with
  `props.subservice-type='non-fedramp'`, and a soft warning when a
  `contracted_controls` ID is not in the current baseline. J.J2 deliberately
  scopes these out to avoid coupling the inventory emitter to the control
  benchmark and to avoid SSP back-matter drift (see CC-8).
- Status: open (deferred follow-on)

### J.J3 — Supply chain risk register (SR-3) + SBOM integration

**J3-R1 — SBOM parse cost on large SBOMs**
- Description: SBOMs with thousands of components require careful
  streaming to avoid memory blow-up. The `sbom_provenance[]`
  NTIA-element flag computation could double-walk the file.
- Severity: medium
- Mitigation: Single-pass walk that emits both vulnerabilities and the
  seven NTIA flags in one read. Use the streaming reader pattern from
  `core/sbom.ts`. Add a perf test with a 10k-component fixture.
- Status: open

**J3-R2 — KEV catalog staleness**
- Description: `docs/cisa-kev.generated.json` is updated by a separate
  scheduled workflow. If stale (>7 days), the register may miss recent
  KEV additions.
- Severity: medium
- Mitigation: Emit a `warnings[]` line when the catalog's
  `metadata.last_updated` (or file mtime) is >7 days old. Do NOT block
  emission (process concern, not data-integrity for emitted entries).
- Status: open

**J3-R3 — KEV elevation regression (double emission)**
- Description: A CVE that appears in both SBOM and KEV could
  accidentally emit TWO entries (one `sbom-cve`, one `sbom-cve-kev`)
  if dedup logic regresses.
- Severity: high
- Mitigation: At end of SBOM walk, dedup by CVE id; KEV-matched CVE
  removes the plain `sbom-cve` entry, retains only `sbom-cve-kev`.
  Test 1 explicitly asserts single-entry-per-CVE.
- Status: open

**J3-R4 — POA&M deadline anchor regression**
- Description: POA&M items emitted for supply-chain entries must use
  `entry.first_seen` as the deadline anchor, NOT the run timestamp.
  A regression could anchor at run-time, making a months-old finding
  "freshly discovered" with a 30-day deadline.
- Severity: critical
- Mitigation: Test 14 explicitly asserts deadline = `first_seen + 30
  days` for a critical entry. Code path computes anchor explicitly and
  never falls back to `Date.now()`.
- Status: open

**J3-R5 — Operator override scope creep**
- Description: `--risks-config` `mitigations[]` entries could be
  abused to silently downgrade a KEV-critical to "accepted" without a
  real mitigation rationale.
- Severity: high
- Mitigation: Override is limited to `status` + `mitigation_summary`
  (NOT `severity`). When override changes an `open` KEV to
  `accepted` without ≥50-char mitigation, emit a `warnings[]` line for
  3PAO review. Document the constraint in YAML schema header.
- Status: open

**J3-R6 — Severity defaulting (UNKNOWN → medium)**
- Description: SBOM CVEs without NVD severity get mapped to `medium` +
  flagged. A reviewer skimming the register might not notice the flag.
- Severity: medium
- Mitigation: Test 17 asserts the flag is set in
  `coverage.entries_missing_mitigation` (NO — that's mitigation; need a
  separate `coverage.entries_with_default_severity[]` list). Add the
  list to coverage. XLSX `Summary` sheet calls out the count.
- Status: open

**J3-R7 — SSP back-matter media-type compliance**
- Description: OSCAL `rlinks[]` should include `media-type`. Forgetting
  it does not break validation (it's optional) but harms downstream
  consumers.
- Severity: low
- Mitigation: Emit `media-type: 'application/json'` for the .json rlink
  and `media-type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'`
  for the .xlsx rlink. Copy pattern from existing
  `core/oscal-ssp.ts` rlinks.
- Status: open

**J3-R8 — CycloneDX vs SPDX NTIA-element path drift**
- Description: The seven NTIA-element fields map to different paths in
  CycloneDX vs SPDX. Wrong paths produce false negatives (NTIA flag
  marked absent when present).
- Severity: high
- Mitigation: Unit tests per format. Fixture CycloneDX SBOM with all
  seven fields present → all flags true. Fixture SPDX SBOM with all
  seven present → all flags true. Each "field absent" → corresponding
  flag false; rest true.
- Status: open

**J3-R9 — POA&M idempotency under re-run**
- Description: Re-running the orchestrator must not emit duplicate
  POA&M items for the same supply-chain entry.
- Severity: high
- Mitigation: Deterministic uuids
  (`deterministicUuid('poam:item:supply-chain:' + entry.id)`)
  guarantee idempotency by construction. Test for double-run with same
  input asserts identical POA&M output.
- Status: open

**J3-R10 — Subprocessor name propagation to register**
- Description: J.J3 propagates subprocessor names into
  `affected_subprocessors[]`. If J.J2's canonical-collision merge
  occurred, the propagated name is ambiguous.
- Severity: medium
- Mitigation: J.J3 propagates J.J2's `warnings[]` into the register's
  own `warnings[]`. Add a `warnings` field at the register root if
  not already present.
- Status: open

**J3-R11 — Empty-input hard fail vs orchestrator flag check**
- Description: `--supply-chain-risk` with no sources throws at emit
  time. Risk: this hard-fails an otherwise-good orchestrator run.
- Severity: medium
- Mitigation: Orchestrator validates the flag combination at parse
  time; emits a clear pre-flight error before any other work. Build-
  step 4 in J.J3.md prescribes this.
- Status: open

**J3-R12 — Multi-sheet XLSX 8-tab limit assumptions**
- Description: XLSX has practical limits on sheet name length (31
  chars), and the writer may not gracefully truncate. The 8 sheets
  J.J3 emits all have short names; risk is low but worth noting.
- Severity: low
- Mitigation: Sheet names are constants in the emitter, all ≤22 chars.
  Add a defensive assertion `name.length <= 31` in the multi-sheet
  writer (J.J1's sub-task).
- Status: open

## External dependencies that may change

- **NIST SP 800-53 Rev 5 updates** — current baseline is 5.1.1 (per
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final). NIST has signaled
  a Rev 5 minor-update workstream; any revision to AC-2 / AC-6 / SA-9 /
  SR-3 / SR-4 / SR-6 control text requires re-quotation in the per-
  slice "Authoritative sources" sections and may shift required fields.
- **NIST SP 800-161 Rev 1 minor updates** — current is May 2022.
  The C-SCRM program may move to Rev 2 in the medium term; J.J3's
  Tier-3 register would need to align.
- **NTIA SBOM Minimum Elements expansion** — the original July 2021
  document (under EO 14028 §4(f)) signaled "as SBOM evolves" updates.
  If CISA / NTIA publish v2 with additional required fields, J.J3's
  `sbom_provenance[]` block needs more flags.
- **CISA KEV catalog schema** — the JSON feed structure
  (`cveID`, `dueDate`, `dateAdded`, etc.) is stable but not formally
  versioned. If CISA adds a column the consumer doesn't read, no risk;
  if CISA renames `dueDate` → `due_date`, J.J3 breaks. Mitigation:
  ajv schema check on the KEV catalog at load time (already in
  `core/kev-feed.ts`).
- **CycloneDX spec updates** — currently 1.5; 1.6 / 1.7 may shift field
  paths for the NTIA-element flags. The path tables in J.J3.md must be
  re-verified per SBOM-format-version. `core/sbom.ts` parses both 1.5
  and prior; J.J3's flag computation needs to track.
- **SPDX spec updates** — currently 2.3; SPDX 3.0 introduces a
  substantially different model (`Element`-based, JSON-LD). When the
  industry moves to SPDX 3.0, J.J3 needs SPDX-3-aware flag computation.
- **FedRAMP Rev 5 template revisions** — Appendix Q (User Roles &
  Privileges) column order or field list could change in a template
  update. J.J1's XLSX writer's column-order array is parameterized so
  an update is a one-line patch.
- **FedRAMP SaaS Subprocessor Inventory template** — currently informal;
  if FedRAMP publishes a formal template (column-by-column), J.J2's
  XLSX header list must match verbatim. Mitigation: J.J2's column
  array is in one place (top of the emitter) for easy update.
- **OSCAL v1.1.2 → v1.2 transition** — OSCAL is on a steady
  publication cadence. A new minor release could add native
  `supply-chain` model fields; J.J3's register would migrate from
  standalone JSON to OSCAL native (open question Q5 in LOOP-J-SPEC.md
  §6). Backward compatibility is required during the transition.
- **`ajv` library updates** — `ajv@8.x` is current. A v9 release
  with breaking API changes would touch all OSCAL validators. LOOP-J
  itself does not run ajv, but LOOP-J slices export schemas that
  downstream consumers ajv-validate.
- **`yaml` library updates** (introduced in J.J2) — `yaml@2.x` is
  current. A v3 with breaking API changes would touch the operator-
  config readers in all three slices.
- **`@aws-sdk/client-iam` schema updates** — AWS IAM SDK shape changes
  would touch the upstream IAM collectors (already shipped), but J.J1
  reads the normalized `RawEvidence.data` shape, so the impact is
  one-collector-deep.
- **GCP IAM API updates** — same as AWS: collectors are upstream of
  J.J1; J.J1 reads normalized evidence.
- **Microsoft Graph + Azure RBAC API updates** — same.
- **Google Sheets API v4** — used by J.J2's existing
  `core/subprocessors-sheet.ts`. Stable; deprecation would force a
  config-only migration (operators would move to YAML/JSON).

## Resolved risks (historical)

(empty — no risks resolved yet; this section is populated as
implementing sessions close out risks with commit hashes + resolution
notes)

Format for resolved entries:
```
### <RISK-ID> — <Title> [RESOLVED <YYYY-MM-DD> commit <hash>]
- Original description: <copied>
- Resolution: <how it was actually resolved; link to test if applicable>
```
