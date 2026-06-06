---
slice_id: I.I4
title: SSP narrative library completion
loop: I
status: pending
commit: —
depends_on: [SSP-1]
blocks: [C.C1, C.C2, C.C3, C.C5, C.C6, C.C7, C.C8, C.C9]
completed_date: —
estimated_effort: 4 days
last_updated: 2026-06-07
---

# I.I4 — SSP narrative library completion

## TL;DR
Canonicalize the SSP narrative-prose fragments (`statements[].by-components[].description`)
into an operator-editable JSON library (`out/ssp-narrative-library.json`)
that auto-fills the OSCAL SSP emitter (`core/oscal-ssp.ts`) while preserving
the REQUIRES-OPERATOR-INPUT defensive pattern. The seed library covers
every 800-53 Moderate-baseline control with a well-known
`{{operator_description_for_<control_id>}}` mustache placeholder, and an
operator can override per-control via a committed `narrative-overrides.yaml`.
Reduces the manual SSP-authoring burden that LOOP-C.C* document templates
only partially address, and gives downstream `.docx` consumers a single
source of truth.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
Today `core/oscal-ssp.ts` emits a draft SSP with REQUIRES-OPERATOR-INPUT
markers literally inlined into every `by-components[].description` slot.
Operators are forced to grep the JSON, replace each marker by hand, and
re-emit — a process that doesn't scale across the ~250 Moderate-baseline
controls and that gives no audit trail of which descriptions were
operator-authored vs auto-derived. LOOP-C.C* document templates (CMP,
ISCP, IRP, etc.) re-encounter the same problem because they reuse the
same narrative content.

This slice closes the gap by introducing a canonical narrative library:
- One entry per `(control_id, statement_id, by_component)` triple.
- Templated with `{{var}}` placeholders for operator-provided values.
- Loaded from a committed seed (`docs/ssp-narrative-library.seed.json`)
  and optionally merged with an operator-supplied
  `narrative-overrides.yaml`.
- Composed by `composeNarrative()` at SSP-emit time.
- Emitted alongside the SSP as a signed `out/ssp-narrative-library.json`
  so the merged content is auditable.

When no library entry matches OR a required variable is unset, the
defensive REQUIRES-OPERATOR-INPUT marker is preserved — the slice never
silently fabricates narrative text.

## Authoritative sources (with verbatim quotes)
- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/
  — OSCAL SSP v1.1.2,
  `control-implementation.implemented-requirements[].statements[].by-components[].description`:
  > "An explanation of how the control or control statement is implemented
  > within the containing component or system, written in prose, optionally
  > including embedded references to other content."

  Implication: this is the canonical OSCAL slot for human-authored
  narrative prose. The library populates it; missing data preserves
  REQUIRES-OPERATOR-INPUT per REO Rule 4.
- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/
  — OSCAL SSP v1.1.2,
  `control-implementation.implemented-requirements[].statements[].by-components[].set-parameters`:
  > "Identifies the parameter that will be set by the enclosed value. The
  > parameter identifier is referenced and the value(s) to be assigned."

  Implication: parameter substitution (e.g. session-timeout minutes) is
  the OSCAL-native variable mechanism; I.I4 surfaces these for operator
  editing without re-implementing the parameter-flag pipeline already in
  `core/oscal-ssp.ts`.
- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/
  — OSCAL SSP v1.1.2,
  `control-implementation.implemented-requirements[].statements[].by-components[].responsible-roles`:
  > "A reference to one or more roles with responsibility for performing a
  > function relative to the containing object."

  Implication: role attribution is OPERATOR-supplied per REO Rule 4 — the
  library does NOT auto-derive these.
- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — NIST SP 800-53 Rev 5
  control PL-2 (System Security Plan), p. 113:
  > "Develop a security and privacy plan for the system that ... describes
  > the operational environment for the system and relationships with or
  > connections to other systems; provides an overview of the security and
  > privacy requirements for the system; identifies any relevant control
  > baselines or overlays, if applicable; describes the controls in place
  > or planned for meeting those requirements including a rationale for
  > any tailoring decisions."

  Implication: the library backbone of "describes the controls in place"
  must be operator-supplied prose, not auto-generated boilerplate. The
  seed's well-known placeholder satisfies the "explicit operator-author
  step" requirement.
- https://github.com/brian-ruf/oscal-content-generation — OSCAL Content
  Generation project (`ssp_content_creator.py`), retrieved 2026-06-07:
  > "automates population of SSP documents by creating
  > implemented-requirement assemblies within existing SSPs based on
  > FedRAMP baselines"

  Implication: this is structural scaffolding, not narrative library —
  I.I4 deliberately closes the gap that this upstream project leaves
  open (canonical, per-control, operator-editable narrative content).
- https://github.com/GoComply/oscalkit — confirms the same gap: oscalkit
  manipulates OSCAL structures but does not maintain a narrative content
  library.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssp-narrative-library.ts`
  — library loader + composer + disk emitter + typed errors
  (`NarrativeLibraryError`, `NarrativeOverrideValidationError`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ssp-narrative-library.test.ts`
  — ≥14 unit tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/ssp-narrative-library.seed.json`
  — committed canonical seed. One entry per Moderate-baseline 800-53
  control (sourced from existing `core/requirement-playbooks.ts` +
  `core/ksi-map.ts` + `core/control-benchmark.ts`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/narrative-overrides.example.yaml`
  — operator-overridable narrative format example (test fixture; mirrors
  the shape an operator commits).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-narrative-seed.mjs`
  — generator that walks `requirement-playbooks.ts` + `ksi-map.ts` and
  emits `ssp-narrative-library.seed.json`. Includes `--verify` mode for
  idempotency check.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` —
  replace the hard-coded REQUIRES-OPERATOR-INPUT marker in
  `buildByComponent()` (or equivalent) with `composeNarrative(library,
  controlId, statementId, byComponentName, ctx)`. When `from ===
  'no-match'` OR `missing_vars.length > 0`, retain the REQUIRES-OPERATOR-
  INPUT marker citing the missing var (defensive REO).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
  — add `--narrative-overrides <path>` flag +
  `CLOUD_EVIDENCE_NARRATIVE_OVERRIDES` env. Load the override file
  before `--oscal-ssp` so the SSP emit picks up the composed content.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
  — register role `'ssp-narrative-library'`, filename
  `ssp-narrative-library.json`, `required: false`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/oscal-ssp.test.ts`
  — extend with 4 new tests verifying library hook + override semantics.

## Schemas / standards
- **OSCAL SSP v1.1.2** — primary OSCAL slot is
  `statements[].by-components[].description` (cited above). Parameter
  substitution slot is `set-parameters[]`. Library does NOT touch
  `responsible-roles[]` (operator-supplied per REO Rule 4).
- **800-53 Rev 5 control IDs** — keyed via existing
  `core/control-benchmark.ts` Moderate baseline.
- **Component-name key** — uses `"this-system"` (per
  `oscal-content-generation` convention) for the system itself plus
  operator-defined component names.
- **Override YAML schema** — per-entry shape:
  ```yaml
  - control_id: AC-2
    statement_id: AC-2_smt.a
    by_component: this-system
    template: "AWS IAM user lifecycle managed via {{provisioning_system}};
               see KSI-IAM-MFA evidence."
    required_vars: [provisioning_system]
    evidence_pointer: KSI-IAM-MFA
    provenance:
      authored_by: jane@acme.example
      authored_at: 2026-06-15
  ```

## Build steps (concrete, numbered)
1. Define library schema in `core/ssp-narrative-library.ts`:
   ```ts
   export interface NarrativeEntry {
     control_id: string;
     statement_id?: string;
     by_component: string;
     template: string;
     required_vars: string[];
     evidence_pointer?: string;
     provenance: {
       source: 'seed' | 'operator-override' | 'auto-derived';
       authored_by?: string;
       authored_at?: string;
       sourceCalls?: string[];
     };
   }
   export interface NarrativeLibrary {
     entries: NarrativeEntry[];
     last_modified: string;
     provenance: { emitter: 'core/ssp-narrative-library.ts';
                   emittedAt: string; sourceCalls: string[];
                   signingKeyId?: string };
   }
   ```
2. Loader:
   `loadNarrativeLibrary({seedPath?, overridesPath?}) → NarrativeLibrary`.
   - Reads seed (default `docs/ssp-narrative-library.seed.json`).
   - If `overridesPath` exists, parses YAML (via existing `yaml` dep) or
     JSON and merges deterministically.
   - Operator override REPLACES seed entry for matching
     `(control_id, statement_id, by_component)`.
   - Merged entries carry `provenance.source = 'operator-override'` +
     `authored_by` + `authored_at` from the override file.
   - Validates override entries: REJECTS any entry missing `control_id`,
     `by_component`, or `template`. Throws
     `NarrativeOverrideValidationError` listing all invalid entries.
3. Composer:
   `composeNarrative(library, controlId, statementId, byComponent, ctx)
   → {text, missing_vars, from}`.
   - Looks up `(controlId, statementId, byComponent)` exact match;
     fall-back to `(controlId, null, byComponent)`.
   - Substitutes `{{var}}` placeholders from `ctx`.
   - When a `required_var` is missing from `ctx`: leaves `{{var}}`
     literal in output AND lists it in `missing_vars[]`. The caller
     (`oscal-ssp.ts`) then renders the literal as
     `REQUIRES-OPERATOR-INPUT: {{var}}`.
   - When no entry matches: `from = 'no-match'`, caller emits the
     defensive REQUIRES-OPERATOR-INPUT marker.
4. Seed file generation: `scripts/extract-narrative-seed.mjs` walks
   `core/requirement-playbooks.ts` + `core/ksi-map.ts` +
   `core/control-benchmark.ts`. For every Moderate-baseline 800-53
   control, emits one entry. For controls with a playbook entry, template
   uses the playbook's existing prose; for controls without, template is
   literally `"{{operator_description_for_<control_id>}}"` (a single
   well-known REQUIRES-OPERATOR-INPUT marker).
5. Disk emitter:
   `emitNarrativeLibrary({outDir, seedPath?, overridesPath?}) → {path,
   library}`. Writes merged library to `out/ssp-narrative-library.json`
   with provenance.
6. Hook into `oscal-ssp.ts`: replace REQUIRES-OPERATOR-INPUT inline
   string with `composeNarrative(library, controlId, statementId,
   byComponentName, ctx)`. When `from === 'no-match' || missing_vars.length
   > 0`, retain the marker (citing missing var names). Library load
   happens once at orchestrator startup and is passed to the emitter.
7. Orchestrator wiring: `--narrative-overrides <path>` /
   `CLOUD_EVIDENCE_NARRATIVE_OVERRIDES`. Loaded BEFORE `--oscal-ssp`.
8. Submission-bundle catalogue entry: role=`ssp-narrative-library`,
   filename=`ssp-narrative-library.json`, required=`false`,
   description=`"Operator-overridable SSP narrative library (LOOP-I.I4)"`.
9. Sign + timestamp: covered by existing `core/sign.ts` pipeline.

## REQUIRES-OPERATOR-INPUT fields
This slice formalizes the operator-input flow for narrative prose:
- **Per-control narrative prose**: operator supplies via
  `narrative-overrides.yaml` committed to repo and passed via
  `--narrative-overrides`. The committed seed exposes EVERY Moderate
  control as `{{operator_description_for_<control_id>}}` so the operator's
  first task is to provide N descriptions.
- **Per-component `set-parameters` values**: operator supplies via the
  existing `--ssp-set-parameter <param-id>=<value>` flag system (not
  re-implemented here).
- **Variable values inside templates**: operator passes via
  `composeNarrative(..., ctx)` — the orchestrator builds `ctx` from
  config.yaml + cloud tags + CLI flags. Missing variables surface as
  REQUIRES-OPERATOR-INPUT markers naming the variable.

## Test specifications (≥14 tests)
1. `it('loads the seed library from disk')`.
2. `it('returns 1 entry per Moderate-baseline 800-53 control')` — asserts
   count matches `buildControlBenchmark('fedramp-mod')` length.
3. `it('merges an operator override file (YAML)')`.
4. `it('merges an operator override file (JSON)')`.
5. `it('marks merged entries with provenance.source = "operator-override"')`.
6. `it('composes narrative by substituting {{var}} placeholders')`.
7. `it('lists missing required_vars and leaves {{var}} literal in output')`.
8. `it('returns from = no-match when no library entry exists')`.
9. `it('hooks into oscal-ssp.ts to populate by-component description')`.
10. `it('preserves REQUIRES-OPERATOR-INPUT marker when no override + no fill')`.
11. `it('emits the merged library to out/ssp-narrative-library.json')`.
12. `it('library is deterministic given identical seed + overrides')`.
13. `it('rejects an override file whose entry lacks control_id')` —
    asserts `NarrativeOverrideValidationError` thrown.
14. `it('records sourceCalls in provenance')`.
15. `it('extract-narrative-seed.mjs --verify is idempotent on seed file')`.
16. `it('control-level lookup falls back to (controlId, null, byComponent) when statement-level missing')`.

## REO compliance specific to this slice
- The seed file is canonical content sourced from
  `requirement-playbooks.ts` (existing real evidence-collector
  documentation strings). Each seed entry's `provenance.sourceCalls`
  cites which playbook it was extracted from.
- For controls without a playbook entry, the seed uses
  `{{operator_description_for_<control_id>}}` — a well-known
  REQUIRES-OPERATOR-INPUT marker. Per CLAUDE.md Rule 4 this is operator-
  input flow, NOT a placeholder under Rule 1.2.
- Operator overrides flow through a committed file (per CLAUDE.md
  Rule 4) — not via tracker UI free-text that bypasses audit.
- Provenance fields populated: every entry has
  `provenance.source ∈ {'seed', 'operator-override', 'auto-derived'}`.
  Library top-level has `provenance.emitter`, `provenance.emittedAt`,
  `provenance.sourceCalls[]`.
- Signed by existing `core/sign.ts` Ed25519 + RFC 3161 pipeline.
- `npm run lint:no-stubs` — the seed file's mustache placeholders are
  recognized by the allowlist as REQUIRES-OPERATOR-INPUT markers (add
  pattern `{{operator_description_for_*}}` to the allowlist or rely on
  the file being under `docs/` which is excluded).
- `npm run check:provenance` will pass because both the in-memory library
  AND the emitted `ssp-narrative-library.json` have provenance.

## Verification commands
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run typecheck
npm test -- tests/core/ssp-narrative-library.test.ts
npm test -- tests/core/oscal-ssp.test.ts          # +4 hook tests
npm run check:reo
node scripts/extract-narrative-seed.mjs --verify  # idempotency check
```

End-to-end smoke:
```bash
cd "/Users/kenith.philip/FedRAMP 20x/cloud-evidence"
npm run collect -- --oscal-ssp --sign --system-id acme-saas \
  --impact-level moderate \
  --narrative-overrides tests/fixtures/narrative-overrides.example.yaml
jq -e '.entries | length > 0' out/ssp-narrative-library.json
# Verify at least one operator-override entry appears
jq -e '[.entries[] | select(.provenance.source == "operator-override")] | length > 0' \
  out/ssp-narrative-library.json
```

## Known risks / issues
- **Risk 1 — Lint:no-stubs false positives on seed placeholders.** The
  seed file contains `{{operator_description_for_*}}` markers that look
  like stubs. Mitigation: place the seed under `docs/` (which is in the
  G1 exclusion list per CLAUDE.md Rule 1) OR add an explicit allowlist
  entry naming the marker pattern. Confirm during implementation that
  G1 still passes.
- **Risk 2 — Seed regeneration drift.** If `requirement-playbooks.ts`
  changes after the seed is generated, the seed becomes stale.
  Mitigation: `--verify` flag in `extract-narrative-seed.mjs` runs in
  CI; mismatch fails the build.
- **Risk 3 — Override file injection risk.** A malicious override could
  inject HTML or markdown into the SSP description. Mitigation: the
  composer treats `template` as plain text (no HTML escaping needed for
  OSCAL JSON output); downstream `.docx` renderer in SSP-2 handles its
  own escaping.
- **Risk 4 — Backward-compat with existing SSP test fixtures.** Existing
  oscal-ssp.test.ts fixtures expect REQUIRES-OPERATOR-INPUT markers in
  well-known positions. Mitigation: when no override file is provided,
  the seed's `{{operator_description_for_<control_id>}}` markers are
  surfaced through composeNarrative + still emit
  REQUIRES-OPERATOR-INPUT — preserving the test contract.
- **Risk 5 — YAML parsing edge cases.** Multi-line templates with
  embedded YAML special chars (`:`, `>`, `|`). Mitigation: use the
  existing `yaml` dep (already in package.json) which handles these
  natively; test #3 covers a multi-line template.
- **Risk 6 — i18n.** Seed is English-only. Mitigation: library schema
  supports a future `locale` field; document as a Q in open questions.
- **Risk 7 — Set-parameters propagation.** I.I4 wires narrative prose
  only; OSCAL `set-parameters[]` is the existing `oscal-ssp.ts`
  parameter-flag system. Mitigation: this slice does NOT re-implement
  that; spec is explicit.
- **Risk 8 — File size.** Seed with 250 controls × multi-line templates
  could be 200-400 KB. Mitigation: still small; serve from disk.
- **Risk 9 — Operator confusion between override file format and SSP
  JSON.** Mitigation: ship `narrative-overrides.example.yaml` fixture
  PLUS a short note in RUNBOOK.md (track as follow-up doc edit).

## Open questions (for implementation session to resolve)
- **Q1**: Should the override file allow inheriting from seed (e.g.
  "use seed template but override one variable")? Current plan: no —
  override fully replaces seed entry. Simpler and explicit.
- **Q2**: For controls in `core/control-benchmark.ts` but NOT in
  `requirement-playbooks.ts`, should the seed include them at all?
  Current plan: yes — every Moderate baseline control gets an entry
  with a `{{operator_description_for_<control_id>}}` placeholder so the
  operator has an exhaustive todo list.
- **Q3**: Library load failure mode — if the seed file is missing
  entirely, do we throw or fall back to all-REQUIRES-OPERATOR-INPUT?
  Current plan: throw `NarrativeLibraryError` — missing seed is a
  build-time misconfiguration that should fail loudly.
- **Q4**: `composeNarrative` cache strategy — composer is called N
  times during SSP emit (once per control × component). Caching by
  `(controlId, statementId, byComponent)` is trivially safe. Current
  plan: yes, cache in memory.
- **Q5**: Should the merged library carry the override file's git
  commit hash in provenance? Helpful for audit trail. Current plan:
  yes, when running inside a git checkout; otherwise omit.
- **Q6**: Override schema validation — JSON Schema, or ad-hoc
  TypeScript checks? Current plan: ad-hoc TS checks for simplicity
  (only 4 required fields); upgrade to JSON Schema later if the
  override schema grows.
- **Q7**: Should the library be split into 800-53 control families
  (AC.*, AU.*, CA.*, etc.) for easier git diff? Current plan: single
  file; alphabetically sorted by `(control_id, statement_id, by_component)`
  for stable diffs.
- **Q8**: i18n / locale field — when should we add this?
  Track as follow-up; not blocking I.I4 completion.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥14 library + 4 SSP-hook = ≥18 new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] `node scripts/extract-narrative-seed.mjs --verify` exits 0
- [ ] STATUS.md updated (I.I4 row + Overall section; if I.I4 is last
  LOOP-I slice, mark LOOP-I as COMPLETE)
- [ ] LOOP-I-SPEC.md status table updated (Section 7)
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
  completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under
  `### Added — LOOP-I.I4: SSP narrative library completion`
- [ ] Commit with `LOOP-I.I4:` prefix in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file +
  LOOP-I-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here's everything it
needs to start:
1. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CLAUDE.md` (REO
   standard, auto-loaded).
2. This file gives you: source obligations + files to create + build
   steps + tests + risks + completion checklist.
3. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-I-SPEC.md`
   Section 2 (Dependencies) + Section 4 / Slice I.I4 for the canonical
   spec.
4. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`
   for the mandatory commit pattern.
5. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts`
   to find the existing REQUIRES-OPERATOR-INPUT inline marker (the hook
   point) + `core/requirement-playbooks.ts` to understand the canonical
   prose source + `core/control-benchmark.ts` for the Moderate baseline
   control list.
6. Read `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts` for
   signing pipeline.
7. Begin implementation; update Implementation log section as you go.
