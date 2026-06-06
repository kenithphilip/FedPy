# cloud-evidence — Real-Evidence-Only (REO) standard

> This file is loaded by every Claude session that touches `cloud-evidence/`.
> It is **enforceable**, not aspirational. Three CI guardrails (see below)
> fail the build on any violation.

## Why this exists

FedRAMP 20x Phase Two for Moderate explicitly mandates "**truly automated and
opinionated validation** of Key Security Indicators" — written attestations are
no longer accepted (RFC-0014). Every artifact this repo emits is consumed by a
3PAO, the FedRAMP PMO, or an Authorizing Official. If any one of them
discovers that an emitted finding, POA&M item, AR entry, IIW cell, or signed
manifest contains placeholder data, fixed sample values, mock SDK output, or
"TODO: implement later" stubs — the authorization is at risk and the trust
basis of the entire pipeline collapses.

So the rule is simple: **every byte we emit must trace back to real evidence
or to operator-supplied configuration**. No exceptions.

---

## Rule 1 — Production code paths contain NONE of:

Applies to: `cloud-evidence/{core,providers,tracker,scripts}/` (excluding
`tests/`, `**/*.test.ts`, `**/fixtures/**`, `docs/`, and anything under
`scripts/extract-*.mjs` that explicitly transforms external catalogs).

1. **Placeholder returns.** Every function returns its computed real value
   or throws a typed error. No `return null // TODO`, no
   `return { data: 'sample' }`.
2. **`TODO`, `FIXME`, `XXX`, `stub`, `placeholder`, `not yet implemented`,
   `lorem`, `coming soon`** comments or string literals that describe
   unfinished behavior. If a slice can't finish, the slice is scoped wrong
   — split it or expand it, do not ship the stub.
3. **Hardcoded sample data.** String literals in production code come from
   one of: FRMR catalog, OSCAL schemas, NIST publications, cloud SDK
   responses, tracker DB, or operator-supplied config. Fixtures live ONLY
   under `tests/`.
4. **Mocked cloud SDKs in production paths.** All cloud queries go through
   the real (read-only Proxy) SDK clients.
5. **Silent fallbacks that mask missing data.** If a cell can't be filled,
   it stays `null` AND inventory-coverage.json shows it AND the run log
   emits a `coverage:miss` line with the asset id + reason.
6. **Fake cryptographic operations.** Every signature is real Ed25519,
   every timestamp is real RFC 3161, every signing key is real and
   provenanced (key id + creation time + holder recorded).
7. **"Synthetic" emit fields without operator opt-in.** Diagram Label /
   Comments / any computed-not-collected field is only emitted when
   explicitly enabled, with provenance recorded in
   `asset.synthesized_fields: string[]`.
8. **`if (process.env.NODE_ENV === 'test')` branches.** Tests inject seams;
   production code never knows it's being tested.
9. **Emit fields without an implementation.** If a JSON output declares a
   field, it must be computed end-to-end from real evidence. Schema does
   not exceed implementation.
10. **Auto-generated assessor / 3PAO sign-offs.** Sign-offs are human
    actions captured in the tracker; the system never auto-signs on behalf
    of an assessor.

---

## Rule 2 — Per-slice "Done" definition (Real Slice Contract)

A slice is **done** only when ALL of:

1. ✅ End-to-end evidence flows from a real cloud SDK call (or real FRMR
   catalog read, or real tracker DB query) through to the emitted output
   file.
2. ✅ Output is signed (Ed25519) + timestamped (RFC 3161).
3. ✅ The relevant coverage report rises measurably (e.g.
   `inventory-coverage.json`, or per-emitter coverage where applicable).
4. ✅ Tests cover the **real** code path. SDK transport may be mocked at
   the wire layer; **parsers, validators, signers, and emitters are never
   mocked.**
5. ✅ `npm run lint:no-stubs` returns NO new matches in production paths.
6. ✅ If the slice introduces a new emit-field, the field has a
   `provenance` entry in the output or a `coverage_source` entry in the
   registry. `npm run check:provenance` passes.
7. ✅ CHANGELOG entry names the slice + describes the real evidence path
   (which SDK calls, which catalog read, which DB query).

---

## Rule 3 — Allowed exceptions (narrow + documented)

A handful of cases are legitimately "fixed data":

- **OSCAL schema constants** (model names, UUIDs of canonical templates,
  schema version strings) — these come from the OSCAL spec, not us.
- **FedRAMP-published constants** (KSI IDs, FRR IDs, baseline parameter
  IDs) — these come from FRMR + 800-53B, not us.
- **NIST control IDs + identifiers** (AC-2, CA-7, etc.) — published.
- **HTTP status codes, JSON schema keywords, MIME types** — universal
  constants.
- **Cryptographic algorithm identifiers** (`ed25519`, `sha256`, `aes-256-gcm`)
  — standard names.
- **AWS/GCP/Azure service names + region IDs** — published by clouds.

If you add new "allowed fixed data" categories, document them here AND in
`scripts/lint-no-stubs.mjs` allowlist. Default is: NOT allowed.

---

## Rule 4 — Operator-supplied data is real data

When the system genuinely needs human input (e.g. SSP narratives that
describe organizational process, Comments column in Appendix M, RoE scope
sign-off, risk acceptance justifications), the input flows through one of:

- **Tracker DB** (process-artifact KSIs) — operator types in the UI,
  signed audit log.
- **`config.yaml` / `org-profile.yaml`** — operator commits to repo.
- **Cloud resource tags** (`fedramp_<field>`, `inventory_<field>`,
  `diagram_label`) — operator tags the asset.
- **CLI flag with documented schema** (`--system-id`, `--csp-name`).

The system **never** substitutes a default that looks like real data.
If a required operator input is missing, emit a `requires_operator_input`
diagnostic naming the field, the consumer artifact, and where the operator
provides it.

---

## CI guardrails (enforce these rules)

Three scripts under `cloud-evidence/scripts/` enforce the REO standard.
They are wired into `.github/workflows/ci.yml` as required checks.

| Guardrail | Script | Fails when |
|---|---|---|
| **G1 lint:no-stubs** | `scripts/lint-no-stubs.mjs` | A forbidden token (TODO, FIXME, XXX, stub, placeholder, sample, lorem, "coming soon", "not yet implemented") appears in production paths |
| **G2 check:coverage-regression** | `scripts/check-coverage-regression.mjs` | A fill-rate cell in `out/inventory-coverage.json` decreased vs `main` (the published baseline) |
| **G3 check:provenance** | `scripts/check-provenance.mjs` | A new emit-field exists without a `provenance` entry or a corresponding `coverage_source` in the registry |

Run all three locally before pushing:

```
npm run lint:no-stubs
npm run check:provenance
npm run check:coverage-regression
```

---

## Reading list (in priority order)

1. This file — REO rules.
2. **`docs/EXECUTION-PLAN.md`** — every remaining slice in LOOP-B through
   LOOP-K with per-slice descriptions, files to create, build steps,
   tests, REO notes. **Read this before starting any new slice.**
3. `CHANGELOG.md` (Unreleased section) — what's already shipped (LOOP-A
   complete; every slice has an entry with module names + file paths).
4. `docs/AFR-FAMILY-CLASSIFICATION.md` — R1: all 10 AFR families REQUIRED
   at Moderate, per-family CSP-actionable MUSTs (drives LOOP-G).
5. `docs/PRE-LOOP-A-RESEARCH-FINDINGS.md` — R2/R3/R4: POA&M format,
   Phase Two pilot, sampling methodology (drives LOOP-E.E2 + LOOP-F.F3).
6. `ARCHITECTURE.md` (repo root) — system shape.
7. `core/inventory-coverage.ts` — the coverage contract pattern. Replicate
   it for new emit families.
8. `docs/IMPACT-LEVEL-NOTES.md` — why Phase 4 / High is not authored by 20x.
9. `RUNBOOK.md` — operational invariants (read-only proxy, signing, etc.).

If a new contributor (human or model) reads only one file, it should be
this one. If they read two, the second is `docs/EXECUTION-PLAN.md`.

## Resuming work

A fresh session opens in the repo and auto-loads this file. To pick up
where LOOP-A left off:

1. `git log --oneline -5` — see the most recent commit.
2. Read `docs/EXECUTION-PLAN.md` "Status snapshot" + the next-slice section.
3. Say: `continue with LOOP-B.B1` (or whichever slice is next).
4. The session creates a TaskCreate entry, executes under REO, commits,
   and pushes. No conversation history needed — every piece of context
   is on disk and committed.
