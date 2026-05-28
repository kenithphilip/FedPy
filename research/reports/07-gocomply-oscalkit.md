# Research report: GoComply/oscalkit

> Part of the FedPy integration-research series. Each report front-loads the
> analysis so implementation work can start without re-investigating the source.

- **Upstream:** https://github.com/GoComply/oscalkit
- **Local clone:** `research/clones/oscalkit` (git-ignored)
- **Language / stack:** Go (1.19 in `go.mod`; CI builds with Go 1.20). CLI via `urfave/cli`. Vendored deps checked in.
- **License:** **CC0 1.0 Universal (public domain)** for oscalkit's own source (`LICENSE.md`); vendored deps are MIT (logrus, urfave/cli), BSD-3 (santhosh-tekuri/jsonschema), Apache-2.0 (yaml.v2). All permissive and Apache-2.0-compatible. We can borrow code or ship the binary freely; CC0 imposes no attribution obligation.
- **Activity / maturity:** Forked from the abandoned `docker/oscalkit` (dead since March 2019). Last commit **2025-10-29** (a dependabot merge); actively maintained by Šimon Lukašík / GoComply. **No git tags in the shallow clone**, but the CLI self-reports `VERSION: 0.2.0`. ~8,760 LOC of Go excluding `vendor/`+`docs/` (~4,306 of that is machine-generated). Repo ~5.5 MB without `.git`/`vendor`.
- **One-line:** A Go SDK + CLI for OSCAL that round-trips OSCAL documents between XML, JSON and YAML and validates them against NIST's bundled schemas, using Go structs generated from the OSCAL Metaschema.

## 1. What it does

oscalkit is a "barebones Go SDK for OSCAL" with an accompanying CLI (`gocomply_oscalkit`). Its headline capability is **lossless format conversion** between the three OSCAL serialisations — XML, JSON, and YAML — for every OSCAL model type. NIST publishes OSCAL content in multiple formats and FedRAMP templates historically ship as XML; oscalkit exists to move documents between those representations without hand-writing serializers.

The CLI exposes six commands (`cli/cmd/cmd.go`): `info`, `convert`, `diff`, `validate`, `sign`, and `generate`. `convert oscal` does the XML↔JSON↔YAML round-trip; `convert` also has `opencontrol` and `html` subcommands (OpenControl→OSCAL and OSCAL→HTML rendering). `validate` checks a file against the matching bundled NIST schema. `sign` produces a JSON Web Signature (JWS) over an OSCAL JSON artifact (RSA/EC/HMAC/Ed25519). `diff` structurally compares two OSCAL documents. `generate` is a developer tool that emits Go code (and FedRAMP catalog/implementation scaffolding) from a profile.

The interesting architectural choice: oscalkit does **not** parse OSCAL generically. It generates strongly-typed Go structs directly from the OSCAL **Metaschema** definitions (via the sister project `GoComply/metaschema`), then leans on Go's native `encoding/xml`, `encoding/json`, and `gopkg.in/yaml.v2` marshalers. Conversion is therefore "unmarshal into typed struct, re-marshal in target format" (`types/oscal/oscal.go`). This makes conversion semantically aware (it understands every OSCAL element) rather than a naive XML-tree-to-JSON transform.

It is aimed at compliance tooling authors and OSCAL pipeline builders — exactly FedPy's situation. The sister project `GoComply/fedramp` (report R9 in this series) builds on oscalkit to convert legacy FedRAMP SSPs (DOCX/OpenControl) into OSCAL.

## 2. Architecture & key components

Top-level layout (real paths from the clone):

- `cli/` — the `gocomply_oscalkit` binary. `cli/cmd/cmd.go` wires the command tree; `cli/cmd/convert/oscal.go`, `validate.go`, `sign.go`, `diff.go`, `info.go`, and `cli/cmd/generate/` are the command implementations.
- `types/oscal/` — the generated Go type packages, one per OSCAL model:
  - `catalog/`, `profile/`, `system_security_plan/`, `component_definition/`, `plan_of_action_and_milestones/`, `assessment_plan/`, `assessment_results/`, plus shared `assessment_common/`, `implementation/`, `validation_root/`, `nominal_catalog/`. Files matching `generated_*.go` are machine-written and **must not be hand-edited** (`types/oscal/README.md`).
  - `types/oscal/oscal.go` is the hand-written dispatcher: an `OSCAL` umbrella struct holding optional pointers to each model, with `New(io.Reader)` (sniffs XML root element / JSON top-level key to pick the model) and `XML()` / `JSON()` / `YAML()` / `Write(format)` encoders.
- `pkg/` — the SDK plumbing:
  - `pkg/bundled/` — NIST schemas (`.xsd` + `.json`) embedded into the binary via `markbates/pkger`. `pkg/bundled/oscal.go` maps `(format, document-type) → schema path` for all seven models.
  - `pkg/xml_validation/validate.go` — shells out to **`xmllint --schema`** (requires `libxml2`'s `xmllint` on the host).
  - `pkg/json_validation/` — validates with the **`santhosh-tekuri/jsonschema`** Go library (pure-Go, no external dep).
  - `pkg/oscal_source/validate.go` — dispatches to the right validator by detected format; **YAML has no validator** (returns "No validator available").
  - `pkg/oscal_diff/`, `pkg/oscal/constants/` (`DocumentType`, `DocumentFormat` enums), `pkg/opencontrol/`, `pkg/xslt/`, `pkg/uuid/`.
- `generator/`, `templates/`, `impl/` — code-generation helpers backing `generate`.
- `.github/workflows/regenerate-models.yml` — **the maintenance engine** (see §6): a nightly cron that re-clones `usnistgov/OSCAL`, runs `make generate`, and opens a PR if the models drifted.

**Data formats consumed/produced:** OSCAL XML, JSON, YAML (in) → any of the three + HTML (out). Validation consumes OSCAL XML/JSON and bundled `.xsd`/`.json` schemas.

**Generation pipeline** (`Makefile`): `make generate` clones `usnistgov/OSCAL` at `--depth 1` (HEAD of master, **no tag pin**) and runs `gocomply_metaschema generate ./OSCAL/src/metaschema …` to regenerate `types/oscal/`.

## 3. What's genuinely interesting for FedPy

The signal, specific to FedPy's OSCAL story:

1. **XML↔JSON↔YAML round-trip for OSCAL.** FedPy's `cloud-evidence/core/oscal.ts` *only emits JSON*. oscalkit's `convert oscal` (`cli/cmd/convert/oscal.go` → `types/oscal/oscal.go`) takes our JSON and produces schema-correct XML or YAML. FedRAMP and many assessor tools still consume OSCAL XML; this closes that gap without us writing an XML serializer for the ~700-element Assessment Results model.

2. **Schema validation against the *real* NIST schemas.** `validate` checks JSON via `santhosh-tekuri/jsonschema` and XML via `xmllint`, using schemas bundled in the binary (`pkg/bundled/`). FedPy's emitter is "hand-built JSON, no schema validation" — we have no way today to prove our Assessment Results actually conform. `gocomply_oscalkit validate evidence.oscal.json` is a one-line conformance gate.

3. **Metaschema-driven type generation as a maintenance pattern.** Rather than hand-maintaining OSCAL types (which we'd have to do in TS), oscalkit *generates* them and runs a nightly job to track upstream drift (`regenerate-models.yml`). Even if we don't adopt their Go code, this is the right mental model: treat OSCAL types as generated artifacts, not hand-written code. (For TS, `easy-dynamodb`-style codegen or the `oscal-js`/`@oscal/...` ecosystem already does this — see §5.)

4. **Full model coverage as a reference of what "complete OSCAL" means.** oscalkit implements **all seven** OSCAL models. FedPy touches exactly one (Assessment Results). The `types/oscal/assessment_results/generated_models.go` struct is a precise, comment-annotated map of every legal field (objectives, assessment-subjects, assets, results-group, findings, observations, risks, back-matter) — useful as documentation for hardening our own emitter even if we never run their binary.

5. **JWS signing of OSCAL JSON (`sign`).** FedPy already does Ed25519 signing + a manifest (task B.1) over evidence bundles. oscalkit's `sign` is OSCAL-artifact-specific JWS — a different, OSCAL-native signature envelope an assessor might expect. Lower priority but worth knowing it exists.

## 4. Gaps in OUR stack this could fill

| FedPy surface | What we DON'T have today | What oscalkit provides |
|---|---|---|
| `cloud-evidence/core/oscal.ts` | OSCAL output **only as JSON**; no XML/YAML | `convert oscal` produces schema-valid XML and YAML from our JSON |
| `cloud-evidence/core/oscal.ts` | **No validation** of emitted OSCAL against NIST schemas | `validate` against bundled `.xsd`/`.json` for all 7 models |
| OSCAL model coverage | Only Assessment Results emitted | Typed handling of catalog, profile, SSP, component-definition, POA&M, assessment-plan, assessment-results |
| Tracker / FRMR ingest | We read FRMR JSON; no path to consume official OSCAL **catalogs/profiles** (e.g. NIST 800-53, FedRAMP baselines) as XML | catalog/profile parsing + XML→JSON conversion to normalize NIST/FedRAMP content into JSON the tracker can ingest |
| Evidence signing (B.1) | Ed25519 over a manifest | OSCAL-native JWS over the OSCAL JSON itself |
| CI / release | No conformance gate on OSCAL artifacts | `validate` is trivially scriptable as a CI check |

The single biggest concrete gap is **format conversion + validation**: we emit one format, unvalidated, in one model. oscalkit covers all three formats, validated, across seven models.

## 5. Integration opportunities (actionable)

The realistic integration is **shell-out to a prebuilt Go binary** (it's Go, not portable to our TS runtime, and CC0 lets us redistribute it). Code-porting the conversion logic to TS is infeasible because it depends on Go's reflection-based marshalers over 4,300 lines of generated structs. The competing option is a **JS-native OSCAL library** (see row 4) which avoids a Go toolchain dependency entirely.

| # | Opportunity | FedPy target | Approach | Borrow code or just the idea? | Effort | Priority |
|---|-------------|--------------|----------|-------------------------------|--------|----------|
| 1 | Opt-in `--oscal-convert` flag that pipes our emitted OSCAL JSON through `gocomply_oscalkit convert oscal` to also produce `.xml`/`.yaml` | orchestrator + `cloud-evidence/core/oscal.ts` | Shell out to the prebuilt binary (download in CI / vendor per-OS); guard behind a flag so the binary is optional | idea + vendor binary | M | P1 |
| 2 | Opt-in `--oscal-validate` that runs `gocomply_oscalkit validate` on emitted artifacts and fails the run/CI on schema errors | orchestrator + `.github/workflows` | Shell out; JSON validation is pure-Go (no `xmllint`), XML validation needs `libxml2` | idea | M | P1 |
| 3 | Document OSCAL version targeting + add a conformance note to `docs/` after pinning a validator schema version | `docs/`, RUNBOOK | Just the idea — adopt their "treat OSCAL types as generated/versioned" discipline | idea | S | P2 |
| 4 | Prefer a **JS-native OSCAL validator** instead of shelling to Go, to avoid a binary dep | `cloud-evidence/core/oscal.ts` | Evaluate `oscal-js` / Metaschema-generated TS types + `ajv` (we already vendor `ajv`, task A.2) against the NIST JSON schema. Reserve oscalkit for the *XML* path only | vendor (JS lib) | M–L | P1 |
| 5 | Consume NIST 800-53 / FedRAMP **catalog & profile** XML by converting to JSON for the tracker | `tracker/`, FRMR ingest | One-shot offline `convert oscal` of NIST XML → JSON checked into repo (not a runtime dep) | idea + one-shot tool | S | P2 |
| 6 | Note OSCAL-native JWS as an alternative/companion to our Ed25519 manifest | evidence signing (B.1) | Just the idea; only if an assessor demands JWS | idea | S | P2 |

**Decision guidance for §4/§5:** For **JSON validation**, prefer a JS lib (row 4) — we already have `ajv` and the NIST JSON schemas are public; shelling to Go just to run a JSON-schema check is overkill and adds a binary dependency. For **XML conversion/validation** (the thing no JS lib does well, and the thing we genuinely lack), oscalkit's `convert oscal` / `xmllint`-backed `validate` is the pragmatic choice — shell out behind an opt-in flag, ship the binary in CI only. Do **not** port oscalkit to TS.

## 6. Risks, caveats, licensing

- **OSCAL version drift — the biggest risk.** oscalkit's models are regenerated nightly from **`usnistgov/OSCAL` HEAD of master, with no tag pin** (`Makefile` clones `--depth 1` of the dev branch; `regenerate-models.yml` runs `make generate` on a cron). This means oscalkit tracks **OSCAL development**, not a stable release. FedPy emits **OSCAL 1.1**. If upstream master has moved to 1.1.x-dev or a future minor, oscalkit's bundled schema may reject perfectly valid 1.1.2 documents, or accept dev-only fields. **Action:** pin a known-good oscalkit build and verify which OSCAL release its bundled schemas correspond to before trusting `validate` as a gate. Do not auto-update the binary.
- **Language mismatch.** Pure Go; FedPy is TypeScript. The only sane integration is binary shell-out, not code reuse. That adds a per-OS binary to ship/download and a subprocess boundary to error-handle (consistent with FedPy's existing `openssl`/`syft`/`cosign` shell-outs, so not a new pattern).
- **`xmllint` dependency for XML validation.** `pkg/xml_validation/validate.go` execs `xmllint`. macOS/Linux have it; Windows needs install. JSON validation has no such dependency.
- **No YAML validation.** `convert` produces YAML but `validate` can't check it (`pkg/oscal_source/validate.go` returns nil validator for YAML). YAML output is convenience-only.
- **Versioning opacity.** No git tags in the clone; the binary says `0.2.0`. Release cadence is unclear beyond the nightly model-regen PRs. Treat it as "maintained but pre-1.0."
- **Licensing — clean.** CC0 1.0 (public domain) for oscalkit's own code; vendored deps are MIT/BSD-3/Apache-2.0. Fully compatible with FedPy's Apache-2.0; we can vendor, redistribute, or borrow with zero obligations. The Docker-origin public-domain heritage is explicitly preserved.

## 7. Verdict

**Moderate, targeted investment — adopt it for the XML path, not as a general OSCAL engine.** The single highest-value thing to take is **schema-valid OSCAL XML output plus validation against the real NIST schemas**, which directly fixes FedPy's two concrete weaknesses (JSON-only emission, no validation). The pragmatic split: handle **JSON validation in-process with `ajv`** (we already ship it) against the public NIST JSON schema, and reserve **oscalkit as an opt-in shell-out for XML conversion/validation** (`--oscal-convert`/`--oscal-validate`), shipping its CC0 binary in CI only. Before relying on its `validate` as a gate, **pin a build and confirm its bundled schema matches OSCAL 1.1** — the nightly-regen-from-master design is the one real footgun. Do not port any of it to TypeScript.
