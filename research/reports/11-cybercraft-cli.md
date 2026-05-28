# Research report: brian-ruf/cybercraft-cli

> Part of the FedPy integration-research series. Each report front-loads the
> analysis so implementation work can start without re-investigating the source.

- **Upstream:** https://github.com/brian-ruf/cybercraft-cli
- **Local clone:** `research/clones/cybercraft-cli` (git-ignored) — includes the two required submodules
  (`src/oscal` = `brian-ruf/oscal-class`, `src/common` = `brian-ruf/common-python`).
- **Language / stack:** Python 3.12. Deps (`src/requirements.txt`): `saxonche` (SaxonC HE — XSLT 3.0 / XPath),
  `jsonschema_rs` (Rust-backed JSON Schema validator), `xmlschema` (XSD validator), `pyyaml`, `loguru`,
  `aiohttp`/`requests`, `Jinja2`. Built to single-file native binaries via **Nuitka** (`.github/workflows/build.yml`,
  Linux/Windows/macOS matrix).
- **License:** ⚠️ **The CLI repo itself has NO LICENSE file** → default all-rights-reserved. The two submodules
  that hold the actual OSCAL logic (`oscal-class`, `common-python`) are **MIT** (`src/oscal/LICENSE`,
  `src/common/LICENSE`). MIT is Apache-2.0-compatible; the unlicensed wrapper is not. Integration-relevance:
  we can borrow ideas freely, and *code* only from the MIT submodules — not from the CLI shell.
- **Activity / maturity:** Last commit 2025-09-15 (all three repos same day). Single-author (Brian Ruf / Ruf Risk
  LLC). **Pre-release / WIP**: README says pre-built binaries "coming soon", `docs/USAGE.md` is empty, and — the
  headline caveat — **the CLI's `validate` and `convert` subcommands are stubbed out as `warning("…is a future
  feature.")`** (`src/cccli.py` lines 294–300). The validation/conversion *engine* exists and looks complete in
  `src/oscal/oscal.py`, but it is **not yet wired into the shipped CLI**. Total hand-written code is small
  (~660 LOC in the CLI shell; ~44 KB `oscal.py` + ~57 KB metaschema parser in the submodule).
- **One-line:** A Python CLI (WIP) that validates OSCAL files and converts them between XML/JSON/YAML using
  **NIST's own published schemas and XSLT converters**, cached locally for offline use.

## 1. What it does

cybercraft-cli ("cccli") is a command-line front end over an OSCAL processing library. Its intended jobs are:
**validate** an OSCAL file against the correct NIST schema, and **convert** OSCAL between the three official
serializations (XML, JSON, YAML). The differentiator versus a generic schema validator is that it does not bundle
or hand-roll OSCAL schemas — it **fetches NIST's official release assets** (XSD, JSON Schema, and the XML↔JSON XSLT
converters) straight from the `usnistgov/OSCAL` GitHub releases, then **caches them locally** so subsequent runs
work offline.

It is version- and model-aware: it sniffs the OSCAL model (root element) and the declared `/metadata/oscal-version`
out of the input file, then selects the matching cached support file for *that exact* version+model. So one binary
validates any model (catalog, profile, SSP, SAP, SAR, POA&M, component-definition, assessment-results) across any
OSCAL release NIST has published, without code changes.

The CLI surface (`src/cccli.py` argparse) already exists: `-va/--validate`, `-c/--convert-to {XML,JSON,YAML}`,
`-o/--overwrite`, `-u/--update` (fetch new OSCAL versions), `-r/--reinitialize` (clear+repopulate cache),
`-f/--export-to FOLDER` (dump cached support files to disk), `-i/--info`, `-d/--debug`, `-l/--logging`. The cache
management commands (`update`/`reinitialize`/`export-to`) are live; **validate/convert are not yet connected** to the
engine (see §6).

It is aimed at OSCAL authors/tool-builders who need a portable, offline, no-Java-install (SaxonC is bundled as a
wheel) validate-and-convert utility — essentially a lighter, NIST-faithful alternative to the Java `oscal-cli`.

## 2. Architecture & key components

Three repos, composed via git submodules:

```
cybercraft-cli/
  src/cccli.py              CLI shell: argparse, app_control, startup (validate/convert STUBBED)
  src/output.py            console/loguru output helpers
  src/oscal/   [submodule oscal-class, MIT]
     oscal.py              ★ the engine: OSCAL_Content class — validate() + convert() + xslt_transform()
     oscal_support.py      ★ OSCAL_support class — SQLite-backed cache of NIST release assets
     cache_files.py        alt/legacy filesystem cache w/ 3-tier fallback (memory→disk→GitHub)
     metaschema_parser.py  parses NIST metaschema XML → JSON tree (toward schema-gen; future)
     metaschema_gen_docs.py, oscal_datatypes.py, oscal_class.py, oscal_project_class.py
  src/common/  [submodule common-python, MIT]
     database.py / database_sqlite3.py   generic DB + a `filecache` table (BLOB store)
     network.py, lfs.py, helper.py, data.py
```

**Validation** (`oscal.py`, `OSCAL_Content.validate`):
- **XML** → `__XML_validation` uses Saxon (`PySaxonProcessor`) to read the root element name + `oscal-version`,
  fetches the matching `oscal_<model>_schema.xsd`, and validates with the **`xmlschema`** library (`__XML_schema_validation`).
- **JSON** → `__JSON_validation` parses the doc, reads model + `oscal-version`, fetches `oscal_<model>_schema.json`,
  and validates with **`jsonschema_rs`** (`__JSON_schema_validation`). Notably it checks `$schema` and warns that
  jsonschema_rs only covers **draft-03/04/07** (OSCAL JSON Schema is draft-07) — relevant because newer drafts may
  need a different validator.
- **YAML** → loaded with `yaml.safe_load`, then validated through the **same JSON-schema path** (YAML treated as JSON).
- Errors are collected into structured `report_message(idx, path, rule, reason, message)` records, not just booleans.

**Conversion** (`oscal.py`, `OSCAL_Content.convert` + `xslt_transform`):
- XML↔JSON is done by running **NIST's published XSLT converters** (`oscal_<model>_xml-to-json-converter.xsl`,
  `..._json-to-xml-converter.xsl`) through SaxonC's XSLT-3.0 processor. This is the key design point: it **reuses
  NIST's own conversion artifacts** rather than re-implementing the metaschema mapping by hand.
- YAML is handled as a serialization swap on the JSON side (`yaml2json`/`json2yaml` via `pyyaml`).
- **Shortest-path routing**: NIST ships only XML↔JSON converters, so XML↔YAML is routed
  `XML → JSON → YAML` (and reverse), reusing any format already materialized on the object. `convert()` documents
  the full path `XML → JSON → YAML → JSON → XML`.

**Offline support-file cache** — *two* implementations exist:
1. **Active (used by the CLI):** `oscal_support.py` stores everything in **SQLite** via `common/database.py`.
   `__get_oscal_versions` hits the GitHub releases API for `usnistgov/OSCAL`, records each non-draft version in an
   `oscal_versions` table, and downloads the five asset types matched by `SUPPORT_FILE_PATTERNS`
   (`_schema.xsd`→xml-schema, `_schema.json`→json-schema, `_xml-to-json-converter.xsl`, `_json-to-xml-converter.xsl`,
   `_metaschema_RESOLVED.xml`→metaschema) into a BLOB `filecache` table, indexed by `(version, model, type)`.
   `asset()` retrieves by that key; `export_support_files()` dumps the cache to a `<version>/` folder tree on disk.
   First run needs network; after that it's fully offline. `-u` adds new versions; `-r` rebuilds.
2. **Alternate (`cache_files.py`, `get_support_file`):** a **3-tier fallback** — in-memory dict → local filesystem
   datastore → NIST GitHub release download — that **promotes** a file to faster tiers on each miss. Same naming
   conventions; not the path the CLI currently wires up, but the cleanest expression of the offline design.

**Metaschema** (`metaschema_parser.py`): parses NIST `*_metaschema_RESOLVED.xml` into a JSON tree of
assemblies/fields/flags/constraints. Today it's used for docs; the stated future direction is to drive
validation/conversion **directly from metaschema** instead of from the derived XSD/JSON-Schema/XSLT artifacts.

**OSCAL versions supported:** *dynamic* — whatever non-draft releases exist in `usnistgov/OSCAL` at cache time
(excludes a hardcoded list of rc/milestone tags). So it tracks v1.0.0 → v1.1.x → v1.2.x → future automatically.
FedPy emits **OSCAL 1.1.x Assessment Results**, which is squarely in range.

## 3. What's genuinely interesting for FedPy

1. **The "reuse NIST's own conversion artifacts" pattern.** Conversion is done by executing NIST's published
   `*-converter.xsl` stylesheets, not by a hand-written XML/JSON mapper. This is the robustness argument: NIST's
   converters are normative and version-matched, so output is correct-by-construction. (`oscal.py:xslt_transform`,
   `__oscal_xml2json`, `__oscal_json2xml`.)
2. **Version+model-aware schema selection from the document itself.** It reads the model root element and
   `metadata/oscal-version` and picks the exact matching schema. This is precisely how a *validator* for our
   emitted OSCAL should behave, and is more disciplined than validating against one pinned schema. (`__JSON_validation`.)
3. **The offline-cache philosophy is a near-exact match to ours.** "Fetch NIST's machine-readable assets once, cache
   them, then run with no network" is the same principle FedPy already follows ("commit generated NIST data, no
   runtime network"). `SUPPORT_FILE_PATTERNS` + `__get_support_files` + `export_support_files` is a clean, copyable
   blueprint for *which* NIST files to grab and how to key them `(version, model, type)`.
4. **draft-07 caveat, documented.** `__JSON_schema_validation` warns that the validator only supports draft-03/04/07.
   We use `ajv`, which natively supports draft-07 (and 2019-09/2020-12) — so we're better positioned here, but it's a
   useful reminder to confirm which draft the OSCAL JSON Schema declares before validating.
5. **Structured validation reports** (`report_message` with path/rule/reason) rather than pass/fail — a nicer shape
   than ajv's raw error array if we ever surface validation results to users.

## 4. Gaps in OUR stack this could fill

FedPy's `cloud-evidence/core/oscal.ts` hand-builds OSCAL 1.1 Assessment Results JSON and has **never been validated
against the NIST OSCAL JSON Schema**. Two concrete gaps map here:

- **Gap A — OSCAL validation.** We have no check that our emitted JSON actually conforms to NIST's
  `oscal_assessment-results_schema.json`. cybercraft shows the end-to-end recipe: pull that schema from the
  `usnistgov/OSCAL` release matching our target version, cache it, validate. **Crucially, we already vendor `ajv`**
  (task A.2) — the only thing we're missing is the *schema file and the offline-fetch/cache step*, which is exactly
  the part cybercraft does well and which is language-agnostic.
- **Gap B — OSCAL format conversion (XML/YAML).** We are JSON-only. If a FedRAMP reviewer or downstream tool ever
  wants OSCAL **XML**, we'd need a converter. cybercraft demonstrates the only robust way to do this: run NIST's
  `*-converter.xsl` through an XSLT-3.0 engine. This is a *latent* need for us, not an active one — our pipeline and
  the OSCAL ecosystem are JSON-first — so it's low priority.

Note the overlap with report 07 (GoComply/oscalkit, Go): oscalkit also validates/converts OSCAL but is built around
**Go structs generated from pinned schemas** and an older OSCAL line. cybercraft's advantage is that it stays
NIST-faithful and **version-dynamic** (any release, no codegen). Its disadvantages vs oscalkit: Python (not our TS),
unlicensed CLI shell, and the CLI conversion/validation paths aren't wired yet.

## 5. Integration opportunities (actionable)

| # | Opportunity | FedPy target | Approach | Borrow code or just the idea? | Effort | Priority |
|---|-------------|--------------|----------|-------------------------------|--------|----------|
| 1 | Validate our emitted OSCAL JSON against NIST's official `assessment-results` JSON Schema, with the schema fetched once + committed for offline use | `cloud-evidence/core/oscal.ts` + a new `core/oscal-validate.ts` using our existing `ajv` | Borrow the **approach**: download `oscal_assessment-results_schema.json` for our pinned OSCAL version from `usnistgov/OSCAL` releases, commit it under `cloud-evidence/vendor/oscal/<version>/`, validate emitter output with ajv in CI. No new runtime dep. | idea (port cybercraft's asset-naming + cache key) | S | **P0** |
| 2 | Version+model-aware schema selection (read `metadata/oscal-version` from the doc, pick matching schema) | `core/oscal-validate.ts` | Idea: mirror `__JSON_validation`'s "sniff model + version, choose schema" so we're future-proof if we bump OSCAL versions | idea | S | P1 |
| 3 | A small script that mirrors NIST OSCAL release assets (schemas + XSLT) into a committed `vendor/` tree | `cloud-evidence/scripts/fetch-oscal-support.ts` | Port the `SUPPORT_FILE_PATTERNS` map + GitHub-releases asset fetch from `oscal_support.py`/`cache_files.py` into a TS fetch script; run at build time, commit output | idea + port the file-pattern table | S/M | P1 |
| 4 | Optional OSCAL JSON→XML/YAML conversion for reviewer exports | (new) `cloud-evidence/core/oscal-convert.ts` | **Shell out** to a Saxon/XSLT-3.0 runner over NIST's committed `*-converter.xsl` — there is no good pure-JS path. Only build if a reviewer actually demands XML. | idea (do NOT port Python; it's the wrong language) | M/L | P2 |
| 5 | Structured validation-report shape (path/rule/reason) for surfacing OSCAL errors to users | `core/oscal-validate.ts` output / tracker | Idea: map ajv errors into cybercraft's `report_message` shape | idea | S | P2 |

## 6. Risks, caveats, licensing

- **License blocker on the wrapper.** The cybercraft-cli repo has **no LICENSE file** — copying from `src/cccli.py`
  or `src/output.py` is not permitted. The reusable engine (`oscal-class`) and `common-python` are **MIT**, which is
  Apache-2.0-compatible; if we port any actual lines, take them only from those submodules and preserve the MIT
  notice. In practice we'd borrow *patterns* (asset names, cache keying), not code, sidestepping the issue.
- **Language mismatch.** Python + SaxonC + Rust-backed `jsonschema_rs`. We are TypeScript with `ajv` already
  vendored. Porting validation is trivial (it's just "ajv + the right schema file"); porting *conversion* would mean
  carrying a Saxon/XSLT runtime, which is heavy and off-stack — hence shell-out-only if ever needed.
- **Maturity / WIP.** Single maintainer; `docs/USAGE.md` empty; binaries unreleased; and **the CLI's validate/convert
  are stubbed** (`cccli.py:294-300` print "future feature" and the engine calls are commented out). So you cannot
  today run `cccli -va file.json` and get a result — you'd have to call the `oscal-class` library functions directly.
  This rules out "just shell out to the published CLI" as a near-term option.
- **First-run network dependency.** The cache must be populated from GitHub at least once. Their model fetches at
  runtime on cache-miss; **our** model would be to fetch *at build time* and commit, preserving FedPy's strict
  no-runtime-network guarantee. That's a philosophy match but an implementation difference to respect.
- **Validator draft limit.** `jsonschema_rs` only does draft-03/04/07. Not our problem (ajv is broader), but confirms
  we should keep using ajv rather than adopting their validator.
- **Format drift.** Because it's version-dynamic, it self-heals as NIST publishes releases — low drift risk. Our
  committed-schema approach trades that for reproducibility (we pin a version), which is the right call for evidence.

## 7. Verdict

**Invest lightly, and borrow the approach rather than the tool.** For FedPy's central question — does this beat
oscalkit (report 07) as our OSCAL validation/conversion answer? — the honest answer is **neither tool should be a
runtime dependency**, but **cybercraft's *design* is the better influence**. For *validation*, the highest-value
move is option (b) from the brief: **use our already-vendored `ajv` to validate the OSCAL JSON our emitter produces,
against NIST's official `assessment-results` JSON Schema, with that schema fetched once at build time and committed**
for offline use — exactly cybercraft's offline-cache philosophy, executed in our own stack with zero new runtime
deps. That cleanly beats shelling out to either cybercraft (Python, unlicensed shell, validate path still stubbed)
or oscalkit (Go, codegen-bound, older OSCAL line). For *conversion* (XML/YAML), we have no real need today and no
good in-stack path; if it ever arises, cybercraft proves the only robust route is running **NIST's own
`*-converter.xsl`** through an XSLT engine — so we'd shell out to a Saxon runner over committed NIST stylesheets, not
hand-roll a converter. **Single highest-value takeaway:** the `SUPPORT_FILE_PATTERNS` → fetch → cache-by-
`(version, model, type)` blueprint (`oscal_support.py`), reimplemented as a tiny TS build-time script that vendors
the one schema we need and validates our emitter with ajv (opportunity #1, P0).
