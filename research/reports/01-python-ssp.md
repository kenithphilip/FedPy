# Research report: brasky/python-ssp

> Part of the FedPy integration-research series. Each report front-loads the
> analysis so implementation work can start without re-investigating the source.

- **Upstream:** https://github.com/brasky/python-ssp
- **Local clone:** `research/clones/python-ssp` (git-ignored)
- **Language / stack:** Python 3.3+, single dependency `python-docx` (lxml under the hood). ~250 LOC of library code across 4 modules.
- **License:** **MIT** (`LICENSE`, "Copyright (c) 2019 Elliot DeMatteis"). Permissive — code is borrowable into our Apache-2.0 project with attribution; no copyleft friction. ← integration-relevance: legally we *could* port; the real question is whether the *approach* survives a 2018-template → FedRAMP-20x reality.
- **Activity / maturity:** Alpha. PyPI version `0.1.1` (`setup.py`), `Development Status :: 3 - Alpha`. Cloned HEAD commit `ab92e20` dated **2020-08-15**; GitHub repo last pushed 2021-11-03 (master metadata only), **not archived**, 11 stars / 4 forks / 1 open issue. Effectively dormant for ~4–5 years. CI is Travis (`.travis.yml`, Python 3.6) — long dead. `HISTORY.rst` shows a single substantive release (0.1.0, 2019-07-09).
- **One-line:** A thin read/parse layer that treats the FedRAMP SSP Word template as a structured database — controls are pairs of docx tables, exposed through a tiny Python API.

## 1. What it does

`python-ssp` opens a **FedRAMP System Security Plan `.docx` template** (the legacy 08/28/2018 NIST 800-53 Rev 4 baseline templates — Low/Moderate/High) and lets you read the control-implementation content programmatically instead of scraping Word by hand. The author built it to "simplify import/export code" for a sibling project, `securityplanmanager` (README). The mental model: a FedRAMP SSP is just a long sequence of Word tables, and every control is encoded as **two adjacent tables** — a "CIS" (Control Information Summary) table holding metadata (responsible role, parameters, implementation-status checkboxes, control-origination checkboxes) and an "implementation" table holding the per-part narrative text.

The library's whole job is to (a) walk every table in the document, (b) recognize which table pairs are controls, (c) wrap each pair in a `Control` object, and (d) expose getters for the fields a compliance tool actually wants: `control.responsible_role`, `control.parameters`, `control.implementation_status`, `control.control_origination`, and `control.part('a').text` for the narrative of a specific control part. It is **read-oriented** in practice: the only "export" path shipped is the sample that dumps everything to an Excel sheet (`samples/export_to_excel.py`). It does not author or render an SSP from scratch — it reads a filled (or blank) template.

Who it's for: people who have an authoritative SSP in the FedRAMP Word format and need to extract its structured content — to migrate into a GRC tool, diff it, report on it, or bulk-edit it. It is the *inverse* of what FedPy needs most (rendering), but it is the canonical worked example of **how the FedRAMP SSP docx is structured at the OOXML level**, which is the hard part of ever rendering one.

## 2. Architecture & key components

Top-level layout (everything that matters):

```
ssp/__init__.py        # re-exports SSP
ssp/api.py             # SSP() factory -> SecurityPlan
ssp/securityplan.py    # document walk + control indexing (version dispatch)
ssp/control.py         # the Control object: all per-control field parsing
samples/export_to_excel.py   # the one shipped consumer (docx -> xlsx via openpyxl)
tests/                 # pytest, plus the three real FedRAMP blank templates as fixtures
tests/test_files/blank_templates/08282018/FedRAMP-SSP-{High,Moderate,Low}-Baseline-Template.docx
```

**Entry point** — `ssp/api.py` `SSP(path)` is a one-line factory returning `SecurityPlan(path)`. `ssp/__init__.py` re-exports it so `from ssp import SSP` works.

**Document model** — `ssp/securityplan.py`:
- `SecurityPlan.__init__` loads the docx via `python-docx`'s `Document(path)`, calls `get_version()`, and dispatches to a per-version subclass. **`get_version()` is hard-coded to return `'08282018'`** — the real version-detection code is commented out (lines 41–52) because "docx doesn't see anything before the table of contents." So version handling is aspirational: any non-08282018 template raises `ValueError('This template version is not compatible.')`.
- `SecurityPlan_08282018.create_control_index()` is the core algorithm (lines 88–106): iterate `document.tables`; when `is_cis_table(table)` is true, remember it and expect the *next* table to be the implementation table; pair them into a `Control`. Recognition is purely heuristic — `is_cis_table` checks that cell (0,0) contains a `-` and passes `is_valid_control()`.
- `is_valid_control()` (lines 75–86) is the key bit of domain knowledge: a regex `([A-Z]*-[0-9]*\s*(\([0-9]*\))*)(\s*\([A-z]*\))*\s*(Req.)*$` that matches `AC-1`, `AC-2(2)`, `AC-2(Ext)`, `AC-2(Privacy)`, etc. This encodes the FedRAMP control-ID grammar (family, number, enhancement, Ext/Privacy variants).
- An index `control_list_to_table_index` maps upper-cased control numbers → position, so `.control('AC-1')` is O(1).

**Per-control parsing** — `ssp/control.py` is where the real OOXML reverse-engineering lives:
- `Control.__init__` takes the two tables and derives `number` from `cis_table.cell(0,0)`, then parses parts, responsible role, parameters (cis rows 2..n-2), implementation status (cis row n-2), and control origination (cis row n-1). **Layout positions are hard-coded by row offset** — brittle against any template change.
- `get_parts()` (lines 29–38): a control's "parts" = rows in the implementation table whose first cell starts with `Part ` or `Req. ` (and is <8 chars). Controls with one undivided response get `parts == [None]`.
- `part(part_id)` (lines 40–65): maps a part letter to a cell via a `letter -> index` table (`LETTERS`, built from `ascii_lowercase`), with special-casing for compound parts like `a1`. Returns the raw `python-docx` cell so callers can do `.text` or manipulate runs.
- `get_implementation_status()` / `get_control_origination()` (lines 79–158): **the genuinely valuable, hard-won code.** These read Word *checkbox* state by inspecting the run XML for `w14:checked w14:val="1"` (modern content-control checkboxes) and the legacy `<w:checked/>` / `<w:default w:val="1"/>` forms, then string-match the adjacent label text to a canonical enum: `Implemented / Partially Implemented / Planned / Alternative Implementation / Not Applicable`, and origination `Service Provider Corporate / System Specific / Hybrid / Configured by Customer / Provided by Customer / Shared / Inherited / Not Applicable`. The author notes the inherited-checkbox edge case explicitly (control.py line 124 TODO).

**Data formats:** consumes FedRAMP SSP `.docx`; produces in-memory Python objects; the sample produces `.xlsx`. No JSON, no OSCAL anywhere.

**Dependencies:** `python-docx` only (`setup.py` `INSTALL_REQUIRES`); `pytest` for tests; sample adds `openpyxl`. Minimal and clean.

**Tests:** `tests/test_control.py` and `tests/test_securityplan.py` assert against the real blank High template (e.g. `AC-1` responsible role == "My Role", parameters list, status == `["Implemented"]`). Confirms the parsing works on the shipped fixtures, but coverage is shallow and fixture-specific.

## 3. What's genuinely interesting for FedPy

The signal here is **not** the API design (alpha, brittle, read-only) — it's the **encoded knowledge of the FedRAMP SSP docx structure**, which is exactly the thing FedPy would otherwise have to reverse-engineer from scratch to ever produce SSP documents.

1. **The control-table pairing model** (`securityplan.py:create_control_index`). The insight that a FedRAMP SSP control = `(CIS table, implementation table)` adjacent pair, recognized by a control-ID regex in cell (0,0), is the foundational layout fact. Whether reading or writing, any tool touching these docs needs this model.

2. **The control-ID grammar regex** (`control.py`/`securityplan.py:is_valid_control`). `([A-Z]*-[0-9]*\s*(\([0-9]*\))*)(\s*\([A-z]*\))*\s*(Req.)*$` cleanly captures family/number/enhancement plus FedRAMP's `(Ext)` / `(Privacy)` / `Req.` variants. Directly portable as a TS regex for any control-ID parsing we do (and we already touch control IDs in `core/control-benchmark.ts` and the crosswalk).

3. **The checkbox-state extraction** (`control.py:get_implementation_status` / `get_control_origination`). This is the most expensive-to-rediscover code in the repo: reading Word checkbox/content-control state via run XML (`w14:checked w14:val="1"`, legacy `<w:checked/>`, `<w:default w:val="1"/>`) and normalizing labels to the FedRAMP implementation-status and control-origination enums. **Those enum value sets themselves are reusable data** regardless of language — they are the canonical FedRAMP vocabulary for status and origination.

4. **The docx-as-database posture.** It demonstrates that `python-docx` (and by extension its JS analog) can treat the SSP template as addressable structured storage — read a cell, and equally *write* a cell (`part()` returns a live cell object). That round-trip capability is the conceptual seed of a renderer: fill the template's cells rather than build a doc from nothing.

5. **A bundled, authoritative artifact:** the three real FedRAMP blank baseline templates (`tests/test_files/blank_templates/08282018/`) are checked in. Even if we never run the code, those `.docx` files (and the OOXML inside them) are reference material for what a FedRAMP SSP actually looks like at the table/checkbox level.

## 4. Gaps in OUR stack this could fill

FedPy's stated blind spot is **SSP authoring / human-readable document rendering**: we emit OSCAL Assessment Results (`cloud-evidence/core/oscal.ts`), a NIST 800-53 benchmark (`core/control-benchmark.ts`), CSV/HTML reports (`core/csv-export.ts`, `core/html-report.ts`), and a crosswalk — but **nothing produces the FedRAMP SSP Word deliverable** an agency package requires. This repo speaks directly to that gap, though only partway:

- **We have no docx read/write capability at all.** There is no `.docx` codepath anywhere in `cloud-evidence/` or `tracker/`. python-ssp proves the table-pairing + cell-addressing model and gives us the OOXML facts (checkbox XML, row layout) needed to build a TS equivalent on top of a library like `docx` (npm) or `docxtemplater`. A future `cloud-evidence/core/ssp-render.ts` (or a `tracker/` "Export SSP" button) would lean on exactly this knowledge.
- **It maps cloud evidence ↔ SSP control narratives — a bridge we lack.** Our collectors produce per-KSI findings and we have a NIST control benchmark, but we have no path from "AC-2 finding" to "the AC-2(a) implementation cell in an SSP." python-ssp's `control.part('a')` cell-addressing is the missing half of that bridge: it shows *where* a generated narrative would be written.
- **The FedRAMP status/origination enums fill a small data gap.** Our findings model has its own scoring vocabulary; it does **not** carry FedRAMP's SSP-native `Implemented/Partially/Planned/Alternative/Not Applicable` status nor the 8-value control-origination set. Those are reusable constants for any SSP export or for enriching `tracker/` item status semantics.
- **A docx *reader* could ingest a customer's existing SSP into the tracker.** Inverse of rendering: `tracker/` currently tracks implementation status against the FRMR catalog from scratch. A docx parser modeled on this could bootstrap the tracker from a customer's already-authored 800-53 SSP (status + responsible role + narrative per control), seeding the database.

**Honest limit on the gap-fill:** python-ssp targets the **2018 Rev-4 SSP Word template**. FedRAMP 20x has moved away from the giant Rev-4 SSP toward machine-readable / OSCAL-centric packages and KSI-based assessment. So this does **not** hand us a 20x-ready renderer — it hands us the *technique and the OOXML facts*, applicable to whatever Word template a given authorization still requires (many Rev-5 / transitional packages still use docx SSPs).

## 5. Integration opportunities (actionable)

| # | Opportunity | FedPy target | Approach | Borrow code or just the idea? | Effort | Priority |
|---|-------------|--------------|----------|-------------------------------|--------|----------|
| 1 | Port the FedRAMP control-ID grammar regex for robust control-ID parsing (family/number/enhancement/Ext/Privacy/Req) | `core/control-benchmark.ts`, crosswalk, any control parser | Translate `is_valid_control()` regex to TS; add unit tests for `AC-2(2)`, `AC-2(Ext)`, `AC-2(Privacy)` | **Port** (1 regex) | S | P1 |
| 2 | Adopt FedRAMP SSP status + control-origination enums as canonical constants | `cloud-evidence/core/*` types; `tracker/` item status | Lift the two enum value sets from `get_implementation_status`/`get_control_origination` into a shared `ssp-enums.ts`/TS const | **Port the data** (idea + values) | S | P1 |
| 3 | New SSP renderer: fill a FedRAMP SSP `.docx` template from findings + tracker status | new `cloud-evidence/core/ssp-render.ts` (or `tracker/` "Export SSP") | Reuse the table-pairing model + cell-addressing as the *write* spec; implement on npm `docx`/`docxtemplater`; map KSI/control findings → CIS metadata cells + part narrative cells | **Idea + structural spec** (re-implement in TS) | L | P2 |
| 4 | SSP *reader*: ingest a customer's existing 800-53 SSP docx to bootstrap the tracker | `tracker/` import path + a parser module | Re-implement `create_control_index` + checkbox XML reading in TS over a JS docx lib; seed tracker items (status, responsible role, narrative) | **Idea + OOXML facts** (no code shares) | M | P2 |
| 5 | Vendor the three blank FedRAMP baseline templates + checkbox-XML notes as renderer reference material | `docs/` or research assets | Copy `tests/test_files/blank_templates/08282018/*.docx`; document the `w14:checked` / `<w:checked/>` / `<w:default>` forms and row layout | **Vendor artifact + notes** | S | P2 |

## 6. Risks, caveats, licensing

- **License: clean.** MIT permits use/modify/sublicense; fully compatible with our Apache-2.0 distribution. If we copy any code or the bundled templates, include the MIT notice/attribution. (The FedRAMP `.docx` templates are themselves U.S. Government works / public templates, but track provenance.)
- **Language mismatch is total.** Python + `python-docx` (lxml). FedPy is TypeScript on Node/Bun/Deno. **Zero runtime code is directly reusable** — there is no Python in our stack and we will not add one. Everything here is a *port or re-implementation* job; the borrowable assets are the regex (one line), the enum value sets (data), the table-pairing/cell-addressing *design*, and the OOXML checkbox facts. Treat it as a spec, not a dependency.
- **Template-version risk is severe for the renderer use-case.** The library only supports the **2018 Rev-4** template and even its version detection is stubbed out (`get_version` hard-returns `'08282018'`, real logic commented). FedRAMP 20x is OSCAL/KSI-centric and de-emphasizes the monolithic Word SSP. A renderer built on this knowledge serves transitional/Rev-5 docx SSPs, **not** the 20x machine-readable package — set expectations accordingly so we don't build a deliverable nobody asks for.
- **Brittleness of the parsing approach.** Field extraction relies on hard-coded row offsets (e.g. status = row n-2, origination = row n-1) and substring matching of checkbox labels — any FedRAMP template revision breaks it. The author flags edge cases (inherited checkboxes, "ugly" workarounds). A TS reader must re-derive layout against current templates, not trust these offsets.
- **Maintenance: abandoned.** Last real commit 2020, alpha status, Travis CI long dead, 11 stars. **Do not depend on or PR upstream** — mine it once, internalize the knowledge, move on.
- **Round-trip / content-controls gotcha.** README warns that the template's Word "Content Controls" around tables can break parsing unless stripped (save-as-.doc-then-.docx). Any FedPy docx work inherits this real-world friction with the official templates.

## 7. Verdict

**Invest lightly — mine the knowledge, don't adopt the code.** python-ssp's lasting value to FedPy is not its (alpha, abandoned, Python) implementation but its **encoded reverse-engineering of the FedRAMP SSP `.docx` structure**: the control = (CIS table + implementation table) pairing, the control-ID grammar regex, and especially the Word checkbox-XML extraction with its canonical status/origination enums. That is precisely the expensive-to-rediscover groundwork our biggest gap — **SSP authoring/rendering** — would need. The single highest-value takeaway: **it proves the SSP docx is mechanically addressable as a table/cell database and documents exactly how**, which de-risks a future TS `ssp-render.ts`/tracker-export feature from "open research problem" to "known engineering task." Two things are immediately, cheaply portable today (the control-ID regex and the FedRAMP status/origination enum sets, opportunities #1–2, both S/P1). The renderer itself (#3) is a large P2 we should only green-light once we confirm a target authorization still consumes a Word SSP rather than a pure 20x/OSCAL package — because this gives us a *Rev-4/transitional* path, not a native 20x one.
