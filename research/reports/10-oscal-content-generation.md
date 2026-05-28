# Research report: brian-ruf/oscal-content-generation

> Part of the FedPy integration-research series. Each report front-loads the
> analysis so implementation work can start without re-investigating the source.

- **Upstream:** https://github.com/brian-ruf/oscal-content-generation
- **Local clone:** `research/clones/oscal-content-generation` (git-ignored)
- **Language / stack:** Python 3. Deps: `saxonche` (Saxon XSLT/XQuery, pinned `12.5.0`), `lxml`, `elementpath` (XPath 3 engine actually used), `loguru`, `requests`. Stdlib `xml.etree.ElementTree` + `uuid`.
- **License:** Apache-2.0 (`LICENSE`, full text present). Same as FedPy — clean to borrow code or ideas.
- **Activity / maturity:** Single author (Brian Ruf, ex-FedRAMP/NIST OSCAL contributor). Last commit 2024-12-13 (README only). Tiny: one real module (`src/ssp_content_creator.py`, ~440 lines) + `src/common.py` (~95 lines) + two large example SSP XML files. No releases, no tests, no CI, no packaging. Self-described as "intended to grow over time" — a working proof-of-concept, not a product.
- **One-line:** A Python script that walks a resolved FedRAMP baseline catalog and injects one placeholder `implemented-requirement` per control into an existing OSCAL SSP shell.

## 1. What it does

The repo generates OSCAL **system-security-plan (SSP)** content. Specifically, `ssp_content_creator.py` takes (a) a *base* SSP XML file that already contains all the metadata, system-characteristics, system-implementation, and an empty-ish `<control-implementation>`, and (b) a **FedRAMP Rev 5 resolved-profile catalog** fetched live from GSA (`fedramp-automation/.../FedRAMP_rev5_HIGH-baseline-resolved-profile_catalog.xml`). It then iterates every `<control>` in that catalog and **appends one `<implemented-requirement>` per control** to the SSP's `<control-implementation>`, writing a completed SSP to disk.

For each control it scaffolds the sub-structure an SSP author would otherwise hand-type: one `<set-parameter>` per catalog `<param>` (value literally `"placeholder"`), and one `<statement>` per FedRAMP "response point" — the statement parts where FedRAMP expects a written response. Inside each statement it drops one `<by-component>` pointing at the mandatory `this-system` component, with a placeholder `<description>`. UUIDs are assigned from a deterministic numeric sequence (`11111111-2222-4000-8000-0000000NNNNN`) so example docs are stable/diffable.

Per the README, the output is "intended for FedRAMP CI/CD pipeline testing, but could also serve to **pre-populate placeholder SSP content when authoring a new SSP based on a FedRAMP baseline**." That second use is exactly FedPy's missing piece. Notably it does **no profile resolution** itself — it relies on GSA's already-resolved baseline catalogs (where every control + parameter is fully inlined), which sidesteps the hardest part of OSCAL tooling.

The only FedRAMP-specific logic is reading the `response-point` prop/extension (`ns="https://fedramp.gov/ns/oscal"`) to decide which statements get a response stub. Everything else it emits is core OSCAL.

## 2. Architecture & key components

Flat layout — everything is in `src/`:

- **`src/ssp_content_creator.py`** — the whole program. Contains:
  - `class oscal` — a thin wrapper around an `ElementTree` parse. Detects the OSCAL model from the root element name (`system-security-plan`, `catalog`, `profile`, …), reads `/metadata/oscal-version`, and exposes `xpath()` / `xpath_atomic()` (via `elementpath` with the default OSCAL namespace `http://csrc.nist.gov/ns/oscal/1.0`), `append_child()`, and `serializer()`. `OSCAL_validate()` and `OSCAL_convert()` are **stubs that do nothing** (schema validation and XML↔JSON↔YAML are declared future work). A second, fully-commented-out Saxon-based code path (`__saxon_*` methods) is dead/aspirational.
  - **Free functions = the actual recipe:**
    - `insert_controls(catalog_obj, ssp_obj)` — loops `//control`, mints a UUID, calls `append_child("control-implementation", "implemented-requirement", attribute_list=[control-id, uuid])`, then calls the two helpers below. **Has a hard `limit = 5` and skips `ac-1`/`ac-2`** (those are hand-authored in the base file) — so the committed run only generates a handful of controls, not a whole baseline. Both are trivially removable.
    - `append_params(control, ir, catalog)` — for each `./param` adds `<set-parameter param-id=…><value>placeholder</value>`.
    - `append_response_points(control, ir, catalog, uuid)` — XPath `./part[@name='statement']//prop[@name='response-point' and @ns='https://fedramp.gov/ns/oscal']/../@id` finds FedRAMP response statements; for each, adds a `<statement statement-id=… uuid=…>` containing one `by-component`.
    - `append_by_component(...)` — emits `<by-component component-uuid="…009000000000" uuid=…><description><p>…</p></description>`. The `…009000000000` UUID is the conventional `this-system` component id.
- **`src/common.py`** — IO helpers: `fetch_file(url)` (urllib GET), `get_file`/`putfile`, `normalize_content` (bytes→str), and `uuid_format(suffix)` (deterministic sequenced UUIDs or random `uuid4()`).
- **`src/fedramp-ssp-example_base.oscal.xml`** (3,581 lines) — the **input shell**: a complete FedRAMP SSP example with all metadata/roles/parties/system-characteristics/components/users, plus hand-authored `ac-1`/`ac-2` `implemented-requirement`s as reference exemplars. `oscal-version` = **1.1.2**; `metadata/version` = `fedramp3.0.0-oscal1.1.4`; `import-profile` points at the FedRAMP Rev 5 Moderate baseline profile.
- **`src/fedramp-ssp-example.oscal.xml`** (3,333 lines) — a committed *output/exemplar* showing the richer target shape (multiple `by-component`s, `implementation-status`, `control-origination` props). This is curated, not raw script output — the script itself emits the leaner single-`by-component` placeholder form.
- **`requirements.txt`, `install.sh`, `dependencies.sh`, `run.sh`, `run.bat`, `install_venv.bat`** — venv setup + run wrappers. `run.sh` just `python ssp_content_creator.py`.

Data in: resolved-profile **catalog XML** (remote) + **base SSP XML** (local). Data out: **SSP XML** on disk. XML only — no JSON/YAML path despite OSCAL supporting all three.

## 3. What's genuinely interesting for FedPy

This is the **smallest known reference implementation of "baseline → skeleton SSP."** The signal is the algorithm, not the code (Python vs our TS):

1. **The skeleton-generation loop is dead simple and directly portable.** "For each control in the resolved baseline → one `implemented-requirement{control-id, uuid}` → one `set-parameter` per `param` → one `statement` per response-point → one `by-component` → placeholder description." That is the entire recipe FedPy needs to go from "set of controls in a baseline" to "one SSP entry per control." (`insert_controls` + `append_params` + `append_response_points` + `append_by_component`.)

2. **Use the GSA resolved-profile catalog as the control source — skip profile resolution entirely.** This is the key shortcut. Profile resolution (the hard, spec-heavy part of OSCAL) is offloaded to GSA's published, already-resolved baseline catalogs, where controls and parameters are fully inlined. FedPy doesn't need its own resolver; it can pull the same artifacts. (URL pattern in `ssp_content_creator.py` line 417.)

3. **The `response-point` filter is the FedRAMP-specific nugget.** FedRAMP marks the exact statement parts where a written response is expected via `prop[@name='response-point' @ns='https://fedramp.gov/ns/oscal']`. Generating a `statement` stub only for those (not every `smt.*` part) is what makes the output FedRAMP-shaped rather than noise. FedPy should replicate this XPath/filter when emitting statements.

4. **Deterministic, sequenced UUIDs** (`uuid_format`) — stable across runs so generated docs diff cleanly. A nice touch for a tool that regenerates SSP skeletons; FedPy's emitter could offer the same "stable vs random" toggle.

5. **The base-SSP-shell pattern.** Rather than synthesizing an entire SSP from nothing, it merges generated `implemented-requirement`s into a pre-built shell that already has metadata/roles/parties/components. FedPy can ship its own shell (with the CSP's real org data) and inject only the control-implementation. The committed `fedramp-ssp-example_base.oscal.xml` is itself a **reusable, well-commented FedRAMP SSP template** worth keeping as reference for required roles/props/`this-system` component conventions.

6. **It confirms the SSP slot FedPy already has data for.** FedPy's tracker holds per-requirement status/owner/notes/evidence; this repo shows the OSCAL targets those map to: tracker status → `implementation-status/@state`, tracker notes → `by-component/description/p`, tracker evidence → `link`/back-matter resource. The repo populates these with `"placeholder"`; FedPy can populate them with real tracker content.

## 4. Gaps in OUR stack this could fill

FedPy's `cloud-evidence/core/oscal.ts` emits OSCAL **Assessment Results** only. We have **no SSP emitter**, and no way to pre-populate placeholder SSP content from a baseline. Sibling report 09 (GoComply/fedramp) *renders* an OSCAL SSP → Word but needs an SSP as **input** — which we don't produce. This repo is the upstream piece that closes that loop:

- **New surface: `cloud-evidence/core/oscal-ssp.ts` (SSP emitter).** Today `core/oscal.ts` only knows the assessment-results model. This repo is the recipe for an SSP-skeleton emitter — the one OSCAL model that turns FedPy from an *evidence* tool into a *draft-SSP* tool.
- **Baseline-membership data we already have.** The brief notes FedPy ships `cloud-evidence/docs/nist-r5-baselines.generated.json` (Low/Mod/High membership) + `docs/nist-r5-controls.generated.json` (names). That is exactly the "set of controls in a baseline" input this repo iterates — we don't even need to fetch the GSA catalog to get the *control list*; we already have it. (We'd still want the GSA resolved catalog for the **parameter ids** and **response-point** statement ids per control, which our generated baselines may not carry.)
- **Tracker → OSCAL mapping (the value-add over this repo).** This repo writes `"placeholder"` everywhere. FedPy's tracker has real per-control implementation status/owner/notes/evidence. Wiring `tracker/` records into `set-parameter/value`, `by-component/description`, and `implementation-status/@state` produces a *partially-populated* SSP, not just an empty skeleton — strictly better than what this repo does.
- **OSCAL JSON output.** This repo is XML-only and its conversion is a stub. FedPy already emits OSCAL **JSON** (assessment results), so a FedPy SSP emitter can natively produce JSON SSP — avoiding the XML-only limitation and matching our existing serialization style.

## 5. Integration opportunities (actionable)

| # | Opportunity | FedPy target | Approach | Borrow code or just the idea? | Effort | Priority |
|---|-------------|--------------|----------|-------------------------------|--------|----------|
| 1 | Skeleton OSCAL-SSP emitter: 1 `implemented-requirement` per baseline control, 1 `set-parameter` per param, 1 `statement` per response-point, 1 `this-system` `by-component` | new `cloud-evidence/core/oscal-ssp.ts` | Port `insert_controls`/`append_params`/`append_response_points`/`append_by_component` logic to TS; emit OSCAL **JSON** (our native format) using existing `core/oscal.ts` style | idea (algorithm) — reimplement in TS | M | **P0** |
| 2 | Pull control list / params / response-points from a resolved baseline | emitter input layer | Reuse our committed `nist-r5-baselines.generated.json` for membership; fetch GSA `FedRAMP_rev5_{LOW,MODERATE,HIGH}-baseline-resolved-profile_catalog` for param-ids + `response-point` statement-ids (cache locally) | idea | S–M | **P0** |
| 3 | Populate stubs from tracker data instead of `"placeholder"` | `tracker/` read API → emitter | Map tracker status→`implementation-status/@state`, notes→`by-component/description`, params→`set-parameter/value`, evidence→`link`/back-matter | idea (this repo only shows the empty form) | M | **P0** |
| 4 | Ship a reusable FedRAMP SSP **shell/template** (metadata, required roles, parties, `this-system` component) | `cloud-evidence/templates/ssp-base.json` (+ docs) | Translate `fedramp-ssp-example_base.oscal.xml`'s required scaffolding to a JSON shell; let users drop in real org data; inject control-implementation | port the structure (Apache-2.0) | S–M | P1 |
| 5 | Deterministic vs random UUID strategy for regenerable SSPs | emitter util | Reimplement `uuid_format` (sequenced) alongside `crypto.randomUUID()` toggle | idea | S | P1 |
| 6 | `response-point` filter to emit response stubs only where FedRAMP expects them | emitter statement logic | Replicate XPath `part[@name='statement']//prop[@name='response-point' @ns='https://fedramp.gov/ns/oscal']` as a JSON-path/filter | idea | S | P1 |
| 7 | Close the SSP→Word loop with report 09 | end-to-end pipeline | Feed FedPy-emitted OSCAL SSP into GoComply/fedramp's Word renderer | idea (cross-report) | M | P2 |

**Concrete P0 plan for a FedPy OSCAL-SSP emitter:**
1. **Input**: baseline level (Low/Mod/High) + a tracker export (per-control status/notes/owner/evidence).
2. **Control set**: from `nist-r5-baselines.generated.json`; enrich each control with its `param` ids and FedRAMP `response-point` statement ids from the GSA resolved-profile catalog (fetch once, cache).
3. **Shell**: load a FedPy SSP base shell (org metadata, required roles/parties, the single `this-system` component) — translated from this repo's base file.
4. **Emit**: for each control, build an `implemented-requirement{control-id, uuid}`; for each param → `set-parameter` (value = tracker value or `"placeholder"`); for each response-point → `statement` → one `by-component` (component-uuid = `this-system`) with `description` = tracker notes (or placeholder) and `implementation-status.state` = mapped tracker status.
5. **Serialize**: OSCAL 1.1.x **JSON** SSP via existing `core/oscal.ts` conventions; assign UUIDs deterministically (stable diffs) or randomly per flag.
6. **Result**: a draft, partially-populated FedRAMP SSP — the input GoComply/fedramp (report 09) renders to Word, and the artifact FedPy currently cannot produce.

## 6. Risks, caveats, licensing

- **License: Apache-2.0** — fully compatible with FedPy's Apache-2.0. We can port code directly with attribution. (We'll reimplement in TS anyway, so this is mostly about reusing the base-SSP shell text.)
- **Language mismatch (Python → TS).** Borrow the *algorithm*, not the source. The logic is ~150 meaningful lines and trivial to re-express in TS; none of the heavy Python deps (`saxonche`, `lxml`, `elementpath`) are needed once we work in OSCAL JSON.
- **Maturity / abandonment risk: high.** Single author, ~one day of commits, no tests, no CI, no releases, last touched Dec 2024, key methods (`OSCAL_validate`, `OSCAL_convert`) are no-op stubs, and `insert_controls` ships with a `limit=5` debug cap and an `ac-1`/`ac-2` skip. This is a *sketch*, not a maintained library — adopt it as a reference recipe, never as a dependency.
- **Format drift (OSCAL versions).** Base SSP declares `oscal-version` **1.1.2** while `metadata/version` mentions `oscal1.1.4`; GSA catalogs track current FedRAMP releases. FedPy should target the current OSCAL 1.1.x and pin/validate the version it emits (this repo doesn't validate at all). FedRAMP's `response-point` extension namespace (`https://fedramp.gov/ns/oscal`) and the `this-system` UUID convention can change with FedRAMP package releases — pin to a known FedRAMP baseline version.
- **XML-only + no validation.** This repo never validates output and can't emit JSON. FedPy must add its own OSCAL schema validation (we already vendor ajv per task log) and should prefer JSON natively.
- **Placeholder-only output.** Out of the box it produces a *non-substantive* SSP (literal "placeholder" text). Useful only as scaffolding; the real value for FedPy comes from wiring in tracker content (opportunity #3).
- **Depends on GSA-hosted catalogs at runtime** (`fetch_file` from raw.githubusercontent). FedPy should cache/vendor the resolved catalogs rather than fetch live, for reproducible, offline-capable runs.

## 7. Verdict

**Low code investment, high conceptual payoff.** Don't depend on or fork this repo — it's an unmaintained one-author sketch with stubbed validation and a debug cap. But it is the clearest existing **recipe** for the single biggest gap in FedPy's OSCAL story: turning a FedRAMP baseline into a skeleton SSP. The algorithm (iterate resolved-catalog controls → `implemented-requirement` + `set-parameter` per param + `statement` per `response-point` + `this-system` `by-component`) is ~150 lines, trivially portable to TS, and lines up perfectly with assets FedPy already owns (committed baseline membership + the tracker's per-control implementation data). The highest-value take: **build `cloud-evidence/core/oscal-ssp.ts` that emits an OSCAL 1.1.x JSON SSP, populating the stubs from tracker records instead of "placeholder."** That single emitter moves FedPy from "evidence collector" to "draft-SSP generator" and feeds directly into the GoComply/fedramp Word renderer from report 09.
