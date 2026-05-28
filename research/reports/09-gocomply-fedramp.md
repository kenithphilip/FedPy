# Research report: GoComply/fedramp

> Part of the FedPy integration-research series. Each report front-loads the
> analysis so implementation work can start without re-investigating the source.

- **Upstream:** https://github.com/GoComply/fedramp
- **Local clone:** `research/clones/gocomply-fedramp` (git-ignored)
- **Language / stack:** Go (`go 1.13` in `go.mod`). ~25 `.go` source files outside `vendor/` (~900 LOC of real logic). CLI built on `urfave/cli`. Hard dependency on **CGO + libxml2** via `jbowtie/gokogiri` for DOCX XML manipulation. Assets embedded with `markbates/pkger` (`bundled/pkged.go` is a 6 MB generated file). Ships a `quay.io/gocomply/gocomply` container and goreleaser binaries (darwin/linux, amd64/arm64).
- **License:** **CC0 1.0 Universal** (public-domain dedication, `LICENSE.md`) for the project's own source. ← integration-relevance: maximally permissive — borrow/port/vendor freely, no attribution required, Apache-2.0-compatible. **Caveat:** `LICENSE.md` opens with *"includes work in both the public domain and dependencies that are not"* — the bundled FedRAMP `.docx`/catalog assets and the vendored Go deps (gokogiri = MIT, masonry, oscalkit = CC0) carry their own terms. The *code* is freely usable; the *bundled FedRAMP templates* are GSA-published government assets (also effectively public domain, but they are the real IP here).
- **Activity / maturity:** **Effectively dormant / pre-1.0.** Cloned HEAD `22fdd08`, a dependabot merge dated **2024-04-30** (most 2023–24 commits are dependabot bumps, not feature work). No git tags / releases in the clone. The README itself admits the core feature is incomplete: *"This latest step is not fully complete… some of the fields in the DOCX being blank. This is work in progress."* Targets **OSCAL `1.0.0-milestone3`** (a 2019/2020 pre-release), NOT OSCAL 1.0.x or 1.1.x. **Zero tests** in the repo (no `*_test.go`, no `testdata/`).
- **One-line:** A Go CLI that fills the *official* FedRAMP SSP Word templates in-place from an OSCAL SSP (and, separately, converts an OpenControl/masonry repo into an OSCAL SSP) — the most direct existing answer to "OSCAL → FedRAMP SSP `.docx`", but built on a frozen pre-1.0 OSCAL model and never finished.

## 1. What it does

`GoComply/fedramp` is a two-command "OSCAL-FedRAMP Workbench" (`cli/cmd/cmd.go`). Command **`convert <ssp.oscal.xml> <output.docx>`** takes a FedRAMP/OSCAL-formatted System Security Plan and emits a filled-in FedRAMP SSP Word document. Command **`opencontrol <masonry-repo> <output-dir>`** takes an [OpenControl](https://open-control.org/) compliance-masonry repository (control narratives in YAML) and produces FedRAMP-formatted OSCAL SSP files (XML/JSON/YAML). Chained, the two give an end-to-end OpenControl-narratives → OSCAL → Word pipeline; that is the project's whole thesis.

The valuable half for FedPy is **`convert`**. It is *not* an OOXML generator — it does **template manipulation**. The repo bundles the three real GSA-published FedRAMP SSP templates (`FedRAMP-SSP-{Low,Moderate,High}-Baseline-Template.docx`, obtained from fedramp.gov Feb 2020 per `bundled/templates/README.md`). At runtime it copies the matching template to `/tmp`, unzips its `word/document.xml`, parses it with libxml2/XPath, locates the per-control tables, writes responsible-role text, parameter values, implementation-status checkboxes, and control-implementation narrative paragraphs *into the existing template structure*, then re-zips it. The output is a genuine FedRAMP-formatted Word doc with the boilerplate, styling, headers, and section numbering already correct — because it *is* the official template, edited.

Who it's for: CSPs/3PAOs who already have (or can produce) an OSCAL SSP and need the human-readable FedRAMP Word deliverable that the PMO and AO actually read. It is the canonical open-source worked example of the render-from-OSCAL approach.

The `opencontrol` half matters less to FedPy: it presumes you author control narratives in the OpenControl ecosystem (masonry YAML), which FedPy does not use. But its `oc2oscal/convert.go` is a clean, readable reference for *how to assemble a valid OSCAL SSP object graph in code* — exactly the model FedPy would need to emit to feed `convert`.

## 2. Architecture & key components

Top-level layout (everything outside `vendor/`):

```
cli/gocomply_fedramp/main.go      # entrypoint -> cmd.Execute()
cli/cmd/cmd.go                    # urfave/cli app; defines `convert`
cli/cmd/opencontrol.go            # defines `opencontrol` (+ -f xml|json|yaml)
bundled/templates.go              # pkger accessors: TemplateDOCX/TemplateOSCAL/CatalogOSCAL by level
bundled/templates/*.docx          # the 3 real FedRAMP SSP Word templates (Low/Mod/High)
bundled/templates/FedRAMP-SSP-OSCAL-Template.xml   # blank GSA OSCAL SSP skeleton
bundled/catalogs/FedRAMP_{LOW,MODERATE,HIGH}-baseline-resolved-profile_catalog.xml  # resolved baselines
bundled/pkged.go                  # 6 MB generated asset blob (pkger)
pkg/templater/open.go             # Convert()/ConvertFile(): OSCAL SSP -> docx orchestration (fillInSSP)
pkg/templater/template/template.go                 # unzip docx, libxml2 parse, register w/w14 namespaces, save
pkg/templater/template/control_summary_information.go      # find/fill "Control Summary" tables
pkg/templater/template/control_implementation_description.go  # find/fill "What is the solution…" tables
pkg/templater/template/checkbox/checkbox.go        # read/set Word checkbox state (impl status)
pkg/templater/template/helpers.go                  # control-id regex
pkg/docx_helper/{table,paragraph,text}.go          # low-level OOXML node edits (clone paragraphs, replace text)
pkg/fedramp/ssp.go                # OSCAL SSP wrapper: reads implemented-requirements, statuses, narratives
pkg/fedramp/profiles.go           # Baseline: loads bundled resolved-profile catalog, param lookups
pkg/fedramp/impl_status.go        # OSCAL status string <-> enum <-> docx label mapping
pkg/fedramp/common/constants.go   # BaselineLevel + the 3 NIST profile URLs that key baseline selection
pkg/fedramp/gsa_template.go       # load the blank OSCAL SSP skeleton (used by oc2oscal)
pkg/oc2oscal/convert.go           # OpenControl -> OSCAL SSP assembly (the writer side)
pkg/oc2oscal/opencontrol.go       # Component wrapper over masonry data
pkg/oc2oscal/masonry/acquire.go   # clone & load a masonry repo via compliance-masonry libs
pkg/utils/oscal.go                # control-key -> OSCAL id normalization (AC-2 (1) -> ac-2.1)
```

**The render pipeline (`convert`), in detail:**

1. `templater.ConvertFile` opens the OSCAL source via `oscalkit`'s `oscal_source.Open`, then `fedramp.NewSSP` (`pkg/fedramp/ssp.go`) wraps it. `NewSSP` **rejects anything whose `DocumentType()` is not `SSPDocument`** and errors if `control-implementation` is missing. It indexes `control-implementation/implemented-requirements` by `control-id` into a cache.
2. **Baseline selection is keyed entirely off `import-profile/@href`.** `SSP.Level()` matches that href against the three hard-coded NIST profile URLs in `common/constants.go` (e.g. `…/FedRAMP_MODERATE-baseline_profile.xml`). If the href is not an exact string match, it errors `"Unrecognized FedRAMP profile URL"`. The matched level picks which bundled `.docx` template to fill.
3. `template.NewTemplate(level)` copies the bundled template to a temp file, `docx.ReadFile` (from `opencontrol/doc-template`) extracts `word/document.xml`, and `gokogiri.ParseXml` parses it with the `w` and `w14` WordprocessingML namespaces registered (`template.go`).
4. `fillInSSP` (`pkg/templater/open.go`) is the conductor:
   - **Control Summary Information tables** — found by XPath `//w:tbl[contains(., 'Control Summary') or contains(., 'Control Enhancement Summary')]` (`control_summary_information.go`). For each: parse control id from the header row (with a hard-coded workaround for a `CM2 (7)` typo in the High template), then set **Responsible Role** (`plan.ResponsibleRoleForControl` → first `responsible-roles/role-id`), **parameter rows** (`plan.ParamValue` reads the *resolved-profile catalog*, not the SSP, returning the constraint value or an `[Assignment: …]` label), and **Implementation Status** by ticking the matching Word checkbox.
   - **Control Implementation Description tables** — found by XPath `//w:tbl[contains(., ' What is the solution and how is it implemented')]`. For each: for "Part a/b/c…" rows, write the narrative from `plan.StatementTextForPart`; for undivided controls, write `plan.StatementTextFor`. Narrative text comes from `implemented-requirements/statements/by-components/remarks` (joined as plain strings).
   - `// TODO: 5.4 Control Origination` — control-origination checkboxes are **explicitly unimplemented**. This (plus system-characteristics, roles, inventory, attachments, etc.) is why the README says fields come out blank.
5. **Checkbox handling** (`checkbox/checkbox.go`): XPath `(.//w:checkBox//w:default)|(.//w14:checkbox//w14:checked)` finds both legacy form-field and modern content-control checkboxes; `SetChecked()` flips the attribute to `1` and swaps the glyph `☐`→`☒`. The impl-status string→enum→docx-label mapping lives in `impl_status.go`.
6. **Text injection** (`docx_helper/paragraph.go`): for multi-paragraph narratives it *clones* the template paragraph (preserving run/formatting), splits the new text on `\n\n`, sets each clone's text, and removes the original — so injected text inherits the template's styling. `libxml2_copy_constant = 2` is the deep-copy flag.
7. `template.Save` serializes the mutated XML back into the docx zip.

**The OSCAL-writer side (`opencontrol`, `pkg/oc2oscal/convert.go`):** clones a masonry repo to `/tmp` (`masonry/acquire.go`, pinned to a `fedramp-high.yaml` certification), then for each component × each baseline, starts from the blank GSA OSCAL skeleton (`gsa_template.go`), sets `import-profile.href` to the baseline URL, walks the resolved-profile catalog's control groups, and for each control with a masonry "satisfies" entry builds an `ImplementedRequirement{ControlId, Annotations:[implementation-status], Statements:[…remarks…]}`. It refreshes UUIDs (`oscalkit/pkg/uuid`) and `Validate()`s each file. **Note the data model:** implementation status is stored as a legacy OSCAL **`<annotation name="implementation-status" ns="https://fedramp.gov/ns/oscal">`** — a milestone3 construct that OSCAL 1.0+ replaced with `<prop>`.

**Data formats:** consumes OSCAL SSP (XML/JSON/YAML, milestone3 model) and OpenControl masonry repos; produces FedRAMP SSP `.docx` and OSCAL SSP files. Bundles GSA resolved-profile catalogs and the blank GSA OSCAL SSP template.

**Dependencies that matter:** `gocomply/oscalkit v0.3.4` (the sibling from report 07 — Go OSCAL SDK, supplies the SSP/catalog Go types and (de)serialization), `jbowtie/gokogiri` (CGO libxml2 binding — the docx XML engine), `opencontrol/compliance-masonry` + `opencontrol/doc-template` (masonry ingest + docx zip handling), `markbates/pkger` (asset embedding, itself deprecated in favor of Go's `embed`), `urfave/cli`, `sirupsen/logrus`.

## 3. What's genuinely interesting for FedPy

This repo is the **single most direct existing solution to FedPy's biggest stated gap: there is no SSP authoring and no Word rendering in our stack.** The signal:

1. **Proof that "fill the official template in place" beats "generate OOXML from scratch."** The entire `pkg/templater` approach — copy the real GSA `.docx`, XPath-locate tables, edit cells/checkboxes, re-zip — sidesteps the impossible task of reproducing FedRAMP's exact Word styling/numbering/boilerplate. The output is correct *by construction* because it is the official template. This is the architectural decision FedPy should copy regardless of language.

2. **The bundled official assets are the real value.** `bundled/templates/*.docx` (the 3 GSA SSP templates), `bundled/templates/FedRAMP-SSP-OSCAL-Template.xml` (the blank OSCAL SSP skeleton), and the three `bundled/catalogs/*resolved-profile_catalog.xml` are vendored, version-pinned, and accompanied by a `Makefile` (`ci-update-fedramp-templates`/`-catalogs`) documenting the exact upstream URLs. FedPy can reuse these files directly (they're government/public-domain assets).

3. **A complete, readable map of the FedRAMP SSP docx structure** — which tables exist, how to recognize them ("Control Summary" / "What is the solution and how is it implemented"), how control IDs appear in headers, how Part rows are laid out, how the impl-status checkboxes are encoded in both legacy and modern Word forms (`checkbox.go`). This is the same hard-won OOXML knowledge report 01 (python-ssp) encodes for *reading*; here it's proven for *writing*.

4. **A reference OSCAL-SSP object graph (`oc2oscal/convert.go`)** showing the minimum field set a tool must populate for the renderer to work: `import-profile.href`, `system-characteristics` (FIPS-199 levels, system ids), `system-implementation` (users, components), and `control-implementation/implemented-requirements` with statements/by-components/remarks + status annotation. This is effectively a spec for the OSCAL SSP **FedPy does not currently emit.**

5. **Container-first delivery.** `quay.io/gocomply/gocomply` + the `podman run … convert` recipe in the README is exactly the shell-out integration surface FedPy could use.

## 4. Gaps in OUR stack this could fill

- **The headline gap: OSCAL → FedRAMP SSP Word doc.** `cloud-evidence/core/oscal.ts` today emits **OSCAL 1.1 Assessment Results** only — there is no SSP model and no Word rendering anywhere in FedPy. `GoComply/fedramp convert` is precisely that missing renderer. **But it consumes an OSCAL *SSP* (system-security-plan document), which FedPy does not produce.** Assessment Results and an SSP are different OSCAL document types with disjoint schemas: assessment-results is observations/findings/risks about a system at a point in time; an SSP is the system description + control-implementation narratives. `NewSSP` will hard-reject our assessment-results file (`DocumentType() != SSPDocument`). So the gap this fills is real, but only if FedPy first grows an **OSCAL SSP emitter** — a new artifact distinct from our current emitter.

- **The control-narrative source we *do* have.** FedPy's `tracker/` already stores per-requirement implementation status / owner / notes / evidence — i.e. the control-narrative-adjacent data an SSP needs. The tracker DB is the natural source for an OSCAL-SSP emitter: tracker status → `implementation-status`, tracker notes → `statements/by-components/remarks`, tracker owner → `responsible-roles`. That maps cleanly onto the exact fields `pkg/fedramp/ssp.go` reads.

- **Bundled FedRAMP assets we don't have.** FedPy has no copy of the GSA SSP templates or resolved-profile catalogs. We can vendor `bundled/templates/*` and `bundled/catalogs/*` and the `Makefile` refresh recipe directly.

- **Caveat — NIST 800-53 SSP vs. FedRAMP 20x.** These templates are the **Rev 4/Rev 5 control-by-control SSP** (AC-1, AC-2…), the legacy authorization deliverable. FedPy's whole orientation is FedRAMP **20x / KSIs**. The 20x program is explicitly moving away from the giant Word SSP toward machine-readable KSI evidence packages. So this renderer fills a gap that is real for *Rev 5 / traditional* authorizations but may be **strategically backward-looking** for a 20x-first toolkit. (See report 07/oscalkit and the 20x KSI work for the forward path.)

## 5. Integration opportunities (actionable)

| # | Opportunity | FedPy target | Approach | Borrow code or just the idea? | Effort | Priority |
|---|-------------|--------------|----------|-------------------------------|--------|----------|
| 1 | Vendor the official GSA SSP `.docx` templates + resolved-profile catalogs + the blank OSCAL SSP skeleton, with the `Makefile` refresh recipe | `cloud-evidence/templates/` (new) or `docs/` | Copy `bundled/templates/*` + `bundled/catalogs/*` + port the `ci-update-*` make targets to an npm script | vendor (CC0 / gov assets) | S | P1 |
| 2 | Adopt the "fill the official template in place" rendering architecture (XPath-locate tables, edit cells/checkboxes, re-zip) instead of generating OOXML | new `cloud-evidence/core/ssp-render.ts` | Port the pattern to TS using `docx`/`pizzip`+`xmldom` or `docxtemplater`; reuse the XPath table-finding strings & checkbox-encoding knowledge from `template/*.go` + `checkbox.go` | idea + port logic | L | P1 |
| 3 | Build an OSCAL **SSP** emitter (distinct from our assessment-results emitter) sourced from the tracker DB | `cloud-evidence/core/oscal-ssp.ts` (new) + read `tracker/` data | Use `oc2oscal/convert.go` as the field-map spec: import-profile href, system-characteristics, implemented-requirements w/ statements/remarks/status | idea (spec), port to TS | L | P1 |
| 4 | Shell-out MVP: pipe a generated OSCAL SSP through the `gocomply` container to get a Word doc, before building our own renderer | `cloud-evidence/scripts/render-ssp.ts` | `podman/docker run quay.io/gocomply/gocomply … convert ssp.xml out.docx`; treat the binary as a black box | use as-is (binary) | S–M | P2 |
| 5 | Reuse the control-id normalization + control-narrative-field mapping (status enum, part lookup) | `cloud-evidence/core/*` and `tracker/` export | Port `utils/oscal.go` (`AC-2 (1)`→`ac-2.1`) and `impl_status.go` enum maps to TS | port (CC0) | S | P2 |
| 6 | Learn the exact OSCAL-SSP minimum-viable field set so our emitter validates | docs / emitter design | Use `convert.go` + the bundled blank OSCAL template as the worked example | idea | S | P2 |

## 6. Risks, caveats, licensing

- **License: ideal.** Project source is **CC0** (public domain) — strictly more permissive than our Apache-2.0; we can port or vendor any of it with no attribution or copyleft. The bundled FedRAMP templates/catalogs are GSA-published government assets, equally safe to redistribute. No license friction whatsoever.
- **OSCAL version mismatch is the dominant technical risk.** This tool targets **OSCAL `1.0.0-milestone3`** (a 2019/2020 pre-release; the bundled OSCAL template literally says `<oscal-version>1.0-Milestone3</oscal-version>`). FedPy emits **OSCAL 1.1**. The milestone3 SSP model is materially different from 1.0.x/1.1.x — most visibly it uses `<annotation name="implementation-status" ns="…">` where OSCAL 1.0+ uses `<prop>`. So FedPy-emitted 1.1 OSCAL will **not** be consumed by this tool unmodified, and the tool's output OSCAL is not 1.1-valid. Shelling out to it requires emitting *milestone3-flavored* OSCAL specifically — an awkward, dead-end format — or forking/upgrading the tool's oscalkit dependency.
- **Wrong document type.** It needs an OSCAL **SSP**; FedPy emits **assessment-results**. There is no path from our current output to this tool without building a new SSP emitter first (opportunity #3). This is the single biggest gating fact for shell-out viability.
- **Wrong control framework for our north star.** The bundled templates are NIST 800-53 Rev 4/5 SSPs, not FedRAMP 20x / KSI artifacts. Valuable for traditional authorizations; less aligned with a 20x-first toolkit.
- **Incomplete & unmaintained.** The README admits `convert` leaves fields blank; control-origination (5.4) is an explicit TODO; system-characteristics/roles/inventory are minimally populated. **Zero tests** in the repo. Last substantive (non-dependabot) work predates 2023; no releases tagged. Treat it as a reference implementation, not a dependable upstream.
- **Build/runtime friction for shell-out.** The renderer depends on **gokogiri → CGO → libxml2**. The goreleaser config sets `CGO_ENABLED=0`, which is in tension with gokogiri's CGO requirement; in practice the supported distribution is the **container** (`quay.io/gocomply/gocomply`), so a FedPy shell-out should target the container, not a `go install`'d binary. That adds a Docker/Podman runtime dependency to any FedPy SSP-generation path.
- **Language mismatch.** It's Go; FedPy is TS. Given the CC0 license, **porting the *approach and knowledge*** (table XPaths, checkbox encoding, field map) into TS is cleaner long-term than a permanent Go-binary/container shell-out, especially because we'd want to point it at the *current* FedRAMP templates and a *current* OSCAL version anyway.

## 7. Verdict

**Medium-high value, but as a blueprint rather than a dependency.** This is the clearest existing proof that FedPy's biggest gap — turning structured compliance data into the FedRAMP SSP Word deliverable — is best solved by *filling the official GSA template in place*, not by generating OOXML. We should (1) vendor the bundled GSA templates/catalogs (P1, trivial, CC0/gov), and (2) port the rendering *pattern* — XPath table-finding, checkbox encoding, paragraph-clone text injection — into a TS renderer driven by our own data.

Direct shell-out is **not viable today** without two prerequisites: an OSCAL **SSP** emitter (we only emit assessment-results) *and* emitting it in the stale **milestone3** flavor this tool expects — a dead-end format. A throwaway container shell-out is fine only as a one-off demo (opportunity #4).

**This vs. report 01 (python-ssp): they are complementary, and FedPy should take from both, but lead with the GoComply *approach*.** python-ssp is MIT, ~250 LOC, and *reads* the docx (control = adjacent CIS+impl table pair, with the canonical control-ID regex and checkbox-reading code). GoComply *writes* the docx from a structured (OSCAL) model and proves the fill-in-template architecture end-to-end. The single highest-value takeaway is the **render-from-structured-data-into-the-official-template** design — GoComply demonstrates the write path and ships the templates; python-ssp's table-pairing/checkbox-parsing knowledge fills in the OOXML details GoComply leaves implicit. Neither is a turnkey dependency; the win is a FedPy-native TS renderer informed by both, fed by a new tracker-DB-sourced OSCAL SSP emitter.
