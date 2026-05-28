# Research report: huntridge-labs/argus

> Part of the FedPy integration-research series. Each report front-loads the
> analysis so implementation work can start without re-investigating the source.

- **Upstream:** https://github.com/huntridge-labs/argus
- **Local clone:** `research/clones/argus` (git-ignored)
- **Language / stack:** **Python 3.11+** SDK (`argus-security` on PyPI) — `click` CLI, dataclass models, Docker-backed tool execution, optional extras (`anthropic`/`openai` for AI, `mcp` for the MCP server, `textual` for the TUI, `fastapi`+`jinja2` for the browser viewer). Wraps a fleet of external scanner binaries (Trivy, Grype, Syft, Bandit, Gitleaks, OpenGrep/Semgrep, Checkov, ClamAV, ZAP, etc.). Also ships ~25 GitHub composite actions (the scanner logic lives in the SDK; actions are thin Python wrappers). No TypeScript anywhere.
- **License:** **AGPL-3.0** (`LICENSE.md`, "Copyright (C) 2025 Huntridge Labs, LLC", PyPI classifier "GNU Affero General Public License v3"). ← integration-relevance: **this is the single biggest constraint.** AGPL is copyleft and network-copyleft; we cannot vendor or port AGPL code into FedPy's Apache-2.0 tree without re-licensing FedPy. We can run the published `pip`/`uvx` tool as a separate process and borrow *ideas/data*, but **not borrow code**.
- **Activity / maturity:** Very active. Last commit **2026-05-27** (`feat(scanner-promptfoo): add promptfoo LLM-security scanner #208`). Version **1.2.1** (`version.yaml`), PyPI "Development Status :: 4 - Beta". ~31k LOC of non-test Python in the `argus/` package; ~9 MB repo without `.git`. No git tags in the shallow clone, but releases are automated via `release-it`. Codecov-enforced 80% coverage, dependabot/renovate-driven, conventional commits, strong AICaC (`.ai/`) docs discipline.
- **One-line:** A unified, Python-first DevSecOps **security-scanning aggregator** (SAST + secrets + deps + IaC + container + DAST + malware + LLM-security) that normalizes many tools' output into one finding model and emits SARIF/JSON/Markdown — *and*, as one bundled feature, a **rule+AI FedRAMP "Significant Change Notification" (SCN) classifier** that triages IaC diffs into Routine/Adaptive/Transformative/Impact.

## 1. What it does

Argus is **not** a FedRAMP/OSCAL tool at its core. It is a general-purpose **security-scanning meta-runner** in the same space as a homegrown "run all the scanners and aggregate" pipeline. The headline product (`argus scan`) wraps ~16 underlying tools behind a single CLI and config (`argus.yml`), runs them locally or via Docker, normalizes every tool's output into one `Finding`/`ScanResult`/`ScanSummary` model (`argus/core/models.py`), and emits unified reports (terminal/Rich TUI, browser UI, Markdown, JSON, **SARIF 2.1.0**, JUnit, GitHub/GitLab PR comments). It adds polish around that: severity-threshold failure gating, SBOM ingestion (CycloneDX/SPDX/Syft), Sigstore/cosign image-provenance verification, secret-redaction defense-in-depth on findings, an MCP server so AI assistants can drive scans, and a tamper-evident audit manifest. This whole surface **overlaps with FedPy's `cloud-evidence` collector conceptually but in a different domain** — argus scans *source code, dependencies, containers, and IaC files* (the build/CI plane), whereas FedPy collects *live cloud-account configuration* (the runtime AWS/GCP/K8s control plane) for FedRAMP 20x KSIs. They are adjacent, not competing.

The genuinely FedRAMP-relevant part is one bundled subcommand: **`argus classify`**, a.k.a. the **SCN Detector** (`argus/scn/`). FedRAMP 20x replaces the old "Significant Change Request" paperwork with a **Significant Change Notification** model where a CSP self-classifies a change and notifies (or doesn't) on a timeline based on category. Argus implements exactly that taxonomy — **ROUTINE** (no notice), **ADAPTIVE** (notify ≤10 business days after completion), **TRANSFORMATIVE** (30-day initial + 10-day final notice), **IMPACT** (requires a new assessment; cannot use the SCN process). It diffs two git refs, parses Terraform / Kubernetes / CloudFormation / GitHub-Actions changes out of the diff, and classifies each resource change first by deterministic regex rules and then (optionally) by an AI fallback (Claude Haiku / OpenAI) for ambiguous cases. The output is a PR comment + a machine-readable JSON audit trail + optional GitHub tracking issues, wired as a GitHub Action with a `fail_on_category` gate.

Who it's for: DevSecOps teams who want a turnkey hardening pipeline (its stated vision is "make it as easy as possible … to employ a hardening pipeline"), with a side bet on FedRAMP CSPs who want change-management automation in CI. For FedPy specifically, **the SCN classifier is the only piece that maps onto our compliance domain**; the rest is a well-built but out-of-scope security scanner.

## 2. Architecture & key components

Top-level layout (real paths from the clone):

- `argus/` — the Python SDK (the product). Key subpackages:
  - `argus/core/models.py` — the normalized data model: `Severity` enum (with alias-normalization from any scanner's vocabulary), frozen `Finding` (id/severity/title/description/location/cwe/cve/scanner/metadata, with a `__post_init__` secret-redaction backstop), `ScanResult` (per-scanner, with `PhaseResult` for multi-phase tools and a `partial_failure` property to avoid "silent PASS"), `ScanSummary` (aggregate + `passed` against a severity threshold + `ScanContext` capturing cwd/repo_root/commit_sha).
  - `argus/core/engine.py`, `argus/core/config.py`, `argus/containers.py` — scan orchestration + Docker execution backend.
  - `argus/scanners/*.py` (+ `argus/linters/*.py`) — one module per tool implementing a `Scanner` protocol (`scan()`/`is_available()`/`install_command()`), auto-registered via `SCANNER_REGISTRY` (`argus/scanners/__init__.py`).
  - `argus/reporters/*.py` — `sarif.py` (SARIF 2.1.0, severity→level map), `json_report.py`, `markdown.py`, `junit.py`, `github.py`/`gitlab.py` (PR comments), `terminal.py`.
  - `argus/audit/manifest.py` — **`AuditManifest`**: an "evidence package" JSON (`argus-audit.json`) recording argus version, scan_id (UUID), timing, platform/CI provenance, config SHA-256, tool versions, container image digests, findings summary, and a **per-artifact SHA-256 inventory** of the output directory.
  - `argus/viewers/` — Textual TUI (`terminal/`) and FastAPI localhost UI (`browser/`) for findings triage.
  - `argus/mcp.py` — MCP server exposing `argus_scan`, `argus_classify`, `argus_explain_finding`, etc.
- **`argus/scn/` — the FedRAMP SCN Detector (the relevant module).**
  - `classifier.py` — `ChangeClassifier`: rule-match engine (pattern/resource/attribute/operation criteria) then AI fallback; `classify_all_changes()` rolls up a per-category summary. AI is **only** enable-able via CLI flag, never from a config file (a deliberate guardrail).
  - `diff.py` — `IaCChangeAnalyzer` (runs `git diff`, raises `GitDiffError` rather than silently returning zero changes — a real CI-gate-safety fix) + format-specific parsers for Terraform / K8s / CloudFormation / GitHub Actions that extract `{type, name, operation, attributes_changed, diff}` from raw diff text via regex.
  - `defaults.py` — the **built-in FedRAMP Low profile**: default rules (e.g. tag/description changes → ROUTINE; AMI/instance-type → ADAPTIVE; region/db-engine → TRANSFORMATIVE; encryption removal or `0.0.0.0/0` ingress → IMPACT), notification timelines, and the AI system/user prompt templates (model `claude-3-haiku-20240307`).
  - `report.py` — `SCNReportGenerator`: emits the PR-comment Markdown (summary table with timelines + per-category detail) and `generate_audit_json()` (machine-readable audit trail with `compliance_actions` per category).
  - `schemas/scn-config.schema.json` — JSON Schema for a custom SCN profile (`version`, `rules`, `ai_fallback`, `notifications`, `issue_templates`, `compliance_framework`, `impact_level`).
- `.github/actions/scn-detector/` — the composite action wrapping `argus classify` (inputs: `base_ref`/`head_ref`/`config_file`/`enable_ai_fallback`/`fail_on_category`/`create_issues`/`dry_run`; scripts `create_scn_issue.py`, `generate_scn_report.py`, `validate_scn_config.py`).
- `examples/configs/scn-profile-custom.example.yml`, `examples/workflows/scn-detection-*.yml` — usage templates.

**Data formats consumed/produced:** consumes git diffs of Terraform/K8s/CFN/GHA + scanner-native outputs + SBOMs (CycloneDX/SPDX/Syft); produces SARIF 2.1.0, JSON, JUnit, Markdown, the SCN audit JSON, and the hashed audit manifest. **No OSCAL anywhere** (`grep -ril oscal` returns nothing in Python/Markdown).

## 3. What's genuinely interesting for FedPy

Be honest about proportions: argus is mostly out of scope. Two things are genuinely relevant, one is a strong idea, the rest is "good to know."

1. **The SCN classifier taxonomy + default rule set is directly on FedPy's domain (the standout).** FedPy is *detective/evidence-and-tracking* and explicitly lists change-management as out of its scope; argus's `argus/scn/` is a working, FedRAMP-20x-aligned **change-classification engine**. The four-category model with concrete notification timelines (`scn/defaults.py` `DEFAULT_NOTIFICATIONS`, `scn/report.py` `TIMELINES`) and the starter rule library (encryption-removal→IMPACT, public-ingress→IMPACT, region-change→TRANSFORMATIVE, AMI/instance-type→ADAPTIVE, tags/description→ROUTINE) are reusable *as data and as a reference implementation* even though the code is AGPL. This is a capability FedPy does not have and arguably should: classify IaC PRs against the SCN timeline and surface it in the tracker.

2. **The hashed "evidence package" audit manifest pattern (`argus/audit/manifest.py`).** It records scan_id/timestamps/CI provenance/config-hash/tool-versions/container-image-digests + a **per-artifact SHA-256 inventory** of the output directory. FedPy already does Ed25519 signing + a manifest (task B.1), so this validates our approach — but the *content model* (CI-platform provenance auto-detection, config-file hash, per-tool versions, image digests, exit code, phase timings) is a richer manifest schema worth comparing against ours.

3. **The normalized finding model with "no silent PASS" semantics (`core/models.py`).** The `PhaseResult.status ∈ {ran, skipped, failed}` + `ScanResult.partial_failure` design deliberately separates "ran and found nothing" from "couldn't run." FedPy's collectors face the same hazard (an `AccessDenied` shouldn't read as "control passes"). Our `failed_ksis` work (tasks #137, B.4) is the same instinct; argus's enum-based phase model is a clean reference for hardening it.

4. **AI-fallback discipline as a pattern (not the code).** Argus uses deterministic rules first and only falls to an LLM for ambiguous cases, gates AI behind an explicit CLI flag (config files can't silently enable it — `classifier.py` line ~45), bounds tokens/diff size, and demands strict JSON back. FedPy has an LLM PR generator (task F.1); the same "rules-first, LLM-as-fallback, explicit opt-in, redact inputs" discipline applies if we ever add AI-assisted KSI triage.

5. **Secret-redaction defense-in-depth on the finding object (`core/redact.py` + `Finding.__post_init__`).** Every finding's text fields are scrubbed for vendor-prefixed tokens (GitHub PATs, AWS keys, Slack tokens, JWTs, PEM keys) at construction, *plus* a per-scanner first-pass audit. Relevant to FedPy because our evidence envelopes can capture cloud config that may include ARNs/secrets; this is a good belt-and-suspenders pattern.

What is **not** interesting for FedPy: the scanner fleet itself (different domain — code/deps/containers vs. cloud control plane), the TUI/browser viewers, the composite-action machinery, MCP server. FedPy's `cloud-evidence/core/sbom.ts` (Syft + cosign, task E.2) and K8s collector (E.1) already cover the small overlap.

## 4. Gaps in OUR stack this could fill

| FedPy surface | What we DON'T have today | What argus shows |
|---|---|---|
| Change management (explicitly out-of-scope per GAP-ANALYSIS) | **No SCN classification at all** — we don't triage IaC changes into Routine/Adaptive/Transformative/Impact or compute notification timelines | A complete rule+AI SCN classifier (`argus/scn/`) with a FedRAMP-Low default profile and timeline logic |
| `tracker/` | No "incoming change → SCN category → notification deadline" view; tracker is implementation-status + NIST crosswalk only | SCN audit JSON + per-category `compliance_actions` that a tracker could ingest and surface as deadlines |
| `cloud-evidence/core/findings.ts` + `failed_ksis` (B.4) | Our "couldn't collect ≠ control passes" handling is ad-hoc | Enum-based `PhaseResult.status` + `partial_failure` as a clean model |
| Evidence signing / manifest (B.1) | Manifest exists but a leaner schema | Richer manifest content model (CI provenance, config hash, tool versions, image digests, per-artifact hash inventory) to crib fields from |
| LLM PR generator (F.1) | No "rules-first, LLM-fallback, opt-in-only" guardrail pattern documented | A concrete, security-conscious AI-fallback design |

The single biggest concrete gap argus highlights is **SCN / change-classification** — a FedRAMP 20x capability FedPy deliberately scoped out, but which argus proves is automatable from git diffs.

## 5. Integration opportunities (actionable)

**Hard constraint up front:** argus is **AGPL-3.0 and pure Python**. We cannot copy or port its code into FedPy (Apache-2.0/TS) without contaminating our license. Every row below is therefore **"idea / re-implement clean-room"** or **"run as a separate tool,"** never "vendor/port the source."

| # | Opportunity | FedPy target | Approach | Borrow code or just the idea? | Effort | Priority |
|---|---|---|---|---|---|---|
| 1 | Build a **clean-room SCN classifier** in TS: parse Terraform/K8s/CFN diffs, classify into Routine/Adaptive/Transformative/Impact with our own rule set + timeline logic | new `cloud-evidence/core/scn.ts` (or a `scripts/scn-classify.ts`), surfaced in `tracker/` | Re-implement the *taxonomy + timelines + default-rule semantics* from scratch in TS; do NOT read/copy argus source line-for-line — design from the public FedRAMP SCN spec + our own rules | **idea only** (AGPL forbids porting) | M–L | P1 |
| 2 | Add an **SCN view to the tracker**: ingest an SCN audit JSON, show category + notification deadline per change, link to the PR | `tracker/` (server + React) | Define our own audit-JSON shape (inspired by `scn/report.py` `generate_audit_json`); render deadlines | idea | M | P2 |
| 3 | Adopt **enum-based "couldn't run vs. clean" status** for collectors to harden `failed_ksis` | `cloud-evidence/core/findings.ts`, orchestrator | Re-implement `PhaseResult.status`/`partial_failure` concept in our envelope | idea | S | P1 |
| 4 | Enrich our **evidence manifest** with argus's manifest fields (CI provenance auto-detect, config hash, tool versions, image digests, per-artifact hash inventory) | evidence signing (B.1), `cloud-evidence/core/*` | Compare field-by-field, add what we lack | idea | S | P2 |
| 5 | If we want SCN *without* building it, **run `argus classify` as an external CLI** in our CI and parse its JSON | `.github/workflows`, `scripts/` | `uvx --from argus-security argus classify --format json …`; treat as a separate AGPL tool invoked at arm's length (no linking) | run-as-tool (no code reuse) | S | P2 |
| 6 | Reuse the **rules-first / LLM-fallback / explicit-opt-in / redact-inputs** discipline for any AI feature | LLM PR generator (F.1) | Adopt the pattern in our prompt/guard code | idea | S | P2 |

**Decision guidance:** The high-value item is **#1 — a clean-room TS SCN classifier**, because it fills a named FedRAMP 20x gap FedPy scoped out and nothing else in this research series covers change management. Because of AGPL, treat argus's `scn/` strictly as a *design reference and spec cross-check*, not a code source. If SCN is wanted quickly and license-cleanly, **#5 (invoke the published tool as a separate process)** is a legitimate stopgap — AGPL's obligations attach to *distributing/modifying argus*, not to running the unmodified PyPI package alongside FedPy.

## 6. Risks, caveats, licensing

- **AGPL-3.0 is the dominant risk — no code reuse.** FedPy is Apache-2.0. AGPL is strong copyleft *plus* a network clause; pulling argus code (or a derivative) into FedPy would force FedPy under AGPL. **Do not port, copy, or vendor any `argus/` source.** Permitted: re-implementing the *ideas/taxonomy* clean-room, and invoking the unmodified upstream `argus-security` package as a separate process. Even the "run as a tool" path should keep argus at arm's length (separate venv/`uvx`, no import-linking into our code).
- **Language mismatch.** Pure Python vs. our TypeScript. Even absent the license issue, there is zero code-level reuse; the SCN logic would be a TS rewrite. This is consistent with — but worse than — the Go reports (oscalkit), because there at least CC0 allowed shelling to a binary freely; here even the shell-out carries AGPL framing.
- **Domain mismatch for ~90% of the repo.** The scanner fleet, viewers, MCP server, and composite actions occupy the **code/CI security-scanning** domain, not FedPy's **cloud-config-evidence** domain. We should not try to absorb argus's scanning; FedPy's overlap (SBOM via Syft+cosign E.2, K8s E.1) is already covered.
- **SCN classifier is regex-on-diff-text, not semantic.** `argus/scn/diff.py` extracts resources via regex over raw `git diff` output (no Terraform-plan / HCL AST parsing). It's pragmatic but lossy (e.g., renamed resources, multi-file modules, computed values). Any FedPy re-implementation should consider parsing `terraform plan -json` instead for fidelity.
- **Default rule set is "FedRAMP Low" and minimal.** `DEFAULT_RULES` is a small starter set; real SCN classification needs an org-tuned profile. The value is the *framework + categories*, not the specific rules.
- **AI fallback sends diffs to a third-party LLM.** Off by default and flag-gated, but a FedRAMP CSP must treat that as a data-egress decision. Our clean-room version should default rules-only.
- **No OSCAL, no NIST control mapping.** Argus does not touch OSCAL or 800-53; it's orthogonal to FedPy's OSCAL emitter, benchmark, and crosswalk work. Nothing to borrow there.
- **Maintenance/health — strong.** Active daily commits, v1.2.1, 80% enforced coverage, automated releases, excellent docs. Low abandonment risk; the constraint is legal, not quality.

## 7. Verdict

**Low overall relevance, with one medium-value idea — and a hard "look, don't copy" rule because of AGPL.** ~90% of argus (the multi-tool security scanner, viewers, MCP server, composite actions) is in a different domain from FedPy and already overlapped by our existing SBOM/K8s work. The one thing worth taking is the **FedRAMP 20x SCN change-classification capability** in `argus/scn/` — a Routine/Adaptive/Transformative/Impact classifier with notification timelines, driven off IaC git diffs. That fills a real, named gap FedPy scoped out (change management) and is not covered by any other repo in this series. **But because argus is AGPL-3.0 and pure Python, we must treat it purely as a design/spec reference and re-implement clean-room in TypeScript (opportunity #1), or invoke the unmodified PyPI tool at arm's length (#5) — never port the code.** Net: spend a little here to lift the *SCN concept and timeline model* into a future FedPy change-classification feature; ignore the rest of the repo.
