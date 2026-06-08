# cloud-evidence — Real-Evidence-Only (REO) standard

> This file is loaded by every Claude session that touches `cloud-evidence/`.
> It is **enforceable**, not aspirational. Three CI guardrails (see below)
> fail the build on any violation.

---

## SCOPE GUARD — read FIRST before proposing any new loop or slice

FedPy is the open-source go-to tooling for SaaS providers to **get to
FedRAMP 20x and FedRAMP Rev5 authorization and operate compliantly
thereafter**. That's the whole mission. Three boundaries are doing the
work:

- **Regime: FedRAMP 20x + Rev5** (the 60 KSIs / 223 requirements;
  NIST 800-53 Rev 5 baselines at Low / Moderate / High; the FRMR
  catalog; the submission-package artifacts; ConMon).
- **Surface: AWS / GCP / Azure / Kubernetes config evidence**
  (read-only collectors; Ed25519-signed; OSCAL-emitted).
- **Audience: SaaS CSPs targeting federal customers** + their 3PAOs +
  the FedRAMP PMO + sponsoring Authorizing Officials.

### What stays in core (`docs/loops/`, `docs/slices/`)

Loops that directly produce / consume / enable FedRAMP-authorization or
operating-in-the-federal-market evidence:

| In core | Reason |
|---|---|
| LOOP-A | OSCAL submission package (SSP, AP, AR, POA&M, IIW, RoE) — the literal FedRAMP submission |
| LOOP-B–K (60 KSI collectors + risk + tracker + signing + dashboards + integrations) | The mission-critical FedRAMP 20x KSI evidence pipeline |
| LOOP-L (CRM) | Customer Responsibility Matrix — FedRAMP-required artifact |
| LOOP-M (federal Privacy: SORN + PIA + E-Gov §208) | Federal Privacy Act + agency PIA — required for FedRAMP packages handling federal data |
| LOOP-N (Threat Modeling) | NIST 800-53 SA control family + FedRAMP 20x KSI baseline |
| LOOP-O (AI/ML Governance) | OMB M-24-10 + EO 14110 — federal-AI-relevant for CSPs using AI |
| LOOP-P (Insider Threat) | NIST 800-53 PS + AC control families — required for FedRAMP Moderate/High |
| LOOP-Q (Marketplace) | FedRAMP Marketplace post-ATO publication |
| LOOP-R (PQC) | NSM-10 + OMB M-23-02 — federal cryptographic migration mandate |
| LOOP-S (DFARS 252.204-7012) | DoD-prime conditional; in-scope when applicable |
| LOOP-T (NIST SSDF + CISA Common Form) | OMB M-22-18 procurement gate — hard prereq for federal software awards |
| LOOP-W (Section 889 Prohibited Vendors) | FAR 52.204-25 — universal federal contracting clause |
| LOOP-X (Zero Trust) | OMB M-22-09 — agency tailoring will demand ZT alignment for FedRAMP-authorized services |
| G.G2 CIRCIA + SEC 8-K extensions | Federal cyber-incident-reporting obligations for FedRAMP-serving CSPs |

### What is NOT in core (lives under `docs/roadmap/`)

Loops that are parallel compliance regimes — a FedRAMP CSP may also
face them, but they are NOT part of FedRAMP authorization. They are
preserved as research / roadmap reference, not as implementation work.

| Out of core | Why | Roadmap location |
|---|---|---|
| LOOP-U Privacy frameworks | State PII (CCPA/CPRA/NY SHIELD/50-state matrix) + EU GDPR + UK GDPR + FERPA + COPPA + GLBA Safeguards — parallel regimes to FedRAMP | `docs/roadmap/loops/LOOP-U-{SPEC,RISKS}.md`, `docs/roadmap/slices/U/` |
| LOOP-V Healthcare | HIPAA Security Rule + Breach Notification + BAA + NIST 800-66 R2 + HITRUST — separate federal regime under HHS OCR | `docs/roadmap/loops/LOOP-V-{SPEC,RISKS}.md`, `docs/roadmap/slices/V/` |
| LOOP-Y Sector overlays | CJIS Security Policy v5.9.5 + IRS Publication 1075 — sector-specific, only relevant for law-enforcement or IRS-authorized customers | `docs/roadmap/loops/LOOP-Y-{SPEC,RISKS}.md`, `docs/roadmap/slices/Y/` |
| LOOP-Z International | ISO/IEC 27001:2022 + 27017 + 27018 + 27701 + ENISA EUCS — parallel certification audit chains | `docs/roadmap/loops/LOOP-Z-{SPEC,RISKS}.md`, `docs/roadmap/slices/Z/` |
| FIFTH-PASS-AUDIT candidates | PCI-DSS, CMMC, FedRAMP Tailored LI-SaaS, TIC 3.0, SOC 2, ISMAP/IRAP/TISAX, StateRAMP, NSM-22, AI EOs, Section 508, FIPS 140-3, CISA CPGs, etc. — out-of-FedRAMP-scope or partially overlapping with existing core loops | `docs/roadmap/FIFTH-PASS-AUDIT.md` |

### Conditional applicability matrix (per-loop trigger; user-confirmed in scope-audit on 2026-06-08)

Several core loops only fire when a specific operator-supplied condition is true.
This table is the **resolved** scope status — the user explicitly confirmed
on 2026-06-08 that all of the following stay in core (rather than being
moved to `docs/roadmap/`) because each one is a plausibly-applicable
federal-adjacent or conditional obligation that a FedRAMP CSP may face.
DO NOT re-litigate these decisions without a fresh user directive.

| Loop / extension | Trigger condition (when this loop fires) | Why it stays in core |
|---|---|---|
| **LOOP-M** Privacy Package (SORN + PIA + DPIA + PT-family) | CSP handles federal PII (SORN/PIA: always) or EU/UK PII (DPIA: conditional) | SORN + PIA are federal Privacy Act + E-Gov §208 — required for federal IT systems. DPIA piece overlaps with roadmap LOOP-U but is documented here for in-loop completeness. |
| **LOOP-O** AI/ML Governance | CSP uses AI/ML in its authorized service (operator declares via `org-profile.yaml`: `uses_ai_ml: true`) | OMB M-24-10 + EO 14110 + NIST AI RMF 1.0 govern federal AI use; agency tailoring will demand AI-RMF alignment from AI-capable FedRAMP CSPs. Conditional but applicable when the CSP has AI components. |
| **LOOP-R** PQC Migration | Always-on for federal-data-handling CSPs (which is most FedRAMP CSPs) | NSM-10 + OMB M-23-02 federal cryptographic mandate. The migration plan is a federally-required artifact for federal-data systems. |
| **LOOP-S** DFARS 252.204-7012 Cloud Equivalency | CSP has DoD-prime customers running CDI workloads (operator declares: `serves_dod_cdi: true`) | DoD market segment (~20-30% of federal CSPs). FedRAMP Moderate is the literal baseline for DFARS 7012 cloud-equivalency — the loop bridges FedRAMP-Moderate authorization into the DoD-CDI market. Conditional on operator's customer base. |
| **LOOP-T** NIST SSDF + CISA Common Form | CSP delivers software to any federal agency (essentially universal for federal-selling SaaS) | OMB M-22-18 + M-23-16 hard procurement gate. Required for every federal software award since Q3 2024. Near-universal for any FedRAMP CSP. |
| **LOOP-W** Section 889 Prohibited Vendors | Universal — every federal contract since 2020-08-13 | FAR 52.204-25 applies to every federal acquisition. Universal. |
| **LOOP-X** Zero Trust Architecture | CSP serves federal customers subject to OMB M-22-09 (essentially universal for federal-customer CSPs) | OMB M-22-09 had a FY 2024 federal-agency deadline; agency tailoring will pull most FedRAMP-authorized services into ZT alignment. Conditional but pervasive. |
| **G.G2-CIRCIA** | CSP is a Covered Entity under CIRCIA Final Rule (critical-infrastructure-related workloads) | 6 USC §681b + CIRCIA Final Rule (effective May 2026). 72-hour incident reporting to CISA. Many FedRAMP CSPs qualify as Covered Entities. |
| **M.M4-CIRCIA** | Same trigger as G.G2-CIRCIA | Privacy-Act + CIRCIA harmonization on incidents involving Privacy Act records. |
| **G.G2-SEC-8K** | CSP is publicly traded, a wholly-owned subsidiary of a publicly-traded parent, or pre-IPO with cyber-disclosure obligations | SEC Final Rule 33-11216 (Jul 26, 2023) imposes 4-business-day disclosure on material cybersecurity incidents for SEC registrants. Operator-conditional on corporate status. |

When a loop in this table is unconditionally in scope (LOOP-R, LOOP-T,
LOOP-W) it runs by default. When it is conditional (LOOP-M-DPIA, LOOP-O,
LOOP-S, LOOP-X, CIRCIA, SEC-8K) it requires an explicit operator opt-in
via `org-profile.yaml`. Each loop's SPEC documents the exact trigger
flag + env var in its frontmatter.

The **default state** of every conditional loop is **off** — an operator
who does not need it should not encounter spurious requirements or
findings. The conditional flag in the YAML frontmatter (`applicable_conditional: true`)
and the trigger guard in the orchestrator are what enforce this.

### Rules of the scope fence

1. **Do NOT propose new loops** unless the new loop is direct
   FedRAMP 20x or Rev5 evidence. New federal-adjacent obligations
   should extend an existing core loop, not become a new top-level loop.
2. **Do NOT cite roadmap loops as dependencies** in any core slice's
   `depends_on:` list. A core slice depends only on other core slices.
3. **Do NOT run audits** with the goal of "finding things missing"
   broader than FedRAMP. The audit-driven expansion reflex is what
   produced the roadmap folder; the user has explicitly scope-fenced
   FedPy.
4. **Do NOT spin LOOP-AA, BB, CC, …** for items in the FIFTH-PASS-AUDIT.
   Those candidates are roadmap-only.
5. **DO** add new slices to existing core loops when a real FedRAMP
   need surfaces — e.g., a new RFC-0014+ requirement extends LOOP-A,
   a new KSI extends LOOP-B–K, a new Marketplace requirement extends
   LOOP-Q.
6. **DO** read `docs/roadmap/README.md` before referencing anything
   in that folder. The README documents the scope-fence rationale and
   the policy on which the rules above are based.

Source-of-truth ordering for "is this in scope":
**This Scope Guard block → STATUS.md "Core" section → docs/roadmap/README.md.**

---

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

1. **This file** — REO rules + Real Slice Contract.
2. **`docs/STATUS.md`** — current master status tracker for every slice. ALWAYS read this first to see what's done, in-progress, and pending. The next slice to work on is in the "Overall → Next priority" line.
3. **`docs/SLICE-COMPLETION-PROCEDURE.md`** — MANDATORY 7-step procedure when shipping any slice.
4. **`docs/EXECUTION-PLAN.md`** — high-level plan with all 55 slices.
5. **`docs/loops/LOOP-X-SPEC.md`** — full per-slice implementation specs for the loop you're working on. Each `LOOP-X-SPEC.md` cross-references its per-slice docs under `docs/slices/X/`:
   - `docs/loops/LOOP-B-SPEC.md` — Risk + Remediation Engine (5 slices)
   - `docs/loops/LOOP-C-SPEC.md` — Document Template Pack (9 slices)
   - `docs/loops/LOOP-D-SPEC.md` — Diagram Auto-Generation (3 slices)
   - `docs/loops/LOOP-E-SPEC.md` — Continuous Monitoring Agent (7 slices)
   - `docs/loops/LOOP-F-SPEC.md` — 3PAO Assessor Experience (7 slices)
   - `docs/loops/LOOP-G-SPEC.md` — AFR Family (6 slices)
   - `docs/loops/LOOP-H-SPEC.md` — Long-Term Storage + Multi-CSO (3 slices)
   - `docs/loops/LOOP-I-SPEC.md` — Stakeholder Dashboards (4 slices)
   - `docs/loops/LOOP-J-SPEC.md` — Supply Chain + Privileges (3 slices)
   - `docs/loops/LOOP-K-SPEC.md` — Test Artifact Ingestion (2 slices)
   - `docs/loops/LOOP-L-SPEC.md` — Customer Responsibility Matrix + Inheritance (4 slices)
   - `docs/loops/LOOP-M-SPEC.md` — Privacy Package Extension (SORN, DPIA) (4 slices)
   - `docs/loops/LOOP-N-SPEC.md` — Threat Modeling + Adversarial Validation (4 slices)
   - `docs/loops/LOOP-O-SPEC.md` — AI/ML Governance per NIST AI RMF + OMB M-24-10 (5 slices)
   - `docs/loops/LOOP-P-SPEC.md` — Insider Threat + PS-family Workforce Security (5 slices)
   - `docs/loops/LOOP-Q-SPEC.md` — Marketplace + Post-ATO Publication (3 slices)
   - `docs/loops/LOOP-R-SPEC.md` — Post-Quantum Cryptography Migration (3 slices)
   - `docs/loops/LOOP-S-SPEC.md` — DFARS 252.204-7012 Cloud Equivalency (3 conditional slices)
   - `docs/loops/LOOP-T-SPEC.md` — NIST SSDF + CISA Self-Attestation Common Form (5 slices) — OMB M-22-18 procurement gate
   - `docs/loops/LOOP-W-SPEC.md` — Prohibited-Vendor Screening + Section 889 Reporting (4 slices) — FAR 52.204-25
   - `docs/loops/LOOP-X-SPEC.md` — Zero Trust Architecture (5 slices) — OMB M-22-09 + NIST 800-207/207A + CISA ZTMM v2.0
   - **OUT OF CORE — see `docs/roadmap/`:** LOOP-U (Privacy frameworks), LOOP-V (HIPAA), LOOP-Y (CJIS + IRS Pub 1075), LOOP-Z (ISO international). These are parallel compliance regimes preserved as research / roadmap reference. Do not cite them as dependencies of core slices. Read `docs/roadmap/README.md` for the scope-fence rationale.
   - `docs/CIRCIA-WORKFLOW.md` — CIRCIA Final Rule extensions to G.G2 + M.M4 (May 2026 effective; HIGH PRIORITY)
   - `docs/slices/G/G.G2-SEC-8K-EXTENSION.md` — SEC Item 1.05 Form 8-K cyber-incident disclosure extension to G.G2 (co-ship requirement; see file for trigger criteria + four-business-day clock)
6. **`docs/slices/X/X.XN.md`** — per-slice deep-context docs (one per pending slice, 49 total). Each carries:
   - YAML frontmatter (`slice_id`, `status`, `commit`, `completed_date`, `depends_on`, `blocks`, `estimated_effort`, `last_updated`)
   - TL;DR, why-this-slice-exists, authoritative sources (verbatim quotes), files to create/extend, schemas, build steps, REQUIRES-OPERATOR-INPUT table, test specifications, REO compliance notes, verification commands, known risks, open questions, **Implementation log** running journal, completion checklist, resume-from-fresh-session checklist.
   - When resuming a SPECIFIC slice, this is the SINGLE file to read after CLAUDE.md.
7. **`docs/loops/LOOP-X-RISKS.md`** — per-loop risks registers (one per LOOP-B..K, 10 total). When a slice surfaces a new risk during implementation, update the register in the same commit.
8. **`docs/DEPENDENCY-GRAPH.md`** — Mermaid + tabular dependency map for every slice; critical path; parallelization streams; advisory graph for proposed LOOP-L..Q.
9. **`docs/GLOSSARY.md`** — A–Z of every FedRAMP / NIST / OSCAL / FedPy-specific term used in the spec corpus (90+ terms). When you encounter an unfamiliar acronym, check here first.
10. **`docs/IMPLEMENTATION-LOG-TEMPLATE.md`** — format + cadence for the per-slice Implementation log. Required reading before you start implementing a slice.
11. **`docs/ADDITIONAL-LOOPS-AUDIT.md`** — audit (2026-06-06) surfacing 6 new loops (L–Q) + 12 extensions. RATIFIED 2026-06-07; loops L–Q now have full SPEC + per-slice docs + risks registers. M and O are confirmed applicable. Implementation queued behind LOOP-B.B1.
12. **`docs/SECOND-PASS-AUDIT.md`** — post-LOOP-L..Q audit (2026-06-07) confirming nothing else is still missing after L-Q specification. Read alongside `ADDITIONAL-LOOPS-AUDIT.md` when assessing roadmap completeness.
12a. **`docs/THIRD-PASS-AUDIT.md`** — post-second-pass audit (2026-06-07) surfacing LOOP-R (PQC), LOOP-S (DFARS 252.204-7012 Cloud Equivalency), and the CIRCIA Final Rule extensions to G.G2 + M.M4. All three are now fully specified (LOOP-R + LOOP-S SPEC + 6 per-slice docs + 2 risks registers; CIRCIA-WORKFLOW.md + 2 CIRCIA-extension per-slice docs). CIRCIA is **HIGH PRIORITY** (May 2026 effective date).
12c. **`docs/FOURTH-PASS-AUDIT.md`** — post-third-pass audit (2026-06-07) surfacing LOOP-W, LOOP-T, and the SEC Form 8-K Item 1.05 extension to G.G2. Read this alongside `THIRD-PASS-AUDIT.md` when assessing roadmap completeness. The audit ratifies LOOP-T + LOOP-W as in-scope and confirms G.G2-SEC-8K-EXTENSION as a co-ship requirement for any G.G2 implementation that touches a registrant subject to SEC reporting.
12d. **`docs/roadmap/FIFTH-PASS-AUDIT.md`** — post-fourth-pass audit (2026-06-08) surfacing LOOP-U, LOOP-V, LOOP-X, LOOP-Y, LOOP-Z + candidates LOOP-AA through LOOP-GG. After the scope-fence (commit `<next>`), LOOP-X stayed in core (Zero Trust per OMB M-22-09 is in-scope for FedRAMP-serving CSPs). LOOP-U, V, Y, Z and all LOOP-AA-GG candidates were moved to `docs/roadmap/` as out-of-FedRAMP-scope reference material. Read `docs/roadmap/README.md` for the scope-fence rationale before referencing any roadmap doc.
12b. **`docs/CIRCIA-WORKFLOW.md`** — CIRCIA Final Rule 72-hour incident reporting workflow. Extends G.G2 (Incident Communications Procedures) and M.M4 (Privacy incident response). Defines Covered Entity / Covered Cyber Incident scoping, 72-hour reporting deadline, 24-hour ransom-payment deadline, CISA submission paths, and harmonization with FedRAMP IR-6 + Privacy Act §552a(e)(10) + OMB M-17-12.
13. **`docs/sections/SECTION-X.md`** — artifact-requirements layer (cross-references loops):
    - `docs/sections/SECTION-A.md` — Submission package artifacts
    - `docs/sections/SECTION-B.md` — 3PAO assessment workflow
    - `docs/sections/SECTION-C.md` — Post-authorization ConMon
    - `docs/sections/SECTION-D.md` — Audit agent UX
    - `docs/sections/SECTION-E.md` — NIST 800-53 control mapping
    - `docs/sections/SECTION-F.md` — FedRAMP 20x specific deliverables
14. **`CHANGELOG.md`** "Unreleased" section — what's already shipped per slice.
15. **`docs/AFR-FAMILY-CLASSIFICATION.md`** — R1: all 10 AFR families REQUIRED at Moderate, per-family CSP-actionable MUSTs (drives LOOP-G).
16. **`docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`** — R2/R3/R4 (drives LOOP-E.E2 + LOOP-F.F3).
17. `ARCHITECTURE.md` (repo root) — system shape.
18. `core/inventory-coverage.ts` — the coverage contract pattern. Replicate for new emit families.
19. `docs/IMPACT-LEVEL-NOTES.md` — why Phase 4 / High is not authored by 20x.
20. `RUNBOOK.md` — operational invariants.

If a new contributor reads only one file, it should be this one. If they read two, the second is `docs/STATUS.md`.

## Resuming work — two paths

A fresh session opens in the repo and auto-loads this file. Pick the path that matches what you were told to do:

### Path A — resuming the "next pending" slice (default)

1. **Read `docs/STATUS.md`** — find the "Overall → Next priority" line. That's the slice you work on.
2. **Read `docs/loops/LOOP-X-SPEC.md`** for that slice's loop — high-level context + slice rationale.
3. **Read `docs/slices/X/X.XN.md`** — the deep-context per-slice doc. Frontmatter (`depends_on`, `blocks`, `status`, `commit`) tells you exactly what's blocked. The body has files-to-create, schemas, build steps, REO checks, REQUIRES-OPERATOR-INPUT table, tests, risks, open questions, **Implementation log** running journal, and verification commands.
4. **Read `docs/loops/LOOP-X-RISKS.md`** — the per-loop risks register. If you discover a new risk during this slice, add it here in the same commit.
5. **Read `docs/SLICE-COMPLETION-PROCEDURE.md`** — review the 7-step procedure you MUST follow when done.
6. **Read `docs/IMPLEMENTATION-LOG-TEMPLATE.md`** if you have not before — defines the running-journal format for the per-slice doc.
7. **Execute** the slice under the REO standard, updating the Implementation log section as you go.
8. **Follow the 7-step completion procedure** atomically with your final commit.

### Path B — resuming a SPECIFIC slice (when told "continue with X.XN")

1. **Read `docs/slices/X/X.XN.md` directly.** That single file has the frontmatter (status, depends_on, blocks, last_updated) + every implementation detail + the Implementation log of prior sessions. It is the entry point for that slice.
2. **Read `docs/loops/LOOP-X-RISKS.md`** — register for the slice's loop.
3. **Cross-reference `docs/DEPENDENCY-GRAPH.md`** if dependencies need to be confirmed (e.g. to check the slice is unblocked).
4. **Read `docs/SLICE-COMPLETION-PROCEDURE.md`**.
5. **Execute + 7-step completion** as in Path A.

NO EXCEPTIONS. The 7-step procedure is what keeps STATUS.md, the spec docs, the per-slice docs, CHANGELOG.md, and the git history in sync. Skipping any step breaks the on-disk source of truth.

> ## Slice-completion directive (apply to EVERY loop / slice / section completion)
>
> When a loop / slice / section completes implementation:
> 1. Update STATUS.md status row for the slice (commit hash, status -> 'done', last_updated).
> 2. Update the loop SPEC status table (commit hash, status -> 'done').
> 3. Append a CHANGELOG.md entry (date, slice ID, summary, commit).
> 4. Commit with the slice ID in the subject line + Co-Authored-By trailer.
> 5. Push to origin/main.
> 6. If a new permanent reference document was created, add it to this reading list.
> 7. Verify with 'git log --oneline -3' that the commit landed before declaring the slice closed.
>
> Failure to do steps 1-7 means the slice is NOT closed.

## Strong directive (REO-enforced)

**Every slice completion MUST:**
1. Pass typecheck + tests + check:reo (atomic — green before commit)
2. Update STATUS.md (slice row + Overall section)
3. Update the loop's spec doc (slice's status row)
4. **Update the per-slice doc's frontmatter** (`status: done`, `commit: <hash>`, `completed_date: <ISO>`, `last_updated: <ISO>`)
5. **Append the final Implementation log entry** to the per-slice doc (per `docs/IMPLEMENTATION-LOG-TEMPLATE.md`) — date, outcome, commit reference
6. **Add any newly-discovered risks to `docs/loops/LOOP-X-RISKS.md`** in the same commit (if surfaced during implementation)
7. Add a CHANGELOG.md "Unreleased" entry
8. Commit with the slice ID in the message
9. Push to origin/main

**During work in-progress** (not at completion), the Implementation log MUST be updated at every meaningful milestone:
- At every commit boundary (even WIP commits)
- At every test failure (transient or persistent)
- At every research question answered
- At every spec divergence
- At every newly-discovered risk (followed by an immediate entry in `LOOP-X-RISKS.md`)
- At every external dependency pin (version, schema, API)

See `docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3 for the full update cadence + §4 for example entries.

**Failure to follow this procedure is a REO violation.** The slice is not "done" until all 9 steps execute. Future sessions WILL see the inconsistency and reject it. The per-slice doc + risks register are the on-disk archaeological record of the slice; if they are not kept current with the code, a 3PAO reviewing the trail will find the gap.

**For CIRCIA-extension slices (G.G2.CIRCIA, M.M4.CIRCIA): when the parent slice (G.G2 or M.M4) ships, the CIRCIA extension MUST ship in the same commit OR be explicitly tracked as a follow-up in STATUS.md.** CIRCIA's May 2026 effective date means any G.G2/M.M4 implementation that omits CIRCIA is incomplete by federal regulation. The CIRCIA-extension docs (`docs/slices/G/G.G2-CIRCIA-EXTENSION.md`, `docs/slices/M/M.M4-CIRCIA-EXTENSION.md`) live alongside the parent slice docs precisely so this co-shipping requirement is impossible to miss — they are siblings on the filesystem, not nested or hidden.
