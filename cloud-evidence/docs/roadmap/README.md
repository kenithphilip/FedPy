# Roadmap — Out-of-Core-Scope Documentation

This folder contains specifications, risks registers, and per-slice docs
for compliance regimes that are **not part of FedPy's core mission** but
were specified during the pre-implementation planning phase and are
preserved here as **future-roadmap / overlay documentation**.

## FedPy core scope (reminder)

> Read-only, evidence-grade automation for **FedRAMP 20x & Rev5**: a
> TypeScript collector that captures AWS / GCP / Kubernetes config
> evidence for all 60 KSIs (223 requirements), benchmarks against NIST
> 800-53 at Low / Moderate / High, signs it (Ed25519 + OSCAL), plus a
> local multi-user tracker over the FRMR catalog.

Everything in this folder is **out of that scope**. FedPy is FedRAMP.

## What lives here and why

| Item | Why it's out of core scope |
|---|---|
| `loops/LOOP-U-SPEC.md` + `LOOP-U-RISKS.md` + `slices/U/*` (5 slices) | **State + EU privacy regimes** (FERPA / COPPA / GLBA / CCPA / CPRA / GDPR / UK GDPR / NY SHIELD / 50-state breach matrix / Schrems II / EU SCCs). A FedRAMP CSP whose tenants process state-PII or EU-data-subject PII faces these obligations, but they are **parallel compliance pipelines**, not part of FedRAMP evidence collection. |
| `loops/LOOP-V-SPEC.md` + `LOOP-V-RISKS.md` + `slices/V/*` (5 slices) | **HIPAA Security Rule + Breach Notification + BAA + NIST SP 800-66 Rev 2 + HITRUST CSF v11.2.0.** Separate federal regime under HHS OCR, not FedRAMP. A FedRAMP CSP that is also a HIPAA Business Associate has distinct obligations handled by a parallel pipeline. |
| `loops/LOOP-Y-SPEC.md` + `LOOP-Y-RISKS.md` + `slices/Y/*` (4 slices) | **Sector overlays — CJIS Security Policy v5.9.5 + IRS Publication 1075.** Only relevant when a CSP's specific tenants are state/local law enforcement (CJIS) or IRS-authorized agencies (FTI). CJIS is broader and more stringent than FedRAMP Moderate. Not part of FedRAMP. |
| `loops/LOOP-Z-SPEC.md` + `LOOP-Z-RISKS.md` + `slices/Z/*` (5 slices) | **International equivalence — ISO/IEC 27001:2022 / 27017 / 27018 / 27701 + ENISA EUCS Candidate Scheme.** Parallel certification audit chains for international market entry. A FedRAMP CSP seeking ISO certification needs these, but they are not part of the FedRAMP authorization. |
| `FIFTH-PASS-AUDIT.md` | Aggressive audit surfacing additional **out-of-FedRAMP-scope** candidates (PCI-DSS, CMMC L2/L3, FedRAMP Tailored LI-SaaS, TIC 3.0, OMB M-21-07 IPv6, NIST SP 800-160 SSE, 800-128/92/184/82/63 Rev 4, DoD STIG, CIS Controls v8.1, CSA CCM v4, SOC 2 Type II, ISMAP/IRAP/TISAX, StateRAMP/TX-RAMP/AZRAMP/GovRAMP, NSM-22, AI Bill of Rights + NIST AI RMF + OMB M-24-10 + EO 14110, Section 508 / ADA Title II, FIPS 140-3 + 800-130/152, CISA CPGs, FAR Part 7.105). Documented as roadmap reference; **none should become core loops without explicit scope re-anchoring.** |

## Why preserve this work instead of deleting it

1. **Substantive research value.** The roadmap docs contain ~37,000 lines
   of verbatim regulatory quotes from FERPA, COPPA, GLBA, CCPA, GDPR,
   HIPAA Security Rule, HIPAA Breach Rule, CJIS Security Policy, IRS Pub
   1075, ISO 27001:2022, ISO 27018:2019, and dozens more — with pinned
   URLs and 2026-06-07 / 2026-06-08 access dates. This is useful
   reference material for a FedRAMP-Moderate CSP whose general counsel
   needs to scope adjacent obligations.

2. **Cross-walk hints for the FedPy core.** Several roadmap items
   contain mappings back to NIST 800-53 Rev 5 baselines that LOOP-B
   uses. The cross-walk tables (ISO 27001:2022 Annex A → NIST 800-53;
   HIPAA Security Rule → NIST 800-53 via SP 800-66 Rev 2) may inform
   future LOOP-C (multi-framework crosswalk) work.

3. **Boundary documentation.** When a FedRAMP CSP's general counsel
   asks "does FedPy do HIPAA?" the answer is a clean "no — but here is
   what HIPAA looks like and how it would intersect; we don't
   implement it."

4. **Future scope re-anchoring.** If the FedPy project ever broadens
   to "CSP compliance evidence platform" (which would be a significant
   mission change), the planning work for these regimes already exists.

## What this folder is NOT

- **Not a backlog.** Implementation will not happen against these specs
  under FedPy.
- **Not a TODO.** These are not deferred work items.
- **Not "next sprint."** The core sprint queue is `LOOP-W.W1 → LOOP-T.T1 →
  LOOP-B.B1 → 50 LOOP-B–K base slices` and lives in
  `cloud-evidence/docs/STATUS.md` "Core" section.
- **Not part of the orchestrator pipeline.** No `--privacy-frameworks`,
  `--hipaa`, `--cjis`, `--iso-27001`, etc. flags are wired into FedPy's
  orchestrator. The roadmap specs reference such flags as a planning
  artifact, not as implementation reality.

## If you are a future Claude session reading this

1. Do NOT propose moving these loops back into core scope without an
   explicit mission re-statement from the user.
2. Do NOT cite roadmap loops as dependencies of core loops. A core
   slice's `depends_on:` list should reference only other core slices.
3. Do NOT spawn audit-driven expansion proposals that add MORE roadmap
   loops. The "audit found things missing" reflex is what produced this
   folder; the user has explicitly scope-fenced FedPy.
4. Treat this folder as **read-only reference**.

## Scope-fence commit history

This folder was created by **commit `<next-commit>`** as the
materialization of the "Option A scope-fence" agreed in the
conversation summarized at the end of commit `ca6ff0f` (LOOP-U/V/X/Y/Z
batch). The user's explicit directive:

> "Let's keep only the loops true to getting to FedRAMP 20x or Rev5 as
> the ones in scope to be implemented. Move the rest to another folder
> as suggested roadmap or out of scope ideas. We do not want to bloat
> or degrade the codebase beyond it being a tool used for FedRAMP
> compliance and attestation and evidence management. This tool should
> be the go-to tooling in the opensource community for SaaS providers
> to leverage to get to FedRAMP."

## Related authoritative docs

- `cloud-evidence/CLAUDE.md` — Scope Guard block enforces this fence
- `cloud-evidence/docs/STATUS.md` — Core-only status tables
- `cloud-evidence/docs/EXECUTION-PLAN.md` — Core priority chain
- `cloud-evidence/docs/DEPENDENCY-GRAPH.md` — Core-only dependency graph
