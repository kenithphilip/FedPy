# Impact-level notes: what `--impact-level high` actually means

**TL;DR — As of June 2026, FedRAMP 20x does not yet cover the High baseline.**
Running this tool with `--impact-level high` is supported and useful, but the
audit it produces is anchored on **NIST SP 800-53 Rev5 High** parameter
overlays — not on a FedRAMP 20x-specific High requirement set, which the
program has not yet published.

---

## The state of FedRAMP 20x (June 2026)

Per [fedramp.gov/20x/phases](https://www.fedramp.gov/20x/phases/), the 20x
program is rolled out in four phases:

| Phase | Status | Scope | What was added |
|---|---|---|---|
| Phase 1 (Low pilot) | ✅ Completed FY25 Q3–Q4 | Class B (Low) | Original ~50 KSI set (RFC-0006) |
| Phase 2 (Moderate expansion) | ✅ Completed FY26 Q1–Q2 | Class C (Moderate) | RFC-0014 — added 5 Moderate-only KSIs + 3 Low+Mod KSIs (now under the 3x3-letter scheme via `fka` mappings) |
| Phase 3 (current) | 🟡 Active FY26 Q3–Q4 | Wide-scale Low + Moderate adoption | No new KSIs; tooling/3PAO process maturity |
| **Phase 4 (Class D / High pilot)** | ⏳ **FUTURE FY27 Q1–Q2** | High-impact services | **Not yet authored** |

The authoritative catalog file
[`FRMR.documentation.json` v0.9.43-beta](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json)
(published 2026-04-08) contains exactly **60 KSI indicators** across **11
families** (AFR=10, CED=4, CMT=4, CNA=8, IAM=7, INR=3, MLA=5, PIY=5, RPL=4,
SCR=2, SVC=8). Every one of them has `applies-Low: true` and
`applies-Moderate: true`; **zero have `applies-High: true`** — because the
program has not yet published High obligations.

## What this tool does at `--impact-level high`

The orchestrator's High-level handling is split between two layers:

1. **KSI assertion layer (`core/ksi-map.ts` + the per-provider collectors)**
   continues to use the catalog as-is. Because the catalog's `applies-High`
   field is empty everywhere, all 60 KSIs are evaluated at Moderate
   semantics. The 6 items in the catalog with `varies_by_level` `key_word`
   shifts (CCM-AGM-SSR, CCM-QTR-MTG, PVA-CSX-PMV, UCM-CSX-UVM, VDR-TFR-IRI,
   VDR-TFR-NRI) do honor their per-level MUST/SHOULD/MAY changes through
   `core/findings.ts:severityForKeyWord(kw)`.

2. **NIST 800-53 Rev5 baseline overlay layer (`core/control-benchmark.ts`)**
   is where the real Low→Moderate→High lift is enforced. The High profile
   is the standard NIST SP 800-53 Rev5 High baseline (committed offline at
   `docs/nist-r5-baselines.generated.json`). Adding ~60 controls and
   tightening ~70 parameters at High is faithfully encoded there. This is
   what makes the `--framework rev5` runs at `--impact-level high` produce
   meaningful audit evidence.

So a `--impact-level high` run produces a hybrid artifact: 20x KSI evidence
+ NIST SP 800-53 Rev5 High baseline overlay. **The audit package should
cite NIST SP 800-53 Rev5 High as the authoritative controlling baseline.**

## What this tool does NOT do at `--impact-level high`

- **It does not invent FedRAMP 20x High-only KSI obligations.** None exist
  in the published 20x catalog. Anyone telling you they have a "FedRAMP 20x
  High" obligation list today is either (a) extrapolating from RFC drafts
  not yet merged to JSON, (b) referring to NIST SP 800-53 Rev5 High (which
  this tool already covers), or (c) wrong.
- **It does not gate KSI findings on a 20x High applicability flag.** That
  flag is uniformly false in the source data. The Moderate KSI set is what
  runs, with control-benchmark.ts handling the level lift.

## When FedRAMP 20x Phase 4 lands

When Phase 4 publishes (FY27 Q1–Q2 per the official roadmap), this tool
will need:

1. A refresh of `docs/FRMR.documentation.json` to pick up the new High
   applicability data.
2. A re-run of `scripts/extract-frmr-requirements.mjs` to regenerate
   `docs/frmr-requirements.generated.json`.
3. Any new High-only KSIs would surface in the `applies-High` filtering
   used by `selectForLevel(impactLevel)` and would automatically be
   evaluated.
4. Any new `varies_by_level` blocks added at High would shift severity
   through the existing `severityForKeyWord` mechanism.

So the tool is structurally ready for Phase 4; it just hasn't been given
the data yet because FedRAMP hasn't published it.

## References

- [fedramp.gov/20x/phases](https://www.fedramp.gov/20x/phases/) — phase
  schedule, current state.
- [FRMR.documentation.json on GitHub](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json)
  — authoritative catalog (v0.9.43-beta, 2026-04-08).
- [RFC-0014 (FedRAMP 20x Phase Two KSIs)](https://www.fedramp.gov/rfcs/0014/)
  — the Moderate expansion that introduced the 5 Mod-only KSIs.
- [github.com/GSA/fedramp-automation](https://github.com/GSA/fedramp-automation)
  — official Rev5 High baseline profile this tool uses for the parameter
  overlay.
