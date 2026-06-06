# LOOP-C — Risks Register

> Live document. Implementing sessions add entries during work; resolved risks stay in the file with `status=resolved` + resolution note. Cross-cutting risks apply to ALL slices in LOOP-C; per-slice risks are local supplements not duplicated from cross-cutting.

> Read this file alongside the per-slice docs (`docs/slices/C/C.C*.md`). The per-slice docs contain a "Known risks / issues" section; this file consolidates loop-wide risks + risks that span multiple slices.

> Last updated: 2026-06-07.

---

## Cross-cutting risks (apply to ALL slices in this loop)

| ID | Description | Severity | Mitigation | Status |
|---|---|---|---|---|
| C-X-1 | **OOXML primitives duplication.** Today `core/ssp-docx.ts` and `core/roe-emit.ts` each define `para`, `heading`, `table`, `fieldTable`, `stylesXml`, `CONTENT_TYPES`, `ROOT_RELS`, `DOC_RELS`. Adding 11 more emitters duplicates 80+ lines × 11 = unmaintainable. | high | Pre-slice `core/docx-primitives.ts` extracts shared helpers BEFORE C.C1 lands. Pre-slice has 8 tests. C.C1..C.C9 import from the shared module. | pending |
| C-X-2 | **REQUIRES-OPERATOR-INPUT marker variants.** Two distinct markers: `REQUIRES-OPERATOR-INPUT` (missing data) vs `REQUIRES-OPERATOR-INPUT-VERIFY` (inferred-not-confirmed). Risk of inconsistent application across emitters. | medium | Both constants exported from `core/docx-primitives.ts` as `TBD` + `TBD_VERIFY`. Every emitter MUST import (no hardcoded strings). Lint script `scripts/lint-no-stubs.mjs` recognizes both markers as legitimate (not stubs). | pending |
| C-X-3 | **Deterministic UUID + metadata.** Every emitter calls `deterministicUuid(slice, systemId, runId)` from `core/oscal.ts`. If `runId` changes (timestamp), output changes — violates byte-identical determinism in tests. | medium | Tests freeze `runId` to a fixed value (e.g. `'test-run-0001'`); production runs naturally vary. Document the test convention in `tests/README.md`. | pending |
| C-X-4 | **Signing pipeline integration.** Every .docx must go through `core/sign.ts` (Ed25519 + RFC 3161). Risk: an emitter forgets to call sign or the orchestrator skips signing. | high | Orchestrator central dispatch wraps EVERY `--*` emitter in the same signing block; integration test asserts every LOOP-C .docx has `<filename>.sig` + `<filename>.tsr` artifacts alongside. | pending |
| C-X-5 | **Submission bundler `Role` union explosion.** Adding 11 new `Role` values may collide with future role names. | low | Use `<slice>-docx` naming convention (e.g. `cmp-docx`, `iscp-docx`); roles namespace by document type. | pending |
| C-X-6 | **Orchestrator CLI flag explosion.** 9 new `--cmp`, `--iscp`, ..., `--baseline-config` flags + 11 envs. Risk: CLI becomes unwieldy; users want a single `--docx-pack` umbrella. | medium | Provide both per-doc flags AND a `--docx-pack` umbrella that enables all 9 slices when set. Document in README. Defer umbrella until all 9 slices ship. | pending |
| C-X-7 | **FedRAMP-published template updates.** FedRAMP may release new versions of the SSP Appendix G ISCP template, PIA template, FIPS 199 template, or publish a CMP template. | medium | Every emitter module header records the template URL + retrieval date. CI cron checks template URLs for HTTP 304 vs 200 monthly; opens an issue when a 200 appears (indicating revision). | pending |
| C-X-8 | **NIST publication updates.** SP 800-60 Rev. 2 (IWD as of Jan 2024), SP 800-128 R2 (possible), CSF 2.0 v1.1 (possible). | medium | Every emitter records `SOURCE_VERSION` constant + URL; revision is a follow-up slice. | pending |
| C-X-9 | **Hyperlink cross-references.** §X cross-links between LOOP-C docs (e.g. CMP §5 → baseline-config.docx) need OOXML `_rels/document.xml.rels` relationship entries. Current SSP-2 + RoE emitters emit text refs, not active hyperlinks. | medium | Pre-slice `core/docx-primitives.ts` ships a `hyperlink(href, text)` helper that produces both the run text + the relationship entry. All cross-references use this. | pending |
| C-X-10 | **Page-break + headers/footers absent.** Current OOXML primitives don't emit headers/footers (system name + page X of Y). 3PAOs may expect them. | low | Scope OUT of LOOP-C per SPEC §6.7. Add LOOP-C.C10 follow-up only if 3PAO feedback demands it. Document the deliberate omission in cover-letter caveats. | pending |
| C-X-11 | **Provenance footer absence in early prototypes.** Risk that an emitter is shipped without footer citing source SHA256s + URLs. | high | `check:provenance` CI guardrail validates every emit-field has a `provenance` entry; integration test asserts each LOOP-C .docx contains a `<w:footer>` block with sha256 references. | pending |
| C-X-12 | **Operator config schema drift.** `config.yaml` accumulates `cmp.*`, `iscp.*`, `irp.*`, `privacy.*`, `fips199.*`, `conmon.*`, `rms.*`, `auth_request.*`, `baseline_config.*` keys. Risk of typos silently being ignored. | medium | Define a single JSON schema for `config.yaml` (`scripts/config-schema.json`) and validate at orchestrator startup; emit warnings for unknown keys. | pending |
| C-X-13 | **Tracker DB schema deferral.** Several operator inputs (CCB roster, IR team roster, privacy responses) belong in the tracker DB but tracker forms haven't been added yet. | medium | C.C1..C.C9 accept inputs via `config.yaml` (committed to repo) as a stop-gap; LOOP-F follow-up adds tracker forms. Document the stop-gap in each slice's `Open questions`. | pending |
| C-X-14 | **Multi-CSO scaling.** Each emitter accepts `outDir` — fine for single CSO. For LOOP-H.H3 multi-CSO, the orchestrator iterates per-CSO and calls each emitter once per CSO. | low | Already designed in. No change to LOOP-C emitters. | pending |
| C-X-15 | **Operator-supplied PII in emitted docs.** Multiple slices include rosters/contacts with real names + emails (CMP §3 CCB, IRP §2 team, ISCP Appendix A, RMS §9 executive, cover letter §6). | high | Emitter never logs full PII (only counts); .docx is signed + bundled into tar with restricted ACL; document handling in CSP operational runbook. Don't include role-based addresses (info@) for external contacts where possible. | pending |
| C-X-16 | **Determinism vs `submissionDate` / `testDate` defaults.** If undefined, emitter must NOT inject `new Date()` (REO Rule 1.7). | medium | Every date opt defaults to runId-derived ISO date (deterministic per run). Explicit REQUIRES-OPERATOR-INPUT marker when no plausible default. | pending |
| C-X-17 | **Word/Office incompatibility.** OOXML strings hand-constructed; risk of Word complaining about malformed parts. | high | Integration test: emit each .docx, run `unzip -t` to verify ZIP integrity; pass through `validator.w3.org`-style XML validator for each part. Optionally test-render via LibreOffice headless in CI. | pending |
| C-X-18 | **`check:reo` guardrail false positives.** `lint-no-stubs.mjs` may flag "TBD" + "REQUIRES-OPERATOR-INPUT" as stubs. | medium | Allowlist `REQUIRES-OPERATOR-INPUT` + `REQUIRES-OPERATOR-INPUT-VERIFY` as legitimate non-stub markers in `scripts/lint-no-stubs.mjs`. Document allowlist in CLAUDE.md Rule 3. | pending |
| C-X-19 | **Baseline-config + AFR-SCG ordering.** C.C9 and LOOP-G.G5 share `core/scg-comparator.ts`. Whichever ships first owns the module. | medium | C.C9 ships the comparator first (it's a LOOP-C dependency); G.G5 reuses without modification. Document the ownership in C.C9 module header. | pending |
| C-X-20 | **C.C1 ↔ C.C9 dispatch order.** Orchestrator must emit C.C9 (baseline-config.docx) BEFORE C.C1 (cmp.docx) so CMP §5 cross-link resolves. | medium | Enforce in orchestrator dispatch logic; document in `LOOP-C-SPEC.md` Section 4 (already noted). Integration test asserts dispatch order. | pending |

---

## Per-slice risks

### C.C1 — Configuration Management Plan
- **C-C1-1**: Tooling-suggestion false-confidence in §10 (REQUIRES-OPERATOR-INPUT-VERIFY for cloud-native CM tooling).
- **C-C1-2**: Inventory drift between emit time and 3PAO sample time — §4 freezes a snapshot.
- **C-C1-3**: KSI map grep brittleness — assert `ksi_count >= 20` in emitter.
- **C-C1-4**: §5 cross-link to baseline-config.docx requires `_rels/document.xml.rels` entry (covered by C-X-9).
- **C-C1-5**: FedRAMP publishes a CMP template later — must re-target.

### C.C2 — ISCP + Test AAR
- **C-C2-1**: RPL evidence shape drift across collector versions.
- **C-C2-2**: Vendor-contact PII leak in Appendix B (covered partially by C-X-15).
- **C-C2-3**: AAR signature blocks confused as digital signatures.
- **C-C2-4**: `testDate` non-determinism (covered by C-X-16).
- **C-C2-5**: Appendix G template revision.
- **C-C2-6**: RPL-TRC test-evidence age (>365 days = stale).

### C.C3 — IRP + Test AAR
- **C-C3-1**: Spec-version confusion (Rev. 2 vs Rev. 3).
- **C-C3-2**: FedRAMP ICP doc supersession.
- **C-C3-3**: External-contact PII in §7 (covered partially by C-X-15).
- **C-C3-4**: INR-RIR coverage thresholds (<95% emits warning).
- **C-C3-5**: CSF 2.0 phase drift across NIST revisions.
- **C-C3-6**: AAR signature blocks (covered by C-C2-3).

### C.C4 — PTA + PIA
- **C-C4-1**: Rev5 PTA/PIA template release (currently absent).
- **C-C4-2**: Inventory mis-tagging causing PTA-negative when PII present.
- **C-C4-3**: PII enumeration leaks PII into emitted doc (§3 of PTA).
- **C-C4-4**: `piaForceMode='never-emit'` inappropriate suppression.
- **C-C4-5**: Rev4 vs Rev5 control-ID mismatch confuses 3PAOs.
- **C-C4-6**: SORN (PT-6) requires Federal Register process — PIA cannot satisfy by itself.

### C.C5 — FIPS 199 worksheet
- **C-C5-1**: SP 800-60 Rev. 2 release requires catalog re-extract.
- **C-C5-2**: Unknown info-type code passed in config.
- **C-C5-3**: SSP MISMATCH false positives.
- **C-C5-4**: `c=n/a` edge case in high-water-mark.
- **C-C5-5**: Operator under-categorization not detectable by worksheet.
- **C-C5-6**: Approver signature freshness across re-emits.

### C.C6 — ConMon Strategy + Plan
- **C-C6-1**: ConMon Playbook v1.0 revision.
- **C-C6-2**: KSI map grep brittleness (covered by C-C1-3).
- **C-C6-3**: Reporting endpoint policy change (USDA Connect.gov ↔ per-agency).
- **C-C6-4**: Collaborative ConMon scope ambiguity (RFC-0026 evolving).
- **C-C6-5**: VDR evidence may miss scanners (under-reports).
- **C-C6-6**: Escalation thresholds vs CISA BOD vs internal SLA conflicts.

### C.C7 — Risk Management Strategy
- **C-C7-1**: LOOP-B not yet shipped — §5/§6/§10 degrade to REQUIRES-OPERATOR-INPUT.
- **C-C7-2**: POA&M severity bucketing drift if LOOP-A.A1 changes enum.
- **C-C7-3**: `oldest_open_finding_age_days` non-determinism (covered by C-X-16).
- **C-C7-4**: Risk-tolerance values overspecified (single tolerance per CIA).
- **C-C7-5**: Cross-reference to ConMon Strategy (§7) dangling when C.C6 not in bundle.
- **C-C7-6**: Executive oversight PII (covered by C-X-15).

### C.C8 — Authorization request cover letter
- **C-C8-1**: Orchestrator dispatch order — cover letter after INDEX, before bundle tar (covered by C-X-20 pattern).
- **C-C8-2**: INDEX.json shape drift across LOOP-A.A4 versions.
- **C-C8-3**: AP metadata absent (`ap.json` not run).
- **C-C8-4**: `submissionDate` non-determinism (covered by C-X-16).
- **C-C8-5**: AO addressee delegated designate handling.
- **C-C8-6**: Cover letter signed twice (Ed25519 + wet/electronic exec signature).

### C.C9 — Baseline Configuration
- **C-C9-1**: Reference-arch.ts schema drift across providers.
- **C-C9-2**: AFR-SCG (LOOP-G.G5) not yet shipped — comparator owned by C.C9 (covered by C-X-19).
- **C-C9-3**: Multi-cloud component-type normalization.
- **C-C9-4**: Deviation severity assignment must not default.
- **C-C9-5**: Cross-cloud reference-arch coverage gaps.
- **C-C9-6**: Baseline drift between emit-time and 3PAO sample-time (covered by C-C1-2).
- **C-C9-7**: CIS Benchmarks license — cannot copy verbatim.

---

## External dependencies that may change

| Dependency | Current Version | Used By | Risk Trigger | Watch URL |
|---|---|---|---|---|
| FedRAMP SSP Appendix G ISCP Template | Rev5 (May 2024) | C.C2 | New Rev release; section reordering | https://www.fedramp.gov/rev5/documents-templates/ |
| FedRAMP SSP A04 PIA Template | Rev4 (June 2019) | C.C4 | Rev5 release (FedRAMP help-desk article 28907995813275 says "no current plans" — but may change) | https://www.fedramp.gov/assets/resources/templates/ |
| FedRAMP SSP A10 FIPS 199 Template | Rev4 (June 2019) | C.C5 | Rev5 release | https://www.fedramp.gov/resources/documents/rev4/ |
| FedRAMP ConMon Playbook | v1.0 (2025-11) | C.C6 | New cadence; new reporting endpoint | https://www.fedramp.gov/resources/documents/Continuous_Monitoring_Playbook.pdf |
| FedRAMP ConMon Strategy Guide | v3.2 (2018-04) | C.C6 | Major rev (likely with Rev5 maturity) | https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf |
| FedRAMP Agency Authorization Playbook | v4.1 (2025-11) | C.C8 | New rev with timeline updates | https://www.fedramp.gov/resources/documents/Agency_Authorization_Playbook.pdf |
| FedRAMP Initial Authorization Package Checklist | (current) | C.C8 | New artifacts added | https://www.fedramp.gov/assets/resources/templates/FedRAMP-Initial-Authorization-Package-Checklist.xlsx |
| FedRAMP Incident Communications Procedures | (CSP_Incident_Communications_Procedures.pdf) | C.C3 | SLA changes; CISA endpoint change | https://www.fedramp.gov/assets/resources/documents/CSP_Incident_Communications_Procedures.pdf |
| RFC-0026 (CA-7 Clarification) | initial (2025) | C.C6 | Final-state language | https://www.fedramp.gov/rfcs/0026/ |
| NIST SP 800-34 | Rev. 1 Upd Nov 2010 | C.C2 | Rev. 2 in some future | https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final |
| NIST SP 800-37 | Rev. 2 (Dec 2018) | C.C7, C.C8 | Rev. 3 | https://csrc.nist.gov/pubs/sp/800/37/r2/final |
| NIST SP 800-39 | (March 2011) | C.C7 | Future rev | https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-39.pdf |
| NIST SP 800-53 | Rev. 5 Upd Dec 2020 | All | Rev. 5.2.0+ patch | https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final |
| NIST SP 800-53A | Rev. 5 (Jan 2022) | C.C6 | Rev. 5.2.0+ | https://csrc.nist.gov/pubs/sp/800/53/a/r5/final |
| NIST SP 800-60 | Vol 2 Rev. 1 (Aug 2008) | C.C5 | Rev. 2 (IWD Jan 2024) — when final, catalog re-extract | https://csrc.nist.gov/pubs/sp/800/60/v2/r1/final |
| NIST SP 800-61 | Rev. 3 (Apr 2025) | C.C3 | Future rev; Rev. 2 retro-references | https://csrc.nist.gov/pubs/sp/800/61/r3/final |
| NIST SP 800-128 | Upd Oct 2019 | C.C1, C.C9 | Rev. 2 | https://csrc.nist.gov/pubs/sp/800/128/upd1/final |
| NIST SP 800-137 | (Sept 2011) | C.C6 | Rev. 1 | https://csrc.nist.gov/pubs/sp/800/137/final |
| NIST SP 800-137A | (May 2020) | C.C6 | Rev. updates | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-137A.pdf |
| NIST Privacy Framework | v1.0 (Jan 2020) | C.C4 | v2.0 | https://www.nist.gov/privacy-framework |
| FIPS 199 | (Feb 2004) | C.C5 | Successor (no public timeline) | https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf |
| FIPS 200 | (March 2006) | C.C5 | Successor | https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.200.pdf |
| CISA BOD 22-01 (KEV catalog) | active | C.C6 escalation defaults | New dueDate semantics | https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01 |
| OMB M-03-22 (E-Government §208) | active | C.C4 | Successor memo | https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2003/m03_22.pdf |
| CIS Benchmarks | rolling | C.C9 indirect | Benchmark updates per service | https://www.cisecurity.org/cis-benchmarks |
| OSCAL 1.1.2 schemas | 1.1.2 | C.C5 indirect (SSP cross-ref) | 1.2.x release | https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/ |

### Upstream library updates
- **ajv**: schema validator (used by `core/oscal-validate.ts`); 8.x → 9.x potential breaking change.
- **pino**: structured logging; minor releases.
- No `docx` npm package used — all .docx are hand-built via `core/zip.ts` `zipStore`. Reduces dependency risk.

---

## Resolved risks (historical)

Empty initially — populated as risks are resolved. Pattern for an entry:

```
| ID | Description | Severity | Resolution | Resolved Date | Resolved Commit |
|---|---|---|---|---|---|
| C-X-N | <description> | <sev> | <resolution note> | YYYY-MM-DD | <hash> |
```

---

## Notes for implementing sessions

1. **Add new risks here** as you encounter them during implementation — preserve evidence (commit, run log) in the description.
2. **Cross-cutting risks (C-X-N)** should be addressed in the pre-slice (`core/docx-primitives.ts`) before C.C1 ships. Pre-slice is the right place to fix shared problems once.
3. **When a risk is resolved**, MOVE it to "Resolved risks (historical)" with the resolution note + commit hash. Don't delete history.
4. **Severity escalation**: if a `medium` risk causes a 3PAO finding or a delivery delay, escalate to `high` and document the trigger.
5. **External-dependency check**: monthly cron (proposed) checks every URL in the "External dependencies" table for HTTP 200/304; opens an issue when a 200 appears that wasn't there before (indicates revision).
