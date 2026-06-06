---
slice_id: G.G5
title: AFR-SCG (Secure Configuration Guide)
loop: G
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A4, LOOP-A.A5, REO-0, R1]
blocks: [LOOP-F.F4, LOOP-F.F5, LOOP-I.I1]
estimated_effort: 5 working days
last_updated: 2026-06-07
---

# G.G5 — AFR-SCG (Secure Configuration Guide)

## TL;DR
Ship a dependency-free `out/afr-scg/secure-configuration-guide.docx` published Secure Configuration Guide + machine-readable `out/afr-scg/scg-baseline.json` baseline + customer-facing `out/afr-scg/use-instructions.md`. Combines the real reference-architecture outputs from `providers/{aws,gcp,azure}/reference-arch.ts` with the FedRAMP Moderate parameter overlay from `core/control-benchmark.ts`, plus operator-supplied customer-facing narrative (responsibilities, deviation request process, support contact). Closes SCG-CSO-RSC and SCG-CSO-AUP; baseline JSON round-trips through the existing `core/scg-comparator.ts` so a drift detector validates the very baseline it publishes.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
A customer deploying a FedRAMP-authorized CSO needs concrete, vendor-published guidance: which encryption suites are FIPS-validated, which logging settings are required, which IAM defaults apply, what the deviation request process looks like, and how to contact support. SCG-CSO-RSC mandates a Secure Configuration Guide with prescribed minimum content; SCG-CSO-AUP mandates instructions for how to obtain and use the guide be included in the authorization package.

Today the codebase has:
- `providers/aws/reference-arch.ts` — emits AWS reference-architecture findings (declared-vs-observed).
- `providers/gcp/reference-arch.ts` — same for GCP.
- `providers/azure/reference-arch.ts` — same for Azure.
- `core/scg-comparator.ts` — diff engine for a baseline file.

What's missing is the published guide itself + the baseline JSON the comparator reads. G.G5 produces both. By generating the baseline from the real reference-arch outputs + the FedRAMP-published parameter overlay, the comparator (which already exists) can immediately drift-detect against the very file we publish — closing a verification loop without inventing new code.

## Authoritative sources (with verbatim quotes)

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **SCG-CSO-RSC / FRR-RSC-01 + FRR-RSC-02 + FRR-RSC-03**:
  > "Providers MUST create, maintain, and make available recommendations for securely configuring their cloud services (the Secure Configuration Guide) that includes at least the following information: …"
  Sub-bullets: encryption settings (FIPS-validated module IDs), authentication (MFA + IdP integration), network (segmentation + boundary protection), logging (event categories + retention), vulnerability response (cadence + SLA), patching cadence.

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta) — **SCG-CSO-AUP**:
  > "Providers MUST include instructions in the FedRAMP authorization package that explain how to obtain and use the Secure Configuration Guide."

- https://csrc.nist.gov/projects/cryptographic-module-validation-program — **NIST Cryptographic Module Validation Program (CMVP)**:
  > "The Cryptographic Module Validation Program (CMVP) … validates cryptographic modules to Federal Information Processing Standards (FIPS) 140-3 (and earlier FIPS 140-2)."
  Used to require FIPS-validated module IDs (140-2 or 140-3) in the SCG encryption section.

- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf — **FIPS 140-3** §1 (Cryptographic Module Validation):
  > "This Standard … establishes security requirements for cryptographic modules used by federal organizations."

- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — **NIST SP 800-53 Rev 5 §CM-2 (Baseline Configuration)**:
  > "Develop, document, and maintain under configuration control, a current baseline configuration of the system."
  Anchors the SCG-as-baseline-document framing.

- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — **NIST SP 800-53 Rev 5 §CM-6 (Configuration Settings)**:
  > "Establish and document configuration settings for components employed within the system that reflect the most restrictive mode consistent with operational requirements."
  Direct mapping for the SCG content + secure-defaults rationale.

- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — **NIST SP 800-53 Rev 5 §SA-22 (Unsupported System Components)**:
  > "Replace system components when support for the components is no longer available from the developer, vendor, or manufacturer."
  Anchors patching cadence section.

- https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/ssp/ — **FedRAMP Rev5 Playbook — SSP §13.1 (Configuration Management Plan)**:
  > "The CSP shall develop and maintain configuration management documentation that describes the baseline configuration, configuration settings, and the configuration management plan."
  Cross-reference for CMP linkage.

- https://aws.amazon.com/compliance/fips/ — **AWS FIPS 140-2 / 140-3 endpoints**:
  > "AWS provides FIPS 140-2 validated endpoints to support customers in meeting FIPS compliance requirements."
  Cited for FIPS-endpoint enumeration in the AWS section of the SCG baseline.

- https://cloud.google.com/security/compliance/fips-140-2-validated — **GCP FIPS 140-2 validated module list**:
  > "Google Cloud uses BoringCrypto, a FIPS 140-2 validated cryptographic module …"

- https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-fips-140-2 — **Azure FIPS 140-2 / 140-3**:
  > "Azure services using FIPS 140-validated cryptographic modules meet the requirements of FedRAMP."

- https://ecma-international.org/publications-and-standards/standards/ecma-376/ — **ECMA-376 (Office Open XML File Formats)** §11.3.10 (WordprocessingML body):
  Cited as the format spec for the dependency-free `.docx` emission (same pattern as SSP-docx + RoE).

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/afr-scg.ts` — pure builders + disk emitter. Exports:
  - `buildScgBaseline(input: ScgBaselineInput): ScgBaseline`
  - `buildScgGuideDocx(input: ScgGuideInput): { bytes: Uint8Array; requires_operator_input: string[]; ready_for_signature: boolean }`
  - `buildUseInstructionsMarkdown(input: ScgUseInstructionsInput): string`
  - `emitAfrScg(outDir: string, ctx: OrchestratorContext): Promise<ScgEmitResult>`
  ~600 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/afr-scg.test.ts` — unit tests (≥12) for baseline merge, .docx body, use-instructions markdown, round-trip with scg-comparator, FIPS module assertions.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-scg.ts` — REST: `GET/POST /api/afr-scg/narratives` (operator-supplied customer-facing sections), `GET /api/afr-scg/baseline` (read latest baseline).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/afr-scg.test.ts`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/ScgNarratives.tsx` — operator UI: four narrative editors (customer responsibilities, secure defaults rationale, deviation request process, customer support contact); preview pane showing how the .docx will render.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/ScgNarratives.test.tsx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/AFR-SCG-RUNBOOK.md` — operator runbook: how to author customer-facing narratives; how to verify FIPS module IDs roll up correctly; where to host the published guide (Trust Center).

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/aws/reference-arch.ts` — add `export function getAwsReferenceArchBaseline(): ReferenceArchBaseline` exporter returning a structured baseline (FIPS endpoints, default IAM password policy, default S3 encryption, default CloudTrail config) alongside the existing finding emit. No SDK changes.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/gcp/reference-arch.ts` — same shape: `getGcpReferenceArchBaseline()`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/azure/reference-arch.ts` — same shape: `getAzureReferenceArchBaseline()`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/scg-comparator.ts` — extend `loadScgBaseline` to accept either a path OR the in-memory `ScgBaseline` produced by `core/afr-scg.ts`. Document the canonical on-disk location as `out/afr-scg/scg-baseline.json`. No new logic — just an additional overload.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/control-benchmark.ts` — add `getModerateBaselineParameterOverlay(): Record<string, string>` exporter returning the FedRAMP Moderate parameter values (e.g. SC-7 boundary protection, AC-2(2) automatic disable period 30d, IA-5(1) password complexity).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/aws/crypto.ts` — expose `getFipsValidatedModuleIds(): Array<{ id: string; standard: 'FIPS-140-2'|'FIPS-140-3'; cmvp_url: string }>`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/gcp/crypto.ts` — same.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/azure/crypto.ts` — same.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--afr-scg` flag + `CLOUD_EVIDENCE_AFR_SCG` env. Optional `--scg-publish-url <url>` flag.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — well-known catalogue rows:
  - `{ role: 'afr-scg-docx', filename: 'afr-scg/secure-configuration-guide.docx', required: true }`
  - `{ role: 'afr-scg-baseline', filename: 'afr-scg/scg-baseline.json', required: true }`
  - `{ role: 'afr-scg-use-instructions', filename: 'afr-scg/use-instructions.md', required: true }`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/schema.sql` — additive: `CREATE TABLE IF NOT EXISTS afr_scg_narratives (key TEXT PRIMARY KEY CHECK (key IN ('customer_responsibilities','secure_defaults_rationale','deviation_request_process','customer_support_contact','scg_publish_url')), value TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by_user_id TEXT NOT NULL);`

## Schemas / standards

**`ScgBaseline`** (re-uses `core/scg-comparator.ts:ScgBaseline` shape — flat key-value map with metadata):

```ts
interface ScgBaseline {
  version: string;                         // e.g. '2026.06'
  generated_at: string;                    // RFC 3339
  system_id: string;
  system_name: string;
  settings: Record<string, ScgSetting>;    // flat map; key = e.g. 'aws.cloudtrail.multi_region'
}

interface ScgSetting {
  expected_value: string;
  source: 'reference-arch'|'control-benchmark'|'operator';
  rationale: string;                       // verbatim from FRR-RSC-01..03 or operator narrative
  references: string[];                    // URLs (FIPS, 800-53, etc.)
}
```

**`ScgGuideInput`** (.docx render input):

```ts
interface ScgGuideInput {
  systemIdentity: { name: string; id: string; impactLevel: 'Low'|'Moderate'; csp: string };
  baseline: ScgBaseline;
  fipsModules: { aws: FipsModule[]; gcp: FipsModule[]; azure: FipsModule[] };
  customerResponsibilities?: string;       // operator
  secureDefaultsRationale?: string;        // operator
  deviationRequestProcess?: string;        // operator
  customerSupportContact?: string;         // operator
  publishUrl?: string;                     // CLI --scg-publish-url
  provenance: ProvenanceBlock;
}

interface FipsModule {
  id: string;                              // e.g. 'AWS-LC-FIPS 1.0.4'
  standard: 'FIPS-140-2'|'FIPS-140-3';
  cmvp_url: string;                        // https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/<n>
  status: 'active'|'historical';
}
```

**`.docx` section structure** (8 sections, mirrors RoE/SSP-docx pattern):
1. **Overview + System Identity** (auto from SSP).
2. **How to Obtain** (per SCG-CSO-AUP; pulls `publishUrl`).
3. **How to Use** (deployment steps, version-tracking, where to download).
4. **Mandatory Secure Defaults** — 7 subsections:
   - 4.1 Encryption (FIPS modules + AES-256 + RSA-2048+).
   - 4.2 Authentication (MFA required, IdP integration).
   - 4.3 Network (segmentation, boundary protection, WAF).
   - 4.4 Logging (event categories, retention, alerting).
   - 4.5 Vulnerability response (cadence + SLA).
   - 4.6 Patching cadence (per asset class).
   - 4.7 Incident reporting (links to AFR-ICP procedures).
5. **Customer Responsibilities** (operator-supplied).
6. **Deviation Request Process** (operator-supplied).
7. **Version History** — append-only.
8. **Provenance** (tool name + run id + commit hash + emittedAt + sourceCalls + requirementTexts).

**`use-instructions.md`** — short markdown with TOC, contact, version, retrieval URL, signing-key fingerprint for verification.

## Build steps (concrete, numbered)

1. Define typed interfaces in `core/afr-scg.ts`. Determinism: settings map sorted ASC by key.
2. Pure `buildScgBaseline(input)`:
   - Call `getAwsReferenceArchBaseline()`, `getGcpReferenceArchBaseline()`, `getAzureReferenceArchBaseline()`.
   - Merge into a single flat settings map (key prefixed with provider).
   - Overlay `getModerateBaselineParameterOverlay()` for FedRAMP Moderate parameters (key prefix `fedramp.moderate.`).
   - Tag each setting with `source` ('reference-arch' | 'control-benchmark' | 'operator').
   - Sort keys ASC; emit deterministic JSON.
3. Pure `buildScgGuideDocx(input)`:
   - Render 8 sections per pattern above.
   - Pull FIPS module lists from `providers/*/crypto.ts`.
   - Insert verbatim SCG-CSO-RSC + SCG-CSO-AUP statements in §2 + §4 headers.
   - Operator-supplied narratives in §5 + §6; REQUIRES-OPERATOR-INPUT marker box when missing.
   - Mirror `core/ssp-docx.ts` body-construction pattern; use `core/zip.ts` `zipStore` for OOXML zip.
4. Pure `buildUseInstructionsMarkdown(input)`:
   - Short doc: TOC + How to Obtain + How to Use + Version + Signing-key fingerprint.
   - REQUIRES-OPERATOR-INPUT for `publishUrl` when missing.
5. Disk emitter `emitAfrScg(outDir, ctx)`:
   - Read SSP + tracker `afr_scg_narratives` rows.
   - Build baseline + docx + markdown.
   - Write 3 artifacts to `out/afr-scg/`.
   - Append `provenance.requirementTexts` (SCG-CSO-RSC + SCG-CSO-AUP verbatim).
   - Return `ScgEmitResult` with `requires_operator_input` + `ready_for_signature`.
6. Round-trip test: feed emitted `scg-baseline.json` back into `core/scg-comparator.ts:loadScgBaseline` → diff against itself → assert zero drift.
7. Orchestrator wiring: `--afr-scg` flag + env. Runs before signing.
8. Submission bundle: 3 new role rows.
9. Tracker route: CRUD on `afr_scg_narratives` table (single-row-per-key upsert).
10. Tracker UI: 4-section narrative editor + preview pane.
11. Validation pass: `npm run typecheck`; `npm test`; `npm run check:reo`.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| `customer_responsibilities` | tracker `afr_scg_narratives.customer_responsibilities` | marker box in `.docx` §5; `ready_for_signature = false` |
| `secure_defaults_rationale` | tracker `afr_scg_narratives.secure_defaults_rationale` | marker in `.docx` §4 header |
| `deviation_request_process` | tracker `afr_scg_narratives.deviation_request_process` | marker in `.docx` §6 |
| `customer_support_contact` | tracker `afr_scg_narratives.customer_support_contact` | marker in `.docx` §5 + use-instructions.md |
| `scg_publish_url` | CLI `--scg-publish-url` or `CLOUD_EVIDENCE_SCG_PUBLISH_URL` env | marker in §2 + use-instructions.md |
| `org-profile.yaml` fallback | when tracker is absent, all four narratives fall back to `org-profile.yaml:scg.{key}` | per REO Rule 4: `config.yaml` is real operator data |

## Test specifications (≥12 tests)

1. `it('merges reference-arch outputs from AWS+GCP+Azure into one baseline')` — synthetic provider outputs → merged map contains all entries with prefix.
2. `it('flat-map setting keys are sorted for determinism')` — keys ASC; same input twice → byte-identical JSON.
3. `it('every setting carries a source attribution')` — every value has `source ∈ {'reference-arch','control-benchmark','operator'}`.
4. `it('emits REQUIRES-OPERATOR-INPUT for customer_responsibilities when missing')` — `requires_operator_input` contains the key; `ready_for_signature = false`.
5. `it('renders the 7 mandatory secure-defaults subsections in the .docx')` — XML body parse; assert each subsection heading present.
6. `it('quotes verbatim SCG-CSO-RSC + SCG-CSO-AUP statements in provenance')` — both keys present byte-equal to FRMR.
7. `it('uses FIPS-validated module IDs from crypto.ts collectors')` — fixture providers → `.docx` §4.1 includes the FIPS module IDs verbatim.
8. `it('use-instructions markdown contains the publish URL when supplied')` — `--scg-publish-url https://csp.example/scg` → markdown contains the URL; missing → REQUIRES-OPERATOR-INPUT.
9. `it('version-history section appends without rewriting prior rows')` — prior version in archive remains untouched after re-emit.
10. `it('.docx zip structure is valid + store-only')` — open with `core/zip.ts` reader; assert parts: `[Content_Types].xml`, `_rels/.rels`, `word/document.xml`, `word/_rels/document.xml.rels`; method = store.
11. `it('scg-comparator.ts can round-trip the emitted baseline')` — feed `scg-baseline.json` back into `loadScgBaseline` → diff against itself → zero drift.
12. `it('records provenance.requirementTexts for both SCG MUSTs')` — exactly 2 keys (SCG-CSO-RSC, SCG-CSO-AUP).
13. `it('falls back to org-profile.yaml when tracker narratives absent')` — no tracker rows; org-profile present → renders the org-profile narrative; provenance.sourceCalls includes `org-profile.yaml`.

## REO compliance specific to this slice

- Every setting value in the baseline traces to: reference-arch (real SDK observation captured at scan time), control-benchmark (FedRAMP-published parameter), or operator (tracker / `org-profile.yaml`). No fabricated security defaults.
- The baseline is signed; the comparator round-trips the same bytes back for the drift check, so the very baseline we publish is the one our drift detector consumes.
- FIPS module IDs are pulled from `providers/*/crypto.ts` — which already only emits real, observed FIPS module IDs (not literal example strings).
- Operator narrative is REQUIRES-OPERATOR-INPUT when missing — never a fake "TBD" string. `ready_for_signature` flips false.
- `provenance.requirementTexts` carries the verbatim SCG-CSO-RSC + SCG-CSO-AUP statements.
- The `.docx` "Customer Support Contact" is operator-supplied or REQUIRES-OPERATOR-INPUT; never substitutes "support@example.com" (REO Rule 1.3).
- Signed by: existing `core/sign.ts` Ed25519 + RFC 3161 pipeline.
- No `if (process.env.NODE_ENV === 'test')` branches (REO Rule 1.8).

## Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/afr-scg.test.ts
npm test -- tracker/server/routes/afr-scg.test.ts
npm test -- tracker/client/src/pages/ScgNarratives.test.tsx
npm run check:reo
```

End-to-end smoke:
```bash
npm run collect -- --impact-level moderate --afr-scg --submission-bundle --sign
ls -la out/afr-scg/
node -e "const b=JSON.parse(require('fs').readFileSync('out/afr-scg/scg-baseline.json','utf8')); console.log(Object.keys(b.settings).length, 'settings')"
```

## Known risks / issues

- **Risk 1: FIPS module ID churn.** CMVP retires modules to "Historical" periodically; if the baseline asserts a Historical module the customer is misled. *Mitigation*: `getFipsValidatedModuleIds()` carries a `status: 'active'|'historical'` field; SCG emitter raises a high-severity diagnostic when any baseline module is historical; operator runbook covers the rotation procedure.
- **Risk 2: Reference-arch outputs diverge per provider over time.** AWS may report `cloudtrail.multi_region: 'enabled'` while GCP reports `logging.organization_sink: 'enabled'`. Naming divergence makes the merged baseline awkward. *Mitigation*: prefix every key with provider (`aws.`, `gcp.`, `azure.`); cross-cloud "abstract" settings (e.g. `boundary.multi_region_audit_log`) come exclusively from the control-benchmark overlay.
- **Risk 3: OOXML rendering at scale.** A baseline with 300+ settings becomes a wall of tables. *Mitigation*: §4 renders as collapsible subsection per provider; `--scg-truncate-tables N` flag adds a "see machine-readable baseline.json for full list" footer.
- **Risk 4: Customer-facing narrative drift.** Operator updates `customer_support_contact` in tracker but the published guide URL points at the old version. *Mitigation*: version-history section in §7 + sha256 of every published version; use-instructions.md prints the current sha256 so customers can verify.
- **Risk 5: OSCAL Component Definition mapping mismatch.** §4 maps imperfectly to OSCAL Component Definition model (per LOOP-G-SPEC.md §6 open question 3). *Mitigation*: ship the flat baseline JSON now; defer OSCAL CD emission to a follow-up gated by `--scg-oscal` flag.
- **Risk 6: PDF rendering on Linux servers without Word.** Some operators want PDF, not `.docx`. *Mitigation*: defer to LOOP-E.E1 pure-JS PDF emitter when available; document the `libreoffice --headless --convert-to pdf` fallback in runbook.
- **Risk 7: SCG-CSO-AUP placement.** SCG-CSO-AUP requires instructions in the authorization package — `use-instructions.md` is the artifact, but the submission-bundle catalogue must include it. *Mitigation*: bundle entry `afr-scg-use-instructions` `required: true` + INDEX.json carries the explicit SCG-CSO-AUP role tag.

## Open questions (for implementation session to resolve)

- **Q1**: Should `scg-baseline.json` include both expected AND observed values, or only expected? Recommendation: expected only — the comparator's output file (`scg-drift.json`) is where observed is reported, separating publication from drift.
- **Q2**: How do we handle multi-cloud customers running only one provider? Recommendation: `--scg-provider aws,gcp` flag filters; default emits all 3 sections, missing provider section says "Not deployed".
- **Q3**: Do we emit a JSON Schema (Draft 2020-12) for `ScgBaseline`? Recommendation: yes, emit alongside under `out/afr-scg/scg-baseline.schema.json` so customer 3PAOs can ajv-validate.
- **Q4**: Should `version` be auto-bumped per emit or operator-managed? Recommendation: auto-bumped to `YYYY.MM` per emit; operator can override via `--scg-version`; archive retains every version.
- **Q5**: Where does the published guide actually live? Recommendation: operator hosts on Trust Center (per ADS-CSX-UTC); use-instructions.md links there. The submission bundle includes a local copy as the authorization-package artifact.
- **Q6**: When operator changes a narrative mid-period, do we re-emit the .docx or wait for next scheduled run? Recommendation: tracker UI has a "Generate now" button calling the orchestrator with `--afr-scg` only; full submission bundle waits for next scheduled run.
- **Q7**: How do we handle FedRAMP-restricted appendices (e.g. ITAR-controlled crypto details)? Recommendation: opt-in via `--scg-include-restricted` flag; default excludes them and use-instructions.md links to a separate restricted bundle.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ~16 for this slice: 13 unit + 3 route/UI)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section: increment next-priority to G.G6)
- [ ] LOOP-G-SPEC.md §7 status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-G.G5: AFR-SCG (Secure Configuration Guide)`
- [ ] Commit with `LOOP-G.G5:` in message
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-G-SPEC.md
- [ ] Pushed to origin/main
- [ ] AFR-SCG-RUNBOOK.md authored
- [ ] End-to-end orchestrator smoke produces all 3 `out/afr-scg/` artifacts + manifest entries + comparator round-trip passes

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context, here's everything it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-G-SPEC.md` §2 (Dependencies) + §4 G.G5 + §6 caveats.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory commit pattern.
5. Read `cloud-evidence/core/roe-emit.ts` + `core/ssp-docx.ts` for the dependency-free .docx + OOXML body pattern.
6. Read `cloud-evidence/core/zip.ts` for the `zipStore` helper used by `.docx` emit.
7. Read `cloud-evidence/core/scg-comparator.ts` for the `ScgBaseline` shape we produce + round-trip into.
8. Read `cloud-evidence/providers/aws/reference-arch.ts` (and gcp/azure equivalents) for the source reference-architecture data we consume.
9. Read `cloud-evidence/providers/aws/crypto.ts` (and gcp/azure equivalents) for the FIPS module list shape.
10. Read `cloud-evidence/core/control-benchmark.ts` for the FedRAMP Moderate parameter overlay shape.
11. Read `cloud-evidence/core/submission-bundle.ts` for catalogue-row pattern.
12. Begin implementation; update Implementation log section as you go.
