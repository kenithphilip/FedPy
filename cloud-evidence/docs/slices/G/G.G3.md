---
slice_id: G.G3
title: AFR-ADS (Authorization Data Sharing)
loop: G
status: pending
commit: —
completed_date: —
depends_on: [LOOP-A.A1, LOOP-A.A2, LOOP-A.A3, LOOP-A.A4, REO-0]
blocks: [LOOP-F.F7, LOOP-H.H2, LOOP-I.I1]
estimated_effort: 5 days
last_updated: 2026-06-06
---

# G.G3 — AFR-ADS (Authorization Data Sharing)

## TL;DR
Generates the public + machine-readable cloud-service-offering data the CSP must publish
per ADS-CSO-PUB, ADS-CSO-CBF, ADS-CSO-SVC, ADS-CSO-RIS, ADS-CSO-HAD, plus a 3-year
historical archive structure. Wraps the existing `core/ads-probe.ts` URL pass-list into
real artifact generation (the probe stays for consistency verification).

## Status
- Status: pending
- Commit: —
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
ADS-CSO-PUB enumerates 13 specific fields the CSP must publish in both human and
machine-readable forms (already enumerated in `core/ads-probe.ts:ADS_CSO_PUB_FIELDS`).
ADS-CSO-CBF requires automation that guarantees the two formats remain consistent.
ADS-CSO-SVC requires a customer-self-service service list. ADS-CSO-HAD requires a
3-year historical archive. ADS-CSX-UTC requires that all of this lives behind a
FedRAMP-compatible trust center.

Today the probe only verifies that the URLs return the expected bytes; it does NOT
*generate* those bytes. G.G3 generates + archives them. Without G.G3 the CSP has no
defensible published service list, no machine-readable counterpart to its marketing site,
and no audit trail of authorization-data history. NIST SP 800-53 Rev5 §CA-2 (Control
Assessments) §CA-3 (Information Exchange) frame the underlying disclosure obligations.

## Authoritative sources (with verbatim quotes)

- https://www.fedramp.gov/rfcs/0024/ — FedRAMP RFC-0024 "Machine-Readable Submissions":
  > "FedRAMP requires machine-readable submissions in OSCAL JSON format for all
  > authorization artifacts to enable automated validation and continuous monitoring."
  (Context: §"Machine-Readable Format Obligation", retrieved 2026-06-06.)

- https://github.com/FedRAMP/docs (FRMR.documentation.json v0.9.43-beta, ADS-CSO-PUB / FRR-ADS-01):
  > "Providers MUST publicly share up-to-date information about the cloud service offering
  > in both human-readable and machine-readable formats, including at least: [13-field
  > checklist enumerated in FRMR sub-bullets]."

- https://github.com/FedRAMP/docs (ADS-CSO-CBF / FRR-ADS-02):
  > "Providers MUST use automation to ensure information remains consistent between
  > human-readable and machine-readable formats when authorization data is provided in
  > both formats."

- https://github.com/FedRAMP/docs (ADS-CSO-SVC / FRR-ADS-03):
  > "Providers MUST publicly share a detailed list of specific services and their security
  > objectives that are included in the cloud service offering using clear feature or
  > service names that align with standard public marketing materials; this list MUST be
  > complete enough for a potential customer to determine which services are and are not
  > included in the FedRAMP Minimum Assessment Scope without requesting access to
  > underlying authorization data."

- https://github.com/FedRAMP/docs (ADS-CSO-RIS / FRR-ADS-05):
  > "Providers MUST provide sufficient information in authorization data to support
  > authorization decisions but SHOULD NOT include sensitive information that would likely
  > enable a threat actor to gain unauthorized access, cause harm, disrupt operations, or
  > otherwise have a negative adverse impact on the cloud service offering."

- https://github.com/FedRAMP/docs (ADS-CSX-UTC / FRR-ADS-07):
  > "Providers MUST use a FedRAMP-compatible trust center to store and share authorization
  > data with all necessary parties."

- https://github.com/FedRAMP/docs (ADS-CSO-HAD / FRR-ADS-09):
  > "Providers MUST make historical versions of authorization data available for three
  > years to all necessary parties UNLESS otherwise specified by applicable FedRAMP
  > requirements; deltas between versions MAY be consolidated quarterly."

- https://pages.nist.gov/OSCAL/concepts/layer/implementation/component-definition/ —
  OSCAL v1.1.2 Component Definition Model:
  > "A Component Definition contains one or more Components, each representing a software
  > or system element with control-implementation statements."
  Used for the service-list back-matter component references.

- https://www.fedramp.gov/marketplace/ — FedRAMP Marketplace (canonical CSO listing):
  > "Each authorized service maintains a Marketplace listing with status, agency users,
  > and service description."
  Used for the `marketplace_url` field validator and per-CSO link.

- https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — NIST SP 800-53 Rev5 §CA-3
  Information Exchange and §CA-7 Continuous Monitoring. Pp. 75-84. Underlying control
  basis for publishing authorization data + continuous validation.

- https://www.rfc-editor.org/rfc/rfc3339 — RFC 3339 "Date and Time on the Internet":
  used for `published_at` + `retention_expiry` timestamps.

## Files to create (exact paths)

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/afr-ads.ts` — pure builders:
  - `buildServiceListJson(input): ServiceListJson`
  - `buildPublicInfoMarkdown(input): string`
  - `buildAuthorizationDataPacket(input): AuthorizationDataPacket`
  - `consistencyCheck(humanMd, machineJson): ConsistencyDiff`
  - `archivePeriod(outDir, period): string` (writes period-stamped dir)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/afr-ads.test.ts` — ≥12 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/AFR-ADS-RUNBOOK.md` — operator runbook for Trust-Center linkage + 3-year retention enforcement (ties into LOOP-H.H2).

## Files to extend

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ads-probe.ts` — add `verifyPublishedMatchesLocal(localServiceListPath, publicUrl): Promise<DiffReport>` that probes the public URL and diffs against the local artifact. Closes ADS-CSO-CBF.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — `--afr-ads` flag + `CLOUD_EVIDENCE_AFR_ADS` env. Optionally probes public URLs (gated by `--afr-ads-probe-public` to skip in offline CI).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — catalogue rows for `afr-ads/service-list.json` (`role='afr-ads-service-list'`), `afr-ads/public-info.md` (`role='afr-ads-public-info'`), `afr-ads/historical-archive-index.json` (`role='afr-ads-archive-index'`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/subprocessors-sheet.ts` — extend to feed `subprocessor exposure` rows into the service list.

## Schemas / standards

### `ServiceListJson` (OSCAL-friendly machine-readable per ADS-CSO-SVC)

```
$schema: 'https://fedramp.gov/schemas/afr-ads/service-list/2026.json'
system_id: string                                              # from SSP
csp_name: string
marketplace_url: string                                        # REQUIRES-OPERATOR-INPUT
service_model: 'SaaS'|'PaaS'|'IaaS'                            # from SSP system-implementation
deployment_model: 'public'|'government-community'|'private'|'hybrid'
services: Array<{
  name: string
  description: string
  service_model: 'SaaS'|'PaaS'|'IaaS'
  in_minimum_assessment_scope: boolean
  security_objectives: { confidentiality: 'Low'|'Moderate'|'High'; integrity; availability }
  underlying_components: string[]                              # component UUIDs from SSP
  marketing_url: string
}>
oar_next_target_date: ISOString                                # from G.G6
quarterly_review_registration_url: string                      # from G.G6
published_at: ISOString
provenance: { emitter, sourceCalls, requirementTexts, runId }
```

Determinism: `services[]` sorted by `name` ASC; RFC 3339 timestamps with seconds precision.

### `AdsPublicInfoMarkdown` shape — 13 sections matching `core/ads-probe.ts:ADS_CSO_PUB_FIELDS` exactly:

1. CSO name + Marketplace URL
2. CSP legal entity
3. Service model + deployment model
4. Impact level + authorization status
5. Authorization date + 3PAO of record
6. Service description (customer-facing)
7. Geographic boundaries (data residency)
8. Subprocessor list (link to subprocessors-sheet)
9. SLAs + uptime targets
10. Customer responsibilities
11. Authorization scope (Minimum Assessment Scope, link to G.G4)
12. OAR cadence + Next-OAR target date (link to G.G6)
13. Quarterly Review registration link / .ics download (link to G.G6)

### Historical-archive layout

```
out/afr-ads/historical-archive/
  <YYYY-MM>/
    service-list.json
    public-info.md
    sha256.txt           # SHA-256 of both files concatenated
out/afr-ads/historical-archive-index.json
  [
    { period: 'YYYY-MM', published_at: ISO, retention_expiry: ISO (+3 years per ADS-CSO-HAD), sha256: string }
  ]
```

Append-only invariant: old rows in `historical-archive-index.json` are never rewritten.

## Build steps (concrete, numbered)

1. Define interfaces. Determinism: sort `services[]` by name ASC; ISO timestamps RFC 3339 seconds.
2. Pure `buildServiceListJson(input)` — pulls services from SSP `system-implementation.components[]` filtered by inventory tag `customer_facing=true` OR tracker UI flag.
3. Pure `buildPublicInfoMarkdown(input)` — renders the 13 sections verbatim from `ADS_CSO_PUB_FIELDS`; each section header matches the field key for trivial consistency diff.
4. Pure `consistencyCheck(humanMd, machineJson): { ok, missing_from_md, missing_from_json }` per ADS-CSO-CBF.
5. Pure `buildAuthorizationDataPacket(input)` — combines service list + public info + SSP/AP/POA&M metadata into a snapshot JSON.
6. Disk emitter `emitAfrAds(outDir, ctx)`:
   - Build 3 artifacts.
   - Run `consistencyCheck`; reject in `--strict-bundle` mode on inconsistency.
   - Write to `out/afr-ads/`.
   - Append to `out/afr-ads/historical-archive/<YYYY-MM>/` (idempotent; same-period rewrite OK).
   - Update `out/afr-ads/historical-archive-index.json` (append-only).
7. Optional public-URL probe via extended `ads-probe.ts`; output `published-vs-local-diff.json`.
8. Orchestrator wiring + submission-bundle catalogue.
9. Validation: JSON schema check (hand-rolled validator in `afr-ads.ts:validateServiceListJson`); markdown section-header check.
10. Sign+timestamp via `core/sign.ts`.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | What happens when missing |
|---|---|---|
| `marketplace_url` | CLI `--marketplace-url` or `CLOUD_EVIDENCE_MARKETPLACE_URL` env | section 1 emits REQUIRES-OPERATOR-INPUT |
| `services[].marketing_url` | inventory tag `customer_marketing_url` OR tracker UI per-component | per-service REQUIRES-OPERATOR-INPUT row |
| `services[].security_objectives.{c,i,a}` | SSP system-information aggregated; OR inventory tag `cia_{level}` | REQUIRES-OPERATOR-INPUT when ambiguous |
| `quarterly_review_registration_url` | G.G6 scheduler | section 13 REQUIRES-OPERATOR-INPUT when G.G6 not yet emitted |
| `oar_next_target_date` | G.G6 scheduler | section 12 REQUIRES-OPERATOR-INPUT when G.G6 not emitted |
| `trust_center_url` (per ADS-CSX-UTC) | CLI `--trust-center-url` | catalogue row gap reported |

## Test specifications (≥12 tests)

1. `it('builds service list JSON with sorted services from SSP components')` — determinism + sort order.
2. `it('only includes components flagged customer_facing=true')` — filter behavior.
3. `it('emits REQUIRES-OPERATOR-INPUT for marketplace_url when missing')`.
4. `it('renders the 13 ADS-CSO-PUB fields in the public info markdown')` — every key in `ADS_CSO_PUB_FIELDS` appears as a section header.
5. `it('passes consistency check when md mentions every service in json and vice versa')`.
6. `it('detects services in md missing from json')` — flag-and-fail.
7. `it('detects services in json missing from md')`.
8. `it('archives a per-period snapshot under historical-archive/<YYYY-MM>/')`.
9. `it('appends to historical-archive-index.json without rewriting old rows')` — append-only invariant.
10. `it('computes retention_expiry as published_at + 3 years exactly')` — per ADS-CSO-HAD.
11. `it('records provenance.requirementTexts for all 6 ADS MUSTs')`.
12. `it('verifyPublishedMatchesLocal flags drift between local artifact and public URL')` — probe diff (injected fake fetch).
13. `it('rejects emit when consistency check fails and --strict-bundle is set')`.
14. `it('handles same-period re-run idempotently — sha256.txt matches')`.

## REO compliance specific to this slice

- Service list mirrors real SSP components — no fabricated services.
- 13 public-info fields are operator-supplied OR auto-derived from SSP; never placeholder marketing text.
- Consistency-check enforces ADS-CSO-CBF: any disagreement between markdown + JSON is surfaced as a finding (not silently reconciled).
- Historical-archive entries are append-only + sha256-locked; cannot be retroactively modified.
- Provenance fields populated: `emitter`, `emittedAt`, `sourceCalls`, `requirementTexts` (6 MUSTs), `runId`.
- Signed by: `core/sign.ts`.

## Verification commands

```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/afr-ads.test.ts
npm run check:reo
# Optional public probe (skip in CI):
# npm run collect -- --afr-ads --afr-ads-probe-public
```

## Known risks / issues

- **Risk 1 — 3-year retention enforcement is LOOP-H.H2.** G.G3 stamps `retention_expiry` but does not enforce immutability. Mitigation: documented in §6 of LOOP-G-SPEC; runbook explains the operator must run LOOP-H.H2 archive enforcement separately.
- **Risk 2 — Trust-Center vs USDA Connect choice.** ADS-CSX-UTC requires a "FedRAMP-compatible trust center"; the CSP can use USDA Connect.gov or a vendor Trust Center. Mitigation: `--trust-center-url` flag supports both; artifact shape identical.
- **Risk 3 — Consistency drift between local + published.** Operator can publish via CDN cache; probe may see stale bytes. Mitigation: `verifyPublishedMatchesLocal` reports drift but does not auto-republish; runbook describes cache-purge process.
- **Risk 4 — Sensitive info leak in public artifacts (ADS-CSO-RIS).** Operator may inadvertently include internal IPs or credentials. Mitigation: redaction reviewer (LOOP-J.J2) reviews before publish; `afr-ads.ts:scrubSensitive(input)` runs a pre-publish scan for IPv4 / private CIDR / API key patterns and emits a warning.
- **Risk 5 — Marketplace URL canonicalization.** FedRAMP Marketplace URLs may include tracking params; consistency check should normalize. Mitigation: validator strips query params before comparison.
- **Risk 6 — Period overlap.** Quarterly consolidation per ADS-CSO-HAD ("deltas MAY be consolidated quarterly") is currently implemented as monthly. Mitigation: monthly periods are a strict superset of quarterly; consolidation script can be added later.

## Open questions (for implementation session to resolve)

- **Q1**: For `services[].underlying_components`, do we emit component UUIDs from SSP OR a flat name string? Recommendation: UUIDs (back-matter reference) + a `name` alias for human readability.
- **Q2**: Markdown rendering — strict CommonMark or extended (tables, footnotes)? Recommendation: CommonMark + GFM tables (widely supported by GitHub Pages / FedRAMP Marketplace).
- **Q3**: Should `consistencyCheck` allow case-insensitive service-name matching? Recommendation: case-sensitive (matches FedRAMP's "clear feature or service names that align with standard public marketing materials" wording).
- **Q4**: For `published_at` granularity, do we use seconds or just date? Recommendation: seconds (RFC 3339); makes archive directory uniqueness clearer.
- **Q5**: When G.G6 is not yet shipped, do we hard-fail or emit REQUIRES-OPERATOR-INPUT for `oar_next_target_date`? Recommendation: emit marker; G.G3 is parallel-safe with G.G6.
- **Q6**: Is `quarterly_review_registration_url` distinct from `meeting_info.url`? Recommendation: distinct — `registration_url` is for external attendees; `meeting_info.url` is the actual conf link.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

- [ ] typecheck clean
- [ ] tests passing (+~14)
- [ ] check:reo green
- [ ] STATUS.md updated (slice row + next-priority = G.G4)
- [ ] LOOP-G-SPEC.md §7 status table updated
- [ ] This file's frontmatter updated
- [ ] CHANGELOG.md "Unreleased" entry added under `### Added — LOOP-G.G3: AFR-ADS (Authorization Data Sharing)`
- [ ] Commit with `LOOP-G.G3:` in message
- [ ] Commit amended with hash
- [ ] Pushed to origin/main
- [ ] AFR-ADS-RUNBOOK.md authored
- [ ] End-to-end orchestrator smoke produces `out/afr-ads/service-list.json`, `out/afr-ads/public-info.md`, `out/afr-ads/historical-archive/<YYYY-MM>/`, `out/afr-ads/historical-archive-index.json`.

## Resume-from-fresh-session checklist

1. Read `cloud-evidence/CLAUDE.md`.
2. This file is the entry point.
3. Read `cloud-evidence/docs/loops/LOOP-G-SPEC.md` §4 (Slice G.G3).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`.
5. Read `cloud-evidence/core/ads-probe.ts` — already implements the 13-field probe pass-list; extend it.
6. Read `cloud-evidence/core/submission-bundle.ts` for catalogue-row pattern.
7. Read `cloud-evidence/core/sign.ts` for the signing wrapper.
8. Read `cloud-evidence/core/inventory-coverage.ts` for the coverage contract pattern (replicate for archive coverage).
9. Read `cloud-evidence/core/subprocessors-sheet.ts` to understand the subprocessor exposure feed.
10. Begin implementation; update Implementation log as you go.
