# LOOP-W — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status=resolved` + resolution note.
> Severity: high = ship-blocking; med = should fix in-loop; low = file
> as follow-up.

> Authoritative companion to `docs/loops/LOOP-W-SPEC.md` and the
> per-slice docs at `docs/slices/W/W.W[1-4].md`. Read those for context
> before acting on any risk here.

> **UNIVERSAL APPLICABILITY**: LOOP-W applies to **every** CSP whose
> authorization package will be evaluated under FedRAMP 20x — civilian
> or DoD. The `--prohibited-vendor-screen` flag is a CI-friendly knob
> for development; the production orchestrator emits W.W1..W.W4 in every
> FedRAMP 20x submission build. There is no opt-out at the regulation
> level — FAR 52.204-25 + 52.204-26 are Government-wide clauses
> incorporated by reference into every Federal solicitation. Every risk
> below activates unconditionally for any CSP holding even one Federal
> contract or grant.

> Last updated: 2026-06-07.

---

## Table of Contents

- [Cross-cutting risks (apply to ALL slices in LOOP-W)](#cross-cutting-risks-apply-to-all-slices-in-loop-w)
  - Catalog & data-source drift (W-X1..W-X9)
  - Catalog correctness & matching (W-X10..W-X17)
  - Reporting clock & calendar (W-X18..W-X22)
  - Signing, provenance, tamper-evidence (W-X23..W-X27)
  - Operator workflow & submission ecosystem (W-X28..W-X33)
  - Cross-loop interaction (W-X34..W-X38)
  - Legal / regulatory boundary (W-X39..W-X43)
- [Per-slice risks](#per-slice-risks)
  - W.W1 — Catalog ingester
  - W.W2 — Subprocessor + SBOM + OCI screen
  - W.W3 — 1-business-day reporter
  - W.W4 — Annual representation
- [External dependencies that may change](#external-dependencies-that-may-change)
- [Resolved risks (historical)](#resolved-risks-historical)
- [Resume-from-fresh-session checklist](#resume-from-fresh-session-checklist)

---

## Cross-cutting risks (apply to ALL slices in LOOP-W)

### W-X1 — OFAC SDN list update cadence (daily, sometimes intra-day)

- **Description**: Treasury OFAC updates the SDN list as designations
  are issued — typically daily, sometimes multiple times per day on
  high-volume sanctions days (e.g. major Russia/Iran/PRC actions).
  Treasury does NOT publish on a fixed cadence. A snapshot more than
  24 hours old MAY miss a newly-designated entity that the operator's
  subprocessor or transitive SBOM dependency just connected to.
  Adversarial timing: a vendor newly designated overnight begins to
  flow data through the CSP environment at 06:00 ET; without a fresh
  catalog, W.W2 fails to detect.
- **Severity**: high (correctness + reporting-clock impact).
- **Mitigation**: W.W1's `scripts/extract-prohibited-vendors.mjs` is
  idempotent and re-runnable; a recommended GitHub Actions cron at
  `0 */6 * * *` (every 6 hours) re-runs the extractor and re-signs the
  snapshot. The orchestrator strict mode (`--strict-prohibited-vendors`)
  refuses to run if the loaded snapshot's `signed_at` is more than 24h
  old. Tracker UI surfaces `catalog_age_hours` prominently.
  CHANGELOG entry per snapshot run captures the count delta vs prior
  snapshot.
- **Status**: open.

### W-X2 — BIS Entity List Federal-Register-only updates (monthly cadence)

- **Description**: The BIS Entity List (15 CFR Part 744 Supp. 4)
  changes through Federal Register final rules — typically once per
  month but sometimes 2-3 updates per month during heightened
  sanctions activity. Trade.gov's Consolidated Screening List (CSL)
  API mirrors the Entity List but with a documented 1-3 day lag from
  Federal Register publication.
- **Severity**: med (slower cadence than SDN but still material).
- **Mitigation**: W.W1 pulls both the CSL JSON API (fast path) AND the
  Federal Register RSS feed (`https://www.federalregister.gov/agencies/industry-and-security-bureau/`)
  to detect the lag window. The snapshot records both sources with
  per-source `last_observed_at`; tracker UI alerts when CSL_last_seen
  > FR_last_seen + 5 days. CHANGELOG entry per Entity List delta.
- **Status**: open.

### W-X3 — SAM.gov Exclusions hourly refresh + auth churn

- **Description**: SAM.gov publishes the Public Exclusions feed
  hourly via `api.sam.gov/entity-information/v3/exclusions`, but the
  API requires a SAM-registered API key that must be renewed (operator
  side) every 90 days. A lapsed key → empty exclusions delta → false
  negatives. The bulk-download ZIP fallback exists but lags by up to
  24 hours.
- **Severity**: high (auth lapse → silent screening gap).
- **Mitigation**: W.W1 records `sam_api_key_expires_at` (operator
  supplies via `prohibited-vendors-config.yaml`); orchestrator emits
  warning at T-30 days, T-7 days, and refuses to run at T-0. Strict
  mode exits non-zero if SAM API key is missing or expired. Fallback
  to bulk ZIP is automatic; the operator is told. Future enhancement:
  W.W1 could expose `key_expires_at` to the tracker UI for a banner.
- **Status**: open.

### W-X4 — OFAC bulk endpoint URL drift (`treasury.gov` → `ofac.treasury.gov`)

- **Description**: Treasury has migrated OFAC content between
  `treasury.gov/ofac/downloads/` and `ofac.treasury.gov` multiple
  times since 2014. Either canonical URL could redirect, 404, or be
  permanently moved. W.W1's hard-coded fetch URLs would silently fail
  on URL drift (HTTP 404 returns "Not Found" body but ajv-style parser
  could mistake it for an empty SDN feed).
- **Severity**: high (silent failure mode).
- **Mitigation**: W.W1 hits the OFAC `/downloads/` index page first to
  verify the publicly-listed URLs for `sdn_advanced.xml`, `sdn.xml`,
  `sdn.csv`, `add.xml`, `alt.xml`; mismatch → REQUIRES-OPERATOR-INPUT
  diagnostic. Extractor asserts `record_count >= 5000` (current SDN is
  ~12,000 entries; a sudden drop below 5,000 indicates a parsing or
  URL failure, not a real list change). CI cron re-verifies endpoint
  reachability daily; PagerDuty + Slack notification on regression.
- **Status**: open.

### W-X5 — OFAC schema migration sdn.xml → sdn_advanced.xml

- **Description**: Treasury has signalled long-term deprecation of
  the legacy `sdn.xml` in favour of `sdn_advanced.xml`. The two
  schemas differ materially: `sdn_advanced.xml` uses `<DistinctParty>`
  + `<Profile>` + `<Identity>` nodes whereas legacy uses flat
  `<sdnEntry>`. A schema migration would break W.W1's XML parser
  silently (zero entities → empty catalog → false negatives).
- **Severity**: high.
- **Mitigation**: W.W1 supports both schemas via parser
  multiplexing (detect root element); per-parser unit tests with
  pinned XML fixtures; CHANGELOG entry per schema bump; strict mode
  asserts `entities_parsed >= entities_in_prior_snapshot * 0.5` (50%
  floor — a legitimate Treasury action can remove ~hundreds of
  entries, but not >50% in one shot).
- **Status**: open.

### W-X6 — SAM.gov Public Exclusions API v3 → v4 migration

- **Description**: SAM.gov has historically deprecated API versions
  with 6-12 months notice. A v3 → v4 migration would require code
  changes to W.W1's fetch logic. The migration could change the
  `exclusionType` enum values, the date format, or the pagination
  scheme.
- **Severity**: med (announced in advance; not a silent failure).
- **Mitigation**: W.W1 pins `api_version: 'v3'` in
  `prohibited-vendors-config.yaml`; CHANGELOG documents when v4
  shipping; per-version parser kept in `core/sam-exclusions-parser.ts`
  with `version` discriminator. Operator runbook lists SAM
  deprecation-policy URL for monitoring.
- **Status**: open.

### W-X7 — BIS Consolidated Screening List API trade.gov key revocation

- **Description**: The `api.trade.gov` API key is free but issued
  per-developer. The Department of Commerce reserves the right to
  revoke keys for unspecified misuse. A revocation → W.W1 falls back
  to bulk CSV → 24-48h staleness.
- **Severity**: low (fallback path exists).
- **Mitigation**: W.W1 records the response code on every fetch;
  401/403 from trade.gov → automatic fallback to bulk CSV download
  via `https://www.trade.gov/consolidated-screening-list` URL;
  operator notified via tracker banner. CHANGELOG entry per key
  rotation.
- **Status**: open.

### W-X8 — Federal Register URL stability for FAR final-rule citations

- **Description**: W.W3's `.docx` and W.W4's annual representation
  cite the Federal Register URLs for the FAR 52.204-25 final rule
  (Aug 2019, July 2020) verbatim. The Federal Register has been
  stable since the GPO archived-content migration of 2008, but
  individual document URLs have occasionally been remapped. A 404 on
  these citations in a printed report submitted to a Contracting
  Officer is embarrassing but not legally fatal.
- **Severity**: low.
- **Mitigation**: Citations include the FR doc number
  (e.g. `2019-17201`) which is permanent regardless of URL drift;
  the operator can search by doc number on
  `https://www.federalregister.gov/search`; CHANGELOG documents the
  citation forms.
- **Status**: open.

### W-X9 — Loss of catalog provenance (signature chain on the snapshot)

- **Description**: The snapshot file `data/prohibited-vendors-snapshot-YYYYMMDD.json`
  is signed Ed25519 by the catalog signing key. If the signing key
  rotates between snapshots without preserving the historical key in
  the registry, prior snapshots fail re-verification when a 3PAO
  audits historical screen runs. Same risk class as LOOP-R R-X4
  and LOOP-S S-X6.
- **Severity**: med (impacts 3PAO audit trail; not run-time blocker).
- **Mitigation**: Catalog signing keys go through the tracker's
  `GET /api/sign/public-keys` historical registry (inherit pattern
  from B-X3); every snapshot records `signing_key_id`; loader verifies
  against the registry. Operator runbook documents quarterly key
  rotation procedure. CHANGELOG entry per key rotation.
- **Status**: open.

### W-X10 — False-positive subprocessor match (similar-name collision)

- **Description**: A subprocessor with a name superficially similar
  to a covered entity — e.g. "Huawei Construction LLC" (a hypothetical
  unrelated US roofing company) or "Hytera Industrial Tools, Inc." —
  could be flagged by a naive substring match. False positives waste
  operator triage time, harm the legitimate subprocessor's reputation
  via internal records, and dilute the value of the screening signal.
  Adversarial: a competitor could falsely brand their subprocessor
  with a covered-entity look-alike token to harm the CSP's signal.
- **Severity**: high (operator trust + 3PAO confidence).
- **Mitigation**: W.W2's `core/prohibited-vendors-screen.ts` uses a
  multi-factor scoring function: name token similarity + industry
  classifier signal + country-of-incorporation signal + provenance
  weight. Pure substring matches without supporting evidence score
  below 0.6 (low-confidence band); operator review required before
  the match becomes a POA&M finding. Tracker UI shows the full
  score breakdown so operators understand WHY a match scored low.
  Adversarial test A1 in `LOOP-W-SPEC.md §7.3` pins this case.
- **Status**: open.

### W-X11 — False-negative SBOM dependency match (transitive prohibited publisher)

- **Description**: A CSP's top-level npm/pip/Go module is
  innocuous, but a transitive dependency at depth 3-7 has a
  maintainer email or package-namespace owner that matches a covered
  entity. SBOM walkers that stop at depth 2 (a common default to
  bound runtime) would miss this. Real-world adversarial pattern:
  an obfuscated dependency chain that intentionally hides the prohibited
  publisher beyond conventional traversal depth.
- **Severity**: high (regulation-mandated screening gap).
- **Mitigation**: W.W2's `core/sbom-prohibited-screen.ts` walks the
  full SBOM graph (Syft / SPDX 2.3 / CycloneDX 1.5 representations)
  to bounded depth = 10 (configurable; default 10 covers >99.9% of
  real chains per LOOP-E.E2 instrumentation). On every walk, the
  match path is recorded in `match.dependency_chain[]` for audit.
  Adversarial test A3 pins depth-4 case. CHANGELOG entry calls out
  the configured depth limit per release.
- **Status**: open.

### W-X12 — OCI image publisher attribution ambiguity (signed vs. unsigned)

- **Description**: An OCI image's publisher claim can be (a) a
  cosign signature whose key fingerprint maps to a publisher
  identity (high trust), (b) a Rekor transparency-log subject identity
  (medium trust — depends on the OIDC provider), (c) an OCI manifest
  `authors` field (low trust — set by the image builder, no chain),
  or (d) nothing (the image is unsigned). LOOP-W.W2 must handle all
  four. Unsigned images from a registry pulled into the CSP build
  pipeline could carry a covered-entity publisher with no verifiable
  attribution either way.
- **Severity**: high (governance + regulation).
- **Mitigation**: W.W2's `core/oci-publisher-screen.ts` reads from
  the cosign+Rekor chain when present; falls back to OCI manifest
  fields with `provenance: oci-manifest-unverified`; for unsigned
  images, emits `REQUIRES-OPERATOR-INPUT: oci-publisher-unverified-<digest>`
  diagnostic and refuses to ship the screen unless the operator
  classifies the image. Adversarial test A4 pins the Rekor-fallback
  case. Cross-references LOOP-J.J3.b — if J.J3.b's cosign verification
  fails for any image, W.W2 fails closed (does NOT silently pass).
- **Status**: open.

### W-X13 — Trust-anchor compromise (cosign root key or Rekor compromise)

- **Description**: If the Sigstore root CA or Rekor signing
  infrastructure is compromised, W.W2's confidence in OCI publisher
  attribution collapses. This is a Sigstore-ecosystem risk that
  LOOP-W cannot remediate, but it must be handled gracefully.
- **Severity**: med (low likelihood; high impact).
- **Mitigation**: W.W2 records `cosign_root_fingerprint` and
  `rekor_endpoint_url` per attestation read; on any change since the
  prior snapshot, emits warning + operator review prompt. Cross-loop
  with LOOP-J.J3.b — the cosign verification chain is the trust root
  of both loops. Sigstore's transparency-log compromise would
  appear on `transparency.dev`; runbook documents how to manually
  verify against Sigstore TUF root.
- **Status**: open.

### W-X14 — Naming inconsistencies: SAM Exclusions vs BIS Entity List vs OFAC SDN

- **Description**: The same entity may be listed differently across
  lists. SAM Exclusions uses commercial-registration name; OFAC SDN
  uses transliterated legal name; BIS Entity List uses operating
  name. Example: "China State Shipbuilding Corporation, Limited"
  (SDN) vs "CSSC" (BIS Entity List, alias-only). A naive catalog
  that doesn't merge across lists would treat them as separate
  entities; alias collisions are possible (two different "CSSCs" in
  unrelated programs).
- **Severity**: high (catalog quality directly affects matching).
- **Mitigation**: W.W1's normalization layer assigns a canonical
  `entity_key` per record and merges across lists only when (a) all
  aliases align AND (b) at least one address or registration ID
  matches AND (c) operator-supplied `prohibited-vendors-merges.yaml`
  has not declared the entries distinct. Catalog records each merged
  source as a separate `provenance[]` array entry. Cross-reference
  fields are inspectable by 3PAO. Adversarial test A6 (alias-only
  match) pins case.
- **Status**: open.

### W-X15 — Transliteration coverage gap (Cyrillic, simplified-Chinese, Pinyin)

- **Description**: Covered entities are sometimes referenced with
  Cyrillic transliteration (e.g. "Хуавэй" in Russian sanctions-
  evasion documentation), simplified Chinese characters ("华为"),
  Pinyin ("Huawei"), or trade-romanizations. A subprocessor record
  in Cyrillic would not match an English-only catalog with a naive
  string comparator.
- **Severity**: high (real adversarial-evasion pattern).
- **Mitigation**: W.W2 applies Unicode NFKC normalization +
  transliteration via the canonical pinyin / Hepburn / GOST tables
  + ASCII-fold. Catalog entries pre-compute the
  `normalised_search_terms[]` for each entity at snapshot time so the
  comparator is fast. Adversarial test A2 pins Cyrillic case.
  Coverage table for transliterations under
  `cloud-evidence/docs/transliteration-table.md` (operator can extend).
- **Status**: open.

### W-X16 — Subsidiary / affiliate chain ambiguity (US-incorporated subsidiary of PRC parent)

- **Description**: FAR 52.204-25(a) includes "any subsidiary or
  affiliate" of the named entities. A US-incorporated Huawei
  subsidiary is still covered, but the operator may believe it's
  exempt because it's "a US company". Conversely, a sister-company
  with no ownership relation may be wrongly flagged because of
  surface-level association.
- **Severity**: high (legal correctness of representation).
- **Mitigation**: W.W1 carries `subsidiary_chain[]` per entity
  (parent → child relationships) sourced from (a) BIS Entity List
  remarks field (which often documents the relationship), (b) SAM
  Exclusions "additional comments", (c) operator-supplied
  `prohibited-vendors-overrides.yaml`. W.W2 traverses up to 5 levels
  (configurable). Match output includes the chain so operator can
  audit. Adversarial test A5 pins the subsidiary-of-subsidiary case.
  Runbook documents how operator can update the chain when new
  ownership data appears.
- **Status**: open.

### W-X17 — Alias-chain collision (two unrelated entities sharing an alias)

- **Description**: Two distinct entities can share an alias (e.g.
  "Sky Communications" — a covered entity's alias in one list, an
  unrelated US company in another). Merging by alias-only would
  cause false-positive matches against the unrelated entity. The
  inverse case is harder: an alias chain that legitimately should
  merge but has different addresses across lists.
- **Severity**: med.
- **Mitigation**: W.W1's `entity_key` merge rule requires (a) alias
  alignment + (b) at least one corroborating field (address /
  registration / nationality). When alias appears but no
  corroboration exists, W.W1 stores both entries with distinct
  `entity_key`s and a `potentially_related: [entity_key, ...]` field
  so W.W2 can warn the operator. Adversarial test A6 pins the
  alias-only case (positive-direction); a future test could pin the
  collision case.
- **Status**: open.

### W-X18 — 1-business-day clock missed due to weekend/holiday discovery

- **Description**: An incident discovered Friday 18:00 ET puts the
  reporting clock through Saturday + Sunday + Monday. If Monday is
  also a Federal holiday (e.g. Labor Day, MLK Day, Memorial Day,
  Indigenous Peoples'/Columbus Day, Veterans Day, Thanksgiving), the
  due time is the close of Tuesday. A naive 24h-arithmetic implementation
  would miss this.
- **Severity**: high (statutory compliance).
- **Mitigation**: W.W3's `core/section889-clock.ts` implements
  Federal business-day arithmetic per 5 U.S.C. §6103: 11 listed
  holidays + in-lieu-of rule (Saturday → preceding Friday; Sunday
  → following Monday) + agency-closure overrides. The clock is
  derived from the discovery timestamp (operator-supplied; defaults
  to the W.W2 match creation time). UI surfaces both `discovered_at`
  and `due_at` separately. Adversarial test A8 pins the Christmas
  Eve discovery case (Dec 24 17:55 → Dec 28 18:00 EST).
- **Status**: open.

### W-X19 — Federal holiday calendar drift (OPM updates, Presidential proclamations)

- **Description**: The 11 Federal holidays in 5 U.S.C. §6103(a)
  are statutory and stable. But OPM has historically issued
  one-off agency-closure proclamations (e.g. Inauguration Day for
  DC-area employees; National Day of Mourning for President Carter
  2025-01-09; weather-related closures). A new Federal holiday
  could be added by statute (Juneteenth was added in 2021). A
  hard-coded list would silently miss the new holiday.
- **Severity**: med.
- **Mitigation**: W.W3 carries `data/federal-holidays-YYYY.json`
  with statutory + observed dates per year, regenerated annually
  from the OPM page (`https://www.opm.gov/policy-data-oversight/pay-leave/federal-holidays/`).
  Operator can add agency-closure days via
  `prohibited-vendors-config.yaml federal_holiday_overrides[]`.
  Strict mode asserts the holiday data is no more than 365 days
  stale. CHANGELOG entry per annual data refresh. The data file is
  signed and tamper-evident.
- **Status**: open.

### W-X20 — Discovery-date misidentification (notification vs identification)

- **Description**: FAR 52.204-25(d)(1) starts the 1BD clock from
  "the date of such identification or notification" — but
  "notification" can be ambiguous. Did the clock start when the
  ticketing system flagged a possible covered-entity SBOM
  dependency? When the operator opened the ticket? When a
  subprocessor self-reported? An incorrect anchor could mean the
  report is late from the contracting officer's perspective.
- **Severity**: high (statutory).
- **Mitigation**: W.W3's tracker records BOTH `system_notified_at`
  (when the screening pipeline raised the finding) and
  `operator_acknowledged_at` (when an operator triaged the finding)
  and `due_at` (computed from the earlier of the two). The .docx
  shows all three timestamps. Operator runbook documents the FAR
  reading: identification = the moment the operator becomes aware,
  which in an automated pipeline is the system-notified moment.
  This is conservative: the report goes out on the tighter clock.
- **Status**: open.

### W-X21 — Time-zone errors in the 1BD calculation

- **Description**: "Business day" anchors to the contracting
  officer's time zone (often Eastern, sometimes Central or Pacific
  depending on the agency). A system computing in UTC could be off
  by hours, causing a missed deadline late on the apparent due
  date.
- **Severity**: high.
- **Mitigation**: W.W3 records `contracting_officer_tz` per affected
  contract in `section889-contacts.yaml`; default `America/New_York`
  if not specified; close-of-business is configurable per contract
  (default 17:00 in the CO's tz). Tracker UI countdown shows both
  the operator's local clock and the due-at in CO tz. Adversarial
  test pins a Pacific-tz discovery with an Eastern CO.
- **Status**: open.

### W-X22 — Catalog snapshot staleness vs incident clock

- **Description**: If a screen-time discovery uses a catalog
  snapshot from 5 days ago, and the entity was added to the SDN list
  3 days ago, the "discovery" event arguably should have happened 3
  days ago when the entity was added. A defensive auditor could argue
  the report is already late. The inverse: snapshot is current, but
  the catalog says the entity was added today — the report is on
  time.
- **Severity**: med (audit-trail clarity).
- **Mitigation**: W.W2 records both `match.catalog_snapshot_signed_at`
  and `match.catalog_entry_added_at` (per-source); the report
  documents the lag transparently. Operator runbook documents that
  the 1BD clock starts from the operator's actual identification, NOT
  the catalog-add date — but the report is transparent about both
  dates so the contracting officer can assess in context. Adversarial
  test A7 pins this case.
- **Status**: open.

### W-X23 — Tracker Ed25519 signing-key rotation on 1BD + annual records

- **Description**: W.W3 (1BD incidents + submissions) and W.W4
  (annual representation + officer sign-off) sign tracker records
  with the tracker-resident Ed25519 key. If the tracker rotates
  without preserving a historical key registry, prior snapshots fail
  verification when a 3PAO audits. Same risk class as LOOP-B-X3,
  LOOP-R-X4, LOOP-S-X6.
- **Severity**: med.
- **Mitigation**: Tracker exposes `GET /api/sign/public-keys`
  returning ALL historical public keys keyed by `key_id`; reader
  cross-references each record's `signing_key_id` against the
  registry. Inherits the B-X3 fix — if B-X3 ships first, W inherits.
  Rotation events written to `audit_log`; runbook documents
  procedure.
- **Status**: open.

### W-X24 — Repository tampering: the catalog snapshot file

- **Description**: The signed snapshot file is committed under
  `data/prohibited-vendors-snapshot-YYYYMMDD.json` in the
  cloud-evidence repo. An attacker with repo-write access could
  swap the file with a tampered version that omits the covered
  entity they want the CSP to use. The Ed25519 signature would
  catch the swap IF the verifier checks; a silent verifier
  bypass is the risk.
- **Severity**: high (security boundary).
- **Mitigation**: (1) Loader unconditionally verifies the snapshot
  signature on every load with no `skip-verify` flag — REO Rule 1
  forbids; CI guardrail rejects code that bypasses. (2) Each snapshot
  file includes `provenance.git_commit` of the cloud-evidence repo at
  signing time + the prior snapshot's hash → forms a hash chain.
  (3) CI cron re-verifies the latest snapshot's signature on every
  push to main; a verification failure pages the team. (4) The
  signing key is held in a hardware-security-module-backed location
  (operator runbook) so unsigned tampering is detectable.
  Adversarial test A10 pins the corrupted-signature case.
- **Status**: open.

### W-X25 — Provenance schema drift across new emit artifacts

- **Description**: W.W1 (`prohibited-vendors-snapshot-*.json`),
  W.W2 (`prohibited-vendors-screen-*.json` + POA&M findings), W.W3
  (`section889-1bd-report-*.json` + `.docx`), W.W4
  (`section889-annual-rep-*.json` + `.docx`) all emit with
  `provenance` blocks per REO Rule 2.6. A missed block fails
  `check:provenance`. Same class as B-X9, R-X9, S-X16.
- **Severity**: high.
- **Mitigation**: Per-slice test verifies provenance via
  `check:provenance`; pattern reused from `core/inventory-coverage.ts`;
  CHANGELOG entry per slice cites provenance contents.
- **Status**: open.

### W-X26 — REO Rule 1.8 `process.env.NODE_ENV === 'test'` branch creep

- **Description**: REO Rule 1.8 prohibits the literal in production
  code. New emitter signing paths, fetch-fallback code, and
  scheduling code are exactly where developers reach for the test-
  short-circuit. Same class as B-X6, R-X6, S-X15.
- **Severity**: high (REO violation; CI rejects).
- **Mitigation**: `scripts/lint-no-stubs.mjs` catches the literal;
  tests inject seams via dependency-injected HTTP fetcher + filesystem
  helper + clock; CI gate is non-bypassable.
- **Status**: open.

### W-X27 — Submission bundle role count growth + nested archive

- **Description**: LOOP-W adds 7+ new roles to
  `submission-bundle.ts:WELL_KNOWN`:
  `prohibited-vendors-snapshot-json`,
  `prohibited-vendors-screen-json`,
  `section889-1bd-report-bundle` (multi-file: per-contract docx + json
  + manifest),
  `section889-annual-rep-docx`,
  `section889-annual-rep-json`,
  `prohibited-vendors-config-yaml`,
  `prohibited-vendors-overrides-yaml`.
  Role collisions or filename collisions corrupt the bundle.
  Same class as S-X17.
- **Severity**: med.
- **Mitigation**: `tests/core/submission-bundle.test.ts` pins the
  full role table; per-slice tests assert presence; CHANGELOG entry
  for W.W4 (last slice) lists the final inventory.
- **Status**: open.

### W-X28 — Operator failing to sign FAR 52.204-26 annual representation in SAM.gov

- **Description**: W.W4 emits the artifact (`.docx` + signed JSON)
  but the operator must take it to SAM.gov to update the actual
  representation in their entity registration. Operators are notorious
  for letting SAM.gov representations lapse — the registration is
  renewed annually, and a missed renewal blocks the entity from
  receiving new awards. If the operator never logs in to SAM.gov
  to file the rep, the artifact gathers dust on the local disk.
- **Severity**: high (operational, not code).
- **Mitigation**: W.W4 includes a checklist .docx + an explicit
  reminder calendar entry generator (`.ics` file) for the SAM
  registration renewal date (registration date + 365 days). Tracker
  UI surfaces "SAM.gov rep last filed: <date>" prominently and emits
  warnings at T-60, T-30, T-7 days. Cross-loop with LOOP-Q.Q1 —
  Marketplace badge "Section 889 Compliant" requires evidence the
  SAM rep is current.
- **Status**: open.

### W-X29 — Confidentiality leak: the 1BD report contains contractor identifiers

- **Description**: The 1BD report includes contract number, order
  number, supplier name, UEI, CAGE code, and item descriptions. These
  are sensitive: a leaked report could expose contract relationships
  that the CSP would prefer to keep confidential. The report goes
  to the Contracting Officer via email by default — email is plaintext.
- **Severity**: high (operational confidentiality).
- **Mitigation**: W.W3's emitter places the .docx in
  `out/section889-reports/` (a directory that should be configured
  with restrictive ACLs); the operator submission step is documented
  in the runbook with a recommendation to use encrypted mail
  (S/MIME) or DoD SAFE (a DoD-operated encrypted file-transfer
  service). The tracker records `submission_channel` (email / DoD SAFE
  / portal) so the audit trail shows what channel was used. The
  runbook flags that the operator MUST coordinate with the CO on the
  preferred channel before sending. The JSON envelope is signed but
  not encrypted — that's a future enhancement.
- **Status**: open.

### W-X30 — DHS Section 889 reporting endpoint format change

- **Description**: A 2024 DHS S2 acquisition memo (referenced in
  acquisition literature) suggests DHS-wide §889 reporting may
  consolidate at a single endpoint. The endpoint URL, format
  (DOCX/PDF/JSON/portal-upload), and required fields may change.
  W.W3's `.docx` format is shaped to the FAR 52.204-25(d)(2)(i)
  text — if DHS publishes a new mandatory schema, W.W3 must update.
- **Severity**: med (open issue per `LOOP-W-SPEC.md §2.11`).
- **Mitigation**: W.W3 emits both .docx (human-readable) AND signed
  JSON (machine-readable). When DHS publishes the new schema, the
  JSON shape can be re-mapped; the operator runbook documents how
  to invoke `scripts/render-section889-report.mjs --schema dhs-2026`
  (placeholder; populated when DHS publishes). REQUIRES-RESEARCH
  ticket on `LOOP-W-SPEC.md §9`.
- **Status**: open.

### W-X31 — SAM.gov authentication flow change (login.gov vs PIV vs CAC)

- **Description**: SAM.gov authentication has migrated from in-system
  passwords → login.gov → in some cases PIV/CAC. A future flow change
  could break the operator's SAM submission workflow. W.W4 doesn't
  automate the SAM upload (REO Rule 4) but a flow change still
  affects the operator's runbook.
- **Severity**: low (out of LOOP-W's code path).
- **Mitigation**: Runbook references SAM.gov's official help page
  for current authentication; W.W4 emits the artifact + the
  operator submits manually; no automation runs.
- **Status**: open.

### W-X32 — Marketplace badge format change (LOOP-Q.Q1)

- **Description**: LOOP-Q.Q1 surfaces "Section 889 Compliant" badge
  by reading W.W4's signed annual-rep envelope. If Q.Q1's badge
  format changes (e.g. requires a new field like `attestation_id` or
  `marketplace_listing_id`), W.W4 may need to emit additional
  fields. Cross-loop with Q.Q1.
- **Severity**: low.
- **Mitigation**: The signed envelope is JSON; adding fields is
  backward-compatible; Q.Q1 reads named fields only. CHANGELOG entry
  per Q.Q1-required field addition.
- **Status**: open.

### W-X33 — Risk-acceptance workflow when discovered vendor cannot be removed in 1BD

- **Description**: An ideal compliance posture is: discover →
  remediate within the reporting window. Real life: discovering a
  Hikvision camera embedded in a third-party SaaS appliance, or a
  transitive npm dependency from a covered publisher, often takes
  weeks to remediate (replace the appliance, fork the npm package, or
  switch vendors). The 1BD report is filed *immediately* upon
  discovery, but the actual removal can take much longer.
- **Severity**: med.
- **Mitigation**: W.W3's report includes a `mitigation_plan` section
  for "what the operator is doing to remove" (paragraph
  (d)(2)(i) "any readily available information about mitigation
  actions undertaken or recommended"); a separate 10-business-day
  follow-up report (paragraph (d)(2)(ii)) carries the detailed plan.
  Tracker UI maintains a `remediation_progress` field per match. POA&M
  item picks up cycle-time SLA tracking via LOOP-B.B2. Runbook
  documents the dual-report cadence.
- **Status**: open.

### W-X34 — Cross-loop dependency: LOOP-E.E2 SBOM cosign verification failures

- **Description**: W.W2's `core/sbom-prohibited-screen.ts` reads
  the cosign-verified SBOM from LOOP-E.E2. If cosign verification
  fails (key expired, registry unreachable, attestation missing), the
  SBOM is untrusted. W.W2 must fail closed — not silently treat the
  SBOM as clean.
- **Severity**: high.
- **Mitigation**: W.W2 explicitly checks `sbom.verified === true`
  before walking; if not, emits `coverage:sbom-unverified-<image>`
  and refuses to ship a clean screen result. Strict mode exits
  non-zero. Cross-loop test integrates with LOOP-E.E2.
- **Status**: open.

### W-X35 — Cross-loop dependency: LOOP-J.J3 Rekor outage

- **Description**: W.W2's `core/oci-publisher-screen.ts` reads
  Rekor entries via the Sigstore transparency-log API. Rekor is a
  hosted service; an outage means OCI publisher provenance is
  unavailable. Pinning to the latest Rekor entry on disk via
  LOOP-J.J3's local cache is the fallback.
- **Severity**: med.
- **Mitigation**: W.W2 reads LOOP-J.J3.b's cached Rekor entries from
  the local artifact (`out/oci-attestations/`); when stale (>24h) +
  strict mode → exits non-zero; when not strict → marks the affected
  images with `provenance:rekor-stale` and the operator decides.
  Cross-loop runbook documents the fallback.
- **Status**: open.

### W-X36 — Cross-loop dependency: subprocessors-sheet schema change

- **Description**: W.W2's direct-relationship screen reads the
  vendor column from `core/subprocessors-sheet.ts` (Google Sheets
  reader). If the spreadsheet schema changes (column renamed, column
  dropped), W.W2 silently reads empty vendor data → false negative.
- **Severity**: med.
- **Mitigation**: W.W2 asserts the expected column names + minimum
  row count from `subprocessors-sheet.ts`; a schema change throws a
  typed error with remediation message. Cross-loop test pins the
  current schema. The shared schema is documented in
  `cloud-evidence/docs/subprocessors-sheet-schema.md` (operator
  updates when the sheet changes).
- **Status**: open.

### W-X37 — Cross-loop overlap with LOOP-D (DOS-bias) and LOOP-S (DFARS)

- **Description**: LOOP-D handles diagram auto-generation; not in
  conflict. LOOP-S handles DFARS 252.204-7012 (DoD-side cyber-incident
  + 800-171 equivalency) — also produces a "1-business-day"-class
  reporting flow but to DIBNet under DFARS, not under FAR §889. The
  two loops both emit reports for some overlap incidents (when a
  DoD-prime CSP discovers a covered-entity SBOM dependency that
  caused or contributed to a cyber-incident). Operators may confuse
  the two duties and skip one.
- **Severity**: med.
- **Mitigation**: Tracker UI surfaces both flows side-by-side with
  distinct labels ("FAR §889 1BD" vs "DFARS 7012 72h"). Tracker
  cross-links incidents that overlap (foreign-key relationship on
  `linked_section889_incident_id` in `dfars_incidents`). Runbook
  documents the distinct triggers + endpoints. Adversarial test
  pins a dual-trigger scenario.
- **Status**: open.

### W-X38 — Multi-tenant LOOP-W isolation deferred to LOOP-H.H3

- **Description**: All LOOP-W tracker tables omit a `tenant_id`
  column. When multi-CSO ships (H.H3), all need migration in a
  single cross-loop sweep. Same risk class as B-X15, R-X15, S-X21.
- **Severity**: med (long-tail).
- **Mitigation**: Documented in `LOOP-W-SPEC.md §6` Open Questions
  + the multi-tenant DEFER note in each per-slice doc; H.H3 spec
  must enumerate every LOOP-W table; LOOP-W ships in single-tenant
  deployments only (documented in runbook).
- **Status**: open.

### W-X39 — Waiver tracking misalignment (FAR 4.2104)

- **Description**: FAR 4.2104 lets the Office of the Director of
  National Intelligence (ODNI) issue waivers permitting otherwise-
  prohibited use. A CSP with a valid waiver should NOT have screen-
  failure POA&Ms emitted. LOOP-W does NOT currently model waivers
  (see `LOOP-W-SPEC.md §1.3` scope guard). Operators with waivers
  must manually suppress the finding, which is brittle.
- **Severity**: med (operator burden).
- **Mitigation**: Operator can suppress per-finding via
  `prohibited-vendors-overrides.yaml waivers[]` block; each waiver
  record includes `waiver_id`, `issuing_agency`, `expiration_date`,
  `scope_description`, and `operator_signature` (signed by the
  officer). W.W2 surfaces the waiver in the match record with
  `provenance: operator-waiver-<id>`. A future LOOP-W-Waivers loop
  could automate. Adversarial test A9 pins the override-conflict
  case (override CANNOT exempt a Federal-published entry without
  a waiver).
- **Status**: open.

### W-X40 — ITAR / EAR boundary confusion

- **Description**: ITAR (export control) and EAR (Commerce Control
  List) are separate regulations. LOOP-W does NOT screen against
  ITAR's prohibited-entities list (out of scope per
  `LOOP-W-SPEC.md §1.3`). An operator could mistakenly believe
  LOOP-W covers ITAR, leading to gaps in export-control compliance.
- **Severity**: med.
- **Mitigation**: Every slice docstring + CHANGELOG entry opens
  with a scope disclaimer ("LOOP-W covers FAR §889 + NDAA §1634 +
  OFAC + BIS + SAM Exclusions; it does NOT cover ITAR or EAR
  export-control screening."). Runbook documents the distinction.
- **Status**: open.

### W-X41 — FAR amendment (additional named entities)

- **Description**: The five FAR 52.204-25(a) named entities (Huawei,
  ZTE, Hytera, Hikvision, Dahua) are statutory. NDAA amendments could
  add entities (e.g. drone manufacturer DJI has been periodically
  proposed for addition). A FAR amendment adding entities would
  require W.W1's `FAR_NAMED_ENTITIES` constant to update.
- **Severity**: low (announced in advance through NDAA cycle).
- **Mitigation**: Constant is in `core/prohibited-vendors-catalog.ts`
  with a `last_verified_against_far` timestamp; W.W1 emits a warning
  if the constant is more than 1 year old (heuristic — FAR amendments
  typically happen yearly). Runbook documents the annual NDAA
  review checkpoint. CHANGELOG entry per addition.
- **Status**: open.

### W-X42 — Sanctions-overlay confusion (DPRK / Iran / Cuba / Syria)

- **Description**: OFAC maintains country-based sanctions programs
  (DPRK / Iran / Cuba / Syria / Russia) that overlay the SDN list.
  Entities in these countries may or may not be on the SDN list
  directly. A CSP must screen against both the SDN list AND
  country-of-origin for these sanctioned countries. LOOP-W screens
  SDN by default; country-of-origin requires operator-supplied
  vendor data.
- **Severity**: med.
- **Mitigation**: W.W2's catalog includes the SDN `nationalityList` +
  `citizenshipList` fields; match output flags entries with
  nationality in the sanctioned-country set. Operator-supplied
  `country_of_incorporation` per subprocessor (via
  `subprocessors-sheet`) lets W.W2 perform country-overlay matching.
  Runbook documents the overlay logic. Future LOOP-Sanctions could
  extend.
- **Status**: open.

### W-X43 — State-by-state aggressive interpretations (e.g. Texas SB 1893, Florida SB 7050)

- **Description**: Several US states have enacted prohibited-vendor
  laws (Texas SB 1893 2023 — TikTok + others; Florida SB 7050 2023 —
  PRC-affiliated entities). CSPs serving state customers may face
  state-level prohibitions that exceed Federal scope. LOOP-W is
  Federal-only by design.
- **Severity**: low.
- **Mitigation**: Scope guard in `LOOP-W-SPEC.md §1.3` makes this
  explicit; operators serving state customers add entries via
  `prohibited-vendors-overrides.yaml` with `provenance: state-law-<state>-<bill>`
  tagging. Runbook lists the major state laws; operator maintains.
- **Status**: open.

---

## Per-slice risks

### W.W1 — Prohibited-Vendor List Ingester

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| W.W1-1 | high | OFAC SDN update cadence drift (cross-ref W-X1) | 6-hourly cron + 24h staleness floor + strict mode | open |
| W.W1-2 | high | OFAC bulk endpoint URL drift (cross-ref W-X4) | Index-page verify + record-count assertion + CI cron | open |
| W.W1-3 | high | OFAC schema migration sdn.xml → sdn_advanced.xml (cross-ref W-X5) | Parser multiplex + 50% floor + per-parser tests | open |
| W.W1-4 | high | SAM.gov auth lapse (cross-ref W-X3) | Key-expires tracking + 30/7/0 day warnings + bulk fallback | open |
| W.W1-5 | med | BIS Entity List Federal Register lag (cross-ref W-X2) | Dual-source (CSL API + FR RSS) + lag tracking | open |
| W.W1-6 | low | trade.gov API key revocation (cross-ref W-X7) | Automatic CSV fallback + tracker banner | open |
| W.W1-7 | high | Catalog provenance loss (cross-ref W-X9) | Tracker key registry + per-snapshot signing_key_id | open |
| W.W1-8 | high | Repository tampering of snapshot file (cross-ref W-X24) | Hash chain + CI re-verify + HSM-held signing key | open |
| W.W1-9 | high | Naming inconsistencies across lists (cross-ref W-X14) | Multi-factor entity_key merge + cross-reference fields | open |
| W.W1-10 | high | Transliteration coverage gap (cross-ref W-X15) | NFKC + pinyin/Hepburn/GOST tables + pre-computed search terms | open |
| W.W1-11 | high | Subsidiary chain ambiguity (cross-ref W-X16) | subsidiary_chain[] from BIS remarks + SAM comments + operator override | open |
| W.W1-12 | med | Alias-chain collision (cross-ref W-X17) | Corroboration requirement + potentially_related[] flag | open |
| W.W1-13 | low | FAR amendment adds named entities (cross-ref W-X41) | last_verified_against_far timestamp + 1y warning + NDAA review checkpoint | open |
| W.W1-14 | med | FAR_NAMED_ENTITIES vs Kaspersky overlay drift (BOD 17-01 amendment) | Per-entity provenance.source = 'far-52.204-25' or 'ndaa-1634-bod-17-01'; CHANGELOG per change | open |
| W.W1-15 | med | Catalog snapshot file size growth (SDN ~12k entries; Entity List ~3k; SAM Exclusions ~100k) | Snapshot is JSON-line-delimited; bench at 100k entries < 50ms load; runbook documents size | open |
| W.W1-16 | low | Snapshot retention policy (how long do we keep historical snapshots) | LOOP-H.H1 long-term storage classifier reads `data/prohibited-vendors-snapshot-*.json` `retention_until` field; default 7 years per FedRAMP record-retention | open |
| W.W1-17 | med | Operator config `prohibited-vendors-config.yaml` schema validation | ajv schema in `core/prohibited-vendors-config-schema.json`; validate on every load; error message names the offending field | open |
| W.W1-18 | low | First-snapshot bootstrap when no prior snapshot exists | `--first-snapshot` flag opts into emit; CHANGELOG documents bootstrap; no hash-chain prior reference | open |
| W.W1-19 | med | **(discovered during impl)** `core/pdf-table-extract.ts` is introduced by the unshipped LOOP-C.C3, so live FASCSA-order PDF auto-extraction cannot run yet. FASCSA entities are sourced from the operator-maintained register `data/fascsa-orders.json`, which can drift from the live CISA FASCSA index. | Register carries `last_reviewed` + per-order `confirmed` flag (unconfirmed orders emit `requires_operator_input`); RUNBOOK documents the quarterly review cadence; wire `core/pdf-table-extract.ts` ingestion when LOOP-C.C3 ships, then backfill any orders the register missed. | open |
| W.W1-20 | low | **(discovered during impl)** The catalog `provenance` block uses camelCase keys (`emitter`/`emittedAt`/`sourceCalls`/`signingKeyId`) to satisfy the G3 `check-provenance` guardrail, diverging from the snake_case in W.W1.md §5.1. A downstream consumer expecting snake_case provenance keys would mis-read the block. | Documented in W.W1.md §12; downstream W.W2/W.W3/W.W4 read the catalog via `loadProhibitedVendorsCatalog()` (typed), not raw key access; the richer fields (`signatureEd25519`, `publicKeyPem`) are additive. | open |
| W.W1-21 | low | **(discovered during impl)** No `core/http-client.ts` / read-only HTTP Proxy guardrail exists; the extract script + the thin core fetch seam use global `fetch` + `core/retry.ts`. Node's global `fetch` does not natively honour `HTTPS_PROXY`, so corp-proxy environments may need an explicit agent. | `prohibited-vendors-config.yaml` exposes `proxy.https_proxy`; air-gapped operators pre-stage snapshots via the extract script; document the proxy-agent gap in RUNBOOK and add an undici `ProxyAgent` when a proxied environment is first encountered. | open |

### W.W2 — Subprocessor + SBOM + OCI Image Screening

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| W.W2-1 | high | False-positive subprocessor match (cross-ref W-X10) | Multi-factor score + low-confidence band + adversarial test A1 | open |
| W.W2-2 | high | False-negative transitive SBOM match (cross-ref W-X11) | Full graph walk to depth 10 + dependency_chain[] + test A3 | open |
| W.W2-3 | high | OCI publisher attribution ambiguity (cross-ref W-X12) | Multi-layer trust (cosign > Rekor > manifest); REQUIRES-OPERATOR-INPUT on unsigned + test A4 | open |
| W.W2-4 | med | Trust-anchor compromise (cross-ref W-X13) | Record root fingerprint + Rekor endpoint per attestation; warn on change | open |
| W.W2-5 | high | Transliteration evasion (cross-ref W-X15) | NFKC + transliteration tables; adversarial test A2 | open |
| W.W2-6 | high | Subsidiary chain incomplete (cross-ref W-X16) | 5-level traversal default + chain in match output + test A5 | open |
| W.W2-7 | med | Alias-only match (cross-ref W-X17) | Canonical-name surface in tracker + test A6 | open |
| W.W2-8 | med | Catalog snapshot staleness vs incident clock (cross-ref W-X22) | Per-match snapshot_signed_at + catalog_entry_added_at; transparent timeline; test A7 | open |
| W.W2-9 | high | SBOM cosign verification failures (cross-ref W-X34) | Fail closed when sbom.verified != true; coverage:sbom-unverified emit | open |
| W.W2-10 | med | Rekor outage (cross-ref W-X35) | Local-cache fallback + 24h strict floor + operator override | open |
| W.W2-11 | med | subprocessors-sheet schema drift (cross-ref W-X36) | Column-name + min-row assertions; typed error on drift | open |
| W.W2-12 | med | Cross-loop overlap with LOOP-S DFARS (cross-ref W-X37) | Side-by-side UI labels + linked_section889_incident_id FK | open |
| W.W2-13 | med | Multi-tenant deferred (cross-ref W-X38) | LOOP-H.H3 sweep + single-tenant deploy | open |
| W.W2-14 | med | Waiver tracking gap (cross-ref W-X39) | overrides.yaml waivers[] block + provenance flag + test A9 | open |
| W.W2-15 | med | Sanctions-overlay country-of-origin gap (cross-ref W-X42) | nationalityList + citizenshipList overlay; subprocessor country flag | open |
| W.W2-16 | low | State-by-state laws (cross-ref W-X43) | Operator override + state-law provenance tagging | open |
| W.W2-17 | med | DNS-routed sub-tenant evasion (test A11) | Fallback substring on provider_tag + sku; low-confidence flag + operator confirm | open |
| W.W2-18 | med | IDN punycode look-alike evasion (test A12) | IDN normalization + ASCII-fold + look-alike score | open |
| W.W2-19 | low | Inventory CUI/data-classification tagging absent (similar to S-X26) | coverage:skipped + runbook with per-provider tag commands | open |
| W.W2-20 | med | POA&M emit explosion (e.g. 500 SBOM packages with hits) | Group by entity_key; one POA&M per entity; UI surfaces "Prohibited Vendor" filter facet; cross-ref LOOP-E.E1 ConMon delta | open |
| W.W2-EXT-1 | med | Tracker DB tables (`prohibited_vendor_screens` / `prohibited_vendor_matches`) + tracker UI specified in §7.2 item 20 do NOT exist in this checkout (no `tracker/` subsystem). W.W2 shipped persisting screen results via the signed JSON envelope + append-only `out/prohibited-vendor-screens.jsonl` ledger (the repo's `core/poam-ledger.ts` / `core/run-ledger.ts` pattern) instead of a SQL migration — a REO-honest substitute that does not fabricate infrastructure. | When the tracker subsystem lands, add the migration + upsert and back-fill from the ledger; the screen-results page + 1BD countdown UI are W.W3 concerns. | open (follow-up) |
| W.W2-EXT-2 | low | In the current orchestrator pipeline `emitOscalPoam` runs BEFORE the catalog + screen, so the W.W2 `vendorScreenItems` POA&M items are not threaded into `poam.json` without a pipeline reorder. W.W2 emits its own signed `prohibited-vendors-screen-result.json` (with per-match `poam_item_uuid` + SR controls) as the primary artifact; `core/oscal-poam.ts:buildVendorScreenPoamItems` + the `vendorScreenItems` option are implemented + unit-tested (T16) for callers. | Reorder the orchestrator so catalog → screen precede `emitOscalPoam`, then pass `vendorScreenItems`; or have the bundler merge the screen items at POA&M assembly. | open (follow-up) |

### W.W3 — FAR 52.204-25(d) 1-Business-Day Reporter

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| W.W3-1 | high | Weekend/holiday discovery clock (cross-ref W-X18) | Federal-business-day arithmetic + Sat/Sun in-lieu-of rule + test A8 | open |
| W.W3-2 | med | Federal holiday calendar drift (cross-ref W-X19) | data/federal-holidays-YYYY.json + annual refresh + operator override | open |
| W.W3-3 | high | Discovery-date misidentification (cross-ref W-X20) | Record system_notified + operator_acknowledged + due_at = min(); .docx shows all | open |
| W.W3-4 | high | Time-zone errors (cross-ref W-X21) | contracting_officer_tz per contract + default America/New_York | open |
| W.W3-5 | high | Confidentiality leak in 1BD report (cross-ref W-X29) | Restrictive ACLs + encrypted-mail recommendation + submission_channel audit | open |
| W.W3-6 | med | DHS endpoint format change (cross-ref W-X30) | Dual-emit (.docx + JSON) + schema-versioned renderer | open |
| W.W3-7 | med | Risk acceptance / cannot-remove-in-1BD (cross-ref W-X33) | mitigation_plan section + 10-business-day follow-up emit + POA&M SLA | open |
| W.W3-8 | med | Per-contract emit explosion (CSP with 50 affected Federal contracts) | One .docx per contract; tracker batches; runbook explains | open |
| W.W3-9 | high | Missing Contracting Officer email (operator unaware which CO to email) | section889-contacts.yaml; REQUIRES-OPERATOR-INPUT on missing CO; tracker UI prompts | open |
| W.W3-10 | med | 10-business-day follow-up tracking | Tracker schedules follow-up at +10 BD; UI countdown; auto-emit reminder | open |
| W.W3-11 | high | Tracker signing-key rotation (cross-ref W-X23) | Inherit B-X3 fix; signing_key_id per record | open |
| W.W3-12 | low | Report file size cap | Warn at 5 MB, fail at 25 MB; per-contract files small (~10-50 KB) | open |
| W.W3-13 | med | Multiple incidents on same day (linked vs separate reports) | Per-entity report grouping; one report per (contract, entity) pair | open |
| W.W3-14 | med | Officer sign-off via WebAuthn vs server-side keys | Server-side first cut; WebAuthn follow-up; cross-ref R-X11 | open |
| W.W3-15 | low | Contracting Officer email vs SAM.gov registered POC mismatch | Operator runbook documents SAM POC vs CO distinction; default to SAM POC | open |
| W.W3-16 | high | Repository tampering / report integrity post-emit | Signed envelope + tracker audit log + submission_channel hash | open |
| W.W3-17 | high | **Discovered 2026-06-18 during W.W3 impl.** The spec §5.4/§7 assumes a tracker subsystem — Postgres `section889_reports` table (migration 0042), REST routes (`tracker/server/routes/section889-reports.ts`), a React countdown-timer status pane (`tracker/ui/section889-status-pane.tsx`), a `scheduled_notifications` T-1h escalation daemon, and pgcrypto-at-rest — none of which exist in this repo (no `pg`/`express`/`react` deps; every prior slice ships as `core/*.ts` + `tests/core/*.test.ts`). W.W3 shipped the **full regulatory deliverable** (signed canonical-JSON + `.docx` report pair per (match × contract), federal-business-day deadline, statutory citations, submission-bundle registration). The tracker-resident operator-workflow layer (status pane, live countdown, scheduled T-1h PagerDuty escalation, DB audit rows, encrypted-at-rest persistence) is **DEFERRED** until the shared tracker subsystem is built. | Interim: append-only ledger `section889-1bd-reports.jsonl` provides the durable idempotency + audit index; notification dispatch is an injectable seam (default env-gated Slack/PagerDuty). Owner: tracker-subsystem buildout (forward-spec shared dependency across many slices). | open (follow-up) |
| W.W3-18 | low | **Discovered 2026-06-18.** Holiday source-of-truth: spec §4.4 wanted a signed `data/federal-holidays-YYYY.json` refreshed annually by `scripts/fetch-opm-holidays.mjs`. W.W3 instead COMPOSES `core/bizdays.ts:usFederalHolidays` (derives the 11 §6103 observed holidays per year with the in-lieu-of rule — no annual file maintenance, no signed-JSON drift). Supersedes W.W3-2's mitigation. | Resolved by design: the holiday set is computed, not maintained; operator one-off §6103(c) proclaimed closures come from `section889-agency-closures.yaml`. | resolved (by design) |
| W.W3-19 | low | **Discovered 2026-06-18.** RFC 3161 timestamp: the report envelope records `rfc3161_timestamp.status: 'pending'` rather than attaching a live TST, mirroring the W.W2 screen envelope (no live TSA in the offline/CI path). | The detached Ed25519 signature + `.sig` sidecar is the integrity mechanism; a manifest-level TST is attached by `core/timestamp.ts` at signing. Attach a per-envelope TST when a TSA is configured. | open (follow-up) |
| W.W3-20 | low | **Discovered 2026-06-18.** Spec §7 #24 wanted `core/oscal-poam.ts:updatePoamItem` extended for `remediation_tracking.events[]`; no such mutation API exists (POA&M items are built by W.W2 `buildVendorScreenPoamItems`, not mutated, and mutation depends on the tracker). | W.W3 back-references the W.W2 `poam_item_uuid` on its report envelope (no POA&M mutation, no auto-signed attestation — REO Rule 1/Rule 10). | open (follow-up, with tracker) |

### W.W4 — Section 889 Part B Annual Representation

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| W.W4-1 | high | Operator fails to file in SAM.gov (cross-ref W-X28) | Calendar .ics + T-60/T-30/T-7 warnings + Marketplace coupling | open |
| W.W4-2 | high | Officer signature missing | REQUIRES-OPERATOR-INPUT diagnostic; .docx renders blank signature line + redacted block | open |
| W.W4-3 | low | SAM.gov auth flow change (cross-ref W-X31) | No automation; runbook references SAM help | open |
| W.W4-4 | low | Marketplace badge format change (cross-ref W-X32) | Signed JSON additive; backward-compat | open |
| W.W4-5 | med | "Reasonable inquiry" definition ambiguity | Quote FAR 4.2101 verbatim in .docx; document inquiry actions in narrative | open |
| W.W4-6 | high | Wrong checkbox emitted (does vs does not) | W.W2 matches drive checkbox; assertion in W.W4 tests | open |
| W.W4-7 | med | Per-prime customized representations (officer wants different language) | Single template first cut; customize via per-prime override; Q5 in W.W4.md open question | open |
| W.W4-8 | med | Annual cadence vs solicitation-response cadence | W.W4 emits annually; runbook documents the operator may need to refresh per solicitation | open |
| W.W4-9 | low | Officer leaves org between sign-off + SAM filing | Signed rep retains historical signature; only the SAM filing requires currently-authorized officer | open |
| W.W4-10 | med | Multi-system / multi-CSO representations | Per-CSP per-FY rep; UNIQUE on (fiscal_year, csp_name); cross-ref R.R3 multi-system pattern | open |
| W.W4-11 | low | Very-large narrative (>10 pages of inquiry description) | Render full; warn at 20-page boundary | open |
| W.W4-12 | med | Annual rep without supporting W.W2 evidence | Strict mode requires W.W2 run within 7 days of rep emit; warn otherwise | open |
| W.W4-13 | high | Tracker schema migration on existing installs (cross-ref to S-X18) | All tables additive CREATE TABLE IF NOT EXISTS; CHANGELOG documents | open |
| W.W4-14 | low | Submission bundle role naming collisions (cross-ref W-X27) | submission-bundle test pins role table | open |
| W.W4-15 | med | Auto-suggest checkbox could mislead operator | UI shows W.W2 match summary + recommended checkbox + operator must explicitly accept; the system never auto-files in SAM | open |

---

## External dependencies that may change

### Federal-Government bulk feeds (catalog source data)

- **OFAC SDN human-readable lists** — index:
  https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists
  — updated as designations occur (daily / intra-day). W.W1 pulls
  `sdn_advanced.xml` first, falls back to legacy `sdn.xml`. Treasury
  has signaled the legacy form will eventually deprecate.
- **OFAC consolidated sanctions program list** —
  https://ofac.treasury.gov/sanctions-programs-and-country-information
  — pinned for catalog `provenance.list_program` mapping; programs
  added (~5-10 per year).
- **BIS Entity List** — index:
  https://www.bis.doc.gov/index.php/policy-guidance/lists-of-parties-of-concern/entity-list
  — Federal Register publication cadence ~1-3 per month.
  Trade.gov Consolidated Screening List API mirror:
  https://api.trade.gov/consolidated_screening_list/search/ (1-3 day
  lag from FR publication).
- **SAM.gov Public Exclusions API** —
  https://api.sam.gov/entity-information/v3/exclusions — hourly
  refresh; v3 → v4 migration likely 2026-2027 with 6-12 months
  notice. Auth: SAM-registered API key, 90-day renewal cycle.
- **SAM Bulk Public Exclusions ZIP** — fallback path, daily refresh
  with up to 24h lag; available via SAM Data Services portal.

### Statute / regulation / directive
- **FAR 52.204-25** — https://www.acquisition.gov/far/52.204-25 —
  stable since Aug 2020 (Part B effective date). Future amendments
  via FAR Council rulemaking.
- **FAR 52.204-26** — https://www.acquisition.gov/far/52.204-26 —
  stable; tied to FAR 52.204-25 by reference.
- **FAR Subpart 4.21** —
  https://www.acquisition.gov/far/subpart-4.21 — full subpart.
- **NDAA FY2019 §889 (Pub. L. 115-232)** — statutory; only
  amendable by Congress.
- **NDAA FY2018 §1634 (Pub. L. 115-91)** — Kaspersky prohibition;
  amendable only by Congress.
- **DHS BOD 17-01** — Sep 13 2017; CISA periodically reviews
  binding operational directives; could be amended or rescinded.
- **5 U.S.C. §6103** — Federal holidays; amendable by Congress
  (most recent addition: Juneteenth, 2021).
- **OPM Federal holidays page** —
  https://www.opm.gov/policy-data-oversight/pay-leave/federal-holidays/
  — annual refresh by OPM with observed-date corrections.

### Federal-Government policy guidance
- **GSA Section 889 page** — operator pins live URL at W.W1 run
  time; the legacy permalink has rotated through several locations
  since 2019.
- **acquisition.gov Section 889 Policies** —
  https://www.acquisition.gov/Section-889-Policies — stable.
- **CISA ICT Supply Chain Risk Management** —
  https://www.cisa.gov/topics/supply-chain-security/ict-supply-chain-risk-management
- **NIST SP 800-161 Rev 1 (C-SCRM)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1.pdf
  — supply-chain controls cross-walked by W.W2 POA&M findings.
- **NIST SP 800-53 Rev 5 SR family** — SR-1, SR-3, SR-5, SR-6,
  SR-11; control IDs stable; Rev 6 is long-tail.

### Federal Register final rules (citations)
- **Federal Register: FAR 52.204-25 Part A (Aug 13 2019)** —
  https://www.federalregister.gov/documents/2019/08/13/2019-17201
- **Federal Register: FAR 52.204-25 Part B (Jul 14 2020)** —
  https://www.federalregister.gov/documents/2020/07/14/2020-15293
- Doc numbers (`2019-17201`, `2020-15293`) are permanent; URL drift
  is recoverable by FR doc-number search.

### Sigstore / supply-chain trust anchors
- **Sigstore TUF root** — https://tuf-repo-cdn.sigstore.dev/ —
  versioned; cosign verifies the root automatically; LOOP-W records
  the root version per snapshot for audit. Compromise risk is
  ecosystem-level (cross-ref W-X13).
- **Rekor transparency log** — https://rekor.sigstore.dev/ — hosted
  by Linux Foundation; outage risk requires fallback (cross-ref
  W-X35).
- **cosign attest** — https://docs.sigstore.dev/cosign/signing/signing_with_blobs/
  — stable API.

### SBOM specs
- **SPDX 2.3 specification** — https://spdx.github.io/spdx-spec/v2.3/
  — stable; SPDX 3.0 is in progress.
- **CycloneDX 1.5 specification** —
  https://cyclonedx.org/docs/1.5/json/ — stable; CycloneDX 1.6 is
  in progress.

### Upstream library updates
- **OSCAL JSON Schema v1.1.2** — committed at
  `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json`. LOOP-W
  emits POA&M findings via existing `core/oscal-poam.ts`; pins
  v1.1.2.
- **ajv (^8.x)** — used by `core/oscal-validate.ts` + future
  `core/prohibited-vendors-config-schema.json`. Schema-behaviour
  changes rare; lock major version.
- **better-sqlite3 (~9.x or ~11.x)** — tracker. SQL dialect stable.
- **noble-ed25519 (^2.x) or @noble/ed25519** — Ed25519 signing.
  Stable API.
- **OOXML compose helpers** — used by `core/oscal-ssp-docx.ts`;
  reused for `core/section889-rep-docx.ts` + 1BD-report renderer.
  No external dep; pure JS.
- **React (^18.x)** — tracker UI; pin major within LOOP-W.

### Cloud-provider OCI registries
- **AWS ECR / ECR Public** — manifest schema stable; cosign
  attestation flow stable.
- **GCP Artifact Registry** — same.
- **Azure Container Registry** — same.
- **Docker Hub / GHCR / private registries** — same OCI spec;
  per-registry rate-limit policy variations.

---

## Resolved risks (historical)

> Empty initially — populated as risks are resolved.

| ID | Resolved date | Resolution note | Resolved by |
|---|---|---|---|
| — | — | — | — |

---

## Procedure for adding / updating a risk in this register

1. New risks discovered during implementation: add a row in the
   appropriate per-slice section with a fresh ID (e.g. `W.W2-21`);
   commit alongside the slice's implementation-log update.
2. Risks resolved during implementation: move the row to the
   "Resolved risks" table at the bottom with date + resolution note +
   responsible session/commit. Do NOT delete the original entry —
   historical record matters.
3. Severity bump (low → med → high): add a `note` line under the
   original entry describing why; do not edit history.
4. Cross-cutting risks affecting multiple slices: keep in the
   cross-cutting section; reference from per-slice tables via
   "(cross-ref W-X<n>)".
5. CHANGELOG entry on every register update — even register-only
   changes; this is the audit trail.

---

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. Read `cloud-evidence/docs/loops/LOOP-W-SPEC.md` — full LOOP-W
   specification with §6 Open Questions overlapping with this
   register.
3. Read the specific per-slice doc at `docs/slices/W/W.W<n>.md` for
   the slice you're implementing — risks here are the LIVE working
   set; risks in the per-slice docs are the spec snapshot.
4. Cross-reference `docs/DEPENDENCY-GRAPH.md` for cross-loop
   dependencies (LOOP-E.E2 SBOM cosign chain; LOOP-J.J3.b OCI cosign /
   Rekor; LOOP-B.B1/B.B2 risk + remediation; LOOP-Q.Q1 Marketplace
   badge).
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` — the
   7-step procedure to follow at slice close.
6. Before shipping a slice, update this file's per-slice section +
   move any resolved risks to the resolved table atomically with the
   slice's commit (per SLICE-COMPLETION-PROCEDURE.md).
7. **Push to origin/main is part of the completion procedure.** Per
   the GROUND-UP DIRECTIVE: "There should be a directive to update
   status each time in claude.md when the respective
   loop, slice, section is completed at the end along with pushing
   to github." Confirm STATUS.md row + CHANGELOG line + per-slice
   doc frontmatter + LOOP-W-SPEC.md status table + this register's
   per-slice section are all current BEFORE the push.

---

## Appendix — when does LOOP-W apply?

LOOP-W applies when ALL of the following are true:

1. The CSP holds at least one Federal contract, grant, or
   cooperative agreement subject to FAR Subpart 4.21 (effectively
   every Federal customer relationship since 2019-08-13 / 2020-08-13).
2. The CSP's CSO is part of the system the contractor uses to
   deliver services to the Government — OR — the CSP itself is the
   contractor offering the CSO directly.

LOOP-W does NOT apply when:

- The CSP has zero Federal customers (effectively no FedRAMP
  authorization need). LOOP-W is a no-op in that case but the
  orchestrator still emits the empty annual representation — a
  no-positive-match emission is itself evidence.
- The CSP is a downstream subprocessor that flows FAR §889
  obligations via FAR 52.204-25(e) (the prime is responsible for
  flow-down). The CSP still owes its own annual representation.

The `--prohibited-vendor-screen` flag is a CI-friendly knob to
suppress LOOP-W execution during development of unrelated slices;
the production orchestrator always emits W.W1..W.W4 in the FedRAMP
20x submission build. There is no production-side opt-out.

---

## Appendix — risk-severity calibration

- **high** = ship-blocker. Resolve before merging the slice's
  commit. CI guardrail or test failure required.
- **med** = should fix in-loop. Resolve before LOOP-W closes (i.e.
  before W.W4 ships). Operator runbook + CHANGELOG must document any
  unresolved med-severity item.
- **low** = file as follow-up. May remain open after LOOP-W closes;
  must have an owner + a target loop (LOOP-W-Waivers, LOOP-Sanctions,
  LOOP-H.H3, etc.) where the resolution will land.

This calibration mirrors LOOP-R-RISKS.md and LOOP-S-RISKS.md.

---
