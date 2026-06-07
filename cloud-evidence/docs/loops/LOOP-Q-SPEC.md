# LOOP-Q — Marketplace + Post-ATO Publication

> Comprehensive implementation specification for the three slices in LOOP-Q.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-Q end-to-end by reading ONLY this file + the three per-slice
> docs under `docs/slices/Q/` + the four supporting files cited in Section 3
> ("Dependencies"). No prior conversation history required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence or
> operator-supplied configuration. Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.
>
> Status of adoption: this loop was surfaced by `docs/ADDITIONAL-LOOPS-AUDIT.md`
> §2 "LOOP-Q — Marketplace Publication + Post-ATO Customer-Facing Artifacts"
> on 2026-06-06 and is queued behind LOOP-B in the audit's recommended
> ordering (§6 "Recommended prioritization for adoption" item 3). LOOP-Q
> is **conditional on operator/sponsoring-agency confirmation** of (a) the
> sponsoring agency being known, (b) intent to publish to the public
> Marketplace (vs an internal authorization path), and (c) confirmation
> that the Marketplace JSON Schema (CR26-bound) is available at run time.

---

## 1. Why this loop exists

### The gap LOOP-A.A4 (submission bundle) and LOOP-F.F6 (ATO workflow) left open

LOOP-A.A4 ships the *submission* package — the bundled OSCAL SSP + AP + AR +
POA&M + IIW + RoE + signed manifest + RFC 3161 timestamp + INDEX.json — as
one uploadable artifact for USDA Connect.gov (per `docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`
R2). LOOP-F.F6 (pending) handles the *pre-ATO* workflow state machine inside
the 3PAO assessor experience.

Neither of those loops handles what happens **after** the Authorizing
Official signs the ATO letter:

1. **FedRAMP Marketplace listing.** The Marketplace
   (`https://marketplace.fedramp.gov/`) is the public-facing registry that
   federal agencies use to discover authorized cloud services and decide
   whether to "leverage" an existing authorization rather than running their
   own. Per FedRAMP help docs and the RFC-0021 outcome notice, a CSO is not
   *visible* in the Marketplace until the CSP publishes the structured
   listing metadata. Without it, the system is technically Authorized but
   commercially invisible — no agency can find it for reuse.

2. **Post-ATO continuous monitoring publication.** Per FedRAMP Continuous
   Monitoring Strategy & Guide and RFC-0026 (CA-7 clarification), the CSP
   MUST share monthly ConMon artifacts (POA&M update, vulnerability scans,
   meeting recordings/notes) with all leveraging agency customers + FedRAMP
   PMO on a documented monthly cadence. LOOP-A.A4 produced the *one-shot*
   ATO submission; LOOP-E (still pending) produces the monthly ConMon
   *analysis report*; but nothing today bundles + signs + ships the
   monthly delivery to the FedRAMP secure repository / Trust Center.

3. **Agency authorization tracking.** Each agency that issues an ATO based
   on the existing FedRAMP authorization (an "agency reuse" or "leverage"
   event) generates a record the CSP must track for two reasons: (a)
   RFC-0021 MKT-GEN-DOD requires a public list of "all _agencies_ that are
   directly using the product" in the Marketplace listing; (b) every
   leveraging agency receives the same monthly ConMon delivery as the
   sponsoring agency, so the Q.Q2 delivery list must stay current.

### Artifacts LOOP-Q delivers

| # | Artifact | Source | Consumer |
|---|---|---|---|
| 1 | `core/marketplace-listing.ts` — JSON + Markdown emitter for the FedRAMP Marketplace listing schema (RFC-0021 / CR26-bound) | LOOP-Q.Q1 | FedRAMP Marketplace ingest; CSP Trust Center publication |
| 2 | `out/marketplace-listing.json` + `out/marketplace-listing.md` | LOOP-Q.Q1 | Published at `<trust-center>/.well-known/fedramp-marketplace.json`; Marketplace registry |
| 3 | `core/conmon-publication.ts` — monthly ConMon delivery bundler + manifest | LOOP-Q.Q2 | FedRAMP secure repository (Connect.gov / future API); leveraging-agency Trust Centers |
| 4 | `out/conmon-publication-<YYYY-MM>.tar.gz` + `out/conmon-publication-<YYYY-MM>.manifest.json` (signed + RFC 3161 timestamped) | LOOP-Q.Q2 | Monthly upload to PMO secure repo + signed Trust Center mirror |
| 5 | `tracker/server/routes/agency-authorizations.ts` + DB tables `agency_authorizations`, `agency_reuse_events`, `marketplace_listing_history` | LOOP-Q.Q3 | UI for tracking each leveraging agency + dating each ATO event |
| 6 | `core/agency-authorization-emitter.ts` — emits `out/agency-authorizations.json` + roll-up section in the marketplace listing | LOOP-Q.Q3 | Q.Q1 listing emit; LOOP-I.I1 exec dashboard; LOOP-H.H1 long-term retention |

### Authorization-package gaps closed

| Package gap | Slice | Authoritative source |
|---|---|---|
| Marketplace listing metadata not produced from the OSCAL submission package | Q.Q1 | RFC-0021 MKT-GEN-DOD; FedRAMP Marketplace help docs |
| Monthly ConMon delivery has no bundled artifact | Q.Q2 | FedRAMP Continuous Monitoring Strategy & Guide §3; RFC-0026 CA-7 |
| Agency leverage events (each new ATO) untracked | Q.Q3 | RFC-0021 MKT-GEN-DOD "list of all agencies"; RFC-0026 "to all agency customers" |
| Trust Center publication endpoint not generated | Q.Q1 + Q.Q3 | FedRAMP 20x Authorization Data Sharing standard (RFC-0011 finalized) |

---

## 2. Connection to FedPy mission

FedPy is a read-only TypeScript collector that captures AWS/GCP/Kubernetes
configuration evidence for all 60 KSIs (223 requirements), benchmarks
against NIST 800-53 at Low/Moderate/High, signs the evidence
(Ed25519 + OSCAL), and ships a local multi-user tracker over the FRMR
catalog. Every byte must trace back to real evidence (REO standard).

LOOP-Q connects to that mission as follows:

### Read-from existing collectors / cloud evidence

- **`providers/{aws,gcp,azure}/*.ts` collectors** — Q.Q2 reads the monthly
  KSI envelopes (`out/KSI-*.json`) produced by every provider collector,
  bundles the deltas, and ships them in the monthly ConMon publication.
  No NEW cloud-provider collectors are added by LOOP-Q.
- **`core/control-benchmark.ts` (NIST 800-53 Rev 5)** — Q.Q1 reads the
  control benchmark to derive the Marketplace listing's "impact level"
  field (low/moderate) and to enumerate the services in scope (the set of
  AWS / GCP / Azure services the collectors actually queried for the
  authorization, per `inventory.json`).
- **`core/inventory-emit.ts` + `out/inventory.json`** — Q.Q1 reads the
  inventory to enumerate "services in scope" verbatim from real cloud
  evidence (AWS service IDs, GCP service IDs, Azure resource providers),
  never from a hand-maintained list.
- **`core/ksi-map.ts`** — Q.Q1 reads the loaded KSI list to populate the
  Marketplace listing's "controls in scope" / "KSI baseline" field.

### Extend existing core modules

- **`core/submission-bundle.ts`** — Q.Q2 adds three new roles
  (`conmon-publication-tarball`, `conmon-publication-manifest`,
  `marketplace-listing-json`) to the `WELL_KNOWN` catalogue so the LOOP-A.A4
  bundler classifies them correctly; the monthly ConMon publication
  REUSES the LOOP-A.A4 pure-JS POSIX tar writer + INDEX.json pattern.
- **`core/sign.ts`** (Ed25519 + manifest pipeline) — Q.Q1 and Q.Q2 outputs
  flow through the existing signing pipeline; no new crypto module.
- **`core/timestamp.ts`** (RFC 3161) — Q.Q2 monthly publication is
  timestamped with the same DigiCert/GlobalSign/Sectigo/FreeTSA cascade
  LOOP-A.A4 uses (per `docs/ADDITIONAL-LOOPS-AUDIT.md` §3.12
  recommendation).
- **`core/oscal-poam.ts` + `core/oscal-ap.ts` + `core/oscal-ar.ts`** — Q.Q2
  consumes the OSCAL artifacts these emit; no schema changes here.
- **`core/orchestrator.ts`** — new flags `--marketplace-listing`,
  `--conmon-publication`, `--agency-auth-export`, `--strict-marketplace`.

### Tracker DB extensions

- New tables: `agency_authorizations`, `agency_reuse_events`,
  `marketplace_listing_history`, `conmon_publication_log`.
- New routes: `/api/agency-authorizations`, `/api/marketplace-listings`,
  `/api/conmon-publications`.
- New UI pages: `AgencyAuthorizations.tsx`, `MarketplaceListing.tsx`,
  `ConmonPublicationLog.tsx`.

### New collectors or providers added by LOOP-Q

**None.** Per FedPy mission constraints (read-only, evidence-grade), the
cloud collectors are stable. LOOP-Q is a CONSUMER of existing collector
output: it bundles, formats, signs, ships. The only "live" inputs Q.Q1
adds are operator-supplied agency-authorization records (Q.Q3, entered
via tracker) and the operator-confirmed sponsoring-agency metadata
(config.yaml).

---

## 3. Dependencies

### Loops / slices that MUST complete first

| Dep | Why |
|---|---|
| LOOP-A.A1 (`core/oscal-poam.ts`) | Q.Q2 reads `out/poam.json` for the monthly delta; Q.Q1 references the POA&M count in the listing. |
| LOOP-A.A2 (`core/oscal-ap.ts`) | Q.Q1 reads the AP's `import-ssp.href` chain to derive the authorized SSP version (Marketplace lists the SSP version). |
| LOOP-A.A3 (`core/oscal.ts` AR chain wiring) | Q.Q2 reads the AR for monthly delta deltas (3PAO-attested findings vs CSP-self-reported). |
| LOOP-A.A4 (`core/submission-bundle.ts`) | Q.Q2 REUSES the pure-JS POSIX tar writer + INDEX.json pattern; Q.Q1 listing JSON is added to the WELL_KNOWN catalogue. |
| LOOP-A.A5 (`core/roe-emit.ts`) | None directly; Q.Q1 references RoE date in the listing's "last 3PAO assessment" field. |
| LOOP-F.F6 (Full ATO workflow tracker — pending) | Q.Q3 picks up the post-ATO state from F.F6's state machine; LOOP-Q is the post-Authorized continuation. |
| LOOP-G.G3 (AFR-ADS Authorization Data Sharing — pending) | Q.Q1 reads ADS Trust Center config so the Marketplace listing's "Trust Center URL" + "authorization data access process" fields are real, not placeholder. |
| LOOP-E.E1 (Monthly ConMon analysis report — pending) | Q.Q2 BUNDLES the monthly analysis report; if E.E1 isn't done, Q.Q2 ships the per-KSI envelopes + POA&M delta only with a `REQUIRES-OPERATOR-INPUT: analysis-report-missing` marker. |
| LOOP-E.E2 (Monthly POA&M delta workflow — pending) | Q.Q2 reads the POA&M delta. |
| `core/sign.ts` + `core/timestamp.ts` | Existing pipeline reused. |

### Existing files this loop EXTENDS

| File | Modification |
|---|---|
| `cloud-evidence/core/submission-bundle.ts` | Add roles `marketplace-listing-json`, `marketplace-listing-md`, `conmon-publication-tarball`, `conmon-publication-manifest`, `agency-authorizations-json` to `WELL_KNOWN`. |
| `cloud-evidence/core/orchestrator.ts` | New flags + env: `--marketplace-listing`, `CLOUD_EVIDENCE_MARKETPLACE_LISTING`; `--conmon-publication`, `CLOUD_EVIDENCE_CONMON_PUBLICATION`; `--conmon-period <YYYY-MM>`; `--agency-auth-export`; `--strict-marketplace`. |
| `cloud-evidence/core/oscal-ap.ts` | (Q.Q1) Read-only — Q.Q1 imports the AP version. No schema change. |
| `cloud-evidence/core/oscal-ssp.ts` | (Q.Q1) Read-only — Q.Q1 reads `system-characteristics.system-name`, impact level, FIPS-199 categorization, and service-list from SSP. |
| `cloud-evidence/core/inventory-emit.ts` | (Q.Q1) Read-only — Q.Q1 enumerates services in scope from `inventory.json`. |
| `cloud-evidence/core/ksi-map.ts` | (Q.Q1) Read-only — Q.Q1 enumerates KSI baseline. |
| `cloud-evidence/CHANGELOG.md` | Unreleased entry per slice. |
| `cloud-evidence/docs/STATUS.md` | Per-slice status line updated when slice ships. |
| `tracker/server/schema.sql` | Tables `agency_authorizations`, `agency_reuse_events`, `marketplace_listing_history`, `conmon_publication_log`. |
| `tracker/server/index.ts` | Mount routes `agency-authorizations.ts`, `marketplace-listings.ts`, `conmon-publications.ts`. |
| `tracker/server/rbac.ts` | New role `ao` (Authorizing Official) gains `marketplace:edit`; `iso` gains `agency-auth:create`; `assessor` gains `marketplace:view`. |
| `tracker/client/src/App.tsx` | Routes `/agency-authorizations`, `/marketplace-listing`, `/conmon-publication-log`. |
| `cloud-evidence/risk-config.yaml` (LOOP-B) | Optional new key `marketplace.public_url` if operator wants to override default Trust Center URL. |

### Loops UNBLOCKED when LOOP-Q is complete

| Unblocked loop | Reason |
|---|---|
| LOOP-G.G3 (AFR-ADS) | Q.Q1's `marketplace-listing.json` is the canonical input ADS Trust Center serves at `/.well-known/fedramp-marketplace.json`. |
| LOOP-I.I1 (Executive posture dashboard) | Q.Q3's agency-authorizations data populates the "agencies using" widget. |
| LOOP-H.H2 (Long-term retention) | Q.Q2's monthly publication tarballs are the canonical retention artifact (3 / 6 / 12-year cohorts). |
| LOOP-E follow-ups | Once Q.Q2 ships, every E slice that emits monthly delta artifacts has a destination (the publication bundler). |

---

## 4. Authoritative sources

Every URL + spec referenced in any LOOP-Q slice. All quotes are verbatim
where retrievable. Citations include section + sub-section identifier
where the source provides one.

### FedRAMP Marketplace + RFC-0021

- **RFC-0021 "Expanding the FedRAMP Marketplace"** —
  https://www.fedramp.gov/rfcs/0021/
  - **Section "FedRAMP Marketplace Listings (MPL) Process":**
    > "Advisors MUST have an appropriate web site that publicly shows at
    > least the following in consistent _machine-readable_ and
    > human-readable formats"
  - **MKT-GEN-DOD ("Ongoing Demand"):**
    > "Providers MUST demonstrate ongoing demand and utility by
    > including…A list of all _agencies_ that are directly using the
    > product"
    > "A list of all _agencies_ that have requested access to
    > _authorization data_, covering the period since the previous
    > _Ongoing Authorization Report_"
  - **MKT-FRX-PAD ("FedRAMP Data Transparency"):**
    > "FedRAMP MUST publish activity data showing the status of all
    > non-sensitive Marketplace-related activities"
  - **Schema reference:**
    > "FedRAMP will publish a JSON Schema for the required
    > machine-readable data"
  - Closed 2026-02-19; outcome at https://www.fedramp.gov/notices/0005/.

- **NTC-0005 — RFC-0021 initial outcome notice** —
  https://www.fedramp.gov/notices/0005/
  - **JSON schema commitment (verbatim):**
    > "FedRAMP will provide a JSON schema for the required web information
    > for [advisory services and independent assessors]"
    > "this schema will be included in the Consolidated Rules for 2026,
    > along with information about validation"
  - **Removal:**
    > "MKT-GEN-SPI Service Pricing Information will be struck"
  - **Timeline:**
    > "FedRAMP will publish the FedRAMP Consolidated Rules for 2026 (CR26)
    > by the end of June, 2026"

- **FedRAMP Marketplace** — https://marketplace.fedramp.gov/
  - The live public registry; field set (CSO name, service model, impact
    level, status, 3PAO, authorization date, agency reuse list) is
    discoverable per listing page. Q.Q1's emitter mirrors these fields.

- **FedRAMP Marketplace listing help** —
  https://help.fedramp.gov/hc/en-us/articles/27703689134107-How-does-a-cloud-service-provider-CSP-get-listed-on-FedRAMP-s-Marketplace
  - HTTP 403 to anonymous fetches as of 2026-06-06; quote pulled from
    web search index:
    > "Once a CSO reaches FedRAMP Authorized status, its authorization
    > package — the SSP, POA&M, and all supporting artifacts — resides in
    > the FedRAMP repository, and the Marketplace listing is what makes the
    > vendor findable."
  - Implementer downloads the article HTML once authenticated and stores
    a snapshot at `cloud-evidence/docs/sources/fedramp-marketplace-help.html`.

### FedRAMP Marketplace status definitions (per FedRAMP help docs + Agency Authorization Playbook v4.1)

- **FedRAMP Agency Authorization Playbook v4.1 (2025-11-17)** —
  https://www.fedramp.gov/resources/documents/Agency_Authorization_Playbook.pdf
  - Defines the three Marketplace statuses CSPs can hold:
    - **FedRAMP Ready** — 3PAO-attested readiness, FedRAMP-reviewed RAR;
      Moderate or High only; one-calendar-year validity; no agency
      partner required.
    - **FedRAMP In Process** — active authorization-in-progress; requires
      In Process Request (IPR) letter + WBS submitted to
      `intake@fedramp.gov`; sponsoring agency partnership formalised.
    - **FedRAMP Authorized** — sponsoring agency Authorizing Official has
      signed ATO letter; FedRAMP has reviewed for government-wide reuse;
      the only status that supports "assess once, use many."

### FedRAMP Continuous Monitoring (post-ATO)

- **FedRAMP Continuous Monitoring Strategy & Guide (Rev 5)** —
  https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Strategy_Guide.pdf
  - HTTP 403 to anonymous fetches as of 2026-06-06 (cross-ref
    `docs/loops/LOOP-B-RISKS.md#B-X1`). Implementer downloads the PDF
    once authenticated and stores at
    `cloud-evidence/docs/sources/fedramp-conmon-strategy-guide.pdf` to
    quote the monthly cadence + artifact list verbatim.
  - Pre-existing R2 quote (`docs/PRE-LOOP-A-RESEARCH-FINDINGS.md`):
    > "Monthly CSP-submitted artifacts include the updated POA&M, monthly
    > vulnerability scan files (OS / DB / Web App / Container / Service
    > Config), and supporting documentation; deliveries occur via the
    > FedRAMP secure repository (Connect.gov for Low/Moderate)."

- **RFC-0026 "Clarifying CA-7 (Continuous Monitoring)"** —
  https://www.fedramp.gov/rfcs/0026/
  - **Monthly meeting + sharing (verbatim):**
    > "host a traditional monthly ConMon meeting open to all agency
    > customers and FedRAMP during any given month"
    > "Sharing Operating System, Database, Web Application, Container, and
    > Service Configuration Scans, at least monthly; AND sharing updated
    > Plans of Action and Milestones (POA&Ms), at least monthly"
    > "recurring monitoring information (including meetings) to all
    > agency customers and FedRAMP"

- **FedRAMP 20x Authorization Data Sharing standard** —
  https://www.fedramp.gov/docs/20x/authorization-data-sharing/
  - **Required Trust Center fields (verbatim):**
    > "FedRAMP Marketplace link; service and deployment models; business
    > category and UEI number; contact information; service description
    > with detailed list of specific services and their security
    > objectives; customer responsibility summary; trust center access
    > process; support information; next Ongoing Authorization Report
    > date"
  - **Automation requirement:**
    > "MUST use automation to ensure information remains consistent
    > between human-readable and machine-readable formats"
  - **Trust Center authorization data access (verbatim):**
    > "Trust centers SHOULD make authorization data available to view and
    > download in both human-readable and machine-readable formats"
    > "Providers SHOULD share the authorization package with agencies
    > upon request"

### NIST publications

- **NIST SP 800-53 Rev 5 — CA-7 (Continuous Monitoring)** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - > "Develop a system-level continuous monitoring strategy and
    > implement continuous monitoring in accordance with the
    > organization-level continuous monitoring strategy"
  - > "Establish the following metrics to be monitored: [Assignment:
    > organization-defined metrics]"
  - LOOP-Q.Q2 satisfies CA-7e ("Reporting the security and privacy status
    of the system to [Assignment: organization-defined personnel or
    roles] [Assignment: organization-defined frequency]") at the
    monthly cadence by bundling and signing the monthly publication.

- **NIST SP 800-37 Rev 2 — Risk Management Framework, Step 7 (Monitor)** —
  https://csrc.nist.gov/pubs/sp/800/37/r2/final
  - > "The continuous monitoring program is implemented and provides
    > ongoing awareness of threats, vulnerabilities, and information
    > security to support organizational risk management decisions."

- **NIST SP 800-137 — ISCM (Information Security Continuous Monitoring)** —
  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-137.pdf
  - Defines the six-step ISCM process; Q.Q2 publication is step 5
    ("Respond") + step 6 ("Review and Update") instrumentation.

### OSCAL

- **OSCAL Plan of Action and Milestones v1.1.2** —
  `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json` +
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/plan-of-action-and-milestones/json-reference/
  - Q.Q2 reads existing POA&M for monthly delta computation; no schema
    changes required.

- **OSCAL Assessment Results v1.1.2** —
  https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/
  - Q.Q2 reads existing AR for the prior-month baseline.

### Federal Register / Federal procurement

- **OMB M-22-09 ("Moving the U.S. Government Toward Zero Trust
  Cybersecurity Principles")** — referenced for the post-ATO agency-
  sharing posture (Trust Center as the federated read endpoint).
- **OMB Circular A-130 §III.A.2** — federal agencies must use FedRAMP
  authorized services for cloud; the Marketplace is the discovery
  surface.
- **BOD 23-01 (CISA)** — federal civilian agencies' asset visibility
  obligations; Marketplace listing metadata helps leveraging agencies
  satisfy BOD 23-01 inventory requirements. Q.Q1 emits Marketplace
  metadata that helps consumers meet this BOD; see
  `docs/ADDITIONAL-LOOPS-AUDIT.md` §4.9.

### Schema / format pins

- **`marketplace-listing.v1` (FedPy-internal schema)** —
  `cloud-evidence/docs/schemas/marketplace-listing.v1.json`. Locally-
  authored schema pending publication of the FedRAMP CR26 schema. When
  CR26 publishes (June 2026 expected), the implementer of Q.Q1
  transitions to `marketplace-listing.cr26.v1` and emits a migration
  note in CHANGELOG. Until then, FedPy's schema is forward-compatible:
  every CR26-required field has a placeholder in v1.
- **`conmon-publication.v1`** — locally-authored manifest schema (mirrors
  LOOP-A.A4 INDEX.json structure with `period: YYYY-MM` discriminator).

---

## 5. Per-slice implementation specs

### Slice Q.Q1 — FedRAMP Marketplace listing emitter (per RFC-0021 format)

**Why this slice**: A FedRAMP-Authorized CSO is commercially invisible
until the structured Marketplace listing is published. Today the FedPy
pipeline emits the OSCAL submission package (LOOP-A.A4) but not the
Marketplace-shaped listing JSON that the registry (and the leveraging-
agency procurement officer) actually consumes. Q.Q1 emits the structured
listing + a Markdown human-readable mirror, both signed under the
existing pipeline, both ready for Trust Center publication.

**Connection to FedPy mission**: 100% derived from real evidence:
- CSO name + impact level + FIPS-199 categorization → SSP
  (`system-characteristics`, `import-profile`).
- 3PAO identifier + authorization date → AP + RoE
  (`assessment-assets.assessment-platforms`, RoE signature block).
- Services in scope → real `inventory.json` (AWS service IDs / GCP
  service IDs / Azure resource providers actually queried).
- Controls in scope / KSI baseline → `core/ksi-map.ts` + control
  benchmark.
- POA&M item count → real `out/poam.json`.
- Agency reuse list → Q.Q3 tracker DB (`agency_authorizations` table
  WHERE status='active').
- Sponsoring agency, POC email, Trust Center URL, UEI number → operator-
  supplied via `config.yaml` (REQUIRES-OPERATOR-INPUT when absent).

**Files to create**:
- `cloud-evidence/core/marketplace-listing.ts` — pure emitter:
  `buildMarketplaceListing(inputs): MarketplaceListing` +
  `emitMarketplaceListing(opts): EmitResult`. Pure first (no IO),
  then a thin disk wrapper that writes JSON + Markdown + provenance
  block.
- `cloud-evidence/core/marketplace-listing-markdown.ts` — Markdown
  renderer for the human-readable mirror.
- `cloud-evidence/docs/schemas/marketplace-listing.v1.json` — local
  JSON Schema for the listing (forward-compat with CR26).
- `cloud-evidence/risk-config.example.yaml` extension: add
  `marketplace:` section.
- `cloud-evidence/tests/core/marketplace-listing.test.ts` — ≥12 tests.
- `cloud-evidence/tests/core/marketplace-listing-markdown.test.ts`.
- `cloud-evidence/tests/fixtures/marketplace-listing/` — sample SSP,
  AP, inventory, KSI envelopes used by tests.

**Files to extend**:
- `cloud-evidence/core/submission-bundle.ts` — add roles
  `marketplace-listing-json` (filename `marketplace-listing.json`) +
  `marketplace-listing-md` (filename `marketplace-listing.md`) to
  `WELL_KNOWN`.
- `cloud-evidence/core/orchestrator.ts` — `--marketplace-listing`
  flag + env `CLOUD_EVIDENCE_MARKETPLACE_LISTING`. Runs AFTER POA&M +
  AR emission (Q.Q1 needs poam.json + assessment-results.json present).
- `cloud-evidence/core/orchestrator.ts` — `--strict-marketplace` flag:
  exits non-zero when any required listing field is REQUIRES-OPERATOR-
  INPUT.

**Schemas / standards**:
- **Locally-authored `marketplace-listing.v1` JSON Schema** at
  `cloud-evidence/docs/schemas/marketplace-listing.v1.json`. Field set
  derived from:
  - RFC-0021 MKT-GEN-DOD: `agencies_directly_using[]`,
    `agencies_requested_access[]`, `next_ongoing_authorization_report_date`.
  - 20x ADS standard: `fedramp_marketplace_link`,
    `service_and_deployment_models[]`, `business_category`, `uei_number`,
    `contact_information`, `service_description`,
    `customer_responsibility_summary`, `trust_center_access_process`,
    `support_information`.
  - Marketplace listing page (live registry): `cso_name`, `impact_level`
    ∈ {low, moderate}, `3pao_name`, `3pao_uei`,
    `sponsoring_agency_name`, `sponsoring_agency_ato_date`,
    `marketplace_status` ∈ {fedramp_ready, in_process, authorized},
    `marketplace_id` (assigned by FedRAMP, operator-supplied),
    `package_id` (assigned by FedRAMP, operator-supplied).
  - Implementation-only fields: `package_format_version:
    "20x.phase-two.preview.2026"`, `emitted_at`, `provenance`.
- When the FedRAMP CR26 schema publishes (June 2026 expected), Q.Q1
  migrates to `marketplace-listing.cr26.v1`; the schema field set
  shifts; the migration emits a CHANGELOG entry quoting the diff.
- **Markdown renderer** mirrors the JSON 1:1 with section headings per
  field group (CSO Identity → Authorization Status → 3PAO + Assessment
  → Services in Scope → Agency Reuse → Trust Center + Contact → POA&M
  Summary → Provenance).

**Build steps**:

1. Define types in `core/marketplace-listing.ts`:
   ```ts
   export type MarketplaceStatus = 'fedramp_ready' | 'in_process' | 'authorized';
   export type ServiceModel = 'iaas' | 'paas' | 'saas';
   export type DeploymentModel = 'public' | 'private' | 'community' | 'hybrid' | 'government';
   export type ImpactLevel = 'low' | 'moderate' | 'high';

   export interface AgencyReuseEntry {
     agency_name: string;
     agency_uei?: string;
     ato_date: string;          // ISO date
     ato_signing_official?: string;
     status: 'active' | 'expired' | 'revoked';
     leveraged_package_id?: string;
   }

   export interface MarketplaceListing {
     schema_version: 'marketplace-listing.v1';
     package_format_version: '20x.phase-two.preview.2026';
     emitted_at: string;
     cso_name: string;
     csp_name: string;
     csp_uei: string;
     impact_level: ImpactLevel;
     service_models: ServiceModel[];
     deployment_models: DeploymentModel[];
     marketplace_status: MarketplaceStatus;
     marketplace_id: string | null;     // FedRAMP-assigned; null until assigned
     package_id: string | null;          // FedRAMP-assigned
     sponsoring_agency: { name: string; uei?: string; ato_date: string | null; signing_official_name?: string } | null;
     three_pao: { name: string; uei?: string; assessment_date: string | null };
     services_in_scope: { provider: 'aws'|'gcp'|'azure'|'k8s'; service_id: string; service_name: string }[];
     controls_in_scope: { control_id: string; control_family: string }[];
     ksi_baseline: { ksi_id: string; domain: string; status: 'PASS'|'FAIL'|'PARTIAL'|'NOT-APPLICABLE' }[];
     poam_summary: { open_count: number; critical_count: number; high_count: number; moderate_count: number; low_count: number; deviation_approved_count: number };
     agencies_directly_using: AgencyReuseEntry[];
     agencies_requested_access: { agency_name: string; requested_at: string; status: 'pending' | 'granted' | 'denied' }[];
     next_ongoing_authorization_report_date: string;
     trust_center: { url: string; access_process: string; data_formats: ('human-readable' | 'machine-readable')[] };
     contact: { name: string; email: string; phone?: string; role: string };
     customer_responsibility_summary: string;
     service_description: string;
     support_information: { url?: string; email?: string; sla?: string };
     business_category: string;
     fedramp_marketplace_link: string | null;
     provenance: {
       emitter: 'marketplace-listing.ts';
       emitted_at: string;
       source_calls: string[];
       signing_key_id: string;
     };
     requires_operator_input: string[];  // every unfilled field with the source pointer
   }
   ```

2. Pure builder signature:
   ```ts
   export function buildMarketplaceListing(inputs: {
     ssp: OscalSsp;
     ap?: OscalAp;
     ar?: OscalAr;
     poam?: OscalPoam;
     inventory: Inventory;
     ksiMap: KsiMap;
     ksiEnvelopes: Map<string, EvidenceEnvelope>;
     controlBenchmark: ControlBenchmark;
     agencyAuthorizations: AgencyAuthorization[];
     configMarketplace: MarketplaceConfig;
     emittedAt?: string;
   }): MarketplaceListing;
   ```

3. **Derive `impact_level`** from SSP `system-characteristics.security-impact-level`
   (`security-objective-confidentiality`, `security-objective-integrity`,
   `security-objective-availability`). Per FIPS 199, max of the three →
   impact level. Q.Q1 emits {low, moderate}; "high" surfaces a
   `REQUIRES-OPERATOR-INPUT: 20x-high-not-yet-supported` marker
   (consistent with the existing HIGH-CLARIFY behaviour).

4. **Derive `services_in_scope`** from `inventory.assets[]` aggregated by
   provider + service. For AWS: distinct `service` field; for GCP:
   distinct `service` field; for Azure: distinct `resource_provider`.
   Display names come from a small lookup table (operator-tunable via
   config) — never invented.

5. **Derive `controls_in_scope`** from `core/control-benchmark.ts` filtered
   by impact level (moderate by default).

6. **Derive `ksi_baseline`** from `core/ksi-map.ts` joined with `out/KSI-*.json`
   envelopes' `summary.status`. Each KSI gets one row.

7. **Derive `poam_summary`** from `out/poam.json`'s
   `poam-items[].risks[]` counted by severity + `risk.status`.

8. **Derive `agencies_directly_using`** from Q.Q3 tracker
   `agency_authorizations` table where `status='active'`. When Q.Q3 is
   not yet shipped, this is an empty array + a
   `REQUIRES-OPERATOR-INPUT: agency-authorizations-source` entry.

9. **Operator-supplied fields** (REQUIRES-OPERATOR-INPUT when absent in
   `config.yaml`):
   - `csp_name`, `csp_uei` — CSP organisation identity.
   - `sponsoring_agency` — required to publish as `authorized`.
   - `three_pao.name`, `three_pao.uei`, `three_pao.assessment_date`.
   - `business_category` — from a controlled vocabulary in config.
   - `service_description` — operator-authored marketing description.
   - `customer_responsibility_summary` — operator-authored (overlaps
     LOOP-L.L1 CRM when ratified; Q.Q1 reads
     `config.marketplace.customer_responsibility_summary` directly).
   - `trust_center.url`, `trust_center.access_process`.
   - `contact.name`, `contact.email`, `contact.role`.
   - `support_information.url`, `support_information.email`,
     `support_information.sla`.
   - `marketplace_id`, `package_id` — FedRAMP-assigned at listing time;
     remain null until PMO assigns + operator records.

10. **Compute `next_ongoing_authorization_report_date`** as the first
    day of the NEXT month from `emittedAt` (mirrors monthly ConMon
    cadence). Q.Q2 publication updates the tracker
    `marketplace_listing_history` row with the actual report date when
    the publication is created.

11. **Validate** the listing against `marketplace-listing.v1.json` schema
    via `core/oscal-validate.ts` (ajv reused). Validation failure
    blocks emission under `--strict-marketplace`.

12. **Disk emitter** in `core/marketplace-listing.ts`:
    ```ts
    export interface MarketplaceListingEmitOptions {
      outDir: string;
      sspPath?: string;            // default outDir/ssp.json
      apPath?: string;
      arPath?: string;
      poamPath?: string;
      inventoryPath?: string;
      configPath?: string;
      agencyAuthorizationsPath?: string;
      strict?: boolean;
      runId: string;
    }
    export interface MarketplaceListingEmitResult {
      jsonPath: string;
      mdPath: string;
      requires_operator_input: string[];
      schema_validation_passed: boolean;
    }
    export function emitMarketplaceListing(opts: MarketplaceListingEmitOptions): Promise<MarketplaceListingEmitResult>;
    ```

13. **Wire into orchestrator**: `--marketplace-listing` invokes
    `emitMarketplaceListing()` AFTER OSCAL POA&M + AR are emitted (so
    `poam_summary` is real) AND AFTER Q.Q3 agency-authorizations snapshot
    is pulled.

14. **Add to `submission-bundle.ts` WELL_KNOWN**:
    ```ts
    { role: 'marketplace-listing-json', filename: 'marketplace-listing.json', description: 'FedRAMP Marketplace listing per RFC-0021 (Q.Q1)' },
    { role: 'marketplace-listing-md', filename: 'marketplace-listing.md', description: 'Marketplace listing Markdown mirror (Q.Q1)' },
    ```

15. **Sign + timestamp**: `marketplace-listing.json` + `.md` are picked up
    by the existing `core/sign.ts` glob + included in the RFC 3161
    manifest. Trust Center publication serves the same signed bytes.

**REQUIRES-OPERATOR-INPUT fields** (per REO Rule 4):

| Field | Source | Behavior when missing |
|---|---|---|
| `csp_name` / `csp_uei` | `config.yaml` `marketplace.csp_name` + `csp_uei` | Listed in `requires_operator_input[]`; `--strict-marketplace` blocks |
| `sponsoring_agency` | `config.yaml` `marketplace.sponsoring_agency` + Q.Q3 tracker | Q.Q3 record OR config; if absent, status forced to `in_process`; emitter records the gap |
| `three_pao` | `config.yaml` `marketplace.three_pao` + RoE signature block | Marker emitted; Markdown shows "TBD - REQUIRES-OPERATOR-INPUT: 3PAO identity not in config" |
| `business_category` | `config.yaml` controlled vocab | Marker emitted |
| `service_description` | `config.yaml` | Marker emitted |
| `customer_responsibility_summary` | `config.yaml` (or LOOP-L.L1 CRM workbook when adopted) | Marker emitted |
| `trust_center` | `config.yaml` `marketplace.trust_center` (LOOP-G.G3 ADS) | Marker emitted; if G.G3 not done, the trust_center fields point at FedPy local Trust Center stub |
| `contact` | `config.yaml` | Marker emitted |
| `support_information` | `config.yaml` | Marker emitted |
| `marketplace_id` / `package_id` | FedRAMP PMO-assigned via tracker UI | Null until assigned; Q.Q3 UI captures |

**Test specifications** (≥12 tests):

1. `it('builds a valid listing from fixture SSP + AP + POA&M + inventory + KSI envelopes')` — pure builder; asserts schema validates.
2. `it('derives impact_level=moderate from FIPS-199 max of confidentiality/integrity/availability')`.
3. `it('flags REQUIRES-OPERATOR-INPUT: 20x-high-not-yet-supported when impact_level=high')`.
4. `it('enumerates services_in_scope from inventory.json aggregated per provider+service')`.
5. `it('reads agency_authorizations from snapshot and populates agencies_directly_using[]')`.
6. `it('emits empty agencies_directly_using[] + marker when Q.Q3 snapshot absent')`.
7. `it('reads operator-supplied sponsoring_agency from config.yaml')`.
8. `it('forces marketplace_status=in_process when sponsoring_agency absent and ATO date missing')`.
9. `it('emits requires_operator_input[] containing every missing operator field')`.
10. `it('--strict-marketplace blocks emission when requires_operator_input[] non-empty')`.
11. `it('writes marketplace-listing.json + .md atomically with matching sha256')`.
12. `it('Markdown renderer produces section headings 1:1 with JSON groups')`.
13. `it('schema validation rejects unknown enum value for marketplace_status')`.
14. `it('next_ongoing_authorization_report_date is the first of next month')`.
15. `it('poam_summary counts critical / high / moderate / low / deviation_approved from poam.json')`.
16. `it('ksi_baseline reads PASS/FAIL/PARTIAL from real KSI envelopes')`.
17. `it('provenance.source_calls lists every file the emitter read')`.
18. `it('submission-bundle WELL_KNOWN includes both marketplace-listing roles')`.

**REO compliance** specific to this slice:
- Every value in the emitted artifact traces to: SSP (CSO identity, impact
  level), AP/AR/RoE (3PAO date), POA&M (item counts), inventory (services),
  KSI envelopes (control coverage), Q.Q3 tracker (agencies),
  `config.yaml` (operator-authored prose).
- No silent fallbacks for: any missing operator field surfaces as
  REQUIRES-OPERATOR-INPUT in `requires_operator_input[]` AND in the
  Markdown.
- Provenance fields populated: `emitter`, `emitted_at`, `source_calls`,
  `signing_key_id`.
- Signed by: existing `core/sign.ts` pipeline (manifest + Ed25519
  detached signature + RFC 3161 timestamp).
- Schema-validated: `marketplace-listing.v1.json` via `core/oscal-validate.ts`'s
  ajv harness.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/marketplace-listing.test.ts tests/core/marketplace-listing-markdown.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 5 working days for a single implementer.

---

### Slice Q.Q2 — Post-ATO ConMon publication (monthly delivery to FedRAMP secure repository)

**Why this slice**: FedRAMP CMP + RFC-0026 obligate the CSP to deliver
monthly ConMon artifacts (POA&M update, vulnerability scans, OS / DB / web
app / container scans, meeting recording or notes) to the FedRAMP secure
repository + every leveraging agency. Today the FedPy pipeline emits all
the *raw* monthly evidence (existing collectors + LOOP-E.E1 analysis +
LOOP-E.E2 POA&M delta) but does not bundle, sign, manifest, and ship them
as the monthly delivery artifact. Q.Q2 closes the post-ATO recurring-
delivery gap.

**Connection to FedPy mission**: Q.Q2 is a CONSUMER of existing FedPy
outputs:
- Reads monthly KSI envelopes (`out/KSI-*.json`) from cloud collectors.
- Reads LOOP-A.A1 OSCAL POA&M (`out/poam.json`).
- Reads LOOP-E.E1 monthly analysis report (when present) +
  LOOP-E.E2 POA&M delta (when present) — gracefully degrades to
  REQUIRES-OPERATOR-INPUT markers when LOOP-E slices not shipped.
- Reuses the LOOP-A.A4 pure-JS POSIX tar writer + INDEX.json pattern +
  reuses `core/sign.ts` + `core/timestamp.ts`.
- Reuses Q.Q1's Marketplace listing as the "current authorization
  status" reference at the top of the manifest.
- Reuses Q.Q3 tracker `agency_authorizations` to determine the
  publication destination list (which agencies / which Trust Centers
  receive a notification when the monthly bundle is ready).

**Files to create**:
- `cloud-evidence/core/conmon-publication.ts` — bundler + manifest.
  Reuses `core/submission-bundle.ts` POSIX tar writer.
- `cloud-evidence/core/conmon-publication-manifest.ts` — manifest
  schema + builder (INDEX.json analogue with `period: YYYY-MM`).
- `cloud-evidence/docs/schemas/conmon-publication.v1.json` — manifest
  schema.
- `cloud-evidence/tests/core/conmon-publication.test.ts` — ≥12 tests.
- `cloud-evidence/tests/core/conmon-publication-manifest.test.ts`.
- `tracker/server/routes/conmon-publications.ts` — log endpoint:
  `POST /api/conmon-publications` (record), `GET /api/conmon-publications`
  (list), `GET /api/conmon-publications/:period` (per-period detail).
- `tracker/client/src/pages/ConmonPublicationLog.tsx` — table view.
- `tracker/server/routes/conmon-publications.test.ts`.
- `tracker/client/src/pages/ConmonPublicationLog.test.tsx`.

**Files to extend**:
- `cloud-evidence/core/submission-bundle.ts` — add roles
  `conmon-publication-tarball`, `conmon-publication-manifest` to
  `WELL_KNOWN`.
- `cloud-evidence/core/orchestrator.ts` — `--conmon-publication` flag +
  env `CLOUD_EVIDENCE_CONMON_PUBLICATION`; `--conmon-period <YYYY-MM>`
  (default current month); `--conmon-destination <list>` for Trust
  Center notification.
- `tracker/server/schema.sql` — table `conmon_publication_log`.
- `tracker/server/index.ts` — mount route.
- `tracker/server/rbac.ts` — `iso` can create publications; `ao` can
  acknowledge.
- `tracker/client/src/App.tsx` — route `/conmon-publication-log`.

**Schemas / standards**:
- **Locally-authored `conmon-publication.v1` manifest schema** at
  `cloud-evidence/docs/schemas/conmon-publication.v1.json`. Top-level
  fields:
  ```jsonc
  {
    "schema_version": "conmon-publication.v1",
    "package_format_version": "20x.phase-two.preview.2026",
    "period": "YYYY-MM",                          // e.g. "2026-07"
    "cso_name": "string",
    "csp_uei": "string",
    "sponsoring_agency": "string",
    "emitted_at": "ISO datetime",
    "artifacts": [
      {
        "filename": "string",
        "role": "poam-update|os-scan|db-scan|web-app-scan|container-scan|service-config-scan|conmon-analysis-report|ksi-envelope|meeting-notes|signed-manifest|rfc3161-timestamp",
        "sha256": "hex64",
        "bytes": "int",
        "description": "string"
      }
    ],
    "prior_period_reference": {
      "period": "YYYY-MM",
      "manifest_sha256": "hex64"
    },
    "destinations": [
      {
        "agency_name": "string",
        "trust_center_url": "string",
        "notified_at": "ISO datetime|null",
        "notification_method": "trust-center-publish|email|api-call"
      }
    ],
    "gaps": [{ "role": "string", "description": "string" }],
    "provenance": {
      "emitter": "conmon-publication.ts",
      "emitted_at": "ISO datetime",
      "source_calls": ["..."],
      "signing_key_id": "string"
    }
  }
  ```
- **FedRAMP CMP** (downloaded PDF) — monthly artifact list quoted
  verbatim in module docstring; the `role` enum above mirrors the
  CMP-required artifact list (OS / DB / Web App / Container / Service
  Config scans + POA&M update + meeting notes).
- **RFC-0026** — quoted in module docstring as the live (2026) source
  for the monthly cadence.
- **OSCAL POA&M v1.1.2** — for the included POA&M update (existing).
- **OSCAL Assessment Results v1.1.2** — for the prior-period
  reference (existing).

**Build steps**:

1. Define `ConmonPublicationManifest` type matching the schema.
2. Pure builder:
   ```ts
   export function buildConmonPublicationManifest(inputs: {
     period: string;             // YYYY-MM
     outDir: string;
     cso_name: string;
     csp_uei: string;
     sponsoring_agency: string;
     priorPeriodPath?: string;
     destinations: AgencyAuthorization[];
     emittedAt?: string;
   }): ConmonPublicationManifest;
   ```
3. **File discovery**: walks `outDir` (and `outDir/summaries`) for files
   matching the per-period glob: `KSI-*.json`, `poam.json`,
   `assessment-results.json`, `conmon-analysis-*.md`,
   `poam-delta-*.json`, `vdr-report-*.json`, scans named
   `*os-scan*.json`, `*db-scan*.json`, `*web-app-scan*.json`,
   `*container-scan*.json`, `*service-config-scan*.json`,
   `*meeting-notes*.md`. Classifies each against the manifest role
   table. Files outside the role table are bundled with `role:
   "unrecognized"` (not silently dropped, per LOOP-A.A4 precedent).
4. **Prior-period reference**: when `--conmon-prior <path>` is given,
   read the prior month's manifest; embed its `period` + `manifest_sha256`
   in `prior_period_reference`. When prior period absent, emit
   `prior_period_reference: null` + a one-line warning (not an error).
5. **Destination list**: read Q.Q3 tracker
   `agency_authorizations WHERE status='active'`; for each agency emit a
   `destinations[]` entry with `trust_center_url` from the Q.Q3 row.
   When Q.Q3 absent OR no agencies, single entry `[{ agency_name:
   "FedRAMP PMO (sponsoring agency)", trust_center_url: <config>,
   notified_at: null, notification_method: "trust-center-publish" }]`.
6. **Bundle** the artifacts into `out/conmon-publication-<YYYY-MM>.tar.gz`
   using the LOOP-A.A4 POSIX ustar writer (reuse the `tarWriter()`
   helper; same `mtime` reproducibility option). Emit a top-level
   `INDEX.json` (= the manifest) inside the tarball.
7. **Sign + timestamp**: write
   `out/conmon-publication-<YYYY-MM>.manifest.json` outside the tarball
   AND inside; sign the outer manifest via `core/sign.ts`; timestamp
   via `core/timestamp.ts`.
8. **Record in tracker**: `POST /api/conmon-publications` with the
   manifest sha256, period, destination count, gap count. Tracker
   stores a row with `created_by_user_id`, audit-log entry.
9. **Notification**: For each destination, write `trust_center_url +
   "/conmon/" + period + "/manifest.json"` to the local mirror at
   `out/trust-center-mirror/<agency_uei>/<period>/`. Actual HTTP push
   to remote Trust Centers is deferred to LOOP-G.G3 (AFR-ADS); Q.Q2
   only materializes the mirror payload.
10. **Idempotency**: re-running with the same `--conmon-period` is
    safe — emitter computes sha256, compares with prior manifest, skips
    write if unchanged + records `no-op` in tracker.
11. **`--strict-marketplace`** (cross-loop flag) also blocks Q.Q2 emit
    when `requires_operator_input[]` in the inner manifest is non-empty.
12. **Submission-bundle integration**: add roles to `WELL_KNOWN`. The
    LOOP-A.A4 bundler can include the conmon publication as a separate
    role; useful when the operator wants a single super-bundle
    containing submission + first monthly delivery.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | Source | Behavior when missing |
|---|---|---|
| `cso_name`, `csp_uei`, `sponsoring_agency` | `config.yaml` `marketplace.*` (Q.Q1 reuses) | Marker emitted; `--strict-marketplace` blocks |
| `destinations[].trust_center_url` | Q.Q3 tracker `agency_authorizations.trust_center_url` | Marker emitted per missing agency; `notification_method: 'trust-center-publish'` falls back to `'email'` with operator-supplied `notification_email` |
| `priorPeriodPath` | CLI flag `--conmon-prior <path>` OR auto-detect from `out/conmon-publication-<prev-month>.manifest.json` | When absent + no prior month detected, `prior_period_reference: null` + warning |
| Scan artifacts (OS / DB / Web App / Container / Service Config) | Collectors per LOOP-E.E1 / E.E2 / existing VDR pipeline | Each missing class becomes a `gaps[]` entry with `role` + descriptive `description` |
| `meeting-notes` | Operator drops the file into `outDir/meeting-notes-<YYYY-MM>.md` | When absent, `gaps[]` entry; `--strict-marketplace` blocks |
| Meeting cadence + topics (per RFC-0026) | Operator-supplied via config | When absent, marker; not strict-blocking (meeting required but content authored by CSP) |

**Test specifications** (≥12 tests):

1. `it('discovers and classifies every per-period artifact under WELL_KNOWN role table')`.
2. `it('emits manifest.json with all required fields and provenance block')`.
3. `it('signs the manifest via core/sign.ts and timestamps via core/timestamp.ts')`.
4. `it('embeds prior_period_reference when prior manifest exists in outDir')`.
5. `it('emits prior_period_reference: null + warning when no prior')`.
6. `it('reads destinations[] from Q.Q3 agency_authorizations snapshot')`.
7. `it('falls back to single sponsoring-agency entry when Q.Q3 absent')`.
8. `it('emits gaps[] entry for each missing scan class (OS / DB / Web App / Container / Service Config)')`.
9. `it('--strict-marketplace blocks emit when meeting-notes file absent')`.
10. `it('idempotent: re-running with same period + identical inputs skips write + records no-op')`.
11. `it('reproducibility: BundleEmitOptions.mtime produces byte-stable tar header')`.
12. `it('tracker route POST /api/conmon-publications records a row with audit-log entry')`.
13. `it('--conmon-publication flag wires into orchestrator after POA&M emit')`.
14. `it('submission-bundle WELL_KNOWN includes both conmon-publication roles')`.
15. `it('trust-center mirror layout writes <agency_uei>/<period>/manifest.json')`.
16. `it('rejects period strings not matching YYYY-MM regex')`.

**REO compliance** specific to this slice:
- Every artifact in the tarball comes from the real `outDir` — no
  synthesized content.
- Every file's sha256 + bytes recorded; mismatch between tarball and
  manifest fails the bundle.
- Provenance: `emitter`, `emitted_at`, `source_calls` listing every
  file globbed.
- Signed by existing `core/sign.ts` (Ed25519 + manifest).
- Timestamped by existing `core/timestamp.ts` (RFC 3161, with multi-TSA
  cascade if `docs/ADDITIONAL-LOOPS-AUDIT.md` §3.12 lands).
- Missing artifacts surface as `gaps[]` — never silently dropped, never
  substituted.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/conmon-publication.test.ts tests/core/conmon-publication-manifest.test.ts
npm run check:reo
npm run check:provenance
cd ../tracker
npm run typecheck
npm test -- server/routes/conmon-publications.test.ts client/src/pages/ConmonPublicationLog.test.tsx
```

**Estimated effort**: 5 - 6 working days (cloud-evidence emitter +
tracker + UI + integration tests).

---

### Slice Q.Q3 — Agency authorization tracking (who is using the CSO + their authorization documents)

**Why this slice**: RFC-0021 MKT-GEN-DOD requires the Marketplace listing
to publish "a list of all _agencies_ that are directly using the
product" + "agencies that have requested access to _authorization data_,
covering the period since the previous _Ongoing Authorization Report_".
Today the FedPy pipeline has nowhere to track per-agency authorization
events (each new ATO that leverages the existing FedRAMP authorization,
each access request for the authorization package, each subsequent
revocation). Q.Q3 creates the tracker workflow, exposes a snapshot to
Q.Q1 + Q.Q2, and emits a structured `agency-authorizations.json`
artifact for long-term retention + executive dashboard consumption.

**Connection to FedPy mission**: Q.Q3 is a tracker-side process-artifact
slice (consistent with the existing tracker process-artifact pattern at
`core/process-artifact-tracker.ts`). It does NOT add any cloud
collectors. It DOES add:
- Structured records of each agency's ATO event (operator-entered via
  UI, signed via the existing Ed25519 tracker key).
- An emitter `core/agency-authorization-emitter.ts` that reads the
  tracker DB through the cloud-evidence read-only API token and
  produces `out/agency-authorizations.json` for inclusion in Q.Q1's
  listing + LOOP-H.H2 retention.
- A timeline view (per-agency event log) that LOOP-I.I1 exec dashboard
  consumes for the "agencies leveraging this CSO" widget.

**Files to create**:
- `tracker/server/routes/agency-authorizations.ts` — CRUD endpoints:
  `POST /api/agency-authorizations`,
  `GET /api/agency-authorizations`,
  `GET /api/agency-authorizations/:uuid`,
  `POST /api/agency-authorizations/:uuid/events`,
  `POST /api/agency-authorizations/:uuid/revoke`.
- `tracker/client/src/pages/AgencyAuthorizations.tsx` — list + create UI.
- `tracker/client/src/pages/AgencyAuthorizationDetail.tsx` — per-agency
  detail with timeline + access-request log + ATO document upload.
- `cloud-evidence/core/agency-authorization-reader.ts` — read-only
  client the orchestrator uses to pull active authorizations from the
  tracker (mirrors `risk-acceptance-reader.ts` pattern).
- `cloud-evidence/core/agency-authorization-emitter.ts` — writes
  `out/agency-authorizations.json` with provenance.
- `tracker/server/routes/agency-authorizations.test.ts`.
- `tracker/client/src/pages/AgencyAuthorizations.test.tsx`.
- `cloud-evidence/tests/core/agency-authorization-reader.test.ts`.
- `cloud-evidence/tests/core/agency-authorization-emitter.test.ts`.

**Files to extend**:
- `tracker/server/schema.sql` — append three tables:
  ```sql
  CREATE TABLE IF NOT EXISTS agency_authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    agency_name TEXT NOT NULL,
    agency_uei TEXT,
    agency_short_name TEXT,                  -- e.g., "DOD", "DHS"
    ato_date TEXT NOT NULL,
    ato_expiration_date TEXT,
    ato_signing_official_name TEXT NOT NULL,
    ato_signing_official_title TEXT,
    ato_letter_evidence_path TEXT,           -- attachment uploaded via tracker
    ato_letter_sha256 TEXT,
    leveraged_package_id TEXT,               -- when this agency leverages our package
    impact_level TEXT CHECK (impact_level IN ('low','moderate','high')),
    is_sponsoring_agency INTEGER NOT NULL CHECK (is_sponsoring_agency IN (0,1)),
    trust_center_url TEXT,
    notification_email TEXT,
    notification_phone TEXT,
    status TEXT NOT NULL CHECK (status IN ('active','expired','revoked')),
    created_by_user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by_user_id INTEGER REFERENCES users(id),
    revocation_reason TEXT,
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_aa_status ON agency_authorizations(status);
  CREATE INDEX IF NOT EXISTS idx_aa_ato_date ON agency_authorizations(ato_date);
  CREATE INDEX IF NOT EXISTS idx_aa_sponsoring ON agency_authorizations(is_sponsoring_agency);

  CREATE TABLE IF NOT EXISTS agency_reuse_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    agency_authorization_id INTEGER NOT NULL REFERENCES agency_authorizations(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK (event_type IN ('access-requested','access-granted','access-denied','package-downloaded','ato-issued','ato-renewed','ato-expired','ato-revoked','conmon-acknowledged','support-ticket')),
    occurred_at TEXT NOT NULL,
    actor_user_id INTEGER REFERENCES users(id),       -- nullable: external event
    actor_name TEXT,                                  -- external actor name when actor_user_id null
    details TEXT,                                     -- JSON-encoded event payload
    signature TEXT,
    signing_key_id TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_are_authorization ON agency_reuse_events(agency_authorization_id);
  CREATE INDEX IF NOT EXISTS idx_are_event_type ON agency_reuse_events(event_type);

  CREATE TABLE IF NOT EXISTS marketplace_listing_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    emitted_at TEXT NOT NULL,
    listing_sha256 TEXT NOT NULL,
    marketplace_status TEXT NOT NULL CHECK (marketplace_status IN ('fedramp_ready','in_process','authorized')),
    marketplace_id TEXT,
    package_id TEXT,
    agency_count INTEGER NOT NULL,
    poam_open_count INTEGER NOT NULL,
    next_ongoing_authorization_report_date TEXT,
    emitted_by_user_id INTEGER REFERENCES users(id),
    signature TEXT,
    signing_key_id TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_mlh_emitted_at ON marketplace_listing_history(emitted_at);

  CREATE TABLE IF NOT EXISTS conmon_publication_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    period TEXT NOT NULL UNIQUE,                      -- YYYY-MM
    manifest_sha256 TEXT NOT NULL,
    tarball_sha256 TEXT NOT NULL,
    tarball_bytes INTEGER NOT NULL,
    artifact_count INTEGER NOT NULL,
    destination_count INTEGER NOT NULL,
    gap_count INTEGER NOT NULL,
    emitted_at TEXT NOT NULL,
    emitted_by_user_id INTEGER REFERENCES users(id),
    rfc3161_timestamp_path TEXT,
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    acknowledged_by_agency_count INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_cpl_period ON conmon_publication_log(period);
  ```
- `tracker/server/index.ts` — mount `agency-authorizations.ts`,
  `marketplace-listings.ts`, `conmon-publications.ts`.
- `tracker/server/rbac.ts` — define `marketplace:edit`,
  `agency-auth:create`, `agency-auth:revoke`, `marketplace:view`,
  `conmon:publish` permissions; assign to existing role set.
- `tracker/client/src/App.tsx` — routes `/agency-authorizations`,
  `/marketplace-listing`, `/conmon-publication-log`.
- `cloud-evidence/core/submission-bundle.ts` — add role
  `agency-authorizations-json` (filename `agency-authorizations.json`).
- `cloud-evidence/core/orchestrator.ts` — `--agency-auth-export` flag +
  env; runs BEFORE `--marketplace-listing` so Q.Q1 picks up the
  snapshot.

**Schemas / standards**:
- RFC-0021 MKT-GEN-DOD: required Marketplace fields (already quoted in
  §4).
- 20x ADS standard: Trust Center URL requirement.
- OSCAL POA&M does NOT have an "agency" concept — Q.Q3's records live
  outside the OSCAL chain; the Marketplace listing (Q.Q1) is where the
  records surface to FedRAMP.
- **Locally-authored `agency-authorizations.v1` JSON Schema** at
  `cloud-evidence/docs/schemas/agency-authorizations.v1.json`. Top-level:
  ```jsonc
  {
    "schema_version": "agency-authorizations.v1",
    "emitted_at": "ISO datetime",
    "cso_name": "string",
    "authorizations": [
      {
        "uuid": "string",
        "agency_name": "string",
        "agency_uei": "string|null",
        "agency_short_name": "string|null",
        "ato_date": "ISO date",
        "ato_expiration_date": "ISO date|null",
        "ato_signing_official_name": "string",
        "ato_signing_official_title": "string|null",
        "impact_level": "low|moderate|high",
        "is_sponsoring_agency": "boolean",
        "leveraged_package_id": "string|null",
        "status": "active|expired|revoked",
        "trust_center_url": "string|null",
        "events": [
          {
            "uuid": "string",
            "event_type": "...",
            "occurred_at": "ISO datetime",
            "actor_name": "string|null",
            "details": "object|null"
          }
        ]
      }
    ],
    "provenance": {
      "emitter": "agency-authorization-emitter.ts",
      "emitted_at": "ISO datetime",
      "source_calls": ["tracker GET /api/agency-authorizations", ...],
      "signing_key_id": "string"
    },
    "requires_operator_input": ["..."]
  }
  ```

**Build steps**:

1. Tracker DB migration: `CREATE TABLE IF NOT EXISTS` (idempotent,
   additive only — per `docs/loops/LOOP-B-RISKS.md#B-X10`).
2. **CRUD route logic** in `tracker/server/routes/agency-authorizations.ts`:
   - `POST /api/agency-authorizations` (create): RBAC `iso`+;
     validates `agency_name` non-empty, `ato_date` valid ISO date,
     `impact_level` ∈ allowed enum; signs the canonical-JSON payload
     `{uuid, agency_name, ato_date, ato_signing_official_name,
     created_by_user_id, created_at}` with the resident Ed25519 key.
   - `POST /api/agency-authorizations/:uuid/events`: append an event
     with `event_type` enum-validated; signed when `actor_user_id` set.
   - `POST /api/agency-authorizations/:uuid/revoke`: RBAC `ao`+;
     records `revoked_at`, `revoked_by_user_id`, `revocation_reason`;
     status flipped to `revoked`; subsequent Marketplace listing
     emission removes the row from `agencies_directly_using`.
3. **Sponsoring-agency invariant**: exactly one row may have
   `is_sponsoring_agency = 1` (enforced via partial unique index +
   route logic). Attempted create violating this returns 409.
4. **ATO letter upload**: reuse H.4 attachment pattern; sha256 stored
   on row; download endpoint requires `assessor`+ role.
5. **Reader** `core/agency-authorization-reader.ts`:
   ```ts
   export interface PulledAgencyAuthorization { ... }
   export async function pullAgencyAuthorizations(
     trackerUrl: string,
     apiToken: string,
     outDir: string,
   ): Promise<PulledAgencyAuthorization[]>;
   ```
   Writes `out/.agency-authorizations.json` snapshot + verifies every
   record's signature against the tracker's published public key
   (per LOOP-B-X3 pattern).
6. **Emitter** `core/agency-authorization-emitter.ts`:
   ```ts
   export interface AgencyAuthorizationEmitOptions {
     outDir: string;
     trackerUrl?: string;
     apiToken?: string;
     snapshotPath?: string;          // default outDir/.agency-authorizations.json
     runId: string;
   }
   export interface AgencyAuthorizationEmitResult {
     path: string;
     authorization_count: number;
     active_count: number;
     event_count: number;
   }
   export function emitAgencyAuthorizations(opts: AgencyAuthorizationEmitOptions): Promise<AgencyAuthorizationEmitResult>;
   ```
   Reads snapshot, produces `out/agency-authorizations.json` with
   provenance.
7. **Orchestrator wiring**: `--agency-auth-export` runs BEFORE
   `--marketplace-listing`; the Marketplace emitter consumes the
   snapshot.
8. **UI**:
   - `AgencyAuthorizations.tsx`: table with columns Agency, Short
     Name, Status, ATO Date, Expiration, Sponsoring (badge),
     Last Event; "Add agency" button → modal with form.
   - `AgencyAuthorizationDetail.tsx`: detail view with timeline of
     `agency_reuse_events`, ATO letter upload, revoke button (AO
     only), Trust Center URL editor.
9. **Audit log**: every create / event-append / revoke writes to the
   existing `audit_log` table.
10. **Snapshot validation under `--strict-marketplace`**:
    - At least one row with `is_sponsoring_agency=1`.
    - Every active row has `trust_center_url` set (Q.Q2 destination
      list requires it).
    - Otherwise: emit REQUIRES-OPERATOR-INPUT markers + non-zero exit.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | Source | Behavior when missing |
|---|---|---|
| All agency rows | Operator UI input (tracker page) | Empty snapshot → marker; Q.Q1 emits empty `agencies_directly_using[]` |
| `is_sponsoring_agency` | Operator selects exactly one row | Validation rejects multiple; `--strict-marketplace` rejects zero |
| `trust_center_url` | Operator UI input per agency | Per-row marker; Q.Q2 destination loses that agency + falls back to notification_email |
| ATO letter attachment | Operator uploads PDF | Optional; absence not blocking but visible in detail page |
| `revocation_reason` | Operator UI on revoke | Required at revoke; route returns 422 if absent |

**Test specifications** (≥12 tests):

1. `it('creates an agency_authorization with iso role and signs the payload')`.
2. `it('rejects create when user lacks iso role')`.
3. `it('enforces single is_sponsoring_agency=1 invariant')`.
4. `it('appends agency_reuse_events and stores signed signature when actor is logged-in user')`.
5. `it('records external (actor_user_id null) events with actor_name')`.
6. `it('revoke flips status to revoked, records revoked_at + revoked_by + reason')`.
7. `it('rejects revoke without revocation_reason')`.
8. `it('only ao role can revoke')`.
9. `it('reader writes .agency-authorizations.json with verified signatures')`.
10. `it('reader rejects snapshot when any record signature invalid')`.
11. `it('emitter writes agency-authorizations.json with provenance + counts')`.
12. `it('emitter excludes revoked rows from active_count')`.
13. `it('--strict-marketplace rejects emission when zero sponsoring agencies')`.
14. `it('--strict-marketplace rejects emission when active agency has no trust_center_url')`.
15. `it('submission-bundle WELL_KNOWN includes agency-authorizations-json role')`.
16. `it('UI list page filters by status (active / expired / revoked)')`.
17. `it('UI detail page renders event timeline in reverse-chronological order')`.
18. `it('attaches ATO letter via H.4 attachment pattern with sha256 recorded')`.

**REO compliance** specific to this slice:
- Every agency record is operator-supplied through the tracker UI;
  nothing is synthesized.
- Every record is signed (Ed25519) with provenance recorded
  (`signing_key_id`).
- Events are append-only; no UPDATE/DELETE on `agency_reuse_events`
  (revocation is a row-level state change with its own audit log).
- ATO letter attachments mirror H.4 with sha256 stored at upload
  time (per LOOP-B-X9 pattern).
- Sponsoring-agency invariant enforced at schema + route layer.
- `--strict-marketplace` blocks emission when sponsoring-agency or
  trust-center URLs absent.

**Verification commands**:
```bash
cd tracker
npm run typecheck
npm test -- server/routes/agency-authorizations.test.ts client/src/pages/AgencyAuthorizations.test.tsx
cd ../cloud-evidence
npm run typecheck
npm test -- tests/core/agency-authorization-reader.test.ts tests/core/agency-authorization-emitter.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 4 - 5 working days (tracker DB + 3 routes + 2 UI
pages + cloud-evidence reader/emitter).

---

## 6. Loop-wide acceptance criteria

LOOP-Q is COMPLETE when ALL of the following are true:

1. **Q.Q1**: `core/marketplace-listing.ts` emits
   `out/marketplace-listing.json` + `out/marketplace-listing.md` end-to-
   end from real SSP / AP / AR / POA&M / inventory / KSI / Q.Q3
   snapshot. Schema validation passes against
   `marketplace-listing.v1.json`. Every missing operator field surfaces
   as `requires_operator_input[]` marker. `--strict-marketplace` blocks
   emission when markers present. Submission-bundle WELL_KNOWN includes
   both roles.
2. **Q.Q2**: `core/conmon-publication.ts` discovers + classifies +
   bundles every per-period artifact under the `conmon-publication.v1`
   schema. Tarball + manifest emit atomically; manifest signed + RFC
   3161 timestamped. Trust-center mirror layout writes per-agency
   per-period bundles. Tracker `conmon_publication_log` row created per
   publication. Idempotent re-run skip works.
3. **Q.Q3**: tracker has `agency_authorizations`,
   `agency_reuse_events`, `marketplace_listing_history`,
   `conmon_publication_log` tables. CRUD routes + 2 UI pages ship.
   Reader + emitter (cloud-evidence side) round-trip a snapshot. Q.Q1
   reads agency snapshot; Q.Q2 reads destinations from snapshot.
4. All three slices pass `npm run typecheck`, `npm test`, and `npm run
   check:reo` in both `cloud-evidence/` and `tracker/`.
5. CHANGELOG "Unreleased" has three entries (one per slice) with
   module names + verification counts + REO compliance notes.
6. STATUS.md per-slice rows updated.
7. Risks register (`LOOP-Q-RISKS.md`) — every newly-discovered risk
   added; resolved risks moved to the resolved table.
8. End-to-end demo: orchestrator run produces
   `marketplace-listing.json` + `conmon-publication-<period>.tar.gz`
   + signed manifests + RFC 3161 timestamp + tracker rows; submission
   bundle includes all five artifacts.

---

## 7. Open questions / caveats

1. **FedRAMP CR26 Marketplace JSON Schema** — RFC-0021 / NTC-0005
   commit to publishing the JSON Schema by end of June 2026. As of
   2026-06-07 this schema is not yet published. Q.Q1 ships
   `marketplace-listing.v1` as a forward-compatible local schema; when
   CR26 publishes, the implementer migrates to
   `marketplace-listing.cr26.v1` and emits a CHANGELOG entry quoting
   the diff. The `package_format_version: "20x.phase-two.preview.2026"`
   field surfaces the lineage so a Marketplace consumer sees the
   version explicitly.

2. **Trust Center API authentication** — NTC-0005 mentions the JSON
   Schema "along with information about validation" but does not yet
   document an authentication model for direct Marketplace ingest
   (OAuth? mTLS? signed-payload-upload?). Until the PMO publishes, Q.Q1
   emits the listing as a signed artifact the operator uploads
   manually; Q.Q2 emits to local mirror only. Cross-ref
   `docs/ADDITIONAL-LOOPS-AUDIT.md` §5.12.

3. **Sponsoring-agency identity** — `docs/ADDITIONAL-LOOPS-AUDIT.md`
   §5.4 flags "20x has eliminated the JAB; replacement is single-
   agency sponsorship + PMO P-ATO. LOOP-Q.Q1 needs the sponsoring
   agency to be declared in config — is the sponsoring agency known
   yet?" Per the FedPy mission context, the operator must answer this
   before the first Q.Q1 run; the slice docs handle absence with
   REQUIRES-OPERATOR-INPUT markers + `--strict-marketplace` block.

4. **Distinction from AFR-ADS (LOOP-G.G3)** — G.G3 covers the CSP's
   Trust Center publication of the Authorization Data (per ADS
   standard). Q.Q1's `marketplace-listing.json` is the CONTENT G.G3's
   Trust Center serves at the
   `<trust-center>/.well-known/fedramp-marketplace.json` path. G.G3 is
   the SERVING infrastructure; Q.Q1 is the AUTHORITATIVE CONTENT. Both
   slices can ship independently; when both are done, the integration
   is automatic.

5. **Multi-CSO tenant isolation** — all LOOP-Q tracker tables omit a
   `tenant_id` column. H.H3 (future) batches multi-tenant migration
   across LOOP-B/Q tables; for now LOOP-Q ships in single-tenant
   deployments only. Documented in operator runbook.

6. **CR26 SPI removal** — NTC-0005 confirms "MKT-GEN-SPI Service
   Pricing Information will be struck"; Q.Q1's schema accordingly does
   NOT include a `pricing` field. Q.Q1 ships forward-compatible with
   CR26.

7. **Q.Q2 prior-period reference + integrity chain** — when monthly
   bundles are published month-after-month, each bundle's manifest
   references the prior period's manifest sha256. This creates an
   integrity chain a consumer can verify back to the original ATO
   bundle. The chain MUST NOT break across version migrations; LOOP-H
   long-term retention guarantees the prior manifests survive.

8. **POA&M XML / JSON parity** — Q.Q1 reads POA&M from `poam.json`
   (the JSON projection); the XML projection (`poam.xml`) is
   ignored. When the FedRAMP PMO Marketplace ingest requires XML
   instead, Q.Q1 emits XML via `core/oscal-xml.ts` reuse. Currently
   JSON only — verify with PMO before first ship.

9. **Conditional applicability** — Q.Q3 is *required* (every CSO has
   at minimum a sponsoring agency). Q.Q1 is *required* (Marketplace
   listing). Q.Q2 is *required* but **only after** the first month of
   post-ATO operation; CSOs in In Process or Ready states ship Q.Q1
   only (with `marketplace_status` set accordingly). The
   orchestrator's `--marketplace-status <enum>` flag (or Q.Q3-derived
   default) controls which slices run.

10. **Subprocessor / leveraged-IaaS attribution** — RFC-0021 +
    LOOP-L.L2 (CRM + Inheritance) overlap with Q.Q1's
    services_in_scope when the CSO inherits from a leveraged IaaS
    (e.g. AWS GovCloud). Q.Q1 does NOT enumerate the leveraged
    underlying services; that's L.L2's scope. Q.Q1's
    `services_in_scope` is the CSP's *own* service inventory.

---

## 8. Status tracking

Update this table when a slice ships (see Section 9).

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| Q.Q1 | FedRAMP Marketplace listing emitter (per RFC-0021 format) | pending | — | — |
| Q.Q2 | Post-ATO ConMon publication (monthly delivery to FedRAMP secure repository) | pending | — | — |
| Q.Q3 | Agency authorization tracking (who is using the CSO + their authorization documents) | pending | — | — |

---

## 9. Slice completion procedure (REO-enforced)

Per `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`, every slice ships
under the 7-step procedure. Summary:

1. **Verify green** — `npm run typecheck` + `npm test` + `npm run
   check:reo` + `npm run check:provenance` all clean.
2. **Update `cloud-evidence/docs/STATUS.md`** — slice row + Overall
   section.
3. **Update this file's Section 8 status table** — slice row.
4. **Update the per-slice doc** at `cloud-evidence/docs/slices/Q/Q.QN.md`
   — frontmatter (`status: done`, `commit: <hash>`, `completed_date:
   <ISO>`, `last_updated: <ISO>`) + append final Implementation log
   entry.
5. **Update `LOOP-Q-RISKS.md`** — add any newly-discovered risks; move
   resolved risks to the resolved table.
6. **Add `CHANGELOG.md` "Unreleased" entry** — `### Added — LOOP-Q.QN:
   <Slice title>` block at the top of Unreleased; mirror the LOOP-A
   entries for tone + depth.
7. **Commit + amend with hash + push** — single commit per slice; amend
   with hash recorded; push to origin/main.

**Failure handling**: If any guardrail fails at step 1, fix the issue.
DO NOT proceed. DO NOT mark the slice done. The slice is not "done"
until all 7 steps execute. Per CLAUDE.md "Strong directive (REO-enforced)",
failure to follow this procedure is a REO violation and future sessions
will reject the inconsistency.

---

## 10. Appendix — Marketplace listing worked example

To make Q.Q1 reviewable, here is the worked example the test suite encodes.
Given the fixture:

- SSP `system-characteristics.system-name = "Example SaaS CI/CD Platform"`
- FIPS-199 → max(C=moderate, I=moderate, A=moderate) → `impact_level: moderate`
- Inventory enumerates services: AWS S3, AWS EC2, AWS RDS, AWS Lambda,
  GCP GKE, GCP Cloud Storage; → 6 services_in_scope entries
- KSI map has 60 KSIs loaded; envelopes show 55 PASS, 3 PARTIAL, 2 FAIL
- POA&M shows 2 open Critical, 5 open High, 12 open Moderate,
  8 open Low, 3 deviation-approved
- Q.Q3 has 4 agency_authorizations: USDA (sponsoring), DHS (leverage,
  active), VA (leverage, active), DOC (leverage, revoked)
- Operator config supplies: csp_name "Example Corp", csp_uei "ABCD1234EFGH",
  three_pao "Example 3PAO LLC", three_pao.uei "EFGH5678IJKL", assessment_date
  "2026-04-15"

Output `marketplace-listing.json` (excerpt):

```json
{
  "schema_version": "marketplace-listing.v1",
  "package_format_version": "20x.phase-two.preview.2026",
  "emitted_at": "2026-06-07T00:00:00Z",
  "cso_name": "Example SaaS CI/CD Platform",
  "csp_name": "Example Corp",
  "csp_uei": "ABCD1234EFGH",
  "impact_level": "moderate",
  "marketplace_status": "authorized",
  "marketplace_id": null,
  "package_id": null,
  "sponsoring_agency": {
    "name": "USDA",
    "ato_date": "2026-05-01"
  },
  "three_pao": {
    "name": "Example 3PAO LLC",
    "uei": "EFGH5678IJKL",
    "assessment_date": "2026-04-15"
  },
  "services_in_scope": [
    { "provider": "aws", "service_id": "s3",     "service_name": "Amazon S3" },
    { "provider": "aws", "service_id": "ec2",    "service_name": "Amazon EC2" },
    { "provider": "aws", "service_id": "rds",    "service_name": "Amazon RDS" },
    { "provider": "aws", "service_id": "lambda", "service_name": "AWS Lambda" },
    { "provider": "gcp", "service_id": "gke",    "service_name": "Google Kubernetes Engine" },
    { "provider": "gcp", "service_id": "storage","service_name": "Google Cloud Storage" }
  ],
  "ksi_baseline": [/* 60 entries */],
  "poam_summary": {
    "open_count": 27,
    "critical_count": 2,
    "high_count": 5,
    "moderate_count": 12,
    "low_count": 8,
    "deviation_approved_count": 3
  },
  "agencies_directly_using": [
    { "agency_name": "USDA", "ato_date": "2026-05-01", "status": "active" },
    { "agency_name": "DHS",  "ato_date": "2026-05-20", "status": "active" },
    { "agency_name": "VA",   "ato_date": "2026-06-01", "status": "active" }
  ],
  "next_ongoing_authorization_report_date": "2026-07-01",
  "trust_center": {
    "url": "https://trust.example.com",
    "access_process": "GET /.well-known/fedramp-marketplace.json (machine-readable); GET /trust (human-readable)",
    "data_formats": ["human-readable", "machine-readable"]
  },
  "contact": {
    "name": "Jane Doe",
    "email": "fedramp@example.com",
    "role": "FedRAMP Program Manager"
  },
  "customer_responsibility_summary": "Customers retain responsibility for...",
  "service_description": "Example SaaS CI/CD Platform provides...",
  "support_information": {
    "url": "https://support.example.com",
    "email": "support@example.com",
    "sla": "P1: 1 hour, P2: 4 hours, P3: next business day"
  },
  "business_category": "SaaS / DevOps",
  "fedramp_marketplace_link": null,
  "provenance": {
    "emitter": "marketplace-listing.ts",
    "emitted_at": "2026-06-07T00:00:00Z",
    "source_calls": [
      "read out/ssp.json",
      "read out/ap.json",
      "read out/assessment-results.json",
      "read out/poam.json",
      "read out/inventory.json",
      "read out/KSI-*.json",
      "read out/.agency-authorizations.json",
      "read config.yaml"
    ],
    "signing_key_id": "ed25519:fingerprint:..."
  },
  "requires_operator_input": [
    "marketplace_id (FedRAMP PMO-assigned; record via tracker once assigned)",
    "package_id (FedRAMP PMO-assigned)",
    "fedramp_marketplace_link (FedRAMP PMO assigns once Marketplace ingests this listing)"
  ]
}
```

Quality of this artifact:
- A 3PAO opens the JSON, validates the schema, sees zero invented data.
- The PMO ingests the same JSON via the CR26 Marketplace API once
  available.
- A leveraging-agency procurement officer reads the Markdown mirror at
  `https://trust.example.com/.well-known/fedramp-marketplace.json` to
  validate impact level, 3PAO identity, POA&M posture, and agency reuse
  history.
- The integrity chain Q.Q2 builds month over month references this
  listing's sha256 so a Marketplace consumer can verify the listing
  was current at each monthly publication.

The same fixture, run through Q.Q2 for `--conmon-period 2026-07`,
produces:

- `out/conmon-publication-2026-07.tar.gz` (gzipped POSIX tar, ~25 MB
  with all monthly scans)
- `out/conmon-publication-2026-07.manifest.json` (signed Ed25519 +
  RFC 3161 timestamp)
- `out/trust-center-mirror/USDA/2026-07/manifest.json` (mirror of the
  above, served by G.G3 Trust Center to USDA)
- `out/trust-center-mirror/DHS/2026-07/manifest.json` (same; DHS
  consumes)
- `out/trust-center-mirror/VA/2026-07/manifest.json` (same; VA
  consumes)
- Tracker row in `conmon_publication_log` recording the period +
  manifest sha256 + 3 destinations + 0 gaps

And Q.Q3 surfaces the four agency authorizations (USDA, DHS, VA, DOC) +
the timeline (USDA ATO 2026-05-01, DHS leverage 2026-05-20, VA
leverage 2026-06-01, DOC leverage 2026-05-15 + revoke 2026-05-25) in
the tracker UI. The full LOOP-Q value chain is end-to-end.

---

End of LOOP-Q-SPEC.md.
