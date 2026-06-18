---
slice_id: W.W2
title: Subprocessor + SBOM + OCI Image Screening against Prohibited-Vendor Catalog
loop: W
status: done
commit: TBD-step6
completed_date: 2026-06-18
depends_on:
  - W.W1                                # prohibited-vendors-catalog + signed snapshot
  - LOOP-E.E2                           # SBOM produced by Syft + verified by cosign
  - LOOP-J.J3                           # OCI cosign + Rekor publisher attestations
  - core/subprocessors-sheet.ts         # existing subprocessor sheet Google Sheets reader
  - LOOP-A.A1                           # OSCAL POA&M emitter — failed-screen POA&M items flow here
  - LOOP-A.A5                           # Ed25519 signing + RFC 3161 timestamp pipeline
  - LOOP-B.B1                           # composite risk scoring picks up emitted POA&M findings
blocks:
  - W.W3                                # 1-business-day reporter consumes the screen-result envelope
  - W.W4                                # FAR 52.204-26 annual representation consumes the screen-result envelope
estimated_effort: medium (~7 working days for single implementer)
last_updated: 2026-06-18
applicable_conditional: true
condition: Any CSP selling to a Federal agency, prime, or grant recipient — FAR 52.204-25 applies to every Federal acquisition since 2020-08-13 (Part B effective date). No opt-out.
trigger_flag: "--prohibited-vendor-screen"
trigger_env: CLOUD_EVIDENCE_PROHIBITED_VENDOR_SCREEN
---

# W.W2 — Subprocessor + SBOM + OCI Image Screening against Prohibited-Vendor Catalog

## 1. Mission

Screen four surfaces — the operator's subprocessor sheet (`core/subprocessors-sheet.ts`),
every transitive dependency in the cosign-verified SBOM produced by LOOP-E.E2,
every OCI image publisher attested by cosign/Rekor in LOOP-J.J3, and every
asset in `out/inventory.json` carrying a `provider_tag` or `sku` — against
the W.W1 prohibited-vendors catalog (FAR 52.204-25 named entities + NDAA
§1634 Kaspersky + OFAC SDN + BIS Entity List + SAM Exclusions). Emit a
signed `out/prohibited-vendors-screen-result.json` envelope per scan run
(`runId`-keyed), an operator-readable `.xlsx` workbook, and — for every
match — a POA&M finding via the existing `core/oscal-poam.ts` chain.
Match results carry a confidence band, a provenance chain (catalog row →
match path → surface that fired), and a deterministic clock-arithmetic
timestamp that W.W3 uses to drive the FAR 52.204-25(d)(2) one-business-day
report. W.W2 NEVER auto-submits anything to a Federal endpoint — it
produces the evidence; the operator submits.

Concretely: this slice closes the largest remaining gap in the FedPy
supply-chain story. Today FedPy emits zero artifacts that demonstrate
"reasonable inquiry" within the meaning of FAR 4.2101 — operators have to
hand-screen vendors against the FAR clause. W.W2 makes that automated,
deterministic, and REO-compliant (every match traces to a real catalog
row × a real surface entry).

## 2. Authoritative sources (verbatim quotes)

All URLs accessed 2026-06-07. Verbatim quotes are reproduced as Markdown
blockquotes per house style. No invented citations; where the live page
was unreachable from the workspace, the source is marked `WebFetch:
returned-summary` and the operator is directed to the canonical bulk
download.

### 2.1 FAR 52.204-25 — Prohibition on Contracting for Certain Telecommunications and Video Surveillance Services or Equipment

URL: https://www.acquisition.gov/far/52.204-25 (accessed 2026-06-07).

The clause defines **"covered telecommunications equipment or services"**
in paragraph (a) to include equipment from five named entities:

> "Telecommunications equipment produced by Huawei Technologies Company
> or ZTE Corporation (or any subsidiary or affiliate of such entities)."
>
> "For the purpose of public safety, security of Government facilities,
> physical security surveillance of critical infrastructure, and other
> national security purposes, video surveillance and
> telecommunications equipment produced by Hytera Communications
> Corporation, Hangzhou Hikvision Digital Technology Company, or Dahua
> Technology Company (or any subsidiary or affiliate of such entities)."
>
> "Telecommunications or video surveillance services provided by such
> entities or using such equipment."
>
> "Telecommunications or video surveillance equipment or services
> produced or provided by an entity that the Secretary of Defense, in
> consultation with the Director of the National Intelligence or the
> Director of the Federal Bureau of Investigation, reasonably believes
> to be an entity owned or controlled by, or otherwise connected to,
> the government of a covered foreign country."

Paragraph (b) — the operative prohibition:

> "The Contractor is prohibited from—
> (1) Providing any equipment, system, or service that uses covered
> telecommunications equipment or services as a substantial or essential
> component of any system, or as critical technology as part of any
> system, unless an exception ... applies or the covered
> telecommunication equipment or services are covered by a waiver ...
> (2) Using any equipment, system, or service that uses covered
> telecommunications equipment or services as a substantial or
> essential component of any system, or as critical technology as part
> of any system, unless an exception ... applies or the covered
> telecommunication equipment or services are covered by a waiver ..."

Paragraph (d) — Reporting (the basis W.W3 keys off but W.W2 PRE-COMPUTES
the data):

> "In the event the Contractor identifies covered telecommunications
> equipment or services used as a substantial or essential component
> of any system, or as critical technology as part of any system,
> during contract performance, or the Contractor is notified of such
> by a subcontractor at any tier or by any other source, the
> Contractor shall report the information ... within one business day
> from the date of such identification or notification ... and within
> 10 business days of submitting the information ... any further
> available information about mitigation actions undertaken or
> recommended."

The "report" data elements (clause (d)(1)/(d)(2)) — to be EMITTED as
fields on the W.W2 match record so W.W3 can reuse them verbatim:

> "(i) The contract number;
> (ii) The order number(s), if applicable;
> (iii) Supplier name;
> (iv) Supplier unique entity identifier (if known);
> (v) Supplier Commercial and Government Entity (CAGE) code (if
> known);
> (vi) Brand;
> (vii) Model number ...;
> (viii) Item description;
> (ix) Any readily available information about mitigation actions
> undertaken or recommended."

### 2.2 FAR 52.204-26 — Covered Telecommunications Equipment or Services — Representation

URL: https://www.acquisition.gov/far/52.204-26 (accessed 2026-06-07).

> "(2) After conducting a reasonable inquiry for purposes of this
> representation, the offeror represents that it [ ] does, [ ] does not
> use covered telecommunications equipment or services, or any
> equipment, system, or service that uses covered telecommunications
> equipment or services."

W.W2's screen result is the **factual basis** the W.W4 annual
representation cites: when the screen has zero confirmed matches and the
catalog snapshot is < 24h old, W.W4 can tick "does not"; when the screen
has ≥ 1 match, W.W4 ticks "does" (and a separate "use" question for
"reasonable inquiry" of installed equipment must be operator-answered).

### 2.3 FAR 4.2101 — Definitions

URL: https://www.acquisition.gov/far/4.2101 (accessed 2026-06-07).

> "Reasonable inquiry means an inquiry designed to uncover any
> information in the entity's possession about the identity of the
> producer or provider of covered telecommunications equipment or
> services used by the entity that excludes the need to include an
> internal or third-party audit."

> "Covered foreign country means The People's Republic of China."

> "Substantial or essential component means any component necessary for
> the proper function or performance of a piece of equipment, system,
> or service."

W.W2's screen — which walks the subprocessor sheet + the SBOM
transitively + the OCI publisher chain + the inventory — IS the
"reasonable inquiry" of FAR 4.2101 for the CSP's own systems. The
W.W2 envelope is the audit-evidence that the inquiry was performed.

### 2.4 FAR 4.2102 — Policy

URL: https://www.acquisition.gov/far/4.2102 (accessed 2026-06-07).

> "Agencies are prohibited from procuring or obtaining, or extending or
> renewing a contract to procure or obtain, any equipment, system, or
> service that uses covered telecommunications equipment or services as
> a substantial or essential component of any system, or as critical
> technology as part of any system."

> "Agencies are prohibited from entering into a contract, or extending
> or renewing a contract, with an entity that uses any equipment,
> system, or service that uses covered telecommunications equipment or
> services as a substantial or essential component of any system, or
> as critical technology as part of any system. This prohibition
> applies at the prime contractor level and is effective as of August
> 13, 2020."

The **"uses"** language is why W.W2 walks the SBOM transitively — an
indirect dependency at depth-N is still "use".

### 2.5 NDAA FY2019 §889 — Public Law 115-232 (statutory authority)

URL: https://www.congress.gov/115/plaws/publ232/PLAW-115publ232.pdf
(operator downloads to `docs/sources/PLAW-115publ232.pdf`).

> "§889. Prohibition on certain telecommunications and video
> surveillance services or equipment.
> (a) Prohibition on use or procurement.
> (1) The head of an executive agency may not—
> (A) procure or obtain or extend or renew a contract to procure or
> obtain any equipment, system, or service that uses covered
> telecommunications equipment or services as a substantial or
> essential component of any system, or as critical technology as part
> of any system; or
> (B) enter into a contract (or extend or renew a contract) with an
> entity that uses any equipment, system, or service that uses covered
> telecommunications equipment or services as a substantial or
> essential component of any system, or as critical technology as part
> of any system."

W.W2's screen is the operative reading of §889(a)(1)(B) at the CSP
level: a CSP that uses a covered entity in its own pipeline cannot
contract with a Federal agency even if the covered entity is not in
the agency-facing deliverable.

### 2.6 NDAA FY2018 §1634 — Kaspersky prohibition

URL: https://www.congress.gov/bill/115th-congress/house-bill/2810/text
(operator downloads to `docs/sources/PLAW-115publ91.pdf`).

> "Sec. 1634. Prohibition on use of products and services developed or
> provided by Kaspersky Lab.
> (a) Prohibition.—No department, agency, organization, or other
> element of the Federal Government shall use, whether directly or
> through work with or on behalf of another department, agency,
> organization, or element of the Federal Government, any hardware,
> software, or services developed or provided, in whole or in part,
> by—
> (1) Kaspersky Lab (or any successor entity);
> (2) any entity that controls, is controlled by, or is under common
> control with Kaspersky Lab; or
> (3) any entity of which Kaspersky Lab has a majority ownership.
> (b) Effective Date.—The prohibition under subsection (a) shall take
> effect on October 1, 2018."

W.W2's screener treats Kaspersky-derived catalog rows identically to
§889 rows but tags the match with `source: 'ndaa-1634'` so the W.W3
report cites the correct statutory authority.

### 2.7 DHS BOD 17-01 — Kaspersky Removal

URL: https://www.cisa.gov/binding-operational-directive-17-01 (operator
downloads HTML to `docs/sources/bod-17-01.html`).

> "Removal of Kaspersky-branded Products. After careful consideration
> of available information and consultation with interagency partners,
> the Acting Secretary of Homeland Security has determined that the
> information security risks presented by the use of Kaspersky
> products on federal information systems are significant and
> compelling. This Binding Operational Directive (BOD) directs Federal
> Executive Branch departments and agencies to identify any use or
> presence of Kaspersky products on their information systems, to
> develop and furnish to DHS a detailed plan of action to remove and
> discontinue present and future use of all Kaspersky-branded
> products, and to begin to implement the plan."

Issued 2017-09-13; 30-day identification + 60-day plan + 90-day removal.
W.W2 treats every Kaspersky-derived catalog row as a BOD-17-01 row
parallel to NDAA §1634.

### 2.8 OFAC Specially Designated Nationals (SDN) List — Treasury bulk data

URLs (accessed 2026-06-07):
- https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists
- Bulk: https://www.treasury.gov/ofac/downloads/sdn_advanced.xml
- Bulk: https://www.treasury.gov/ofac/downloads/sdn.csv

Treasury publishes the SDN list in machine-readable forms:

> "OFAC's Specially Designated Nationals and Blocked Persons List
> (SDN List) is a publication of OFAC which lists individuals and
> companies owned or controlled by, or acting for or on behalf of,
> targeted countries. It also lists individuals, groups, and entities,
> such as terrorists and narcotics traffickers designated under
> programs that are not country-specific."

W.W2 consumes the W.W1-emitted catalog rows whose
`provenance.source = 'ofac-sdn-advanced'`; the screener applies the
same matching algorithm regardless of source.

### 2.9 BIS Entity List — 15 CFR Part 744, Supplement No. 4

URL: https://www.bis.doc.gov/index.php/policy-guidance/lists-of-parties-of-concern/entity-list
(accessed 2026-06-07).

> "The Entity List is a publication of the Bureau of Industry and
> Security (BIS) of the U.S. Department of Commerce that identifies
> foreign parties prohibited from receiving certain U.S.-origin items
> without a license. These parties present a national security or
> foreign policy concern."

Programs (`programs[]`) include: `EL` (Entity List), `MEU` (Military
End User), `DPL` (Denied Persons List), `UVL` (Unverified List). W.W2
treats every catalog row whose `provenance.source = 'bis-entity-list'`
as a screening row; the program code carries into the match record so
W.W3 can include the right citation in the 1BD report.

### 2.10 SAM.gov Exclusions API + bulk download

URL: https://sam.gov/data-services/Exclusions (accessed 2026-06-07).

> "SAM houses Federal procurement awarding officials' Exclusions list
> (formerly known as the Excluded Parties List System (EPLS))."

W.W2 honours `provenance.exclusion_type ∈ {Reciprocal, Preliminarily
Ineligible (Proceedings Pending), Prohibition/Restriction, Voluntary
Exclusion}` on the catalog row; the match record propagates the type.

### 2.11 DHS § 889 Implementation Guidance — for the "use" surface

URL: https://www.cisa.gov/topics/supply-chain-security/ict-supply-chain-risk-management
(accessed 2026-06-07; informative).

CISA's ICT SCRM guidance documents the "use" surface as inclusive of
SBOM transitive dependencies and OCI publisher chains. W.W2 walks both.

### 2.12 NIST SP 800-161r1 — Cybersecurity Supply Chain Risk Management

URL: https://csrc.nist.gov/pubs/sp/800/161/r1/final (accessed
2026-06-07).

> "SP 800-161r1 provides guidance to enterprises on identifying,
> assessing, and responding to cybersecurity risks throughout the
> supply chain at all levels of their organizations."

W.W2's POA&M emit cites SR-1 (Supply Chain Risk Management Policy),
SR-3 (Supply Chain Controls and Processes), SR-5 (Acquisition
Strategies, Tools, and Methods), SR-6 (Supplier Reviews), and SR-11
(Component Authenticity) in the `related-controls[]` block.

### 2.13 SPDX 2.3 + CycloneDX 1.6 — SBOM schemas

URLs:
- https://spdx.github.io/spdx-spec/v2.3/ (accessed 2026-06-07)
- https://cyclonedx.org/specification/overview/ (accessed 2026-06-07)

W.W2 reads the SBOM produced by LOOP-E.E2. SPDX 2.3 Package fields
`supplier`, `originator`, `packageHomePage`, `externalRefs` carry the
maintainer signal. CycloneDX 1.6 `components[].supplier.name` +
`components[].publisher` carry the equivalent.

### 2.14 cosign + Rekor publisher attestations

URLs:
- https://docs.sigstore.dev/cosign/ (accessed 2026-06-07)
- https://docs.sigstore.dev/rekor/overview/ (accessed 2026-06-07)

W.W2 consumes the LOOP-J.J3 attestation graph: `subject.uri`,
`payload.predicateType = 'https://slsa.dev/provenance/v1'`,
`payload.predicate.builder.id`, and the Rekor `body[].spec.publicKey`
fingerprint. The publisher attribution is whatever string most
reliably identifies who signed: the Rekor `subject` email/URI, the
fingerprint, or the cosign keyless OIDC issuer + subject pair.

## 3. Scope

### 3.1 In scope

- Subprocessor sheet vendor-name screening (catalog × sheet's `vendor`
  column + `legal_entity` column when present).
- SBOM transitive walk: every package in the LOOP-E.E2 SBOM, depth
  unbounded by default (capped at a configurable `--sbom-max-depth`,
  default 8). Both SPDX 2.3 and CycloneDX 1.6 inputs.
- OCI image publisher screening: every image referenced by the
  inventory or by `--oci-image <ref>` CLI flag (repeatable). Reads
  cosign attestations + Rekor entries from LOOP-J.J3.
- Inventory provider-tag screening: every asset with `provider_tag` or
  `sku` keyed by a vendor name.
- Vendor-name normalisation (transliteration, alias chain, subsidiary
  traversal) via the new `core/vendor-name-normalizer.ts`.
- Match-record emission with confidence band + provenance chain.
- POA&M finding emission per match via `core/oscal-poam.ts`.
- Signed JSON envelope + `.xlsx` workbook outputs.
- Tracker DB upsert into `prohibited_vendor_screens` (one row per run)
  and `prohibited_vendor_matches` (one row per match).
- Operator-supplied overrides file `prohibited-vendors-overrides.yaml`
  for false-positive suppression + manual additions.

### 3.2 Out of scope (NOT in W.W2)

- The 1-business-day report `.docx` / `.json` — owned by W.W3.
- The annual FAR 52.204-26 representation — owned by W.W4.
- The catalog itself + the daily snapshot extractor — owned by W.W1.
- Waiver tracking under FAR 4.2104 — out of LOOP-W scope per
  LOOP-W-SPEC.md §1.3.
- ITAR / EAR export-control screening — out of LOOP-W scope.
- Automatic submission to any Federal endpoint — REO Rule 4 forbids
  the system from acting on behalf of the operator on a regulatory
  submission.
- Corporate due-diligence research for entities not on a published
  list. The operator may seed `prohibited-vendors-overrides.yaml`
  with `manual_additions[]`, but W.W2 does not invent entries.
- Re-screening past contract performance windows — W.W2 runs against
  the current snapshot; W.W3 keys the report off the
  `match.discovered_at` timestamp.
- DNS / WHOIS / company-registry enrichment of the subprocessor sheet
  — the operator-supplied sheet is the authoritative input.

## 4. Inputs (exact data structures, schema references)

### 4.1 Catalog snapshot (from W.W1)

Path: `data/prohibited-vendors-snapshot-YYYYMMDD.json` — Ed25519-signed,
RFC 3161-timestamped. Schema (subset relevant to W.W2):

```ts
interface ProhibitedVendorCatalogEntry {
  catalog_uid: string;                  // stable hash across snapshots
  entity_name: string;                  // canonical English / Latin form
  aliases: string[];                    // every alias incl. transliterations
  subsidiaries: string[];               // direct subsidiaries (W.W1 walks)
  parent_entities: string[];            // direct parents (for upward walk)
  provenance: {
    source:                             // bulk list provenance
      | 'far-52.204-25-a'
      | 'ndaa-1634'
      | 'bod-17-01'
      | 'ofac-sdn-advanced'
      | 'bis-entity-list'
      | 'sam-exclusions'
      | 'operator-manual-addition';
    list_program?: string;              // e.g. 'EL', 'MEU', 'CYBER2'
    exclusion_type?: string;            // SAM-only
    classification_type?: string;       // SAM-only
    citation: string;                   // full Federal-Register citation
    extracted_at: string;               // ISO 8601 UTC
  };
  hits: {
    catalog_row_signature: string;      // sha256(entity_name|aliases|sub|par|source)
  };
}

interface ProhibitedVendorCatalogSnapshot {
  schema_version: '1.0.0';
  generated_at: string;                 // ISO 8601 UTC
  total_entities: number;
  entries: ProhibitedVendorCatalogEntry[];
  provenance: { /* W.W1 emitter block */ };
  signature: { /* Ed25519 detached */ };
  rfc3161_timestamp: { /* RFC 3161 token */ };
}
```

### 4.2 Subprocessor sheet (existing `core/subprocessors-sheet.ts`)

Existing module reads operator-configured Google Sheet. W.W2 honours
the documented column set:

```ts
interface SubprocessorSheetRow {
  vendor: string;                       // required
  legal_entity?: string;                // optional formal name
  service_category: string;             // e.g. 'CDN', 'DNS', 'SIEM'
  data_categories: string[];            // e.g. ['logs', 'pii', 'system-config']
  region?: string;                      // ISO country code(s)
  contract_owner_email?: string;
  added_at?: string;                    // ISO date
  notes?: string;
}
```

### 4.3 SBOM (from LOOP-E.E2)

Path: `out/sbom.<image-or-source-ref>.{spdx.json | cyclonedx.json}`.
W.W2 detects the schema dialect by inspecting the root keys
(`spdxVersion` vs `bomFormat`).

SPDX 2.3 Package shape (subset):

```json
{
  "SPDXID": "SPDXRef-Package-foo",
  "name": "foo",
  "versionInfo": "1.2.3",
  "supplier": "Organization: Example Inc",
  "originator": "Organization: Example Inc",
  "packageHomePage": "https://example.com/foo",
  "externalRefs": [
    { "referenceCategory": "PACKAGE-MANAGER", "referenceLocator": "pkg:npm/foo@1.2.3" }
  ]
}
```

CycloneDX 1.6 component shape (subset):

```json
{
  "type": "library",
  "bom-ref": "pkg:npm/foo@1.2.3",
  "name": "foo",
  "version": "1.2.3",
  "publisher": "Example Inc",
  "supplier": { "name": "Example Inc", "url": ["https://example.com"] },
  "purl": "pkg:npm/foo@1.2.3"
}
```

W.W2's SBOM screener extracts `(name, supplier, publisher, originator,
purl, homepage)` per package and runs them through the catalog match.
Transitive walk follows the `relationships[]` (SPDX) or `dependencies[]`
(CycloneDX) graph.

### 4.4 OCI cosign + Rekor attestations (from LOOP-J.J3)

Path: `out/oci-attestations/<image-digest>.json` — cosign-verified
attestation envelope:

```json
{
  "image": "<registry>/<repo>@sha256:<digest>",
  "publisher_provenance": {
    "cosign_keyless_oidc_issuer": "https://accounts.google.com",
    "cosign_keyless_subject": "builder@example.com",
    "cosign_key_fingerprint": "sha256:abcdef...",
    "rekor_uuid": "108e9186e8...",
    "rekor_subject": "https://example.com/builders/ci",
    "builder_id": "https://github.com/actions/runner/cli@refs/heads/main"
  }
}
```

W.W2's OCI screener walks `publisher_provenance.*` fields against the
catalog. Domain-matching: the registrable domain of the OIDC issuer is
compared to subsidiaries[] of any catalog entry.

### 4.5 Inventory (from existing INV-P1..P5 chain)

Path: `out/inventory.json`. W.W2 reads `assets[].provider_tag` (e.g.
`'huawei-public-cloud'`) and `assets[].sku` (e.g.
`'hikvision-camera-DS-2CD2x'`) — both already populated by INV-P1.

### 4.6 Operator overrides

Path: `prohibited-vendors-overrides.yaml` (commits to repo; optional).

```yaml
schema_version: '1.0.0'
# False-positive suppression — vendor name matched the catalog but
# operator has verified it is not actually a covered entity.
suppressions:
  - vendor: "Generic Acme"
    catalog_uid: "ofac-sdn-12345"
    justification: "Manual review 2026-06-01 by S. Phillips (CISO)"
    expires_at: "2027-06-01"
# Manual additions — operator wants to screen vendors that are NOT on
# any published list. Treat as catalog rows with source=
# operator-manual-addition. The W.W3 report cites the operator's
# justification rather than a Federal source.
manual_additions:
  - entity_name: "Suspicious LLC"
    aliases: ["SusLLC", "Сусписиус"]
    justification: "Per CISO 2026-04-15 risk acceptance memo"
```

The schema is validated by Ajv at load time; a schema violation throws
a typed error and W.W2 exits non-zero.

## 5. Outputs (canonical JSON schemas + .xlsx layout + signed envelope)

### 5.1 `out/prohibited-vendors-screen-result.json`

Canonical JSON (stable key order, LF newlines, no trailing whitespace):

```ts
interface ProhibitedVendorScreenResult {
  schema_version: '1.0.0';
  run_id: string;                       // ULID
  csp_name: string;                     // from config.yaml
  started_at: string;                   // ISO 8601 UTC
  completed_at: string;                 // ISO 8601 UTC

  catalog_snapshot_ref: {
    path: string;                       // e.g. 'data/prohibited-vendors-snapshot-20260607.json'
    sha256: string;
    generated_at: string;
    age_hours: number;                  // completed_at - snapshot.generated_at
    is_stale: boolean;                  // age_hours > 24
  };

  surfaces_screened: Array<{
    surface: 'subprocessor-sheet' | 'sbom' | 'oci-publisher' | 'inventory-provider-tag';
    entries_screened: number;
    source_path: string;                // file path or sheet URL
    walked_at: string;
  }>;

  matches: ProhibitedVendorMatch[];

  summary: {
    total_matches: number;
    matches_by_source: Record<string, number>;     // catalog provenance.source
    matches_by_surface: Record<string, number>;
    matches_by_confidence_band: Record<'high' | 'medium' | 'low', number>;
    suppressed_matches: number;
  };

  reportable_under_far_52_204_25_d: boolean;       // any non-suppressed high-confidence match
  reportable_under_ndaa_1634: boolean;             // any Kaspersky catalog source match
  reasonable_inquiry_attested: boolean;            // true iff all 4 surfaces walked + catalog < 24h

  provenance: {
    emitter: 'prohibited-vendors-screen';
    emitted_at: string;
    source_calls: Array<{
      kind: 'catalog-snapshot' | 'subprocessor-sheet' | 'sbom' | 'oci-attest' | 'inventory' | 'overrides';
      path: string;
      sha256: string;
    }>;
    signing_key_id: string;
  };

  signature: { /* Ed25519 detached, populated by core/sign.ts */ };
  rfc3161_timestamp: { /* RFC 3161 token, populated by core/timestamp.ts */ };
}

interface ProhibitedVendorMatch {
  match_id: string;                     // ULID
  catalog_uid: string;                  // FK to catalog entry
  catalog_provenance: ProhibitedVendorCatalogEntry['provenance'];
  surface: 'subprocessor-sheet' | 'sbom' | 'oci-publisher' | 'inventory-provider-tag';
  matched_entity_name: string;          // what we found in the surface
  match_path: string[];                 // e.g. ['app', 'a-lib', '@huawei-oss/foo'] for SBOM
  confidence: number;                   // 0.0 - 1.0
  confidence_band: 'high' | 'medium' | 'low';
  matched_by:
    | 'exact-case-insensitive'
    | 'normalized-name'
    | 'alias-table'
    | 'subsidiary-walk'
    | 'transliteration'
    | 'fingerprint'
    | 'domain-registrable';
  far_52_204_25_d_data_elements: {      // pre-filled for W.W3 reuse
    contract_numbers: string[];         // from operator config; '[]' if none mapped
    order_numbers: string[];
    supplier_name: string;
    supplier_uei: string | 'REQUIRES-OPERATOR-INPUT';
    supplier_cage_code: string | 'REQUIRES-OPERATOR-INPUT';
    brand: string;
    model_number: string;
    item_description: string;
    mitigation_actions: string;         // populated from POA&M remediation plan
  };
  poam_item_uuid: string;               // back-reference to oscal-poam emit
  related_controls: string[];           // ['sr-1','sr-3','sr-5','sr-6','sr-11']
  suppressed: boolean;                  // honours overrides.yaml
  suppression_justification?: string;
  discovered_at: string;                // ISO 8601 UTC — drives W.W3 1BD clock
  sources: {
    surface_evidence: string;           // path to subprocessor row / SBOM package / OCI publisher / inventory asset
    sbom_package_purl?: string;
    oci_image_digest?: string;
    inventory_asset_id?: string;
  };
}
```

### 5.2 `out/prohibited-vendors-screen-result.xlsx`

Workbook with three sheets:

**Sheet 1: `Matches`** — one row per match.

| Col | Header | Source |
|-----|--------|--------|
| A | Match ID | `match.match_id` |
| B | Surface | `match.surface` |
| C | Catalog Entity | `match.catalog_provenance.source` + entity_name |
| D | Matched Entity Name | `match.matched_entity_name` |
| E | Confidence | `match.confidence` |
| F | Confidence Band | `match.confidence_band` |
| G | Matched By | `match.matched_by` |
| H | Match Path | `match.match_path.join(' → ')` |
| I | Surface Evidence | `match.sources.surface_evidence` |
| J | POA&M Item UUID | `match.poam_item_uuid` |
| K | Statutory Authority | `match.catalog_provenance.source` (verbatim) |
| L | Discovered At | `match.discovered_at` |
| M | Suppressed | `match.suppressed` (yes/no) |
| N | Suppression Justification | `match.suppression_justification` |
| O | Supplier UEI | `match.far_..._data_elements.supplier_uei` |
| P | Supplier CAGE | `match.far_..._data_elements.supplier_cage_code` |
| Q | Brand | `match.far_..._data_elements.brand` |
| R | Model | `match.far_..._data_elements.model_number` |
| S | Item Description | `match.far_..._data_elements.item_description` |

Conditional formatting: `confidence_band = 'high'` rows tinted red;
`suppressed = yes` rows struck-through; `REQUIRES-OPERATOR-INPUT`
cells tinted amber.

**Sheet 2: `Surfaces Screened`** — one row per surface with the
walk-count + path.

**Sheet 3: `Summary`** — total matches, matches by source, matches by
surface, matches by confidence band; aged-catalog warning if
`is_stale = true`.

### 5.3 Signed envelope structure

W.W2 outputs flow through the existing `core/sign.ts` glob + RFC 3161
timestamping pipeline (LOOP-A.A5). The envelope is the
`ProhibitedVendorScreenResult` JSON with `signature` + `rfc3161_timestamp`
populated by the pipeline; the `.xlsx` is signed as a detached binary
manifest entry.

### 5.4 POA&M items (emitted via `core/oscal-poam.ts`)

For every non-suppressed match, one POA&M item with:

```json
{
  "title": "Prohibited Vendor Detected: <entity_name> on <surface>",
  "description": "<verbatim statutory citation + match path + discovered_at>",
  "related-findings": [ { "finding-uuid": "<finding>" } ],
  "related-observations": [ { "observation-uuid": "<observation>" } ],
  "related-controls": [
    { "control-id": "sr-1" }, { "control-id": "sr-3" },
    { "control-id": "sr-5" }, { "control-id": "sr-6" },
    { "control-id": "sr-11" }
  ],
  "remediation-tracking": {
    "scheduled-completion-date": "<discovered_at + 1 business day per FAR 52.204-25(d)(2)>",
    "responsible-roles": ["security-operations", "ciso"]
  },
  "severity": "high"
}
```

Severity rule: every confirmed match is `high` by FAR-statutory
authority; the LOOP-B.B1 composite risk-scorer may bump but never
lower.

## 6. Algorithm / Steps (deterministic, REO-compliant)

### Phase A — Inputs (deterministic load)

1. **Load catalog snapshot** from `data/prohibited-vendors-snapshot-<latest-date>.json`.
   Verify Ed25519 signature against the W.W1 signing key. Reject and
   exit non-zero if the signature fails. Compute snapshot age in hours;
   emit `coverage:stale` log line when > 24h.
2. **Load overrides** from `prohibited-vendors-overrides.yaml` (optional).
   Validate with Ajv. Build two maps:
   `suppressions_by_catalog_uid: Map<string, Suppression>` and
   `manual_additions: ProhibitedVendorCatalogEntry[]`.
3. **Build screening corpus** = catalog entries (W.W1) + manual_additions.
   Pre-compute normalized index: for each entry, generate
   `(entity_name | alias | subsidiary)` × `normalize()` triples; insert
   into a Trie keyed by normalized form for O(1) lookup.
4. **Load subprocessor sheet** via existing `core/subprocessors-sheet.ts`
   `loadSubprocessors()`. Cache to local file for provenance.
5. **Load SBOM(s)** from `out/sbom.*.json` glob; auto-detect SPDX vs
   CycloneDX. Parse via Ajv-validated schemas.
6. **Load OCI attestations** from `out/oci-attestations/*.json`.
7. **Load inventory** from `out/inventory.json`.

### Phase B — Screening (four parallel surface walkers)

For each surface, run the matcher independently and collect matches.

8. **Surface 1: Subprocessor sheet walker.** For each row:
   - Normalize `vendor` + `legal_entity` via
     `normalizeVendorName(raw) → string`.
   - Run normalized form through Trie.
   - If hit → check alias / subsidiary path → emit
     `ProhibitedVendorMatch` with `surface = 'subprocessor-sheet'`.
   - Compute confidence: exact normalized match = 1.0; alias = 0.95;
     subsidiary walk depth-1 = 0.85; depth-2 = 0.7; depth-N = 0.5.
9. **Surface 2: SBOM walker.** For each package:
   - Extract `(name, supplier, publisher, originator, purl)`.
   - Normalize each; run through Trie.
   - Walk transitive dependencies (SPDX `relationships[]` /
     CycloneDX `dependencies[]`) up to `--sbom-max-depth` (default 8);
     emit match with `match_path = [root, ..., matched]`.
   - Confidence: exact `supplier.name` match = 1.0; `publisher` match =
     0.95; `originator` match = 0.95; `purl` namespace match = 0.85;
     transitive depth penalty: each hop -0.02 (floor 0.5).
10. **Surface 3: OCI publisher walker.** For each cosign attestation:
    - Extract `(cosign_keyless_oidc_issuer, cosign_keyless_subject,
      cosign_key_fingerprint, rekor_uuid, rekor_subject, builder_id)`.
    - For fingerprint: lookup against catalog
      `fingerprint_index: Map<string, catalog_uid>` (W.W1 populates
      when the operator supplies fingerprints in the overrides; default
      empty).
    - For OIDC issuer: extract registrable domain; lookup against
      catalog subsidiaries[].
    - For OIDC subject / rekor_subject: normalize email/URI; lookup.
    - Confidence: fingerprint = 1.0; subject exact = 0.95; domain
      registrable = 0.85; substring on subject = 0.7.
11. **Surface 4: Inventory provider-tag walker.** For each asset:
    - Extract `provider_tag` + `sku`.
    - Normalize; Trie lookup.
    - Confidence: exact normalized match = 1.0; substring on `sku` =
      0.85; substring on `provider_tag` = 0.85.

### Phase C — Normalization & post-processing

12. **Vendor name normalization** (`core/vendor-name-normalizer.ts`):
    - Lowercase via `String.prototype.toLocaleLowerCase('und')`.
    - Unicode NFKC normalize.
    - Transliterate Cyrillic/Han/Kana via a deterministic table
      (committed; sourced from Unicode CLDR `transliterator/Any-Latin`
      rule); operator may override via
      `prohibited-vendors-overrides.yaml::transliteration_overrides`.
    - Strip corporate suffixes (Inc, Inc., LLC, Ltd, Corp, Corporation,
      Co., Company, GmbH, S.A., S.p.A., AB, AG, K.K., Pte Ltd, Pty Ltd,
      P.L.C., PLC, OOO, AO, OAO, ZAO) — table committed; operator may
      extend.
    - Strip parenthetical content.
    - Strip diacritics (NFD → strip M-class → recompose).
    - Strip whitespace; collapse multiple spaces; trim.
    - Output is the canonical normalized form.
13. **Alias chain traversal.** For every catalog hit, walk
    `catalog_entry.aliases[]` (already part of the Trie at load time)
    and `catalog_entry.subsidiaries[]` (up to depth 3 by default,
    configurable via `--max-subsidiary-depth`).
14. **Confidence band assignment.** `band = 'high'` if `confidence ≥ 0.85`;
    `'medium'` if `0.7 ≤ confidence < 0.85`; `'low'` if
    `confidence < 0.7`. Low-confidence matches are emitted with
    `suppressed = false` but the W.W3 reporter ignores them unless the
    operator confirms via override.
15. **De-duplicate.** Key: `(surface | catalog_uid | matched_entity_name |
    normalize(match_path))`. Within a duplicate set, keep the highest
    confidence; aggregate `match_paths[]` if duplicates differ only by
    depth.
16. **Apply suppressions.** For each match whose
    `(catalog_uid, vendor) ∈ suppressions` AND the suppression is
    unexpired, set `suppressed = true` and propagate
    `suppression_justification`.

### Phase D — Emission

17. **POA&M emit.** For each non-suppressed match, call
    `emitPoamFinding(match)` against the existing `core/oscal-poam.ts`
    pipeline. Persist `match.poam_item_uuid` back into the match record.
18. **Compute summary block + reportable flags.**
    - `reportable_under_far_52_204_25_d` = any non-suppressed match with
      `confidence_band = 'high'` AND
      `catalog_provenance.source ∈ {'far-52.204-25-a', 'operator-manual-addition'}`.
    - `reportable_under_ndaa_1634` = any non-suppressed match with
      `catalog_provenance.source ∈ {'ndaa-1634', 'bod-17-01'}`.
    - `reasonable_inquiry_attested` = `surfaces_screened.length = 4` AND
      `catalog_snapshot_ref.age_hours < 24` AND
      `suppressed_matches < 0.05 * total_matches` (operator-bypass-rate
      ceiling — protects against override abuse).
19. **Write JSON envelope** to
    `out/prohibited-vendors-screen-result.json` with canonical JSON
    (stable key order, 2-space indent, LF newlines).
20. **Write XLSX** to `out/prohibited-vendors-screen-result.xlsx`.
21. **Tracker DB upsert.** Insert one row into
    `prohibited_vendor_screens` keyed by `run_id`; insert one row per
    match into `prohibited_vendor_matches`.
22. **Sign + timestamp.** Glob both outputs through `core/sign.ts` +
    `core/timestamp.ts` (LOOP-A.A5).
23. **Coverage report.** Append `prohibited_vendor_screen_coverage`
    section to `out/inventory-coverage.json`:
    `{ surfaces_walked: 4, sbom_packages_screened: N,
       subprocessor_rows_screened: N, oci_images_screened: N,
       inventory_assets_screened: N, catalog_age_hours: H }`.
24. **CHANGELOG + STATUS update** — performed by the slice-completion
    procedure (see §13).

### Phase E — Validation

25. `npm run check:provenance` must pass for the new envelope.
26. `npm run lint:no-stubs` must remain green.
27. `npm run check:reo` (G1 + G2 + G3) must pass.

## 7. Files to create / modify (absolute paths)

### Files to CREATE

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/prohibited-vendors-screen.ts`
   — pure screener: catalog × surfaces → matches. ~700 lines.
2. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sbom-prohibited-screen.ts`
   — extends LOOP-E.E2's `core/sbom.ts`; reads cosign-verified SBOM and
   walks every package's maintainer / origin / transitive deps.
   ~350 lines.
3. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oci-publisher-screen.ts`
   — extends LOOP-J.J3's `core/oci-attest.ts`; reads cosign / Rekor
   publisher key + repository owner against catalog. ~300 lines.
4. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/vendor-name-normalizer.ts`
   — transliteration, alias chain, subsidiary traversal, corporate
   suffix stripping. ~250 lines.
5. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/prohibited-vendors-screen-emit.ts`
   — JSON + .xlsx emitter; provenance block; sign + timestamp wiring.
   ~300 lines.
6. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/prohibited-vendors-screen-xlsx.ts`
   — OOXML xlsx renderer reusing the `core/inventory-workbook.ts`
   pattern. 3 sheets. ~400 lines.
7. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/prohibited-vendors-overrides.ts`
   — Ajv-validated loader for `prohibited-vendors-overrides.yaml`.
   ~120 lines.
8. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/prohibited-vendors-overrides.example.yaml`
   — committed example with documented schema. ~40 lines.
9. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/prohibited-vendors-screen.test.ts`
   — ≥ 15 tests (see § 8).
10. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/sbom-prohibited-screen.test.ts`
    — ≥ 5 tests for SBOM walker behavior.
11. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/oci-publisher-screen.test.ts`
    — ≥ 4 tests for OCI publisher walker.
12. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/vendor-name-normalizer.test.ts`
    — ≥ 8 tests for normalization (transliteration, suffix strip,
    diacritics).
13. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/prohibited-vendors-overrides.test.ts`
    — ≥ 3 tests for overrides loader (valid, invalid schema, expired
    suppression).
14. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/prohibited-vendors/`
    — catalog fixtures (one row per provenance source); subprocessor
    sheet fixture; SPDX 2.3 + CycloneDX 1.6 sample SBOMs; OCI
    attestation fixture; inventory fixture; overrides fixture.

### Files to EXTEND

15. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/subprocessors-sheet.ts`
    — extend with `screenAgainstProhibitedVendors(rows, catalog,
    normalizer) → ProhibitedVendorMatch[]` helper. The existing
    sheet-reading paths remain untouched.
16. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
    — new `--prohibited-vendor-screen` flag + env
    `CLOUD_EVIDENCE_PROHIBITED_VENDOR_SCREEN`; runs AFTER inventory +
    SBOM + OCI attest in the orchestrator order. New
    `--sbom-max-depth <int>` flag (default 8). New
    `--max-subsidiary-depth <int>` flag (default 3).
17. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
    — `WELL_KNOWN` adds:
    ```ts
    { role: 'prohibited-vendors-screen-json',
      filename: 'prohibited-vendors-screen-result.json',
      description: 'Prohibited-vendor screen result envelope per FAR 4.2101 reasonable inquiry (LOOP-W.W2)' },
    { role: 'prohibited-vendors-screen-xlsx',
      filename: 'prohibited-vendors-screen-result.xlsx',
      description: 'Operator-readable prohibited-vendor screen workbook (LOOP-W.W2)' },
    ```
18. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`
    — extend with `prohibited_vendor_screen_coverage` section.
19. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts`
    — extend the `emitPoamFinding(...)` signature to accept a
    `vendor_screen_match` discriminator so W.W2's matches surface with
    the right `related-controls[]`.
20. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/db/migrations/`
    — new migration: tables `prohibited_vendor_screens(run_id PK,
    started_at, completed_at, total_matches, reportable, ...)` and
    `prohibited_vendor_matches(match_id PK, run_id FK, catalog_uid,
    surface, confidence, ...)`.

## 8. Test specifications

| id   | scenario                                                                 | fixture path                                                                  | expected                                                                                                                              | acceptance                                                |
|------|--------------------------------------------------------------------------|-------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| T1   | Exact-name match against Huawei in subprocessor sheet                   | `tests/fixtures/prohibited-vendors/subprocessors-huawei.csv`                  | One match: `confidence=1.0, band='high', matched_by='exact-case-insensitive'`                                                         | Match present; `reportable_under_far_52_204_25_d = true`  |
| T2   | Alias-table match for "ZTE Corporation Ltd" (corp suffix stripped)      | `tests/fixtures/prohibited-vendors/subprocessors-zte-corp.csv`                | `matched_by='normalized-name'`, confidence 1.0 after suffix strip                                                                     | Strip-and-match path covered                              |
| T3   | Transliteration: Cyrillic "Хуавэй" → Huawei                              | `tests/fixtures/prohibited-vendors/subprocessors-cyrillic.csv`                | `matched_by='transliteration'`, confidence 0.95                                                                                       | Transliteration table applied                             |
| T4   | Subsidiary walk depth-1: "HiSilicon" → Huawei (subsidiary)               | `tests/fixtures/prohibited-vendors/catalog-with-hisilicon.json`               | `matched_by='subsidiary-walk'`, confidence 0.85, `match_path=['HiSilicon','Huawei']`                                                   | Subsidiary edge resolved                                  |
| T5   | Subsidiary walk depth-2: "ZheJiang HikvisionInfo" → Hikvision → covered  | `tests/fixtures/prohibited-vendors/catalog-with-hik-grandchild.json`          | `matched_by='subsidiary-walk'`, confidence 0.7, depth-2 path                                                                          | Depth-2 traversal works                                   |
| T6   | SBOM transitive: pkg→a-lib→b-lib→@huawei-oss/foo                          | `tests/fixtures/prohibited-vendors/sbom-spdx-transitive.json`                 | Match w/ `surface='sbom'`, `match_path` includes all 4 hops, confidence 1.0 - (3 * 0.02) = 0.94                                        | Transitive walk + depth penalty                           |
| T7   | SBOM publisher field match (CycloneDX 1.6)                              | `tests/fixtures/prohibited-vendors/sbom-cyclonedx-publisher.json`             | `confidence=0.95, matched_by='exact-case-insensitive'` via `publisher` field                                                          | CycloneDX path                                            |
| T8   | OCI publisher fingerprint match                                          | `tests/fixtures/prohibited-vendors/oci-attest-fingerprint.json` + catalog override w/ fingerprint | `surface='oci-publisher', matched_by='fingerprint', confidence=1.0`                                                                   | Fingerprint index hits                                    |
| T9   | OCI publisher OIDC issuer registrable-domain match                       | `tests/fixtures/prohibited-vendors/oci-attest-oidc-domain.json`               | `matched_by='domain-registrable', confidence=0.85`                                                                                    | Domain lookup correct                                     |
| T10  | Inventory provider_tag match: `provider_tag='huawei-public-cloud'`       | `tests/fixtures/prohibited-vendors/inventory-huawei-tag.json`                 | Match w/ `surface='inventory-provider-tag', confidence=1.0`                                                                           | Inventory walker covered                                  |
| T11  | Inventory SKU substring: `sku='hikvision-camera-DS-2CD2x'`               | `tests/fixtures/prohibited-vendors/inventory-hik-sku.json`                    | `confidence=0.85, matched_by='exact-case-insensitive'` after suffix strip                                                              | Substring path                                            |
| T12  | False-positive defence: vendor "Acme-Hikvision-Inspired-Brand" no match  | `tests/fixtures/prohibited-vendors/subprocessors-fp.csv`                      | No match emitted (suffix-strip + Trie boundary check rejects)                                                                         | No false positive                                         |
| T13  | Suppression honoured + expiry check                                      | `tests/fixtures/prohibited-vendors/overrides-suppression.yaml`                | Match flagged `suppressed=true` while suppression unexpired; emerges as `suppressed=false` after expiry                               | Suppression + expiry                                       |
| T14  | Manual-addition row screened identically                                 | `tests/fixtures/prohibited-vendors/overrides-manual.yaml`                     | Match w/ `catalog_provenance.source='operator-manual-addition'`                                                                       | Operator addition path                                    |
| T15  | Stale catalog (>24h) surfaces `coverage:stale` log line                  | `tests/fixtures/prohibited-vendors/catalog-stale.json`                        | Run completes; log line emitted; `catalog_snapshot_ref.is_stale=true`                                                                  | Staleness surface                                          |
| T16  | POA&M item emitted per non-suppressed match w/ SR-1/3/5/6/11 controls    | `tests/fixtures/prohibited-vendors/sbom-spdx-transitive.json`                 | `out/poam.json` carries an item with `related-controls = ['sr-1','sr-3','sr-5','sr-6','sr-11']` and `severity='high'`                  | POA&M chain integration                                   |
| T17  | Provenance block populated on envelope (`check:provenance` exits 0)      | `tests/fixtures/prohibited-vendors/full-run.json`                             | Envelope has `provenance.emitter='prohibited-vendors-screen'`, source_calls listing 6 paths                                            | `npm run check:provenance` green                          |
| T18  | XLSX round-trip: 3 sheets, A2 of `Matches` = match_id format             | (any of the above)                                                            | SheetJS read-back returns matches, surfaces, summary                                                                                   | OOXML correctness                                         |
| T19  | Orchestrator runs only when `--prohibited-vendor-screen` set             | n/a (CLI test)                                                                | Without flag, no envelope written; with flag, envelope + xlsx emitted                                                                 | Flag respected                                            |
| T20  | Env-var trigger: `CLOUD_EVIDENCE_PROHIBITED_VENDOR_SCREEN=1`             | n/a (env-var test)                                                            | Same as T19                                                                                                                            | Env honoured                                              |
| T21  | Catalog signature verification fails → exit non-zero w/ typed error      | `tests/fixtures/prohibited-vendors/catalog-bad-sig.json`                     | Process exits 2; error `CatalogSignatureInvalidError`                                                                                  | Signature-check path                                      |
| T22  | Kaspersky catalog row triggers NDAA 1634 reportable flag                  | `tests/fixtures/prohibited-vendors/catalog-kaspersky.json` + SBOM match       | `reportable_under_ndaa_1634 = true`; POA&M cites NDAA §1634 in description                                                            | NDAA citation correctness                                 |
| T23  | OFAC SDN catalog row produces match w/ provenance.source='ofac-sdn-advanced' | `tests/fixtures/prohibited-vendors/catalog-ofac.json` + subprocessor match  | Match propagates `provenance.list_program` (e.g. 'CYBER2')                                                                            | OFAC provenance propagation                               |
| T24  | BIS Entity List catalog row produces match w/ program code               | `tests/fixtures/prohibited-vendors/catalog-bis-entity.json` + inventory match | Match propagates `list_program='EL'` or `'MEU'`                                                                                       | BIS provenance propagation                                |
| T25  | SAM Exclusions catalog row produces match w/ exclusion_type              | `tests/fixtures/prohibited-vendors/catalog-sam-exclusions.json`               | Match propagates `exclusion_type='Prohibition/Restriction'`                                                                            | SAM provenance propagation                                |
| T26  | `--sbom-max-depth=2` truncates walk at depth 2                          | `tests/fixtures/prohibited-vendors/sbom-spdx-deep.json`                       | Match at depth 3 NOT reported; coverage notes `sbom_walks_truncated_at_depth: 2`                                                       | Depth bound honoured                                      |
| T27  | Vendor-name normalizer test suite                                        | (unit)                                                                        | All 8 normalization paths covered (case, Unicode NFKC, transliterate, suffix strip, parens strip, diacritics, whitespace, collapse)   | Normalizer correctness                                    |
| T28  | Overrides loader rejects malformed YAML                                  | `tests/fixtures/prohibited-vendors/overrides-bad-schema.yaml`                 | Throws `ProhibitedVendorOverridesSchemaError` w/ Ajv error path                                                                       | Loader hardening                                          |
| T29  | Reasonable-inquiry attestation flag computed correctly                  | (run with all 4 surfaces walked + fresh catalog)                              | `reasonable_inquiry_attested = true`                                                                                                  | Attestation logic                                         |
| T30  | Tracker DB rows inserted for screens + matches                          | (integration)                                                                 | `SELECT * FROM prohibited_vendor_screens WHERE run_id=...` returns 1 row; `prohibited_vendor_matches` returns N                       | DB integration                                            |

Total: 30 tests (well above the minimum of 15).

## 9. Risks (≥ 4 with mitigations)

### Risk 1: False positives explode the operator's review queue

**Description.** Vendor names like "Acme Hikvision-Inspired Optics LLC"
(no actual covered-entity affiliation) could naively match "Hikvision".
A 1000-row subprocessor sheet × 1500 catalog rows could produce hundreds
of false positives if matching is too loose; the operator would lose
faith in the system and start blanket-suppressing.

**Mitigation.**
- Trie matching is **boundary-respecting**: only matches if the
  normalized form is a complete token sequence in the input string, not
  a substring. "Hikvision-Inspired" tokenizes as `hikvision inspired`;
  the matcher only fires on the standalone token `hikvision` (which IS
  in this case present, but at lower confidence — 0.7 substring band,
  which the W.W3 reporter ignores absent operator confirmation).
- Operator can mass-suppress via `overrides.yaml` with documented
  justification.
- The `suppression_justification` is required (Ajv-enforced) — an
  operator cannot suppress silently.
- Bypass-rate ceiling: `reasonable_inquiry_attested = false` if
  `suppressed_matches > 0.05 * total_matches`. The CHANGELOG +
  CISO-review trail surfaces over-suppression patterns.

### Risk 2: Subsidiary chain drifts (catalog incomplete on aliases)

**Description.** Federal published lists frequently lag corporate
restructurings. A subsidiary spun off into a new name may not appear in
any FAR/NDAA/OFAC/BIS/SAM list for years. W.W2 would miss the link.

**Mitigation.**
- `prohibited-vendors-overrides.yaml::manual_additions` lets the
  operator-of-record (CISO) add operator-discovered subsidiaries with a
  documented justification (3PAO can review the justification).
- W.W1's daily snapshot pulls the source lists every 24h, capping the
  drift window.
- The match-record `catalog_provenance.source = 'operator-manual-addition'`
  is explicitly distinguished from Federal-sourced rows so a 3PAO can
  filter to Federal-only when deciding contract-level reportability.

### Risk 3: SBOM walker performance on large dependency graphs

**Description.** A modern Node.js or Go service may have 5000-15000
packages transitively. At depth 8, the worst-case walk is O(N × catalog
size). With a 1500-row catalog and an aggressive walker this could push
the run beyond 30 minutes, breaking the orchestrator's overall SLA.

**Mitigation.**
- Trie-based catalog lookup is O(1) per package (with a
  catalog-precomputed index built once at load time, amortizing the
  N × catalog cost).
- Worker-pool parallelism: SBOM walk runs across `os.cpus().length - 1`
  workers; each owns a subtree.
- Configurable depth cap (`--sbom-max-depth`, default 8); coverage
  notes when truncated.
- Benchmarked in CI: a 10k-package SBOM × 2000-row catalog completes
  in < 5 minutes on a 4-vCPU runner.

### Risk 4: OCI publisher attribution ambiguity

**Description.** A cosign keyless attestation may expose
`cosign_keyless_oidc_issuer = 'https://accounts.google.com'` and
`cosign_keyless_subject = 'builder@example.com'`. Neither uniquely
identifies the publishing organization; the same OIDC pair could be
used by an in-house build and a covered entity if the covered entity
runs CI on Google's hosted runners.

**Mitigation.**
- W.W2's OCI screener uses a **fingerprint-first** strategy: when
  catalog rows include cosign public-key fingerprints (operator
  populates via `overrides.yaml`), fingerprint match is unambiguous.
- For domain-only matches, confidence band drops to `medium`
  (registrable-domain match = 0.85); W.W3 reporter ignores medium-band
  matches unless operator confirms.
- The match-record carries the raw `cosign_keyless_oidc_issuer +
  subject + rekor_uuid` so a 3PAO can perform supplementary inquiry.

### Risk 5: Stale catalog (snapshot > 24h) and weekend / holiday cadence

**Description.** W.W1's snapshot extractor runs on a daily cron; if the
cron fails Friday evening, the Monday-morning W.W2 run will use a
72-hour-old snapshot. New SDN additions in that window would be missed.

**Mitigation.**
- W.W2 computes `catalog_snapshot_ref.age_hours`. When > 24 it emits
  `coverage:stale` to the run log and sets
  `is_stale = true` on the envelope.
- Orchestrator `--strict` mode upgrades stale-catalog warnings to
  fatal (non-zero exit). Default mode logs but proceeds.
- The CISO sign-off step in the tracker UI is gated on the catalog
  age — if `> 48h`, the UI requires explicit acknowledgement.

### Risk 6: Provenance block accidentally signed without source paths

**Description.** A regression in the emit pipeline could ship an
envelope whose `provenance.source_calls` is empty, which would
nevertheless pass Ed25519 signing — REO Rule 2.6 violated.

**Mitigation.**
- `check:provenance` script enforces non-empty `source_calls[]` AND
  each entry has a non-empty `sha256` AND each `path` exists on disk
  AND each `sha256` matches the on-disk hash.
- Unit test T17 calls the same script against a fixture.
- CI gate G3 fails the build on regression.

## 10. Open questions

- **Q1.** Should depth-N (`N ≥ 3`) subsidiary matches default to
  `confidence_band = 'low'` or `'medium'`? Recommend: `'medium'` —
  Federal lists rarely enumerate beyond direct subsidiaries, so depth-2
  is a reasonable inquiry; depth-3 is a stretch but should still
  surface for operator review.

- **Q2.** When the SBOM contains a package whose `supplier` is
  ambiguous (e.g. `"Various, see contributors"`), do we fail open or
  closed? Recommend: emit a `REQUIRES-OPERATOR-INPUT` match with
  `confidence_band = 'low'` rather than silently ignore — the operator
  must explicitly attest by overrides.yaml.

- **Q3.** Should OCI publisher screening walk the base-image graph
  (FROM chain in the Dockerfile)? Recommend: yes — read the
  `slsa.predicate.materials[]` from the LOOP-J.J3 attestation, which
  enumerates every base image; walk each.

- **Q4.** Cosign GitHub-Actions OIDC identities use the pattern
  `https://github.com/<owner>/<repo>/.github/workflows/<wf>@<ref>`.
  Should `<owner>` extraction (e.g. "@huawei") become a screening
  surface? Recommend: yes, as a low-confidence band (0.7) heuristic;
  operator confirms.

- **Q5.** How do we handle the case where W.W1's catalog mistakenly
  includes a CSP's own legitimate subsidiary (e.g. CSP has a subsidiary
  in a covered foreign country that is **not** on any list but the
  matcher fires on shared trade name)? Recommend: documented
  suppression with CISO sign-off; the suppression-justification is the
  evidence trail.

- **Q6.** Should the screener also walk the `inventory.assets[].vendor`
  field (when present, e.g. from Azure resource graph
  `properties.publisher`)? Recommend: yes, as a 5th surface. Defer to
  W.W2.5 if scope balloons; otherwise include in initial ship.

- **Q7.** Should suppression entries automatically open a tracker
  follow-up ticket for re-review at expiry? Recommend: yes; the
  tracker DB layer enforces this when migrations land.

- **Q8.** When the screen yields zero matches AND
  `reasonable_inquiry_attested = true`, do we emit a positive
  POA&M-equivalent "compliance-evidence" record? Recommend: yes, a
  single OSCAL `assessment-result.observation` per run with
  `methods=['EXAMINE']` and `assessment-objective` cite to FAR 4.2101
  "reasonable inquiry".

## 11. REQUIRES-OPERATOR-INPUT fields

Per REO Rule 4, every field that cannot be auto-derived flows through
one of: tracker DB, `config.yaml`, cloud resource tags, or a CLI flag.

| Field name                                 | Type     | Validator                            | UI location                                                                          | Failure mode if missing                                                                                                       |
|--------------------------------------------|----------|--------------------------------------|--------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| `match.far_..._data_elements.supplier_uei` | string   | Ajv: pattern UEI (12 alnum chars)    | Tracker DB `subprocessors.uei`; CLI `--vendor-uei <name>:<uei>`; operator can paste in tracker UI | Field set to `'REQUIRES-OPERATOR-INPUT'`; W.W3 1BD report flagged `requires_operator_input_count > 0`; report submission gated |
| `match.far_..._data_elements.supplier_cage_code` | string | Ajv: pattern CAGE (5 alnum chars)  | Tracker DB `subprocessors.cage_code`                                                  | `'REQUIRES-OPERATOR-INPUT'`; same gate as UEI                                                                                  |
| `match.far_..._data_elements.contract_numbers` | string[] | Ajv: each pattern non-empty       | `config.yaml::federal_contracts[].contract_number`                                    | Empty array; W.W3 cannot key per-contract reports; CISO override allows roll-up reporting                                     |
| `match.far_..._data_elements.brand` / `model_number` / `item_description` | string | Ajv: each non-empty | Tracker DB `subprocessors.brand` etc., or operator paste in the screen-results page | `'REQUIRES-OPERATOR-INPUT'` for each; W.W3 reports lacking brand/model fail FAR 52.204-25(d)(1)(vi)(vii)(viii) data-element schema |
| `match.far_..._data_elements.mitigation_actions` | string | Ajv: non-empty                  | Tracker UI per-match remediation page; auto-populated from POA&M remediation plan when present | Field set to `'REQUIRES-OPERATOR-INPUT'`; W.W3 reports default to "operator declines to state" until populated                  |
| `suppressions[*].justification`            | string   | Ajv: non-empty                       | `prohibited-vendors-overrides.yaml`                                                  | Loader throws schema error; W.W2 exits non-zero                                                                                |
| `suppressions[*].expires_at`               | ISO date | Ajv: future date or null             | Same                                                                                 | Loader throws schema error                                                                                                     |
| `manual_additions[*]`                      | catalog  | Ajv: matches CatalogEntry subset     | Same                                                                                 | Loader throws schema error                                                                                                     |
| `--prohibited-vendor-screen` enable flag   | bool     | CLI flag OR env `CLOUD_EVIDENCE_PROHIBITED_VENDOR_SCREEN=1` | Orchestrator CLI                                                              | When false (development), W.W2 skipped silently with `log.info('w.w2: skipped')`                                              |
| `--sbom-max-depth <int>` (default 8)       | int      | int >= 1                             | Orchestrator CLI                                                                     | Defaults to 8                                                                                                                  |
| `--max-subsidiary-depth <int>` (default 3) | int      | int >= 1                             | Orchestrator CLI                                                                     | Defaults to 3                                                                                                                  |
| Catalog signing-key fingerprint (Ed25519)  | hex      | 64 hex chars                         | `config.yaml::wW1_signing_key_id`                                                    | Verification step throws `CatalogSignatureInvalidError`; W.W2 exits non-zero (T21)                                            |
| `transliteration_overrides{}`              | map      | Ajv: source-script → Latin           | `prohibited-vendors-overrides.yaml`                                                  | Defaults to committed CLDR-derived table                                                                                       |

## 12. Implementation log

> The implementing session fills this table at every meaningful
> milestone per `docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3.

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| 2026-06-18 | impl-w-w2 | Shipped end to end per spec (adapted to the real codebase). 54 new tests (normalizer 11, overrides 7, sbom 6, oci 5, screen 25); full suite 1073→1127. typecheck/test/check:reo all green; G3 verified on the real `out/prohibited-vendors-screen-result.json`. | `TBD-step6` | See divergences below. |

**Spec-vs-reality divergences (documented per the CLAUDE.md Strong Directive):**

1. **Catalog shape.** The spec's §4.1 idealized `ProhibitedVendorCatalogEntry`
   (with `catalog_uid`, `subsidiaries[]`, `parent_entities[]`) does not match
   the W.W1 catalog actually shipped — `core/prohibited-vendors-catalog.ts`
   emits `ProhibitedVendorEntity[]` keyed by `(source_id, source_record_id)`
   with `name_canonical`, `name_canonical_stripped`, `aliases[]`, `programs[]`.
   The matcher was built against the REAL shape. `catalog_uid` is synthesized
   as `${source_id}::${source_record_id}`. Federal lists carry no subsidiary
   edges, so the subsidiary walk fires ONLY on operator-supplied
   `manual_additions[].subsidiaries` (REO Rule 4) — for a pure federal catalog
   it honestly finds nothing.
2. **No `tracker/` subsystem.** §7.2 item 20 (tracker DB migration) + T30
   reference a `tracker/` directory that does NOT exist in this checkout.
   Rather than fabricate infrastructure (a REO violation), screen results are
   persisted via the signed JSON envelope + an append-only
   `out/prohibited-vendor-screens.jsonl` ledger — the repo's established
   durable-record pattern (`core/poam-ledger.ts`, `core/run-ledger.ts`). The
   tracker-DB tables + UI are logged as a follow-up risk (W.W2-EXT-1).
3. **SBOM API.** `core/sbom.ts` (E.E2) flattens components without supplier/
   publisher/originator or a dependency graph, so `sbom-prohibited-screen.ts`
   parses SPDX `relationships[]` / CycloneDX `dependencies[]` directly for the
   transitive walk + maintainer fields (composing `listSbomFiles`).
4. **No OCI producer.** The spec's `core/oci-attest.ts` (J.J3) does not exist;
   J.J3 shipped `core/supply-chain-risk.ts`. `oci-publisher-screen.ts` reads
   cosign/Rekor attestation files from `out/oci-attestations/*.json` when
   present (the documented §4.4 shape) and returns zero matches (no fabrication)
   when absent.
5. **POA&M integration.** There is no `emitPoamFinding` function. Mirroring the
   existing `supplyChainPoamItems` pattern, `core/oscal-poam.ts` gained
   `buildVendorScreenPoamItems(matches)` + a `vendorScreenItems` option on
   `emitOscalPoam`. In the current orchestrator pipeline `emitOscalPoam` runs
   BEFORE the catalog/screen, so threading items into that call would require a
   pipeline reorder (out of scope); the screen emits its own signed envelope as
   the primary W.W2 artifact and the POA&M builder is unit-tested (T16) for
   callers. Logged as follow-up risk W.W2-EXT-2.
6. **Provenance casing.** The envelope's top-level `provenance` block uses
   camelCase keys (`emitter`/`emittedAt`/`sourceCalls`/`signingKeyId`) per the
   G3 guardrail (the spec's snake_case would fail `check:provenance`); the
   richer per-source digests live in `provenance.sourceDigests`.
7. **Open §10 questions resolved:** Q1 — depth-2 subsidiary = medium (0.7),
   depth-3 = low (0.5), per the confidence bands. Q4 — GitHub-Actions OIDC
   `<owner>` IS screened as a low-confidence (0.7) heuristic. Remaining §10
   questions (Q2/Q3/Q5/Q6/Q7/Q8) are deferred to W.W3/W.W4 or operator policy
   and are not gating for W.W2.

## 13. Completion checklist (SLICE-COMPLETION-PROCEDURE.md verbatim + push directive)

Per `docs/SLICE-COMPLETION-PROCEDURE.md`, the implementing session MUST
check every box atomically with the final commit:

- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥ 30 for this slice's new
      tests; see § 8 T1..T30)
- [ ] `npm run check:reo` green (G1 + G2 + G3)
- [ ] `npm run check:provenance` green for
      `out/prohibited-vendors-screen-result.json`
- [ ] `npm run check:coverage-regression` green
      (`prohibited_vendor_screen_coverage` baseline established or
      maintained)
- [ ] `npm run lint:no-stubs` green (no TODO/stub markers introduced)
- [ ] `docs/STATUS.md` updated (slice W.W2 row + Overall section;
      "Next priority" line updated to W.W3)
- [ ] `docs/loops/LOOP-W-SPEC.md` § 3 status table row for W.W2 updated
      (status=done, commit=`<sha>`)
- [ ] `docs/loops/LOOP-W-RISKS.md` updated if new risks surfaced
      during implementation
- [ ] This file's frontmatter updated (`status: done`,
      `commit: <sha>`, `completed_date: <ISO>`, `last_updated: <ISO>`)
- [ ] Final Implementation log entry appended (§ 12) per
      `docs/IMPLEMENTATION-LOG-TEMPLATE.md` §4 format
- [ ] `CHANGELOG.md` "Unreleased" entry added; entry cites
      FAR 52.204-25, FAR 4.2101 "reasonable inquiry", NDAA §1634,
      BOD 17-01, OFAC SDN, BIS Entity List, SAM Exclusions, SPDX 2.3,
      CycloneDX 1.6, cosign + Rekor — i.e. every authoritative source
      this slice's evidence traces to
- [ ] Commit message includes slice ID `LOOP-W.W2` + the
      Co-Authored-By trailer
- [ ] **After commit lands, append a row to `docs/STATUS.md` for this
      slice; update the loop SPEC status row; append a CHANGELOG line;
      push to `origin/main`; only THEN is the slice closed.**

Per the GROUND-UP DIRECTIVE: this push step is **non-negotiable**. A
W.W2 commit that does not push to `origin/main` leaves the on-disk
record of W.W2 untrustable; a fresh session opening from `main` would
not see the new doc/code and would re-do the work.

## 14. Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build
   steps + tests + risks + completion checklist + REQUIRES-OPERATOR-INPUT
   table.
3. Read `cloud-evidence/docs/loops/LOOP-W-SPEC.md` §§ 1, 2, 5, 6, 7
   for cross-slice context (especially §6 dataflow diagram).
4. Read `cloud-evidence/docs/loops/LOOP-W-RISKS.md` for cross-cutting
   risks.
5. Read `cloud-evidence/docs/slices/W/W.W1.md` for the catalog schema
   you'll consume.
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step procedure.
7. Read `cloud-evidence/core/subprocessors-sheet.ts` (existing) — your
   subprocessor walker extends it.
8. Read `cloud-evidence/core/sbom.ts` (LOOP-E.E2) — your SBOM walker
   consumes its output.
9. Read `cloud-evidence/core/oci-attest.ts` (LOOP-J.J3.b) — your OCI
   publisher walker consumes its attestations.
10. Read `cloud-evidence/core/oscal-poam.ts` (LOOP-A.A1) — your POA&M
    emit extends its dispatcher with a `vendor_screen_match` kind.
11. Read `cloud-evidence/core/sign.ts` + `core/timestamp.ts`
    (LOOP-A.A5) — your outputs flow through these.
12. Read `cloud-evidence/core/inventory-workbook.ts` for the OOXML
    .xlsx renderer pattern you mirror.
13. Read `cloud-evidence/core/inventory-coverage.ts` for the coverage
    contract pattern.
14. Confirm W.W1 has shipped (catalog snapshot exists in
    `data/prohibited-vendors-snapshot-YYYYMMDD.json` with valid
    Ed25519 signature); if not, gate W.W2 on W.W1 completion.
15. Begin implementation; update the Implementation log section
    (§ 12) at every commit boundary, test-failure, research question
    answered, spec divergence, newly-discovered risk, or external
    dependency pin.

---

## Appendix A — Pseudocode: surface walkers

```ts
// 8. Subprocessor sheet walker
function screenSubprocessorSheet(
  rows: SubprocessorSheetRow[],
  trie: VendorNameTrie,
  normalizer: VendorNameNormalizer,
): ProhibitedVendorMatch[] {
  return rows.flatMap(row => {
    const candidates = [row.vendor, row.legal_entity].filter(Boolean);
    return candidates.flatMap(name => {
      const norm = normalizer.normalize(name);
      const hit = trie.find(norm);
      if (!hit) return [];
      return [buildMatch({
        surface: 'subprocessor-sheet',
        catalog: hit,
        matched: name,
        match_path: [name],
        confidence: confidenceFor(hit.match_kind),
        sources: { surface_evidence: `subprocessor-row:${row.vendor}` },
        far_data: extractFarData(row),
      })];
    });
  });
}

// 9. SBOM walker (recursive DFS w/ depth cap)
function screenSbom(
  sbom: SpdxOrCycloneDx,
  trie: VendorNameTrie,
  normalizer: VendorNameNormalizer,
  maxDepth: number,
): ProhibitedVendorMatch[] {
  const matches: ProhibitedVendorMatch[] = [];
  const visited = new Set<string>();
  const roots = sbom.rootPackages();
  for (const root of roots) {
    walk(root, [root.name], 0);
  }
  function walk(pkg: Pkg, path: string[], depth: number): void {
    if (depth > maxDepth) return;
    const key = pkg.purl ?? pkg.SPDXID ?? pkg.name;
    if (visited.has(key)) return;
    visited.add(key);
    const candidates = [pkg.name, pkg.supplier, pkg.publisher, pkg.originator]
      .filter(Boolean);
    for (const name of candidates) {
      const norm = normalizer.normalize(name);
      const hit = trie.find(norm);
      if (hit) {
        matches.push(buildMatch({
          surface: 'sbom',
          catalog: hit,
          matched: name,
          match_path: [...path, name],
          confidence: confidenceFor(hit.match_kind) - depth * 0.02,
          sources: {
            surface_evidence: `sbom:${pkg.purl ?? pkg.SPDXID}`,
            sbom_package_purl: pkg.purl,
          },
          far_data: extractFarDataFromPkg(pkg),
        }));
      }
    }
    for (const child of sbom.dependenciesOf(pkg)) {
      walk(child, [...path, child.name], depth + 1);
    }
  }
  return matches;
}
```

## Appendix B — Pseudocode: normalizer

```ts
// core/vendor-name-normalizer.ts
export class VendorNameNormalizer {
  constructor(
    private readonly transliterationTable: Map<string, string>,
    private readonly corporateSuffixes: ReadonlyArray<string>,
  ) {}

  normalize(raw: string): string {
    let s = raw.normalize('NFKC');
    s = s.toLocaleLowerCase('und');
    s = this.transliterate(s);
    s = this.stripParentheticals(s);
    s = this.stripDiacritics(s);
    s = this.stripCorporateSuffixes(s);
    s = s.replace(/\s+/g, ' ').trim();
    return s;
  }

  private transliterate(s: string): string { /* CLDR table */ }
  private stripParentheticals(s: string): string {
    return s.replace(/\([^)]*\)/g, '').replace(/\[[^\]]*\]/g, '');
  }
  private stripDiacritics(s: string): string {
    return s.normalize('NFD').replace(/[̀-ͯ]/g, '').normalize('NFC');
  }
  private stripCorporateSuffixes(s: string): string {
    for (const suf of this.corporateSuffixes) {
      const re = new RegExp(`(\\s|^)${suf}(\\s|$|[.,])`, 'gi');
      s = s.replace(re, ' ');
    }
    return s;
  }
}
```

## Appendix C — Pseudocode: emit + sign

```ts
// core/prohibited-vendors-screen-emit.ts
export async function emitProhibitedVendorsScreenResult(
  opts: EmitOpts,
): Promise<EmitResult> {
  const result = await screen(opts);
  const provenance = {
    emitter: 'prohibited-vendors-screen',
    emitted_at: nowIso(),
    source_calls: [
      { kind: 'catalog-snapshot', path: opts.catalogPath, sha256: await sha256File(opts.catalogPath) },
      { kind: 'subprocessor-sheet', path: opts.subprocessorPath, sha256: await sha256File(opts.subprocessorPath) },
      ...opts.sbomPaths.map(p => ({ kind: 'sbom' as const, path: p, sha256: '<sha>' })),
      ...opts.ociPaths.map(p => ({ kind: 'oci-attest' as const, path: p, sha256: '<sha>' })),
      { kind: 'inventory', path: opts.inventoryPath, sha256: await sha256File(opts.inventoryPath) },
      ...(opts.overridesPath ? [{ kind: 'overrides' as const, path: opts.overridesPath, sha256: await sha256File(opts.overridesPath) }] : []),
    ],
    signing_key_id: opts.signingKeyId,
  };
  result.provenance = provenance;
  await writeCanonicalJson(opts.outJsonPath, result);
  await writeXlsx(opts.outXlsxPath, result);
  await sign(opts.outJsonPath);
  await timestamp(opts.outJsonPath);
  await upsertTracker(result);
  await updateInventoryCoverage(result);
  return { result, paths: [opts.outJsonPath, opts.outXlsxPath] };
}
```

---

> End of `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/slices/W/W.W2.md`.
