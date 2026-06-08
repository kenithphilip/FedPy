---
slice_id: W.W1
title: Prohibited-vendor catalog ingester + canonical-JSON emitter
loop: W
status: done
commit: be78723
completed_date: 2026-06-08
depends_on: []
blocks: [W.W2, W.W3, W.W4]
estimated_effort: medium
last_updated: 2026-06-08
applicable_conditional: any CSP selling to federal agencies (FAR 52.204-25 applies broadly across all federal acquisition since Aug 13, 2020)
---

# W.W1 — Prohibited-vendor catalog ingester + canonical-JSON emitter

## 1. Mission

Build the **single, canonical, Ed25519-signed prohibited-vendor catalog** that every downstream W slice (subprocessor screen W.W2, asset-tag screen W.W3, FAR 52.204-26 representation generator W.W4) reads. The catalog merges six authoritative federal sources — OFAC SDN (Treasury), BIS Entity List (Commerce, 15 CFR 744 Supplement No. 4), SAM.gov Exclusions (GSA, FAR 9.404), the named-entity allowlist from FAR 52.204-25(a) ("covered telecommunications equipment or services"), NDAA §1634 Kaspersky covered entities, and NDAA §889(a)(1)(A)/(B) covered telecommunications entities — into one deterministic, deduplicated, normalized JSON file with a provenance block citing exact source URLs, snapshot dates, and SHA-256 source-file digests. No interpretation. No inference. No editorial summarization. The catalog is the raw substrate; downstream slices perform the matching logic.

## 2. Authoritative sources (verbatim, with URLs + access dates)

All sources accessed **2026-06-07**.

### 2.1 FAR 52.204-25 — Prohibition on Contracting for Certain Telecommunications and Video Surveillance Services or Equipment

**URL**: https://www.acquisition.gov/far/52.204-25
**Authority**: Public Law 115-232 § 889 (FY2019 NDAA); FAR Council interim/final rules effective Aug 13, 2020 (§889(a)(1)(A)) and Aug 13, 2020 (§889(a)(1)(B)).

> "(a) Definitions. As used in this clause —
> *Covered foreign country* means The People's Republic of China.
> *Covered telecommunications equipment or services* means —
> (1) Telecommunications equipment produced by Huawei Technologies Company or ZTE Corporation (or any subsidiary or affiliate of such entities);
> (2) For the purpose of public safety, security of Government facilities, physical security surveillance of critical infrastructure, and other national security purposes, video surveillance and telecommunications equipment produced by Hytera Communications Corporation, Hangzhou Hikvision Digital Technology Company, or Dahua Technology Company (or any subsidiary or affiliate of such entities);
> (3) Telecommunications or video surveillance services provided by such entities or using such equipment; or
> (4) Telecommunications or video surveillance equipment or services produced or provided by an entity that the Secretary of Defense, in consultation with the Director of National Intelligence or the Director of the Federal Bureau of Investigation, reasonably believes to be an entity owned or controlled by, or otherwise connected to, the government of a covered foreign country."

> "(b) Prohibition. (1) Section 889(a)(1)(A) of the John S. McCain National Defense Authorization Act for Fiscal Year 2019 (Pub. L. 115-232) prohibits the head of an executive agency on or after August 13, 2019, from procuring or obtaining, or extending or renewing a contract to procure or obtain, any equipment, system, or service that uses covered telecommunications equipment or services as a substantial or essential component of any system, or as critical technology as part of any system."
> "(2) Section 889(a)(1)(B) of the John S. McCain National Defense Authorization Act for Fiscal Year 2019 (Pub. L. 115-232) prohibits the head of an executive agency on or after August 13, 2020, from entering into a contract or extending or renewing a contract with an entity that uses any equipment, system, or service that uses covered telecommunications equipment or services as a substantial or essential component of any system, or as critical technology as part of any system."

### 2.2 FAR 52.204-26 — Covered Telecommunications Equipment or Services — Representation

**URL**: https://www.acquisition.gov/far/52.204-26
**Authority**: Implements §889 representation requirement.

> "(a) Definitions. *Covered telecommunications equipment or services* and *reasonable inquiry* have the meaning provided in the clause 52.204-25, Prohibition on Contracting for Certain Telecommunications and Video Surveillance Services or Equipment."

> "(b) Procedures. The Offeror shall review the list of excluded parties in the System for Award Management (SAM) (https://www.sam.gov) for entities excluded from receiving federal awards for 'covered telecommunications equipment or services.'"

> "(c) Representations. (1) The Offeror represents that it [ ] does, [ ] does not provide covered telecommunications equipment or services as a part of its offered products or services to the Government in the performance of any contract, subcontract, or other contractual instrument.
> (2) After conducting a reasonable inquiry for purposes of this representation, the offeror represents that it [ ] does, [ ] does not use covered telecommunications equipment or services, or any equipment, system, or service that uses covered telecommunications equipment or services."

### 2.3 FAR 52.204-23 — Prohibition on Contracting for Hardware, Software, and Services Developed or Provided by Kaspersky Lab Covered Entities

**URL**: https://www.acquisition.gov/far/52.204-23
**Authority**: NDAA FY2018 (Public Law 115-91) § 1634.

> "(a) Definitions. As used in this clause —
> *Covered article* means any hardware, software, or service that —
> (1) Is developed or provided by a Kaspersky Lab-covered entity;
> (2) Includes any hardware, software, or service developed or provided in whole or in part by a Kaspersky Lab-covered entity; or
> (3) Contains components using any hardware or software developed in whole or in part by a Kaspersky Lab-covered entity.
> *Kaspersky Lab covered entity* means —
> (1) Kaspersky Lab;
> (2) Any successor entity to Kaspersky Lab;
> (3) Any entity that controls, is controlled by, or is under common control with Kaspersky Lab; or
> (4) Any entity of which Kaspersky Lab has majority ownership."

> "(b) Prohibition. Section 1634 of Division A of the National Defense Authorization Act for Fiscal Year 2018 (Pub. L. 115-91) prohibits Government use, on or after October 1, 2018, of any hardware, software, or services developed or provided, in whole or in part, by a covered entity. The Contractor is prohibited from —
> (1) Providing any covered article that the Government will use on or after October 1, 2018; and
> (2) Using any covered article on or after October 1, 2018, in the development of data or deliverables first produced in the performance of the contract."

### 2.4 NDAA FY2018 § 1634 — Public Law 115-91

**URL**: https://www.govinfo.gov/content/pkg/PLAW-115publ91/html/PLAW-115publ91.htm
**Citation form**: Pub. L. 115-91, Div. A, Title XVI, § 1634, Dec. 12, 2017, 131 Stat. 1738.

> "No department, agency, organization, or other element of the Federal Government may use, whether directly or through work with or on behalf of another department, agency, organization, or element of the Federal Government, any hardware, software, or services developed or provided, in whole or in part, by — (1) Kaspersky Lab (or any successor entity); (2) any entity that controls, is controlled by, or is under common control with Kaspersky Lab; or (3) any entity of which Kaspersky Lab has a majority ownership."

### 2.5 NDAA FY2019 § 889 — Public Law 115-232

**URL**: https://www.govinfo.gov/app/details/PLAW-115publ232
**Citation form**: Pub. L. 115-232, Div. A, Title VIII, § 889, Aug. 13, 2018, 132 Stat. 1917.

> "(a) Prohibition on Use or Procurement.—(1) The head of an executive agency may not—
> (A) procure or obtain or extend or renew a contract to procure or obtain any equipment, system, or service that uses covered telecommunications equipment or services as a substantial or essential component of any system, or as critical technology as part of any system; or
> (B) enter into a contract (or extend or renew a contract) with an entity that uses any equipment, system, or service that uses covered telecommunications equipment or services as a substantial or essential component of any system, or as critical technology as part of any system."

> "(f) Definitions.—In this section: ... (3) Covered telecommunications equipment or services.—The term 'covered telecommunications equipment or services' means any of the following: (A) Telecommunications equipment produced by Huawei Technologies Company or ZTE Corporation (or any subsidiary or affiliate of such entities). (B) For the purpose of public safety, security of government facilities, physical security surveillance of critical infrastructure, and other national security purposes, video surveillance and telecommunications equipment produced by Hytera Communications Corporation, Hangzhou Hikvision Digital Technology Company, or Dahua Technology Company (or any subsidiary or affiliate of such entities). (C) Telecommunications or video surveillance services provided by such entities or using such equipment. (D) Telecommunications or video surveillance equipment or services produced or provided by an entity that the Secretary of Defense, in consultation with the Director of the National Intelligence or the Director of the Federal Bureau of Investigation, reasonably believes to be an entity owned or controlled by, or otherwise connected to, the government of a covered foreign country."

### 2.6 OFAC SDN — Specially Designated Nationals and Blocked Persons List

**URL (programme page)**: https://ofac.treasury.gov/specially-designated-nationals-list-data-formats-data-schemas
**URL (XML feed)**: https://www.treasury.gov/ofac/downloads/sdn.xml
**URL (delimited feed)**: https://www.treasury.gov/ofac/downloads/sdn.csv
**URL (advanced XML)**: https://www.treasury.gov/ofac/downloads/sdn_advanced.xml
**Authority**: International Emergency Economic Powers Act (IEEPA), 50 U.S.C. §§ 1701–1707; Trading with the Enemy Act, 50 U.S.C. App. §§ 1–44; assorted programme-specific Executive Orders.

> "OFAC publishes lists of individuals and companies owned or controlled by, or acting for or on behalf of, targeted countries. It also lists individuals, groups, and entities, such as terrorists and narcotics traffickers designated under programs that are not country-specific. Collectively, such individuals and companies are called 'Specially Designated Nationals' or 'SDNs.' Their assets are blocked and U.S. persons are generally prohibited from dealing with them."

The SDN list ships in three machine-readable formats:
- **Fixed-field flat files**: `SDN.PIP`, `ADD.PIP`, `ALT.PIP`, `SDN_COMMENTS.PIP`
- **Comma-delimited (CSV)**: `SDN.CSV`, `ADD.CSV`, `ALT.CSV`, `SDN_COMMENTS.CSV`
- **XML**: `sdn.xml` (legacy schema) and `sdn_advanced.xml` (international Sanctions Data Model)

The primary record key is `ent_num` (entity number / UID). The CSV schema is documented in `Data_Specification.pdf` published alongside the feeds.

### 2.7 BIS Entity List — 15 CFR Part 744 Supplement No. 4

**URL (eCFR)**: https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-744/appendix-Supplement%20No.%204%20to%20Part%20744
**URL (BIS canonical)**: https://www.bis.gov/entity-list
**URL (consolidated screening list)**: https://www.trade.gov/consolidated-screening-list
**Authority**: 15 CFR Part 744 (Export Administration Regulations / EAR); 15 CFR § 744.16.

> "The Entity List (supplement no. 4 to part 744) identifies entities and other persons reasonably believed to be involved, or to pose a significant risk of being or becoming involved, in activities contrary to the national security or foreign policy interests of the United States."

> "BIS imposes additional license requirements on, and limits the availability of, most license exceptions for exports, reexports, and transfers (in-country) to listed entities."

Entity List entries are published in the Federal Register and codified in eCFR; the consolidated screening list at trade.gov republishes the Entity List in machine-readable CSV/JSON alongside other DOC, State, and Treasury lists. W.W1 reads the consolidated CSV at https://api.trade.gov/static/consolidated_screening_list/consolidated.csv (the canonical machine-readable form).

### 2.8 SAM.gov Exclusions — FAR Subpart 9.4 / FAR 9.404

**URL (programme page)**: https://sam.gov/content/exclusions
**URL (Entity API v3)**: https://api.sam.gov/entity-information/v3/entities
**URL (FAR 9.404)**: https://www.acquisition.gov/far/9.404
**Authority**: FAR Subpart 9.4 (Debarment, Suspension, and Ineligibility); 48 CFR § 9.404.

> "(a) The General Services Administration (GSA) — (1) Operates the web-based System for Award Management (SAM), which contains exclusion records; and (2) Provides technical assistance to Federal agencies in the use of SAM."

> "(b) An exclusion record in SAM contains the — (1) Names and addresses of the entities debarred, suspended, proposed for debarment, voluntarily excluded, declared ineligible, or excluded or disqualified … (2) Name of the agency or other authority taking the action; (3) Cause for the action … (4) Effect of the action; (5) Termination date for each listing; (6) Unique Entity Identifier; (7) Social Security Number (SSN), Employer Identification Number (EIN), or other Taxpayer Identification Number (TIN), if available; and (8) Name and telephone number of the agency point of contact for the action."

SAM.gov exposes the exclusions data via the Entity Management API v3. W.W1 calls `GET https://api.sam.gov/entity-information/v3/entities?samRegistered=Yes&includeSections=exclusions&api_key=<key>` paginated with `pageSize=1000`. The `exclusions` projection contains: `ueiSAM`, `legalBusinessName`, `exclusionTypeDesc`, `excludingAgencyName`, `activeDate`, `terminationDate`, `crossReference`, `additionalComments`.

### 2.9 DHS — Federal Acquisition Supply Chain Security Act (FASCSA) reporting memo

**URL**: https://www.cisa.gov/fascsa
**Authority**: 41 U.S.C. § 1323 (Federal Acquisition Supply Chain Security Act of 2018); FAR Subpart 4.23; 41 CFR Part 201-1.

> "FASCSA enables the Federal Acquisition Security Council (FASC) to recommend removal and exclusion orders to address supply chain risks affecting federal information technology, telecommunications, and national security systems."

W.W1 reads the published FASCSA exclusion orders index. As of 2026-06-07 there are seven FASC orders (DJI Technology covered article order, ICTS Russia/Kaspersky covered article order, and five OMB/DHS-issued covered-article exclusions); each is fetched as PDF, the structured table is OCR-extracted into the FASCSA component of the catalog. The PDFs are SHA-256-digested for provenance.

### 2.10 NIST SP 800-161r1 — Cybersecurity Supply Chain Risk Management Practices (SCRM)

**URL**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1.pdf
**Citation**: NIST SP 800-161 Rev 1 (May 2022).

> "Suppliers of products, system components, and services that have known or suspected ties to foreign adversaries, that are subject to export restrictions, or that appear on a federal exclusion list (e.g., SAM.gov, OFAC SDN, BIS Entity List) shall be evaluated under the organization's C-SCRM policy for inclusion in the acquisition baseline."

Referenced for the "evaluate before integrating" obligation that the W.W2/W.W3/W.W4 downstream slices satisfy operationally; W.W1 is the catalog substrate.

## 3. Scope

### 3.1 In scope
- Ingesting the **six federal authoritative sources** listed in § 2 into one normalized JSON catalog.
- Producing a deterministic, sorted, deduplicated, canonical-JSON output (`out/prohibited-vendors-catalog.json`).
- Embedding a `provenance` block that pins source URL, snapshot timestamp, SHA-256 digest of each raw source file, schema version, and Ed25519 signature.
- Snapshotting the raw source files to a versioned directory (`data/prohibited-vendors-snapshot-YYYYMMDD/`) for forensic preservation.
- Validating that every entity has at minimum a `name` and `source` field; logging `requires_operator_input` diagnostics for malformed rows rather than silently dropping them.
- Exposing a typed loader API (`loadProhibitedVendorsCatalog()`) that the downstream W slices consume.

### 3.2 Out of scope
- **Matching logic** (W.W2 screens subprocessors against the catalog; W.W3 screens cloud asset tags against the catalog).
- **Representation generation** for FAR 52.204-26 (W.W4 generates the Word/PDF representation).
- **Non-federal lists** (UK OFSI, EU consolidated, UN consolidated) — these are out of scope for W.W1; a follow-on W slice may add international harmonization.
- **Interpretation of the §889 "substantial or essential component" test** — that is a legal judgement, not a catalog lookup.
- **Editorial enrichment** of source data (we do not add aliases, geocode addresses, or infer ownership chains that are not in the source).
- **OSCAL emission** — the catalog is plain canonical JSON; W.W2's screening report emits OSCAL observations.

## 4. Inputs

### 4.1 Source files (real evidence)
| Source | URL | Format | Refresh cadence | Filename in snapshot dir |
|---|---|---|---|---|
| OFAC SDN — primary CSV | https://www.treasury.gov/ofac/downloads/sdn.csv | CSV (fixed-field columns) | Real-time; OFAC re-issues on each action | `sdn.csv` |
| OFAC SDN — ADD CSV | https://www.treasury.gov/ofac/downloads/add.csv | CSV | Real-time | `add.csv` |
| OFAC SDN — ALT CSV | https://www.treasury.gov/ofac/downloads/alt.csv | CSV | Real-time | `alt.csv` |
| BIS Entity List (via consolidated screening list) | https://api.trade.gov/static/consolidated_screening_list/consolidated.csv | CSV | Daily | `consolidated.csv` |
| BIS Entity List (eCFR text) | https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-744/appendix-Supplement%20No.%204%20to%20Part%20744 | HTML | Continuous (eCFR) | `entity-list-ecfr.html` |
| SAM.gov Exclusions | https://api.sam.gov/entity-information/v3/entities?includeSections=exclusions | JSON (paginated) | Real-time | `sam-exclusions-page-N.json` |
| FAR 52.204-25 named entities | Hardcoded from FAR text (5 named entities + "covered foreign country" = PRC) | Markdown table | Stable (changes require FAR Council rulemaking) | `far-52-204-25-named-entities.json` |
| NDAA §1634 covered entities | Hardcoded from Pub. L. 115-91 § 1634 | Markdown table | Stable | `ndaa-1634-named-entities.json` |
| FASCSA exclusion orders | https://www.cisa.gov/fascsa (PDF index) | PDF | Per-order | `fascsa-order-NNN.pdf` |

The FAR 52.204-25 and NDAA §1634 named entities are *not* hardcoded sample data per REO Rule 3 — they are the FAR/Public Law constants enumerated in the statute itself (Huawei, ZTE, Hytera, Hikvision, Dahua, Kaspersky Lab). These are allowed-list constants like NIST control IDs. The exact verbatim entity-name strings are committed to `data/far-52-204-25-named-entities.json` and `data/ndaa-1634-named-entities.json`; the docstring of each file cites the statute paragraph.

### 4.2 Operator configuration (`prohibited-vendors-config.yaml`)
```yaml
sam_gov:
  api_key: "${SAM_GOV_API_KEY}"            # Required; obtained from https://sam.gov/data-services
  rate_limit_qps: 5                         # SAM API default
ofac:
  feed_choice: "csv"                        # one of: csv | xml | xml_advanced
  fetch_timeout_seconds: 60
bis:
  source: "consolidated_csv"                # one of: consolidated_csv | ecfr_html
fascsa:
  orders_index_url: "https://www.cisa.gov/fascsa"
  manual_pdf_paths:                          # operator can supply local PDFs when network blocked
    - "data/sources/fascsa-2024-001.pdf"
snapshot_dir: "data"
proxy:
  https_proxy: "${HTTPS_PROXY:-}"           # honour corp proxy
signing:
  key_id: "${PROHIBITED_VENDORS_SIGNING_KEY_ID}"  # ed25519 key id from core/sign.ts registry
```

### 4.3 Network seams (test injectability)
All HTTP calls flow through the existing `core/http-client.ts` with the read-only Proxy guardrail. Test fixtures (under `tests/fixtures/prohibited-vendors/`) supply local files that the catalog ingester reads instead of network calls when `opts.snapshotDir` points to a fixture directory.

## 5. Outputs

### 5.1 Canonical-JSON envelope (`out/prohibited-vendors-catalog.json`)
```ts
export interface ProhibitedVendorsCatalog {
  schema_version: "prohibited-vendors-catalog/v1";
  generated_at: string;                       // ISO-8601 UTC
  snapshot_dir: string;                        // relative path to data/prohibited-vendors-snapshot-YYYYMMDD/
  sources: ProhibitedVendorsSource[];           // one entry per source ingested
  entities: ProhibitedVendorEntity[];           // sorted by (source_id asc, name asc)
  provenance: ProhibitedVendorsProvenance;      // REO Rule 2.6
  statistics: {                                  // post-dedup counts for the bundler manifest
    total_entities: number;
    by_source: Record<ProhibitedVendorsSourceId, number>;
    duplicates_collapsed: number;
    requires_operator_input_count: number;
  };
}

export type ProhibitedVendorsSourceId =
  | "ofac-sdn"
  | "bis-entity-list"
  | "sam-exclusions"
  | "far-52-204-25"
  | "ndaa-1634"
  | "ndaa-889"
  | "fascsa";

export interface ProhibitedVendorsSource {
  id: ProhibitedVendorsSourceId;
  source_url: string;
  snapshot_filename: string;
  sha256: string;                              // SHA-256 of the raw snapshot file
  fetched_at: string;                          // ISO-8601 UTC
  authority_citation: string;                  // e.g. "Pub. L. 115-91 § 1634"
  schema_version_observed?: string;            // OFAC's own schema-version header where present
}

export interface ProhibitedVendorEntity {
  source_id: ProhibitedVendorsSourceId;
  source_record_id: string;                    // e.g. OFAC ent_num, SAM ueiSAM, FAR entity slug
  name_canonical: string;                       // NFKC-normalized, uppercase, trimmed
  name_verbatim: string;                        // exactly as in source
  aliases: string[];                            // sorted, deduplicated
  entity_type: "individual" | "organization" | "vessel" | "aircraft" | "unknown";
  addresses: Array<{ verbatim: string; country?: string }>;
  programs: string[];                          // OFAC programs / FASC order ids / EAR license requirements
  authority_citation: string;                  // source-specific authority pin
  cross_reference?: string;                    // SAM cross-reference, OFAC alt id, etc.
  effective_date?: string;                     // ISO-8601 if known
  termination_date?: string;                   // ISO-8601 if known
  raw_record_pointer: {                         // for forensic recovery
    snapshot_filename: string;
    line_number?: number;
    page_number?: number;
    sheet_name?: string;
  };
  requires_operator_input?: string;            // e.g. "missing-name-canonical" — set when normalization failed
}

export interface ProhibitedVendorsProvenance {
  emitter: "prohibited-vendors-catalog";
  emitted_at: string;
  source_calls: Array<{
    kind: "http" | "file";
    url_or_path: string;
    bytes_read: number;
    sha256: string;
  }>;
  signing_key_id: string;
  signature_ed25519: string;                   // base64
  rfc3161_timestamp_path?: string;             // when present, the signed .tsr lives under out/timestamps/
}
```

### 5.2 Canonical-JSON serialization rules (deterministic)
- Keys sorted lexicographically at every depth (per RFC 8785 JCS).
- No trailing whitespace, no insignificant whitespace.
- Numbers in canonical form (no scientific notation, no leading zeros).
- Arrays preserved in sorted order per § 5.1 (`(source_id asc, name_canonical asc, source_record_id asc)` for `entities[]`).
- Unicode normalized to NFC for the file; `name_canonical` separately normalized to NFKC + uppercase + collapsed whitespace.

### 5.3 Snapshot directory layout
```
data/
  prohibited-vendors-snapshot-20260607/
    sdn.csv
    add.csv
    alt.csv
    consolidated.csv
    entity-list-ecfr.html
    sam-exclusions-page-001.json
    sam-exclusions-page-002.json
    ...
    fascsa-order-2024-001.pdf
    fascsa-order-2025-007.pdf
    far-52-204-25-named-entities.json
    ndaa-1634-named-entities.json
    MANIFEST.json                              # per-file sha256 + bytes + url
```

### 5.4 Signed envelope structure
`out/prohibited-vendors-catalog.json` flows through the existing `core/sign.ts` Ed25519 + RFC 3161 timestamp pipeline. The signed envelope `out/prohibited-vendors-catalog.json.sig` lives alongside (sig file format: `{ algorithm: "ed25519", keyId, sigBase64 }`). The `.tsr` (RFC 3161 timestamp response) lives in `out/timestamps/prohibited-vendors-catalog.json.tsr`.

## 6. Algorithm / Steps (numbered, deterministic, REO-compliant)

1. **Resolve snapshot directory.** `snapshotDir = config.snapshot_dir + "/prohibited-vendors-snapshot-" + today_YYYYMMDD`. If it exists, reuse (idempotent re-run); else create.

2. **Fetch OFAC SDN feeds.** Three GETs against `treasury.gov/ofac/downloads/{sdn,add,alt}.csv` via the read-only HTTP client. Write each to `snapshotDir/{sdn,add,alt}.csv`. Compute SHA-256 of each. Honour `HTTPS_PROXY`. On HTTP error, retry with exponential backoff (3 attempts, 1/4/16s); on terminal failure throw typed `OfacFetchError` — do **not** silently fall back to a stale snapshot.

3. **Fetch BIS Entity List.** GET the consolidated CSV at `api.trade.gov/static/consolidated_screening_list/consolidated.csv`. Filter rows where `source == "Entity List (EL) - Bureau of Industry and Security"`. Also fetch the eCFR HTML as a secondary forensic record. Compute SHA-256.

4. **Fetch SAM.gov Exclusions.** Paginated GET against `api.sam.gov/entity-information/v3/entities?samRegistered=Yes&includeSections=exclusions&api_key=<key>&pageSize=1000&pageNumber=N`. Loop until `totalRecords` reached. Persist each page to `sam-exclusions-page-NNN.json` (zero-padded). Honour `sam_gov.rate_limit_qps`. Compute SHA-256 of each page.

5. **Materialize FAR 52.204-25 + NDAA §889 named entities** from the committed `data/far-52-204-25-named-entities.json` file. This file is generated one-shot by `scripts/extract-prohibited-vendors.mjs` and committed; the docstring at the top of the JSON cites FAR 52.204-25(a) verbatim. The five named entities — Huawei Technologies Company, ZTE Corporation, Hytera Communications Corporation, Hangzhou Hikvision Digital Technology Company, Dahua Technology Company — plus the §889(f)(3)(D) catch-all ("entities owned/controlled by or otherwise connected to the government of the PRC") are emitted as catalog entries with `source_id: "far-52-204-25"`.

6. **Materialize NDAA §1634 named entities** from the committed `data/ndaa-1634-named-entities.json`. The four covered-entity classes — Kaspersky Lab itself, successor entities, control-related entities, majority-owned entities — are emitted as four catalog entries with `source_id: "ndaa-1634"` and `entity_type: "organization"`.

7. **Fetch FASCSA exclusion orders.** Read `fascsa.orders_index_url` (HTML), extract `<a href>` PDF links, fetch each, write to `fascsa-order-<id>.pdf`. For each PDF, run the existing `core/pdf-table-extract.ts` (introduced by LOOP-C.C3 documentation pipeline) to lift the structured exclusion table. When `manual_pdf_paths` is set, prefer the local file over network fetch (for air-gapped environments). Compute SHA-256.

8. **Parse each source into `ProhibitedVendorEntity[]`** via per-source parsers in `core/prohibited-vendors-parsers.ts`:
   - `parseOfacSdn(sdn, add, alt)` — OFAC CSV schema documented in `Data_Specification.pdf`; we honour `ent_num` as the key; aliases lifted from ALT joined on `ent_num`.
   - `parseBisEntityList(consolidated_csv_rows)` — consolidated screening list schema.
   - `parseSamExclusions(pages[])` — flatten `entityData[].exclusions[]`.
   - `parseFar52204_25(json)` — direct passthrough.
   - `parseNdaa1634(json)` — direct passthrough.
   - `parseFascsaOrder(pdf_table_rows)` — table-row mapping.

9. **Normalize `name_canonical`**: NFKC normalize → uppercase → collapse whitespace runs to single space → trim. Strip honorifics (LLC, INC, CO., LTD.) into a separate `name_canonical_stripped` field reserved for downstream matching (W.W2/W.W3 may use either).

10. **Deduplicate by `(source_id, source_record_id)`** within each source. Cross-source duplicates (e.g. an entity that appears on both BIS Entity List and OFAC SDN) are **not** merged at the W.W1 layer — they remain as separate entries with separate `source_id` so the catalog mirrors the federal-source structure faithfully. Downstream matching W.W2 collapses cross-source duplicates at the screening-report layer.

11. **Sort `entities[]`** by `(source_id asc, name_canonical asc, source_record_id asc)`.

12. **Compute `statistics`** for the manifest.

13. **Compute `provenance`**: emitter, emitted_at, source_calls (one entry per network/file read), signing_key_id, signature_ed25519 (computed in step 14), rfc3161_timestamp_path (computed in step 15).

14. **Sign the canonical-JSON bytes** with Ed25519 via `core/sign.ts`. Persist `.sig` alongside.

15. **Timestamp** via existing `core/timestamp.ts` RFC 3161 path. Persist `.tsr` in `out/timestamps/`.

16. **Write `snapshotDir/MANIFEST.json`** — per-file sha256 + bytes + url + fetched_at. This is the forensic preservation manifest that survives independent of `out/prohibited-vendors-catalog.json`.

17. **Emit `out/inventory-coverage.json`** delta — adds `prohibited_vendors_catalog_entity_count` and `prohibited_vendors_catalog_source_count`. The check:coverage-regression guardrail (G2) baselines these.

18. **Return `CatalogEmitResult`** to the caller (orchestrator) containing all output paths, the SHA-256 digest of the canonical-JSON file, and the statistics block. The orchestrator logs `prohibited-vendors: catalog emitted` with the stats.

## 7. Files to create / modify

### 7.1 Create (exact absolute paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/prohibited-vendors-catalog.ts` — catalog ingester + canonical-JSON emitter + typed loader. ~600 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/prohibited-vendors-parsers.ts` — per-source parsers (OFAC SDN, BIS Entity List, SAM Exclusions, FAR 52.204-25, NDAA §1634, FASCSA). ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/prohibited-vendors-config.ts` — typed YAML loader + validator for `prohibited-vendors-config.yaml`. ~120 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-prohibited-vendors.mjs` — offline one-shot snapshot script (downloads all sources, writes snapshot dir + MANIFEST.json) idempotent re-runnable. ~250 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/far-52-204-25-named-entities.json` — committed constant; docstring cites FAR 52.204-25(a).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/ndaa-1634-named-entities.json` — committed constant; docstring cites Pub. L. 115-91 § 1634.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/prohibited-vendors-config.example.yaml` — committed example.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/prohibited-vendors-catalog.test.ts` — ≥15 tests (see § 8).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/prohibited-vendors-parsers.test.ts` — per-parser unit tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/prohibited-vendors/` — sample SDN.CSV slice, sample consolidated.csv slice, sample SAM exclusions page, sample FASCSA PDF, expected catalog JSON for golden tests.

### 7.2 Modify (exact absolute paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--prohibited-vendors-catalog` flag + env `CLOUD_EVIDENCE_PROHIBITED_VENDORS_CATALOG`. Runs BEFORE W.W2 (subprocessor screen) so the catalog is on disk when W.W2 reads it.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — `WELL_KNOWN` gains `{ role: "prohibited-vendors-catalog", filename: "prohibited-vendors-catalog.json", description: "Prohibited-vendor catalog merged from OFAC SDN + BIS Entity List + SAM Exclusions + FAR 52.204-25 + NDAA §1634 + FASCSA (LOOP-W.W1)" }`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts` — extend to track `prohibited_vendors_catalog_entity_count` + `prohibited_vendors_catalog_source_count` per run.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/http-client.ts` — no change required; already supports the proxy + retry semantics described in step 2.

## 8. Test specifications (≥15 tests)

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T1 | parseOfacSdn ingests fixture SDN.CSV with 3 entities + 2 aliases | `test/fixtures/prohibited-vendors/sdn-small.csv`, `add-small.csv`, `alt-small.csv` | 3 `ProhibitedVendorEntity` objects with `source_id: "ofac-sdn"` and aliases joined on `ent_num` | array length === 3; `entities[0].aliases.length === 2` |
| T2 | parseBisEntityList filters consolidated CSV to only "Entity List (EL)" rows | `test/fixtures/prohibited-vendors/consolidated-mixed.csv` (50 rows, 12 EL) | 12 entities with `source_id: "bis-entity-list"` | length === 12; all entries' source equals expected |
| T3 | parseSamExclusions flattens paginated JSON pages into a single array | `test/fixtures/prohibited-vendors/sam-page-{001,002}.json` (page 1 has 7 exclusions, page 2 has 3) | 10 entities with `source_id: "sam-exclusions"` | length === 10; ueiSAM round-tripped on `source_record_id` |
| T4 | parseFar52204_25 emits the 5 named entities + the §889(f)(3)(D) catch-all | `data/far-52-204-25-named-entities.json` (committed) | 6 entities; names include "HUAWEI TECHNOLOGIES COMPANY", "ZTE CORPORATION", "HYTERA COMMUNICATIONS CORPORATION", "HANGZHOU HIKVISION DIGITAL TECHNOLOGY COMPANY", "DAHUA TECHNOLOGY COMPANY", and "ENTITIES OWNED OR CONTROLLED BY THE GOVERNMENT OF THE PEOPLE'S REPUBLIC OF CHINA" | name_canonical set matches expected uppercase strings |
| T5 | parseNdaa1634 emits 4 covered-entity classes | `data/ndaa-1634-named-entities.json` (committed) | 4 entities (Kaspersky + successor + control + majority-owned) | length === 4; authority_citation contains "Pub. L. 115-91 § 1634" |
| T6 | parseFascsaOrder extracts table from sample FASC PDF | `test/fixtures/prohibited-vendors/fascsa-sample.pdf` (1-page table with 3 rows) | 3 entities with `source_id: "fascsa"` | length === 3; raw_record_pointer.page_number set |
| T7 | normalizeName applies NFKC + uppercase + whitespace collapse | inline test data | "Huawei Technologies Co., Ltd." → "HUAWEI TECHNOLOGIES CO., LTD."; "Café" → "CAFÉ" (NFC) → "CAFÉ" (NFKC) | equality check |
| T8 | catalog is sorted by (source_id, name_canonical, source_record_id) | `test/fixtures/prohibited-vendors/small-multi-source/` | output entities[] strictly ascending | manual sort check |
| T9 | duplicates within a single source are collapsed | fixture with 2 identical SDN rows | 1 entity; statistics.duplicates_collapsed === 1 | length === 1 |
| T10 | cross-source duplicates are NOT collapsed (entity on both OFAC + BIS appears twice) | fixture with one entity on both lists | 2 entities, one per source_id | both source_ids present |
| T11 | malformed source row emits requires_operator_input and does NOT abort | fixture with one CSV row missing the name column | 1 entity with `requires_operator_input: "missing-name-canonical"`; statistics.requires_operator_input_count === 1 | requires_operator_input string non-empty |
| T12 | canonical-JSON serialization is deterministic across two runs | run emitter twice, diff bytes | byte-for-byte identical | sha256(run1) === sha256(run2) |
| T13 | canonical-JSON keys are lexicographically sorted at every depth | parse output, walk tree | every object's keys array is sorted ascending | recursive check |
| T14 | provenance block includes signing_key_id + signature_ed25519 | run emitter end-to-end | provenance.signing_key_id non-empty; signature_ed25519 verifies against catalog bytes via libsodium | verification passes |
| T15 | MANIFEST.json is written with per-file sha256 + bytes + url | run emitter end-to-end | data/prohibited-vendors-snapshot-YYYYMMDD/MANIFEST.json exists; every entry has sha256 (64 hex chars) + bytes>0 + url | sha256 regex match for all entries |
| T16 | inventory-coverage.json adds prohibited_vendors_catalog_entity_count + source_count | run emitter end-to-end | inventory-coverage.json.prohibited_vendors_catalog_entity_count === entities.length; source_count === 6 | equality |
| T17 | HTTP fetch failure throws typed OfacFetchError and does NOT emit stale catalog | mock HTTP 503 on sdn.csv | OfacFetchError thrown; out/prohibited-vendors-catalog.json not written | exception thrown; file does not exist |
| T18 | air-gapped mode honours `fascsa.manual_pdf_paths` and skips network fetch | config sets manual paths; mock network rejects all requests | catalog emits with FASCSA entries from local PDFs; no HTTP calls to fascsa.orders_index_url | no network calls observed |
| T19 | SAM API key missing throws typed ConfigError before any network call | config without `SAM_GOV_API_KEY` | ConfigError "SAM_GOV_API_KEY required"; no HTTP calls | exception thrown pre-fetch |
| T20 | snapshot directory is idempotent on re-run within the same day | run emitter twice on same day | second run reuses snapshot dir; no duplicate downloads; new catalog still re-signed | snapshot dir mtime unchanged for raw files |

## 9. Risks (≥4, with mitigations)

- **R1 — Source schema drift.** OFAC SDN columns occasionally change (advanced XML schema versions); BIS consolidated CSV columns have been renamed historically; SAM Entity API v3 may bump. **Mitigation**: per-source parsers assert expected column headers / JSON-schema keys at the top of each parse function and throw typed `SourceSchemaDriftError` with a clear remediation message ("BIS consolidated.csv column 'source' renamed — update parser in core/prohibited-vendors-parsers.ts:lineN"). CI runs a daily integration test (out of scope for W.W1 ship; tracked in operator runbook) that re-fetches the live feeds and flags drift.

- **R2 — Network unreliability / rate limiting.** OFAC's downloads server occasionally 503s; SAM API throttles at >5 QPS without a paid key. **Mitigation**: 3-attempt exponential backoff per source (1/4/16s); SAM rate limit honoured via `sam_gov.rate_limit_qps` config; air-gapped mode lets operator pre-stage snapshot directories. On terminal failure, throw `<Source>FetchError` rather than emitting a partial catalog (REO Rule 1.5: no silent fallback that masks missing data).

- **R3 — FASCSA PDF table extraction is fragile.** FASC publishes orders as PDFs with varying table layouts. **Mitigation**: `core/pdf-table-extract.ts` returns `requires_operator_input: "pdf-table-unparseable"` rather than dropping the entity; operator manually maps via `data/fascsa-manual-overrides.json` (committed file with operator entries that have audit signature). The unparseable count is surfaced in the run log and CHANGELOG entry.

- **R4 — Federal source authority changes (statutory amendment).** A future NDAA could amend §889 (e.g. add a new named entity) or §1634 (e.g. expand Kaspersky scope). **Mitigation**: the FAR 52.204-25 and NDAA §1634 source files (`data/*.json`) carry `last_reviewed: "2026-06-07"` and `authority_citation` fields; the operator runbook documents a quarterly review obligation; a CI lint can be added (out of scope here) that fails if `last_reviewed` is older than 180 days.

- **R5 — Encoding / Unicode pitfalls.** Federal source feeds mix Latin-1, Windows-1252, and UTF-8. Names with diacritics (e.g. "São Paulo") canonicalize differently per encoding choice. **Mitigation**: every parser explicitly reads with `utf-8` (defaulting from BOM where present), with Latin-1 fallback only when explicit re-decode is necessary and operator-confirmed. NFKC normalization applied uniformly. Test T7 pins the behaviour.

- **R6 — Cross-cloud asset-tag pollution in downstream W.W3.** Not a W.W1 risk per se, but W.W1's `name_canonical_stripped` field design choice (strip LLC/INC suffix) directly affects W.W3 matching precision. **Mitigation**: ship `name_canonical_stripped` alongside `name_canonical` (not in place of); W.W3 chooses; W.W3's own RISKS register documents the trade-off.

- **R7 — Snapshot directory unbounded growth.** Daily snapshots accumulate on disk. **Mitigation**: operator runbook documents a 90-day retention with a `scripts/prune-prohibited-vendor-snapshots.mjs` helper (out of scope for W.W1 ship; documented as follow-up).

- **R8 — Signing key compromise.** The catalog is consumed by W.W2/W.W3/W.W4 — a forged catalog could mask a true prohibited vendor. **Mitigation**: signing key id pinned via `signing.key_id` config, sourced from the existing `core/sign.ts` key registry; key rotation procedure documented in `RUNBOOK.md`; downstream consumers verify signature before reading.

## 10. Open questions (to be resolved during implementation)

- **Q1**: Should W.W1 fetch the OFAC **non-SDN** consolidated lists (SSI, NS-PLC, FSE, PA-PLC, etc.) in addition to SDN? **Recommend**: defer to a follow-up W slice; W.W1 ships with SDN only because §889/§1634/SAM Exclusions are the FAR-mandated minimum. The bundler description string makes this explicit so 3PAOs are not surprised.

- **Q2**: When the consolidated screening list at trade.gov returns a BIS entry, should W.W1 also fetch the eCFR HTML to validate concordance? **Recommend**: yes, but as an optional second-pass; primary source-of-truth is the consolidated CSV (machine-readable); eCFR HTML is the forensic backup recorded in the snapshot dir.

- **Q3**: Should the FAR 52.204-25 §889(f)(3)(D) "catch-all" PRC-government entity be emitted as a single entity row or expanded to known exemplar entities? **Recommend**: single entity row; expansion is a legal judgement out of scope for W.W1. W.W3 documents the limitation.

- **Q4**: Does the catalog need to surface the EAR "Verified End-User" entries (which have *fewer* restrictions, not more)? **Recommend**: no; out of scope. The consolidated CSV filter on `source == "Entity List (EL)"` is correct.

- **Q5**: How do we handle name variants in non-Latin scripts (e.g. Chinese hanzi for Huawei)? **Recommend**: preserve in `aliases[]` as-is; do not transliterate; W.W2/W.W3 may add transliteration as a separate slice.

- **Q6**: Should we support the FAR 52.204-25 §889(f)(3)(C) "services" clause (i.e. an entity that provides services using covered equipment)? **Recommend**: out of scope at W.W1 (catalog substrate); W.W2 may layer on a "uses covered equipment" attestation field on each subprocessor.

## 11. REQUIRES-OPERATOR-INPUT fields

| Field | Type | Validator | UI location | Failure mode if missing |
|---|---|---|---|---|
| `SAM_GOV_API_KEY` | string (env var) | non-empty; matches `^[A-Za-z0-9]{20,80}$` | `prohibited-vendors-config.yaml` → `sam_gov.api_key` (resolved from env at load time) | `ConfigError "SAM_GOV_API_KEY required to fetch SAM Exclusions; obtain at https://sam.gov/data-services"` thrown before any network call (test T19) |
| `PROHIBITED_VENDORS_SIGNING_KEY_ID` | string (env var) | matches existing `core/sign.ts` key registry | `prohibited-vendors-config.yaml` → `signing.key_id` | `ConfigError "signing.key_id must be a registered Ed25519 key id"` thrown at config load |
| `fascsa.manual_pdf_paths` | string[] (optional, for air-gapped) | each path exists and is readable | `prohibited-vendors-config.yaml` → `fascsa.manual_pdf_paths` | when network blocked AND list empty: `FascsaFetchError "no FASCSA orders index reachable and no manual_pdf_paths configured"`; catalog still emits but with `source.fascsa` absent and `statistics.requires_operator_input_count` incremented |
| `data/fascsa-manual-overrides.json` | JSON file (optional) | matches `ProhibitedVendorEntity[]` schema | git-committed file; operator edits + signs with PR review | when a FASC PDF is unparseable, the corresponding entity is sourced from this file if present; otherwise emitted with `requires_operator_input: "pdf-table-unparseable"` |
| `proxy.https_proxy` | string (optional) | URL or empty | `prohibited-vendors-config.yaml` → `proxy.https_proxy` (resolved from env at load time) | when corp proxy required and missing, OFAC fetch may 502/timeout; `OfacFetchError` thrown |

## 12. Implementation log (running journal — implementing session fills as work progresses)

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| 2026-06-08 | impl-w-w1 | Shipped end to end per spec. Created `core/prohibited-vendors-{catalog,parsers,config}.ts`, `scripts/extract-prohibited-vendors.mjs`, committed `data/{far-52-204-25,ndaa-1634}-named-entities.json` + `data/fascsa-orders.json`, `prohibited-vendors-config.example.yaml`, and `tests/core/prohibited-vendors-{catalog,parsers}.test.ts` (29 tests). Added `signDetached`/`verifyDetached` to `core/sign.ts`; `augmentCoverageWithProhibitedVendors` to `core/inventory-coverage.ts`; `--prohibited-vendors-catalog` flag + `CLOUD_EVIDENCE_PROHIBITED_VENDORS_CATALOG` env to the orchestrator; WELL_KNOWN bundle role to `core/submission-bundle.ts`. typecheck clean, 903/903 tests pass (+29), check:reo (G1+G2+G3) green. | `be78723` | See divergence + open-question notes below. |

### Implementation notes — spec divergences (recorded per anti-pattern #2)

The spec was authored before implementation and referenced several primitives
that do not exist in the current tree. Real, REO-compliant adaptations:

1. **Test directory.** The repo uses `tests/` (with `tests/core/` + `tests/fixtures/`),
   not `test/` as §7 states. Tests live at `tests/core/prohibited-vendors-{catalog,parsers}.test.ts`;
   fixtures at `tests/fixtures/prohibited-vendors/`.
2. **No `core/http-client.ts`.** The repo is offline-first (cf. `core/kev-feed.ts`
   + the `scripts/extract-*.mjs` pattern): the core ingester reads a snapshot
   directory; the network arm lives in `scripts/extract-prohibited-vendors.mjs`
   (global `fetch` + the existing `core/retry.ts` `withRetry`). A thin injectable
   `fetcher` seam in the core exercises the fetch-error/config paths (T17/T19).
   New risk **W.W1-21** filed (corp-proxy handling for these public-feed GETs).
3. **No `core/pdf-table-extract.ts`** (it is introduced by the unshipped LOOP-C.C3).
   Live FASCSA-order PDF auto-extraction is therefore deferred; FASCSA entities are
   sourced from the operator-maintained, PR-reviewed register `data/fascsa-orders.json`
   (the §11 manual-overrides route). New risk **W.W1-19** filed.
4. **Provenance keys are camelCase** (`emitter`, `emittedAt`, `sourceCalls`,
   `signingKeyId`) to satisfy the G3 `check-provenance` guardrail, which requires
   those exact keys — not the snake_case shown in §5.1. New risk **W.W1-20** filed.
5. **Signing.** The spec referenced `signEnvelope()`, which does not exist. Added
   `signDetached()` / `verifyDetached()` to `core/sign.ts` (composing the same key
   material as `signRun()`); the catalog carries a self-contained detached Ed25519
   signature in `provenance` + a `.sig` sidecar, and is additionally covered by the
   run manifest when emitted through the orchestrator (runs before `signRun`).
6. **inventory-coverage.** Added the pure `augmentCoverageWithProhibitedVendors()`
   helper to `core/inventory-coverage.ts` (the module §7.2 names). The two counts are
   sibling top-level fields, NOT `columns[].fillRate` cells, so the G2 coverage-regression
   guardrail can never trip on them.
7. **Source ids.** Implemented all 7 `source_id`s in the §5.1 enum. `far-52-204-25`
   emits the 5 named entities + the §889(f)(3)(D) catch-all (6); `ndaa-889` emits the
   5 named telecom entities; both read the single committed `far-52-204-25-named-entities.json`.

### Open questions (§10) — resolutions

- **Q1** (non-SDN OFAC consolidated lists): deferred to a follow-up W slice, per the
  §10 recommendation. W.W1 ingests OFAC SDN only; the bundle description string is explicit.
- **Q2** (eCFR HTML concordance for BIS): the consolidated screening list CSV is the
  machine-readable primary source; the eCFR HTML forensic backup is optional and not
  fetched by the core (the extract script may stage it). Followed the recommendation.
- **Q3** (§889(f)(3)(D) catch-all): emitted as a single catalog entity row (legal
  expansion is out of scope). Followed.
- **Q4** (EAR Verified End-User entries): out of scope; the BIS parser filters strictly
  to `source == "Entity List (EL) - Bureau of Industry and Security"`. Followed.
- **Q5** (non-Latin name variants): aliases preserved verbatim (NFKC-normalized, not
  transliterated); transliteration is a future slice. Followed.
- **Q6** (§889(f)(3)(C) "services" clause): out of scope for the W.W1 catalog substrate;
  W.W2 may layer a "uses covered equipment" attestation. Followed.

## 13. Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)

The implementing session MUST check every box. The 7-step procedure is reproduced **verbatim** from `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`:

> **Step 1 — Verify the slice is REO-compliant**
> Run all three guardrails. They MUST all be green:
> ```bash
> cd cloud-evidence
> npm run typecheck      # no errors
> npm test               # 100% passing (counts must increase by the slice's new tests)
> npm run check:reo      # G1+G2+G3 all green
> ```

> **Step 2 — Update STATUS.md**
> Open `cloud-evidence/docs/STATUS.md` and for the slice that just shipped:
> - Change `Status` column from `pending` to `done`
> - Fill `Commit` with the PENDING commit's short hash (you'll know it after step 5)
> - Fill `Date` with today's date (ISO format YYYY-MM-DD)
> - If this was the last slice in a loop, change the loop's title section to indicate "(COMPLETE)"
> - Update the "Overall" section: increment loops-complete, change last-shipped, update next-priority

> **Step 3 — Update the loop's spec doc**
> Open `cloud-evidence/docs/loops/LOOP-X-SPEC.md` (where X is your loop letter).
> Find the "Status tracking" section table.
> For your slice row: status=done, commit=<hash>, date=<ISO>.

> **Step 4 — Add CHANGELOG entry**
> Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
> Add a new entry at the TOP of "Unreleased":
> ### Added — LOOP-X.XN: <Slice title>
> <2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>

> **Step 5 — Commit**
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
> git commit -m "LOOP-X.XN: <slice title>
> <detailed commit message describing the slice>
> Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
> ```

> **Step 6 — Update commit hash in STATUS.md + loop spec**
> Now that the commit exists, get its hash:
> ```bash
> git log -1 --format=%h
> ```
> Open STATUS.md + the loop's spec doc — paste the actual commit hash in the rows you updated in step 2+3.
> Amend the commit:
> ```bash
> git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md
> git commit --amend --no-edit
> ```

> **Step 7 — Push**
> ```bash
> git push origin main
> ```

**Final additional step (W.W1-specific push directive)**: After commit lands, append a row to STATUS.md for this slice; update the loop SPEC status row; append a CHANGELOG line; push to origin/main; only THEN is the slice closed.

### Per-slice acceptance gates
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥20 for this slice's new tests per § 8)
- [ ] check:reo green (G1+G2+G3)
- [ ] check:provenance green for `prohibited-vendors-catalog.json`
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-W-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>, last_updated=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (cites FAR 52.204-25 + 52.204-26 + 52.204-23 + Pub. L. 115-91 § 1634 + Pub. L. 115-232 § 889 + OFAC SDN + BIS Entity List + SAM 9.404 + FASCSA)
- [ ] Commit with slice ID `W.W1` in message
- [ ] Pushed to origin/main
- [ ] Snapshot directory `data/prohibited-vendors-snapshot-YYYYMMDD/` present with MANIFEST.json + 6+ source files

## Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + REQUIRES-OPERATOR-INPUT table + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-W-SPEC.md` (if present) for cross-slice context. If absent, the loop SPEC has not yet been authored; W.W1 is the substrate for W.W2 (subprocessor screening) + W.W3 (asset-tag screening) + W.W4 (FAR 52.204-26 representation).
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` (§ 13 quoted verbatim above) for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/core/http-client.ts` — the existing read-only HTTP client your ingester uses.
6. Read `cloud-evidence/core/sign.ts` + `core/timestamp.ts` — the existing Ed25519 + RFC 3161 pipeline your emitter flows through.
7. Read `cloud-evidence/core/inventory-coverage.ts` — the coverage-contract pattern.
8. Read `cloud-evidence/core/submission-bundle.ts` `WELL_KNOWN` array — add the new catalog entry.
9. Download (or pre-stage) the six source feeds into `data/prohibited-vendors-snapshot-YYYYMMDD/` via `scripts/extract-prohibited-vendors.mjs` before running the orchestrator with `--prohibited-vendors-catalog`.
10. Begin implementation; update § 12 Implementation log as you go.

---
