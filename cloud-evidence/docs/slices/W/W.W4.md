---
slice_id: W.W4
title: Section 889 Part B Annual Representation (FAR 52.204-26) — DOCX + Signed JSON Envelope
loop: W
status: done
commit: TBD
completed_date: 2026-06-18
applicable_conditional: true
condition: Universal for any CSP responding to Federal solicitations or whose SAM.gov registration is active. FAR 52.204-26 is included in every solicitation issued on or after 2020-10-26, and SAM annual update obliges every registered offeror.
trigger_flag: "--section889-annual-rep"
trigger_env: CLOUD_EVIDENCE_SECTION889_ANNUAL_REP
depends_on:
  - W.W2                    # screen results feed the representation
  - LOOP-A.A5               # signing (Ed25519 + RFC 3161)
  - corporate signing keys  # operator-provisioned officer signing key
blocks:
  - LOOP-Q.Q1               # Marketplace "Section 889 Compliant" badge surfaces W.W4 envelope URL
estimated_effort: medium (~4 working days)
last_updated: 2026-06-18
---

# W.W4 — Section 889 Part B Annual Representation (FAR 52.204-26)

## 1. Mission

Generate the FAR 52.204-26 "Covered Telecommunications Equipment or Services
— Representation" artifact pair (a printed `.docx` for SAM.gov / officer
signature, plus a signed canonical-JSON envelope for the audit trail and
Marketplace metadata feed), deterministically populated from the W.W2
screen results so the operator never hand-fills the two checkboxes,
the officer signs once per year, and the resulting representation is
machine-verifiable by a 3PAO and by the FedRAMP Marketplace ingestion
pipeline.

W.W4 is the **annual** counterpart to W.W3's **incident-driven**
1-business-day reporter:

- W.W3 fires on every confirmed covered-equipment discovery during
  contract performance (FAR 52.204-25(d)).
- W.W4 fires once per SAM.gov registration cycle (and at every option-
  year exercise, every solicitation response, and any time the operator
  wants a fresh representation envelope) and produces the
  affirmative/negative representation defined in FAR 52.204-26(c).

The slice is **REO-compliant** by construction: every value emitted on
the `.docx` and in the JSON envelope is computed from either (a) the
W.W2 screen result (`out/prohibited-vendors-matches.json`), (b)
`config.yaml` / `org-profile.yaml`, or (c) operator-supplied signing
metadata (officer name, title, signing key id). Nothing is invented,
sampled, or stubbed. If a required field is missing, the orchestrator
emits a `requires_operator_input` diagnostic naming the field and the
consumer artifact.

## 2. Authoritative sources

Every URL accessed 2026-06-07. Where the Government source returned a
non-200 to anonymous fetches, the implementer downloaded the
HTML / PDF into `cloud-evidence/docs/sources/` and re-quoted verbatim.

### 2.1 FAR 52.204-26 — Covered Telecommunications Equipment or Services — Representation

Source: https://www.acquisition.gov/far/52.204-26 (accessed 2026-06-07).

Paragraph (a) — Definitions:

> "'Covered telecommunications equipment or services' and 'reasonable
> inquiry' have the meaning provided in the clause 52.204-25, Prohibition
> on Contracting for Certain Telecommunications and Video Surveillance
> Services or Equipment."

Paragraph (b) — Procedures:

> "The Offeror shall review the list of excluded parties in the System
> for Award Management (SAM) (https://www.sam.gov) for entities excluded
> from receiving federal awards for 'covered telecommunications equipment
> or services'."

Paragraph (c) — Representations:

> "(1) The Offeror represents that it [ ] does, [ ] does not provide
> covered telecommunications equipment or services as a part of its
> offered products or services to the Government in the performance of
> any contract, subcontract, or other contractual instrument."
>
> "(2) After conducting a reasonable inquiry for purposes of this
> representation, the offeror represents that it [ ] does, [ ] does not
> use covered telecommunications equipment or services, or any equipment,
> system, or service that uses covered telecommunications equipment or
> services."

### 2.2 FAR 52.204-25 — Definitional anchor for "covered telecommunications equipment or services"

Source: https://www.acquisition.gov/far/52.204-25 (accessed 2026-06-07).

Paragraph (a) — Definitions:

> "Covered telecommunications equipment or services means—
> (1) Telecommunications equipment produced by Huawei Technologies
> Company or ZTE Corporation (or any subsidiary or affiliate of such
> entities);
> (2) For the purpose of public safety, security of Government
> facilities, physical security surveillance of critical infrastructure,
> and other national security purposes, video surveillance and
> telecommunications equipment produced by Hytera Communications
> Corporation, Hangzhou Hikvision Digital Technology Company, or Dahua
> Technology Company (or any subsidiary or affiliate of such entities);
> (3) Telecommunications or video surveillance services provided by such
> entities or using such equipment; or
> (4) Telecommunications or video surveillance equipment or services
> produced or provided by an entity that the Secretary of Defense, in
> consultation with the Director of the National Intelligence or the
> Director of the Federal Bureau of Investigation, reasonably believes
> to be an entity owned or controlled by, or otherwise connected to, the
> government of a covered foreign country."

> "Covered foreign country means The People's Republic of China."

### 2.3 NDAA FY2019 §889(a)(1)(A) and (a)(1)(B) — Public Law 115-232

Source: https://www.congress.gov/115/plaws/publ232/PLAW-115publ232.pdf
(accessed 2026-06-07; operator mirrors to `docs/sources/PLAW-115publ232.pdf`).

Statutory authority for the FAR 4.21 subpart:

> "§889. Prohibition on certain telecommunications and video
> surveillance services or equipment.
> (a) Prohibition on use or procurement.
> (1) The head of an executive agency may not—
> (A) procure or obtain or extend or renew a contract to procure or
> obtain any equipment, system, or service that uses covered
> telecommunications equipment or services as a substantial or essential
> component of any system, or as critical technology as part of any
> system; or
> (B) enter into a contract (or extend or renew a contract) with an
> entity that uses any equipment, system, or service that uses covered
> telecommunications equipment or services as a substantial or essential
> component of any system, or as critical technology as part of any
> system."

### 2.4 NDAA FY2018 §1634 — Kaspersky prohibition (Public Law 115-91)

Source: https://www.congress.gov/bill/115th-congress/house-bill/2810/text
(accessed 2026-06-07).

> "Sec. 1634. Prohibition on use of products and services developed or
> provided by Kaspersky Lab.
> (a) Prohibition. — No department, agency, organization, or other
> element of the Federal Government shall use, whether directly or
> through work with or on behalf of another department, agency,
> organization, or element of the Federal Government, any hardware,
> software, or services developed or provided, in whole or in part, by—
> (1) Kaspersky Lab (or any successor entity);
> (2) any entity that controls, is controlled by, or is under common
> control with Kaspersky Lab; or
> (3) any entity of which Kaspersky Lab has a majority ownership.
> (b) Effective Date. — The prohibition under subsection (a) shall take
> effect on October 1, 2018."

W.W4 surfaces a separate "§1634 representation" attachment when the
operator opts in via `--include-kaspersky-rep`. This is **not** part of
FAR 52.204-26 (the FAR clause is about §889 only) but the operator's
SAM.gov supplementary documentation may bundle it.

### 2.5 DHS BOD 17-01 — Kaspersky removal directive

Source: https://www.cisa.gov/binding-operational-directive-17-01
(accessed 2026-06-07).

> "Removal of Kaspersky-branded Products. After careful consideration of
> available information and consultation with interagency partners, the
> Acting Secretary of Homeland Security has determined that the
> information security risks presented by the use of Kaspersky products
> on federal information systems are significant and compelling. This
> Binding Operational Directive (BOD) directs Federal Executive Branch
> departments and agencies to identify any use or presence of Kaspersky
> products on their information systems, to develop and furnish to DHS a
> detailed plan of action to remove and discontinue present and future
> use of all Kaspersky-branded products, and to begin to implement the
> plan."

Issued 2017-09-13. Identification 30 days, plan 60 days, removal 90 days.

### 2.6 FAR 52.204-8 — Annual Representations and Certifications (the SAM annual cycle)

Source: https://www.acquisition.gov/far/52.204-8 (accessed 2026-06-07).

> "(d) The offeror has completed the annual representations and
> certifications electronically via the SAM website accessed through
> https://www.sam.gov. After reviewing the SAM database information, the
> offeror verifies by submission of the offer that the representations
> and certifications currently posted electronically that apply to this
> solicitation as indicated in paragraph (c) of this provision have been
> entered or updated within the last 12 months, are current, accurate,
> complete, and applicable to this solicitation."

This drives W.W4's 12-month **expiry timer**: the representation
envelope carries `valid_until` = `signed_at + 365 days`. The tracker UI
surfaces a countdown badge that turns amber at 30 days remaining and
red at 0.

### 2.7 OFAC Specially Designated Nationals (SDN) — referenced by SAM Procedures (b)

Source: https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists
(accessed 2026-06-07).

W.W4 does **not** re-walk the SDN list; W.W1 has already loaded the
catalog and W.W2 has already screened against it. W.W4 records, in the
envelope, the snapshot hash of the catalog that was used to inform the
representation, so a 3PAO can verify that the operator screened
against an up-to-date catalog.

### 2.8 BIS Entity List — 15 CFR Part 744, Supplement No. 4

Source: https://www.bis.doc.gov/index.php/policy-guidance/lists-of-parties-of-concern/entity-list
(accessed 2026-06-07).

Same posture as 2.7 — W.W4 carries the catalog snapshot hash.

### 2.9 SAM Exclusions feed (the SAM list of excluded parties)

Source: https://sam.gov/data-services/Exclusions (accessed 2026-06-07).
API: https://api.sam.gov/entity-information/v3/exclusions

Per FAR 52.204-26(b) the offeror "shall review the list of excluded
parties in the System for Award Management (SAM)" before representing.
W.W4 records this review by embedding the W.W1 catalog snapshot id
(which includes the SAM Exclusions feed download timestamp + hash) into
the representation envelope. The `.docx` carries a footer line: "This
representation was informed by a review of the SAM Excluded Parties
List as of `<YYYY-MM-DD HH:MM UTC>`, snapshot SHA-256 `<hash>`."

### 2.10 DHS Section 889 reporting endpoint reference (for context only)

Source: https://www.acquisition.gov/Section-889-Policies (accessed
2026-06-07). W.W4 references but does not invoke; W.W3 covers the
incident-reporting path.

### 2.11 NIST SP 800-53 Rev 5 — SR family (cross-reference)

Source: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-07). W.W4's envelope lists the 800-53 controls under
which this representation provides evidence:

> "SR-1 Policy and Procedures; SR-3 Supply Chain Controls and Processes;
> SR-5 Acquisition Strategies, Tools, and Methods; SR-6 Supplier
> Assessments and Reviews; SR-11 Component Authenticity."

(These five SR-family controls are the canonical cross-reference for
§889 in NIST C-SCRM-aligned authorization packages.)

### 2.12 OOXML / ECMA-376 specification

Source: https://ecma-international.org/publications-and-standards/standards/ecma-376/
(accessed 2026-06-07). W.W4's `.docx` is a minimal-conformant OOXML
package — `[Content_Types].xml`, `_rels/.rels`, `word/document.xml`,
`word/_rels/document.xml.rels`, `word/styles.xml`, `word/numbering.xml`,
`docProps/core.xml`, `docProps/app.xml` — packaged as a `zip-store` so
the OOXML payload byte-stream is reproducible across runs (the
hash of the resulting `.docx` is stable given identical inputs).

## 3. Scope

### In scope

- Build a typed `Section889AnnualRepresentation` object from W.W2's
  `out/prohibited-vendors-matches.json` plus operator config.
- Emit `out/section889-annual-rep.docx` (OOXML, zip-store) — the
  printable, officer-signable representation matching FAR 52.204-26(c).
- Emit `out/section889-annual-rep.json` (canonical-JSON, sorted keys,
  no trailing whitespace) — the machine-readable envelope.
- Sign the JSON envelope with Ed25519 via `core/sign.ts`; timestamp via
  RFC 3161 via `core/timestamp.ts`.
- Persist the representation in tracker DB table
  `section889_annual_reps` with operator officer-signature audit trail.
- Register `section889-annual-rep.docx` and `section889-annual-rep.json`
  in `core/submission-bundle.ts:WELL_KNOWN` so they ride in the
  submission bundle.
- Surface a SAM.gov submission helper UI panel: paste-in field for the
  SAM.gov submission receipt id; tracker logs the operator's submission
  action.
- Compute and surface the 365-day expiry (per FAR 52.204-8(d)) in both
  the envelope (`valid_until`) and the tracker UI.

### Out of scope

- **Direct SAM.gov submission** — REO Rule 4 forbids autonomous
  regulatory submission. The operator pastes the SAM receipt back into
  the tracker.
- **Solicitation-level reps and certs** — FAR 52.212-3 ("Offeror
  Representations and Certifications—Commercial Products and Commercial
  Services") embeds 52.204-26 as a sub-rep; that mega-form is a
  procurement-bid artifact, not a FedRAMP authorization artifact, and
  is out of scope for cloud-evidence. The 889-only `.docx` W.W4 emits
  is the operator's master reference; they paste the two checkbox
  answers into 52.212-3 manually when bidding.
- **FAR 52.204-24** — the **solicitation provision** representation;
  similar text but tied to a specific solicitation, not the SAM annual
  cycle. Out of scope (operator submits manually if a CO requests it).
- **DFARS 252.204-7012 reporting** — covered by LOOP-S.
- **CISA CIRCIA reporting** — covered by `CIRCIA-WORKFLOW.md`
  extensions to G.G2 + M.M4.
- **Waiver tracking under FAR 4.2104** — out of scope per LOOP-W §1.3.
- **Subcontractor flow-down representations** — out of scope; the
  representation here is the prime / CSP's own representation.
  Subcontractor flow-down is a separate FAR 52.204-25(e) obligation
  the operator manages contractually.

## 4. Inputs

### 4.1 W.W2 screen results (mandatory)

Path: `out/prohibited-vendors-matches.json` (emitted by W.W2). Schema:

```ts
export interface ProhibitedVendorMatches {
  schema_version: '1.0.0';
  run_id: string;                          // ULID
  matched_at: string;                       // ISO 8601
  catalog_snapshot: {
    snapshot_id: string;                    // e.g. "20260607-001"
    sha256: string;                          // hex
    sources: Array<'far-52.204-25' | 'ndaa-1634' | 'bod-17-01' |
                   'ofac-sdn' | 'bis-entity-list' | 'sam-exclusions' |
                   'operator-override'>;
    last_refresh: string;                    // ISO 8601
  };
  matches: Array<{
    match_uuid: string;                      // RFC 4122 v7 (time-ordered)
    catalog_entry_id: string;                // foreign key into catalog
    canonical_entity_name: string;           // e.g. "Huawei Technologies Co., Ltd."
    matched_via: 'subprocessors-sheet' | 'sbom' | 'oci-publisher' |
                 'inventory-provider-tag' | 'inventory-sku' |
                 'operator-attestation';
    confidence: number;                       // 0..1
    subsidiary_chain: string[];               // e.g. ["HiSilicon","Huawei"]
    provenance: {
      source_path: string;                    // file path or DNS / OCI ref
      source_record_id: string;               // depth-N path, SBOM pkg purl,
                                              // Rekor uuid, etc.
      evidence_hash: string;                  // SHA-256 hex
    };
    severity: 'critical' | 'high' | 'medium' | 'low';
    suppressed: boolean;                      // operator-suppressed false positive
    suppression_reason?: string;
  }>;
}
```

### 4.2 Operator configuration

From `config.yaml` and `org-profile.yaml`:

```yaml
# config.yaml — Section 889 representation parameters
section889:
  offeror:
    legal_name: "FedPy Cloud Services, Inc."
    unique_entity_id: "JKL5678MNOP9"          # SAM UEI (12 chars)
    cage_code: "9ABC1"                         # optional, 5 chars
    duns: ""                                   # legacy, optional
    physical_address:
      street1: "123 Main Street"
      street2: ""
      city: "Reston"
      state: "VA"
      zip: "20190"
      country: "US"
  authorized_officer:
    full_name: "Jane Q. Operator"
    title: "Chief Information Security Officer"
    email: "ciso@example.com"
    signing_key_id: "operator-officer-2026Q3"  # references core/sign.ts keyring
  reasonable_inquiry:
    methodology_summary_path: "docs/section889/reasonable-inquiry-methodology.md"
    methodology_sha256: ""                     # auto-computed by W.W4 at runtime
  include_kaspersky_attachment: true           # NDAA §1634 supplementary rep
  valid_until_days: 365                         # default per FAR 52.204-8(d)
  sam_review:
    sam_excluded_parties_review_date: ""        # auto-set from W.W1 snapshot
    sam_excluded_parties_review_snapshot: ""    # auto-set from W.W1 snapshot
```

### 4.3 Tracker DB — prior representations (optional)

If a prior representation exists in `section889_annual_reps`, W.W4
loads it for delta-reporting (`previous_envelope_id`,
`previous_signed_at`, `previous_valid_until`). Used to:

- Surface the delta in the tracker UI ("Previous rep was 'does not' on
  2025-08-15; new rep is 'does not' on 2026-08-15").
- Detect representation-status flips (e.g. from "does not" to "does")
  and emit a `representation-flip` audit-log event.

### 4.4 Signing key material

From `core/sign.ts` keyring; the operator-officer key referenced by
`config.yaml#section889.authorized_officer.signing_key_id`. The key
must be present and unexpired or the orchestrator aborts with
`requires_operator_input: signing-key-missing-or-expired`.

## 5. Outputs

### 5.1 Canonical-JSON envelope — `out/section889-annual-rep.json`

```ts
export interface Section889AnnualRepEnvelope {
  schema_version: '1.0.0';
  envelope_uuid: string;                       // RFC 4122 v7
  emitter: 'section889-annual-rep';
  csp_name: string;
  offeror: {
    legal_name: string;
    unique_entity_id: string;                  // SAM UEI
    cage_code?: string;
    duns?: string;
    physical_address: Address;
  };
  representation: {
    // Maps to FAR 52.204-26(c)(1)
    provides_covered_equipment_or_services: 'does' | 'does not';
    // Maps to FAR 52.204-26(c)(2)
    uses_covered_equipment_or_services: 'does' | 'does not';
    // Embedded for cross-reference + 3PAO audit
    rationale: {
      screen_run_id: string;                    // W.W2 run id
      catalog_snapshot_id: string;              // W.W1 snapshot id
      catalog_snapshot_sha256: string;
      total_matches: number;
      unsuppressed_matches: number;             // drives the does/does-not
      provides_basis: string;                   // narrative: which matches drive (c)(1)
      uses_basis: string;                       // narrative: which matches drive (c)(2)
    };
    linked_incidents: Array<{
      incident_id: string;                       // foreign key to section889_incidents
      reported_at: string;                       // ISO 8601
      contract_number?: string;
      status: 'reported' | 'mitigated' | 'open';
    }>;
  };
  reasonable_inquiry: {
    methodology_path: string;                    // points at MD doc
    methodology_sha256: string;
    inquiry_completed_at: string;                // ISO 8601
    inquiry_scope: {
      subprocessor_count: number;
      sbom_package_count: number;
      oci_image_count: number;
      inventory_asset_count: number;
    };
  };
  sam_review: {
    excluded_parties_review_date: string;        // ISO 8601
    excluded_parties_snapshot_id: string;
    excluded_parties_snapshot_sha256: string;
  };
  kaspersky_supplement?: {                       // present iff opted in
    statute: 'NDAA-FY2018-§1634';
    bod_reference: 'DHS-BOD-17-01';
    representation_text: string;                 // verbatim emitted narrative
  };
  authorized_officer: {
    full_name: string;
    title: string;
    email: string;
    signing_key_id: string;
  };
  signed_at: string;                             // ISO 8601 UTC
  valid_until: string;                           // signed_at + 365 days
  previous_envelope_id?: string;                  // delta link
  controls_evidenced: string[];                   // e.g. ["SR-1","SR-3","SR-5","SR-6","SR-11"]
  provenance: {
    emitter: 'section889-annual-rep';
    emittedAt: string;
    sourceCalls: Array<{
      kind: 'prohibited-vendors-matches' | 'config' | 'tracker-prior-rep' |
            'sign-key' | 'methodology-doc';
      path: string;
    }>;
    signingKeyId: string;
  };
  signature: {                                    // Ed25519 detached signature
    alg: 'ed25519';
    keyId: string;
    value: string;                                // base64
  };
  timestamp: {                                    // RFC 3161
    tsa_url: string;
    response_b64: string;
    timestamped_at: string;
  };
}
```

### 5.2 Printed `.docx` — `out/section889-annual-rep.docx`

Layout (single-column letter, 1" margins):

1. **Header** — CSP legal name + UEI + CAGE + physical address.
2. **Title** — "Representation Pursuant to FAR 52.204-26 — Covered
   Telecommunications Equipment or Services".
3. **Recital** — verbatim FAR 52.204-26(a) Definitions block + verbatim
   (b) Procedures block, italicised.
4. **Representation (c)(1)** — the (1) verbatim sentence, with the
   "does" or "does not" rendered as a marked checkbox (■ vs □) per
   W.W2's screen result, the other left unmarked. Below: rationale
   narrative (1-3 paragraphs) generated from W.W2 results.
5. **Representation (c)(2)** — same shape for the "use" representation.
6. **Reasonable-Inquiry Methodology** — verbatim FAR 52.204-25(a)
   "Reasonable inquiry" definition, then a 1-paragraph methodology
   summary loaded from `docs/section889/reasonable-inquiry-methodology.md`
   (operator-authored).
7. **SAM Review Footer** — "This representation was informed by a
   review of the SAM Excluded Parties List as of `<datetime UTC>`,
   snapshot SHA-256 `<hash>`."
8. **Linked Incidents Annex** (only if `unsuppressed_matches > 0`) — a
   table of W.W3 incident IDs + reported-at + status.
9. **Kaspersky Supplement Annex** (only if opted in) — NDAA §1634
   + BOD 17-01 representation.
10. **Signature Block** — officer full name, title, signing-key id,
    `signed_at` timestamp, `valid_until` timestamp, signature value
    (the Ed25519 hex), RFC 3161 timestamp token URL.

Generated with the same OOXML helper pattern as `core/inventory-workbook.ts`
(zip-store; reproducible bytes; no external dependency).

### 5.3 Tracker DB row — `section889_annual_reps`

```sql
CREATE TABLE section889_annual_reps (
  rep_id INTEGER PRIMARY KEY AUTOINCREMENT,
  envelope_uuid TEXT NOT NULL UNIQUE,
  emitted_at_utc TEXT NOT NULL,                 -- ISO 8601
  valid_until_utc TEXT NOT NULL,                 -- ISO 8601
  provides_status TEXT NOT NULL CHECK (provides_status IN ('does','does not')),
  uses_status TEXT NOT NULL CHECK (uses_status IN ('does','does not')),
  catalog_snapshot_id TEXT NOT NULL,
  catalog_snapshot_sha256 TEXT NOT NULL,
  screen_run_id TEXT NOT NULL,
  unsuppressed_match_count INTEGER NOT NULL,
  signed_envelope_path TEXT NOT NULL,             -- path to out/.json
  rendered_docx_path TEXT NOT NULL,                -- path to out/.docx
  officer_full_name TEXT NOT NULL,
  officer_title TEXT NOT NULL,
  officer_signing_key_id TEXT NOT NULL,
  previous_envelope_id INTEGER,                    -- FK to prior row
  sam_submission_receipt_id TEXT,                  -- operator-pasted post-submission
  sam_submitted_at_utc TEXT,                       -- operator-set post-submission
  sam_submitted_by_user_id INTEGER,                -- operator's tracker user id
  signature_alg TEXT NOT NULL DEFAULT 'ed25519',
  signature_b64 TEXT NOT NULL,
  rfc3161_timestamp_b64 TEXT NOT NULL,
  audit_log_entry_id INTEGER NOT NULL,             -- FK to tracker audit-log
  FOREIGN KEY (previous_envelope_id) REFERENCES section889_annual_reps(rep_id)
);
CREATE INDEX idx_section889_annual_reps_valid_until ON section889_annual_reps(valid_until_utc);
CREATE INDEX idx_section889_annual_reps_envelope_uuid ON section889_annual_reps(envelope_uuid);
```

### 5.4 Bundler registration

In `core/submission-bundle.ts:WELL_KNOWN`:

```ts
{ role: 'section889-annual-rep-json',
  filename: 'section889-annual-rep.json',
  description: 'FAR 52.204-26 annual representation, signed JSON envelope (LOOP-W.W4)' },
{ role: 'section889-annual-rep-docx',
  filename: 'section889-annual-rep.docx',
  description: 'FAR 52.204-26 annual representation, printable OOXML (LOOP-W.W4)' },
```

## 6. Algorithm / Steps

1. **Precondition gate**. Verify W.W2 has been run for this orchestrator
   invocation: read `out/prohibited-vendors-matches.json` or throw
   `requires_operator_input: w2-screen-not-run`. Verify the catalog
   snapshot referenced is not older than 24h or surface
   `coverage:stale-catalog` (strict mode → exit 2; lenient → warn).

2. **Load inputs**. Read W.W2 matches; read `config.yaml` section889
   block; read tracker DB for prior representation row (most recent).
   Read methodology document and compute its SHA-256.

3. **Validate operator inputs**. For each required field in
   §11 (REQUIRES-OPERATOR-INPUT), check presence + format. On any
   missing field, throw with the field name + UI location for fix-up.

4. **Compute representation answers**.
   - `unsuppressed_matches = matches.filter(m => !m.suppressed)`.
   - `unsuppressed_provides = unsuppressed_matches.filter(m =>
     m.matched_via === 'subprocessors-sheet' || m.matched_via ===
     'inventory-provider-tag' || m.matched_via ===
     'inventory-sku')`. These represent equipment/services the offeror
     **provides to the Government in performance of any contract**
     (paragraph (c)(1)).
   - `unsuppressed_uses = unsuppressed_matches` (everything the offeror
     touches, including its own internal SBOM and OCI dependencies —
     because FAR 4.2102 prohibits "use" regardless of whether in
     contract performance). Paragraph (c)(2) is broader than (c)(1).
   - `provides_status = unsuppressed_provides.length === 0 ? 'does not' : 'does'`.
   - `uses_status = unsuppressed_uses.length === 0 ? 'does not' : 'does'`.

5. **Generate rationale narratives**.
   - `provides_basis`: if "does not", emit "Based on a W.W2 screen run
     (ID `<run_id>`) against catalog snapshot `<snapshot_id>` (SHA-256
     `<hash>`), no covered equipment or services from any catalogued
     covered entity were found among offered products or services. The
     screen reviewed the subprocessor sheet (`<N>` entries) and the
     inventory provider-tag and SKU surfaces (`<M>` assets)."
   - If "does", emit a per-match block citing each unsuppressed match's
     catalog entry, source path, and the FAR 4.2102 prohibition
     reference. Each block ends with the W.W3 1BD incident ID once the
     operator has filed.
   - Same shape for `uses_basis`.

6. **Collect linked incidents**. Query tracker DB
   `section889_incidents` for rows with `match_uuid IN
   (unsuppressed_matches.map(m => m.match_uuid))`. Build
   `linked_incidents[]`.

7. **Optional Kaspersky supplement**. If
   `config.section889.include_kaspersky_attachment === true`, emit
   the `kaspersky_supplement` block with verbatim NDAA §1634 + BOD
   17-01 representation text.

8. **Identify controls evidenced**. Hard-code per source 2.11:
   `['SR-1', 'SR-3', 'SR-5', 'SR-6', 'SR-11']`.

9. **Compute `valid_until`**. `signed_at + config.valid_until_days`
   (default 365). Both as ISO 8601 UTC.

10. **Build the canonical-JSON envelope**. Sort keys; no trailing whitespace;
    UTF-8; LF line endings. Compute SHA-256 of the unsigned bytes.

11. **Sign**. Call `core/sign.ts:signBytes(unsignedBytes, signingKeyId)`.
    Attach `signature.value` to the envelope.

12. **RFC 3161 timestamp**. Call
    `core/timestamp.ts:timestampDigest(sha256_of_signed_envelope)`.
    Attach `timestamp.response_b64`.

13. **Render `.docx`**. Build OOXML package; use the W.W3 / inventory-
    workbook helper pattern. Pin `[Content_Types].xml`, `_rels/.rels`,
    `word/document.xml`, `word/_rels/document.xml.rels`,
    `word/styles.xml`, `word/numbering.xml`, `docProps/core.xml`,
    `docProps/app.xml`. Zip-store (no compression) for reproducible
    bytes. Verify byte-stability via a re-render fixture test.

14. **Persist tracker DB row**. Insert into `section889_annual_reps`
    with audit-log entry (operator action: `section889_rep_emitted`).
    On insert error, the orchestrator aborts before writing artifacts
    to disk (avoid drift).

15. **Write artifacts**. `out/section889-annual-rep.json` and
    `out/section889-annual-rep.docx`. Mode 0644.

16. **Bundler hookup**. Returned descriptor is consumed by `core/submission-bundle.ts`
    which writes manifest entries.

17. **Tracker UI signal**. Post a tracker notification to the operator
    queue: "Annual §889 representation envelope `<uuid>` ready. Visit
    `/section889/annual-rep/<id>` to download `.docx`, submit to SAM.gov,
    and record the SAM submission receipt id."

18. **Marketplace metadata feed**. Write
    `out/marketplace-section889-badge.json` (consumed by LOOP-Q.Q1)
    containing the envelope_uuid, valid_until, representation answers,
    and a public-verification URL pattern. Q.Q1 surfaces the badge
    iff `valid_until > now` AND both representation answers are
    "does not".

19. **Verification pass**.
    - `npm run check:reo` G1+G2+G3.
    - `npm run check:provenance` — envelope MUST carry a `provenance`
      block listing every read path.
    - `npm run typecheck`.
    - `npm test -- tests/core/section889-annual-rep.test.ts`.

20. **Completion hook** (per §13 below): update STATUS.md row,
    SPEC status table, CHANGELOG, commit with W.W4 in the message, push.

## 7. Files to create / modify

### Create

| Absolute path | Purpose | Approximate size |
|---|---|---|
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/section889-annual-rep.ts` | Pure builder + entry point `emitSection889AnnualRep()` | ~580 lines |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/section889-rep-docx.ts` | OOXML `.docx` renderer (zip-store) | ~420 lines |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/db/migrations/add-section889-annual-reps.sql` | Tracker DB schema for the new table + indexes | ~75 lines |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/section889-annual-rep-status.tsx` | Tracker UI page: rep status, SAM submission helper, history | ~350 lines |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/section889-annual-rep.test.ts` | ≥15 tests covering all REQUIRES-OPERATOR-INPUT branches + signing + delta + docx + envelope schema | ~600 lines |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/section889-annual-rep/` | Fixtures: matches.json variants, config.yaml variants, prior-rep tracker row, expected envelope golden, expected docx hash | (multiple) |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/section889/reasonable-inquiry-methodology.md` | Operator-authored methodology summary (template seeded by W.W4) | ~80 lines |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/section889/annual-rep-runbook.md` | Operator runbook: annual submission ceremony, SAM steps, who-signs | ~150 lines |

### Modify

| Absolute path | Change |
|---|---|
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` | New flag `--section889-annual-rep`; env `CLOUD_EVIDENCE_SECTION889_ANNUAL_REP`. After W.W2 emits matches, when flag is on, run `emitSection889AnnualRep()`. |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` | Append two `WELL_KNOWN` rows (json + docx). |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/section889.ts` | New endpoints: `GET /api/section889/annual-reps`, `GET /api/section889/annual-reps/:id`, `POST /api/section889/annual-reps/:id/sam-receipt` (operator-records submission). |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/nav.tsx` | Add nav item "§889 Annual Rep" under the "Compliance Reps" group. |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` | Slice row + Overall section update at completion. |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-W-SPEC.md` | Slice status table row update at completion. |
| `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CHANGELOG.md` | "Unreleased" entry at completion. |

## 8. Test specifications

Minimum 15 tests, listed as a table. Fixtures live under
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/section889-annual-rep/`.

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T1 | Zero unsuppressed matches → both reps `'does not'` | `matches.empty.json`, `config.baseline.yaml` | `envelope.representation.provides_covered_equipment_or_services === 'does not'` AND `...uses_covered_equipment_or_services === 'does not'` | Envelope re-parses; both narratives cite zero matches |
| T2 | One subprocessor match (Hikvision) → provides=`does`, uses=`does` | `matches.subproc-hikvision.json` | `provides === 'does'` AND `uses === 'does'`; `provides_basis` cites subprocessor sheet entry | Linked-incidents annex populated |
| T3 | SBOM-only transitive match → provides=`does not`, uses=`does` | `matches.sbom-only-huawei.json` | `provides === 'does not'` AND `uses === 'does'` | (c)(1) vs (c)(2) distinction enforced |
| T4 | OCI publisher-only match → provides=`does not`, uses=`does` | `matches.oci-publisher.json` | Same as T3 | OCI is "use" but not "provision-to-Government" |
| T5 | Inventory provider-tag match (Kaspersky cloud sub-tenant) → provides=`does`, uses=`does` | `matches.inventory-kaspersky.json` | Both `'does'`; rationale narrative cites NDAA §1634 alongside §889 | When `include_kaspersky_attachment === true`, supplement annex is rendered |
| T6 | All matches suppressed by operator with reason → both `'does not'`; suppressions surfaced in rationale | `matches.all-suppressed.json` | Both `'does not'`; rationale lists each suppression reason | 3PAO-readable suppression trail |
| T7 | Missing `offeror.unique_entity_id` (UEI) → throws `requires_operator_input: offeror.unique_entity_id` | `matches.empty.json`, `config.missing-uei.yaml` | Throw before any artifact write | Tracker UI surfaces the field id |
| T8 | UEI present but wrong length (11 chars instead of 12) → throws `requires_operator_input: offeror.unique_entity_id:invalid-format` | `config.invalid-uei.yaml` | Throw with validator name | Validator name `UEI_REGEX` |
| T9 | Missing `authorized_officer.signing_key_id` → throws `requires_operator_input: authorized_officer.signing_key_id` | `config.missing-keyid.yaml` | Throw | UI deep-link to key-ring page |
| T10 | Signing key expired in keyring → throws `requires_operator_input: signing-key-expired` | (keyring mock with expired key) | Throw with expiry date in message | Operator-actionable |
| T11 | Stale catalog snapshot (>24h) in strict mode → exit 2; in lenient mode → emit `coverage:stale-catalog` warning + proceed | `matches.stale-catalog.json` | Strict: throw; Lenient: warn + emit | Both behaviours covered |
| T12 | Methodology doc missing → throws `requires_operator_input: reasonable_inquiry.methodology_path` | `config.missing-method.yaml` | Throw | UI link to docs/section889/ |
| T13 | Envelope JSON canonical-form is stable across re-runs (byte-equal) | `matches.empty.json` | SHA-256 of two consecutive runs identical (with `signed_at`, `envelope_uuid`, `signature`, `timestamp` zeroed for comparison) | Bit-stability for reproducible builds |
| T14 | `.docx` byte-stream is stable across re-runs (byte-equal) | `matches.empty.json` | SHA-256 of two `.docx` byte-streams identical (with metadata fields zeroed for comparison) | OOXML reproducibility for the audit chain |
| T15 | `.docx` opens with `unzip -l`; declared parts present | (golden output) | parts list contains exactly the 8 OOXML parts named in §5.2 | OOXML well-formedness |
| T16 | Delta-link: prior rep exists in tracker DB → envelope's `previous_envelope_id` is set to prior row's UUID | (prior tracker row inserted) | `envelope.previous_envelope_id === prior.envelope_uuid` | Continuity audit trail |
| T17 | Representation flip from "does not" → "does" emits tracker `representation-flip` audit-log event | (prior rep "does not"; new screen with match) | Audit-log event present with prior + new statuses | Flip is high-signal for AO |
| T18 | Marketplace feed `out/marketplace-section889-badge.json` emitted with badge enabled iff both `does not` AND `valid_until > now` | (empty matches; future expiry) | `badge.enabled === true`; with at least one `does` → `false` | LOOP-Q.Q1 consumer correctness |
| T19 | Ed25519 signature verifies against the operator officer's public key | (live keyring; in-process sign + verify) | `verifySignature(envelope) === true` | Signing integrity |
| T20 | RFC 3161 timestamp response decodes; embedded SHA-256 matches the envelope hash | (mocked TSA response with known digest) | TSA digest === SHA-256(signed envelope) | Timestamp integrity |
| T21 | Tracker DB insert failure → orchestrator aborts before any artifact is written to disk | (DB pool stub that throws) | No `.docx` and no `.json` present on disk | Drift-free failure mode |
| T22 | Kaspersky supplement opt-out (`include_kaspersky_attachment: false`) → envelope.kaspersky_supplement undefined; `.docx` has no Annex C | `config.no-kaspersky.yaml` | `kaspersky_supplement === undefined` | Opt-in narrative gating |

## 9. Risks

### R1 — "Provides" vs "Uses" misclassification

Severity: **high**. Likelihood: **medium**.

FAR 52.204-26(c)(1) is about provision **to the Government in
performance of any contract**; (c)(2) is broader — about the offeror's
own use regardless of contract context. W.W2 produces a single `matches`
list; W.W4 must split it correctly per source. If the algorithm wrongly
counts SBOM-internal transitive deps as "provides to the Government",
the rep flips from "does not" to "does" inappropriately, which is a
materially incorrect statement to the Government and a contract-
performance risk.

**Mitigation:** Algorithm step 4 makes the split explicit and the tests
T2/T3/T4/T5 lock the split. The rationale narratives in step 5 cite
each match's `matched_via` so an external reviewer can verify the
split.

### R2 — Stale catalog snapshot drives a "does not" rep that misses a current covered entity

Severity: **high**. Likelihood: **low** (with W.W1 daily refresh) but
**high impact** if it occurs.

If the catalog snapshot W.W4 reads is stale (e.g. a new BIS Entity
List addition published yesterday is not yet in the snapshot), W.W4
may emit "does not" while in fact a current vendor is now covered.

**Mitigation:** Step 1 freshness gate (24h max), strict-mode exit code
2 (default for production), tracker UI flag on the rep status page
showing the catalog snapshot age. Annual SAM cycle aligned with a
fresh refresh.

### R3 — Officer signing key rotated mid-cycle without keyring update

Severity: **medium**. Likelihood: **medium**.

If the officer's signing key rotates and the keyring `signing_key_id`
in `config.yaml` is not updated, signing fails late in the orchestrator
flow.

**Mitigation:** Step 3 validates key presence + expiry before any
expensive work; T9 + T10 cover both failure modes. Tracker UI shows
the current signing-key fingerprint next to the operator's name on the
rep status page.

### R4 — `.docx` non-reproducibility breaks the audit chain

Severity: **medium**. Likelihood: **medium**.

OOXML packages contain timestamps and locale-dependent fields that
introduce nondeterminism. If two runs produce different `.docx` bytes
for identical inputs, the 3PAO cannot verify the artifact via hash.

**Mitigation:** Zip-store (no compression), pinned timestamps from the
envelope's `signed_at` (not `Date.now()`), pinned locale `en-US`, no
`Last Modified By` field, and T14 + T15 lock byte-stability. Documented
in `docs/section889/annual-rep-runbook.md`.

### R5 — SAM submission receipt not pasted back; expiry timer drifts

Severity: **medium**. Likelihood: **medium-high** (operator workflow
discipline).

Operator generates envelope, submits to SAM.gov, forgets to paste the
SAM receipt id back into the tracker. The tracker then shows the rep
as "emitted but unsubmitted" — which it actually was when the user
forgot the paste-back — and the AO dashboard shows a perpetual yellow
indicator.

**Mitigation:** Tracker UI shows a per-rep submit-status badge + email
nag at 24h post-emission if no SAM receipt paste-back; runbook step
calls out the paste-back as a checkbox in the operator's quarterly
governance checklist.

### R6 — FAR 52.204-26 text amendment

Severity: **low**. Likelihood: **low**.

The FAR clause text could be amended (new sub-paragraph, new defined
term, new checkbox). W.W4's verbatim recital would then be out of date.

**Mitigation:** The verbatim recital is loaded from
`docs/sources/far-52.204-26.html` (W.W1 snapshot) rather than hard-
coded; W.W1's quarterly refresh re-pulls and W.W4 fails its own
"recital is stale" check if the source file is older than 90 days.

### R7 — Cross-jurisdictional "covered foreign country" expansion

Severity: **low**. Likelihood: **low** (statutory change required).

Today FAR 52.204-25(a) defines "covered foreign country" as the PRC.
A future NDAA could add jurisdictions (e.g. DPRK, Russia). Catalog
sources (OFAC, BIS) cover that automatically; the recital block in
W.W4's docx would need an update.

**Mitigation:** Same as R6 — recital sourced from a refreshed mirror,
not hard-coded.

### R8 — Subprocessor sheet update lag

Severity: **medium**. Likelihood: **medium**.

If the subprocessor sheet is updated mid-quarter and the rep was
emitted before the update, the rep may be over- or under-reporting at
the time of SAM submission.

**Mitigation:** Tracker UI shows the subprocessor sheet hash next to
the rep emission timestamp; runbook requires re-emission if the
subprocessor sheet has changed since the last W.W2 run.

## 10. Open questions

The implementer must answer or explicitly defer the following before
the slice ships:

- **Q1.** Does the operator-officer keyring support hardware-token
  signing (YubiKey / HSM) or only software keys? If hardware, the
  signing step is interactive — the tracker UI must prompt for token
  insertion. Defer to LOOP-W-RISKS R10 if hardware is in scope.
- **Q2.** Should W.W4 also emit a CSV row for SAM.gov "Reps & Certs"
  upload tooling (some agencies have semi-automated upload helpers
  that consume CSV)? Recommend: optional output file
  `out/section889-annual-rep.csv` controlled by `--emit-rep-csv`.
- **Q3.** Should the kaspersky_supplement annex appear ONLY when the
  W.W2 screen surfaced a Kaspersky match, or unconditionally when the
  operator opts in? Current default: unconditional opt-in. Operator
  may want match-driven; document the toggle.
- **Q4.** What expiry warning cadence does the tracker UI use? Default:
  amber at 30 days, red at 0. Some operators want amber at 60 days
  (for procurement-cycle planning). Make configurable in
  `config.yaml#section889.expiry_warning_amber_days`.
- **Q5.** Does the FedRAMP Marketplace badge (LOOP-Q.Q1) require a
  PUBLIC verification URL or is the envelope SHA-256 sufficient? If
  public URL, W.W4 must additionally emit a tiny GitHub Pages /
  S3 static page rendering the envelope (out of scope for W.W4 unless
  Q.Q1 imposes it; coordinate with Q.Q1 author).
- **Q6.** For multi-CSP installations (LOOP-H.H3), is the rep emitted
  per CSP or per CSP+system? Default: per CSP (offeror is the CSP
  entity). Confirm with Multi-CSO requirements before W.W4 ships.
- **Q7.** Should W.W4 emit a parallel FAR 52.204-24 representation when
  the operator is preparing a solicitation response? Recommend: defer
  to a separate W.W5 slice if the demand surfaces.

## 11. REQUIRES-OPERATOR-INPUT fields

Every field that cannot be auto-derived from W.W2 results or signing
material is documented here. UI location refers to the tracker page
`/section889/annual-rep/new` (form fields) plus `config.yaml` keys.

| Field name | Type | Validator | UI location | Failure mode if missing |
|---|---|---|---|---|
| `offeror.legal_name` | string (1..200) | `nonempty + strip-trim` | `/org-profile` → "Legal name"; `config.yaml#section889.offeror.legal_name` | Throw `requires_operator_input: offeror.legal_name`; orchestrator exits 2 before any write |
| `offeror.unique_entity_id` | string (12 chars, `[A-Z0-9]`) | `UEI_REGEX = /^[A-Z0-9]{12}$/` | `/org-profile` → "SAM UEI"; `config.yaml#section889.offeror.unique_entity_id` | Throw `requires_operator_input: offeror.unique_entity_id` or `:invalid-format`; orchestrator exits 2 |
| `offeror.cage_code` | string (5 chars, `[A-Z0-9]`) optional | `CAGE_REGEX = /^[A-Z0-9]{5}$/` | `/org-profile` → "CAGE code"; `config.yaml#section889.offeror.cage_code` | Warn (CAGE is optional for some entities); proceed |
| `offeror.physical_address.{street1,city,state,zip,country}` | object | per-field nonempty + zip regex per country | `/org-profile` → "Physical address"; `config.yaml#section889.offeror.physical_address` | Throw `requires_operator_input: offeror.physical_address.<field>`; exits 2 |
| `authorized_officer.full_name` | string (1..200) | `nonempty + strip-trim` | `/section889/annual-rep/new` → "Officer name"; `config.yaml#section889.authorized_officer.full_name` | Throw `requires_operator_input: authorized_officer.full_name`; exits 2 |
| `authorized_officer.title` | string (1..200) | `nonempty` | same as above | Throw `requires_operator_input: authorized_officer.title`; exits 2 |
| `authorized_officer.email` | string | RFC 5322 email regex | same | Throw `requires_operator_input: authorized_officer.email:invalid-format`; exits 2 |
| `authorized_officer.signing_key_id` | string | `keyring.has(id) === true AND keyring.get(id).expiresAt > now` | `/keyring` admin page; `config.yaml#section889.authorized_officer.signing_key_id` | Throw `requires_operator_input: signing-key-missing-or-expired`; exits 2 |
| `reasonable_inquiry.methodology_path` | string | `fs.existsSync(path) === true` | `docs/section889/reasonable-inquiry-methodology.md` | Throw `requires_operator_input: reasonable_inquiry.methodology_path`; exits 2 |
| `reasonable_inquiry.methodology_sha256` | string | auto-computed at runtime — empty in config is OK | `config.yaml#section889.reasonable_inquiry.methodology_sha256` | Field is recomputed; no failure |
| `sam_review.excluded_parties_review_date` | ISO 8601 | auto-set from W.W1 snapshot timestamp | (auto) | If W.W1 hasn't run, throw `requires_operator_input: w1-snapshot-missing`; exits 2 |
| `sam_review.excluded_parties_snapshot_id` | string | auto-set from W.W1 snapshot id | (auto) | Same as above |
| `include_kaspersky_attachment` | boolean | typed `boolean` | `config.yaml#section889.include_kaspersky_attachment` | Default `true` (NDAA §1634 supplement opt-in recommended); never blocks |
| `valid_until_days` | integer (1..730) | `1 ≤ n ≤ 730` | `config.yaml#section889.valid_until_days` | Default 365 per FAR 52.204-8(d); validates if non-default |
| `sam_submission_receipt_id` | string | nonempty when pasted | `/section889/annual-rep/<id>` → "Record SAM submission" form | Tracker UI badge stays amber until operator pastes; no envelope-time failure |
| `sam_submitted_at_utc` | ISO 8601 | auto-set from `Date.now()` at paste-back time | (auto, set at paste-back) | No failure |
| `sam_submitted_by_user_id` | integer | tracker session user id | (auto, set from tracker session) | No failure |

## 12. Implementation log

Implementing session updates this table at every meaningful milestone
per `docs/IMPLEMENTATION-LOG-TEMPLATE.md`.

| date (ISO) | session id | action | commit | notes |
|---|---|---|---|---|
| 2026-06-18 | impl-w-w4 | ship | `TBD` | Shipped the realizable core deliverable end to end. Created `core/section889-annual-rep.ts` (pure builder `composeAnnualRepEnvelope` + `computeRepresentation` does/does-not split + operator-input validation + detached-Ed25519 signing + ledger + linked-incident collection + Marketplace badge + coverage augmentation + `emitSection889AnnualRep` entry point) and `core/section889-rep-docx.ts` (OOXML/zip-store renderer on `core/zip.ts` — verbatim FAR 52.204-26(a)/(b)/(c)(1)/(c)(2) + FAR 52.204-25(a) "covered" + "reasonable inquiry" recitals, ■/□ screen-driven checkboxes, linked-incident + Kaspersky annexes, 18 U.S.C. §1001 attestation + reserved signature region). Wired orchestrator `--section889-annual-rep` (env `CLOUD_EVIDENCE_SECTION889_ANNUAL_REP`) after W.W3 + before signing; registered 5 `section889-annual-rep-*` / `marketplace-section889-badge` WELL_KNOWN bundle roles. Seeded `docs/section889/reasonable-inquiry-methodology.md` + `docs/section889/annual-rep-runbook.md` + `section889-annual-rep.example.yaml`. typecheck clean; 1211/1211 tests (+39, exceeding the §8 ≥15 target); `npm run check:reo` (G1+G2+G3) returns 0; end-to-end `check:provenance` on real emitted artifacts (incl. the new `marketplace-section889-badge.json`) passes. |
| 2026-06-18 | impl-w-w4 | spec-divergence | `TBD` | (1) **Input shape:** the spec §4.1 names the W.W2 input `out/prohibited-vendors-matches.json` with a `ProhibitedVendorMatches` interface; the shipped W.W2 emits `out/prohibited-vendors-screen-result.json` (`ProhibitedVendorScreenResult`). W.W4 consumes the real artifact (signature-verified, same posture as W.W3) — resolved Q-divergence, no behaviour change. (2) **`provides` vs `uses` surfaces:** the spec's `matched_via` values map to the real `ScreenSurface` set — `provides` = {`subprocessor-sheet`, `inventory-provider-tag`}, `uses` = all non-suppressed matches. (3) **OOXML parts:** the renderer emits the 5 minimal-conformant parts the repo's proven `core/zip.ts` byte-reproducible pattern produces (matching W.W3), not the 8 parts the spec §5.2/T15 enumerate; T15 asserts the actual declared parts. (4) **RFC 3161:** envelope records `rfc3161_timestamp.status:'pending'` (manifest-level TST attaches at run signing — same as W.W2/W.W3; no per-artifact `timestampDigest` primitive exists). |
| 2026-06-18 | impl-w-w4 | scope-deferral | `TBD` | Tracker DB table `section889_annual_reps` (`tracker/db/migrations/*.sql`), REST routes (`tracker/server/routes/section889.ts`), React review/sign-off UI (`tracker/ui/section889-annual-rep-status.tsx`, `nav.tsx`), the SAM-receipt paste-back form, the officer-keyring expiry check (spec §4.4/§11 T10), and the `.ics` renewal-reminder generator are **deferred** — no tracker subsystem exists in this checkout (no `pg`/`express`/`react` deps; every prior slice ships as `core/*.ts`). The append-only `section889-annual-reps.jsonl` ledger is the interim delta/continuity substrate. Tracked as LOOP-W-RISKS W.W4-EXT-1..4. |

## 13. Completion checklist

Per `docs/SLICE-COMPLETION-PROCEDURE.md` (verbatim 7-step procedure)
plus push directive. Every box MUST be checked before the slice is
considered done:

- [ ] **Step 1.** `npm run typecheck` clean.
- [ ] **Step 2.** `npm test -- tests/core/section889-annual-rep.test.ts`
      passes 100% (≥15 new tests counted in CI summary).
- [ ] **Step 3.** `npm run check:reo` (G1+G2+G3) green; specifically:
      `lint:no-stubs` finds zero new forbidden tokens in production
      paths under `core/section889-*.ts`, `tracker/db/migrations/*.sql`,
      `tracker/ui/section889-*.tsx`.
- [ ] **Step 4.** `npm run check:provenance` confirms the envelope
      carries a `provenance` block + every emit-field has a
      `coverage_source` entry where applicable.
- [ ] **Step 5.** STATUS.md updated:
      - Slice row in the slice table flipped to `done` + commit hash +
        completed date.
      - "Overall → Next priority" line points to the next slice.
- [ ] **Step 6.** `docs/loops/LOOP-W-SPEC.md` §12 status table row for
      W.W4 flipped to `done`, commit hash recorded.
- [ ] **Step 7.** This file's frontmatter updated:
      `status: done`, `commit: <hash>`, `completed_date: <ISO>`,
      `last_updated: <ISO>`.

**After commit lands, append a row to STATUS.md for this slice; update
the loop SPEC status row; append a CHANGELOG line; push to origin/main;
only THEN is the slice closed.** Specifically:

- [ ] **Push directive.** `git commit -m "<msg>" --signoff` with W.W4
      in the subject line, then `git push origin main`. Verify the
      push with `git log --oneline -1 origin/main`.
- [ ] **CHANGELOG.md "Unreleased" entry** added with the line:
      "W.W4 — Section 889 Part B Annual Representation (FAR 52.204-26)
      emitter + signed JSON envelope + OOXML `.docx` + tracker
      `section889_annual_reps` table; satisfies SAM annual-rep cycle
      per FAR 52.204-8(d). Real-evidence trace: W.W2 screen results
      drive the representation answers; W.W1 catalog snapshot hash
      embedded for 3PAO verification; Ed25519 + RFC 3161 signing."
- [ ] **Implementation log** (§12 above) final row appended:
      `date | session id | action='ship' | commit=<hash> | notes`.
- [ ] **Risks register** (`docs/loops/LOOP-W-RISKS.md`) updated if any
      new risk surfaced during implementation.
- [ ] **CLAUDE.md reading list** unchanged (W.W4 introduces no new
      permanent reference document beyond the per-slice doc itself).

## 14. Resume-from-fresh-session checklist

If a session opens with ONLY this file as context:

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded by harness) — REO
   rules + Real Slice Contract + the 9-step completion directive.
2. This file gives you: full source obligations + verbatim FAR 52.204-26
   recital + algorithm + tests + risks + completion checklist + the
   `section889_annual_reps` schema.
3. Read `cloud-evidence/docs/loops/LOOP-W-SPEC.md`:
   - §1 (mission + scope guard) for the loop's universal-applicability
     posture.
   - §2.2 + §2.6 for FAR 52.204-26 + FAR 52.204-8 verbatim.
   - §3 (slice table) for cross-slice dependencies.
   - §5 (reusable primitives) for the signing + bundler + tracker
     primitives W.W4 calls.
4. Read `cloud-evidence/docs/slices/W/W.W2.md` — the upstream slice
   that produces `out/prohibited-vendors-matches.json`.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
6. Read `cloud-evidence/core/sign.ts` and `core/timestamp.ts` — the
   primitives W.W4 calls in algorithm steps 11 + 12.
7. Read `cloud-evidence/core/inventory-workbook.ts` — the OOXML
   helper pattern reused in `core/section889-rep-docx.ts`.
8. Read `cloud-evidence/core/submission-bundle.ts` — append two
   `WELL_KNOWN` rows per §5.4.
9. Read `cloud-evidence/tracker/db/migrations/0001-initial.sql`
   pattern for migration shape; then write the
   `add-section889-annual-reps.sql` per §5.3.
10. Confirm `out/prohibited-vendors-matches.json` (from W.W2) exists in
    fixtures; if not, run W.W2 first (or use the test fixture variants
    listed in §8).
11. Begin implementation; update §12 Implementation log as you go.
12. At completion, execute the §13 completion checklist atomically with
    the final commit.

---

End of W.W4 per-slice doc. Apache-2.0 clean-room.
