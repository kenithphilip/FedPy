---
slice_id: U.U2
title: Per-Datastore Privacy-Framework Applicability Mapper (FERPA / COPPA / GLBA / CCPA-CPRA / NY SHIELD / GDPR) — Data-Subject Mapper + PII Classifier + Jurisdiction Resolver
loop: U
status: proposed
commit: TBD
completed_date: —
depends_on:
  - U.U1                                # privacy-framework catalog (FERPA / COPPA / GLBA / CCPA / NY SHIELD / GDPR rule files)
  - LOOP-INV-S                          # cloud-evidence inventory (Org-grade per-datastore enumeration emitted under inventory.json + inventory-coverage.json)
  - LOOP-A.A5                           # Ed25519 + RFC 3161 signing (applies to the emitted applicability matrix)
  - tracker DB (existing)               # operator-supplied customer-jurisdiction metadata + data-class tags + per-datastore overrides
blocks:
  - U.U3                                # GLBA Safeguards Rule §314.4 evidence pack (consumes per-datastore GLBA-applicability rows)
  - U.U5                                # State-breach-notification dispatch matrix (consumes per-datastore jurisdictional reach to know which state AGs to notify)
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-07
applicable_conditional: true
condition: Universal when U.U1 catalog is loaded; per-datastore applicability is computed automatically based on (a) data-class tags read from the LOOP-INV-S inventory + (b) operator-supplied customer-jurisdiction metadata in the tracker DB. The slice itself runs unconditionally; its outputs are the trigger flags for downstream loops (U.U3 GLBA only fires for datastores that carry NPI under §314.1(b); U.U5 only dispatches state notifications for states whose data subjects appear in the matrix).
trigger_flag: "--privacy-applicability-matrix"
trigger_env: CLOUD_EVIDENCE_PRIVACY_APPLICABILITY_MATRIX
---

# U.U2 — Per-Datastore Privacy-Framework Applicability Mapper (FERPA / COPPA / GLBA / CCPA-CPRA / NY SHIELD / GDPR)

> This slice is the **applicability oracle** for LOOP-U. U.U1 loads the
> catalog of privacy-framework rules (each rule encoded as a portable
> JSON file under `cloud-evidence/data/privacy-frameworks/`); U.U3..U.U6
> each consume *only the subset of the catalog that applies to a given
> datastore*. U.U2 is the slice that decides that subset. Without U.U2,
> every downstream LOOP-U slice would over-collect (treating every S3
> bucket as if it held student records subject to FERPA) or under-collect
> (treating an audit-log bucket as if it held no PII at all). U.U2
> produces a deterministic, signed, per-datastore applicability matrix
> that drives every downstream privacy artifact.
>
> Why "deterministic" matters: privacy regulations are
> jurisdiction-triggered, not service-triggered. The fact that an S3
> bucket exists in `us-east-1` tells you NOTHING about whether the
> records in it are subject to CCPA — that depends on whether the
> records describe California *residents*. U.U2 reads (a) the
> data-class tags the operator has applied to the bucket (e.g.
> `data_class: "student-pii"`, `data_class: "child-pii-under-13"`),
> (b) the customer-jurisdiction metadata the operator maintains in the
> tracker DB (e.g. "customer #4711 is a California-resident customer"),
> and (c) the FRMR-aligned data-class taxonomy from U.U1's catalog, and
> emits one row per `(datastore_id, framework_id)` tuple with
> `applies: true | false | requires-operator-input` + a citation chain
> back to the framework's statutory definition.

## 1. Mission

U.U2 reads the cloud-evidence inventory artifact emitted by LOOP-INV-S
(canonical path `out/inventory.json`), walks every datastore-class
resource (S3 buckets, RDS instances, DynamoDB tables, Aurora clusters,
GCS buckets, Cloud SQL instances, BigQuery datasets, Firestore
collections, Azure Blob containers, Azure SQL databases, Cosmos DB
accounts, plus any operator-registered custom datastore type), reads
the data-class tags applied to each datastore, joins them against the
customer-jurisdiction metadata in the tracker DB, and for each of the
six in-scope privacy frameworks (FERPA, COPPA, GLBA Safeguards Rule,
CCPA/CPRA, NY SHIELD Act, GDPR — the catalog set frozen in U.U1)
computes whether the framework applies to that datastore.

The output is a signed JSON envelope written to
`out/privacy-applicability-matrix.json` and an `.docx`/`.pdf` rendering
written to `out/privacy-applicability-matrix.{docx,pdf}` for the
operator's General Counsel / Chief Privacy Officer to attest to. Each
row carries the citation chain (statute / regulation paragraph + URL +
date of access), the inputs the decision was based on (which
data-class tag, which jurisdiction tag, which catalog rule), the
operator's optional override + override justification, and a SHA-256
digest of the inputs so a 3PAO can replay the decision deterministically
from the signed envelope alone.

U.U2 does **not** decide compliance — it decides applicability. A row
saying "CCPA applies to bucket `csp-prod-customer-data`" means "this
bucket is in scope for CCPA"; it does **not** mean "this bucket is
CCPA-compliant". Downstream slices (U.U3 GLBA evidence pack, U.U5 state
breach dispatch, the CCPA-specific narrative emitter in U.U4) consume
the applicability matrix to know what to assess. REO Rule 4 governs the
operator inputs: when a datastore lacks a `data_class` tag AND the
operator has not supplied a tracker-DB override, the row is emitted
with `applies: requires-operator-input` and the orchestrator emits a
`coverage:miss` diagnostic so the gap is visible in
`inventory-coverage.json`.

## 2. Authoritative sources

Every URL accessed 2026-06-07. Verbatim quotes appear in Markdown
blockquotes. Where the live Federal Government source returned a non-200
to anonymous fetches, the implementer downloads the page or PDF to
`cloud-evidence/docs/sources/` and re-quotes verbatim from the local
copy. Each quote is pinned to a specific section / paragraph / control
ID so a 3PAO can independently verify.

### 2.1 FERPA — 20 U.S.C. §1232g definition of "education records" (the in-scope-data trigger)

URL: https://www.law.cornell.edu/uscode/text/20/1232g (accessed
2026-06-07). Cross-checked against
https://www.ecfr.gov/current/title-34/subtitle-A/part-99 (34 CFR Part 99,
the implementing regulation).

20 U.S.C. §1232g(a)(4)(A) — the **definition** of "education records":

> "(4)(A) For the purposes of this section, the term 'education records'
> means, except as may be provided otherwise in subparagraph (B), those
> records, files, documents, and other materials which—
> (i) contain information directly related to a student; and
> (ii) are maintained by an educational agency or institution or by a
> person acting for such agency or institution."

U.U2 maps this to the data-class tag `student-pii` (canonical name
emitted by U.U1's catalog). A datastore whose `data_class` tag matches
`student-pii` AND whose operator-declared `customer_type` includes
`educational-agency-or-institution` triggers `applies: true` for
FERPA. The "person acting for such agency or institution" clause is
the SaaS-as-school-official angle — the operator declares that
attestation once in the tracker UI; U.U2 propagates it across every
datastore for the affected customer.

### 2.2 COPPA — 15 U.S.C. §6501(1) definition of "child" (the under-13 trigger)

URL: https://www.law.cornell.edu/uscode/text/15/6501 (accessed
2026-06-07). Cross-checked against
https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-312
(16 CFR Part 312, the Children's Online Privacy Protection Rule).

15 U.S.C. §6501(1):

> "(1) Child
> The term 'child' means an individual under the age of 13."

15 U.S.C. §6501(8) — the **personal information** scope (what triggers
the rule for a datastore):

> "(8) Personal information
> The term 'personal information' means individually identifiable
> information about an individual collected online, including—
> (A) a first and last name;
> (B) a home or other physical address including street name and name
> of a city or town;
> (C) an online contact information;
> (D) a screen or user name;
> (E) a telephone number;
> (F) a Social Security number;
> (G) a persistent identifier, such as a customer number held in a
> cookie or a processor serial number, where such identifier is
> associated with individually identifiable information; or other
> identifier that the Commission determines permits the physical or
> online contacting of a specific individual; or
> (H) information concerning the child or the parents of that child that
> the operator collects online from the child and combines with an
> identifier described in this paragraph."

U.U2 maps these eight categories to the data-class tag
`child-pii-under-13` (canonical name from U.U1's catalog). A datastore
whose tag matches AND whose `customer_type` includes
`directs-services-to-children-under-13` triggers `applies: true` for
COPPA. The "directed to children" criterion is operator-attested
exactly once per customer; U.U2 propagates.

### 2.3 GLBA Safeguards Rule — 16 CFR §314.1(b) definition of "customer information" + §314.2(l) "nonpublic personal information"

URL: https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314
(accessed 2026-06-07). The FTC Safeguards Rule was substantially
amended in 2021 and again in 2023.

16 CFR §314.1(b) — **scope**:

> "(b) Scope. This part applies to the handling of customer information
> by all financial institutions over which the Federal Trade Commission
> ('FTC' or 'Commission') has jurisdiction."

16 CFR §314.2(l) — the **customer information** trigger:

> "(l) Customer information means any record containing nonpublic
> personal information about a customer of a financial institution,
> whether in paper, electronic, or other form, that is handled or
> maintained by or on behalf of you or your affiliates."

The defined term "nonpublic personal information" is borrowed from the
Privacy Rule (16 CFR §313.3(n)) which is incorporated by reference:

> "(p) Nonpublic personal information has the same meaning as in
> §313.3(n) of this chapter."

U.U2 maps this to the data-class tag `npi-financial` (canonical name
from U.U1's catalog). A datastore whose tag matches AND whose
operator-declared `customer_type` includes `financial-institution` OR
`processes-on-behalf-of-financial-institution` triggers `applies: true`
for GLBA. The 30-day FTC breach-notification clock (16 CFR §314.5,
effective May 13, 2024) is gated on the same applicability decision.

### 2.4 CCPA / CPRA — California Civil Code §1798.140(o) "personal information" + §1798.140(g) "consumer"

URL: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.140&lawCode=CIV
(accessed 2026-06-07). Cross-checked against the CPRA-amended text
maintained by the California Privacy Protection Agency at
https://cppa.ca.gov/regulations/

Cal. Civ. Code §1798.140(g) — the **consumer** trigger (residency
test):

> "(g) 'Consumer' means a natural person who is a California resident,
> as defined in Section 17014 of Title 18 of the California Code of
> Regulations, as that section read on September 1, 2017, however
> identified, including by any unique identifier."

Cal. Civ. Code §1798.140(o)(1) — the **personal information** scope:

> "(o)(1) 'Personal information' means information that identifies,
> relates to, describes, is reasonably capable of being associated
> with, or could reasonably be linked, directly or indirectly, with a
> particular consumer or household."

U.U2 maps this to the data-class tag `pii-california-resident`
(canonical name from U.U1's catalog) OR — and this is the critical
join — to ANY data-class tag that holds personal information when the
**customer-jurisdiction metadata** in the tracker DB declares the
customer has California-resident end users. The CCPA applies because
the data subject is a California resident, regardless of where the
data physically sits; U.U2 expresses this with the jurisdictional join
in §6 step 4.

### 2.5 NY SHIELD Act — N.Y. Gen. Bus. Law §899-bb definition of "private information"

URL: https://www.nysenate.gov/legislation/laws/GBS/899-BB (accessed
2026-06-07). The Stop Hacks and Improve Electronic Data Security
(SHIELD) Act was enacted 2019 and significantly amended in 2023 to add
biometric and email-credential scope.

N.Y. Gen. Bus. Law §899-bb(1)(b) — **scope of the data-security
obligations**:

> "(b) Any person or business that owns or licenses computerized data
> which includes private information of a resident of New York shall
> develop, implement and maintain reasonable safeguards to protect the
> security, confidentiality and integrity of the private information
> including, but not limited to, disposal of data."

The defined term "private information" (a strict superset of
"personal information") covers categories enumerated in
§899-aa(1)(b):

> "(b) 'Private information' shall mean either: (i) personal
> information consisting of any information in combination with any
> one or more of the following data elements, when either the personal
> information or the data element is not encrypted, or encrypted with
> an encryption key that has also been accessed or acquired:
> (1) social security number;
> (2) driver's license number or non-driver identification card number;
> (3) account number, credit or debit card number, in combination with
> any required security code, access code, password or other
> information that would permit access to an individual's financial
> account;
> (4) account number, credit or debit card number, if circumstances
> exist wherein such number could be used to access an individual's
> financial account without additional identifying information,
> security code, access code, or password; or
> (5) biometric information, meaning data generated by electronic
> measurements of an individual's unique physical characteristics,
> such as a fingerprint, voice print, retina or iris image, or other
> unique physical representation or digital representation of
> biometric data which are used to authenticate or ascertain the
> individual's identity; or
> (ii) a user name or e-mail address in combination with a password or
> security question and answer that would permit access to an online
> account."

U.U2 maps each of these categories to a fine-grained data-class tag
(`pii-ny-resident.ssn`, `pii-ny-resident.financial-account`,
`pii-ny-resident.biometric`, `pii-ny-resident.email-credential-pair`)
so the §6 algorithm can decide both *whether* SHIELD applies and
*which* SHIELD-flavor (data-security obligation vs.
breach-notification obligation) governs. The jurisdictional trigger is
the same as CCPA's — residency, not location-of-data.

### 2.6 GDPR — Regulation (EU) 2016/679 Article 3 territorial scope + Article 4(1) "personal data"

URL: https://eur-lex.europa.eu/eli/reg/2016/679/oj (accessed
2026-06-07). Cross-checked against the consolidated text maintained by
the European Data Protection Board at
https://www.edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_3_2018_territorial_scope_after_public_consultation_en_0.pdf

Article 4(1) — **personal data** definition:

> "(1) 'personal data' means any information relating to an identified
> or identifiable natural person ('data subject'); an identifiable
> natural person is one who can be identified, directly or indirectly,
> in particular by reference to an identifier such as a name, an
> identification number, location data, an online identifier or to one
> or more factors specific to the physical, physiological, genetic,
> mental, economic, cultural or social identity of that natural
> person;"

Article 3(2) — **territorial scope** (the extra-territorial trigger
that makes GDPR apply to a US-resident CSP processing EU-resident
data):

> "(2) This Regulation applies to the processing of personal data of
> data subjects who are in the Union by a controller or processor not
> established in the Union, where the processing activities are
> related to:
> (a) the offering of goods or services, irrespective of whether a
> payment of the data subject is required, to such data subjects in
> the Union; or
> (b) the monitoring of their behaviour as far as their behaviour takes
> place within the Union."

U.U2 maps Article 4(1) to the data-class tag `pii-eu-data-subject` and
gates GDPR applicability on the operator-declared customer attribute
`offers-goods-or-services-to-eu-data-subjects` OR
`monitors-eu-data-subject-behavior`. The §3(1) "establishment in the
Union" path is a separate trigger captured via the customer-attribute
`has-eu-establishment` and short-circuits the §3(2) test.

### 2.7 NIST SP 800-122 — PII confidentiality impact level (the FRMR-aligned baseline taxonomy U.U1 mirrors)

URL: https://csrc.nist.gov/pubs/sp/800/122/final (accessed
2026-06-07). PDF cached locally at
`cloud-evidence/docs/sources/NIST.SP.800-122.pdf` (SHA-256 recorded in
the cache manifest).

NIST SP 800-122 §2.1 — **PII definition** (the federal baseline U.U1's
data-class taxonomy is anchored on):

> "Personally Identifiable Information (PII) is any information about
> an individual maintained by an agency, including (1) any information
> that can be used to distinguish or trace an individual's identity,
> such as name, social security number, date and place of birth,
> mother's maiden name, or biometric records; and (2) any other
> information that is linked or linkable to an individual, such as
> medical, educational, financial, and employment information."

U.U2 uses this definition as the **default-applies-as-PII** rule when
no fine-grained data-class tag is present but the datastore is flagged
as `contains-pii-unspecified` — in that case the matrix marks every
US-federal-baseline-applicable framework (FERPA if customer-type
matches; COPPA if customer-type matches; GLBA if customer-type matches;
CCPA / SHIELD if jurisdictional join matches) as
`applies: requires-operator-input` rather than `false`, because the
operator has acknowledged PII presence but has not refined the class.

## 3. Scope

### In

- Per-datastore applicability decision for FERPA, COPPA, GLBA, CCPA,
  NY SHIELD, GDPR (the catalog frozen in U.U1).
- Reading the cloud-evidence inventory artifact (`out/inventory.json`)
  and walking every datastore-class resource (S3, RDS, DynamoDB, GCS,
  Cloud SQL, BigQuery, Firestore, Azure Blob, Azure SQL, Cosmos DB,
  plus any operator-registered custom type).
- Reading data-class tags from inventory resource records (the
  `tags.data_class` field that LOOP-INV-S surfaces).
- Reading customer-jurisdiction metadata from the tracker DB
  (`customer_jurisdictions` table — operator-maintained).
- Reading operator overrides (a `privacy_applicability_overrides`
  table in the tracker DB; one row per `(datastore_id, framework_id)`
  override, with operator user_id + timestamp + justification).
- Emitting the signed JSON applicability matrix
  (`out/privacy-applicability-matrix.json`).
- Emitting the `.docx` and `.pdf` rendering for General Counsel review.
- Surfacing every `requires-operator-input` row in the tracker UI's
  "Privacy applicability gaps" panel + a `coverage:miss` line per row.

### Out

- Actually collecting evidence for any framework — that is U.U3
  (GLBA), U.U4 (CCPA narrative + Notice at Collection emitter), U.U5
  (state breach dispatch), U.U6 (GDPR Article 30 record-of-processing
  emitter). U.U2 is a classifier; it never asserts compliance.
- Inventory enumeration — that is LOOP-INV-S. U.U2 consumes the
  inventory; it never re-discovers datastores.
- Catalog maintenance — that is U.U1. If a framework changes
  (e.g. the Apr 2026 COPPA amendments take effect), U.U1's rule files
  are updated; U.U2 just re-reads.
- Data-class tagging itself — that is the operator's responsibility,
  surfaced in the LOOP-INV-S "tagging gaps" report.
- Acting on the matrix — REO Rule 4. U.U2 emits; downstream slices
  consume; the operator approves transmission.

## 4. Inputs

```typescript
// Read from out/inventory.json (LOOP-INV-S canonical output)
interface InventoryDatastoreRecord {
  id: string;                              // canonical inventory id (e.g. "aws:s3:csp-prod-customer-data")
  provider: 'aws' | 'gcp' | 'azure';
  service: string;                         // e.g. "s3", "rds", "dynamodb", "gcs", "cloud-sql", "bigquery"
  region: string;                          // physical region (does NOT determine applicability)
  arn_or_self_link: string;
  tags: {
    data_class?: string;                   // e.g. "student-pii", "child-pii-under-13", "npi-financial"
    data_class_fine?: string;              // optional refinement e.g. "pii-ny-resident.ssn"
    customer_attribution?: string;         // optional customer id; joins to customer_jurisdictions
    [k: string]: string | undefined;
  };
  synthesized_fields: string[];            // LOOP-INV-S provenance marker
  created_at: string;                      // ISO 8601
  last_modified: string;                   // ISO 8601
}

// Read from tracker DB: customer_jurisdictions table
interface CustomerJurisdictionRecord {
  customer_id: string;                     // operator-supplied internal id
  customer_type: Array<
    | 'educational-agency-or-institution'
    | 'directs-services-to-children-under-13'
    | 'financial-institution'
    | 'processes-on-behalf-of-financial-institution'
    | 'offers-goods-or-services-to-eu-data-subjects'
    | 'monitors-eu-data-subject-behavior'
    | 'has-eu-establishment'
    | 'general-commercial'
  >;
  resident_jurisdictions: Array<
    | 'us-ca'                              // CCPA / CPRA
    | 'us-ny'                              // NY SHIELD
    | 'us-federal'                         // baseline (FERPA / COPPA / GLBA / federal PII)
    | 'eu'                                 // GDPR (any EU member state)
    | string                               // future jurisdictions (Virginia VCDPA, Colorado CPA, etc. — open list)
  >;
  attested_by_user_id: string;             // tracker user id; signed audit log entry
  attested_at: string;                     // ISO 8601
  expires_at: string;                      // attestation expiry (annual re-attest required)
}

// Read from tracker DB: privacy_applicability_overrides table
interface ApplicabilityOverrideRecord {
  datastore_id: string;                    // FK to InventoryDatastoreRecord.id
  framework_id: 'ferpa' | 'coppa' | 'glba' | 'ccpa' | 'ny-shield' | 'gdpr';
  override_applies: 'true' | 'false';      // operator forces the decision
  justification: string;                   // free-text; signed audit log; min 32 chars
  operator_user_id: string;
  created_at: string;
  expires_at: string;                      // overrides MUST expire (default 1 year)
}

// Read from U.U1 catalog: cloud-evidence/data/privacy-frameworks/<framework>.json
interface PrivacyFrameworkRule {
  framework_id: 'ferpa' | 'coppa' | 'glba' | 'ccpa' | 'ny-shield' | 'gdpr';
  framework_name: string;                  // e.g. "Family Educational Rights and Privacy Act"
  statute_citation: string;                // e.g. "20 U.S.C. §1232g"
  statute_url: string;
  regulation_citation: string;             // e.g. "34 CFR Part 99"
  regulation_url: string;
  data_class_triggers: string[];           // e.g. ["student-pii", "student-pii.directory-information"]
  customer_type_triggers: string[];        // e.g. ["educational-agency-or-institution"]
  jurisdiction_triggers: string[];         // e.g. ["us-federal"]; CCPA uses ["us-ca"]
  effective_date: string;                  // ISO 8601 — guards future-dated amendments
  last_amended: string;                    // ISO 8601
  source_pdf_sha256: string | null;        // when source pinned to local PDF
}
```

## 5. Outputs

### 5.1 Canonical signed JSON envelope

Written to `out/privacy-applicability-matrix.json`. Schema:

```typescript
interface PrivacyApplicabilityMatrixEnvelope {
  envelope_version: '1.0';
  run_id: string;                          // ULID
  emitted_at: string;                      // ISO 8601 UTC
  csp_uei: string;                         // from org-profile
  csp_name: string;                        // from org-profile
  inventory_run_id: string;                // pinned to the LOOP-INV-S run consumed
  catalog_version: string;                 // pinned U.U1 catalog version
  rows: PrivacyApplicabilityRow[];
  signature: {
    algorithm: 'ed25519';
    key_id: string;                        // KMS resource arn
    signed_at: string;
    signature_b64: string;
  };
  rfc3161_timestamp?: {
    tsa_url: string;
    token_b64: string;
    status: 'attached' | 'pending';
  };
  provenance: {
    inventory_path: string;                // out/inventory.json
    inventory_sha256: string;
    catalog_path: string;                  // cloud-evidence/data/privacy-frameworks/
    catalog_sha256: string;
    tracker_db_snapshot_id: string;
  };
}

interface PrivacyApplicabilityRow {
  row_id: string;                          // ULID
  datastore_id: string;                    // FK to inventory
  framework_id: 'ferpa' | 'coppa' | 'glba' | 'ccpa' | 'ny-shield' | 'gdpr';
  applies: 'true' | 'false' | 'requires-operator-input';
  decision_inputs: {
    data_class: string | null;
    data_class_fine: string | null;
    customer_attribution: string | null;
    customer_type: string[] | null;
    resident_jurisdictions: string[] | null;
    catalog_rule_id: string;
    operator_override: ApplicabilityOverrideRecord | null;
  };
  citation_chain: Array<{
    statute_citation: string;
    statute_url: string;
    paragraph_pinned: string;              // e.g. "20 U.S.C. §1232g(a)(4)(A)"
    accessed_date: '2026-06-07';
  }>;
  decision_input_sha256: string;           // deterministic replay digest
  reasoning_note: string;                  // 1-3 sentences for the GC's review
}
```

### 5.2 `.docx` / `.pdf` rendering (General Counsel attestation pack)

Layout:

1. Cover page: CSP name + UEI + run_id + emitted_at + total
   `(datastores × frameworks)` cell count + counts of
   true / false / requires-operator-input.
2. Executive table: framework_id × datastore_count breakdown.
3. Per-framework section (6 sections, one per framework):
   - Statute + regulation citation in the header.
   - Table of all `applies: true` datastores with the decision-inputs
     summarized.
   - Subsection of `applies: requires-operator-input` rows (red-flagged
     for GC action before the next run).
4. Appendix A: signed audit log of every operator override consumed.
5. Appendix B: SHA-256 of the JSON envelope, link to the local file
   path, link to the RFC 3161 timestamp token.

## 6. Algorithm / Steps

Phase A — load:

1. Validate orchestrator flag `--privacy-applicability-matrix` or env
   `CLOUD_EVIDENCE_PRIVACY_APPLICABILITY_MATRIX` is set; otherwise the
   slice is skipped without error.
2. Read `out/inventory.json`. Verify schema version is
   `>= inv-1.4` (the version that introduced the `tags.data_class`
   field per LOOP-INV-S R2). On mismatch, exit code 2 with
   `InventoryVersionTooOldError`.
3. Read every catalog file under
   `cloud-evidence/data/privacy-frameworks/*.json`, validate against
   the U.U1 schema, and build the in-memory rule map.
4. Read tracker DB tables `customer_jurisdictions` and
   `privacy_applicability_overrides`. SHA-256 the JSON projection of
   each so the envelope can carry deterministic provenance.

Phase B — classify (per datastore × per framework):

5. For each `InventoryDatastoreRecord` in the inventory:
   - 5.a — resolve `customer_attribution`: if the tag is present, look
     up the `CustomerJurisdictionRecord`; if absent, the datastore is
     treated as a *shared / multi-tenant* asset and the
     classifier walks all distinct customers attributed to any
     tenant-id that touches this datastore (looked up via the
     LOOP-INV-S `attributions[]` field).
   - 5.b — read `tags.data_class` and `tags.data_class_fine`. Resolve
     against the catalog's `data_class_triggers` list.
6. For each framework in the catalog:
   - 6.a — check operator override first. If present and non-expired:
     emit row with `applies = override_applies`,
     `operator_override = <record>`, citation chain still attached.
   - 6.b — if the `data_class` is null AND the datastore is not flagged
     `contains-pii-unspecified`: emit
     `applies: false`, with the reasoning_note noting the absence of
     any PII signal.
   - 6.c — if the `data_class` is in the framework's
     `data_class_triggers` AND the joined `customer_type` is in
     `customer_type_triggers` AND the joined `resident_jurisdictions`
     intersects `jurisdiction_triggers`: emit `applies: true`.
   - 6.d — if any one of the three triggers matches but at least one
     other is missing or ambiguous (e.g. `data_class` is the broad
     `contains-pii-unspecified` rather than a refined class): emit
     `applies: requires-operator-input`.
   - 6.e — otherwise: emit `applies: false`.
7. For each emitted row compute `decision_input_sha256` as
   `sha256(canonical_json(decision_inputs))`.

Phase C — emit + sign:

8. Compose the envelope; sign with Ed25519 via `core/sign.ts`.
9. Request RFC 3161 TST via `core/timestamp.ts`. On TSA failure, emit
   with `status: 'pending'` and schedule a retry job (same retry
   pattern as W.W3 §9.4).
10. Write `out/privacy-applicability-matrix.json` + `.docx` + `.pdf`.
11. Update `out/inventory-coverage.json`: for every datastore that has
    at least one `applies: requires-operator-input` row, emit a
    `coverage:miss` line naming the datastore + framework_id + missing
    input field (`data_class`, `customer_type`, `resident_jurisdictions`).
12. Write the tracker DB row (`privacy_applicability_runs` table) with
    run_id, signed envelope path, count of rows, and the SHA-256 of
    the envelope. Surfaces in tracker UI.

REO compliance: every emitted row traces to a real inventory record + a
real tracker-DB customer attestation + a real catalog rule. No invented
applicability. No silent fallback. Any missing input surfaces as
`requires-operator-input`.

## 7. Files to create / modify

All paths absolute under `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/`.

Created:

- `core/data-subject-mapper.ts` — the main classifier module; exports
  `mapDatastoreToFrameworks(record, catalog, jurisdictions, overrides)`.
- `core/pii-classifier.ts` — resolves a raw `data_class` tag (or
  `data_class_fine`) against the catalog's data-class taxonomy;
  exports `classifyDataClass(tag, catalog)` returning the canonical
  data-class node + the set of frameworks that trigger on it.
- `core/jurisdiction-resolver.ts` — joins `customer_attribution` tag →
  `customer_jurisdictions` table; exports
  `resolveCustomerJurisdictions(customer_attribution, tracker_db)`
  returning `{ customer_type[], resident_jurisdictions[] }`.
- `core/privacy-applicability-emitter.ts` — composes the envelope;
  signs; writes JSON / `.docx` / `.pdf`.
- `tracker/migrations/2026-06-07-add-customer-jurisdictions.sql` —
  schema for the `customer_jurisdictions` and
  `privacy_applicability_overrides` and `privacy_applicability_runs`
  tables (tracker SQLite).
- `tracker/api/customer-jurisdictions.ts` — REST endpoints (GET /
  POST / PUT / DELETE) for the operator UI to maintain the
  customer-jurisdiction metadata.
- `tracker/web/CustomerJurisdictionsPage.tsx` — the operator UI form.
- `test/data-subject-mapper.test.ts` — Jest test specs (see §8).
- `test/pii-classifier.test.ts` — Jest test specs.
- `test/jurisdiction-resolver.test.ts` — Jest test specs.
- `test/fixtures/privacy/inventory-mixed-datastores.json` — fixture.
- `test/fixtures/privacy/customer-jurisdictions.json` — fixture.
- `test/fixtures/privacy/expected-applicability-matrix.json` —
  expected output.

Modified:

- `orchestrator.ts` — register `--privacy-applicability-matrix` flag;
  dispatch into the new emitter; pipe coverage diagnostics.
- `core/ksi-map.ts` — register the new emitter under the
  privacy-cross-framework family.
- `docs/STATUS.md` — add U.U2 row.
- `docs/loops/LOOP-U-SPEC.md` — flip U.U2 status row (on completion).
- `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md` — add Unreleased
  entry on completion.

## 8. Test specifications

Minimum 15 specs. Every fixture file is real JSON committed under
`test/fixtures/privacy/`.

| id | scenario | fixture path | expected | acceptance |
|----|----------|--------------|----------|-----------|
| U.U2-T01 | S3 bucket tagged `student-pii`, customer attributed to an `educational-agency-or-institution` | inventory-mixed-datastores.json | FERPA row `applies: true`; COPPA / GLBA / CCPA / SHIELD / GDPR rows `applies: false` | exit 0; SHA-256 of envelope deterministic across 3 runs |
| U.U2-T02 | RDS instance tagged `child-pii-under-13`, customer `directs-services-to-children-under-13` | inventory-mixed-datastores.json | COPPA row `applies: true`; others `false` | exit 0; row carries the verbatim §6501(8) citation |
| U.U2-T03 | DynamoDB table tagged `npi-financial`, customer `financial-institution` | inventory-mixed-datastores.json | GLBA row `applies: true`; others `false`; reasoning_note cites 16 CFR §314.1(b) | exit 0 |
| U.U2-T04 | BigQuery dataset tagged `pii-california-resident`, customer `general-commercial` with `resident_jurisdictions: ['us-ca']` | inventory-mixed-datastores.json | CCPA row `applies: true`; others `false` | exit 0 |
| U.U2-T05 | Azure Blob container tagged `pii-ny-resident.ssn`, customer `resident_jurisdictions: ['us-ny']` | inventory-mixed-datastores.json | NY SHIELD row `applies: true`; reasoning_note cites §899-bb(1)(b) | exit 0 |
| U.U2-T06 | GCS bucket tagged `pii-eu-data-subject`, customer `offers-goods-or-services-to-eu-data-subjects` | inventory-mixed-datastores.json | GDPR row `applies: true`; reasoning_note cites Article 3(2)(a) | exit 0 |
| U.U2-T07 | Datastore with NO `data_class` tag AND NOT flagged `contains-pii-unspecified` | inventory-no-pii.json | ALL six frameworks `applies: false` | exit 0; no `requires-operator-input` rows |
| U.U2-T08 | Datastore tagged `contains-pii-unspecified` (operator acknowledges PII but no class) | inventory-unrefined-pii.json | ALL six frameworks `applies: requires-operator-input` | exit 0; coverage:miss line emitted per row |
| U.U2-T09 | Datastore tagged `student-pii` BUT no `customer_attribution` AND no `attributions[]` join | inventory-orphan-pii.json | FERPA row `applies: requires-operator-input` (jurisdictional join unresolved) | coverage:miss line emitted |
| U.U2-T10 | Operator override flips FERPA to `false` with valid justification | inventory-mixed-datastores.json + overrides-ferpa-false.json | FERPA row `applies: false`; row carries the override record | exit 0; audit log entry written |
| U.U2-T11 | Operator override has expired (`expires_at` in the past) | inventory-mixed-datastores.json + overrides-expired.json | Override ignored; classifier proceeds as if absent; emit a `coverage:miss` line for the expired override | exit 0 |
| U.U2-T12 | Multi-tenant datastore (e.g. shared S3 bucket) with 3 distinct attributions; one CA, one NY, one EU | inventory-multitenant.json | CCPA + NY SHIELD + GDPR rows `applies: true` (union across attributions) | exit 0 |
| U.U2-T13 | Inventory schema version `inv-1.3` (too old; missing `tags.data_class`) | inventory-old-schema.json | Exit code 2 with `InventoryVersionTooOldError` | clear error message; no envelope written |
| U.U2-T14 | Catalog file corrupted (invalid JSON) | corrupted-catalog/ferpa.json | Exit code 2 with `CatalogValidationError`; named file reported | no envelope written |
| U.U2-T15 | Tracker DB unavailable (simulated connection failure) | inventory-mixed-datastores.json | Exit code 2 with `TrackerDbUnavailableError`; no envelope written; retry hint in error | clear error |
| U.U2-T16 | Ed25519 signing key missing | inventory-mixed-datastores.json | Exit code 2 with `KmsKeyUnavailableError` | clear error |
| U.U2-T17 | TSA unreachable (simulated TSA timeout) | inventory-mixed-datastores.json | Envelope written with `rfc3161_timestamp.status: 'pending'`; retry job scheduled | exit 0; warning emitted |
| U.U2-T18 | Two consecutive runs with identical inputs produce identical `decision_input_sha256` for every row | inventory-mixed-datastores.json | Deterministic digest | exit 0 |
| U.U2-T19 | Catalog version pinned in envelope matches `cloud-evidence/data/privacy-frameworks/VERSION` | inventory-mixed-datastores.json | Envelope `catalog_version` equals the on-disk VERSION file | exit 0 |
| U.U2-T20 | `.docx` rendering opens cleanly in Microsoft Word + LibreOffice; tables enumerate every framework | inventory-mixed-datastores.json | Manual QA OK (CI proxy: `unoconv` smoke test passes) | exit 0 |

## 9. Risks

### R-U.U2-1 — Operator misclassifies the customer type (e.g. forgets to flag a school district as `educational-agency-or-institution`)

**Impact.** Critical — FERPA would be silently marked `applies: false`
even though the datastore carries student records. Downstream U.U3 and
U.U5 would skip the affected customer. 3PAO finding.

**Mitigation.** The customer-jurisdiction attestation form requires
annual re-attestation (the `expires_at` field on the
`CustomerJurisdictionRecord`). The tracker UI shows a red banner 30
days before expiry. The CHANGELOG entry for U.U2 instructs the
operator to schedule an annual GC review. Additionally, U.U2 emits a
"jurisdiction-uncovered" diagnostic for any customer whose record is
older than 11 months, even if not yet expired.

### R-U.U2-2 — Data-class tag drift (operator renames `student-pii` to `student_pii` in some buckets)

**Impact.** High — the catalog rule would not match the renamed tag;
the classifier would emit `applies: requires-operator-input` (correct
fail-safe) but flooding the GC's queue. Productivity drag, not a
compliance gap.

**Mitigation.** `core/pii-classifier.ts` carries a small alias map
(operator-maintainable JSON file
`cloud-evidence/data/privacy-frameworks/data-class-aliases.json`) that
normalizes common tag-format variants (`student_pii` → `student-pii`,
`StudentPII` → `student-pii`, etc.). The alias map is signed and the
operator approves any new alias via PR review.

### R-U.U2-3 — Catalog rule regresses (a U.U1 rule update accidentally drops a `data_class_triggers` entry)

**Impact.** Critical — every datastore previously matching that entry
would silently flip from `true` to `false` on the next run.

**Mitigation.** The catalog `VERSION` file is pinned in every emitted
envelope. The `npm run check:coverage-regression` guardrail (G2) trips
on a drop in `applies: true` count across runs by more than the
configured threshold (default ≤ 5%); larger drops require operator
override with justification. A separate `npm run check:catalog-diff`
script runs in CI and posts a PR comment summarizing the rule deltas.

### R-U.U2-4 — Multi-tenant datastore over-applies frameworks (R-U.U2-1's inverse)

**Impact.** Medium — a shared S3 bucket attributed to 3 customers (one
CA, one not) would emit `CCPA: applies: true`, which is correct, but
the operator must implement CCPA-grade controls bucket-wide rather
than per-record. False-positive cost is real; false-negative cost is
worse, so the design errs toward over-applying.

**Mitigation.** The reasoning_note explicitly identifies which
attribution drove the `true` decision; the GC can decide to re-partition
the datastore (separate per-customer buckets) to scope the control set.
The matrix supports a `partitioning_recommended: true` advisory flag
on multi-tenant rows.

### R-U.U2-5 — Inventory completeness gap (LOOP-INV-S misses a datastore type, e.g. a new service)

**Impact.** Critical — a datastore not in the inventory is not in the
matrix; downstream slices skip it.

**Mitigation.** U.U2 reads `inventory-coverage.json`'s tagging-coverage
report and refuses to run if datastore-tagging coverage is below 95%
(configurable threshold). Operator must close the LOOP-INV-S gap
first. The threshold is enforced at startup (exit code 2 with
`InventoryCoverageTooLowError`), not at row time.

## 10. Open questions

- **Q1 — Aug 2026 CPPA regulations** on automated decision-making
  technology may add a new data-class trigger for "ADM personal
  information"; the U.U1 catalog will receive a new rule, but the
  exact ADP definition is REQUIRES-RESEARCH until the final
  regulation publishes.
- **Q2 — Texas TDPSA (effective July 1, 2024)** is not in the U.U1
  catalog yet; should U.U2 treat `resident_jurisdictions: ['us-tx']`
  as triggering a TDPSA placeholder row? **REQUIRES-OPERATOR-INPUT**
  for the operator's General Counsel to confirm scope.
- **Q3 — Virginia VCDPA + Colorado CPA + Connecticut CTDPA** —
  similar to Q2; the architecture supports them but the catalog
  doesn't yet ship a rule. Tracked as future U.U1 catalog work.
- **Q4 — Aggregated / de-identified data under CCPA §1798.140(e)** —
  should de-identified data with HIPAA-compliant Safe Harbor de-id be
  excluded from the matrix entirely, or marked
  `applies: requires-operator-input` until the operator attests the
  Safe Harbor steps? Default is the latter; **REQUIRES-OPERATOR-INPUT**
  for GC confirmation.
- **Q5 — GLBA jurisdictional scope** — GLBA does not have a
  state-of-residence trigger like CCPA does; the `jurisdiction_triggers`
  for GLBA is the federal baseline `us-federal`. This is correct per
  the FTC's reading; **REQUIRES-RESEARCH** to confirm against the
  May 2024 FTC enforcement guidance on cross-border financial
  customers.
- **Q6 — Application of GDPR Article 3(1) "establishment in the
  Union"** when a CSP has a single EU sales rep — does that count as
  an "establishment"? The EDPB's 2018 Guidelines 3/2018 §1.1.b
  suggest yes; **REQUIRES-OPERATOR-INPUT** for GC review.

## 11. REQUIRES-OPERATOR-INPUT fields

| Field name | Type | Validator | UI location | Failure mode if missing |
|------------|------|-----------|-------------|--------------------------|
| `customer_jurisdictions[customer_id].customer_type` | array of enums | enum validator + at least one entry required | Tracker UI → Compliance → Customer Jurisdictions | Datastores attributed to that customer emit `applies: requires-operator-input` for every framework |
| `customer_jurisdictions[customer_id].resident_jurisdictions` | array of strings | enum validator (CA / NY / federal / EU / extensible) + at least one entry required | Tracker UI → Compliance → Customer Jurisdictions | Same as above |
| `customer_jurisdictions[customer_id].expires_at` | ISO 8601 | future-dated; max 1 year from `attested_at` | Tracker UI → Compliance → Customer Jurisdictions | Expired record is treated as missing; classifier defaults to `requires-operator-input` |
| `tags.data_class` (per datastore, via cloud tag) | string | catalog-vocabulary validator | Cloud console tag editor | Datastore emits `applies: false` for all frameworks (unless `contains-pii-unspecified` flag is on, in which case `requires-operator-input`) |
| `tags.data_class_fine` (per datastore, via cloud tag) | string | catalog-vocabulary validator | Cloud console tag editor | Optional; coarse-grained classification falls back to `data_class` |
| `tags.customer_attribution` (per datastore, via cloud tag) | string | tracker-customer-id validator | Cloud console tag editor | LOOP-INV-S attribution heuristics attempt to backfill; if still null, `requires-operator-input` |
| `privacy_applicability_overrides[*].justification` | string | min 32 chars; no control chars | Tracker UI → Compliance → Applicability Overrides | Override is rejected; classifier proceeds as if absent |
| `privacy_applicability_overrides[*].expires_at` | ISO 8601 | future-dated; max 1 year | Tracker UI → Compliance → Applicability Overrides | Override is rejected |
| `org_profile.csp_uei` | string (12-char SAM UEI) | UEI regex | Settings → Org Profile | Envelope cannot be signed; exit code 2 |
| `org_profile.csp_name` | string | non-empty, no control chars | Settings → Org Profile | Same |
| `ed25519_signing_key_ref` | string (KMS resource arn) | sign-test on startup | Settings → Compliance → Signing | Orchestrator refuses to run; exit code 2 |
| `tsa_url` | string (URL) | URL validator + TSA-handshake test | Settings → Signing → Timestamp Authority | Default to the org's existing TSA; warn if missing |
| `inventory_tagging_coverage_threshold` | float ∈ [0, 1] | range check | Settings → Compliance → Privacy | Default 0.95; if datastore-tagging coverage is below threshold, orchestrator refuses to run (exit 2) |
| `data_class_alias_map_path` | string (filesystem path) | file-exists + JSON-valid | Settings → Compliance → Privacy | Default to the shipped alias map; warn if absent |
| `catalog_version_pin` | string (semver) | semver validator + matches on-disk VERSION | Settings → Compliance → Catalog | Default to on-disk VERSION; emit warning if mismatch |

Total: 15 fields. Of these, **5 are blocking** at startup (orchestrator
refuses to run), **6 are soft-fail** (emit
`requires-operator-input` rows; classifier still completes), and **4
are defaulting** (U.U2 chooses a safe default if missing).

## 12. Implementation log

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| 2026-06-07 | spec proposed | wf-uvxyz | Specification authored via FedPy workflow | TBD | — |

## 13. Completion checklist

> The following 7 steps are quoted verbatim from
> `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`. They are MANDATORY
> for every slice in every loop. NO EXCEPTIONS. Every session that ships
> a slice MUST execute this checklist atomically with the slice's own
> commit.
>
> ### Step 1 — Verify the slice is REO-compliant
> Run all three guardrails. They MUST all be green:
> ```bash
> cd cloud-evidence
> npm run typecheck      # no errors
> npm test               # 100% passing (counts must increase by the slice's new tests)
> npm run check:reo      # G1+G2+G3 all green
> ```
>
> ### Step 2 — Update STATUS.md
> Open `cloud-evidence/docs/STATUS.md` and for the slice that just shipped:
> - Change `Status` column from `pending` to `done`
> - Fill `Commit` with the PENDING commit's short hash (you'll know it after step 5)
> - Fill `Date` with today's date (ISO format YYYY-MM-DD)
> - If this was the last slice in a loop, change the loop's title section to indicate "(COMPLETE)"
> - Update the "Overall" section: increment loops-complete, change last-shipped, update next-priority
>
> ### Step 3 — Update the loop's spec doc
> Open `cloud-evidence/docs/loops/LOOP-X-SPEC.md` (where X is your loop letter).
> Find the "Status tracking" section table.
> For your slice row: status=done, commit=<hash>, date=<ISO>.
>
> ### Step 4 — Add CHANGELOG entry
> Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
> Add a new entry at the TOP of "Unreleased":
>
> ### Added — LOOP-X.XN: <Slice title>
> <2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>
>
> ### Step 5 — Commit
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
> git commit -m "LOOP-X.XN: <slice title>
> <detailed commit message describing the slice>
> Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
> ```
>
> ### Step 6 — Update commit hash in STATUS.md + loop spec
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
>
> ### Step 7 — Push
> ```bash
> git push origin main
> ```
>
> Step 8: After commit lands, append/update the slice row in STATUS.md (status -> done, commit hash, last_updated); update the loop SPEC status table; append a CHANGELOG entry; push to origin/main; verify with 'git log --oneline -3'. Only THEN is the slice closed.

REO STANDARD (Rule 1–4) governs every line of production code described
in §7. No invented citations. Apache-2.0 clean-room.
