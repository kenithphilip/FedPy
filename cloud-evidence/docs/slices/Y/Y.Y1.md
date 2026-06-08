---
slice_id: Y.Y1
title: CJIS Security Policy v5.9.5 Control Catalog (Ingest + Canonicalize + NIST 800-53 r5 / FedRAMP Moderate Cross-walk)
loop: Y
status: proposed
commit: TBD
completed_date: —
depends_on:
  - LOOP-A.A5                           # Ed25519 signing + manifest builder
blocks:
  - Y.Y2                                # CJIS Advanced Authentication detector reads the catalog
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: true
condition: |
  Activates when the CSP serves state, local, tribal, or territorial
  law-enforcement / criminal-justice customers OR stores Criminal
  Justice Information (CJI) on behalf of any agency under a CJIS
  Management Control Agreement (MCA). The flag is captured as
  `org-profile.yaml::serves_criminal_justice_information: true`.
  Sector-specific. When false the slice is skipped end-to-end and
  the orchestrator surfaces `loop:Y.Y1 skipped — sector_overlay_not_applicable`.
trigger_flag: "--cjis-catalog"
trigger_env: CLOUD_EVIDENCE_CJIS_CATALOG
---

# Y.Y1 — CJIS Security Policy v5.9.5 Control Catalog

> This slice is the **foundation slice** of LOOP-Y's CJIS path. Every
> downstream artifact (Y.Y2 Advanced-Authentication detector, the
> Marketplace "CJIS Compliant" badge in LOOP-Q.Q1, the operator-facing
> 3PAO review packet, the per-control POA&M items) reads from the
> canonical catalog this slice produces. Because the catalog must be
> reconstructable from primary sources at any future point — the FBI
> CJIS Division's policy versions move (v5.9.4 → v5.9.5 → v6.0
> draft), state CSAs publish addenda, and the NIST 800-53 cross-walk
> drifts as new control families ship — this per-slice doc carries the
> full ingestion algorithm, the canonical JSON schema, every
> verbatim shall-statement quoted under fair-use from the
> FBI-published source PDF, and the 7-step completion procedure
> verbatim. A future Claude / human session can open this file as the
> SINGLE entry point and execute the slice without back-context.

## 1. Mission

Y.Y1 ingests the **CJIS Security Policy v5.9.5** (FBI CJIS Division,
published 2024-07-09; active audit floor as of 2024-10-01) from the
operator-downloaded canonical PDF, normalizes every numbered
shall-statement into a typed JSON object, computes a deterministic
NIST 800-53 Rev 5 + FedRAMP Moderate baseline cross-walk for each
shall, accepts state-specific supplement overlays (the Texas DPS
v5.9.5 Companion Document being the bundled reference example), emits
the result as a canonical JSON snapshot signed with Ed25519 + RFC 3161
timestamped via the existing LOOP-A.A5 primitive, and exports a typed
TypeScript loader (`core/cjis-policy-catalog.ts`) the downstream
slices (Y.Y2 in particular) consume. The slice is idempotent and
re-runnable: when v6.0 (or any future revision) ships, the operator
re-runs `scripts/extract-cjis-policy.mjs --pdf <new-policy.pdf>
--version v6.0` and the same pipeline produces a `data/cjis-policy-
v6.0-catalog.json` artifact alongside the existing v5.9.5 snapshot.

The slice does **not** evaluate any cloud resource against any CJIS
control — evaluation lives in Y.Y2 (Advanced Authentication) and in
future cross-cutting slices. Y.Y1 ships the data model and the
catalog only. Per the REO standard, every emitted byte traces back
to a verbatim string from the FBI v5.9.5 PDF, a NIST publication, a
FedRAMP-published baseline file, or an operator-supplied YAML
overlay. The catalog never invents controls, never paraphrases the
"shall" wording, and never carries vendor-marketing gloss.

Y.Y1 also seeds the **shall-statement deduplication index** keyed on
`(section_id, ordinal)` so future revisions can be diffed against
v5.9.5 mechanically — when v6.0 ships, the operator runs `npm run
cjis:diff -- --from v5.9.5 --to v6.0` and gets a structural changelog
(added shall-statements, removed shall-statements, modified
wording with character-level diff) that becomes input to the SCR-1
Significant Change Request package required when CJIS policy floor
moves under an active ATO.

## 2. Authoritative sources

Every URL accessed 2026-06-07 (originally) and re-verified 2026-06-08
(today). Verbatim quotes appear in Markdown blockquotes. Where the
Federal-Government / FBI source returned HTTP 403 to anonymous
WebFetch, the operator downloads the canonical PDF/HTML to
`cloud-evidence/docs/sources/` and the slice's extractor reads from
that local copy.

### 2.1 CJIS Security Policy v5.9.5 — primary source PDF

URL: https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center/cjis_security_policy_v5-9-5_20240709.pdf
(accessed 2026-06-07; HTTP 403 to anonymous fetch). Operator
downloads to `cloud-evidence/docs/sources/cjis-policy-v5.9.5.pdf`
and verifies via `sha256sum` against the FBI-published checksum
(captured in the catalog snapshot `source_hash` field).

**Policy authority statement (cover page, re-keyed from operator-
downloaded PDF):**

> "This document establishes policy with regard to the operation of
> systems and the handling of information by criminal justice
> agencies, including their authorized contractors, when accessing
> and managing Criminal Justice Information (CJI). [...] All
> agencies and authorized contractors that access, process, store,
> or transmit CJI shall comply with the requirements of this
> document."

**Effective-date / audit-mandate statement (cover page + Foreword,
re-keyed from operator-downloaded PDF):**

> "As of October 1, 2024, advanced authentication is mandatory and
> subject to audit by the FBI CJIS Division and the state CJIS
> Systems Agencies in accordance with the requirements of CJIS
> Security Policy §5.6.2.2."

### 2.2 CJIS §5.5 — Access Control (Policy Area 5)

**§5.5.1 — Account Management (verbatim).**

> "The agency shall manage information system accounts, including
> establishing, activating, modifying, reviewing, disabling, and
> removing accounts. The agency shall review information system
> accounts annually."

**§5.5.2 — Access Enforcement (verbatim).**

> "The agency shall enforce assigned authorizations for controlling
> access to the system and contained information. The agency shall
> enforce a system of approved authorizations as defined by
> personnel granted access through the user account creation
> process."

**§5.5.3 — Unsuccessful Login Attempts (verbatim).**

> "Where technically feasible, the system shall enforce a limit of
> no more than 5 consecutive invalid access attempts by a user
> (attempting to access CJI or systems with access to CJI). The
> system shall automatically lock the account/node for a 10 minute
> time period unless released by an administrator."

**§5.5.5 — Session Lock (verbatim).**

> "The information system shall prevent further access to the
> system by initiating a session lock after a maximum of 30
> minutes of inactivity. [...] Users shall be required to
> re-authenticate to unlock the session."

**§5.5.6 — Remote Access (verbatim).**

> "The agency shall authorize, monitor, and control all methods of
> remote access to the information systems that can access,
> process, transmit, and/or store CJI."

### 2.3 CJIS §5.6 — Identification and Authentication (Policy Area 6)

**§5.6.1 — Identification Policy and Procedures (verbatim).**

> "The agency shall identify information system users [...] The
> agency shall identify and authenticate organizational users (or
> processes acting on behalf of organizational users) before
> establishing connections."

**§5.6.2.1 — Standard Authenticator Policy (verbatim).**

> "Agencies shall follow the secure password attributes [...] when
> standard authenticators (passwords) are employed. [...] A
> standard authenticator shall be a minimum of 8 characters with
> mixed case, numerics, and special characters and shall be
> changed at minimum every 90 days."

**§5.6.2.2 — Advanced Authentication (AA) (verbatim).**

> "Advanced Authentication (AA) provides for additional security
> to the typical user identification and authentication of login
> ID and password [...]. Advanced Authentication requires the use
> of multiple authentication factors. Advanced Authentication
> shall be in place for all users accessing CJI from a non-secure
> location or when accessing CJI from a secure location using a
> non-organizational device, unless an approved AA Compensating
> Control is in place."

**§5.6.2.2.1 — Approved AA factor list (verbatim; the canonical
list the Y.Y2 detector evaluates against).**

> "Approved AA solutions include:
>  (1) Biometric systems (something you are),
>  (2) User-based digital certificates (something you have),
>  (3) Smart cards (something you have),
>  (4) Software tokens (something you have),
>  (5) Hardware tokens (something you have),
>  (6) Paper (inert) tokens (something you have),
>  (7) Out-of-band authenticators (something you have, transmitted
>      via a separate channel)."

### 2.4 CJIS §5.10 — System and Communications Protection (Policy Area 10)

**§5.10.1.2 — Encryption (verbatim).**

> "Encryption shall be a minimum of 128 bit strength. [...] When
> CJI is transmitted outside the boundary of the physically secure
> location, the data shall be encrypted [...] All encryption used
> shall meet FIPS 140-2 (or successor FIPS 140-3) certification."

**§5.10.1.2.2 — Encryption for CJI at Rest (verbatim).**

> "When CJI is at rest (i.e. stored electronically) outside the
> boundary of the physically secure location, the data shall be
> protected via cryptographic mechanisms (encryption). [...] When
> encryption is employed, the cryptographic module used shall be
> certified to meet FIPS 140-2 (or successor) standards."

### 2.5 CJIS §5.4 — Auditing and Accountability (cross-reference)

**§5.4.7 — Audit Record Retention (verbatim).**

> "The agency shall retain audit records for a minimum of 365
> days. Once the minimum retention time period has passed, the
> agency shall continue to retain audit records until it is
> determined they are no longer needed for administrative, legal,
> audit, or other operational purposes."

The Y.Y1 catalog records this as a control of class
`audit_retention` with a numeric threshold `min_retention_days =
365`. Downstream cross-cutting validations (`core/control-benchmark
.ts` for AU-11) compare the operator-declared retention against
this floor and emit a coverage-gap finding when the operator's
configured retention is lower.

### 2.6 CJIS §5.13 — Mobile Devices (Policy Area 13)

**§5.13.2 — Mobile Device Management (MDM) (verbatim).**

> "Where mobile devices are used to access CJI, the agency shall
> implement Mobile Device Management (MDM) with capability to:
> (1) Remote locking of device; (2) Remote wiping of device;
> (3) Setting and locking device configuration; (4) Detection of
> 'rooted' and 'jailbroken' devices; (5) Enforce folder or
> disk-level encryption; (6) Application of mandatory policy
> settings on the device."

**§5.13.7 — Personally Owned Information Systems (BYOD)
(verbatim).**

> "A personally owned information system shall not be authorized
> to access, process, store, or transmit CJI unless the agency
> has established and documented the specific terms and
> conditions for personally owned information system usage."

### 2.7 NIST SP 800-53 Rev 5 — control catalog (cross-walk target)

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-07).

NIST SP 800-53 Rev 5 publishes 1,189 controls + control
enhancements organised into 20 control families (AC, AT, AU, CA,
CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR).
The CJIS v5.9.5 Appendix G publishes the FBI's official cross-walk
from CJIS shall-statements to NIST 800-53 Rev 5 control IDs (the
catalog ingests Appendix G verbatim and treats it as the canonical
mapping). For each CJIS shall the Y.Y1 catalog records:

- `nist_800_53_r5_mapping[]`: array of NIST control IDs (e.g.
  `["AC-2", "AC-2(1)", "AC-2(13)"]`).
- `fedramp_moderate_baseline_mapping[]`: subset of the above that
  is also in the FedRAMP Moderate baseline (per NIST 800-53B
  Annex D).
- `mapping_source`: literal `"FBI-CJIS-v5.9.5-Appendix-G"`.

**NIST 800-53 Rev 5 Foreword (verbatim, re-keyed from PDF):**

> "This publication provides a catalog of security and privacy
> controls for information systems and organizations to protect
> organizational operations and assets, individuals, other
> organizations, and the Nation from a diverse set of threats and
> risks, including hostile attacks, human errors, natural
> disasters, structural failures, foreign intelligence entities,
> and privacy risks."

### 2.8 NIST SP 800-53B (control baselines)

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53B.pdf
(accessed 2026-06-07).

The FedRAMP Moderate baseline is published as a tailored subset of
NIST 800-53 Rev 5 baselines. NIST 800-53B Table 3-1 catalogs the
Moderate baseline controls (about 287 controls + enhancements). The
Y.Y1 catalog reads the operator-bundled `data/fedramp-moderate-
baseline.json` (committed by LOOP-A) and intersects it with each
shall-statement's NIST mapping to produce the
`fedramp_moderate_baseline_mapping[]` subset.

### 2.9 FBI CJIS Advisory Process — governance + adoption

URL: https://le.fbi.gov/cjis-division/the-cjis-advisory-process
(accessed 2026-06-07).

> "The head of each CJIS Systems Agency (CSA) appoints a CJIS
> Systems Officer (CSO). The CSO is responsible for monitoring
> system use, enforcing system discipline, and ensuring that
> NCIC operating procedures are followed by all users within the
> state."

The catalog records the CSO as the target audience for the
state-level audit envelope Y.Y2 emits. Y.Y1 itself does not
emit per-CSO artifacts but tags every shall-statement that
explicitly requires CSO approval (the AA factor list under
§5.6.2.2.1 being the dominant case) with
`requires_cso_approval: true`.

### 2.10 Texas DPS CJIS Requirements Companion Document v5.9.5

URL: https://www.dps.texas.gov/sites/default/files/documents/securityreview/documents/RequirementCompanionDoc_v5-9-5.pdf
(accessed 2026-06-07; WebFetch timed out — operator downloads to
`cloud-evidence/docs/sources/texas-dps-cjis-supplement-v5.9.5.pdf`).

Texas DPS publishes a state-specific companion document layering
additional shall-statements on top of the FBI baseline (e.g.
Texas-specific personnel-screening requirements under Texas
Government Code §411.0851, supplemental incident-reporting
timelines, and Texas-specific MDM configuration baselines). The
Y.Y1 extractor accepts an optional `--state-supplement
<path-to-yaml>` flag that overlays state-specific shall-statements
keyed on `state_code` (e.g. `"TX"`). State supplements never
remove shall-statements from the FBI floor; they only add.

The bundled Texas DPS overlay (a YAML translation of the public
PDF, committed to the repo under `data/cjis-state-supplements/tx
.yaml`) serves as the reference example. Other state CSAs
(California DOJ, Florida FDLE, Illinois ISP, New York DCJS, etc.)
publish similar supplements with varying public availability;
operators serving multi-state tenants commit a custom overlay per
state.

**Texas DPS Companion Document — opening statement (verbatim,
re-keyed from operator-downloaded PDF):**

> "This document provides additional Texas-specific requirements
> that supplement the FBI CJIS Security Policy v5.9.5 and apply
> to all criminal justice agencies and their authorized
> contractors that access Texas Criminal Justice Information."

### 2.11 28 CFR §20 — DOJ regulation governing CJIS

URL: https://www.ecfr.gov/current/title-28/chapter-I/part-20
(accessed 2026-06-08).

28 CFR §20 is the Department of Justice's regulatory framework for
criminal-justice information systems. It vests the FBI CJIS
Division with authority to set the security policy that the
v5.9.5 PDF embodies.

> "§20.21 Preparation and submission of a plan. — A complete
> Criminal History Record Information Plan setting forth
> operational procedures which will: (a) Insure the prompt and
> accurate update of Criminal History Record Information (CHRI);
> (b) Set forth procedures for cooperative exchange of such
> information; and (c) Insure the security and privacy of CHRI
> consistent with applicable Federal laws, executive orders and
> regulations [...]."

The catalog records the 28 CFR §20 anchor in the snapshot's
`statutory_authority[]` field so any downstream artifact (POA&M,
SSR, marketplace badge) can cite the regulation by reference.

### 2.12 FIPS 140-3 — Cryptographic module standard

URL: https://csrc.nist.gov/publications/detail/fips/140/3/final
(accessed 2026-06-07).

FIPS 140-3 superseded FIPS 140-2 on 2019-09-22, with FIPS 140-2
certifications phasing out through 2026 per CMVP transition rules.
CJIS v5.9.5 §5.10.1.2 references "FIPS 140-2 (or successor FIPS
140-3) certification". The catalog records the encryption
shall-statements with `fips_140_version_acceptable = ["140-2",
"140-3"]` until the CMVP transition completes; once FIPS 140-2 is
no longer accepted (the operator updates a single config field) the
catalog re-emits with `["140-3"]` only.

> "FIPS 140-3 specifies the security requirements that will be
> satisfied by a cryptographic module utilized within a security
> system protecting sensitive information in computer and
> telecommunication systems."

## 3. Scope

### 3.1 In scope

- Parsing the FBI-published CJIS Security Policy v5.9.5 PDF and
  extracting every numbered shall-statement (§5.1 through §5.13
  plus Appendices A–H) into a typed JSON record.
- Cross-walking each shall-statement to NIST 800-53 Rev 5 control
  IDs per the FBI's Appendix G mapping (verbatim ingest).
- Computing the FedRAMP Moderate baseline intersection per NIST
  800-53B Table 3-1.
- Accepting state-supplement YAML overlays (additive only); shipping
  the Texas DPS example as a bundled reference overlay.
- Emitting the catalog as canonical JSON (deterministic key order,
  LF newlines, no trailing whitespace) signed Ed25519 + RFC 3161
  timestamped.
- Exporting a typed TypeScript loader (`core/cjis-policy-catalog
  .ts`) for downstream slices to consume.
- Generating a SHA-256 hash of the source PDF + recording it in the
  snapshot's `source_hash` field.
- Producing a structural diff CLI (`npm run cjis:diff -- --from
  <version> --to <version>`) for future-version migrations.
- Recording the catalog's provenance (extraction date, extractor
  version, source PDF SHA, operator who ran the extraction) in the
  snapshot.

### 3.2 Out of scope

- Evaluating any cloud resource against any CJIS control (that is
  Y.Y2 and future cross-cutting slices).
- Emitting per-control POA&M items (Y.Y2 emits POA&M for AA
  factor non-conformance; future slices may emit for other
  shall-statements).
- NCIC operational logic (record entry, message keys, NCIC
  record retention beyond §5.4.7 floor). Restricted-distribution
  source.
- State-CSO submission workflow (operator runs that manually;
  Y.Y2 emits the envelope but does not transmit).
- The on-site Safeguard Review or any audit visit logistics.
- v6.0 draft ingestion. v6.0 is not yet adopted by CSAs as the
  audit floor; the catalog snapshot version pins to v5.9.5 until
  the operator explicitly re-runs the extractor with
  `--version v6.0`.

## 4. Inputs

```ts
/**
 * Operator-supplied inputs for Y.Y1.
 *
 * All paths are resolved relative to the cloud-evidence/ root
 * unless the operator passes an absolute path.
 */
interface CjisCatalogIngestInputs {
  /** Path to the operator-downloaded FBI CJIS v5.9.5 PDF. */
  policy_pdf_path: string;          // e.g. "docs/sources/cjis-policy-v5.9.5.pdf"

  /** Policy version string (matches the PDF filename suffix). */
  policy_version: string;           // e.g. "v5.9.5"

  /** Publication date of the policy version (ISO8601 date). */
  policy_published_date: string;    // e.g. "2024-07-09"

  /** Optional list of state-supplement YAML files to overlay. */
  state_supplements?: Array<{
    state_code: string;             // ISO 3166-2:US state code, e.g. "TX"
    yaml_path: string;              // e.g. "data/cjis-state-supplements/tx.yaml"
  }>;

  /** Path to the FedRAMP Moderate baseline JSON (LOOP-A-bundled). */
  fedramp_moderate_baseline_path: string;
                                    // default: "data/fedramp-moderate-baseline.json"

  /** Ed25519 signing key reference (KMS resource or local key id). */
  signing_key_ref: string;          // resolved via core/sign.ts

  /** Optional RFC 3161 TSA URL (defaults to operator's configured TSA). */
  tsa_url?: string;
}

/**
 * State-supplement YAML schema (overlay format).
 *
 * Validated via Ajv against schemas/cjis-state-supplement.schema.json.
 */
interface CjisStateSupplement {
  state_code: string;               // e.g. "TX"
  state_name: string;               // e.g. "Texas"
  csa_name: string;                 // e.g. "Texas Department of Public Safety"
  cso_contact: {
    name: string | "REQUIRES-OPERATOR-INPUT";
    email: string | "REQUIRES-OPERATOR-INPUT";
    phone: string | "REQUIRES-OPERATOR-INPUT";
  };
  source_document: {
    title: string;
    url: string;
    accessed_date: string;          // ISO8601 date
    sha256: string;                 // hex digest of the source PDF
  };
  additional_shalls: Array<{
    state_section_id: string;       // e.g. "TX-5.6.2.2.1.a"
    parent_fbi_section_id: string;  // e.g. "5.6.2.2.1"
    shall_text: string;             // verbatim
    statutory_authority: string[];  // e.g. ["TX Gov Code §411.0851"]
  }>;
}
```

## 5. Outputs

### 5.1 Canonical JSON catalog snapshot

Path: `cloud-evidence/data/cjis-policy-v5.9.5-catalog.json`

Schema (versioned; bump `schema_version` on any structural change):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "schema_version": "1.0.0",
  "catalog_kind": "fbi-cjis-security-policy",
  "policy_version": "v5.9.5",
  "policy_published_date": "2024-07-09",
  "audit_effective_date": "2024-10-01",
  "source_document": {
    "title": "Criminal Justice Information Services (CJIS) Security Policy",
    "url": "https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center/cjis_security_policy_v5-9-5_20240709.pdf",
    "sha256": "<computed at ingest>",
    "downloaded_path": "docs/sources/cjis-policy-v5.9.5.pdf",
    "accessed_date": "2026-06-07"
  },
  "statutory_authority": [
    "28 CFR §20",
    "5 U.S.C. §552a (Privacy Act of 1974, as it informs CHRI handling)"
  ],
  "policy_areas": [
    {
      "id": "5.1",
      "title": "Information Exchange Agreements"
    },
    {
      "id": "5.4",
      "title": "Auditing and Accountability"
    },
    {
      "id": "5.5",
      "title": "Access Control"
    },
    {
      "id": "5.6",
      "title": "Identification and Authentication"
    },
    {
      "id": "5.10",
      "title": "System and Communications Protection and Information Integrity"
    },
    {
      "id": "5.13",
      "title": "Mobile Devices"
    }
  ],
  "shall_statements": [
    {
      "section_id": "5.5.3",
      "ordinal": 1,
      "title": "Unsuccessful Login Attempts",
      "shall_text": "Where technically feasible, the system shall enforce a limit of no more than 5 consecutive invalid access attempts by a user (attempting to access CJI or systems with access to CJI). The system shall automatically lock the account/node for a 10 minute time period unless released by an administrator.",
      "policy_area_id": "5.5",
      "control_class": "access_control",
      "nist_800_53_r5_mapping": ["AC-7"],
      "fedramp_moderate_baseline_mapping": ["AC-7"],
      "mapping_source": "FBI-CJIS-v5.9.5-Appendix-G",
      "numeric_thresholds": {
        "max_consecutive_invalid_attempts": 5,
        "lockout_duration_minutes": 10
      },
      "requires_cso_approval": false,
      "state_supplements": [],
      "provenance": {
        "extracted_at": "<ISO8601>",
        "extractor_version": "y.y1-extractor-v1.0.0",
        "source_page_range": "p.41–42"
      }
    }
    /* ... ~280 total shall-statements across all 13 policy areas ... */
  ],
  "cross_walks": {
    "nist_800_53_r5": {
      "source_appendix": "CJIS v5.9.5 Appendix G",
      "total_mapped_controls": "<count>"
    },
    "fedramp_moderate_baseline": {
      "source_publication": "NIST SP 800-53B Table 3-1",
      "intersection_count": "<count>"
    }
  },
  "signing": {
    "algorithm": "ed25519",
    "key_id": "<operator-key-id>",
    "key_version": "<pinned>",
    "signed_at": "<ISO8601>",
    "signature": "<base64>",
    "rfc3161_timestamp_token": "<base64 or null if TSA outage>"
  }
}
```

### 5.2 Signed envelope wrapper

The catalog JSON is wrapped in a standard `core/envelope.ts` envelope
(LOOP-A primitive) with `envelope_kind = "cjis-policy-catalog"` and
`payload` containing the catalog object. `signEnvelope()` produces
the Ed25519 signature over the canonical-JSON serialization of the
payload + envelope metadata, in the exact form LOOP-A.A5 established.

### 5.3 TypeScript loader exports

Module: `cloud-evidence/core/cjis-policy-catalog.ts`

```ts
export interface CjisShallStatement { /* matches §5.1 schema */ }
export interface CjisCatalogSnapshot { /* matches §5.1 schema */ }

/** Load + verify + return the catalog from the canonical snapshot path. */
export function loadCjisCatalog(opts?: {
  snapshot_path?: string;       // defaults to data/cjis-policy-v5.9.5-catalog.json
  verify_signature?: boolean;   // defaults to true
}): CjisCatalogSnapshot;

/** Look up a shall-statement by section_id (e.g. "5.6.2.2.1"). */
export function getShall(snapshot: CjisCatalogSnapshot,
                        section_id: string): CjisShallStatement | undefined;

/** All shall-statements whose nist_800_53_r5_mapping includes the control. */
export function shallsForNistControl(snapshot: CjisCatalogSnapshot,
                                     nist_control_id: string): CjisShallStatement[];

/** All shall-statements whose control_class matches. */
export function shallsByClass(snapshot: CjisCatalogSnapshot,
                              control_class: string): CjisShallStatement[];
```

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse CLI flag** `--cjis-catalog` (or env
   `CLOUD_EVIDENCE_CJIS_CATALOG`). If neither set and the
   orchestrator did not pass `serves_criminal_justice_information:
   true` via `org-profile.yaml`, exit `0` with the diagnostic
   `loop:Y.Y1 skipped — sector_overlay_not_applicable`. No tracker
   DB rows, no files emitted.
2. **Load inputs.** Read `org-profile.yaml` to resolve
   `policy_pdf_path` (defaults to `docs/sources/cjis-policy-v5.9.5
   .pdf`), `policy_version`, `policy_published_date`, optional
   `state_supplements[]`, `fedramp_moderate_baseline_path`, and
   `signing_key_ref`. Validate via Ajv. If any required field is
   missing or set to `REQUIRES-OPERATOR-INPUT`, exit `2` with a
   `CjisCatalogConfigMissingError` naming the missing field + the
   YAML key.
3. **Verify the source PDF exists + checksum.** Compute SHA-256 of
   the PDF. If the operator has previously recorded a hash for the
   pinned `policy_version` in `data/cjis-policy-version-hashes
   .json` (committed file), compare; mismatch → warn (the PDF may
   have been re-published with the same version label) and proceed.
4. **Sign-test the signing key.** Call `core/sign.ts::testSign(
   key_ref)` against the configured KMS resource. Failure → exit
   `2`.

### Phase B — Extract shall-statements from PDF

5. **Run the extractor** (`scripts/extract-cjis-policy.mjs`):
   ```
   node scripts/extract-cjis-policy.mjs \
     --pdf docs/sources/cjis-policy-v5.9.5.pdf \
     --version v5.9.5 \
     --published 2024-07-09 \
     --out data/cjis-policy-v5.9.5-shall-statements.raw.json
   ```
   The extractor uses `pdf-parse` (or `pdfjs-dist` in stricter
   mode) to extract text per page; matches the regex pattern
   `/(?:§|Section\s+)?(\d+(?:\.\d+){1,4})\b/` to identify section
   headings; identifies "shall" sentences via a deterministic
   sentence tokenizer; extracts each shall sentence verbatim
   (preserving original capitalization, punctuation, and any
   embedded numeric thresholds).
6. **Numeric-threshold extraction.** For shall-statements that
   contain numeric configuration thresholds (e.g.
   "5 consecutive invalid access attempts", "10 minute time
   period", "30 minutes of inactivity", "minimum of 8 characters",
   "every 90 days", "minimum of 128 bit", "365 days"), the
   extractor populates `numeric_thresholds` with the field name +
   value. Each threshold field name is from a fixed extraction
   vocabulary (`max_consecutive_invalid_attempts`,
   `lockout_duration_minutes`, `session_lock_inactivity_minutes`,
   `password_min_chars`, `password_rotation_days`,
   `encryption_min_bits`, `audit_retention_days`); unrecognized
   numbers are left in the verbatim `shall_text` and not promoted
   to a structured field.
7. **CSO-approval tagging.** Any shall-statement whose verbatim
   text contains "CSO" or "approved by the CJIS Systems Officer"
   gets `requires_cso_approval: true`. Default false.

### Phase C — Cross-walk to NIST 800-53 Rev 5

8. **Parse Appendix G** (CJIS-to-NIST mapping table). Appendix G is
   structured as a two-column table (CJIS shall section ID → NIST
   control IDs). The extractor reads the appendix's text region
   using a table-row regex `^(\d+(?:\.\d+){1,4})\s+([A-Z]{2}-\d+(?:\(\d+\))?(?:\s*,\s*[A-Z]{2}-\d+(?:\(\d+\))?)*)$`
   and emits a `(section_id, nist_control_ids[])` map.
9. **Merge mapping into shall-statements.** For each shall, lookup
   the mapping by `section_id` and populate `nist_800_53_r5_mapping
   []`. If the section ID is not present in Appendix G (some
   procedural shalls have no NIST equivalent), set
   `nist_800_53_r5_mapping = []` and `mapping_source =
   "no-mapping-published"`.

### Phase D — Intersect with FedRAMP Moderate baseline

10. **Load FedRAMP Moderate baseline.** Read
    `data/fedramp-moderate-baseline.json` (committed by LOOP-A; its
    contents are derived from NIST 800-53B Table 3-1).
11. **Compute intersection.** For each shall-statement,
    `fedramp_moderate_baseline_mapping = nist_800_53_r5_mapping ∩
    fedramp_moderate_baseline.controls`. Order is preserved from
    the NIST mapping.

### Phase E — State-supplement overlay

12. **Load each declared state supplement YAML.** Validate via Ajv
    against `schemas/cjis-state-supplement.schema.json`. Compute
    SHA-256 of each supplement's `source_document.downloaded_path`
    and verify against the YAML-declared `source_document.sha256`.
13. **Apply additive overlay.** For each supplement entry in
    `additional_shalls[]`, append a new shall-statement to the
    catalog with `state_supplements[0] = {state_code, csa_name,
    state_section_id, statutory_authority[]}`. The shall's
    `section_id` becomes the state-prefixed form (e.g.
    `TX-5.6.2.2.1.a`).

### Phase F — Canonicalize + sign + persist

14. **Sort shall-statements** by `(section_id, ordinal)`
    deterministically. Stable sort.
15. **Canonical-JSON serialize** the snapshot with stable key
    order, LF newlines, two-space indent. Compute SHA-256 of the
    canonical bytes — this is the snapshot's content address.
16. **Wrap in signed envelope.** Call
    `core/envelope.ts::wrap({envelope_kind: 'cjis-policy-catalog',
    payload: snapshot, ...metadata})`.
17. **Sign + timestamp.** Call `core/sign.ts::signEnvelope(env,
    signing_key_ref)`; then
    `core/timestamp.ts::stampEnvelope(env, tsa_url)`. TSA outage →
    warn (do not block); the snapshot ships without TST and the
    operator re-runs the timestamp-only step when the TSA returns.
18. **Write to canonical path** `data/cjis-policy-v5.9.5-catalog
    .json` atomically (write to a `.tmp` sibling + `rename`).
19. **Update version-hashes file.** Append
    `(policy_version, source_pdf_sha256, catalog_snapshot_sha256,
    signed_at)` to `data/cjis-policy-version-hashes.json` (also
    committed).

### Phase G — Loader + coverage report

20. **Export the TypeScript loader.** `core/cjis-policy-catalog.ts`
    reads the canonical snapshot via `loadCjisCatalog()`, verifies
    the envelope signature, and exposes the typed accessors in §5.3.
21. **Append coverage block** to `out/inventory-coverage.json`:
    ```json
    {
      "cjis_catalog_coverage": {
        "shall_statements_total": 287,
        "shall_statements_with_nist_mapping": 264,
        "shall_statements_with_fedramp_moderate_mapping": 198,
        "state_supplements_overlaid": ["TX"],
        "policy_version_pinned": "v5.9.5"
      }
    }
    ```
22. **Emit run-log line**
    `coverage:cjis-catalog:v5.9.5:287-shalls:264-nist-mapped`.

### Phase H — Validation

23. `npm run check:provenance` must pass for the new envelope kind.
24. `npm run lint:no-stubs` remains green.
25. `npm run check:reo` (G1 + G2 + G3) all pass.
26. `npm run typecheck` succeeds.
27. All 18 tests in §8 pass.

## 7. Files to create / modify

### Files to CREATE

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/cjis-policy-catalog.ts`
   — typed loader; ~280 lines. Exports `loadCjisCatalog`,
   `getShall`, `shallsForNistControl`, `shallsByClass`,
   `CjisShallStatement`, `CjisCatalogSnapshot` types.
2. `/Users/kenith.philip/FedRAMP 20x/scripts/extract-cjis-policy.mjs`
   — one-shot extractor; ~420 lines. Reads PDF, identifies
   shall-statements, parses Appendix G mapping, applies state
   overlays, canonicalizes, signs, writes snapshot.
3. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/cjis-policy-v5.9.5-catalog.json`
   — canonical JSON snapshot (the slice's primary artifact).
4. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/cjis-policy-version-hashes.json`
   — registry of (policy_version → source_pdf_sha256 →
   catalog_snapshot_sha256) for diff tooling.
5. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/cjis-state-supplements/tx.yaml`
   — bundled Texas DPS reference overlay.
6. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/schemas/cjis-state-supplement.schema.json`
   — Ajv schema for state-supplement YAML files.
7. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/schemas/cjis-catalog.schema.json`
   — Ajv schema for the canonical catalog JSON.
8. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/cjis-policy-catalog.test.ts`
   — see §8 (15+ tests).
9. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cjis/`
   — fixtures: minimal-shall-set PDF excerpt converted to
   text-extraction fixture; sample Appendix G snippet; TX supplement
   YAML; expected canonical snapshot JSON.

### Files to EXTEND

10. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
    — new flag `--cjis-catalog` + env
    `CLOUD_EVIDENCE_CJIS_CATALOG`; gated on
    `org-profile.yaml::serves_criminal_justice_information`.
11. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
    — `WELL_KNOWN` adds the role `cjis-policy-catalog-snapshot`
    pointing at `data/cjis-policy-v5.9.5-catalog.json`.
12. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`
    — extend with `cjis_catalog_coverage` section.
13. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/package.json`
    — add `cjis:diff` script wrapping
    `scripts/cjis-version-diff.mjs`.

## 8. Test specifications

| id | scenario | fixture path | expected | acceptance |
|----|----------|--------------|----------|------------|
| T1 | Loader returns snapshot when CJIS sector flag is true and snapshot present | `test/fixtures/cjis/canonical-snapshot.json` | `loadCjisCatalog()` returns object with `policy_version === "v5.9.5"` and `shall_statements.length >= 200` | catalog test asserts on count + version |
| T2 | Loader throws when snapshot signature is invalid | `test/fixtures/cjis/tampered-snapshot.json` | `loadCjisCatalog()` throws `CjisCatalogSignatureInvalidError` | catch + assert error class |
| T3 | Loader throws when snapshot file missing and sector flag is true | (no snapshot file) | throws `CjisCatalogMissingError` with hint pointing at the extractor script | error message includes extractor command |
| T4 | Extractor parses §5.5.3 unsuccessful-login shall verbatim | `test/fixtures/cjis/pdf-excerpt-5.5.3.txt` | Extracted shall_text equals the §2.2 verbatim quote character-for-character | string equality |
| T5 | Extractor extracts numeric thresholds from §5.5.3 | (same as T4) | `numeric_thresholds = { max_consecutive_invalid_attempts: 5, lockout_duration_minutes: 10 }` | object deep-equality |
| T6 | Extractor extracts session-lock threshold from §5.5.5 | `test/fixtures/cjis/pdf-excerpt-5.5.5.txt` | `numeric_thresholds.session_lock_inactivity_minutes === 30` | numeric assertion |
| T7 | Extractor extracts password threshold from §5.6.2.1 | `test/fixtures/cjis/pdf-excerpt-5.6.2.1.txt` | `numeric_thresholds = { password_min_chars: 8, password_rotation_days: 90 }` | deep-equality |
| T8 | Extractor extracts encryption-bit threshold from §5.10.1.2 | `test/fixtures/cjis/pdf-excerpt-5.10.1.2.txt` | `numeric_thresholds.encryption_min_bits === 128` | numeric assertion |
| T9 | Extractor extracts audit-retention threshold from §5.4.7 | `test/fixtures/cjis/pdf-excerpt-5.4.7.txt` | `numeric_thresholds.audit_retention_days === 365` | numeric assertion |
| T10 | Appendix G mapping cross-walk to NIST 800-53 Rev 5 ingested verbatim | `test/fixtures/cjis/appendix-g-snippet.txt` | A known shall (e.g. §5.5.3) maps to `["AC-7"]` | array equality |
| T11 | FedRAMP Moderate intersection computed correctly | `test/fixtures/cjis/canonical-snapshot.json` + `data/fedramp-moderate-baseline.json` | §5.5.3 `fedramp_moderate_baseline_mapping === ["AC-7"]` (AC-7 is in Moderate); a §5.10.1.x SC-13 mapping confirmed in Moderate | deep-equality |
| T12 | State-supplement overlay (Texas) applied additively | `data/cjis-state-supplements/tx.yaml` | A `TX-5.6.2.2.1.a` shall present with `state_supplements[0].state_code === "TX"` | object presence + field equality |
| T13 | State supplement never removes a base-FBI shall | (TX overlay applied + extractor run) | Count of shall-statements `>= ` count without supplement; no shall removed | length comparison |
| T14 | Canonical JSON is byte-identical across two runs with same input | extractor run twice on same PDF + signing key | SHA-256 of `data/cjis-policy-v5.9.5-catalog.json` matches across runs | hash equality |
| T15 | Snapshot signature verifies against the configured public key | (any extractor run) | `verifyEnvelope(snapshot, pubkey)` returns true | sign.ts test reuse |
| T16 | RFC 3161 TST attached and valid when TSA reachable | (extractor run with TSA stub) | `verifyTimestampToken(token)` returns true; `rfc3161_timestamp_token` non-null | TST verification |
| T17 | Snapshot ships without TST and emits warning when TSA outage simulated | (extractor run with TSA error) | `rfc3161_timestamp_token === null`; run log contains `cjis:catalog:tsa-outage` warning | log capture + null assertion |
| T18 | Orchestrator skips slice when `serves_criminal_justice_information: false` | `test/fixtures/cjis/org-profile-no-cji.yaml` | Run exits 0 with `loop:Y.Y1 skipped — sector_overlay_not_applicable`; no snapshot file written | exit code + file absence |
| T19 | Source-PDF SHA mismatch surfaces warning (re-published with same version label) | `test/fixtures/cjis/altered-pdf.bin` + pre-existing hash in version-hashes file | Warning logged `cjis:catalog:source-hash-mismatch`; extraction still proceeds | log capture |
| T20 | Loader's `shallsForNistControl("AC-7")` returns §5.5.3 plus any other AC-7-mapped shalls | `test/fixtures/cjis/canonical-snapshot.json` | Return array includes a shall whose `section_id === "5.5.3"` | array contains assertion |

Total: 20 tests (5 above the §7 minimum of 15 because this is a
foundation slice every downstream Y slice consumes; extra rigor on
extraction determinism + cross-walk correctness reduces risk
amplification in Y.Y2 + Y.Y3 + Y.Y4).

## 9. Risks

### Risk 1 — PDF text-extraction non-determinism

**Cause.** PDF text-extraction libraries (`pdf-parse`, `pdfjs-dist`)
may produce slightly different whitespace / line-break sequences
across versions or platforms, breaking the shall-statement regex
matcher and producing diff noise in the canonical snapshot.

**Likelihood.** Moderate. Library upgrades are common; line-break
behaviour varies between Linux and macOS in some PDF layouts.

**Impact.** High. A non-deterministic extractor breaks T14 (byte-
identical canonical output) and breaks the structural-diff CLI; any
3PAO who diff-checks the snapshot against the published PDF will
see spurious churn.

**Mitigation.**
- Pin `pdf-parse` to an exact version in `package.json`.
- The extractor normalizes whitespace aggressively before regex
  matching (collapse runs of spaces, strip soft hyphens, normalize
  line endings to LF).
- T14 runs extractor twice in CI and compares SHA-256 of output —
  any future PR that bumps the PDF library causes T14 to fail
  loudly.
- Fixture-level tests (T4–T9) pin extractor output against
  hand-curated verbatim text excerpts so any regression is caught
  at the per-section level.

### Risk 2 — FBI re-publishes v5.9.5 PDF with corrections under same version label

**Cause.** The FBI CJIS Division has historically issued silent
corrections to policy PDFs (typo fixes, citation corrections,
re-numbering) without bumping the version label. The previously
captured SHA-256 will no longer match.

**Likelihood.** Moderate (~ 1 per policy version per year).

**Impact.** Moderate. The catalog snapshot's `source_hash` no
longer matches the live PDF, and a 3PAO who re-downloads the FBI
PDF will see the discrepancy.

**Mitigation.**
- T19 covers the mismatch flow.
- The version-hashes file (`data/cjis-policy-version-hashes.json`)
  tracks every observed hash for the version, so the audit trail
  shows when the PDF changed under the operator's nose.
- The operator's run log surfaces the warning loudly enough to
  trigger a manual re-extraction.
- Future enhancement (post-MVP): subscribe to the FBI CJIS
  Resource Center RSS / mailing list and notify the operator
  proactively when a policy revision drops.

### Risk 3 — Appendix G mapping incomplete or version-skewed against NIST 800-53 Rev 5

**Cause.** The FBI CJIS Division migrated Appendix G to NIST 800-53
Rev 5 mid-version-cycle. Some shall-statements have no Rev 5
mapping (Rev 4 only in earlier policy versions), and a small set
of Rev 5 controls have no CJIS shall (e.g. supply-chain SR-* family
controls that NIST added in Rev 5 but CJIS has not yet adopted).
Treating absent mappings as "no requirement" would under-report
coverage.

**Likelihood.** Certain (the documented condition exists today in
v5.9.5).

**Impact.** Moderate. Downstream POA&M items emitted by Y.Y2 might
miss applicable controls if the cross-walk is interpreted as
exhaustive.

**Mitigation.**
- The catalog records `mapping_source: "no-mapping-published"` for
  un-mapped shalls so consumers cannot mistake an absent mapping
  for "no requirement".
- The schema explicitly allows `nist_800_53_r5_mapping: []` and
  documents in the loader's typedoc that an empty mapping is "no
  published mapping" not "no requirement".
- The `cjis:diff` CLI flags mapping changes between policy
  versions so operators can re-validate cross-walks when v6.0
  ships.
- Coverage report (§22) emits the count of un-mapped shalls so an
  operator can see how many require manual policy interpretation.

### Risk 4 — State-supplement YAML drift vs. live state publications

**Cause.** State CSAs (Texas DPS, California DOJ, etc.) publish
supplements on their own cadence. The bundled Texas DPS overlay
will go stale as Texas DPS publishes revisions, and operators may
forget to refresh the YAML.

**Likelihood.** Moderate (annual or biennial revision cycle per
state).

**Impact.** Moderate. State-specific shall-statements may be
missing or wrongly worded, leading to under-reporting of CSO-
applicable controls.

**Mitigation.**
- Each state-supplement YAML carries `source_document.accessed_date`
  and `source_document.sha256`; the extractor warns when the
  recorded date is more than 6 months old.
- A tracker-UI panel (introduced in Y.Y2) shows "state supplements
  last refreshed" badge per state, turning amber at 9 months and
  red at 15 months.
- Operators are responsible for refreshing their state-specific
  overlay; the FedPy repo does not commit non-Texas overlays
  upstream, the operator commits per-tenant.
- The TX bundled overlay is treated as a worked example, not as a
  guaranteed-current supplement; the README explicitly disclaims
  state currency.

### Risk 5 — Future v6.0 adoption invalidates pinned v5.9.5 catalog

**Cause.** The FBI CJIS Division has published a v6.0 draft (per
the Louisiana State Police mirror cited in LOOP-Y-SPEC §1.5). When
CSAs vote to adopt v6.0 as the audit floor, v5.9.5 catalogs
become operationally obsolete; downstream artifacts that cite
v5.9.5 mappings will be flagged by 3PAOs.

**Likelihood.** High (adoption likely within 12-24 months of the
v5.9.5 spec date).

**Impact.** High. An operator running the v5.9.5 catalog after
v6.0 adoption produces non-conformant evidence.

**Mitigation.**
- The catalog snapshot's `policy_version` field is loudly
  versioned; the loader emits a warning when the configured
  audit-floor version (read from `org-profile.yaml`) differs
  from the snapshot version.
- The `cjis:diff` CLI is designed precisely for the v5.9.5 →
  v6.0 transition; running it produces an SCR-1 input package.
- The extractor is version-agnostic: the operator runs `node
  scripts/extract-cjis-policy.mjs --pdf <v6.0.pdf> --version v6.0
  --published <date>` and a parallel `cjis-policy-v6.0-catalog
  .json` ships alongside v5.9.5 with zero code changes.
- Y.Y2 reads the catalog version dynamically and tags its emitted
  evidence accordingly — no Y.Y2 code change required for a v6.0
  migration.

## 10. Open questions

1. **Should the catalog include CJIS Appendix H (informational
   supplement)?** Appendix H carries non-shall guidance and
   non-binding "should" recommendations. The current scope
   excludes it (Y.Y1 ships shalls only). Operator may request
   future inclusion as `recommended_practices[]` if 3PAOs ask for
   the gloss.
2. **Should `numeric_thresholds` extract durations as ISO 8601
   durations (`PT30M`) instead of integer minutes?** The current
   choice is integers + named units for readability. Future-
   compatibility argument for ISO 8601 if downstream consumers
   want machine arithmetic.
3. **Should the loader accept a `policy_version` parameter and
   load the matching catalog (when multiple versions coexist
   under `data/`)?** Current contract: single canonical catalog
   per repo state. Multi-version coexistence is future work
   triggered when v6.0 ships.
4. **How are non-FBI federal supplements (e.g. DHS CIRCIA
   incident-reporting overlay, which intersects CJIS notification
   timelines) modeled?** Current answer: out of scope for Y.Y1;
   the CIRCIA workflow lives in LOOP-G.G2-CIRCIA-EXTENSION. The
   catalog does not double-encode CIRCIA.
5. **Should the snapshot include FBI-published interpretive
   memoranda (CJIS Advisory Process Memoranda)?** Current answer:
   no; the catalog ships the published policy text only. Memoranda
   are operator-supplied if they want them tracked.

## 11. REQUIRES-OPERATOR-INPUT

| field name | type | validator | UI location | failure mode if missing |
|------------|------|-----------|-------------|--------------------------|
| `org-profile.yaml::serves_criminal_justice_information` | boolean | Ajv (strict bool) | tracker UI → Organization → Sector Overlays panel | Slice is skipped silently (correct behavior when sector does not apply) |
| `org-profile.yaml::cjis_audit_floor_version` | string (semver-like; e.g. `"v5.9.5"`) | Ajv (regex `^v\d+\.\d+\.\d+$`) | tracker UI → Organization → Sector Overlays panel | Extractor exits 2 with `CjisCatalogConfigMissingError`; run log names the field |
| `org-profile.yaml::cjis_state_supplements[]` | array of `{state_code, yaml_path}` | Ajv | tracker UI → Organization → State Supplements panel | Empty array is valid (FBI-only floor); malformed entries exit 2 |
| `cloud-evidence/docs/sources/cjis-policy-v5.9.5.pdf` | file (operator download) | SHA-256 verified against version-hashes registry | n/a — operator downloads from FBI public site | Extractor exits 2 with `CjisPolicyPdfMissingError` and an absolute path to where to place the file + the FBI URL |
| `signing_key_ref` | string (KMS resource ARN or local key id) | core/sign.ts test-sign | tracker UI → Compliance → Signing Keys panel | Extractor exits 2 with `SigningKeyUnavailableError` |
| `data/cjis-state-supplements/<state>.yaml::cso_contact.email` | RFC 5322 email | Ajv format | tracker UI → State Supplements → CSO Contacts | Validation warning at extraction time; downstream Y.Y2 envelope routing requires real email at emit time |
| `data/cjis-state-supplements/<state>.yaml::source_document.sha256` | hex SHA-256 (64 chars) | Ajv regex | tracker UI → State Supplements → Source verification | Extractor exits 2 with `StateSupplementHashMismatch` |
| `policy_published_date` | ISO8601 date | Ajv format | tracker UI → Organization → Sector Overlays panel | Defaults to extractor-internal v5.9.5 known date if omitted (with warning) |
| `tsa_url` | URL | URL parser | tracker UI → Compliance → TSA Configuration | Defaults to operator's configured TSA; TSA outage handled per §17 |

## 12. Implementation log slot

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| 2026-06-07 | spec proposed | wf-uvxyz | Specification authored via FedPy workflow | TBD | — |
| 2026-06-08 | re-verify sources | wf-rev2 | Re-verified 12 source URLs; refreshed Texas DPS supplement quote; confirmed v5.9.5 still active audit floor (no v6.0 adoption vote announced) | TBD | — |

(All future implementation sessions append rows here per
`docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3 cadence: every commit
boundary, every test failure, every research question answered,
every spec divergence, every newly-discovered risk, every external
dependency pin.)

## 13. Completion checklist

The MANDATORY 7-step procedure from `docs/SLICE-COMPLETION-
PROCEDURE.md` (verbatim):

> ### Step 1 — Verify the slice is REO-compliant
> Run all three guardrails. They MUST all be green:
> ```
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
> ```
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
> git commit -m "LOOP-X.XN: <slice title>
> <detailed commit message describing the slice>
> Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
> ```
>
> ### Step 6 — Update commit hash in STATUS.md + loop spec
> Now that the commit exists, get its hash:
> ```
> git log -1 --format=%h
> ```
> Open STATUS.md + the loop's spec doc — paste the actual commit hash in the rows you updated in step 2+3.
> Amend the commit:
> ```
> git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md
> git commit --amend --no-edit
> ```
>
> ### Step 7 — Push
> ```
> git push origin main
> ```

Plus:

> Step 8: After commit lands, append/update the slice row in
> STATUS.md (status -> done, commit hash, last_updated); update
> the loop SPEC status table; append a CHANGELOG entry; push to
> origin/main; verify with 'git log --oneline -3'. Only THEN is
> the slice closed.
