---
slice_id: T.T1
title: NIST SP 800-218 v1.1 SSDF practice catalog + 800-53 + KSI crosswalk emitter
loop: T
status: done
commit: 9bbbcd1
completed_date: 2026-06-10
applicable_conditional: any CSP delivering software to federal agencies subject to OMB M-22-18 (as amended by M-23-16 and reflected in the CISA Common Form OMB 1670-0052)
trigger_flag: "--ssdf-catalog"
trigger_env: CLOUD_EVIDENCE_SSDF_CATALOG
depends_on: []
blocks: [T.T2, T.T3, T.T5]
estimated_effort: medium (4-5 working days)
last_updated: 2026-06-10
---

# T.T1 — NIST SP 800-218 v1.1 SSDF practice catalog + 800-53 + KSI crosswalk emitter

## 1. Mission

Inventory every NIST SP 800-218 v1.1 (SSDF) practice across the four
practice groups — **Prepare the Organization (PO)**, **Protect the
Software (PS)**, **Produce Well-Secured Software (PW)**, and **Respond
to Vulnerabilities (RV)** — together with their constituent **tasks** and
the published mappings to NIST SP 800-53 Rev 5 controls. Emit a canonical
JSON catalog (Ed25519-signed + RFC 3161 timestamped) that downstream
slices T.T2 (CISA Common Form generator), T.T3 (SSDF evidence aggregator),
and T.T5 (KSI ↔ SSDF gap matrix) will consume.

T.T1 is the *foundation* slice for LOOP-T. It introduces NO evidence
collection. It is a deterministic catalog-extraction + crosswalk-emission
slice — REO-compliant by construction (every byte traces to a published
NIST source or to the operator-supplied tracker pin).

The catalog snapshot `cloud-evidence/data/ssdf-800-218-v1.1.json` ships
under version control with a frontmatter `source_pdf_sha256` so a 3PAO
reviewing the package can confirm the catalog was extracted from the
NIST-signed PDF (`docs/sources/NIST.SP.800-218.pdf`) and not invented.

## 2. Authoritative sources (verbatim quotes, accessed 2026-06-07)

### 2.1 Executive Order 14028 (May 12, 2021) — the originating mandate

Source: https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity (date of access: 2026-06-07; the executive order text is mirrored on NIST's portal pointing back to the Federal Register publication).

> "The security of software used by the Federal Government is vital to
> the Federal Government's ability to perform its critical functions.
> The development of commercial software often lacks transparency,
> sufficient focus on the ability of the software to resist attack, and
> adequate controls to prevent tampering by malicious actors."
> — EO 14028 §4(a)

> "Within 180 days of the date of this order, the Secretary of Commerce
> acting through the Director of NIST, in consultation with the heads of
> such agencies as the Director of NIST deems appropriate, shall publish
> guidelines recommending minimum standards for vendors' testing of
> their software source code, including identifying recommended types of
> manual or automated testing (such as code review tools, static and
> dynamic analysis, software composition tools, and penetration
> testing)."
> — EO 14028 §4(r)

### 2.2 NIST SP 800-218 v1.1 (February 2022) — the SSDF specification

Source: https://csrc.nist.gov/pubs/sp/800/218/final (PDF: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf) — date of access: 2026-06-07.

> "The Secure Software Development Framework (SSDF) is a set of
> fundamental, sound, and secure software development practices based on
> established secure software development practice documents from
> organizations such as BSA, OWASP, and SAFECode."

> "Following these practices should help software producers reduce the
> number of vulnerabilities in released software, mitigate the potential
> impact of the exploitation of undetected or unaddressed vulnerabilities,
> and address the root causes of vulnerabilities to prevent future
> recurrences."

> "Prepare the Organization (PO): Ensure that the organization's people,
> processes, and technology are prepared to perform secure software
> development at the organization level. Many organizations will find
> some PO practices applicable to subsets of their software development,
> like individual development groups or projects."

> "Protect the Software (PS): Protect all components of the software
> from tampering and unauthorized access."

> "Produce Well-Secured Software (PW): Produce well-secured software
> with minimal security vulnerabilities in its releases."

> "Respond to Vulnerabilities (RV): Identify residual vulnerabilities in
> software releases and respond appropriately to address those
> vulnerabilities and prevent similar vulnerabilities from occurring in
> the future."

> "PO.1: Define Security Requirements for Software Development. Ensure
> that security requirements for software development are known at all
> times so that they can be taken into account throughout the SDLC and
> duplication of effort can be minimized because the requirements
> information can be collected once and shared."

> "PO.1.1: Identify and document all security requirements for the
> organization's software development infrastructures and processes, and
> maintain the requirements over time."

> "PO.1.2: Identify and document all security requirements for
> organization-developed software to meet, and maintain the requirements
> over time."

> "PO.1.3: Communicate requirements to all third parties who will
> provide commercial software components to the organization for reuse
> by the organization's own software."

> "PO.5: Implement and Maintain Secure Environments for Software
> Development."

### 2.3 NIST SP 800-218A (Initial Public Draft, April 2024) — AI / Generative AI extension

Source: https://csrc.nist.gov/pubs/sp/800/218/A/ipd (date of access: 2026-06-07).

> "Each practice has a comprehensive definition tailored for generative
> AI and dual-use foundation models. SSDF practices are software-
> development-focused. SSDF practices are intended to apply to the
> development and use of AI models, particularly generative AI and
> dual-use foundation models."

NOTE: 218A is consulted but NOT loaded as the primary T.T1 catalog;
T.T1's primary scope is 800-218 v1.1 (the catalog the CISA Common Form
explicitly references). 218A is the source for the optional
`ai_extension_practices` block in the catalog JSON when the operator sets
`--ssdf-ai-extension` (out of scope for this slice — wired in T.T4).

### 2.4 OMB M-22-18 (Sept 14, 2022) — Federal-agency mandate

Source: https://www.whitehouse.gov/wp-content/uploads/2022/09/M-22-18.pdf (referenced; redistribution copies cited via SEWP at https://www.sewp.nasa.gov/documents/Updates_Concerning_Secure_Software_Requirements.pdf), date of access 2026-06-07.

> "Federal agencies must only use software provided by software
> producers who can attest to complying with the Government-specified
> secure software development practices, as described in the NIST
> Guidance."

> "The term 'software' for purposes of this memorandum includes
> firmware, operating systems, applications, and application services
> (e.g., cloud-based software), as well as products containing software."

> "Agencies must obtain a self-attestation from the software producer
> before using the software."

> "The requirements of this memorandum apply to all software (other
> than agency-developed software) developed or experiencing major
> version changes to be operated 'on the agency's information systems
> or otherwise affecting the agency's information,' and used by the
> agency after the effective date of this memorandum."

### 2.5 OMB M-23-16 (June 9, 2023) — extension + scope clarifications

Source: https://www.whitehouse.gov/wp-content/uploads/2023/06/M-23-16-Update-to-M-22-18.pdf (referenced via NITAAC publication: https://nitaac.nih.gov/resources/news/omb-issues-new-guidance-software-attestation), date of access 2026-06-07.

> "Agencies must collect attestations for 'critical software' no later
> than three months after the CISA common form is approved by OMB, and
> agencies must collect attestations for all other in-scope software
> within six months after the common form is approved."

> "Agencies will not be required to collect attestations from producers
> of software components incorporated into the software end products
> used by agencies."

> "No-cost, publicly available, proprietary software (such as web
> browsers) is out of scope for attestation collection."

### 2.6 CISA Common Form (OMB Control No. 1670-0052; final March 11, 2024)

Source: https://www.cisa.gov/sites/default/files/2024-04/Self_Attestation_Common_Form_FINAL_508c.pdf (date of access 2026-06-07; supplementary references via https://www.cisa.gov/secure-software-attestation-form and OMB inventory at https://omb.report/omb/1670-0052).

> "OMB Control No.: 1670-0052"
> "Expiration Date: 3/31/2027"

The form requires the signing CEO (or designee with comparable authority)
to affirm conformity with FOUR aggregated SSDF practice clusters. From
CISA's instructional companion document (citing the practice mappings
verbatim):

> "1. The software was developed and built in secure environments. Those
> environments were secured by the following actions, at a minimum [the
> form then enumerates: separating and protecting each environment
> involved in developing and building software; regularly logging,
> monitoring, and auditing trust relationships used for authorization
> and access to any software development and build environments;
> enforcing multi-factor authentication and conditional access across
> the environments relevant to developing and building software;
> taking consistent and reasonable steps to document as well as
> minimize use or inclusion of software products that create undue
> risk; encrypting sensitive data, such as credentials, to the extent
> practicable and based on risk; implementing defensive cybersecurity
> practices, including continuous monitoring of operations and alerts]."
> — Common Form §IV(1) (paraphrasing the bulleted sub-actions inline)

> "2. The software producer has made a good-faith effort to maintain
> trusted source code supply chains by employing automated tools or
> comparable processes to address the security of internal code and
> third-party components and to manage related vulnerabilities."
> — Common Form §IV(2)

> "3. The software producer maintains provenance for internal code and
> third-party components incorporated into the software to the extent
> feasible."
> — Common Form §IV(3)

> "4. The software producer employed automated tools or comparable
> processes that check for security vulnerabilities. In addition: a) the
> software producer operated these processes on an ongoing basis and,
> at a minimum, prior to product, version, or update releases; b) the
> software producer has a policy or process to address discovered
> security vulnerabilities prior to product release; and c) the software
> producer operates a vulnerability disclosure program and accepts,
> reviews, and addresses disclosed software vulnerabilities in a timely
> fashion and according to any timelines specified in the vulnerability
> disclosure program or applicable policies."
> — Common Form §IV(4)

The Common Form maps each numbered attestation to specific 800-218 v1.1
practice IDs (operator/3PAO-readable trail). Mapping per CISA appendix:

- §IV(1) ↔ PO.5.1, PO.5.2 (Secure Environments) and PS.1.1 (Protecting
  Code from Unauthorized Access).
- §IV(2) ↔ PO.1.3, PO.3.2, PO.5.1, PS.3.1, PW.4.1, PW.4.4 (good-faith
  trusted-source-chain), and RV.1.* (vulnerability handling on
  third-party code).
- §IV(3) ↔ PS.3.2 (Collect and Safeguard Provenance Data).
- §IV(4) ↔ PW.7.*, PW.8.*, RV.1.1, RV.1.2, RV.1.3, RV.2.1, RV.2.2,
  RV.3.* (automated tooling + vuln response + disclosure).

### 2.7 NIST SP 800-53 Rev 5 — control mapping target

Source: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final (date of access 2026-06-07). The SSDF v1.1 Section 3 table lists, per practice, the relevant 800-53 Rev 5 controls (e.g. PO.1 ↔ PM-3, PM-7, PM-30, SA-1, SA-3, SA-8, SA-15; PW.7 ↔ SA-11, SR-3; RV.1 ↔ CA-7, RA-5, SI-2, SI-5). The catalog imports this mapping verbatim from Appendix A of 800-218.

### 2.8 FedRAMP Key Security Indicator (KSI) catalog — KSI mapping target

Source: https://github.com/FedRAMP/docs (FRMR JSON repository; the FedPy `core/ksi-map.ts` is the canonical local mirror). Date of access 2026-06-07. T.T1 produces a forward-mapping table from each SSDF task to the FedRAMP KSI IDs that already satisfy (in whole or part) the SSDF task — primarily for the CMT, SCR, and CED domains.

## 3. Scope

### In scope
- Extracting all SSDF v1.1 practices (PO.1, PO.2, PO.3, PO.4, PO.5, PS.1, PS.2, PS.3, PW.1, PW.2, PW.4, PW.5, PW.6, PW.7, PW.8, PW.9, RV.1, RV.2, RV.3 — **19 practices**) and all constituent tasks (PO.1.1, PO.1.2, …) from `docs/sources/NIST.SP.800-218.pdf` into a canonical JSON catalog.
- Importing the 800-53 Rev 5 control mapping appendix verbatim into the catalog.
- Computing a forward-mapping from each SSDF task to FedRAMP KSI IDs (sourced from `core/ksi-map.ts`).
- Emitting `cloud-evidence/data/ssdf-800-218-v1.1.json` signed + timestamped.
- Building the ingester script `scripts/extract-ssdf-practices.mjs` that reads the PDF (offline; PDF stays in `docs/sources/`) and re-generates the JSON deterministically.
- Building `cloud-evidence/core/ssdf-practices-catalog.ts` — a strongly-typed in-memory loader/validator used by T.T2–T.T5.
- Writing `tests/core/ssdf-practices-catalog.test.ts` with ≥ 15 tests.
- Catalog integrity: the JSON carries a `source_pdf_sha256` provenance field so any consumer can verify the catalog was built from the published NIST PDF (not from a derivative summary).

### Out of scope
- Generating the actual CISA Common Form (that is T.T2).
- Aggregating evidence to demonstrate conformity (that is T.T3 + T.T5).
- Loading 218A (AI extension) practices into the primary catalog (that is T.T4).
- 218 Rev 1 (v1.2) draft practices — pending until v1.2 reaches Final status.
- Producing 800-218 → ISO 27034 / SOC 2 / CMMC L2 crosswalks (out-of-loop; will be in LOOP-C C.6 if requested).

## 4. Inputs

### 4.1 The NIST SP 800-218 v1.1 PDF (committed source)
Path: `cloud-evidence/docs/sources/NIST.SP.800-218.pdf`
Acquired: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf` (2026-06-07).
Expected SHA-256 (operator confirms at ingest time): captured into `data/ssdf-800-218-v1.1.json#provenance.source_pdf_sha256` by the extraction script.

### 4.2 The FedRAMP KSI map (existing, in-tree)
Path: `cloud-evidence/core/ksi-map.ts`
Schema: the well-known `KsiCatalogEntry` shape (`{ id, family, title, ... }`). The extractor reads this in-memory at catalog-build time and computes the forward mapping per task.

### 4.3 Operator inputs
None for T.T1 — this is a pure extraction slice. T.T2/T.T3/T.T5 add operator-supplied attestation signer + responses.

## 5. Outputs

### 5.1 `cloud-evidence/data/ssdf-800-218-v1.1.json` (signed, timestamped)

```json
{
  "catalog_id": "ssdf-800-218-v1.1",
  "framework_version": "SSDF v1.1 (NIST SP 800-218, Feb 2022)",
  "extracted_at": "2026-06-07T00:00:00Z",
  "source_pdf_path": "docs/sources/NIST.SP.800-218.pdf",
  "source_pdf_sha256": "<computed by extractor>",
  "publication": {
    "title": "Secure Software Development Framework (SSDF) Version 1.1",
    "publisher": "NIST",
    "publication_date": "2022-02",
    "doi": "10.6028/NIST.SP.800-218"
  },
  "practice_groups": [
    {
      "id": "PO",
      "name": "Prepare the Organization",
      "definition": "Ensure that the organization's people, processes, and technology are prepared to perform secure software development at the organization level. Many organizations will find some PO practices applicable to subsets of their software development, like individual development groups or projects."
    },
    { "id": "PS", "name": "Protect the Software", "definition": "Protect all components of the software from tampering and unauthorized access." },
    { "id": "PW", "name": "Produce Well-Secured Software", "definition": "Produce well-secured software with minimal security vulnerabilities in its releases." },
    { "id": "RV", "name": "Respond to Vulnerabilities", "definition": "Identify residual vulnerabilities in software releases and respond appropriately to address those vulnerabilities and prevent similar vulnerabilities from occurring in the future." }
  ],
  "practices": [
    {
      "id": "PO.1",
      "group": "PO",
      "name": "Define Security Requirements for Software Development",
      "intent": "Ensure that security requirements for software development are known at all times so that they can be taken into account throughout the SDLC and duplication of effort can be minimized because the requirements information can be collected once and shared.",
      "tasks": [
        { "id": "PO.1.1", "statement": "Identify and document all security requirements for the organization's software development infrastructures and processes, and maintain the requirements over time." },
        { "id": "PO.1.2", "statement": "Identify and document all security requirements for organization-developed software to meet, and maintain the requirements over time." },
        { "id": "PO.1.3", "statement": "Communicate requirements to all third parties who will provide commercial software components to the organization for reuse by the organization's own software." }
      ],
      "nist_800_53_r5_controls": ["pm-3", "pm-7", "pm-30", "sa-1", "sa-3", "sa-8", "sa-15", "sr-3"],
      "common_form_section_ref": ["§IV(2)"],
      "fedramp_ksi_forward_map": ["CMT-RMV", "CMT-VTD", "SCR-MON"]
    }
    /* ... 18 more practice objects ... */
  ],
  "provenance": {
    "emitter": "extract-ssdf-practices",
    "emitter_version": "1.0.0",
    "extracted_by_run_id": "<run-uuid>",
    "extractor_script_sha256": "<computed>",
    "ksi_map_sha256": "<computed at build time>"
  },
  "envelope": {
    "signature": "<Ed25519 base64>",
    "signing_key_id": "<UUID>",
    "rfc3161_timestamp": "<base64 token>"
  }
}
```

### 5.2 The in-memory TypeScript module
`cloud-evidence/core/ssdf-practices-catalog.ts` exports:

```ts
export interface SsdfPracticeGroup {
  id: 'PO' | 'PS' | 'PW' | 'RV';
  name: string;
  definition: string;
}
export interface SsdfTask {
  id: string;          // e.g. "PO.1.1"
  statement: string;
}
export interface SsdfPractice {
  id: string;          // e.g. "PO.1"
  group: 'PO' | 'PS' | 'PW' | 'RV';
  name: string;
  intent: string;
  tasks: SsdfTask[];
  nist_800_53_r5_controls: string[];
  common_form_section_ref: ('§IV(1)' | '§IV(2)' | '§IV(3)' | '§IV(4)')[];
  fedramp_ksi_forward_map: string[];
}
export interface SsdfCatalog {
  catalog_id: 'ssdf-800-218-v1.1';
  framework_version: string;
  extracted_at: string;
  source_pdf_path: string;
  source_pdf_sha256: string;
  publication: { title: string; publisher: string; publication_date: string; doi: string };
  practice_groups: SsdfPracticeGroup[];
  practices: SsdfPractice[];
  provenance: { emitter: string; emitter_version: string; extracted_by_run_id: string; extractor_script_sha256: string; ksi_map_sha256: string };
  envelope: { signature: string; signing_key_id: string; rfc3161_timestamp: string };
}
export function loadSsdfCatalog(path?: string): SsdfCatalog;
export function getPractice(id: string): SsdfPractice;
export function getTasksByPracticeGroup(g: 'PO'|'PS'|'PW'|'RV'): SsdfTask[];
export function tasksByCommonFormSection(s: '§IV(1)'|'§IV(2)'|'§IV(3)'|'§IV(4)'): SsdfTask[];
```

### 5.3 The extraction script
`scripts/extract-ssdf-practices.mjs` is a Node ESM module that:
1. Loads the source PDF via `pdf-parse` (existing dependency from LOOP-C.C2).
2. Walks Section 3 (Practices) and Appendix A (Mappings) using deterministic anchors (practice ID regex `/^P[OSW][12345]?:|^RV\.[123]:/` and sub-task regex `/^[PR][OSWV]\.\d+\.\d+\s/`).
3. Cross-references the FedRAMP KSI map (`core/ksi-map.ts` — read as JSON via `tsx --eval` or pre-built `data/ksi-map.json`).
4. Computes deterministic SHA-256 over the source PDF.
5. Writes the catalog JSON to `cloud-evidence/data/ssdf-800-218-v1.1.json` with stable key ordering (alphabetical within objects; array order matches NIST publication order — PO before PS before PW before RV; within group, ascending numeric).
6. Calls `core/sign.ts:signFile()` + `core/timestamp.ts:rfc3161Stamp()`.
7. Exits 0 on success; non-zero with typed error code on mismatch (e.g. fewer than 19 practices found, missing 800-53 mapping appendix, KSI map version mismatch).

## 6. Algorithm / Steps (deterministic, REO-compliant)

1. **Source verification.** Read `docs/sources/NIST.SP.800-218.pdf`; compute SHA-256; abort with `ERR_SSDF_SOURCE_MISSING` if not present, `ERR_SSDF_SOURCE_SHA256_DRIFT` if the hash disagrees with a previously-committed value when one exists in the existing catalog JSON.
2. **PDF parse.** Stream the PDF through `pdf-parse`; concatenate page text; normalize Unicode (` ` → space, smart-quotes → ASCII).
3. **Anchor detection.** Locate Section 3 ("The Secure Software Development Framework Practices and Tasks"). Slice text from there to "Appendix A".
4. **Practice extraction.** Iterate practice headings (`/^(PO|PS|PW|RV)\.(\d+):\s+(.+)$/m`). For each: capture `id`, `group`, `name`. Read forward to the next heading for `intent` (immediately following descriptive paragraph). Read tasks (`/^(PO|PS|PW|RV)\.\d+\.\d+\s+(.+)$/m`).
5. **Mapping import.** Locate Appendix A ("References Mapping"). For each practice ID, parse the comma-list of 800-53 r5 control IDs (lower-cased; `ac-2`, `sa-11`, etc.).
6. **KSI forward map.** Load `core/ksi-map.ts` (compiled to JS via `tsx`; or use a generated `data/ksi-map.json` snapshot). For each SSDF practice, compute the KSI forward map by applying a deterministic curated mapping table baked into the extractor (see `scripts/data/ssdf-ksi-mapping.json`). Curated because the SSDF → KSI relationship is semantic, not 1:1; the mapping table is operator-reviewed at PR time. Any KSI ID referenced in the mapping that does not exist in `ksi-map.ts` fails extraction (`ERR_SSDF_KSI_UNKNOWN`).
7. **Common Form section labeling.** For each practice, attach the `common_form_section_ref` value per CISA's Common Form mapping table (baked in; sourced from `docs/sources/Self_Attestation_Common_Form_FINAL_508c.pdf` companion mapping appendix).
8. **Assertions.** Assert exactly 19 practices, exactly 4 groups, exactly the documented practice IDs (PO.1, PO.2, PO.3, PO.4, PO.5, PS.1, PS.2, PS.3, PW.1, PW.2, PW.4, PW.5, PW.6, PW.7, PW.8, PW.9, RV.1, RV.2, RV.3 — note PW.3 was intentionally dropped between v1.0 and v1.1; the assertion catches accidental re-introduction).
9. **JSON serialization.** Use `canonicalize` (json-canonicalize package) for stable byte output so signatures stay reproducible.
10. **Sign.** Pipe the canonical bytes through `core/sign.ts:signBytes(ed25519PrivKey)` → emit `envelope.signature`.
11. **Timestamp.** Call `core/timestamp.ts:rfc3161Stamp(signatureBytes)` → emit `envelope.rfc3161_timestamp`.
12. **Write.** Write atomically (`fs.promises.writeFile` to `<path>.tmp` then `fs.promises.rename`).
13. **Lint.** Run `npm run check:provenance` and `npm run lint:no-stubs` — both must pass.

## 7. Files to create / modify

### Create
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssdf-practices-catalog.ts` — typed loader/validator/lookup (~ 280 lines).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/extract-ssdf-practices.mjs` — offline ingester (~ 350 lines).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/scripts/data/ssdf-ksi-mapping.json` — curated SSDF practice → FedRAMP KSI forward map (operator-reviewed).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/ssdf-800-218-v1.1.json` — generated, signed catalog (committed).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/ssdf-practices-catalog.test.ts` — ≥ 15 tests (see §8).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/ssdf/` — three fixture files: `ssdf-catalog.valid.json`, `ssdf-catalog.missing-practice.json`, `ssdf-catalog.bad-mapping.json` for negative tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/NIST.SP.800-218.pdf` — committed published PDF.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/sources/Self_Attestation_Common_Form_FINAL_508c.pdf` — committed published PDF.

### Modify
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/package.json` — add `"build:ssdf-catalog": "node scripts/extract-ssdf-practices.mjs"`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add role `ssdf-practice-catalog-json` to `WELL_KNOWN` so the catalog ships in the submission bundle when the optional `--include-ssdf-catalog` flag is set (default: off; T.T2 turns it on when emitting the Common Form).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CLAUDE.md` (reading list) — add `data/ssdf-800-218-v1.1.json` as a permanent reference.

## 8. Test specifications (≥ 15 tests)

| # | Scenario | Fixture | Expected | Acceptance |
|---|----------|---------|----------|------------|
| T1 | Catalog loads from disk and parses to `SsdfCatalog` | `tests/fixtures/ssdf/ssdf-catalog.valid.json` | object returned, `practices.length === 19` | `expect(catalog.practices).toHaveLength(19)` |
| T2 | All four practice groups present in order | (uses loaded catalog) | `['PO','PS','PW','RV']` | `expect(catalog.practice_groups.map(g=>g.id)).toEqual(['PO','PS','PW','RV'])` |
| T3 | Practice IDs match the canonical 19 | (loaded catalog) | exact set `{PO.1..PO.5, PS.1..PS.3, PW.1, PW.2, PW.4..PW.9, RV.1..RV.3}` | set equality |
| T4 | PW.3 is intentionally absent | (loaded catalog) | `getPractice('PW.3')` throws `ERR_SSDF_PRACTICE_NOT_FOUND` | `expect(()=>getPractice('PW.3')).toThrow()` |
| T5 | Every practice has a non-empty 800-53 r5 control mapping | loaded catalog | every `nist_800_53_r5_controls.length > 0` | `for (p of practices) expect(p.nist_800_53_r5_controls.length).toBeGreaterThan(0)` |
| T6 | PO.1 maps to expected r5 controls | loaded catalog | superset of `{pm-3, pm-7, sa-1, sa-3, sa-8, sa-15}` | superset assertion |
| T7 | RV.1 maps to expected r5 controls | loaded catalog | superset of `{ca-7, ra-5, si-2, si-5}` | superset assertion |
| T8 | Every task statement is non-empty + ASCII-normalized | loaded catalog | no smart-quotes / nbsp | regex `/^[\x20-\x7e]+$/` per statement |
| T9 | Each practice carries ≥ 1 `common_form_section_ref` entry | loaded catalog | `common_form_section_ref.length >= 1` | per-practice assertion |
| T10 | `getTasksByPracticeGroup('RV')` returns RV.1.*, RV.2.*, RV.3.* | loaded catalog | every task id starts with `RV.` | startsWith assertion |
| T11 | `tasksByCommonFormSection('§IV(3)')` includes PS.3.2 | loaded catalog | `ids.includes('PS.3.2') === true` | direct check |
| T12 | Catalog provenance block is fully populated | loaded catalog | `provenance.emitter === 'extract-ssdf-practices'` + `source_pdf_sha256.length === 64` | regex + length |
| T13 | Catalog envelope carries Ed25519 signature + RFC 3161 token | loaded catalog | `envelope.signature` decodes to 64 bytes; `envelope.rfc3161_timestamp` non-empty | base64 decode + size |
| T14 | Loader rejects missing practice (negative) | `tests/fixtures/ssdf/ssdf-catalog.missing-practice.json` (only 18 practices) | throws `ERR_SSDF_PRACTICE_COUNT_MISMATCH` | rejected promise / throw |
| T15 | Loader rejects unknown KSI in forward map (negative) | `tests/fixtures/ssdf/ssdf-catalog.bad-mapping.json` | throws `ERR_SSDF_KSI_UNKNOWN` | throw assertion |
| T16 | Extractor SHA-256 of PDF persists into catalog | live extractor run against fixture mini-PDF | hex SHA-256 matches `sha256sum` of source | byte-exact compare |
| T17 | Extractor exits non-zero when PDF sha drifts from committed catalog | run extractor with mutated mini-PDF + committed catalog with old sha | exit code 4 (`ERR_SSDF_SOURCE_SHA256_DRIFT`) | child_process exit code |
| T18 | Re-extracting the same PDF produces byte-identical canonical JSON (excluding envelope) | run extractor twice; strip `envelope` + `extracted_at` | byte-equality after strip | sha256(a) === sha256(b) |
| T19 | Catalog passes `check:provenance` and `lint:no-stubs` | `npm run check:provenance` + `npm run lint:no-stubs` on a clean tree | both exit 0 | spawn assertion |

## 9. Risks (minimum 4 — actually surface 6 here)

### Risk T.T1-R1 — NIST PDF layout drift between revisions
**Description.** NIST may republish 800-218 v1.1 with reformatted section headings, alternative pagination, or revised mapping appendix. The deterministic anchor regexes could miss practices or mis-bind intent paragraphs.
**Likelihood.** Low for v1.1 (final, frozen Feb 2022). Medium when v1.2 ships.
**Impact.** High — silent catalog corruption breaks T.T2/T.T3 downstream.
**Mitigation.** (a) Hard-pin the source PDF SHA-256 in the committed catalog JSON; reject mismatches at extraction time; (b) assert exact practice IDs + counts; (c) when v1.2 lands, build a *parallel* catalog (T.T1 stays at v1.1) and add a `--ssdf-version v1.2` selector — do NOT in-place mutate.

### Risk T.T1-R2 — CISA Common Form mapping evolution
**Description.** CISA's mapping of §IV attestation paragraphs to specific SSDF practice IDs may be revised (the 2024 release already differs from the 2023 draft). The `common_form_section_ref` table baked into the extractor could drift.
**Likelihood.** Medium (OMB recently rescinded portions of M-22-18 on Jan 23, 2026; the risk-based replacement may further change form mappings).
**Impact.** Medium — T.T2 (Common Form generator) would generate the wrong cross-reference appendix.
**Mitigation.** (a) Maintain the mapping table as `scripts/data/ssdf-common-form-mapping.json` (separate from the extractor code) so it can be PR-reviewed independently; (b) include a CISA publication date in the catalog JSON; (c) when OMB issues the M-22-18 replacement, gate downstream slices behind an explicit operator confirmation flag.

### Risk T.T1-R3 — KSI forward-map subjectivity
**Description.** The SSDF practice → FedRAMP KSI relationship is *semantic* (e.g. PO.5 ↔ CNA-EIS is a judgment call, not a published NIST mapping). Curators may disagree.
**Likelihood.** High at curation time; Low after the table is reviewed.
**Impact.** Medium — T.T5 (gap matrix) could over-claim or under-claim KSI coverage.
**Mitigation.** (a) Keep the mapping table in a separate JSON (`scripts/data/ssdf-ksi-mapping.json`) with a `rationale` field per pair; (b) require at least one citation per mapping (KSI FRD URL or 800-53 control linkage); (c) mark uncertain mappings `confidence: 'low'` so T.T5 surfaces them as `requires-operator-review` rather than `satisfied`.

### Risk T.T1-R4 — OMB rescission timing (Jan 23, 2026 alert)
**Description.** OMB has signaled rescission of the M-22-18 mandate in favor of a risk-based approach. The CISA Common Form may become advisory rather than mandatory; existing federal contracts may still cite M-22-18 + the Common Form.
**Likelihood.** High (publicly reported Jan 2026; replacement memorandum forthcoming).
**Impact.** Medium-Low — T.T1 (catalog only) is unaffected; downstream T.T2–T.T5 may need to gate on a `--legacy-m-22-18-common-form` flag once the replacement memorandum names a new form.
**Mitigation.** (a) Keep T.T1 framework-agnostic — it's a pure 800-218 catalog; (b) document the policy state in `docs/loops/LOOP-T-SPEC.md` §2; (c) wire a `policy_basis` field on the catalog `provenance` block so the catalog records "as-of-2026-06-07 policy regime: M-22-18 + M-23-16 + Common Form 1670-0052"; (d) when the replacement memorandum publishes, ship LOOP-T extension slice updating downstream consumers (NOT T.T1).

### Risk T.T1-R5 — pdf-parse library bugs / Unicode normalization
**Description.** PDF text extraction is notoriously lossy; multi-column layouts, ligatures, and font subsetting can drop or merge characters.
**Likelihood.** Medium.
**Impact.** High — silently corrupt task statements.
**Mitigation.** (a) After extraction, run a sanity check that asserts each task statement matches a deterministic length-range (`statement.length > 30 && statement.length < 1500`); (b) maintain a *golden* fixture (`tests/fixtures/ssdf/golden-task-statements.json`) for ≥ 5 hand-verified task statements and assert byte-equality; (c) provide a `--strict` flag that fails on any character outside `[\x20-\x7e]` after Unicode normalization.

### Risk T.T1-R6 — Catalog signing key rotation
**Description.** The catalog is Ed25519-signed; if the signing key rotates without re-signing the catalog, downstream verification will fail.
**Likelihood.** Low (key rotation is rare).
**Impact.** Medium — submission-bundle verification breaks.
**Mitigation.** (a) Add `signing_key_id` to the envelope so a verifier can locate the right pubkey; (b) `core/key-registry.ts` already supports multiple historical pubkeys; (c) include a re-sign script `npm run resign:ssdf-catalog` that emits a fresh envelope without re-extracting; (d) cover with regression test T13.

## 10. Open questions

- **Q1.** Should the catalog include the SSDF v1.1 *implementation examples* (the lettered sub-bullets under each task — e.g. PO.1.1.a, PO.1.1.b)? They are *informative*, not normative. **Recommendation:** include them under a separate optional `examples[]` array per task (off by default; gated on `--include-examples` extractor flag). Defer to T.T3 (evidence aggregator) for actual use.
- **Q2.** Should the catalog carry a Rev 4 (800-53 Rev 4) mapping for legacy consumers? **Recommendation:** No — Rev 4 is withdrawn; Rev 5 is canonical. Capture in catalog comments.
- **Q3.** Should the extractor pull from the OSCAL-formatted SSDF catalog if NIST publishes one? **Recommendation:** Yes when available; preferred over PDF-parse. Track NIST OSCAL repo (https://github.com/usnistgov/oscal-content) in T.T1's Implementation log.
- **Q4.** Should the catalog include a `withdrawn_practices` array enumerating practices removed between v1.0 and v1.1 (notably PW.3)? **Recommendation:** Yes — improves transparency for cross-version mapping consumers.
- **Q5.** Should the curated KSI forward-mapping be reviewable through the tracker UI? **Recommendation:** Out of scope for T.T1; T.T5 will add a tracker page for reviewing the gap matrix; mapping edits remain code-review-only.

### §10 resolutions (impl session 2026-06-10)

- **Q1 (implementation examples):** Deferred per recommendation — the catalog omits the lettered `Example N:` sub-bullets (the extractor truncates each task statement at the first `Example`). They remain available in the committed PDF for T.T3. No `examples[]` array shipped (no `--include-examples` flag in T.T1 scope).
- **Q2 (Rev 4 mapping):** Resolved NO — the catalog carries only SP 800-53 Rev 5 controls (verbatim from Table 1's `SP80053:` reference cells); `provenance.nist53Revision = "5"`.
- **Q3 (OSCAL SSDF source):** NIST publishes no official OSCAL SSDF catalog as of 2026-06-10; the extractor parses the published PDF. The extractor re-verifies each practice name appears verbatim in the PDF text and pins `source_pdf_sha256`, so a 3PAO can confirm the catalog traces to the NIST-signed PDF.
- **Q4 (withdrawn enumeration):** Resolved YES — the catalog carries `withdrawn_practices` (PW.3) and `withdrawn_tasks` (PW.3.1, PW.3.2, PW.4.3, PW.4.5, PW.5.2 — the 5 "Moved to" tasks). The extractor asserts exactly 5 withdrawn tasks.
- **Q5 (tracker review):** Deferred to T.T5 per recommendation; the curated map ships as `scripts/data/ssdf-ksi-mapping.json` with `reviewed: true` + per-pair `confidence`/`rationale`, PR-reviewed only.

### Spec-vs-source reconciliations (authoritative NIST PDF wins — REO)

The per-slice spec made three numeric/shape assumptions that the authoritative
extraction from `docs/sources/NIST.SP.800-218.pdf` corrected. Per REO, the
catalog + tests assert the real source, and the §8 test table was adapted:

1. **Task count is 42, not 43.** NIST SP 800-218 v1.1 Table 1 has 42 active
   tasks plus 5 withdrawn ("Moved to") task headings. `EXPECTED_TASK_COUNT = 42`.
   (Per-group split: PO 13, PS 4, PW 16, RV 9.)
2. **PW.2 and PW.5 have NO SP 800-53 mapping.** Their Table 1 References cells
   cite other frameworks (BSAFSS, BSIMM, EO14028, IEC62443, ISO27034, OWASP, …)
   but no `SP80053:` line. So 17 of 19 practices carry a 800-53 mapping, not 19.
   Spec test T5 was changed from "every practice" to "17 of 19; PW.2/PW.5 empty".
3. **The Common Form covers 11 of 19 practices** at the practice level (the four
   §IV attestations map to PO.1, PO.3, PO.5, PS.1, PS.3, PW.4, PW.7, PW.8, RV.1,
   RV.2, RV.3). Spec test T9 ("each practice carries ≥1 ref") was changed to
   "11 carry ≥1 ref; the field is present (possibly empty) on all 19".
4. Tests T6/T7 (PO.1 / RV.1 expected controls) were set to the controls actually
   published in those practices' References cells (e.g. PO.1 ⊇ {sa-1, sa-8, sa-15,
   sr-3}; RV.1 ⊇ {sa-10, sa-11, sr-3, sr-4}) rather than the spec's illustrative
   {pm-3, pm-7, …} guess.

## 11. REQUIRES-OPERATOR-INPUT fields (per REO Rule 4)

| Field name | Type | Validator | UI location | Failure mode if missing |
|------------|------|-----------|-------------|-------------------------|
| `provenance.extracted_by_run_id` | UUID v4 | `/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i` | injected by the extractor CLI from `--run-id` flag; orchestrator generates if missing | If the CLI is called without `--run-id` AND not invoked from orchestrator: extractor synthesizes a v4 UUID and logs `provenance:auto-run-id` — no operator block; recorded honestly in run log. |
| `envelope.signing_key_id` | UUID v4 | `key-registry.ts:isKnownKey()` | `config.yaml:signing.active_key_id` | Extractor exits with `ERR_SSDF_NO_SIGNING_KEY` and instructs operator to run `npm run init:signing-key`. |
| `data/ksi-map.json` snapshot version | semver | `package.json:cloud-evidence#version` | injected by `scripts/build-ksi-map-snapshot.mjs` (existing) | If `data/ksi-map.json` missing: extractor exits with `ERR_SSDF_KSI_MAP_MISSING`; runbook documents the rebuild command. |
| `docs/sources/NIST.SP.800-218.pdf` | committed PDF | SHA-256 byte check at extraction | committed file under version control | If file missing: `ERR_SSDF_SOURCE_MISSING`; remediation message says "download from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf and commit". |
| `scripts/data/ssdf-ksi-mapping.json` curator review checkbox | boolean (`reviewed: true`) | mapping JSON's top-level `reviewed === true` | code-review only | If `reviewed !== true`: extractor exits with `ERR_SSDF_KSI_MAPPING_UNREVIEWED`. |

## 12. Implementation log (running journal — implementing session updates this)

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| 2026-06-07 | authoring | T.T1 spec authored | (this commit TBD) | per-slice doc created from ground up; awaiting implementation session |
| 2026-06-10 | impl-t-t1 | Downloaded + committed the authoritative NIST SP 800-218 v1.1 PDF (sha256 `617746e5…`) + CISA Common Form PDF (sha256 `a8d6b568…`) to `docs/sources/` | 9bbbcd1 | `docs/sources/` did not previously exist; T.T1 establishes it. Both PDFs are now version-controlled provenance anchors. |
| 2026-06-10 | impl-t-t1 | Added `pdf-parse@^2.4.5` devDependency for the offline extractor's PDF-text fidelity parse | 9bbbcd1 | spec assumed `pdf-parse` was "existing from LOOP-C.C2"; LOOP-C is unimplemented + the dep was absent, so it was added here. pdf-parse v2 uses the `new PDFParse({data}).getText()` class API (not the v1 callable). |
| 2026-06-10 | impl-t-t1 | Implemented `scripts/extract-ssdf-practices.mjs` (parses Table 1 verbatim) + `core/ssdf-practices-catalog.ts` (typed loader/validator/lookup) + `scripts/data/ssdf-ksi-mapping.json` (curated forward map) | 9bbbcd1 | extractor parses statements/intents/800-53 controls verbatim from the PDF; 19 practice names are verified-present published constants; runs via `tsx` so it composes `core/sign.ts`. |
| 2026-06-10 | impl-t-t1 | Generated + committed signed catalog `data/ssdf-800-218-v1.1.json` (un-ignored via `.gitignore` negation, mirroring the W.W1 constants) | 9bbbcd1 | 19 practices, 42 tasks, 17/19 practices with 800-53 mapping, 11 with Common Form refs, 12 KSI-mapped; detached Ed25519 signature self-verifies via embedded `provenance.publicKeyPem`. |
| 2026-06-10 | impl-t-t1 | Wrote 25 vitest tests (`tests/core/ssdf-practices-catalog.test.ts`) + 3 fixtures; typecheck clean, 964/964 tests pass (+25), `npm run check:reo` (G1+G2+G3) all green | 9bbbcd1 | spec §8 test expectations were adapted to the authoritative source (see §10 resolutions): real task count is 42 (not 43); PW.2/PW.5 carry no SP 800-53 mapping; 11 (not all 19) practices carry a Common Form ref. |

(Implementation session: append a new row at every meaningful milestone — see `docs/IMPLEMENTATION-LOG-TEMPLATE.md` §3.)

## 13. Completion checklist (the SLICE-COMPLETION-PROCEDURE.md 7-step procedure, verbatim)

The implementing session MUST execute every step atomically with the final commit:

1. **Pass typecheck + tests + check:reo** (atomic — green before commit). Concretely: `npm run typecheck && npm test -- tests/core/ssdf-practices-catalog.test.ts && npm run check:reo`.
2. **Update STATUS.md** — append a row for T.T1 in the LOOP-T section with `status: done`, `commit: <hash>`, `completed_date: <ISO>`, and update the Overall → "Next priority" line.
3. **Update the LOOP-T spec doc** (`docs/loops/LOOP-T-SPEC.md`) — flip T.T1 status row from `proposed` to `done`; record commit hash + date.
4. **Update this file's frontmatter** — `status: done`, `commit: <hash>`, `completed_date: <ISO>`, `last_updated: <ISO>`.
5. **Append a final Implementation log entry** to §12 above — date, outcome, commit hash, tests added count, notes.
6. **Add any newly-discovered risks to `docs/loops/LOOP-T-RISKS.md`** in the same commit (if surfaced during implementation).
7. **Add a CHANGELOG.md "Unreleased" entry** — opens with "T.T1 — NIST SP 800-218 v1.1 SSDF catalog (signed) extracted from `docs/sources/NIST.SP.800-218.pdf`; <N> tests added; 800-53 Rev 5 + KSI forward maps published in `data/ssdf-800-218-v1.1.json`."
8. **Commit with `T.T1` in the message** and the `Co-Authored-By` trailer.
9. **Push to `origin/main`**.

**Then — and only then — the slice is closed.** After commit lands, append a row to `STATUS.md` for this slice; update the loop SPEC status row; append a CHANGELOG line; push to `origin/main`; only THEN is the slice closed.

## 14. Resume-from-fresh-session checklist

If a session opens with ONLY this file as context (Path B in `cloud-evidence/CLAUDE.md`):

1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard, reading list, 7-step procedure).
2. This file gives you: mission + authoritative sources + scope + I/O + algorithm + files + tests + risks + REQUIRES-OPERATOR-INPUT table + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-T-SPEC.md` for cross-loop context: how T.T1 feeds T.T2 (Common Form generator), T.T3 (evidence aggregator), and T.T5 (KSI ↔ SSDF gap matrix).
4. Read `cloud-evidence/docs/loops/LOOP-T-RISKS.md` register for the loop-level risk view; add any new risk surfaced during implementation.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step procedure.
6. Read `cloud-evidence/docs/IMPLEMENTATION-LOG-TEMPLATE.md` for the running-journal format used in §12.
7. Read `cloud-evidence/core/ksi-map.ts` — the KSI catalog the forward-map curator references; the catalog snapshot used at extract time is `cloud-evidence/data/ksi-map.json` (rebuild with `npm run build:ksi-map-snapshot`).
8. Read `cloud-evidence/core/sign.ts` and `cloud-evidence/core/timestamp.ts` — the signing + timestamping primitives the extractor calls.
9. Confirm `docs/sources/NIST.SP.800-218.pdf` exists; if missing, download from `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf` (sha256 confirmed at PR review time).
10. Confirm `docs/sources/Self_Attestation_Common_Form_FINAL_508c.pdf` exists; if missing, download from `https://www.cisa.gov/sites/default/files/2024-04/Self_Attestation_Common_Form_FINAL_508c.pdf`.
11. Begin implementation; update §12 Implementation log at every commit boundary.

## 15. Cross-references

- **LOOP-T-SPEC** — parent specification (slice list + reusable primitives + integration tests).
- **LOOP-T-RISKS** — loop-level risk register; add new findings here in the same commit as the code.
- **T.T2** (downstream) — CISA Common Form (`OMB 1670-0052`) JSON+PDF generator; reads this catalog to label each attestation paragraph with the underlying practice IDs.
- **T.T3** (downstream) — SSDF evidence aggregator; reads this catalog to compute per-practice satisfaction status from cloud + tracker evidence.
- **T.T5** (downstream) — KSI ↔ SSDF gap matrix; reads this catalog's `fedramp_ksi_forward_map` to render the matrix.
- **LOOP-A.A4** — submission bundle catalogue; T.T1 adds `ssdf-practice-catalog-json` role.
- **LOOP-G.G2** — incident communication; SSDF RV.1 dovetails with CIRCIA / IR-6 in M.M4 + G.G2 (see `docs/slices/G/G.G2-CIRCIA-EXTENSION.md` for the comparable pattern).
- **CLAUDE.md** reading list — add `data/ssdf-800-218-v1.1.json` after this slice ships.

## 16. Glossary deltas (terms added by this slice)

- **SSDF** — Secure Software Development Framework; NIST SP 800-218 v1.1.
- **SSDF Practice Group** — top-level grouping: PO, PS, PW, RV.
- **SSDF Practice** — second-level item (e.g. PO.1, RV.3); 19 in v1.1.
- **SSDF Task** — third-level item (e.g. PO.1.1, PO.1.2, RV.3.4); the actionable unit.
- **CISA Common Form** — the OMB-approved `1670-0052` self-attestation form a software producer signs to attest conformity with the four §IV(1)–§IV(4) practice clusters.
- **In-scope software** (per M-22-18) — firmware, OS, applications, application services (incl. cloud-based), and products containing software; agency-developed software, no-cost publicly-available proprietary software (e.g. browsers), and software components incorporated into end products are out of scope.
- **KSI forward map** — T.T1's curated mapping from each SSDF practice/task to the FedRAMP KSIs that satisfy it in whole or part; carries `confidence` (high|medium|low) and `rationale`.

## 17. REO compliance — slice-specific

- The catalog is loaded from a real PDF published by NIST. The extractor's output JSON is byte-deterministic and Ed25519-signed + RFC 3161 timestamped.
- The 800-53 mapping is taken verbatim from Appendix A of the published PDF; not synthesized.
- The KSI forward map is a curated table with `rationale` per pair, reviewed at PR time; uncertain pairs are marked `confidence: 'low'` so T.T5 surfaces them as `requires-operator-review`.
- No `process.env.NODE_ENV === 'test'` branches; tests inject the catalog via the `path?` parameter of `loadSsdfCatalog`.
- No fake signatures; the test envelope is signed with a *test* key (in `key-registry`'s `test` slot) — provenanced, not faked.
- No silent fallback if a practice statement is malformed; the loader rejects with a typed `ERR_SSDF_*` error.
- The catalog ships under `data/` and is treated as published evidence — its provenance block traces back to the source PDF SHA-256.

## 18. Verification commands

```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/ssdf-practices-catalog.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
npm run build:ssdf-catalog     # rebuilds data/ssdf-800-218-v1.1.json from the committed PDF
```

## 19. Notes for the next slice (T.T2)

T.T2 builds the CISA Common Form (`OMB 1670-0052`) JSON + PDF emitter on top of this catalog. T.T2 will:
- Read `data/ssdf-800-218-v1.1.json` via `loadSsdfCatalog()`.
- Aggregate per-§IV attestation paragraph using `tasksByCommonFormSection()`.
- Bind operator-supplied signer metadata (CEO name + title + signing date + signature image OR digital-sig token) via the tracker.
- Emit `out/cisa-common-form-1670-0052.json` and `out/cisa-common-form-1670-0052.pdf` (the rendered PDF mirrors the official layout).
- Sign and timestamp the emitted bundle through the existing pipeline.

T.T2 inherits T.T1's catalog SHA-256 in its provenance block so a 3PAO can trace from the form back through the catalog back through the PDF.

---

End of T.T1.
